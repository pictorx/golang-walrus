use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uchar};
use std::path::{Path, PathBuf};
use std::slice;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use zeroize::ZeroizeOnDrop;

mod builder;
mod error;
mod ffi;
mod intent;

// Re-export for C interop and for ffi.rs / intent submodules.
pub use builder::{Argument, Function, ObjectInput, TransactionBuilder};
pub use error::Error;
pub use ffi::*;
// Re-export the intent API so downstream crates import from the crate root.
#[cfg(feature = "intents")]
pub use intent::CoinWithBalance;

use walrus_sdk::{
    config::load_configuration,
    node_client::{
        responses::{BlobStoreResult, PooledBlobStoreResult},
        store_args::StoreArgs,
        StoreBlobsApi, StoreBlobsInStoragePoolApi, WalrusNodeClient,
    },
    uploader::TailHandling,
};
use walrus_sui::client::BlobPersistence;
use walrus_sui::types::move_structs::BlobAttribute;
use walrus_sui::types::move_structs::ObjectID;

// ── Shared Tokio runtime ──────────────────────────────────────────────────────
static RUNTIME: OnceLock<Runtime> = OnceLock::new();
const CLIENT_TIMEOUT_SECS: u64 = 15;

fn runtime() -> Result<&'static Runtime> {
    Ok(RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build shared tokio runtime")
    }))
}

fn block_on<F: std::future::Future<Output = Result<T>>, T>(f: F) -> Result<T> {
    runtime()?.block_on(f)
}

// ── Ephemeral wallet ──────────────────────────────────────────────────────────
//
// new_contract_client_with_wallet_in_config(timeout: Option<u64>) finds the
// Sui wallet via `wallet_config.path` inside the loaded ClientConfig, falling
// back to ~/.sui/sui_config/client.yaml when the field is absent.
//
// We never want to rely on that default path, so instead of passing a path to
// the SDK call we inject our ephemeral wallet path into the walrus YAML before
// loading it. The call then naturally picks up our temp file.
//
// Concretely, for each FFI call we:
//   1. Write a locked-down temp directory  (0o700)
//   2. Write sui.keystore                  (0o600)  ← private key lives here
//   3. Write client.yaml                   (0o600)  ← points at the keystore
//   4. Read the caller's walrus config YAML, inject
//        path: "/tmp/ww_.../client.yaml"
//      into every wallet_config block, and write the modified YAML (0o600)
//   5. Call load_configuration(modified_yaml) + new_contract_client_with_wallet_in_config(None)
//   6. On drop: zero the keystore, then delete the whole directory.
//
// Security:
//   • Non-guessable directory name (time-nanos × golden-ratio + PID + counter).
//   • 0o700 dir / 0o600 files — no group or world access.
//   • Keystore zeroed + fsync'd before deletion to limit page-cache exposure.

static WALLET_COUNTER: AtomicU64 = AtomicU64::new(0);

struct EphemeralWallet {
    /// Modified walrus client_config.yaml — has wallet_config.path injected.
    /// Pass this to load_configuration() for every SDK call in this request.
    pub walrus_config_path: PathBuf,
    /// sui.keystore — overwritten with zeros on drop.
    keystore_path: PathBuf,
    /// Root temp dir — removed on drop after keystore is zeroed.
    dir: PathBuf,
}

impl Drop for EphemeralWallet {
    fn drop(&mut self) {
        // Zero the private-key material before the OS reclaims the inode.
        if let Ok(meta) = std::fs::metadata(&self.keystore_path) {
            let len = meta.len() as usize;
            if len > 0 {
                use std::io::Write as _;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&self.keystore_path)
                {
                    let _ = f.write_all(&vec![0u8; len]);
                    let _ = f.flush();
                    let _ = f.sync_all(); // push past the OS page cache
                }
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Non-guessable 64-bit ID used to name the temp directory.
fn unique_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    let seq = WALLET_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mixed = ns
        .wrapping_mul(0x9e3779b97f4a7c15) // Knuth multiplicative hash
        .wrapping_add(seq)
        .wrapping_add(std::process::id() as u64);
    format!("{:016x}", mixed)
}

/// Read `default_context` from a walrus client_config.yaml and return
/// (context_name, rpc_url). Defaults to testnet on any parse failure.
fn walrus_context(config_path: &str) -> (String, String) {
    let Ok(contents) = std::fs::read_to_string(config_path) else {
        return (
            "testnet".into(),
            "https://fullnode.testnet.sui.io:443".into(),
        );
    };
    let env = contents
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("default_context:")
                .map(|v| v.trim().to_string())
        })
        .unwrap_or_else(|| "testnet".to_string());

    let rpc = match env.as_str() {
        "mainnet" => "https://fullnode.mainnet.sui.io:443".to_string(),
        _ => "https://fullnode.testnet.sui.io:443".to_string(),
    };
    (env, rpc)
}

/// Stamp `sui_wallet_path` into every `wallet_config:` block in the walrus
/// YAML by replacing the standard commented-out placeholder line:
///
///   # path: ~/.sui/sui_config/client.yaml
///
/// with an uncommented `path:` entry pointing at our ephemeral file.
///
/// If the placeholder comment is absent (non-standard YAML), we fall back to
/// inserting the line immediately after every `wallet_config:` heading.
/// Both mainnet and testnet occurrences are updated — only the active context
/// is ever read by the SDK so updating both is harmless.
fn inject_wallet_path(yaml: &str, sui_wallet_path: &Path) -> String {
    const PLACEHOLDER: &str = "# path: ~/.sui/sui_config/client.yaml";

    let replacement = format!("path: \"{}\"", sui_wallet_path.display());

    if yaml.contains(PLACEHOLDER) {
        // Fast path: replace every occurrence of the standard comment.
        return yaml.replace(PLACEHOLDER, &replacement);
    }

    // Fallback: insert after each `wallet_config:` line, preserving indentation.
    yaml.lines()
        .flat_map(|line| -> Vec<String> {
            if line.trim() == "wallet_config:" {
                let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
                vec![line.to_string(), format!("{}  {}", indent, replacement)]
            } else {
                vec![line.to_string()]
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Build an ephemeral Sui wallet from caller-supplied credentials and return
/// a modified walrus config that points at it.
///
/// # Arguments
///
/// * `private_key`   — `base64_std( [0x00] || seed_32_bytes )`.
///                     Go: `base64.StdEncoding.EncodeToString(append([]byte{0x00}, signer.PriKey[:32]...))`
/// * `sui_address`   — `0x…` owner address (e.g. `signer.Address`).
/// * `walrus_config` — path to the original walrus client_config.yaml.
fn build_ephemeral_wallet(
    private_key: &str,
    sui_address: &str,
    walrus_config: &str,
) -> Result<EphemeralWallet> {
    let (active_env, rpc_url) = walrus_context(walrus_config);

    // ── 1. Locked-down temp directory ────────────────────────────────────────
    let dir = std::env::temp_dir().join(format!("ww_{}", unique_id()));

    std::fs::create_dir_all(&dir).context("create ephemeral wallet dir")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .context("restrict ephemeral wallet dir to 0o700")?;
    }

    // ── 2. sui.keystore ───────────────────────────────────────────────────────
    let keystore_path = dir.join("sui.keystore");
    write_restricted_file(&keystore_path, format!(r#"["{}"]"#, private_key).as_bytes())
        .context("write ephemeral keystore")?;

    // ── 3. Sui client.yaml ────────────────────────────────────────────────────
    let sui_wallet_path = dir.join("client.yaml");
    let wallet_yaml = format!(
        "keystore:\n  File: \"{ks}\"\n\
         active_address: \"{addr}\"\n\
         envs:\n  - alias: {env}\n    rpc: \"{rpc}\"\n    ws: null\n    basic_auth: null\n\
         active_env: {env}\n",
        ks = keystore_path.display(),
        addr = sui_address,
        env = active_env,
        rpc = rpc_url,
    );
    write_restricted_file(&sui_wallet_path, wallet_yaml.as_bytes())
        .context("write ephemeral client.yaml")?;

    // ── 4. Modified walrus config (wallet_config.path injected) ──────────────
    // new_contract_client_with_wallet_in_config reads wallet_config.path from
    // the loaded ClientConfig, so we must embed our path there before loading.
    let original_yaml =
        std::fs::read_to_string(walrus_config).context("read original walrus config")?;
    let modified_yaml = inject_wallet_path(&original_yaml, &sui_wallet_path);

    let walrus_config_path = dir.join("walrus_config.yaml");
    write_restricted_file(&walrus_config_path, modified_yaml.as_bytes())
        .context("write modified walrus config")?;

    Ok(EphemeralWallet {
        walrus_config_path,
        keystore_path,
        dir,
    })
}

/// Write bytes to path with owner-only permissions (0o600 on Unix).
fn write_restricted_file(path: &Path, content: &[u8]) -> Result<()> {
    use std::io::Write as _;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(content)?;
        f.flush()?;
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::File::create(path)?;
        f.write_all(content)?;
        f.flush()?;
    }
    Ok(())
}

// ── Store ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ZeroizeOnDrop)]
struct BridgeConfig {
    #[zeroize(skip)]
    walrus_config: String,
    #[zeroize(skip)]
    epochs: u32,
    #[serde(default)]
    #[zeroize(skip)]
    deletable: bool,
    #[serde(default)]
    #[zeroize(skip)]
    metadata: std::collections::HashMap<String, String>, // unchanged from original —
    // NOT Option<...>, bare HashMap
    private_key: String, // sensitive — zeroized on drop, no #[zeroize(skip)]
    #[zeroize(skip)]
    sui_address: String, // public address, not sensitive
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum FfiResult {
    Ok {
        blob_id: String,
        already_certified: bool,
        tx_digest: String,
    },
    Err {
        error: String,
    },
}

async fn store_async(mut config: BridgeConfig, data: Vec<u8>) -> Result<FfiResult> {
    let wallet = build_ephemeral_wallet(
        &config.private_key,
        &config.sui_address,
        &config.walrus_config,
    )?;

    // Load from the modified YAML — wallet_config.path now points at our temp file.
    let client_config = load_configuration(Some(wallet.walrus_config_path.clone()), None)
        .context("load walrus config")?;

    // None = default request timeout. The wallet path is read from the YAML.
    let sui_client = client_config
        .new_contract_client_with_wallet_in_config(None)
        .await
        .context("build sui contract client")?;

    let walrus_client =
        WalrusNodeClient::new_contract_client_with_refresher(client_config, sui_client)
            .await
            .context("build walrus node client")?;

    let persistence = if config.deletable {
        BlobPersistence::Deletable
    } else {
        BlobPersistence::Permanent
    };

    let store_args = StoreArgs::default_with_epochs(config.epochs)
        .with_persistence(persistence)
        .with_tail_handling(TailHandling::Blocking);

    let attribute = BlobAttribute::from(std::mem::take(&mut config.metadata).into_iter());

    let mut results = walrus_client
        .reserve_and_store_blobs_retry_committees(vec![data], vec![attribute], &store_args)
        .await
        .context("reserve_and_store_blobs_retry_committees")?;

    if results.is_empty() {
        anyhow::bail!("reserve_and_store_blobs_retry_committees returned empty results");
    }

    match results.remove(0) {
        BlobStoreResult::NewlyCreated { blob_object, .. } => Ok(FfiResult::Ok {
            blob_id: URL_SAFE_NO_PAD.encode(blob_object.blob_id.as_ref()),
            already_certified: false,
            tx_digest: blob_object.id.to_string(),
        }),
        BlobStoreResult::AlreadyCertified { blob_id, .. } => Ok(FfiResult::Ok {
            blob_id: URL_SAFE_NO_PAD.encode(blob_id.as_ref()),
            already_certified: true,
            tx_digest: String::new(),
        }),
        BlobStoreResult::MarkedInvalid { blob_id, .. } => Ok(FfiResult::Err {
            error: format!(
                "blob {} marked invalid",
                URL_SAFE_NO_PAD.encode(blob_id.as_ref())
            ),
        }),
        BlobStoreResult::Error { error_msg, .. } => Ok(FfiResult::Err { error: error_msg }),
    }
}

/// Store a blob on Walrus (encode → register → upload → certify).
///
/// config_json: {
///   "walrus_config": "/path/to/client_config.yaml",
///   "epochs": 5,
///   "deletable": false,
///   "metadata": {"key":"value"},
///   "private_key": "<base64_std([0x00] || seed_32_bytes)>",
///   "sui_address": "0x…"
/// }
///
/// Returns JSON: {"blob_id":"…","already_certified":bool,"tx_digest":"…"}
///           or: {"error":"…"}
/// MUST be freed with walrus_free_string().
#[no_mangle]
pub extern "C" fn walrus_store_blob(
    config_json: *const c_char,
    data_ptr: *const c_uchar,
    data_len: usize,
) -> *mut c_char {
    let config_str = unsafe {
        match CStr::from_ptr(config_json).to_str() {
            Ok(s) => s,
            Err(e) => return err_ptr(format!("invalid config UTF-8: {e}")),
        }
    };
    let config: BridgeConfig = match serde_json::from_str(config_str) {
        Ok(c) => c,
        Err(e) => return err_ptr(format!("config parse error: {e}")),
    };

    if data_ptr.is_null() && data_len > 0 {
        return err_ptr("data_ptr is NULL but data_len > 0".to_string());
    }
    let data = if data_len == 0 {
        Vec::new()
    } else {
        unsafe { slice::from_raw_parts(data_ptr, data_len) }.to_vec()
    };

    let result = match block_on(store_async(config, data)) {
        Ok(r) => r,
        Err(e) => FfiResult::Err {
            error: format!("{e:#}"),
        },
    };

    let json = serde_json::to_string(&result)
        .unwrap_or_else(|_| r#"{"error":"serialise failed"}"#.to_string());
    CString::new(json)
        .unwrap_or_else(|_| CString::new(r#"{"error":"response contained null byte"}"#).unwrap())
        .into_raw()
}

// ── Store — Storage Pool variant ─────────────────────────────────────────────
//
// IMPORTANT — read before wiring up retries on the Go side.
//
// reserve_and_store_blobs_in_storage_pool does register + upload + certify
// as one sequenced call, same as reserve_and_store_blobs_retry_committees
// above — so it doesn't have the register-then-separately-upload race that
// splitting across two processes would introduce. Good.
//
// But unlike the owned-blob path, it is NOT safe to retry this call as a
// black box on failure. register_pooled_blob (the underlying Move call)
// creates a brand-new PooledBlob object in the pool every time it's called —
// there is no on-chain check for "does this pool already have an entry for
// this blob_id" the way there is for the classic Storage/Blob model. Notice
// PooledBlobStoreResult below only has two variants — NewlyCreated and
// Error — there is no AlreadyCertified/reuse case at all. If a first attempt
// registers successfully but then fails during upload or certify (network
// blip, node timeout, process killed), and Go retries this whole call, you
// get a second PooledBlob for the same content sitting in the pool, burning
// extra capacity and WAL.
//
// PooledBlobStoreResult::Error carries a `failure_phase` string precisely so
// callers can tell these cases apart — inspect it before deciding whether a
// retry is safe. Treat anything that isn't clearly "failed before
// registration" as NOT safely retryable without first checking, out-of-band,
// whether a PooledBlob for this blob_id already exists in the pool (fetch by
// id if you tracked one, or list the pool's contents). Do not wire an
// automatic backoff retry loop around walrus_store_blob_in_pool the way you
// might around walrus_store_blob until that check is in place.

#[derive(Debug, Deserialize, ZeroizeOnDrop)]
struct PoolBridgeConfig {
    #[zeroize(skip)]
    walrus_config: String,
    #[zeroize(skip)]
    epochs: u32,
    #[serde(default)]
    #[zeroize(skip)]
    deletable: bool,
    #[zeroize(skip)]
    storage_pool_object_id: String,
    private_key: String, // sensitive — zeroized on drop
    #[zeroize(skip)]
    sui_address: String,
}

async fn store_in_pool_async(config: PoolBridgeConfig, data: Vec<u8>) -> Result<FfiResult> {
    let wallet = build_ephemeral_wallet(
        &config.private_key,
        &config.sui_address,
        &config.walrus_config,
    )?;

    let client_config = load_configuration(Some(wallet.walrus_config_path.clone()), None)
        .context("load walrus config")?;

    let sui_client = client_config
        .new_contract_client_with_wallet_in_config(None)
        .await
        .context("build sui contract client")?;

    let walrus_client =
        WalrusNodeClient::new_contract_client_with_refresher(client_config, sui_client)
            .await
            .context("build walrus node client")?;

    let storage_pool_object_id: ObjectID = config
        .storage_pool_object_id
        .parse()
        .context("parse storage_pool_object_id")?;

    let persistence = if config.deletable {
        BlobPersistence::Deletable
    } else {
        BlobPersistence::Permanent
    };

    let store_args = StoreArgs::default_with_epochs(config.epochs).with_persistence(persistence);
    // Note: no .with_tail_handling(TailHandling::Blocking) override here —
    // check whether the pooled path needs it explicitly or already defaults
    // to blocking; the owned path above sets it explicitly so mirror that if
    // reserve_and_store_blobs_in_storage_pool doesn't behave the same way by
    // default.

    let mut results = walrus_client
        .reserve_and_store_blobs_in_storage_pool(vec![data], storage_pool_object_id, &store_args)
        .await
        .context("reserve_and_store_blobs_in_storage_pool")?;

    if results.is_empty() {
        anyhow::bail!("reserve_and_store_blobs_in_storage_pool returned empty results");
    }

    match results.remove(0) {
        PooledBlobStoreResult::NewlyCreated { pooled_blob_object } => Ok(FfiResult::Ok {
            blob_id: URL_SAFE_NO_PAD.encode(pooled_blob_object.blob_id.as_ref()),
            already_certified: false,
            tx_digest: pooled_blob_object.id.to_string(),
        }),
        PooledBlobStoreResult::Error {
            blob_id,
            failure_phase,
            error_msg,
        } => Ok(FfiResult::Err {
            error: format!(
                "storage-pool store failed in phase '{failure_phase}'{}: {error_msg}",
                blob_id
                    .map(|id| format!(" (blob_id {})", URL_SAFE_NO_PAD.encode(id.as_ref())))
                    .unwrap_or_default()
            ),
        }),
    }
}

/// Store a blob into a specific storage pool (encode → register-in-pool →
/// upload → certify), instead of the caller's own owned Storage.
///
/// config_json: {
///   "walrus_config":          "/path/to/client_config.yaml",
///   "epochs":                 5,
///   "deletable":              false,
///   "storage_pool_object_id": "0x…",
///   "private_key":            "<base64_std([0x00] || seed_32_bytes)>",
///   "sui_address":            "0x…"
/// }
///
/// Returns JSON: {"blob_id":"…","already_certified":false,"tx_digest":"…"}
///           or: {"error":"…"}
///
/// See the module comment above this function before adding any retry logic
/// around this call — it is NOT safely idempotent to retry blindly.
/// MUST be freed with walrus_free_string().
#[no_mangle]
pub extern "C" fn walrus_store_blob_in_pool(
    config_json: *const c_char,
    data_ptr: *const c_uchar,
    data_len: usize,
) -> *mut c_char {
    let config_str = unsafe {
        match CStr::from_ptr(config_json).to_str() {
            Ok(s) => s,
            Err(e) => return err_ptr(format!("invalid config UTF-8: {e}")),
        }
    };
    let config: PoolBridgeConfig = match serde_json::from_str(config_str) {
        Ok(c) => c,
        Err(e) => return err_ptr(format!("config parse error: {e}")),
    };

    if data_ptr.is_null() && data_len > 0 {
        return err_ptr("data_ptr is NULL but data_len > 0".to_string());
    }
    let data = if data_len == 0 {
        Vec::new()
    } else {
        unsafe { slice::from_raw_parts(data_ptr, data_len) }.to_vec()
    };

    let result = match block_on(store_in_pool_async(config, data)) {
        Ok(r) => r,
        Err(e) => FfiResult::Err {
            error: format!("{e:#}"),
        },
    };

    let json = serde_json::to_string(&result)
        .unwrap_or_else(|_| r#"{"error":"serialise failed"}"#.to_string());
    CString::new(json)
        .unwrap_or_else(|_| CString::new(r#"{"error":"response contained null byte"}"#).unwrap())
        .into_raw()
}

#[no_mangle]
pub extern "C" fn walrus_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

fn err_ptr(msg: String) -> *mut c_char {
    let json = format!(
        r#"{{"error":{}}}"#,
        serde_json::to_string(&msg).unwrap_or_default()
    );
    CString::new(json)
        .unwrap_or_else(|_| CString::new(r#"{"error":"internal error"}"#).unwrap())
        .into_raw()
}

// ── Read ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ZeroizeOnDrop)]
struct ReadConfig {
    #[zeroize(skip)]
    walrus_config: String,
    #[zeroize(skip)]
    blob_id: String,
    private_key: String,
    #[zeroize(skip)]
    sui_address: String,
}

/// Heap-allocated byte buffer returned by walrus_read_blob.
///
/// On success: ptr/len hold the blob data, err is NULL.
/// On failure: ptr is NULL, len is 0, err points to {"error":"…"}.
///
/// walrus_free_bytes() MUST be called in both cases.
#[repr(C)]
pub struct WalrusBytes {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
    pub err: *mut c_char,
}

unsafe impl Send for WalrusBytes {}

async fn read_async(config: ReadConfig) -> Result<Vec<u8>> {
    use walrus_core::BlobId;
    use walrus_sdk::core::encoding::Primary;

    let wallet = build_ephemeral_wallet(
        &config.private_key,
        &config.sui_address,
        &config.walrus_config,
    )?;

    let client_config = load_configuration(Some(wallet.walrus_config_path.clone()), None)
        .context("load walrus config")?;

    let sui_client = client_config
        .new_contract_client_with_wallet_in_config(None)
        .await
        .context("build sui client")?;

    let walrus_client =
        WalrusNodeClient::new_contract_client_with_refresher(client_config, sui_client)
            .await
            .context("build walrus client")?;

    let blob_id: BlobId = config.blob_id.parse().context("parse blob id")?;

    walrus_client
        .read_blob::<Primary>(&blob_id)
        .await
        .context("read_blob failed")
}

/// Read a blob from Walrus by blob ID.
///
/// config_json: {
///   "walrus_config": "/path/to/client_config.yaml",
///   "blob_id": "<base64url>",
///   "private_key": "<base64_std([0x00] || seed_32_bytes)>",
///   "sui_address": "0x…"
/// }
///
/// Always returns a non-NULL WalrusBytes*. Check wb->err before using wb->ptr.
/// MUST be freed with walrus_free_bytes() in all cases.
#[no_mangle]
pub extern "C" fn walrus_read_blob(config_json: *const c_char) -> *mut WalrusBytes {
    fn err_bytes(msg: String) -> *mut WalrusBytes {
        let json = format!(
            r#"{{"error":{}}}"#,
            serde_json::to_string(&msg).unwrap_or_default()
        );
        let err = CString::new(json)
            .unwrap_or_else(|_| CString::new(r#"{"error":"internal error"}"#).unwrap())
            .into_raw();
        Box::into_raw(Box::new(WalrusBytes {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
            err,
        }))
    }

    let config_str = unsafe {
        match CStr::from_ptr(config_json).to_str() {
            Ok(s) => s,
            Err(e) => return err_bytes(format!("invalid config UTF-8: {e}")),
        }
    };
    let config: ReadConfig = match serde_json::from_str(config_str) {
        Ok(c) => c,
        Err(e) => return err_bytes(format!("config parse error: {e}")),
    };

    match block_on(read_async(config)) {
        Ok(mut data) => {
            data.shrink_to_fit();
            let len = data.len();
            let cap = data.capacity();
            let ptr = data.as_mut_ptr();
            std::mem::forget(data);
            Box::into_raw(Box::new(WalrusBytes {
                ptr,
                len,
                cap,
                err: std::ptr::null_mut(),
            }))
        }
        Err(e) => err_bytes(format!("{e:#}")),
    }
}

/// Free a WalrusBytes returned by walrus_read_blob.
/// Safe to call in both success and error cases.
/// Do NOT free wb->err separately — this function handles it.
#[no_mangle]
pub extern "C" fn walrus_free_bytes(wb: *mut WalrusBytes) {
    if wb.is_null() {
        return;
    }
    unsafe {
        let wb = Box::from_raw(wb);
        if !wb.ptr.is_null() && wb.cap > 0 {
            let _ = Vec::from_raw_parts(wb.ptr, wb.len, wb.cap);
        }
        if !wb.err.is_null() {
            let _ = CString::from_raw(wb.err);
        }
    }
}

// ── Delete ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ZeroizeOnDrop)]
struct DeleteConfig {
    #[zeroize(skip)]
    walrus_config: String,
    #[zeroize(skip)]
    blob_id: Option<String>,
    #[zeroize(skip)]
    blob_object_id: Option<String>,
    private_key: String,
    #[zeroize(skip)]
    sui_address: String,
}
async fn delete_async(mut config: DeleteConfig) -> Result<u64> {
    use walrus_core::BlobId;

    let wallet = build_ephemeral_wallet(
        &config.private_key,
        &config.sui_address,
        &config.walrus_config,
    )?;

    let client_config = load_configuration(Some(wallet.walrus_config_path.clone()), None)
        .context("load walrus config")?;

    let sui_client = client_config
        .new_contract_client_with_wallet_in_config(None)
        .await
        .context("build sui client")?;

    let walrus_client =
        WalrusNodeClient::new_contract_client_with_refresher(client_config, sui_client)
            .await
            .context("build walrus client")?;

    if let Some(blob_id_str) = std::mem::take(&mut config.blob_id) {
        let blob_id: BlobId = blob_id_str.parse().context("parse blob_id")?;
        let deleted = walrus_client
            .delete_owned_blob(&blob_id)
            .await
            .context("delete_owned_blob")?;
        anyhow::ensure!(deleted > 0, "no deletable blobs found with that blob ID");
        Ok(u64::try_from(deleted).context("deleted count overflows u64")?)
    } else if let Some(obj_id_str) = std::mem::take(&mut config.blob_id) {
        let obj_id: ObjectID = obj_id_str.parse().context("parse blob_object_id")?;
        walrus_client
            .delete_owned_blob_by_object(obj_id)
            .await
            .context("delete_owned_blob_by_object")?;
        Ok(1)
    } else {
        anyhow::bail!("must provide either blob_id or blob_object_id")
    }
}

/// Delete a deletable blob from Walrus.
///
/// config_json: {
///   "walrus_config": "…",
///   "blob_id": "<base64url>",      ← supply one of these two
///   "blob_object_id": "0x…",       ←
///   "private_key": "<base64_std([0x00] || seed_32_bytes)>",
///   "sui_address": "0x…"
/// }
///
/// Returns JSON: {"deleted":N} or {"error":"…"}
/// MUST be freed with walrus_free_string().
#[no_mangle]
pub extern "C" fn walrus_delete_blob(config_json: *const c_char) -> *mut c_char {
    let config_str = unsafe {
        match CStr::from_ptr(config_json).to_str() {
            Ok(s) => s,
            Err(e) => return err_ptr(format!("invalid UTF-8: {e}")),
        }
    };
    let config: DeleteConfig = match serde_json::from_str(config_str) {
        Ok(c) => c,
        Err(e) => return err_ptr(format!("config parse error: {e}")),
    };

    let result = match block_on(delete_async(config)) {
        Ok(n) => format!(r#"{{"deleted":{n}}}"#),
        Err(e) => return err_ptr(format!("{e:#}")),
    };

    CString::new(result)
        .unwrap_or_else(|_| CString::new(r#"{"error":"internal error"}"#).unwrap())
        .into_raw()
}

// ── Extend ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ZeroizeOnDrop)]
struct ExtendConfig {
    #[zeroize(skip)]
    walrus_config: String,
    #[zeroize(skip)]
    blob_object_id: String,
    #[zeroize(skip)]
    epochs: u32,
    private_key: String,
    #[zeroize(skip)]
    sui_address: String,
}
async fn extend_async(config: ExtendConfig) -> Result<()> {
    let wallet = build_ephemeral_wallet(
        &config.private_key,
        &config.sui_address,
        &config.walrus_config,
    )?;

    let client_config = load_configuration(Some(wallet.walrus_config_path.clone()), None)
        .context("load walrus config")?;

    let sui_client = client_config
        .new_contract_client_with_wallet_in_config(None)
        .await
        .context("build sui client")?;

    let walrus_client =
        WalrusNodeClient::new_contract_client_with_refresher(client_config, sui_client)
            .await
            .context("build walrus client")?;

    let obj_id: ObjectID = config
        .blob_object_id
        .parse()
        .context("parse blob_object_id")?;

    walrus_client
        .sui_client()
        .extend_blob(obj_id, config.epochs)
        .await
        .context("extend_blob")
}

/// Extend a blob's storage duration by additional epochs.
///
/// config_json: {
///   "walrus_config": "…",
///   "blob_object_id": "0x…",
///   "epochs": 5,
///   "private_key": "<base64_std([0x00] || seed_32_bytes)>",
///   "sui_address": "0x…"
/// }
///
/// Returns JSON: {"success":true} or {"error":"…"}
/// MUST be freed with walrus_free_string().
#[no_mangle]
pub extern "C" fn walrus_extend_blob(config_json: *const c_char) -> *mut c_char {
    let config_str = unsafe {
        match CStr::from_ptr(config_json).to_str() {
            Ok(s) => s,
            Err(e) => return err_ptr(format!("invalid UTF-8: {e}")),
        }
    };
    let config: ExtendConfig = match serde_json::from_str(config_str) {
        Ok(c) => c,
        Err(e) => return err_ptr(format!("config parse error: {e}")),
    };

    match block_on(extend_async(config)) {
        Ok(()) => CString::new(r#"{"success":true}"#)
            .unwrap_or_else(|_| CString::new(r#"{"error":"internal error"}"#).unwrap())
            .into_raw(),
        Err(e) => err_ptr(format!("{e:#}")),
    }
}

// ── List blobs ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ZeroizeOnDrop)]
struct ListConfig {
    #[zeroize(skip)]
    walrus_config: String,
    #[serde(default = "default_expiry_policy")]
    #[zeroize(skip)]
    expiry_policy: String,
    private_key: String,
    #[zeroize(skip)]
    sui_address: String,
}
fn default_expiry_policy() -> String {
    "valid".to_string()
}

#[derive(Debug, Serialize)]
struct BlobInfo {
    object_id: String,
    blob_id: String,
    size: u64,
    encoding_type: u8,
    registered_epoch: u64,
    certified_epoch: Option<u64>,
    end_epoch: u64,
    deletable: bool,
}

async fn list_async(config: ListConfig) -> Result<Vec<BlobInfo>> {
    use walrus_sui::client::ExpirySelectionPolicy;

    let wallet = build_ephemeral_wallet(
        &config.private_key,
        &config.sui_address,
        &config.walrus_config,
    )?;

    let client_config = load_configuration(Some(wallet.walrus_config_path.clone()), None)
        .context("load walrus config")?;

    let sui_client = client_config
        .new_contract_client_with_wallet_in_config(None)
        .await
        .context("build sui client")?;

    let walrus_client =
        WalrusNodeClient::new_contract_client_with_refresher(client_config, sui_client)
            .await
            .context("build walrus client")?;

    let policy = match config.expiry_policy.to_lowercase().as_str() {
        "expired" => ExpirySelectionPolicy::Expired,
        "all" => ExpirySelectionPolicy::All,
        _ => ExpirySelectionPolicy::Valid,
    };

    let blobs = walrus_client
        .sui_client()
        .owned_blobs(None, policy)
        .await
        .context("owned_blobs")?;

    Ok(blobs
        .into_iter()
        .map(|b| BlobInfo {
            object_id: b.id.to_string(),
            blob_id: URL_SAFE_NO_PAD.encode(b.blob_id.as_ref()),
            size: b.size,
            encoding_type: u8::from(b.encoding_type),
            registered_epoch: b.registered_epoch as u64,
            certified_epoch: b.certified_epoch.map(|e| e as u64),
            end_epoch: b.storage.end_epoch as u64,
            deletable: b.deletable,
        })
        .collect())
}

/// List blobs owned by the wallet.
///
/// config_json: {
///   "walrus_config": "…",
///   "expiry_policy": "valid",   ← "valid" | "expired" | "all"
///   "private_key": "<base64_std([0x00] || seed_32_bytes)>",
///   "sui_address": "0x…"
/// }
///
/// Returns JSON: {"blobs":[{"object_id":"0x…","blob_id":"…","size":N,...},...]}
///           or: {"error":"…"}
/// MUST be freed with walrus_free_string().
#[no_mangle]
pub extern "C" fn walrus_list_blobs(config_json: *const c_char) -> *mut c_char {
    let config_str = unsafe {
        match CStr::from_ptr(config_json).to_str() {
            Ok(s) => s,
            Err(e) => return err_ptr(format!("invalid UTF-8: {e}")),
        }
    };
    let config: ListConfig = match serde_json::from_str(config_str) {
        Ok(c) => c,
        Err(e) => return err_ptr(format!("config parse error: {e}")),
    };

    match block_on(list_async(config)) {
        Ok(blobs) => {
            let json = serde_json::json!({ "blobs": blobs }).to_string();
            CString::new(json)
                .unwrap_or_else(|_| {
                    CString::new(r#"{"error":"response contained null byte"}"#).unwrap()
                })
                .into_raw()
        }
        Err(e) => err_ptr(format!("{e:#}")),
    }
}

// ── Batch Read ────────────────────────────────────────────────────────────────
//
// walrus_read_blobs builds the Sui/Walrus client ONCE and reads every blob
// concurrently on the shared Tokio runtime, returning one WalrusBytesArray
// whose items slot mirrors WalrusBytes (ptr+len on success, err on failure).
//
// NOTE: tokio::task::JoinSet::spawn requires WalrusNodeClient: Send.
// walrus-sdk async types are Send, but if you see a compile error here you
// can replace the JoinSet block with a sequential loop over .await — you still
// save the N-1 client builds.

#[repr(C)]
pub struct WalrusBytesArray {
    /// Heap-allocated array of `count` WalrusBytes (one per input blob_id).
    pub items: *mut WalrusBytes,
    pub count: usize,
    /// Non-NULL only when setup fails before any read (config parse, client
    /// build, …).  Per-blob errors live in items[i].err instead.
    pub err: *mut c_char,
}

unsafe impl Send for WalrusBytesArray {}

#[derive(Debug, Deserialize, ZeroizeOnDrop)]
struct BatchReadConfig {
    #[zeroize(skip)]
    walrus_config: String,
    #[zeroize(skip)]
    blob_ids: Vec<String>,
    private_key: String,
    #[zeroize(skip)]
    sui_address: String,
}
/// Reads every blob in `config.blob_ids` concurrently, sharing one client.
/// Returns a Vec in the same order as the input.
async fn read_blobs_async(mut config: BatchReadConfig) -> Result<Vec<Result<Vec<u8>>>> {
    use walrus_core::BlobId;
    use walrus_sdk::core::encoding::Primary;

    let wallet = build_ephemeral_wallet(
        &config.private_key,
        &config.sui_address,
        &config.walrus_config,
    )?;
    let client_config = load_configuration(Some(wallet.walrus_config_path.clone()), None)
        .context("load walrus config")?;
    let sui_client = client_config
        .new_contract_client_with_wallet_in_config(None)
        .await
        .context("build sui client")?;
    let walrus_client = Arc::new(
        WalrusNodeClient::new_contract_client_with_refresher(client_config, sui_client)
            .await
            .context("build walrus client")?,
    );

    let n = config.blob_ids.len();

    // Spawn one task per blob; preserve input order via index tag.
    let mut set: tokio::task::JoinSet<(usize, Result<Vec<u8>>)> = tokio::task::JoinSet::new();

    for (i, id_str) in std::mem::take(&mut config.blob_ids).into_iter().enumerate() {
        let client = Arc::clone(&walrus_client);
        set.spawn(async move {
            let result = async {
                let blob_id: BlobId = id_str.parse().context("parse blob_id")?;
                client
                    .read_blob::<Primary>(&blob_id)
                    .await
                    .context("read_blob")
            }
            .await;
            (i, result)
        });
    }

    // Collect into a pre-sized Vec; default to an error in the unlikely event
    // a task is never returned (should not happen with JoinSet).
    let mut ordered: Vec<Result<Vec<u8>>> = (0..n)
        .map(|_| Err(anyhow::anyhow!("task did not complete")))
        .collect();

    while let Some(join_result) = set.join_next().await {
        match join_result {
            Ok((i, r)) => ordered[i] = r,
            Err(e) => {
                // Task panicked — leave the slot as its default error.
                eprintln!("walrus_read_blobs: task panicked: {e}");
            }
        }
    }

    Ok(ordered)
}

/// Builds a top-level-error WalrusBytesArray (items == NULL, err set).
fn make_bytes_array_error(msg: String) -> *mut WalrusBytesArray {
    let json = format!(
        r#"{{"error":{}}}"#,
        serde_json::to_string(&msg).unwrap_or_default()
    );
    let err = CString::new(json)
        .unwrap_or_else(|_| CString::new(r#"{"error":"internal error"}"#).unwrap())
        .into_raw();
    Box::into_raw(Box::new(WalrusBytesArray {
        items: std::ptr::null_mut(),
        count: 0,
        err,
    }))
}

/// Read multiple blobs from Walrus in one call.
///
/// config_json: {
///   "walrus_config": "/path/to/client_config.yaml",
///   "blob_ids":      ["<base64url>", …],
///   "private_key":   "<base64_std([0x00] || seed_32_bytes)>",
///   "sui_address":   "0x…"
/// }
///
/// Always returns a non-NULL WalrusBytesArray*:
///   wba->err != NULL  → setup failure; no reads were attempted.
///   wba->err == NULL  → reads ran; check each wba->items[i].err individually.
///
/// MUST be freed with walrus_free_bytes_array() in all cases.
#[no_mangle]
pub extern "C" fn walrus_read_blobs(config_json: *const c_char) -> *mut WalrusBytesArray {
    let config_str = unsafe {
        match CStr::from_ptr(config_json).to_str() {
            Ok(s) => s,
            Err(e) => return make_bytes_array_error(format!("invalid UTF-8: {e}")),
        }
    };
    let config: BatchReadConfig = match serde_json::from_str(config_str) {
        Ok(c) => c,
        Err(e) => return make_bytes_array_error(format!("config parse error: {e}")),
    };

    let per_blob = match block_on(read_blobs_async(config)) {
        Ok(v) => v,
        Err(e) => return make_bytes_array_error(format!("{e:#}")),
    };

    // Convert each per-blob Result<Vec<u8>> into a WalrusBytes.
    let mut items: Vec<WalrusBytes> = per_blob
        .into_iter()
        .map(|r| match r {
            Ok(mut data) => {
                data.shrink_to_fit();
                let len = data.len();
                let cap = data.capacity();
                let ptr = data.as_mut_ptr();
                std::mem::forget(data);
                WalrusBytes {
                    ptr,
                    len,
                    cap,
                    err: std::ptr::null_mut(),
                }
            }
            Err(e) => {
                let msg = format!("{e:#}");
                let json = format!(
                    r#"{{"error":{}}}"#,
                    serde_json::to_string(&msg).unwrap_or_default()
                );
                let err = CString::new(json)
                    .unwrap_or_else(|_| CString::new(r#"{"error":"internal"}"#).unwrap())
                    .into_raw();
                WalrusBytes {
                    ptr: std::ptr::null_mut(),
                    len: 0,
                    cap: 0,
                    err,
                }
            }
        })
        .collect();

    items.shrink_to_fit();
    let count = items.len();
    let items_ptr = items.as_mut_ptr();
    std::mem::forget(items); // ownership transferred to caller via raw pointer

    Box::into_raw(Box::new(WalrusBytesArray {
        items: items_ptr,
        count,
        err: std::ptr::null_mut(),
    }))
}

/// Free a WalrusBytesArray returned by walrus_read_blobs.
/// Frees all per-blob data buffers, per-blob error strings, and the items
/// array itself before freeing the struct.
#[no_mangle]
pub extern "C" fn walrus_free_bytes_array(wba: *mut WalrusBytesArray) {
    if wba.is_null() {
        return;
    }
    unsafe {
        let wba = Box::from_raw(wba);
        // Free top-level error string if present.
        if !wba.err.is_null() {
            let _ = CString::from_raw(wba.err);
        }
        // Free each item's data buffer and error string, then the items array.
        if !wba.items.is_null() && wba.count > 0 {
            let items = Vec::from_raw_parts(wba.items, wba.count, wba.count);
            for item in items {
                if !item.ptr.is_null() && item.cap > 0 {
                    let _ = Vec::from_raw_parts(item.ptr, item.len, item.cap);
                }
                if !item.err.is_null() {
                    let _ = CString::from_raw(item.err);
                }
            }
        }
    }
}

// ── Batch Delete ──────────────────────────────────────────────────────────────
//
// walrus_delete_blobs builds the Sui/Walrus client ONCE and iterates over the
// blob IDs sequentially.  Sui transactions from the same key must be submitted
// one at a time (sequence-number ordering), so parallelism is not safe here.
// The single client build is still a significant saving over N separate calls.

#[derive(Debug, Deserialize, ZeroizeOnDrop)]
struct BatchDeleteConfig {
    #[zeroize(skip)]
    walrus_config: String,
    #[zeroize(skip)]
    blob_ids: Vec<String>,
    private_key: String,
    #[zeroize(skip)]
    sui_address: String,
}

#[derive(Debug, Serialize)]
struct BatchDeleteBlobResult {
    blob_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    deleted: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn delete_blobs_async(mut config: BatchDeleteConfig) -> Result<Vec<BatchDeleteBlobResult>> {
    use walrus_core::BlobId;

    let wallet = build_ephemeral_wallet(
        &config.private_key,
        &config.sui_address,
        &config.walrus_config,
    )?;
    let client_config = load_configuration(Some(wallet.walrus_config_path.clone()), None)
        .context("load walrus config")?;
    let sui_client = client_config
        .new_contract_client_with_wallet_in_config(None)
        .await
        .context("build sui client")?;
    let walrus_client =
        WalrusNodeClient::new_contract_client_with_refresher(client_config, sui_client)
            .await
            .context("build walrus client")?;

    let mut results = Vec::with_capacity(config.blob_ids.len());
    for id_str in std::mem::take(&mut config.blob_ids) {
        let outcome: Result<u64> = async {
            let blob_id: BlobId = id_str.parse().context("parse blob_id")?;
            let deleted = walrus_client
                .delete_owned_blob(&blob_id)
                .await
                .context("delete_owned_blob")?;
            anyhow::ensure!(deleted > 0, "no deletable blobs found with that blob ID");
            u64::try_from(deleted).context("deleted count overflows u64")
        }
        .await;

        results.push(match outcome {
            Ok(n) => BatchDeleteBlobResult {
                blob_id: id_str,
                deleted: Some(n),
                error: None,
            },
            Err(e) => BatchDeleteBlobResult {
                blob_id: id_str,
                deleted: None,
                error: Some(format!("{e:#}")),
            },
        });
    }
    Ok(results)
}

/// Delete multiple deletable blobs in one call.
///
/// config_json: {
///   "walrus_config": "…",
///   "blob_ids":      ["<base64url>", …],
///   "private_key":   "<base64_std([0x00] || seed_32_bytes)>",
///   "sui_address":   "0x…"
/// }
///
/// Returns JSON:
///   success: {"results":[{"blob_id":"…","deleted":N}, {"blob_id":"…","error":"…"}, …]}
///   setup failure: {"error":"…"}
///
/// Per-blob failures are reported inside the results array and do NOT abort
/// the remaining deletions.  MUST be freed with walrus_free_string().
#[no_mangle]
pub extern "C" fn walrus_delete_blobs(config_json: *const c_char) -> *mut c_char {
    let config_str = unsafe {
        match CStr::from_ptr(config_json).to_str() {
            Ok(s) => s,
            Err(e) => return err_ptr(format!("invalid UTF-8: {e}")),
        }
    };
    let config: BatchDeleteConfig = match serde_json::from_str(config_str) {
        Ok(c) => c,
        Err(e) => return err_ptr(format!("config parse error: {e}")),
    };

    match block_on(delete_blobs_async(config)) {
        Ok(results) => {
            let json = serde_json::json!({ "results": results }).to_string();
            CString::new(json)
                .unwrap_or_else(|_| {
                    CString::new(r#"{"error":"response contained null byte"}"#).unwrap()
                })
                .into_raw()
        }
        Err(e) => err_ptr(format!("{e:#}")),
    }
}

// ── Burn Expired ──────────────────────────────────────────────────────────────
//
// walrus_burn_expired_blobs lists every Walrus Blob object owned by the wallet
// whose storage epoch has already elapsed, then burns them all.  burn_blobs on
// the SuiContractClient already handles batching internally (≤1000 burns per
// Programmable Transaction Block), so a single call here handles any number of
// expired objects.

#[derive(Debug, Deserialize, ZeroizeOnDrop)]
struct BurnExpiredConfig {
    #[zeroize(skip)]
    walrus_config: String,
    private_key: String,
    #[zeroize(skip)]
    sui_address: String,
}

async fn burn_expired_async(config: BurnExpiredConfig) -> Result<u64> {
    use walrus_sui::client::ExpirySelectionPolicy;
    let wallet = build_ephemeral_wallet(
        &config.private_key,
        &config.sui_address,
        &config.walrus_config,
    )?;
    let client_config = load_configuration(Some(wallet.walrus_config_path.clone()), None)
        .context("load walrus config")?;
    let sui_client_raw = client_config
        .new_contract_client_with_wallet_in_config(None)
        .await
        .context("build sui client")?;
    let walrus_client =
        WalrusNodeClient::new_contract_client_with_refresher(client_config, sui_client_raw)
            .await
            .context("build walrus client")?;

    let sui = walrus_client.sui_client();

    // Fetch only blobs whose storage epoch has elapsed.
    let expired = sui
        .owned_blobs(None, ExpirySelectionPolicy::Expired)
        .await
        .context("list expired blobs")?;

    let obj_ids: Vec<ObjectID> = expired.into_iter().map(|b| b.id).collect();

    if obj_ids.is_empty() {
        return Ok(0);
    }

    let count = u64::try_from(obj_ids.len()).context("object count overflows u64")?;

    // burn_blobs sends ≤1000 burns per PTB, so one call handles any number.
    sui.burn_blobs(&obj_ids).await.context("burn_blobs")?;

    Ok(count)
}

/// List all expired Walrus blob objects owned by the wallet and burn them.
///
/// config_json – UTF-8 JSON:
///   {
///     "walrus_config": "/path/to/client_config.yaml",
///     "private_key":   "<base64_std([0x00] || seed_32_bytes)>",
///     "sui_address":   "0x…"
///   }
///
/// Returns JSON:
///   success: {"burned":N}   (N == 0 means no expired blobs were found)
///   failure: {"error":"…"}
///
/// MUST be freed with walrus_free_string().
#[no_mangle]
pub extern "C" fn walrus_burn_expired_blobs(config_json: *const c_char) -> *mut c_char {
    let config_str = unsafe {
        match CStr::from_ptr(config_json).to_str() {
            Ok(s) => s,
            Err(e) => return err_ptr(format!("invalid UTF-8: {e}")),
        }
    };
    let config: BurnExpiredConfig = match serde_json::from_str(config_str) {
        Ok(c) => c,
        Err(e) => return err_ptr(format!("config parse error: {e}")),
    };

    match block_on(burn_expired_async(config)) {
        Ok(n) => {
            let json = serde_json::json!({ "burned": n }).to_string();
            CString::new(json)
                .unwrap_or_else(|_| CString::new(r#"{"error":"internal error"}"#).unwrap())
                .into_raw()
        }
        Err(e) => err_ptr(format!("{e:#}")),
    }
}

// ── Storage Pool Admin ────────────────────────────────────────────────────────
//
// create_storage_pool / extend_storage_pool / increase_storage_pool_capacity
// are plain SuiContractClient methods — each is a single, self-contained
// transaction with no multi-step register/upload/certify sequencing, so
// unlike walrus_store_blob_in_pool these ARE safe to retry with backoff on
// failure: a failed create/extend/increase-capacity call either didn't land
// (safe to retry) or landed and you'll see the effect next time you check
// storage_pool_status — there's no "partially succeeded, now duplicated"
// state possible the way there is for pooled blob registration.

#[derive(Debug, Deserialize, ZeroizeOnDrop)]
struct CreatePoolConfig {
    #[zeroize(skip)]
    walrus_config: String,
    #[zeroize(skip)]
    reserved_encoded_capacity_bytes: u64,
    #[zeroize(skip)]
    epochs_ahead: u32,
    private_key: String,
    #[zeroize(skip)]
    sui_address: String,
}

async fn create_storage_pool_async(config: CreatePoolConfig) -> Result<ObjectID> {
    let wallet = build_ephemeral_wallet(
        &config.private_key,
        &config.sui_address,
        &config.walrus_config,
    )?;
    let client_config = load_configuration(Some(wallet.walrus_config_path.clone()), None)
        .context("load walrus config")?;
    let sui_client = client_config
        .new_contract_client_with_wallet_in_config(None)
        .await
        .context("build sui contract client")?;

    sui_client
        .create_storage_pool(config.reserved_encoded_capacity_bytes, config.epochs_ahead)
        .await
        .context("create_storage_pool")
}

/// Creates a new storage pool and returns its object ID.
///
/// config_json: {
///   "walrus_config":                  "/path/to/client_config.yaml",
///   "reserved_encoded_capacity_bytes": 10485760,
///   "epochs_ahead":                    5,
///   "private_key":                     "<base64_std([0x00] || seed_32_bytes)>",
///   "sui_address":                     "0x…"
/// }
///
/// Returns JSON: {"storage_pool_object_id":"0x…"}
///           or: {"error":"…"}
/// MUST be freed with walrus_free_string().
#[no_mangle]
pub extern "C" fn walrus_create_storage_pool(config_json: *const c_char) -> *mut c_char {
    let config_str = unsafe {
        match CStr::from_ptr(config_json).to_str() {
            Ok(s) => s,
            Err(e) => return err_ptr(format!("invalid config UTF-8: {e}")),
        }
    };
    let config: CreatePoolConfig = match serde_json::from_str(config_str) {
        Ok(c) => c,
        Err(e) => return err_ptr(format!("config parse error: {e}")),
    };

    match block_on(create_storage_pool_async(config)) {
        Ok(id) => {
            let json = serde_json::json!({ "storage_pool_object_id": id.to_string() }).to_string();
            CString::new(json)
                .unwrap_or_else(|_| CString::new(r#"{"error":"internal error"}"#).unwrap())
                .into_raw()
        }
        Err(e) => err_ptr(format!("{e:#}")),
    }
}

#[derive(Debug, Deserialize, ZeroizeOnDrop)]
struct ExtendPoolConfig {
    #[zeroize(skip)]
    walrus_config: String,
    #[zeroize(skip)]
    storage_pool_object_id: String,
    #[zeroize(skip)]
    epochs_extended: u32,
    private_key: String,
    #[zeroize(skip)]
    sui_address: String,
}

async fn extend_storage_pool_async(config: ExtendPoolConfig) -> Result<()> {
    let wallet = build_ephemeral_wallet(
        &config.private_key,
        &config.sui_address,
        &config.walrus_config,
    )?;
    let client_config = load_configuration(Some(wallet.walrus_config_path.clone()), None)
        .context("load walrus config")?;
    let sui_client = client_config
        .new_contract_client_with_wallet_in_config(None)
        .await
        .context("build sui contract client")?;

    let storage_pool_object_id: ObjectID = config
        .storage_pool_object_id
        .parse()
        .context("parse storage_pool_object_id")?;

    sui_client
        .extend_storage_pool(storage_pool_object_id, config.epochs_extended)
        .await
        .context("extend_storage_pool")
}

/// Extends a storage pool's lifetime by the given number of epochs.
///
/// config_json: {
///   "walrus_config":          "/path/to/client_config.yaml",
///   "storage_pool_object_id": "0x…",
///   "epochs_extended":        2,
///   "private_key":            "<base64_std([0x00] || seed_32_bytes)>",
///   "sui_address":            "0x…"
/// }
///
/// Returns JSON: {"ok":true}
///           or: {"error":"…"}
/// MUST be freed with walrus_free_string().
#[no_mangle]
pub extern "C" fn walrus_extend_storage_pool(config_json: *const c_char) -> *mut c_char {
    let config_str = unsafe {
        match CStr::from_ptr(config_json).to_str() {
            Ok(s) => s,
            Err(e) => return err_ptr(format!("invalid config UTF-8: {e}")),
        }
    };
    let config: ExtendPoolConfig = match serde_json::from_str(config_str) {
        Ok(c) => c,
        Err(e) => return err_ptr(format!("config parse error: {e}")),
    };

    match block_on(extend_storage_pool_async(config)) {
        Ok(()) => CString::new(r#"{"ok":true}"#)
            .unwrap_or_else(|_| CString::new(r#"{"error":"internal error"}"#).unwrap())
            .into_raw(),
        Err(e) => err_ptr(format!("{e:#}")),
    }
}

#[derive(Debug, Deserialize, ZeroizeOnDrop)]
struct IncreasePoolCapacityConfig {
    #[zeroize(skip)]
    walrus_config: String,
    #[zeroize(skip)]
    storage_pool_object_id: String,
    #[zeroize(skip)]
    additional_encoded_capacity_bytes: u64,
    private_key: String,
    #[zeroize(skip)]
    sui_address: String,
}

async fn increase_storage_pool_capacity_async(config: IncreasePoolCapacityConfig) -> Result<()> {
    let wallet = build_ephemeral_wallet(
        &config.private_key,
        &config.sui_address,
        &config.walrus_config,
    )?;
    let client_config = load_configuration(Some(wallet.walrus_config_path.clone()), None)
        .context("load walrus config")?;
    let sui_client = client_config
        .new_contract_client_with_wallet_in_config(None)
        .await
        .context("build sui contract client")?;

    let storage_pool_object_id: ObjectID = config
        .storage_pool_object_id
        .parse()
        .context("parse storage_pool_object_id")?;

    sui_client
        .increase_storage_pool_capacity(
            storage_pool_object_id,
            config.additional_encoded_capacity_bytes,
        )
        .await
        .context("increase_storage_pool_capacity")
}

/// Increases a storage pool's reserved encoded capacity.
///
/// config_json: {
///   "walrus_config":                     "/path/to/client_config.yaml",
///   "storage_pool_object_id":            "0x…",
///   "additional_encoded_capacity_bytes": 10485760,
///   "private_key":                       "<base64_std([0x00] || seed_32_bytes)>",
///   "sui_address":                       "0x…"
/// }
///
/// Returns JSON: {"ok":true}
///           or: {"error":"…"}
/// MUST be freed with walrus_free_string().
#[no_mangle]
pub extern "C" fn walrus_increase_storage_pool_capacity(config_json: *const c_char) -> *mut c_char {
    let config_str = unsafe {
        match CStr::from_ptr(config_json).to_str() {
            Ok(s) => s,
            Err(e) => return err_ptr(format!("invalid config UTF-8: {e}")),
        }
    };
    let config: IncreasePoolCapacityConfig = match serde_json::from_str(config_str) {
        Ok(c) => c,
        Err(e) => return err_ptr(format!("config parse error: {e}")),
    };

    match block_on(increase_storage_pool_capacity_async(config)) {
        Ok(()) => CString::new(r#"{"ok":true}"#)
            .unwrap_or_else(|_| CString::new(r#"{"error":"internal error"}"#).unwrap())
            .into_raw(),
        Err(e) => err_ptr(format!("{e:#}")),
    }
}

// ── Storage Pool Status (read-only) ──────────────────────────────────────────
//
// Bonus: storage_pool_status is a read-only view — no signing actually
// required for this one, but it's built here via the same contract client
// for simplicity/consistency with the rest of this file. Useful before
// calling walrus_store_blob_in_pool to confirm the pool has enough remaining
// capacity/epochs, per the earlier warning that the store call won't extend
// or top up the pool for you.

#[derive(Debug, Deserialize, ZeroizeOnDrop)]
struct PoolStatusConfig {
    #[zeroize(skip)]
    walrus_config: String,
    #[zeroize(skip)]
    storage_pool_object_id: String,
    private_key: String,
    #[zeroize(skip)]
    sui_address: String,
}

async fn storage_pool_status_async(config: PoolStatusConfig) -> Result<serde_json::Value> {
    let wallet = build_ephemeral_wallet(
        &config.private_key,
        &config.sui_address,
        &config.walrus_config,
    )?;
    let client_config = load_configuration(Some(wallet.walrus_config_path.clone()), None)
        .context("load walrus config")?;
    let sui_client = client_config
        .new_contract_client_with_wallet_in_config(None)
        .await
        .context("build sui contract client")?;

    let storage_pool_object_id: ObjectID = config
        .storage_pool_object_id
        .parse()
        .context("parse storage_pool_object_id")?;

    let status = sui_client
        .storage_pool_status(storage_pool_object_id)
        .await
        .context("storage_pool_status")?;

    Ok(serde_json::json!({
        "storage_pool_object_id": status.storage_pool_object_id.to_string(),
        "start_epoch": status.start_epoch,
        "end_epoch": status.end_epoch,
        "reserved_encoded_capacity_bytes": status.reserved_encoded_capacity_bytes,
        "used_encoded_bytes": status.used_encoded_bytes,
        "available_encoded_capacity_bytes": status.available_encoded_capacity_bytes(),
        "blob_count": status.blob_count,
    }))
}

/// Returns the current state of a storage pool (capacity used/available,
/// epoch range, blob count).
///
/// config_json: {
///   "walrus_config":          "/path/to/client_config.yaml",
///   "storage_pool_object_id": "0x…",
///   "private_key":            "<base64_std([0x00] || seed_32_bytes)>",
///   "sui_address":            "0x…"
/// }
///
/// MUST be freed with walrus_free_string().
#[no_mangle]
pub extern "C" fn walrus_storage_pool_status(config_json: *const c_char) -> *mut c_char {
    let config_str = unsafe {
        match CStr::from_ptr(config_json).to_str() {
            Ok(s) => s,
            Err(e) => return err_ptr(format!("invalid config UTF-8: {e}")),
        }
    };
    let config: PoolStatusConfig = match serde_json::from_str(config_str) {
        Ok(c) => c,
        Err(e) => return err_ptr(format!("config parse error: {e}")),
    };

    match block_on(storage_pool_status_async(config)) {
        Ok(json_val) => CString::new(json_val.to_string())
            .unwrap_or_else(|_| CString::new(r#"{"error":"internal error"}"#).unwrap())
            .into_raw(),
        Err(e) => err_ptr(format!("{e:#}")),
    }
}
