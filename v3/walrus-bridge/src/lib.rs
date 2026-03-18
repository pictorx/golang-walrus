use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uchar};
use std::path::PathBuf;
use std::slice;

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use walrus_sdk::{
    client::{
        store_args::StoreArgs,
        responses::BlobStoreResult,
        StoreBlobsApi,
        WalrusNodeClient,
    },
    config::load_configuration,
    uploader::TailHandling,
};
use walrus_sui::client::BlobPersistence;
use walrus_sui::types::move_structs::BlobAttribute;

#[derive(Debug, Deserialize)]
struct BridgeConfig {
    walrus_config: String,
    epochs: u32,
    #[serde(default)]
    deletable: bool,
    #[serde(default)]
    metadata: std::collections::HashMap<String, String>,
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

fn block_on<F: std::future::Future<Output = Result<T>>, T>(f: F) -> Result<T> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(f)
}

async fn store_async(config: BridgeConfig, data: Vec<u8>) -> Result<FfiResult> {
    let client_config = load_configuration(Some(PathBuf::from(&config.walrus_config)), None)
        .context("load walrus config")?;

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

    let attribute = BlobAttribute::from(config.metadata.into_iter());

    let mut results = walrus_client
        .reserve_and_store_blobs_retry_committees(vec![data], vec![attribute], &store_args)
        .await
        .context("reserve_and_store_blobs_retry_committees")?;

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
            error: format!("blob {} marked invalid", URL_SAFE_NO_PAD.encode(blob_id.as_ref())),
        }),
        BlobStoreResult::Error { error_msg, .. } => Ok(FfiResult::Err { error: error_msg }),
    }
}

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
    let data = unsafe { slice::from_raw_parts(data_ptr, data_len) }.to_vec();

    let result = match block_on(store_async(config, data)) {
        Ok(r) => r,
        Err(e) => FfiResult::Err { error: format!("{e:#}") },
    };

    let json = serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"serialise failed"}"#.to_string());
    CString::new(json).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn walrus_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { let _ = CString::from_raw(ptr); }
    }
}

fn err_ptr(msg: String) -> *mut c_char {
    let json = format!(r#"{{"error":{}}}"#, serde_json::to_string(&msg).unwrap_or_default());
    CString::new(json).unwrap().into_raw()
}