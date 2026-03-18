// Copyright (c) Walrus Foundation / Project Contributors
// SPDX-License-Identifier: Apache-2.0

//! Walrus WASM FFI — BLS12-381 crypto + Reed-Solomon encoding + direct sliver upload.
//!
//! ## Architecture
//!
//! ```text
//!  Go (wazero host)                    WASM (this crate)
//!  ─────────────────                   ──────────────────────────────
//!  encode_for_upload()          ──▶    encodes blob, stores pairs in
//!                               ◀──    thread_local, returns blob info
//!
//!  (on-chain: register blob)
//!
//!  upload_stored_slivers()      ──▶    loops slivers, per sliver calls ──▶
//!                                        host_http_put_sliver (import)  ──▶  storage node HTTP
//!                               ◀──    aggregated BLS cert bytes        ◀──
//!
//!  (on-chain: certify blob with cert)
//! ```
//!
//! ## URL routing
//!
//! The WASM constructs one canonical URL per attempt:
//!   `http://{node_addr}/v1/blobs/{blob_id_b64url}/slivers/{sliver_index}`
//!
//! The Go host function (`host_http_put_sliver`) is responsible for trying
//! http/https variants and fallback ports — matching `uploadSliverToNodeWithRetry`
//! in `direct_upload.go`.

#![deny(unsafe_op_in_unsafe_fn)]

use core::num::NonZeroU16;
use std::{cell::RefCell, slice};

use fastcrypto::bls12381::min_pk::{
    BLS12381AggregateSignature, BLS12381PublicKey, BLS12381Signature,
};
use fastcrypto::traits::{AggregateAuthenticator, ToFromBytes, VerifyingKey};
use serde::{Deserialize, Serialize};
use walrus_core::{
    encoding::{EncodingConfig, EncodingConfigEnum, EncodingFactory, SliverPair},
    metadata::{BlobMetadata, BlobMetadataApi},
    BlobId, EncodingType,
};

// ── Error codes (mirror the Go constants) ────────────────────────────────────

const SUCCESS: i32 = 0;
const ERROR_INVALID_SIGNATURE: i32 = -1;
const ERROR_INVALID_PUBLIC_KEY: i32 = -2;
#[allow(dead_code)]
const ERROR_VERIFICATION_FAILED: i32 = -3;
const ERROR_AGGREGATION_FAILED: i32 = -4;
const ERROR_DESERIALIZATION_FAILED: i32 = -5;
const ERROR_ENCODING_FAILED: i32 = -6;
const ERROR_BUFFER_SIZE_MISMATCH: i32 = -7;
const ERROR_INVALID_SHARDS: i32 = -8;
const ERROR_DECODING_FAILED: i32 = -9;
/// Quorum was not reached during sliver upload.
const ERROR_QUORUM_NOT_REACHED: i32 = -10;
/// No upload state is present — call `encode_for_upload` first.
const ERROR_NO_UPLOAD_STATE: i32 = -11;
/// The host HTTP function returned an unexpected error.
const ERROR_HTTP_FAILED: i32 = -12;

// ── Host-imported functions (implemented by Go/wazero) ───────────────────────
//
// Go registers these via:
//   r.NewHostModuleBuilder("env").
//       NewFunctionBuilder().WithGoModuleFunction(...).Export("host_http_put_sliver").
//       Instantiate(ctx)
//
// The host function should:
//   1. Build the full URL from the base address passed in.
//   2. Try http/https and port-9185 variants (matching uploadSliverToNodeWithRetry).
//   3. On HTTP 200, parse the JSON response, extract .data.primary.{sig,msg} (base64).
//   4. Decode them and write raw bytes into out_sig / out_msg.
//   5. Return the HTTP status code (200) or a negative sentinel on network error.

#[link(wasm_import_module = "env")]
extern "C" {
    /// PUT a BCS-encoded primary sliver to a storage node.
    ///
    /// # Parameters
    /// - `url_ptr / url_len`       — UTF-8 URL, e.g. `http://host:9185/v1/blobs/{id}/slivers/{n}`
    /// - `body_ptr / body_len`     — BCS-encoded primary sliver bytes
    /// - `out_sig_ptr`             — caller-allocated buffer (≥96 bytes) for the partial BLS sig
    /// - `out_sig_len`             — pointer to u32; host writes actual sig length here
    /// - `out_msg_ptr`             — caller-allocated buffer (≥256 bytes) for the serialized message
    /// - `out_msg_len`             — pointer to u32; host writes actual msg length here
    ///
    /// # Returns
    /// HTTP status code on success (200 = stored), or negative on transport error.
    fn host_http_put_sliver(
        url_ptr: *const u8,
        url_len: u32,
        body_ptr: *const u8,
        body_len: u32,
        out_sig_ptr: *mut u8,
        out_sig_len: *mut u32,
        out_msg_ptr: *mut u8,
        out_msg_len: *mut u32,
    ) -> i32;
}

// ── Shared data types ─────────────────────────────────────────────────────────

/// Per-node info supplied by the Go host, mirroring `NodeInfo` in `direct_upload.go`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeInfoFFI {
    /// Position in the committee array (0-based).
    pub index: u32,
    /// `"host:port"` network address, e.g. `"walrus-01.example.com:9185"`.
    pub network_address: String,
    /// 48-byte BLS12-381 min-pk.
    pub public_key: Vec<u8>,
}

/// Partial BLS signature collected from one storage node after a successful PUT.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct NodePartialSig {
    node_index: u32,
    /// Raw BLS signature bytes (48 bytes for min-pk scheme).
    sig: Vec<u8>,
    /// Serialized confirmation message returned by the node — same value for all nodes
    /// for a given blob, so we just keep the first one.
    msg: Vec<u8>,
}

/// Confirmation certificate ready to submit to the `certify_blob` Move call.
/// Serialized via bincode for the Go host to deserialize.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConfirmationCertificate {
    /// Bit-array where bit `i` is set iff node `i` signed.
    /// Length = `ceil(n_members / 8)`.
    pub signers: Vec<u8>,
    /// The serialized confirmation message (identical across all nodes).
    pub serialized_message: Vec<u8>,
    /// Aggregated BLS signature bytes (96 bytes).
    pub signature: Vec<u8>,
}

// ── Thread-local storage ──────────────────────────────────────────────────────

thread_local! {
    /// Active encoder instances, indexed by handle returned from `encoder_create`.
    static ENCODERS: RefCell<Vec<EncodingConfigEnum>> = RefCell::new(Vec::new());

    /// Sliver pairs retained between `encode_for_upload` and `upload_stored_slivers`.
    static UPLOAD_STATE: RefCell<Option<UploadState>> = RefCell::new(None);
}

struct UploadState {
    sliver_pairs: Vec<SliverPair>,
}

// ── Memory management ─────────────────────────────────────────────────────────

/// Allocate `size` bytes in WASM memory and return the pointer.
/// Go calls `allocate` / `deallocate` to manage shared buffers.
#[no_mangle]
pub extern "C" fn allocate(size: u32) -> *mut u8 {
    let mut buf: Vec<u8> = Vec::with_capacity(size as usize);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Free a buffer previously allocated with `allocate`.
#[no_mangle]
pub extern "C" fn deallocate(ptr: *mut u8, size: u32) {
    // SAFETY: ptr was allocated by `allocate` with the same capacity.
    let _ = unsafe { Vec::from_raw_parts(ptr, size as usize, size as usize) };
}

// ── BLS12-381 functions ───────────────────────────────────────────────────────

/// Verify a single BLS12-381 (min-pk) signature.
/// Returns 1 if valid, 0 if invalid, negative error code on bad input.
#[no_mangle]
pub extern "C" fn bls12381_min_pk_verify(
    signature_ptr: *const u8,
    signature_len: u32,
    public_key_ptr: *const u8,
    public_key_len: u32,
    msg_ptr: *const u8,
    msg_len: u32,
) -> i32 {
    let signature_bytes =
        unsafe { slice::from_raw_parts(signature_ptr, signature_len as usize) };
    let public_key_bytes =
        unsafe { slice::from_raw_parts(public_key_ptr, public_key_len as usize) };
    let msg_bytes = unsafe { slice::from_raw_parts(msg_ptr, msg_len as usize) };

    let signature = match BLS12381Signature::from_bytes(signature_bytes) {
        Ok(s) => s,
        Err(_) => return ERROR_INVALID_SIGNATURE,
    };
    let public_key = match BLS12381PublicKey::from_bytes(public_key_bytes) {
        Ok(pk) => pk,
        Err(_) => return ERROR_INVALID_PUBLIC_KEY,
    };

    if public_key.verify(msg_bytes, &signature).is_ok() {
        1
    } else {
        0
    }
}

/// Aggregate multiple BLS12-381 (min-pk) signatures.
///
/// `signatures_ptr` must point to a bincode-serialized `Vec<Vec<u8>>` (same
/// format used by `serializeVecVecU8` in `walrus.go`).
///
/// Returns: number of bytes written to `output_ptr` on success, negative error on failure.
#[no_mangle]
pub extern "C" fn bls12381_min_pk_aggregate(
    signatures_ptr: *const u8,
    signatures_len: u32,
    output_ptr: *mut u8,
    output_capacity: u32,
) -> i32 {
    let signatures_bytes =
        unsafe { slice::from_raw_parts(signatures_ptr, signatures_len as usize) };

    let signatures_vec: Vec<Vec<u8>> = match bincode::deserialize(signatures_bytes) {
        Ok(v) => v,
        Err(_) => return ERROR_DESERIALIZATION_FAILED,
    };

    let signatures: Result<Vec<BLS12381Signature>, _> = signatures_vec
        .iter()
        .map(|sig| BLS12381Signature::from_bytes(sig))
        .collect();
    let signatures = match signatures {
        Ok(s) => s,
        Err(_) => return ERROR_INVALID_SIGNATURE,
    };

    let agg = match BLS12381AggregateSignature::aggregate(&signatures) {
        Ok(a) => a,
        Err(_) => return ERROR_AGGREGATION_FAILED,
    };

    let result_bytes = agg.as_bytes().to_vec();
    if result_bytes.len() > output_capacity as usize {
        return ERROR_BUFFER_SIZE_MISMATCH;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(result_bytes.as_ptr(), output_ptr, result_bytes.len());
    }
    result_bytes.len() as i32
}

/// Verify an aggregate BLS12-381 (min-pk) signature against multiple public keys.
///
/// `public_keys_ptr` → bincode `Vec<Vec<u8>>`.
/// Returns 1 if valid, 0 if invalid, negative error code on bad input.
#[no_mangle]
pub extern "C" fn bls12381_min_pk_verify_aggregate(
    public_keys_ptr: *const u8,
    public_keys_len: u32,
    msg_ptr: *const u8,
    msg_len: u32,
    signature_ptr: *const u8,
    signature_len: u32,
) -> i32 {
    let public_keys_bytes =
        unsafe { slice::from_raw_parts(public_keys_ptr, public_keys_len as usize) };
    let msg_bytes = unsafe { slice::from_raw_parts(msg_ptr, msg_len as usize) };
    let signature_bytes =
        unsafe { slice::from_raw_parts(signature_ptr, signature_len as usize) };

    let public_keys_vec: Vec<Vec<u8>> = match bincode::deserialize(public_keys_bytes) {
        Ok(v) => v,
        Err(_) => return ERROR_DESERIALIZATION_FAILED,
    };
    let public_keys: Result<Vec<BLS12381PublicKey>, _> = public_keys_vec
        .iter()
        .map(|pk| BLS12381PublicKey::from_bytes(pk))
        .collect();
    let public_keys = match public_keys {
        Ok(pks) => pks,
        Err(_) => return ERROR_INVALID_PUBLIC_KEY,
    };

    let signature = match BLS12381AggregateSignature::from_bytes(signature_bytes) {
        Ok(s) => s,
        Err(_) => return ERROR_INVALID_SIGNATURE,
    };

    if signature.verify(&public_keys, msg_bytes).is_ok() {
        1
    } else {
        0
    }
}

// ── Encoder functions (existing API, unchanged) ───────────────────────────────

/// Create an encoder for `n_shards`.  Returns a handle (≥0) or negative error.
#[no_mangle]
pub extern "C" fn encoder_create(n_shards: u16) -> i32 {
    let config = match NonZeroU16::new(n_shards) {
        Some(n) => EncodingConfig::new(n),
        None => return ERROR_INVALID_SHARDS,
    };
    let encoder = config.get_for_type(EncodingType::RS2);
    ENCODERS.with(|encoders| {
        let mut encoders = encoders.borrow_mut();
        let handle = encoders.len() as i32;
        encoders.push(encoder);
        handle
    })
}

/// Returns a conservative upper-bound on BCS-serialized sliver size.
/// Useful so Go can allocate buffers before calling `encoder_encode`.
#[no_mangle]
pub extern "C" fn encoder_get_sliver_size(
    encoder_handle: i32,
    data_ptr: *const u8,
    data_len: u32,
) -> i32 {
    let data_vec = unsafe { slice::from_raw_parts(data_ptr, data_len as usize) }.to_vec();
    let encoder = get_encoder(encoder_handle);
    let encoder = match encoder {
        Some(e) => e,
        None => return ERROR_ENCODING_FAILED,
    };
    let (sliver_pairs, _) = match encoder.encode_with_metadata(data_vec) {
        Ok(r) => r,
        Err(_) => return ERROR_ENCODING_FAILED,
    };
    if sliver_pairs.is_empty() {
        return ERROR_ENCODING_FAILED;
    }
    let mut max_size = 0usize;
    for sp in &sliver_pairs {
        if let Ok(b) = bcs::to_bytes(&sp.primary) {
            max_size = max_size.max(b.len());
        }
        if let Ok(b) = bcs::to_bytes(&sp.secondary) {
            max_size = max_size.max(b.len());
        }
    }
    max_size as i32
}

/// Encode `data` into `num_buffers` primary + secondary shard pairs, plus metadata.
///
/// The arrays of pointers (`primary_buffers_ptr`, `secondary_buffers_ptr`) each hold
/// `num_buffers` WASM pointers to pre-allocated buffers. The corresponding `*_buffer_lens`
/// arrays hold the buffer capacity on input and are overwritten with the actual bytes
/// written on output — matching the existing Go `Encode()` caller.
///
/// Returns: actual metadata size written, or negative error code.
#[no_mangle]
pub extern "C" fn encoder_encode(
    encoder_handle: i32,
    data_ptr: *const u8,
    data_len: u32,
    primary_buffers_ptr: *const *mut u8,
    primary_buffer_lens: *mut u32,
    secondary_buffers_ptr: *const *mut u8,
    secondary_buffer_lens: *mut u32,
    num_buffers: u32,
    output_metadata_ptr: *mut u8,
    output_metadata_capacity: u32,
) -> i32 {
    let data_vec = unsafe { slice::from_raw_parts(data_ptr, data_len as usize) }.to_vec();
    let encoder = match get_encoder(encoder_handle) {
        Some(e) => e,
        None => return ERROR_ENCODING_FAILED,
    };
    let (sliver_pairs, metadata) = match encoder.encode_with_metadata(data_vec) {
        Ok(r) => r,
        Err(_) => return ERROR_ENCODING_FAILED,
    };
    if sliver_pairs.len() != num_buffers as usize {
        return ERROR_BUFFER_SIZE_MISMATCH;
    }

    let primary_buffers =
        unsafe { slice::from_raw_parts(primary_buffers_ptr, num_buffers as usize) };
    let primary_lens =
        unsafe { slice::from_raw_parts_mut(primary_buffer_lens, num_buffers as usize) };
    let secondary_buffers =
        unsafe { slice::from_raw_parts(secondary_buffers_ptr, num_buffers as usize) };
    let secondary_lens =
        unsafe { slice::from_raw_parts_mut(secondary_buffer_lens, num_buffers as usize) };

    for (i, sp) in sliver_pairs.iter().enumerate() {
        let pb = match bcs::to_bytes(&sp.primary) {
            Ok(b) => b,
            Err(_) => return ERROR_ENCODING_FAILED,
        };
        if pb.len() > primary_lens[i] as usize {
            return ERROR_BUFFER_SIZE_MISMATCH;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(pb.as_ptr(), primary_buffers[i], pb.len());
        }
        primary_lens[i] = pb.len() as u32;

        let sb = match bcs::to_bytes(&sp.secondary) {
            Ok(b) => b,
            Err(_) => return ERROR_ENCODING_FAILED,
        };
        if sb.len() > secondary_lens[i] as usize {
            return ERROR_BUFFER_SIZE_MISMATCH;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(sb.as_ptr(), secondary_buffers[i], sb.len());
        }
        secondary_lens[i] = sb.len() as u32;
    }

    let root_hash = match metadata.metadata() {
        BlobMetadata::V1(inner) => inner.compute_root_hash(),
    };
    let meta_output = (metadata, root_hash);
    let serialized = match bincode::serialize(&meta_output) {
        Ok(s) => s,
        Err(_) => return ERROR_ENCODING_FAILED,
    };
    if serialized.len() > output_metadata_capacity as usize {
        return ERROR_BUFFER_SIZE_MISMATCH;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            serialized.as_ptr(),
            output_metadata_ptr,
            serialized.len(),
        );
    }
    serialized.len() as i32
}

/// Compute metadata without producing slivers.
/// Output: bincode `(BlobId, root_hash, unencoded_length, encoding_type)`.
#[no_mangle]
pub extern "C" fn encoder_compute_metadata(
    encoder_handle: i32,
    data_ptr: *const u8,
    data_len: u32,
    output_ptr: *mut u8,
    output_capacity: u32,
) -> i32 {
    let data_vec = unsafe { slice::from_raw_parts(data_ptr, data_len as usize) }.to_vec();
    let encoder = match get_encoder(encoder_handle) {
        Some(e) => e,
        None => return ERROR_ENCODING_FAILED,
    };
    let metadata = match encoder.compute_metadata(&data_vec) {
        Ok(m) => m,
        Err(_) => return ERROR_ENCODING_FAILED,
    };

    let blob_id = metadata.blob_id();
    let (root_hash_node, unencoded_length, encoding_type) = match metadata.metadata() {
        BlobMetadata::V1(inner) => (
            inner.compute_root_hash().bytes(), // [u8; 32], no enum discriminant
            inner.unencoded_length,
            inner.encoding_type,
        ),
    };

    let output_data = (blob_id, root_hash_node, unencoded_length, encoding_type);
    let serialized = match bincode::serialize(&output_data) {
        Ok(s) => s,
        Err(_) => return ERROR_ENCODING_FAILED,
    };
    if serialized.len() > output_capacity as usize {
        return ERROR_BUFFER_SIZE_MISMATCH;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(serialized.as_ptr(), output_ptr, serialized.len());
    }
    serialized.len() as i32
}

/// Decode a blob from BCS-encoded `SliverData<Primary>` buffers.
/// Returns SUCCESS or negative error code.
#[no_mangle]
pub extern "C" fn encoder_decode(
    encoder_handle: i32,
    blob_id_ptr: *const u8,
    blob_id_len: u32,
    blob_size: u64,
    bcs_buffers_ptr: *const *const u8,
    bcs_buffer_lens: *const u32,
    num_buffers: u32,
    output_buffer_ptr: *mut u8,
    output_buffer_len: u32,
) -> i32 {
    use walrus_core::encoding::{Primary, SliverData};

    if output_buffer_len as u64 != blob_size {
        return ERROR_BUFFER_SIZE_MISMATCH;
    }

    let blob_id_bytes = unsafe { slice::from_raw_parts(blob_id_ptr, blob_id_len as usize) };
    let _blob_id: BlobId = match bincode::deserialize(blob_id_bytes) {
        Ok(id) => id,
        Err(_) => return ERROR_DESERIALIZATION_FAILED,
    };

    let encoder = match get_encoder(encoder_handle) {
        Some(e) => e,
        None => return ERROR_DECODING_FAILED,
    };

    let bcs_buffers = unsafe { slice::from_raw_parts(bcs_buffers_ptr, num_buffers as usize) };
    let bcs_lens = unsafe { slice::from_raw_parts(bcs_buffer_lens, num_buffers as usize) };

    let mut sliver_data: Vec<SliverData<Primary>> = Vec::with_capacity(num_buffers as usize);
    for i in 0..num_buffers as usize {
        let buffer = unsafe { slice::from_raw_parts(bcs_buffers[i], bcs_lens[i] as usize) };
        let sliver: SliverData<Primary> = match bcs::from_bytes(buffer) {
            Ok(s) => s,
            Err(_) => return ERROR_DESERIALIZATION_FAILED,
        };
        sliver_data.push(sliver);
    }

    let decoded = match encoder.decode(blob_size, sliver_data) {
        Ok(d) => d,
        Err(_) => return ERROR_DECODING_FAILED,
    };

    unsafe {
        std::ptr::copy_nonoverlapping(decoded.as_ptr(), output_buffer_ptr, decoded.len());
    }
    SUCCESS
}

/// Destroy an encoder instance (marks its slot as unused).
#[no_mangle]
pub extern "C" fn encoder_destroy(encoder_handle: i32) -> i32 {
    ENCODERS.with(|encoders| {
        let encoders = encoders.borrow();
        if encoder_handle < 0 || encoder_handle >= encoders.len() as i32 {
            return ERROR_ENCODING_FAILED;
        }
        SUCCESS
    })
}

/// Returns the exact byte length of the bincode metadata for `data`.
#[no_mangle]
pub extern "C" fn encoder_get_metadata_size(
    encoder_handle: i32,
    data_ptr: *const u8,
    data_len: u32,
) -> i32 {
    let data_vec = unsafe { slice::from_raw_parts(data_ptr, data_len as usize) }.to_vec();
    let encoder = match get_encoder(encoder_handle) {
        Some(e) => e,
        None => return ERROR_ENCODING_FAILED,
    };
    let (_, metadata) = match encoder.encode_with_metadata(data_vec) {
        Ok(r) => r,
        Err(_) => return ERROR_ENCODING_FAILED,
    };
    let root_hash = match metadata.metadata() {
        BlobMetadata::V1(inner) => inner.compute_root_hash(),
    };
    let meta_output = (metadata, root_hash);
    let serialized = match bincode::serialize(&meta_output) {
        Ok(s) => s,
        Err(_) => return ERROR_ENCODING_FAILED,
    };
    serialized.len() as i32
}

// ── Direct upload: Phase 1 — encode and retain slivers ───────────────────────

/// Encode `data` into sliver pairs and store them in WASM-side state for the
/// subsequent `upload_stored_slivers` call.
///
/// This mirrors Step 1 of `CompleteWalrusFlowDirect` (Go) but keeps the BCS
/// serialized slivers inside WASM memory to avoid the trailing-zero bug that
/// arises when Go reads `sliverSizeUint` bytes instead of the actual size.
///
/// **Output** (`out_ptr`): bincode-serialized `BlobInfoFFI`:
/// ```
/// struct BlobInfoFFI {
///     blob_id:          [u8; 32],
///     root_hash:        [u8; 32],
///     unencoded_length: u64,
///     encoding_type:    u32,   // 0 = RedStuff, 1 = RS2
/// }
/// ```
///
/// Returns: bytes written to `out_ptr`, or negative error code.
#[no_mangle]
pub extern "C" fn encode_for_upload(
    data_ptr: *const u8,
    data_len: u32,
    n_shards: u16,
    out_ptr: *mut u8,
    out_capacity: u32,
) -> i32 {
    let data_vec = unsafe { slice::from_raw_parts(data_ptr, data_len as usize) }.to_vec();

    let n = match NonZeroU16::new(n_shards) {
        Some(n) => n,
        None => return ERROR_INVALID_SHARDS,
    };
    let encoding_config = EncodingConfig::new(n);
    let encoder = encoding_config.get_for_type(EncodingType::RS2);

    let (sliver_pairs, metadata) = match encoder.encode_with_metadata(data_vec) {
        Ok(r) => r,
        Err(_) => return ERROR_ENCODING_FAILED,
    };

    // Extract blob info for the Go host to use in on-chain registration.
    let blob_id = *metadata.blob_id();
    let (root_hash, unencoded_length, encoding_type_val) = match metadata.metadata() {
        BlobMetadata::V1(inner) => (
            inner.compute_root_hash(),
            inner.unencoded_length,
            inner.encoding_type,
        ),
    };

    // Stash the sliver pairs for `upload_stored_slivers`.
    UPLOAD_STATE.with(|state| {
        *state.borrow_mut() = Some(UploadState { sliver_pairs });
    });

    // Serialize blob info.
    let blob_info = BlobInfoFFI {
        blob_id: blob_id.0,
        root_hash: root_hash.bytes(),
        unencoded_length,
        encoding_type: encoding_type_val as u32,
    };
    let serialized = match bincode::serialize(&blob_info) {
        Ok(s) => s,
        Err(_) => return ERROR_ENCODING_FAILED,
    };
    if serialized.len() > out_capacity as usize {
        return ERROR_BUFFER_SIZE_MISMATCH;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(serialized.as_ptr(), out_ptr, serialized.len());
    }
    serialized.len() as i32
}

/// Blob info returned by `encode_for_upload`, used by Go for on-chain registration.
#[derive(Serialize, Deserialize, Debug)]
struct BlobInfoFFI {
    blob_id: [u8; 32],
    root_hash: [u8; 32],
    unencoded_length: u64,
    encoding_type: u32,
}

/// Return the byte size of a `BlobInfoFFI` bincode serialization.
/// Useful for pre-allocating the output buffer.
#[no_mangle]
pub extern "C" fn blob_info_ffi_size() -> u32 {
    // BlobInfoFFI is fixed-size: 32 + 32 + 8 + 4 + bincode framing = ~84 bytes.
    // Return a safe upper bound.
    128
}

// ── Direct upload: Phase 2 — upload slivers via host HTTP ────────────────────

/// Upload the sliver pairs stored by `encode_for_upload` directly to storage nodes.
///
/// This is the WASM equivalent of `uploadSliversDirect` in `direct_upload.go`.
/// It calls the `host_http_put_sliver` import for each sliver, collects partial
/// BLS signatures, checks for a 2f+1 quorum, aggregates the signatures, and
/// returns a `ConfirmationCertificate`.
///
/// # Parameters
/// - `blob_id_b64url_ptr / _len` — URL-safe base64 blob ID (no padding), UTF-8.
/// - `nodes_ptr / nodes_len`     — bincode-serialized `Vec<NodeInfoFFI>`.
/// - `n_members`                 — total committee members (for bitmap width).
/// - `out_ptr / out_capacity`    — buffer for bincode-serialized `ConfirmationCertificate`.
///
/// # Returns
/// Bytes written to `out_ptr`, or a negative error code.
///
/// After this call, the internal upload state is automatically cleared.
#[no_mangle]
pub extern "C" fn upload_stored_slivers(
    blob_id_b64url_ptr: *const u8,
    blob_id_b64url_len: u32,
    nodes_ptr: *const u8,
    nodes_len: u32,
    n_members: u32,
    out_ptr: *mut u8,
    out_capacity: u32,
) -> i32 {
    // ── 1. Read inputs ────────────────────────────────────────────────────────
    let blob_id_b64url = {
        let bytes =
            unsafe { slice::from_raw_parts(blob_id_b64url_ptr, blob_id_b64url_len as usize) };
        match std::str::from_utf8(bytes) {
            Ok(s) => s.to_owned(),
            Err(_) => return ERROR_DESERIALIZATION_FAILED,
        }
    };

    let nodes_bytes = unsafe { slice::from_raw_parts(nodes_ptr, nodes_len as usize) };
    let nodes: Vec<NodeInfoFFI> = match bincode::deserialize(nodes_bytes) {
        Ok(n) => n,
        Err(_) => return ERROR_DESERIALIZATION_FAILED,
    };

    if nodes.is_empty() {
        return ERROR_QUORUM_NOT_REACHED;
    }

    // ── 2. Retrieve stored sliver pairs ───────────────────────────────────────
    // Borrow (not take) so a failed upload can be retried without re-encoding.
    // State is cleared at the end only on success.
    let sliver_pairs: Vec<SliverPair> = match UPLOAD_STATE.with(|s| {
        s.borrow().as_ref().map(|st| st.sliver_pairs.clone())
    }) {
        Some(pairs) => pairs,
        None => return ERROR_NO_UPLOAD_STATE,
    };

    let n_nodes = nodes.len();
    let n_shards = sliver_pairs.len();
    // quorum threshold = 2f+1 where f = floor((n-1)/3)
    let quorum = (2 * n_nodes) / 3 + 1;

    // ── 3. Upload slivers, collect partial signatures ─────────────────────────
    // BLS sig buffer: 96 bytes for aggregate; partial sigs are 48 bytes.
    const SIG_BUF_SIZE: usize = 96;
    // Serialized confirmation message: nodes return ≤ 512 bytes in practice.
    const MSG_BUF_SIZE: usize = 512;

    let mut partial_sigs: Vec<NodePartialSig> = Vec::new();
    let mut seen_nodes: Vec<bool> = vec![false; n_nodes];

    for sliver_idx in 0..n_shards {
        // Serialize this primary sliver to BCS — exactly the bytes the node expects.
        let sliver_bcs = match bcs::to_bytes(&sliver_pairs[sliver_idx].primary) {
            Ok(b) => b,
            Err(_) => return ERROR_ENCODING_FAILED,
        };

        // Target nodes for this sliver: try primary candidate + up to 2 neighbors,
        // matching `getTargetNodesForSliver` in direct_upload.go.
        const MAX_CANDIDATES: usize = 3;
        for candidate_offset in 0..MAX_CANDIDATES {
            let node_idx = (sliver_idx + candidate_offset) % n_nodes;
            if seen_nodes[node_idx] {
                // Already got a sig from this node for a previous sliver.
                // (Each node only needs one sig; skip to avoid double-counting.)
                continue;
            }

            let node = &nodes[node_idx];
            // Strip any scheme prefix — the host handles http/https fallback.
            let host = node
                .network_address
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/');

            let url = format!(
                "http://{}/v1/blobs/{}/slivers/{}",
                host, blob_id_b64url, sliver_idx
            );

            // Allocate output buffers on the stack via fixed-size arrays.
            let mut sig_buf = [0u8; SIG_BUF_SIZE];
            let mut sig_len: u32 = SIG_BUF_SIZE as u32;
            let mut msg_buf = [0u8; MSG_BUF_SIZE];
            let mut msg_len: u32 = MSG_BUF_SIZE as u32;

            let status = unsafe {
                host_http_put_sliver(
                    url.as_ptr(),
                    url.len() as u32,
                    sliver_bcs.as_ptr(),
                    sliver_bcs.len() as u32,
                    sig_buf.as_mut_ptr(),
                    &mut sig_len,
                    msg_buf.as_mut_ptr(),
                    &mut msg_len,
                )
            };

            if status == 200 && sig_len == 96 && msg_len > 0 {
                let sig = sig_buf[..sig_len as usize].to_vec();
                let msg = if partial_sigs.is_empty() {
                    // First success — keep the message (same for all nodes).
                    msg_buf[..msg_len as usize].to_vec()
                } else {
                    // Reuse the first message to save space.
                    partial_sigs[0].msg.clone()
                };

                seen_nodes[node_idx] = true;
                partial_sigs.push(NodePartialSig {
                    node_index: node.index,
                    sig,
                    msg,
                });

                // Once we have quorum, stop trying more candidates for this sliver.
                if partial_sigs.len() >= quorum {
                    break;
                }
            }
            // On failure, try the next candidate.
        }

        // Early exit once quorum is secured to save HTTP round-trips.
        if partial_sigs.len() >= quorum {
            break;
        }
    }

    if partial_sigs.len() < quorum {
        return ERROR_QUORUM_NOT_REACHED;
    }

    // ── 4. Aggregate BLS signatures ───────────────────────────────────────────
    let raw_sigs: Vec<Vec<u8>> = partial_sigs.iter().map(|ps| ps.sig.clone()).collect();
    let bls_sigs: Result<Vec<BLS12381Signature>, _> = raw_sigs
        .iter()
        .map(|b| BLS12381Signature::from_bytes(b))
        .collect();
    let bls_sigs = match bls_sigs {
        Ok(s) => s,
        Err(_) => return ERROR_INVALID_SIGNATURE,
    };
    let agg = match BLS12381AggregateSignature::aggregate(&bls_sigs) {
        Ok(a) => a,
        Err(_) => return ERROR_AGGREGATION_FAILED,
    };
    let aggregated_sig = agg.as_bytes().to_vec();

    // ── 5. Build signers bitmap ───────────────────────────────────────────────
    // Walrus bitmap: ceil(n_members / 8) bytes, bit i set iff node i signed.
    let signers = build_bitmap(
        partial_sigs.iter().map(|ps| ps.node_index as u8),
        n_members as usize,
    );

    // ── 6. Assemble certificate ───────────────────────────────────────────────
    let serialized_message = partial_sigs[0].msg.clone();
    let cert = ConfirmationCertificate {
        signers,
        serialized_message,
        signature: aggregated_sig,
    };

    let cert_bytes = match bincode::serialize(&cert) {
        Ok(b) => b,
        Err(_) => return ERROR_ENCODING_FAILED,
    };
    if cert_bytes.len() > out_capacity as usize {
        return ERROR_BUFFER_SIZE_MISMATCH;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(cert_bytes.as_ptr(), out_ptr, cert_bytes.len());
    }
    // Clear upload state only on success so a failed upload can be retried.
    UPLOAD_STATE.with(|s| *s.borrow_mut() = None);
    cert_bytes.len() as i32
}

// ── Utility exports ───────────────────────────────────────────────────────────

/// Build the Walrus signers bitmap from a list of node indices.
///
/// `signer_indices_ptr` → array of `num_signers` u8 node indices.
/// `n_members`          → total committee size.
///
/// Output: `ceil(n_members / 8)` bytes written to `out_ptr`.
/// Returns: bytes written, or negative error code.
#[no_mangle]
pub extern "C" fn build_signers_bitmap(
    signer_indices_ptr: *const u8,
    num_signers: u32,
    n_members: u32,
    out_ptr: *mut u8,
    out_capacity: u32,
) -> i32 {
    let indices = unsafe { slice::from_raw_parts(signer_indices_ptr, num_signers as usize) };
    let bitmap = build_bitmap(indices.iter().copied(), n_members as usize);
    if bitmap.len() > out_capacity as usize {
        return ERROR_BUFFER_SIZE_MISMATCH;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bitmap.as_ptr(), out_ptr, bitmap.len());
    }
    bitmap.len() as i32
}

/// Returns the size of the upload state (number of sliver pairs stored), or 0 if empty.
/// Useful for the Go host to verify that `encode_for_upload` succeeded before
/// calling `upload_stored_slivers`.
#[no_mangle]
pub extern "C" fn upload_state_sliver_count() -> u32 {
    UPLOAD_STATE.with(|s| {
        s.borrow()
            .as_ref()
            .map(|st| st.sliver_pairs.len() as u32)
            .unwrap_or(0)
    })
}

/// Discard any stored upload state without uploading.
/// Call this to clean up after a failed upload attempt.
#[no_mangle]
pub extern "C" fn clear_upload_state() {
    UPLOAD_STATE.with(|s| {
        *s.borrow_mut() = None;
    });
}

/// Compute the sliver-to-node dispatch table for `n_shards` slivers and
/// `n_nodes` committee members, returning a flat `u32` array of length
/// `n_shards` where element `i` is the primary node index for sliver `i`.
///
/// This uses the same `(sliver_idx % n_nodes)` mapping as `getTargetNodesForSliver`
/// in `direct_upload.go`. Go can use this table to drive parallel HTTP uploads
/// itself while still using WASM for BLS aggregation.
///
/// Output: `n_shards * 4` bytes (little-endian u32 values).
/// Returns: bytes written, or negative error code.
#[no_mangle]
pub extern "C" fn compute_sliver_dispatch_table(
    n_shards: u32,
    n_nodes: u32,
    out_ptr: *mut u8,
    out_capacity: u32,
) -> i32 {
    let needed = (n_shards as usize) * 4;
    if needed > out_capacity as usize {
        return ERROR_BUFFER_SIZE_MISMATCH;
    }
    if n_nodes == 0 {
        return ERROR_QUORUM_NOT_REACHED;
    }

    let out = unsafe { slice::from_raw_parts_mut(out_ptr as *mut u32, n_shards as usize) };
    for i in 0..n_shards as usize {
        out[i] = (i % n_nodes as usize) as u32;
    }
    needed as i32
}

/// Aggregate partial signatures collected outside WASM (e.g. by parallel Go goroutines)
/// and build a `ConfirmationCertificate`.
///
/// Input (`partial_sigs_ptr`): bincode `Vec<NodePartialSig>`:
/// ```
/// struct NodePartialSig { node_index: u32, sig: Vec<u8>, msg: Vec<u8> }
/// ```
///
/// Returns: bytes written to `out_ptr`, or negative error code.
#[no_mangle]
pub extern "C" fn aggregate_and_build_certificate(
    partial_sigs_ptr: *const u8,
    partial_sigs_len: u32,
    n_members: u32,
    out_ptr: *mut u8,
    out_capacity: u32,
) -> i32 {
    let bytes =
        unsafe { slice::from_raw_parts(partial_sigs_ptr, partial_sigs_len as usize) };
    let partial_sigs: Vec<NodePartialSig> = match bincode::deserialize(bytes) {
        Ok(v) => v,
        Err(_) => return ERROR_DESERIALIZATION_FAILED,
    };
    if partial_sigs.is_empty() {
        return ERROR_INVALID_SIGNATURE;
    }

    let bls_sigs: Result<Vec<BLS12381Signature>, _> = partial_sigs
        .iter()
        .map(|ps| BLS12381Signature::from_bytes(&ps.sig))
        .collect();
    let bls_sigs = match bls_sigs {
        Ok(s) => s,
        Err(_) => return ERROR_INVALID_SIGNATURE,
    };
    let agg = match BLS12381AggregateSignature::aggregate(&bls_sigs) {
        Ok(a) => a,
        Err(_) => return ERROR_AGGREGATION_FAILED,
    };

    let signers = build_bitmap(
        partial_sigs.iter().map(|ps| ps.node_index as u8),
        n_members as usize,
    );

    let cert = ConfirmationCertificate {
        signers,
        serialized_message: partial_sigs[0].msg.clone(),
        signature: agg.as_bytes().to_vec(),
    };

    let cert_bytes = match bincode::serialize(&cert) {
        Ok(b) => b,
        Err(_) => return ERROR_ENCODING_FAILED,
    };
    if cert_bytes.len() > out_capacity as usize {
        return ERROR_BUFFER_SIZE_MISMATCH;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(cert_bytes.as_ptr(), out_ptr, cert_bytes.len());
    }
    cert_bytes.len() as i32
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn get_encoder(handle: i32) -> Option<EncodingConfigEnum> {
    ENCODERS.with(|encoders| {
        let encoders = encoders.borrow();
        if handle < 0 || handle >= encoders.len() as i32 {
            return None;
        }
        Some(encoders[handle as usize].clone())
    })
}

/// Build a Walrus-style signers bit-array.
/// Matches `signersToWalrusBitmap` in `walrus.go`:
///   bitmap[idx/8] |= 1 << (idx % 8)
fn build_bitmap(indices: impl Iterator<Item = u8>, n_members: usize) -> Vec<u8> {
    let mut bitmap = vec![0u8; (n_members + 7) / 8];
    for idx in indices {
        let i = idx as usize;
        if i / 8 < bitmap.len() {
            bitmap[i / 8] |= 1 << (i % 8);
        }
    }
    bitmap
}