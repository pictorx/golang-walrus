use core::num::NonZeroU16;
use std::ffi::{c_int, c_uchar};
use std::ptr;
use std::slice;

// External Crates
use fastcrypto::bls12381::min_pk::{
    BLS12381AggregateSignature, BLS12381PublicKey, BLS12381Signature,
};
use fastcrypto::traits::{AggregateAuthenticator, ToFromBytes, VerifyingKey};
use walrus_core::encoding::{
    EncodingConfig, EncodingConfigEnum, EncodingFactory, Primary, SliverData,
};
use walrus_core::metadata::{BlobMetadata, BlobMetadataApi};
use walrus_core::{EncodingType};

/// Helper macro to safely unwind panics across FFI boundaries.
/// Returns -1 on panic.
macro_rules! ffi_wrap {
    ($body:block) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
            Ok(result) => result,
            Err(_) => -1,
        }
    };
}

/// Helper to convert raw C pointers to safe Rust slices
unsafe fn safe_slice<'a, T>(ptr: *const T, len: usize) -> Option<&'a [T]> {
    if ptr.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(ptr, len))
    }
}

// ==============================================================================================
// BLS12-381 Operations
// ==============================================================================================

#[no_mangle]
pub extern "C" fn bls12381_min_pk_verify(
    signature: *const c_uchar,
    sig_len: usize,
    public_key: *const c_uchar,
    pk_len: usize,
    msg: *const c_uchar,
    msg_len: usize,
) -> c_int {
    ffi_wrap!({
        unsafe {
            let sig_bytes = match safe_slice(signature, sig_len) {
                Some(s) => s,
                None => return -1,
            };
            let pk_bytes = match safe_slice(public_key, pk_len) {
                Some(s) => s,
                None => return -1,
            };
            let msg_bytes = match safe_slice(msg, msg_len) {
                Some(s) => s,
                None => return -1,
            };

            match BLS12381Signature::from_bytes(sig_bytes) {
                Ok(sig) => match BLS12381PublicKey::from_bytes(pk_bytes) {
                    Ok(pk) => {
                        if pk.verify(msg_bytes, &sig).is_ok() {
                            1 // Success: Valid
                        } else {
                            0 // Success: Invalid
                        }
                    }
                    Err(_) => -1, // Error: Bad Key Format
                },
                Err(_) => -1, // Error: Bad Sig Format
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn bls12381_min_pk_aggregate(
    num_sigs: usize,
    sig_ptrs: *const *const c_uchar,
    sig_lens: *const usize,
    out_agg: *mut *mut c_uchar,
    out_agg_len: *mut usize,
) -> c_int {
    ffi_wrap!({
        unsafe {
            if sig_ptrs.is_null() || sig_lens.is_null() || out_agg.is_null() || out_agg_len.is_null() {
                return -1;
            }

            let sig_ptrs_slice = slice::from_raw_parts(sig_ptrs, num_sigs);
            let sig_lens_slice = slice::from_raw_parts(sig_lens, num_sigs);

            let mut signatures = Vec::with_capacity(num_sigs);
            for i in 0..num_sigs {
                let sig_slice = slice::from_raw_parts(sig_ptrs_slice[i], sig_lens_slice[i]);
                match BLS12381Signature::from_bytes(sig_slice) {
                    Ok(sig) => signatures.push(sig),
                    Err(_) => return -1,
                }
            }

            match BLS12381AggregateSignature::aggregate(&signatures) {
                Ok(aggregate_signatures) => {
                    let mut bytes = aggregate_signatures.as_bytes().to_vec();
                    // We must use strict Vec capacity management for free_bytes to work
                    bytes.shrink_to_fit(); 
                    
                    *out_agg = bytes.as_mut_ptr();
                    *out_agg_len = bytes.len();
                    
                    std::mem::forget(bytes); // Handover ownership to C
                    0
                }
                Err(_) => -1,
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn bls12381_min_pk_verify_aggregate(
    num_pks: usize,
    pk_ptrs: *const *const c_uchar,
    pk_lens: *const usize,
    msg: *const c_uchar,
    msg_len: usize,
    signature: *const c_uchar,
    sig_len: usize,
) -> c_int {
    ffi_wrap!({
        unsafe {
            if pk_ptrs.is_null() || pk_lens.is_null() {
                return -1;
            }

            let pk_ptrs_slice = slice::from_raw_parts(pk_ptrs, num_pks);
            let pk_lens_slice = slice::from_raw_parts(pk_lens, num_pks);

            let mut public_keys = Vec::with_capacity(num_pks);
            for i in 0..num_pks {
                let pk_slice = slice::from_raw_parts(pk_ptrs_slice[i], pk_lens_slice[i]);
                match BLS12381PublicKey::from_bytes(pk_slice) {
                    Ok(pk) => public_keys.push(pk),
                    Err(_) => return -1,
                }
            }

            let msg_slice = match safe_slice(msg, msg_len) { Some(s) => s, None => return -1 };
            let sig_slice = match safe_slice(signature, sig_len) { Some(s) => s, None => return -1 };

            match BLS12381AggregateSignature::from_bytes(sig_slice) {
                Ok(sig) => {
                    if sig.verify(&public_keys, msg_slice).is_ok() {
                        1
                    } else {
                        0
                    }
                }
                Err(_) => -1,
            }
        }
    })
}

// ==============================================================================================
// Blob Encoding / Decoding
// ==============================================================================================

pub struct BlobEncoder {
    encoder: EncodingConfigEnum,
}

#[no_mangle]
pub extern "C" fn blob_encoder_new(n_shards: u16) -> *mut BlobEncoder {
    // Note: No FFI unwind safety needed for simple allocations usually, but strictly good practice.
    match NonZeroU16::new(n_shards) {
        Some(n) => {
            let config = EncodingConfig::new(n);
            let encoder = config.get_for_type(EncodingType::RS2);
            Box::into_raw(Box::new(BlobEncoder { encoder }))
        }
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn blob_encoder_free(ptr: *mut BlobEncoder) {
    if !ptr.is_null() {
        unsafe { let _ = Box::from_raw(ptr); }
    }
}

#[no_mangle]
pub extern "C" fn blob_encoder_encode(
    this: *mut BlobEncoder,
    data: *const c_uchar,
    data_len: usize,
    num_buffers: usize,
    primary_buffers: *const *mut c_uchar,
    primary_capacities: *const usize,
    secondary_buffers: *const *mut c_uchar,
    secondary_capacities: *const usize,
    out_result: *mut *mut c_uchar,
    out_result_len: *mut usize,
) -> c_int {
    ffi_wrap!({
        unsafe {
            if this.is_null() || data.is_null() || primary_buffers.is_null() || secondary_buffers.is_null() {
                return -1;
            }
            
            let encoder = &(*this).encoder;
            let data_vec = slice::from_raw_parts(data, data_len).to_vec();

            let (sliver_pairs, metadata) = match encoder.encode_with_metadata(data_vec) {
                Ok(res) => res,
                Err(_) => return -1,
            };

            if sliver_pairs.len() != num_buffers {
                return -1;
            }

            let prim_bufs = slice::from_raw_parts(primary_buffers, num_buffers);
            let prim_caps = slice::from_raw_parts(primary_capacities, num_buffers);
            let sec_bufs = slice::from_raw_parts(secondary_buffers, num_buffers);
            let sec_caps = slice::from_raw_parts(secondary_capacities, num_buffers);

            for (i, pair) in sliver_pairs.iter().enumerate() {
                if write_sliver_data_bcs(&pair.primary, prim_bufs[i], prim_caps[i]) != 0 {
                    return -1;
                }
                if write_sliver_data_bcs(&pair.secondary, sec_bufs[i], sec_caps[i]) != 0 {
                    return -1;
                }
            }

            let root_hash = match metadata.metadata() {
                BlobMetadata::V1(inner) => inner.compute_root_hash(),
            };

            let result_tuple = (metadata, root_hash);
            let mut serialized = match bcs::to_bytes(&result_tuple) {
                Ok(bytes) => bytes,
                Err(_) => return -1,
            };

            serialized.shrink_to_fit();
            *out_result = serialized.as_mut_ptr();
            *out_result_len = serialized.len();
            std::mem::forget(serialized);

            0
        }
    })
}

#[no_mangle]
pub extern "C" fn blob_encoder_compute_metadata(
    this: *mut BlobEncoder,
    data: *const c_uchar,
    data_len: usize,
    out_result: *mut *mut c_uchar,
    out_result_len: *mut usize,
) -> c_int {
    ffi_wrap!({
        unsafe {
            if this.is_null() || data.is_null() {
                return -1;
            }
            let encoder = &(*this).encoder;
            let data_vec = slice::from_raw_parts(data, data_len).to_vec();

            let metadata = match encoder.compute_metadata(&data_vec) {
                Ok(m) => m,
                Err(_) => return -1,
            };

            let blob_id = metadata.blob_id();
            let (root_hash, unencoded_length, encoding_type) = match metadata.metadata() {
                BlobMetadata::V1(inner) => (
                    inner.compute_root_hash(),
                    inner.unencoded_length,
                    inner.encoding_type,
                ),
            };

            let result_tuple = (blob_id, root_hash, unencoded_length, encoding_type);
            let mut serialized = match bcs::to_bytes(&result_tuple) {
                Ok(bytes) => bytes,
                Err(_) => return -1,
            };

            serialized.shrink_to_fit();
            *out_result = serialized.as_mut_ptr();
            *out_result_len = serialized.len();
            std::mem::forget(serialized);

            0
        }
    })
}

#[no_mangle]
pub extern "C" fn blob_encoder_decode(
    this: *mut BlobEncoder,
    blob_id: *const c_uchar,
    blob_size: u64,
    num_buffers: usize,
    bcs_buffer_ptrs: *const *const c_uchar,
    bcs_buffer_lens: *const usize,
    output_buffer: *mut c_uchar,
    output_capacity: u64,
) -> c_int {
    ffi_wrap!({
        unsafe {
            if this.is_null() || blob_id.is_null() || output_buffer.is_null() {
                return -1;
            }
            if output_capacity != blob_size {
                return -1;
            }

            let encoder = &(*this).encoder;

            let mut id_arr = [0u8; 32];
            ptr::copy_nonoverlapping(blob_id, id_arr.as_mut_ptr(), 32);
            // let blob_id_struct = BlobId(id_arr);

            let bcs_ptrs = slice::from_raw_parts(bcs_buffer_ptrs, num_buffers);
            let bcs_lens = slice::from_raw_parts(bcs_buffer_lens, num_buffers);

            let mut sliver_data: Vec<SliverData<Primary>> = Vec::with_capacity(num_buffers);
            for i in 0..num_buffers {
                let bytes = slice::from_raw_parts(bcs_ptrs[i], bcs_lens[i]);
                match bcs::from_bytes(bytes) {
                    Ok(sliver) => sliver_data.push(sliver),
                    Err(_) => return -1,
                }
            }

            match encoder.decode(blob_size, sliver_data) {
                Ok(decoded) => {
                    ptr::copy_nonoverlapping(decoded.as_ptr(), output_buffer, blob_size as usize);
                    0
                }
                Err(_) => -1,
            }
        }
    })
}

// Internal Helper
fn write_sliver_data_bcs<T: walrus_core::encoding::EncodingAxis>(
    sliver: &SliverData<T>,
    buffer: *mut c_uchar,
    capacity: usize,
) -> c_int {
    match bcs::to_bytes(sliver) {
        Ok(serialized) => {
            if serialized.len() > capacity {
                return -1; // Buffer too small
            }
            unsafe {
                ptr::copy_nonoverlapping(serialized.as_ptr(), buffer, serialized.len());
            }
            0
        }
        Err(_) => -1,
    }
}

// ==============================================================================================
// Memory Management
// ==============================================================================================

/// Frees a byte array allocated by Rust and returned to C/Go.
/// 
/// # Safety
/// This must ONLY be called with a pointer returned by this library's functions 
/// (specifically `out_result` arguments). 
/// The `len` must match exactly the length returned by the creating function.
#[no_mangle]
pub extern "C" fn free_bytes(ptr: *mut c_uchar, len: usize) {
    if !ptr.is_null() {
        unsafe {
            // We reconstruct the Vec using the length as the capacity,
            // because we called shrink_to_fit() before forgetting the vector.
            let _ = Vec::from_raw_parts(ptr, len, len);
        }
    }
}

#[no_mangle]
pub extern "C" fn blob_encoder_get_sliver_size(
    this: *mut BlobEncoder,
    // data_len: usize,
) -> usize {
    unsafe {
        if this.is_null() {
            return 0;
        }

        // FIX: The variant name in walrus-core for RS2 is 'ReedSolomon'
        match &(*this).encoder {
            EncodingConfigEnum::ReedSolomon(inner) => inner.max_sliver_size() as usize,
            // This ensures the code compiles even if Walrus adds more types later
            //_ => 0, 
        }
    }
}