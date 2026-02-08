use core::num::NonZeroU16;
use std::slice;

use fastcrypto::bls12381::min_pk::BLS12381AggregateSignature;
use fastcrypto::bls12381::min_pk::{BLS12381PublicKey, BLS12381Signature};
use fastcrypto::traits::AggregateAuthenticator;
use fastcrypto::traits::ToFromBytes;
use fastcrypto::traits::VerifyingKey;

use walrus_core::encoding::{
    EncodingConfig, EncodingConfigEnum, EncodingFactory, Primary, SliverData,
};
use walrus_core::metadata::{BlobMetadata, BlobMetadataApi};
use walrus_core::{BlobId, EncodingType};

// Error codes for return values
const SUCCESS: i32 = 0;
const ERROR_INVALID_SIGNATURE: i32 = -1;
const ERROR_INVALID_PUBLIC_KEY: i32 = -2;
const ERROR_VERIFICATION_FAILED: i32 = -3;
const ERROR_AGGREGATION_FAILED: i32 = -4;
const ERROR_DESERIALIZATION_FAILED: i32 = -5;
const ERROR_ENCODING_FAILED: i32 = -6;
const ERROR_BUFFER_SIZE_MISMATCH: i32 = -7;
const ERROR_INVALID_SHARDS: i32 = -8;
const ERROR_DECODING_FAILED: i32 = -9;

// Memory management helpers
#[no_mangle]
pub extern "C" fn allocate(size: u32) -> *mut u8 {
    let mut buf = Vec::with_capacity(size as usize);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

#[no_mangle]
pub extern "C" fn deallocate(ptr: *mut u8, size: u32) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr, size as usize, size as usize);
    }
}

// BLS12381 Functions

/// Verify a BLS12381 signature
/// Returns: 1 if valid, 0 if invalid, negative error code on error
#[no_mangle]
pub extern "C" fn bls12381_min_pk_verify(
    signature_ptr: *const u8,
    signature_len: u32,
    public_key_ptr: *const u8,
    public_key_len: u32,
    msg_ptr: *const u8,
    msg_len: u32,
) -> i32 {
    let signature_bytes = unsafe { slice::from_raw_parts(signature_ptr, signature_len as usize) };
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

/// Aggregate BLS12381 signatures
/// Input: serialized Vec<Vec<u8>> (using bincode or similar)
/// Output: writes aggregated signature to output buffer
/// Returns: length of output on success, negative error code on failure
#[no_mangle]
pub extern "C" fn bls12381_min_pk_aggregate(
    signatures_ptr: *const u8,
    signatures_len: u32,
    output_ptr: *mut u8,
    output_capacity: u32,
) -> i32 {
    let signatures_bytes =
        unsafe { slice::from_raw_parts(signatures_ptr, signatures_len as usize) };

    // Deserialize Vec<Vec<u8>>
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

    let aggregate_signature = match BLS12381AggregateSignature::aggregate(&signatures) {
        Ok(agg) => agg,
        Err(_) => return ERROR_AGGREGATION_FAILED,
    };

    let result_bytes = aggregate_signature.as_bytes().to_vec();
    
    if result_bytes.len() > output_capacity as usize {
        return ERROR_BUFFER_SIZE_MISMATCH;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(
            result_bytes.as_ptr(),
            output_ptr,
            result_bytes.len(),
        );
    }

    result_bytes.len() as i32
}

/// Verify an aggregate BLS12381 signature
/// Returns: 1 if valid, 0 if invalid, negative error code on error
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
    let signature_bytes = unsafe { slice::from_raw_parts(signature_ptr, signature_len as usize) };

    // Deserialize Vec<Vec<u8>>
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

// Encoder Functions

/// Create encoder configuration
/// Returns: encoder handle (index), or negative error code on failure
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

/// Get the maximum size of BCS-encoded slivers for allocation purposes
/// This returns a conservative estimate that will fit any sliver
/// Returns: size in bytes, or negative error code on failure
#[no_mangle]
pub extern "C" fn encoder_get_sliver_size(
    encoder_handle: i32,
    data_ptr: *const u8,
    data_len: u32,
) -> i32 {
    let data_vec = unsafe { slice::from_raw_parts(data_ptr, data_len as usize) }.to_vec();

    let encoder = ENCODERS.with(|encoders| {
        let encoders = encoders.borrow();
        if encoder_handle < 0 || encoder_handle >= encoders.len() as i32 {
            return None;
        }
        Some(encoders[encoder_handle as usize].clone())
    });

    let encoder = match encoder {
        Some(e) => e,
        None => return ERROR_ENCODING_FAILED,
    };

    let (sliver_pairs, _) = match encoder.encode_with_metadata(data_vec) {
        Ok(result) => result,
        Err(_) => return ERROR_ENCODING_FAILED,
    };

    if sliver_pairs.is_empty() {
        return ERROR_ENCODING_FAILED;
    }

    // Find the maximum size across all slivers to ensure buffers are big enough
    let mut max_size = 0;
    for sliver_pair in sliver_pairs.iter() {
        let primary_serialized = match bcs::to_bytes(&sliver_pair.primary) {
            Ok(s) => s,
            Err(_) => return ERROR_ENCODING_FAILED,
        };
        let secondary_serialized = match bcs::to_bytes(&sliver_pair.secondary) {
            Ok(s) => s,
            Err(_) => return ERROR_ENCODING_FAILED,
        };
        max_size = max_size.max(primary_serialized.len());
        max_size = max_size.max(secondary_serialized.len());
    }

    max_size as i32
}

/// Encode data
/// Returns: actual metadata size written on success, negative error code on failure
/// Note: The length arrays are updated in-place with actual bytes written per buffer
#[no_mangle]
pub extern "C" fn encoder_encode(
    encoder_handle: i32,
    data_ptr: *const u8,
    data_len: u32,
    primary_buffers_ptr: *const *mut u8,
    primary_buffer_lens: *mut u32,  // Mutable - we write back actual sizes
    secondary_buffers_ptr: *const *mut u8,
    secondary_buffer_lens: *mut u32,  // Mutable - we write back actual sizes
    num_buffers: u32,
    output_metadata_ptr: *mut u8,
    output_metadata_capacity: u32,
) -> i32 {
    let data_vec = unsafe { slice::from_raw_parts(data_ptr, data_len as usize) }.to_vec();

    let encoder = ENCODERS.with(|encoders| {
        let encoders = encoders.borrow();
        if encoder_handle < 0 || encoder_handle >= encoders.len() as i32 {
            return None;
        }
        Some(encoders[encoder_handle as usize].clone())
    });

    let encoder = match encoder {
        Some(e) => e,
        None => return ERROR_ENCODING_FAILED,
    };

    let (sliver_pairs, metadata) = match encoder.encode_with_metadata(data_vec) {
        Ok(result) => result,
        Err(_) => return ERROR_ENCODING_FAILED,
    };

    if sliver_pairs.len() != num_buffers as usize {
        return ERROR_BUFFER_SIZE_MISMATCH;
    }

    let primary_buffers =
        unsafe { slice::from_raw_parts(primary_buffers_ptr, num_buffers as usize) };
    let primary_lens = unsafe { slice::from_raw_parts_mut(primary_buffer_lens, num_buffers as usize) };
    let secondary_buffers =
        unsafe { slice::from_raw_parts(secondary_buffers_ptr, num_buffers as usize) };
    let secondary_lens =
        unsafe { slice::from_raw_parts_mut(secondary_buffer_lens, num_buffers as usize) };

    // Write BCS-encoded slivers to buffers
    for (i, sliver_pair) in sliver_pairs.iter().enumerate() {
        let primary_serialized = match bcs::to_bytes(&sliver_pair.primary) {
            Ok(s) => s,
            Err(_) => return ERROR_ENCODING_FAILED,
        };

        // Check if buffer is big enough
        if primary_serialized.len() > primary_lens[i] as usize {
            return ERROR_BUFFER_SIZE_MISMATCH;
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                primary_serialized.as_ptr(),
                primary_buffers[i],
                primary_serialized.len(),
            );
        }
        
        // Write back the actual size used
        primary_lens[i] = primary_serialized.len() as u32;

        let secondary_serialized = match bcs::to_bytes(&sliver_pair.secondary) {
            Ok(s) => s,
            Err(_) => return ERROR_ENCODING_FAILED,
        };

        // Check if buffer is big enough
        if secondary_serialized.len() > secondary_lens[i] as usize {
            return ERROR_BUFFER_SIZE_MISMATCH;
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                secondary_serialized.as_ptr(),
                secondary_buffers[i],
                secondary_serialized.len(),
            );
        }
        
        // Write back the actual size used
        secondary_lens[i] = secondary_serialized.len() as u32;
    }

    // Serialize metadata
    let root_hash = match metadata.metadata() {
        BlobMetadata::V1(inner) => inner.compute_root_hash(),
    };

    let metadata_output = (metadata, root_hash);
    let serialized_metadata = match bincode::serialize(&metadata_output) {
        Ok(s) => s,
        Err(_) => return ERROR_ENCODING_FAILED,
    };

    if serialized_metadata.len() > output_metadata_capacity as usize {
        return ERROR_BUFFER_SIZE_MISMATCH;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(
            serialized_metadata.as_ptr(),
            output_metadata_ptr,
            serialized_metadata.len(),
        );
    }

    // Return actual metadata size written
    serialized_metadata.len() as i32
}

/// Compute metadata without encoding
/// Returns: length of output on success, negative error code on failure
#[no_mangle]
pub extern "C" fn encoder_compute_metadata(
    encoder_handle: i32,
    data_ptr: *const u8,
    data_len: u32,
    output_ptr: *mut u8,
    output_capacity: u32,
) -> i32 {
    let data_vec = unsafe { slice::from_raw_parts(data_ptr, data_len as usize) }.to_vec();

    let encoder = ENCODERS.with(|encoders| {
        let encoders = encoders.borrow();
        if encoder_handle < 0 || encoder_handle >= encoders.len() as i32 {
            return None;
        }
        Some(encoders[encoder_handle as usize].clone())
    });

    let encoder = match encoder {
        Some(e) => e,
        None => return ERROR_ENCODING_FAILED,
    };

    let metadata = match encoder.compute_metadata(&data_vec) {
        Ok(m) => m,
        Err(_) => return ERROR_ENCODING_FAILED,
    };

    let blob_id = metadata.blob_id();
    let (root_hash, unencoded_length, encoding_type) = match metadata.metadata() {
        BlobMetadata::V1(inner) => (
            inner.compute_root_hash(),
            inner.unencoded_length,
            inner.encoding_type,
        ),
    };

    let output_data = (blob_id, root_hash, unencoded_length, encoding_type);
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

/// Decode blob from BCS-encoded SliverData buffers
/// Returns: SUCCESS on success, negative error code on failure
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
    if output_buffer_len as u64 != blob_size {
        return ERROR_BUFFER_SIZE_MISMATCH;
    }

    let blob_id_bytes = unsafe { slice::from_raw_parts(blob_id_ptr, blob_id_len as usize) };
    let _blob_id: BlobId = match bincode::deserialize(blob_id_bytes) {
        Ok(id) => id,
        Err(_) => return ERROR_DESERIALIZATION_FAILED,
    };

    let encoder = ENCODERS.with(|encoders| {
        let encoders = encoders.borrow();
        if encoder_handle < 0 || encoder_handle >= encoders.len() as i32 {
            return None;
        }
        Some(encoders[encoder_handle as usize].clone())
    });

    let encoder = match encoder {
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

/// Destroy encoder instance
#[no_mangle]
pub extern "C" fn encoder_destroy(encoder_handle: i32) -> i32 {
    ENCODERS.with(|encoders| {
        let encoders = encoders.borrow_mut();
        if encoder_handle < 0 || encoder_handle >= encoders.len() as i32 {
            return ERROR_ENCODING_FAILED;
        }
        SUCCESS
    })
}

/// Get the actual size of the metadata for a given data set
/// Returns: size in bytes, or negative error code on failure
#[no_mangle]
pub extern "C" fn encoder_get_metadata_size(
    encoder_handle: i32,
    data_ptr: *const u8,
    data_len: u32,
) -> i32 {
    let data_vec = unsafe { slice::from_raw_parts(data_ptr, data_len as usize) }.to_vec();

    let encoder = ENCODERS.with(|encoders| {
        let encoders = encoders.borrow();
        if encoder_handle < 0 || encoder_handle >= encoders.len() as i32 {
            return None;
        }
        Some(encoders[encoder_handle as usize].clone())
    });

    let encoder = match encoder {
        Some(e) => e,
        None => return ERROR_ENCODING_FAILED,
    };

    // We only need the metadata here
    let (_, metadata) = match encoder.encode_with_metadata(data_vec) {
        Ok(result) => result,
        Err(_) => return ERROR_ENCODING_FAILED,
    };

    // Serialize metadata exactly as encoder_encode does
    let root_hash = match metadata.metadata() {
        BlobMetadata::V1(inner) => inner.compute_root_hash(),
    };

    let metadata_output = (metadata, root_hash);
    let serialized_metadata = match bincode::serialize(&metadata_output) {
        Ok(s) => s,
        Err(_) => return ERROR_ENCODING_FAILED,
    };

    serialized_metadata.len() as i32
}

// Thread-local storage for encoders
use std::cell::RefCell;
thread_local! {
    static ENCODERS: RefCell<Vec<EncodingConfigEnum>> = RefCell::new(Vec::new());
}