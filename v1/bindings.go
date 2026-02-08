package golangwalrus

/*
#cgo LDFLAGS: -L./target/release -lwalrus_app
#include <stdlib.h>
#include <stdint.h>

// --- BLS Functions ---
int32_t bls12381_min_pk_verify(const uint8_t* signature, size_t sig_len, const uint8_t* public_key, size_t pk_len, const uint8_t* msg, size_t msg_len);
int32_t bls12381_min_pk_aggregate(size_t num_sigs, const uint8_t** sig_ptrs, const size_t* sig_lens, uint8_t** out_agg, size_t* out_agg_len);
int32_t bls12381_min_pk_verify_aggregate(size_t num_pks, const uint8_t** pk_ptrs, const size_t* pk_lens, const uint8_t* msg, size_t msg_len, const uint8_t* signature, size_t sig_len);

// --- Blob Encoder Functions ---
typedef struct BlobEncoder BlobEncoder;
BlobEncoder* blob_encoder_new(uint16_t n_shards);
void blob_encoder_free(BlobEncoder* ptr);

int32_t blob_encoder_encode(
    BlobEncoder* this,
    const uint8_t* data, size_t data_len,
    size_t num_buffers,
    uint8_t** primary_buffers, size_t* primary_capacities,
    uint8_t** secondary_buffers, size_t* secondary_capacities,
    uint8_t** out_result, size_t* out_result_len
);

int32_t blob_encoder_compute_metadata(BlobEncoder* this, const uint8_t* data, size_t data_len, uint8_t** out_result, size_t* out_result_len);

ssize_t blob_encoder_get_sliver_size(BlobEncoder* this);

int32_t blob_encoder_decode(
    BlobEncoder* this,
    const uint8_t* blob_id, uint64_t blob_size,
    size_t num_buffers,
    const uint8_t** bcs_buffer_ptrs, const size_t* bcs_buffer_lens,
    uint8_t* output_buffer, uint64_t output_capacity
);

void free_bytes(uint8_t* ptr, size_t len);
*/
import "C"
import (
	"errors"
	"unsafe"
)

// =============================================================================
// BLS12-381 Wrappers
// =============================================================================

func BlsVerify(signature, publicKey, msg []byte) (bool, error) {
	if len(signature) == 0 || len(publicKey) == 0 {
		return false, errors.New("empty signature or public key")
	}

	// unsafe.Pointer(&slice[0]) gets the pointer to the underlying array
	sigPtr := (*C.uint8_t)(unsafe.Pointer(&signature[0]))
	pkPtr := (*C.uint8_t)(unsafe.Pointer(&publicKey[0]))

	var msgPtr *C.uint8_t
	if len(msg) > 0 {
		msgPtr = (*C.uint8_t)(unsafe.Pointer(&msg[0]))
	}

	res := C.bls12381_min_pk_verify(
		sigPtr, C.size_t(len(signature)),
		pkPtr, C.size_t(len(publicKey)),
		msgPtr, C.size_t(len(msg)),
	)

	if res == 1 {
		return true, nil
	} else if res == 0 {
		return false, nil
	}
	return false, errors.New("verification internal error")
}

func BlsAggregate(signatures [][]byte) ([]byte, error) {
	if len(signatures) == 0 {
		return nil, errors.New("no signatures to aggregate")
	}

	// We must build C-compatible arrays of pointers and lengths
	cSigPtrs := make([]*C.uint8_t, len(signatures))
	cSigLens := make([]C.size_t, len(signatures))

	for i, sig := range signatures {
		if len(sig) == 0 {
			return nil, errors.New("encountered empty signature")
		}
		cSigPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&sig[0]))
		cSigLens[i] = C.size_t(len(sig))
	}

	var outPtr *C.uint8_t
	var outLen C.size_t

	res := C.bls12381_min_pk_aggregate(
		C.size_t(len(signatures)),
		&cSigPtrs[0],
		&cSigLens[0],
		&outPtr,
		&outLen,
	)

	if res != 0 {
		return nil, errors.New("aggregation failed")
	}

	// Important: Free the memory allocated by Rust after copying it to Go
	defer C.free_bytes(outPtr, outLen)
	return C.GoBytes(unsafe.Pointer(outPtr), C.int(outLen)), nil
}

// =============================================================================
// Blob Encoder Wrappers
// =============================================================================

type BlobEncoder struct {
	ptr *C.BlobEncoder
}

func NewBlobEncoder(nShards uint16) (*BlobEncoder, error) {
	ptr := C.blob_encoder_new(C.uint16_t(nShards))
	if ptr == nil {
		return nil, errors.New("failed to create blob encoder")
	}
	return &BlobEncoder{ptr: ptr}, nil
}

func (be *BlobEncoder) Close() {
	if be.ptr != nil {
		C.blob_encoder_free(be.ptr)
		be.ptr = nil
	}
}

type EncodeResult struct {
	PrimaryShards   [][]byte
	SecondaryShards [][]byte
	Metadata        []byte
}

/*
	func (be *BlobEncoder) Encode(data []byte, numBuffers int, shardCapacity int) (*EncodeResult, error) {
		if be.ptr == nil {
			return nil, errors.New("encoder is closed")
		}

		// 1. Allocate C buffers for the shards.
		// We use C.malloc because Go's Garbage Collector moves Go memory.
		// Passing Go pointers for Rust to WRITE into is risky without pinning.
		// C.malloc memory is stable.

		primaryPtrs := make([]*C.uint8_t, numBuffers)
		primaryCaps := make([]C.size_t, numBuffers)
		secondaryPtrs := make([]*C.uint8_t, numBuffers)
		secondaryCaps := make([]C.size_t, numBuffers)

		for i := 0; i < numBuffers; i++ {
			primaryPtrs[i] = (*C.uint8_t)(C.malloc(C.size_t(shardCapacity)))
			secondaryPtrs[i] = (*C.uint8_t)(C.malloc(C.size_t(shardCapacity)))

			if primaryPtrs[i] == nil || secondaryPtrs[i] == nil {
				return nil, errors.New("c malloc failed")
			}

			// Ensure we free these C buffers when this function exits
			defer C.free(unsafe.Pointer(primaryPtrs[i]))
			defer C.free(unsafe.Pointer(secondaryPtrs[i]))

			primaryCaps[i] = C.size_t(shardCapacity)
			secondaryCaps[i] = C.size_t(shardCapacity)
		}

		var outResPtr *C.uint8_t
		var outResLen C.size_t
		dataPtr := (*C.uint8_t)(unsafe.Pointer(&data[0]))

		// 2. Call Rust
		res := C.blob_encoder_encode(
			be.ptr,
			dataPtr, C.size_t(len(data)),
			C.size_t(numBuffers),
			&primaryPtrs[0], &primaryCaps[0],
			&secondaryPtrs[0], &secondaryCaps[0],
			&outResPtr, &outResLen,
		)

		if res != 0 {
			return nil, errors.New("encoding failed")
		}

		// 3. Copy from C buffers to Go slices
		result := &EncodeResult{
			PrimaryShards:   make([][]byte, numBuffers),
			SecondaryShards: make([][]byte, numBuffers),
		}

		for i := 0; i < numBuffers; i++ {
			result.PrimaryShards[i] = C.GoBytes(unsafe.Pointer(primaryPtrs[i]), C.int(shardCapacity))
			result.SecondaryShards[i] = C.GoBytes(unsafe.Pointer(secondaryPtrs[i]), C.int(shardCapacity))
		}

		// Free the result metadata allocated by Rust
		defer C.free_bytes(outResPtr, outResLen)
		result.Metadata = C.GoBytes(unsafe.Pointer(outResPtr), C.int(outResLen))

		return result, nil
	}
*/
func (be *BlobEncoder) ComputeMetadata(data []byte) ([]byte, error) {
	if be.ptr == nil {
		return nil, errors.New("encoder is closed")
	}

	var outPtr *C.uint8_t
	var outLen C.size_t
	dataPtr := (*C.uint8_t)(unsafe.Pointer(&data[0]))

	res := C.blob_encoder_compute_metadata(be.ptr, dataPtr, C.size_t(len(data)), &outPtr, &outLen)
	if res != 0 {
		return nil, errors.New("failed to compute metadata")
	}

	defer C.free_bytes(outPtr, outLen)
	return C.GoBytes(unsafe.Pointer(outPtr), C.int(outLen)), nil
}

/*func (be *BlobEncoder) Encode(data []byte, numBuffers int) (*EncodeResult, error) {
	if be.ptr == nil {
		return nil, errors.New("encoder is closed")
	}

	// 1. Get the exact size needed per sliver from Rust
	shardSize := int(C.blob_encoder_get_sliver_size(be.ptr))
	if shardSize <= 0 {
		return nil, errors.New("failed to calculate sliver size")
	}

	// numBuffers := numBuffers

	// Preparation for C arrays
	primaryPtrs := make([]*C.uint8_t, numBuffers)
	primaryCaps := make([]C.size_t, numBuffers)
	secondaryPtrs := make([]*C.uint8_t, numBuffers)
	secondaryCaps := make([]C.size_t, numBuffers)

	// 2. Allocate stable C memory for 1000 shards
	for i := 0; i < numBuffers; i++ {
		primaryPtrs[i] = (*C.uint8_t)(C.malloc(C.size_t(shardSize)))
		secondaryPtrs[i] = (*C.uint8_t)(C.malloc(C.size_t(shardSize)))

		if primaryPtrs[i] == nil || secondaryPtrs[i] == nil {
			return nil, errors.New("system out of memory for C allocation")
		}

		// Crucial: Ensure memory is freed even if Go panics
		defer C.free(unsafe.Pointer(primaryPtrs[i]))
		defer C.free(unsafe.Pointer(secondaryPtrs[i]))

		primaryCaps[i] = C.size_t(shardSize)
		secondaryCaps[i] = C.size_t(shardSize)
	}

	var outResPtr *C.uint8_t
	var outResLen C.size_t
	dataPtr := (*C.uint8_t)(unsafe.Pointer(&data[0]))

	// 3. Perform the Walrus Encoding
	res := C.blob_encoder_encode(
		be.ptr, dataPtr, C.size_t(len(data)),
		C.size_t(numBuffers),
		&primaryPtrs[0], &primaryCaps[0],
		&secondaryPtrs[0], &secondaryCaps[0],
		&outResPtr, &outResLen,
	)

	if res != 0 {
		return nil, errors.New("rust encoder failed")
	}

	// 4. Move data back to Go-managed memory
	result := &EncodeResult{
		PrimaryShards:   make([][]byte, numBuffers),
		SecondaryShards: make([][]byte, numBuffers),
	}

	for i := 0; i < numBuffers; i++ {
		result.PrimaryShards[i] = C.GoBytes(unsafe.Pointer(primaryPtrs[i]), C.int(shardSize))
		result.SecondaryShards[i] = C.GoBytes(unsafe.Pointer(secondaryPtrs[i]), C.int(shardSize))
	}

	// Clean up the metadata pointer returned by Rust
	defer C.free_bytes(outResPtr, outResLen)
	result.Metadata = C.GoBytes(unsafe.Pointer(outResPtr), C.int(outResLen))

	return result, nil
}
*/

func (be *BlobEncoder) Encode(data []byte, numBuffers int) (*EncodeResult, error) {
	if be.ptr == nil {
		return nil, errors.New("encoder is closed")
	}

	shardSize := int(C.blob_encoder_get_sliver_size(be.ptr))
	if shardSize <= 0 {
		return nil, errors.New("failed to calculate sliver size")
	}

	numShards := numBuffers
	totalBytesPerType := shardSize * numShards

	// 1. ALLOCATE BULK: Only 2 mallocs instead of 2000
	// This is much faster and more stable for the OS.
	primaryBulk := (*C.uint8_t)(C.malloc(C.size_t(totalBytesPerType)))
	secondaryBulk := (*C.uint8_t)(C.malloc(C.size_t(totalBytesPerType)))

	if primaryBulk == nil || secondaryBulk == nil {
		if primaryBulk != nil {
			C.free(unsafe.Pointer(primaryBulk))
		}
		if secondaryBulk != nil {
			C.free(unsafe.Pointer(secondaryBulk))
		}
		return nil, errors.New("out of memory for bulk allocation")
	}
	// Only 2 defers total!
	defer C.free(unsafe.Pointer(primaryBulk))
	defer C.free(unsafe.Pointer(secondaryBulk))

	// 2. PREPARE POINTER ARRAYS: Map the bulk memory to individual pointers
	primaryPtrs := make([]*C.uint8_t, numShards)
	secondaryPtrs := make([]*C.uint8_t, numShards)
	caps := make([]C.size_t, numShards)

	for i := 0; i < numShards; i++ {
		// Offset the pointer by (index * shardSize)
		offset := uintptr(i) * uintptr(shardSize)
		primaryPtrs[i] = (*C.uint8_t)(unsafe.Pointer(uintptr(unsafe.Pointer(primaryBulk)) + offset))
		secondaryPtrs[i] = (*C.uint8_t)(unsafe.Pointer(uintptr(unsafe.Pointer(secondaryBulk)) + offset))
		caps[i] = C.size_t(shardSize)
	}

	var outResPtr *C.uint8_t
	var outResLen C.size_t
	dataPtr := (*C.uint8_t)(unsafe.Pointer(&data[0]))

	// 3. CALL RUST
	res := C.blob_encoder_encode(
		be.ptr, dataPtr, C.size_t(len(data)),
		C.size_t(numShards),
		&primaryPtrs[0], &caps[0],
		&secondaryPtrs[0], &caps[0],
		&outResPtr, &outResLen,
	)

	if res != 0 {
		return nil, errors.New("rust encoding logic failed")
	}

	// 4. COLLECT RESULTS: Convert C memory back to Go slices
	result := &EncodeResult{
		PrimaryShards:   make([][]byte, numShards),
		SecondaryShards: make([][]byte, numShards),
	}

	for i := 0; i < numShards; i++ {
		// Use GoBytes to copy the specific segment of the bulk memory
		offset := i * shardSize
		pSeg := unsafe.Pointer(uintptr(unsafe.Pointer(primaryBulk)) + uintptr(offset))
		sSeg := unsafe.Pointer(uintptr(unsafe.Pointer(secondaryBulk)) + uintptr(offset))

		result.PrimaryShards[i] = C.GoBytes(pSeg, C.int(shardSize))
		result.SecondaryShards[i] = C.GoBytes(sSeg, C.int(shardSize))
	}

	defer C.free_bytes(outResPtr, outResLen)
	result.Metadata = C.GoBytes(unsafe.Pointer(outResPtr), C.int(outResLen))

	return result, nil
}
