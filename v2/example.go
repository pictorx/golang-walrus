package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// Error codes matching Rust implementation
const (
	SUCCESS                      = 0
	ERROR_INVALID_SIGNATURE      = -1
	ERROR_INVALID_PUBLIC_KEY     = -2
	ERROR_VERIFICATION_FAILED    = -3
	ERROR_AGGREGATION_FAILED     = -4
	ERROR_DESERIALIZATION_FAILED = -5
	ERROR_ENCODING_FAILED        = -6
	ERROR_BUFFER_SIZE_MISMATCH   = -7
	ERROR_INVALID_SHARDS         = -8
	ERROR_DECODING_FAILED        = -9
)

type WalrusWASM struct {
	ctx    context.Context
	module api.Module
}

func NewWalrusWASM(ctx context.Context, wasmPath string) (*WalrusWASM, error) {
	// Create runtime
	r := wazero.NewRuntime(ctx)

	// Instantiate WASI
	_, err := wasi_snapshot_preview1.Instantiate(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate WASI: %w", err)
	}

	// Load WASM module
	wasmBytes, err := os.ReadFile(wasmPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read WASM file: %w", err)
	}

	// Instantiate module
	mod, err := r.InstantiateWithConfig(ctx, wasmBytes,
		wazero.NewModuleConfig().WithName("walrus"))
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate module: %w", err)
	}

	return &WalrusWASM{
		ctx:    ctx,
		module: mod,
	}, nil
}

func (w *WalrusWASM) Close() error {
	return w.module.Close(w.ctx)
}

// Allocate memory in WASM module
func (w *WalrusWASM) allocate(size uint32) (uint32, error) {
	allocate := w.module.ExportedFunction("allocate")
	result, err := allocate.Call(w.ctx, uint64(size))
	if err != nil {
		return 0, err
	}
	return uint32(result[0]), nil
}

// Deallocate memory in WASM module
func (w *WalrusWASM) deallocate(ptr uint32, size uint32) error {
	deallocate := w.module.ExportedFunction("deallocate")
	_, err := deallocate.Call(w.ctx, uint64(ptr), uint64(size))
	return err
}

// Write data to WASM memory and return pointer
func (w *WalrusWASM) writeBytes(data []byte) (uint32, error) {
	ptr, err := w.allocate(uint32(len(data)))
	if err != nil {
		return 0, err
	}

	if !w.module.Memory().Write(ptr, data) {
		w.deallocate(ptr, uint32(len(data)))
		return 0, fmt.Errorf("failed to write to WASM memory")
	}

	return ptr, nil
}

// Read data from WASM memory
func (w *WalrusWASM) readBytes(ptr uint32, size uint32) ([]byte, error) {
	data, ok := w.module.Memory().Read(ptr, size)
	if !ok {
		return nil, fmt.Errorf("failed to read from WASM memory")
	}
	return data, nil
}

// BLS12381 signature verification
func (w *WalrusWASM) VerifyBLS12381(signature, publicKey, message []byte) (bool, error) {
	verify := w.module.ExportedFunction("bls12381_min_pk_verify")

	// Allocate and write signature
	sigPtr, err := w.writeBytes(signature)
	if err != nil {
		return false, err
	}
	defer w.deallocate(sigPtr, uint32(len(signature)))

	// Allocate and write public key
	pkPtr, err := w.writeBytes(publicKey)
	if err != nil {
		return false, err
	}
	defer w.deallocate(pkPtr, uint32(len(publicKey)))

	// Allocate and write message
	msgPtr, err := w.writeBytes(message)
	if err != nil {
		return false, err
	}
	defer w.deallocate(msgPtr, uint32(len(message)))

	// Call verify function
	result, err := verify.Call(w.ctx,
		uint64(sigPtr), uint64(len(signature)),
		uint64(pkPtr), uint64(len(publicKey)),
		uint64(msgPtr), uint64(len(message)))
	if err != nil {
		return false, err
	}

	code := int32(result[0])
	if code == 1 {
		return true, nil
	} else if code == 0 {
		return false, nil
	} else {
		return false, fmt.Errorf("verification error: code %d", code)
	}
}

// Simple bincode serialization for Vec<Vec<u8>>
func serializeVecVecU8(vecs [][]byte) []byte {
	// Calculate total size
	size := 8 // length prefix
	for _, v := range vecs {
		size += 8 + len(v) // length + data
	}

	buf := make([]byte, size)
	offset := 0

	// Write vector count
	binary.LittleEndian.PutUint64(buf[offset:], uint64(len(vecs)))
	offset += 8

	// Write each vector
	for _, v := range vecs {
		binary.LittleEndian.PutUint64(buf[offset:], uint64(len(v)))
		offset += 8
		copy(buf[offset:], v)
		offset += len(v)
	}

	return buf
}

// Aggregate BLS12381 signatures
func (w *WalrusWASM) AggregateBLS12381(signatures [][]byte) ([]byte, error) {
	aggregate := w.module.ExportedFunction("bls12381_min_pk_aggregate")

	// Serialize signatures
	serialized := serializeVecVecU8(signatures)
	sigPtr, err := w.writeBytes(serialized)
	if err != nil {
		return nil, err
	}
	defer w.deallocate(sigPtr, uint32(len(serialized)))

	// Allocate output buffer (BLS12381 aggregate signature is 96 bytes)
	outputSize := uint32(96)
	outputPtr, err := w.allocate(outputSize)
	if err != nil {
		return nil, err
	}
	defer w.deallocate(outputPtr, outputSize)

	// Call aggregate function
	result, err := aggregate.Call(w.ctx,
		uint64(sigPtr), uint64(len(serialized)),
		uint64(outputPtr), uint64(outputSize))
	if err != nil {
		return nil, err
	}

	code := int32(result[0])
	if code < 0 {
		return nil, fmt.Errorf("aggregation error: code %d", code)
	}

	// Read result
	return w.readBytes(outputPtr, uint32(code))
}

// Verify aggregate BLS12381 signature
func (w *WalrusWASM) VerifyAggregateBLS12381(publicKeys [][]byte, message, signature []byte) (bool, error) {
	verifyAgg := w.module.ExportedFunction("bls12381_min_pk_verify_aggregate")

	// Serialize public keys
	serialized := serializeVecVecU8(publicKeys)
	pkPtr, err := w.writeBytes(serialized)
	if err != nil {
		return false, err
	}
	defer w.deallocate(pkPtr, uint32(len(serialized)))

	// Write message
	msgPtr, err := w.writeBytes(message)
	if err != nil {
		return false, err
	}
	defer w.deallocate(msgPtr, uint32(len(message)))

	// Write signature
	sigPtr, err := w.writeBytes(signature)
	if err != nil {
		return false, err
	}
	defer w.deallocate(sigPtr, uint32(len(signature)))

	// Call verify function
	result, err := verifyAgg.Call(w.ctx,
		uint64(pkPtr), uint64(len(serialized)),
		uint64(msgPtr), uint64(len(message)),
		uint64(sigPtr), uint64(len(signature)))
	if err != nil {
		return false, err
	}

	code := int32(result[0])
	if code == 1 {
		return true, nil
	} else if code == 0 {
		return false, nil
	} else {
		return false, fmt.Errorf("verification error: code %d", code)
	}
}

// Create encoder
func (w *WalrusWASM) CreateEncoder(nShards uint16) (int32, error) {
	create := w.module.ExportedFunction("encoder_create")
	result, err := create.Call(w.ctx, uint64(nShards))
	if err != nil {
		return 0, err
	}

	handle := int32(result[0])
	if handle < 0 {
		return 0, fmt.Errorf("encoder creation failed: code %d", handle)
	}

	return handle, nil
}

// Destroy encoder
func (w *WalrusWASM) DestroyEncoder(handle int32) error {
	destroy := w.module.ExportedFunction("encoder_destroy")
	_, err := destroy.Call(w.ctx, uint64(handle))
	return err
}

// GetSliverSize calculates the required buffer size for a single shard
func (w *WalrusWASM) GetSliverSize(handle int32, data []byte) (int32, error) {
	getSliverSize := w.module.ExportedFunction("encoder_get_sliver_size")

	// Write data to WASM memory
	dataPtr, err := w.writeBytes(data)
	if err != nil {
		return 0, err
	}
	defer w.deallocate(dataPtr, uint32(len(data)))

	// Call the function
	results, err := getSliverSize.Call(w.ctx, uint64(handle), uint64(dataPtr), uint64(len(data)))
	if err != nil {
		return 0, err
	}

	ret := int32(results[0])
	if ret < 0 {
		return 0, fmt.Errorf("encoder_get_sliver_size failed with code: %d", ret)
	}

	return ret, nil
}

// Helper to write a slice of uint32s to WASM memory (used for pointer arrays)
func (w *WalrusWASM) writeUint32Array(arr []uint32) (uint32, error) {
	buf := make([]byte, len(arr)*4)
	for i, v := range arr {
		binary.LittleEndian.PutUint32(buf[i*4:], v)
	}
	return w.writeBytes(buf)
}

// EncodeResult holds the output of the encoding process
type EncodeResult struct {
	PrimaryShards   [][]byte
	SecondaryShards [][]byte
	Metadata        []byte // The full serialized metadata
	RootHash        []byte // The raw 32-byte root hash
	BlobID          string // The Walrus-standard string representation
}

// GetMetadataSize calculates the exact buffer size needed for metadata
func (w *WalrusWASM) GetMetadataSize(handle int32, data []byte) (int32, error) {
	getMetaSize := w.module.ExportedFunction("encoder_get_metadata_size")

	dataPtr, err := w.writeBytes(data)
	if err != nil {
		return 0, err
	}
	defer w.deallocate(dataPtr, uint32(len(data)))

	results, err := getMetaSize.Call(w.ctx, uint64(handle), uint64(dataPtr), uint64(len(data)))
	if err != nil {
		return 0, err
	}

	ret := int32(results[0])
	if ret < 0 {
		return 0, fmt.Errorf("failed to get metadata size: code %d", ret)
	}

	return ret, nil
}

// Encode performs the encoding operation
func (w *WalrusWASM) Encode(handle int32, data []byte, nShards int) (*EncodeResult, error) {
	encodeFunc := w.module.ExportedFunction("encoder_encode")

	metaSize, err := w.GetMetadataSize(handle, data)
	if err != nil {
		return nil, err
	}

	// 1. Determine the size needed for each shard buffer
	sliverSize, err := w.GetSliverSize(handle, data)
	if err != nil {
		return nil, fmt.Errorf("failed to get sliver size: %w", err)
	}
	sliverSizeUint := uint32(sliverSize)

	// 2. Write Input Data
	dataPtr, err := w.writeBytes(data)
	if err != nil {
		return nil, err
	}
	defer w.deallocate(dataPtr, uint32(len(data)))

	// 3. Allocate Output Buffers for Shards
	// We need to pass "pointers to arrays of pointers".
	// So we create Go slices to hold the WASM pointers, then write those slices to WASM.

	primaryPtrs := make([]uint32, nShards)
	primaryLens := make([]uint32, nShards)
	secondaryPtrs := make([]uint32, nShards)
	secondaryLens := make([]uint32, nShards)

	// Track allocations to free them later
	var allocatedBuffers []uint32
	defer func() {
		for _, ptr := range allocatedBuffers {
			w.deallocate(ptr, sliverSizeUint)
		}
	}()

	for i := 0; i < nShards; i++ {
		// Allocate Primary Buffer
		pPtr, err := w.allocate(sliverSizeUint)
		if err != nil {
			return nil, err
		}
		primaryPtrs[i] = pPtr
		primaryLens[i] = sliverSizeUint
		allocatedBuffers = append(allocatedBuffers, pPtr)

		// Allocate Secondary Buffer
		sPtr, err := w.allocate(sliverSizeUint)
		if err != nil {
			return nil, err
		}
		secondaryPtrs[i] = sPtr
		secondaryLens[i] = sliverSizeUint
		allocatedBuffers = append(allocatedBuffers, sPtr)
	}

	// 4. Write the Arrays of Pointers/Lengths to WASM memory
	primaryPtrsAddr, err := w.writeUint32Array(primaryPtrs)
	if err != nil {
		return nil, err
	}
	defer w.deallocate(primaryPtrsAddr, uint32(len(primaryPtrs)*4))

	primaryLensAddr, err := w.writeUint32Array(primaryLens)
	if err != nil {
		return nil, err
	}
	defer w.deallocate(primaryLensAddr, uint32(len(primaryLens)*4))

	secondaryPtrsAddr, err := w.writeUint32Array(secondaryPtrs)
	if err != nil {
		return nil, err
	}
	defer w.deallocate(secondaryPtrsAddr, uint32(len(secondaryPtrs)*4))

	secondaryLensAddr, err := w.writeUint32Array(secondaryLens)
	if err != nil {
		return nil, err
	}
	defer w.deallocate(secondaryLensAddr, uint32(len(secondaryLens)*4))

	// 5. Allocate Metadata Buffer
	metaCapacity := uint32(metaSize)
	metaPtr, err := w.allocate(metaCapacity)
	if err != nil {
		return nil, err
	}
	defer w.deallocate(metaPtr, metaCapacity)

	// 6. Call the Encode function
	results, err := encodeFunc.Call(w.ctx,
		uint64(handle),
		uint64(dataPtr), uint64(len(data)),
		uint64(primaryPtrsAddr), uint64(primaryLensAddr),
		uint64(secondaryPtrsAddr), uint64(secondaryLensAddr),
		uint64(nShards),
		uint64(metaPtr), uint64(metaCapacity),
	)

	if err != nil {
		return nil, err
	}

	ret := int32(results[0])
	if ret < 0 {
		return nil, fmt.Errorf("encoding failed with code: %d", ret)
	}
	actualMetaLen := uint32(ret)
	// 7. Read Results back into Go
	result := &EncodeResult{
		PrimaryShards:   make([][]byte, nShards),
		SecondaryShards: make([][]byte, nShards),
	}

	for i := 0; i < nShards; i++ {
		// Read Primary
		pBytes, err := w.readBytes(primaryPtrs[i], sliverSizeUint)
		if err != nil {
			return nil, err
		}
		// Copy ensures we own the data after deallocation
		pCopy := make([]byte, len(pBytes))
		copy(pCopy, pBytes)
		result.PrimaryShards[i] = pCopy

		// Read Secondary
		sBytes, err := w.readBytes(secondaryPtrs[i], sliverSizeUint)
		if err != nil {
			return nil, err
		}
		sCopy := make([]byte, len(sBytes))
		copy(sCopy, sBytes)
		result.SecondaryShards[i] = sCopy
	}

	// For metadata, we need to know the actual length.
	// The Rust API assumes we know how to deserialize or the buffer is full.
	// Since the Rust API doesn't return the *actual* bytes written for metadata in this specific signature
	// (it returns SUCCESS/ERROR code), we read the whole buffer.
	// In a real app, you might want to modify the Rust to return the metadata len,
	// or scan for the end if it's self-describing.
	// For now, we read the full capacity or rely on bincode being valid.
	metaBytes, err := w.readBytes(metaPtr, actualMetaLen)
	if err != nil {
		return nil, err
	}

	// 1. Extract Root Hash (the last 32 bytes)
	rootHash := make([]byte, 32)
	copy(rootHash, metaBytes[len(metaBytes)-32:])
	result.RootHash = rootHash

	// 2. Extract Metadata (everything before the root hash)
	metadataOnly := make([]byte, len(metaBytes)-32)
	copy(metadataOnly, metaBytes[:len(metaBytes)-32])
	result.Metadata = metadataOnly

	// 3. Generate Blob ID
	// Walrus typically uses a specific Base64 encoding (URL-safe, no padding)
	// or Hex for the Blob ID.
	blobID := base64.RawURLEncoding.EncodeToString(rootHash)
	result.BlobID = blobID

	return result, nil
}

func main() {
	ctx := context.Background()

	// Create WASM instance
	wasm, err := NewWalrusWASM(ctx, "./target/wasm32-wasip1/release/walrus_wasm_wazero.wasm")
	if err != nil {
		panic(err)
	}
	defer wasm.Close()

	fmt.Println("WASM module loaded successfully!")

	// Example: Create encoder
	/*encoder, err := wasm.CreateEncoder(1024)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Encoder created with handle: %d\n", encoder)

	// Clean up encoder
	if err := wasm.DestroyEncoder(encoder); err != nil {
		panic(err)
	}
	fmt.Println("Encoder destroyed successfully!")*/

	// ... inside main ...

	// 1. Create Encoder (e.g., 10 shards)
	// Note: Rust code uses RS2, so nShards usually implies specific breakdown (e.g., 2n)
	nShards := 1000
	encoderHandle, err := wasm.CreateEncoder(uint16(nShards))
	if err != nil {
		panic(err)
	}
	defer wasm.DestroyEncoder(encoderHandle)

	// 2. Prepare Data
	data := []byte("Hello, Walrus! This is a test of the encoding system.")

	// 3. Encode
	fmt.Println("Encoding data...")
	result, err := wasm.Encode(encoderHandle, data, nShards)
	if err != nil {
		panic(fmt.Errorf("Encoding error: %v", err))
	}

	fmt.Printf("Encoding successful!\n")
	fmt.Printf("Metadata size: %d bytes\n", len(result.Metadata))
	fmt.Printf("Generated %d primary shards and %d secondary shards\n",
		len(result.PrimaryShards), len(result.SecondaryShards))

	// Print first shard content length to verify
	if len(result.PrimaryShards) > 0 {
		fmt.Printf("Shard 0 size: %d bytes\n", len(result.PrimaryShards[0]))
	}

	fmt.Println(result.BlobID)
	// fmt.Println(result.RootHash)

	// Example: BLS12381 verification (you would need real signature/key data)
	// signature := []byte{ /* ... */ }
	// publicKey := []byte{ /* ... */ }
	// message := []byte("Hello, World!")
	//
	// valid, err := wasm.VerifyBLS12381(signature, publicKey, message)
	// if err != nil {
	//     panic(err)
	// }
	// fmt.Printf("Signature valid: %v\n", valid)
}
