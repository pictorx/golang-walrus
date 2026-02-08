package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

func main() {
	ctx := context.Background()

	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)

	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	wasmBytes, err := os.ReadFile("../target/wasm32-wasip1/release/walrus_wasm_wazero.wasm")
	if err != nil {
		panic(err)
	}

	mod, err := r.InstantiateWithConfig(ctx, wasmBytes,
		wazero.NewModuleConfig().WithName("walrus"))
	if err != nil {
		panic(err)
	}
	defer mod.Close(ctx)

	allocate := mod.ExportedFunction("allocate")
	deallocate := mod.ExportedFunction("deallocate")
	encoderCreate := mod.ExportedFunction("encoder_create")
	getSliverSize := mod.ExportedFunction("encoder_get_sliver_size")
	getMetadataSize := mod.ExportedFunction("encoder_get_metadata_size")
	encode := mod.ExportedFunction("encoder_encode")

	// Create encoder
	result, _ := encoderCreate.Call(ctx, uint64(1024))
	encoderHandle := int32(result[0])

	// Test data
	data := []byte("Hello, Walrus! This is a test message for blob registration.")

	dataPtr, _ := allocate.Call(ctx, uint64(len(data)))
	defer deallocate.Call(ctx, dataPtr[0], uint64(len(data)))
	mod.Memory().Write(uint32(dataPtr[0]), data)

	// Get sizes
	sliverSizeResult, _ := getSliverSize.Call(ctx, uint64(encoderHandle), dataPtr[0], uint64(len(data)))
	sliverSize := uint32(sliverSizeResult[0])

	metaSizeResult, _ := getMetadataSize.Call(ctx, uint64(encoderHandle), dataPtr[0], uint64(len(data)))
	metadataSize := uint32(metaSizeResult[0])

	fmt.Printf("Test data size: %d bytes\n", len(data))
	fmt.Printf("Sliver size: %d bytes\n", sliverSize)
	fmt.Printf("Metadata size: %d bytes\n\n", metadataSize)

	// Allocate buffers
	numShards := 1024

	primaryPtrs := make([]uint32, numShards)
	primaryLens := make([]uint32, numShards)
	for i := 0; i < numShards; i++ {
		ptr, _ := allocate.Call(ctx, uint64(sliverSize))
		primaryPtrs[i] = uint32(ptr[0])
		primaryLens[i] = sliverSize
	}
	defer func() {
		for i := 0; i < numShards; i++ {
			deallocate.Call(ctx, uint64(primaryPtrs[i]), uint64(sliverSize))
		}
	}()

	secondaryPtrs := make([]uint32, numShards)
	secondaryLens := make([]uint32, numShards)
	for i := 0; i < numShards; i++ {
		ptr, _ := allocate.Call(ctx, uint64(sliverSize))
		secondaryPtrs[i] = uint32(ptr[0])
		secondaryLens[i] = sliverSize
	}
	defer func() {
		for i := 0; i < numShards; i++ {
			deallocate.Call(ctx, uint64(secondaryPtrs[i]), uint64(sliverSize))
		}
	}()

	// Create pointer arrays
	primaryPtrsSize := uint32(numShards * 4)
	primaryPtrsPtr, _ := allocate.Call(ctx, uint64(primaryPtrsSize))
	defer deallocate.Call(ctx, primaryPtrsPtr[0], uint64(primaryPtrsSize))

	primaryPtrsBytes := make([]byte, primaryPtrsSize)
	for i, ptr := range primaryPtrs {
		binary.LittleEndian.PutUint32(primaryPtrsBytes[i*4:], ptr)
	}
	mod.Memory().Write(uint32(primaryPtrsPtr[0]), primaryPtrsBytes)

	primaryLensPtr, _ := allocate.Call(ctx, uint64(primaryPtrsSize))
	defer deallocate.Call(ctx, primaryLensPtr[0], uint64(primaryPtrsSize))

	primaryLensBytes := make([]byte, primaryPtrsSize)
	for i, l := range primaryLens {
		binary.LittleEndian.PutUint32(primaryLensBytes[i*4:], l)
	}
	mod.Memory().Write(uint32(primaryLensPtr[0]), primaryLensBytes)

	secondaryPtrsPtr, _ := allocate.Call(ctx, uint64(primaryPtrsSize))
	defer deallocate.Call(ctx, secondaryPtrsPtr[0], uint64(primaryPtrsSize))

	secondaryPtrsBytes := make([]byte, primaryPtrsSize)
	for i, ptr := range secondaryPtrs {
		binary.LittleEndian.PutUint32(secondaryPtrsBytes[i*4:], ptr)
	}
	mod.Memory().Write(uint32(secondaryPtrsPtr[0]), secondaryPtrsBytes)

	secondaryLensPtr, _ := allocate.Call(ctx, uint64(primaryPtrsSize))
	defer deallocate.Call(ctx, secondaryLensPtr[0], uint64(primaryPtrsSize))

	secondaryLensBytes := make([]byte, primaryPtrsSize)
	for i, l := range secondaryLens {
		binary.LittleEndian.PutUint32(secondaryLensBytes[i*4:], l)
	}
	mod.Memory().Write(uint32(secondaryLensPtr[0]), secondaryLensBytes)

	// Allocate metadata buffer
	metadataPtr, _ := allocate.Call(ctx, uint64(metadataSize))
	defer deallocate.Call(ctx, metadataPtr[0], uint64(metadataSize))

	// Encode
	encodeResult, _ := encode.Call(ctx,
		uint64(encoderHandle),
		dataPtr[0], uint64(len(data)),
		primaryPtrsPtr[0], primaryLensPtr[0],
		secondaryPtrsPtr[0], secondaryLensPtr[0],
		uint64(numShards),
		metadataPtr[0], uint64(metadataSize))

	actualMetaSize := uint32(encodeResult[0])
	fmt.Printf("Encoding successful!\n")
	fmt.Printf("Actual metadata size: %d bytes\n\n", actualMetaSize)

	// Read metadata
	metadataBytes, _ := mod.Memory().Read(uint32(metadataPtr[0]), actualMetaSize)

	blobId, rootHash, unencodedLen, encodingType, err := ExtractBlobInfo(metadataBytes)
	if err != nil {
		fmt.Printf("❌ QuickExtract failed: %v\n", err)
	} else {
		fmt.Printf("✅ Success!\n")
		fmt.Printf("BlobId:          %s\n", hex.EncodeToString(blobId))
		fmt.Printf("RootHash:        %s\n", hex.EncodeToString(rootHash))
		fmt.Printf("Encoding Type:   %d\n", encodingType)
		fmt.Printf("Original Size:   %d bytes\n", unencodedLen)
	}

}
