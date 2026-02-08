package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

func main() {
	ctx := context.Background()

	// Step 1: Load WASM module
	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)

	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	wasmBytes, err := os.ReadFile("../target/wasm32-wasip1/release/walrus_wasm_wazero.wasm")
	if err != nil {
		panic(fmt.Sprintf("Failed to read WASM file: %v", err))
	}

	mod, err := r.InstantiateWithConfig(ctx, wasmBytes,
		wazero.NewModuleConfig().WithName("walrus"))
	if err != nil {
		panic(fmt.Sprintf("Failed to instantiate: %v", err))
	}
	defer mod.Close(ctx)

	// Step 2: Get function exports
	allocate := mod.ExportedFunction("allocate")
	deallocate := mod.ExportedFunction("deallocate")
	encoderCreate := mod.ExportedFunction("encoder_create")
	encoderDestroy := mod.ExportedFunction("encoder_destroy")
	getSliverSize := mod.ExportedFunction("encoder_get_sliver_size")
	encode := mod.ExportedFunction("encoder_encode")

	// Step 3: Create encoder with 1024 shards
	nShards := uint16(1024)
	result, err := encoderCreate.Call(ctx, uint64(nShards))
	if err != nil {
		panic(err)
	}

	encoderHandle := int32(result[0])
	if encoderHandle < 0 {
		panic(fmt.Sprintf("Failed to create encoder: error code %d", encoderHandle))
	}
	fmt.Printf("✓ Created encoder with handle: %d\n", encoderHandle)
	defer encoderDestroy.Call(ctx, uint64(encoderHandle))

	// Step 4: Prepare data to encode
	data := []byte("Hello, Walrus! This is a test message for encoding.")
	fmt.Printf("✓ Data to encode: %d bytes\n", len(data))

	// Step 5: Allocate and write data to WASM memory
	dataPtr, err := allocate.Call(ctx, uint64(len(data)))
	if err != nil {
		panic(err)
	}
	defer deallocate.Call(ctx, dataPtr[0], uint64(len(data)))
	mod.Memory().Write(uint32(dataPtr[0]), data)
	fmt.Printf("✓ Wrote data to WASM memory at ptr: %d\n", dataPtr[0])

	// Step 6: Get the sliver size (how big each encoded piece will be)
	sliverSizeResult, err := getSliverSize.Call(ctx,
		uint64(encoderHandle),
		dataPtr[0], uint64(len(data)))
	if err != nil {
		panic(err)
	}

	sliverSize := int32(sliverSizeResult[0])
	if sliverSize < 0 {
		panic(fmt.Sprintf("Failed to get sliver size: error code %d", sliverSize))
	}
	fmt.Printf("✓ Sliver size: %d bytes\n", sliverSize)

	// Step 7: Allocate buffers for encoded slivers
	numShards := int(nShards)

	// Allocate primary sliver buffers
	primaryPtrs := make([]uint32, numShards)
	primaryLens := make([]uint32, numShards)
	for i := 0; i < numShards; i++ {
		ptr, _ := allocate.Call(ctx, uint64(sliverSize))
		primaryPtrs[i] = uint32(ptr[0])
		primaryLens[i] = uint32(sliverSize)
	}
	defer func() {
		for i := 0; i < numShards; i++ {
			deallocate.Call(ctx, uint64(primaryPtrs[i]), uint64(primaryLens[i]))
		}
	}()
	fmt.Printf("✓ Allocated %d primary buffers\n", numShards)

	// Allocate secondary sliver buffers
	secondaryPtrs := make([]uint32, numShards)
	secondaryLens := make([]uint32, numShards)
	for i := 0; i < numShards; i++ {
		ptr, _ := allocate.Call(ctx, uint64(sliverSize))
		secondaryPtrs[i] = uint32(ptr[0])
		secondaryLens[i] = uint32(sliverSize)
	}
	defer func() {
		for i := 0; i < numShards; i++ {
			deallocate.Call(ctx, uint64(secondaryPtrs[i]), uint64(secondaryLens[i]))
		}
	}()
	fmt.Printf("✓ Allocated %d secondary buffers\n", numShards)

	// Step 8: Create arrays of pointers in WASM memory
	// We need to pass arrays of pointers to the encode function

	// Primary pointers array
	primaryPtrsSize := uint32(numShards * 4) // 4 bytes per uint32
	primaryPtrsPtr, _ := allocate.Call(ctx, uint64(primaryPtrsSize))
	defer deallocate.Call(ctx, primaryPtrsPtr[0], uint64(primaryPtrsSize))

	primaryPtrsBytes := make([]byte, primaryPtrsSize)
	for i, ptr := range primaryPtrs {
		binary.LittleEndian.PutUint32(primaryPtrsBytes[i*4:], ptr)
	}
	mod.Memory().Write(uint32(primaryPtrsPtr[0]), primaryPtrsBytes)

	// Primary lengths array
	primaryLensPtr, _ := allocate.Call(ctx, uint64(primaryPtrsSize))
	defer deallocate.Call(ctx, primaryLensPtr[0], uint64(primaryPtrsSize))

	primaryLensBytes := make([]byte, primaryPtrsSize)
	for i, len := range primaryLens {
		binary.LittleEndian.PutUint32(primaryLensBytes[i*4:], len)
	}
	mod.Memory().Write(uint32(primaryLensPtr[0]), primaryLensBytes)

	// Secondary pointers array
	secondaryPtrsPtr, _ := allocate.Call(ctx, uint64(primaryPtrsSize))
	defer deallocate.Call(ctx, secondaryPtrsPtr[0], uint64(primaryPtrsSize))

	secondaryPtrsBytes := make([]byte, primaryPtrsSize)
	for i, ptr := range secondaryPtrs {
		binary.LittleEndian.PutUint32(secondaryPtrsBytes[i*4:], ptr)
	}
	mod.Memory().Write(uint32(secondaryPtrsPtr[0]), secondaryPtrsBytes)

	// Secondary lengths array
	secondaryLensPtr, _ := allocate.Call(ctx, uint64(primaryPtrsSize))
	defer deallocate.Call(ctx, secondaryLensPtr[0], uint64(primaryPtrsSize))

	secondaryLensBytes := make([]byte, primaryPtrsSize)
	for i, len := range secondaryLens {
		binary.LittleEndian.PutUint32(secondaryLensBytes[i*4:], len)
	}
	mod.Memory().Write(uint32(secondaryLensPtr[0]), secondaryLensBytes)

	fmt.Printf("✓ Created pointer arrays in WASM memory\n")

	// Step 9: Allocate metadata output buffer
	metadataCapacity := uint32(10240) // 10KB should be enough
	metadataPtr, _ := allocate.Call(ctx, uint64(metadataCapacity))
	defer deallocate.Call(ctx, metadataPtr[0], uint64(metadataCapacity))
	fmt.Printf("✓ Allocated metadata buffer: %d bytes\n", metadataCapacity)

	// Step 10: Call the encode function!
	encodeResult, err := encode.Call(ctx,
		uint64(encoderHandle),
		dataPtr[0], uint64(len(data)),
		primaryPtrsPtr[0], primaryLensPtr[0],
		secondaryPtrsPtr[0], secondaryLensPtr[0],
		uint64(numShards),
		metadataPtr[0], uint64(metadataCapacity))
	if err != nil {
		panic(fmt.Sprintf("Encode call failed: %v", err))
	}

	code := int32(encodeResult[0])
	if code != 0 { // 0 = SUCCESS
		panic(fmt.Sprintf("Encode failed with error code: %d", code))
	}

	fmt.Printf("✓ Encoding successful!\n")

	// Step 11: Read the metadata
	metadataBytes, ok := mod.Memory().Read(uint32(metadataPtr[0]), metadataCapacity)
	if !ok {
		panic("Failed to read metadata")
	}

	fmt.Printf("✓ Metadata retrieved: %d bytes\n", len(metadataBytes))
	fmt.Printf("  First 100 bytes: %x...\n", metadataBytes[:min(100, len(metadataBytes))])

	// Step 12: Now you can read the encoded slivers if needed
	// Each primary/secondary buffer now contains a BCS-encoded sliver
	firstPrimarySliverBytes, _ := mod.Memory().Read(primaryPtrs[0], primaryLens[0])
	fmt.Printf("✓ First primary sliver: %d bytes\n", len(firstPrimarySliverBytes))
	fmt.Printf("  Preview: %x...\n", firstPrimarySliverBytes[:min(50, len(firstPrimarySliverBytes))])

	fmt.Println("\n✅ Encoding complete! All data is now encoded and ready for storage/transmission.")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
