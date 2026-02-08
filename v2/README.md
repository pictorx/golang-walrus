# Walrus WASM for Wazero

This is a WASI-compatible WebAssembly build of the Walrus encoding library and BLS12381 cryptographic functions, designed to work with [wazero](https://github.com/wazero/wazero) (a Go-based WebAssembly runtime).

## Key Differences from wasm-bindgen

Unlike the original `wasm-bindgen` implementation (which targets JavaScript), this version:

1. **Uses C-style FFI**: All functions are exported with `#[no_mangle]` and `extern "C"` for direct memory access
2. **Manual memory management**: Provides `allocate()` and `deallocate()` functions for host-side memory management
3. **Serialization**: Uses `bincode` for complex data structures instead of `serde-wasm-bindgen`
4. **Error codes**: Returns integer error codes instead of throwing JavaScript exceptions
5. **WASI compatibility**: Can run in any WASI-compliant runtime (wazero, wasmtime, wasmer, etc.)

## Building

### Prerequisites

1. Install Rust: https://rustup.rs/
2. Add WASM target:

```bash
rustup target add wasm32-wasi
```

### Compile

```bash
cargo build --target wasm32-wasi --release
```

The compiled WASM module will be at: `target/wasm32-wasi/release/walrus_wasm_wazero.wasm`

### Optimize (optional but recommended)

For smaller binaries, use `wasm-opt` from [binaryen](https://github.com/WebAssembly/binaryen):

```bash
wasm-opt -Oz -o walrus_optimized.wasm target/wasm32-wasi/release/walrus_wasm_wazero.wasm
```

## API Reference

### Error Codes

```
SUCCESS = 0
ERROR_INVALID_SIGNATURE = -1
ERROR_INVALID_PUBLIC_KEY = -2
ERROR_VERIFICATION_FAILED = -3
ERROR_AGGREGATION_FAILED = -4
ERROR_DESERIALIZATION_FAILED = -5
ERROR_ENCODING_FAILED = -6
ERROR_BUFFER_SIZE_MISMATCH = -7
ERROR_INVALID_SHARDS = -8
ERROR_DECODING_FAILED = -9
```

### Memory Management

```c
// Allocate memory in WASM module
uint8_t* allocate(uint32_t size);

// Free memory in WASM module
void deallocate(uint8_t* ptr, uint32_t size);
```

### BLS12381 Functions

#### bls12381_min_pk_verify

```c
int32_t bls12381_min_pk_verify(
    const uint8_t* signature_ptr,
    uint32_t signature_len,
    const uint8_t* public_key_ptr,
    uint32_t public_key_len,
    const uint8_t* msg_ptr,
    uint32_t msg_len
);
```

Returns: `1` if valid, `0` if invalid, negative error code on error.

#### bls12381_min_pk_aggregate

```c
int32_t bls12381_min_pk_aggregate(
    const uint8_t* signatures_ptr,    // bincode-serialized Vec<Vec<u8>>
    uint32_t signatures_len,
    uint8_t* output_ptr,
    uint32_t output_capacity
);
```

Returns: length of output on success, negative error code on failure.

#### bls12381_min_pk_verify_aggregate

```c
int32_t bls12381_min_pk_verify_aggregate(
    const uint8_t* public_keys_ptr,   // bincode-serialized Vec<Vec<u8>>
    uint32_t public_keys_len,
    const uint8_t* msg_ptr,
    uint32_t msg_len,
    const uint8_t* signature_ptr,
    uint32_t signature_len
);
```

Returns: `1` if valid, `0` if invalid, negative error code on error.

### Encoder Functions

#### encoder_create

```c
int32_t encoder_create(uint16_t n_shards);
```

Returns: encoder handle (>= 0) on success, negative error code on failure.

#### encoder_encode

```c
int32_t encoder_encode(
    int32_t encoder_handle,
    const uint8_t* data_ptr,
    uint32_t data_len,
    const uint8_t** primary_buffers_ptr,      // array of buffer pointers
    const uint32_t* primary_buffer_lens,      // array of buffer lengths
    const uint8_t** secondary_buffers_ptr,    // array of buffer pointers
    const uint32_t* secondary_buffer_lens,    // array of buffer lengths
    uint32_t num_buffers,
    uint8_t* output_metadata_ptr,
    uint32_t output_metadata_capacity
);
```

Returns: `SUCCESS` (0) on success, negative error code on failure.

#### encoder_compute_metadata

```c
int32_t encoder_compute_metadata(
    int32_t encoder_handle,
    const uint8_t* data_ptr,
    uint32_t data_len,
    uint8_t* output_ptr,
    uint32_t output_capacity
);
```

Returns: length of output on success, negative error code on failure.

#### encoder_decode

```c
int32_t encoder_decode(
    int32_t encoder_handle,
    const uint8_t* blob_id_ptr,
    uint32_t blob_id_len,
    uint64_t blob_size,
    const uint8_t** bcs_buffers_ptr,     // array of BCS-encoded sliver pointers
    const uint32_t* bcs_buffer_lens,     // array of buffer lengths
    uint32_t num_buffers,
    uint8_t* output_buffer_ptr,
    uint32_t output_buffer_len
);
```

Returns: `SUCCESS` (0) on success, negative error code on failure.

#### encoder_destroy

```c
int32_t encoder_destroy(int32_t encoder_handle);
```

Returns: `SUCCESS` (0) on success, negative error code on failure.

## Usage Example (Go with wazero)

```go
package main

import (
    "context"
    "fmt"
    "os"
    
    "github.com/tetratelabs/wazero"
    "github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

func main() {
    ctx := context.Background()
    
    // Create runtime
    r := wazero.NewRuntime(ctx)
    defer r.Close(ctx)
    
    // Instantiate WASI
    wasi_snapshot_preview1.MustInstantiate(ctx, r)
    
    // Load WASM module
    wasmBytes, err := os.ReadFile("walrus_wasm_wazero.wasm")
    if err != nil {
        panic(err)
    }
    
    mod, err := r.InstantiateWithConfig(ctx, wasmBytes,
        wazero.NewModuleConfig().WithName("walrus"))
    if err != nil {
        panic(err)
    }
    defer mod.Close(ctx)
    
    // Get exports
    allocate := mod.ExportedFunction("allocate")
    deallocate := mod.ExportedFunction("deallocate")
    verify := mod.ExportedFunction("bls12381_min_pk_verify")
    
    // Example: Verify a signature
    signature := []byte{ /* ... signature bytes ... */ }
    publicKey := []byte{ /* ... public key bytes ... */ }
    message := []byte("Hello, World!")
    
    // Allocate memory in WASM
    sigPtr, err := allocate.Call(ctx, uint64(len(signature)))
    if err != nil {
        panic(err)
    }
    defer deallocate.Call(ctx, sigPtr[0], uint64(len(signature)))
    
    pkPtr, err := allocate.Call(ctx, uint64(len(publicKey)))
    if err != nil {
        panic(err)
    }
    defer deallocate.Call(ctx, pkPtr[0], uint64(len(publicKey)))
    
    msgPtr, err := allocate.Call(ctx, uint64(len(message)))
    if err != nil {
        panic(err)
    }
    defer deallocate.Call(ctx, msgPtr[0], uint64(len(message)))
    
    // Write data to WASM memory
    mod.Memory().Write(uint32(sigPtr[0]), signature)
    mod.Memory().Write(uint32(pkPtr[0]), publicKey)
    mod.Memory().Write(uint32(msgPtr[0]), message)
    
    // Call verify function
    result, err := verify.Call(ctx,
        sigPtr[0], uint64(len(signature)),
        pkPtr[0], uint64(len(publicKey)),
        msgPtr[0], uint64(len(message)))
    if err != nil {
        panic(err)
    }
    
    if result[0] == 1 {
        fmt.Println("Signature is valid!")
    } else {
        fmt.Printf("Signature verification failed (code: %d)\n", int32(result[0]))
    }
}
```

## Data Serialization

For complex data structures (like `Vec<Vec<u8>>`), this implementation uses **bincode** serialization:

```go
// Go example: serialize Vec<Vec<u8>> for WASM
import "github.com/google/go-cmp/cmp/cmpopts"

func serializeVecVec(data [][]byte) []byte {
    // You'll need a bincode library for Go, or pre-serialize on Rust side
    // Example structure:
    // [length: u64][vec1_len: u64][vec1_data...][vec2_len: u64][vec2_data...]...
}
```

## Notes

1. **Thread Safety**: The current encoder implementation uses `thread_local!` storage. For multi-threaded Go applications, you may need to instantiate separate WASM modules per thread.

2. **Memory Management**: Always deallocate memory you allocate to prevent leaks.

3. **Error Handling**: Check return values and handle negative error codes appropriately.

4. **Performance**: WASM adds overhead compared to native code. For production, benchmark your specific use case.

## Testing

Build and test the module:

```bash
# Build
cargo build --target wasm32-wasi --release

# Run tests (requires wasmtime or similar)
cargo test --target wasm32-wasi
```

## License

Same as original Walrus project.
