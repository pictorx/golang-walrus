# Migration Guide: wasm-bindgen to WASI/wazero

This document explains the key differences between the original `wasm-bindgen` implementation and this WASI-compatible version for wazero.

## Architecture Differences

### Original (wasm-bindgen)
- **Target**: JavaScript/Browser environments
- **Interface**: JavaScript-friendly with automatic type conversions
- **Memory**: Managed by JavaScript glue code
- **Serialization**: `serde-wasm-bindgen` for JsValue conversion
- **Errors**: JavaScript exceptions via `JsError`

### New (WASI/wazero)
- **Target**: Any WASI runtime (Go, Rust, C++, etc.)
- **Interface**: C FFI with manual pointer management
- **Memory**: Manual allocation/deallocation via exported functions
- **Serialization**: `bincode` for binary data structures
- **Errors**: Integer error codes (C-style)

## Key Changes

### 1. Function Signatures

**Before (wasm-bindgen):**
```rust
#[wasm_bindgen]
pub fn bls12381_min_pk_verify(
    signature: &[u8],
    public_key: &[u8],
    msg: &[u8],
) -> Result<bool, JsError>
```

**After (WASI):**
```rust
#[no_mangle]
pub extern "C" fn bls12381_min_pk_verify(
    signature_ptr: *const u8,
    signature_len: u32,
    public_key_ptr: *const u8,
    public_key_len: u32,
    msg_ptr: *const u8,
    msg_len: u32,
) -> i32  // Returns: 1=valid, 0=invalid, <0=error
```

### 2. Memory Management

**Before (wasm-bindgen):**
```javascript
// JavaScript automatically handles memory
const result = instance.bls12381_min_pk_verify(signature, publicKey, message);
```

**After (WASI):**
```go
// Manual allocation and deallocation
sigPtr, _ := allocate(len(signature))
defer deallocate(sigPtr, len(signature))
memory.Write(sigPtr, signature)
result, _ := verify.Call(ctx, sigPtr, len(signature), ...)
```

### 3. Complex Data Structures

**Before (wasm-bindgen):**
```rust
#[wasm_bindgen]
pub fn bls12381_min_pk_aggregate(signatures: JsValue) -> Result<Vec<u8>, JsError> {
    let signatures = serde_wasm_bindgen::from_value::<Vec<Vec<u8>>>(signatures)?;
    // ...
}
```

**After (WASI):**
```rust
#[no_mangle]
pub extern "C" fn bls12381_min_pk_aggregate(
    signatures_ptr: *const u8,    // bincode-serialized Vec<Vec<u8>>
    signatures_len: u32,
    output_ptr: *mut u8,
    output_capacity: u32,
) -> i32 {
    let signatures_bytes = unsafe { slice::from_raw_parts(signatures_ptr, signatures_len as usize) };
    let signatures_vec: Vec<Vec<u8>> = bincode::deserialize(signatures_bytes)?;
    // ...
}
```

### 4. Error Handling

**Before (wasm-bindgen):**
```rust
return Err(JsError::new("Buffer size mismatch"));
```

**After (WASI):**
```rust
const ERROR_BUFFER_SIZE_MISMATCH: i32 = -7;
return ERROR_BUFFER_SIZE_MISMATCH;
```

### 5. State Management

**Before (wasm-bindgen):**
```rust
#[wasm_bindgen]
pub struct BlobEncoder {
    encoder: EncodingConfigEnum,
}

#[wasm_bindgen]
impl BlobEncoder {
    #[wasm_bindgen(constructor)]
    pub fn new(n_shards: u16) -> Result<Self, JsError> {
        // ...
    }
}
```

**After (WASI):**
```rust
// Use global state with handles
thread_local! {
    static ENCODERS: RefCell<Vec<EncodingConfigEnum>> = RefCell::new(Vec::new());
}

#[no_mangle]
pub extern "C" fn encoder_create(n_shards: u16) -> i32 {
    // Returns handle (index) instead of object
}
```

## Data Serialization

### JavaScript (wasm-bindgen)
Uses `serde-wasm-bindgen` which automatically converts between Rust and JavaScript types:

```javascript
// JavaScript automatically serializes/deserializes
const signatures = [sig1, sig2, sig3];  // Array of Uint8Arrays
const result = instance.bls12381_min_pk_aggregate(signatures);
```

### WASI (bincode)
Requires manual serialization using a consistent binary format:

```go
// Go must manually serialize to bincode format
func serializeVecVecU8(vecs [][]byte) []byte {
    buf := make([]byte, calculatedSize)
    // Write length
    binary.LittleEndian.PutUint64(buf[0:], uint64(len(vecs)))
    // Write each vector
    for _, v := range vecs {
        binary.LittleEndian.PutUint64(buf[offset:], uint64(len(v)))
        copy(buf[offset+8:], v)
    }
    return buf
}
```

## Buffer Management Patterns

### wasm-bindgen Pattern
```javascript
const encoder = new BlobEncoder(1024);
const result = encoder.encode(data, primaryBuffers, secondaryBuffers);
// Memory automatically managed
```

### WASI Pattern
```go
// 1. Create encoder and get handle
handle, _ := createEncoder(1024)
defer destroyEncoder(handle)

// 2. Allocate all buffers
dataPtr, _ := allocate(len(data))
defer deallocate(dataPtr, len(data))

// 3. Write input data
memory.Write(dataPtr, data)

// 4. Allocate output buffers
outputPtr, _ := allocate(outputSize)
defer deallocate(outputPtr, outputSize)

// 5. Call function
encode.Call(ctx, handle, dataPtr, len(data), outputPtr, outputSize)

// 6. Read results
result, _ := memory.Read(outputPtr, outputSize)
```

## Performance Considerations

### wasm-bindgen
- **Pros**: Zero-copy for many operations, tight JavaScript integration
- **Cons**: Limited to JavaScript/browser environments, larger binary size

### WASI
- **Pros**: Universal compatibility, smaller binaries, direct system integration
- **Cons**: More memory copying, manual memory management overhead

## Testing Strategy

### wasm-bindgen
```javascript
// Browser or Node.js testing
import { bls12381_min_pk_verify } from './pkg/walrus_wasm';

test('verify signature', () => {
    const result = bls12381_min_pk_verify(sig, pk, msg);
    expect(result).toBe(true);
});
```

### WASI
```go
// Go testing
func TestVerifySignature(t *testing.T) {
    wasm, _ := NewWalrusWASM(ctx, "walrus.wasm")
    defer wasm.Close()
    
    valid, err := wasm.VerifyBLS12381(sig, pk, msg)
    if err != nil {
        t.Fatal(err)
    }
    if !valid {
        t.Error("signature should be valid")
    }
}
```

## Build Differences

### wasm-bindgen
```bash
wasm-pack build --target web
# Generates: pkg/ with .wasm, .js, .d.ts files
```

### WASI
```bash
cargo build --target wasm32-wasi --release
# Generates: single .wasm file
# No JavaScript glue code needed
```

## Common Pitfalls

### 1. Pointer Lifetime
❌ **Wrong:**
```go
ptr, _ := allocate(100)
// ... some operations ...
// Forgot to deallocate - memory leak!
```

✅ **Correct:**
```go
ptr, _ := allocate(100)
defer deallocate(ptr, 100)
```

### 2. Buffer Size Calculation
❌ **Wrong:**
```go
data := []byte{1, 2, 3}
ptr, _ := allocate(10)  // Over-allocated
```

✅ **Correct:**
```go
data := []byte{1, 2, 3}
ptr, _ := allocate(uint32(len(data)))  // Exact size
```

### 3. Error Code Checking
❌ **Wrong:**
```go
result, _ := verify.Call(ctx, ...)
if result[0] == 0 {  // Only checks for "false", not errors
    // ...
}
```

✅ **Correct:**
```go
result, _ := verify.Call(ctx, ...)
code := int32(result[0])
if code < 0 {
    return fmt.Errorf("error: %d", code)
}
if code == 0 {
    return fmt.Errorf("verification failed")
}
// code == 1, success
```

## Migration Checklist

- [ ] Replace `#[wasm_bindgen]` with `#[no_mangle]` and `extern "C"`
- [ ] Change function parameters from references to raw pointers + lengths
- [ ] Replace `Result<T, JsError>` with integer return codes
- [ ] Add `allocate` and `deallocate` functions
- [ ] Replace `serde-wasm-bindgen` with `bincode` for complex types
- [ ] Update build target from `wasm32-unknown-unknown` to `wasm32-wasi`
- [ ] Implement handle-based state management for structs
- [ ] Update host code to use wazero API
- [ ] Add proper error code constants and documentation
- [ ] Test memory management for leaks

## Advantages of WASI Approach

1. **Universal**: Works with any language that supports WASM (Go, Rust, Python, C++, etc.)
2. **Smaller**: No JavaScript glue code, smaller final binary
3. **Standards-based**: Uses WASI standard, future-proof
4. **Sandboxed**: Better security model with WASI capabilities
5. **Portable**: Same WASM runs on server, edge, embedded, etc.

## When to Use Each

### Use wasm-bindgen when:
- Targeting browsers or Node.js specifically
- Need tight JavaScript integration
- Want automatic type conversion
- Building web applications

### Use WASI when:
- Need server-side WASM execution
- Want language-agnostic API
- Building microservices or edge functions
- Need maximum portability
- Using non-JavaScript host (Go, Rust, etc.)
