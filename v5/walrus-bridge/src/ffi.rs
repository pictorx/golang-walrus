// ffi.rs
//
// Sui Transaction Builder FFI — exported C symbols for libwalrus_go_ffi.a.
//
// Calling convention:
//   - Builder pointer is an opaque *mut TransactionBuilder; never NULL after
//     new_builder(), never valid after free_builder() or build_transaction().
//   - JSON inputs are (ptr: *const u8, len: usize) UTF-8 byte slices borrowed
//     only for the call duration; Rust does not retain them.
//   - Functions returning an Argument ID use i64; negative = error code.
//   - Functions returning only success/failure use i32 (1 = ok).
//   - build_transaction returns a heap buffer [u32 LE len][BCS payload];
//     free with free_bytes(ptr, 4 + len).
//   - last_error_message returns a pointer into Rust thread-local storage;
//     valid only until the next FFI call on this OS thread.

use crate::{Argument, Function, ObjectInput, TransactionBuilder};
use crate::builder::ResolvedArgument;
use sui_sdk_types::{Address, Identifier, TypeTag};
use std::cell::RefCell;
use std::mem;
use std::slice;
use std::str::FromStr;

// ── Thread-local error slot ──────────────────────────────────────────────────
//
// FIX (P1-5): The slot is thread_local! which means each OS thread has its own
// independent copy.  Go's cgo runtime pins each goroutine to an OS thread for
// the duration of a cgo call (runtime.LockOSThread semantics), so reading
// last_error_message immediately after a failing call on the same goroutine is
// always safe and returns the correct error.

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn set_last_error(e: impl std::fmt::Display) {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = Some(e.to_string());
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

/// Return a pointer to the last error message (UTF-8, NOT null-terminated) and
/// write its byte length into `*len_out`.
///
/// Returns NULL and sets `*len_out = 0` if no error has occurred since the last
/// successful call.
///
/// The pointer is valid only until the NEXT FFI call on this OS thread.
/// Do NOT pass it to `dealloc` or `free_bytes`.
#[no_mangle]
pub unsafe extern "C" fn last_error_message(len_out: *mut usize) -> *const u8 {
    // SAFETY: len_out is a valid writable pointer supplied by the caller.
    LAST_ERROR.with(|cell| {
        match cell.borrow().as_ref() {
            None => {
                if !len_out.is_null() {
                    // SAFETY: caller guarantees len_out is valid.
                    unsafe { *len_out = 0 };
                }
                std::ptr::null()
            }
            Some(s) => {
                if !len_out.is_null() {
                    unsafe { *len_out = s.len() };
                }
                s.as_ptr()
            }
        }
    })
}

// ── Memory management ────────────────────────────────────────────────────────

/// Allocate `len` bytes via the Rust global allocator.
/// Free with `dealloc(ptr, len)`.
/// Returns a non-null dangling pointer for len=0.
#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    if len == 0 {
        // SAFETY: NonNull::dangling() is always non-null and non-zero.
        return std::ptr::NonNull::dangling().as_ptr();
    }
    // SAFETY: align=1 is always valid; len > 0 checked above.
    let layout = std::alloc::Layout::from_size_align(len, 1)
        .expect("alloc: invalid layout");
    unsafe { std::alloc::alloc(layout) }
}

/// Free memory previously allocated with `alloc(len)`.
/// No-op for len=0 or NULL ptr.
#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    if len == 0 || ptr.is_null() {
        return;
    }
    // SAFETY: layout must exactly match the one used in `alloc`.
    let layout = std::alloc::Layout::from_size_align(len, 1)
        .expect("dealloc: invalid layout");
    // SAFETY: caller guarantees ptr was returned by alloc(len).
    unsafe { std::alloc::dealloc(ptr, layout) };
}

// ── Builder lifecycle ────────────────────────────────────────────────────────

/// Allocate a new TransactionBuilder on the heap and return an opaque pointer.
/// Free with `free_builder` if `build_transaction` is never called.
#[no_mangle]
pub extern "C" fn new_builder() -> *mut TransactionBuilder {
    Box::into_raw(Box::new(TransactionBuilder::new()))
}

/// Free a builder that was NOT consumed by `build_transaction`.
/// No-op for NULL.  Do NOT call after a successful `build_transaction`.
#[no_mangle]
pub unsafe extern "C" fn free_builder(builder: *mut TransactionBuilder) {
    if !builder.is_null() {
        // SAFETY: builder was produced by new_builder() and has not been freed.
        unsafe { drop(Box::from_raw(builder)) };
    }
}

// ── Configuration ────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct ConfigParams {
    sender: Address,
    gas_budget: Option<u64>,
    gas_price: Option<u64>,
}

/// Set sender, gas_budget, and gas_price from a JSON object.
/// JSON: `{"sender":"0x…","gas_budget":10000000,"gas_price":1000}`
/// Returns 1 on success, -1 on parse error.
#[no_mangle]
pub unsafe extern "C" fn set_config(
    builder: *mut TransactionBuilder,
    json_ptr: *const u8,
    json_len: usize,
) -> i32 {
    // SAFETY: builder is a valid non-null pointer; json slice valid for call.
    let builder = unsafe { &mut *builder };
    let bytes = unsafe { slice::from_raw_parts(json_ptr, json_len) };
    match serde_json::from_slice::<ConfigParams>(bytes) {
        Ok(p) => {
            builder.set_sender(p.sender);
            if let Some(b) = p.gas_budget {
                builder.set_gas_budget(b);
            }
            if let Some(p) = p.gas_price {
                builder.set_gas_price(p);
            }
            clear_last_error();
            1
        }
        Err(e) => {
            set_last_error(format!("set_config: {e}"));
            -1
        }
    }
}

// ── Gas objects ───────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct GasObjectParams {
    id: Address,
    version: u64,
    digest: String,
}

/// Add an owned gas coin from a JSON object.
/// JSON: `{"id":"0x…","version":2,"digest":"base58…"}`
/// Returns 1 on success, -1 on JSON parse error, -2 on invalid digest.
#[no_mangle]
pub unsafe extern "C" fn add_gas_object(
    builder: *mut TransactionBuilder,
    json_ptr: *const u8,
    json_len: usize,
) -> i32 {
    // SAFETY: builder valid; json slice valid for call.
    let builder = unsafe { &mut *builder };
    let bytes = unsafe { slice::from_raw_parts(json_ptr, json_len) };
    match serde_json::from_slice::<GasObjectParams>(bytes) {
        Ok(g) => {
            let digest = match sui_sdk_types::Digest::from_str(&g.digest) {
                Ok(d) => d,
                Err(e) => {
                    set_last_error(format!("add_gas_object: invalid digest: {e}"));
                    return -2;
                }
            };
            builder.add_gas_objects(vec![ObjectInput::owned(g.id, g.version, digest)]);
            clear_last_error();
            1
        }
        Err(e) => {
            set_last_error(format!("add_gas_object: {e}"));
            -1
        }
    }
}

// ── Gas pseudo-input ──────────────────────────────────────────────────────────

/// Register (or retrieve) the gas-coin pseudo-input and return its Argument ID.
/// Idempotent; always returns a non-negative ID; cannot fail.
#[no_mangle]
pub unsafe extern "C" fn gas_argument(builder: *mut TransactionBuilder) -> i64 {
    // SAFETY: builder is valid.
    unsafe { (&mut *builder).gas().id as i64 }
}

// ── Object inputs ─────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct ObjectInputParams {
    id: Address,
    version: u64,
    digest: Option<String>,
    mutable: Option<bool>,
    #[serde(rename = "kind")]
    kind: String,
}

/// Push an object input (owned / immutable / receiving / shared) from JSON.
///
/// Returns Argument ID (≥ 0) or: -1 parse error, -2 bad digest, -3 unknown kind.
#[no_mangle]
pub unsafe extern "C" fn input_object(
    builder: *mut TransactionBuilder,
    json_ptr: *const u8,
    json_len: usize,
) -> i64 {
    // SAFETY: builder valid; json slice valid for call.
    let builder = unsafe { &mut *builder };
    let bytes = unsafe { slice::from_raw_parts(json_ptr, json_len) };
    let p: ObjectInputParams = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(format!("input_object: {e}"));
            return -1;
        }
    };

    let obj = match p.kind.as_str() {
        "owned" | "immutable" | "receiving" => {
            let digest_str = match &p.digest {
                Some(d) => d,
                None => {
                    set_last_error(
                        "input_object: 'digest' is required for owned/immutable/receiving",
                    );
                    return -2;
                }
            };
            let digest = match sui_sdk_types::Digest::from_str(digest_str) {
                Ok(d) => d,
                Err(e) => {
                    set_last_error(format!("input_object: invalid digest: {e}"));
                    return -2;
                }
            };
            match p.kind.as_str() {
                "owned" => ObjectInput::owned(p.id, p.version, digest),
                "immutable" => ObjectInput::immutable(p.id, p.version, digest),
                _ => ObjectInput::receiving(p.id, p.version, digest),
            }
        }
        "shared" => ObjectInput::shared(p.id, p.version, p.mutable.unwrap_or(true)),
        _ => {
            set_last_error(format!("input_object: unknown kind {:?}", p.kind));
            return -3;
        }
    };

    clear_last_error();
    builder.object(obj).id as i64
}

// ── Pure-value helpers ────────────────────────────────────────────────────────

/// Push a BCS bool (0=false, non-zero=true). Returns Argument ID.
#[no_mangle]
pub unsafe extern "C" fn pure_bool(builder: *mut TransactionBuilder, value: u8) -> i64 {
    unsafe { (&mut *builder).pure(&(value != 0)).id as i64 }
}

/// Push a BCS u8. Returns Argument ID.
#[no_mangle]
pub unsafe extern "C" fn pure_u8(builder: *mut TransactionBuilder, value: u8) -> i64 {
    unsafe { (&mut *builder).pure(&value).id as i64 }
}

/// Push a BCS u16. Returns Argument ID.
#[no_mangle]
pub unsafe extern "C" fn pure_u16(builder: *mut TransactionBuilder, value: u16) -> i64 {
    unsafe { (&mut *builder).pure(&value).id as i64 }
}

/// Push a BCS u32. Returns Argument ID.
#[no_mangle]
pub unsafe extern "C" fn pure_u32(builder: *mut TransactionBuilder, value: u32) -> i64 {
    unsafe { (&mut *builder).pure(&value).id as i64 }
}

/// Push a BCS u64. Returns Argument ID.
#[no_mangle]
pub unsafe extern "C" fn pure_u64(builder: *mut TransactionBuilder, value: u64) -> i64 {
    unsafe { (&mut *builder).pure(&value).id as i64 }
}

/// Push a BCS u128 as two u64 halves: value = (hi << 64) | lo.
/// Returns Argument ID.
#[no_mangle]
pub unsafe extern "C" fn pure_u128(
    builder: *mut TransactionBuilder,
    hi: u64,
    lo: u64,
) -> i64 {
    let value: u128 = ((hi as u128) << 64) | (lo as u128);
    unsafe { (&mut *builder).pure(&value).id as i64 }
}

/// Push a BCS Sui address from a bare hex string (e.g. "0xabc…").
/// Returns Argument ID (≥ 0) or -1 on parse error.
#[no_mangle]
pub unsafe extern "C" fn pure_address(
    builder: *mut TransactionBuilder,
    ptr: *const u8,
    len: usize,
) -> i64 {
    // SAFETY: ptr slice valid for call duration.
    let bytes = unsafe { slice::from_raw_parts(ptr, len) };
    let s = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("pure_address: invalid UTF-8: {e}"));
            return -1;
        }
    };
    match Address::from_str(s.trim().trim_matches('"')) {
        Ok(addr) => {
            clear_last_error();
            // SAFETY: builder valid.
            unsafe { (&mut *builder).pure(&addr).id as i64 }
        }
        Err(e) => {
            set_last_error(format!("pure_address: {e}"));
            -1
        }
    }
}

/// Push raw pre-BCS-encoded bytes as a pure argument. Returns Argument ID.
#[no_mangle]
pub unsafe extern "C" fn pure_raw_bcs(
    builder: *mut TransactionBuilder,
    ptr: *const u8,
    len: usize,
) -> i64 {
    // SAFETY: ptr slice valid for call duration; builder valid.
    let bytes = unsafe { slice::from_raw_parts(ptr, len) }.to_vec();
    unsafe { (&mut *builder).pure_bytes(bytes).id as i64 }
}

// ── Nested result ─────────────────────────────────────────────────────────────

/// Return the Argument ID for the sub_index-th result of a multi-output command.
///
/// FIX (P1-6): Use `arguments.keys().last().map(|k| k+1).unwrap_or(0)` for
/// the new ID instead of `arguments.len()` which produces a collision when any
/// argument was ever removed (currently impossible, but fragile by assumption).
///
/// Returns new Argument ID (≥ 0) or: -1 base_id unknown, -2 not a command result.
#[no_mangle]
pub unsafe extern "C" fn nested_result(
    builder: *mut TransactionBuilder,
    base_id: u64,
    sub_index: u64,
) -> i64 {
    // SAFETY: builder valid.
    let builder = unsafe { &mut *builder };
    let base = base_id as usize;

    if !builder.arguments.contains_key(&base) {
        set_last_error(format!(
            "nested_result: base_id {base_id} does not refer to a known argument"
        ));
        return -1;
    }

    if !builder.commands.contains_key(&base) {
        set_last_error(format!(
            "nested_result: base_id {base_id} is a plain input, not a command result; \
             sub_index is only valid on command outputs (e.g. from command_split_coins)"
        ));
        return -2;
    }

    let nested = Argument {
        id: base,
        sub_index: Some(sub_index as usize),
    };

    // FIX (P1-6): derive new_id from the last existing key + 1 rather than len()
    // so that the key is unique even if keys are non-contiguous.
    let new_id = builder
        .arguments
        .keys()
        .last()
        .map(|k| k + 1)
        .unwrap_or(0);
    builder
        .arguments
        .insert(new_id, ResolvedArgument::ReplaceWith(nested));
    clear_last_error();
    new_id as i64
}

// ── Commands ──────────────────────────────────────────────────────────────────

/// Execute a Move function.
///
/// JSON: `{"package":"0x2","module":"coin","function":"split",
///          "type_args":["0x2::sui::SUI"],
///          "arguments":[{"id":3},{"pure_bcs":[1,0,0,0,0,0,0,0]}]}`
///
/// Returns result Argument ID (≥ 0) or: -1 JSON error, -2 bad module, -3 bad function.
#[no_mangle]
pub unsafe extern "C" fn command_move_call(
    builder: *mut TransactionBuilder,
    json_ptr: *const u8,
    json_len: usize,
) -> i64 {
    #[derive(serde::Deserialize)]
    struct Req {
        package: Address,
        module: String,
        function: String,
        #[serde(default)]
        type_args: Vec<TypeTag>,
        #[serde(default)]
        arguments: Vec<CallArg>,
    }
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum CallArg {
        Id { id: usize },
        PureBcs { pure_bcs: Vec<u8> },
    }

    // SAFETY: builder valid; json slice valid for call.
    let builder = unsafe { &mut *builder };
    let bytes = unsafe { slice::from_raw_parts(json_ptr, json_len) };
    let req: Req = match serde_json::from_slice(bytes) {
        Ok(r) => r,
        Err(e) => {
            set_last_error(format!("command_move_call: {e}"));
            return -1;
        }
    };
    let module = match Identifier::from_str(&req.module) {
        Ok(m) => m,
        Err(e) => {
            set_last_error(format!("command_move_call: invalid module identifier: {e}"));
            return -2;
        }
    };
    let function = match Identifier::from_str(&req.function) {
        Ok(f) => f,
        Err(e) => {
            set_last_error(format!(
                "command_move_call: invalid function identifier: {e}"
            ));
            return -3;
        }
    };
    let mut args = Vec::new();
    for a in req.arguments {
        match a {
            CallArg::Id { id } => args.push(Argument::new(id)),
            CallArg::PureBcs { pure_bcs } => args.push(builder.pure_bytes(pure_bcs)),
        }
    }
    clear_last_error();
    builder
        .move_call(
            Function::new(req.package, module, function).with_type_args(req.type_args),
            args,
        )
        .id as i64
}

/// Split a coin into N new coins of specified amounts.
///
/// Returns the BASE Argument ID; use nested_result(base, 0..N-1) for individual coins.
/// Returns -1 if count == 0.
#[no_mangle]
pub unsafe extern "C" fn command_split_coins(
    builder: *mut TransactionBuilder,
    coin_arg_id: u64,
    amount_arg_ids_ptr: *const u64,
    count: usize,
) -> i64 {
    if count == 0 {
        set_last_error("command_split_coins: count must be > 0");
        return -1;
    }
    // SAFETY: builder valid; amount_arg_ids_ptr has count entries.
    let builder = unsafe { &mut *builder };
    let coin = Argument::new(coin_arg_id as usize);
    let amounts = unsafe { slice::from_raw_parts(amount_arg_ids_ptr, count) }
        .iter()
        .map(|&id| Argument::new(id as usize))
        .collect();
    let results = builder.split_coins(coin, amounts);
    clear_last_error();
    results[0].id as i64
}

/// Merge source coins into target (no result produced).
/// Returns 1 on success, -1 if count == 0.
#[no_mangle]
pub unsafe extern "C" fn command_merge_coins(
    builder: *mut TransactionBuilder,
    target_coin_arg_id: u64,
    source_arg_ids_ptr: *const u64,
    count: usize,
) -> i32 {
    if count == 0 {
        set_last_error("command_merge_coins: count must be > 0");
        return -1;
    }
    // SAFETY: builder valid; source_arg_ids_ptr has count entries.
    let builder = unsafe { &mut *builder };
    let target = Argument::new(target_coin_arg_id as usize);
    let sources = unsafe { slice::from_raw_parts(source_arg_ids_ptr, count) }
        .iter()
        .map(|&id| Argument::new(id as usize))
        .collect();
    builder.merge_coins(target, sources);
    clear_last_error();
    1
}

/// Transfer objects to a recipient address.
/// Returns 1 on success, -1 if count == 0.
#[no_mangle]
pub unsafe extern "C" fn command_transfer_objects(
    builder: *mut TransactionBuilder,
    object_arg_ids_ptr: *const u64,
    count: usize,
    recipient_arg_id: u64,
) -> i32 {
    if count == 0 {
        set_last_error("command_transfer_objects: count must be > 0");
        return -1;
    }
    // SAFETY: builder valid; object_arg_ids_ptr has count entries.
    let builder = unsafe { &mut *builder };
    let objects = unsafe { slice::from_raw_parts(object_arg_ids_ptr, count) }
        .iter()
        .map(|&id| Argument::new(id as usize))
        .collect();
    let recipient = Argument::new(recipient_arg_id as usize);
    builder.transfer_objects(objects, recipient);
    clear_last_error();
    1
}

/// Construct a Move vector<T>.
/// type_tag_ptr=NULL / type_tag_len=0 means infer from elements.
/// Returns result Argument ID or: -1 bad UTF-8, -2 type-tag parse error.
#[no_mangle]
pub unsafe extern "C" fn command_make_move_vec(
    builder: *mut TransactionBuilder,
    type_tag_ptr: *const u8,
    type_tag_len: usize,
    elem_arg_ids_ptr: *const u64,
    count: usize,
) -> i64 {
    // SAFETY: builder valid; optional type_tag slice valid when non-null;
    //         elem_arg_ids_ptr has count entries when non-null.
    let builder = unsafe { &mut *builder };

    let type_tag: Option<TypeTag> = if type_tag_ptr.is_null() || type_tag_len == 0 {
        None
    } else {
        let bytes = unsafe { slice::from_raw_parts(type_tag_ptr, type_tag_len) };
        let s = match std::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(format!(
                    "command_make_move_vec: invalid UTF-8 in type_tag: {e}"
                ));
                return -1;
            }
        };
        match s.trim().parse::<TypeTag>() {
            Ok(t) => Some(t),
            Err(e) => {
                set_last_error(format!(
                    "command_make_move_vec: type_tag parse error: {e}"
                ));
                return -2;
            }
        }
    };

    let elements = if count == 0 || elem_arg_ids_ptr.is_null() {
        vec![]
    } else {
        unsafe { slice::from_raw_parts(elem_arg_ids_ptr, count) }
            .iter()
            .map(|&id| Argument::new(id as usize))
            .collect()
    };

    clear_last_error();
    builder.make_move_vec(type_tag, elements).id as i64
}

/// Publish new Move modules.
/// JSON: `{"modules":[[…],…],"dependencies":["0x1","0x2"]}`
/// Returns UpgradeCap Argument ID (≥ 0) or -1 on JSON parse error.
#[no_mangle]
pub unsafe extern "C" fn command_publish(
    builder: *mut TransactionBuilder,
    json_ptr: *const u8,
    json_len: usize,
) -> i64 {
    #[derive(serde::Deserialize)]
    struct Req {
        modules: Vec<Vec<u8>>,
        dependencies: Vec<Address>,
    }
    // SAFETY: builder valid; json slice valid for call.
    let builder = unsafe { &mut *builder };
    let bytes = unsafe { slice::from_raw_parts(json_ptr, json_len) };
    let req: Req = match serde_json::from_slice(bytes) {
        Ok(r) => r,
        Err(e) => {
            set_last_error(format!("command_publish: {e}"));
            return -1;
        }
    };
    clear_last_error();
    builder.publish(req.modules, req.dependencies).id as i64
}

/// Upgrade an existing Move package.
/// JSON: `{"modules":[[…],…],"dependencies":["0x…"],"package":"0xCAFE…","ticket_arg_id":7}`
/// Returns UpgradeReceipt Argument ID (≥ 0) or -1 on JSON parse error.
#[no_mangle]
pub unsafe extern "C" fn command_upgrade(
    builder: *mut TransactionBuilder,
    json_ptr: *const u8,
    json_len: usize,
) -> i64 {
    #[derive(serde::Deserialize)]
    struct Req {
        modules: Vec<Vec<u8>>,
        dependencies: Vec<Address>,
        package: Address,
        ticket_arg_id: usize,
    }
    // SAFETY: builder valid; json slice valid for call.
    let builder = unsafe { &mut *builder };
    let bytes = unsafe { slice::from_raw_parts(json_ptr, json_len) };
    let req: Req = match serde_json::from_slice(bytes) {
        Ok(r) => r,
        Err(e) => {
            set_last_error(format!("command_upgrade: {e}"));
            return -1;
        }
    };
    clear_last_error();
    builder
        .upgrade(
            req.modules,
            req.dependencies,
            req.package,
            Argument::new(req.ticket_arg_id),
        )
        .id as i64
}

// ── Finalisation ──────────────────────────────────────────────────────────────

/// Serialise the transaction to BCS and return a heap buffer:
///   `[u32 LE payload_len][BCS bytes…]`
///
/// Free with `free_bytes(ptr, 4 + payload_len)`.
/// Returns NULL on any error; call `last_error_message` for details.
///
/// IMPORTANT: this call CONSUMES the builder.
/// Do NOT call `free_builder` afterwards.
#[no_mangle]
pub unsafe extern "C" fn build_transaction(builder: *mut TransactionBuilder) -> *mut u8 {
    // SAFETY: builder is a valid Box<TransactionBuilder> produced by new_builder().
    // Box::from_raw re-takes ownership; the builder is dropped at end of scope
    // on both success and error paths.
    let builder = unsafe { Box::from_raw(builder) };
    let payload = match builder.try_build().and_then(|tx| {
        bcs::to_bytes(&tx).map_err(|e| crate::error::Error::Serialization(e.to_string()))
    }) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(format!("build_transaction: {e}"));
            return std::ptr::null_mut();
        }
    };

    clear_last_error();

    // Layout: [u32 LE payload_len][payload bytes]
    let total = 4 + payload.len();
    let mut buf = Vec::<u8>::with_capacity(total);
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(&payload);
    debug_assert_eq!(buf.len(), total);
    debug_assert_eq!(buf.capacity(), total);
    let ptr = buf.as_mut_ptr();
    mem::forget(buf);
    ptr
}

/// Free the buffer returned by `build_transaction`.
/// total_len must equal 4 + payload_len (the u32 from the first 4 bytes).
#[no_mangle]
pub unsafe extern "C" fn free_bytes(ptr: *mut u8, total_len: usize) {
    if total_len == 0 || ptr.is_null() {
        return;
    }
    // SAFETY: ptr was produced by build_transaction with capacity == total_len.
    let layout = std::alloc::Layout::from_size_align(total_len, 1)
        .expect("free_bytes: invalid layout");
    unsafe { std::alloc::dealloc(ptr, layout) };
}
