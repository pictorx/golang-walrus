// ffi.rs
use crate::{TransactionBuilder, ObjectInput, Function, Argument};
use crate::builder::ResolvedArgument;
use sui_sdk_types::{Address, TypeTag, Identifier};
use std::cell::RefCell;
use std::slice;
use std::mem;
use std::str::FromStr;

// ── Thread-local error slot ───────────────────────────────────────────────────

thread_local! {
    /// Stores the last error message produced by any FFI call on this thread.
    /// Cleared to None on any successful call that returns a meaningful value.
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Record an error message into the thread-local slot.
fn set_last_error(e: impl std::fmt::Display) {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = Some(e.to_string());
    });
}

/// Clear the thread-local error slot after a successful operation.
fn clear_last_error() {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

/// Return a pointer to the last error message (UTF-8, **not** null-terminated)
/// and write its byte length into `*len_out`.
///
/// Returns NULL and sets `*len_out = 0` if no error has occurred since the last
/// successful call.
///
/// The pointer is valid only until the **next** FFI call on the same thread.
/// Do NOT pass it to `dealloc` or `free_bytes` — it is owned by the runtime.
#[no_mangle]
pub unsafe extern "C" fn last_error_message(len_out: *mut usize) -> *const u8 {
    LAST_ERROR.with(|cell| {
        match cell.borrow().as_ref() {
            None => {
                if !len_out.is_null() {
                    *len_out = 0;
                }
                std::ptr::null()
            }
            Some(s) => {
                if !len_out.is_null() {
                    *len_out = s.len();
                }
                s.as_ptr()
            }
        }
    })
}

// ── Memory Management ────────────────────────────────────────────────────────

/// Allocate `len` bytes of memory for the caller to write into.
/// Free with `dealloc(ptr, len)`.
///
/// Uses `std::alloc::alloc` directly so that capacity == len is an explicit
/// invariant, making the matching `dealloc` safe regardless of future changes.
#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    if len == 0 {
        // SAFETY: NonNull::dangling() is a valid non-null, non-zero pointer.
        return std::ptr::NonNull::dangling().as_ptr();
    }
    // SAFETY: align=1 is always valid; len>0 checked above.
    let layout = std::alloc::Layout::from_size_align(len, 1)
        .expect("alloc: invalid layout");
    unsafe { std::alloc::alloc(layout) }
}

/// Free memory previously allocated by `alloc(len)`.
/// Calling with len=0 or a null pointer is a no-op.
#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    if len == 0 || ptr.is_null() {
        return;
    }
    // SAFETY: layout must exactly match the one used in `alloc`.
    let layout = std::alloc::Layout::from_size_align(len, 1)
        .expect("dealloc: invalid layout");
    std::alloc::dealloc(ptr, layout);
}

// ── Builder Lifecycle ────────────────────────────────────────────────────────

/// Create a new TransactionBuilder and return an opaque pointer to it.
#[no_mangle]
pub extern "C" fn new_builder() -> *mut TransactionBuilder {
    Box::into_raw(Box::new(TransactionBuilder::new()))
}

/// Free a builder that was NOT consumed by `build_transaction`.
/// Do NOT call this after a successful `build_transaction` call.
#[no_mangle]
pub unsafe extern "C" fn free_builder(builder: *mut TransactionBuilder) {
    if !builder.is_null() {
        drop(Box::from_raw(builder));
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
/// JSON shape: `{"sender":"0x…","gas_budget":10000000,"gas_price":1000}`
/// Returns 1 on success, -1 on parse error.
#[no_mangle]
pub unsafe extern "C" fn set_config(
    builder: *mut TransactionBuilder,
    json_ptr: *const u8,
    json_len: usize,
) -> i32 {
    let builder = &mut *builder;
    let bytes = slice::from_raw_parts(json_ptr, json_len);
    match serde_json::from_slice::<ConfigParams>(bytes) {
        Ok(p) => {
            builder.set_sender(p.sender);
            if let Some(b) = p.gas_budget { builder.set_gas_budget(b); }
            if let Some(p) = p.gas_price  { builder.set_gas_price(p);  }
            clear_last_error();
            1
        }
        Err(e) => {
            set_last_error(format!("set_config: {e}"));
            -1
        }
    }
}

// ── Gas Objects ───────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct GasObjectParams {
    id: Address,
    version: u64,
    digest: String,
}

/// Add an owned gas object from a JSON object.
/// JSON shape: `{"id":"0x…","version":2,"digest":"base58…"}`
/// Returns 1 on success, -1 on JSON parse error, -2 on invalid digest.
#[no_mangle]
pub unsafe extern "C" fn add_gas_object(
    builder: *mut TransactionBuilder,
    json_ptr: *const u8,
    json_len: usize,
) -> i32 {
    let builder = &mut *builder;
    let bytes = slice::from_raw_parts(json_ptr, json_len);
    match serde_json::from_slice::<GasObjectParams>(bytes) {
        Ok(g) => {
            let digest = match sui_sdk_types::Digest::from_str(&g.digest) {
                Ok(d)  => d,
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
///
/// Idempotent — always returns the same ID within one builder.
/// Pass this ID to `command_split_coins` or `command_move_call` wherever
/// a gas-coin argument is needed.
///
/// Returns the Argument ID as an i64 (always ≥ 0; cannot fail).
///
/// CHANGED: return type is now `i64` (was `u64`) to be consistent with all
/// other argument-returning FFI functions which use i64 with negative = error.
#[no_mangle]
pub unsafe extern "C" fn gas_argument(builder: *mut TransactionBuilder) -> i64 {
    (&mut *builder).gas().id as i64
}

// ── Object inputs ─────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct ObjectInputParams {
    id: Address,
    version: u64,
    digest: Option<String>,   // required for owned / immutable / receiving
    mutable: Option<bool>,    // required for shared; ignored otherwise
    #[serde(rename = "kind")]
    kind: String,             // "owned" | "immutable" | "receiving" | "shared"
}

/// Push an object input (owned, immutable, receiving, or shared) and return
/// its Argument ID.
///
/// JSON shape:
///   Owned/immutable/receiving: `{"id":"0x…","version":N,"digest":"…","kind":"owned"}`
///   Shared:                    `{"id":"0x…","version":N,"mutable":true,"kind":"shared"}`
///
/// Returns Argument ID (≥ 0) on success, or:
///   -1  JSON parse error
///   -2  missing or invalid digest
///   -3  unknown kind string
#[no_mangle]
pub unsafe extern "C" fn input_object(
    builder: *mut TransactionBuilder,
    json_ptr: *const u8,
    json_len: usize,
) -> i64 {
    let builder = &mut *builder;
    let bytes = slice::from_raw_parts(json_ptr, json_len);
    let p: ObjectInputParams = match serde_json::from_slice(bytes) {
        Ok(v)  => v,
        Err(e) => {
            set_last_error(format!("input_object: {e}"));
            return -1;
        }
    };

    let obj = match p.kind.as_str() {
        "owned" | "immutable" | "receiving" => {
            let digest_str = match &p.digest {
                Some(d) => d,
                None    => {
                    set_last_error("input_object: 'digest' is required for owned/immutable/receiving");
                    return -2;
                }
            };
            let digest = match sui_sdk_types::Digest::from_str(digest_str) {
                Ok(d)  => d,
                Err(e) => {
                    set_last_error(format!("input_object: invalid digest: {e}"));
                    return -2;
                }
            };
            match p.kind.as_str() {
                "owned"     => ObjectInput::owned(p.id, p.version, digest),
                "immutable" => ObjectInput::immutable(p.id, p.version, digest),
                _           => ObjectInput::receiving(p.id, p.version, digest),
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

/// Push a BCS-encoded `bool` pure argument. Returns Argument ID.
#[no_mangle]
pub unsafe extern "C" fn pure_bool(builder: *mut TransactionBuilder, value: u8) -> i64 {
    (&mut *builder).pure(&(value != 0)).id as i64
}

/// Push a BCS-encoded `u8` pure argument. Returns Argument ID.
#[no_mangle]
pub unsafe extern "C" fn pure_u8(builder: *mut TransactionBuilder, value: u8) -> i64 {
    (&mut *builder).pure(&value).id as i64
}

/// Push a BCS-encoded `u16` pure argument. Returns Argument ID.
#[no_mangle]
pub unsafe extern "C" fn pure_u16(builder: *mut TransactionBuilder, value: u16) -> i64 {
    (&mut *builder).pure(&value).id as i64
}

/// Push a BCS-encoded `u32` pure argument. Returns Argument ID.
#[no_mangle]
pub unsafe extern "C" fn pure_u32(builder: *mut TransactionBuilder, value: u32) -> i64 {
    (&mut *builder).pure(&value).id as i64
}

/// Push a BCS-encoded `u64` pure argument. Returns Argument ID.
#[no_mangle]
pub unsafe extern "C" fn pure_u64(builder: *mut TransactionBuilder, value: u64) -> i64 {
    (&mut *builder).pure(&value).id as i64
}

/// Push a BCS-encoded `u128` pure argument supplied as two `u64` halves.
///
/// Argument order: `hi` = high 64 bits, `lo` = low 64 bits.
/// Reconstructed value = `(hi << 64) | lo`.
///
/// Example — passing `u128::MAX`:
///   `pure_u128(builder, u64::MAX, u64::MAX)`
///
/// Returns Argument ID.
#[no_mangle]
pub unsafe extern "C" fn pure_u128(
    builder: *mut TransactionBuilder,
    hi: u64,
    lo: u64,
) -> i64 {
    let value: u128 = ((hi as u128) << 64) | (lo as u128);
    (&mut *builder).pure(&value).id as i64
}

/// Push a BCS-encoded `address` pure argument.
/// Accepts a bare hex string (e.g. `0xabc…`) — no JSON quotes needed.
/// Returns Argument ID on success, -1 on parse error.
#[no_mangle]
pub unsafe extern "C" fn pure_address(
    builder: *mut TransactionBuilder,
    ptr: *const u8,
    len: usize,
) -> i64 {
    let bytes = slice::from_raw_parts(ptr, len);
    let s = match std::str::from_utf8(bytes) {
        Ok(s)  => s,
        Err(e) => {
            set_last_error(format!("pure_address: invalid UTF-8: {e}"));
            return -1;
        }
    };
    match Address::from_str(s.trim().trim_matches('"')) {
        Ok(addr) => {
            clear_last_error();
            (&mut *builder).pure(&addr).id as i64
        }
        Err(e) => {
            set_last_error(format!("pure_address: {e}"));
            -1
        }
    }
}

/// Push raw pre-BCS-encoded bytes as a pure argument. Returns Argument ID.
/// Use this when you have already BCS-encoded the value on the Go side.
#[no_mangle]
pub unsafe extern "C" fn pure_raw_bcs(
    builder: *mut TransactionBuilder,
    ptr: *const u8,
    len: usize,
) -> i64 {
    let bytes = slice::from_raw_parts(ptr, len).to_vec();
    (&mut *builder).pure_bytes(bytes).id as i64
}

// ── Nested result helper ──────────────────────────────────────────────────────

/// Mint a new Argument ID that aliases the Nth sub-result of a multi-output
/// command (e.g. the Kth coin from a SplitCoins with N amounts).
///
/// - `base_id`   – Argument ID returned by `command_split_coins`.
///                 Must refer to a command (not a plain input).
/// - `sub_index` – 0-based index of the desired result (0 … N-1).
///
/// Returns the new Argument ID (≥ 0) on success, or:
///   -1  `base_id` does not refer to any known argument
///   -2  `base_id` is a plain input, not a command result
///
/// Use the returned ID wherever a plain Argument ID is accepted
/// (move_call, transfer_objects, etc.).
#[no_mangle]
pub unsafe extern "C" fn nested_result(
    builder: *mut TransactionBuilder,
    base_id: u64,
    sub_index: u64,
) -> i64 {
    let builder = &mut *builder;
    let base = base_id as usize;

    // Validate that base_id was previously returned by a builder call.
    if !builder.arguments.contains_key(&base) {
        set_last_error(format!(
            "nested_result: base_id {base_id} does not refer to a known argument"
        ));
        return -1;
    }

    // Validate that base_id is a command result, not a plain input.
    // Only commands produce multi-value results that can be indexed by sub_index.
    if !builder.commands.contains_key(&base) {
        set_last_error(format!(
            "nested_result: base_id {base_id} is a plain input, not a command result; \
             sub_index is only valid on command outputs (e.g. from command_split_coins)"
        ));
        return -2;
    }

    let nested = Argument { id: base, sub_index: Some(sub_index as usize) };
    let new_id = builder.arguments.len();
    builder.arguments.insert(new_id, ResolvedArgument::ReplaceWith(nested));
    clear_last_error();
    new_id as i64
}

// ── Commands ──────────────────────────────────────────────────────────────────

/// Generic Move call.
///
/// JSON shape:
/// ```json
/// {
///   "package":   "0x2",
///   "module":    "coin",
///   "function":  "split",
///   "type_args": ["0x2::sui::SUI"],
///   "arguments": [
///     {"id": 3},
///     {"pure_bcs": [1,0,0,0,0,0,0,0]}
///   ]
/// }
/// ```
/// `arguments` entries:
///   - `{"id": N}` – reference an existing Argument by ID.
///   - `{"pure_bcs": [bytes…]}` – raw pre-encoded BCS bytes.
///
/// Returns the result Argument ID (≥ 0), or:
///   -1  JSON parse error
///   -2  invalid module identifier
///   -3  invalid function identifier
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
        Id      { id: usize },
        PureBcs { pure_bcs: Vec<u8> },
    }

    let builder = &mut *builder;
    let bytes = slice::from_raw_parts(json_ptr, json_len);
    let req: Req = match serde_json::from_slice(bytes) {
        Ok(r)  => r,
        Err(e) => {
            set_last_error(format!("command_move_call: {e}"));
            return -1;
        }
    };
    let module = match Identifier::from_str(&req.module) {
        Ok(m)  => m,
        Err(e) => {
            set_last_error(format!("command_move_call: invalid module identifier: {e}"));
            return -2;
        }
    };
    let function = match Identifier::from_str(&req.function) {
        Ok(f)  => f,
        Err(e) => {
            set_last_error(format!("command_move_call: invalid function identifier: {e}"));
            return -3;
        }
    };
    let mut args = Vec::new();
    for a in req.arguments {
        match a {
            CallArg::Id      { id }       => args.push(Argument::new(id)),
            CallArg::PureBcs { pure_bcs } => args.push(builder.pure_bytes(pure_bcs)),
        }
    }
    clear_last_error();
    builder.move_call(
        Function::new(req.package, module, function).with_type_args(req.type_args),
        args,
    ).id as i64
}

/// SplitCoins — split `coin_arg_id` into N coins of the specified amounts.
///
/// - `coin_arg_id`        – Argument ID of the coin to split (use `gas_argument`
///                          for the gas coin, or `input_object` for another coin).
/// - `amount_arg_ids_ptr` – pointer to a C array of `count` i64 values, each an
///                          Argument ID returned by `pure_u64`.
/// - `count`              – number of amounts / result coins.
///
/// Returns the **base** Argument ID shared by all result coins.
/// Use `nested_result(base, 0)`, `nested_result(base, 1)`, … to address
/// individual result coins.
///
/// Returns -1 if `count` is 0.
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
    let builder = &mut *builder;
    let coin    = Argument::new(coin_arg_id as usize);
    let amounts = slice::from_raw_parts(amount_arg_ids_ptr, count)
        .iter().map(|&id| Argument::new(id as usize)).collect();
    // split_coins returns a Vec of Arguments that all share the same base `id`
    // but have different sub_index values (0..count).  We return the base id
    // so the caller can use nested_result(base, k) to address individual coins.
    let results = builder.split_coins(coin, amounts);
    clear_last_error();
    results[0].id as i64
}

/// MergeCoins — merge `sources` into `target_coin_arg_id` (no result produced).
///
/// - `target_coin_arg_id` – Argument ID of the coin to merge into.
/// - `source_arg_ids_ptr` – pointer to a C array of `count` uint64 Argument IDs.
/// - `count`              – number of coins to merge (must be ≥ 1).
///
/// Returns 1 on success, -1 if `count` is 0.
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
    let builder = &mut *builder;
    let target  = Argument::new(target_coin_arg_id as usize);
    let sources = slice::from_raw_parts(source_arg_ids_ptr, count)
        .iter().map(|&id| Argument::new(id as usize)).collect();
    builder.merge_coins(target, sources);
    clear_last_error();
    1
}

/// TransferObjects — send a list of objects to a recipient address.
///
/// - `object_arg_ids_ptr` – pointer to a C array of `count` uint64 Argument IDs.
/// - `count`              – number of objects to transfer (must be ≥ 1).
/// - `recipient_arg_id`   – Argument ID returned by `pure_address`.
///
/// Returns 1 on success, -1 if `count` is 0.
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
    let builder  = &mut *builder;
    let objects  = slice::from_raw_parts(object_arg_ids_ptr, count)
        .iter().map(|&id| Argument::new(id as usize)).collect();
    let recipient = Argument::new(recipient_arg_id as usize);
    builder.transfer_objects(objects, recipient);
    clear_last_error();
    1
}

/// MakeMoveVector — construct a Move `vector<T>` from a list of arguments.
///
/// - `type_tag_ptr` / `type_tag_len` – UTF-8 type-tag string (e.g. `"0x2::sui::SUI"`).
///   Pass ptr=0 / len=0 when the type can be inferred from the elements.
/// - `elem_arg_ids_ptr` – pointer to a C array of `count` uint64 Argument IDs.
/// - `count`            – number of elements.
///
/// Returns the result Argument ID, or:
///   -1  bad type-tag UTF-8
///   -2  type-tag parse error
#[no_mangle]
pub unsafe extern "C" fn command_make_move_vec(
    builder: *mut TransactionBuilder,
    type_tag_ptr: *const u8,
    type_tag_len: usize,
    elem_arg_ids_ptr: *const u64,
    count: usize,
) -> i64 {
    let builder = &mut *builder;

    let type_tag: Option<TypeTag> = if type_tag_ptr.is_null() || type_tag_len == 0 {
        None
    } else {
        let bytes = slice::from_raw_parts(type_tag_ptr, type_tag_len);
        let s = match std::str::from_utf8(bytes) {
            Ok(s)  => s,
            Err(e) => {
                set_last_error(format!("command_make_move_vec: invalid UTF-8 in type_tag: {e}"));
                return -1;
            }
        };
        match s.trim().parse::<TypeTag>() {
            Ok(t)  => Some(t),
            Err(e) => {
                set_last_error(format!("command_make_move_vec: type_tag parse error: {e}"));
                return -2;
            }
        }
    };

    let elements = if count == 0 || elem_arg_ids_ptr.is_null() {
        vec![]
    } else {
        slice::from_raw_parts(elem_arg_ids_ptr, count)
            .iter().map(|&id| Argument::new(id as usize)).collect()
    };

    clear_last_error();
    builder.make_move_vec(type_tag, elements).id as i64
}

/// Publish — publish new Move modules.
///
/// JSON shape:
/// ```json
/// {
///   "modules":      [[…bytecode bytes…], …],
///   "dependencies": ["0x1", "0x2", …]
/// }
/// ```
/// Returns the `UpgradeCap` Argument ID (≥ 0), or -1 on JSON parse error.
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
    let builder = &mut *builder;
    let bytes = slice::from_raw_parts(json_ptr, json_len);
    let req: Req = match serde_json::from_slice(bytes) {
        Ok(r)  => r,
        Err(e) => {
            set_last_error(format!("command_publish: {e}"));
            return -1;
        }
    };
    clear_last_error();
    builder.publish(req.modules, req.dependencies).id as i64
}

/// Upgrade — upgrade an existing Move package.
///
/// JSON shape:
/// ```json
/// {
///   "modules":      [[…bytecode bytes…], …],
///   "dependencies": ["0x1", "0x2"],
///   "package":      "0xCAFE…",
///   "ticket_arg_id": 7
/// }
/// ```
/// `ticket_arg_id` must be an Argument ID pointing to the `UpgradeTicket`
/// produced by `0x2::package::authorize_upgrade`.
///
/// Returns the `UpgradeReceipt` Argument ID (≥ 0), or -1 on JSON parse error.
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
    let builder = &mut *builder;
    let bytes = slice::from_raw_parts(json_ptr, json_len);
    let req: Req = match serde_json::from_slice(bytes) {
        Ok(r)  => r,
        Err(e) => {
            set_last_error(format!("command_upgrade: {e}"));
            return -1;
        }
    };
    clear_last_error();
    builder.upgrade(
        req.modules,
        req.dependencies,
        req.package,
        Argument::new(req.ticket_arg_id),
    ).id as i64
}

// ── Finalisation ─────────────────────────────────────────────────────────────

/// Serialise the fully-built transaction to BCS.
///
/// Returns a pointer to a heap buffer laid out as:
///   `[u32 payload_len (LE 4 bytes)][BCS bytes … payload_len bytes]`
///
/// Free with `free_bytes(ptr, 4 + payload_len)` where `payload_len` is the
/// u32 read from the first 4 bytes.
///
/// Returns NULL on any build or serialisation error.  On NULL, call
/// `last_error_message` to retrieve a human-readable description of what
/// went wrong.
///
/// IMPORTANT: this call consumes (drops) the builder.
/// Do NOT call `free_builder` afterwards.
#[no_mangle]
pub unsafe extern "C" fn build_transaction(builder: *mut TransactionBuilder) -> *mut u8 {
    let builder = Box::from_raw(builder);
    let payload = match builder.try_build().and_then(|tx| {
        bcs::to_bytes(&tx).map_err(|e| crate::error::Error::Input(e.to_string()))
    }) {
        Ok(b)  => b,
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
///
/// Pass `4 + payload_len` as `total_len`, where `payload_len` is the u32
/// read from the first 4 bytes of the buffer.
#[no_mangle]
pub unsafe extern "C" fn free_bytes(ptr: *mut u8, total_len: usize) {
    if total_len == 0 || ptr.is_null() {
        return;
    }
    let layout = std::alloc::Layout::from_size_align(total_len, 1)
        .expect("free_bytes: invalid layout");
    std::alloc::dealloc(ptr, layout);
}