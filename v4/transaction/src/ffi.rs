// ffi.rs
use crate::{TransactionBuilder, ObjectInput, Function, Argument};
use crate::builder::ResolvedArgument;
use sui_sdk_types::{Address, TypeTag, Identifier};
use std::slice;
use std::mem;
use std::str::FromStr;

// ── Memory Management ────────────────────────────────────────────────────────

/// Allocate `len` bytes of WASM-linear memory for Go to write into.
/// Free with `dealloc(ptr, len)`.
#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    mem::forget(buf);
    ptr
}

/// Free memory previously allocated by `alloc`.
#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    let _ = Vec::from_raw_parts(ptr, len, len);
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
            1
        }
        Err(_) => -1,
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
                Err(_) => return -2,
            };
            builder.add_gas_objects(vec![ObjectInput::owned(g.id, g.version, digest)]);
            1
        }
        Err(_) => -1,
    }
}

// ── Gas pseudo-input ──────────────────────────────────────────────────────────

/// Register (or retrieve) the gas-coin pseudo-input and return its Argument ID.
/// Idempotent — always returns the same ID within one builder.
/// Pass this ID to `command_split_coins` or `command_move_call` wherever
/// a gas-coin argument is needed.
#[no_mangle]
pub unsafe extern "C" fn gas_argument(builder: *mut TransactionBuilder) -> u64 {
    (&mut *builder).gas().id as u64
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
/// Returns Argument ID (≥ 0) on success, -1 on JSON error, -2 on bad digest,
/// -3 on unknown kind.
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
        Err(_) => return -1,
    };

    let obj = match p.kind.as_str() {
        "owned" | "immutable" | "receiving" => {
            let digest_str = match &p.digest {
                Some(d) => d,
                None    => return -2,
            };
            let digest = match sui_sdk_types::Digest::from_str(digest_str) {
                Ok(d)  => d,
                Err(_) => return -2,
            };
            match p.kind.as_str() {
                "owned"     => ObjectInput::owned(p.id, p.version, digest),
                "immutable" => ObjectInput::immutable(p.id, p.version, digest),
                _           => ObjectInput::receiving(p.id, p.version, digest),
            }
        }
        "shared" => ObjectInput::shared(p.id, p.version, p.mutable.unwrap_or(true)),
        _        => return -3,
    };

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

/// Push a BCS-encoded `u128` pure argument supplied as two u64 halves
/// (lo = low 64 bits, hi = high 64 bits). Returns Argument ID.
#[no_mangle]
pub unsafe extern "C" fn pure_u128(
    builder: *mut TransactionBuilder,
    lo: u64,
    hi: u64,
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
        Err(_) => return -1,
    };
    match Address::from_str(s.trim().trim_matches('"')) {
        Ok(addr) => (&mut *builder).pure(&addr).id as i64,
        Err(_)   => -1,
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
/// - `sub_index` – 0-based index of the desired result (0 … N-1).
///
/// Returns the new Argument ID.  Use it wherever a plain Argument ID is
/// accepted (move_call, transfer_objects, etc.).
#[no_mangle]
pub unsafe extern "C" fn nested_result(
    builder: *mut TransactionBuilder,
    base_id: u64,
    sub_index: u64,
) -> i64 {
    let builder = &mut *builder;
    let nested = Argument { id: base_id as usize, sub_index: Some(sub_index as usize) };
    let new_id = builder.arguments.len();
    builder.arguments.insert(new_id, ResolvedArgument::ReplaceWith(nested));
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
        Err(_) => return -1,
    };
    let module = match Identifier::from_str(&req.module) {
        Ok(m)  => m,
        Err(_) => return -2,
    };
    let function = match Identifier::from_str(&req.function) {
        Ok(f)  => f,
        Err(_) => return -3,
    };
    let mut args = Vec::new();
    for a in req.arguments {
        match a {
            CallArg::Id      { id }       => args.push(Argument::new(id)),
            CallArg::PureBcs { pure_bcs } => args.push(builder.pure_bytes(pure_bcs)),
        }
    }
    builder.move_call(
        Function::new(req.package, module, function).with_type_args(req.type_args),
        args,
    ).id as i64
}

/// SplitCoins — split `coin_arg_id` into N coins of the specified amounts.
///
/// - `coin_arg_id`        – Argument ID of the coin to split (use `gas_argument`
///                          for the gas coin, or `input_object` for another coin).
/// - `amount_arg_ids_ptr` – pointer to a C array of `count` uint64 values, each
///                          an Argument ID returned by `pure_u64`.
/// - `count`              – number of amounts / result coins.
///
/// Returns the **base** Argument ID shared by all result coins.
/// Use `nested_result(base, 0)`, `nested_result(base, 1)`, … to address
/// individual coins.
///
/// Returns -1 if `count` is 0.
#[no_mangle]
pub unsafe extern "C" fn command_split_coins(
    builder: *mut TransactionBuilder,
    coin_arg_id: u64,
    amount_arg_ids_ptr: *const u64,
    count: usize,
) -> i64 {
    if count == 0 { return -1; }
    let builder = &mut *builder;
    let coin    = Argument::new(coin_arg_id as usize);
    let amounts = slice::from_raw_parts(amount_arg_ids_ptr, count)
        .iter().map(|&id| Argument::new(id as usize)).collect();
    builder.split_coins(coin, amounts)[0].id as i64
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
    if count == 0 { return -1; }
    let builder = &mut *builder;
    let target  = Argument::new(target_coin_arg_id as usize);
    let sources = slice::from_raw_parts(source_arg_ids_ptr, count)
        .iter().map(|&id| Argument::new(id as usize)).collect();
    builder.merge_coins(target, sources);
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
    if count == 0 { return -1; }
    let builder  = &mut *builder;
    let objects  = slice::from_raw_parts(object_arg_ids_ptr, count)
        .iter().map(|&id| Argument::new(id as usize)).collect();
    let recipient = Argument::new(recipient_arg_id as usize);
    builder.transfer_objects(objects, recipient);
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
            Err(_) => return -1,
        };
        match s.trim().parse::<TypeTag>() {
            Ok(t)  => Some(t),
            Err(_) => return -2,
        }
    };

    let elements = if count == 0 || elem_arg_ids_ptr.is_null() {
        vec![]
    } else {
        slice::from_raw_parts(elem_arg_ids_ptr, count)
            .iter().map(|&id| Argument::new(id as usize)).collect()
    };

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
        Err(_) => return -1,
    };
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
        Err(_) => return -1,
    };
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
/// Free with `free_bytes(ptr, payload_len)` where `payload_len` is the u32
/// read from the first 4 bytes.
///
/// Returns NULL on any build or serialisation error.
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
        Err(_) => return std::ptr::null_mut(),
    };
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
/// Pass the u32 payload length read from the first 4 bytes as `payload_len`.
#[no_mangle]
pub unsafe extern "C" fn free_bytes(ptr: *mut u8, payload_len: usize) {
    let total = 4 + payload_len;
    let _ = Vec::from_raw_parts(ptr, total, total);
}