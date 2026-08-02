#ifndef WALRUS_GO_FFI_H
#define WALRUS_GO_FFI_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Wallet credentials — required in every config_json
 * ====================================================
 * All eight functions require two additional fields so the library never
 * needs ~/.sui/sui_config/client.yaml:
 *
 *   "private_key" : string
 *       Standard Sui keystore entry: base64-std( [scheme_flag_byte] || seed_32_bytes ).
 *       For the Ed25519 signer used by this project the flag byte is 0x00.
 *       Produce it in Go with:
 *           entry := append([]byte{0x00}, signer.PriKey[:32]...)
 *           privateKeyB64 := base64.StdEncoding.EncodeToString(entry)
 *
 *   "sui_address" : string  (0x-prefixed hex, 64 hex chars)
 *       The Sui address that owns the blobs, e.g. signer.Address.
 *
 * Security of temporary files
 * ===========================
 * The library writes an ephemeral sui.keystore and client.yaml under a
 * randomly-named subdirectory of the OS temp dir.  These files are:
 *   • created with mode 0o600 (owner read/write only, no group/world access)
 *   • stored in a directory with mode 0o700
 *   • overwritten with zeros and then deleted when the SDK call returns
 *     (even on error — the zeroing happens in Rust's Drop implementation)
 * The directory name includes a 64-bit mix of wall-clock sub-second nanos
 * and a per-process counter, making it non-guessable by other processes.
 */


/**
 * Store a blob on Walrus (encode → register → upload → certify).
 *
 * config_json – UTF-8 JSON:
 *   {
 *     "walrus_config": "/path/to/client_config.yaml",
 *     "epochs":        5,
 *     "deletable":     false,
 *     "metadata":      {"key": "value"},
 *     "private_key":   "<base64_std([0x00] || seed_32_bytes)>",
 *     "sui_address":   "0x…"
 *   }
 *
 * data_ptr / data_len – raw blob bytes to store.
 *
 * Returns a heap-allocated C string with JSON:
 *   success: {"blob_id":"…","already_certified":bool,"tx_digest":"…"}
 *   failure: {"error":"…"}
 *
 * MUST be freed with walrus_free_string().
 */
char* walrus_store_blob(const char*    config_json,
                        const uint8_t* data_ptr,
                        size_t         data_len);

/** Free a string returned by walrus_store_blob / walrus_delete_blob /
 *  walrus_extend_blob / walrus_list_blobs / walrus_delete_blobs /
 *  walrus_store_blob_in_pool / walrus_create_storage_pool /
 *  walrus_extend_storage_pool / walrus_increase_storage_pool_capacity /
 *  walrus_storage_pool_status / walrus_register_pooled_blob /
 *  walrus_upload_and_certify_pooled_blob. */
void walrus_free_string(char* ptr);


/**
 * Heap-allocated byte buffer returned by walrus_read_blob.
 *
 * On success: ptr/len hold the blob data, cap is the allocation capacity,
 *             err is NULL.
 * On failure: ptr is NULL, len and cap are 0, err points to a JSON string
 *             {"error":"…"} describing what went wrong.
 *
 * walrus_read_blob ALWAYS returns a non-NULL pointer to this struct.
 * walrus_free_bytes MUST be called in both the success and error cases —
 * it frees ptr (if non-NULL) and err (if non-NULL) before freeing the struct.
 * Do NOT free wb->err separately.
 */
typedef struct {
    uint8_t* ptr;
    size_t   len;
    size_t   cap;
    char*    err;
} WalrusBytes;

/**
 * Read a blob from Walrus by blob ID.
 *
 * config_json – UTF-8 JSON:
 *   {
 *     "walrus_config": "/path/to/client_config.yaml",
 *     "blob_id":       "<base64url>",
 *     "private_key":   "<base64_std([0x00] || seed_32_bytes)>",
 *     "sui_address":   "0x…"
 *   }
 *
 * Always returns a non-NULL WalrusBytes*.  Check wb->err before using wb->ptr:
 *   wb->err != NULL  →  read failed; wb->err contains {"error":"…"}
 *   wb->err == NULL  →  success; blob bytes are at wb->ptr[0..wb->len]
 *
 * MUST be freed with walrus_free_bytes() in all cases.
 */
WalrusBytes* walrus_read_blob(const char* config_json);

/** Free a WalrusBytes returned by walrus_read_blob. */
void walrus_free_bytes(WalrusBytes* wb);


/**
 * Delete a deletable blob from Walrus.
 *
 * config_json – UTF-8 JSON:
 *   {
 *     "walrus_config":  "…",
 *     "blob_id":        "<base64url>",   ← supply one of these two
 *     "blob_object_id": "0x…",           ←
 *     "private_key":    "<base64_std([0x00] || seed_32_bytes)>",
 *     "sui_address":    "0x…"
 *   }
 *
 * Returns JSON: {"deleted":N} or {"error":"…"}
 * MUST be freed with walrus_free_string().
 */
char* walrus_delete_blob(const char* config_json);


/**
 * Extend a blob's storage duration by additional epochs.
 *
 * config_json – UTF-8 JSON:
 *   {
 *     "walrus_config":  "…",
 *     "blob_object_id": "0x…",
 *     "epochs":         5,
 *     "private_key":    "<base64_std([0x00] || seed_32_bytes)>",
 *     "sui_address":    "0x…"
 *   }
 *
 * Returns JSON: {"success":true} or {"error":"…"}
 * MUST be freed with walrus_free_string().
 */
char* walrus_extend_blob(const char* config_json);


/**
 * List blobs owned by the configured wallet.
 *
 * config_json – UTF-8 JSON:
 *   {
 *     "walrus_config": "…",
 *     "expiry_policy": "valid",   ← "valid" (default) | "expired" | "all"
 *     "private_key":   "<base64_std([0x00] || seed_32_bytes)>",
 *     "sui_address":   "0x…"
 *   }
 *
 * Returns JSON: {"blobs":[…]} or {"error":"…"}
 * MUST be freed with walrus_free_string().
 */
char* walrus_list_blobs(const char* config_json);


/**
 * Array of per-blob results returned by walrus_read_blobs.
 *
 * When wba->err == NULL, wba->items points to a heap array of wba->count
 * WalrusBytes structs in the same order as the blob_ids supplied.
 * Each items[i] follows the same success/failure convention as WalrusBytes:
 *   items[i].err == NULL  →  success; data at items[i].ptr[0..items[i].len]
 *   items[i].err != NULL  →  that blob failed; items[i].err is {"error":"…"}
 *
 * When wba->err != NULL, setup failed before any read ran (config parse error,
 * client build failure, …); wba->items is NULL and wba->count is 0.
 *
 * walrus_read_blobs ALWAYS returns a non-NULL pointer.
 * walrus_free_bytes_array MUST be called in both the success and error cases.
 * Do NOT free any sub-pointers (items, items[i].ptr, items[i].err) separately.
 */
typedef struct {
    WalrusBytes* items;   /* heap array of `count` WalrusBytes              */
    size_t       count;   /* number of items == number of blob_ids supplied  */
    char*        err;     /* non-NULL only on setup failure                  */
} WalrusBytesArray;

/**
 * Read multiple blobs from Walrus in a single call.
 *
 * Builds the Sui/Walrus client once and reads every blob concurrently,
 * saving N-1 client-build round-trips compared with calling walrus_read_blob
 * N times.
 *
 * config_json – UTF-8 JSON:
 *   {
 *     "walrus_config": "/path/to/client_config.yaml",
 *     "blob_ids":      ["<base64url>", "<base64url>", …],
 *     "private_key":   "<base64_std([0x00] || seed_32_bytes)>",
 *     "sui_address":   "0x…"
 *   }
 *
 * Always returns a non-NULL WalrusBytesArray*.
 * MUST be freed with walrus_free_bytes_array() in all cases.
 */
WalrusBytesArray* walrus_read_blobs(const char* config_json);

/**
 * Free a WalrusBytesArray returned by walrus_read_blobs.
 *
 * Frees every per-blob data buffer, every per-blob error string, the items
 * array, the top-level error string, and finally the struct itself.
 * Safe to call when wba->err != NULL (items will be NULL and is skipped).
 * Do NOT free any sub-pointer before calling this function.
 */
void walrus_free_bytes_array(WalrusBytesArray* wba);


/**
 * Delete multiple deletable blobs from Walrus in a single call.
 *
 * Builds the Sui/Walrus client once and processes deletions sequentially
 * (Sui transactions from one key must be ordered by sequence number).
 * A per-blob failure is recorded in the results array but does NOT abort
 * the remaining deletions.
 *
 * config_json – UTF-8 JSON:
 *   {
 *     "walrus_config": "…",
 *     "blob_ids":      ["<base64url>", "<base64url>", …],
 *     "private_key":   "<base64_std([0x00] || seed_32_bytes)>",
 *     "sui_address":   "0x…"
 *   }
 *
 * Returns JSON:
 *   success:       {"results":[{"blob_id":"…","deleted":N}, …,
 *                               {"blob_id":"…","error":"…"}, …]}
 *   setup failure: {"error":"…"}
 *
 * MUST be freed with walrus_free_string().
 */
char* walrus_delete_blobs(const char* config_json);


/**
 * Store a blob into a specific storage pool (encode → register-in-pool →
 * upload → certify), instead of the caller's own owned Storage.
 *
 * config_json – UTF-8 JSON:
 *   {
 *     "walrus_config":          "/path/to/client_config.yaml",
 *     "epochs":                 5,
 *     "deletable":              false,
 *     "storage_pool_object_id": "0x…",
 *     "private_key":            "<base64_std([0x00] || seed_32_bytes)>",
 *     "sui_address":            "0x…"
 *   }
 *
 * data_ptr / data_len – raw blob bytes to store.
 *
 * Returns a heap-allocated C string with JSON:
 *   success: {"blob_id":"…","pooled_blob_object_id":"…","already_certified":false}
 *   failure: {"error":"…","failure_phase":"…" or null,"blob_id":"…" or null}
 *
 * failure_phase == null means the failure was before any chain call
 * (config/wallet setup) — always safe to retry this call clean.
 * failure_phase set means something already reached the chain — do NOT
 * retry this call blindly. Instead: check real chain state for this
 * blob_id, then either retry this call clean (nothing found), call
 * walrus_upload_and_certify_pooled_blob with the pooled_blob_object_id
 * (found, uncertified), or just update your own bookkeeping (found,
 * already certified — this can happen even on a reported failure, due to
 * read-after-write staleness on the immediate post-certify check).
 *
 * MUST be freed with walrus_free_string().
 */
char* walrus_store_blob_in_pool(const char*    config_json,
                                 const uint8_t* data_ptr,
                                 size_t         data_len);

/**
 * Registers a new PooledBlob entry in the given storage pool. Call this
 * EXACTLY ONCE per logical upload — persist the returned
 * pooled_blob_object_id before calling walrus_upload_and_certify_pooled_blob.
 * Do not retry this call automatically on failure; check real chain state
 * first (see walrus_store_blob_in_pool's doc comment above).
 *
 * config_json – UTF-8 JSON:
 *   {
 *     "walrus_config":          "/path/to/client_config.yaml",
 *     "storage_pool_object_id": "0x…",
 *     "deletable":              false,
 *     "encoding_type":          "RS2",       ← optional
 *     "private_key":            "<base64_std([0x00] || seed_32_bytes)>",
 *     "sui_address":            "0x…"
 *   }
 *
 * data_ptr / data_len – raw blob bytes (needed to compute blob_id/metadata;
 * NOT uploaded to storage nodes in this call — that happens in
 * walrus_upload_and_certify_pooled_blob).
 *
 * Returns JSON: {"blob_id":"…","pooled_blob_object_id":"…"} or {"error":"…"}
 * MUST be freed with walrus_free_string().
 */
char* walrus_register_pooled_blob(const char*    config_json,
                                   const uint8_t* data_ptr,
                                   size_t         data_len);

/**
 * Uploads slivers for an already-registered PooledBlob and certifies it.
 * Safe to call repeatedly with backoff on failure — always checks on-chain
 * certification state first, so a retry after a lost response won't
 * double-certify.
 *
 * config_json – UTF-8 JSON:
 *   {
 *     "walrus_config":          "/path/to/client_config.yaml",
 *     "storage_pool_object_id": "0x…",
 *     "pooled_blob_object_id":  "0x…",       ← from walrus_register_pooled_blob
 *     "blob_id":                "<base64url>",
 *     "encoding_type":          "RS2",       ← optional
 *     "private_key":            "<base64_std([0x00] || seed_32_bytes)>",
 *     "sui_address":            "0x…"
 *   }
 *
 * data_ptr / data_len – raw blob bytes — MUST be the same bytes originally
 * passed to walrus_register_pooled_blob (re-encoded here; encoding is not
 * persisted between the two calls).
 *
 * Returns JSON: {"already_certified":bool} or {"error":"…"}
 * MUST be freed with walrus_free_string().
 */
char* walrus_upload_and_certify_pooled_blob(const char*    config_json,
                                             const uint8_t* data_ptr,
                                             size_t         data_len);

/**
 * Creates a new storage pool and returns its object ID.
 *
 * config_json – UTF-8 JSON:
 *   {
 *     "walrus_config":                   "/path/to/client_config.yaml",
 *     "reserved_encoded_capacity_bytes": 10485760,
 *     "epochs_ahead":                    5,
 *     "private_key":                     "<base64_std([0x00] || seed_32_bytes)>",
 *     "sui_address":                     "0x…"
 *   }
 *
 * Returns JSON: {"storage_pool_object_id":"0x…"} or {"error":"…"}
 *
 * Safe to retry with backoff on failure — a create either lands or it
 * doesn't; there's no partial/duplicate state like walrus_store_blob_in_pool.
 *
 * MUST be freed with walrus_free_string().
 */
char* walrus_create_storage_pool(const char* config_json);

/**
 * Extends a storage pool's lifetime by the given number of epochs.
 *
 * config_json – UTF-8 JSON:
 *   {
 *     "walrus_config":          "/path/to/client_config.yaml",
 *     "storage_pool_object_id": "0x…",
 *     "epochs_extended":        2,
 *     "private_key":            "<base64_std([0x00] || seed_32_bytes)>",
 *     "sui_address":            "0x…"
 *   }
 *
 * Returns JSON: {"ok":true} or {"error":"…"}
 *
 * Safe to retry with backoff on failure.
 *
 * MUST be freed with walrus_free_string().
 */
char* walrus_extend_storage_pool(const char* config_json);

/**
 * Increases a storage pool's reserved encoded capacity.
 *
 * config_json – UTF-8 JSON:
 *   {
 *     "walrus_config":                     "/path/to/client_config.yaml",
 *     "storage_pool_object_id":            "0x…",
 *     "additional_encoded_capacity_bytes": 10485760,
 *     "private_key":                       "<base64_std([0x00] || seed_32_bytes)>",
 *     "sui_address":                       "0x…"
 *   }
 *
 * Returns JSON: {"ok":true} or {"error":"…"}
 *
 * Safe to retry with backoff on failure.
 *
 * MUST be freed with walrus_free_string().
 */
char* walrus_increase_storage_pool_capacity(const char* config_json);

/**
 * Returns the current state of a storage pool: capacity used/available,
 * epoch range, and blob count. Read-only; safe to call anytime, including
 * before walrus_store_blob_in_pool to confirm the pool has enough remaining
 * capacity and epochs — that call will NOT top up or extend the pool itself.
 *
 * config_json – UTF-8 JSON:
 *   {
 *     "walrus_config":          "/path/to/client_config.yaml",
 *     "storage_pool_object_id": "0x…",
 *     "private_key":            "<base64_std([0x00] || seed_32_bytes)>",
 *     "sui_address":            "0x…"
 *   }
 *
 * Returns JSON:
 *   {"storage_pool_object_id":"0x…","start_epoch":N,"end_epoch":N,
 *    "reserved_encoded_capacity_bytes":N,"used_encoded_bytes":N,
 *    "available_encoded_capacity_bytes":N,"blob_count":N}
 *   or {"error":"…"}
 *
 * MUST be freed with walrus_free_string().
 */
char* walrus_storage_pool_status(const char* config_json);


/**
 * List all expired Walrus blob objects owned by the wallet and burn them.
 *
 * Expired blobs can no longer be extended or accessed; burning reclaims their
 * on-chain storage and is the only valid cleanup operation for them.
 * burn_blobs batches up to 1 000 burns per Programmable Transaction Block
 * internally, so a single call handles any number of expired objects.
 *
 * config_json – UTF-8 JSON:
 *   {
 *     "walrus_config": "/path/to/client_config.yaml",
 *     "private_key":   "<base64_std([0x00] || seed_32_bytes)>",
 *     "sui_address":   "0x…"
 *   }
 *
 * Returns JSON:
 *   success: {"burned":N}   — N == 0 means no expired blobs were found
 *   failure: {"error":"…"}
 *
 * MUST be freed with walrus_free_string().
 */
char* walrus_burn_expired_blobs(const char* config_json);

/* ── Opaque handle ───────────────────────────────────────────────────────── */

/**
 * Opaque pointer to a TransactionBuilder.
 * Create with new_builder(), destroy with free_builder() or (implicitly) with
 * a successful build_transaction() call.
 */
typedef struct TransactionBuilder TransactionBuilder;


/* ── Memory management ───────────────────────────────────────────────────── */

/**
 * alloc(len)
 * Allocate `len` bytes inside the Rust heap and return a pointer to them.
 * Use this when your runtime needs to write data into Rust-managed memory.
 * Must be freed with dealloc(ptr, len).
 */
uint8_t *alloc(size_t len);

/**
 * dealloc(ptr, len)
 * Free a buffer previously allocated by alloc().
 * `len` must equal the value passed to the matching alloc() call.
 */
void dealloc(uint8_t *ptr, size_t len);


/* ── Builder lifecycle ───────────────────────────────────────────────────── */

/**
 * new_builder()
 * Create a new, empty TransactionBuilder.
 * Returns an opaque pointer; never NULL.
 */
TransactionBuilder *new_builder(void);

/**
 * free_builder(builder)
 * Destroy a builder that was NOT consumed by build_transaction().
 * Safe to call with NULL.
 * Do NOT call this after a successful build_transaction() call — the builder
 * is already gone.
 */
void free_builder(TransactionBuilder *builder);


/* ── Configuration ───────────────────────────────────────────────────────── */

/**
 * set_config(builder, json_ptr, json_len)
 * Set sender address, optional gas_budget, and optional gas_price from JSON.
 *
 * JSON shape:
 *   {"sender":"0x<hex>","gas_budget":10000000,"gas_price":1000}
 *
 * Returns  1 on success, -1 on JSON parse error.
 */
int32_t set_config(TransactionBuilder *builder,
                   const uint8_t     *json_ptr,
                   size_t             json_len);


/* ── Gas objects ─────────────────────────────────────────────────────────── */

/**
 * add_gas_object(builder, json_ptr, json_len)
 * Add an owned gas object from JSON.
 *
 * JSON shape:
 *   {"id":"0x<hex>","version":2,"digest":"<base58>"}
 *
 * Returns  1 on success, -1 on JSON parse error, -2 on invalid digest.
 */
int32_t add_gas_object(TransactionBuilder *builder,
                       const uint8_t      *json_ptr,
                       size_t              json_len);

/**
 * gas_argument(builder)
 * Register (or retrieve) the gas-coin pseudo-input.
 * Idempotent — always returns the same Argument ID within one builder.
 * Pass the returned ID wherever a gas-coin argument is expected.
 */
uint64_t gas_argument(TransactionBuilder *builder);


/* ── Object inputs ───────────────────────────────────────────────────────── */

/**
 * input_object(builder, json_ptr, json_len)
 * Push an object input (owned / immutable / receiving / shared).
 *
 * JSON shapes:
 *   Owned / immutable / receiving:
 *     {"id":"0x<hex>","version":N,"digest":"<base58>","kind":"owned"}
 *   Shared:
 *     {"id":"0x<hex>","version":N,"mutable":true,"kind":"shared"}
 *
 * Returns Argument ID (>= 0) on success.
 *   -1  JSON parse error
 *   -2  bad or missing digest
 *   -3  unknown kind string
 */
int64_t input_object(TransactionBuilder *builder,
                     const uint8_t      *json_ptr,
                     size_t              json_len);


/* ── Pure-value helpers ──────────────────────────────────────────────────── */

/** Push a BCS-encoded bool. Returns Argument ID. value=0 → false, else true. */
int64_t pure_bool(TransactionBuilder *builder, uint8_t value);

/** Push a BCS-encoded u8. Returns Argument ID. */
int64_t pure_u8(TransactionBuilder *builder, uint8_t value);

/** Push a BCS-encoded u16. Returns Argument ID. */
int64_t pure_u16(TransactionBuilder *builder, uint16_t value);

/** Push a BCS-encoded u32. Returns Argument ID. */
int64_t pure_u32(TransactionBuilder *builder, uint32_t value);

/** Push a BCS-encoded u64. Returns Argument ID. */
int64_t pure_u64(TransactionBuilder *builder, uint64_t value);

/**
 * pure_u128(builder, lo, hi)
 * Push a BCS-encoded u128 supplied as two u64 halves.
 *   value = (hi << 64) | lo
 * Returns Argument ID.
 */
int64_t pure_u128(TransactionBuilder *builder, uint64_t lo, uint64_t hi);

/**
 * pure_address(builder, ptr, len)
 * Push a BCS-encoded Sui address.
 * `ptr` points to a UTF-8 hex string (e.g. "0xabc…") — no JSON quotes.
 * Returns Argument ID on success, -1 on parse error.
 */
int64_t pure_address(TransactionBuilder *builder,
                     const uint8_t      *ptr,
                     size_t              len);

/**
 * pure_raw_bcs(builder, ptr, len)
 * Push raw pre-BCS-encoded bytes as a pure argument.
 * Use this when you have already serialised the value yourself.
 * Returns Argument ID.
 */
int64_t pure_raw_bcs(TransactionBuilder *builder,
                     const uint8_t      *ptr,
                     size_t              len);


/* ── Nested result helper ─────────────────────────────────────────────────── */

/**
 * nested_result(builder, base_id, sub_index)
 * Mint a new Argument ID addressing the `sub_index`-th sub-result of a
 * multi-output command (e.g. the k-th coin from command_split_coins).
 *
 *   base_id   – Argument ID returned by command_split_coins (or similar).
 *   sub_index – 0-based index into the result tuple.
 *
 * Returns the new Argument ID.
 * Example: to access the 2nd split coin — nested_result(builder, base, 1).
 */
int64_t nested_result(TransactionBuilder *builder,
                      uint64_t            base_id,
                      uint64_t            sub_index);


/* ── Commands ────────────────────────────────────────────────────────────── */

/**
 * command_move_call(builder, json_ptr, json_len)
 * Generic Move function call.
 *
 * JSON shape:
 * {
 *   "package":   "0x2",
 *   "module":    "coin",
 *   "function":  "split",
 *   "type_args": ["0x2::sui::SUI"],          // optional
 *   "arguments": [                            // optional
 *     {"id": 3},                              // reference an existing Argument
 *     {"pure_bcs": [1,0,0,0,0,0,0,0]}        // raw BCS bytes inline
 *   ]
 * }
 *
 * Returns result Argument ID (>= 0) on success.
 *   -1  JSON parse error
 *   -2  invalid module identifier
 *   -3  invalid function identifier
 */
int64_t command_move_call(TransactionBuilder *builder,
                          const uint8_t      *json_ptr,
                          size_t              json_len);

/**
 * command_split_coins(builder, coin_arg_id, amount_arg_ids_ptr, count)
 * Split one coin into `count` coins of specified amounts.
 *
 *   coin_arg_id        – Argument ID of the source coin (use gas_argument()
 *                        for the gas coin).
 *   amount_arg_ids_ptr – C array of `count` Argument IDs, each from pure_u64().
 *   count              – number of output coins (must be >= 1).
 *
 * Returns the BASE Argument ID shared by all result coins.
 * Address individual results with nested_result(base, 0..count-1).
 * Returns -1 if count == 0.
 */
int64_t command_split_coins(TransactionBuilder *builder,
                            uint64_t            coin_arg_id,
                            const uint64_t     *amount_arg_ids_ptr,
                            size_t              count);

/**
 * command_merge_coins(builder, target_coin_arg_id, source_arg_ids_ptr, count)
 * Merge `count` source coins into `target_coin_arg_id` (in-place, no result).
 *
 *   target_coin_arg_id – Argument ID of the coin to merge into.
 *   source_arg_ids_ptr – C array of `count` Argument IDs to merge.
 *   count              – number of source coins (must be >= 1).
 *
 * Returns 1 on success, -1 if count == 0.
 */
int32_t command_merge_coins(TransactionBuilder *builder,
                            uint64_t            target_coin_arg_id,
                            const uint64_t     *source_arg_ids_ptr,
                            size_t              count);

/**
 * command_transfer_objects(builder, object_arg_ids_ptr, count, recipient_arg_id)
 * Transfer a list of objects to a recipient.
 *
 *   object_arg_ids_ptr – C array of `count` Argument IDs.
 *   count              – number of objects (must be >= 1).
 *   recipient_arg_id   – Argument ID from pure_address().
 *
 * Returns 1 on success, -1 if count == 0.
 */
int32_t command_transfer_objects(TransactionBuilder *builder,
                                 const uint64_t     *object_arg_ids_ptr,
                                 size_t              count,
                                 uint64_t            recipient_arg_id);

/**
 * command_make_move_vec(builder,
 *                       type_tag_ptr, type_tag_len,
 *                       elem_arg_ids_ptr, count)
 * Construct a Move vector<T> from a list of existing arguments.
 *
 *   type_tag_ptr / type_tag_len – UTF-8 type-tag string e.g. "0x2::sui::SUI".
 *                                 Pass ptr=NULL / len=0 to infer from elements.
 *   elem_arg_ids_ptr            – C array of `count` Argument IDs (may be
 *                                 NULL when count == 0).
 *   count                       – number of elements.
 *
 * Returns result Argument ID (>= 0) on success.
 *   -1  bad type-tag UTF-8
 *   -2  type-tag parse error
 */
int64_t command_make_move_vec(TransactionBuilder *builder,
                              const uint8_t      *type_tag_ptr,
                              size_t              type_tag_len,
                              const uint64_t     *elem_arg_ids_ptr,
                              size_t              count);

/**
 * command_publish(builder, json_ptr, json_len)
 * Publish new Move modules.
 *
 * JSON shape:
 * {
 *   "modules":      [[...bytecode bytes...], ...],
 *   "dependencies": ["0x1", "0x2", ...]
 * }
 *
 * Returns the UpgradeCap Argument ID (>= 0), or -1 on JSON parse error.
 */
int64_t command_publish(TransactionBuilder *builder,
                        const uint8_t      *json_ptr,
                        size_t              json_len);

/**
 * command_upgrade(builder, json_ptr, json_len)
 * Upgrade an existing Move package.
 *
 * JSON shape:
 * {
 *   "modules":       [[...bytecode bytes...], ...],
 *   "dependencies":  ["0x1", "0x2"],
 *   "package":       "0xCAFE...",
 *   "ticket_arg_id": 7
 * }
 * `ticket_arg_id` must point to the UpgradeTicket from
 * 0x2::package::authorize_upgrade.
 *
 * Returns the UpgradeReceipt Argument ID (>= 0), or -1 on JSON parse error.
 */
int64_t command_upgrade(TransactionBuilder *builder,
                        const uint8_t      *json_ptr,
                        size_t              json_len);


/* ── Finalisation ────────────────────────────────────────────────────────── */

/**
 * build_transaction(builder)
 * Serialise the fully-built transaction to BCS and return a heap buffer.
 *
 * Buffer layout:
 *   [4 bytes: uint32_t payload_len, little-endian]
 *   [payload_len bytes: BCS-encoded transaction data]
 *
 * To consume:
 *   1. Read the first 4 bytes as a little-endian uint32_t → payload_len.
 *   2. Read the next payload_len bytes → your BCS payload.
 *   3. Call free_bytes(ptr, payload_len) to release the buffer.
 *
 * Returns NULL on any build or serialisation error.
 *
 * IMPORTANT: This call CONSUMES (drops) the builder.
 *            Do NOT call free_builder() after a successful call.
 *            On NULL return the builder is still valid and must be freed with
 *            free_builder().
 */
uint8_t *build_transaction(TransactionBuilder *builder);

/**
 * free_bytes(ptr, payload_len)
 * Free the buffer returned by build_transaction().
 * `payload_len` is the uint32_t read from the first 4 bytes of the buffer
 * (NOT the total buffer size — the library adds 4 internally).
 */
void free_bytes(uint8_t *ptr, size_t payload_len);

/**
 * Estimates the on-chain encoded size of a blob BEFORE uploading it, split
 * into metadata bytes vs. data (sliver) bytes. Pure computation — no
 * network calls, no signing, safe to call as often as you like (e.g. as
 * soon as the user picks a file, before any upload begins).
 *
 * config_json – UTF-8 JSON:
 *   {
 *     "unencoded_length": 39,
 *     "n_shards":         1000,
 *     "encoding_type":    "RS2"     ← optional, defaults to RS2
 *   }
 *
 * Returns a heap-allocated C string with JSON:
 *   success: {"metadata_size":64032000,"data_size":2002000,"total_encoded_size":66034000}
 *   failure: {"error":"…"}
 *
 * metadata_size scales with n_shards, not with unencoded_length — it's the
 * fixed cost that makes small blobs disproportionately expensive on-chain.
 * data_size is the part that actually scales with the input size.
 *
 * MUST be freed with walrus_free_string().
 */
char* walrus_estimate_encoded_size(const char* config_json);

#ifdef __cplusplus
}
#endif

#endif /* WALRUS_GO_FFI_H */
