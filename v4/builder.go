// builder.go
//
// Go bindings for the transaction_builder WASM module.
//
// Usage:
//
//	b, err := txbuilder.NewBuilder(ctx, mod)
//	b.SetConfig(sender, 10_000_000, 1_000)
//	b.AddGasObject(id, version, digest)
//	gasID        := b.GasArgument()
//	amtID        := b.PureU64(100_000_000)
//	baseID, err  := b.SplitCoins(gasID, []uint64{amtID})
//	coinID, err  := b.NestedResult(baseID, 0)   // now returns (uint64, error)
//	recID,  err  := b.PureAddress("0xabc…")
//	b.TransferObjects([]uint64{coinID}, recID)
//	bcsBytes, err := b.Build()

package v4

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
)

// ── internal memory helpers ───────────────────────────────────────────────────

func writeBytes(ctx context.Context, mod api.Module, data []byte) (ptr uint64, size uint64) {
	if len(data) == 0 {
		return 0, 0
	}
	res, err := mod.ExportedFunction("alloc").Call(ctx, uint64(len(data)))
	if err != nil {
		panic(fmt.Sprintf("txbuilder alloc: %v", err))
	}
	ptr = res[0]
	if !mod.Memory().Write(uint32(ptr), data) {
		panic("txbuilder: Memory.Write failed")
	}
	return ptr, uint64(len(data))
}

func freeBytes_(ctx context.Context, mod api.Module, ptr, size uint64) {
	if ptr == 0 {
		return
	}
	mod.ExportedFunction("dealloc").Call(ctx, ptr, size) //nolint:errcheck
}

func callFn(ctx context.Context, mod api.Module, name string, args ...uint64) []uint64 {
	res, err := mod.ExportedFunction(name).Call(ctx, args...)
	if err != nil {
		panic(fmt.Sprintf("txbuilder %s: %v", name, err))
	}
	return res
}

// u64SlicePtr writes a []uint64 into WASM memory as a C uint64_t array and
// returns (wasmPtr, byteSize).  Caller must free with dealloc(ptr, size).
func u64SlicePtr(ctx context.Context, mod api.Module, ids []uint64) (uint64, uint64) {
	if len(ids) == 0 {
		return 0, 0
	}
	buf := make([]byte, len(ids)*8)
	for i, v := range ids {
		*(*uint64)(unsafe.Pointer(&buf[i*8])) = v
	}
	return writeBytes(ctx, mod, buf)
}

// ── Builder ───────────────────────────────────────────────────────────────────

// Builder wraps the WASM TransactionBuilder pointer and the wazero module.
// It is NOT safe for concurrent use.
type Builder struct {
	ctx context.Context
	mod api.Module
	ptr uint64 // opaque pointer into WASM linear memory
}

// NewBuilder instantiates a fresh TransactionBuilder inside the WASM module.
func NewBuilder(ctx context.Context, mod api.Module) *Builder {
	ptr := callFn(ctx, mod, "new_builder")[0]
	return &Builder{ctx: ctx, mod: mod, ptr: ptr}
}

// Free releases a builder that was NOT consumed by Build().
// After a successful Build() call the builder is already freed — do not call
// Free() in that case.
func (b *Builder) Free() {
	if b.ptr != 0 {
		callFn(b.ctx, b.mod, "free_builder", b.ptr)
		b.ptr = 0
	}
}

// ── Error helper ──────────────────────────────────────────────────────────────

// lastError reads the last error message stored by the Rust WASM module via
// last_error_message and returns it as a Go error.
// Falls back to fallback if no Rust-side message is available.
//
// IMPORTANT: call this immediately after a failing FFI call, before any other
// WASM call on the same goroutine.  The string pointer returned by Rust points
// into thread-local storage and is only valid until the next FFI call.
func (b *Builder) lastError(fallback string) error {
	// Allocate 4 bytes in WASM for the usize (= u32 on wasm32) length output.
	lenPtrRes, err := b.mod.ExportedFunction("alloc").Call(b.ctx, 4)
	if err != nil || len(lenPtrRes) == 0 {
		return fmt.Errorf("%s", fallback)
	}
	lenPtr := lenPtrRes[0]
	defer b.mod.ExportedFunction("dealloc").Call(b.ctx, lenPtr, 4) //nolint:errcheck

	// last_error_message(len_out: *mut usize) -> *const u8
	// Writes the byte-length of the error string into *lenPtr and returns a
	// pointer to the UTF-8 string data inside Rust thread-local storage.
	msgPtrRes, err := b.mod.ExportedFunction("last_error_message").Call(b.ctx, lenPtr)
	if err != nil || len(msgPtrRes) == 0 {
		return fmt.Errorf("%s", fallback)
	}
	strPtr := uint32(msgPtrRes[0])
	if strPtr == 0 {
		// No error recorded on the Rust side; use caller-supplied fallback.
		return fmt.Errorf("%s", fallback)
	}

	// Read the 4-byte little-endian length written into lenPtr.
	// On wasm32, usize = u32, so Rust writes exactly 4 bytes.
	lenBytes, ok := b.mod.Memory().Read(uint32(lenPtr), 4)
	if !ok {
		return fmt.Errorf("%s", fallback)
	}
	strLen := binary.LittleEndian.Uint32(lenBytes)
	if strLen == 0 {
		return fmt.Errorf("%s", fallback)
	}

	// Read the UTF-8 error string from WASM linear memory.
	msgBytes, ok := b.mod.Memory().Read(strPtr, strLen)
	if !ok {
		return fmt.Errorf("%s", fallback)
	}
	return fmt.Errorf("%s", string(msgBytes))
}

// ── Configuration ─────────────────────────────────────────────────────────────

// SetConfig sets the sender address, gas budget, and gas price.
// sender must be a 0x-prefixed 32-byte hex string.
func (b *Builder) SetConfig(sender string, gasBudget, gasPrice uint64) error {
	payload, _ := json.Marshal(map[string]any{
		"sender":     sender,
		"gas_budget": gasBudget,
		"gas_price":  gasPrice,
	})
	ptr, size := writeBytes(b.ctx, b.mod, payload)
	defer freeBytes_(b.ctx, b.mod, ptr, size)
	code := int32(callFn(b.ctx, b.mod, "set_config", b.ptr, ptr, size)[0])
	if code != 1 {
		return b.lastError(fmt.Sprintf("set_config failed (code %d) — check sender address format", code))
	}
	return nil
}

// ── Gas objects ───────────────────────────────────────────────────────────────

// AddGasObject adds an owned gas coin identified by its object ID, version,
// and base-58 digest string.
func (b *Builder) AddGasObject(id string, version uint64, digest string) error {
	payload, _ := json.Marshal(map[string]any{
		"id":      id,
		"version": version,
		"digest":  digest,
	})
	ptr, size := writeBytes(b.ctx, b.mod, payload)
	defer freeBytes_(b.ctx, b.mod, ptr, size)
	code := int32(callFn(b.ctx, b.mod, "add_gas_object", b.ptr, ptr, size)[0])
	switch code {
	case 1:
		return nil
	case -2:
		return b.lastError(fmt.Sprintf("add_gas_object: invalid digest %q", digest))
	default:
		return b.lastError(fmt.Sprintf("add_gas_object failed (code %d)", code))
	}
}

// ── Gas pseudo-input ──────────────────────────────────────────────────────────

// GasArgument returns the Argument ID for the transaction's gas coin.
// Idempotent — always returns the same ID within one builder.
//
// CHANGED: gas_argument now returns i64 in Rust (was u64) to match the
// convention of all other argument-returning FFI functions.  It can never be
// negative, so the Go return type remains uint64.
func (b *Builder) GasArgument() uint64 {
	res := int64(callFn(b.ctx, b.mod, "gas_argument", b.ptr)[0])
	// gas_argument cannot fail; always returns a valid non-negative argument ID.
	return uint64(res)
}

// ── Object inputs ─────────────────────────────────────────────────────────────

// ObjectKind describes how an object is used as an input.
type ObjectKind string

const (
	ObjectKindOwned     ObjectKind = "owned"
	ObjectKindImmutable ObjectKind = "immutable"
	ObjectKindReceiving ObjectKind = "receiving"
	ObjectKindShared    ObjectKind = "shared"
)

// InputObject pushes an object input and returns its Argument ID.
//
// For owned / immutable / receiving: supply id, version, digest, kind.
// For shared: supply id, version, mutable, kind="shared" (digest is ignored).
func (b *Builder) InputObject(id string, version uint64, digest string, kind ObjectKind, mutable bool) (uint64, error) {
	m := map[string]any{
		"id":      id,
		"version": version,
		"kind":    string(kind),
	}
	if kind == ObjectKindShared {
		m["mutable"] = mutable
	} else {
		m["digest"] = digest
	}
	payload, _ := json.Marshal(m)
	ptr, size := writeBytes(b.ctx, b.mod, payload)
	defer freeBytes_(b.ctx, b.mod, ptr, size)
	res := int64(callFn(b.ctx, b.mod, "input_object", b.ptr, ptr, size)[0])
	if res < 0 {
		return 0, b.lastError(fmt.Sprintf("input_object failed (code %d)", res))
	}
	return uint64(res), nil
}

// ── Pure-value helpers ────────────────────────────────────────────────────────

// PureBool pushes a BCS-encoded bool and returns its Argument ID.
func (b *Builder) PureBool(v bool) uint64 {
	var u uint64
	if v {
		u = 1
	}
	return uint64(callFn(b.ctx, b.mod, "pure_bool", b.ptr, u)[0])
}

// PureU8 pushes a BCS-encoded u8 and returns its Argument ID.
func (b *Builder) PureU8(v uint8) uint64 {
	return uint64(callFn(b.ctx, b.mod, "pure_u8", b.ptr, uint64(v))[0])
}

// PureU16 pushes a BCS-encoded u16 and returns its Argument ID.
func (b *Builder) PureU16(v uint16) uint64 {
	return uint64(callFn(b.ctx, b.mod, "pure_u16", b.ptr, uint64(v))[0])
}

// PureU32 pushes a BCS-encoded u32 and returns its Argument ID.
func (b *Builder) PureU32(v uint32) uint64 {
	return uint64(callFn(b.ctx, b.mod, "pure_u32", b.ptr, uint64(v))[0])
}

// PureU64 pushes a BCS-encoded u64 and returns its Argument ID.
func (b *Builder) PureU64(v uint64) uint64 {
	return uint64(callFn(b.ctx, b.mod, "pure_u64", b.ptr, v)[0])
}

// PureU128 pushes a BCS-encoded u128 (supplied as high/low uint64 halves)
// and returns its Argument ID.
//
// CHANGED: the old Rust signature was pure_u128(builder, lo, hi) and this
// method compensated by passing (lo, hi) despite the Go parameter order being
// (hi, lo).  The Rust signature is now pure_u128(builder, hi, lo), matching
// the natural convention, so the internal call order is corrected to (hi, lo).
// The Go method signature is unchanged.
func (b *Builder) PureU128(hi, lo uint64) uint64 {
	// Rust: pure_u128(builder, hi, lo) — hi is the high 64 bits, lo the low 64 bits.
	return uint64(callFn(b.ctx, b.mod, "pure_u128", b.ptr, hi, lo)[0])
}

// PureAddress pushes a BCS-encoded Sui address (bare 0x-prefixed hex string)
// and returns its Argument ID.
func (b *Builder) PureAddress(addr string) (uint64, error) {
	ptr, size := writeBytes(b.ctx, b.mod, []byte(addr))
	defer freeBytes_(b.ctx, b.mod, ptr, size)
	res := int64(callFn(b.ctx, b.mod, "pure_address", b.ptr, ptr, size)[0])
	if res < 0 {
		return 0, b.lastError(fmt.Sprintf("pure_address: invalid address %q", addr))
	}
	return uint64(res), nil
}

// PureRawBCS pushes already-BCS-encoded bytes as a pure argument and returns
// its Argument ID.  Use this when you need a type not covered by the helpers
// above and you have encoded it yourself.
func (b *Builder) PureRawBCS(bcsBytes []byte) uint64 {
	ptr, size := writeBytes(b.ctx, b.mod, bcsBytes)
	defer freeBytes_(b.ctx, b.mod, ptr, size)
	return uint64(callFn(b.ctx, b.mod, "pure_raw_bcs", b.ptr, ptr, size)[0])
}

// ── Nested result ─────────────────────────────────────────────────────────────

// NestedResult returns the Argument ID for the Nth sub-result of a
// multi-output command (e.g. the Kth coin from SplitCoins).
// baseID is the value returned by SplitCoins; subIndex is 0-based.
//
// CHANGED: now returns (uint64, error) because the Rust implementation
// validates that baseID exists and refers to a command result, returning -1
// or -2 on invalid input rather than silently inserting a dangling reference
// that would produce an opaque NULL from Build() later.
func (b *Builder) NestedResult(baseID, subIndex uint64) (uint64, error) {
	res := int64(callFn(b.ctx, b.mod, "nested_result", b.ptr, baseID, subIndex)[0])
	if res < 0 {
		return 0, b.lastError(fmt.Sprintf(
			"nested_result: invalid base_id %d or sub_index %d (code %d)",
			baseID, subIndex, res,
		))
	}
	return uint64(res), nil
}

// ── Commands ──────────────────────────────────────────────────────────────────

// MoveCallArg describes a single argument to a Move call.
// Supply exactly one of ArgID (existing Argument) or PureBCS (raw bytes).
type MoveCallArg struct {
	ArgID   *uint64 // reference an existing Argument by ID
	PureBCS []byte  // pre-encoded BCS bytes
}

// MoveCall executes an entry or public Move function and returns the result
// Argument ID.
func (b *Builder) MoveCall(pkg, module, function string, typeArgs []string, args []MoveCallArg) (uint64, error) {
	type callArgJSON struct {
		ID      *uint64 `json:"id,omitempty"`
		PureBCS []byte  `json:"pure_bcs,omitempty"`
	}
	jsonArgs := make([]callArgJSON, len(args))
	for i, a := range args {
		if a.ArgID != nil {
			jsonArgs[i] = callArgJSON{ID: a.ArgID}
		} else {
			jsonArgs[i] = callArgJSON{PureBCS: a.PureBCS}
		}
	}
	payload, _ := json.Marshal(map[string]any{
		"package":   pkg,
		"module":    module,
		"function":  function,
		"type_args": typeArgs,
		"arguments": jsonArgs,
	})
	ptr, size := writeBytes(b.ctx, b.mod, payload)
	defer freeBytes_(b.ctx, b.mod, ptr, size)
	res := int64(callFn(b.ctx, b.mod, "command_move_call", b.ptr, ptr, size)[0])
	if res < 0 {
		return 0, b.lastError(fmt.Sprintf("command_move_call failed (code %d)", res))
	}
	return uint64(res), nil
}

// ArgID is a convenience constructor for a MoveCallArg that references an
// existing Argument by ID.
func ArgID(id uint64) MoveCallArg { return MoveCallArg{ArgID: &id} }

// ArgBCS is a convenience constructor for a MoveCallArg that passes raw
// pre-encoded BCS bytes.
func ArgBCS(bcs []byte) MoveCallArg { return MoveCallArg{PureBCS: bcs} }

// SplitCoins splits coinArgID into len(amountArgIDs) new coins.
// amountArgIDs must be Argument IDs returned by PureU64.
// Returns the base Argument ID; use NestedResult(base, i) to get coin i.
func (b *Builder) SplitCoins(coinArgID uint64, amountArgIDs []uint64) (uint64, error) {
	if len(amountArgIDs) == 0 {
		return 0, fmt.Errorf("SplitCoins: at least one amount required")
	}
	amidsPtr, amidsSize := u64SlicePtr(b.ctx, b.mod, amountArgIDs)
	defer freeBytes_(b.ctx, b.mod, amidsPtr, amidsSize)
	res := int64(callFn(b.ctx, b.mod, "command_split_coins",
		b.ptr, coinArgID, amidsPtr, uint64(len(amountArgIDs)),
	)[0])
	if res < 0 {
		return 0, b.lastError(fmt.Sprintf("command_split_coins failed (code %d)", res))
	}
	return uint64(res), nil
}

// MergeCoins merges sourceArgIDs into targetCoinArgID.
// Produces no result; the target coin absorbs all sources.
func (b *Builder) MergeCoins(targetCoinArgID uint64, sourceArgIDs []uint64) error {
	if len(sourceArgIDs) == 0 {
		return fmt.Errorf("MergeCoins: at least one source required")
	}
	srcsPtr, srcsSize := u64SlicePtr(b.ctx, b.mod, sourceArgIDs)
	defer freeBytes_(b.ctx, b.mod, srcsPtr, srcsSize)
	code := int32(callFn(b.ctx, b.mod, "command_merge_coins",
		b.ptr, targetCoinArgID, srcsPtr, uint64(len(sourceArgIDs)),
	)[0])
	if code != 1 {
		return b.lastError(fmt.Sprintf("command_merge_coins failed (code %d)", code))
	}
	return nil
}

// TransferObjects sends objectArgIDs to the address identified by recipientArgID.
// recipientArgID must be an Argument ID returned by PureAddress.
func (b *Builder) TransferObjects(objectArgIDs []uint64, recipientArgID uint64) error {
	if len(objectArgIDs) == 0 {
		return fmt.Errorf("TransferObjects: at least one object required")
	}
	objsPtr, objsSize := u64SlicePtr(b.ctx, b.mod, objectArgIDs)
	defer freeBytes_(b.ctx, b.mod, objsPtr, objsSize)
	code := int32(callFn(b.ctx, b.mod, "command_transfer_objects",
		b.ptr, objsPtr, uint64(len(objectArgIDs)), recipientArgID,
	)[0])
	if code != 1 {
		return b.lastError(fmt.Sprintf("command_transfer_objects failed (code %d)", code))
	}
	return nil
}

// MakeMoveVec constructs a Move vector<T> from elemArgIDs.
// typeTag is the element type as a string (e.g. "0x2::sui::SUI"); pass ""
// when the type can be inferred from the elements.
// Returns the result Argument ID.
func (b *Builder) MakeMoveVec(typeTag string, elemArgIDs []uint64) (uint64, error) {
	ttPtr, ttSize := writeBytes(b.ctx, b.mod, []byte(typeTag))
	defer freeBytes_(b.ctx, b.mod, ttPtr, ttSize)

	elemsPtr, elemsSize := u64SlicePtr(b.ctx, b.mod, elemArgIDs)
	defer freeBytes_(b.ctx, b.mod, elemsPtr, elemsSize)

	res := int64(callFn(b.ctx, b.mod, "command_make_move_vec",
		b.ptr, ttPtr, ttSize, elemsPtr, uint64(len(elemArgIDs)),
	)[0])
	if res < 0 {
		return 0, b.lastError(fmt.Sprintf("command_make_move_vec failed (code %d)", res))
	}
	return uint64(res), nil
}

// Publish publishes a new Move package.
// modules is a slice of compiled module bytecodes.
// dependencies is a slice of 0x-prefixed package IDs this package depends on.
// Returns the UpgradeCap Argument ID.
func (b *Builder) Publish(modules [][]byte, dependencies []string) (uint64, error) {
	payload, _ := json.Marshal(map[string]any{
		"modules":      modules,
		"dependencies": dependencies,
	})
	ptr, size := writeBytes(b.ctx, b.mod, payload)
	defer freeBytes_(b.ctx, b.mod, ptr, size)
	res := int64(callFn(b.ctx, b.mod, "command_publish", b.ptr, ptr, size)[0])
	if res < 0 {
		return 0, b.lastError(fmt.Sprintf("command_publish failed (code %d)", res))
	}
	return uint64(res), nil
}

// Upgrade upgrades an existing Move package.
// modules is the new compiled bytecodes; dependencies is the updated dep list.
// packageID is the on-chain ID of the package being upgraded.
// ticketArgID is the Argument ID of the UpgradeTicket from authorize_upgrade.
// Returns the UpgradeReceipt Argument ID.
func (b *Builder) Upgrade(modules [][]byte, dependencies []string, packageID string, ticketArgID uint64) (uint64, error) {
	payload, _ := json.Marshal(map[string]any{
		"modules":       modules,
		"dependencies":  dependencies,
		"package":       packageID,
		"ticket_arg_id": ticketArgID,
	})
	ptr, size := writeBytes(b.ctx, b.mod, payload)
	defer freeBytes_(b.ctx, b.mod, ptr, size)
	res := int64(callFn(b.ctx, b.mod, "command_upgrade", b.ptr, ptr, size)[0])
	if res < 0 {
		return 0, b.lastError(fmt.Sprintf("command_upgrade failed (code %d)", res))
	}
	return uint64(res), nil
}

// ── Finalisation ─────────────────────────────────────────────────────────────

// Build serialises the transaction to BCS bytes and returns them.
// The builder is consumed — do NOT call Free() after a successful Build().
// Returns an error if any required field (sender, gas, budget, price) is
// missing, or if there are unresolved intents or no commands.
func (b *Builder) Build() ([]byte, error) {
	res := callFn(b.ctx, b.mod, "build_transaction", b.ptr)
	b.ptr = 0 // builder is consumed regardless of outcome
	resPtr := uint32(res[0])
	if resPtr == 0 {
		// CHANGED: read the real error from the Rust thread-local slot rather than
		// returning a generic message.  This surfaces the exact failure reason
		// (missing sender, missing gas, unresolved intents, BCS serialisation
		// error, etc.) directly from the Rust side.
		return nil, b.lastError(
			"build_transaction failed — ensure sender, gas object, gas_budget, " +
				"gas_price and at least one command are set",
		)
	}

	// Read the 4-byte little-endian payload length prefix.
	lenBytes, ok := b.mod.Memory().Read(resPtr, 4)
	if !ok {
		// WASM memory is fundamentally broken; free the header as best-effort.
		callFn(b.ctx, b.mod, "free_bytes", uint64(resPtr), 4)
		return nil, fmt.Errorf("build_transaction: failed to read length prefix from WASM memory")
	}
	dataLen := binary.LittleEndian.Uint32(lenBytes)

	// Read the BCS payload, then free the entire buffer.
	//
	// CHANGED: free_bytes now expects the TOTAL allocation size (4 + dataLen),
	// not just the payload length.  The Rust side allocates the header and
	// payload in a single contiguous buffer; the allocator must be given the
	// exact original size to correctly release the memory.
	bcsData, ok := b.mod.Memory().Read(resPtr+4, dataLen)
	callFn(b.ctx, b.mod, "free_bytes", uint64(resPtr), uint64(4+dataLen))
	if !ok {
		return nil, fmt.Errorf(
			"build_transaction: failed to read BCS payload (%d bytes) from WASM memory",
			dataLen,
		)
	}

	// Return a copy — WASM memory has been freed above.
	out := make([]byte, len(bcsData))
	copy(out, bcsData)
	return out, nil
}
