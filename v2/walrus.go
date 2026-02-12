package v2

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/block-vision/sui-go-sdk/signer"
	gosuisdk "github.com/pictorx/go-sui-sdk"
	pb "github.com/pictorx/go-sui-sdk/sui_rpc_proto/generated"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"google.golang.org/grpc"
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
	// RPC Endpoint
	RPC_ENDPOINT = "fullnode.testnet.sui.io:443"

	// Walrus Protocol Config (Testnet)
	WAL_PKG_ID          = "0xa998b8719ca1c0a6dc4e24a859bbb39f5477417f71885fbf2967a6510f699144"
	WAL_SYSTEM_OBJ_ID   = "0x6c2547cbbc38025cf3adac45f63cb0a8d12ecf777cdc75a4971612bf97fdf6af"
	WAL_SYSTEM_VERSION  = 400185623 // Initial shared version
	WALRUS_TESTNET_COIN = "0x8270feb7375eee355e64fdb69c50abb6b5f9393a722883c1cf45f8e26048810a::wal::WAL"
	SUI_COIN_TYPE       = "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI"
)

// BlobId is 32 bytes
type BlobId [32]byte

// EncodingType enum
type EncodingType uint32

const (
	RedStuff EncodingType = 0
	RS2      EncodingType = 1
)

func ExtractBlobInfo(data []byte) (blobId []byte, rootHash []byte, unencodedLength uint32, encodingType uint32, err error) {
	minSize := 32 + 4 + 4 + 4 + 4 + 8 + 32
	if len(data) < minSize {
		return nil, nil, 0, 0, fmt.Errorf("metadata too small: %d bytes (need at least %d)", len(data), minSize)
	}

	// BlobId is the first 32 bytes [0-31]
	blobId = make([]byte, 32)
	copy(blobId, data[0:32])

	// EncodingType is at bytes 36-39 (u32)
	encodingType = binary.LittleEndian.Uint32(data[36:40])

	// Unencoded length is at bytes 40-43 (u32, not u64!)
	unencodedLength = binary.LittleEndian.Uint32(data[40:44])

	// RootHash is the last 32 bytes
	rootHash = make([]byte, 32)
	copy(rootHash, data[len(data)-32:])

	return blobId, rootHash, unencodedLength, encodingType, nil
}

// String representation helpers
func (b BlobId) String() string {
	return hex.EncodeToString(b[:])
}

func (b BlobId) Bytes() []byte {
	return b[:]
}

func (e EncodingType) String() string {
	switch e {
	case RedStuff:
		return "RedStuff"
	case RS2:
		return "RS2"
	default:
		return fmt.Sprintf("Unknown(%d)", e)
	}
}

// ToHex converts bytes to hex string
func ToHex(b []byte) string {
	return hex.EncodeToString(b)
}

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
	result.Metadata = metaBytes

	return result, nil
}

type WalrusReserveSpace struct {
	Gasbudget uint64
	Gasprice  uint64
	Amount    uint64
	GasCoin   *pb.Object
	WalCoin   *pb.Object

	Epoch uint32
}

func (reserve *WalrusReserveSpace) ReserveSpace(conn *grpc.ClientConn, mod api.Module, acc *signer.Signer, ctx context.Context) (*pb.ExecuteTransactionResponse, error) {
	b := gosuisdk.NewBuilder(ctx, mod)
	if err := b.SetConfig(acc.Address, reserve.Gasbudget, reserve.Gasprice); err != nil {
		return nil, err
	}

	if err := b.AddGasObject(*reserve.GasCoin.ObjectId, uint64(*reserve.GasCoin.Version), *reserve.GasCoin.Digest); err != nil {
		return nil, fmt.Errorf("add gas object: %w", err)
	}

	// A. Inputs
	// Shared Object: Walrus System
	sysArg, err := b.InputObject(WAL_SYSTEM_OBJ_ID, WAL_SYSTEM_VERSION, "", gosuisdk.ObjectKindShared, true)
	if err != nil {
		return nil, fmt.Errorf("input system: %w", err)
	}

	// Owned Object: WAL Payment Coin
	walArg, err := b.InputObject(*reserve.WalCoin.ObjectId, uint64(*reserve.WalCoin.Version), *reserve.WalCoin.Digest, gosuisdk.ObjectKindOwned, false)
	if err != nil {
		return nil, fmt.Errorf("input wal coin: %w", err)
	}

	// Pure Arguments
	amtArg := b.PureU64(reserve.Amount) // Amount of storage
	perArg := b.PureU32(reserve.Epoch)  // Periods (Note: u32)

	// B. Move Call: system::reserve_space
	resArg, err := b.MoveCall(
		WAL_PKG_ID,
		"system",
		"reserve_space",
		[]string{}, // No type arguments
		[]gosuisdk.MoveCallArg{
			gosuisdk.ArgID(sysArg),
			gosuisdk.ArgID(amtArg),
			gosuisdk.ArgID(perArg),
			gosuisdk.ArgID(walArg),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("move call: %w", err)
	}

	// C. Transfer Result (StorageGuard?) to Sender
	recArg, err := b.PureAddress(acc.Address)
	if err != nil {
		return nil, err
	}
	b.TransferObjects([]uint64{resArg}, recArg)

	TxBuildBytes, err := b.Build()
	if err != nil {
		return nil, err
	}

	// Sign
	signed, err := gosuisdk.SignTransaction(TxBuildBytes, acc)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	// Decode Signature parts
	sigRaw, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return nil, err
	}

	// Execute
	resp, err := gosuisdk.SignExecuteTransaction(conn, TxBuildBytes, sigRaw, ctx)
	if err != nil {
		return nil, err
	}
	return resp, err

}

func FindCoins(ctx context.Context, conn *grpc.ClientConn, owner string) (gas *pb.Object, wal *pb.Object, err error) {
	// We iterate owned objects to find one SUI coin and one WAL coin
	// In production, you'd want to merge coins if balances are too small.
	resp, err := gosuisdk.ListOwnedObjects(conn, owner, nil, nil, ctx)
	if err != nil {
		return nil, nil, err
	}
	gasCoin := gosuisdk.Coin{
		Type: SUI_COIN_TYPE,
	}
	walCoin := gosuisdk.Coin{
		Type: WALRUS_TESTNET_COIN,
	}

	for _, obj := range resp.Objects {
		if gas == nil && *obj.ObjectType == gasCoin.String() {
			gas = obj
		}
		if wal == nil && *obj.ObjectType == walCoin.String() {
			wal = obj
		}
		if gas != nil && wal != nil {
			break
		}
	}

	if gas == nil {
		return nil, nil, fmt.Errorf("no SUI gas coin found")
	}
	if wal == nil {
		return nil, nil, fmt.Errorf("no WAL coin found")
	}
	gas_coin, err := gosuisdk.GetObject(conn, *gas.ObjectId, gas.Version, ctx)
	if err != nil {
		return nil, nil, err
	}
	wal_coin, err := gosuisdk.GetObject(conn, *wal.ObjectId, wal.Version, ctx)
	if err != nil {
		return nil, nil, err
	}
	return gas_coin.Object, wal_coin.Object, nil
}
