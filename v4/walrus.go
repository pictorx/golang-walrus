package v4

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/block-vision/sui-go-sdk/constant"
	"github.com/block-vision/sui-go-sdk/models"
	"github.com/block-vision/sui-go-sdk/signer"
	"github.com/block-vision/sui-go-sdk/sui"

	"golangwalrus/v4/sui_rpc_proto/generated"
	pb "golangwalrus/v4/sui_rpc_proto/generated"

	"github.com/tetratelabs/wazero/api"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
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

	WAL_SYSTEM_OBJ_ID   string = "0x6c2547cbbc38025cf3adac45f63cb0a8d12ecf777cdc75a4971612bf97fdf6af"
	WALRUS_TESTNET_COIN string = "0x8270feb7375eee355e64fdb69c50abb6b5f9393a722883c1cf45f8e26048810a::wal::WAL"
	SUI_COIN_TYPE       string = "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI"
)

type WalrusWASM struct {
	ctx    context.Context
	module api.Module
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
	b := NewBuilder(ctx, mod)
	if err := b.SetConfig(acc.Address, reserve.Gasbudget, reserve.Gasprice); err != nil {
		return nil, err
	}

	if err := b.AddGasObject(*reserve.GasCoin.ObjectId, uint64(*reserve.GasCoin.Version), *reserve.GasCoin.Digest); err != nil {
		return nil, fmt.Errorf("add gas object: %w", err)
	}

	// A. Inputs
	// Shared Object: Walrus System
	wal_system, err := GetWalSystem(conn, ctx)
	if err != nil {
		return nil, err
	}

	sysArg, err := b.InputObject(WAL_SYSTEM_OBJ_ID, wal_system.Owner, "", ObjectKindShared, true)
	if err != nil {
		return nil, fmt.Errorf("input system: %w", err)
	}

	// Owned Object: WAL Payment Coin
	walArg, err := b.InputObject(*reserve.WalCoin.ObjectId, uint64(*reserve.WalCoin.Version), *reserve.WalCoin.Digest, ObjectKindOwned, false)
	if err != nil {
		return nil, fmt.Errorf("input wal coin: %w", err)
	}

	// Pure Arguments
	amtArg := b.PureU64(reserve.Amount) // Amount of storage
	perArg := b.PureU32(reserve.Epoch)  // Periods (Note: u32)

	// B. Move Call: system::reserve_space
	resArg, err := b.MoveCall(
		wal_system.PackageID,
		"system",
		"reserve_space",
		[]string{}, // No type arguments
		[]MoveCallArg{
			ArgID(sysArg),
			ArgID(amtArg),
			ArgID(perArg),
			ArgID(walArg),
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
	signed, err := SignTransaction(TxBuildBytes, acc)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	// Decode Signature parts
	sigRaw, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return nil, err
	}

	// Execute
	resp, err := SignExecuteTransaction(conn, TxBuildBytes, sigRaw, ctx)
	if err != nil {
		return nil, err
	}
	return resp, err

}

func FindCoins(ctx context.Context, conn *grpc.ClientConn, owner string) (gas *pb.Object, wal *pb.Object, err error) {
	// We iterate owned objects to find one SUI coin and one WAL coin
	// In production, you'd want to merge coins if balances are too small.
	resp, err := ListOwnedObjects(conn, owner, nil, nil, ctx)
	if err != nil {
		return nil, nil, err
	}
	gasCoin := Coin{
		Type: SUI_COIN_TYPE,
	}
	walCoin := Coin{
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
	gas_coin, err := GetObject(conn, *gas.ObjectId, gas.Version, ctx)
	if err != nil {
		return nil, nil, err
	}
	wal_coin, err := GetObject(conn, *wal.ObjectId, wal.Version, ctx)
	if err != nil {
		return nil, nil, err
	}
	return gas_coin.Object, wal_coin.Object, nil
}

type WalrusRegisterBlob struct {
	Gasbudget uint64
	Gasprice  uint64

	// Reservation Params
	Amount uint64 // Size in bytes
	Epochs uint32 // Duration

	// Registration Params
	BlobId          [32]byte
	RootHash        [32]byte
	UnencodedLength uint64
	EncodingType    uint8 // 0 for RedStuff, 1 for RS2
	Deletable       bool

	// Resources
	GasCoin *pb.Object
	WalCoin *pb.Object

	Metadata map[string]string
}

// ReserveAndRegisterBlob executes the reservation and registration in a single PTB
func (op *WalrusRegisterBlob) ReserveAndRegisterBlob(conn *grpc.ClientConn, mod api.Module, acc *signer.Signer, ctx context.Context) (*pb.ExecuteTransactionResponse, error) {
	b := NewBuilder(ctx, mod)

	// 1. Configure Transaction
	if err := b.SetConfig(acc.Address, op.Gasbudget, op.Gasprice); err != nil {
		return nil, err
	}
	// Add Gas Payment
	if err := b.AddGasObject(*op.GasCoin.ObjectId, uint64(*op.GasCoin.Version), *op.GasCoin.Digest); err != nil {
		return nil, fmt.Errorf("add gas object: %w", err)
	}

	// 2. Prepare Inputs
	// Shared Object: Walrus System
	wal_system, err := GetWalSystem(conn, ctx)
	if err != nil {
		return nil, err
	}
	sysArg, err := b.InputObject(WAL_SYSTEM_OBJ_ID, wal_system.Owner, "", ObjectKindShared, true)
	if err != nil {
		return nil, fmt.Errorf("input system: %w", err)
	}

	// Owned Object: WAL Coin for payment
	// IMPORTANT: This will be used by BOTH reserve_space and register_blob
	// The Move functions should take &mut Coin<WAL>, not Coin<WAL> by value
	walArg, err := b.InputObject(*op.WalCoin.ObjectId, uint64(*op.WalCoin.Version), *op.WalCoin.Digest, ObjectKindOwned, false)
	if err != nil {
		return nil, fmt.Errorf("input wal coin: %w", err)
	}

	// 3. Define Pure Arguments
	// For reserve_space
	amtArg := b.PureU64(op.Amount)
	epochArg := b.PureU32(op.Epochs)

	// For register_blob - must create separate args even if same value
	// to ensure they're both added as transaction inputs
	sizeArg := b.PureU64(op.UnencodedLength)
	encArg := b.PureU8(op.EncodingType)
	deletableArg := b.PureBool(op.Deletable)

	// Blob Meta: Use PureRawBCS for byte arrays (u256 equivalent)
	blobIdArg := b.PureRawBCS(op.BlobId[:])
	rootHashArg := b.PureRawBCS(op.RootHash[:])

	// 4. Command A: reserve_space
	// Returns: Storage resource
	storageArg, err := b.MoveCall(
		wal_system.PackageID,
		"system",
		"reserve_space",
		[]string{}, // No type args
		[]MoveCallArg{
			ArgID(sysArg),
			ArgID(amtArg),
			ArgID(epochArg),
			ArgID(walArg),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("reserve_space failed: %w", err)
	}

	// 5. Command B: register_blob
	// Uses the storageArg from the previous command
	// NOTE: Still needs WAL coin for metadata/registration costs (separate from storage)
	blobObjArg, err := b.MoveCall(
		wal_system.PackageID,
		"system",
		"register_blob",
		[]string{},
		[]MoveCallArg{
			ArgID(sysArg),       // &mut System
			ArgID(storageArg),   // Storage (consumed from reserve_space)
			ArgID(blobIdArg),    // u256 blob_id
			ArgID(rootHashArg),  // u256 root_hash
			ArgID(sizeArg),      // u64 size
			ArgID(encArg),       // u8 encoding_type
			ArgID(deletableArg), // bool deletable
			ArgID(walArg),       // Coin<WAL> for metadata costs
		},
	)
	if err != nil {
		return nil, fmt.Errorf("register_blob failed: %w", err)
	}

	// After blobObjArg is returned from register_blob, before TransferObjects:
	fmt.Println(len(op.Metadata))
	if len(op.Metadata) > 0 {
		// Command: metadata::new() → returns Metadata object
		metaArg, err := b.MoveCall(
			wal_system.PackageID,
			"metadata",
			"new",
			[]string{},
			[]MoveCallArg{},
		)
		if err != nil {
			return nil, fmt.Errorf("metadata::new: %w", err)
		}

		// Command: metadata::insert_or_update(meta, key, value) for each pair
		for key, value := range op.Metadata {

			keyArg := b.PureRawBCS(encodeVectorU8([]byte(key)))
			valArg := b.PureRawBCS(encodeVectorU8([]byte(value)))
			_, err = b.MoveCall(
				wal_system.PackageID,
				"metadata",
				"insert_or_update",
				[]string{},
				[]MoveCallArg{
					ArgID(metaArg),
					ArgID(keyArg),
					ArgID(valArg),
				},
			)
			if err != nil {
				return nil, fmt.Errorf("metadata::insert_or_update: %w", err)
			}
		}

		// Command: blob::add_metadata(blob, meta) — consumes meta
		_, err = b.MoveCall(
			wal_system.PackageID,
			"blob",
			"add_metadata",
			[]string{},
			[]MoveCallArg{
				ArgID(blobObjArg),
				ArgID(metaArg),
			},
		)
		if err != nil {
			return nil, fmt.Errorf("blob::add_metadata: %w", err)
		}
	}

	// 6. Command C: Transfer the new Blob Object to Sender
	recArg, err := b.PureAddress(acc.Address)
	if err != nil {
		return nil, err
	}
	// Transfer the result of register_blob (blobObjArg)
	if err := b.TransferObjects([]uint64{blobObjArg}, recArg); err != nil {
		return nil, fmt.Errorf("transfer failed: %w", err)
	}

	// 7. Build, Sign, Execute
	txBytes, err := b.Build()
	if err != nil {
		return nil, err
	}

	signed, err := SignTransaction(txBytes, acc)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	sigRaw, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return nil, err
	}

	// Using standard ExecuteTransaction (assuming signature scheme handling is in place)
	return submitWithRetry(conn, txBytes, sigRaw, ctx)
}

// ConfirmationCertificate represents the certificate returned from storage nodes
type ConfirmationCertificate struct {
	Signers           []uint8 `json:"signers"`
	SerializedMessage []uint8 `json:"serialized_message"`
	Signature         string  `json:"signature"`
}

func (c *ConfirmationCertificate) GetDecodedSignature() ([]byte, error) {
	return base64.StdEncoding.DecodeString(c.Signature)
}

// signersToWalrusBitmap converts signer indices to a plain bit-array.
// committeeSize is n_members (103 for testnet), NOT n_shards (1000).
// bitmap length = ceil(n_members / 8).
func signersToWalrusBitmap(signerIndices []uint8, nMembers int) []byte {
	bitmap := make([]byte, (nMembers+7)/8) // ceil(103/8) = 13 bytes
	for _, idx := range signerIndices {
		bitmap[idx/8] |= 1 << (idx % 8)
	}
	return bitmap
}

func (op *WalrusCertifyBlob) CertifyBlob(
	conn *grpc.ClientConn,
	mod api.Module,
	acc *signer.Signer,
	ctx context.Context,
) (*pb.ExecuteTransactionResponse, error) {
	b := NewBuilder(ctx, mod)

	if err := b.SetConfig(acc.Address, op.Gasbudget, op.Gasprice); err != nil {
		return nil, err
	}
	if err := b.AddGasObject(*op.GasCoin.ObjectId, uint64(*op.GasCoin.Version), *op.GasCoin.Digest); err != nil {
		return nil, fmt.Errorf("add gas object: %w", err)
	}
	wal_system, err := GetWalSystem(conn, ctx)
	if err != nil {
		return nil, err
	}
	sysArg, err := b.InputObject(WAL_SYSTEM_OBJ_ID, wal_system.Owner, "", ObjectKindShared, true)
	if err != nil {
		return nil, fmt.Errorf("input system: %w", err)
	}

	blobArg, err := b.InputObject(op.BlobObjectId, op.BlobVersion, op.BlobDigest, ObjectKindOwned, true)
	if err != nil {
		return nil, fmt.Errorf("input blob object: %w", err)
	}

	signatureBytes, err := op.Certificate.GetDecodedSignature()
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	signersBitmap := signersToWalrusBitmap(op.Certificate.Signers, op.Config.NMembers)

	// SerializedMessage is already []byte from JSON int array
	msgBytes := op.Certificate.SerializedMessage

	// Debug — remove once working
	fmt.Printf("   sig len=%d  bitmap len=%d  msg len=%d\n",
		len(signatureBytes), len(signersBitmap), len(msgBytes))

	sigArg := b.PureRawBCS(encodeVectorU8(signatureBytes))
	signersArg := b.PureRawBCS(encodeVectorU8(signersBitmap))
	messageArg := b.PureRawBCS(encodeVectorU8(msgBytes))

	_, err = b.MoveCall(
		wal_system.PackageID,
		"system",
		"certify_blob",
		[]string{},
		[]MoveCallArg{
			ArgID(sysArg),
			ArgID(blobArg),
			ArgID(sigArg),
			ArgID(signersArg),
			ArgID(messageArg),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("certify_blob move call failed: %w", err)
	}

	txBytes, err := b.Build()
	if err != nil {
		return nil, fmt.Errorf("build transaction: %w", err)
	}

	signed, err := SignTransaction(txBytes, acc)
	if err != nil {
		return nil, fmt.Errorf("sign transaction: %w", err)
	}

	sigRaw, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	return submitWithRetry(conn, txBytes, sigRaw, ctx)
}

type WalrusCertifyBlob struct {
	Gasbudget uint64
	Gasprice  uint64

	// The Blob Object created in registration
	BlobObjectId string
	BlobVersion  uint64
	BlobDigest   string

	// The confirmation certificate from storage nodes
	Certificate *ConfirmationCertificate

	GasCoin *pb.Object
	Config  *CommitteeConfig
}

func encodeVectorU8(data []byte) []byte {
	// Encode length as ULEB128
	var lengthBytes []byte
	length := uint64(len(data))

	for {
		byte := uint8(length & 0x7f)
		length >>= 7
		if length != 0 {
			byte |= 0x80 // Set continuation bit
		}
		lengthBytes = append(lengthBytes, byte)
		if length == 0 {
			break
		}
	}

	// Return length + data
	result := make([]byte, 0, len(lengthBytes)+len(data))
	result = append(result, lengthBytes...)
	result = append(result, data...)
	return result
}

func CommitteeInfo(ctx context.Context) (nMembers int, nShards int, err error) {
	var client = sui.NewSuiClient(constant.SuiTestnetEndpoint)

	resp, err := client.SuiXGetDynamicField(ctx, models.SuiXGetDynamicFieldRequest{
		ObjectId: WAL_SYSTEM_OBJ_ID,
	})
	if err != nil {
		return 0, 0, err
	}

	committee, err := client.SuiGetObject(ctx, models.SuiGetObjectRequest{
		ObjectId: resp.Data[0].ObjectId,
		Options: models.SuiObjectDataOptions{
			ShowType:    true,
			ShowContent: true,
		},
	})
	if err != nil {
		return 0, 0, err
	}

	committeeFields, ok := committee.Data.Content.Fields["value"].(map[string]any)["fields"].(map[string]any)["committee"].(map[string]any)["fields"].(map[string]any)
	if !ok {
		return 0, 0, fmt.Errorf("unexpected committee structure")
	}

	members, ok := committeeFields["members"].([]any)
	if !ok {
		return 0, 0, fmt.Errorf("members field missing or wrong type")
	}
	nMembers = len(members)

	// n_shards is a u16 — the JSON unmarshaler gives us either float64 or string
	switch v := committeeFields["n_shards"].(type) {
	case float64:
		nShards = int(v)
	case string:
		_, err = fmt.Sscanf(v, "%d", &nShards)
		if err != nil {
			return 0, 0, fmt.Errorf("parse n_shards: %w", err)
		}
	default:
		return 0, 0, fmt.Errorf("n_shards has unexpected type %T", committeeFields["n_shards"])
	}

	return nMembers, nShards, nil
}

// CommitteeConfig holds the on-chain committee parameters fetched at startup.
type CommitteeConfig struct {
	NMembers int
	NShards  int
}

var committeeConfig *CommitteeConfig

// InitCommitteeConfig fetches committee info once at startup and caches it.
// Call this before making any transactions.
func InitCommitteeConfig(ctx context.Context) error {
	nMembers, nShards, err := CommitteeInfo(ctx)
	if err != nil {
		return fmt.Errorf("init committee config: %w", err)
	}
	committeeConfig = &CommitteeConfig{
		NMembers: nMembers,
		NShards:  nShards,
	}
	fmt.Printf("   ✓ Committee: %d members, %d shards\n", nMembers, nShards)
	return nil
}

// GetCommitteeConfig returns the cached committee config.
// Panics if InitCommitteeConfig was not called first.
func GetCommitteeConfig() *CommitteeConfig {
	if committeeConfig == nil {
		panic("committeeConfig not initialized: call InitCommitteeConfig first")
	}
	return committeeConfig
}

type WalSystem struct {
	PackageID string
	Owner     uint64
}

func GetWalSystem(conn *grpc.ClientConn, ctx context.Context) (*WalSystem, error) {
	client := generated.NewLedgerServiceClient(conn)
	address := WAL_SYSTEM_OBJ_ID
	resp, err := client.GetObject(ctx, &generated.GetObjectRequest{
		ObjectId: &address,
		Version:  nil,
		ReadMask: &fieldmaskpb.FieldMask{
			Paths: []string{"json", "owner"}, // ← owner.shared.initial_shared_version
		},
	})
	if err != nil {
		return nil, err
	}
	raw, ok := resp.Object.Json.AsInterface().(map[string]any)
	if !ok {
		return nil, fmt.Errorf("object %s: JSON is not a map", address)
	}

	w := WalSystem{
		PackageID: raw["package_id"].(string),
		Owner:     resp.Object.Owner.GetVersion(),
	}

	return &w, nil
}

func submitWithRetry(
	conn *grpc.ClientConn,
	txBytes, sigRaw []byte,
	ctx context.Context,
) (*pb.ExecuteTransactionResponse, error) {
	const maxAttempts = 4
	backoff := 2 * time.Second

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, err := SignExecuteTransaction(conn, txBytes, sigRaw, ctx)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if attempt == maxAttempts {
			break
		}
		/*log.Printf("submit attempt %d/%d failed: %v — retrying in %v",
		  attempt, maxAttempts, err, backoff)*/
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled while waiting to retry: %w", ctx.Err())
		}
		backoff *= 2
	}
	return nil, fmt.Errorf("all %d submit attempts failed, last error: %w", maxAttempts, lastErr)
}
