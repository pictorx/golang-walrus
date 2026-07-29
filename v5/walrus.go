package main

/*
#cgo windows LDFLAGS: -L. -lwalrus_go_ffi -lstdc++ -static-libgcc -static-libstdc++ -Wl,-Bstatic -lstdc++ -Wl,-Bdynamic
#cgo linux,!android LDFLAGS: -Lwalrus-bridge/target/release -lwalrus_go_ffi -lstdc++ -ldl -lpthread -lm
#cgo android LDFLAGS: -Lwalrus-bridge/target/aarch64-linux-android/release -lwalrus_go_ffi -L. -lc++_static -lc++abi -ldl -lm
#cgo CFLAGS: -I.
#include "walrus_go_ffi.h"
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang-walrus/v5/crypt"
	"golang-walrus/v5/suigraphql"
	"golang-walrus/v5/suigrpc/generated"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/Khan/genqlient/graphql"
	"github.com/block-vision/sui-go-sdk/constant"
	"github.com/block-vision/sui-go-sdk/models"
	"github.com/block-vision/sui-go-sdk/signer"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

var pageSize uint32 = 50

// ─────────────────────────────────────────────
// NETWORK CONFIGURATION
//
// Network selects between Sui/Walrus Testnet and Mainnet.
// Pass a NetworkConfig (obtained via TestnetConfig or MainnetConfig) to any
// function that needs to contact a remote endpoint. This is the single source
// of truth for every URL and object-type constant; nothing else in this file
// hard-codes network addresses.
//
// gRPC connections are caller-managed: create a *grpc.ClientConn with the
// appropriate GRPCEndpoint and pass it to the relevant functions.
//
//	// Testnet
//	conn, _ := grpc.NewClient(walrus.TestnetConfig.GRPCEndpoint, grpc.WithTransportCredentials(credentials.NewTLS(nil)))
//	files, err := walrus.GetAllFiles(conn, mk, epoch, ctx, privKey, walrus.TestnetConfig)
//
//	// Mainnet
//	conn, _ := grpc.NewClient(walrus.MainnetConfig.GRPCEndpoint, grpc.WithTransportCredentials(credentials.NewTLS(nil)))
//	files, err := walrus.GetAllFiles(conn, mk, epoch, ctx, privKey, walrus.MainnetConfig)
// ─────────────────────────────────────────────

// Network identifies which Sui/Walrus deployment to target.
type Network int

const (
	Testnet Network = iota
	Mainnet
)

// NetworkConfig bundles every endpoint and on-chain constant that varies
// between Testnet and Mainnet into one value.
type NetworkConfig struct {
	// GRPCEndpoint is the host:port used to dial a gRPC ClientConn.
	GRPCEndpoint string
	// GraphQLEndpoint is the full HTTPS URL for the Sui GraphQL service.
	GraphQLEndpoint string
	// WalrusObjectType is the fully-qualified Move type for Walrus Blob objects.
	WalrusObjectType string
	// WalrusStoragePoolObjectType is the fully-qualified Move type for the
	// StoragePool container object itself.
	WalrusStoragePoolObjectType string
	// WalrusPooledBlobObjectType is the fully-qualified Move type for
	// individual PooledBlob entries living inside a StoragePool — this is
	// the pooled-model equivalent of WalrusObjectType, NOT the same as
	// WalrusStoragePoolObjectType. Same Move module (storage_pool), same
	// package, different struct name.
	WalrusPooledBlobObjectType string
	// WalrusStakingObject is the on-chain object ID used to query epoch info.
	WalrusStakingObject string
	WalrusSystemObject  string
	WalrusCoinObject    string
	SuiCoinObject       string
}

// TestnetConfig is the ready-to-use NetworkConfig for Sui/Walrus Testnet.
var TestnetConfig = NetworkConfig{
	GRPCEndpoint:                "fullnode.testnet.sui.io:443",
	GraphQLEndpoint:             "https://graphql.testnet.sui.io/graphql",
	WalrusObjectType:            "0xd84704c17fc870b8764832c535aa6b11f21a95cd6f5bb38a9b07d2cf42220c66::blob::Blob",
	WalrusStoragePoolObjectType: "0xd84704c17fc870b8764832c535aa6b11f21a95cd6f5bb38a9b07d2cf42220c66::storage_pool::StoragePool",
	WalrusPooledBlobObjectType:  "0xd84704c17fc870b8764832c535aa6b11f21a95cd6f5bb38a9b07d2cf42220c66::storage_pool::PooledBlob",
	WalrusStakingObject:         "0xbe46180321c30aab2f8b3501e24048377287fa708018a5b7c2792b35fe339ee3",
	WalrusSystemObject:          "0x6c2547cbbc38025cf3adac45f63cb0a8d12ecf777cdc75a4971612bf97fdf6af",
	WalrusCoinObject:            "0x8270feb7375eee355e64fdb69c50abb6b5f9393a722883c1cf45f8e26048810a::wal::WAL",
	SuiCoinObject:               "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI",
}

// MainnetConfig is the ready-to-use NetworkConfig for Sui/Walrus Mainnet.
var MainnetConfig = NetworkConfig{
	GRPCEndpoint:                "fullnode.mainnet.sui.io:443",
	GraphQLEndpoint:             "https://graphql.mainnet.sui.io/graphql",
	WalrusObjectType:            "0xfdc88f7d7cf30afab2f82e8380d11ee8f70efb90e863d1de8616fae1bb09ea77::blob::Blob",
	WalrusStoragePoolObjectType: "0xfdc88f7d7cf30afab2f82e8380d11ee8f70efb90e863d1de8616fae1bb09ea77::storage_pool::StoragePool",
	WalrusPooledBlobObjectType:  "0xfdc88f7d7cf30afab2f82e8380d11ee8f70efb90e863d1de8616fae1bb09ea77::storage_pool::PooledBlob",
	WalrusStakingObject:         "0x10b9d30c28448939ce6c4d6c6e0ffce4a7f8a4ada8248bdad09ef8b70e4a3904",
	WalrusSystemObject:          "0x2134d52768ea07e8c43570ef975eb3e4c27a39fa6396bef985b5abc58d03ddd2",
	WalrusCoinObject:            "0x356a26eb9e012a68958082340d4c4116e7f55615cf27affcff209cf0ae544f59::wal::WAL",
	SuiCoinObject:               "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI",
}

var gqlHTTPClient = &http.Client{Timeout: 15 * time.Second}

// NetworkConfigFor returns the built-in NetworkConfig for the given Network
// constant. Useful when passing a Network value rather than the config struct.
func NetworkConfigFor(n Network) NetworkConfig {
	if n == Mainnet {
		return MainnetConfig
	}
	return TestnetConfig
}

//go:embed client_config.yaml
var walrusConfigYAML []byte

var (
	configOnce    sync.Once
	configPath    string
	configInitErr error
)

// ConfigPath returns the path to the embedded walrus config file.
// The file is written to a temp location once and reused for the
// lifetime of the process.
func ConfigPath() (string, error) {
	configOnce.Do(func() {
		f, err := os.CreateTemp("", "walrus_config_*.yaml")
		if err != nil {
			configInitErr = fmt.Errorf("create walrus config: %w", err)
			return
		}

		if _, err := f.Write(walrusConfigYAML); err != nil {
			f.Close()
			os.Remove(f.Name())
			configInitErr = fmt.Errorf("write walrus config: %w", err)
			return
		}
		f.Close()
		configPath = f.Name()
	})
	return configPath, configInitErr
}

// CleanupConfig removes the temp config file. Call this when the app exits.
func CleanupConfig() {
	if configPath != "" {
		os.Remove(configPath)
	}
}

// walrus.go — replace the string-returning helper with a []byte builder
// that can be zeroed after use:

// walrusConfigJSON builds the FFI config as a zeroing-safe []byte.
// The caller MUST call zeroBytes(buf) after passing buf to C.CString.
func walrusConfigJSON(fields map[string]any, privKey *signer.Signer) ([]byte, error) {
	// Build the private key entry directly into the map — never as a
	// standalone string variable that outlives this function.
	var entry [33]byte
	entry[0] = 0x00
	copy(entry[1:], privKey.PriKey[:32])
	fields["private_key"] = base64.StdEncoding.EncodeToString(entry[:])
	fields["sui_address"] = privKey.Address
	// Zero the stack buffer — the base64 string in the map still holds
	// a copy, but this reduces the exposure window for the raw seed.
	for i := range entry {
		entry[i] = 0
	}

	buf, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// zeroBytes zeros a []byte and is called immediately after C.CString copies it.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// walrusPrivKeyEntry encodes a signer's Ed25519 private key into the standard
// Sui keystore entry format expected by the Rust library:
//
//	base64_std( [0x00] || seed_32_bytes )
//
// The Go ed25519 private key is 64 bytes: seed[0:32] + compressed_pubkey[32:64].
// Only the 32-byte seed is needed; the Rust side writes it directly into a
// temporary sui.keystore file that is zeroed and deleted after each SDK call.
//
// This value is passed as "private_key" in every FFI config JSON.
func walrusPrivKeyEntry(privKey *signer.Signer) string {
	var entry [33]byte // stack-allocated
	entry[0] = 0x00
	copy(entry[1:], privKey.PriKey[:32])
	s := base64.StdEncoding.EncodeToString(entry[:])
	// Zero the stack buffer before return.
	// The string `s` still holds a copy; this at minimum reduces exposure window.
	for i := range entry {
		entry[i] = 0
	}
	return s
}

// ─────────────────────────────────────────────
// SESSION MANAGEMENT
//
// DeriveFromSignature (Argon2id, ~500ms) must run exactly once per login
// session, not once per vault operation. All functions that perform
// encryption or decryption accept a *crypt.MasterKey rather than
// re-deriving it internally.
//
// Typical caller lifecycle:
//
//	mk, err := NewSession(privKey)   // once at login — ~500ms
//	if err != nil { ... }
//	defer mk.Zero()                  // wipe on logout / session end
//
//	// All vault calls reuse mk — each is now microseconds, not ~500ms:
//	store, err  := StoringBlob(data, name, mk, privKey)
//	err          = RetrieveBlob(blobID, addr, mk, privKey, walrus.TestnetConfig)
//	files, err  := GetAllFiles(conn, mk, epoch, ctx, privKey, walrus.TestnetConfig)
// ─────────────────────────────────────────────

// NewSession signs the AppDomain message with the wallet and derives the
// session MasterKey using Argon2id. This is the ONLY place in the entire
// codebase that calls DeriveFromSignature — it must never be called inside
// a loop or a per-operation function.
//
// The caller owns the returned *crypt.MasterKey and must call mk.Zero()
// when the session ends (logout, vault lock, or app exit).
func NewSession(privKey *signer.Signer) (*crypt.MasterKey, error) {
	k := fmt.Sprintf(crypt.AppDomain, privKey.Address)
	b, err := privKey.SignMessage(k, constant.PersonalMessageIntentScope)
	if err != nil {
		return nil, fmt.Errorf("sign domain message: %w", err)
	}
	mk, err := crypt.DeriveFromSignature([]byte(b.Signature))
	if err != nil {
		return nil, fmt.Errorf("derive master key: %w", err)
	}
	return mk, nil
}

// ─────────────────────────────────────────────
// WALRUS FFI WRAPPERS (no crypto — unchanged)
// ─────────────────────────────────────────────

type StoreResult struct {
	BlobID           string `json:"blob_id"`
	AlreadyCertified bool   `json:"already_certified"`
	TxDigest         string `json:"tx_digest"`
}

type ErrorResult struct {
	Error string `json:"error"`
}

func StoreBlob(
	epochs uint32, deletable bool,
	metadata map[string]string, data []byte,
	privKey *signer.Signer,
) (*StoreResult, error) {
	walrusConfigPath, err := ConfigPath()
	if err != nil {
		return nil, err
	}

	configBuf, err := walrusConfigJSON(map[string]any{
		"walrus_config": walrusConfigPath,
		"epochs":        epochs,
		"deletable":     deletable,
		"metadata":      metadata,
	}, privKey)

	if err != nil {
		return nil, err
	}

	cConfig := C.CString(string(configBuf))
	zeroBytes(configBuf) // zero immediately after C.CString copies it
	defer func() {
		C.memset(unsafe.Pointer(cConfig), 0, C.size_t(C.strlen(cConfig)))
		C.free(unsafe.Pointer(cConfig))
	}()

	var cDataPtr *C.uint8_t
	if len(data) > 0 {
		cDataPtr = (*C.uint8_t)(C.CBytes(data))
		defer C.free(unsafe.Pointer(cDataPtr))
	}

	raw := C.walrus_store_blob(cConfig, cDataPtr, C.size_t(len(data)))
	if raw == nil {
		return nil, fmt.Errorf("walrus_store_blob returned nil")
	}
	defer C.walrus_free_string(raw)

	var combined struct {
		BlobID           string `json:"blob_id"`
		AlreadyCertified bool   `json:"already_certified"`
		TxDigest         string `json:"tx_digest"`
		Error            string `json:"error"`
	}
	if err := json.Unmarshal([]byte(C.GoString(raw)), &combined); err != nil {
		return nil, fmt.Errorf("failed to parse result JSON: %w", err)
	}
	if combined.Error != "" {
		return nil, fmt.Errorf("walrus error: %s", combined.Error)
	}
	return &StoreResult{
		BlobID:           combined.BlobID,
		AlreadyCertified: combined.AlreadyCertified,
		TxDigest:         combined.TxDigest,
	}, nil
}

func ReadBlob(blobID string, privKey *signer.Signer) ([]byte, error) {
	walrusConfigPath, err := ConfigPath()
	if err != nil {
		return nil, err
	}

	configBuf, err := walrusConfigJSON(map[string]any{
		"walrus_config": walrusConfigPath,
		"blob_id":       blobID,
	}, privKey)

	if err != nil {
		return nil, fmt.Errorf("marshal read config: %w", err)
	}

	cConfig := C.CString(string(configBuf))
	zeroBytes(configBuf) // zero immediately after C.CString copies it
	defer func() {
		C.memset(unsafe.Pointer(cConfig), 0, C.size_t(C.strlen(cConfig)))
		C.free(unsafe.Pointer(cConfig))
	}()
	wb := C.walrus_read_blob(cConfig)
	defer C.walrus_free_bytes(wb)

	if wb.err != nil {
		return nil, fmt.Errorf("walrus_read_blob: %s", C.GoString(wb.err))
	}

	return C.GoBytes(unsafe.Pointer(wb.ptr), C.int(wb.len)), nil
}

type DeleteResult struct {
	Deleted int    `json:"deleted"`
	Error   string `json:"error"`
}

func DeleteBlob(blobID string, privKey *signer.Signer) (int, error) {
	walrusConfigPath, err := ConfigPath()
	if err != nil {
		return 0, err
	}
	type config struct {
		WalrusConfig string `json:"walrus_config"`
		BlobID       string `json:"blob_id"`
	}
	configBuf, err := walrusConfigJSON(map[string]any{
		"walrus_config": walrusConfigPath,
		"blob_id":       blobID,
	}, privKey)
	if err != nil {
		return 0, fmt.Errorf("marshal delete config: %w", err)
	}

	cConfig := C.CString(string(configBuf))
	zeroBytes(configBuf) // zero immediately after C.CString copies it
	defer func() {
		C.memset(unsafe.Pointer(cConfig), 0, C.size_t(C.strlen(cConfig)))
		C.free(unsafe.Pointer(cConfig))
	}()

	raw := C.walrus_delete_blob(cConfig)
	if raw == nil {
		return 0, fmt.Errorf("walrus_delete_blob returned nil")
	}
	defer C.walrus_free_string(raw)

	var result DeleteResult
	if err := json.Unmarshal([]byte(C.GoString(raw)), &result); err != nil {
		return 0, err
	}
	if result.Error != "" {
		return 0, fmt.Errorf("walrus error: %s", result.Error)
	}
	return result.Deleted, nil
}

func ExtendBlob(blobObjectID string, epochs uint32, privKey *signer.Signer) error {
	walrusConfigPath, err := ConfigPath()
	if err != nil {
		return err
	}

	configBuf, err := walrusConfigJSON(map[string]any{
		"walrus_config":  walrusConfigPath,
		"blob_object_id": blobObjectID,
		"epochs":         epochs,
	}, privKey)
	if err != nil {
		return fmt.Errorf("marshal extend config: %w", err)
	}

	cConfig := C.CString(string(configBuf))
	zeroBytes(configBuf) // zero immediately after C.CString copies it
	defer func() {
		C.memset(unsafe.Pointer(cConfig), 0, C.size_t(C.strlen(cConfig)))
		C.free(unsafe.Pointer(cConfig))
	}()
	raw := C.walrus_extend_blob(cConfig)
	if raw == nil {
		return fmt.Errorf("walrus_extend_blob returned nil")
	}
	defer C.walrus_free_string(raw)

	var result struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal([]byte(C.GoString(raw)), &result); err != nil {
		return err
	}
	if result.Error != "" {
		return fmt.Errorf("walrus error: %s", result.Error)
	}
	return nil
}

type BlobInfo struct {
	ObjectID        string  `json:"object_id"`
	BlobID          string  `json:"blob_id"`
	Size            uint64  `json:"size"`
	EncodingType    uint8   `json:"encoding_type"`
	RegisteredEpoch uint64  `json:"registered_epoch"`
	CertifiedEpoch  *uint64 `json:"certified_epoch"`
	EndEpoch        uint64  `json:"end_epoch"`
	Deletable       bool    `json:"deletable"`
}

func ListBlobs(expiryPolicy string, privKey *signer.Signer) ([]BlobInfo, error) {
	walrusConfigPath, err := ConfigPath()
	if err != nil {
		return nil, err
	}

	type config struct {
		WalrusConfig string `json:"walrus_config"`
		ExpiryPolicy string `json:"expiry_policy"`
		PrivateKey   string `json:"private_key"`
		SuiAddress   string `json:"sui_address"`
	}
	if expiryPolicy == "" {
		expiryPolicy = "valid"
	}
	configBuf, err := walrusConfigJSON(map[string]any{
		"walrus_config": walrusConfigPath,
		"expiry_policy": expiryPolicy,
	}, privKey)
	if err != nil {
		return nil, fmt.Errorf("marshal list config: %w", err)
	}
	cConfig := C.CString(string(configBuf))
	zeroBytes(configBuf) // zero immediately after C.CString copies it
	defer func() {
		C.memset(unsafe.Pointer(cConfig), 0, C.size_t(C.strlen(cConfig)))
		C.free(unsafe.Pointer(cConfig))
	}()
	raw := C.walrus_list_blobs(cConfig)
	if raw == nil {
		return nil, fmt.Errorf("walrus_list_blobs returned nil")
	}
	defer C.walrus_free_string(raw)

	var result struct {
		Blobs []BlobInfo `json:"blobs"`
		Error string     `json:"error"`
	}
	if err := json.Unmarshal([]byte(C.GoString(raw)), &result); err != nil {
		return nil, err
	}
	if result.Error != "" {
		return nil, fmt.Errorf("walrus error: %s", result.Error)
	}
	return result.Blobs, nil
}

// ─────────────────────────────────────────────
// VAULT OPERATIONS (all accept a session MasterKey)
// ─────────────────────────────────────────────

type Store struct {
	FileId      string
	BlobId      string
	BlobAddress string
	Certified   bool
}

// StoringBlob encrypts blobData and uploads it to Walrus.
//
// mk must be obtained from NewSession — do not call DeriveFromSignature here.
// privKey is required to encrypt the per-file ID with EncryptFileID.
func StoringBlob(
	blobData []byte, fileName string,
	mk *crypt.MasterKey, privKey *signer.Signer,
) (*Store, error) {
	blob, fileID, err := mk.EncryptFile(blobData)
	if err != nil {
		return nil, fmt.Errorf("encrypt file: %w", err)
	}

	var f [16]byte
	copy(f[:], fileID)

	encryptedFileID, err := crypt.EncryptFileID(privKey, f)
	if err != nil {
		return nil, fmt.Errorf("encrypt file ID: %w", err)
	}

	name, err := mk.EncryptMetadata(fileID, []byte(fileName))
	if err != nil {
		return nil, fmt.Errorf("encrypt filename: %w", err)
	}
	filename := base64.StdEncoding.EncodeToString(name)

	result, err := StoreBlob(uint32(5), true, map[string]string{
		"filename": filename,
		"fileid":   encryptedFileID,
	}, blob, privKey)
	if err != nil {
		return nil, err
	}
	fileId := base64.StdEncoding.EncodeToString(fileID)
	return &Store{
		FileId:      fileId,
		BlobId:      result.BlobID,
		BlobAddress: result.TxDigest,
		Certified:   result.AlreadyCertified,
	}, nil
}

func GetBlobId(conn *grpc.ClientConn, address string, ctx context.Context) (*string, error) {
	client := generated.NewLedgerServiceClient(conn)
	resp, err := client.GetObject(ctx, &generated.GetObjectRequest{
		ObjectId: &address,
		Version:  nil,
		ReadMask: &fieldmaskpb.FieldMask{
			Paths: []string{"json"},
		},
	})
	if err != nil {
		return nil, err
	}
	raw, ok := resp.Object.Json.AsInterface().(map[string]any)
	if !ok {
		return nil, fmt.Errorf("object %s: JSON is not a map", address)
	}
	blobIDVal, ok := raw["blob_id"].(string)
	if !ok {
		return nil, fmt.Errorf("object %s: blob_id missing or not a string", address)
	}
	blobIdBase64 := BlobIDToBase64(blobIDVal)
	return &blobIdBase64, nil
}

func OwnedObjects(
	conn *grpc.ClientConn,
	owner,
	objectType string,
	pagesize *uint32,
	pagetoken []byte,
	ctx context.Context,
) (*generated.ListOwnedObjectsResponse, error) {
	client := generated.NewStateServiceClient(conn)
	resp, err := client.ListOwnedObjects(ctx, &generated.ListOwnedObjectsRequest{
		Owner:      &owner,
		PageSize:   pagesize,
		PageToken:  pagetoken,
		ObjectType: &objectType,
		ReadMask: &fieldmaskpb.FieldMask{
			Paths: []string{"object_id", "json"},
		},
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

type Epoch struct {
	Start   time.Time
	End     time.Time
	Current int
}

func getWalrusEpochTime(ctx context.Context, graphqlEndpoint, stakingObject string) (*Epoch, error) {
	client := graphql.NewClient(graphqlEndpoint, gqlHTTPClient)
	resp, err := suigraphql.GetDynamicFields(ctx, client, stakingObject)
	if err != nil {
		return nil, err
	}

	nodes := resp.Address.GetDynamicFields().Nodes
	if len(nodes) == 0 {
		return nil, fmt.Errorf("staking object %s has no dynamic fields", stakingObject)
	}
	moveVal := suigraphql.GetDynamicFieldsAddressDynamicFieldsDynamicFieldConnectionNodesDynamicFieldValueMoveValue(nodes[0].Value)

	var meta map[string]any
	if err := json.Unmarshal(moveVal.GetJson(), &meta); err != nil {
		return nil, fmt.Errorf("unmarshal epoch metadata: %w", err)
	}

	epochState, ok := meta["epoch_state"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("epoch_state missing or wrong type")
	}
	pos0, ok := epochState["pos0"].(string)
	if !ok {
		return nil, fmt.Errorf("epoch_state.pos0 missing or wrong type")
	}
	start, err := strconv.Atoi(pos0)
	if err != nil {
		return nil, err
	}
	epochDurationStr, ok := meta["epoch_duration"].(string)
	if !ok {
		return nil, fmt.Errorf("epoch_duration missing or wrong type")
	}
	duration, err := strconv.Atoi(epochDurationStr)
	if err != nil {
		return nil, err
	}
	epochNum, ok := meta["epoch"].(float64)
	if !ok {
		return nil, fmt.Errorf("epoch missing or wrong type")
	}
	end := start + duration
	return &Epoch{
		Start:   time.UnixMilli(int64(start)),
		End:     time.UnixMilli(int64(end)),
		Current: int(epochNum),
	}, nil
}

// GetWalrusEpochTime returns the current Walrus epoch information for the
// given network. Use TestnetConfig or MainnetConfig as the net argument.
func GetWalrusEpochTime(conn *grpc.ClientConn, ctx context.Context, net NetworkConfig) (*Epoch, error) {
	return getWalrusEpochTime(ctx, net.GraphQLEndpoint, net.WalrusStakingObject)
}

// GetWalrusEpochTimeTestnet is a convenience wrapper for Testnet.
func GetWalrusEpochTimeTestnet(conn *grpc.ClientConn, ctx context.Context) (*Epoch, error) {
	return GetWalrusEpochTime(conn, ctx, TestnetConfig)
}

// GetWalrusEpochTimeMainnet is a convenience wrapper for Mainnet.
func GetWalrusEpochTimeMainnet(conn *grpc.ClientConn, ctx context.Context) (*Epoch, error) {
	return GetWalrusEpochTime(conn, ctx, MainnetConfig)
}

// GetAllFileNames returns the decrypted filename for every non-expired blob
// on the specified network. mk must be obtained from NewSession.
func GetAllFileNames(
	conn *grpc.ClientConn, mk *crypt.MasterKey,
	ctx context.Context, privKey *signer.Signer,
	net NetworkConfig,
) ([]string, error) {
	epoch, err := GetWalrusEpochTime(conn, ctx, net)
	if err != nil {
		return nil, err
	}

	var (
		pageToken  []byte
		allObjects []*generated.Object
	)

	for {
		resp, err := OwnedObjects(
			conn,
			privKey.Address,
			net.WalrusObjectType,
			&pageSize,
			pageToken,
			ctx,
		)
		if err != nil {
			return nil, fmt.Errorf("list owned blobs (page token %x): %w", pageToken, err)
		}

		allObjects = append(allObjects, resp.Objects...)

		// GetNextPageToken() returns nil/empty when there are no more pages.
		nextToken := resp.GetNextPageToken()
		if len(nextToken) == 0 {
			break
		}
		pageToken = nextToken
	}

	var filenames []string
	for i := range allObjects {
		object := allObjects[i]
		raw, ok := object.Json.AsInterface().(map[string]any)
		if !ok {
			continue
		}
		storage, ok := raw["storage"].(map[string]any)
		if !ok {
			continue
		}
		endEpoch, ok := storage["end_epoch"].(float64)
		if !ok {
			continue
		}
		if float64(epoch.Current) < endEpoch {
			gqlClient := graphql.NewClient(net.GraphQLEndpoint, gqlHTTPClient)
			filename, err := GetFileName(*object.ObjectId, mk, &gqlClient, privKey)
			if err != nil {
				return nil, err
			}
			filenames = append(filenames, *filename)
		}
	}

	return filenames, nil
}

// blobMetadata holds both pieces of per-blob on-chain metadata that require
// decryption. It is populated by a single GetDynamicFields call.
type blobMetadata struct {
	FileID   []byte // decrypted file ID (16 bytes)
	Filename string // decrypted filename
}

// getMetadata fetches dynamic fields for a blob object and returns the
// decrypted file ID and filename in one GraphQL round-trip.
//
// mk is passed in rather than derived here — this function is called
// concurrently by GetAllFiles and must never re-run Argon2id internally.
// MasterKey reads are safe across goroutines; only Zero() must not be
// called while goroutines are still running.
func getMetadata(
	address string, mk *crypt.MasterKey,
	client graphql.Client, ctx context.Context,
	privKey *signer.Signer,
) (*blobMetadata, error) {
	resp, err := suigraphql.GetDynamicFields(ctx, client, address)
	if err != nil {
		return nil, err
	}
	nodes := resp.Address.GetDynamicFields().Nodes
	if len(nodes) == 0 {
		return nil, fmt.Errorf("object %s has no dynamic fields", address)
	}
	moveVal := suigraphql.GetDynamicFieldsAddressDynamicFieldsDynamicFieldConnectionNodesDynamicFieldValueMoveValue(nodes[0].Value)

	var meta map[string]any
	if err := json.Unmarshal(moveVal.GetJson(), &meta); err != nil {
		return nil, fmt.Errorf("unmarshal metadata for %s: %w", address, err)
	}
	metaMap, ok := meta["metadata"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("object %s: metadata field missing or wrong type", address)
	}
	contents, ok := metaMap["contents"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("object %s: metadata.contents missing or wrong type", address)
	}

	var encryptedFileID, encryptedFilenameB64 *string
	for _, item := range contents {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		switch entry["key"] {
		case "fileid":
			if v, ok := entry["value"].(string); ok {
				encryptedFileID = &v
			}
		case "filename":
			if v, ok := entry["value"].(string); ok {
				encryptedFilenameB64 = &v
			}
		}
	}
	if encryptedFileID == nil {
		return nil, fmt.Errorf("object %s: fileid not found in metadata", address)
	}
	if encryptedFilenameB64 == nil {
		return nil, fmt.Errorf("object %s: filename not found in metadata", address)
	}

	fileID, err := crypt.DecryptFileID(privKey, *encryptedFileID)
	if err != nil {
		return nil, fmt.Errorf("object %s: decrypt fileid: %w", address, err)
	}
	encryptedFilename, err := base64.StdEncoding.DecodeString(*encryptedFilenameB64)
	if err != nil {
		return nil, fmt.Errorf("object %s: base64 decode filename: %w", address, err)
	}
	filename, err := mk.DecryptMetadata(fileID[:], encryptedFilename)
	if err != nil {
		return nil, fmt.Errorf("object %s: decrypt filename: %w", address, err)
	}

	return &blobMetadata{
		FileID:   fileID[:],
		Filename: string(filename),
	}, nil
}

// GetFileId returns the decrypted file ID for a blob object.
// mk must be obtained from NewSession.
func GetFileId(
	address string, mk *crypt.MasterKey,
	client *graphql.Client, ctx context.Context,
	privKey *signer.Signer) ([]byte, error) {
	m, err := getMetadata(address, mk, *client, ctx, privKey)
	if err != nil {
		return nil, err
	}
	return m.FileID, nil
}

// GetFileName returns the decrypted filename for a blob object.
// Build the client with the correct NetworkConfig.GraphQLEndpoint before calling:
//
//	name, err := GetFileName(objectID, mk, &gqlClient, privKey)
//
// mk must be obtained from NewSession.
func GetFileName(
	address string, mk *crypt.MasterKey,
	client *graphql.Client, privKey *signer.Signer,
) (*string, error) {
	ctx := context.Background()
	m, err := getMetadata(address, mk, *client, ctx, privKey)
	if err != nil {
		return nil, err
	}
	return &m.Filename, nil
}

// FileEntry holds the human-readable properties of a valid Walrus file.
type FileEntry struct {
	ObjectID    string    `db:"object_id"`    // Sui blob object ID (0x...)
	BlobID      string    `db:"blob_id"`      // Walrus blob ID (base64url)
	Filename    string    `db:"filename"`     // decrypted filename from on-chain metadata
	CertifiedAt time.Time `db:"certified_at"` // wall-clock time the blob was certified
	ExpiresAt   time.Time `db:"expires_at"`   // wall-clock time the blob expires
	SizeBytes   uint64    `db:"size_bytes"`   // original unencoded size in bytes
}

// GetAllFiles returns all valid (non-expired) files owned by privKey on the
// given network. Pass TestnetConfig or MainnetConfig as net.
//
// mk is passed in and shared read-only across all goroutines — no locking
// needed because MasterKey.keySlice() only reads from the locked buffer.
// The caller must not call mk.Zero() until after GetAllFiles returns.
func GetAllFiles(
	conn *grpc.ClientConn, mk *crypt.MasterKey,
	ctx context.Context, privKey *signer.Signer,
	net NetworkConfig,
) ([]FileEntry, error) {
	// 1. Get current epoch info for epoch→wall-clock conversion.
	epoch, err := GetWalrusEpochTime(conn, ctx, net)
	if err != nil {
		return nil, fmt.Errorf("get epoch time: %w", err)
	}

	epochDuration := epoch.End.Sub(epoch.Start)
	epochToTime := func(targetEpoch float64) time.Time {
		delta := targetEpoch - float64(epoch.Current)
		return epoch.Start.Add(time.Duration(delta * float64(epochDuration)))
	}

	// 2. Fetch all owned blob objects in one gRPC call.
	var (
		pageToken  []byte
		allObjects []*generated.Object
	)

	for {
		resp, err := OwnedObjects(
			conn,
			privKey.Address,
			net.WalrusObjectType,
			&pageSize,
			pageToken,
			ctx,
		)
		if err != nil {
			return nil, fmt.Errorf("list owned blobs (page token %x): %w", pageToken, err)
		}

		allObjects = append(allObjects, resp.Objects...)

		// GetNextPageToken() returns nil/empty when there are no more pages.
		nextToken := resp.GetNextPageToken()
		if len(nextToken) == 0 {
			break
		}
		pageToken = nextToken
	}

	// 3. Filter expired/uncertified blobs before issuing any GraphQL calls.
	type candidate struct {
		objectID       string
		blobIDBase64   string
		certifiedEpoch float64
		endEpoch       float64
		sizeBytes      uint64
	}
	var candidates []candidate
	for i := range allObjects {
		obj := allObjects[i]
		raw, ok := obj.Json.AsInterface().(map[string]any)
		if !ok {
			continue
		}
		storage, ok := raw["storage"].(map[string]any)
		if !ok {
			continue
		}
		endEpoch, ok := storage["end_epoch"].(float64)
		if !ok {
			continue
		}
		if float64(epoch.Current) >= endEpoch {
			continue // expired
		}
		certifiedEpochRaw := raw["certified_epoch"]
		if certifiedEpochRaw == nil {
			continue // not yet certified
		}
		certifiedEpoch, ok := certifiedEpochRaw.(float64)
		if !ok {
			continue
		}
		blobIDDecimal, ok := raw["blob_id"].(string)
		if !ok {
			continue
		}
		var sizeBytes uint64
		if sizeRaw, ok := raw["size"].(string); ok && sizeRaw != "" {
			if v, err := strconv.ParseUint(sizeRaw, 10, 64); err == nil {
				sizeBytes = v
			}
			// else: log.Printf("unexpected size format %q for object %s", sizeRaw, objectID)
		}
		candidates = append(candidates, candidate{
			objectID:       *obj.ObjectId,
			blobIDBase64:   BlobIDToBase64(blobIDDecimal),
			certifiedEpoch: certifiedEpoch,
			endEpoch:       endEpoch,
			sizeBytes:      sizeBytes,
		})
	}

	if len(candidates) == 0 {
		return nil, nil
	}

	// 4. Fan out getMetadata calls concurrently, capped at maxConcurrent
	//    in-flight goroutines to avoid spawning O(blobs) goroutines and
	//    overwhelming the GraphQL endpoint.
	//    mk is shared read-only — no mutex needed.
	//    Each goroutine runs only cheap HKDF (~1µs), not Argon2id.
	const maxConcurrent = 20
	sem := make(chan struct{}, maxConcurrent)

	type result struct {
		entry FileEntry
		err   error
		skip  bool
	}
	results := make([]result, len(candidates))

	gqlClient := graphql.NewClient(net.GraphQLEndpoint, gqlHTTPClient)

	var wg sync.WaitGroup
	wg.Add(len(candidates))
	for i, c := range candidates {
		i, c := i, c
		sem <- struct{}{} // acquire slot; blocks when maxConcurrent are running
		go func() {
			defer wg.Done()
			defer func() { <-sem }() // release slot on exit
			m, err := getMetadata(c.objectID, mk, gqlClient, ctx, privKey)
			if err != nil {
				// Blobs without app metadata are silently skipped.
				results[i] = result{skip: true}
				return
			}
			results[i] = result{
				entry: FileEntry{
					ObjectID:    c.objectID,
					BlobID:      c.blobIDBase64,
					Filename:    m.Filename,
					CertifiedAt: epochToTime(c.certifiedEpoch),
					ExpiresAt:   epochToTime(c.endEpoch),
					SizeBytes:   c.sizeBytes,
				},
			}
		}()
	}
	wg.Wait()

	// 5. Collect non-skipped results in original order.
	var files []FileEntry
	for _, r := range results {
		if !r.skip && r.err == nil {
			files = append(files, r.entry)
		}
	}
	return files, nil
}

func GetAllFilesUncertified(
	conn *grpc.ClientConn, mk *crypt.MasterKey,
	StoragePoolID *string, ctx context.Context,
	privKey *signer.Signer, net NetworkConfig,
) ([]FileEntry, error) {
	// 1. Get current epoch info for epoch→wall-clock conversion.
	epoch, err := GetWalrusEpochTime(conn, ctx, net)
	if err != nil {
		return nil, fmt.Errorf("get epoch time: %w", err)
	}

	epochDuration := epoch.End.Sub(epoch.Start)
	epochToTime := func(targetEpoch float64) time.Time {
		delta := targetEpoch - float64(epoch.Current)
		return epoch.Start.Add(time.Duration(delta * float64(epochDuration)))
	}

	// 2. Fetch all owned blob objects in one gRPC call.
	var (
		pageToken  []byte
		allObjects []*generated.Object
	)

	for {
		resp, err := OwnedObjects(
			conn,
			privKey.Address,
			net.WalrusObjectType,
			&pageSize,
			pageToken,
			ctx,
		)
		if err != nil {
			return nil, fmt.Errorf("list owned blobs (page token %x): %w", pageToken, err)
		}

		allObjects = append(allObjects, resp.Objects...)

		// GetNextPageToken() returns nil/empty when there are no more pages.
		nextToken := resp.GetNextPageToken()
		if len(nextToken) == 0 {
			break
		}
		pageToken = nextToken
	}

	// 3. Filter expired/uncertified blobs before issuing any GraphQL calls.
	type candidate struct {
		objectID       string
		blobIDBase64   string
		certifiedEpoch float64
		endEpoch       float64
		sizeBytes      uint64
	}
	var candidates []candidate
	for i := range allObjects {
		obj := allObjects[i]
		raw, ok := obj.Json.AsInterface().(map[string]any)
		if !ok {
			continue
		}
		storage, ok := raw["storage"].(map[string]any)
		if !ok {
			continue
		}
		if StoragePoolID == nil {
			continue
		}
		if strings.EqualFold(*StoragePoolID, storage["id"].(string)) == false {
			continue
		}
		endEpoch, ok := storage["end_epoch"].(float64)
		if !ok {
			continue
		}
		certifiedEpochRaw := raw["certified_epoch"]
		if certifiedEpochRaw != nil {
			continue // certified
		}
		blobIDDecimal, ok := raw["blob_id"].(string)
		if !ok {
			continue
		}
		var sizeBytes uint64
		if sizeRaw, ok := raw["size"].(string); ok && sizeRaw != "" {
			if v, err := strconv.ParseUint(sizeRaw, 10, 64); err == nil {
				sizeBytes = v
			}
			// else: log.Printf("unexpected size format %q for object %s", sizeRaw, objectID)
		}
		candidates = append(candidates, candidate{
			objectID:       *obj.ObjectId,
			blobIDBase64:   BlobIDToBase64(blobIDDecimal),
			certifiedEpoch: 0,
			endEpoch:       endEpoch,
			sizeBytes:      sizeBytes,
		})
	}

	if len(candidates) == 0 {
		return nil, nil
	}

	// 4. Fan out getMetadata calls concurrently, capped at maxConcurrent
	//    in-flight goroutines to avoid spawning O(blobs) goroutines and
	//    overwhelming the GraphQL endpoint.
	//    mk is shared read-only — no mutex needed.
	//    Each goroutine runs only cheap HKDF (~1µs), not Argon2id.
	const maxConcurrent = 20
	sem := make(chan struct{}, maxConcurrent)

	type result struct {
		entry FileEntry
		err   error
		skip  bool
	}
	results := make([]result, len(candidates))

	gqlClient := graphql.NewClient(net.GraphQLEndpoint, gqlHTTPClient)

	var wg sync.WaitGroup
	wg.Add(len(candidates))
	for i, c := range candidates {
		i, c := i, c
		sem <- struct{}{} // acquire slot; blocks when maxConcurrent are running
		go func() {
			defer wg.Done()
			defer func() { <-sem }() // release slot on exit
			m, err := getMetadata(c.objectID, mk, gqlClient, ctx, privKey)
			if err != nil {
				// Blobs without app metadata are silently skipped.
				results[i] = result{skip: true}
				return
			}
			results[i] = result{
				entry: FileEntry{
					ObjectID:    c.objectID,
					BlobID:      c.blobIDBase64,
					Filename:    m.Filename,
					CertifiedAt: epochToTime(c.certifiedEpoch),
					ExpiresAt:   epochToTime(c.endEpoch),
					SizeBytes:   c.sizeBytes,
				},
			}
		}()
	}
	wg.Wait()

	// 5. Collect non-skipped results in original order.
	var files []FileEntry
	for _, r := range results {
		if !r.skip && r.err == nil {
			files = append(files, r.entry)
		}
	}
	return files, nil
}

func BlobIDToBase64(decimal string) string {
	n := new(big.Int)
	n.SetString(decimal, 10)

	bytes := n.Bytes() // big-endian

	// Pad to 32 bytes (u256)
	if len(bytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(bytes):], bytes)
		bytes = padded
	}

	// Reverse to little-endian
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}

	return base64.RawURLEncoding.EncodeToString(bytes)
}

// ── Batch Read ────────────────────────────────────────────────────────────────

// ReadBlobResult holds the outcome of one blob in a ReadBlobs call.
// Exactly one of Data or Err will be non-nil.
type ReadBlobResult struct {
	BlobID string
	Data   []byte
	Err    error
}

// ReadBlobs downloads multiple blobs in one FFI call.  The Rust side builds
// the Walrus client once and reads every blob concurrently via JoinSet,
// saving N-1 client-build round-trips compared with calling ReadBlob N times.
//
// Results are returned in the same order as blobIDs.
// A top-level error means setup failed before any read ran.
// Per-blob failures are reported in the individual ReadBlobResult.Err fields.
func ReadBlobs(blobIDs []string, privKey *signer.Signer) ([]ReadBlobResult, error) {
	if len(blobIDs) == 0 {
		return nil, nil
	}

	walrusConfigPath, err := ConfigPath()
	if err != nil {
		return nil, err
	}

	configBuf, err := walrusConfigJSON(map[string]any{
		"walrus_config": walrusConfigPath,
		"blob_ids":      blobIDs,
	}, privKey)
	if err != nil {
		return nil, fmt.Errorf("marshal batch read config: %w", err)
	}

	cConfig := C.CString(string(configBuf))
	zeroBytes(configBuf) // zero immediately after C.CString copies it
	defer func() {
		C.memset(unsafe.Pointer(cConfig), 0, C.size_t(C.strlen(cConfig)))
		C.free(unsafe.Pointer(cConfig))
	}()
	wba := C.walrus_read_blobs(cConfig)
	defer C.walrus_free_bytes_array(wba)

	// Top-level error: setup failed, no blobs were read.
	if wba.err != nil {
		return nil, fmt.Errorf("walrus_read_blobs: %s", C.GoString(wba.err))
	}

	count := int(wba.count)
	results := make([]ReadBlobResult, count)
	itemSize := unsafe.Sizeof(C.WalrusBytes{})

	for i := 0; i < count; i++ {
		item := (*C.WalrusBytes)(unsafe.Pointer(
			uintptr(unsafe.Pointer(wba.items)) + uintptr(i)*itemSize,
		))
		results[i].BlobID = blobIDs[i]
		if item.err != nil {
			results[i].Err = fmt.Errorf("%s", C.GoString(item.err))
		} else {
			results[i].Data = C.GoBytes(unsafe.Pointer(item.ptr), C.int(item.len))
		}
	}

	return results, nil
}

// ── Batch Delete ──────────────────────────────────────────────────────────────

// DeleteBlobResult holds the outcome of one blob in a DeleteBlobs call.
type DeleteBlobResult struct {
	BlobID  string
	Deleted int
	Err     error
}

// DeleteBlobs removes multiple deletable blobs in one FFI call.  The Rust
// side builds the Walrus client once and processes deletions sequentially
// (Sui transactions from one key must be ordered by sequence number).
//
// A top-level error means setup failed before any deletion ran.
// Per-blob failures are reported in the individual DeleteBlobResult.Err fields
// and do NOT abort the remaining deletions.
func DeleteBlobs(blobIDs []string, privKey *signer.Signer) ([]DeleteBlobResult, error) {
	if len(blobIDs) == 0 {
		return nil, nil
	}

	walrusConfigPath, err := ConfigPath()
	if err != nil {
		return nil, err
	}

	configBuf, err := walrusConfigJSON(map[string]any{
		"walrus_config": walrusConfigPath,
		"blob_ids":      blobIDs,
	}, privKey)

	if err != nil {
		return nil, fmt.Errorf("marshal batch delete config: %w", err)
	}

	cConfig := C.CString(string(configBuf))
	zeroBytes(configBuf) // zero immediately after C.CString copies it
	defer func() {
		C.memset(unsafe.Pointer(cConfig), 0, C.size_t(C.strlen(cConfig)))
		C.free(unsafe.Pointer(cConfig))
	}()
	raw := C.walrus_delete_blobs(cConfig)
	if raw == nil {
		return nil, fmt.Errorf("walrus_delete_blobs returned nil")
	}
	defer C.walrus_free_string(raw)

	var response struct {
		Results []struct {
			BlobID  string `json:"blob_id"`
			Deleted *int   `json:"deleted"`
			Error   string `json:"error"`
		} `json:"results"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(C.GoString(raw)), &response); err != nil {
		return nil, fmt.Errorf("parse batch delete response: %w", err)
	}
	if response.Error != "" {
		return nil, fmt.Errorf("walrus error: %s", response.Error)
	}

	results := make([]DeleteBlobResult, len(response.Results))
	for i, r := range response.Results {
		results[i].BlobID = r.BlobID
		if r.Error != "" {
			results[i].Err = fmt.Errorf("%s", r.Error)
		} else if r.Deleted != nil {
			results[i].Deleted = *r.Deleted
		}
	}
	return results, nil
}

func GenerateBlobName(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Hex encoding makes it URL-safe and readable
	randomStr := hex.EncodeToString(bytes)
	return fmt.Sprintf("%s", &randomStr), nil
}

// ── Storage Pool ──────────────────────────────────────────────────────────────
//
// StoreBlobInPool is NOT safe to retry blindly, unlike every other function
// in this file. Registering a pooled blob is not idempotent — there is no
// on-chain check for "does this pool already have an entry for this
// blob_id", so a retry after a partially-succeeded attempt (registration
// landed, then upload or certify failed) creates a second, duplicate
// PooledBlob for the same content. If a call fails, use
// StoragePoolStatus / your own bookkeeping to determine whether it's safe
// to retry before doing so — do not wrap StoreBlobInPool in the same
// backoff-retry helper you'd use for StoreBlob.
//
// CreateStoragePool, ExtendStoragePool, and IncreaseStoragePoolCapacity are
// all single, self-contained transactions with no partial-success state —
// those three are safe to retry with backoff as usual.

type StoragePoolStatus struct {
	StoragePoolObjectID           string `json:"storage_pool_object_id"`
	StartEpoch                    uint64 `json:"start_epoch"`
	EndEpoch                      uint64 `json:"end_epoch"`
	ReservedEncodedCapacityBytes  uint64 `json:"reserved_encoded_capacity_bytes"`
	UsedEncodedBytes              uint64 `json:"used_encoded_bytes"`
	AvailableEncodedCapacityBytes uint64 `json:"available_encoded_capacity_bytes"`
	BlobCount                     uint64 `json:"blob_count"`
}

// StoreBlobInPool stores a blob into a specific storage pool instead of the
// caller's own owned Storage. See the warning above this section before
// adding any retry logic around this call.
func StoreBlobInPool(
	epochs uint32, deletable bool,
	storagePoolObjectID string, data []byte,
	privKey *signer.Signer,
) (*StoreResult, error) {
	walrusConfigPath, err := ConfigPath()
	if err != nil {
		return nil, err
	}

	configBuf, err := walrusConfigJSON(map[string]any{
		"walrus_config":          walrusConfigPath,
		"epochs":                 epochs,
		"deletable":              deletable,
		"storage_pool_object_id": storagePoolObjectID,
	}, privKey)
	if err != nil {
		return nil, fmt.Errorf("marshal store-in-pool config: %w", err)
	}

	cConfig := C.CString(string(configBuf))
	zeroBytes(configBuf) // zero immediately after C.CString copies it
	defer func() {
		C.memset(unsafe.Pointer(cConfig), 0, C.size_t(C.strlen(cConfig)))
		C.free(unsafe.Pointer(cConfig))
	}()

	var cDataPtr *C.uint8_t
	if len(data) > 0 {
		cDataPtr = (*C.uint8_t)(C.CBytes(data))
		defer C.free(unsafe.Pointer(cDataPtr))
	}

	raw := C.walrus_store_blob_in_pool(cConfig, cDataPtr, C.size_t(len(data)))
	if raw == nil {
		return nil, fmt.Errorf("walrus_store_blob_in_pool returned nil")
	}
	defer C.walrus_free_string(raw)

	var combined struct {
		BlobID           string `json:"blob_id"`
		AlreadyCertified bool   `json:"already_certified"`
		TxDigest         string `json:"tx_digest"`
		Error            string `json:"error"`
	}
	if err := json.Unmarshal([]byte(C.GoString(raw)), &combined); err != nil {
		return nil, fmt.Errorf("failed to parse result JSON: %w", err)
	}
	if combined.Error != "" {
		return nil, fmt.Errorf("walrus error: %s", combined.Error)
	}
	return &StoreResult{
		BlobID:           combined.BlobID,
		AlreadyCertified: combined.AlreadyCertified,
		TxDigest:         combined.TxDigest,
	}, nil
}

// CreateStoragePool creates a new storage pool and returns its object ID.
// Safe to retry with backoff on failure.
func CreateStoragePool(reservedEncodedCapacityBytes uint64, epochsAhead uint32, privKey *signer.Signer) (string, error) {
	walrusConfigPath, err := ConfigPath()
	if err != nil {
		return "", err
	}

	configBuf, err := walrusConfigJSON(map[string]any{
		"walrus_config":                   walrusConfigPath,
		"reserved_encoded_capacity_bytes": reservedEncodedCapacityBytes,
		"epochs_ahead":                    epochsAhead,
	}, privKey)
	if err != nil {
		return "", fmt.Errorf("marshal create-storage-pool config: %w", err)
	}

	cConfig := C.CString(string(configBuf))
	zeroBytes(configBuf)
	defer func() {
		C.memset(unsafe.Pointer(cConfig), 0, C.size_t(C.strlen(cConfig)))
		C.free(unsafe.Pointer(cConfig))
	}()

	raw := C.walrus_create_storage_pool(cConfig)
	if raw == nil {
		return "", fmt.Errorf("walrus_create_storage_pool returned nil")
	}
	defer C.walrus_free_string(raw)

	var result struct {
		StoragePoolObjectID string `json:"storage_pool_object_id"`
		Error               string `json:"error"`
	}
	if err := json.Unmarshal([]byte(C.GoString(raw)), &result); err != nil {
		return "", fmt.Errorf("parse create-storage-pool response: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("walrus error: %s", result.Error)
	}
	return result.StoragePoolObjectID, nil
}

// ExtendStoragePool extends a storage pool's lifetime by the given number
// of epochs. Safe to retry with backoff on failure.
func ExtendStoragePool(storagePoolObjectID string, epochsExtended uint32, privKey *signer.Signer) error {
	walrusConfigPath, err := ConfigPath()
	if err != nil {
		return err
	}

	configBuf, err := walrusConfigJSON(map[string]any{
		"walrus_config":          walrusConfigPath,
		"storage_pool_object_id": storagePoolObjectID,
		"epochs_extended":        epochsExtended,
	}, privKey)
	if err != nil {
		return fmt.Errorf("marshal extend-storage-pool config: %w", err)
	}

	cConfig := C.CString(string(configBuf))
	zeroBytes(configBuf)
	defer func() {
		C.memset(unsafe.Pointer(cConfig), 0, C.size_t(C.strlen(cConfig)))
		C.free(unsafe.Pointer(cConfig))
	}()

	raw := C.walrus_extend_storage_pool(cConfig)
	if raw == nil {
		return fmt.Errorf("walrus_extend_storage_pool returned nil")
	}
	defer C.walrus_free_string(raw)

	var result struct {
		Ok    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(C.GoString(raw)), &result); err != nil {
		return err
	}
	if result.Error != "" {
		return fmt.Errorf("walrus error: %s", result.Error)
	}
	return nil
}

// IncreaseStoragePoolCapacity increases a storage pool's reserved encoded
// capacity. Safe to retry with backoff on failure.
func IncreaseStoragePoolCapacity(storagePoolObjectID string, additionalEncodedCapacityBytes uint64, privKey *signer.Signer) error {
	walrusConfigPath, err := ConfigPath()
	if err != nil {
		return err
	}

	configBuf, err := walrusConfigJSON(map[string]any{
		"walrus_config":                     walrusConfigPath,
		"storage_pool_object_id":            storagePoolObjectID,
		"additional_encoded_capacity_bytes": additionalEncodedCapacityBytes,
	}, privKey)
	if err != nil {
		return fmt.Errorf("marshal increase-storage-pool-capacity config: %w", err)
	}

	cConfig := C.CString(string(configBuf))
	zeroBytes(configBuf)
	defer func() {
		C.memset(unsafe.Pointer(cConfig), 0, C.size_t(C.strlen(cConfig)))
		C.free(unsafe.Pointer(cConfig))
	}()

	raw := C.walrus_increase_storage_pool_capacity(cConfig)
	if raw == nil {
		return fmt.Errorf("walrus_increase_storage_pool_capacity returned nil")
	}
	defer C.walrus_free_string(raw)

	var result struct {
		Ok    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(C.GoString(raw)), &result); err != nil {
		return err
	}
	if result.Error != "" {
		return fmt.Errorf("walrus error: %s", result.Error)
	}
	return nil
}

func GetAllStoragePools(
	conn *grpc.ClientConn,
	mk *crypt.MasterKey,
	ctx context.Context,
	privKey *signer.Signer,
	net NetworkConfig,
) ([]*generated.Object, error) {
	// 1. Fetch all owned blob objects in one gRPC call.
	var (
		pageToken  []byte
		allObjects []*generated.Object
	)

	for {
		resp, err := OwnedObjects(
			conn,
			privKey.Address,
			net.WalrusStoragePoolObjectType,
			&pageSize,
			pageToken,
			ctx,
		)
		if err != nil {
			return nil, fmt.Errorf("list owned blobs (page token %x): %w", pageToken, err)
		}

		allObjects = append(allObjects, resp.Objects...)

		// GetNextPageToken() returns nil/empty when there are no more pages.
		nextToken := resp.GetNextPageToken()
		if len(nextToken) == 0 {
			break
		}
		pageToken = nextToken
	}

	return allObjects, nil
}

func GetStoragePoolBlobObjects(ctx context.Context, graphqlEndpoint, storage_pool string) ([]map[string]any, error) {
	client := graphql.NewClient(graphqlEndpoint, gqlHTTPClient)
	resp, err := suigraphql.GetDynamicFields(ctx, client, storage_pool)
	if err != nil {
		return nil, err
	}

	nodes := resp.Address.GetDynamicFields().Nodes
	if len(nodes) == 0 {
		return nil, fmt.Errorf("storage_pool object %s  has no dynamic fields", storage_pool)
	}
	moveVal := suigraphql.GetDynamicFieldsAddressDynamicFieldsDynamicFieldConnectionNodesDynamicFieldValueMoveValue(nodes[0].Value)

	var meta map[string]any
	if err := json.Unmarshal(moveVal.GetJson(), &meta); err != nil {
		return nil, fmt.Errorf("unmarshal storage_pool metadata: %w", err)
	}

	pooledObjectsTable, ok := meta["blobs"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("pooledObjectsTable missing or wrong type")
	}

	poolBlobObjectTableID, ok := pooledObjectsTable["id"].(string)
	if !ok {
		return nil, fmt.Errorf("poolBlobObjectTableID is not a string")
	}

	resp2, err := suigraphql.GetDynamicFields(ctx, client, poolBlobObjectTableID)
	if err != nil {
		return nil, err
	}

	nodes2 := resp2.Address.GetDynamicFields().Nodes

	if len(nodes2) == 0 {
		return nil, fmt.Errorf("no dynamic fields")
	}
	var movObjs []map[string]any
	for i := range nodes2 {
		moveObj, err := nodes2[i].MarshalJSON()
		if err != nil {
			return nil, err
		}

		var meta map[string]any
		if err := json.Unmarshal(moveObj, &meta); err != nil {
			return nil, err
		}

		movObjs = append(movObjs, meta["value"].(map[string]any)["contents"].(map[string]any)["json"].(map[string]any))
	}

	return movObjs, nil
}

// GetStoragePoolStatus returns a storage pool's current capacity
// used/available, epoch range, and blob count. Read-only — call this before
// StoreBlobInPool to confirm the pool has enough remaining capacity and
// epochs, since that call will not top up or extend the pool itself.
func GetStoragePoolStatus(storagePoolObjectID string, privKey *signer.Signer) (*StoragePoolStatus, error) {
	walrusConfigPath, err := ConfigPath()
	if err != nil {
		return nil, err
	}

	configBuf, err := walrusConfigJSON(map[string]any{
		"walrus_config":          walrusConfigPath,
		"storage_pool_object_id": storagePoolObjectID,
	}, privKey)
	if err != nil {
		return nil, fmt.Errorf("marshal storage-pool-status config: %w", err)
	}

	cConfig := C.CString(string(configBuf))
	zeroBytes(configBuf)
	defer func() {
		C.memset(unsafe.Pointer(cConfig), 0, C.size_t(C.strlen(cConfig)))
		C.free(unsafe.Pointer(cConfig))
	}()

	raw := C.walrus_storage_pool_status(cConfig)
	if raw == nil {
		return nil, fmt.Errorf("walrus_storage_pool_status returned nil")
	}
	defer C.walrus_free_string(raw)

	var result struct {
		StoragePoolStatus
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(C.GoString(raw)), &result); err != nil {
		return nil, fmt.Errorf("parse storage-pool-status response: %w", err)
	}
	if result.Error != "" {
		return nil, fmt.Errorf("walrus error: %s", result.Error)
	}
	return &result.StoragePoolStatus, nil
}

// ── Burn Expired ──────────────────────────────────────────────────────────────

// BurnExpiredBlobs lists every Walrus Blob object owned by the wallet whose
// storage epoch has already elapsed and burns them all in one call.
//
// Expired blobs cannot be read, extended, or deleted via the normal delete
// path — burning is the only valid cleanup operation for them. The Rust side
// handles PTB batching internally (≤1 000 burns per transaction), so this
// function works correctly regardless of how many expired objects exist.
//
// Returns the number of objects burned, or 0 if nothing was expired.
func BurnExpiredBlobs(privKey *signer.Signer) (int, error) {
	walrusConfigPath, err := ConfigPath()
	if err != nil {
		return 0, err
	}

	configBuf, err := walrusConfigJSON(map[string]any{
		"walrus_config": walrusConfigPath,
	}, privKey)

	if err != nil {
		return 0, fmt.Errorf("marshal burn-expired config: %w", err)
	}

	cConfig := C.CString(string(configBuf))
	zeroBytes(configBuf) // zero immediately after C.CString copies it
	defer func() {
		C.memset(unsafe.Pointer(cConfig), 0, C.size_t(C.strlen(cConfig)))
		C.free(unsafe.Pointer(cConfig))
	}()

	raw := C.walrus_burn_expired_blobs(cConfig)
	if raw == nil {
		return 0, fmt.Errorf("walrus_burn_expired_blobs returned nil")
	}
	defer C.walrus_free_string(raw)

	var result struct {
		Burned int    `json:"burned"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal([]byte(C.GoString(raw)), &result); err != nil {
		return 0, fmt.Errorf("parse burn-expired response: %w", err)
	}
	if result.Error != "" {
		return 0, fmt.Errorf("walrus error: %s", result.Error)
	}
	return result.Burned, nil
}

// EncodedSizeEstimate breaks down a blob's on-chain encoded footprint —
// metadata_size scales with n_shards (the fixed, per-shard-replicated cost
// that makes small files disproportionately expensive); data_size scales
// with the actual content length.
type EncodedSizeEstimate struct {
	MetadataSize     uint64 `json:"metadata_size"`
	DataSize         uint64 `json:"data_size"`
	TotalEncodedSize uint64 `json:"total_encoded_size"`
}

// EstimateEncodedSize computes a blob's on-chain encoded size BEFORE
// uploading it — pure computation, no network call, safe to call as often
// as needed (e.g. as soon as a user picks a file, to warn them if it's
// small enough that fixed overhead will dominate — see EncodedSizeEstimate's
// doc comment). encodingType is optional; pass "" to use the default (RS2).
func EstimateEncodedSize(unencodedLength uint64, nShards uint16, encodingType string) (*EncodedSizeEstimate, error) {
	payload := map[string]any{
		"unencoded_length": unencodedLength,
		"n_shards":         nShards,
	}
	if encodingType != "" {
		payload["encoding_type"] = encodingType
	}
	configBuf, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal estimate-encoded-size config: %w", err)
	}

	cConfig := C.CString(string(configBuf))
	defer C.free(unsafe.Pointer(cConfig))

	raw := C.walrus_estimate_encoded_size(cConfig)
	if raw == nil {
		return nil, fmt.Errorf("walrus_estimate_encoded_size returned nil")
	}
	defer C.walrus_free_string(raw)

	var result struct {
		EncodedSizeEstimate
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(C.GoString(raw)), &result); err != nil {
		return nil, fmt.Errorf("parse estimate-encoded-size response: %w", err)
	}
	if result.Error != "" {
		return nil, fmt.Errorf("walrus error: %s", result.Error)
	}
	return &result.EncodedSizeEstimate, nil
}

// ── Builder ───────────────────────────────────────────────────────────────────

// Builder wraps the native (CGo) TransactionBuilder pointer.
// It is NOT safe for concurrent use.
type Builder struct {
	ptr *C.TransactionBuilder // nil after Build() or Free()
}

// NewBuilder instantiates a fresh TransactionBuilder inside the static library.
// The ctx parameter is accepted for API compatibility with the WASM version
// but is not used — native calls are synchronous.
func NewBuilder() *Builder {
	return &Builder{ptr: C.new_builder()}
}

// Free releases a builder that was NOT consumed by Build().
// After a successful Build() the builder is already freed — do not call Free()
// in that case.  Safe to call on a nil/already-freed builder.
func (b *Builder) Free() {
	if b.ptr != nil {
		C.free_builder(b.ptr)
		b.ptr = nil
	}
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
	cptr, clen := goBytesCopy(payload)
	defer C.free(unsafe.Pointer(cptr))
	code := C.set_config(b.ptr, (*C.uint8_t)(cptr), C.size_t(clen))
	if code != 1 {
		return fmt.Errorf("set_config failed (code %d) — check sender address format", code)
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
	cptr, clen := goBytesCopy(payload)
	defer C.free(unsafe.Pointer(cptr))
	code := C.add_gas_object(b.ptr, (*C.uint8_t)(cptr), C.size_t(clen))
	switch code {
	case 1:
		return nil
	case -2:
		return fmt.Errorf("add_gas_object: invalid digest %q", digest)
	default:
		return fmt.Errorf("add_gas_object failed (code %d)", code)
	}
}

// ── Gas pseudo-input ──────────────────────────────────────────────────────────

// GasArgument returns the Argument ID for the transaction's gas coin.
// Idempotent — always returns the same ID within one builder.
func (b *Builder) GasArgument() uint64 {
	return uint64(C.gas_argument(b.ptr))
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
	cptr, clen := goBytesCopy(payload)
	defer C.free(unsafe.Pointer(cptr))
	res := int64(C.input_object(b.ptr, (*C.uint8_t)(cptr), C.size_t(clen)))
	if res < 0 {
		return 0, fmt.Errorf("input_object failed (code %d)", res)
	}
	return uint64(res), nil
}

// ── Pure-value helpers ────────────────────────────────────────────────────────

// PureBool pushes a BCS-encoded bool and returns its Argument ID.
func (b *Builder) PureBool(v bool) uint64 {
	var u C.uint8_t
	if v {
		u = 1
	}
	return uint64(C.pure_bool(b.ptr, u))
}

// PureU8 pushes a BCS-encoded u8 and returns its Argument ID.
func (b *Builder) PureU8(v uint8) uint64 {
	return uint64(C.pure_u8(b.ptr, C.uint8_t(v)))
}

// PureU16 pushes a BCS-encoded u16 and returns its Argument ID.
func (b *Builder) PureU16(v uint16) uint64 {
	return uint64(C.pure_u16(b.ptr, C.uint16_t(v)))
}

// PureU32 pushes a BCS-encoded u32 and returns its Argument ID.
func (b *Builder) PureU32(v uint32) uint64 {
	return uint64(C.pure_u32(b.ptr, C.uint32_t(v)))
}

// PureU64 pushes a BCS-encoded u64 and returns its Argument ID.
func (b *Builder) PureU64(v uint64) uint64 {
	return uint64(C.pure_u64(b.ptr, C.uint64_t(v)))
}

// PureU128 pushes a BCS-encoded u128 (supplied as high/low uint64 halves)
// and returns its Argument ID.
func (b *Builder) PureU128(hi, lo uint64) uint64 {
	// CGo signature: pure_u128(builder, lo, hi) — lo first, matching Rust.
	return uint64(C.pure_u128(b.ptr, C.uint64_t(lo), C.uint64_t(hi)))
}

// PureAddress pushes a BCS-encoded Sui address (bare 0x-prefixed hex string)
// and returns its Argument ID.
func (b *Builder) PureAddress(addr string) (uint64, error) {
	cptr, clen := goBytesCopy([]byte(addr))
	defer C.free(unsafe.Pointer(cptr))
	res := int64(C.pure_address(b.ptr, (*C.uint8_t)(cptr), C.size_t(clen)))
	if res < 0 {
		return 0, fmt.Errorf("pure_address: invalid address %q", addr)
	}
	return uint64(res), nil
}

// PureRawBCS pushes already-BCS-encoded bytes as a pure argument and returns
// its Argument ID.
func (b *Builder) PureRawBCS(bcsBytes []byte) uint64 {
	cptr, clen := goBytesCopy(bcsBytes)
	defer C.free(unsafe.Pointer(cptr))
	return uint64(C.pure_raw_bcs(b.ptr, (*C.uint8_t)(cptr), C.size_t(clen)))
}

// ── Nested result ─────────────────────────────────────────────────────────────

// NestedResult returns the Argument ID for the Nth sub-result of a
// multi-output command (e.g. the Kth coin from SplitCoins).
func (b *Builder) NestedResult(baseID, subIndex uint64) uint64 {
	return uint64(C.nested_result(b.ptr, C.uint64_t(baseID), C.uint64_t(subIndex)))
}

// ── Commands ──────────────────────────────────────────────────────────────────

// MoveCallArg describes a single argument to a Move call.
// Supply exactly one of ArgID (existing Argument) or PureBCS (raw bytes).
type MoveCallArg struct {
	ArgID   *uint64
	PureBCS []byte
}

// ArgID is a convenience constructor for a MoveCallArg that references an
// existing Argument by ID.
func ArgID(id uint64) MoveCallArg { return MoveCallArg{ArgID: &id} }

// ArgBCS is a convenience constructor for a MoveCallArg that passes raw
// pre-encoded BCS bytes.
func ArgBCS(bcs []byte) MoveCallArg { return MoveCallArg{PureBCS: bcs} }

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
	cptr, clen := goBytesCopy(payload)
	defer C.free(unsafe.Pointer(cptr))
	res := int64(C.command_move_call(b.ptr, (*C.uint8_t)(cptr), C.size_t(clen)))
	if res < 0 {
		return 0, fmt.Errorf("command_move_call failed (code %d)", res)
	}
	return uint64(res), nil
}

// SplitCoins splits coinArgID into len(amountArgIDs) new coins.
// amountArgIDs must be Argument IDs returned by PureU64.
// Returns the base Argument ID; use NestedResult(base, i) to address coin i.
func (b *Builder) SplitCoins(coinArgID uint64, amountArgIDs []uint64) (uint64, error) {
	if len(amountArgIDs) == 0 {
		return 0, fmt.Errorf("SplitCoins: at least one amount required")
	}
	cAmounts, cCount := goU64SliceCopy(amountArgIDs)
	defer C.free(unsafe.Pointer(cAmounts))
	res := int64(C.command_split_coins(b.ptr, C.uint64_t(coinArgID), cAmounts, cCount))
	if res < 0 {
		return 0, fmt.Errorf("command_split_coins failed (code %d)", res)
	}
	return uint64(res), nil
}

// MergeCoins merges sourceArgIDs into targetCoinArgID.
// Produces no result; the target coin absorbs all sources.
func (b *Builder) MergeCoins(targetCoinArgID uint64, sourceArgIDs []uint64) error {
	if len(sourceArgIDs) == 0 {
		return fmt.Errorf("MergeCoins: at least one source required")
	}
	cSrcs, cCount := goU64SliceCopy(sourceArgIDs)
	defer C.free(unsafe.Pointer(cSrcs))
	code := int32(C.command_merge_coins(b.ptr, C.uint64_t(targetCoinArgID), cSrcs, cCount))
	if code != 1 {
		return fmt.Errorf("command_merge_coins failed (code %d)", code)
	}
	return nil
}

// TransferObjects sends objectArgIDs to the address identified by recipientArgID.
// recipientArgID must be an Argument ID returned by PureAddress.
func (b *Builder) TransferObjects(objectArgIDs []uint64, recipientArgID uint64) error {
	if len(objectArgIDs) == 0 {
		return fmt.Errorf("TransferObjects: at least one object required")
	}
	cObjs, cCount := goU64SliceCopy(objectArgIDs)
	defer C.free(unsafe.Pointer(cObjs))
	code := int32(C.command_transfer_objects(b.ptr, cObjs, cCount, C.uint64_t(recipientArgID)))
	if code != 1 {
		return fmt.Errorf("command_transfer_objects failed (code %d)", code)
	}
	return nil
}

// MakeMoveVec constructs a Move vector<T> from elemArgIDs.
// typeTag is the element type string (e.g. "0x2::sui::SUI"); pass "" to infer.
// Returns the result Argument ID.
func (b *Builder) MakeMoveVec(typeTag string, elemArgIDs []uint64) (uint64, error) {
	var ttPtr *C.uint8_t
	var ttLen C.size_t
	if typeTag != "" {
		p, l := goBytesCopy([]byte(typeTag))
		defer C.free(unsafe.Pointer(p))
		ttPtr = (*C.uint8_t)(p)
		ttLen = C.size_t(l)
	}

	var elemsPtr *C.uint64_t
	var elemsCount C.size_t
	if len(elemArgIDs) > 0 {
		p, c := goU64SliceCopy(elemArgIDs)
		defer C.free(unsafe.Pointer(p))
		elemsPtr = p
		elemsCount = c
	}

	res := int64(C.command_make_move_vec(b.ptr, ttPtr, ttLen, elemsPtr, elemsCount))
	if res < 0 {
		return 0, fmt.Errorf("command_make_move_vec failed (code %d)", res)
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
	cptr, clen := goBytesCopy(payload)
	defer C.free(unsafe.Pointer(cptr))
	res := int64(C.command_publish(b.ptr, (*C.uint8_t)(cptr), C.size_t(clen)))
	if res < 0 {
		return 0, fmt.Errorf("command_publish failed (code %d)", res)
	}
	return uint64(res), nil
}

// Upgrade upgrades an existing Move package.
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
	cptr, clen := goBytesCopy(payload)
	defer C.free(unsafe.Pointer(cptr))
	res := int64(C.command_upgrade(b.ptr, (*C.uint8_t)(cptr), C.size_t(clen)))
	if res < 0 {
		return 0, fmt.Errorf("command_upgrade failed (code %d)", res)
	}
	return uint64(res), nil
}

// ── Finalisation ─────────────────────────────────────────────────────────────

// Build serialises the transaction to BCS bytes and returns them.
// The builder is consumed — do NOT call Free() after a successful Build().
// Returns an error if any required field is missing or if build fails.
func (b *Builder) Build() ([]byte, error) {
	// build_transaction consumes the builder regardless of outcome.
	raw := C.build_transaction(b.ptr)
	b.ptr = nil

	if raw == nil {
		return nil, fmt.Errorf("build_transaction failed — ensure sender, gas object, gas_budget, gas_price and at least one command are set")
	}

	// Buffer layout: [4-byte LE uint32 payload_len][payload_len bytes BCS]
	rawSlice := unsafe.Slice((*byte)(unsafe.Pointer(raw)), 4)
	payloadLen := binary.LittleEndian.Uint32(rawSlice)

	bcsData := C.GoBytes(unsafe.Pointer(uintptr(unsafe.Pointer(raw))+4), C.int(payloadLen))

	// Free the Rust-owned buffer before returning.
	C.free_bytes(raw, C.size_t(payloadLen))

	return bcsData, nil
}

// ── internal CGo helpers ──────────────────────────────────────────────────────

// goBytesCopy copies a Go []byte into a C.malloc buffer.
// The caller must C.free the returned pointer.
func goBytesCopy(data []byte) (unsafe.Pointer, int) {
	if len(data) == 0 {
		return nil, 0
	}
	ptr := C.malloc(C.size_t(len(data)))
	C.memcpy(ptr, unsafe.Pointer(&data[0]), C.size_t(len(data)))
	return ptr, len(data)
}

// goU64SliceCopy copies a Go []uint64 into a C.malloc buffer of C.uint64_t.
// The caller must C.free the returned pointer.
func goU64SliceCopy(ids []uint64) (*C.uint64_t, C.size_t) {
	if len(ids) == 0 {
		return nil, 0
	}
	byteLen := len(ids) * 8
	ptr := C.malloc(C.size_t(byteLen))
	dst := unsafe.Slice((*byte)(ptr), byteLen)
	for i, v := range ids {
		binary.LittleEndian.PutUint64(dst[i*8:], v)
	}
	return (*C.uint64_t)(ptr), C.size_t(len(ids))
}

func GetObject(conn *grpc.ClientConn, objectId string, version *uint64, ctx context.Context) (*generated.GetObjectResponse, error) {
	client := generated.NewLedgerServiceClient(conn)
	resp, err := client.GetObject(ctx, &generated.GetObjectRequest{
		ObjectId: &objectId,
		Version:  version,
	})
	if err != nil {
		return nil, err
	}

	return resp, err
}

func ListOwnedObjects(conn *grpc.ClientConn, owner string, pagesize *uint32, pagetoken []byte, ctx context.Context) (*generated.ListOwnedObjectsResponse, error) {
	client := generated.NewStateServiceClient(conn)
	resp, err := client.ListOwnedObjects(ctx, &generated.ListOwnedObjectsRequest{
		Owner:     &owner,
		PageSize:  pagesize,
		PageToken: pagetoken,
	})

	if err != nil {
		return nil, err
	}

	return resp, nil
}

func ListDynamicFields(conn *grpc.ClientConn, objectId string, pagesize *uint32, pagetoken []byte, ctx context.Context) (*generated.ListDynamicFieldsResponse, error) {
	client := generated.NewStateServiceClient(conn)
	resp, err := client.ListDynamicFields(ctx, &generated.ListDynamicFieldsRequest{
		Parent:    &objectId,
		PageSize:  pagesize,
		PageToken: pagetoken,
	})

	if err != nil {
		return nil, err
	}

	return resp, nil
}

func OwnedCoins(listownedobjects *generated.ListOwnedObjectsResponse, cointype, owner string) []*generated.Object {
	list := listownedobjects

	var coins []*generated.Object
	for _, v := range list.GetObjects() {

		if *v.ObjectType == cointype {

			coins = append(coins, v)
		}
	}

	return coins
}

type Coin struct {
	Type string
}

func (c *Coin) String() string {
	prefix := "0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin"
	return prefix + "<" + c.Type + ">"
}

var SuiCoin Coin = Coin{
	Type: "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI",
}

var schemeMap = map[byte]generated.SignatureScheme{
	0x00: generated.SignatureScheme_ED25519,
	0x01: generated.SignatureScheme_SECP256K1,
	0x02: generated.SignatureScheme_SECP256R1,
}

func SignExecuteTransaction(conn *grpc.ClientConn, txBytes, signature []byte, ctx context.Context) (*generated.ExecuteTransactionResponse, error) {
	// The serialized signature format is: [flag: 1 byte][sig: 64 bytes][pubkey: 32 bytes]
	if len(signature) != 97 {
		return nil, fmt.Errorf("invalid signature length: expected 97, got %d", len(signature))
	}

	// Extract components
	flagByte := signature[0]        // Should be 0x00 for Ed25519
	sigBytes := signature[1:65]     // 64-byte signature
	pubKeyBytes := signature[65:97] // 32-byte public key

	scheme, exists := schemeMap[flagByte]
	if !exists {
		return nil, fmt.Errorf("Unsupported signature scheme flag: 0x%02x", flagByte)
	}

	client := generated.NewTransactionExecutionServiceClient(conn)
	resp, err := client.ExecuteTransaction(ctx, &generated.ExecuteTransactionRequest{
		Transaction: &generated.Transaction{
			Bcs: &generated.Bcs{Value: txBytes},
		},
		Signatures: []*generated.UserSignature{
			{
				Scheme: scheme.Enum(),
				Signature: &generated.UserSignature_Simple{
					Simple: &generated.SimpleSignature{
						Scheme:    scheme.Enum(),
						Signature: sigBytes,
						PublicKey: pubKeyBytes,
					},
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func GetGas(conn *grpc.ClientConn, ctx context.Context) (*generated.GetEpochResponse, error) {
	client := generated.NewLedgerServiceClient(conn)
	resp, err := client.GetEpoch(ctx, &generated.GetEpochRequest{})

	if err != nil {
		return nil, err
	}

	return resp, nil
}

func SimulateTransaction(conn *grpc.ClientConn, txBytes []byte, ctx context.Context) (*generated.SimulateTransactionResponse, error) {
	client := generated.NewTransactionExecutionServiceClient(conn)
	resp, err := client.SimulateTransaction(ctx, &generated.SimulateTransactionRequest{
		Transaction: &generated.Transaction{
			Bcs: &generated.Bcs{Value: txBytes},
		},
	})
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Helper function to extract estimated budget from simulation response
func EstimateGasBudget(resp *generated.SimulateTransactionResponse) (uint64, error) {
	effects := resp.Transaction.GetEffects()
	if !effects.GetStatus().GetSuccess() {
		return 0, fmt.Errorf("simulation failed: %s", effects.GetStatus().GetError())
	}

	gasUsed := effects.GetGasUsed()

	// Budget must cover Computation + Storage
	// We do NOT subtract the rebate here; the rebate is a refund applied *after* execution.
	estimatedCost := gasUsed.GetComputationCost() + gasUsed.GetStorageCost()

	// Add a small safety buffer (e.g., 5-10%) just to be safe against slight network fluctuations
	// 2.97M becomes ~3.1M
	buffer := estimatedCost / 10
	finalBudget := estimatedCost + buffer

	return finalBudget, nil
}

func FindCoins(ctx context.Context, network NetworkConfig, conn *grpc.ClientConn, owner string) (gas *generated.Object, wal *generated.Object, err error) {
	// We iterate owned objects to find one SUI coin and one WAL coin
	// In production, you'd want to merge coins if balances are too small.
	resp, err := ListOwnedObjects(conn, owner, nil, nil, ctx)
	if err != nil {
		return nil, nil, err
	}
	gasCoin := SuiCoin
	walCoin := Coin{
		Type: network.WalrusCoinObject,
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

type WalSystem struct {
	PackageID string
	Owner     uint64
}

func GetWalSystem(conn *grpc.ClientConn, network NetworkConfig, ctx context.Context) (*WalSystem, error) {
	client := generated.NewLedgerServiceClient(conn)
	address := network.WalrusSystemObject
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

func submitWithRetry(
	conn *grpc.ClientConn,
	txBytes, sigRaw []byte,
	ctx context.Context,
) (*generated.ExecuteTransactionResponse, error) {
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

// SignedTx holds everything needed to submit a transaction.
type SignedTx struct {
	// TxBytes is the base64-encoded BCS transaction — pass as the first
	// argument to sui_executeTransactionBlock.
	TxBytes string

	// Signature is the serialized Ed25519 signature — pass in the
	// "signatures" array to sui_executeTransactionBlock.
	// Format: base64( 0x00 | sig[64] | pubkey[32] )
	Signature string
}

// SignTransaction signs rawBCS (the []byte returned by builder.Build())
// with the private key derived from the given BIP-39 mnemonic.
//
// The mnemonic must be the 12- or 24-word phrase for the Sui account
// whose address matches the sender set in the transaction.
//
// Only Ed25519 keys are supported by this helper; for Secp256k1 use
// signer.NewSignerWithPrivateKey with a Secp256k1 key directly.
func SignTransaction(rawBCS []byte, account *signer.Signer) (*SignedTx, error) {
	// ── 1. Wrap raw BCS in TxnMetaData ────────────────────────────────────
	// TxnMetaData.TxBytes must be standard base64 (not URL-safe, no padding
	// stripped).  The SDK decodes it before intent-wrapping and hashing.
	txMeta := models.TxnMetaData{
		TxBytes: base64.StdEncoding.EncodeToString(rawBCS),
	}

	// ── 2. Sign ───────────────────────────────────────────────────────────
	// SignSerializedSigWith internally:
	//   a. base64-decodes TxBytes
	//   b. prepends the 3-byte transaction intent [0, 0, 0]
	//   c. computes blake2b-256 of the intent message
	//   d. signs the hash with ed25519
	//   e. serialises: base64(flagByte=0x00 | signature[64] | pubKey[32])
	signed := txMeta.SignSerializedSigWith(account.PriKey)

	return &SignedTx{
		TxBytes:   signed.TxBytes,
		Signature: signed.Signature,
	}, nil
}

// AddPooledBlobMetadata sets (creates or updates) a single metadata key/value
// pair on a PooledBlob. Mirrors CertifyBlob's exact shape in sui.go: same
// NewBuilder()/SetConfig/AddGasObject/InputObject/MoveCall/Build/SignTransaction/
// submitWithRetry sequence, same GetWalSystem-based package lookup — storage_pool
// is a module in the same walrus package as system/blob/metadata, so
// wal_system.PackageID is the right package id here too, not a separate one.
func AddPooledBlobMetadata(
	conn *grpc.ClientConn, network NetworkConfig, ctx context.Context,
	acc *signer.Signer,
	storagePoolObjectID string, blobIDBase64 string,
	key, value string,
	gasBudget, gasPrice uint64,
) (*generated.ExecuteTransactionResponse, error) {
	b := NewBuilder()
	defer b.Free() // no-op once Build() succeeds — safe on an already-freed builder

	if err := b.SetConfig(acc.Address, gasBudget, gasPrice); err != nil {
		return nil, fmt.Errorf("set config: %w", err)
	}

	gasCoin, _, err := FindCoins(ctx, network, conn, acc.Address)
	if err != nil {
		return nil, fmt.Errorf("find gas coin: %w", err)
	}
	if err := b.AddGasObject(*gasCoin.ObjectId, uint64(*gasCoin.Version), *gasCoin.Digest); err != nil {
		return nil, fmt.Errorf("add gas object: %w", err)
	}

	wal_system, err := GetWalSystem(conn, network, ctx)
	if err != nil {
		return nil, fmt.Errorf("get wal system: %w", err)
	}

	poolVersion, poolDigest, err := fetchStoragePoolVersionAndDigest(conn, ctx, storagePoolObjectID)
	if err != nil {
		return nil, fmt.Errorf("fetch storage pool version/digest: %w", err)
	}
	poolArg, err := b.InputObject(storagePoolObjectID, poolVersion, poolDigest, ObjectKindOwned, true) // &mut StoragePool
	if err != nil {
		return nil, fmt.Errorf("input storage pool object: %w", err)
	}

	// blob_id as Move u256 — 32 raw little-endian bytes, same wire layout as
	// BlobId itself. Passed via PureRawBCS same as blobIdArg elsewhere in
	// this file — not run through encodeVectorU8, since that helper is for
	// vector<u8> (length-prefixed), and u256 is a fixed-size value with no
	// length prefix.
	blobIDBytes, err := base64.RawURLEncoding.DecodeString(blobIDBase64)
	if err != nil {
		return nil, fmt.Errorf("decode blob_id: %w", err)
	}
	if len(blobIDBytes) != 32 {
		return nil, fmt.Errorf("blob_id must decode to 32 bytes, got %d", len(blobIDBytes))
	}
	blobIDArg := b.PureRawBCS(blobIDBytes)

	// String args DO need the vector<u8> length prefix — same encodeVectorU8
	// already used for key/value in the owned-blob metadata path above.
	keyArg := b.PureRawBCS(encodeVectorU8([]byte(key)))
	valueArg := b.PureRawBCS(encodeVectorU8([]byte(value)))

	_, err = b.MoveCall(
		wal_system.PackageID,
		"storage_pool",
		"insert_or_update_blob_metadata_pair",
		[]string{},
		[]MoveCallArg{
			ArgID(poolArg),
			ArgID(blobIDArg),
			ArgID(keyArg),
			ArgID(valueArg),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("insert_or_update_blob_metadata_pair move call: %w", err)
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

// fetchStoragePoolVersionAndDigest returns a StoragePool object's own
// current version and digest — StoragePool is owned (has key, store in the
// Move struct), not shared, so an owned-object input needs both, not just
// a version.
func fetchStoragePoolVersionAndDigest(conn *grpc.ClientConn, ctx context.Context, objectID string) (uint64, string, error) {
	client := generated.NewLedgerServiceClient(conn)
	resp, err := client.GetObject(ctx, &generated.GetObjectRequest{
		ObjectId: &objectID,
		Version:  nil,
		ReadMask: &fieldmaskpb.FieldMask{
			Paths: []string{"version", "digest"},
		},
	})

	if err != nil {
		return 0, "", err
	}
	return resp.Object.GetVersion(), resp.Object.GetDigest(), nil
}
