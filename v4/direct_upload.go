package v4

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"golangwalrus/v4/suigraphql"

	"golangwalrus/v4/sui_rpc_proto/generated"
	pb "golangwalrus/v4/sui_rpc_proto/generated"

	"github.com/Khan/genqlient/graphql"
	"github.com/block-vision/sui-go-sdk/signer"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// NodeInfo holds the network address and BLS public key for one storage node.
type NodeInfo struct {
	Index          int    // position in the committee members array
	NetworkAddress string // host:port, e.g. "walrus-01.tududes.com:9185"
	PublicKey      []byte // raw BLS12-381 min-pk (48 bytes)
}

// ExtendedCommitteeConfig extends CommitteeConfig with per-node information.
type ExtendedCommitteeConfig struct {
	CommitteeConfig
	Nodes []NodeInfo
}

var extendedCommitteeConfig *ExtendedCommitteeConfig

// mapKeys returns a map's keys for use in error messages.
func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// CommitteeInfoExtended fetches the full committee config.
//
// Call 1: suigraphql.GetDynamicFields(WAL_SYSTEM_OBJ_ID)
//
//	→ committee JSON: n_shards + members[]{node_id, public_key, weight}
//
// Calls 2+: gRPC GetObject(node_id) per member — fired concurrently
//
//	→ staking pool object JSON → node_info.network_address
//
// conn is the caller's existing gRPC connection — no new connection is opened.
func CommitteeInfoExtended(ctx context.Context, conn *grpc.ClientConn) (*ExtendedCommitteeConfig, error) {
	gqlClient := graphql.NewClient(
		"https://graphql.testnet.sui.io/graphql",
		http.DefaultClient,
	)

	// ── Call 1: committee struct ──────────────────────────────────────────
	resp, err := suigraphql.GetDynamicFields(ctx, gqlClient, WAL_SYSTEM_OBJ_ID)
	if err != nil {
		return nil, fmt.Errorf("get system dynamic fields: %w", err)
	}
	dfNodes := resp.Address.GetDynamicFields().Nodes
	if len(dfNodes) == 0 {
		return nil, fmt.Errorf("walrus system object %s has no dynamic fields", WAL_SYSTEM_OBJ_ID)
	}

	moveVal := suigraphql.GetDynamicFieldsAddressDynamicFieldsDynamicFieldConnectionNodesDynamicFieldValueMoveValue(dfNodes[0].Value)

	var sysJSON map[string]any
	if err := json.Unmarshal(moveVal.GetJson(), &sysJSON); err != nil {
		return nil, fmt.Errorf("unmarshal system object JSON: %w", err)
	}

	committeeRaw, ok := sysJSON["committee"].(map[string]any)
	if !ok {
		if valWrap, ok2 := sysJSON["value"].(map[string]any); ok2 {
			committeeRaw, ok = valWrap["committee"].(map[string]any)
		}
		if !ok {
			return nil, fmt.Errorf("committee key not found; top-level keys: %v", mapKeys(sysJSON))
		}
	}

	var nShards int
	switch v := committeeRaw["n_shards"].(type) {
	case float64:
		nShards = int(v)
	case string:
		if _, err := fmt.Sscanf(v, "%d", &nShards); err != nil {
			return nil, fmt.Errorf("parse n_shards: %w", err)
		}
	default:
		return nil, fmt.Errorf("n_shards unexpected type %T", committeeRaw["n_shards"])
	}

	membersRaw, ok := committeeRaw["members"].([]any)
	if !ok {
		return nil, fmt.Errorf("members not found; committee keys: %v", mapKeys(committeeRaw))
	}

	type memberStub struct {
		index     int
		nodeID    string
		publicKey []byte
	}
	stubs := make([]memberStub, 0, len(membersRaw))
	for i, m := range membersRaw {
		member, ok := m.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("member %d: unexpected type %T", i, m)
		}
		nodeID, ok := member["node_id"].(string)
		if !ok {
			return nil, fmt.Errorf("member %d: node_id missing; keys: %v", i, mapKeys(member))
		}
		// public_key is map[bytes:"<base64-std string>"] — confirmed from live data
		pkMap, ok := member["public_key"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("member %d: public_key wrong type (got %T)", i, member["public_key"])
		}
		pkB64, ok := pkMap["bytes"].(string)
		if !ok {
			return nil, fmt.Errorf("member %d: public_key.bytes missing or wrong type", i)
		}
		pkBytes, err := base64.StdEncoding.DecodeString(pkB64)
		if err != nil {
			return nil, fmt.Errorf("member %d: decode public_key base64: %w", i, err)
		}
		stubs = append(stubs, memberStub{index: i, nodeID: nodeID, publicKey: pkBytes})
	}

	// ── Calls 2+: fetch network_address from each staking pool object ─────
	// Confirmed path from live data: node_info["network_address"] (no "fields" wrapper)
	type nodeResult struct {
		index  int
		addr   string
		pubKey []byte
		err    error
	}
	results := make([]nodeResult, len(stubs))
	var wg sync.WaitGroup
	for i, stub := range stubs {
		i, stub := i, stub
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr, err := fetchNodeNetworkAddress(ctx, conn, stub.nodeID)
			if err != nil {
				results[i] = nodeResult{
					index: stub.index,
					err:   fmt.Errorf("member %d (node_id %s): %w", stub.index, stub.nodeID, err),
				}
				return
			}
			results[i] = nodeResult{index: stub.index, addr: addr, pubKey: stub.publicKey}
		}()
	}
	wg.Wait()

	nodeInfos := make([]NodeInfo, len(stubs))
	for i, r := range results {
		if r.err != nil {
			return nil, r.err
		}
		nodeInfos[i] = NodeInfo{
			Index:          r.index,
			NetworkAddress: r.addr,
			PublicKey:      r.pubKey,
		}
	}

	return &ExtendedCommitteeConfig{
		CommitteeConfig: CommitteeConfig{
			NMembers: len(nodeInfos),
			NShards:  nShards,
		},
		Nodes: nodeInfos,
	}, nil
}

// fetchNodeNetworkAddress fetches network_address from the staking pool object
// via gRPC GetObject. Confirmed path from live data:
//
//	node_info["network_address"] — no "fields" wrapper in the gRPC JSON response.
func fetchNodeNetworkAddress(ctx context.Context, conn *grpc.ClientConn, nodeID string) (string, error) {
	client := generated.NewLedgerServiceClient(conn)
	resp, err := client.GetObject(ctx, &generated.GetObjectRequest{
		ObjectId: &nodeID,
		Version:  nil,
		ReadMask: &fieldmaskpb.FieldMask{
			Paths: []string{"json"},
		},
	})
	if err != nil {
		return "", fmt.Errorf("GetObject %s: %w", nodeID, err)
	}

	raw, ok := resp.Object.Json.AsInterface().(map[string]any)
	if !ok {
		return "", fmt.Errorf("object %s: JSON is not a map", nodeID)
	}

	nodeInfo, ok := raw["node_info"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("object %s: node_info missing or wrong type; top-level keys: %v",
			nodeID, mapKeys(raw))
	}

	// Confirmed from live data: network_address is directly in node_info,
	// no "fields" wrapper (gRPC JSON omits Move struct wrapper keys).
	addr, ok := nodeInfo["network_address"].(string)
	if !ok {
		return "", fmt.Errorf("object %s: node_info.network_address missing or wrong type; node_info keys: %v",
			nodeID, mapKeys(nodeInfo))
	}

	return addr, nil
}

// InitExtendedCommitteeConfig fetches and caches the full committee config.
// Pass the existing gRPC conn — no second connection is opened.
// Also populates committeeConfig so all existing code still works.
func InitExtendedCommitteeConfig(ctx context.Context, conn *grpc.ClientConn) error {
	cfg, err := CommitteeInfoExtended(ctx, conn)
	if err != nil {
		return fmt.Errorf("init extended committee config: %w", err)
	}
	extendedCommitteeConfig = cfg
	committeeConfig = &cfg.CommitteeConfig
	fmt.Printf("   ✓ Committee: %d members, %d shards\n", cfg.NMembers, cfg.NShards)
	return nil
}

// GetExtendedCommitteeConfig returns the cached config.
// Panics if InitExtendedCommitteeConfig was not called first.
func GetExtendedCommitteeConfig() *ExtendedCommitteeConfig {
	if extendedCommitteeConfig == nil {
		panic("extendedCommitteeConfig not initialized: call InitExtendedCommitteeConfig first")
	}
	return extendedCommitteeConfig
}

// NewWalrusWASMWithHTTP is the upgraded constructor that registers the
// host_http_put_sliver import before instantiating the WASM module.
//
// Pass nil for httpClient to use a sensible default (60 s timeout, TLS skip).
//
// IMPORTANT: Always use this constructor instead of NewWalrusWASM when you
// intend to call EncodeForUpload / UploadStoredSlivers / AggregateAndBuildCert.
// NewWalrusWASM does not register the "env" host module and the WASM linker
// will refuse to instantiate a module that imports host_http_put_sliver.
func NewWalrusWASMWithHTTP(ctx context.Context, wasmPath string, httpClient *http.Client) (*WalrusWASM, error) {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
		}
	}

	r := wazero.NewRuntime(ctx)

	// Step 1: WASI (must come first — the module links against it).
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		r.Close(ctx)
		return nil, fmt.Errorf("instantiate WASI: %w", err)
	}

	// Step 2: Register our host module ("env") BEFORE instantiating the WASM
	// module.  The linker resolves imports at instantiation time; if "env" is
	// absent the call fails with "unknown import".
	if err := RegisterWalrusHostFunctions(ctx, r, httpClient); err != nil {
		r.Close(ctx)
		return nil, fmt.Errorf("register host functions: %w", err)
	}

	// Step 3: Load + instantiate the WASM module.
	wasmBytes, err := os.ReadFile(wasmPath)
	if err != nil {
		r.Close(ctx)
		return nil, fmt.Errorf("read WASM: %w", err)
	}
	mod, err := r.InstantiateWithConfig(ctx, wasmBytes,
		wazero.NewModuleConfig().WithName("walrus"))
	if err != nil {
		r.Close(ctx)
		return nil, fmt.Errorf("instantiate WASM module: %w", err)
	}

	return &WalrusWASM{ctx: ctx, module: mod}, nil
}

// ── Complete WASM upload flow ─────────────────────────────────────────────────

// UploadResult is returned by CompleteWalrusFlowDirectWASM on success.
type UploadResult struct {
	BlobID           string        // URL-safe base64, no padding
	BlobObjectID     string        // Sui object ID of the on-chain Blob
	RegisterTxDigest string        // Sui TX digest for the register step
	CertifyTxDigest  string        // Sui TX digest for the certify step
	Elapsed          time.Duration // Total wall time
}

// CompleteWalrusFlowDirectWASM is a relay-free, WASM-accelerated upload:
//
//  1. WASM: encode blob → BlobInfo for on-chain args (no trailing-zero bug)
//  2. Go:   reserve + register blob on-chain (same PTB as the original)
//  3. Go:   parallel HTTP PUT of primary slivers to storage nodes
//  4. WASM: aggregate BLS partial signatures → ConfirmationCertificate
//  3. WASM: upload slivers + collect BLS sigs + aggregate certificate
//  4. Go:   certify blob on-chain
//
// Prerequisites:
//   - wasm was created with NewWalrusWASMWithHTTP
//   - cfg was populated with InitExtendedCommitteeConfig (not InitCommitteeConfig)
func CompleteWalrusFlowDirectWASM(
	ctx context.Context,
	conn *grpc.ClientConn,
	acc *signer.Signer,
	mod api.Module,
	blobData []byte,
	filename string,
	cfg *ExtendedCommitteeConfig,
	wasm *WalrusWASM,
) (*UploadResult, error) {
	start := time.Now()
	fmt.Printf("\n[WASM Upload] %s  (%d bytes)\n", filename, len(blobData))
	fmt.Printf("[WASM Upload] Timestamp: %s\n\n", start.Format(time.RFC3339))

	// ── Step 1: WASM encode ───────────────────────────────────────────────────
	fmt.Printf("📝 Step 1/4: Encoding via WASM (%d shards)…\n", cfg.NShards)
	blobInfo, err := wasm.EncodeForUpload(blobData, uint16(cfg.NShards))
	if err != nil {
		return nil, fmt.Errorf("step 1 encode: %w", err)
	}
	blobIDBase64URL := base64.RawURLEncoding.EncodeToString(blobInfo.BlobID)
	fmt.Printf("   ✓ Blob ID:   %s\n", blobIDBase64URL)
	fmt.Printf("   ✓ Unencoded: %d bytes\n\n", blobInfo.UnencodedLength)

	// ── Step 2: get coins + register on-chain ─────────────────────────────────
	fmt.Println("🔍 Step 2/4: Finding coins…")
	gas0, err := GetGas(conn, ctx)
	if err != nil {
		return nil, fmt.Errorf("step 2 get gas price: %w", err)
	}
	gasPrice := *gas0.Epoch.ReferenceGasPrice

	gasCoin, walCoin, err := FindCoins(ctx, conn, acc.Address)
	if err != nil {
		return nil, fmt.Errorf("step 2 find coins: %w", err)
	}
	fmt.Printf("   ✓ Gas coin: %s\n", *gasCoin.ObjectId)
	fmt.Printf("   ✓ WAL coin: %s\n\n", *walCoin.ObjectId)

	fmt.Println("📋 Step 3/4: Registering blob on-chain…")
	register := WalrusRegisterBlob{
		Gasbudget:       100_000_000,
		Gasprice:        gasPrice,
		Amount:          100_000_000,
		Epochs:          5,
		GasCoin:         gasCoin,
		WalCoin:         walCoin,
		BlobId:          [32]byte(blobInfo.BlobID),
		RootHash:        [32]byte(blobInfo.RootHash),
		UnencodedLength: blobInfo.UnencodedLength,
		EncodingType:    uint8(blobInfo.EncodingType),
		Deletable:       true,
		Metadata:        map[string]string{"file_name": filename},
	}
	regResp, err := register.ReserveAndRegisterBlob(conn, mod, acc, ctx)
	if err != nil {
		return nil, fmt.Errorf("step 3 register: %w", err)
	}
	if !*regResp.Transaction.Effects.Status.Success {
		return nil, fmt.Errorf("step 3 register tx failed: %s",
			regResp.Transaction.Effects.Status.Error.String())
	}

	var blobObj *pb.ChangedObject
	for _, obj := range regResp.Transaction.Effects.ChangedObjects {
		if *obj.IdOperation.Enum() == pb.ChangedObject_CREATED {
			blobObj = obj
			break
		}
	}
	if blobObj == nil {
		return nil, fmt.Errorf("step 3: no blob object found in register tx effects")
	}
	registerTxDigest := *regResp.Transaction.Effects.TransactionDigest
	fmt.Printf("   ✓ Blob Object: %s\n", *blobObj.ObjectId)
	fmt.Printf("   ✓ TX:          %s\n\n", registerTxDigest)

	// ── Step 3: WASM sliver upload + BLS aggregation ──────────────────────────
	// upload_stored_slivers drives the full upload loop: for each sliver it calls
	// host_http_put_sliver (Go transport shim), collects partial BLS signatures,
	// checks quorum, and aggregates the certificate — all inside Rust.
	fmt.Printf("☁️  Step 4/4: Uploading slivers and aggregating certificate (WASM)…\n")
	uploadCtx, cancelUpload := context.WithTimeout(ctx, 5*time.Minute)
	defer cancelUpload()

	// Swap the WASM module's context for the upload-scoped one so the host
	// function inherits the timeout.
	origCtx := wasm.ctx
	wasm.ctx = uploadCtx
	certBytes, err := wasm.UploadStoredSlivers(blobIDBase64URL, cfg.Nodes, cfg.NMembers)
	wasm.ctx = origCtx
	if err != nil {
		return nil, fmt.Errorf("step 4 upload slivers: %w", err)
	}

	certFFI, err := DecodeCertificateFFI(certBytes)
	if err != nil {
		return nil, fmt.Errorf("step 4 decode certificate: %w", err)
	}
	cert := certFFI.ToConfirmationCertificate()
	fmt.Printf("   ✓ Certificate: %d signers\n\n", len(certFFI.Signers)*8)

	// ── Step 4: certify on-chain ──────────────────────────────────────────────
	fmt.Println("✍️  Step 5/4: Certifying blob on-chain…")

	latestBlobObj, err := GetObject(conn, *blobObj.ObjectId, blobObj.OutputVersion, ctx)
	if err != nil {
		return nil, fmt.Errorf("step 4 get blob object: %w", err)
	}
	ownedObjs, err := ListOwnedObjects(conn, acc.Address, nil, nil, ctx)
	if err != nil {
		return nil, fmt.Errorf("step 4 list objects: %w", err)
	}
	suiCoins := OwnedCoins(ownedObjs, SuiCoin.String(), acc.Address)
	if len(suiCoins) == 0 {
		return nil, fmt.Errorf("step 4: no SUI coins for certification gas")
	}
	certGasCoin, err := GetObject(conn, *suiCoins[0].ObjectId, suiCoins[0].Version, ctx)
	if err != nil {
		return nil, fmt.Errorf("step 4 get cert gas coin: %w", err)
	}

	certTx := WalrusCertifyBlob{
		Gasbudget:    100_000_000,
		Gasprice:     gasPrice,
		BlobObjectId: *latestBlobObj.Object.ObjectId,
		BlobVersion:  *latestBlobObj.Object.Version,
		BlobDigest:   *latestBlobObj.Object.Digest,
		Certificate:  cert,
		GasCoin:      certGasCoin.Object,
		Config:       &cfg.CommitteeConfig,
	}
	certResp, err := certTx.CertifyBlob(conn, mod, acc, ctx)
	if err != nil {
		return nil, fmt.Errorf("step 4 certify: %w", err)
	}
	if !*certResp.Transaction.Effects.Status.Success {
		return nil, fmt.Errorf("step 4 certify tx failed: %s",
			certResp.Transaction.Effects.Status.Error.String())
	}

	elapsed := time.Since(start)
	certTxDigest := *certResp.Transaction.Effects.TransactionDigest
	fmt.Printf("   ✅ CERTIFIED!\n")
	fmt.Printf("   TX: %s\n\n", certTxDigest)
	fmt.Printf("🎉 COMPLETE in %v\n\n", elapsed)

	return &UploadResult{
		BlobID:           blobIDBase64URL,
		BlobObjectID:     *blobObj.ObjectId,
		RegisterTxDigest: registerTxDigest,
		CertifyTxDigest:  certTxDigest,
		Elapsed:          elapsed,
	}, nil
}
