package v4

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	pb "golangwalrus/v4/sui_rpc_proto/generated"

	"github.com/block-vision/sui-go-sdk/signer"
	"github.com/tetratelabs/wazero/api"
	"google.golang.org/grpc"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// TipConfigResponse is the JSON body returned by GET /v1/tip-config.
// SendTip is nil when the relay is free (no_tip configuration).
type TipConfigResponse struct {
	SendTip *TipRequirement `json:"send_tip,omitempty"`
}

func (t *TipConfigResponse) RequiresTip() bool {
	return t != nil && t.SendTip != nil
}

type TipRequirement struct {
	Address string  `json:"address"`
	Kind    TipKind `json:"kind"`
}

// TipKind is either a fixed amount ("const") or per-shard linear pricing.
type TipKind struct {
	Const  *uint64 `json:"const,omitempty"`
	Linear *uint64 `json:"linear,omitempty"`
}

// Compute returns the tip amount in MIST for nShards shards.
func (k TipKind) Compute(nShards int) uint64 {
	if k.Const != nil {
		return *k.Const
	}
	if k.Linear != nil {
		return uint64(nShards) * (*k.Linear)
	}
	return 0
}

// UploadOptions are the query-string parameters for POST /v1/blob-upload-relay.
type UploadOptions struct {
	BlobID string // Required. Base64 URL-safe, no padding.

	// Required only when the relay charges a tip.
	TxID  string // Base58 transaction digest from PayRelayTip.
	Nonce string // Base64 URL-safe raw nonce preimage from PayRelayTip.

	// Optional.
	DeletableBlobObject string // Hex object ID, only for deletable blobs.
	EncodingType        string // "RS2" (default) or "RedStuff".
}

// UploadResponse is the JSON body returned on a successful relay upload.
// The relay encodes the blob, fans out slivers, and returns the certificate.
type UploadResponse struct {
	BlobID                  json.RawMessage `json:"blob_id"`
	ConfirmationCertificate json.RawMessage `json:"confirmation_certificate"`
}

// relayError is a typed error that carries the HTTP status so the retry
// loop can distinguish permanent (4xx) from transient (5xx / network) failures.
type relayError struct {
	StatusCode int // 0 means a network/transport error
	Body       string
}

func (e *relayError) Error() string {
	if e.StatusCode == 0 {
		return fmt.Sprintf("relay network error: %s", e.Body)
	}
	return fmt.Sprintf("relay error (status %d): %s", e.StatusCode, e.Body)
}

// retryable returns true for transient failures. 4xx (except 429) are permanent.
func (e *relayError) retryable() bool {
	return e.StatusCode == 0 || e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500
}

// ── Client ────────────────────────────────────────────────────────────────────

// UploadRelayClient talks to a Walrus Upload Relay.
type UploadRelayClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewUploadRelayClient creates a client for the given relay base URL,
// e.g. "https://upload-relay.testnet.walrus.space".
func NewUploadRelayClient(baseURL string) *UploadRelayClient {
	return &UploadRelayClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     60 * time.Second,
			},
		},
	}
}

// GetTipConfig fetches the relay's tipping policy from GET /v1/tip-config.
func (c *UploadRelayClient) GetTipConfig(ctx context.Context) (*TipConfigResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/v1/tip-config", nil)
	if err != nil {
		return nil, fmt.Errorf("tip-config request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tip-config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("tip-config status %d: %s", resp.StatusCode, body)
	}

	var cfg TipConfigResponse
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("tip-config decode: %w", err)
	}
	return &cfg, nil
}

// UploadBlob sends raw blob bytes to POST /v1/blob-upload-relay.
// On a non-200 response it returns a *relayError so callers can inspect retryability.
func (c *UploadRelayClient) UploadBlob(ctx context.Context, blobData []byte, opts UploadOptions) (*UploadResponse, error) {
	// Build the query string without double-encoding already URL-safe base64 values.
	parts := make([]string, 0, 5)
	parts = append(parts, "blob_id="+opts.BlobID)
	if opts.TxID != "" {
		parts = append(parts, "tx_id="+opts.TxID)
	}
	if opts.Nonce != "" {
		parts = append(parts, "nonce="+opts.Nonce)
	}
	if opts.DeletableBlobObject != "" {
		parts = append(parts, "deletable_blob_object="+opts.DeletableBlobObject)
	}
	if opts.EncodingType != "" {
		parts = append(parts, "encoding_type="+opts.EncodingType)
	}

	url := c.baseURL + "/v1/blob-upload-relay?" + strings.Join(parts, "&")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(blobData))
	if err != nil {
		return nil, &relayError{Body: err.Error()}
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(blobData))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &relayError{Body: err.Error()}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 4 MB cap
	if err != nil {
		return nil, &relayError{Body: fmt.Sprintf("read response: %v", err)}
	}

	if resp.StatusCode != http.StatusOK {
		preview := string(body)
		if len(preview) > 256 {
			preview = preview[:256] + "…"
		}
		return nil, &relayError{StatusCode: resp.StatusCode, Body: preview}
	}

	var out UploadResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("relay response decode: %w", err)
	}
	return &out, nil
}

// UploadBlobWithRetry calls UploadBlob, retrying transient failures with
// exponential back-off. Permanent errors (4xx except 429) are returned immediately.
// Pass maxAttempts=0 to rely solely on the context deadline.
func (c *UploadRelayClient) UploadBlobWithRetry(
	ctx context.Context,
	blobData []byte,
	opts UploadOptions,
	maxAttempts int,
) (*UploadResponse, error) {
	const (
		initialBackoff = 100 * time.Millisecond
		maxBackoff     = 6 * time.Second
	)
	backoff := initialBackoff

	for attempt := 1; ; attempt++ {
		resp, err := c.UploadBlob(ctx, blobData, opts)
		if err == nil {
			return resp, nil
		}

		// Surface permanent relay errors immediately — no point retrying.
		if re, ok := err.(*relayError); ok && !re.retryable() {
			return nil, fmt.Errorf("permanent relay error after %d attempt(s): %w", attempt, err)
		}

		if maxAttempts > 0 && attempt >= maxAttempts {
			return nil, fmt.Errorf("relay upload failed after %d attempt(s): %w", attempt, err)
		}

		fmt.Printf("   ⚠️  Relay attempt %d failed: %v — retrying in %s\n", attempt, err, backoff)

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("relay upload cancelled after %d attempt(s): %w", attempt, ctx.Err())
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// ── Tip Payment ───────────────────────────────────────────────────────────────

// TipResult holds the on-chain transaction digest and the raw nonce preimage
// that must be forwarded to the relay in the upload query string.
type TipResult struct {
	TxDigest string // Base58 transaction digest
	Nonce    string // Base64 URL-safe raw nonce (the preimage, NOT the hash)
}

// PayRelayTip constructs and executes the tip PTB required by a relay that has
// tip_config = send_tip.  It returns the transaction digest and raw nonce
// preimage that must be forwarded verbatim to UploadOptions.TxID / .Nonce.
//
// gasBudget is typically 10_000_000 MIST; tipAmount is in MIST.
func PayRelayTip(
	ctx context.Context,
	conn *grpc.ClientConn,
	mod api.Module,
	acc *signer.Signer,
	blobData []byte,
	tipAmount uint64,
	recipient string,
	gasCoin *pb.Object,
	gasPrice uint64,
	gasBudget uint64,
) (*TipResult, error) {
	// ── 1. Generate 32-byte random nonce ─────────────────────────────────────
	nonceRaw := make([]byte, 32)
	if _, err := rand.Read(nonceRaw); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	// The URL carries the raw preimage; the on-chain auth package carries its hash.
	nonceStr := base64.RawURLEncoding.EncodeToString(nonceRaw)

	// ── 2. Build auth package: blob_digest || nonce_digest || unencoded_len ──
	blobDigest := sha256.Sum256(blobData)
	nonceDigest := sha256.Sum256(nonceRaw)
	lenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBytes, uint64(len(blobData)))

	authPayload := make([]byte, 0, 32+32+8)
	authPayload = append(authPayload, blobDigest[:]...)
	authPayload = append(authPayload, nonceDigest[:]...)
	authPayload = append(authPayload, lenBytes...)

	// ── 3. Build PTB ──────────────────────────────────────────────────────────
	b := NewBuilder(ctx, mod)
	if err := b.SetConfig(acc.Address, gasBudget, gasPrice); err != nil {
		return nil, fmt.Errorf("tip PTB config: %w", err)
	}
	if err := b.AddGasObject(*gasCoin.ObjectId, uint64(*gasCoin.Version), *gasCoin.Digest); err != nil {
		return nil, fmt.Errorf("tip PTB gas object: %w", err)
	}

	// Input 0: BCS auth package (raw bytes, not ULEB128-prefixed here)
	b.PureRawBCS(authPayload)

	// Split tip from gas coin and transfer to relay address.
	gasArg := b.GasArgument()
	amtArg := b.PureU64(tipAmount)
	recArg, err := b.PureAddress(recipient)
	if err != nil {
		return nil, fmt.Errorf("tip PTB recipient: %w", err)
	}

	splitRes, err := b.SplitCoins(gasArg, []uint64{amtArg})
	if err != nil {
		return nil, fmt.Errorf("tip PTB split coins: %w", err)
	}
	tipCoin, err := b.NestedResult(splitRes, 0)
	if err != nil {
		return nil, err
	}
	b.TransferObjects([]uint64{tipCoin}, recArg)

	// ── 4. Sign and execute ───────────────────────────────────────────────────
	txBytes, err := b.Build()
	if err != nil {
		return nil, fmt.Errorf("tip PTB build: %w", err)
	}

	signed, err := SignTransaction(txBytes, acc)
	if err != nil {
		return nil, fmt.Errorf("tip PTB sign: %w", err)
	}

	sigRaw, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return nil, fmt.Errorf("tip PTB decode sig: %w", err)
	}

	execResp, err := submitWithRetry(conn, txBytes, sigRaw, ctx)
	if err != nil {
		return nil, fmt.Errorf("tip PTB execute: %w", err)
	}

	return &TipResult{
		TxDigest: *execResp.Transaction.Effects.TransactionDigest,
		Nonce:    nonceStr,
	}, nil
}

// ── ParseCertificate ──────────────────────────────────────────────────────────

// ParseCertificate unmarshals the ConfirmationCertificate embedded in the
// relay's UploadResponse.ConfirmationCertificate field.
func ParseCertificate(certBytes []byte) (*ConfirmationCertificate, error) {
	var cert ConfirmationCertificate
	if err := json.Unmarshal(certBytes, &cert); err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return &cert, nil
}

// ── CompleteWalrusFlowRelay ───────────────────────────────────────────────────

// CompleteWalrusFlowRelay is the relay-backed upload path:
//
//  1. WASM encodes the blob → blob_id, root_hash            (concurrent with 1a)
//     1a. Prefetch gas price + relay tip config                (concurrent with 1)
//  2. Reserve + register the blob on-chain
//  3. Pay relay tip (skipped for free relays)
//  4. POST raw blob to relay → relay fans out slivers,
//     collects BLS signatures, returns ConfirmationCertificate
//  5. Certify the blob on-chain with the certificate
//
// cfg only needs NMembers and NShards — node addresses are not required.
func CompleteWalrusFlowRelay(
	ctx context.Context,
	conn *grpc.ClientConn,
	acc *signer.Signer,
	mod api.Module,
	blobData []byte,
	filename string,
	cfg *CommitteeConfig,
	wasm *WalrusWASM,
	relay *UploadRelayClient,
) (*UploadResult, error) {
	start := time.Now()
	fmt.Printf("\n[Relay Upload] %s  (%d bytes)\n", filename, len(blobData))
	fmt.Printf("[Relay Upload] Timestamp: %s\n\n", start.Format(time.RFC3339))

	// ── Step 1: Prefetch gas + tip config concurrently while WASM encodes ────
	// Both are read-only network calls that overlap with CPU-bound encoding.
	type gasResult struct {
		price uint64
		err   error
	}
	type tipConfigResult struct {
		cfg *TipConfigResponse
		err error
	}

	gasCh := make(chan gasResult, 1)
	tipCh := make(chan tipConfigResult, 1)

	go func() {
		gas, err := GetGas(conn, ctx)
		if err != nil {
			gasCh <- gasResult{err: err}
			return
		}
		gasCh <- gasResult{price: *gas.Epoch.ReferenceGasPrice}
	}()
	go func() {
		tc, err := relay.GetTipConfig(ctx)
		tipCh <- tipConfigResult{cfg: tc, err: err}
	}()

	fmt.Printf("📝 Step 1/5: Encoding via WASM (%d shards)…\n", cfg.NShards)
	blobInfo, err := wasm.EncodeForUpload(blobData, uint16(cfg.NShards))
	if err != nil {
		return nil, fmt.Errorf("step 1 encode: %w", err)
	}
	blobIDBase64URL := base64.RawURLEncoding.EncodeToString(blobInfo.BlobID)
	fmt.Printf("   ✓ Blob ID:   %s\n", blobIDBase64URL)
	fmt.Printf("   ✓ Unencoded: %d bytes\n\n", blobInfo.UnencodedLength)

	gr := <-gasCh
	if gr.err != nil {
		return nil, fmt.Errorf("step 1 gas price: %w", gr.err)
	}
	gasPrice := gr.price

	tcr := <-tipCh
	if tcr.err != nil {
		return nil, fmt.Errorf("step 1 tip config: %w", tcr.err)
	}
	tipCfg := tcr.cfg

	// ── Step 2: Find coins + register blob on-chain ───────────────────────────
	fmt.Println("🔍 Step 2/5: Finding coins…")
	gasCoin, walCoin, err := FindCoins(ctx, conn, acc.Address)
	if err != nil {
		return nil, fmt.Errorf("step 2 find coins: %w", err)
	}
	fmt.Printf("   ✓ Gas coin: %s\n", *gasCoin.ObjectId)
	fmt.Printf("   ✓ WAL coin: %s\n\n", *walCoin.ObjectId)

	fmt.Println("📋 Step 2/5: Registering blob on-chain…")
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
		return nil, fmt.Errorf("step 2 register: %w", err)
	}
	if !*regResp.Transaction.Effects.Status.Success {
		return nil, fmt.Errorf("step 2 register tx failed: %s",
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
		return nil, fmt.Errorf("step 2: no blob object in register tx effects")
	}
	registerTxDigest := *regResp.Transaction.Effects.TransactionDigest
	fmt.Printf("   ✓ Blob Object: %s\n", *blobObj.ObjectId)
	fmt.Printf("   ✓ TX:          %s\n\n", registerTxDigest)

	// ── Step 3: Pay relay tip (skipped for free relays) ───────────────────────
	uploadOpts := UploadOptions{
		BlobID:              blobIDBase64URL,
		DeletableBlobObject: *blobObj.ObjectId,
	}

	if tipCfg.RequiresTip() {
		tipAmount := tipCfg.SendTip.Kind.Compute(cfg.NShards)
		fmt.Printf("💰 Step 3/5: Paying relay tip (%d MIST → %s)…\n",
			tipAmount, tipCfg.SendTip.Address)

		// Registration consumed gasCoin; fetch a fresh SUI coin for the tip PTB.
		tipGasCoin, _, err := FindCoins(ctx, conn, acc.Address)
		if err != nil {
			return nil, fmt.Errorf("step 3 find tip gas coin: %w", err)
		}

		tip, err := PayRelayTip(ctx, conn, mod, acc,
			blobData,
			tipAmount,
			tipCfg.SendTip.Address,
			tipGasCoin,
			gasPrice,
			10_000_000,
		)
		if err != nil {
			return nil, fmt.Errorf("step 3 pay tip: %w", err)
		}
		uploadOpts.TxID = tip.TxDigest
		uploadOpts.Nonce = tip.Nonce
		fmt.Printf("   ✓ Tip TX: %s\n\n", tip.TxDigest)
	} else {
		fmt.Println("💰 Step 3/5: Free relay — no tip required")
	}

	// ── Step 4: Upload raw blob to relay ──────────────────────────────────────
	// The relay re-encodes, fans out slivers to all nodes, collects BLS
	// partial signatures, aggregates them, and returns the certificate.
	fmt.Println("☁️  Step 4/5: Uploading via relay…")
	uploadCtx, cancelUpload := context.WithTimeout(ctx, 10*time.Minute)
	defer cancelUpload()

	uploadResp, err := relay.UploadBlobWithRetry(uploadCtx, blobData, uploadOpts, 3)
	if err != nil {
		return nil, fmt.Errorf("step 4 relay upload: %w", err)
	}

	cert, err := ParseCertificate(uploadResp.ConfirmationCertificate)
	if err != nil {
		return nil, fmt.Errorf("step 4 parse certificate: %w", err)
	}
	fmt.Printf("   ✓ Certificate received\n\n")

	// ── Step 5: Certify blob on-chain ─────────────────────────────────────────
	fmt.Println("✍️  Step 5/5: Certifying blob on-chain…")

	// Re-fetch blob object at its latest version after relay upload.
	latestBlobObj, err := GetObject(conn, *blobObj.ObjectId, blobObj.OutputVersion, ctx)
	if err != nil {
		return nil, fmt.Errorf("step 5 get blob object: %w", err)
	}

	// Find a fresh SUI coin for certification gas (registration + tip consumed earlier ones).
	ownedObjs, err := ListOwnedObjects(conn, acc.Address, nil, nil, ctx)
	if err != nil {
		return nil, fmt.Errorf("step 5 list objects: %w", err)
	}
	suiCoins := OwnedCoins(ownedObjs, SuiCoin.String(), acc.Address)
	if len(suiCoins) == 0 {
		return nil, fmt.Errorf("step 5: no SUI coins available for certification gas")
	}
	certGasCoin, err := GetObject(conn, *suiCoins[0].ObjectId, suiCoins[0].Version, ctx)
	if err != nil {
		return nil, fmt.Errorf("step 5 get cert gas coin: %w", err)
	}

	certTx := WalrusCertifyBlob{
		Gasbudget:    100_000_000,
		Gasprice:     gasPrice,
		BlobObjectId: *latestBlobObj.Object.ObjectId,
		BlobVersion:  *latestBlobObj.Object.Version,
		BlobDigest:   *latestBlobObj.Object.Digest,
		Certificate:  cert,
		GasCoin:      certGasCoin.Object,
		Config:       cfg,
	}
	certResp, err := certTx.CertifyBlob(conn, mod, acc, ctx)
	if err != nil {
		return nil, fmt.Errorf("step 5 certify: %w", err)
	}
	if !*certResp.Transaction.Effects.Status.Success {
		return nil, fmt.Errorf("step 5 certify tx failed: %s",
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
