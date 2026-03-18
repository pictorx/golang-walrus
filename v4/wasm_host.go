package v4

// wasm_host.go — wazero host-function registration and helpers for the direct
// upload flow that delegates HTTP to Go but encoding/BLS to WASM.
//
// Call RegisterWalrusHostFunctions once after creating the wazero Runtime but
// before instantiating the WASM module.  Then use the new WalrusWASM methods:
//
//   EncodeForUpload        → replaces CreateEncoder + GetSliverSize + Encode
//   UploadStoredSlivers    → replaces uploadSliversDirect (Go) + buildCertificate
//   AggregateAndBuildCert  → standalone aggregator for parallel-Go-HTTP workflows
//   ComputeDispatchTable   → sliver-index → node-index mapping for Go parallelism
//   BuildSignersBitmap     → mirrors signersToWalrusBitmap in walrus.go

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// ── Host function registration ────────────────────────────────────────────────

// RegisterWalrusHostFunctions registers the "env" module that the WASM module
// imports.  Call this before instantiating the WASM module.
//
//	r  := wazero.NewRuntime(ctx)
//	wasi_snapshot_preview1.Instantiate(ctx, r)
//	RegisterWalrusHostFunctions(ctx, r, httpClient)        // ← new step
//	mod, _ := r.InstantiateWithConfig(ctx, wasmBytes, ...)
func RegisterWalrusHostFunctions(
	ctx context.Context,
	r wazero.Runtime,
	httpClient *http.Client,
) error {
	if httpClient == nil {
		httpClient = defaultHTTPClient()
	}
	_, err := r.NewHostModuleBuilder("env").
		NewFunctionBuilder().
		WithGoModuleFunction(
			hostPutSliverFunc(ctx, httpClient),
			// params: url_ptr, url_len, body_ptr, body_len,
			//         out_sig_ptr, out_sig_len_ptr, out_msg_ptr, out_msg_len_ptr
			[]api.ValueType{
				api.ValueTypeI32, api.ValueTypeI32, // url
				api.ValueTypeI32, api.ValueTypeI32, // body
				api.ValueTypeI32, api.ValueTypeI32, // out sig buf + len ptr
				api.ValueTypeI32, api.ValueTypeI32, // out msg buf + len ptr
			},
			[]api.ValueType{api.ValueTypeI32}, // return: HTTP status or negative
		).
		Export("host_http_put_sliver").
		Instantiate(ctx)
	return err
}

// defaultHTTPClient matches the settings used in CompleteWalrusFlowDirect.
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}

// encodeI32 converts a signed i32 to the uint64 representation wazero uses
// for WASM stack values.  This is necessary for negative return codes because
// uint64(int(-12)) produces the wrong bit pattern on 64-bit platforms.
func encodeI32(v int32) uint64 {
	return uint64(uint32(v))
}

// hostPutSliverFunc returns the wazero host function that WASM calls to PUT a
// single BCS-encoded primary sliver to a Walrus storage node.
//
// It mirrors the inner loop of uploadSliverToNodeWithRetry in direct_upload.go:
//   - tries http + https × with and without explicit :9185 port
//   - parses the node JSON response to extract sig + msg bytes
//   - writes them into the WASM output buffers
//
// wazero v1 GoModuleFunc writes return values into stack in-place; the func
// must NOT return []uint64.
func hostPutSliverFunc(_ context.Context, client *http.Client) api.GoModuleFunc {
	return api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
		urlPtr := uint32(stack[0])
		urlLen := uint32(stack[1])
		bodyPtr := uint32(stack[2])
		bodyLen := uint32(stack[3])
		outSigPtr := uint32(stack[4])
		outSigLenPtr := uint32(stack[5])
		outMsgPtr := uint32(stack[6])
		outMsgLenPtr := uint32(stack[7])

		mem := mod.Memory()

		urlBytes, ok := mem.Read(urlPtr, urlLen)
		if !ok {
			stack[0] = encodeI32(ERROR_HTTP_FAILED)
			return
		}
		bodyBytes, ok := mem.Read(bodyPtr, bodyLen)
		if !ok {
			stack[0] = encodeI32(ERROR_HTTP_FAILED)
			return
		}

		baseURL := string(urlBytes)
		sig, msg, statusCode := tryPutVariants(ctx, client, baseURL, bodyBytes)

		if statusCode == http.StatusOK && len(sig) > 0 {
			mem.Write(outSigPtr, sig)
			mem.WriteUint32Le(outSigLenPtr, uint32(len(sig)))
			mem.Write(outMsgPtr, msg)
			mem.WriteUint32Le(outMsgLenPtr, uint32(len(msg)))
		}

		// Encode the HTTP status code as i32 — works correctly for both
		// positive status codes (200, 404 …) and negative sentinels (-1).
		stack[0] = encodeI32(int32(statusCode))
	})
}

// logFirstSliver enables per-variant logging for the first sliver only,
// so a 1000-shard upload doesn't flood stdout.
var (
	logFirstSliverOnce   sync.Once
	logFirstSliverActive bool
)

// tryPutVariants attempts PUT against HTTPS-first variants of the URL.
// Nodes speak TLS on port 9185, so we try HTTPS before HTTP.
func tryPutVariants(ctx context.Context, client *http.Client, canonical string, body []byte) (sig, msg []byte, statusCode int) {
	host := extractHost(canonical)
	path := extractPath(canonical)

	// HTTPS on 9185 first — Walrus storage nodes require TLS.
	variants := []string{
		"https://" + ensurePort(host, "9185") + path,
		"https://" + host + path,
		"http://" + ensurePort(host, "9185") + path,
		"http://" + host + path,
	}

	logFirstSliverOnce.Do(func() { logFirstSliverActive = true })

	for _, url := range variants {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
		if err != nil {
			if logFirstSliverActive {
				log.Printf("[sliver:first] build error  url=%s  err=%v", url, err)
			}
			continue
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("User-Agent", "walrus-wasm-client/0.1")

		resp, err := client.Do(req)
		if err != nil {
			if logFirstSliverActive {
				log.Printf("[sliver:first] transport error  url=%s  err=%v", url, err)
			}
			continue
		}
		rawBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if logFirstSliverActive {
			log.Printf("[sliver:first] url=%s  status=%d  body=%s",
				url, resp.StatusCode, truncate(rawBody, 512))
		}

		if resp.StatusCode == http.StatusOK {
			sig, msg = parseNodeResponse(rawBody)
			if logFirstSliverActive {
				log.Printf("[sliver:first] parse  sig_len=%d  msg_len=%d", len(sig), len(msg))
				if len(sig) == 0 {
					log.Printf("[sliver:first] WARNING: 200 OK but sig is empty — response shape mismatch")
				}
				logFirstSliverActive = false
			}
			return sig, msg, http.StatusOK
		}
	}

	if logFirstSliverActive {
		log.Printf("[sliver:first] all variants failed  canonical=%s", canonical)
		logFirstSliverActive = false
	}
	return nil, nil, -1
}

// truncate returns body as a readable string, capped at maxBytes.
func truncate(b []byte, maxBytes int) string {
	if len(b) > maxBytes {
		b = b[:maxBytes]
	}
	return strings.ToValidUTF8(string(b), "<?>")
}

// nodeResponse mirrors the JSON returned by a Walrus storage node on success.
type nodeResponse struct {
	Type string `json:"type"`
	Data struct {
		Primary struct {
			Sig string `json:"sig"` // base64-std
			Msg string `json:"msg"` // base64-std
		} `json:"primary"`
	} `json:"data"`
}

func parseNodeResponse(body []byte) (sig, msg []byte) {
	var nr nodeResponse
	if err := json.Unmarshal(body, &nr); err != nil || nr.Type != "success" {
		return nil, nil
	}
	sig, _ = base64.StdEncoding.DecodeString(nr.Data.Primary.Sig)
	msg, _ = base64.StdEncoding.DecodeString(nr.Data.Primary.Msg)
	return sig, msg
}

func extractHost(rawURL string) string {
	s := strings.TrimPrefix(rawURL, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.Index(s, "/"); idx >= 0 {
		return s[:idx]
	}
	return s
}

func extractPath(rawURL string) string {
	s := strings.TrimPrefix(rawURL, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.Index(s, "/"); idx >= 0 {
		return s[idx:]
	}
	return "/"
}

// ensurePort appends ":port" if the host string has no port already.
func ensurePort(host, port string) string {
	if strings.Contains(host, ":") {
		return host
	}
	return host + ":" + port
}

// ── New WalrusWASM methods ────────────────────────────────────────────────────

// BlobInfo is returned by EncodeForUpload and contains the fields needed for
// the on-chain ReserveAndRegisterBlob call.
type BlobInfo struct {
	BlobID          []byte // 32 bytes
	RootHash        []byte // 32 bytes
	UnencodedLength uint64
	EncodingType    uint32 // 0 = RedStuff, 1 = RS2
}

// EncodeForUpload encodes blobData into sliver pairs stored inside WASM state
// and returns the BlobInfo needed for on-chain registration.
//
// This replaces the CreateEncoder → GetSliverSize → Encode → ExtractBlobInfo
// sequence in CompleteWalrusFlowDirect.  It avoids the trailing-zero sliver
// bytes that arise when Go pre-allocates sliverSizeUint-byte buffers.
func (w *WalrusWASM) EncodeForUpload(blobData []byte, nShards uint16) (*BlobInfo, error) {
	encodeFunc := w.module.ExportedFunction("encode_for_upload")
	blobInfoSize := w.module.ExportedFunction("blob_info_ffi_size")

	// Determine output buffer size.
	sizeResult, err := blobInfoSize.Call(w.ctx)
	if err != nil {
		return nil, fmt.Errorf("blob_info_ffi_size: %w", err)
	}
	outCapacity := uint32(sizeResult[0])

	// Write blob data into WASM memory.
	dataPtr, err := w.writeBytes(blobData)
	if err != nil {
		return nil, err
	}
	defer w.deallocate(dataPtr, uint32(len(blobData)))

	outPtr, err := w.allocate(outCapacity)
	if err != nil {
		return nil, err
	}
	defer w.deallocate(outPtr, outCapacity)

	results, err := encodeFunc.Call(w.ctx,
		uint64(dataPtr), uint64(len(blobData)),
		uint64(nShards),
		uint64(outPtr), uint64(outCapacity),
	)
	if err != nil {
		return nil, fmt.Errorf("encode_for_upload: %w", err)
	}
	ret := int32(results[0])
	if ret < 0 {
		return nil, fmt.Errorf("encode_for_upload failed: code %d", ret)
	}

	// Read bincode BlobInfoFFI: [32]u8 blob_id, [32]u8 root_hash, u64 unencoded_len, u32 encoding_type
	raw, err := w.readBytes(outPtr, uint32(ret))
	if err != nil {
		return nil, err
	}
	return parseBlobInfo(raw)
}

// parseBlobInfo decodes a bincode-serialized BlobInfoFFI.
// bincode uses little-endian; fields are: 32+32+8+4 bytes (no length prefixes
// for fixed-size arrays).
func parseBlobInfo(raw []byte) (*BlobInfo, error) {
	// bincode serializes [u8; 32] as 32 raw bytes (no length prefix).
	// u64 / u32 are little-endian.
	const minSize = 32 + 32 + 8 + 4
	if len(raw) < minSize {
		return nil, fmt.Errorf("blob info too short: %d bytes", len(raw))
	}
	bi := &BlobInfo{
		BlobID:   make([]byte, 32),
		RootHash: make([]byte, 32),
	}
	copy(bi.BlobID, raw[0:32])
	copy(bi.RootHash, raw[32:64])
	bi.UnencodedLength = binary.LittleEndian.Uint64(raw[64:72])
	bi.EncodingType = binary.LittleEndian.Uint32(raw[72:76])
	return bi, nil
}

// UploadStoredSlivers uploads the sliver pairs previously stored by EncodeForUpload
// directly to storage nodes and returns the aggregated ConfirmationCertificate.
//
// The certificate is returned as raw bincode bytes — pass them to
// DecodeCertificateFFI to get a *ConfirmationCertificate.
//
// This replaces uploadSliversDirect + buildCertificate in direct_upload.go when
// using the WASM-orchestrated upload path.
func (w *WalrusWASM) UploadStoredSlivers(
	blobIDBase64URL string,
	nodes []NodeInfo,
	nMembers int,
) ([]byte, error) {
	uploadFunc := w.module.ExportedFunction("upload_stored_slivers")

	// Serialize blob ID.
	blobIDBytes := []byte(blobIDBase64URL)
	blobIDPtr, err := w.writeBytes(blobIDBytes)
	if err != nil {
		return nil, err
	}
	defer w.deallocate(blobIDPtr, uint32(len(blobIDBytes)))

	// Serialize node table as bincode Vec<NodeInfoFFI>.
	nodesFFI := make([]nodeInfoFFI, len(nodes))
	for i, n := range nodes {
		nodesFFI[i] = nodeInfoFFI{
			Index:          uint32(n.Index),
			NetworkAddress: n.NetworkAddress,
			PublicKey:      n.PublicKey,
		}
	}
	nodesBytes, err := bincodeSerialize(nodesFFI)
	if err != nil {
		return nil, fmt.Errorf("serialize nodes: %w", err)
	}
	nodesPtr, err := w.writeBytes(nodesBytes)
	if err != nil {
		return nil, err
	}
	defer w.deallocate(nodesPtr, uint32(len(nodesBytes)))

	// Output buffer: certificate is small (< 4 KiB).
	const certBufSize = 4096
	outPtr, err := w.allocate(certBufSize)
	if err != nil {
		return nil, err
	}
	defer w.deallocate(outPtr, certBufSize)

	results, err := uploadFunc.Call(w.ctx,
		uint64(blobIDPtr), uint64(len(blobIDBytes)),
		uint64(nodesPtr), uint64(len(nodesBytes)),
		uint64(nMembers),
		uint64(outPtr), uint64(certBufSize),
	)
	if err != nil {
		return nil, fmt.Errorf("upload_stored_slivers: %w", err)
	}
	ret := int32(results[0])
	if ret < 0 {
		return nil, fmt.Errorf("upload_stored_slivers failed: code %d", ret)
	}

	raw, err := w.readBytes(outPtr, uint32(ret))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	return out, nil
}

// AggregateAndBuildCert aggregates partial BLS signatures collected by parallel
// Go goroutines (e.g. from uploadSliversDirect) and builds a certificate.
//
// Use this when you prefer Go's parallel HTTP but still want WASM for crypto.
//
// partialSigs is a slice of (NodeIndex, sigBytes, msgBytes) — use the
// NodePartialSigFFI helper below.
func (w *WalrusWASM) AggregateAndBuildCert(partialSigs []NodePartialSigFFI, nMembers int) ([]byte, error) {
	aggFunc := w.module.ExportedFunction("aggregate_and_build_certificate")

	sigsBytes, err := bincodeSerialize(partialSigs)
	if err != nil {
		return nil, fmt.Errorf("serialize partial sigs: %w", err)
	}
	sigsPtr, err := w.writeBytes(sigsBytes)
	if err != nil {
		return nil, err
	}
	defer w.deallocate(sigsPtr, uint32(len(sigsBytes)))

	const certBufSize = 4096
	outPtr, err := w.allocate(certBufSize)
	if err != nil {
		return nil, err
	}
	defer w.deallocate(outPtr, certBufSize)

	results, err := aggFunc.Call(w.ctx,
		uint64(sigsPtr), uint64(len(sigsBytes)),
		uint64(nMembers),
		uint64(outPtr), uint64(certBufSize),
	)
	if err != nil {
		return nil, fmt.Errorf("aggregate_and_build_certificate: %w", err)
	}
	ret := int32(results[0])
	if ret < 0 {
		return nil, fmt.Errorf("aggregate_and_build_certificate failed: code %d", ret)
	}

	raw, err := w.readBytes(outPtr, uint32(ret))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	return out, nil
}

// ComputeDispatchTable returns a slice of length nShards where element i is the
// primary node index for sliver i.  Matches getTargetNodesForSliver in
// direct_upload.go (simple modulo routing).
func (w *WalrusWASM) ComputeDispatchTable(nShards, nNodes int) ([]uint32, error) {
	dispatchFunc := w.module.ExportedFunction("compute_sliver_dispatch_table")
	outSize := uint32(nShards * 4)
	outPtr, err := w.allocate(outSize)
	if err != nil {
		return nil, err
	}
	defer w.deallocate(outPtr, outSize)

	results, err := dispatchFunc.Call(w.ctx,
		uint64(nShards), uint64(nNodes),
		uint64(outPtr), uint64(outSize),
	)
	if err != nil {
		return nil, fmt.Errorf("compute_sliver_dispatch_table: %w", err)
	}
	ret := int32(results[0])
	if ret < 0 {
		return nil, fmt.Errorf("compute_sliver_dispatch_table failed: code %d", ret)
	}

	raw, err := w.readBytes(outPtr, uint32(ret))
	if err != nil {
		return nil, err
	}
	table := make([]uint32, nShards)
	for i := range table {
		table[i] = binary.LittleEndian.Uint32(raw[i*4:])
	}
	return table, nil
}

// BuildSignersBitmapWASM calls the WASM build_signers_bitmap function.
// Equivalent to signersToWalrusBitmap in walrus.go but runs inside WASM.
func (w *WalrusWASM) BuildSignersBitmapWASM(signerIndices []uint8, nMembers int) ([]byte, error) {
	bitmapFunc := w.module.ExportedFunction("build_signers_bitmap")
	idxPtr, err := w.writeBytes(signerIndices)
	if err != nil {
		return nil, err
	}
	defer w.deallocate(idxPtr, uint32(len(signerIndices)))

	outSize := uint32((nMembers + 7) / 8)
	outPtr, err := w.allocate(outSize)
	if err != nil {
		return nil, err
	}
	defer w.deallocate(outPtr, outSize)

	results, err := bitmapFunc.Call(w.ctx,
		uint64(idxPtr), uint64(len(signerIndices)),
		uint64(nMembers),
		uint64(outPtr), uint64(outSize),
	)
	if err != nil {
		return nil, fmt.Errorf("build_signers_bitmap: %w", err)
	}
	ret := int32(results[0])
	if ret < 0 {
		return nil, fmt.Errorf("build_signers_bitmap failed: code %d", ret)
	}
	raw, err := w.readBytes(outPtr, uint32(ret))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	return out, nil
}

// ── FFI-compatible struct types ───────────────────────────────────────────────

// nodeInfoFFI mirrors NodeInfoFFI in Rust — must be bincode-serialized before
// passing to WASM.
type nodeInfoFFI struct {
	Index          uint32
	NetworkAddress string
	PublicKey      []byte
}

// NodePartialSigFFI mirrors NodePartialSig in Rust.
// Populate from your uploadSliverToNodeWithRetry results.
type NodePartialSigFFI struct {
	NodeIndex uint32
	Sig       []byte
	Msg       []byte
}

// CertificateFFI mirrors ConfirmationCertificate in Rust (bincode).
type CertificateFFI struct {
	Signers           []byte
	SerializedMessage []byte
	Signature         []byte // raw bytes, not base64
}

// DecodeCertificateFFI decodes a bincode-serialized ConfirmationCertificate
// returned by UploadStoredSlivers or AggregateAndBuildCert.
//
// The resulting CertificateFFI.Signature contains raw bytes; convert to
// base64.StdEncoding for use in WalrusCertifyBlob.
func DecodeCertificateFFI(raw []byte) (*CertificateFFI, error) {
	cert, err := bincodeDeserializeCert(raw)
	if err != nil {
		return nil, fmt.Errorf("decode certificate: %w", err)
	}
	return cert, nil
}

// ToConfirmationCertificate converts a CertificateFFI into the ConfirmationCertificate
// type used by WalrusCertifyBlob.
func (c *CertificateFFI) ToConfirmationCertificate() *ConfirmationCertificate {
	return &ConfirmationCertificate{
		Signers:           c.Signers,
		SerializedMessage: c.SerializedMessage,
		Signature:         base64.StdEncoding.EncodeToString(c.Signature),
	}
}

// ── Parallel-Go upload variant ────────────────────────────────────────────────

// CompleteWalrusFlowDirectWASM is a drop-in replacement for CompleteWalrusFlowDirect
// that uses WASM for encoding and BLS but keeps Go's parallel HTTP for uploads.
//
// Workflow:
//  1. EncodeForUpload  (WASM: encode + store sliver pairs)
//  2. Register blob on-chain  (Go: same as before)
//  3. uploadSliversParallelGo  (Go: parallel HTTP PUT using the encode result)
//  4. AggregateAndBuildCert  (WASM: aggregate BLS sigs)
//  5. Certify blob on-chain  (Go: same as before)
//
// It is intentionally structured so each step can be replaced independently.
func (w *WalrusWASM) UploadSliversParallelGo(
	ctx context.Context,
	blobIDBase64URL string,
	// encodeResult must come from a preceding EncodeForUpload call's internal
	// state.  Pass the BlobInfo only for routing — slivers are fetched from
	// the EncodeResult that was captured during encoding via the encode function.
	encodedPrimary [][]byte, // from the classic Encode() path
	nodes []NodeInfo,
	httpClient *http.Client,
	nMembers int,
) ([]byte, error) {
	type result struct {
		ps  NodePartialSigFFI
		err error
	}

	n := len(nodes)
	quorum := (2*n)/3 + 1
	resultCh := make(chan result, len(encodedPrimary)*3)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var partial []NodePartialSigFFI
	var reachedQuorum bool

	for sliverIdx, sliverBCS := range encodedPrimary {
		for candidateOff := 0; candidateOff < 3 && candidateOff < n; candidateOff++ {
			nodeIdx := (sliverIdx + candidateOff) % n
			node := nodes[nodeIdx]
			bcs := sliverBCS
			sidx := sliverIdx

			wg.Add(1)
			go func() {
				defer wg.Done()
				mu.Lock()
				if reachedQuorum {
					mu.Unlock()
					return
				}
				mu.Unlock()

				sig, msg, status := tryPutVariants(ctx, httpClient,
					fmt.Sprintf("http://%s/v1/blobs/%s/slivers/%d",
						strings.TrimPrefix(strings.TrimPrefix(node.NetworkAddress, "https://"), "http://"),
						blobIDBase64URL, sidx),
					bcs)
				if status != http.StatusOK {
					resultCh <- result{err: fmt.Errorf("node %d sliver %d: status %d", node.Index, sidx, status)}
					return
				}
				resultCh <- result{ps: NodePartialSigFFI{
					NodeIndex: uint32(node.Index),
					Sig:       sig,
					Msg:       msg,
				}}
			}()
		}
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	seen := make(map[uint32]bool)
	for r := range resultCh {
		if r.err != nil {
			continue
		}
		if seen[r.ps.NodeIndex] {
			continue
		}
		seen[r.ps.NodeIndex] = true
		partial = append(partial, r.ps)
		if len(partial) >= quorum {
			reachedQuorum = true
			break
		}
	}

	if len(partial) < quorum {
		return nil, fmt.Errorf("quorum not reached: %d/%d", len(partial), n)
	}

	return w.AggregateAndBuildCert(partial, nMembers)
}

// ── Minimal bincode helpers ───────────────────────────────────────────────────
// bincode v1 (Rust) wire format for the types we need:
//   Vec<T>      → u64 length prefix (LE) + T elements
//   String      → u64 length prefix (LE) + UTF-8 bytes
//   Vec<u8>     → u64 length prefix (LE) + bytes
//   [u8; N]     → N raw bytes (no prefix)
//   u32/u64     → little-endian

func bincodeSerialize(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case []nodeInfoFFI:
		return bincodeSerializeNodeInfoSlice(val)
	case []NodePartialSigFFI:
		return bincodeSerializePartialSigSlice(val)
	default:
		return nil, fmt.Errorf("unsupported type for bincode serialization: %T", v)
	}
}

func bincodeSerializeNodeInfoSlice(nodes []nodeInfoFFI) ([]byte, error) {
	var buf bytes.Buffer
	// Vec length as u64 LE
	writeU64LE(&buf, uint64(len(nodes)))
	for _, n := range nodes {
		// u32 index
		writeU32LE(&buf, n.Index)
		// String: u64 len + bytes
		writeString(&buf, n.NetworkAddress)
		// Vec<u8>: u64 len + bytes
		writeVecU8(&buf, n.PublicKey)
	}
	return buf.Bytes(), nil
}

func bincodeSerializePartialSigSlice(sigs []NodePartialSigFFI) ([]byte, error) {
	var buf bytes.Buffer
	writeU64LE(&buf, uint64(len(sigs)))
	for _, s := range sigs {
		writeU32LE(&buf, s.NodeIndex)
		writeVecU8(&buf, s.Sig)
		writeVecU8(&buf, s.Msg)
	}
	return buf.Bytes(), nil
}

// bincodeDeserializeCert decodes a bincode ConfirmationCertificate:
//
//	signers: Vec<u8>, serialized_message: Vec<u8>, signature: Vec<u8>
func bincodeDeserializeCert(raw []byte) (*CertificateFFI, error) {
	r := bytes.NewReader(raw)
	signers, err := readVecU8(r)
	if err != nil {
		return nil, fmt.Errorf("read signers: %w", err)
	}
	msg, err := readVecU8(r)
	if err != nil {
		return nil, fmt.Errorf("read message: %w", err)
	}
	sig, err := readVecU8(r)
	if err != nil {
		return nil, fmt.Errorf("read signature: %w", err)
	}
	return &CertificateFFI{Signers: signers, SerializedMessage: msg, Signature: sig}, nil
}

func writeU64LE(w *bytes.Buffer, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	w.Write(b[:])
}
func writeU32LE(w *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	w.Write(b[:])
}
func writeString(w *bytes.Buffer, s string) {
	writeU64LE(w, uint64(len(s)))
	w.WriteString(s)
}
func writeVecU8(w *bytes.Buffer, b []byte) {
	writeU64LE(w, uint64(len(b)))
	w.Write(b)
}
func readVecU8(r *bytes.Reader) ([]byte, error) {
	var lenBuf [8]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint64(lenBuf[:])
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

// error sentinel matching Rust ERROR_HTTP_FAILED = -12
const ERROR_HTTP_FAILED = -12
