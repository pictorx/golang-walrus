package main

import (
	"context"
	"crypto/rand"
	"fmt"
	v4 "golangwalrus/v4"
	"log"
	"os"

	"github.com/block-vision/sui-go-sdk/signer"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	account, err := signer.NewSignerWithSecretKey("example")
	if err != nil {
		panic(err)
	}
	ctx := context.Background()

	conn, err := grpc.Dial(v4.RPC_ENDPOINT, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")))
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	// InitExtendedCommitteeConfig reuses the existing conn — no second
	// connection is opened. Also populates the base committeeConfig so
	// CompleteWalrusFlow2 continues to work unchanged if called elsewhere.
	if err := v4.InitExtendedCommitteeConfig(ctx, conn); err != nil {
		log.Fatalf("Failed to init committee config: %v", err)
	}

	example(account, conn, ctx)
}

func example(acc *signer.Signer, conn *grpc.ClientConn, ctx context.Context) {
	cfg := v4.GetCommitteeConfig()

	wasm, err := v4.NewWalrusWASMWithHTTP(ctx, "../target/wasm32-wasip1/release/walrus_wasm_wazero.wasm", nil)
	if err != nil {
		panic(err)
	}
	defer wasm.Close()

	// ── WASM runtime ─────────────────────────────────────────────────────
	rt := wazero.NewRuntime(ctx)
	defer rt.Close(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, rt)

	wasmBytes, err := os.ReadFile("../transaction/target/wasm32-wasip1/release/transaction_builder.wasm")
	if err != nil {
		panic(err)
	}
	mod, err := rt.Instantiate(ctx, wasmBytes)
	if err != nil {
		panic(err)
	}

	randomSuffix := make([]byte, 8)
	rand.Read(randomSuffix)
	blobData := []byte(fmt.Sprintf("Hello, Walrus! Test at %x", randomSuffix))
	fmt.Println("blob data:", string(blobData))
	relayClient := v4.NewUploadRelayClient("https://upload-relay.testnet.walrus.space")
	results, err := v4.CompleteWalrusFlowRelay(ctx, conn, acc, mod, blobData, "file.bin", cfg, wasm, relayClient)
	if err != nil {
		panic(err)
	}
	fmt.Println(results)

}
