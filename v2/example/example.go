package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/block-vision/sui-go-sdk/signer"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	v2 "golangwalrus/v2"
)

func main() {
	account, err := signer.NewSignerWithSecretKey("example_priv_key")
	if err != nil {
		panic(err)
	}
	ctx := context.Background()

	if err := v2.InitCommitteeConfig(ctx); err != nil {
		log.Fatalf("Failed to init committee config: %v", err)
	}

	example(account, ctx)

}

func example(acc *signer.Signer, ctx context.Context) {
	cfg := v2.GetCommitteeConfig()

	wasm, err := v2.NewWalrusWASM(ctx, "../target/wasm32-wasip1/release/walrus_wasm_wazero.wasm")
	if err != nil {
		panic(err)
	}
	defer wasm.Close()

	randomSuffix := make([]byte, 8)
	rand.Read(randomSuffix)
	blobData := []byte(fmt.Sprintf("Hello, Walrus! Test at %x",
		randomSuffix))

	fmt.Println("blob data: ", string(blobData))

	conn, err := grpc.Dial(v2.RPC_ENDPOINT, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")))
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	wasmBytes, err := os.ReadFile("../go-sui-sdk/transaction/target/wasm32-wasip1/release/transaction_builder.wasm")
	if err != nil {
		log.Fatalf("Failed to read wasm file: %v", err)
	}
	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, r)
	mod, err := r.Instantiate(ctx, wasmBytes)
	if err != nil {
		log.Fatalf("Failed to instantiate WASM: %v", err)
	}

	client := v2.NewClient("https://upload-relay.testnet.walrus.space")
	client.HTTPClient.Timeout = 10 * time.Minute

	err = v2.CompleteWalrusFlow(
		ctx,
		conn,
		mod,
		acc,
		client,
		blobData,
		cfg,
		wasm,
	)
	if err != nil {
		panic(err)
	}
}
