package main

import (
	"context"
	"encoding/hex"
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

	gosuisdk "github.com/pictorx/go-sui-sdk"
)

func main() {
	ctx := context.Background()

	// Create WASM instance
	wasm, err := v2.NewWalrusWASM(ctx, "./target/wasm32-wasip1/release/walrus_wasm_wazero.wasm")
	if err != nil {
		panic(err)
	}
	defer wasm.Close()

	// ... inside main ...

	// 1. Create Encoder (e.g., 10 shards)
	// Note: Rust code uses RS2, so nShards usually implies specific breakdown (e.g., 2n)
	nShards := 1000
	encoderHandle, err := wasm.CreateEncoder(uint16(nShards))
	if err != nil {
		panic(err)
	}
	defer wasm.DestroyEncoder(encoderHandle)

	data := []byte("Hello, Walrus! This is a test of the encoding system.")

	result, err := wasm.Encode(encoderHandle, data, nShards)
	if err != nil {
		panic(fmt.Errorf("Encoding error: %v", err))
	}

	blobId, rootHash, unencodedLen, encodingType, err := v2.ExtractBlobInfo(result.Metadata)
	if err != nil {
		fmt.Printf("❌ QuickExtract failed: %v\n", err)
	} else {
		fmt.Printf("✅ Success!\n")
		fmt.Printf("BlobId:          %s\n", hex.EncodeToString(blobId))
		fmt.Printf("RootHash:        %s\n", hex.EncodeToString(rootHash))
		fmt.Printf("Original Size:   %d bytes\n", unencodedLen)
		fmt.Printf("Encoding Type:   %d bytes\n", encodingType)

	}

	account, err := signer.NewSignerWithSecretKey("example_priv_key")
	if err != nil {
		panic(err)
	}
	exampleReserveSpace(account)

}

func exampleReserveSpace(acc *signer.Signer) {
	// 1. Setup Context & Connection
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := grpc.Dial(v2.RPC_ENDPOINT, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")))
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	// 2. Setup WASM Runtime (Load your builder.wasm file)
	wasmBytes, err := os.ReadFile("./go-sui-sdk/transaction/target/wasm32-wasip1/release/transaction_builder.wasm")
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

	// 3. Setup Signer
	senderAddr := acc.Address
	fmt.Printf("Sender: %s\n", senderAddr)

	// 4. Find Required Coins (Gas & Payment)
	fmt.Println("🔍 Finding coins...")
	gasCoin, walCoin, err := v2.FindCoins(ctx, conn, senderAddr)
	if err != nil {
		log.Fatalf("Coin discovery failed: %v", err)
	}
	fmt.Printf("   Gas Coin: %s (Ver: %d)\n", *gasCoin.ObjectId, *gasCoin.Version)
	fmt.Printf("   WAL Coin: %s (Ver: %d)\n", *walCoin.ObjectId, *walCoin.Version)

	gas, err := gosuisdk.GetGas(conn, ctx)
	if err != nil {
		panic(err)
	}
	gasPrice := gas.Epoch.ReferenceGasPrice

	reserve := v2.WalrusReserveSpace{
		Gasbudget: 100_000_000,
		Gasprice:  *gasPrice,
		Amount:    1,
		Epoch:     1,
		GasCoin:   gasCoin,
		WalCoin:   walCoin,
	}

	resp, err := reserve.ReserveSpace(conn, mod, acc, ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println(resp)
}
