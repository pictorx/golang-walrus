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

	gosuisdk "github.com/pictorx/go-sui-sdk"
)

func main() {
	account, err := signer.NewSignerWithSecretKey("example_priv_key")
	if err != nil {
		panic(err)
	}
	//exampleReserveSpace(account)
	example(account)

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

func example(acc *signer.Signer) {
	ctx := context.Background()
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
		1000,
		wasm,
	)
	if err != nil {
		panic(err)
	}
}

/*
func fullExample(acc *signer.Signer) {
	ctx := context.Background()
	wasm, err := v2.NewWalrusWASM(ctx, "../target/wasm32-wasip1/release/walrus_wasm_wazero.wasm")
	if err != nil {
		panic(err)
	}
	defer wasm.Close()
	// Using the Testnet relay address provided in the docs
	client := v2.NewClient("https://upload-relay.testnet.walrus.space")
	client.HTTPClient.Timeout = 10 * time.Minute

	nShards := 1000
	encoderHandle, err := wasm.CreateEncoder(uint16(nShards))
	if err != nil {
		panic(err)
	}
	defer wasm.DestroyEncoder(encoderHandle)

	blobData := []byte("Hello, Walrus This is a test of the encoding systems 25")
	fmt.Println("blob data: ", string(blobData))

	result, err := wasm.Encode(encoderHandle, blobData, nShards)
	if err != nil {
		panic(fmt.Errorf("Encoding error: %v", err))
	}

	var encodedLen uint64 = 0

	// Sum BCS-encoded primary shards
	for _, shard := range result.PrimaryShards {
		encodedLen += uint64(len(shard))
	}

	// Sum BCS-encoded secondary shards
	for _, shard := range result.SecondaryShards {
		encodedLen += uint64(len(shard))
	}


	blobId, rootHash, unencodedLen, encodingType, err := v2.ExtractBlobInfo(result.Metadata)
	if err != nil {
		fmt.Printf("❌ QuickExtract failed: %v\n", err)
	}

	//register
	conn, err := grpc.Dial(v2.RPC_ENDPOINT, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")))
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	// 2. Setup WASM Runtime (Load your builder.wasm file)
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
	regCoin := gosuisdk.Coin{
		Type: v2.WALRUS_TESTNET_COIN,
	}

	ownedObjs, err := gosuisdk.ListOwnedObjects(conn, acc.Address, nil, nil, ctx)
	if err != nil {
		panic(err)
	}
	Coins := gosuisdk.OwnedCoins(ownedObjs, regCoin.String(), acc.Address)
	if len(Coins) == 0 {
		log.Fatal("no coins found for sender")
	}
	walRegister, err := gosuisdk.GetObject(conn, *Coins[0].ObjectId, Coins[0].Version, ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println("register wal: ", *walRegister.Object.ObjectId)
	gasPrice := gas.Epoch.ReferenceGasPrice
	register := v2.WalrusRegisterBlob{
		Gasbudget: 100_000_000,
		Gasprice:  *gasPrice,
		Amount:    100_000_000,
		Epochs:    5,
		GasCoin:   gasCoin,
		WalCoin:   walCoin,
		//RegisterWalCoin: walRegister.Object,

		BlobId:          [32]byte(blobId),
		RootHash:        [32]byte(rootHash),
		UnencodedLength: uint64(unencodedLen),
		EncodingType:    uint8(encodingType),
		Deletable:       true,
	}

	resp_reg, err := register.ReserveAndRegisterBlob(conn, mod, acc, ctx)

	if err != nil {
		panic(err)
	}
	success := true
	if *resp_reg.Transaction.Effects.Status.Success != success {
		panic(resp_reg.Transaction.Effects.Status.Error.String())
	}

	// pay tip
	var payTip *pb.ExecuteTransactionResponse
	var nonceStr string

	fmt.Println("Checking tip configuration...")
	config, err := client.GetTipConfig(ctx)
	if err != nil {
		panic(err)
	}

	if config.SendTip != nil {
		fmt.Printf("Relay requires payment to: %s\n", config.SendTip.Address)
		if config.SendTip.Kind.Const != nil {
			fmt.Printf("Cost: %d MIST (Constant)\n", *config.SendTip.Kind.Const)
		}

		// ── Fetch gas coin from chain ─────────────────────────────────────────
		ownedObjs, err := gosuisdk.ListOwnedObjects(conn, acc.Address, nil, nil, ctx)
		if err != nil {
			panic(err)
		}
		suiCoins := gosuisdk.OwnedCoins(ownedObjs, gosuisdk.SuiCoin.String(), acc.Address)
		if len(suiCoins) == 0 {
			log.Fatal("no SUI coins found for sender")
		}
		suiGasCoin, err := gosuisdk.GetObject(conn, *suiCoins[0].ObjectId, suiCoins[0].Version, ctx)
		if err != nil {
			panic(err)
		}

		// This handles Nonce generation AND the special transaction structure
		payTip, nonceStr, err = v2.PayRelayTip(
			ctx, conn, mod, acc,
			blobData,                   // Raw data needed for digest
			*config.SendTip.Kind.Const, // Tip Amount
			config.SendTip.Address,     // Relay Address
			suiGasCoin.Object,          // Gas Object
			*gasPrice,
			100_000_000, // Budget for tip tx
		)
		if err != nil {
			panic(fmt.Errorf("failed to pay tip: %v", err))
		}

		if *payTip.Transaction.Effects.Status.Success != success {
			panic(resp_reg.Transaction.Effects.Status.Error.String())
		}
	}
	// 2. Upload a Blob (Mock Data)
	// NOTE: In a real app, you must first register this blob on-chain to get the BlobID
	// and perform the tip transaction to get TxID and Nonce.
	fmt.Println("base64 blob id: ", base64.RawURLEncoding.EncodeToString(blobId))
	opts := v2.UploadOptions{
		BlobID: base64.RawURLEncoding.EncodeToString(blobId), // Example from docs
	}
	// Add this debug code to your fullExample function right after PayRelayTip:

	if payTip != nil {
		fmt.Println("\n=== TIP TRANSACTION DEBUG ===")
		fmt.Printf("Transaction Digest: %s\n", *payTip.Transaction.Effects.TransactionDigest)
		fmt.Printf("Transaction Status: Success=%v\n", *payTip.Transaction.Effects.Status.Success)

		// Verify the nonce
		fmt.Printf("\nNonce (base64 URL no padding): %s\n", nonceStr)
		fmt.Printf("Nonce length: %d chars\n", len(nonceStr))

		// Decode and verify
		nonceDecoded, err := base64.RawURLEncoding.DecodeString(nonceStr)
		if err != nil {
			fmt.Printf("ERROR decoding nonce: %v\n", err)
		} else {
			fmt.Printf("Nonce decoded: %d bytes\n", len(nonceDecoded))
			fmt.Printf("Nonce hex: %x\n", nonceDecoded)

			// Verify the hash in the transaction
			nonceHash := sha256.Sum256(nonceDecoded)
			fmt.Printf("Nonce hash (SHA256): %x\n", nonceHash)
		}

		// Verify the blob digest
		blobHash := sha256.Sum256(blobData)
		fmt.Printf("\nBlob digest (SHA256): %x\n", blobHash)
		fmt.Printf("Blob size: %d bytes\n", len(blobData))

		fmt.Println("=== END DEBUG ===")

	}
	blobIdBase64 := base64.RawURLEncoding.EncodeToString(blobId)

	// Also verify the blob_id used in register_blob
	fmt.Printf("\nBlobId in register struct: %x\n", register.BlobId)
	fmt.Printf("BlobId from encoding:      %x\n", blobId)
	fmt.Printf("Match: %v\n", bytes.Equal(register.BlobId[:], blobId))

	fmt.Println("=== END DEBUG ===")
	if opts.BlobID != blobIdBase64 {
		panic("BLOB ID MISMATCH!")
	}
	if payTip != nil {
		opts.TxID = *payTip.Transaction.Effects.TransactionDigest
		opts.Nonce = nonceStr
	}
	var blobObj *pb.ChangedObject
	for i, v := range resp_reg.Transaction.Effects.ChangedObjects {
		if *v.IdOperation.Enum() == pb.ChangedObject_CREATED {
			blobObj = resp_reg.Transaction.Effects.ChangedObjects[i]
		}
	}
	if blobObj == nil {
		panic("no blob obj")
	}

	if register.Deletable == true {
		opts.DeletableBlobObject = *blobObj.ObjectId
	}

	// Then before calling UploadBlob, add:
	fmt.Println("\n=== UPLOAD REQUEST DEBUG ===")
	fmt.Printf("BlobID: %s\n", opts.BlobID)
	fmt.Printf("TxID: %s\n", opts.TxID)
	fmt.Printf("Nonce: %s\n", opts.Nonce)
	if opts.DeletableBlobObject != "" {
		fmt.Printf("DeletableBlobObject: %s\n", opts.DeletableBlobObject)
	}

	fmt.Println("\nUploading blob...")
	// This will fail with a 400/500 if the blobID isn't actually registered on-chain first
	resp, err := client.UploadBlob(ctx, blobData, opts)
	if err != nil {
		fmt.Printf("Upload request error (expected if blob not registered): %v\n", err)
		return
	}

	fmt.Printf("Success! Blob ID: %s\n", resp.BlobID)
	fmt.Printf("Certificate received: %s\n", string(resp.ConfirmationCertificate))

	// ── Fetch gas coin from chain ─────────────────────────────────────────
	ownedObjs2, err := gosuisdk.ListOwnedObjects(conn, acc.Address, nil, nil, ctx)
	if err != nil {
		panic(err)
	}
	suiCoins := gosuisdk.OwnedCoins(ownedObjs2, gosuisdk.SuiCoin.String(), acc.Address)
	if len(suiCoins) == 0 {
		log.Fatal("no SUI coins found for sender")
	}
	suiGasCoin, err := gosuisdk.GetObject(conn, *suiCoins[0].ObjectId, suiCoins[0].Version, ctx)
	if err != nil {
		panic(err)
	}

	blob_obj, err := gosuisdk.GetObject(conn, *blobObj.ObjectId, blobObj.OutputVersion, ctx)
	if err != nil {
		panic(err)
	}
	cert, err := v2.ParseCertificate(resp.ConfirmationCertificate)
	if err != nil {
		panic(fmt.Errorf("parse certificate: %v", err))
	}

	// Add this right before calling CertifyBlob:

	fmt.Println("\n=== CERTIFICATE DEBUG ===")
	fmt.Printf("Certificate Signature (base64): %s\n", cert.Signature)

	// Decode and check signature
	signatureBytes, err := base64.StdEncoding.DecodeString(cert.Signature)
	if err != nil {
		fmt.Printf("ERROR decoding signature: %v\n", err)
	} else {
		fmt.Printf("Signature bytes: %d bytes\n", len(signatureBytes))
		fmt.Printf("Signature (hex): %x\n", signatureBytes[:min(32, len(signatureBytes))])
	}

	fmt.Printf("\nSigners bitmap: %d bytes\n", len(cert.Signers))
	fmt.Printf("Signers (hex): %x\n", cert.Signers)
	fmt.Printf("Signers (decimal): %v\n", cert.Signers)

	fmt.Printf("\nSerialized message: %d bytes\n", len(cert.SerializedMessage))
	fmt.Printf("Message (hex): %x\n", cert.SerializedMessage)

	// Parse the message to understand its structure
	if len(cert.SerializedMessage) > 0 {
		fmt.Printf("\nMessage breakdown:\n")
		fmt.Printf("  Byte 0 (version?): %d\n", cert.SerializedMessage[0])
		if len(cert.SerializedMessage) > 1 {
			fmt.Printf("  Byte 1: %d\n", cert.SerializedMessage[1])
		}
		if len(cert.SerializedMessage) >= 36 {
			// Might be: version + flags + blob_id (32 bytes)
			fmt.Printf("  Possible blob_id: %x\n", cert.SerializedMessage[4:36])
		}
	}

	fmt.Println("=== END CERTIFICATE DEBUG ===")

	certTx := v2.WalrusCertifyBlob{
		Gasbudget:    100_000_000,
		Gasprice:     *gasPrice,
		BlobObjectId: *blob_obj.Object.ObjectId,
		BlobVersion:  *blob_obj.Object.Version,
		BlobDigest:   *blob_obj.Object.Digest,
		Certificate:  cert,
		GasCoin:      suiGasCoin.Object,
	}
	certifyResp, err := certTx.CertifyBlob(conn, mod, acc, ctx)
	if err != nil {
		panic(fmt.Errorf("certify blob: %v", err))
	}

	if !*certifyResp.Transaction.Effects.Status.Success {
		panic(certifyResp.Transaction.Effects.Status.Error.String())
	}
	fmt.Println("✅ Blob certified successfully!")
	fmt.Printf("   Transaction: %s\n", *certifyResp.Transaction.Effects.TransactionDigest)
}
*/
