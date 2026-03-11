package v2

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/block-vision/sui-go-sdk/signer"
	gosuisdk "github.com/pictorx/go-sui-sdk"
	pb "github.com/pictorx/go-sui-sdk/sui_rpc_proto/generated"
	"github.com/tetratelabs/wazero/api"
	"google.golang.org/grpc"
)

// CompleteWalrusFlow performs register -> upload -> certify in one rapid sequence
func CompleteWalrusFlow(
	ctx context.Context,
	conn *grpc.ClientConn,
	mod api.Module,
	acc *signer.Signer,
	client *UploadRelayClient,
	blobData []byte,
	filename string,
	cfg *CommitteeConfig,
	wasm *WalrusWASM,
) error {
	startTime := time.Now()

	// Get initial epoch
	gas0, err := gosuisdk.GetGas(conn, ctx)
	if err != nil {
		return fmt.Errorf("get gas: %w", err)
	}
	gasPrice := gas0.Epoch.ReferenceGasPrice

	fmt.Printf("   Timestamp: %s\n\n", startTime.Format(time.RFC3339))

	// ===================================================================
	// STEP 1: ENCODE BLOB
	// ===================================================================
	fmt.Println("📝 Step 1: Encoding blob...")
	encoderHandle, err := wasm.CreateEncoder(uint16(cfg.NShards))
	if err != nil {
		return fmt.Errorf("create encoder: %w", err)
	}
	defer wasm.DestroyEncoder(encoderHandle)

	result, err := wasm.Encode(encoderHandle, blobData, cfg.NShards)
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	blobId, rootHash, unencodedLen, encodingType, err := ExtractBlobInfo(result.Metadata)
	if err != nil {
		return fmt.Errorf("extract blob info: %w", err)
	}

	fmt.Printf("   ✓ Blob ID: %s\n", base64.RawURLEncoding.EncodeToString(blobId))
	fmt.Printf("   ✓ Encoded: %d bytes\n\n", unencodedLen)

	// ===================================================================
	// STEP 2: FIND COINS
	// ===================================================================
	fmt.Println("🔍 Step 2: Finding coins...")
	gasCoin, walCoin, err := FindCoins(ctx, conn, acc.Address)
	if err != nil {
		return fmt.Errorf("find coins: %w", err)
	}
	fmt.Printf("   ✓ Gas Coin: %s\n", *gasCoin.ObjectId)
	fmt.Printf("   ✓ WAL Coin: %s\n\n", *walCoin.ObjectId)

	// ===================================================================
	// STEP 3: REGISTER BLOB
	// ===================================================================
	fmt.Println("📋 Step 3: Registering blob on-chain...")
	register := WalrusRegisterBlob{
		Gasbudget:       100_000_000,
		Gasprice:        *gasPrice,
		Amount:          100_000_000,
		Epochs:          5,
		GasCoin:         gasCoin,
		WalCoin:         walCoin,
		BlobId:          [32]byte(blobId),
		RootHash:        [32]byte(rootHash),
		UnencodedLength: uint64(unencodedLen),
		EncodingType:    uint8(encodingType),
		Deletable:       true,
		Metadata: map[string]string{
			"file_name": filename,
		},
	}

	regResp, err := register.ReserveAndRegisterBlob(conn, mod, acc, ctx)
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}

	if !*regResp.Transaction.Effects.Status.Success {
		return fmt.Errorf("register failed: %s", regResp.Transaction.Effects.Status.Error.String())
	}

	// Find the created blob object
	var blobObj *pb.ChangedObject
	for _, obj := range regResp.Transaction.Effects.ChangedObjects {
		if *obj.IdOperation.Enum() == pb.ChangedObject_CREATED {
			blobObj = obj
			break
		}
	}
	if blobObj == nil {
		return fmt.Errorf("no blob object created")
	}

	fmt.Printf("   ✓ Blob Object: %s\n", *blobObj.ObjectId)
	fmt.Printf("   ✓ TX: %s\n\n", *regResp.Transaction.Effects.TransactionDigest)

	// ===================================================================
	// STEP 4: PAY TIP (if required)
	// ===================================================================
	fmt.Println("💰 Step 4: Checking tip configuration...")
	config, err := client.GetTipConfig(ctx)
	if err != nil {
		return fmt.Errorf("get tip config: %w", err)
	}

	var tipResp *pb.ExecuteTransactionResponse
	var nonceStr string

	if config.SendTip != nil {
		fmt.Printf("   💸 Relay requires tip: %d MIST\n", *config.SendTip.Kind.Const)

		// Get fresh gas coin
		ownedObjs, err := gosuisdk.ListOwnedObjects(conn, acc.Address, nil, nil, ctx)
		if err != nil {
			return fmt.Errorf("list objects: %w", err)
		}
		suiCoins := gosuisdk.OwnedCoins(ownedObjs, gosuisdk.SuiCoin.String(), acc.Address)
		if len(suiCoins) == 0 {
			return fmt.Errorf("no SUI coins found")
		}
		tipGasCoin, err := gosuisdk.GetObject(conn, *suiCoins[0].ObjectId, suiCoins[0].Version, ctx)
		if err != nil {
			return fmt.Errorf("get tip gas coin: %w", err)
		}

		tipResp, nonceStr, err = PayRelayTip(
			ctx, conn, mod, acc,
			blobData,
			*config.SendTip.Kind.Const,
			config.SendTip.Address,
			tipGasCoin.Object,
			*gasPrice,
			100_000_000,
		)
		if err != nil {
			return fmt.Errorf("pay tip: %w", err)
		}

		if !*tipResp.Transaction.Effects.Status.Success {
			return fmt.Errorf("tip payment failed: %s", tipResp.Transaction.Effects.Status.Error.String())
		}

		fmt.Printf("   ✓ Tip TX: %s\n\n", *tipResp.Transaction.Effects.TransactionDigest)
	} else {
		fmt.Println("   ✓ No tip required")
	}

	fmt.Println("☁️  Step 5: Uploading to storage nodes...")

	opts := UploadOptions{
		BlobID: base64.RawURLEncoding.EncodeToString(blobId),
	}
	if tipResp != nil {
		opts.TxID = *tipResp.Transaction.Effects.TransactionDigest
		opts.Nonce = nonceStr
	}
	if register.Deletable {
		opts.DeletableBlobObject = *blobObj.ObjectId
	}

	// In CompleteWalrusFlow — give upload 5 minutes to succeed, retry freely within that
	uploadCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	uploadResp, err := client.UploadBlobWithRetry(uploadCtx, blobData, opts, 20) // 0 = unlimited
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}

	cert, err := ParseCertificate(uploadResp.ConfirmationCertificate)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	fmt.Printf("   ✓ Certificate received\n")
	fmt.Printf("   ✓ Signature: %d bytes\n", len(cert.Signature))
	fmt.Printf("   ✓ Signers: %d bytes\n\n", len(cert.Signers))

	// ===================================================================
	// STEP 6: CERTIFY BLOB ON-CHAIN (IMMEDIATELY!)
	// ===================================================================
	fmt.Println("✍️  Step 6: Certifying blob on-chain...")

	// Get LATEST blob object state
	latestBlobObj, err := gosuisdk.GetObject(conn, *blobObj.ObjectId, blobObj.OutputVersion, ctx)
	if err != nil {
		return fmt.Errorf("get blob object: %w", err)
	}

	// Get fresh gas coin for certification
	ownedObjs2, err := gosuisdk.ListOwnedObjects(conn, acc.Address, nil, nil, ctx)
	if err != nil {
		return fmt.Errorf("list objects: %w", err)
	}
	certSuiCoins := gosuisdk.OwnedCoins(ownedObjs2, gosuisdk.SuiCoin.String(), acc.Address)
	if len(certSuiCoins) == 0 {
		return fmt.Errorf("no SUI coins found for certification")
	}
	certGasCoin, err := gosuisdk.GetObject(conn, *certSuiCoins[0].ObjectId, certSuiCoins[0].Version, ctx)
	if err != nil {
		return fmt.Errorf("get cert gas coin: %w", err)
	}

	//wasm.VerifyAggregateBLS12381()
	certTx := WalrusCertifyBlob{
		Gasbudget:    100_000_000,
		Gasprice:     *gasPrice,
		BlobObjectId: *latestBlobObj.Object.ObjectId,
		BlobVersion:  *latestBlobObj.Object.Version,
		BlobDigest:   *latestBlobObj.Object.Digest,
		Certificate:  cert,
		GasCoin:      certGasCoin.Object,
		Config:       cfg,
	}

	certifyResp, err := certTx.CertifyBlob(conn, mod, acc, ctx)
	if err != nil {
		return fmt.Errorf("certify: %w", err)
	}

	if !*certifyResp.Transaction.Effects.Status.Success {
		return fmt.Errorf("certification failed: %s", certifyResp.Transaction.Effects.Status.Error.String())
	}

	fmt.Printf("   ✅ CERTIFIED!\n")
	fmt.Printf("   TX: %s\n\n", *certifyResp.Transaction.Effects.TransactionDigest)

	elapsed := time.Since(startTime)
	fmt.Printf("🎉 COMPLETE!\n")
	fmt.Printf("   Total time: %v\n", elapsed)

	return nil
}
