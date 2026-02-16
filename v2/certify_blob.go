package v2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/block-vision/sui-go-sdk/signer"
	gosuisdk "github.com/pictorx/go-sui-sdk"
	pb "github.com/pictorx/go-sui-sdk/sui_rpc_proto/generated"
	"github.com/tetratelabs/wazero/api"
	"google.golang.org/grpc"
)

// ConfirmationCertificate represents the certificate returned from storage nodes
type ConfirmationCertificate struct {
	Signers           []byte `json:"signers"`
	SerializedMessage []byte `json:"serialized_message"`
	Signature         string `json:"signature"` // Base64 encoded
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
}

func (op *WalrusCertifyBlob) CertifyBlob(
	conn *grpc.ClientConn,
	mod api.Module,
	acc *signer.Signer,
	ctx context.Context,
) (*pb.ExecuteTransactionResponse, error) {
	b := gosuisdk.NewBuilder(ctx, mod)

	// 1. Configure
	if err := b.SetConfig(acc.Address, op.Gasbudget, op.Gasprice); err != nil {
		return nil, err
	}
	if err := b.AddGasObject(*op.GasCoin.ObjectId, uint64(*op.GasCoin.Version), *op.GasCoin.Digest); err != nil {
		return nil, fmt.Errorf("add gas object: %w", err)
	}

	// 2. System object (shared, immutable for certify_blob)
	sysArg, err := b.InputObject(WAL_SYSTEM_OBJ_ID, WAL_SYSTEM_VERSION, "", gosuisdk.ObjectKindShared, true)
	if err != nil {
		return nil, fmt.Errorf("input system: %w", err)
	}

	// 3. Blob object (owned, mutable)
	blobArg, err := b.InputObject(op.BlobObjectId, op.BlobVersion, op.BlobDigest, gosuisdk.ObjectKindOwned, true)
	if err != nil {
		return nil, fmt.Errorf("input blob object: %w", err)
	}

	// 4. Decode and prepare certificate arguments
	// The signature is base64 encoded
	signatureBytes, err := base64.StdEncoding.DecodeString(op.Certificate.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	// Create pure arguments for the certificate
	// According to Walrus contract, certify_blob expects:
	// - system: &System
	// - blob: &mut Blob
	// - signature: vector<u8> (BLS aggregate signature)
	// - signers: vector<u8> (bitmap of signers) - already a bitmap!
	// - message: vector<u8> (serialized message)

	// BCS encode the signature as vector<u8>
	sigArg := b.PureRawBCS(append([]byte{byte(len(signatureBytes))}, signatureBytes...))

	// BCS encode the signers bitmap as vector<u8> (it's already a bitmap from the relay)
	signersArg := b.PureRawBCS(append([]byte{byte(len(op.Certificate.Signers))}, op.Certificate.Signers...))

	// BCS encode the serialized message as vector<u8>
	messageArg := b.PureRawBCS(append([]byte{byte(len(op.Certificate.SerializedMessage))}, op.Certificate.SerializedMessage...))

	// 5. Call certify_blob
	_, err = b.MoveCall(
		WAL_PKG_ID,
		"system",
		"certify_blob",
		[]string{},
		[]gosuisdk.MoveCallArg{
			gosuisdk.ArgID(sysArg),     // &System (immutable)
			gosuisdk.ArgID(blobArg),    // &mut Blob
			gosuisdk.ArgID(sigArg),     // vector<u8> signature
			gosuisdk.ArgID(signersArg), // vector<u8> signers bitmap
			gosuisdk.ArgID(messageArg), // vector<u8> serialized message
		},
	)
	if err != nil {
		return nil, fmt.Errorf("certify_blob move call failed: %w", err)
	}

	// 6. Build, sign, and execute
	txBytes, err := b.Build()
	if err != nil {
		return nil, fmt.Errorf("build transaction: %w", err)
	}

	signed, err := gosuisdk.SignTransaction(txBytes, acc)
	if err != nil {
		return nil, fmt.Errorf("sign transaction: %w", err)
	}

	sigRaw, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	return gosuisdk.SignExecuteTransaction(conn, txBytes, sigRaw, ctx)
}

// Helper function to parse the certificate from upload response
func ParseCertificate(certBytes []byte) (*ConfirmationCertificate, error) {
	var cert ConfirmationCertificate
	if err := json.Unmarshal(certBytes, &cert); err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return &cert, nil
}

// CompleteWalrusFlow performs register -> upload -> certify in one rapid sequence
func CompleteWalrusFlow(
	ctx context.Context,
	conn *grpc.ClientConn,
	mod api.Module,
	acc *signer.Signer,
	client *UploadRelayClient,
	blobData []byte,
	nShards int,
	wasm *WalrusWASM,
) error {
	startTime := time.Now()

	// Get initial epoch
	gas0, err := gosuisdk.GetGas(conn, ctx)
	if err != nil {
		return fmt.Errorf("get gas: %w", err)
	}
	startEpoch := *gas0.Epoch.Epoch
	gasPrice := gas0.Epoch.ReferenceGasPrice

	fmt.Printf("\n🚀 Starting Walrus flow in epoch %d\n", startEpoch)
	fmt.Printf("   Timestamp: %s\n\n", startTime.Format(time.RFC3339))

	// ===================================================================
	// STEP 1: ENCODE BLOB
	// ===================================================================
	fmt.Println("📝 Step 1: Encoding blob...")
	encoderHandle, err := wasm.CreateEncoder(uint16(nShards))
	if err != nil {
		return fmt.Errorf("create encoder: %w", err)
	}
	defer wasm.DestroyEncoder(encoderHandle)

	result, err := wasm.Encode(encoderHandle, blobData, nShards)
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

	// ===================================================================
	// STEP 5: UPLOAD TO STORAGE NODES
	// ===================================================================
	/*var size uint32 = 0
	commitee, err := gosuisdk.ListDynamicFields(
		conn,
		WAL_SYSTEM_OBJ_ID,
		&size,
		nil,
		ctx,
	)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	field := commitee.DynamicFields[0].FieldId
	comObj := pb.NewLedgerServiceClient(conn)
	fieldObj, err := comObj.GetObject(ctx, &pb.GetObjectRequest{
		ObjectId: field,
		Version:  nil,
		ReadMask: &fieldmaskpb.FieldMask{
			Paths: []string{
				"contents",
			},
		},
	})
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	fmt.Println(fieldObj.Object.Contents.String())*/

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

	uploadResp, err := client.UploadBlob(ctx, blobData, opts)
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

	// Final epoch check
	gas4, _ := gosuisdk.GetGas(conn, ctx)
	finalEpoch := *gas4.Epoch.Epoch

	elapsed := time.Since(startTime)
	fmt.Printf("🎉 COMPLETE!\n")
	fmt.Printf("   Total time: %v\n", elapsed)
	fmt.Printf("   Start epoch: %d\n", startEpoch)
	fmt.Printf("   End epoch: %d\n", finalEpoch)
	if finalEpoch == startEpoch {
		fmt.Printf("   ✅ Completed in same epoch!\n")
	} else {
		fmt.Printf("   ⚠️  Epoch changed during flow (but still succeeded)\n")
	}

	return nil
}
