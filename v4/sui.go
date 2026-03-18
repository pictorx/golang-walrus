package v4

import (
	"context"
	"fmt"

	pb "golangwalrus/v4/sui_rpc_proto/generated"

	"google.golang.org/grpc"
)

func GetObject(conn *grpc.ClientConn, objectId string, version *uint64, ctx context.Context) (*pb.GetObjectResponse, error) {
	client := pb.NewLedgerServiceClient(conn)
	resp, err := client.GetObject(ctx, &pb.GetObjectRequest{
		ObjectId: &objectId,
		Version:  version,
	})
	if err != nil {
		return nil, err
	}

	return resp, err
}

func ListOwnedObjects(conn *grpc.ClientConn, owner string, pagesize *uint32, pagetoken []byte, ctx context.Context) (*pb.ListOwnedObjectsResponse, error) {
	client := pb.NewStateServiceClient(conn)
	resp, err := client.ListOwnedObjects(ctx, &pb.ListOwnedObjectsRequest{
		Owner:     &owner,
		PageSize:  pagesize,
		PageToken: pagetoken,
	})

	if err != nil {
		return nil, err
	}

	return resp, nil
}

func ListDynamicFields(conn *grpc.ClientConn, objectId string, pagesize *uint32, pagetoken []byte, ctx context.Context) (*pb.ListDynamicFieldsResponse, error) {
	client := pb.NewStateServiceClient(conn)
	resp, err := client.ListDynamicFields(ctx, &pb.ListDynamicFieldsRequest{
		Parent:    &objectId,
		PageSize:  pagesize,
		PageToken: pagetoken,
	})

	if err != nil {
		return nil, err
	}

	return resp, nil
}

func OwnedCoins(listownedobjects *pb.ListOwnedObjectsResponse, cointype, owner string) []*pb.Object {
	list := listownedobjects

	var coins []*pb.Object
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

var schemeMap = map[byte]pb.SignatureScheme{
	0x00: pb.SignatureScheme_ED25519,
	0x01: pb.SignatureScheme_SECP256K1,
	0x02: pb.SignatureScheme_SECP256R1,
}

func SignExecuteTransaction(conn *grpc.ClientConn, txBytes, signature []byte, ctx context.Context) (*pb.ExecuteTransactionResponse, error) {
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

	client := pb.NewTransactionExecutionServiceClient(conn)
	resp, err := client.ExecuteTransaction(ctx, &pb.ExecuteTransactionRequest{
		Transaction: &pb.Transaction{
			Bcs: &pb.Bcs{Value: txBytes},
		},
		Signatures: []*pb.UserSignature{
			{
				Scheme: scheme.Enum(),
				Signature: &pb.UserSignature_Simple{
					Simple: &pb.SimpleSignature{
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

func GetGas(conn *grpc.ClientConn, ctx context.Context) (*pb.GetEpochResponse, error) {
	client := pb.NewLedgerServiceClient(conn)
	resp, err := client.GetEpoch(ctx, &pb.GetEpochRequest{})

	if err != nil {
		return nil, err
	}

	return resp, nil
}

func SimulateTransaction(conn *grpc.ClientConn, txBytes []byte, ctx context.Context) (*pb.SimulateTransactionResponse, error) {
	client := pb.NewTransactionExecutionServiceClient(conn)
	resp, err := client.SimulateTransaction(ctx, &pb.SimulateTransactionRequest{
		Transaction: &pb.Transaction{
			Bcs: &pb.Bcs{Value: txBytes},
		},
	})
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Helper function to extract estimated budget from simulation response
func EstimateGasBudget(resp *pb.SimulateTransactionResponse) (uint64, error) {
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
