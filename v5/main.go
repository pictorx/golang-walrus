package main

import (
	// "context"

	"context"
	"fmt"
	"github.com/block-vision/sui-go-sdk/signer"
	"log"
	// "google.golang.org/grpc"
	// "google.golang.org/grpc/credentials"
)

const (
	RPC_ENDPOINT = "fullnode.testnet.sui.io:443"
)

func main() {
	acc, err := signer.NewSignerWithSecretKey("")
	if err != nil {
		log.Fatal(err)
	}

	/*storage_pool_objectID, err := CreateStoragePool(100, 5, acc)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(storage_pool_objectID)*/

	ctx := context.Background()

	/*conn, err := grpc.Dial(TestnetConfig.GRPCEndpoint, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")))
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()*/

	/* randomSuffix := make([]byte, 8)
	rand.Read(randomSuffix)
	blobData := []byte(fmt.Sprintf("Hello, Walrus! Test at %x", randomSuffix))

	blob, err := StoreBlobInPool(5, true, "0x15270e9746c8c4085d6b5d3915f5d26e605dc38136e94813a8d064c169bad5a2", blobData, acc)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(blob)*/

	/*gasPrice, err := GetGas(conn, ctx)
	if err != nil {
		log.Fatal(err)
	}

	price := gasPrice.Epoch.ReferenceGasPrice
	add, err := AddPooledBlobMetadata(
		conn,
		TestnetConfig,
		ctx, acc, "0x15270e9746c8c4085d6b5d3915f5d26e605dc38136e94813a8d064c169bad5a2",
		BlobIDToBase64("80392606948090037230430042512468532838133279124717429954941529119024196032378"), "filename", "file.bin",
		100_000_000, *price,
	)
	if err != nil {
		log.Fatal(err)
	}*/

	/*estimate, err := EstimateEncodedSize(39, 1000, "RS2")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Metadata: %d\nData: %d\nEncoded: %d\n", estimate.MetadataSize, estimate.DataSize, estimate.TotalEncodedSize)
	*/

	pooledBlobs, err := GetStoragePoolBlobObjects(
		ctx, TestnetConfig.GraphQLEndpoint,
		"0x15270e9746c8c4085d6b5d3915f5d26e605dc38136e94813a8d064c169bad5a2")
	if err != nil {
		log.Fatal(err)
	}

	//fmt.Println(pooledBlobs)

	/*getPooledBlob, err := ReadBlob(BlobIDToBase64(pooledBlobs[0]["blob_id"].(string)), acc)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(getPooledBlob))*/

	var pooledBlobsId []string
	for i := range pooledBlobs {
		pooledBlobsId = append(pooledBlobsId, BlobIDToBase64(pooledBlobs[i]["blob_id"].(string)))
	}

	getPooledBlobs, err := ReadBlobs(pooledBlobsId, acc)
	if err != nil {
		log.Fatal(err)
	}
	for i := range getPooledBlobs {
		b := getPooledBlobs[i]
		if b.Err == nil {
			fmt.Println(string(b.Data))
		}
	}

}
