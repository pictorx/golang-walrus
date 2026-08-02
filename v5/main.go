package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/block-vision/sui-go-sdk/signer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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

	storage_pool_objectID := "0x86e445d81c8a2921d4e93c029f402b2998c5cf439f74a17dad6b996c0c5e8415"
	storage_status, err := GetStoragePoolStatus(storage_pool_objectID, acc)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	current_epoch, err := getWalrusEpochTime(ctx, TestnetConfig.GraphQLEndpoint, TestnetConfig.WalrusStakingObject)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := grpc.Dial(TestnetConfig.GRPCEndpoint, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")))
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	// If the storage_pool has expired create a new Storage pool
	if uint32(current_epoch.Current) > uint32(storage_status.EndEpoch) {
		storage_pool_objectID, err = CreateStoragePool(100, 5, acc)
		if err != nil {
			log.Fatal(err)
		}

		storage_status, err = GetStoragePoolStatus(storage_pool_objectID, acc)
		if err != nil {
			log.Fatal(err)
		}
	}

	randomSuffix := make([]byte, 8)
	rand.Read(randomSuffix)
	blobData := []byte(fmt.Sprintf("Hello, Walrus! Test at %x", randomSuffix))

	estimate, err := EstimateEncodedSize(uint64(len(blobData)), 1000, "RS2")
	if err != nil {
		log.Fatal(err)
	}

	if storage_status.AvailableEncodedCapacityBytes < estimate.TotalEncodedSize {
		err = IncreaseStoragePoolCapacity(storage_pool_objectID, estimate.TotalEncodedSize, acc)
		if err != nil {
			log.Fatal(err)
		}
	}

	blob, err := StoreBlobInPoolSplit(
		(uint32(storage_status.EndEpoch) - uint32(storage_status.StartEpoch)), true,
		storage_pool_objectID, "RS2", blobData,
		acc)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(blob)
	time.Sleep(time.Second * 5)

	gasPrice, err := GetGas(conn, ctx)
	if err != nil {
		log.Fatal(err)
	}

	price := gasPrice.Epoch.ReferenceGasPrice
	add, err := AddPooledBlobMetadata(
		conn,
		TestnetConfig,
		ctx, acc, storage_pool_objectID,
		blob.BlobID, "filename", "file.bin",
		100_000_000, *price,
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(add)

	/*estimate, err := EstimateEncodedSize(39, 1000, "RS2")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Metadata: %d\nData: %d\nEncoded: %d\n", estimate.MetadataSize, estimate.DataSize, estimate.TotalEncodedSize)
	*/

	pooledBlobs, err := GetStoragePoolBlobObjects(
		ctx, TestnetConfig.GraphQLEndpoint,
		storage_pool_objectID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(pooledBlobs)

	//fmt.Println(pooledBlobs)

	/*getPooledBlob, err := ReadBlob(BlobIDToBase64(pooledBlobs[0]["blob_id"].(string)), acc)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(getPooledBlob))*/

	/*var pooledBlobsId []string
	for i := range pooledBlobs {
		pooledBlobsId = append(pooledBlobsId, BlobIDToBase64(pooledBlobs[i]["blob_id"].(string)))
	}*/

	/*getPooledBlobs, err := ReadBlobs(pooledBlobsId, acc)
	if err != nil {
		log.Fatal(err)
	}
	for i := range getPooledBlobs {
		b := getPooledBlobs[i]
		if b.Err == nil {
			fmt.Println(string(b.Data))
		}
	}*/

	/*storages, err := GetAllStoragePools(conn, ctx, acc, TestnetConfig)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(storages)*/
	storage_status, err = GetStoragePoolStatus(storage_pool_objectID, acc)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(storage_status.BlobCount)
	fmt.Printf("storage used - %s\n", formatStoragePool(storage_status.UsedEncodedBytes))
	fmt.Printf("storage available - %s\n", formatStoragePool(storage_status.AvailableEncodedCapacityBytes))
}
