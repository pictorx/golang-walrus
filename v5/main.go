package main

import (
	"context"

	"encoding/json"
	"fmt"
	"golang-walrus/v5/suigraphql"
	"log"

	"github.com/Khan/genqlient/graphql"
	"github.com/block-vision/sui-go-sdk/signer"
)

const (
	RPC_ENDPOINT = "fullnode.testnet.sui.io:443"
)

func main() {
	_, err := signer.NewSignerWithSecretKey("")
	if err != nil {
		log.Fatal(err)
	}

	/*storage_pool_objectID, err := CreateStoragePool(100, 5, acc)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(storage_pool_objectID)*/

	ctx := context.Background()

	poolBlobObjects, err := GetStoragePoolBlobObjects(
		ctx, TestnetConfig.GraphQLEndpoint,
		"0x15270e9746c8c4085d6b5d3915f5d26e605dc38136e94813a8d064c169bad5a2",
	)
	if err != nil {
		log.Fatal(err)
	}

	//fmt.Println(poolBlobObjects)

	poolBlobObjectTableID, ok := poolBlobObjects["id"].(string)
	if !ok {
		log.Fatal("poolBlobObjectTableID is not a string")
	}

	/* randomSuffix := make([]byte, 8)
	rand.Read(randomSuffix)
	blobData := []byte(fmt.Sprintf("Hello, Walrus! Test at %x", randomSuffix))

	blob, err := StoreBlobInPool(5, true, "0x15270e9746c8c4085d6b5d3915f5d26e605dc38136e94813a8d064c169bad5a2", blobData, acc)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(blob)*/
	client_graph := graphql.NewClient(TestnetConfig.GraphQLEndpoint, gqlHTTPClient)

	resp, err := suigraphql.GetDynamicFields(ctx, client_graph, poolBlobObjectTableID)
	if err != nil {
		log.Fatal(err)
	}

	nodes := resp.Address.GetDynamicFields().Nodes

	if len(nodes) == 0 {
		log.Fatal("no dynamic fields")
	}
	var movObjs []map[string]any
	for i := range nodes {
		moveObj, err := nodes[i].MarshalJSON()
		if err != nil {
			log.Fatal(err)
		}

		var meta map[string]any
		if err := json.Unmarshal(moveObj, &meta); err != nil {
			log.Fatal(err)
		}

		movObjs = append(movObjs, meta)
	}

	fmt.Println(movObjs)

}
