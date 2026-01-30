package main

import (
	"fmt"
	"golangwalrus"
	"log"
)

// cargo clean && cargo build --release
// cd example/
// export LD_LIBRARY_PATH=../target/release
// go build
// ./example

func main() {
	// --- Example: Blob Encoding ---
	fmt.Println("Initializing Encoder...")

	// Create encoder with 4 shards
	encoder, err := golangwalrus.NewBlobEncoder(4)
	if err != nil {
		log.Fatalf("Error creating encoder: %v", err)
	}
	defer encoder.Close() // ALWAYS Close() to prevent memory leaks

	data := []byte("Hello, this is some data that we want to encode into shards!")

	numShards := 4

	fmt.Println("Encoding data...")
	result, err := encoder.Encode(data, numShards)
	if err != nil {
		log.Fatalf("Encode error: %v", err)
	}

	fmt.Printf("Success! Metadata size: %d bytes\n", len(result.Metadata))
	fmt.Printf("Primary Shard 1: %x\n", result.PrimaryShards[0][:20]) // Print first 20 bytes
}
