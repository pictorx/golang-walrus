package main

import (
	"fmt"
	v3 "golangwalrus/v3"
)

func main() {
	// Example usage — adjust paths to your setup
	walrusConfig := "/home/immanu3l/.config/walrus/client_config.yaml"
	privateKey := "suiprivkey1qqqzjfp65wl44ve65a2cpf77006hl2wrrau702nf7huxzr99nxmq2uyepsl"
	blobData := []byte("Hello, Walrus! Direct via static lib metadata added 3")

	result, err := v3.StoreBlob(walrusConfig, privateKey, 5, map[string]string{
		"content-type": "text/plain",
		"filename":     "hello.txt",
		"author":       "myapp",
	}, blobData)
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		return
	}

	fmt.Printf("✅ Blob stored!\n")
	fmt.Printf("   Blob ID:            %s\n", result.BlobID)
	fmt.Printf("   Already certified:  %v\n", result.AlreadyCertified)
	fmt.Printf("   TX digest:          %s\n", result.TxDigest)
}
