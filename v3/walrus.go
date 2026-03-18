package v3

/*
#cgo LDFLAGS: -L. -lwalrus_go_ffi -ldl -lpthread -lm -lstdc++
#cgo CFLAGS: -I.
#include "walrus_go_ffi.h"
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"unsafe"
)

type StoreResult struct {
	BlobID           string `json:"blob_id"`
	AlreadyCertified bool   `json:"already_certified"`
	TxDigest         string `json:"tx_digest"`
}

type ErrorResult struct {
	Error string `json:"error"`
}

func StoreBlob(walrusConfigPath, privateKeyB64 string, epochs uint64, metadata map[string]string, data []byte) (*StoreResult, error) {
	type config struct {
		WalrusConfig  string            `json:"walrus_config"`
		PrivateKeyB64 string            `json:"private_key_b64"`
		Epochs        uint64            `json:"epochs"`
		Encoding      string            `json:"encoding"`
		Deletable     bool              `json:"deletable"`
		Metadata      map[string]string `json:"metadata,omitempty"`
	}

	cfgJSON, err := json.Marshal(config{
		WalrusConfig:  walrusConfigPath,
		PrivateKeyB64: privateKeyB64,
		Epochs:        epochs,
		Encoding:      "RS2",
		Deletable:     false,
		Metadata:      metadata, // ← add this
	})
	if err != nil {
		return nil, err
	}

	cConfig := C.CString(string(cfgJSON))
	defer C.free(unsafe.Pointer(cConfig))

	var cDataPtr *C.uint8_t
	if len(data) > 0 {
		cDataPtr = (*C.uint8_t)(C.CBytes(data))
		defer C.free(unsafe.Pointer(cDataPtr))
	}

	raw := C.walrus_store_blob(cConfig, cDataPtr, C.size_t(len(data)))
	if raw == nil {
		return nil, fmt.Errorf("walrus_store_blob returned nil")
	}
	defer C.walrus_free_string(raw)

	jsonStr := C.GoString(raw)

	// Try parsing as error first
	var errResult ErrorResult
	if json.Unmarshal([]byte(jsonStr), &errResult) == nil && errResult.Error != "" {
		return nil, fmt.Errorf("walrus error: %s", errResult.Error)
	}

	var result StoreResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("failed to parse result JSON: %w\nraw: %s", err, jsonStr)
	}

	return &result, nil
}
