package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// BlobId is 32 bytes
type BlobId [32]byte

// EncodingType enum
type EncodingType uint32

const (
	RedStuff EncodingType = 0
	RS2      EncodingType = 1
)

func ExtractBlobInfo(data []byte) (blobId []byte, rootHash []byte, unencodedLength uint32, encodingType uint32, err error) {
	minSize := 32 + 4 + 4 + 4 + 4 + 8 + 32
	if len(data) < minSize {
		return nil, nil, 0, 0, fmt.Errorf("metadata too small: %d bytes (need at least %d)", len(data), minSize)
	}

	// BlobId is the first 32 bytes [0-31]
	blobId = make([]byte, 32)
	copy(blobId, data[0:32])

	// EncodingType is at bytes 36-39 (u32)
	encodingType = binary.LittleEndian.Uint32(data[36:40])

	// Unencoded length is at bytes 40-43 (u32, not u64!)
	unencodedLength = binary.LittleEndian.Uint32(data[40:44])

	// RootHash is the last 32 bytes
	rootHash = make([]byte, 32)
	copy(rootHash, data[len(data)-32:])

	return blobId, rootHash, unencodedLength, encodingType, nil
}

// String representation helpers
func (b BlobId) String() string {
	return hex.EncodeToString(b[:])
}

func (b BlobId) Bytes() []byte {
	return b[:]
}

func (e EncodingType) String() string {
	switch e {
	case RedStuff:
		return "RedStuff"
	case RS2:
		return "RS2"
	default:
		return fmt.Sprintf("Unknown(%d)", e)
	}
}

// ToHex converts bytes to hex string
func ToHex(b []byte) string {
	return hex.EncodeToString(b)
}
