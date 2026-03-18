// signer.go
//
// Signs a Sui transaction using github.com/block-vision/sui-go-sdk.
//
// This file does ONE thing: take raw BCS bytes produced by the WASM
// transaction builder and return a SignedTransactionSerializedSig that
// is ready to hand to sui_executeTransactionBlock.
//
// Signing flow (matches what the SDK does internally):
//
//   1. base64-encode the raw BCS bytes       → TxnMetaData.TxBytes
//   2. prepend 3-byte intent prefix [0,0,0]  → intent message
//   3. blake2b-256 hash the intent message   → digest
//   4. ed25519-sign the digest               → 64-byte signature
//   5. serialize: flag(0x00) | sig | pubkey  → base64 string
//
// Steps 2-5 are all performed inside TxnMetaData.SignSerializedSigWith,
// so all we do here is build a TxnMetaData and call that method.

package v4

import (
	"encoding/base64"

	"github.com/block-vision/sui-go-sdk/models"
	"github.com/block-vision/sui-go-sdk/signer"
)

// SignedTx holds everything needed to submit a transaction.
type SignedTx struct {
	// TxBytes is the base64-encoded BCS transaction — pass as the first
	// argument to sui_executeTransactionBlock.
	TxBytes string

	// Signature is the serialized Ed25519 signature — pass in the
	// "signatures" array to sui_executeTransactionBlock.
	// Format: base64( 0x00 | sig[64] | pubkey[32] )
	Signature string
}

// SignTransaction signs rawBCS (the []byte returned by builder.Build())
// with the private key derived from the given BIP-39 mnemonic.
//
// The mnemonic must be the 12- or 24-word phrase for the Sui account
// whose address matches the sender set in the transaction.
//
// Only Ed25519 keys are supported by this helper; for Secp256k1 use
// signer.NewSignerWithPrivateKey with a Secp256k1 key directly.
func SignTransaction(rawBCS []byte, account *signer.Signer) (*SignedTx, error) {
	// ── 1. Wrap raw BCS in TxnMetaData ────────────────────────────────────
	// TxnMetaData.TxBytes must be standard base64 (not URL-safe, no padding
	// stripped).  The SDK decodes it before intent-wrapping and hashing.
	txMeta := models.TxnMetaData{
		TxBytes: base64.StdEncoding.EncodeToString(rawBCS),
	}

	// ── 2. Sign ───────────────────────────────────────────────────────────
	// SignSerializedSigWith internally:
	//   a. base64-decodes TxBytes
	//   b. prepends the 3-byte transaction intent [0, 0, 0]
	//   c. computes blake2b-256 of the intent message
	//   d. signs the hash with ed25519
	//   e. serialises: base64(flagByte=0x00 | signature[64] | pubKey[32])
	signed := txMeta.SignSerializedSigWith(account.PriKey)

	return &SignedTx{
		TxBytes:   signed.TxBytes,
		Signature: signed.Signature,
	}, nil
}
