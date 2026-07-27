// PictorxApp vault — Path A only.
//
// Design:
//   wallet.SignPersonalMessage(AppDomain) → 64-byte Ed25519 signature
//   → Argon2id → Master Key (32 bytes, memguard-protected, zeroed after session)
//   → per-file HKDF(master_key, file_id) → File Key (32 bytes)
//   → AES-256-GCM encrypt/decrypt file content (fileID bound as AAD)
//
// Nothing is stored except the encrypted blobs on Walrus.
// No vault.json. No key escrow. No server involvement.
//
// To decrypt without this app forever:
//  1. Sign AppDomain message with your wallet (any Ed25519 signer)
//  2. Argon2id(sig, salt="PictorxApp-v1-argon2id-root-key-2025", t=1, m=65536, p=4) → master key
//  3. For each file: HKDF(master_key, salt=file_id, info="file-key-v1") → file key
//  4. AES-256-GCM decrypt with file key + nonce prepended to ciphertext + fileID as AAD
//
// Dependencies:
//
//	go get golang.org/x/crypto
//	go get github.com/awnumar/memguard

package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/awnumar/memguard"
	"github.com/block-vision/sui-go-sdk/signer"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// ─────────────────────────────────────────────
// CONSTANTS — document these publicly so users
// can always re-derive without your app
// ─────────────────────────────────────────────

// AppDomain is the exact message the wallet must sign.
//
// SECURITY: The bracketed [PictorxApp-v1] prefix and descriptive label prevent
// cross-protocol attacks — a malicious app cannot trick users into signing a
// message that happens to produce this app's master key.
//
// ⚠️  BREAKING CHANGE vs prior versions: changing this constant makes all
// existing encrypted data permanently unrecoverable. Never change it in production.
//
// Format with the user's Sui address before signing.
const AppDomain = "[PictorxApp-v1]: Root Key Derivation for %s"

const (
	masterKeyHKDFSalt    = "pictorxApp-v1-hkdf-salt"
	masterKeyHKDFInfo    = "master-key-v1"
	fileKeyHKDFInfo      = "file-key-v1"
	metaKeyHKDFInfo      = "metadata-key-v1"
	fileIDEncryptionInfo = "walrus-file-id-v1"
)

// ─────────────────────────────────────────────
// ARGON2ID PARAMETERS
//
// Used for Signature → Master Key derivation.
// These values are part of the public spec — changing them is a breaking change.
//
// t=1, m=64 MB satisfies OWASP minimum recommendations.
// On a modern laptop this takes ~300–500 ms, which is imperceptible to the user
// (key is derived once per login session) but makes brute-forcing a leaked
// signature ~10,000x more expensive than plain HKDF.
// ─────────────────────────────────────────────

const (
	argon2Time    uint32 = 1
	argon2Memory  uint32 = 64 * 1024 // 64 MB — increase on higher-end targets
	argon2Threads uint8  = 4
	argon2KeyLen  uint32 = 32
)

// argon2Salt is a fixed, public, domain-separated salt.
// Per-user entropy comes from the wallet signature (the "password" input),
// which is unique per private key. The fixed salt prevents cross-application
// Argon2id rainbow tables.
const argon2Salt = "PictorxApp-v1-argon2id-root-key-2025"

var fileMagic = [4]byte{'M', 'D', 'A', 0x01} // PictorxApp encrypted file

// ─────────────────────────────────────────────
// MASTER KEY
//
// Derived once per session from wallet signature using Argon2id.
// Stored in a memguard-protected memory region that:
//   - is locked against OS swap (mlock)
//   - is guarded with canary pages that trigger SIGSEGV on overflow
//   - is explicitly zeroed on Destroy()
//
// This defends against cold-boot attacks and local RAM-dump malware.
// Always call Zero() when the user locks the vault or the session ends.
// ─────────────────────────────────────────────

// MasterKey wraps the session master key in an OS-protected memory region.
// Never copy the underlying bytes — pass *MasterKey by pointer everywhere.
type MasterKey struct {
	buf *memguard.LockedBuffer
}

// DeriveFromSignature derives the session MasterKey from raw wallet
// signature bytes returned by wallet.SignPersonalMessage(AppDomain).
//
// Uses Argon2id (memory-hard) for the first derivation step.
//
// sigBytes: raw 64-byte Ed25519 signature (or 65-byte Secp256k1 — both work)
func DeriveFromSignature(sigBytes []byte) (*MasterKey, error) {
	if len(sigBytes) < 64 {
		return nil, errors.New("signature too short: expected at least 64 bytes")
	}

	// Argon2id: memory-hard KDF — brute-forcing a leaked signature requires
	// 64 MB of RAM per attempt, not just CPU cycles.
	raw := argon2.IDKey(
		sigBytes,
		[]byte(argon2Salt),
		argon2Time,
		argon2Memory,
		argon2Threads,
		argon2KeyLen,
	)
	// Wipe the intermediate Argon2id output before transferring to the
	// protected buffer; defer ensures cleanup even if NewBuffer panics.
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()

	// Allocate a guarded, mlock'd memory region for the master key.
	buf := memguard.NewBuffer(int(argon2KeyLen))
	copy(buf.Bytes(), raw)
	return &MasterKey{buf: buf}, nil
}

// Zero wipes and frees the protected memory region.
// Call when the session ends or the user locks the vault.
func (mk *MasterKey) Zero() {
	mk.buf.Destroy()
}

// keySlice returns a view into the protected memory for internal use.
//
// IMPORTANT: never store this slice or pass it to goroutines — the
// underlying buffer may be destroyed. Use it only within a single call frame.
func (mk *MasterKey) keySlice() []byte {
	return mk.buf.Bytes()
}

// ─────────────────────────────────────────────
// FILE KEY
// Derived per-file from the master key + a unique file ID.
// Each file gets its own key — compromise of one file key
// does not affect any other file.
// ─────────────────────────────────────────────

// deriveFileKey derives a 32-byte AES key for a specific file.
// fileID must be unique per file — 16 random bytes generated at upload
// time, encrypted and stored in the Sui blob object metadata.
func (mk *MasterKey) deriveFileKey(fileID []byte) ([32]byte, error) {
	r := hkdf.New(
		sha256.New,
		mk.keySlice(),
		fileID, // file ID is the HKDF salt — unique per file
		[]byte(fileKeyHKDFInfo),
	)

	var fk [32]byte
	if _, err := io.ReadFull(r, fk[:]); err != nil {
		return fk, err
	}
	return fk, nil
}

// ─────────────────────────────────────────────
// FILE ENCRYPTION / DECRYPTION
//
// Encrypted file layout on Walrus (no header — fileID lives on-chain):
//
//	[0:12]  nonce      — 12 random bytes, AES-GCM nonce
//	[12:]   ciphertext — AES-256-GCM encrypted content (includes 16-byte GCM tag)
//
// The fileID is passed as AAD so the ciphertext is cryptographically bound
// to its file identity. Swapping two encrypted blobs will cause decryption to
// fail with "invalid key or corrupted file", preventing Mapping Attacks.
//
// The fileID is stored encrypted in the Sui blob object metadata field "fileid".
// Retrieve it with DecryptFileID before calling DecryptFile.
// ─────────────────────────────────────────────

// EncryptFile encrypts plaintext and returns an encrypted blob ready to upload
// to Walrus, plus the random fileID that must be stored in the blob's on-chain
// metadata (encrypted with EncryptFileID).
//
// The fileID is bound to the ciphertext as AES-GCM Additional Authenticated
// Data (AAD). Decryption will fail if the wrong fileID is supplied, preventing
// an attacker from swapping two encrypted blobs at the storage layer.
//
// Returns (encryptedBlob, fileID, error).
func (mk *MasterKey) EncryptFile(plaintext []byte) ([]byte, []byte, error) {
	// 1. Generate a unique random file ID (16 bytes)
	fileID := make([]byte, 16)
	if _, err := rand.Read(fileID); err != nil {
		return nil, nil, err
	}

	// 2. Derive the file-specific key
	fileKey, err := mk.deriveFileKey(fileID)
	if err != nil {
		return nil, nil, err
	}
	defer zeroArray32(&fileKey)

	// 3. Generate a random nonce (12 bytes for AES-GCM)
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	// 4. Encrypt with AES-256-GCM — fileID is the AAD, binding this
	//    ciphertext to its identity. Any attempt to use it with a different
	//    fileID will produce an authentication failure.
	block, err := aes.NewCipher(fileKey[:])
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, fileID) // AAD = fileID

	// 5. Build blob: nonce + ciphertext (no file header)
	blob := make([]byte, 0, 12+len(ciphertext))
	blob = append(blob, nonce...)      // [0:12]  nonce
	blob = append(blob, ciphertext...) // [12:]   ciphertext

	return blob, fileID, nil
}

// DecryptFile decrypts an encrypted blob downloaded from Walrus.
// fileID must be obtained from the blob's on-chain metadata ("fileid" field)
// via GetFileId + DecryptFileID before calling this function.
//
// The fileID is verified as AAD — decryption fails if it does not match
// the value used during encryption. This detects blob-swapping attacks.
//
// Returns the original plaintext.
func (mk *MasterKey) DecryptFile(blob []byte, fileID []byte) ([]byte, error) {
	const minLen = 12 + 16 // nonce(12) + minimum GCM tag(16)
	if len(blob) < minLen {
		return nil, errors.New("blob too short to be a valid encrypted file")
	}

	// 1. Parse: nonce is the first 12 bytes, rest is ciphertext+tag
	nonce := blob[0:12]
	ciphertext := blob[12:]

	// 2. Derive the file key using the fileID from on-chain metadata
	fileKey, err := mk.deriveFileKey(fileID)
	if err != nil {
		return nil, err
	}
	defer zeroArray32(&fileKey)

	// 3. Decrypt — fileID is authenticated as AAD
	block, err := aes.NewCipher(fileKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// AAD = fileID — must exactly match the value supplied at encrypt time.
	// Error here means wrong fileID, wrong key, or corrupted blob.
	plaintext, err := gcm.Open(nil, nonce, ciphertext, fileID) // AAD = fileID
	if err != nil {
		// Deliberately vague — could be wrong key, wrong fileID, or corrupted blob
		return nil, errors.New("decryption failed: invalid key, wrong fileID, or corrupted file")
	}

	return plaintext, nil
}

// ─────────────────────────────────────────────
// FILE INDEX ENTRY
// ─────────────────────────────────────────────

// IndexEntry maps a logical file path to its Walrus Blob ID and file ID.
type IndexEntry struct {
	Path     string `json:"path"`
	BlobID   string `json:"blob_id"`
	FileID   string `json:"file_id"`
	MimeType string `json:"mime_type"`
	Size     int64  `json:"size"`
	ModTime  int64  `json:"mod_time"`
}

// ─────────────────────────────────────────────
// METADATA ENCRYPTION
//
// Sui object metadata is encrypted with a key derived from the same
// file_id as the blob content, but a different HKDF info string
// ("metadata-key-v1") so the metadata key and file content key are
// always distinct even though they share the same file_id as input.
//
// Encrypted metadata layout (stored as bytes in the Sui object field):
//
//	[4 magic][1 version][12 nonce][N ciphertext+tag]
//
//	magic:      'M','D','M',0x01  (MyDriveMeta)
//	version:    0x01
// ─────────────────────────────────────────────

var metaMagic = [4]byte{'M', 'D', 'M', 0x01}

const metaHeaderSize = 4 + 1 + 12 // magic + version + nonce = 17 bytes

func (mk *MasterKey) deriveMetaKey(fileID []byte) ([32]byte, error) {
	r := hkdf.New(
		sha256.New,
		mk.keySlice(),
		fileID,
		[]byte(metaKeyHKDFInfo),
	)
	var mk2 [32]byte
	if _, err := io.ReadFull(r, mk2[:]); err != nil {
		return mk2, err
	}
	return mk2, nil
}

// EncryptMetadata encrypts arbitrary metadata bytes (e.g. a filename) bound
// to a specific file via its fileID.
func (mk *MasterKey) EncryptMetadata(fileID, plaintext []byte) ([]byte, error) {
	metaKey, err := mk.deriveMetaKey(fileID)
	if err != nil {
		return nil, err
	}
	defer zeroArray32(&metaKey)

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(metaKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	blob := make([]byte, 0, metaHeaderSize+len(ciphertext))
	blob = append(blob, metaMagic[:]...) // [0:4]  magic
	blob = append(blob, 0x01)            // [4:5]  version
	blob = append(blob, nonce...)        // [5:17] nonce
	blob = append(blob, ciphertext...)   // [17:]  ciphertext

	return blob, nil
}

// DecryptMetadata decrypts metadata encrypted by EncryptMetadata.
// fileID must match the one used during encryption.
func (mk *MasterKey) DecryptMetadata(fileID, blob []byte) ([]byte, error) {
	if len(blob) < metaHeaderSize+16 {
		return nil, errors.New("metadata blob too short")
	}

	// 1. Parse and validate header
	magic := blob[0:4]
	version := blob[4]
	nonce := blob[5:17]
	ciphertext := blob[17:]

	if magic[0] != metaMagic[0] || magic[1] != metaMagic[1] ||
		magic[2] != metaMagic[2] || magic[3] != metaMagic[3] {
		return nil, errors.New("not a MyDriveApp metadata blob")
	}
	if version != 0x01 {
		return nil, errors.New("unsupported metadata format version")
	}

	// 2. Derive metadata key from file_id
	metaKey, err := mk.deriveMetaKey(fileID)
	if err != nil {
		return nil, err
	}
	defer zeroArray32(&metaKey)

	// 3. Decrypt
	block, err := aes.NewCipher(metaKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("metadata decryption failed: invalid key or corrupted blob")
	}
	return plaintext, nil
}

// ─────────────────────────────────────────────
// STREAMING ENCRYPTION (large files)
// For files too large to hold in memory.
// Splits into chunks, each independently encrypted.
//
// Each chunk's AAD is fileID || bigEndian(chunkCounter), preventing
// chunk reordering and cross-stream substitution attacks.
// ─────────────────────────────────────────────

const defaultChunkSize = 4 * 1024 * 1024 // 4 MB per chunk

// chunkAAD constructs the AAD for a streaming chunk:
//
//	fileID (16 bytes) || chunkCounter (8 bytes, big-endian)
//
// Binding the chunk counter prevents an attacker from reordering chunks
// or substituting a chunk from a different encrypted file.
func chunkAAD(fileID []byte, chunkCounter uint64) []byte {
	aad := make([]byte, len(fileID)+8)
	copy(aad, fileID)
	binary.BigEndian.PutUint64(aad[len(fileID):], chunkCounter)
	return aad
}

// EncryptStream encrypts r in chunks and writes the encrypted blob to w.
// fileID must be generated by the caller and stored in on-chain metadata.
// Each chunk is independently encrypted with a counter-derived nonce and
// fileID+counter AAD.
//
// Chunk layout:
//
//	[4 bytes] chunk length (uint32 big-endian, length of encrypted chunk)
//	[N bytes] encrypted chunk (AES-GCM: counter-nonce + ciphertext + tag)
func (mk *MasterKey) EncryptStream(fileID []byte, r io.Reader, w io.Writer) error {
	fileKey, err := mk.deriveFileKey(fileID)
	if err != nil {
		return err
	}
	defer zeroArray32(&fileKey)

	block, err := aes.NewCipher(fileKey[:])
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	buf := make([]byte, defaultChunkSize)
	var chunkCounter uint64 = 0

	for {
		n, readErr := io.ReadFull(r, buf)
		if n == 0 {
			break
		}

		// Derive nonce from chunk counter (deterministic, no need to store)
		nonce := make([]byte, gcm.NonceSize())
		binary.BigEndian.PutUint64(nonce[4:], chunkCounter)

		// AAD = fileID || chunkCounter — prevents chunk reordering and
		// substitution of chunks from a different encrypted stream.
		aad := chunkAAD(fileID, chunkCounter)
		encrypted := gcm.Seal(nil, nonce, buf[:n], aad)

		// Write chunk length prefix
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(encrypted)))
		if _, err := w.Write(lenBuf); err != nil {
			return err
		}
		if _, err := w.Write(encrypted); err != nil {
			return err
		}

		chunkCounter++
		if readErr == io.ErrUnexpectedEOF || readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	return nil
}

// DecryptStream decrypts a stream written by EncryptStream.
// fileID must match the one used during encryption (from on-chain metadata).
func (mk *MasterKey) DecryptStream(fileID []byte, r io.Reader, w io.Writer) error {
	fileKey, err := mk.deriveFileKey(fileID)
	if err != nil {
		return err
	}
	defer zeroArray32(&fileKey)

	block, err := aes.NewCipher(fileKey[:])
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	var chunkCounter uint64 = 0
	lenBuf := make([]byte, 4)

	for {
		_, err := io.ReadFull(r, lenBuf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		chunkLen := binary.BigEndian.Uint32(lenBuf)
		encrypted := make([]byte, chunkLen)
		if _, err := io.ReadFull(r, encrypted); err != nil {
			return err
		}

		nonce := make([]byte, gcm.NonceSize())
		binary.BigEndian.PutUint64(nonce[4:], chunkCounter)

		// AAD must exactly match what was used during encryption.
		aad := chunkAAD(fileID, chunkCounter)
		plaintext, err := gcm.Open(nil, nonce, encrypted, aad)
		if err != nil {
			return errors.New("stream decryption failed: invalid key, wrong fileID, or corrupted chunk")
		}
		if _, err := w.Write(plaintext); err != nil {
			return err
		}
		chunkCounter++
	}
	return nil
}

// ─────────────────────────────────────────────
// FILE ID ENCRYPTION
// The per-file random ID is stored encrypted in Sui object metadata.
// ─────────────────────────────────────────────

// deriveAESKey derives a 16-byte AES-128 key from an Ed25519 private key
// using HKDF-SHA256. Domain-separated with fileIDEncryptionInfo.
func deriveAESKey(priKey []byte) ([]byte, error) {
	// Ed25519 PrivateKey is 64 bytes: seed(32) + pubkey(32)
	// We use the 32-byte seed as IKM
	if len(priKey) < 32 {
		return nil, fmt.Errorf("private key too short: %d bytes", len(priKey))
	}
	seed := priKey[:32]

	hkdfReader := hkdf.New(sha256.New, seed, nil, []byte(fileIDEncryptionInfo))
	key := make([]byte, 16)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("HKDF derive: %w", err)
	}
	return key, nil
}

// EncryptFileID encrypts a 16-byte file ID using the signer's private key.
// Returns base64url(nonce[12] + ciphertext[16] + tag[16]) = ~59 chars.
// Safe to store in blob metadata — opaque to anyone without the private key.
func EncryptFileID(s *signer.Signer, fileID [16]byte) (string, error) {
	key, err := deriveAESKey(s.PriKey)
	if err != nil {
		return "", fmt.Errorf("derive key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("new GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	// out = nonce(12) + ciphertext(16) + tag(16) = 44 bytes
	out := gcm.Seal(nonce, nonce, fileID[:], nil)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// DecryptFileID decrypts a file ID encrypted by EncryptFileID.
func DecryptFileID(s *signer.Signer, encrypted string) ([16]byte, error) {
	var zero [16]byte

	key, err := deriveAESKey(s.PriKey)
	if err != nil {
		return zero, fmt.Errorf("derive key: %w", err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil {
		return zero, fmt.Errorf("base64 decode: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return zero, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return zero, fmt.Errorf("new GCM: %w", err)
	}

	nonceSize := gcm.NonceSize() // 12
	if len(raw) < nonceSize {
		return zero, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return zero, fmt.Errorf("decrypt: wrong key or corrupted data: %w", err)
	}
	if len(plaintext) != 16 {
		return zero, fmt.Errorf("unexpected plaintext length: %d", len(plaintext))
	}

	var out [16]byte
	copy(out[:], plaintext)
	return out, nil
}

// ─────────────────────────────────────────────
// INTERNAL HELPERS
// ─────────────────────────────────────────────

func zeroArray32(b *[32]byte) {
	for i := range b {
		b[i] = 0
	}
}
