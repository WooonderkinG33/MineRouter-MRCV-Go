package mrcv

import (
	"crypto/rand"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Defaults matching the JS implementation's deriveKey defaults.
const (
	DefaultMemory     = 256 * 1024 * 1024 // bytes
	DefaultIterations = 3
	keySize           = 32
	// argon2MemoryKiB is DefaultMemory expressed in KiB (argon2.IDKey unit).
	argon2MemoryKiB = DefaultMemory / 1024
	// parallelism matches libsodium crypto_pwhash (single lane).
	argon2Parallelism = 1
)

// DeriveKey runs Argon2id over the binding ID to produce the 32-byte
// encryption key. Must match libsodium's crypto_pwhash(ARGON2ID13) with the
// same opslimit/memlimit/parallelism.
func DeriveKey(bindingID, salt []byte, memory, iterations int) ([]byte, error) {
	if memory <= 0 {
		memory = DefaultMemory
	}
	if iterations <= 0 {
		iterations = DefaultIterations
	}
	return argon2.IDKey(bindingID, salt, uint32(iterations), uint32(memory/1024), uint8(argon2Parallelism), keySize), nil
}

// Encrypt seals plaintext with XChaCha20-Poly1305, returning ciphertext,
// the 24-byte nonce, and the 16-byte tag. aad (the file header) is bound to
// the ciphertext. If nonce is nil, a fresh one is generated. The caller MUST
// build the aad from a header that already contains the nonce (matching the
// JS implementation, where the nonce is created before the header).
func Encrypt(key, plaintext, aad, nonce []byte) (ciphertext, outNonce, tag []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, nil, err
	}
	if nonce == nil {
		nonce = make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, nil, nil, err
		}
	}
	sealed := aead.Seal(nil, nonce, plaintext, aad)
	tagLen := aead.Overhead() // 16
	ciphertext = sealed[:len(sealed)-tagLen]
	tag = sealed[len(sealed)-tagLen:]
	return ciphertext, nonce, tag, nil
}

// Decrypt opens ciphertext with XChaCha20-Poly1305. It must be given the
// SAME aad used at encryption.
func Decrypt(key, ciphertext, nonce, tag, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	combined := append(append([]byte{}, ciphertext...), tag...)
	plaintext, err := aead.Open(nil, nonce, combined, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}
