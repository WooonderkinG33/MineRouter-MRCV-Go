package mrcv

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"os"
)

// File-format constants — MUST match the JS implementation byte-for-byte.
const (
	magicLen     = 4
	versionLen   = 2
	flagsLen     = 2
	saltLen      = 16
	nonceLen     = 24
	bindingIDLen = 32
	tagLen       = 16
	headerLen    = 84
	fileVersion  = 1
)

var magic = []byte{0x4D, 0x52, 0x43, 0x56} // "MRCV"

// vaultFile is the on-disk layout.
type vaultFile struct {
	strict     bool
	salt       []byte
	nonce      []byte
	bindingID  []byte
	ciphertext []byte
	tag        []byte
}

// buildHeader serializes the fixed header (everything before ciphertext).
// It is used both for writing the file and as AEAD additional data.
func buildHeader(f *vaultFile) []byte {
	buf := make([]byte, headerLen)
	copy(buf[0:4], magic)
	binary.LittleEndian.PutUint16(buf[4:6], fileVersion)
	flags := uint16(0)
	if f.strict {
		flags |= flagStrict
	}
	binary.LittleEndian.PutUint16(buf[6:8], flags)
	copy(buf[8:24], f.salt)
	copy(buf[24:48], f.nonce)
	copy(buf[48:80], f.bindingID)
	// bytes 80..83 are reserved (zero) — matches JS Buffer.alloc(84).
	return buf
}

// readFile parses a .mrcv file. Returns nil if it is not a valid MRCV file.
func readFile(path string) *vaultFile {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if len(b) < headerLen+tagLen {
		return nil
	}
	if string(b[0:4]) != string(magic) {
		return nil
	}
	flags := binary.LittleEndian.Uint16(b[6:8])
	return &vaultFile{
		strict:     flags&flagStrict != 0,
		salt:       append([]byte{}, b[8:24]...),
		nonce:      append([]byte{}, b[24:48]...),
		bindingID:  append([]byte{}, b[48:80]...),
		ciphertext: append([]byte{}, b[headerLen:len(b)-tagLen]...),
		tag:        append([]byte{}, b[len(b)-tagLen:]...),
	}
}

// bindingMatches reports whether the file was created for the given binding.
func bindingMatches(f *vaultFile, bindingID []byte) bool {
	return string(f.bindingID) == string(bindingID)
}

// loadFile decrypts the payload of an existing file. Returns nil on any
// failure (wrong binding, tampered file, wrong key).
func loadFile(path string, bindingID []byte, memory, iterations int) (map[string]interface{}, error) {
	f := readFile(path)
	if f == nil {
		return nil, ErrDecryptionFailed
	}
	if !bindingMatches(f, bindingID) {
		return nil, ErrBindingMismatch
	}
	key, err := DeriveKey(bindingID, f.salt, memory, iterations)
	if err != nil {
		return nil, err
	}
	aad := buildHeader(f)
	plaintext, err := Decrypt(key, f.ciphertext, f.nonce, f.tag, aad)
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, ErrDecryptionFailed
	}
	return data, nil
}

// saveFile encrypts data and writes the .mrcv file. The nonce is generated
// BEFORE the header so the header (used as AEAD additional data) already
// contains it — this matches the JS implementation exactly.
func saveFile(path string, data map[string]interface{}, bindingID []byte, strict bool, memory, iterations int) error {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	key, err := DeriveKey(bindingID, salt, memory, iterations)
	if err != nil {
		return err
	}
	plaintext, err := json.Marshal(data)
	if err != nil {
		return err
	}
	f := &vaultFile{strict: strict, salt: salt, nonce: nonce, bindingID: bindingID}
	aad := buildHeader(f)
	ct, _, tag, err := Encrypt(key, plaintext, aad, nonce)
	if err != nil {
		return err
	}
	f.ciphertext = ct
	f.tag = tag

	header := buildHeader(f)
	out := make([]byte, headerLen+len(ct)+tagLen)
	copy(out, header)
	copy(out[headerLen:], ct)
	copy(out[headerLen+len(ct):], tag)
	return os.WriteFile(path, out, 0o600)
}
