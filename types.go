package mrcv

import "errors"

// Mode controls what happens when the vault is opened on a machine whose
// device binding does not match.
type Mode string

const (
	// ModeBound: on mismatch the file is left untouched, vault is not opened.
	ModeBound Mode = "bound"
	// ModeStrict: on mismatch the file is destroyed (self-destruct).
	ModeStrict Mode = "strict"
)

// File-format flags.
const (
	flagStrict = 0x0001
	flagCBOR   = 0x0002
)

// Errors returned by the vault.
var (
	ErrNotOpen          = errors.New("mrcv: vault is not open")
	ErrAlreadyOpen      = errors.New("mrcv: vault is already open")
	ErrBindingMismatch  = errors.New("mrcv: device binding does not match")
	ErrInvalidMode      = errors.New("mrcv: invalid mode (must be 'bound' or 'strict')")
	ErrInvalidConfig    = errors.New("mrcv: invalid config")
	ErrDecryptionFailed = errors.New("mrcv: decryption failed")
)

// Config configures a Vault. Path is required; everything else has defaults.
type Config struct {
	Path           string          // .mrcv file location; defaults to ~/.config/@minerouter/mrcv/storage.mrcv
	Mode           Mode            // bound (default) or strict
	BindingSources []BindingSource // optional custom device-binding sources
	Memory         int             // Argon2id memory in bytes, default 256 MiB
	Iterations     int             // Argon2id iterations, default 3
}

// BindingSource is one device fingerprint that contributes to the binding ID.
type BindingSource struct {
	Name   string
	Getter func() (string, error)
}
