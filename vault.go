package mrcv

import (
	"os"
	"path/filepath"
	"runtime"
)

// DefaultVaultPath mirrors the JS default: ~/.config/@minerouter/mrcv/storage.mrcv
// on non-Windows, %APPDATA%/@minerouter/mrcv/storage.mrcv on Windows.
func DefaultVaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	if runtime.GOOS == "windows" {
		appdata := os.Getenv("APPDATA")
		if appdata != "" {
			return filepath.Join(appdata, "@minerouter", "mrcv", "storage.mrcv")
		}
		return filepath.Join(home, "AppData", "Roaming", "@minerouter", "mrcv", "storage.mrcv")
	}
	return filepath.Join(home, ".config", "@minerouter", "mrcv", "storage.mrcv")
}

// OpenResult is the outcome of Open.
type OpenResult struct {
	// State: "unlocked" (vault ready, created = first-time) or "mismatch"
	// (device binding does not match).
	State   string
	Created bool
}

// Vault is a device-bound encrypted key-value store. It mirrors the JS Vault
// API: Open -> Unlock -> Get/Set/... -> Save, with bound/strict modes.
type Vault struct {
	path       string
	mode       Mode
	sources    []BindingSource
	memory     int
	iterations int

	bindingID []byte
	data      map[string]interface{}
	opened    bool
	unlocked  bool
}

// New creates a Vault with the given config.
func New(cfg Config) (*Vault, error) {
	path := cfg.Path
	if path == "" {
		path = DefaultVaultPath()
	}
	if path == "" {
		return nil, ErrInvalidConfig
	}
	mode := cfg.Mode
	if mode == "" {
		mode = ModeBound
	}
	if mode != ModeBound && mode != ModeStrict {
		return nil, ErrInvalidMode
	}
	memory := cfg.Memory
	if memory <= 0 {
		memory = DefaultMemory
	}
	iter := cfg.Iterations
	if iter <= 0 {
		iter = DefaultIterations
	}
	sources := cfg.BindingSources
	if sources == nil {
		sources = DefaultBindingSources()
	}
	return &Vault{
		path:       path,
		mode:       mode,
		sources:    sources,
		memory:     memory,
		iterations: iter,
		data:       map[string]interface{}{},
	}, nil
}

// Open computes the device binding and either opens an existing vault or
// creates a new one. On mismatch in strict mode the file is destroyed.
func (v *Vault) Open() (OpenResult, error) {
	if v.opened {
		return OpenResult{}, ErrAlreadyOpen
	}
	v.bindingID = ComputeBinding(v.sources)

	if _, err := os.Stat(v.path); os.IsNotExist(err) {
		v.opened = true
		v.unlocked = true
		if err := v.Save(); err != nil {
			return OpenResult{}, err
		}
		return OpenResult{State: "unlocked", Created: true}, nil
	}

	f := readFile(v.path)
	if f == nil || !bindingMatches(f, v.bindingID) {
		if v.mode == ModeStrict {
			v.destroy()
		}
		return OpenResult{State: "mismatch"}, nil
	}
	v.opened = true
	return OpenResult{State: "unlocked", Created: false}, nil
}

// Unlock decrypts the payload so Get/Set become available.
func (v *Vault) Unlock() error {
	if !v.opened {
		return ErrNotOpen
	}
	if v.unlocked {
		return nil
	}
	data, err := loadFile(v.path, v.bindingID, v.memory, v.iterations)
	if err != nil {
		if v.mode == ModeStrict {
			v.destroy()
		}
		return ErrBindingMismatch
	}
	if data == nil {
		data = map[string]interface{}{}
	}
	v.data = data
	v.unlocked = true
	return nil
}

// Lock clears the decrypted data (keys are removed from memory).
func (v *Vault) Lock() {
	v.data = map[string]interface{}{}
	v.unlocked = false
}

// Save writes the current data back to the vault file.
func (v *Vault) Save() error {
	if !v.opened {
		return ErrNotOpen
	}
	if err := os.MkdirAll(filepath.Dir(v.path), 0o700); err != nil {
		return err
	}
	return saveFile(v.path, v.data, v.bindingID, v.mode == ModeStrict, v.memory, v.iterations)
}

// Get returns the value for a key, or nil if absent.
func (v *Vault) Get(key string) interface{} {
	if !v.unlocked {
		return nil
	}
	return v.data[key]
}

// Set stores a value for a key (does not persist until Save).
func (v *Vault) Set(key string, value interface{}) {
	if !v.unlocked {
		return
	}
	v.data[key] = value
}

// Delete removes a key (does not persist until Save).
func (v *Vault) Delete(key string) {
	if !v.unlocked {
		return
	}
	delete(v.data, key)
}

// Has reports whether a key exists.
func (v *Vault) Has(key string) bool {
	if !v.unlocked {
		return false
	}
	_, ok := v.data[key]
	return ok
}

// Keys returns all stored keys.
func (v *Vault) Keys() []string {
	if !v.unlocked {
		return nil
	}
	keys := make([]string, 0, len(v.data))
	for k := range v.data {
		keys = append(keys, k)
	}
	return keys
}

// IsOpen reports whether the vault file is bound (opened).
func (v *Vault) IsOpen() bool { return v.opened }

// IsUnlocked reports whether the payload is decrypted.
func (v *Vault) IsUnlocked() bool { return v.unlocked }

// Path returns the vault file location.
func (v *Vault) Path() string { return v.path }

// destroy removes the vault file (strict-mode self-destruct).
func (v *Vault) destroy() {
	_ = os.Remove(v.path)
}
