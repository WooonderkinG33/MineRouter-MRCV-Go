package mrcv

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// vaultFor creates a Vault whose binding is deterministically derived from
// the given tag via a custom BindingSource (no real device access).
func vaultFor(t *testing.T, path string, mode Mode, tag string) *Vault {
	t.Helper()
	src := []BindingSource{{Name: "test", Getter: func() (string, error) { return tag, nil }}}
	v, err := New(Config{Path: path, Mode: mode, BindingSources: src})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestCreateOpenSaveRoundtrip: create a vault, set values, save, re-open.
func TestCreateOpenSaveRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.mrcv")

	v := vaultFor(t, path, ModeBound, "devA")
	res, err := v.Open()
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "unlocked" || !res.Created {
		t.Fatalf("first open: want unlocked+created, got %+v", res)
	}
	v.Set("greeting", "hello")
	v.Set("answer", float64(42))
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}

	// Re-open a fresh vault against the same file + same binding.
	v2 := vaultFor(t, path, ModeBound, "devA")
	res2, err := v2.Open()
	if err != nil {
		t.Fatal(err)
	}
	if res2.State != "unlocked" || res2.Created {
		t.Fatalf("second open: want unlocked+not-created, got %+v", res2)
	}
	if err := v2.Unlock(); err != nil {
		t.Fatal(err)
	}
	if v2.Get("greeting") != "hello" {
		t.Fatalf("greeting = %v, want hello", v2.Get("greeting"))
	}
	if v2.Get("answer") != float64(42) {
		t.Fatalf("answer = %v, want 42", v2.Get("answer"))
	}
}

// TestHeaderLayout: the fixed header must be exactly 84 bytes with the magic
// "MRCV", version 1 LE, and all fields at the JS-documented offsets.
func TestHeaderLayout(t *testing.T) {
	f := &vaultFile{
		strict:    true,
		salt:      bytes.Repeat([]byte{0x01}, saltLen),
		nonce:     bytes.Repeat([]byte{0x02}, nonceLen),
		bindingID: bytes.Repeat([]byte{0x03}, bindingIDLen),
	}
	h := buildHeader(f)
	if len(h) != headerLen {
		t.Fatalf("header len = %d, want %d", len(h), headerLen)
	}
	if string(h[0:4]) != string(magic) {
		t.Fatalf("magic = %q, want MRCV", h[0:4])
	}
	if h[4] != fileVersion || h[5] != 0 {
		t.Fatalf("version = %d, want 1", h[4])
	}
	if h[6] != 0x01 || h[7] != 0 {
		t.Fatalf("flags = %v, want 0x0001", h[6:8])
	}
	if !bytes.Equal(h[8:24], f.salt) {
		t.Fatal("salt offset mismatch (want 8:24)")
	}
	if !bytes.Equal(h[24:48], f.nonce) {
		t.Fatal("nonce offset mismatch (want 24:48)")
	}
	if !bytes.Equal(h[48:80], f.bindingID) {
		t.Fatal("bindingID offset mismatch (want 48:80)")
	}
	for i := 80; i < 84; i++ {
		if h[i] != 0 {
			t.Fatalf("reserved byte %d = %d, want 0", i, h[i])
		}
	}
}

// TestStrictModeDestroys: opening with a mismatched binding in strict mode
// removes the file.
func TestStrictModeDestroys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.mrcv")

	v := vaultFor(t, path, ModeStrict, "devA")
	if _, err := v.Open(); err != nil {
		t.Fatal(err)
	}
	v.Set("secret", "x")
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}

	// Different binding opens strict vault -> file destroyed.
	v2 := vaultFor(t, path, ModeStrict, "devB")
	res, err := v2.Open()
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "mismatch" {
		t.Fatalf("want mismatch, got %+v", res)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("strict mode must destroy the file on mismatch")
	}
}

// TestBoundModePreserves: opening with a mismatched binding in bound mode
// leaves the file untouched.
func TestBoundModePreserves(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "b.mrcv")

	v := vaultFor(t, path, ModeBound, "devA")
	if _, err := v.Open(); err != nil {
		t.Fatal(err)
	}
	v.Set("secret", "x")
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}

	v2 := vaultFor(t, path, ModeBound, "devB")
	res, err := v2.Open()
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "mismatch" {
		t.Fatalf("want mismatch, got %+v", res)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("bound mode must preserve the file on mismatch")
	}
}

// TestTamperedFile: corrupting a byte of ciphertext must make Unlock fail.
func TestTamperedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.mrcv")

	v := vaultFor(t, path, ModeBound, "devA")
	if _, err := v.Open(); err != nil {
		t.Fatal(err)
	}
	v.Set("secret", "x")
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[headerLen+2] ^= 0xFF
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	v2 := vaultFor(t, path, ModeBound, "devA")
	if _, err := v2.Open(); err != nil {
		t.Fatal(err)
	}
	if err := v2.Unlock(); err == nil {
		t.Fatal("tampered file must fail to unlock")
	}
}
