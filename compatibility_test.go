package mrcv

import (
	"encoding/hex"
	"path/filepath"
	"testing"
)

// testDevBinding returns a binding source with a deterministic value shared
// between the JS and Go test fixtures ("devA").
func testDevBinding() []BindingSource {
	return []BindingSource{{Name: "test", Getter: func() (string, error) { return "devA", nil }}}
}

// TestJSCompatibility_BindingVector: ComputeBinding must produce the exact
// same SHA-256 as the JS @minerouter/mrcv for the same sources. Vector
// captured from the JS implementation (crypto.subtle SHA-256).
func TestJSCompatibility_BindingVector(t *testing.T) {
	got := ComputeBinding(testDevBinding())
	want := "3e25b34386d01d8cab93450748f47350505124ed975338110a30ff507499c8ea"
	if h := hex.EncodeToString(got); h != want {
		t.Fatalf("binding mismatch:\n got %s\nwant %s", h, want)
	}
}

// TestJSCompatibility_OpenFile: this .mrcv file was created by the REAL
// @minerouter/mrcv (Node.js, v2.0.2) with binding source "devA" and the
// values greeting=hello-from-js, answer=42. Go must open and decrypt it.
func TestJSCompatibility_OpenFile(t *testing.T) {
	path := filepath.Join("testdata", "js-vault.mrcv")
	v, err := New(Config{Path: path, Mode: ModeBound, BindingSources: testDevBinding()})
	if err != nil {
		t.Fatal(err)
	}
	res, err := v.Open()
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "unlocked" {
		t.Fatalf("JS-created vault: want unlocked, got %+v", res)
	}
	if err := v.Unlock(); err != nil {
		t.Fatalf("failed to decrypt JS-created vault: %v", err)
	}
	if got := v.Get("greeting"); got != "hello-from-js" {
		t.Fatalf("greeting = %v, want hello-from-js", got)
	}
	if got := v.Get("answer"); got != float64(42) {
		t.Fatalf("answer = %v, want 42", got)
	}
}

// TestJSCompatibility_Format: the fixture header must parse with the exact
// JS layout (MAGIC, version, flags, salt/nonce/bindingId offsets).
func TestJSCompatibility_Format(t *testing.T) {
	f := readFile(filepath.Join("testdata", "js-vault.mrcv"))
	if f == nil {
		t.Fatal("fixture did not parse as MRCV")
	}
	if len(f.salt) != saltLen || len(f.nonce) != nonceLen || len(f.bindingID) != bindingIDLen {
		t.Fatalf("field sizes: salt=%d nonce=%d binding=%d", len(f.salt), len(f.nonce), len(f.bindingID))
	}
	wantBinding, _ := hex.DecodeString("3e25b34386d01d8cab93450748f47350505124ed975338110a30ff507499c8ea")
	if string(f.bindingID) != string(wantBinding) {
		t.Fatal("fixture bindingId does not match the JS vector")
	}
}
