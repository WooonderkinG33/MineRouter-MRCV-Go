// Cross-compatibility check: creates a vault from Go, then verifies it
// opens from Node.js (@minerouter/mrcv). Run from the repo root:
//
//	sh scripts/cross-node.sh
//
// Requires: node with @minerouter/mrcv installed (npm i @minerouter/mrcv).

package main

import (
	"fmt"
	"os"

	mrcv "github.com/WooonderkinG33/MineRouter-MRCV-Go"
)

func main() {
	path := "testdata/go-vault.mrcv"
	_ = os.Remove(path)

	src := []mrcv.BindingSource{{Name: "test", Getter: func() (string, error) { return "devA", nil }}}
	v, err := mrcv.New(mrcv.Config{Path: path, Mode: mrcv.ModeBound, BindingSources: src})
	if err != nil {
		panic(err)
	}
	if _, err := v.Open(); err != nil {
		panic(err)
	}
	v.Set("greeting", "hello-from-go")
	v.Set("answer", 7)
	if err := v.Save(); err != nil {
		panic(err)
	}
	fmt.Println("Go vault written:", path)
}
