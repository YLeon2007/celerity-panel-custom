//go:build wasip1 && wasm

// A WASI reactor for ML-KEM-768 seed-to-public-key derivation only.
package main

import "crypto/mlkem"

var scratch [mlkem.SeedSize + mlkem.EncapsulationKeySize768]byte

//go:wasmexport buffer
func buffer() *byte { return &scratch[0] }

//go:wasmexport derive
func derive() uint32 {
	seed := scratch[:mlkem.SeedSize]
	defer clear(seed)
	key, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return 0
	}
	return uint32(copy(scratch[mlkem.SeedSize:], key.EncapsulationKey().Bytes()))
}

func main() {}
