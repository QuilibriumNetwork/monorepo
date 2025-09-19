//
// enc_test.go
//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"crypto/aes"
	"crypto/rand"
	"testing"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/ot"
)

func TestEnc(t *testing.T) {
	a, _ := ot.NewLabel(rand.Reader)
	b, _ := ot.NewLabel(rand.Reader)
	c, _ := ot.NewLabel(rand.Reader)
	tweak := uint32(42)
	var key [32]byte

	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatalf("Failed to create cipher: %s", err)
	}

	var data ot.LabelData

	encrypted := encrypt(cipher, a, b, c, tweak, &data)
	if err != nil {
		t.Fatalf("Encrypt failed: %s", err)
	}

	plain := decrypt(cipher, a, b, tweak, encrypted, &data)

	if !c.Equal(plain) {
		t.Fatalf("Encrypt-decrypt failed")
	}
}

func BenchmarkEnc(b *testing.B) {
	var key [32]byte

	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		b.Fatalf("Failed to create cipher: %s", err)
	}

	al, err := ot.NewLabel(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to create label: %s", err)
	}
	bl, err := ot.NewLabel(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to create label: %s", err)
	}
	cl, err := ot.NewLabel(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to create label: %s", err)
	}

	b.ResetTimer()
	var data ot.LabelData
	for i := 0; i < b.N; i++ {
		encrypt(cipher, al, bl, cl, uint32(i), &data)
	}
}

func BenchmarkEncHalf(b *testing.B) {
	var key [32]byte

	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		b.Fatalf("Failed to create cipher: %s", err)
	}

	xl, err := ot.NewLabel(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to create label: %s", err)
	}

	b.ResetTimer()
	var data ot.LabelData
	for i := 0; i < b.N; i++ {
		encryptHalf(cipher, xl, uint32(i), &data)
	}
}
