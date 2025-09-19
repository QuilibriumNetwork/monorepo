//
// enc_test.go
//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package aesni

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"
)

type LabelX struct {
	d0 uint64
	d1 uint64
}

func NewLabelX(rand io.Reader) (LabelX, error) {
	var buf [16]byte
	var result LabelX

	_, err := rand.Read(buf[:])
	if err != nil {
		return result, err
	}
	result.SetData(&buf)

	return result, nil
}

func (l *LabelX) SetData(buf *[16]byte) {
	l.d0 = binary.BigEndian.Uint64((*buf)[0:8])
	l.d1 = binary.BigEndian.Uint64((*buf)[8:16])
}

func (l *LabelX) GetData(buf *[16]byte) {
	binary.BigEndian.PutUint64((*buf)[0:8], l.d0)
	binary.BigEndian.PutUint64((*buf)[8:16], l.d1)
}

func (l *LabelX) Xor(o LabelX) {
	l.d0 ^= o.d0
	l.d1 ^= o.d1
}

func (l *LabelX) Mul2() {
	l.d0 <<= 1
	l.d0 |= (l.d1 >> 63)
	l.d1 <<= 1
}

func (l *LabelX) Mul4() {
	l.d0 <<= 2
	l.d0 |= (l.d1 >> 62)
	l.d1 <<= 2
}

func TestLabelXor(t *testing.T) {
	val := uint64(0b0101010101010101010101010101010101010101010101010101010101010101)
	a := LabelX{
		d0: val,
		d1: val << 1,
	}
	b := LabelX{
		d0: 0xffffffffffffffff,
		d1: 0xffffffffffffffff,
	}
	a.Xor(b)
	if a.d0 != val<<1 {
		t.Errorf("Xor: unexpected d0=%x, epected %x", a.d0, val<<1)
	}
	if a.d1 != val {
		t.Errorf("Xor: unexpected d1=%x, epected %x", a.d1, val)
	}
}

func NewTweakX(tweak uint32) LabelX {
	return LabelX{
		d1: uint64(tweak),
	}
}

func encryptX(alg cipher.Block, a, b, c LabelX, t uint32,
	buf *[16]byte) LabelX {

	k := makeKX(a, b, t)

	k.GetData(buf)
	alg.Encrypt(buf[:], buf[:])

	var pi LabelX
	pi.SetData(buf)

	pi.Xor(k)
	pi.Xor(c)

	return pi
}

func makeKX(a, b LabelX, t uint32) LabelX {
	a.Mul2()

	b.Mul4()
	a.Xor(b)

	a.Xor(NewTweakX(t))

	return a
}

func BenchmarkLabelX(b *testing.B) {
	var key [32]byte

	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		b.Fatalf("Failed to create cipher: %s", err)
	}

	al, err := NewLabelX(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to create label: %s", err)
	}
	bl, err := NewLabelX(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to create label: %s", err)
	}
	cl, err := NewLabelX(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to create label: %s", err)
	}

	b.ResetTimer()
	var buf [16]byte
	for i := 0; i < b.N; i++ {
		encryptX(cipher, al, bl, cl, uint32(i), &buf)
	}
}
