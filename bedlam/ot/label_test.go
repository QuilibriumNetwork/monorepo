//
// label_test.go
//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package ot

import (
	"testing"
)

func BenchmarkLabelMul2(b *testing.B) {
	var l Label

	for i := 0; i < b.N; i++ {
		l.Mul2()
	}
}

func BenchmarkLabelMul4(b *testing.B) {
	var l Label

	for i := 0; i < b.N; i++ {
		l.Mul4()
	}
}

func BenchmarkLabelXor(b *testing.B) {
	var l0, l1 Label

	for i := 0; i < b.N; i++ {
		l0.Xor(l1)
	}
}

func TestLabel(t *testing.T) {
	label := &Label{
		D0: 0xffffffffffffffff,
		D1: 0xffffffffffffffff,
	}

	label.SetS(true)
	if label.D0 != 0xffffffffffffffff {
		t.Fatal("Failed to set S-bit")
	}

	label.SetS(false)
	if label.D0 != 0x7fffffffffffffff {
		t.Fatalf("Failed to clear S-bit: %x", label.D0)
	}

	label = &Label{
		D1: 0xffffffffffffffff,
	}
	label.Mul2()
	if label.D0 != 0x1 {
		t.Fatalf("Mul2 D0 failed")
	}
	if label.D1 != 0xfffffffffffffffe {
		t.Fatalf("Mul2 D1 failed: %x", label.D1)
	}

	label = &Label{
		D1: 0xffffffffffffffff,
	}
	label.Mul4()
	if label.D0 != 0x3 {
		t.Fatalf("Mul4 D0 failed")
	}
	if label.D1 != 0xfffffffffffffffc {
		t.Fatalf("Mul4 D1 failed")
	}

	val := uint64(0x5555555555555555)
	label = &Label{
		D0: val,
		D1: val << 1,
	}
	label.Xor(Label{
		D0: 0xffffffffffffffff,
		D1: 0xffffffffffffffff,
	})
	if label.D0 != val<<1 {
		t.Errorf("Xor failed: D0=%x, expected=%x", label.D0, val<<1)
	}
	if label.D1 != val {
		t.Errorf("Xor failed: D1=%x, expected=%x", label.D1, val)
	}
}
