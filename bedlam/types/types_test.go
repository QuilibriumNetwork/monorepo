//
// Copyright (c) 2020-2024 Markku Rossi
//
// All rights reserved.
//

package types

import (
	"testing"
)

func TestUndefined(t *testing.T) {
	undef := Info{}
	if !undef.Undefined() {
		t.Errorf("undef is not undefined")
	}
}

func TestInstantiate(t *testing.T) {
	testInstantiate(t, Info{
		Type: TInt,
	}, Int32)
	testInstantiate(t, Info{
		Type: TUint,
	}, Uint32)
	testInstantiate(t, Info{
		Type: TUint,
	}, Uint64)

	// Array instantiation.

	at10 := Info{
		Type:        TArray,
		IsConcrete:  true,
		Bits:        10 * 8,
		MinBits:     10 * 8,
		ElementType: &Byte,
		ArraySize:   10,
	}
	testInstantiate(t, Info{
		Type:        TArray,
		ElementType: &Byte,
	}, at10)

	at10Ptr := Info{
		Type:        TPtr,
		IsConcrete:  true,
		ElementType: &at10,
	}
	testInstantiate(t, Info{
		Type:        TArray,
		ElementType: &Byte,
	}, at10Ptr)

	// Slice instantiation.
	st := Info{
		Type:        TSlice,
		ElementType: &Byte,
	}
	testInstantiate(t, st, at10)
	testInstantiate(t, st, at10Ptr)
}

func testInstantiate(t *testing.T, i, o Info) {
	if !i.Instantiate(o) {
		t.Errorf("%v.Instantiate(%v) failed", i, o)
	}
}
