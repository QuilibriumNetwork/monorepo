//
// Copyright (c) 2023-2024 Markku Rossi
//
// All rights reserved.
//

package ssa

import (
	"testing"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/mpa"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

var inputs = []string{
	"$127", "$126", "$125", "$124", "$123", "$122", "$121", "$119",
	"$118", "$117", "$116", "$115", "$114", "$113", "$111", "$110",
	"$109", "$108", "$107", "$106", "$105", "$103", "$102", "$101",
	"$100",
}

func TestHashCode(t *testing.T) {
	counts := make(map[int]int)
	for _, input := range inputs {
		v := Value{
			Name:  input,
			Const: true,
		}
		counts[v.HashCode()]++
	}

	for k, v := range counts {
		if v > 1 {
			t.Errorf("HashCode %v: count=%v\n", k, v)
		}
	}
}

var intTypes = []types.Info{
	types.Byte,
	types.Rune,
	types.Int32,
	types.Uint32,
	types.Uint64,
}

func TestAssignFrom(t *testing.T) {
	gen := NewGenerator(utils.NewParams())

	testConstIntAssign(t, gen.Constant(int64(0), types.Int32))
	testConstIntAssign(t, gen.Constant(int64(0), types.Uint32))
	testConstIntAssign(t, gen.Constant(int64(0), types.Uint64))
	testConstIntAssign(t, gen.Constant(mpa.NewInt(0, 0), types.Int32))
	testConstIntAssign(t, gen.Constant(mpa.NewInt(0, 0), types.Uint32))
	testConstIntAssign(t, gen.Constant(mpa.NewInt(0, 0), types.Uint64))

	// Array assignment.

	at10 := types.Info{
		Type:        types.TArray,
		IsConcrete:  true,
		Bits:        10 * 8,
		MinBits:     10 * 8,
		ElementType: &types.Byte,
		ArraySize:   10,
	}
	testCanAssign(t, at10, Value{
		Type: at10,
	}, true)
	at9 := types.Info{
		Type:        types.TArray,
		IsConcrete:  true,
		Bits:        9 * 8,
		MinBits:     9 * 8,
		ElementType: &types.Byte,
		ArraySize:   9,
	}
	testCanAssign(t, at10, Value{
		Type: at9,
	}, false)

	at10Ptr := types.Info{
		Type:        types.TPtr,
		IsConcrete:  true,
		ElementType: &at10,
	}
	at10PtrValue := Value{
		Type: at10Ptr,
		PtrInfo: &PtrInfo{
			ContainerType: at10,
		},
	}
	testCanAssign(t, at10, at10PtrValue, true)

	// Slice assignment.
	st := types.Info{
		Type:        types.TSlice,
		IsConcrete:  true,
		ElementType: &types.Byte,
	}
	testCanAssign(t, st, Value{
		Type: at10,
	}, true)
	testCanAssign(t, st, Value{
		Type: at9,
	}, true)
	testCanAssign(t, st, at10PtrValue, true)
}

func testConstIntAssign(t *testing.T, v Value) {
	for _, ti := range intTypes {
		testCanAssign(t, ti, v, true)
	}
}

func testCanAssign(t *testing.T, ti types.Info, v Value, expected bool) {
	result := CanAssign(ti, v)
	if result != expected {
		t.Errorf("LValueFor(%v, %v)=%v != %v", ti, v, result, expected)
	}
}
