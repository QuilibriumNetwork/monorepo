//
// Copyright (c) 2021-2024 Markku Rossi
//
// All rights reserved.
//

package types

import (
	"testing"
)

var parseTests = []struct {
	input string
	info  Info
}{
	{
		input: "b",
		info:  Bool,
	},
	{
		input: "bool",
		info:  Bool,
	},
	{
		input: "byte",
		info:  Byte,
	},
	{
		input: "rune",
		info:  Rune,
	},
	{
		input: "i32",
		info:  Int32,
	},
	{
		input: "int32",
		info:  Int32,
	},
	{
		input: "u32",
		info:  Uint32,
	},
	{
		input: "uint32",
		info:  Uint32,
	},
	{
		input: "i32",
		info:  Int32,
	},
	{
		input: "int32",
		info:  Int32,
	},
	{
		input: "string8",
		info: Info{
			Type:       TString,
			IsConcrete: true,
			Bits:       8,
			MinBits:    8,
		},
	},
	{
		input: "[8]byte",
		info: Info{
			Type:       TArray,
			IsConcrete: true,
			Bits:       64,
			MinBits:    64,
			ElementType: &Info{
				Type:       TUint,
				IsConcrete: true,
				Bits:       8,
				MinBits:    8,
			},
			ArraySize: 8,
		},
	},
	{
		input: "[]byte",
		info: Info{
			Type:       TSlice,
			IsConcrete: true,
			Bits:       0,
			MinBits:    0,
			ElementType: &Info{
				Type:       TUint,
				IsConcrete: true,
				Bits:       8,
				MinBits:    8,
			},
			ArraySize: 0,
		},
	},
}

func TestParse(t *testing.T) {
	for idx, test := range parseTests {
		info, err := Parse(test.input)
		if err != nil {
			t.Errorf("parseTest[%d]: %s\n", idx, err)
			continue
		}
		if !info.Equal(test.info) {
			t.Errorf("%v != %v", info, test.info)
		}
	}
}
