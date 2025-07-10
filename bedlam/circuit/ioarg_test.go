//
// Copyright (c) 2023 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"testing"
)

var inputSizeTests = []struct {
	inputs []string
	sizes  []int
}{
	{
		inputs: []string{
			"0", "f", "false", "1", "t", "true",
		},
		sizes: []int{
			1, 1, 1, 1, 1, 1,
		},
	},
	{
		inputs: []string{
			"0xdeadbeef", "255",
		},
		sizes: []int{
			32, 8,
		},
	},
	{
		inputs: []string{
			"0x0", "0x00", "0x000", "0x0000",
		},
		sizes: []int{
			4, 8, 12, 16,
		},
	},
}

func TestInputSizes(t *testing.T) {
	for idx, test := range inputSizeTests {
		sizes, err := InputSizes(test.inputs)
		if err != nil {
			t.Errorf("t%v: InputSizes(%v) failed: %v", idx, test.inputs, err)
			continue
		}
		if len(sizes) != len(test.sizes) {
			t.Errorf("t%v: unexpected # of sizes: got %v, expected %v",
				idx, len(sizes), len(test.sizes))
			continue
		}
		for i := 0; i < len(sizes); i++ {
			if sizes[i] != test.sizes[i] {
				t.Errorf("t%v: sizes[%v]=%v, expected %v",
					idx, i, sizes[i], test.sizes[i])
			}
		}
	}
}
