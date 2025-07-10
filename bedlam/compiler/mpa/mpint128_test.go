//
// Copyright (c) 2023 Markku Rossi
//
// All rights reserved.
//

package mpa

import (
	"testing"
)

type int128Test struct {
	a int64
	b int64
	r string
}

var lsh128Tests = []int128Test{
	{
		a: 1,
		b: 64,
		r: "10000000000000000",
	},
	{
		a: 1,
		b: 128,
		r: "0",
	},
}

func TestInt128Lsh(t *testing.T) {
	for _, test := range lsh128Tests {
		a := NewInt(test.a, 128)
		r := New(128).Lsh(a, uint(test.b))
		result := r.Text(16)
		if result != test.r {
			t.Errorf("TestInt128Lsh: got %v, expected %v", result, test.r)
		}
	}
}
