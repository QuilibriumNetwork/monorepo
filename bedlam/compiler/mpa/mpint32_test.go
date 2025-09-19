//
// Copyright (c) 2023 Markku Rossi
//
// All rights reserved.
//

package mpa

import (
	"math"
	"testing"
)

type int32Test struct {
	a int64
	b int64
	r int64
}

var add32Tests = []int32Test{
	{
		a: math.MaxInt32,
		b: 0x00000001,
		r: math.MinInt32,
	},
	{
		a: 0x7fffffff,
		b: 0x7fffffff,
		r: -2,
	},
	{
		a: 0,
		b: -1,
		r: -1,
	},
}

func TestInt32Add(t *testing.T) {
	for idx, test := range add32Tests {
		a := NewInt(test.a, 32)
		b := NewInt(test.b, 32)
		r := New(32).Add(a, b)
		if r.Int64() != test.r {
			t.Errorf("TestInt32Add-%v: %v+%v=%v, expected %v\n",
				idx, test.a, test.b, r.Int64(), test.r)
		}
	}
}

var div32Tests = []int32Test{
	{
		a: 0x0000ffff,
		b: 0x00001111,
		r: 0x0000000f,
	},
	{
		a: 0x0000ffff,
		b: 0x00000000,
		r: -1,
	},
	{
		a: 10,
		b: 2,
		r: 5,
	},
}

func TestInt32Div(t *testing.T) {
	for _, test := range div32Tests {
		a := NewInt(test.a, 32)
		b := NewInt(test.b, 32)
		r := New(32).Div(a, b)
		if r.Int64() != test.r {
			t.Errorf("%v/%v=%v, expected %v\n",
				test.a, test.b, r.Int64(), test.r)
		}
	}
}

var lsh32Tests = []int32Test{
	{
		a: 0x0000ffff,
		b: 1,
		r: 0x0001fffe,
	},
	{
		a: 0x7fffffff,
		b: 1,
		r: -2,
	},
	{
		a: 0x0000ffff,
		b: 0x00000000,
		r: 0x0000ffff,
	},
	{
		a: 10,
		b: 2,
		r: 40,
	},
	{
		a: 1,
		b: 31,
		r: -2147483648,
	},
}

func TestInt32Lsh(t *testing.T) {
	for idx, test := range lsh32Tests {
		a := NewInt(test.a, 32)
		r := New(32).Lsh(a, uint(test.b))
		if r.Int64() != test.r {
			t.Errorf("TestInt32Lsh-%v: %v<<%v=%v(%x), expected %v\n",
				idx, test.a, test.b, r.Int64(), r.Int64(), test.r)
		}
	}
}

var mul32Tests = []int32Test{
	{
		a: 0x0000ffff,
		b: 0x00001111,
		r: 0x1110eeef,
	},
	{
		a: 0x0000ffff,
		b: 0x00000000,
		r: 0x00000000,
	},
	{
		a: 10,
		b: 2,
		r: 20,
	},
	{
		a: 0x7fffffff,
		b: 2,
		r: -2,
	},
	{
		a: 0x7fffffff,
		b: 0x0000ffff,
		r: 0x7fff0001,
	},
}

func TestInt32Mul(t *testing.T) {
	for idx, test := range mul32Tests {
		a := NewInt(test.a, 32)
		b := NewInt(test.b, 32)
		r := New(32).Mul(a, b)
		if r.Int64() != test.r {
			t.Errorf("TestInt32Mul-%v: %v*%v=%v, expected %v\n",
				idx, test.a, test.b, r.Int64(), test.r)
		}
	}
}

var rsh32Tests = []int32Test{
	{
		a: 0x0000ffff,
		b: 1,
		r: 0x00007fff,
	},
	{
		a: 0x0000ffff,
		b: 0x00000000,
		r: 0x0000ffff,
	},
	{
		a: 10,
		b: 2,
		r: 2,
	},
	{
		a: 1,
		b: 31,
		r: 0,
	},
}

func TestInt32Rsh(t *testing.T) {
	for _, test := range rsh32Tests {
		a := NewInt(test.a, 32)
		r := New(32).Rsh(a, uint(test.b))
		if r.Int64() != test.r {
			t.Errorf("%v>>%v=%v(%x), expected %v\n",
				test.a, test.b, r.Int64(), r.Int64(), test.r)
		}
	}
}

var sub32Tests = []int32Test{
	{
		a: 0x00010000,
		b: 0x00000001,
		r: 0x0000ffff,
	},
	{
		a: 0x0000ffff,
		b: -1,
		r: 0x00010000,
	},
	{
		a: math.MaxInt32,
		b: -1,
		r: math.MinInt32,
	},
	{
		a: math.MinInt32,
		b: 1,
		r: math.MaxInt32,
	},
	{
		a: math.MaxInt32,
		b: 1,
		r: math.MaxInt32 - 1,
	},
	{
		a: 0,
		b: 5,
		r: -5,
	},
}

func TestInt32Sub(t *testing.T) {
	for idx, test := range sub32Tests {
		a := NewInt(test.a, 32)
		b := NewInt(test.b, 32)
		r := New(32).Sub(a, b)
		if r.Int64() != test.r {
			t.Errorf("TestInt32Sub-%v: %v-%v=%v, expected %v\n",
				idx, test.a, test.b, r.Int64(), test.r)
		}
	}
}

func TestInt32SubMaxInt32(t *testing.T) {
	a := NewInt(math.MaxInt32, 32)
	b := NewInt(1, 32)
	r := New(32).Sub(a, b)
	if r.Int64() != int64(math.MaxInt32-1) {
		t.Errorf("%v-%v=%v, expected %v\n", a, b, r, math.MaxInt32-1)
	}
}
