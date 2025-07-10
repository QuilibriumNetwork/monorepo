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

type int64Test struct {
	a int64
	b int64
	r int64
}

var add64Tests = []int64Test{
	{
		a: 0x0000ffff,
		b: 0x00000001,
		r: 0x00010000,
	},
	{
		a: 0x0000ffff,
		b: -1,
		r: 0x0000fffe,
	},
	{
		a: math.MaxInt64,
		b: 1,
		r: math.MinInt64,
	},
	{
		a: math.MinInt64,
		b: -1,
		r: math.MaxInt64,
	},
	{
		a: math.MinInt64,
		b: 1,
		r: math.MinInt64 + 1,
	},
}

func TestInt64Add(t *testing.T) {
	for idx, test := range add64Tests {
		a := NewInt(test.a, 64)
		b := NewInt(test.b, 64)
		r := New(64).Add(a, b)
		if r.Int64() != test.r {
			t.Errorf("add%v: %v+%v=%v, expected %v\n",
				idx, test.a, test.b, r.Int64(), test.r)
		}
	}
}

var and64Tests = []int64Test{
	{
		a: 0x0000ffff,
		b: 0x00001111,
		r: 0x00001111,
	},
	{
		a: 0x0000ffff,
		b: 0x00000000,
		r: 0x00000000,
	},
}

func TestInt64And(t *testing.T) {
	for _, test := range and64Tests {
		a := NewInt(test.a, 64)
		b := NewInt(test.b, 64)
		r := New(64).And(a, b)
		if r.Int64() != test.r {
			t.Errorf("%v&%v=%v, expected %v\n",
				test.a, test.b, r.Int64(), test.r)
		}
	}
}

func TestInt64Cmp(t *testing.T) {
	a := NewInt(1, 64)
	b := NewInt(1, 64)
	a.Sub(a, b)
	a.Sub(a, b)

	c := NewInt(0, 64)
	cmp := a.Cmp(c)
	if cmp >= 0 {
		t.Errorf("%v.Cmp(%v)=%v\n", a.Int64(), c.Int64(), cmp)
	}
}

var div64Tests = []int64Test{
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

func TestInt64Div(t *testing.T) {
	for _, test := range div64Tests {
		a := NewInt(test.a, 0)
		b := NewInt(test.b, 0)
		r := New(64).Div(a, b)
		if r.Int64() != test.r {
			t.Errorf("%v/%v=%v, expected %v\n",
				test.a, test.b, r.Int64(), test.r)
		}
	}
}

var lsh64Tests = []int64Test{
	{
		a: 0x0000ffff,
		b: 1,
		r: 0x0001fffe,
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
		b: 63,
		r: -9223372036854775808,
	},
}

func TestInt64Lsh(t *testing.T) {
	for _, test := range lsh64Tests {
		a := NewInt(test.a, 64)
		r := New(64).Lsh(a, uint(test.b))
		if r.Int64() != test.r {
			t.Errorf("%v<<%v=%v(%x), expected %v\n",
				test.a, test.b, r.Int64(), r.Int64(), test.r)
		}
	}
}

var mod64Tests = []int64Test{
	{
		a: 0x0000ffff,
		b: 0x00001111,
		r: 0,
	},
	{
		a: 0x0000ffff,
		b: 0x00000000,
		r: 0x0000ffff,
	},
	{
		a: 10,
		b: 2,
		r: 0,
	},
}

func TestInt64Mod(t *testing.T) {
	for _, test := range mod64Tests {
		a := NewInt(test.a, 64)
		b := NewInt(test.b, 64)
		r := New(64).Mod(a, b)
		if r.Int64() != test.r {
			t.Errorf("%v%%%v=%v, expected %v\n",
				test.a, test.b, r.Int64(), test.r)
		}
	}
}

var mul64Tests = []int64Test{
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
		a: 0x7fffffffffffffff,
		b: 2,
		r: -2,
	},
	{
		a: 0x7fffffffffffffff,
		b: 0x00000000ffffffff,
		r: 0x7fffffff00000001,
	},
}

func TestInt64Mul(t *testing.T) {
	for _, test := range mul64Tests {
		a := NewInt(test.a, 64)
		b := NewInt(test.b, 64)
		r := New(64).Mul(a, b)
		if r.Int64() != test.r {
			t.Errorf("%v*%v=%v, expected %v\n",
				test.a, test.b, r.Int64(), test.r)
		}
	}
}

var or64Tests = []int64Test{
	{
		a: 0x0000ffff,
		b: 0x00001111,
		r: 0x0000ffff,
	},
	{
		a: 0x0000ffff,
		b: 0x00000000,
		r: 0x0000ffff,
	},
	{
		a: 10,
		b: 2,
		r: 10,
	},
	{
		a: 0x7fffffffffffffff,
		b: 2,
		r: 0x7fffffffffffffff,
	},
	{
		a: 0x0555555555555555,
		b: 0x0aaaaaaaaaaaaaaa,
		r: 0x0fffffffffffffff,
	},
}

func TestInt64Or(t *testing.T) {
	for _, test := range or64Tests {
		a := NewInt(test.a, 64)
		b := NewInt(test.b, 64)
		r := New(64).Or(a, b)
		if r.Int64() != test.r {
			t.Errorf("%v|%v=%v, expected %x\n",
				test.a, test.b, r.Int64(), test.r)
		}
	}
}

var rsh64Tests = []int64Test{
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
		b: 63,
		r: 0,
	},
}

func TestInt64Rsh(t *testing.T) {
	for _, test := range rsh64Tests {
		a := NewInt(test.a, 64)
		r := New(64).Rsh(a, uint(test.b))
		if r.Int64() != test.r {
			t.Errorf("%v>>%v=%v(%x), expected %v\n",
				test.a, test.b, r.Int64(), r.Int64(), test.r)
		}
	}
}

func TestIntSetString(t *testing.T) {
	i, ok := Parse("0xdeadbeef", 0)
	if !ok {
		t.Fatalf("SetString failed")
	}
	if i.Int64() != 0xdeadbeef {
		t.Errorf("SetString returned unexpected value")
	}
}

var sub64Tests = []int64Test{
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
		a: math.MaxInt64,
		b: -1,
		r: math.MinInt64,
	},
	{
		a: math.MinInt64,
		b: 1,
		r: math.MaxInt64,
	},
	{
		a: math.MaxInt64,
		b: 1,
		r: math.MaxInt64 - 1,
	},
	{
		a: 0,
		b: 5,
		r: -5,
	},
}

func TestInt64Sub(t *testing.T) {
	for idx, test := range sub64Tests {
		a := NewInt(test.a, 64)
		b := NewInt(test.b, 64)
		r := New(64).Sub(a, b)
		if r.Int64() != test.r {
			t.Errorf("test-%v: %v-%v=%v, expected %v\n",
				idx, test.a, test.b, r.Int64(), test.r)
		}
	}
}

func TestIntSubNegative(t *testing.T) {
	val := NewInt(5, 64)
	r := NewInt(0, 64)
	r.Sub(r, val)

	add := NewInt(10, 64)
	r.Add(r, add)
	result := r.Int64()
	if result != 5 {
		t.Errorf("TestIntSubNegative: +10 failed, got %v", result)
	}
}

var xor64Tests = []int64Test{
	{
		a: 0x0000ffff,
		b: 0x00001111,
		r: 0x0000eeee,
	},
	{
		a: 0x0000ffff,
		b: 0x00000000,
		r: 0x0000ffff,
	},
	{
		a: 10,
		b: 2,
		r: 8,
	},
	{
		a: 0x7fffffffffffffff,
		b: 2,
		r: 0x7ffffffffffffffd,
	},
	{
		a: 0x0555555555555555,
		b: 0x0aaaaaaaaaaaaaaa,
		r: 0x0fffffffffffffff,
	},
}

func TestInt64Xor(t *testing.T) {
	for _, test := range xor64Tests {
		a := NewInt(test.a, 64)
		b := NewInt(test.b, 64)
		r := New(64).Xor(a, b)
		if r.Int64() != test.r {
			t.Errorf("%v^%v=%v, expected %x\n",
				test.a, test.b, r.Int64(), test.r)
		}
	}
}
