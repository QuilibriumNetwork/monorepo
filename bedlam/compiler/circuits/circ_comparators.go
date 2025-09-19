//
// Copyright (c) 2020-2023 Markku Rossi
//
// All rights reserved.
//

package circuits

import (
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

// comparator tests if x>y if cin=0, and x>=y if cin=1.
func comparator(cc *Compiler, cin *Wire, x, y, r []*Wire) error {
	x, y = cc.ZeroPad(x, y)
	if len(r) != 1 {
		return fmt.Errorf("invalid lt comparator arguments: r=%d", len(r))
	}

	for i := 0; i < len(x); i++ {
		w1 := cc.Calloc.Wire()
		cc.AddGate(cc.Calloc.BinaryGate(circuit.XNOR, cin, y[i], w1))
		w2 := cc.Calloc.Wire()
		cc.AddGate(cc.Calloc.BinaryGate(circuit.XOR, cin, x[i], w2))
		w3 := cc.Calloc.Wire()
		cc.AddGate(cc.Calloc.BinaryGate(circuit.AND, w1, w2, w3))

		var cout *Wire
		if i+1 < len(x) {
			cout = cc.Calloc.Wire()
		} else {
			cout = r[0]
		}
		cc.AddGate(cc.Calloc.BinaryGate(circuit.XOR, cin, w3, cout))
		cin = cout
	}
	return nil
}

// NewGtComparator tests if x>y.
func NewGtComparator(cc *Compiler, x, y, r []*Wire) error {
	return comparator(cc, cc.ZeroWire(), x, y, r)
}

// NewGeComparator tests if x>=y.
func NewGeComparator(cc *Compiler, x, y, r []*Wire) error {
	return comparator(cc, cc.OneWire(), x, y, r)
}

// NewLtComparator tests if x<y.
func NewLtComparator(cc *Compiler, x, y, r []*Wire) error {
	return comparator(cc, cc.ZeroWire(), y, x, r)
}

// NewLeComparator tests if x<=y.
func NewLeComparator(cc *Compiler, x, y, r []*Wire) error {
	return comparator(cc, cc.OneWire(), y, x, r)
}

// NewNeqComparator tewsts if x!=y.
func NewNeqComparator(cc *Compiler, x, y, r []*Wire) error {
	x, y = cc.ZeroPad(x, y)
	if len(r) != 1 {
		return fmt.Errorf("invalid neq comparator arguments: r=%d", len(r))
	}

	if len(x) == 1 {
		cc.AddGate(cc.Calloc.BinaryGate(circuit.XOR, x[0], y[0], r[0]))
		return nil
	}

	c := cc.Calloc.Wire()
	cc.AddGate(cc.Calloc.BinaryGate(circuit.XOR, x[0], y[0], c))

	for i := 1; i < len(x); i++ {
		xor := cc.Calloc.Wire()
		cc.AddGate(cc.Calloc.BinaryGate(circuit.XOR, x[i], y[i], xor))

		var out *Wire
		if i+1 >= len(x) {
			out = r[0]
		} else {
			out = cc.Calloc.Wire()
		}
		cc.AddGate(cc.Calloc.BinaryGate(circuit.OR, c, xor, out))
		c = out
	}
	return nil
}

// NewEqComparator tests if x==y.
func NewEqComparator(cc *Compiler, x, y, r []*Wire) error {
	if len(r) != 1 {
		return fmt.Errorf("invalid eq comparator arguments: r=%d", len(r))
	}

	// w = x == y
	w := cc.Calloc.Wire()
	err := NewNeqComparator(cc, x, y, []*Wire{w})
	if err != nil {
		return err
	}
	// r = !w
	cc.INV(w, r[0])
	return nil
}

// NewLogicalAND implements logical AND implementing r=x&y. The input
// and output wires must be 1 bit wide.
func NewLogicalAND(cc *Compiler, x, y, r []*Wire) error {
	if len(x) != 1 || len(y) != 1 || len(r) != 1 {
		return fmt.Errorf("invalid logical and arguments: x=%d, y=%d, r=%d",
			len(x), len(y), len(r))
	}
	cc.AddGate(cc.Calloc.BinaryGate(circuit.AND, x[0], y[0], r[0]))
	return nil
}

// NewLogicalOR implements logical OR implementing r=x|y.  The input
// and output wires must be 1 bit wide.
func NewLogicalOR(cc *Compiler, x, y, r []*Wire) error {
	if len(x) != 1 || len(y) != 1 || len(r) != 1 {
		return fmt.Errorf("invalid logical or arguments: x=%d, y=%d, r=%d",
			len(x), len(y), len(r))
	}
	cc.AddGate(cc.Calloc.BinaryGate(circuit.OR, x[0], y[0], r[0]))
	return nil
}

// NewBitSetTest tests if the index'th bit of x is set.
func NewBitSetTest(cc *Compiler, x []*Wire, index types.Size, r []*Wire) error {
	if len(r) != 1 {
		return fmt.Errorf("invalid bit set test arguments: x=%d, r=%d",
			len(x), len(r))
	}
	if index < types.Size(len(x)) {
		w := cc.ZeroWire()
		cc.AddGate(cc.Calloc.BinaryGate(circuit.XOR, x[index], w, r[0]))
	} else {
		r[0] = cc.ZeroWire()
	}
	return nil
}

// NewBitClrTest tests if the index'th bit of x is unset.
func NewBitClrTest(cc *Compiler, x []*Wire, index types.Size, r []*Wire) error {
	if len(r) != 1 {
		return fmt.Errorf("invalid bit clear test arguments: x=%d, r=%d",
			len(x), len(r))
	}
	if index < types.Size(len(x)) {
		w := cc.OneWire()
		cc.AddGate(cc.Calloc.BinaryGate(circuit.XOR, x[index], w, r[0]))
	} else {
		r[0] = cc.OneWire()
	}
	return nil
}
