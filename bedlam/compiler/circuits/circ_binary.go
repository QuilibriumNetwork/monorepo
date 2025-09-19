//
// Copyright (c) 2020-2021, 2023 Markku Rossi
//
// All rights reserved.
//

package circuits

import (
	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
)

// NewBinaryAND creates a new binary AND circuit implementing r=x&y
func NewBinaryAND(cc *Compiler, x, y, r []*Wire) error {
	x, y = cc.ZeroPad(x, y)
	if len(r) < len(x) {
		x = x[0:len(r)]
		y = y[0:len(r)]
	}
	for i := 0; i < len(x); i++ {
		cc.AddGate(cc.Calloc.BinaryGate(circuit.AND, x[i], y[i], r[i]))
	}
	return nil
}

// NewBinaryClear creates a new binary clear circuit implementing r=x&^y.
func NewBinaryClear(cc *Compiler, x, y, r []*Wire) error {
	x, y = cc.ZeroPad(x, y)
	if len(r) < len(x) {
		x = x[0:len(r)]
		y = y[0:len(r)]
	}
	for i := 0; i < len(x); i++ {
		w := cc.Calloc.Wire()
		cc.INV(y[i], w)
		cc.AddGate(cc.Calloc.BinaryGate(circuit.AND, x[i], w, r[i]))
	}
	return nil
}

// NewBinaryOR creates a new binary OR circuit implementing r=x|y.
func NewBinaryOR(cc *Compiler, x, y, r []*Wire) error {
	x, y = cc.ZeroPad(x, y)
	if len(r) < len(x) {
		x = x[0:len(r)]
		y = y[0:len(r)]
	}
	for i := 0; i < len(x); i++ {
		cc.AddGate(cc.Calloc.BinaryGate(circuit.OR, x[i], y[i], r[i]))
	}
	return nil
}

// NewBinaryXOR creates a new binary XOR circuit implementing r=x^y.
func NewBinaryXOR(cc *Compiler, x, y, r []*Wire) error {
	x, y = cc.ZeroPad(x, y)
	if len(r) < len(x) {
		x = x[0:len(r)]
		y = y[0:len(r)]
	}
	for i := 0; i < len(x); i++ {
		cc.AddGate(cc.Calloc.BinaryGate(circuit.XOR, x[i], y[i], r[i]))
	}
	return nil
}
