//
// circ_subtractor.go
//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package circuits

import (
	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
)

// NewFullSubtractor creates a full subtractor circuit.
func NewFullSubtractor(cc *Compiler, x, y, cin, d, cout *Wire) {
	w1 := cc.Calloc.Wire()
	cc.AddGate(cc.Calloc.BinaryGate(circuit.XNOR, y, cin, w1))
	cc.AddGate(cc.Calloc.BinaryGate(circuit.XNOR, x, w1, d))

	if cout != nil {
		w2 := cc.Calloc.Wire()
		cc.AddGate(cc.Calloc.BinaryGate(circuit.XOR, x, cin, w2))

		w3 := cc.Calloc.Wire()
		cc.AddGate(cc.Calloc.BinaryGate(circuit.AND, w1, w2, w3))

		cc.AddGate(cc.Calloc.BinaryGate(circuit.XOR, w3, cin, cout))
	}
}

// NewSubtractor creates a new subtractor circuit implementing z=x-y.
func NewSubtractor(cc *Compiler, x, y, z []*Wire) error {
	x, y = cc.ZeroPad(x, y)
	if len(x) > len(z) {
		x = x[0:len(z)]
		y = y[0:len(z)]
	}
	cin := cc.ZeroWire()

	for i := 0; i < len(x); i++ {
		var cout *Wire
		if i+1 >= len(x) {
			if i+1 >= len(z) {
				// N-N=N, overflow, drop carry bit.
				cout = nil
			} else {
				cout = z[i+1]
			}
		} else {
			cout = cc.Calloc.Wire()
		}

		// Note y-x here.
		NewFullSubtractor(cc, y[i], x[i], cin, z[i], cout)

		cin = cout
	}
	for i := len(x) + 1; i < len(z); i++ {
		z[i] = cc.ZeroWire()
	}
	return nil
}
