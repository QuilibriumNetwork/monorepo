//
// Copyright (c) 2020-2023 Markku Rossi
//
// All rights reserved.
//

package circuits

import (
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
)

// NewMUX creates a multiplexer circuit that selects the input t or f
// to output, based on the value of the condition cond.
func NewMUX(cc *Compiler, cond, t, f, out []*Wire) error {
	t, f = cc.ZeroPad(t, f)
	if len(cond) != 1 || len(t) != len(f) || len(t) != len(out) {
		return fmt.Errorf("invalid mux arguments: cond=%d, l=%d, r=%d, out=%d",
			len(cond), len(t), len(f), len(out))
	}

	for i := 0; i < len(t); i++ {
		w1 := cc.Calloc.Wire()
		w2 := cc.Calloc.Wire()

		// w1 = XOR(f[i], t[i])
		cc.AddGate(cc.Calloc.BinaryGate(circuit.XOR, f[i], t[i], w1))

		// w2 = AND(w1, cond)
		cc.AddGate(cc.Calloc.BinaryGate(circuit.AND, w1, cond[0], w2))

		// out[i] = XOR(w2, f[i])
		cc.AddGate(cc.Calloc.BinaryGate(circuit.XOR, w2, f[i], out[i]))
	}

	return nil
}
