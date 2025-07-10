//
// Copyright (c) 2021 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"fmt"
)

// Analyze identifies potential optimizations for the circuit.
func (c *Circuit) Analyze() {
	fmt.Printf("analyzing circuit %v\n", c)

	from := make([][]Gate, c.NumWires)
	to := make([][]Gate, c.NumWires)

	// Collect wire inputs and outputs.
	for _, g := range c.Gates {
		switch g.Op {
		case XOR, XNOR, AND, OR:
			to[g.Input1] = append(to[g.Input1], g)
			fallthrough

		case INV:
			to[g.Input0] = append(to[g.Input0], g)
			from[g.Output] = append(to[g.Output], g)
		}
	}

	// INV gates as single output of input gate.
	for _, g := range c.Gates {
		if g.Op != INV {
			continue
		}
		if len(to[g.Input0]) == 1 && len(from[g.Input0]) == 1 {
			fmt.Printf("%v -> %v\n", from[g.Input0][0].Op, g.Op)
		}
	}
}
