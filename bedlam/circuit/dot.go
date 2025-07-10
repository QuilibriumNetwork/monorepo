//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"fmt"
	"io"
)

// Dot creates graphviz dot output of the circuit.
func (c *Circuit) Dot(out io.Writer) {
	fmt.Fprintf(out, "digraph circuit\n{\n")
	fmt.Fprintf(out, "  overlap=scale;\n")
	fmt.Fprintf(out, "  node\t[fontname=\"Helvetica\"];\n")
	fmt.Fprintf(out, "  {\n    node [shape=plaintext];\n")
	for w := 0; w < c.NumWires; w++ {
		fmt.Fprintf(out, "    w%d\t[label=\"%d\"];\n", w, w)
	}
	fmt.Fprintf(out, "  }\n")

	fmt.Fprintf(out, "  {\n    node [shape=box];\n")
	for idx, gate := range c.Gates {
		fmt.Fprintf(out, "    g%d\t[label=\"%s\"];\n", idx, gate.Op)
	}
	fmt.Fprintf(out, "  }\n")

	if true {
		fmt.Fprintf(out, "  {  rank=same")
		var numInputs int
		for _, input := range c.Inputs {
			numInputs += int(input.Type.Bits)
		}
		for w := 0; w < numInputs; w++ {
			fmt.Fprintf(out, "; w%d", w)
		}
		fmt.Fprintf(out, ";}\n")

		fmt.Fprintf(out, "  {  rank=same")
		for w := 0; w < c.Outputs.Size(); w++ {
			fmt.Fprintf(out, "; w%d", c.NumWires-w-1)
		}
		fmt.Fprintf(out, ";}\n")
	}

	for idx, gate := range c.Gates {
		for _, i := range gate.Inputs() {
			fmt.Fprintf(out, "  w%d -> g%d;\n", i, idx)
		}
		fmt.Fprintf(out, "  g%d -> w%d;\n", idx, gate.Output)
	}
	fmt.Fprintf(out, "}\n")
}
