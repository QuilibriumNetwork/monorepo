//
// main.go
//
// Copyright (c) 2019-2022 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"flag"
	"fmt"
	"log"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
)

func main() {
	flag.Parse()

	for _, file := range flag.Args() {
		c, err := circuit.Parse(file)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("digraph circuit\n{\n")
		fmt.Printf("  overlap=scale;\n")
		fmt.Printf("  node\t[fontname=\"Helvetica\"];\n")
		fmt.Printf("  {\n    node [shape=plaintext];\n")
		for w := 0; w < c.NumWires; w++ {
			fmt.Printf("    w%d\t[label=\"%d\"];\n", w, w)
		}
		fmt.Printf("  }\n")

		fmt.Printf("  {\n    node [shape=box];\n")
		for idx, gate := range c.Gates {
			fmt.Printf("    g%d\t[label=\"%s\"];\n", idx, gate.Op)
		}
		fmt.Printf("  }\n")

		if true {
			fmt.Printf("  {  rank=same")
			for w := 0; w < c.Inputs.Size(); w++ {
				fmt.Printf("; w%d", w)
			}
			fmt.Printf(";}\n")

			fmt.Printf("  {  rank=same")
			for w := 0; w < c.Outputs.Size(); w++ {
				fmt.Printf("; w%d", c.NumWires-w-1)
			}
			fmt.Printf(";}\n")
		}

		for idx, gate := range c.Gates {
			for _, i := range gate.Inputs() {
				fmt.Printf("  w%d -> g%d;\n", i, idx)
			}
			fmt.Printf("  g%d -> w%d;\n", idx, gate.Output)
		}
		fmt.Printf("}\n")
	}
}
