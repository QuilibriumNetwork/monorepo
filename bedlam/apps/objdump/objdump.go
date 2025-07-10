//
// main.go
//
// Copyright (c) 2019-2022 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"os"

	"github.com/markkurossi/tabulate"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
)

func dumpObjects(files []string) error {
	type oCircuit struct {
		name    string
		circuit *circuit.Circuit
	}
	var circuits []oCircuit

	for _, file := range files {
		if circuit.IsFilename(file) {
			c, err := circuit.Parse(file)
			if err != nil {
				return err
			}
			circuits = append(circuits, oCircuit{
				name:    file,
				circuit: c,
			})
		}
	}

	if len(circuits) > 0 {
		tab := tabulate.New(tabulate.Github)
		tab.Header("File")
		tab.Header("XOR").SetAlign(tabulate.MR)
		tab.Header("XNOR").SetAlign(tabulate.MR)
		tab.Header("AND").SetAlign(tabulate.MR)
		tab.Header("OR").SetAlign(tabulate.MR)
		tab.Header("INV").SetAlign(tabulate.MR)
		tab.Header("Gates").SetAlign(tabulate.MR)
		tab.Header("xor").SetAlign(tabulate.MR)
		tab.Header("!xor").SetAlign(tabulate.MR)
		tab.Header("Wires").SetAlign(tabulate.MR)

		for _, c := range circuits {
			row := tab.Row()
			row.Column(c.name)
			c.circuit.TabulateRow(row)
		}

		tab.Print(os.Stdout)
	}

	return nil
}
