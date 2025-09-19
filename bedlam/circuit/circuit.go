//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"fmt"
	"io"
	"math"

	"github.com/markkurossi/tabulate"
)

// Operation specifies gate function.
type Operation byte

// Gate functions.
const (
	XOR Operation = iota
	XNOR
	AND
	OR
	INV
	Count
	NumLevels
	MaxWidth
)

// Known multi-party computation roles.
const (
	IDGarbler int = iota
	IDEvaluator
)

// Stats holds statistics about circuit operations.
type Stats [MaxWidth + 1]uint64

// Add adds the argument statistics to this statistics object.
func (stats *Stats) Add(o Stats) {
	for i := XOR; i < Count; i++ {
		stats[i] += o[i]
	}
	stats[Count]++

	for i := NumLevels; i <= MaxWidth; i++ {
		if o[i] > stats[i] {
			stats[i] = o[i]
		}
	}
}

// Count returns the number of gates in the statistics object.
func (stats Stats) Count() uint64 {
	var result uint64
	for i := XOR; i < Count; i++ {
		result += stats[i]
	}
	return result
}

// Cost computes the relative computational cost of the circuit.
func (stats Stats) Cost() uint64 {
	return (stats[AND]+stats[INV])*2 + stats[OR]*3
}

func (stats Stats) String() string {
	var result string

	for i := XOR; i < Count; i++ {
		v := stats[i]
		if len(result) > 0 {
			result += " "
		}
		result += fmt.Sprintf("%s=%d", i, v)
	}
	result += fmt.Sprintf(" xor=%d", stats[XOR]+stats[XNOR])
	result += fmt.Sprintf(" !xor=%d", stats[AND]+stats[OR]+stats[INV])
	result += fmt.Sprintf(" levels=%d", stats[NumLevels])
	result += fmt.Sprintf(" width=%d", stats[MaxWidth])
	return result
}

func (op Operation) String() string {
	switch op {
	case XOR:
		return "XOR"
	case XNOR:
		return "XNOR"
	case AND:
		return "AND"
	case OR:
		return "OR"
	case INV:
		return "INV"
	case Count:
		return "#"
	default:
		return fmt.Sprintf("{Operation %d}", op)
	}
}

// Circuit specifies a boolean circuit.
type Circuit struct {
	NumGates int
	NumWires int
	Inputs   IO
	Outputs  IO
	Gates    []Gate
	Stats    Stats
}

func (c *Circuit) String() string {
	return fmt.Sprintf("#gates=%d (%s) #w=%d", c.NumGates, c.Stats, c.NumWires)
}

// NumParties returns the number of parties needed for the circuit.
func (c *Circuit) NumParties() int {
	return len(c.Inputs)
}

// PrintInputs prints the circuit inputs.
func (c *Circuit) PrintInputs(id int, input []string) {
	for i := 0; i < len(c.Inputs); i++ {
		if i == id {
			fmt.Print(" + ")
		} else {
			fmt.Print(" - ")
		}
		fmt.Printf("In%d: %s\n", i, c.Inputs[i])
	}
	fmt.Printf(" - Out: %s\n", c.Outputs)
	fmt.Printf(" -  In: %s\n", input)
}

// TabulateStats prints the circuit stats as a table to the specified
// output Writer.
func (c *Circuit) TabulateStats(out io.Writer) {
	tab := tabulate.New(tabulate.UnicodeLight)
	tab.Header("XOR").SetAlign(tabulate.MR)
	tab.Header("XNOR").SetAlign(tabulate.MR)
	tab.Header("AND").SetAlign(tabulate.MR)
	tab.Header("OR").SetAlign(tabulate.MR)
	tab.Header("INV").SetAlign(tabulate.MR)
	tab.Header("Gates").SetAlign(tabulate.MR)
	tab.Header("XOR").SetAlign(tabulate.MR)
	tab.Header("!XOR").SetAlign(tabulate.MR)
	tab.Header("Wires").SetAlign(tabulate.MR)

	c.TabulateRow(tab.Row())
	tab.Print(out)
}

// TabulateRow tabulates circuit statistics to the argument tabulation
// row.
func (c *Circuit) TabulateRow(row *tabulate.Row) {
	var sumGates uint64
	for op := XOR; op < Count; op++ {
		row.Column(fmt.Sprintf("%v", c.Stats[op]))
		sumGates += c.Stats[op]
	}
	row.Column(fmt.Sprintf("%v", sumGates))
	row.Column(fmt.Sprintf("%v", c.Stats[XOR]+c.Stats[XNOR]))
	row.Column(fmt.Sprintf("%v", c.Stats[AND]+c.Stats[OR]+c.Stats[INV]))
	row.Column(fmt.Sprintf("%v", c.NumWires))
}

// Cost computes the relative computational cost of the circuit.
func (c *Circuit) Cost() uint64 {
	return c.Stats.Cost()
}

// Dump prints a debug dump of the circuit.
func (c *Circuit) Dump() {
	fmt.Printf("circuit %s\n", c)
	for id, gate := range c.Gates {
		fmt.Printf("%04d\t%s\n", id, gate)
	}
}

// AssignLevels assigns levels for gates. The level desribes how many
// steps away the gate is from input wires.
func (c *Circuit) AssignLevels() {
	levels := make([]Level, c.NumWires)
	countByLevel := make([]uint32, c.NumWires)

	var max Level

	for idx, gate := range c.Gates {
		level := levels[gate.Input0]
		if gate.Op != INV {
			l1 := levels[gate.Input1]
			if l1 > level {
				level = l1
			}
		}
		c.Gates[idx].Level = level
		countByLevel[level]++

		level++

		levels[gate.Output] = level
		if level > max {
			max = level
		}
	}
	c.Stats[NumLevels] = uint64(max)

	var maxWidth uint32
	for _, count := range countByLevel {
		if count > maxWidth {
			maxWidth = count
		}
	}
	if false {
		for i := 0; i < int(max); i++ {
			fmt.Printf("%v,%v\n", i, countByLevel[i])
		}
	}

	c.Stats[MaxWidth] = uint64(maxWidth)
}

// Level defines gate's distance from input wires.
type Level uint32

// Gate specifies a boolean gate.
type Gate struct {
	Input0 Wire
	Input1 Wire
	Output Wire
	Op     Operation
	Level  Level
}

func (g Gate) String() string {
	return fmt.Sprintf("%v %v %v", g.Inputs(), g.Op, g.Output)
}

// Inputs returns gate input wires.
func (g Gate) Inputs() []Wire {
	switch g.Op {
	case XOR, XNOR, AND, OR:
		return []Wire{g.Input0, g.Input1}
	case INV:
		return []Wire{g.Input0}
	default:
		panic(fmt.Sprintf("unsupported gate type %s", g.Op))
	}
}

// Wire specifies a wire ID.
type Wire uint32

// InvalidWire specifies an invalid wire ID.
const InvalidWire Wire = math.MaxUint32

// Int returns the wire ID as integer.
func (w Wire) Int() int {
	if uint64(w) > math.MaxInt {
		panic(w)
	}
	return int(w)
}

func (w Wire) String() string {
	return fmt.Sprintf("w%d", w)
}
