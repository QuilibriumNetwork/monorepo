//
// gates.go
//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package circuits

import (
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
)

// Gate implements binary gates.
type Gate struct {
	Op       circuit.Operation
	Visited  bool
	Compiled bool
	Dead     bool
	A        *Wire
	B        *Wire
	O        *Wire
}

func (g *Gate) String() string {
	return fmt.Sprintf("%s %x %x %x", g.Op, g.A.ID(), g.B.ID(), g.O.ID())
}

// Visit adds gate to the list of pending gates to be compiled.
func (g *Gate) Visit(cc *Compiler) {
	switch g.Op {
	case circuit.INV:
		if !g.Dead && !g.Visited && g.A.Assigned() {
			g.Visited = true
			cc.pending = append(cc.pending, g)
		}

	default:
		if !g.Dead && !g.Visited && g.A.Assigned() && g.B.Assigned() {
			g.Visited = true
			cc.pending = append(cc.pending, g)
		}
	}
}

// ShortCircuit replaces gate with the value of the wire o.
func (g *Gate) ShortCircuit(o *Wire) {
	// Do not short circuit output wires.
	if g.O.Output() {
		return
	}

	// Add gate's outputs to short circuit output wire.
	g.O.ForEachOutput(func(gate *Gate) {
		gate.ReplaceInput(g.O, o)
	})
	g.O.DisconnectOutputs()
}

// ResetOutput resets the gate's output with the wire o.
func (g *Gate) ResetOutput(o *Wire) {
	g.O = o
}

// ReplaceInput replaces gate's input wire from with wire to. The
// function panics if from is not gate's input wire.
func (g *Gate) ReplaceInput(from, to *Wire) {
	if g.A == from {
		g.A.RemoveOutput(g)
		to.AddOutput(g)
		g.A = to
	} else if g.B == from {
		g.B.RemoveOutput(g)
		to.AddOutput(g)
		g.B = to
	} else {
		panic(fmt.Sprintf("%s is not input for gate %s", from, g))
	}
}

// Prune removes gate from the circuit if gate is dead i.e. its output
// wire is not connected into circuit's output wires.
func (g *Gate) Prune() bool {
	if g.Dead || g.O.Output() || g.O.NumOutputs() > 0 {
		return false
	}
	g.Dead = true
	switch g.Op {
	case circuit.XOR, circuit.XNOR, circuit.AND, circuit.OR:
		g.B.RemoveOutput(g)
		fallthrough

	case circuit.INV:
		g.A.RemoveOutput(g)
	}
	return true
}

// Assign assigns gate's output wire ID.
func (g *Gate) Assign(cc *Compiler) {
	if !g.Dead {
		g.O.Assign(cc)
		cc.assigned = append(cc.assigned, g)
	}
}

// Compile adds gate's binary circuit into compile circuit.
func (g *Gate) Compile(cc *Compiler) {
	if g.Dead || g.Compiled {
		return
	}
	g.Compiled = true
	switch g.Op {
	case circuit.INV:
		cc.compiled = append(cc.compiled, circuit.Gate{
			Input0: circuit.Wire(g.A.ID()),
			Output: circuit.Wire(g.O.ID()),
			Op:     g.Op,
		})

	default:
		cc.compiled = append(cc.compiled, circuit.Gate{
			Input0: circuit.Wire(g.A.ID()),
			Input1: circuit.Wire(g.B.ID()),
			Output: circuit.Wire(g.O.ID()),
			Op:     g.Op,
		})
	}
}
