//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package circuits

import (
	"fmt"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
)

// Builtin implements a buitin circuit that uses input wires a and b
// and returns the circuit result in r.
type Builtin func(cc *Compiler, a, b, r []*Wire) error

// Compiler implements binary circuit compiler.
type Compiler struct {
	Params          *utils.Params
	Calloc          *Allocator
	OutputsAssigned bool
	Inputs          circuit.IO
	Outputs         circuit.IO
	InputWires      []*Wire
	OutputWires     []*Wire
	Gates           []*Gate
	nextWireID      circuit.Wire
	pending         []*Gate
	assigned        []*Gate
	compiled        []circuit.Gate
	invI0Wire       *Wire
	zeroWire        *Wire
	oneWire         *Wire
}

// NewCompiler creates a new circuit compiler for the specified
// circuit input and output values.
func NewCompiler(params *utils.Params, calloc *Allocator,
	inputs, outputs circuit.IO, inputWires, outputWires []*Wire) (
	*Compiler, error) {

	if len(inputWires) == 0 {
		return nil, fmt.Errorf("no inputs defined")
	}
	return &Compiler{
		Params:      params,
		Calloc:      calloc,
		Inputs:      inputs,
		Outputs:     outputs,
		InputWires:  inputWires,
		OutputWires: outputWires,
		Gates:       make([]*Gate, 0, 65536),
	}, nil
}

// InvI0Wire returns a wire holding value INV(input[0]).
func (cc *Compiler) InvI0Wire() *Wire {
	if cc.invI0Wire == nil {
		cc.invI0Wire = cc.Calloc.Wire()
		cc.AddGate(cc.Calloc.INVGate(cc.InputWires[0], cc.invI0Wire))
	}
	return cc.invI0Wire
}

// ZeroWire returns a wire holding value 0.
func (cc *Compiler) ZeroWire() *Wire {
	if cc.zeroWire == nil {
		cc.zeroWire = cc.Calloc.Wire()
		cc.AddGate(cc.Calloc.BinaryGate(circuit.AND, cc.InputWires[0],
			cc.InvI0Wire(), cc.zeroWire))
		cc.zeroWire.SetValue(Zero)
	}
	return cc.zeroWire
}

// OneWire returns a wire holding value 1.
func (cc *Compiler) OneWire() *Wire {
	if cc.oneWire == nil {
		cc.oneWire = cc.Calloc.Wire()
		cc.AddGate(cc.Calloc.BinaryGate(circuit.OR, cc.InputWires[0],
			cc.InvI0Wire(), cc.oneWire))
		cc.oneWire.SetValue(One)
	}
	return cc.oneWire
}

// ZeroPad pads the argument wires x and y with zero values so that
// the resulting wires have the same number of bits.
func (cc *Compiler) ZeroPad(x, y []*Wire) ([]*Wire, []*Wire) {
	if len(x) == len(y) {
		return x, y
	}

	max := len(x)
	if len(y) > max {
		max = len(y)
	}

	rx := make([]*Wire, max)
	for i := 0; i < max; i++ {
		if i < len(x) {
			rx[i] = x[i]
		} else {
			rx[i] = cc.ZeroWire()
		}
	}

	ry := make([]*Wire, max)
	for i := 0; i < max; i++ {
		if i < len(y) {
			ry[i] = y[i]
		} else {
			ry[i] = cc.ZeroWire()
		}
	}

	return rx, ry
}

// ShiftLeft shifts the size number of bits of the input wires w,
// count bits left.
func (cc *Compiler) ShiftLeft(w []*Wire, size, count int) []*Wire {
	result := make([]*Wire, size)

	if count < size {
		copy(result[count:], w)
	}
	for i := 0; i < count; i++ {
		result[i] = cc.ZeroWire()
	}
	for i := count + len(w); i < size; i++ {
		result[i] = cc.ZeroWire()
	}
	return result
}

// INV creates an inverse wire inverting the input wire i's value to
// the output wire o.
func (cc *Compiler) INV(i, o *Wire) {
	cc.AddGate(cc.Calloc.BinaryGate(circuit.XOR, i, cc.OneWire(), o))
}

// ID creates an identity wire passing the input wire i's value to the
// output wire o.
func (cc *Compiler) ID(i, o *Wire) {
	cc.AddGate(cc.Calloc.BinaryGate(circuit.XOR, i, cc.ZeroWire(), o))
}

// AddGate adds a get into the circuit.
func (cc *Compiler) AddGate(gate *Gate) {
	cc.Gates = append(cc.Gates, gate)
}

// SetNextWireID sets the next unique wire ID to use.
func (cc *Compiler) SetNextWireID(next circuit.Wire) {
	cc.nextWireID = next
}

// NextWireID returns the next unique wire ID.
func (cc *Compiler) NextWireID() circuit.Wire {
	ret := cc.nextWireID
	cc.nextWireID++
	return ret
}

// ConstPropagate propagates constant wire values in the circuit and
// short circuits gates if their output does not depend on the gate's
// logical operation.
func (cc *Compiler) ConstPropagate() {
	var stats circuit.Stats

	start := time.Now()

	for _, g := range cc.Gates {
		switch g.Op {
		case circuit.XOR:
			if (g.A.Value() == Zero && g.B.Value() == Zero) ||
				(g.A.Value() == One && g.B.Value() == One) {
				g.O.SetValue(Zero)
				stats[g.Op]++
			} else if (g.A.Value() == Zero && g.B.Value() == One) ||
				(g.A.Value() == One && g.B.Value() == Zero) {
				g.O.SetValue(One)
				stats[g.Op]++
			} else if g.A.Value() == Zero {
				// O = B
				stats[g.Op]++
				g.ShortCircuit(g.B)
			} else if g.B.Value() == Zero {
				// O = A
				stats[g.Op]++
				g.ShortCircuit(g.A)
			}

		case circuit.XNOR:
			if (g.A.Value() == Zero && g.B.Value() == Zero) ||
				(g.A.Value() == One && g.B.Value() == One) {
				g.O.SetValue(One)
				stats[g.Op]++
			} else if (g.A.Value() == Zero && g.B.Value() == One) ||
				(g.A.Value() == One && g.B.Value() == Zero) {
				g.O.SetValue(Zero)
				stats[g.Op]++
			}

		case circuit.AND:
			if g.A.Value() == Zero || g.B.Value() == Zero {
				g.O.SetValue(Zero)
				stats[g.Op]++
			} else if g.A.Value() == One && g.B.Value() == One {
				g.O.SetValue(One)
				stats[g.Op]++
			} else if g.A.Value() == One {
				// O = B
				stats[g.Op]++
				g.ShortCircuit(g.B)
			} else if g.B.Value() == One {
				// O = A
				stats[g.Op]++
				g.ShortCircuit(g.A)
			}

		case circuit.OR:
			if g.A.Value() == One || g.B.Value() == One {
				g.O.SetValue(One)
				stats[g.Op]++
			} else if g.A.Value() == Zero && g.B.Value() == Zero {
				g.O.SetValue(Zero)
				stats[g.Op]++
			} else if g.A.Value() == Zero {
				// O = B
				stats[g.Op]++
				g.ShortCircuit(g.B)
			} else if g.B.Value() == Zero {
				// O = A
				stats[g.Op]++
				g.ShortCircuit(g.A)
			}

		case circuit.INV:
			if g.A.Value() == One {
				g.O.SetValue(Zero)
				stats[g.Op]++
			} else if g.A.Value() == Zero {
				g.O.SetValue(One)
				stats[g.Op]++
			}
		}

		if g.A.Value() == Zero {
			g.A.RemoveOutput(g)
			g.A = cc.ZeroWire()
			g.A.AddOutput(g)
		} else if g.A.Value() == One {
			g.A.RemoveOutput(g)
			g.A = cc.OneWire()
			g.A.AddOutput(g)
		}
		if g.B != nil {
			if g.B.Value() == Zero {
				g.B.RemoveOutput(g)
				g.B = cc.ZeroWire()
				g.B.AddOutput(g)
			} else if g.B.Value() == One {
				g.B.RemoveOutput(g)
				g.B = cc.OneWire()
				g.B.AddOutput(g)
			}
		}
	}

	elapsed := time.Since(start)

	if cc.Params.Diagnostics && stats.Count() > 0 {
		fmt.Printf(" - ConstPropagate:      %12s: %d/%d (%.2f%%)\n",
			elapsed, stats.Count(), len(cc.Gates),
			float64(stats.Count())/float64(len(cc.Gates))*100)
	}
}

// ShortCircuitXORZero short circuits input to output where input is
// XOR'ed to zero.
func (cc *Compiler) ShortCircuitXORZero() {
	var stats circuit.Stats

	start := time.Now()

	for _, g := range cc.Gates {
		if g.Op != circuit.XOR {
			continue
		}
		if g.A.Value() == Zero && !g.B.IsInput() &&
			g.B.Input().O.NumOutputs() == 1 {

			g.B.Input().ResetOutput(g.O)

			// Disconnect gate's output wire.
			g.O = cc.Calloc.Wire()

			stats[g.Op]++
		}
		if g.B.Value() == Zero && !g.A.IsInput() &&
			g.A.Input().O.NumOutputs() == 1 {

			g.A.Input().ResetOutput(g.O)

			// Disconnect gate's output wire.
			g.O = cc.Calloc.Wire()

			stats[g.Op]++
		}
	}

	elapsed := time.Since(start)

	if cc.Params.Diagnostics && stats.Count() > 0 {
		fmt.Printf(" - ShortCircuitXORZero: %12s: %d/%d (%.2f%%)\n",
			elapsed, stats.Count(), len(cc.Gates),
			float64(stats.Count())/float64(len(cc.Gates))*100)
	}
}

// Prune removes all gates whose output wires are unused.
func (cc *Compiler) Prune() int {

	n := make([]*Gate, len(cc.Gates))
	nPos := len(n)

	for i := len(cc.Gates) - 1; i >= 0; i-- {
		g := cc.Gates[i]
		if !g.Prune() {
			nPos--
			n[nPos] = g
		}
	}
	cc.Gates = n[nPos:]

	return nPos
}

// Compile compiles the circuit.
func (cc *Compiler) Compile() *circuit.Circuit {
	if len(cc.pending) != 0 {
		panic("Compile: pending set")
	}
	cc.pending = make([]*Gate, 0, len(cc.Gates))
	if len(cc.assigned) != 0 {
		panic("Compile: assigned set")
	}
	cc.assigned = make([]*Gate, 0, len(cc.Gates))
	if len(cc.compiled) != 0 {
		panic("Compile: compiled set")
	}
	cc.compiled = make([]circuit.Gate, 0, len(cc.Gates))

	for _, w := range cc.InputWires {
		w.Assign(cc)
	}
	for len(cc.pending) > 0 {
		gate := cc.pending[0]
		cc.pending = cc.pending[1:]
		gate.Assign(cc)
	}
	// Assign outputs.
	for _, w := range cc.OutputWires {
		if w.Assigned() {
			if !cc.OutputsAssigned {
				panic("Output already assigned")
			}
		} else {
			w.SetID(cc.NextWireID())
		}
	}

	// Compile circuit.
	for _, gate := range cc.assigned {
		gate.Compile(cc)
	}

	var stats circuit.Stats
	for _, g := range cc.compiled {
		stats[g.Op]++
	}

	result := &circuit.Circuit{
		NumGates: len(cc.compiled),
		NumWires: int(cc.nextWireID),
		Inputs:   cc.Inputs,
		Outputs:  cc.Outputs,
		Gates:    cc.compiled,
		Stats:    stats,
	}

	return result
}
