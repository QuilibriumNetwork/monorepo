//
// Copyright (c) 2019-2024 Markku Rossi
//
// All rights reserved.
//

package circuits

import (
	"fmt"
	"math"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
)

const (
	// UnassignedID identifies an unassigned wire ID.
	UnassignedID circuit.Wire = math.MaxUint32
	outputMask                = 0b10000000000000000000000000000000
	valueMask                 = 0b01100000000000000000000000000000
	numMask                   = 0b00011111111111111111111111111111
	valueShift                = 29
)

// Wire implements a wire connecting binary gates.
type Wire struct {
	ovnum uint32
	id    circuit.Wire
	// The gates[0] is the input gate, gates[1:] are the output gates.
	gates []*Gate
}

// WireValue defines wire values.
type WireValue uint8

// Possible wire values.
const (
	Unknown WireValue = iota
	Zero
	One
)

func (v WireValue) String() string {
	switch v {
	case Zero:
		return "0"
	case One:
		return "1"
	default:
		return "?"
	}
}

// Reset resets the wire with the new ID.
func (w *Wire) Reset(id circuit.Wire) {
	w.SetOutput(false)
	w.SetValue(Unknown)
	w.SetID(id)
	w.SetInput(nil)
	w.DisconnectOutputs()
}

// ID returns the wire ID.
func (w *Wire) ID() circuit.Wire {
	return w.id
}

// SetID sets the wire ID.
func (w *Wire) SetID(id circuit.Wire) {
	w.id = id
}

// Assigned tests if the wire is assigned with an unique ID.
func (w *Wire) Assigned() bool {
	return w.id != UnassignedID
}

// Output tests if the wire is an output wire.
func (w *Wire) Output() bool {
	return w.ovnum&outputMask != 0
}

// SetOutput sets the wire output flag.
func (w *Wire) SetOutput(output bool) {
	if output {
		w.ovnum |= outputMask
	} else {
		w.ovnum &^= outputMask
	}
}

// Value returns the wire value.
func (w *Wire) Value() WireValue {
	return WireValue((w.ovnum & valueMask) >> valueShift)
}

// SetValue sets the wire value.
func (w *Wire) SetValue(value WireValue) {
	w.ovnum &^= valueMask
	w.ovnum |= (uint32(value) << valueShift) & valueMask
}

// NumOutputs returns the number of output gates assigned to the wire.
func (w *Wire) NumOutputs() uint32 {
	return w.ovnum & numMask
}

// SetNumOutputs sets the number of output gates assigned to the wire.
func (w *Wire) SetNumOutputs(num uint32) {
	if num > numMask {
		panic("too big circuit, wire outputs overflow")
	}
	w.ovnum &^= numMask
	w.ovnum |= num
}

// DisconnectOutputs disconnects wire from its output gates.
func (w *Wire) DisconnectOutputs() {
	w.SetNumOutputs(0)
	if len(w.gates) > 1 {
		w.gates = w.gates[0:1]
	}
}

func (w *Wire) String() string {
	return fmt.Sprintf("Wire{%x, Input:%s, Value:%s, Outputs:%v, Output=%v}",
		w.ID(), w.Input(), w.Value(), w.gates[1:], w.Output())
}

// Assign assings wire ID.
func (w *Wire) Assign(cc *Compiler) {
	if w.Output() {
		return
	}
	if !w.Assigned() {
		w.id = cc.NextWireID()
	}
	w.ForEachOutput(func(gate *Gate) {
		gate.Visit(cc)
	})
}

// Input returns the wire's input gate.
func (w *Wire) Input() *Gate {
	if len(w.gates) == 0 {
		return nil
	}
	return w.gates[0]
}

// SetInput sets the wire's input gate.
func (w *Wire) SetInput(gate *Gate) {
	if gate == nil {
		if len(w.gates) > 0 {
			w.gates[0] = nil
		}
	} else {
		if len(w.gates) == 0 {
			w.gates = append(w.gates, gate)
		} else {
			if w.gates[0] != nil {
				panic("wire input gate already set")
			}
			w.gates[0] = gate
		}
	}
}

// IsInput tests if the wire is an input wire.
func (w *Wire) IsInput() bool {
	return w.Input() == nil
}

// ForEachOutput calls the argument function for each output gate of
// the wire.
func (w *Wire) ForEachOutput(f func(gate *Gate)) {
	if len(w.gates) > 1 {
		for _, gate := range w.gates[1:] {
			f(gate)
		}
	}
}

// AddOutput adds gate to the wire's output gates.
func (w *Wire) AddOutput(gate *Gate) {
	if len(w.gates) == 0 {
		w.gates = append(w.gates, nil)
	}
	w.gates = append(w.gates, gate)
	w.SetNumOutputs(w.NumOutputs() + 1)
}

// RemoveOutput removes gate from the wire's output gates.
func (w *Wire) RemoveOutput(gate *Gate) {
	w.SetNumOutputs(w.NumOutputs() - 1)
}
