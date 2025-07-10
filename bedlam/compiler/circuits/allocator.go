//
// Copyright (c) 2023 Markku Rossi
//
// All rights reserved.
//

package circuits

import (
	"fmt"
	"unsafe"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

var (
	sizeofWire = uint64(unsafe.Sizeof(Wire{}))
	sizeofGate = uint64(unsafe.Sizeof(Gate{}))
)

// Allocator implements circuit wire and gate allocation.
type Allocator struct {
	numWire  uint64
	numWires uint64
	numGates uint64
}

// NewAllocator creates a new circuit allocator.
func NewAllocator() *Allocator {
	return new(Allocator)
}

// Wire allocates a new Wire.
func (alloc *Allocator) Wire() *Wire {
	alloc.numWire++
	w := new(Wire)
	w.Reset(UnassignedID)
	return w
}

// Wires allocate an array of Wires.
func (alloc *Allocator) Wires(bits types.Size) []*Wire {
	alloc.numWires += uint64(bits)

	wires := make([]Wire, bits)
	result := make([]*Wire, bits)
	for i := 0; i < int(bits); i++ {
		w := &wires[i]
		w.id = UnassignedID
		result[i] = w
	}
	return result
}

// BinaryGate creates a new binary gate.
func (alloc *Allocator) BinaryGate(op circuit.Operation, a, b, o *Wire) *Gate {
	alloc.numGates++
	gate := &Gate{
		Op: op,
		A:  a,
		B:  b,
		O:  o,
	}
	a.AddOutput(gate)
	b.AddOutput(gate)
	o.SetInput(gate)

	return gate
}

// INVGate creates a new INV gate.
func (alloc *Allocator) INVGate(i, o *Wire) *Gate {
	alloc.numGates++
	gate := &Gate{
		Op: circuit.INV,
		A:  i,
		O:  o,
	}
	i.AddOutput(gate)
	o.SetInput(gate)

	return gate
}

// Debug print debugging information about the circuit allocator.
func (alloc *Allocator) Debug() {
	wireSize := circuit.FileSize(alloc.numWire * sizeofWire)
	wiresSize := circuit.FileSize(alloc.numWires * sizeofWire)
	gatesSize := circuit.FileSize(alloc.numGates * sizeofGate)

	total := float64(wireSize + wiresSize + gatesSize)

	fmt.Println("circuits.Allocator:")
	fmt.Printf("  wire : %9v %5s %5.2f%%\n",
		alloc.numWire, wireSize, float64(wireSize)/total*100.0)
	fmt.Printf("  wires: %9v %5s %5.2f%%\n",
		alloc.numWires, wiresSize, float64(wiresSize)/total*100.0)
	fmt.Printf("  gates: %9v %5s %5.2f%%\n",
		alloc.numGates, gatesSize, float64(gatesSize)/total*100.0)
}
