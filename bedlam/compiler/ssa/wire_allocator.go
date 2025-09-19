//
// Copyright (c) 2023 Markku Rossi
//
// All rights reserved.
//

package ssa

import (
	"fmt"
	"math"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/circuits"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

// WireAllocator implements wire allocation using Value.HashCode to
// map values to wires.
type WireAllocator struct {
	calloc      *circuits.Allocator
	freeHdrs    []*allocByValue
	freeWires   map[types.Size][][]*circuits.Wire
	freeIDs     map[types.Size][][]circuit.Wire
	hash        [10240]*allocByValue
	nextWireID  circuit.Wire
	flHdrs      cacheStats
	flWires     cacheStats
	flIDs       cacheStats
	lookupCount int
	lookupFound int
}

type cacheStats struct {
	hit  int
	miss int
}

func (cs cacheStats) String() string {
	total := float64(cs.hit + cs.miss)
	return fmt.Sprintf("hit=%v (%.2f%%), miss=%v (%.2f%%)",
		cs.hit, float64(cs.hit)/total*100,
		cs.miss, float64(cs.miss)/total*100)
}

type allocByValue struct {
	next  *allocByValue
	key   Value
	base  circuit.Wire
	wires []*circuits.Wire
	ids   []circuit.Wire
}

func (alloc *allocByValue) String() string {
	return fmt.Sprintf("%v[%v]: base=%v, len(wires)=%v",
		alloc.key.String(), alloc.key.Type,
		alloc.base, len(alloc.wires))
}

// NewWireAllocator creates a new WireAllocator.
func NewWireAllocator(calloc *circuits.Allocator) *WireAllocator {
	return &WireAllocator{
		calloc:    calloc,
		freeWires: make(map[types.Size][][]*circuits.Wire),
		freeIDs:   make(map[types.Size][][]circuit.Wire),
	}
}

func (walloc *WireAllocator) hashCode(v Value) int {
	return v.HashCode() % len(walloc.hash)
}

func (walloc *WireAllocator) newHeader(v Value) (ret *allocByValue) {
	if len(walloc.freeHdrs) == 0 {
		ret = new(allocByValue)
		walloc.flHdrs.miss++
	} else {
		ret = walloc.freeHdrs[len(walloc.freeHdrs)-1]
		walloc.freeHdrs = walloc.freeHdrs[:len(walloc.freeHdrs)-1]
		walloc.flHdrs.hit++
	}
	ret.key = v
	ret.base = circuits.UnassignedID
	return ret
}

func (walloc *WireAllocator) newWires(bits types.Size) (
	result []*circuits.Wire) {

	fl, ok := walloc.freeWires[bits]
	if ok && len(fl) > 0 {
		result = fl[len(fl)-1]
		walloc.freeWires[bits] = fl[:len(fl)-1]
		walloc.flWires.hit++
	} else {
		result = walloc.calloc.Wires(bits)
		walloc.flWires.miss++
	}
	return result
}

func (walloc *WireAllocator) newIDs(bits types.Size) (result []circuit.Wire) {
	fl, ok := walloc.freeIDs[bits]
	if ok && len(fl) > 0 {
		result = fl[len(fl)-1]
		walloc.freeIDs[bits] = fl[:len(fl)-1]
		walloc.flIDs.hit++
	} else {
		result = make([]circuit.Wire, bits)
		for i := 0; i < int(bits); i++ {
			result[i] = circuits.UnassignedID
		}
		walloc.flIDs.miss++
	}
	return result
}

func (walloc *WireAllocator) lookup(hash int, v Value) *allocByValue {
	var count int
	for ptr := &walloc.hash[hash]; *ptr != nil; ptr = &(*ptr).next {
		count++
		if (*ptr).key.Equal(&v) {
			alloc := *ptr

			if count > 2 {
				// MRU in the hash bucket.
				*ptr = alloc.next
				alloc.next = walloc.hash[hash]
				walloc.hash[hash] = alloc
			}

			walloc.lookupCount++
			walloc.lookupFound += count
			return alloc
		}
	}
	return nil
}

func (walloc *WireAllocator) alloc(bits types.Size, v Value,
	wires, ids bool) *allocByValue {

	result := walloc.newHeader(v)
	if bits == 0 {
		return result
	}

	if wires && ids {
		result.wires = walloc.newWires(bits)
		result.ids = walloc.newIDs(bits)
		result.base = result.wires[0].ID()

		for i := 0; i < int(bits); i++ {
			result.ids[i] = result.wires[i].ID()
		}
	} else if wires {
		result.wires = walloc.newWires(bits)
		result.base = result.wires[0].ID()
	} else {
		result.ids = walloc.newIDs(bits)
		result.base = result.ids[0]
	}
	return result
}

func (walloc *WireAllocator) remove(hash int, v Value) *allocByValue {
	for ptr := &walloc.hash[hash]; *ptr != nil; ptr = &(*ptr).next {
		if (*ptr).key.Equal(&v) {
			ret := *ptr
			*ptr = (*ptr).next
			return ret
		}
	}
	return nil
}

// Allocated tests if the wires have been allocated for the value.
func (walloc *WireAllocator) Allocated(v Value) bool {
	hash := walloc.hashCode(v)
	alloc := walloc.lookup(hash, v)
	return alloc != nil
}

// NextWireID allocated and returns the next unassigned wire ID.
// XXX is this sync with circuits.Compiler.NextWireID()?
func (walloc *WireAllocator) NextWireID() circuit.Wire {
	ret := walloc.nextWireID
	walloc.nextWireID++
	return ret
}

// AssignedIDs allocates assigned wire IDs for the argument value.
func (walloc *WireAllocator) AssignedIDs(v Value, bits types.Size) (
	[]circuit.Wire, error) {

	hash := walloc.hashCode(v)
	alloc := walloc.lookup(hash, v)
	if alloc == nil {
		alloc = walloc.alloc(bits, v, false, true)
		alloc.next = walloc.hash[hash]
		walloc.hash[hash] = alloc

		// Assign wire IDs.
		if alloc.base == circuits.UnassignedID {
			alloc.base = walloc.nextWireID
			for i := 0; i < int(bits); i++ {
				alloc.ids[i] = walloc.nextWireID + circuit.Wire(i)
			}
			walloc.nextWireID += circuit.Wire(bits)
		}
	}
	if alloc.ids == nil {
		alloc.ids = walloc.newIDs(bits)
		for i := 0; i < int(bits); i++ {
			alloc.ids[i] = alloc.wires[i].ID()
		}
	}
	return alloc.ids, nil
}

// AssignedWires allocates assigned wires for the argument value.
func (walloc *WireAllocator) AssignedWires(v Value, bits types.Size) (
	[]*circuits.Wire, error) {

	hash := walloc.hashCode(v)
	alloc := walloc.lookup(hash, v)
	if alloc == nil {
		alloc = walloc.alloc(bits, v, true, true)
		alloc.next = walloc.hash[hash]
		walloc.hash[hash] = alloc

		// Assign wire IDs.
		if alloc.base == circuits.UnassignedID {
			alloc.base = walloc.nextWireID
			for i := 0; i < int(bits); i++ {
				alloc.wires[i].SetID(walloc.nextWireID + circuit.Wire(i))
			}
			walloc.nextWireID += circuit.Wire(bits)
		}
	}
	if alloc.ids == nil {
		alloc.ids = walloc.newIDs(bits)
		for i := 0; i < int(bits); i++ {
			alloc.ids[i] = alloc.wires[i].ID()
		}
	}
	return alloc.wires, nil
}

// GCWires recycles the wires of the argument value. The wires must
// have been previously allocated with Wires, AssignedWires, or
// SetWires; the function panics if the wires have not been allocated.
func (walloc *WireAllocator) GCWires(v Value) {
	hash := walloc.hashCode(v)
	alloc := walloc.remove(hash, v)
	if alloc == nil {
		panic(fmt.Sprintf("GC: %s not known", v))
	}

	if alloc.wires != nil {
		if alloc.base == circuits.UnassignedID {
			alloc.base = alloc.wires[0].ID()
		}
		// Clear wires and reassign their IDs.
		for i := 0; i < len(alloc.wires); i++ {
			alloc.wires[i].Reset(alloc.base + circuit.Wire(i))
		}
		bits := types.Size(len(alloc.wires))
		walloc.freeWires[bits] = append(walloc.freeWires[bits], alloc.wires)
	}
	if len(alloc.ids) > 0 {
		if alloc.base == circuits.UnassignedID {
			alloc.base = alloc.ids[0]
		}
		// Clear IDs.
		for i := 0; i < len(alloc.ids); i++ {
			alloc.ids[i] = alloc.base + circuit.Wire(i)
		}
		bits := types.Size(len(alloc.ids))
		walloc.freeIDs[bits] = append(walloc.freeIDs[bits], alloc.ids)
	}

	alloc.next = nil
	alloc.base = circuits.UnassignedID
	alloc.wires = nil
	alloc.ids = nil
	walloc.freeHdrs = append(walloc.freeHdrs, alloc)
}

// Wires allocates unassigned wires for the argument value.
func (walloc *WireAllocator) Wires(v Value, bits types.Size) (
	[]*circuits.Wire, error) {

	hash := walloc.hashCode(v)
	alloc := walloc.lookup(hash, v)
	if alloc == nil {
		alloc = walloc.alloc(bits, v, true, false)
		alloc.next = walloc.hash[hash]
		walloc.hash[hash] = alloc
	}
	return alloc.wires, nil
}

// SetWires allocates wire IDs for the value's wires.
func (walloc *WireAllocator) SetWires(v Value, w []*circuits.Wire) {
	hash := walloc.hashCode(v)
	alloc := walloc.lookup(hash, v)
	if alloc != nil {
		panic(fmt.Sprintf("wires already set for %v", v))
	}
	alloc = &allocByValue{
		key:   v,
		wires: w,
		ids:   make([]circuit.Wire, len(w)),
	}
	if len(w) == 0 {
		alloc.base = circuits.UnassignedID
	} else {
		alloc.base = w[0].ID()
		for i := 0; i < len(w); i++ {
			alloc.ids[i] = w[i].ID()
		}
	}

	alloc.next = walloc.hash[hash]
	walloc.hash[hash] = alloc
}

// Debug prints debugging information about the wire allocator.
func (walloc *WireAllocator) Debug() {
	fmt.Printf("WireAllocator:\n")
	fmt.Printf("  hdrs : %s\n", walloc.flHdrs)
	fmt.Printf("  wires: %s\n", walloc.flWires)
	fmt.Printf("  ids  : %s\n", walloc.flIDs)

	var sum, max int
	min := math.MaxInt

	var maxIndex int

	for i := 0; i < len(walloc.hash); i++ {
		var count int
		for alloc := walloc.hash[i]; alloc != nil; alloc = alloc.next {
			count++
		}
		sum += count
		if count < min {
			min = count
		}
		if count > max {
			max = count
			maxIndex = i
		}
	}
	fmt.Printf("Hash: min=%v, max=%v, avg=%.4f, lookup=%v (avg=%.4f)\n",
		min, max, float64(sum)/float64(len(walloc.hash)),
		walloc.lookupCount,
		float64(walloc.lookupFound)/float64(walloc.lookupCount))

	if false {
		fmt.Printf("Max bucket:\n")
		for alloc := walloc.hash[maxIndex]; alloc != nil; alloc = alloc.next {
			fmt.Printf(" %v: %v\n", alloc.key.String(), len(alloc.wires))
		}
	}
}
