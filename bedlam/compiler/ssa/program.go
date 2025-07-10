//
// Copyright (c) 2020-2023 Markku Rossi
//
// All rights reserved.
//

package ssa

import (
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/circuits"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

// Program implements SSA program.
type Program struct {
	Params      *utils.Params
	Inputs      circuit.IO
	Outputs     circuit.IO
	InputWires  []*circuits.Wire
	OutputWires []*circuits.Wire
	Constants   map[string]ConstantInst
	Steps       []Step
	walloc      *WireAllocator
	calloc      *circuits.Allocator
	zeroWire    *circuits.Wire
	oneWire     *circuits.Wire
	stats       circuit.Stats
	numWires    int
	tInit       time.Duration
	tGarble     time.Duration
}

// NewProgram creates a new program for the constants and program
// steps.
func NewProgram(params *utils.Params, in, out circuit.IO,
	consts map[string]ConstantInst, steps []Step) (*Program, error) {

	calloc := circuits.NewAllocator()

	prog := &Program{
		Params:    params,
		Inputs:    in,
		Outputs:   out,
		Constants: consts,
		Steps:     steps,
		walloc:    NewWireAllocator(calloc),
		calloc:    calloc,
	}

	// Inputs into wires.
	for idx, arg := range in {
		if len(arg.Name) == 0 {
			arg.Name = fmt.Sprintf("arg{%d}", idx)
		}
		wires, err := prog.walloc.Wires(Value{
			Name:  arg.Name,
			Scope: 1, // Arguments are at scope 1.
			Type:  arg.Type,
		}, arg.Type.Bits)
		if err != nil {
			return nil, err
		}
		prog.InputWires = append(prog.InputWires, wires...)
	}

	return prog, nil
}

// Step defines one SSA program step.
type Step struct {
	Label string
	Instr Instr
	Live  Set
}

func (prog *Program) liveness() {
	aliases := make(map[ValueID]Value)

	// Collect value aliases.
	for i := 0; i < len(prog.Steps); i++ {
		step := &prog.Steps[i]
		switch step.Instr.Op {
		case Slice, Mov:
			if !step.Instr.In[0].Const {
				// The `out' will be an alias for `in[0]'.
				aliases[step.Instr.Out.ID] = step.Instr.In[0]
			}
		case Amov:
			// v arr from to o: v | arr[from:to] = o
			// XXX aliases are 1:1 mapping but here amov's output
			// aliases two inputs.
			if !step.Instr.In[0].Const && false {
				// The `out' will be an alias for `in[0]'
				aliases[step.Instr.Out.ID] = step.Instr.In[0]
			}
			if !step.Instr.In[1].Const {
				// The `out' will be an alias for `in[1]'
				aliases[step.Instr.Out.ID] = step.Instr.In[1]
			}
		}
	}

	live := NewSet()

	for i := len(prog.Steps) - 1; i >= 0; i-- {
		step := &prog.Steps[i]
		for _, in := range step.Instr.In {
			if in.Const {
				continue
			}
			live.Add(in)
		}

		if step.Instr.Out != nil {
			delete(live, step.Instr.Out.ID)
		}
		step.Live = NewSet()
		for _, v := range live {
			step.Live.Add(v)
			// Follow alias chains.
			from := v
			for {
				to, ok := aliases[from.ID]
				if !ok {
					break
				}
				step.Live.Add(to)
				from = to
			}
		}
	}
}

// GC adds garbage collect (gc) instructions to recycle dead value
// wires.
func (prog *Program) GC() {
	set := big.NewInt(0)

	// Return values are live at the end of the program.
	if len(prog.Steps) == 0 {
		panic("empty program")
	}
	last := prog.Steps[len(prog.Steps)-1]
	if last.Instr.Op != Ret {
		panic("last instruction is not return")
	}
	for _, in := range last.Instr.In {
		set.SetBit(set, int(in.ID), 1)
	}

	start := time.Now()

	// Collect value aliases.
	aliases := make(map[ValueID][]Value)
	for i := 0; i < len(prog.Steps); i++ {
		step := &prog.Steps[i]
		switch step.Instr.Op {
		case Lshift, Rshift, Srshift, Slice, Mov, Smov, Amov:
			// Output is an alias for all non-const inputs.
			for _, in := range step.Instr.In {
				if in.Const {
					continue
				}
				aliases[in.ID] = append(aliases[in.ID], *step.Instr.Out)
			}
		}
	}

	steps := make([]Step, 0, len(prog.Steps)*2)

	for i := len(prog.Steps) - 1; i >= 0; i-- {
		step := &prog.Steps[i]

		for _, in := range step.Instr.In {
			if in.Const {
				continue
			}
			// Is input live after this instruction?
			if set.Bit(int(in.ID)) == 0 {
				var live bool
				// Check if input aliases are live.
				for _, alias := range aliases[in.ID] {
					if set.Bit(int(alias.ID)) == 1 {
						live = true
					}
				}
				if !live {
					// Input is not live.
					steps = append(steps, Step{
						Instr: NewGCInstr(in),
					})
				}
			}
			set.SetBit(set, int(in.ID), 1)
		}
		if step.Instr.Out != nil {
			set.SetBit(set, int(step.Instr.Out.ID), 0)
		}

		steps = append(steps, *step)
	}
	reverse(steps)
	prog.Steps = steps

	elapsed := time.Since(start)

	if prog.Params.Diagnostics {
		fmt.Printf(" - Program.GC: %s\n", elapsed)
	}
}

func reverse(steps []Step) {
	for i, j := 0, len(steps)-1; i < j; i, j = i+1, j-1 {
		steps[i], steps[j] = steps[j], steps[i]
	}
}

// DefineConstants defines the program constants.
func (prog *Program) DefineConstants(zero, one *circuits.Wire) error {

	var consts []Value
	for _, c := range prog.Constants {
		consts = append(consts, c.Const)
	}
	sort.Slice(consts, func(i, j int) bool {
		return strings.Compare(consts[i].Name, consts[j].Name) == -1
	})

	var constWires int
	for _, c := range consts {
		if prog.walloc.Allocated(c) {
			continue
		}

		constWires += int(c.Type.Bits)

		var wires []*circuits.Wire
		for bit := types.Size(0); bit < c.Type.Bits; bit++ {
			var w *circuits.Wire
			if c.Bit(bit) {
				w = one
			} else {
				w = zero
			}
			wires = append(wires, w)
		}

		prog.walloc.SetWires(c, wires)
	}
	if len(consts) > 0 && prog.Params.Verbose {
		fmt.Printf("Defined %d constants: %d wires\n",
			len(consts), constWires)
		if false {
			for _, c := range consts {
				fmt.Printf(" - %s:\t%v\n", c.Name, c.ConstValue)
			}
		}
	}
	return nil
}

// StreamDebug print debugging information about streaming mode.
func (prog *Program) StreamDebug() {
	prog.walloc.Debug()
	prog.calloc.Debug()
}

// PP pretty-prints the program to the argument io.Writer.
func (prog *Program) PP(out io.Writer) {
	for i, in := range prog.Inputs {
		fmt.Fprintf(out, "# Input%d: %s\n", i, in)
	}
	for i, in := range prog.Outputs {
		fmt.Fprintf(out, "# Output%d: %s\n", i, in)
	}
	for _, step := range prog.Steps {
		if len(step.Label) > 0 {
			fmt.Fprintf(out, "# %s:\n", step.Label)
		}
		step.Instr.PP(out)
		if false {
			for _, live := range step.Live {
				fmt.Fprintf(out, "#\t\t- %v\n", live)
			}
		}
	}
}
