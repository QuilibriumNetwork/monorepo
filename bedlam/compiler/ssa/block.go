//
// Copyright (c) 2020-2023 Markku Rossi
//
// All rights reserved.
//

package ssa

import (
	"fmt"
	"io"
	"strings"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

// Block implements a basic block.
type Block struct {
	ID         BlockID
	Name       string
	From       []*Block
	Next       *Block
	BranchCond Value
	Branch     *Block
	Instr      []Instr
	Bindings   *Bindings
	Dead       bool
	Processed  bool
}

// BlockID defines unique block IDs.
type BlockID int

func (id BlockID) String() string {
	return fmt.Sprintf("l%d", id)
}

func (b *Block) String() string {
	return b.ID.String()
}

// Equals tests if the argument block is equal to this basic block.
func (b *Block) Equals(o *Block) bool {
	return b.ID == o.ID
}

// SetNext sets the next basic block.
func (b *Block) SetNext(o *Block) {
	if b.Next != nil && b.Next.ID != o.ID {
		panic(fmt.Sprintf("%s.Next already set to %s, now setting to %s",
			b, b.Next, o))
	}
	b.Next = o
	o.addFrom(b)
}

// SetBranch sets the argument block being a branch block for this
// basic block.
func (b *Block) SetBranch(o *Block) {
	if b.Branch != nil && b.Branch.ID != o.ID {
		panic(fmt.Sprintf("%s.Branch already set to %s, now setting to %s",
			b, b.Next, o))
	}
	b.Branch = o
	o.addFrom(b)
}

func (b *Block) addFrom(o *Block) {
	for _, f := range b.From {
		if f.Equals(o) {
			return
		}
	}
	b.From = append(b.From, o)
}

// AddInstr adds an instruction to this basic block.
func (b *Block) AddInstr(instr Instr) {
	instr.Check()
	b.Instr = append(b.Instr, instr)
}

type returnBindingKey struct {
	BlockID BlockID
	Name    string
}

// ReturnBindingValue define return binding value for a return value.
type ReturnBindingValue struct {
	v    Value
	diff bool
	ok   bool
}

// ReturnBindingCTX defines a context for return binding resolve
// operation.
type ReturnBindingCTX struct {
	cache map[returnBindingKey]ReturnBindingValue
}

// Get gets the return binding for the return value in the basic
// block.
func (ctx *ReturnBindingCTX) Get(b *Block, name string) (
	ReturnBindingValue, bool) {
	value, ok := ctx.cache[returnBindingKey{
		BlockID: b.ID,
		Name:    name,
	}]
	return value, ok
}

// Set sets the return binding for the return value in the basic
// block.
func (ctx *ReturnBindingCTX) Set(b *Block, name string, v Value,
	diff, ok bool) {

	ctx.cache[returnBindingKey{
		BlockID: b.ID,
		Name:    name,
	}] = ReturnBindingValue{
		v:    v,
		diff: diff,
		ok:   ok,
	}
}

// NewReturnBindingCTX creates a new return binding resolve context.
func NewReturnBindingCTX() *ReturnBindingCTX {
	return &ReturnBindingCTX{
		cache: make(map[returnBindingKey]ReturnBindingValue),
	}
}

// ReturnBinding returns the return statement binding for the argument
// value. If the block contains a branch and value is modified in both
// branches, the function adds a Phi instruction to resolve the value
// binding after this basic block. The return value diff tells if
// branch return values has different sizes.
func (b *Block) ReturnBinding(ctx *ReturnBindingCTX, name string,
	retBlock *Block, gen *Generator) (v Value, diff, ok bool) {

	binding, ok := ctx.Get(b, name)
	if ok {
		return binding.v, binding.diff, binding.ok
	}
	v, diff, ok = b.returnBinding(ctx, name, retBlock, gen)
	ctx.Set(b, name, v, diff, ok)
	return v, diff, ok
}

func (b *Block) returnBinding(ctx *ReturnBindingCTX, name string,
	retBlock *Block, gen *Generator) (v Value, diff, ok bool) {

	// XXX Check if the if-ssagen could omit branch in this case?
	if b.Branch == nil || b.Next == b.Branch {
		// Sequential block, return latest value
		if b.Next != nil {
			v, diff, ok = b.Next.ReturnBinding(ctx, name, retBlock, gen)
			if ok {
				return v, diff, true
			}
			// Next didn't have value, take ours below.
		}
		bind, ok := b.Bindings.Get(name)
		if !ok {
			return v, false, false
		}
		return bind.Value(retBlock, gen), false, true
	}
	vTrue, diffTrue, ok := b.Branch.ReturnBinding(ctx, name, retBlock, gen)
	if !ok {
		return v, false, false
	}
	vFalse, diffFalse, ok := b.Next.ReturnBinding(ctx, name, retBlock, gen)
	if !ok {
		return v, false, false
	}
	if vTrue.Equal(&vFalse) {
		return vTrue, diffTrue || diffFalse, true
	}

	var rType types.Info
	if vTrue.Type.Bits > vFalse.Type.Bits {
		rType = vTrue.Type
	} else {
		rType = vFalse.Type
	}

	v = gen.AnonVal(rType)
	retBlock.AddInstr(NewPhiInstr(b.BranchCond, vTrue, vFalse, v))

	return v, vTrue.Type.Bits != vFalse.Type.Bits || diffTrue || diffFalse, true
}

// Serialize serializes the basic block's instructions.
func (b *Block) Serialize() []Step {
	seen := make(map[BlockID]bool)
	return b.serialize(nil, seen)
}

func (b *Block) serialize(code []Step, seen map[BlockID]bool) []Step {
	if seen[b.ID] {
		return code
	}
	// Have all predecessors been processed?
	for _, from := range b.From {
		if !seen[from.ID] {
			return code
		}
	}
	seen[b.ID] = true

	var label string
	if len(b.Name) > 0 {
		label = b.Name
	}

	for _, instr := range b.Instr {
		code = append(code, Step{
			Label: label,
			Instr: instr,
		})
		label = ""
	}

	if b.Branch != nil {
		code = b.Branch.serialize(code, seen)
	}
	if b.Next != nil {
		code = b.Next.serialize(code, seen)
	}
	return code
}

// DotNodes creates graphviz dot description of this basic block.
func (b *Block) DotNodes(out io.Writer, seen map[BlockID]bool) {
	if seen[b.ID] {
		return
	}
	seen[b.ID] = true

	var label string
	if len(b.Instr) == 1 {
		label = b.Instr[0].string(0, false)
	} else {
		var maxLen int
		for _, i := range b.Instr {
			l := len(i.Op.String())
			if l > maxLen {
				maxLen = l
			}
		}
		for _, i := range b.Instr {
			label += i.string(maxLen, false)
			label += "\\l"
		}
	}

	fmt.Fprintf(out, "  %s [label=\"%s\"]\n", b,
		strings.ReplaceAll(label, `"`, `\"`))

	if b.Next != nil {
		b.Next.DotNodes(out, seen)
	}
	if b.Branch != nil {
		b.Branch.DotNodes(out, seen)
	}
}

// DotLinks creates graphviz dot description of the links to and from
// this basic block.
func (b *Block) DotLinks(out io.Writer, seen map[BlockID]bool) {
	if seen[b.ID] {
		return
	}
	seen[b.ID] = true
	if b.Next != nil {
		fmt.Fprintf(out, "  %s -> %s [label=\"%s\"];\n",
			b, b.Next, b.Next)
	}
	if b.Branch != nil {
		fmt.Fprintf(out, "  %s -> %s [label=\"%s\"];\n",
			b, b.Branch, b.Branch)
	}

	if b.Next != nil {
		b.Next.DotLinks(out, seen)
	}
	if b.Branch != nil {
		b.Branch.DotLinks(out, seen)
	}
}

// Dot creates a graphviz dot description of this basic block.
func Dot(out io.Writer, block *Block) {
	fontname := "Courier"
	fontsize := 10

	fmt.Fprintln(out, "digraph program {")
	fmt.Fprintf(out, "  node [shape=box fontname=\"%s\" fontsize=\"%d\"]\n",
		fontname, fontsize)
	fmt.Fprintf(out, "  edge [fontname=\"%s\" fontsize=\"%d\"]\n",
		fontname, fontsize)
	block.DotNodes(out, make(map[BlockID]bool))
	block.DotLinks(out, make(map[BlockID]bool))
	fmt.Fprintln(out, "}")
}
