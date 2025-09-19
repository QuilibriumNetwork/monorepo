//
// Copyright (c) 2020-2024 Markku Rossi
//
// All rights reserved.
//

package ssa

import (
	"fmt"
	"io"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/circuits"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

// Operand specifies SSA assembly operand
type Operand uint8

// SSA assembly operands.
const (
	Iadd Operand = iota
	Uadd
	Fadd
	Isub
	Usub
	Fsub
	Bor
	Bxor
	Band
	Bclr
	Bts
	Btc
	Imult
	Umult
	Fmult
	Idiv
	Udiv
	Fdiv
	Imod
	Umod
	Fmod
	Concat
	Lshift
	Rshift
	Srshift
	Slice
	Index
	Ilt
	Ult
	Flt
	Ile
	Ule
	Fle
	Igt
	Ugt
	Fgt
	Ige
	Uge
	Fge
	Eq
	Neq
	And
	Or
	Not
	Mov
	Smov
	Amov
	Phi
	Ret
	Circ
	Builtin
	GC
)

var operands = map[Operand]string{
	Iadd:    "iadd",
	Uadd:    "uadd",
	Fadd:    "fadd",
	Isub:    "isub",
	Usub:    "usub",
	Fsub:    "fsub",
	Band:    "band",
	Bor:     "bor",
	Bxor:    "bxor",
	Bclr:    "bclr",
	Bts:     "bts",
	Btc:     "btc",
	Imult:   "imult",
	Umult:   "umult",
	Fmult:   "fmult",
	Idiv:    "idiv",
	Udiv:    "udiv",
	Fdiv:    "fdiv",
	Imod:    "imod",
	Umod:    "umod",
	Fmod:    "fmod",
	Concat:  "concat",
	Lshift:  "lshift",
	Rshift:  "rshift",
	Srshift: "srshift",
	Slice:   "slice",
	Index:   "index",
	Ilt:     "ilt",
	Ult:     "ult",
	Flt:     "flt",
	Ile:     "ile",
	Ule:     "ule",
	Fle:     "fle",
	Igt:     "igt",
	Ugt:     "ugt",
	Fgt:     "fgt",
	Ige:     "ige",
	Uge:     "uge",
	Fge:     "fge",
	Eq:      "eq",
	Neq:     "neq",
	And:     "and",
	Or:      "or",
	Not:     "not",
	Mov:     "mov",
	Smov:    "smov",
	Amov:    "amov",
	Phi:     "phi",
	Ret:     "ret",
	Circ:    "circ",
	Builtin: "builtin",
	GC:      "gc",
}

var maxOperandLength int

func init() {
	for _, v := range operands {
		if len(v) > maxOperandLength {
			maxOperandLength = len(v)
		}
	}
}

func (op Operand) String() string {
	name, ok := operands[op]
	if ok {
		return name
	}
	return fmt.Sprintf("{Operand %d}", op)
}

// Instr implements SSA assembly instruction.
type Instr struct {
	Op      Operand
	In      []Value
	Out     *Value
	Label   *Block
	Circ    *circuit.Circuit
	Builtin circuits.Builtin
	GC      *Value
	Ret     []Value
}

// Check verifies that the instruction values are properly set. If any
// unspecified values are found, the Check function panics.
func (i Instr) Check() {
	for _, in := range i.In {
		in.Check()
	}
}

// NewAddInstr creates a new addition instruction based on the type t.
func NewAddInstr(t types.Info, l, r, o Value) (Instr, error) {
	var op Operand
	switch t.Type {
	case types.TInt:
		op = Iadd
	case types.TUint:
		op = Uadd
	case types.TFloat:
		op = Fadd
	case types.TString, types.TArray, types.TSlice:
		op = Concat
	default:
		fmt.Printf("%v + %v (%v)\n", l, r, t)
		return Instr{}, fmt.Errorf("invalid type %s for addition", t)
	}
	return Instr{
		Op:  op,
		In:  []Value{l, r},
		Out: &o,
	}, nil
}

// NewSubInstr creates a new subtraction instruction based on the type
// t.
func NewSubInstr(t types.Info, l, r, o Value) (Instr, error) {
	var op Operand
	switch t.Type {
	case types.TInt:
		op = Isub
	case types.TUint:
		op = Usub
	case types.TFloat:
		op = Fsub
	default:
		return Instr{}, fmt.Errorf("invalid type %s for subtraction", t)
	}
	return Instr{
		Op:  op,
		In:  []Value{l, r},
		Out: &o,
	}, nil
}

// NewMultInstr creates a new multiplication instruction based on the
// type t.
func NewMultInstr(t types.Info, l, r, o Value) (Instr, error) {
	var op Operand
	switch t.Type {
	case types.TInt:
		op = Imult
	case types.TUint:
		op = Umult
	case types.TFloat:
		op = Fmult
	default:
		return Instr{}, fmt.Errorf("invalid type %s for multiplication", t)
	}
	return Instr{
		Op:  op,
		In:  []Value{l, r},
		Out: &o,
	}, nil
}

// NewDivInstr creates a new division instruction based on the type t.
func NewDivInstr(t types.Info, l, r, o Value) (Instr, error) {
	var op Operand
	switch t.Type {
	case types.TInt:
		op = Idiv
	case types.TUint:
		op = Udiv
	case types.TFloat:
		op = Fdiv
	default:
		return Instr{}, fmt.Errorf("invalid type %s for division", t)
	}
	return Instr{
		Op:  op,
		In:  []Value{l, r},
		Out: &o,
	}, nil
}

// NewModInstr creates a new modulo instruction based on the type t.
func NewModInstr(t types.Info, l, r, o Value) (Instr, error) {
	var op Operand
	switch t.Type {
	case types.TInt:
		op = Imod
	case types.TUint:
		op = Umod
	case types.TFloat:
		op = Fmod
	default:
		return Instr{}, fmt.Errorf("invalid type %s for modulo", t)
	}
	return Instr{
		Op:  op,
		In:  []Value{l, r},
		Out: &o,
	}, nil
}

// NewLshiftInstr creates a new Lshift instruction.
func NewLshiftInstr(l, r, o Value) Instr {
	return Instr{
		Op:  Lshift,
		In:  []Value{l, r},
		Out: &o,
	}
}

// NewRshiftInstr creates a new Rshift instruction.
func NewRshiftInstr(l, r, o Value) Instr {
	return Instr{
		Op:  Rshift,
		In:  []Value{l, r},
		Out: &o,
	}
}

// NewSrshiftInstr creates a new Srshift instruction.
func NewSrshiftInstr(l, r, o Value) Instr {
	return Instr{
		Op:  Srshift,
		In:  []Value{l, r},
		Out: &o,
	}
}

// NewSliceInstr creates a new Slice instruction.
func NewSliceInstr(v, from, to, o Value) Instr {
	f, err := from.ConstInt()
	if err != nil {
		panic(err)
	}
	t, err := from.ConstInt()
	if err != nil {
		panic(err)
	}
	if f > t {
		panic(fmt.Sprintf("slice: %v:%v", f, t))
	}
	return Instr{
		Op:  Slice,
		In:  []Value{v, from, to},
		Out: &o,
	}
}

// NewIndexInstr creates a new Index instruction.
func NewIndexInstr(v, offset, index, o Value) Instr {
	return Instr{
		Op:  Index,
		In:  []Value{v, offset, index},
		Out: &o,
	}
}

// NewLtInstr creates a new less-than instruction based on the type t.
func NewLtInstr(t types.Info, l, r, o Value) (Instr, error) {
	var op Operand
	switch t.Type {
	case types.TInt:
		op = Ilt
	case types.TUint:
		op = Ult
	case types.TFloat:
		op = Flt
	default:
		return Instr{}, fmt.Errorf("invalid type %s for < comparison", t)
	}
	return Instr{
		Op:  op,
		In:  []Value{l, r},
		Out: &o,
	}, nil
}

// NewLeInstr creates a new less-equal instruction based on the type
// t.
func NewLeInstr(t types.Info, l, r, o Value) (Instr, error) {
	var op Operand
	switch t.Type {
	case types.TInt:
		op = Ile
	case types.TUint:
		op = Ule
	case types.TFloat:
		op = Fle
	default:
		return Instr{}, fmt.Errorf("invalid type %s for <= comparison", t)
	}
	return Instr{
		Op:  op,
		In:  []Value{l, r},
		Out: &o,
	}, nil
}

// NewGtInstr creates a new greater-than instruction based on the type
// t.
func NewGtInstr(t types.Info, l, r, o Value) (Instr, error) {
	var op Operand
	switch t.Type {
	case types.TInt:
		op = Igt
	case types.TUint:
		op = Ugt
	case types.TFloat:
		op = Fgt
	default:
		return Instr{}, fmt.Errorf("invalid type %s for > comparison", t)
	}
	return Instr{
		Op:  op,
		In:  []Value{l, r},
		Out: &o,
	}, nil
}

// NewGeInstr creates a new greater-equal instruction based on the
// type t.
func NewGeInstr(t types.Info, l, r, o Value) (Instr, error) {
	var op Operand
	switch t.Type {
	case types.TInt:
		op = Ige
	case types.TUint:
		op = Uge
	case types.TFloat:
		op = Fge
	default:
		return Instr{}, fmt.Errorf("invalid type %s for >= comparison", t)
	}
	return Instr{
		Op:  op,
		In:  []Value{l, r},
		Out: &o,
	}, nil
}

// NewEqInstr creates a new Eq instruction.
func NewEqInstr(l, r, o Value) (Instr, error) {
	return Instr{
		Op:  Eq,
		In:  []Value{l, r},
		Out: &o,
	}, nil
}

// NewNeqInstr creates a new Neq instruction.
func NewNeqInstr(l, r, o Value) (Instr, error) {
	return Instr{
		Op:  Neq,
		In:  []Value{l, r},
		Out: &o,
	}, nil
}

// NewAndInstr creates a new And instruction.
func NewAndInstr(l, r, o Value) (Instr, error) {
	return Instr{
		Op:  And,
		In:  []Value{l, r},
		Out: &o,
	}, nil
}

// NewOrInstr creates a new Or instruction.
func NewOrInstr(l, r, o Value) (Instr, error) {
	return Instr{
		Op:  Or,
		In:  []Value{l, r},
		Out: &o,
	}, nil
}

// NewNotInstr creates a new Not instruction.
func NewNotInstr(i, o Value) (Instr, error) {
	return Instr{
		Op:  Not,
		In:  []Value{i},
		Out: &o,
	}, nil
}

// NewBandInstr creates a new Band instruction.
func NewBandInstr(l, r, o Value) (Instr, error) {
	return Instr{
		Op:  Band,
		In:  []Value{l, r},
		Out: &o,
	}, nil
}

// NewBclrInstr creates a new Bclr instruction.
func NewBclrInstr(l, r, o Value) (Instr, error) {
	return Instr{
		Op:  Bclr,
		In:  []Value{l, r},
		Out: &o,
	}, nil
}

// NewBtsInstr creates a new Bts instruction.
func NewBtsInstr(l, r, o Value) Instr {
	return Instr{
		Op:  Bts,
		In:  []Value{l, r},
		Out: &o,
	}
}

// NewBorInstr creates a new Bor instruction.
func NewBorInstr(l, r, o Value) (Instr, error) {
	return Instr{
		Op:  Bor,
		In:  []Value{l, r},
		Out: &o,
	}, nil
}

// NewBxorInstr creates a new Bxor instruction.
func NewBxorInstr(l, r, o Value) (Instr, error) {
	return Instr{
		Op:  Bxor,
		In:  []Value{l, r},
		Out: &o,
	}, nil
}

// NewMovInstr creates a new Mov instruction.
func NewMovInstr(from, to Value) Instr {
	return Instr{
		Op:  Mov,
		In:  []Value{from},
		Out: &to,
	}
}

// NewSmovInstr creates a new Mov instruction.
func NewSmovInstr(from, to Value) Instr {
	return Instr{
		Op:  Smov,
		In:  []Value{from},
		Out: &to,
	}
}

// NewAmovInstr creates a new Amov instruction.
func NewAmovInstr(v, arr, from, to, o Value) Instr {
	return Instr{
		Op:  Amov,
		In:  []Value{v, arr, from, to},
		Out: &o,
	}
}

// NewPhiInstr creates a new Phi instruction.
func NewPhiInstr(cond, t, f, v Value) Instr {
	return Instr{
		Op:  Phi,
		In:  []Value{cond, t, f},
		Out: &v,
	}
}

// NewRetInstr creates a new Ret instruction.
func NewRetInstr(ret []Value) Instr {
	return Instr{
		Op: Ret,
		In: ret,
	}
}

// NewCircInstr creates a new Circ instruction.
func NewCircInstr(args []Value, circ *circuit.Circuit,
	ret []Value) Instr {
	return Instr{
		Op:   Circ,
		In:   args,
		Circ: circ,
		Ret:  ret,
	}
}

// NewBuiltinInstr creates a new Builtin instruction.
func NewBuiltinInstr(builtin circuits.Builtin, a, b, r Value) Instr {
	return Instr{
		Op:      Builtin,
		In:      []Value{a, b},
		Out:     &r,
		Builtin: builtin,
	}
}

// NewGCInstr creates a new GC instruction.
func NewGCInstr(v Value) Instr {
	return Instr{
		Op: GC,
		GC: &v,
	}
}

func (i Instr) String() string {
	return i.string(maxOperandLength, false)
}

// StringTyped returns a typed string representation of the instruction.
func (i Instr) StringTyped() string {
	return i.string(0, true)
}

func (i Instr) string(maxLen int, typesOnly bool) string {
	result := i.Op.String()

	if len(i.In) == 0 && i.Out == nil && i.Label == nil && i.GC == nil {
		return result
	}

	for len(result) < maxLen {
		result += " "
	}
	for _, i := range i.In {
		result += " "
		if typesOnly {
			result += i.Type.String()
		} else {
			result += i.String()
		}
	}
	if i.Out != nil {
		result += " "
		if typesOnly {
			result += i.Out.Type.String()
		} else {
			result += i.Out.String()
		}
	}
	if i.Label != nil {
		result += " "
		result += i.Label.String()
	}
	if i.Circ != nil {
		result += fmt.Sprintf(" {G=%d, W=%d}", i.Circ.NumGates, i.Circ.NumWires)
	}
	if i.GC != nil {
		result += " "
		result += i.GC.String()
	}
	for _, r := range i.Ret {
		result += " "
		result += r.String()
	}
	return result
}

// PP pretty-prints instruction to the specified io.Writer.
func (i Instr) PP(out io.Writer) {
	fmt.Fprintf(out, "\t%s\n", i)
}
