//
// Copyright (c) 2020-2024 Markku Rossi
//
// All rights reserved.
//

package ssa

import (
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/circuits"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

// CompileCircuit compiles the QCL program into a boolean circuit.
func (prog *Program) CompileCircuit(params *utils.Params) (
	*circuit.Circuit, error) {

	calloc := circuits.NewAllocator()

	cc, err := circuits.NewCompiler(params, calloc, prog.Inputs, prog.Outputs,
		prog.InputWires, prog.OutputWires)
	if err != nil {
		return nil, err
	}

	err = prog.DefineConstants(cc.ZeroWire(), cc.OneWire())
	if err != nil {
		return nil, err
	}

	if params.Verbose {
		fmt.Printf("Creating circuit...\n")
	}
	err = prog.Circuit(cc)
	if err != nil {
		return nil, err
	}

	if params.Verbose {
		fmt.Printf("Compiling circuit...\n")
	}
	cc.ConstPropagate()
	cc.ShortCircuitXORZero()
	if params.OptPruneGates {
		orig := float64(len(cc.Gates))
		pruned := cc.Prune()
		if params.Verbose {
			fmt.Printf(" - Pruned %d gates (%.2f%%)\n", pruned,
				float64(pruned)/orig*100)
		}
	}
	circ := cc.Compile()
	if params.CircOut != nil {
		if params.Verbose {
			fmt.Printf("Serializing circuit...\n")
		}
		err = circ.MarshalFormat(params.CircOut, params.CircFormat)
		if err != nil {
			return nil, err
		}
	}
	if params.CircDotOut != nil {
		circ.Dot(params.CircDotOut)
	}
	if params.CircSvgOut != nil {
		circ.Svg(params.CircSvgOut)
	}

	return circ, nil
}

// Circuit creates the boolean circuits for the program steps.
func (prog *Program) Circuit(cc *circuits.Compiler) error {

	for _, step := range prog.Steps {
		instr := step.Instr
		var wires [][]*circuits.Wire
		for idx, in := range instr.In {
			if !in.Type.Concrete() {
				return fmt.Errorf("%s: type %v of input %v not concrete",
					instr, in, idx)
			}
			w, err := prog.walloc.Wires(in, in.Type.Bits)
			if err != nil {
				return err
			}
			if len(w) != int(in.Type.Bits) {
				// Const values are cast to different value
				// sizes. Make sure wire length matches type size.
				cw := make([]*circuits.Wire, in.Type.Bits)

				var pad *circuits.Wire
				if in.Type.Type == types.TInt && len(w) > 0 {
					// Sign extension.
					pad = w[len(w)-1]
				} else {
					pad = cc.ZeroWire()
				}

				for bit := 0; bit < int(in.Type.Bits); bit++ {
					if bit < len(w) {
						cw[bit] = w[bit]
					} else {
						cw[bit] = pad
					}
				}
				wires = append(wires, cw)
			} else {
				wires = append(wires, w)
			}
		}
		switch instr.Op {
		case Iadd, Uadd:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			err = circuits.NewAdder(cc, wires[0], wires[1], o)
			if err != nil {
				return err
			}

		case Isub, Usub:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			err = circuits.NewSubtractor(cc, wires[0], wires[1], o)
			if err != nil {
				return err
			}

		case Imult, Umult:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			err = circuits.NewMultiplier(cc, cc.Params.CircMultArrayTreshold,
				wires[0], wires[1], o)
			if err != nil {
				return err
			}

		case Idiv:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}

			err = circuits.NewIDivider(cc, wires[0], wires[1], o, nil)
			if err != nil {
				return err
			}

		case Udiv:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}

			err = circuits.NewUDivider(cc, wires[0], wires[1], o, nil)
			if err != nil {
				return err
			}

		case Imod:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}

			err = circuits.NewIDivider(cc, wires[0], wires[1], nil, o)
			if err != nil {
				return err
			}

		case Umod:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}

			err = circuits.NewUDivider(cc, wires[0], wires[1], nil, o)
			if err != nil {
				return err
			}

		case Concat:
			o := make([]*circuits.Wire, instr.Out.Type.Bits)
			for i := 0; i < len(wires[0]); i++ {
				o[i] = wires[0][i]
			}
			for i := 0; i < len(wires[1]); i++ {
				o[len(wires[0])+i] = wires[1][i]
			}
			prog.walloc.SetWires(*instr.Out, o)

		case Lshift:
			count, err := instr.In[1].ConstInt()
			if err != nil {
				return fmt.Errorf("%s: unsupported index type %T: %s",
					instr.Op, instr.In[1], err)
			}
			if count < 0 {
				return fmt.Errorf("%s: negative shift count %d",
					instr.Op, count)
			}
			o := make([]*circuits.Wire, instr.Out.Type.Bits)
			for bit := 0; bit < len(o); bit++ {
				var w *circuits.Wire
				if bit-int(count) >= 0 && bit-int(count) < len(wires[0]) {
					w = wires[0][bit-int(count)]
				} else {
					w = cc.ZeroWire()
				}
				o[bit] = w
			}
			prog.walloc.SetWires(*instr.Out, o)

		case Rshift, Srshift:
			var signWire *circuits.Wire
			if instr.Op == Srshift {
				signWire = wires[0][len(wires[0])-1]
			} else {
				signWire = cc.ZeroWire()
			}
			count, err := instr.In[1].ConstInt()
			if err != nil {
				return fmt.Errorf("%s: unsupported index type %T: %s",
					instr.Op, instr.In[1], err)
			}
			if count < 0 {
				return fmt.Errorf("%s: negative shift count %d",
					instr.Op, count)
			}
			o := make([]*circuits.Wire, instr.Out.Type.Bits)
			for bit := 0; bit < len(o); bit++ {
				var w *circuits.Wire
				if bit+int(count) < len(wires[0]) {
					w = wires[0][bit+int(count)]
				} else {
					w = signWire
				}
				o[bit] = w
			}
			prog.walloc.SetWires(*instr.Out, o)

		case Slice:
			from, err := instr.In[1].ConstInt()
			if err != nil {
				return fmt.Errorf("%s: unsupported index type %T: %s",
					instr.Op, instr.In[1], err)
			}

			to, err := instr.In[2].ConstInt()
			if err != nil {
				return fmt.Errorf("%s: unsupported index type %T: %s",
					instr.Op, instr.In[2], err)
			}
			if from >= to {
				return fmt.Errorf("%s: bounds out of range [%d:%d]",
					instr.Op, from, to)
			}
			o := make([]*circuits.Wire, instr.Out.Type.Bits)

			for bit := from; bit < to; bit++ {
				var w *circuits.Wire
				if int(bit) < len(wires[0]) {
					w = wires[0][bit]
				} else {
					w = cc.ZeroWire()
				}
				o[bit-from] = w
			}
			// Make sure all output bits are wired.
			for bit := to - from; int(bit) < len(o); bit++ {
				o[bit] = cc.ZeroWire()
			}
			prog.walloc.SetWires(*instr.Out, o)

		case Index:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			offset, err := instr.In[1].ConstInt()
			if err != nil {
				return fmt.Errorf("%s: unsupported offset type %T: %s",
					instr.Op, instr.In[1], err)
			}
			err = circuits.NewIndex(cc, int(instr.In[0].Type.ElementType.Bits),
				wires[0][offset:], wires[2], o)
			if err != nil {
				return err
			}

		case Ilt, Ult:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			err = circuits.NewLtComparator(cc, wires[0], wires[1], o)
			if err != nil {
				return err
			}

		case Ile, Ule:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			err = circuits.NewLeComparator(cc, wires[0], wires[1], o)
			if err != nil {
				return err
			}

		case Igt, Ugt:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			err = circuits.NewGtComparator(cc, wires[0], wires[1], o)
			if err != nil {
				return err
			}

		case Ige, Uge:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			err = circuits.NewGeComparator(cc, wires[0], wires[1], o)
			if err != nil {
				return err
			}

		case Eq:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			err = circuits.NewEqComparator(cc, wires[0], wires[1], o)
			if err != nil {
				return err
			}

		case Neq:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			err = circuits.NewNeqComparator(cc, wires[0], wires[1], o)
			if err != nil {
				return err
			}

		case Bts:
			index, err := instr.In[1].ConstInt()
			if err != nil {
				return fmt.Errorf("%s unsupported index type %T: %s",
					instr.Op, instr.In[1], err)
			}
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			err = circuits.NewBitSetTest(cc, wires[0], index, o)
			if err != nil {
				return err
			}

		case Btc:
			index, err := instr.In[1].ConstInt()
			if err != nil {
				return fmt.Errorf("%s unsupported index type %T: %s",
					instr.Op, instr.In[1], err)
			}
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			err = circuits.NewBitClrTest(cc, wires[0], index, o)
			if err != nil {
				return err
			}

		case And:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			err = circuits.NewLogicalAND(cc, wires[0], wires[1], o)
			if err != nil {
				return err
			}

		case Or:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			err = circuits.NewLogicalOR(cc, wires[0], wires[1], o)
			if err != nil {
				return err
			}

		case Not:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			for i := 0; i < int(instr.Out.Type.Bits); i++ {
				cc.INV(wires[0][i], o[i])
			}

		case Band:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			err = circuits.NewBinaryAND(cc, wires[0], wires[1], o)
			if err != nil {
				return err
			}

		case Bclr:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			err = circuits.NewBinaryClear(cc, wires[0], wires[1], o)
			if err != nil {
				return err
			}

		case Bor:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			err = circuits.NewBinaryOR(cc, wires[0], wires[1], o)
			if err != nil {
				return err
			}

		case Bxor:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			err = circuits.NewBinaryXOR(cc, wires[0], wires[1], o)
			if err != nil {
				return err
			}

		case Mov, Smov:
			var signWire *circuits.Wire
			if instr.Op == Smov {
				signWire = wires[0][len(wires[0])-1]
			} else {
				signWire = cc.ZeroWire()
			}

			o := make([]*circuits.Wire, instr.Out.Type.Bits)

			for bit := 0; bit < int(instr.Out.Type.Bits); bit++ {
				var w *circuits.Wire
				if bit < len(wires[0]) {
					w = wires[0][bit]
				} else {
					w = signWire
				}
				o[bit] = w
			}
			prog.walloc.SetWires(*instr.Out, o)

		case Amov:
			// v arr from to:
			// array[from:to] = v
			from, err := instr.In[2].ConstInt()
			if err != nil {
				return fmt.Errorf("%s: unsupported index type %T: %s",
					instr.Op, instr.In[2], err)
			}
			to, err := instr.In[3].ConstInt()
			if err != nil {
				return fmt.Errorf("%s: unsupported index type %T: %s",
					instr.Op, instr.In[3], err)
			}
			if from < 0 || from >= to {
				return fmt.Errorf("%s: bounds out of range [%d:%d]",
					instr.Op, from, to)
			}
			o := make([]*circuits.Wire, instr.Out.Type.Bits)

			for bit := types.Size(0); bit < instr.Out.Type.Bits; bit++ {
				var w *circuits.Wire
				if bit < from || bit >= to {
					if bit < types.Size(len(wires[1])) {
						w = wires[1][bit]
					} else {
						w = cc.ZeroWire()
					}
				} else {
					idx := bit - from
					if idx < types.Size(len(wires[0])) {
						w = wires[0][idx]
					} else {
						w = cc.ZeroWire()
					}
				}
				o[bit] = w
			}
			prog.walloc.SetWires(*instr.Out, o)

		case Phi:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			err = circuits.NewMUX(cc, wires[0], wires[1], wires[2], o)
			if err != nil {
				return err
			}

		case Ret:
			// Assign output wires.
			for _, wg := range wires {
				for _, w := range wg {
					o := cc.Calloc.Wire()
					cc.ID(w, o)
					cc.OutputWires = append(cc.OutputWires, o)
				}
			}
			for _, o := range cc.OutputWires {
				o.SetOutput(true)
			}

		case Circ:
			var circWires []*circuits.Wire

			// Flatten input wires.
			for wi, w := range wires {
				circWires = append(circWires, w...)
				for i := len(w); i < int(instr.Circ.Inputs[wi].Type.Bits); i++ {
					// Zeroes for unset input wires.
					zw := cc.ZeroWire()
					circWires = append(circWires, zw)
				}
			}

			// Flatten output wires.
			var circOut []*circuits.Wire

			for _, r := range instr.Ret {
				o, err := prog.walloc.Wires(r, r.Type.Bits)
				if err != nil {
					return err
				}
				circOut = append(circOut, o...)
			}

			// Add intermediate wires.
			nint := instr.Circ.NumWires - len(circWires) - len(circOut)
			for i := 0; i < nint; i++ {
				circWires = append(circWires, cc.Calloc.Wire())
			}

			// Append output wires.
			circWires = append(circWires, circOut...)

			// Add gates.
			for _, gate := range instr.Circ.Gates {
				switch gate.Op {
				case circuit.XOR:
					cc.AddGate(cc.Calloc.BinaryGate(circuit.XOR,
						circWires[gate.Input0],
						circWires[gate.Input1],
						circWires[gate.Output]))
				case circuit.XNOR:
					cc.AddGate(cc.Calloc.BinaryGate(circuit.XNOR,
						circWires[gate.Input0],
						circWires[gate.Input1],
						circWires[gate.Output]))
				case circuit.AND:
					cc.AddGate(cc.Calloc.BinaryGate(circuit.AND,
						circWires[gate.Input0],
						circWires[gate.Input1],
						circWires[gate.Output]))
				case circuit.OR:
					cc.AddGate(cc.Calloc.BinaryGate(circuit.OR,
						circWires[gate.Input0],
						circWires[gate.Input1],
						circWires[gate.Output]))
				case circuit.INV:
					cc.INV(circWires[gate.Input0], circWires[gate.Output])
				default:
					return fmt.Errorf("unknown gate %s", gate)
				}
			}

		case Builtin:
			o, err := prog.walloc.Wires(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return err
			}
			err = instr.Builtin(cc, wires[0], wires[1], o)
			if err != nil {
				return err
			}

		case GC:

		default:
			return fmt.Errorf("Block.Circuit: %s not implemented yet", instr.Op)
		}
	}

	return nil
}
