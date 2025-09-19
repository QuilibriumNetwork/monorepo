//
// Copyright (c) 2020-2024 Markku Rossi
//
// All rights reserved.
//

package ssa

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"sort"
	"time"

	"github.com/markkurossi/tabulate"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/circuits"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/ot"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/p2p"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

// Stream streams the program circuit into the P2P connection.
func (prog *Program) Stream(conn *p2p.Conn, oti ot.OT,
	params *utils.Params, inputs *big.Int, timing *circuit.Timing) (
	circuit.IO, []*big.Int, error) {

	var key [32]byte
	_, err := rand.Read(key[:])
	if err != nil {
		return nil, nil, err
	}

	if params.Verbose {
		fmt.Printf(" - Sending program info...\n")
	}
	if err := conn.SendData(key[:]); err != nil {
		return nil, nil, err
	}
	if params.Verbose {
		fmt.Println(" - Sent initial data")
	}
	// Our input.
	if err := sendArgument(conn, prog.Inputs[0]); err != nil {
		return nil, nil, err
	}
	if params.Verbose {
		fmt.Println(" - Sent input data")
	}
	// Peer input.
	if err := sendArgument(conn, prog.Inputs[1]); err != nil {
		return nil, nil, err
	}
	if params.Verbose {
		fmt.Println(" - Sent peer input data")
	}
	// Program outputs.
	if err := conn.SendUint32(len(prog.Outputs)); err != nil {
		return nil, nil, err
	}
	if params.Verbose {
		fmt.Println(" - Sent program outputs length")
	}
	for _, o := range prog.Outputs {
		if err := sendArgument(conn, o); err != nil {
			return nil, nil, err
		}
	}
	if params.Verbose {
		fmt.Println(" - Sent program outputs")
	}
	// Number of program steps.
	if err := conn.SendUint32(len(prog.Steps)); err != nil {
		return nil, nil, err
	}

	if err := conn.Flush(); err != nil {
		return nil, nil, err
	}
	if params.Verbose {
		fmt.Println(" - Sent program steps")
	}
	// Collect input wire IDs.
	var ids []circuit.Wire
	for _, w := range prog.InputWires {
		// Program's inputs are unassigned because parser is shared
		// between streaming and non-streaming modes.
		w.SetID(prog.walloc.NextWireID())
		ids = append(ids, w.ID())
	}

	streaming, err := circuit.NewStreaming(key[:], ids, conn)
	if err != nil {
		return nil, nil, err
	}

	// Select our inputs.
	var n1 []ot.Label
	for i := 0; i < int(prog.Inputs[0].Type.Bits); i++ {
		wire := streaming.GetInput(circuit.Wire(i))

		var n ot.Label
		if inputs.Bit(i) == 1 {
			n = wire.L1
		} else {
			n = wire.L0
		}
		n1 = append(n1, n)
	}

	// Send our inputs.
	var labelData ot.LabelData
	for idx, i := range n1 {
		if params.Verbose && false {
			fmt.Printf("N1[%d]:\t%s\n", idx, i)
		}
		if err := conn.SendLabel(i, &labelData); err != nil {
			return nil, nil, err
		}
	}

	if err := conn.Flush(); err != nil {
		return nil, nil, err
	}

	ioStats := conn.Stats.Sum()
	timing.Sample("Init", []string{circuit.FileSize(ioStats).String()})

	// Init oblivious transfer.
	err = oti.InitSender(conn)
	if err != nil {
		return nil, nil, err
	}
	xfer := conn.Stats.Sum() - ioStats
	ioStats = conn.Stats.Sum()
	timing.Sample("OT Init", []string{circuit.FileSize(xfer).String()})

	// Peer OTs its inputs.
	err = oti.Send(streaming.GetInputs(int(prog.Inputs[0].Type.Bits),
		int(prog.Inputs[1].Type.Bits)))
	if err != nil {
		return nil, nil, err
	}
	xfer = conn.Stats.Sum() - ioStats
	ioStats = conn.Stats.Sum()
	timing.Sample("Peer Inputs", []string{circuit.FileSize(xfer).String()})

	zero, err := prog.ZeroWire(conn, streaming)
	if err != nil {
		return nil, nil, err
	}
	one, err := prog.OneWire(conn, streaming)
	if err != nil {
		return nil, nil, err
	}

	err = prog.DefineConstants(zero, one)
	if err != nil {
		return nil, nil, err
	}

	// Stream circuit.

	cache := make(map[string]*circuit.Circuit)
	var returnIDs []circuit.Wire

	start := time.Now()
	lastReport := start

	var dInstrInit time.Duration
	var dCircCompile time.Duration

	istats := make(map[string]circuit.Stats)

	var wires [][]circuit.Wire
	var iIDs, oIDs []circuit.Wire

	for idx, step := range prog.Steps {
		dStart := time.Now()
		if idx%10 == 0 && params.Verbose {
			now := time.Now()
			if now.Sub(lastReport) > time.Second*5 {
				lastReport = now
				elapsed := now.Sub(start)
				done := float64(idx) / float64(len(prog.Steps))
				if done > 0 {
					total := time.Duration(float64(elapsed) / done)
					progress := fmt.Sprintf("%d/%d", idx, len(prog.Steps))
					remaining := fmt.Sprintf("%24s", total-elapsed)
					fmt.Printf("%-14s\t%s remaining\tETA %s\n",
						progress, remaining,
						start.Add(total).Format(time.Stamp))
				} else {
					fmt.Printf("%d/%d\n", idx, len(prog.Steps))
				}
			}
		}
		instr := step.Instr
		wires = wires[:0]
		for _, in := range instr.In {
			w, err := prog.walloc.AssignedIDs(in, in.Type.Bits)
			if err != nil {
				return nil, nil, err
			}
			if len(w) != int(in.Type.Bits) {
				// Const values are cast to different value
				// sizes. Make sure wire length matches type size.
				cw := make([]circuit.Wire, in.Type.Bits)

				var pad circuit.Wire
				if in.Type.Type == types.TInt && len(w) > 0 {
					// Sign expansion.
					pad = w[len(w)-1]
				} else {
					zero, err = prog.ZeroWire(conn, streaming)
					if err != nil {
						return nil, nil, err
					}
					pad = zero.ID()
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

		var out []circuit.Wire
		var err error
		if instr.Out != nil {
			out, err = prog.walloc.AssignedIDs(*instr.Out, instr.Out.Type.Bits)
			if err != nil {
				return nil, nil, err
			}
		}

		if params.Verbose && circuit.StreamDebug {
			fmt.Printf("%05d: %s\n", idx, instr.String())
		}
		dInstrInit += time.Now().Sub(dStart)

		switch instr.Op {

		case Concat:
			for bit := 0; bit < len(out); bit++ {
				var id circuit.Wire
				if bit < len(wires[0]) {
					id = wires[0][bit]
				} else {
					id = wires[1][bit-len(wires[0])]
				}
				out[bit] = id
			}

		case Lshift:
			count, err := instr.In[1].ConstInt()
			if err != nil {
				return nil, nil,
					fmt.Errorf("%s: unsupported index type %T: %s",
						instr.Op, instr.In[1], err)
			}
			if count < 0 {
				return nil, nil,
					fmt.Errorf("%s: negative shift count %d", instr.Op, count)
			}
			for bit := 0; bit < len(out); bit++ {
				var id circuit.Wire
				if bit-int(count) >= 0 && bit-int(count) < len(wires[0]) {
					id = wires[0][bit-int(count)]
				} else {
					w, err := prog.ZeroWire(conn, streaming)
					if err != nil {
						return nil, nil, err
					}
					id = w.ID()
				}
				out[bit] = id
			}

		case Rshift, Srshift:
			var signWire circuit.Wire
			if instr.Op == Srshift {
				signWire = wires[0][len(wires[0])-1]
			} else {
				zero, err := prog.ZeroWire(conn, streaming)
				if err != nil {
					return nil, nil, err
				}
				signWire = zero.ID()
			}
			count, err := instr.In[1].ConstInt()
			if err != nil {
				return nil, nil,
					fmt.Errorf("%s: unsupported index type %T: %s",
						instr.Op, instr.In[1], err)
			}
			if count < 0 {
				return nil, nil,
					fmt.Errorf("%s: negative shift count %d", instr.Op, count)
			}
			for bit := 0; bit < len(out); bit++ {
				var id circuit.Wire
				if bit+int(count) < len(wires[0]) {
					id = wires[0][bit+int(count)]
				} else {
					id = signWire
				}
				out[bit] = id
			}

		case Slice:
			from, err := instr.In[1].ConstInt()
			if err != nil {
				return nil, nil,
					fmt.Errorf("%s: unsupported index type %T: %s",
						instr.Op, instr.In[1], err)
			}
			to, err := instr.In[2].ConstInt()
			if err != nil {
				return nil, nil,
					fmt.Errorf("%s: unsupported index type %T: %s",
						instr.Op, instr.In[2], err)
			}
			if from >= to {
				return nil, nil, fmt.Errorf("%s: bounds out of range [%d:%d]",
					instr.Op, from, to)
			}
			for bit := from; bit < to; bit++ {
				var id circuit.Wire
				if int(bit) < len(wires[0]) {
					id = wires[0][bit]
				} else {
					w, err := prog.ZeroWire(conn, streaming)
					if err != nil {
						return nil, nil, err
					}
					id = w.ID()
				}
				out[bit-from] = id
			}

		case Mov, Smov:
			var signWire circuit.Wire
			if instr.Op == Smov {
				signWire = wires[0][len(wires[0])-1]
			} else {
				zero, err := prog.ZeroWire(conn, streaming)
				if err != nil {
					return nil, nil, err
				}
				signWire = zero.ID()
			}
			for bit := types.Size(0); bit < instr.Out.Type.Bits; bit++ {
				var id circuit.Wire
				if bit < types.Size(len(wires[0])) {
					id = wires[0][bit]
				} else {
					id = signWire
				}
				out[bit] = id
			}

		case Amov:
			// v arr from to:
			// array[from:to] = v
			from, err := instr.In[2].ConstInt()
			if err != nil {
				return nil, nil, fmt.Errorf("%s: unsupported index type %T: %s",
					instr.Op, instr.In[2], err)
			}
			to, err := instr.In[3].ConstInt()
			if err != nil {
				return nil, nil, fmt.Errorf("%s: unsupported index type %T: %s",
					instr.Op, instr.In[3], err)
			}
			if from < 0 || from >= to {
				return nil, nil, fmt.Errorf("%s: bounds out of range [%d:%d]",
					instr.Op, from, to)
			}

			for bit := types.Size(0); bit < instr.Out.Type.Bits; bit++ {
				var id circuit.Wire
				if bit < from || bit >= to {
					if bit < types.Size(len(wires[1])) {
						id = wires[1][bit]
					} else {
						w, err := prog.ZeroWire(conn, streaming)
						if err != nil {
							return nil, nil, err
						}
						id = w.ID()
					}
				} else {
					idx := bit - from
					if idx < types.Size(len(wires[0])) {
						id = wires[0][idx]
					} else {
						w, err := prog.ZeroWire(conn, streaming)
						if err != nil {
							return nil, nil, err
						}
						id = w.ID()
					}
				}
				out[bit] = id
			}

		case Ret:
			if err := conn.SendUint32(circuit.OpReturn); err != nil {
				return nil, nil, err
			}
			for _, arg := range wires {
				for _, w := range arg {
					if err := conn.SendUint32(w.Int()); err != nil {
						return nil, nil, err
					}
					returnIDs = append(returnIDs, w)
				}
			}
			if circuit.StreamDebug {
				fmt.Printf("return=%v\n", returnIDs)
			}
			if err := conn.Flush(); err != nil {
				return nil, nil, err
			}

		case Circ:
			// Collect input and output IDs
			iIDs = iIDs[:0]
			oIDs = oIDs[:0]
			for i := 0; i < len(wires); i++ {
				for j := 0; j < int(instr.Circ.Inputs[i].Type.Bits); j++ {
					if j < len(wires[i]) {
						iIDs = append(iIDs, wires[i][j])
					} else {
						iIDs = append(iIDs, prog.zeroWire.ID())
					}
				}
			}
			// Return wires.
			for i, ret := range instr.Ret {
				wires, err := prog.walloc.AssignedIDs(ret, ret.Type.Bits)
				if err != nil {
					return nil, nil, err
				}
				for j := 0; j < int(instr.Circ.Outputs[i].Type.Bits); j++ {
					if j < len(wires) {
						oIDs = append(oIDs, wires[j])
					} else {
						oIDs = append(oIDs, prog.zeroWire.ID())
					}
				}
			}
			if len(oIDs) != instr.Circ.Outputs.Size() {
				return nil, nil, fmt.Errorf("%s: output mismatch: %d vs. %d",
					instr.Op, len(oIDs), instr.Circ.Outputs.Size())
			}
			if params.Verbose && circuit.StreamDebug {
				fmt.Printf("%05d: - circuit: %s\n", idx, instr.Circ)
			}
			if params.Diagnostics {
				addStats(istats, instr, instr.Circ)
			}
			err = prog.garble(conn, streaming, idx, instr.Circ, iIDs, oIDs)
			if err != nil {
				return nil, nil, err
			}

		case GC:
			prog.walloc.GCWires(*instr.GC)

		default:
			f, ok := circuitGenerators[instr.Op]
			if !ok {
				return nil, nil,
					fmt.Errorf("Program.StreamCircuit: %s not implemented yet",
						instr.Op)
			}
			if params.Verbose && circuit.StreamDebug {
				fmt.Printf(" - %s\n", instr.StringTyped())
			}
			circ, ok := cache[instr.StringTyped()]
			if !ok {
				var cIn [][]*circuits.Wire
				var flat []*circuits.Wire
				startTime := time.Now()

				for _, in := range wires {
					w := prog.calloc.Wires(types.Size(len(in)))
					cIn = append(cIn, w)
					flat = append(flat, w...)
				}

				cOut := prog.calloc.Wires(instr.Out.Type.Bits)
				for i := types.Size(0); i < instr.Out.Type.Bits; i++ {
					cOut[i].SetOutput(true)
				}

				cc, err := circuits.NewCompiler(params, prog.calloc, nil, nil,
					flat, cOut)
				if err != nil {
					return nil, nil, err
				}
				cacheable, err := f(cc, instr, cIn, cOut)
				if err != nil {
					return nil, nil, err
				}
				cc.ConstPropagate()
				pruned := cc.Prune()
				if params.Verbose && circuit.StreamDebug {
					fmt.Printf("%05d: - pruned %d gates\n", idx, pruned)
				}
				circ = cc.Compile()
				if cacheable {
					cache[instr.StringTyped()] = circ
				}
				if params.Verbose && circuit.StreamDebug {
					fmt.Printf("%05d: - %s\n", idx, circ)
				}
				circ.AssignLevels()
				dCircCompile += time.Now().Sub(startTime)
			}
			if false {
				circ.Dump()
				fmt.Printf("%05d: - circuit: %s\n", idx, circ)
			}
			if params.Diagnostics {
				addStats(istats, instr, circ)
			}

			// Collect input and output IDs
			iIDs = iIDs[:0]
			oIDs = oIDs[:0]
			for _, vars := range wires {
				for _, w := range vars {
					iIDs = append(iIDs, w)
				}
			}
			for _, w := range out {
				oIDs = append(oIDs, w)
			}

			err = prog.garble(conn, streaming, idx, circ, iIDs, oIDs)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	xfer = conn.Stats.Sum() - ioStats
	ioStats = conn.Stats.Sum()
	sample := timing.Sample("Stream", []string{circuit.FileSize(xfer).String()})
	sample.Samples = append(sample.Samples, &circuit.Sample{
		Label: "InstrInit",
		Abs:   dInstrInit,
	})
	sample.Samples = append(sample.Samples, &circuit.Sample{
		Label: "CircComp",
		Abs:   dCircCompile,
	})
	sample.Samples = append(sample.Samples, &circuit.Sample{
		Label: "StreamInit",
		Abs:   prog.tInit,
	})
	sample.Samples = append(sample.Samples, &circuit.Sample{
		Label: "Garble",
		Abs:   prog.tGarble,
	})

	result := new(big.Int)

	op, err := conn.ReceiveUint32()
	if err != nil {
		return nil, nil, err
	}
	if op != circuit.OpResult {
		return nil, nil, fmt.Errorf("unexpected operation: %d", op)
	}

	var label ot.Label

	for i := 0; i < prog.Outputs.Size(); i++ {
		err := conn.ReceiveLabel(&label, &labelData)
		if err != nil {
			return nil, nil, err
		}
		wire := streaming.GetInput(returnIDs[i])
		var bit uint
		if label.Equal(wire.L0) {
			bit = 0
		} else if label.Equal(wire.L1) {
			bit = 1
		} else {
			return nil, nil, fmt.Errorf("unknown label %s for result %d",
				label, i)
		}
		result.SetBit(result, i, bit)
	}
	data := result.Bytes()
	if err := conn.SendData(data); err != nil {
		return nil, nil, err
	}
	if err := conn.Flush(); err != nil {
		return nil, nil, err
	}

	xfer = conn.Stats.Sum() - ioStats
	timing.Sample("Result", []string{circuit.FileSize(xfer).String()})

	if params.Verbose {
		timing.Print(conn.Stats)
	}

	fmt.Printf("Max permanent wires: %d, cached circuits: %d\n",
		prog.walloc.NextWireID(), len(cache))
	fmt.Printf("#gates=%d (%s) #w=%d\n", prog.stats.Count(), prog.stats,
		prog.numWires)

	if params.Diagnostics {
		tab := tabulate.New(tabulate.CompactUnicodeLight)
		tab.Header("Instr").SetAlign(tabulate.ML)
		tab.Header("Count").SetAlign(tabulate.MR)
		tab.Header("XOR").SetAlign(tabulate.MR)
		tab.Header("XNOR").SetAlign(tabulate.MR)
		tab.Header("AND").SetAlign(tabulate.MR)
		tab.Header("OR").SetAlign(tabulate.MR)
		tab.Header("INV").SetAlign(tabulate.MR)
		tab.Header("!XOR").SetAlign(tabulate.MR)
		tab.Header("L").SetAlign(tabulate.MR)
		tab.Header("W").SetAlign(tabulate.MR)

		var keys []string
		for k := range istats {
			keys = append(keys, k)
		}

		sort.Slice(keys, func(i, j int) bool {
			return istats[keys[i]].Cost() > istats[keys[j]].Cost()
		})

		for _, key := range keys {
			stats := istats[key]
			if stats.Count() > 0 {
				row := tab.Row()
				row.Column(key)
				row.Column(fmt.Sprintf("%d", stats[circuit.Count]))
				row.Column(fmt.Sprintf("%d", stats[circuit.XOR]))
				row.Column(fmt.Sprintf("%d", stats[circuit.XNOR]))
				row.Column(fmt.Sprintf("%d", stats[circuit.AND]))
				row.Column(fmt.Sprintf("%d", stats[circuit.OR]))
				row.Column(fmt.Sprintf("%d", stats[circuit.INV]))
				row.Column(fmt.Sprintf("%d",
					stats[circuit.OR]+stats[circuit.AND]+stats[circuit.INV]))
				row.Column(fmt.Sprintf("%d", stats[circuit.NumLevels]))
				row.Column(fmt.Sprintf("%d", stats[circuit.MaxWidth]))
			}
		}
		tab.Print(os.Stdout)
	}

	return prog.Outputs, prog.Outputs.Split(result), nil
}

func addStats(istats map[string]circuit.Stats, instr Instr,
	circ *circuit.Circuit) {

	var max types.Size
	for _, in := range instr.In {
		if in.Type.Bits > max {
			max = in.Type.Bits
		}
	}
	key := fmt.Sprintf("%s/%d", instr.Op, max)
	stats, ok := istats[key]
	if !ok {
		stats = circuit.Stats{}
	}
	stats.Add(circ.Stats)
	istats[key] = stats
}

func (prog *Program) garble(conn *p2p.Conn, streaming *circuit.Streaming,
	step int, circ *circuit.Circuit, in, out []circuit.Wire) error {

	var maxID circuit.Wire
	for _, id := range in {
		if id > maxID {
			maxID = id
		}
	}
	for _, id := range out {
		if id > maxID {
			maxID = id
		}
	}

	if err := conn.SendUint32(circuit.OpCircuit); err != nil {
		return err
	}
	if err := conn.SendUint32(step); err != nil {
		return err
	}
	if err := conn.SendUint32(circ.NumGates); err != nil {
		return err
	}
	if err := conn.SendUint32(circ.NumWires); err != nil {
		return err
	}
	if err := conn.SendUint32(int(maxID + 1)); err != nil {
		return err
	}
	if err := conn.Flush(); err != nil {
		return err
	}
	tInit, tGarble, err := streaming.Garble(circ, in, out)
	if err != nil {
		return err
	}
	prog.tInit += tInit
	prog.tGarble += tGarble
	prog.stats.Add(circ.Stats)
	prog.numWires += circ.NumWires

	return nil
}

// ZeroWire returns a wire with value 0.
func (prog *Program) ZeroWire(conn *p2p.Conn, streaming *circuit.Streaming) (
	*circuits.Wire, error) {

	if prog.zeroWire == nil {
		wires, err := prog.walloc.AssignedWires(Value{
			Const: true,
			Name:  "{zero}",
		}, 1)
		if err != nil {
			return nil, err
		}
		err = prog.garble(conn, streaming, 0, &circuit.Circuit{
			NumGates: 1,
			NumWires: 2,
			Inputs: []circuit.IOArg{
				{
					Name: "i0",
					Type: types.Info{
						Type:       types.TUint,
						IsConcrete: true,
						Bits:       1,
					},
				},
			},
			Outputs: []circuit.IOArg{
				{
					Name: "o0",
					Type: types.Info{
						Type:       types.TUint,
						IsConcrete: true,
						Bits:       1,
					},
				},
			},
			Gates: []circuit.Gate{
				{
					Input0: 0,
					Input1: 0,
					Output: 1,
					Op:     circuit.XOR,
				},
			},
			Stats: circuit.Stats{
				circuit.XOR: 1,
			},
		}, []circuit.Wire{0}, []circuit.Wire{wires[0].ID()})
		if err != nil {
			return nil, err
		}
		prog.zeroWire = wires[0]
	}
	return prog.zeroWire, nil
}

// OneWire returns wire with value 1.
func (prog *Program) OneWire(conn *p2p.Conn, streaming *circuit.Streaming) (
	*circuits.Wire, error) {

	if prog.oneWire == nil {
		wires, err := prog.walloc.AssignedWires(Value{
			Const: true,
			Name:  "{one}",
		}, 1)
		if err != nil {
			return nil, err
		}
		err = prog.garble(conn, streaming, 0, &circuit.Circuit{
			NumGates: 1,
			NumWires: 2,
			Inputs: []circuit.IOArg{
				{
					Name: "i0",
					Type: types.Info{
						Type:       types.TUint,
						IsConcrete: true,
						Bits:       1,
					},
				},
			},
			Outputs: []circuit.IOArg{
				{
					Name: "o0",
					Type: types.Info{
						Type:       types.TUint,
						IsConcrete: true,
						Bits:       1,
					},
				},
			},
			Gates: []circuit.Gate{
				{
					Input0: 0,
					Input1: 0,
					Output: 1,
					Op:     circuit.XNOR,
				},
			},
			Stats: circuit.Stats{
				circuit.XNOR: 1,
			},
		}, []circuit.Wire{0}, []circuit.Wire{wires[0].ID()})
		if err != nil {
			return nil, err
		}
		prog.oneWire = wires[0]
	}
	return prog.oneWire, nil
}

func sendArgument(conn *p2p.Conn, arg circuit.IOArg) error {
	if err := conn.SendString(arg.Name); err != nil {
		return err
	}
	if err := conn.SendString(arg.Type.String()); err != nil {
		return err
	}
	if err := conn.SendUint32(int(arg.Type.Bits)); err != nil {
		return err
	}

	if err := conn.SendUint32(len(arg.Compound)); err != nil {
		return err
	}
	for _, a := range arg.Compound {
		if err := sendArgument(conn, a); err != nil {
			return err
		}
	}

	return nil
}

// NewCircuit creates a new circuit.
type NewCircuit func(cc *circuits.Compiler, instr Instr, in [][]*circuits.Wire,
	out []*circuits.Wire) (cacheable bool, err error)

// NewBinary creates a new binary circuit.
type NewBinary func(cc *circuits.Compiler, a, b []*circuits.Wire,
	out []*circuits.Wire) error

func newBinary(bin NewBinary) NewCircuit {
	return func(cc *circuits.Compiler, instr Instr, in [][]*circuits.Wire,
		out []*circuits.Wire) (bool, error) {
		return true, bin(cc, in[0], in[1], out)
	}
}

func newMultiplier(cc *circuits.Compiler, instr Instr, in [][]*circuits.Wire,
	out []*circuits.Wire) (bool, error) {
	return true, circuits.NewMultiplier(cc, cc.Params.CircMultArrayTreshold,
		in[0], in[1], out)
}

func newIDivider(cc *circuits.Compiler, instr Instr, in [][]*circuits.Wire,
	out []*circuits.Wire) (bool, error) {
	return true, circuits.NewIDivider(cc, in[0], in[1], out, nil)
}

func newUDivider(cc *circuits.Compiler, instr Instr, in [][]*circuits.Wire,
	out []*circuits.Wire) (bool, error) {
	return true, circuits.NewUDivider(cc, in[0], in[1], out, nil)
}

func newIModulo(cc *circuits.Compiler, instr Instr, in [][]*circuits.Wire,
	out []*circuits.Wire) (bool, error) {
	return true, circuits.NewIDivider(cc, in[0], in[1], nil, out)
}

func newUModulo(cc *circuits.Compiler, instr Instr, in [][]*circuits.Wire,
	out []*circuits.Wire) (bool, error) {
	return true, circuits.NewUDivider(cc, in[0], in[1], nil, out)
}

func newIndex(cc *circuits.Compiler, instr Instr, in [][]*circuits.Wire,
	out []*circuits.Wire) (bool, error) {
	offset, err := instr.In[1].ConstInt()
	if err != nil {
		return false, fmt.Errorf("%s: unsupported offset type %T: %s",
			instr.Op, instr.In[1], err)
	}
	return true, circuits.NewIndex(cc, int(instr.In[0].Type.ElementType.Bits),
		in[0][offset:], in[2], out)
}

func newNot(cc *circuits.Compiler, instr Instr, in [][]*circuits.Wire,
	out []*circuits.Wire) (bool, error) {
	for i := 0; i < len(out); i++ {
		cc.INV(in[0][i], out[i])
	}
	return true, nil
}

var circuitGenerators = map[Operand]NewCircuit{
	Iadd:  newBinary(circuits.NewAdder),
	Uadd:  newBinary(circuits.NewAdder),
	Isub:  newBinary(circuits.NewSubtractor),
	Usub:  newBinary(circuits.NewSubtractor),
	Imult: newMultiplier,
	Umult: newMultiplier,
	Idiv:  newIDivider,
	Udiv:  newUDivider,
	Imod:  newIModulo,
	Umod:  newUModulo,
	Index: newIndex,
	Ilt:   newBinary(circuits.NewLtComparator),
	Ult:   newBinary(circuits.NewLtComparator),
	Ile:   newBinary(circuits.NewLeComparator),
	Ule:   newBinary(circuits.NewLeComparator),
	Igt:   newBinary(circuits.NewGtComparator),
	Ugt:   newBinary(circuits.NewGtComparator),
	Ige:   newBinary(circuits.NewGeComparator),
	Uge:   newBinary(circuits.NewGeComparator),
	Eq:    newBinary(circuits.NewEqComparator),
	Neq:   newBinary(circuits.NewNeqComparator),
	And:   newBinary(circuits.NewLogicalAND),
	Or:    newBinary(circuits.NewLogicalOR),
	Not:   newNot,
	Band:  newBinary(circuits.NewBinaryAND),
	Bclr:  newBinary(circuits.NewBinaryClear),
	Bor:   newBinary(circuits.NewBinaryOR),
	Bxor:  newBinary(circuits.NewBinaryXOR),

	Builtin: func(cc *circuits.Compiler, instr Instr, in [][]*circuits.Wire,
		out []*circuits.Wire) (bool, error) {
		return true, instr.Builtin(cc, in[0], in[1], out)
	},
	Phi: func(cc *circuits.Compiler, instr Instr, in [][]*circuits.Wire,
		out []*circuits.Wire) (bool, error) {
		return true, circuits.NewMUX(cc, in[0], in[1], in[2], out)
	},
	Bts: func(cc *circuits.Compiler, instr Instr, in [][]*circuits.Wire,
		out []*circuits.Wire) (bool, error) {
		index, err := instr.In[1].ConstInt()
		if err != nil {
			return false,
				fmt.Errorf("%s unsupported index type %T: %s",
					instr.Op, instr.In[1], err)
		}
		return false, circuits.NewBitSetTest(cc, in[0], index, out)
	},
	Btc: func(cc *circuits.Compiler, instr Instr, in [][]*circuits.Wire,
		out []*circuits.Wire) (bool, error) {
		index, err := instr.In[1].ConstInt()
		if err != nil {
			return false,
				fmt.Errorf("%s unsupported index type %T: %s",
					instr.Op, instr.In[1], err)
		}
		return false, circuits.NewBitClrTest(cc, in[0], index, out)
	},
}
