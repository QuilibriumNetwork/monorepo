//
// Copyright (c) 2020-2021, 2023 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/ot"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/p2p"
)

const (
	// StreamDebug controls the debugging output of the streaming
	// garbling.
	StreamDebug = false
)

// Streaming is a streaming garbled circuit garbler.
type Streaming struct {
	conn     *p2p.Conn
	key      []byte
	alg      cipher.Block
	r        ot.Label
	wires    []ot.Wire
	tmp      []ot.Wire
	in       []Wire
	out      []Wire
	firstTmp Wire
	firstOut Wire
}

// NewStreaming creates a new streaming garbled circuit garbler.
func NewStreaming(key []byte, inputs []Wire, conn *p2p.Conn) (
	*Streaming, error) {

	r, err := ot.NewLabel(rand.Reader)
	if err != nil {
		return nil, err
	}
	r.SetS(true)

	alg, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	stream := &Streaming{
		conn: conn,
		key:  key,
		alg:  alg,
		r:    r,
	}

	stream.ensureWires(maxWire(0, inputs))

	// Assing all input wires.
	for i := 0; i < len(inputs); i++ {
		w, err := makeLabels(stream.r)
		if err != nil {
			return nil, err
		}
		stream.wires[inputs[i]] = w
	}

	return stream, nil
}

func maxWire(max Wire, wires []Wire) Wire {
	for _, w := range wires {
		if w > max {
			max = w
		}
	}
	return max
}

func (stream *Streaming) ensureWires(max Wire) {
	// Verify that wires is big enough.
	if len(stream.wires) <= int(max) {
		var i int
		for i = 65536; i <= int(max); i <<= 1 {
		}
		n := make([]ot.Wire, i)
		copy(n, stream.wires)
		stream.wires = n
	}
}

func (stream *Streaming) initCircuit(c *Circuit, in, out []Wire) {
	stream.ensureWires(maxWire(maxWire(0, in), out))

	if len(stream.tmp) < c.NumWires {
		stream.tmp = make([]ot.Wire, c.NumWires)
	}

	stream.in = in
	stream.out = out

	stream.firstTmp = Wire(len(in))
	stream.firstOut = Wire(c.NumWires - len(out))
}

// GetInput gets the value of the input wire.
func (stream *Streaming) GetInput(w Wire) ot.Wire {
	return stream.wires[w]
}

// GetInputs gets the specified input wire range.
func (stream *Streaming) GetInputs(offset, count int) []ot.Wire {
	return stream.wires[offset : offset+count]
}

// Get gets the value of the wire.
func (stream *Streaming) Get(w Wire) (ot.Wire, Wire, bool) {
	if w < stream.firstTmp {
		index := stream.in[w]
		return stream.wires[index], index, false
	} else if w >= stream.firstOut {
		index := stream.out[w-stream.firstOut]
		return stream.wires[index], index, false
	} else {
		return stream.tmp[w], w, true
	}
}

// Set sets the value of the wire.
func (stream *Streaming) Set(w Wire, val ot.Wire) (index Wire, tmp bool) {
	if w < stream.firstTmp {
		index = stream.in[w]
		stream.wires[index] = val
	} else if w >= stream.firstOut {
		index = stream.out[w-stream.firstOut]
		stream.wires[index] = val
	} else {
		index = w
		tmp = true
		stream.tmp[w] = val
	}
	return index, tmp
}

// Garble garbles the circuit and streams the garbled tables into the
// stream.
func (stream *Streaming) Garble(c *Circuit, in, out []Wire) (
	time.Duration, time.Duration, error) {
	if StreamDebug {
		fmt.Printf(" - Streaming.Garble: in=%v, out=%v\n", in, out)
	}

	start := time.Now()

	stream.initCircuit(c, in, out)

	// Garble gates.

	var data ot.LabelData
	var id uint32
	var table [4]ot.Label

	mid := time.Now()

	for i := 0; i < len(c.Gates); i++ {
		gate := &c.Gates[i]
		err := stream.conn.NeedSpace(512)
		if err != nil {
			return 0, 0, err
		}
		err = stream.garbleGate(gate, &id, table[:], &data,
			stream.conn.WriteBuf, &stream.conn.WritePos)
		if err != nil {
			return 0, 0, err
		}
	}
	return mid.Sub(start), time.Now().Sub(mid), nil
}

// GarbleGate garbles the gate and streams it to the stream.
func (stream *Streaming) garbleGate(g *Gate, idp *uint32,
	table []ot.Label, data *ot.LabelData, buf []byte, bufpos *int) error {

	var a, b, c ot.Wire
	var aIndex, bIndex, cIndex Wire
	var aTmp, bTmp, cTmp bool

	table = table[0:4]
	var tableStart, tableCount, wireCount int

	// Inputs.
	switch g.Op {
	case XOR, XNOR, AND, OR:
		b, bIndex, bTmp = stream.Get(g.Input1)
		fallthrough

	case INV:
		a, aIndex, aTmp = stream.Get(g.Input0)

	default:
		return fmt.Errorf("invalid gate type %s", g.Op)
	}

	// Output.
	switch g.Op {
	case XOR:
		l0 := a.L0
		l0.Xor(b.L0)

		l1 := l0
		l1.Xor(stream.r)
		c = ot.Wire{
			L0: l0,
			L1: l1,
		}

	case XNOR:
		l0 := a.L0
		l0.Xor(b.L0)

		l1 := l0
		l1.Xor(stream.r)
		c = ot.Wire{
			L0: l1,
			L1: l0,
		}

	case AND:
		pa := a.L0.S()
		pb := b.L0.S()

		j0 := *idp
		j1 := *idp + 1
		*idp = *idp + 2

		// First half gate.
		tg := encryptHalf(stream.alg, a.L0, j0, data)
		tg.Xor(encryptHalf(stream.alg, a.L1, j0, data))
		if pb {
			tg.Xor(stream.r)
		}
		wg0 := encryptHalf(stream.alg, a.L0, j0, data)
		if pa {
			wg0.Xor(tg)
		}

		// Second half gate.
		te := encryptHalf(stream.alg, b.L0, j1, data)
		te.Xor(encryptHalf(stream.alg, b.L1, j1, data))
		te.Xor(a.L0)
		we0 := encryptHalf(stream.alg, b.L0, j1, data)
		if pb {
			we0.Xor(te)
			we0.Xor(a.L0)
		}

		// Combine halves
		l0 := wg0
		l0.Xor(we0)

		l1 := l0
		l1.Xor(stream.r)

		c = ot.Wire{
			L0: l0,
			L1: l1,
		}
		table[0] = tg
		table[1] = te
		tableCount = 2

	case OR, INV:
		// Row reduction creates labels below so that the first row is
		// all zero.

	default:
		panic("invalid gate type")
	}

	switch g.Op {
	case XOR, XNOR:
		// Free XOR.
		wireCount = 3

	case AND:
		// Half AND garbled above.
		wireCount = 3

	case OR:
		// a b c
		// -----
		// 0 0 0
		// 0 1 1
		// 1 0 1
		// 1 1 1
		id := *idp
		*idp = *idp + 1
		table[idx(a.L0, b.L0)] = encrypt(stream.alg, a.L0, b.L0, c.L0, id, data)
		table[idx(a.L0, b.L1)] = encrypt(stream.alg, a.L0, b.L1, c.L1, id, data)
		table[idx(a.L1, b.L0)] = encrypt(stream.alg, a.L1, b.L0, c.L1, id, data)
		table[idx(a.L1, b.L1)] = encrypt(stream.alg, a.L1, b.L1, c.L1, id, data)

		// Row reduction. Make first table all zero so we don't have
		// to transmit it.

		l0Index := idx(a.L0, b.L0)

		c.L0 = table[0]
		c.L1 = table[0]

		if l0Index == 0 {
			c.L1.Xor(stream.r)
		} else {
			c.L0.Xor(stream.r)
		}
		for i := 0; i < 4; i++ {
			if i == l0Index {
				table[i].Xor(c.L0)
			} else {
				table[i].Xor(c.L1)
			}
		}

		tableStart = 1
		tableCount = 3
		wireCount = 3

	case INV:
		// a b c
		// -----
		// 0   1
		// 1   0
		zero := ot.Label{}
		id := *idp
		*idp = *idp + 1
		table[idxUnary(a.L0)] = encrypt(stream.alg, a.L0, zero, c.L1, id, data)
		table[idxUnary(a.L1)] = encrypt(stream.alg, a.L1, zero, c.L0, id, data)

		l0Index := idxUnary(a.L0)

		c.L0 = table[0]
		c.L1 = table[0]

		if l0Index == 0 {
			c.L0.Xor(stream.r)
		} else {
			c.L1.Xor(stream.r)
		}
		for i := 0; i < 2; i++ {
			if i == l0Index {
				table[i].Xor(c.L1)
			} else {
				table[i].Xor(c.L0)
			}
		}

		tableStart = 1
		tableCount = 1
		wireCount = 2

	default:
		return fmt.Errorf("invalid operand %s", g.Op)
	}

	if g.Output < stream.firstTmp {
		cIndex = stream.in[g.Output]
		stream.wires[cIndex] = c
	} else if g.Output >= stream.firstOut {
		cIndex = stream.out[g.Output-stream.firstOut]
		stream.wires[cIndex] = c
	} else {
		cIndex = g.Output
		cTmp = true
		stream.tmp[g.Output] = c
	}

	op := byte(g.Op)
	if aTmp {
		op |= 0b10000000
	}
	if bTmp {
		op |= 0b01000000
	}
	if cTmp {
		op |= 0b00100000
	}
	if aIndex <= 0xffff && bIndex <= 0xffff && cIndex <= 0xffff {
		op |= 0b00010000
		buf[*bufpos] = op
		*bufpos = *bufpos + 1

		switch wireCount {
		case 3:
			bo.PutUint16(buf[*bufpos+0:], uint16(aIndex))
			bo.PutUint16(buf[*bufpos+2:], uint16(bIndex))
			bo.PutUint16(buf[*bufpos+4:], uint16(cIndex))
			*bufpos = *bufpos + 6

		case 2:
			bo.PutUint16(buf[*bufpos+0:], uint16(aIndex))
			bo.PutUint16(buf[*bufpos+2:], uint16(cIndex))
			*bufpos = *bufpos + 4

		default:
			panic(fmt.Sprintf("invalid wire count: %d", wireCount))
		}
	} else {
		buf[*bufpos] = op
		*bufpos = *bufpos + 1

		switch wireCount {
		case 3:
			bo.PutUint32(buf[*bufpos+0:], uint32(aIndex))
			bo.PutUint32(buf[*bufpos+4:], uint32(bIndex))
			bo.PutUint32(buf[*bufpos+8:], uint32(cIndex))
			*bufpos = *bufpos + 12

		case 2:
			bo.PutUint32(buf[*bufpos+0:], uint32(aIndex))
			bo.PutUint32(buf[*bufpos+4:], uint32(cIndex))
			*bufpos = *bufpos + 8

		default:
			panic(fmt.Sprintf("invalid wire count: %d", wireCount))
		}
	}

	for i := 0; i < tableCount; i++ {
		bytes := table[tableStart+i].Bytes(data)
		copy(buf[*bufpos:], bytes)
		*bufpos = *bufpos + len(bytes)
	}

	return nil
}
