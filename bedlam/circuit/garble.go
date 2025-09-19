//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/ot"
)

var (
	verbose = false
)

func idxUnary(l0 ot.Label) int {
	if l0.S() {
		return 1
	}
	return 0
}

func idx(l0, l1 ot.Label) int {
	var ret int

	if l0.S() {
		ret |= 0x2
	}
	if l1.S() {
		ret |= 0x1
	}

	return ret
}

func encrypt(alg cipher.Block, a, b, c ot.Label, t uint32,
	data *ot.LabelData) ot.Label {

	k := makeK(a, b, t)

	k.GetData(data)
	alg.Encrypt(data[:], data[:])

	var pi ot.Label
	pi.SetData(data)

	pi.Xor(k)
	pi.Xor(c)

	return pi
}

func decrypt(alg cipher.Block, a, b ot.Label, t uint32, c ot.Label,
	data *ot.LabelData) ot.Label {

	k := makeK(a, b, t)

	k.GetData(data)
	alg.Encrypt(data[:], data[:])

	var crypted ot.Label
	crypted.SetData(data)

	c.Xor(crypted)
	c.Xor(k)

	return c
}

func makeK(a, b ot.Label, t uint32) ot.Label {
	a.Mul2()

	b.Mul4()
	a.Xor(b)

	a.Xor(ot.NewTweak(t))

	return a
}

// Hash function for half gates: Hπ(x, i) to be π(K) ⊕ K where K = 2x ⊕ i
func encryptHalfReference(alg cipher.Block, x ot.Label, i uint32,
	data *ot.LabelData) ot.Label {

	k := makeKHalf(x, i)

	k.GetData(data)
	alg.Encrypt(data[:], data[:])

	var pi ot.Label
	pi.SetData(data)

	pi.Xor(k)

	return pi
}

// Optimized version of encryptHalfReference. Label operations are
// inlined below, producing about 11% performance improvements.
func encryptHalf(alg cipher.Block, x ot.Label, i uint32,
	data *ot.LabelData) ot.Label {

	// k := makeKHalf(x, i) {
	k := x
	//   k.Mul2()
	k.D0 <<= 1
	k.D0 |= (k.D1 >> 63)
	k.D1 <<= 1
	//   k.Xor(ot.NewTweak(i))
	k.D1 ^= uint64(i)
	// }

	// k.GetData(data) {
	binary.BigEndian.PutUint64(data[0:8], k.D0)
	binary.BigEndian.PutUint64(data[8:16], k.D1)
	// }

	alg.Encrypt(data[:], data[:])

	var pi ot.Label
	// pi.SetData(data) {
	pi.D0 = binary.BigEndian.Uint64((*data)[0:8])
	pi.D1 = binary.BigEndian.Uint64((*data)[8:16])
	// }

	// pi.Xor(k) {
	pi.D0 ^= k.D0
	pi.D1 ^= k.D1
	// }

	return pi
}

// K = 2x ⊕ i
func makeKHalf(x ot.Label, i uint32) ot.Label {
	x.Mul2()
	x.Xor(ot.NewTweak(i))
	return x
}

func makeLabels(r ot.Label) (ot.Wire, error) {
	l0, err := ot.NewLabel(rand.Reader)
	if err != nil {
		return ot.Wire{}, err
	}
	l1 := l0
	l1.Xor(r)

	return ot.Wire{
		L0: l0,
		L1: l1,
	}, nil
}

// Garbled contains garbled circuit information.
type Garbled struct {
	R     ot.Label
	Wires []ot.Wire
	Gates [][]ot.Label
}

// Lambda returns the lambda value of the wire.
func (g *Garbled) Lambda(wire Wire) uint {
	if g.Wires[wire].L0.S() {
		return 1
	}
	return 0
}

// SetLambda sets the lambda value of the wire.
func (g *Garbled) SetLambda(wire Wire, val uint) {
	w := g.Wires[wire]
	if val == 0 {
		w.L0.SetS(false)
	} else {
		w.L0.SetS(true)
	}
	g.Wires[wire] = w
}

// Garble garbles the circuit.
func (c *Circuit) Garble(key []byte) (*Garbled, error) {
	// Create R.
	r, err := ot.NewLabel(rand.Reader)
	if err != nil {
		return nil, err
	}
	r.SetS(true)

	garbled := make([][]ot.Label, c.NumGates)

	alg, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Wire labels.
	wires := make([]ot.Wire, c.NumWires)

	// Assing all input wires.
	for i := 0; i < c.Inputs.Size(); i++ {
		w, err := makeLabels(r)
		if err != nil {
			return nil, err
		}
		wires[i] = w
	}

	// Garble gates.
	var data ot.LabelData
	var id uint32
	for i := 0; i < len(c.Gates); i++ {
		gate := &c.Gates[i]
		data, err := gate.garble(wires, alg, r, &id, &data)
		if err != nil {
			return nil, err
		}
		garbled[i] = data
	}

	return &Garbled{
		R:     r,
		Wires: wires,
		Gates: garbled,
	}, nil
}

// Garble garbles the gate and returns it labels.
func (g *Gate) garble(wires []ot.Wire, enc cipher.Block, r ot.Label,
	idp *uint32, data *ot.LabelData) ([]ot.Label, error) {

	var a, b, c ot.Wire

	var table [4]ot.Label
	var start, count int

	// Inputs.
	switch g.Op {
	case XOR, XNOR, AND, OR:
		b = wires[g.Input1]
		fallthrough

	case INV:
		a = wires[g.Input0]

	default:
		return nil, fmt.Errorf("invalid gate type %s", g.Op)
	}

	// Output.
	switch g.Op {
	case XOR:
		l0 := a.L0
		l0.Xor(b.L0)

		l1 := l0
		l1.Xor(r)
		c = ot.Wire{
			L0: l0,
			L1: l1,
		}

	case XNOR:
		l0 := a.L0
		l0.Xor(b.L0)

		l1 := l0
		l1.Xor(r)
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
		tg := encryptHalf(enc, a.L0, j0, data)
		tg.Xor(encryptHalf(enc, a.L1, j0, data))
		if pb {
			tg.Xor(r)
		}
		wg0 := encryptHalf(enc, a.L0, j0, data)
		if pa {
			wg0.Xor(tg)
		}

		// Second half gate.
		te := encryptHalf(enc, b.L0, j1, data)
		te.Xor(encryptHalf(enc, b.L1, j1, data))
		te.Xor(a.L0)
		we0 := encryptHalf(enc, b.L0, j1, data)
		if pb {
			we0.Xor(te)
			we0.Xor(a.L0)
		}

		// Combine halves
		l0 := wg0
		l0.Xor(we0)

		l1 := l0
		l1.Xor(r)

		c = ot.Wire{
			L0: l0,
			L1: l1,
		}
		table[0] = tg
		table[1] = te
		count = 2

	case OR, INV:
		// Row reduction creates labels below so that the first row is
		// all zero.

	default:
		panic("invalid gate type")
	}

	switch g.Op {
	case XOR, XNOR:
		// Free XOR.

	case AND:
		// Half AND garbled above.

	case OR:
		// a b c
		// -----
		// 0 0 0
		// 0 1 1
		// 1 0 1
		// 1 1 1
		id := *idp
		*idp = *idp + 1
		table[idx(a.L0, b.L0)] = encrypt(enc, a.L0, b.L0, c.L0, id, data)
		table[idx(a.L0, b.L1)] = encrypt(enc, a.L0, b.L1, c.L1, id, data)
		table[idx(a.L1, b.L0)] = encrypt(enc, a.L1, b.L0, c.L1, id, data)
		table[idx(a.L1, b.L1)] = encrypt(enc, a.L1, b.L1, c.L1, id, data)

		l0Index := idx(a.L0, b.L0)

		c.L0 = table[0]
		c.L1 = table[0]

		if l0Index == 0 {
			c.L1.Xor(r)
		} else {
			c.L0.Xor(r)
		}
		for i := 0; i < 4; i++ {
			if i == l0Index {
				table[i].Xor(c.L0)
			} else {
				table[i].Xor(c.L1)
			}
		}
		start = 1
		count = 3

	case INV:
		// a b c
		// -----
		// 0   1
		// 1   0
		id := *idp
		*idp = *idp + 1
		table[idxUnary(a.L0)] = encrypt(enc, a.L0, ot.Label{}, c.L1, id, data)
		table[idxUnary(a.L1)] = encrypt(enc, a.L1, ot.Label{}, c.L0, id, data)

		l0Index := idxUnary(a.L0)

		c.L0 = table[0]
		c.L1 = table[0]

		if l0Index == 0 {
			c.L0.Xor(r)
		} else {
			c.L1.Xor(r)
		}
		for i := 0; i < 2; i++ {
			if i == l0Index {
				table[i].Xor(c.L1)
			} else {
				table[i].Xor(c.L0)
			}
		}
		start = 1
		count = 1

	default:
		return nil, fmt.Errorf("invalid operand %s", g.Op)
	}
	wires[g.Output] = c

	return table[start : start+count], nil
}
