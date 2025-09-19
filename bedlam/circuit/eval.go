//
// Copyright (c) 2019-2021 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"crypto/aes"
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/ot"
)

// Eval evaluates the circuit.
func (c *Circuit) Eval(key []byte, wires []ot.Label,
	garbled [][]ot.Label) error {

	alg, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	var data ot.LabelData
	var id uint32

	for i := 0; i < len(c.Gates); i++ {
		gate := &c.Gates[i]

		var a, b, c ot.Label

		switch gate.Op {
		case XOR, XNOR, AND, OR:
			a = wires[gate.Input0]
			b = wires[gate.Input1]

		case INV:
			a = wires[gate.Input0]

		default:
			return fmt.Errorf("invalid operation %s", gate.Op)
		}

		var output ot.Label

		switch gate.Op {
		case XOR, XNOR:
			a.Xor(b)
			output = a

		case AND:
			row := garbled[i]
			if len(row) != 2 {
				return fmt.Errorf("corrupted ciruit: AND row length: %d",
					len(row))
			}
			sa := a.S()
			sb := b.S()

			j0 := id
			j1 := id + 1
			id += 2

			tg := row[0]
			te := row[1]

			wg := encryptHalf(alg, a, j0, &data)
			if sa {
				wg.Xor(tg)
			}
			we := encryptHalf(alg, b, j1, &data)
			if sb {
				we.Xor(te)
				we.Xor(a)
			}
			output = wg
			output.Xor(we)

		case OR:
			row := garbled[i]
			index := idx(a, b)
			if index > 0 {
				// First row is zero and not transmitted.
				index--
				if index >= len(row) {
					return fmt.Errorf("corrupted circuit: index %d >= row %d",
						index, len(row))
				}
				c = row[index]
			}

			output = decrypt(alg, a, b, id, c, &data)
			id++

		case INV:
			row := garbled[i]
			index := idxUnary(a)
			if index > 0 {
				// First row is zero and not transmitted.
				index--
				if index >= len(row) {
					return fmt.Errorf("corrupted circuit: index %d >= row %d",
						index, len(row))
				}
				c = row[index]
			}
			output = decrypt(alg, a, ot.Label{}, id, c, &data)
			id++
		}
		wires[gate.Output] = output
	}

	return nil
}
