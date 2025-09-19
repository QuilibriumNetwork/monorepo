//
// Copyright (c) 2020-2023 Markku Rossi
//
// All rights reserved.
//

package circuits

import (
	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

// Hamming creates a hamming distance circuit computing the hamming
// distance between a and b and returning the distance in r.
func Hamming(cc *Compiler, a, b, r []*Wire) error {
	a, b = cc.ZeroPad(a, b)

	var arr [][]*Wire
	for i := 0; i < len(a); i++ {
		w := cc.Calloc.Wire()
		cc.AddGate(cc.Calloc.BinaryGate(circuit.XOR, a[i], b[i], w))
		arr = append(arr, []*Wire{w})
	}

	for len(arr) > 2 {
		var n [][]*Wire
		for i := 0; i < len(arr); i += 2 {
			if i+1 < len(arr) {
				result := cc.Calloc.Wires(types.Size(len(arr[i]) + 1))
				err := NewAdder(cc, arr[i], arr[i+1], result)
				if err != nil {
					return err
				}
				n = append(n, result)
			} else {
				n = append(n, arr[i])
			}
		}
		arr = n
	}

	return NewAdder(cc, arr[0], arr[1], r)
}
