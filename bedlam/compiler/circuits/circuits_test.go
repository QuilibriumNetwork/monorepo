//
// circuits_test.go
//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package circuits

import (
	"fmt"
	"os"
	"testing"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

const (
	verbose = false
)

var (
	params = utils.NewParams()
	calloc = NewAllocator()
)

func makeWires(count int, output bool) []*Wire {
	var result []*Wire
	for i := 0; i < count; i++ {
		w := calloc.Wire()
		w.SetOutput(output)
		result = append(result, w)
	}
	return result
}

func NewIO(size int, name string) circuit.IO {
	return circuit.IO{
		circuit.IOArg{
			Name: name,
			Type: types.Info{
				Type:       types.TUint,
				IsConcrete: true,
				Bits:       types.Size(size),
			},
		},
	}
}

func TestAdd4(t *testing.T) {
	bits := 4

	// 2xbits inputs, bits+1 outputs
	inputs := makeWires(bits*2, false)
	outputs := makeWires(bits+1, true)
	c, err := NewCompiler(params, calloc, NewIO(bits*2, "in"),
		NewIO(bits+1, "out"), inputs, outputs)
	if err != nil {
		t.Fatalf("NewCompiler: %s", err)
	}

	cin := calloc.Wire()
	NewHalfAdder(c, inputs[0], inputs[bits], outputs[0], cin)

	for i := 1; i < bits; i++ {
		var cout *Wire
		if i+1 >= bits {
			cout = outputs[bits]
		} else {
			cout = calloc.Wire()
		}

		NewFullAdder(c, inputs[i], inputs[bits+i], cin, outputs[i], cout)

		cin = cout
	}

	result := c.Compile()
	if verbose {
		fmt.Printf("Result: %s\n", result)
		result.Marshal(os.Stdout)
	}
}

func TestFullSubtractor(t *testing.T) {
	inputs := makeWires(1+2, false)
	outputs := makeWires(2, true)
	c, err := NewCompiler(params, calloc, NewIO(1+2, "in"), NewIO(2, "out"),
		inputs, outputs)
	if err != nil {
		t.Fatalf("NewCompiler: %s", err)
	}

	NewFullSubtractor(c, inputs[0], inputs[1], inputs[2],
		outputs[0], outputs[1])

	result := c.Compile()
	if verbose {
		fmt.Printf("Result: %s\n", result)
		result.Marshal(os.Stdout)
	}
}

func TestMultiply1(t *testing.T) {
	inputs := makeWires(2, false)
	outputs := makeWires(2, true)
	c, err := NewCompiler(params, calloc, NewIO(2, "in"), NewIO(2, "out"),
		inputs, outputs)
	if err != nil {
		t.Fatalf("NewCompiler: %s", err)
	}

	err = NewMultiplier(c, 0, inputs[0:1], inputs[1:2], outputs)
	if err != nil {
		t.Error(err)
	}
}

func TestMultiply(t *testing.T) {
	bits := 64

	inputs := makeWires(bits*2, false)
	outputs := makeWires(bits*2, true)

	c, err := NewCompiler(params, calloc, NewIO(bits*2, "in"),
		NewIO(bits*2, "out"), inputs, outputs)
	if err != nil {
		t.Fatalf("NewCompiler: %s", err)
	}

	err = NewMultiplier(c, 0, inputs[0:bits], inputs[bits:2*bits], outputs)
	if err != nil {
		t.Error(err)
	}

	result := c.Compile()
	if verbose {
		fmt.Printf("Result: %s\n", result)
		result.Marshal(os.Stdout)
	}
}
