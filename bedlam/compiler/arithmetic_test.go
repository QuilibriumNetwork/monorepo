//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package compiler

import (
	"fmt"
	"io"
	"math/big"
	"testing"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/ot"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/p2p"
)

type Test struct {
	Name    string
	Heavy   bool
	Operand string
	Bits    int
	Eval    func(a *big.Int, b *big.Int) *big.Int
	Code    string
}

var tests = []Test{
	{
		Name:    "Add",
		Heavy:   true,
		Operand: "+",
		Bits:    2,
		Eval: func(a *big.Int, b *big.Int) *big.Int {
			result := big.NewInt(0)
			result.Add(a, b)
			return result
		},
		Code: `
package main
func main(a, b int3) int3 {
    return a + b
}
`,
	},
	// 1-bit, 2-bit, and n-bit multipliers have a bit different wiring.
	{
		Name:    "Multiply 1-bit",
		Heavy:   false,
		Operand: "*",
		Bits:    1,
		Eval: func(a *big.Int, b *big.Int) *big.Int {
			result := big.NewInt(0)
			result.Mul(a, b)
			return result
		},
		Code: `
package main
func main(a, b int1) int1 {
    return a * b
}
`,
	},
	{
		Name:    "Multiply 2-bits",
		Heavy:   true,
		Operand: "*",
		Bits:    2,
		Eval: func(a *big.Int, b *big.Int) *big.Int {
			result := big.NewInt(0)
			result.Mul(a, b)
			return result
		},
		Code: `
package main
func main(a, b int4) int4 {
    return a * b
}
`,
	},
	{
		Name:    "Multiply n-bits",
		Heavy:   true,
		Operand: "*",
		Bits:    2,
		Eval: func(a *big.Int, b *big.Int) *big.Int {
			result := big.NewInt(0)
			result.Mul(a, b)
			return result
		},
		Code: `
package main
func main(a, b int6) int6 {
    return a * b
}
`,
	},
}

func TestArithmetics(t *testing.T) {
	for _, test := range tests {
		if testing.Short() && test.Heavy {
			fmt.Printf("Skipping %s\n", test.Name)
			continue
		}
		circ, _, err := New(utils.NewParams()).Compile(test.Code, nil)
		if err != nil {
			t.Fatalf("Failed to compile test %s: %s", test.Name, err)
		}

		limit := 1 << test.Bits

		for g := 0; g < limit; g++ {
			for e := 0; e < limit; e++ {
				gr, ew := io.Pipe()
				er, gw := io.Pipe()

				gio := newReadWriter(gr, gw)
				eio := newReadWriter(er, ew)

				gInput := big.NewInt(int64(g))
				eInput := big.NewInt(int64(e))

				gerr := make(chan error)
				eerr := make(chan error)
				res := make(chan []*big.Int)

				go func() {
					fmt.Println("start garbler")
					_, err := circuit.Garbler(p2p.NewConn(gio), ot.NewFerret(1, ":5555"),
						circ, gInput, false)
					fmt.Println("end garbler")
					gerr <- err
				}()

				go func() {
					fmt.Println("start evaluator")
					result, err := circuit.Evaluator(p2p.NewConn(eio),
						ot.NewFerret(2, "127.0.0.1:5555"), circ, eInput, false)
					fmt.Println("end evaluator")
					eerr <- err
					res <- result
				}()

				err = <-gerr
				if err != nil {
					t.Fatalf("Garbler failed: %s\n", err)
				}
				err = <-eerr
				if err != nil {
					t.Fatalf("Evaluator failed: %s\n", err)
				}

				result := <-res
				expected := test.Eval(gInput, eInput)

				if expected.Cmp(result[0]) != 0 {
					t.Errorf("%s failed: %s %s %s = %s, expected %s\n",
						test.Name, gInput, test.Operand, eInput, result,
						expected)
				}
			}
		}
	}
}

var mult512 = `
package main
func main(a, b int512) int512 {
    return a * b
}
`

func BenchmarkMult(b *testing.B) {
	circ, _, err := New(utils.NewParams()).Compile(mult512, nil)
	if err != nil {
		b.Fatalf("failed to compile test: %s", err)
	}

	gr, ew := io.Pipe()
	er, gw := io.Pipe()

	gio := newReadWriter(gr, gw)
	eio := newReadWriter(er, ew)

	gInput := big.NewInt(int64(11))
	eInput := big.NewInt(int64(13))

	gerr := make(chan error)
	eerr := make(chan error)
	res := make(chan []*big.Int)

	go func() {
		_, err := circuit.Garbler(p2p.NewConn(gio), ot.NewFerret(1, ":5555"),
			circ, gInput, false)
		gerr <- err
	}()

	go func() {
		result, err := circuit.Evaluator(p2p.NewConn(eio),
			ot.NewFerret(2, "127.0.0.1:5555"), circ, eInput, false)
		eerr <- err
		res <- result
	}()

	err = <-gerr
	if err != nil {
		b.Fatalf("Garbler failed: %s\n", err)
	}
	err = <-eerr
	if err != nil {
		b.Fatalf("Evaluator failed: %s\n", err)
	}

	<-res
}

func newReadWriter(in io.Reader, out io.Writer) io.ReadWriter {
	return &wrap{
		in:  in,
		out: out,
	}
}

type wrap struct {
	in  io.Reader
	out io.Writer
}

func (w *wrap) Read(p []byte) (n int, err error) {
	return w.in.Read(p)
}

func (w *wrap) Write(p []byte) (n int, err error) {
	return w.out.Write(p)
}
