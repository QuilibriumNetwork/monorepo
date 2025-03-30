//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package compiler

import (
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"testing"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
)

type IteratorTest struct {
	Name    string
	Operand string
	Bits    int
	Eval    func(a int64, b int64) int64
	Code    string
}

var iteratorTests = []IteratorTest{
	{
		Name:    "Add",
		Operand: "+",
		Bits:    2,
		Eval: func(a int64, b int64) int64 {
			return a + b
		},
		Code: `
package main
func main(a, b uint3) uint3 {
    return a + b
}
`,
	},
	{
		Name:    "Sub",
		Operand: "-",
		Bits:    2,
		Eval: func(a int64, b int64) int64 {
			return a - b
		},
		Code: `
package main
func main(a, b uint64) uint {
    return a - b
}
`,
	},
	// 1-bit, 2-bit, and n-bit multipliers have a bit different wiring.
	{
		Name:    "Multiply 1-bit",
		Operand: "*",
		Bits:    1,
		Eval: func(a int64, b int64) int64 {
			return a * b
		},
		Code: `
package main
func main(a, b uint1) uint1 {
    return a * b
}
`,
	},
	{
		Name:    "Multiply 2-bits",
		Operand: "*",
		Bits:    2,
		Eval: func(a int64, b int64) int64 {
			return a * b
		},
		Code: `
package main
func main(a, b uint4) uint4 {
    return a * b
}
`,
	},
	{
		Name:    "Multiply n-bits",
		Operand: "*",
		Bits:    2,
		Eval: func(a int64, b int64) int64 {
			return a * b
		},
		Code: `
package main
func main(a, b uint6) uint6 {
    return a * b
}
`,
	},
}

func TestIterator(t *testing.T) {
	for idx, test := range iteratorTests {
		circ, _, err := New(utils.NewParams()).Compile(test.Code, nil)
		if err != nil {
			t.Fatalf("Failed to compile test %s: %s", test.Name, err)
		}

		limit := int64(1 << test.Bits)

		var g, e int64

		for g = 0; g < limit; g++ {
			for e = 0; e < limit; e++ {
				n1 := big.NewInt(g)
				n2 := big.NewInt(e)

				results, err := circ.Compute([]*big.Int{n1, n2})
				if err != nil {
					t.Fatalf("%d: compute failed: %s\n", idx, err)
				}

				expected := test.Eval(g, e)

				if expected != results[0].Int64() {
					t.Errorf("%s failed: %d %s %d = %d, expected %d\n",
						test.Name, g, test.Operand, e, results[0],
						expected)
				}
			}
		}
	}
}

type FixedTest struct {
	N1   int64
	N2   int64
	N3   int64
	Code string
}

var fixedTests = []FixedTest{
	{
		N1: 5,
		N2: 3,
		N3: 5,
		Code: `
package main
func main(a, b int4) int4 {
    if a > b {
        return a
    }
    return b
}
`,
	},
	{
		N1: 5,
		N2: 3,
		N3: 6,
		Code: `
package main
func main(a, b int4) int4 {
    if a > b {
        return add1(a)
    }
    return add1(b)
}
func add1(val int) int {
    return val + 1
}
`,
	},
	{
		N1: 5,
		N2: 3,
		N3: 7,
		Code: `
package main
func main(a, b int4) int4 {
    if a > b {
        return add2(a)
    }
    return add2(b)
}
func add1(val int) int {
    return val + 1
}
func add2(val int) int {
    return add1(add1(val))
}
`,
	},
	{
		N1: 5,
		N2: 3,
		N3: 8,
		Code: `
package main
func main(a, b int4) int4 {
    return Sum2(MinMax(a, b))
}
func Sum2(a, b int) int {
    return a + b
}
func MinMax(a, b int) (int, int) {
    if a > b {
        return b, a
    }
    return a, b
}
`,
	},
}

func TestFixed(t *testing.T) {
	for idx, test := range fixedTests {
		circ, _, err := New(utils.NewParams()).Compile(test.Code, nil)
		if err != nil {
			t.Errorf("failed to compile test %d: %s", idx, err)
			continue
		}
		n1 := big.NewInt(test.N1)
		n2 := big.NewInt(test.N2)
		results, err := circ.Compute([]*big.Int{n1, n2})
		if err != nil {
			t.Errorf("compute failed: %s", err)
			continue
		}
		if results[0].Int64() != test.N3 {
			t.Errorf("test %d failed: got %d (%x), expected %d (%x)", idx,
				results[0].Int64(), results[0].Int64(), test.N3, test.N3)
		}
	}
}

func TestSubtraction(t *testing.T) {
	circ, _, err := New(utils.NewParams()).Compile(`package main
func main(a, b uint64) uint64 {
    return a - b
}
`, nil)
	if err != nil {
		t.Fatalf("Failed to compile test: %s", err)
	}

	r := rand.New(rand.NewSource(99))

	for i := 0; i < 1000; i++ {
		g := new(big.Int).Rand(r, big.NewInt(math.MaxInt64))

		var e *big.Int
		for {
			e = new(big.Int).Rand(r, big.NewInt(math.MaxInt64))
			if e.Cmp(g) < 0 {
				break
			}
		}

		results, err := circ.Compute([]*big.Int{g, e})
		if err != nil {
			t.Fatalf("compute failed: %s\n", err)
		}

		expected := new(big.Int).Sub(g, e)

		if expected.Cmp(results[0]) != 0 {
			t.Errorf("failed: %d - %d = %d, expected %d\n",
				g, e, results[0], expected)
		}
	}
}

type parseErrorTestData struct {
	code         string
	errorMessage string
}

var compileErrorTests = []parseErrorTestData{
	{
		code: `packag main`,
		errorMessage: `Compile error [parse]: unexpected token 'packag': expected 'package', {data}:1:0
packag main
^`,
	},
	{
		code:         `package mai`,
		errorMessage: `found packages mai and main`,
	},
	{
		code: `
	package main
	func main1(a, b int4) int4 {
	    return Sum2(MinMax(a, b))
	}
	`,
		errorMessage: `no main function defined`,
	},
	{
		code: `
	package main
	fun main(a, b int4) int4 {
		return Sum2(MinMax(a, b))
	}`,
		errorMessage: `Compile error [parse]: unexpected token 'identifier', {data}:3:1
	fun main(a, b int4) int4 {
	^`,
	},
	{
		code: `package main
		func main(a, b) int4 {
			return Sum2(MinMax(a, b))
		}`,

		errorMessage: `Compile error [parse]: unexpected token ')' while parsing type, {data}:2:16
		func main(a, b) int4 {
		              ^`,
	},
	{
		code: `package main
		func main(a, b int4 int4 {
			return Sum2(MinMax(a, b))
		}`,

		errorMessage: `Compile error [parse]: unexpected token 'int4': expected ',', {data}:2:22
		func main(a, b int4 int4 {
		                    ^`,
	},
	{
		code: `package main
		func main(a, b int4) int4 {
			a+b
		}`,

		errorMessage: `missing return at the end of function`,
	},
}

func TestCompileErrorMessage(t *testing.T) {
	for idx, testData := range compileErrorTests {
		t.Run(fmt.Sprintf("test parse %d", idx), func(t *testing.T) {
			_, _, err := New(utils.NewParams()).Compile(testData.code, nil)
			if err == nil {
				t.Fatalf("Parse test %d failed: expected error", idx)
			}
			if err.Error() != testData.errorMessage {
				t.Fatalf("Parse test %d failed: expected error message %s, got %s", idx, testData.errorMessage, err.Error())
			}
		})
	}
}
