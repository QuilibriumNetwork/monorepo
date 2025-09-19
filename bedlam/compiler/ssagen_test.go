//
// Copyright (c) 2020-2023 Markku Rossi
//
// All rights reserved.
//

package compiler

import (
	"fmt"
	"io"
	"os"
	"testing"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
)

type SSAGenTest struct {
	Enabled bool
	Name    string
	Code    string
}

var ssagenTests = []SSAGenTest{
	{
		Enabled: true,
		Name:    "constant",
		Code: `
package main
func main(a, b int32) int32 {
    return 42
}
`,
	},
	{
		Enabled: true,
		Name:    "add",
		Code: `
package main
func main(a, b int32) int32 {
    return a + b
}
`,
	},
	{
		Enabled: true,
		Name:    "add3",
		Code: `
package main
func main(a, b, e int32) (int32) {
    return a + b + e
}
`,
	},
	{
		Enabled: false,
		Name:    "ret2",
		Code: `
package main
func main(a, b int32) (int32, int32) {
    return a + b, a - b
}
`,
	},
	{
		Enabled: false,
		Name:    "if",
		Code: `
package main
func main(a, b int32) int32 {
    if a > b {
        return a
    }
    return b
}
`,
	},
	{
		Enabled: false,
		Name:    "ifelse",
		Code: `
package main
func main(a, b int32) int32 {
    if a > b {
        return a
    } else {
        return b
    }
}
`,
	},
	{
		Enabled: false,
		Name:    "if-else-assign",
		Code: `
package main
func main(a, b int32) (int32, int32) {
    var max, min int32
    if a > b {
        max = a
        min = b
    } else {
        max = b
        min = a
    }
    min = min + max
    max = max + min
    return min, max
}
`,
	},
	{
		Enabled: false,
		Name:    "max3",
		Code: `
package main
func main(a, b, c int32) int32 {
    var max int32
    if a > b {
        if a > c {
            max = a
        } else {
            max = c
        }
    } else {
        if b > c {
            max = b
        } else {
            max = c
        }
    }
    return max
}
`,
	},
	{
		Enabled: true,
		Name:    "Millionaire",
		Code: `
package main
func main(a, b int32) int32 {
    if a > b {
        return 0
    } else {
        return 1
    }
}
`,
	},
	{
		Enabled: true,
		Name:    "Mult",
		Code: `
package main
func main(a, b int32) int32 {
    return a * b
}
`,
	},
	{
		Enabled: true,
		Name:    "Bool",
		Code: `
package main
func main(a, b int32) bool {
    if a > b {
        return true
    }
    return false
}
`,
	},
	{
		Enabled: true,
		Name:    "Call",
		Code: `
package main
func main(a, b int32) int32 {
    return max(a, b)
}
func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}
`,
	},
	{
		Enabled: true,
		Name:    "Multiple-value-call",
		Code: `
package main
func main(a, b int32) int32 {
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
	{
		Enabled: true,
		Name:    "Constants",
		Code: `
package main

const One = 1
const H0 = 0x5be0cd191f83d9ab9b05688c510e527fa54ff53a3c6ef372bb67ae856a09e667

func main(a, b int32) uint256 {
    return H0
}
`,
	},
	{
		Enabled: true,
		Name:    "Constants block",
		Code: `
package main

const (
    One = 1
    H0 = 0x5be0cd191f83d9ab9b05688c510e527fa54ff53a3c6ef372bb67ae856a09e667
)

func main(a, b int32) uint256 {
    return H0
}
`,
	},
	{
		Enabled: true,
		Name:    "Packages",
		Code: `
package main

import (
    "math"
)

func main(a, b uint64) uint64 {
    return math.MaxUint(a, b)
}
`,
	},
	{
		Enabled: true,
		Name:    "Packages",
		Code: `
package main

import (
    "crypto/sha256"
)

func main(data, a uint512) uint256 {
    return sha256.Block(data, sha256.init)
}
`,
	},
}

func TestSSAGen(t *testing.T) {
	for idx, test := range ssagenTests {
		if !test.Enabled {
			continue
		}
		var ssaOut io.WriteCloser
		var verbose bool
		if testing.Verbose() {
			ssaOut = os.Stdout
			verbose = true
			fmt.Printf(`==================================================
// Test '%s':
%s--------------------------------------------------
`,
				test.Name, test.Code)
		}
		params := utils.NewParams()
		params.Verbose = verbose
		params.SSAOut = ssaOut
		_, _, err := New(params).Compile(test.Code, nil)
		if err != nil {
			t.Fatalf("SSA test %s (%d) failed: %s", test.Name, idx, err)
		}
	}
}
