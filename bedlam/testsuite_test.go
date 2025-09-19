//
// Copyright (c) 2019-2024 Markku Rossi
//
// All rights reserved.
//

package bedlam

import (
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime/pprof"
	"strings"
	"testing"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

const (
	testsuite = "testsuite"
)

var (
	reWhitespace = regexp.MustCompilePOSIX(`[[:space:]]+`)
)

func TestSuite(t *testing.T) {
	params := utils.NewParams()
	params.QCLCErrorLoc = true

	filepath.WalkDir(testsuite,
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			testFile(t, compiler.New(params), path)
			return nil
		})
}

func testFile(t *testing.T, cc *compiler.Compiler, file string) {
	if !strings.HasSuffix(file, ".qcl") {
		return
	}
	pkg, err := cc.ParseFile(file)
	if err != nil {
		t.Errorf("failed to parse '%s': %s", file, err)
		return
	}
	main, ok := pkg.Functions["main"]
	if !ok {
		t.Errorf("%s: no main function", file)
	}

	var cpuprof bool
	var prof *os.File
	var lsb bool
	base := 10
	var testNumber int

	for _, annotation := range main.Annotations {
		ann := strings.TrimSpace(annotation)
		if strings.HasPrefix(ann, "@heavy") && testing.Short() {
			fmt.Printf("Skipping heavy test %s\n", file)
			return
		}
		if strings.HasPrefix(ann, "@pprof") {
			cpuprof = true
			prof, err = os.Create(fmt.Sprintf("%s.cpu.prof", file))
			if err != nil {
				t.Errorf("%s: failed to create cpu.prof: %s", file, err)
				return
			}
			err = pprof.StartCPUProfile(prof)
			if err != nil {
				t.Errorf("%s: failed to start CPU profile: %s", file, err)
				return
			}
			continue
		}
		if strings.HasPrefix(ann, "@Hex") {
			base = 16
			continue
		}
		if strings.HasPrefix(ann, "@LSB") {
			lsb = true
			continue
		}
		if !strings.HasPrefix(ann, "@Test ") {
			continue
		}
		parts := reWhitespace.Split(ann, -1)

		var inputValues [][]string
		var inputs []*big.Int
		var outputs []*big.Int
		var sep bool

		for i := 1; i < len(parts); i++ {
			part := parts[i]
			if part == "=" {
				sep = true
				continue
			}
			var iv []string
			for _, input := range strings.Split(part, ",") {
				var v *big.Int
				if input != "_" {
					v = new(big.Int)
					if base == 16 && lsb {
						input = reverse(input)
					}

					_, ok := v.SetString(input, 0)
					if !ok {
						t.Errorf("%s: invalid argument '%s'", file, input)
						return
					}
				}
				if sep {
					outputs = append(outputs, v)
				} else {
					iv = append(iv, input)
					inputs = append(inputs, v)
				}
			}
			inputValues = append(inputValues, iv)
		}
		var inputSizes [][]int
		for _, iv := range inputValues {
			sizes, err := circuit.InputSizes(iv)
			if err != nil {
				t.Errorf("%s: invalid inputs: %s", file, err)
				return
			}
			inputSizes = append(inputSizes, sizes)
		}
		circ, _, err := cc.CompileFile(file, inputSizes)
		if err != nil {
			t.Errorf("failed to compile '%s': %s", file, err)
			return
		}

		results, err := circ.Compute(inputs)
		if err != nil {
			t.Errorf("%s: compute failed: %s", file, err)
			return
		}

		if len(results) != len(outputs) {
			t.Errorf("%s: unexpected return values: got %v, expected %v",
				file, results, outputs)
			return
		}
		for idx := range results {
			out := circ.Outputs[idx]
			rr := Result(results[idx], out)
			re := Result(outputs[idx], out)

			if !reflect.DeepEqual(rr, re) {
				if out.Type.Type == types.TArray &&
					out.Type.ElementType.Type == types.TUint &&
					out.Type.ElementType.Bits == 8 {
					t.Errorf("%s/%v: result %d mismatch: got %x, expected %x",
						file, testNumber, idx, rr, re)
				} else {
					t.Errorf("%s/%v: result %d mismatch: got %v, expected %v",
						file, testNumber, idx, rr, re)
				}
			}
		}
		testNumber++
	}
	if cpuprof {
		pprof.StopCPUProfile()
		prof.Close()
	}
}

func reverse(val string) string {
	var prefix string
	if strings.HasPrefix(val, "0x") {
		val = val[2:]
		prefix = "0x"
	}
	var result string

	for i := len(val) - 2; i >= 0; i -= 2 {
		result += val[i : i+2]
	}
	if len(val)%2 == 1 {
		result += val[0:1]
	}
	return prefix + result
}
