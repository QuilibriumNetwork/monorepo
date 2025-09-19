//
// Copyright (c) 2024 Markku Rossi
//
// All rights reserved.
//

package ssa

import (
	"bufio"
	"io"
	"os"
	"regexp"
	"strconv"
	"testing"
)

var reOpcode = regexp.MustCompilePOSIX(`opcode ([[:^space:]]+) \(([^\)]+)\)`)

func TestOpcodes(t *testing.T) {
	operandsByName := make(map[string]Operand)

	for k, v := range operands {
		if len(v) > maxOperandLength {
			maxOperandLength = len(v)
		}
		operandsByName[v] = k
	}

	filename := "../../docs/apidoc/language,content.md"
	file, err := os.Open(filename)
	if err != nil {
		t.Fatalf("could not open '%v': %v", filename, err)
	}
	defer file.Close()

	r := bufio.NewReader(file)
	var linenum int
	var nextCode int64
	for {
		linenum++
		line, err := r.ReadString('\n')
		if len(line) == 0 {
			if err != nil {
				if err != io.EOF {
					t.Fatal(err)
				}
				break
			}
			continue
		}
		m := reOpcode.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		code, err := strconv.ParseInt(m[2], 0, 32)
		if err != nil {
			t.Errorf("%s:%v: invalid opcode '%s': %s", filename, linenum,
				m[2], err)
		}
		if code != nextCode {
			t.Errorf("%s:%v: expected opcode 0x%02x, got 0x%02x",
				filename, linenum, nextCode, code)
		}
		nextCode++

		op, ok := operandsByName[m[1]]
		if !ok {
			t.Errorf("%s:%v: unknown operand: %v", filename, linenum, m[1])
		}
		if int64(op) != code {
			t.Errorf("%s:%v: wrong opcode for '%s': got %v, expected %v",
				filename, linenum, m[1], code, int64(op))
		}
	}
}
