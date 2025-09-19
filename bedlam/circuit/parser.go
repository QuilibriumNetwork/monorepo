//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

var reParts = regexp.MustCompilePOSIX("[[:space:]]+")

// Seen describes whether wire has been seen.
type Seen []bool

// Get gets the wire seen flag.
func (s Seen) Get(index Wire) (bool, error) {
	if index >= Wire(len(s)) {
		return false, fmt.Errorf("invalid wire %d [0...%d[", index, len(s))
	}
	return s[index], nil
}

// Set marks the wire seen.
func (s Seen) Set(index Wire) error {
	if index >= Wire(len(s)) {
		return fmt.Errorf("invalid wire %d [0...%d[", index, len(s))
	}
	s[index] = true
	return nil
}

// IsFilename tests if the argument file is a potential circuit
// filename.
func IsFilename(file string) bool {
	return strings.HasSuffix(file, ".circ") ||
		strings.HasSuffix(file, ".bristol") ||
		strings.HasSuffix(file, ".qclc")
}

// Parse parses the circuit file.
func Parse(file string) (*Circuit, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if strings.HasSuffix(file, ".circ") || strings.HasSuffix(file, ".bristol") {
		return ParseBristol(f)
	} else if strings.HasSuffix(file, ".qclc") {
		return ParseQCLC(f)
	}
	return nil, fmt.Errorf("unsupported circuit format")
}

// ParseQCLC parses an QCL circuit file.
func ParseQCLC(in io.Reader) (*Circuit, error) {
	r := bufio.NewReader(in)

	var header struct {
		Magic      uint32
		NumGates   uint32
		NumWires   uint32
		NumInputs  uint32
		NumOutputs uint32
	}
	if err := binary.Read(r, bo, &header); err != nil {
		return nil, err
	}
	var inputs, outputs IO
	var inputWires, outputWires int

	wiresSeen := make(Seen, header.NumWires)

	for i := 0; i < int(header.NumInputs); i++ {
		arg, err := parseIOArg(r)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, arg)
		inputWires += int(arg.Type.Bits)
	}
	for i := 0; i < int(header.NumOutputs); i++ {
		out, err := parseIOArg(r)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, out)
		outputWires += int(out.Type.Bits)
	}

	// Mark input wires seen.
	for i := 0; i < inputWires; i++ {
		if err := wiresSeen.Set(Wire(i)); err != nil {
			return nil, err
		}
	}

	gates := make([]Gate, header.NumGates)
	var stats Stats
	var gate int
	for gate = 0; ; gate++ {
		op, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		switch Operation(op) {
		case XOR, XNOR, AND, OR:
			var bin struct {
				Input0 uint32
				Input1 uint32
				Output uint32
			}
			if err := binary.Read(r, bo, &bin); err != nil {
				return nil, err
			}
			seen, err := wiresSeen.Get(Wire(bin.Input0))
			if err != nil {
				return nil, err
			}
			if !seen {
				return nil, fmt.Errorf("input %d of gate %d not set",
					bin.Input0, gate)
			}
			seen, err = wiresSeen.Get(Wire(bin.Input1))
			if err != nil {
				return nil, err
			}
			if !seen {
				return nil, fmt.Errorf("input %d of gate %d not set",
					bin.Input1, gate)
			}
			if err := wiresSeen.Set(Wire(bin.Output)); err != nil {
				return nil, err
			}
			gates[gate] = Gate{
				Input0: Wire(bin.Input0),
				Input1: Wire(bin.Input1),
				Output: Wire(bin.Output),
				Op:     Operation(op),
			}

		case INV:
			var unary struct {
				Input0 uint32
				Output uint32
			}
			if err := binary.Read(r, bo, &unary); err != nil {
				return nil, err
			}
			seen, err := wiresSeen.Get(Wire(unary.Input0))
			if err != nil {
				return nil, err
			}
			if !seen {
				return nil, fmt.Errorf("input %d of gate %d not set",
					unary.Input0, gate)
			}
			if err := wiresSeen.Set(Wire(unary.Output)); err != nil {
				return nil, err
			}
			gates[gate] = Gate{
				Input0: Wire(unary.Input0),
				Output: Wire(unary.Output),
				Op:     Operation(op),
			}

		default:
			return nil, fmt.Errorf("unsupported gate type %s", Operation(op))
		}
		stats[Operation(op)]++
	}

	if uint32(gate) != header.NumGates {
		return nil, fmt.Errorf("not enough gates: got %d, expected %d",
			gate, header.NumGates)
	}

	// Check that all wires are seen.
	for i := 0; i < len(wiresSeen); i++ {
		if !wiresSeen[i] {
			return nil, fmt.Errorf("wire %d not assigned", i)
		}
	}

	return &Circuit{
		NumGates: int(header.NumGates),
		NumWires: int(header.NumWires),
		Inputs:   inputs,
		Outputs:  outputs,
		Gates:    gates,
		Stats:    stats,
	}, nil
}

func parseIOArg(r *bufio.Reader) (arg IOArg, err error) {
	name, err := parseString(r)
	if err != nil {
		return arg, err
	}
	t, err := parseString(r)
	if err != nil {
		return arg, err
	}
	var ui32 uint32
	if err := binary.Read(r, bo, &ui32); err != nil {
		return arg, err
	}
	arg.Name = name
	arg.Type, err = types.Parse(t)
	if err != nil {
		return arg, err
	}
	arg.Type.Bits = types.Size(ui32)

	// Compound
	if err := binary.Read(r, bo, &ui32); err != nil {
		return arg, err
	}
	for i := 0; i < int(ui32); i++ {
		c, err := parseIOArg(r)
		if err != nil {
			return arg, err
		}
		arg.Compound = append(arg.Compound, c)
	}

	return
}

func parseString(r *bufio.Reader) (string, error) {
	var ui32 uint32
	if err := binary.Read(r, bo, &ui32); err != nil {
		return "", err
	}
	if ui32 == 0 {
		return "", nil
	}
	buf := make([]byte, ui32)
	_, err := r.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

// ParseBristol parses a Briston circuit file.
func ParseBristol(in io.Reader) (*Circuit, error) {
	r := bufio.NewReader(in)

	// NumGates NumWires
	line, err := readLine(r)
	if err != nil {
		return nil, err
	}
	if len(line) != 2 {
		return nil, fmt.Errorf("invalid 1st line: '%s'", line)
	}
	numGates, err := strconv.Atoi(line[0])
	if err != nil {
		return nil, err
	}
	if numGates < 0 || numGates > math.MaxInt32 {
		return nil, fmt.Errorf("invalid numGates: %d", numGates)
	}
	numWires, err := strconv.Atoi(line[1])
	if err != nil {
		return nil, err
	}
	if numWires < 0 || numWires > math.MaxInt32 {
		return nil, fmt.Errorf("invalid numWires: %d", numWires)
	}
	wiresSeen := make(Seen, numWires)

	// Inputs
	line, err = readLine(r)
	if err != nil {
		return nil, err
	}
	niv, err := strconv.Atoi(line[0])
	if err != nil {
		return nil, err
	}
	if 1+niv != len(line) {
		return nil, fmt.Errorf("invalid inputs line: niv=%d, len=%d",
			niv, len(line))
	}
	var inputs IO
	var inputWires int64
	for i := 1; i < len(line); i++ {
		bits, err := strconv.ParseInt(line[i], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid input bits: %s", err)
		}
		if bits < 0 {
			return nil, fmt.Errorf("invalid input bits: %d", bits)
		}
		inputs = append(inputs, IOArg{
			Name: fmt.Sprintf("NI%d", i),
			Type: types.Info{
				Type:       types.TUint,
				IsConcrete: true,
				Bits:       types.Size(bits),
			},
		})
		inputWires += bits
	}
	if inputWires == 0 {
		return nil, fmt.Errorf("no inputs defined")
	}

	// Mark input wires seen.
	for i := int64(0); i < inputWires; i++ {
		if err := wiresSeen.Set(Wire(i)); err != nil {
			return nil, err
		}
	}

	// Outputs
	line, err = readLine(r)
	if err != nil {
		return nil, err
	}
	nov, err := strconv.Atoi(line[0])
	if err != nil {
		return nil, err
	}
	if 1+nov != len(line) {
		return nil, errors.New("invalid outputs line")
	}
	var outputs IO
	for i := 1; i < len(line); i++ {
		bits, err := strconv.ParseInt(line[i], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid output bits: %s", err)
		}
		if bits < 0 {
			return nil, fmt.Errorf("invalid output bits: %d", bits)
		}
		outputs = append(outputs, IOArg{
			Name: fmt.Sprintf("NO%d", i),
			Type: types.Info{
				Type:       types.TUint,
				IsConcrete: true,
				Bits:       types.Size(bits),
			},
		})
	}

	gates := make([]Gate, numGates)
	var stats Stats
	var gate int
	for gate = 0; ; gate++ {
		line, err = readLine(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if gate >= numGates {
			return nil, errors.New("too many gates")
		}
		if len(line) < 3 {
			return nil, fmt.Errorf("invalid gate: %v", line)
		}
		n1, err := strconv.Atoi(line[0])
		if err != nil {
			return nil, err
		}
		if n1 < 0 {
			return nil, fmt.Errorf("invalid n1: %v", n1)
		}
		n2, err := strconv.Atoi(line[1])
		if err != nil {
			return nil, err
		}
		if n2 < 0 {
			return nil, fmt.Errorf("invalid n2: %v", n2)
		}
		if 2+n1+n2+1 != len(line) {
			return nil, fmt.Errorf("invalid gate: %v", line)
		}

		var inputs []Wire
		for i := 0; i < n1; i++ {
			v, err := strconv.ParseUint(line[2+i], 10, 32)
			if err != nil {
				return nil, err
			}
			seen, err := wiresSeen.Get(Wire(v))
			if err != nil {
				return nil, err
			}
			if !seen {
				return nil, fmt.Errorf("input %d of gate %d not set", v, gate)
			}
			inputs = append(inputs, Wire(v))
		}

		var outputs []Wire
		for i := 0; i < n2; i++ {
			v, err := strconv.ParseUint(line[2+n1+i], 10, 32)
			if err != nil {
				return nil, err
			}
			err = wiresSeen.Set(Wire(v))
			if err != nil {
				return nil, err
			}
			outputs = append(outputs, Wire(v))
		}
		var op Operation
		var numInputs int
		switch line[len(line)-1] {
		case "XOR":
			op = XOR
			numInputs = 2
		case "XNOR":
			op = XNOR
			numInputs = 2
		case "AND":
			op = AND
			numInputs = 2
		case "OR":
			op = OR
			numInputs = 2
		case "INV":
			op = INV
			numInputs = 1
		default:
			return nil, fmt.Errorf("invalid operation '%s'", line[len(line)-1])
		}

		if len(inputs) != numInputs {
			return nil, fmt.Errorf("invalid number of inputs %d for %s",
				len(inputs), op)
		}
		if len(outputs) != 1 {
			return nil, fmt.Errorf("invalid number of outputs %d for %s",
				len(outputs), op)
		}

		var input1 Wire
		if len(inputs) > 1 {
			input1 = inputs[1]
		}

		gates[gate] = Gate{
			Input0: inputs[0],
			Input1: input1,
			Output: outputs[0],
			Op:     op,
		}
		stats[op]++
	}
	if gate != numGates {
		return nil, fmt.Errorf("not enough gates: got %d, expected %d",
			gate, numGates)
	}

	// Check that all wires are seen.
	for i := 0; i < len(wiresSeen); i++ {
		if !wiresSeen[i] {
			return nil, fmt.Errorf("wire %d not assigned", i)
		}
	}

	return &Circuit{
		NumGates: numGates,
		NumWires: numWires,
		Inputs:   inputs,
		Outputs:  outputs,
		Gates:    gates,
		Stats:    stats,
	}, nil
}

func readLine(r *bufio.Reader) ([]string, error) {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		parts := reParts.Split(line, -1)
		if len(parts) > 0 {
			return parts, nil
		}
	}
}
