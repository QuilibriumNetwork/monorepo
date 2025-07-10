//
// Copyright (c) 2020-2021, 2023 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// MAGIC is a magic number for the QCL circuit format version 0.
	MAGIC = 0x63726300 // crc0
)

var (
	bo = binary.BigEndian
)

// MarshalFormat marshals circuit in the specified format.
func (c *Circuit) MarshalFormat(out io.Writer, format string) error {
	switch format {
	case "qclc":
		return c.Marshal(out)
	case "bristol":
		return c.MarshalBristol(out)
	default:
		return fmt.Errorf("unsupported circuit format: %s", format)
	}
}

// Marshal marshals circuit in the QCL circuit format.
func (c *Circuit) Marshal(out io.Writer) error {
	var data = []interface{}{
		uint32(MAGIC),
		uint32(c.NumGates),
		uint32(c.NumWires),
		uint32(len(c.Inputs)),
		uint32(len(c.Outputs)),
	}
	for _, v := range data {
		if err := binary.Write(out, bo, v); err != nil {
			return err
		}
	}
	for _, input := range c.Inputs {
		if err := marshalIOArg(out, input); err != nil {
			return err
		}
	}
	for _, output := range c.Outputs {
		if err := marshalIOArg(out, output); err != nil {
			return err
		}
	}

	for _, g := range c.Gates {
		switch g.Op {
		case XOR, XNOR, AND, OR:
			data = []interface{}{
				byte(g.Op),
				uint32(g.Input0), uint32(g.Input1), uint32(g.Output),
			}

		case INV:
			data = []interface{}{
				byte(g.Op),
				uint32(g.Input0), uint32(g.Output),
			}
		default:
			return fmt.Errorf("unsupported gate type %s", g.Op)
		}
		for _, v := range data {
			if err := binary.Write(out, bo, v); err != nil {
				return err
			}
		}
	}
	return nil
}

func marshalIOArg(out io.Writer, arg IOArg) error {
	if err := marshalString(out, arg.Name); err != nil {
		return err
	}
	if err := marshalString(out, arg.Type.String()); err != nil {
		return err
	}
	if err := binary.Write(out, bo, uint32(arg.Type.Bits)); err != nil {
		return err
	}
	if err := binary.Write(out, bo, uint32(len(arg.Compound))); err != nil {
		return err
	}
	for _, c := range arg.Compound {
		if err := marshalIOArg(out, c); err != nil {
			return err
		}
	}
	return nil
}

func marshalString(out io.Writer, val string) error {
	bytes := []byte(val)
	if err := binary.Write(out, bo, uint32(len(bytes))); err != nil {
		return err
	}
	_, err := out.Write(bytes)
	return err
}

// MarshalBristol marshals the circuit in the Bristol format.
func (c *Circuit) MarshalBristol(out io.Writer) error {
	fmt.Fprintf(out, "%d %d\n", c.NumGates, c.NumWires)
	fmt.Fprintf(out, "%d", len(c.Inputs))
	for _, input := range c.Inputs {
		fmt.Fprintf(out, " %d", input.Type.Bits)
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%d", len(c.Outputs))
	for _, ret := range c.Outputs {
		fmt.Fprintf(out, " %d", ret.Type.Bits)
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out)

	for _, g := range c.Gates {
		fmt.Fprintf(out, "%d 1", len(g.Inputs()))
		for _, w := range g.Inputs() {
			fmt.Fprintf(out, " %d", w)
		}
		fmt.Fprintf(out, " %d", g.Output)
		fmt.Fprintf(out, " %s\n", g.Op)
	}

	return nil
}
