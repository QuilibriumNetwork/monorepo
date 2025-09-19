//
// protocol_test.go
//
// Copyright (c) 2023 Markku Rossi
//
// All rights reserved.
//

package p2p

import (
	"fmt"
	"io"
	"testing"
)

type pipe struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p *pipe) Close() error {
	if err := p.r.Close(); err != nil {
		return err
	}
	return p.w.Close()
}

func (p *pipe) Read(data []byte) (n int, err error) {
	return p.r.Read(data)
}

func (p *pipe) Write(data []byte) (n int, err error) {
	return p.w.Write(data)
}

func newPipes() (*pipe, *pipe) {
	var p0, p1 pipe

	p0.r, p1.w = io.Pipe()
	p1.r, p0.w = io.Pipe()

	return &p0, &p1
}

var tests = []interface{}{
	byte(42),
	uint16(43),
	uint32(44),
	"Hello, world!",
}

func writer(c *Conn) {
	for _, test := range tests {
		switch d := test.(type) {
		case byte:
			if err := c.SendByte(d); err != nil {
				fmt.Printf("SendByte: %v\n", err)
			}

		case uint16:
			if err := c.SendUint16(int(d)); err != nil {
				fmt.Printf("SendUint16: %v\n", err)
			}

		case uint32:
			if err := c.SendUint32(int(d)); err != nil {
				fmt.Printf("SendUint32: %v\n", err)
			}

		case string:
			if err := c.SendString(d); err != nil {
				fmt.Printf("SendString: %v\n", err)
			}

		default:
			fmt.Printf("writer: invalid data: %v(%T)\n", test, test)
		}
	}
	if err := c.Flush(); err != nil {
		fmt.Printf("Flush: %v\n", err)
	}
}

func TestProtocol(t *testing.T) {
	p0, p1 := newPipes()

	go writer(NewConn(p0))

	c := NewConn(p1)

	for _, test := range tests {
		switch d := test.(type) {
		case byte:
			v, err := c.ReceiveByte()
			if err != nil {
				t.Fatalf("ReceiveByte: %v", err)
			}
			if v != d {
				t.Errorf("ReceiveByte: got %v, expected %v", v, d)
			}

		case uint16:
			v, err := c.ReceiveUint16()
			if err != nil {
				t.Fatalf("ReceiveUint16: %v", err)
			}
			if v != int(d) {
				t.Errorf("ReceiveUint16: got %v, expected %v", v, d)
			}

		case uint32:
			v, err := c.ReceiveUint32()
			if err != nil {
				t.Fatalf("ReceiveUint32: %v", err)
			}
			if v != int(d) {
				t.Errorf("ReceiveUint32: got %v, expected %v", v, d)
			}

		case string:
			v, err := c.ReceiveString()
			if err != nil {
				t.Fatalf("ReceiveString: %v", err)
			}
			if v != d {
				t.Errorf("ReceiveString: got %v, expected %v", v, d)
			}

		default:
			t.Errorf("invalid value: %v(%T)", test, test)
		}
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
