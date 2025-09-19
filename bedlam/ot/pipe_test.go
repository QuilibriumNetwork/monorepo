//
// pipe_test.go
//
// Copyright (c) 2023-2024 Markku Rossi
//
// All rights reserved.
//

package ot

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

func TestPipe(t *testing.T) {
	var tests = []interface{}{
		byte('@'),
		42,
		[]byte("Hello, world!"),
	}

	pipe, rPipe := NewPipe()
	done := make(chan error)

	go func(pipe *Pipe) {
		for _, test := range tests {
			switch v := test.(type) {
			case byte:
				val, err := pipe.ReceiveByte()
				if err != nil {
					done <- err
					pipe.Close()
					return
				}
				if val != v {
					done <- fmt.Errorf("ReceiveByte: mismatch: %v != %v",
						val, v)
					pipe.Close()
					return
				}

			case int:
				val, err := pipe.ReceiveUint32()
				if err != nil {
					done <- err
					pipe.Close()
					return
				}
				if val != v {
					done <- fmt.Errorf("ReceiveUint32: mismatch: %v != %v",
						val, v)
					pipe.Close()
					return
				}

			case []byte:
				data, err := pipe.ReceiveData()
				if err != nil {
					done <- err
					pipe.Close()
					return
				}
				if bytes.Compare(data, v) != 0 {
					done <- fmt.Errorf("ReceiveData: mismatch: %x != %x",
						data, v)
					pipe.Close()
					return
				}

			default:
				panic(fmt.Sprintf("receive %v(%T) not supported", v, v))
			}
		}
		_, err := pipe.ReceiveUint32()
		if err != io.EOF {
			done <- fmt.Errorf("expected EOF")
		}
		done <- nil
	}(rPipe)

	for _, test := range tests {
		switch v := test.(type) {
		case byte:
			err := pipe.SendByte(v)
			if err != nil {
				t.Errorf("SendByte failed: %v", err)
			}

		case int:
			err := pipe.SendUint32(v)
			if err != nil {
				t.Errorf("SendUint32 failed: %v", err)
			}

		case []byte:
			err := pipe.SendData(v)
			if err != nil {
				t.Errorf("SendData failed: %v", err)
			}
		}
	}
	err := pipe.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	err = <-done
	if err != nil {
		t.Errorf("consumer failed: %v", err)
	}
}
