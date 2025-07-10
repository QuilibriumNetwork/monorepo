//
// ferret.go
//
// Copyright (c) 2024-2025 Quilibrium, Inc.
//
// All rights reserved.
//

package ot

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/ferret"
)

var (
	bo    = binary.BigEndian
	_  OT = &Ferret{}
)

// Ferret implements FERRET OT as the OT interface.
type Ferret struct {
	party   uint8
	address string
	io      IO
}

// NewFerret creates a new FERRET OT implementing the OT interface.
func NewFerret(party uint8, address string) *Ferret {
	return &Ferret{
		party:   party,
		address: address,
		io:      nil,
	}
}

// InitSender initializes the OT sender.
func (ferret *Ferret) InitSender(io IO) error {
	ferret.io = io
	return nil
}

// InitReceiver initializes the OT receiver.
func (ferret *Ferret) InitReceiver(io IO) error {
	ferret.io = io
	return nil
}

func xor(a, b []byte) []byte {
	l := len(a)
	if len(b) < l {
		l = len(b)
	}
	for i := 0; i < l; i++ {
		a[i] ^= b[i]
	}
	return a[:l]
}

// Send sends the wire labels with OT.
func (f *Ferret) Send(wires []Wire) error {
	wiresCnt := len(wires)
	errch := make(chan error)
	portStr := strings.Split(f.address, ":")[1]
	addr := strings.Split(f.address, ":")[0]
	port, err := strconv.ParseInt(portStr, 10, 0)
	if err != nil {
		return err
	}
	go func() {
		fmt.Println(" - Starting FERRET OT Sender")
		alice, err := ferret.NewFerretOT(
			1,
			addr,
			int(port),
			1,
			uint64(wiresCnt),
			make([]bool, 0),
			true,
		)
		if err != nil {
			errch <- errors.Wrap(err, "send")
			return
		}

		fmt.Println(" - Performing FERRET cOT for wires len =", wiresCnt)
		alice.SendCOT()
		fmt.Println(" - Performing FERRET ROT for wires len =", wiresCnt)
		alice.SendROT()
		fmt.Println(" - Completed FERRET OT")

		// Transfer the random values to wire labels
		for i := 0; i < wiresCnt; i++ {
			// Get block data for label 0 and label 1
			l0Data := alice.SenderGetBlockData(false, uint64(i))
			l1Data := alice.SenderGetBlockData(true, uint64(i))
			var labelData LabelData

			wires[i].L0.GetData(&labelData)
			e0 := xor(l0Data, labelData[:])
			if err := f.io.SendData(e0); err != nil {
				errch <- err
				return
			}
			wires[i].L1.GetData(&labelData)
			e1 := xor(l1Data, labelData[:])
			if err := f.io.SendData(e1); err != nil {
				errch <- err
				return
			}
		}
		errch <- nil
	}()

	err = <-errch
	if err != nil {
		return err
	}

	if err := f.io.Flush(); err != nil {
		return err
	}

	return nil
}

// Receive receives the wire labels with OT based on the flag values.
func (f *Ferret) Receive(flags []bool, result []Label) error {
	flagsCnt := len(flags)

	errch := make(chan error)

	portStr := strings.Split(f.address, ":")[1]
	addr := strings.Split(f.address, ":")[0]
	port, err := strconv.ParseInt(portStr, 10, 0)
	if err != nil {
		return err
	}

	go func() {
		fmt.Println(" - Starting FERRET OT Receiver")
		bob, err := ferret.NewFerretOT(2, addr, int(port), 1, uint64(flagsCnt), flags, true)
		if err != nil {
			errch <- errors.Wrap(err, "receive")
			return
		}
		fmt.Println(" - Performing FERRET cOT for inputs len =", flagsCnt)

		bob.RecvCOT()
		fmt.Println(" - Performing FERRET ROT for inputs len =", flagsCnt)
		bob.RecvROT()
		fmt.Println(" - Completed FERRET OT")

		for i := 0; i < flagsCnt; i++ {
			data := bob.ReceiverGetBlockData(uint64(i))

			var e []byte
			if flags[i] {
				_, err = f.io.ReceiveData()
				if err != nil {
					errch <- err
					return
				}
				e, err := f.io.ReceiveData()
				if err != nil {
					errch <- err
					return
				}
				data = xor(data, e)
			} else {
				e, err = f.io.ReceiveData()
				if err != nil {
					errch <- err
					return
				}
				data = xor(data, e)
				_, err := f.io.ReceiveData()
				if err != nil {
					errch <- err
					return
				}
			}
			result[i].SetBytes(data)
		}
		errch <- nil
	}()

	err = <-errch
	if err != nil {
		return err
	}

	return nil
}
