//
// main.go
//
// Copyright (c) 2023 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"fmt"
	"io"
	"net"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/ot"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/p2p"
)

func evaluatorTestIO(size int64, once bool) error {
	ln, err := net.Listen("tcp", port)
	if err != nil {
		return err
	}
	fmt.Printf("Listening for connections at %s\n", port)

	for {
		nc, err := ln.Accept()
		if err != nil {
			return err
		}
		fmt.Printf("New connection from %s\n", nc.RemoteAddr())

		conn := p2p.NewConn(nc)
		for {
			var label ot.Label
			var labelData ot.LabelData
			err = conn.ReceiveLabel(&label, &labelData)
			if err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
		}
		fmt.Printf("Received: %v\n",
			circuit.FileSize(conn.Stats.Sum()).String())

		if once {
			return nil
		}
	}
}

func garblerTestIO(size int64) error {
	nc, err := net.Dial("tcp", port)
	if err != nil {
		return err
	}
	conn := p2p.NewConn(nc)

	var sent int64
	var label ot.Label
	var labelData ot.LabelData

	for sent < size {
		err = conn.SendLabel(label, &labelData)
		if err != nil {
			return err
		}
		sent += int64(len(labelData))
	}
	if err := conn.Flush(); err != nil {
		return err
	}
	if err := conn.Close(); err != nil {
		return err
	}

	fmt.Printf("Sent: %v\n", circuit.FileSize(conn.Stats.Sum()).String())
	return nil
}
