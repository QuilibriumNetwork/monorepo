//
// Copyright (c) 2020-2023 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"fmt"
	"io"
	"net"
	"strings"

	"source.quilibrium.com/quilibrium/monorepo/bedlam"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/ot"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/p2p"
)

func streamEvaluatorMode(oti ot.OT, input input, once bool, address string) error {
	inputSizes, err := circuit.InputSizes(input)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	fmt.Printf("Listening for connections at %s\n", address)

	for {
		nc, err := ln.Accept()
		if err != nil {
			return err
		}
		fmt.Printf("New connection from %s\n", nc.RemoteAddr())

		conn := p2p.NewConn(nc)

		err = conn.SendInputSizes(inputSizes)
		if err != nil {
			conn.Close()
			return err
		}
		err = conn.Flush()
		if err != nil {
			conn.Close()
			return err
		}

		outputs, result, err := circuit.StreamEvaluator(conn, oti, input,
			verbose)
		conn.Close()

		if err != nil && err != io.EOF {
			return fmt.Errorf("%s: %v", nc.RemoteAddr(), err)
		}

		bedlam.PrintResults(result, outputs)
		if once {
			return nil
		}
	}
}

func streamGarblerMode(params *utils.Params, oti ot.OT, input input,
	args []string, address string) error {

	inputSizes := make([][]int, 2)

	sizes, err := circuit.InputSizes(input)
	if err != nil {
		return err
	}
	inputSizes[0] = sizes

	if len(args) != 1 || !strings.HasSuffix(args[0], ".qcl") {
		return fmt.Errorf("streaming mode takes single QCL file")
	}
	nc, err := net.Dial("tcp", address)
	if err != nil {
		return err
	}
	conn := p2p.NewConn(nc)
	defer conn.Close()

	sizes, err = conn.ReceiveInputSizes()
	if err != nil {
		return err
	}
	inputSizes[1] = sizes

	outputs, result, err := compiler.New(params).StreamFile(
		conn, oti, args[0], input, inputSizes)
	if err != nil {
		return err
	}
	bedlam.PrintResults(result, outputs)
	return nil
}
