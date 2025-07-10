//
// main.go
//
// Copyright (c) 2019-2024 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"slices"
	"strings"

	"source.quilibrium.com/quilibrium/monorepo/bedlam"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/ot"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/p2p"
)

var (
	verbose = false
)

type input []string

func (i *input) String() string {
	return fmt.Sprint(*i)
}

func (i *input) Set(value string) error {
	for _, v := range strings.Split(value, ",") {
		*i = append(*i, v)
	}
	return nil
}

var inputFlag, peerFlag input

func init() {
	flag.Var(&inputFlag, "i", "comma-separated list of circuit inputs")
	flag.Var(&peerFlag, "pi", "comma-separated list of peer's circuit inputs")
}

func main() {
	evaluator := flag.Bool("e", false, "evaluator / garbler mode")
	stream := flag.Bool("stream", false, "streaming mode")
	compile := flag.Bool("circ", false, "compile QCL to circuit")
	circFormat := flag.String("format", "qclc",
		"circuit format: qclc, bristol")
	ssa := flag.Bool("ssa", false, "compile QCL to SSA assembly")
	dot := flag.Bool("dot", false, "create Graphviz DOT output")
	svg := flag.Bool("svg", false, "create SVG output")
	optimize := flag.Int("O", 1, "optimization level")
	address := flag.String("address", "127.0.0.1:8080", "address and port")
	otAddress := flag.String("ot-address", "127.0.0.1:5555", "address and port")
	fVerbose := flag.Bool("v", false, "verbose output")
	fDiagnostics := flag.Bool("d", false, "diagnostics output")
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to `file`")
	memprofile := flag.String("memprofile", "",
		"write memory profile to `file`")
	qclcErrLoc := flag.Bool("qclc-err-loc", false,
		"print QCLC error locations")
	benchmarkCompile := flag.Bool("benchmark-compile", false,
		"benchmark QCL compilation")
	flag.Parse()

	log.SetFlags(0)

	verbose = *fVerbose

	if len(*cpuprofile) > 0 {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}

	params := utils.NewParams()
	defer params.Close()

	params.Verbose = *fVerbose
	params.Diagnostics = *fDiagnostics
	params.QCLCErrorLoc = *qclcErrLoc
	params.BenchmarkCompile = *benchmarkCompile

	if *optimize > 0 {
		params.OptPruneGates = true
	}
	if *ssa && !*compile {
		params.NoCircCompile = true
	}

	if *compile || *ssa {
		inputSizes := make([][]int, 2)
		iSizes, err := circuit.InputSizes(inputFlag)
		if err != nil {
			log.Fatal(err)
		}
		pSizes, err := circuit.InputSizes(peerFlag)
		if err != nil {
			log.Fatal(err)
		}
		if *evaluator {
			inputSizes[0] = pSizes
			inputSizes[1] = iSizes
		} else {
			inputSizes[0] = iSizes
			inputSizes[1] = pSizes
		}

		err = compileFiles(flag.Args(), params, inputSizes,
			*compile, *ssa, *dot, *svg, *circFormat)
		if err != nil {
			log.Fatalf("compile failed: %s", err)
		}
		memProfile(*memprofile)
		return
	}

	var err error

	party := uint8(1)
	if *evaluator {
		party = 2
	}

	oti := ot.NewFerret(party, *otAddress)

	if *stream {
		if *evaluator {
			err = streamEvaluatorMode(oti, inputFlag, len(*cpuprofile) > 0, *address)
		} else {
			err = streamGarblerMode(params, oti, inputFlag, flag.Args(), *address)
		}
		memProfile(*memprofile)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	if len(flag.Args()) != 1 {
		log.Fatalf("expected one input file, got %v\n", len(flag.Args()))
	}
	file := flag.Args()[0]

	if *evaluator {
		err = evaluatorMode(oti, file, params, len(*cpuprofile) > 0, *address)
	} else {
		err = garblerMode(oti, file, params, *address)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func loadCircuit(file string, params *utils.Params, inputSizes [][]int) (
	*circuit.Circuit, error) {

	var circ *circuit.Circuit
	var err error

	if circuit.IsFilename(file) {
		circ, err = circuit.Parse(file)
		if err != nil {
			return nil, err
		}
	} else if strings.HasSuffix(file, ".qcl") {
		circ, _, err = compiler.New(params).CompileFile(file, inputSizes)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("unknown file type '%s'", file)
	}

	if circ != nil {
		circ.AssignLevels()
		if verbose {
			fmt.Printf("circuit: %v\n", circ)
		}
	}
	return circ, err
}

func memProfile(file string) {
	if len(file) == 0 {
		return
	}

	f, err := os.Create(file)
	if err != nil {
		log.Fatal("could not create memory profile: ", err)
	}
	defer f.Close()
	if false {
		runtime.GC()
	}
	if err := pprof.WriteHeapProfile(f); err != nil {
		log.Fatal("could not write memory profile: ", err)
	}
}

func evaluatorMode(oti ot.OT, file string, params *utils.Params,
	once bool, address string) error {

	inputSizes := make([][]int, 2)
	myInputSizes, err := circuit.InputSizes(inputFlag)
	if err != nil {
		return err
	}
	inputSizes[1] = myInputSizes

	ln, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	fmt.Printf("Listening for connections at %s\n", address)

	var oPeerInputSizes []int
	var circ *circuit.Circuit

	for {
		nc, err := ln.Accept()
		if err != nil {
			return err
		}
		fmt.Printf("New connection from %s\n", nc.RemoteAddr())

		conn := p2p.NewConn(nc)

		err = conn.SendInputSizes(myInputSizes)
		if err != nil {
			conn.Close()
			return err
		}
		err = conn.Flush()
		if err != nil {
			conn.Close()
			return err
		}
		peerInputSizes, err := conn.ReceiveInputSizes()
		if err != nil {
			conn.Close()
			return err
		}
		inputSizes[0] = peerInputSizes

		if circ == nil || slices.Compare(peerInputSizes, oPeerInputSizes) != 0 {
			circ, err = loadCircuit(file, params, inputSizes)
			if err != nil {
				conn.Close()
				return err
			}
			oPeerInputSizes = peerInputSizes
		}
		circ.PrintInputs(circuit.IDEvaluator, inputFlag)
		if len(circ.Inputs) != 2 {
			return fmt.Errorf("invalid circuit for 2-party MPC: %d parties",
				len(circ.Inputs))
		}

		input, err := circ.Inputs[1].Parse(inputFlag)
		if err != nil {
			conn.Close()
			return fmt.Errorf("%s: %v", file, err)
		}
		result, err := circuit.Evaluator(conn, oti, circ, input, verbose)
		conn.Close()
		if err != nil && err != io.EOF {
			return err
		}
		bedlam.PrintResults(result, circ.Outputs)
		if once {
			return nil
		}
	}
}

func garblerMode(oti ot.OT, file string, params *utils.Params, address string) error {
	inputSizes := make([][]int, 2)
	myInputSizes, err := circuit.InputSizes(inputFlag)
	if err != nil {
		return err
	}
	inputSizes[0] = myInputSizes

	nc, err := net.Dial("tcp", address)
	if err != nil {
		return err
	}
	conn := p2p.NewConn(nc)
	defer conn.Close()

	if params.Verbose {
		fmt.Println(" - Receiving input sizes")
	}
	peerInputSizes, err := conn.ReceiveInputSizes()
	if err != nil {
		conn.Close()
		return err
	}

	if params.Verbose {
		fmt.Println(" - Sending input sizes")
	}
	inputSizes[1] = peerInputSizes
	err = conn.SendInputSizes(myInputSizes)
	if err != nil {
		conn.Close()
		return err
	}

	if params.Verbose {
		fmt.Println(" - Sent input sizes")
	}
	err = conn.Flush()
	if err != nil {
		conn.Close()
		return err
	}

	circ, err := loadCircuit(file, params, inputSizes)
	if err != nil {
		return err
	}
	circ.PrintInputs(circuit.IDGarbler, inputFlag)
	if len(circ.Inputs) != 2 {
		return fmt.Errorf("invalid circuit for 2-party MPC: %d parties",
			len(circ.Inputs))
	}

	input, err := circ.Inputs[0].Parse(inputFlag)
	if err != nil {
		return fmt.Errorf("%s: %v", file, err)
	}

	if params.Verbose {
		fmt.Println(" - Initiating garbler")
	}
	result, err := circuit.Garbler(conn, oti, circ, input, verbose)
	if err != nil {
		return err
	}
	bedlam.PrintResults(result, circ.Outputs)

	return nil
}
