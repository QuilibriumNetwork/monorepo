//
// main.go
//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"flag"
	"log"
	"os"
	"runtime/pprof"
)

var (
	port = ":8080"
)

func main() {
	evaluator := flag.Bool("e", false, "evaluator / garbler mode")
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to `file`")
	testIO := flag.Int64("test-io", 0, "test I/O performance")
	flag.Parse()

	log.SetFlags(0)

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

	if *testIO > 0 {
		if *evaluator {
			err := evaluatorTestIO(*testIO, len(*cpuprofile) > 0)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			err := garblerTestIO(*testIO)
			if err != nil {
				log.Fatal(err)
			}
		}
		return
	}
}
