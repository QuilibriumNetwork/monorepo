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
	"fmt"
	"log"
	"os"
)

func main() {
	flag.Parse()

	log.SetFlags(0)

	if len(flag.Args()) == 0 {
		fmt.Printf("no files specified\n")
		os.Exit(1)
	}
	if err := dumpObjects(flag.Args()); err != nil {
		log.Fatal(err)
	}
}
