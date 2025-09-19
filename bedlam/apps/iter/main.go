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
	"math"
	"os"
	"runtime/pprof"
	"strings"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
)

var template = `
package main

func main(a, b int%d) int {
    return a * b
}
`

type result struct {
	bits       int
	bestLimit  int
	bestCost   uint64
	worstLimit int
	worstCost  uint64
	costs      []uint64
}

func main() {
	numWorkers := flag.Int("workers", 8, "number of workers")
	startBits := flag.Int("start", 8, "start bit count")
	endBits := flag.Int("end", 0xffffffff, "end bit count")
	minLimit := flag.Int("min", 8, "treshold minimum limit")
	maxLimit := flag.Int("max", 22, "treshold maximum limit")
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to `file`")
	flag.Parse()

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

	results := make(map[int]*result)
	ch := make(chan *result)

	for i := 0; i < *numWorkers; i++ {
		go func(bits int) {
			for ; bits <= *endBits; bits += *numWorkers {
				code := fmt.Sprintf(template, bits)
				var bestLimit int
				var bestCost uint64
				var worstLimit int
				var worstCost uint64
				var costs []uint64

				params := utils.NewParams()

				for limit := *minLimit; limit <= *maxLimit; limit++ {
					params.CircMultArrayTreshold = limit
					circ, _, err := compiler.New(params).Compile(code, nil)
					if err != nil {
						log.Fatalf("Compilation %d:%d failed: %s\n%s",
							bits, limit, err, code)
					}
					cost := circ.Cost()
					costs = append(costs, cost)

					if bestCost == 0 || cost < bestCost ||
						(limit == 21 && cost <= bestCost) {
						bestCost = cost
						bestLimit = limit
					}
					if cost > worstCost {
						worstCost = cost
						worstLimit = limit
					}
				}
				ch <- &result{
					bits:       bits,
					bestLimit:  bestLimit,
					bestCost:   bestCost,
					worstLimit: worstLimit,
					worstCost:  worstCost,
					costs:      costs,
				}
			}
		}(*startBits + i)
	}

	next := *startBits

outer:
	for result := range ch {
		results[result.bits] = result
		for {
			r, ok := results[next]
			if !ok {
				break
			}
			if r.bestLimit == 21 {
				fmt.Printf("\t// %d: %d, %10d\t%.4f\t%s\n",
					r.bits, r.bestLimit,
					r.bestCost, float64(r.bestCost)/float64(r.worstCost),
					Sparkline(r.costs))
			} else {
				fmt.Printf("\t%d: %d, // %10d\t%.4f\t%s\n",
					r.bits, r.bestLimit,
					r.bestCost, float64(r.bestCost)/float64(r.worstCost),
					Sparkline(r.costs))
			}
			if next >= *endBits {
				break outer
			}
			next++
		}
	}
}

// Sparkline creates a histogram chart of values. The chart is scaled
// to [min...max] containing differences between values.
func Sparkline(values []uint64) string {
	if len(values) == 0 {
		return ""
	}

	var min uint64 = math.MaxUint64
	var max uint64

	for _, v := range values {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	delta := max - min

	var sb strings.Builder
	for _, v := range values {
		var tick uint64
		if delta == 0 {
			tick = 4
		} else {
			tick = (v - min) * 7 / delta
		}
		if v == min && false {
			sb.WriteString("\x1b[92m")
			sb.WriteRune(rune(0x2581 + tick))
			sb.WriteString("\x1b[0m")
		} else {
			sb.WriteRune(rune(0x2581 + tick))
		}
	}
	return sb.String()
}
