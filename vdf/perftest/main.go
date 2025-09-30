package main

import (
	"flag"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"

	"source.quilibrium.com/quilibrium/monorepo/vdf"
)

var parallelism = flag.Int(
	"parallelism",
	1,
	"number of parallel instances to run of the VDF",
)

func main() {
	flag.Parse()

	fmt.Println("===========================================")
	fmt.Println("VDF Performance Tester")
	fmt.Println("===========================================")

	fmt.Println("Step 1. Generate challenge hashes")
	challenges := make([][]byte, 10)
	for i := range 10 {
		if i == 0 {
			c := sha3.Sum256([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
			challenges[i] = c[:]
		} else {
			c := sha3.Sum256(challenges[i-1])
			challenges[i] = c[:]
		}
	}

	fmt.Println("Step 2. Run Perf Test Scenarios")
	difficulties := []uint32{10000, 50000, 100000, 200000, 400000}
	solveDurations := [5][]time.Duration{}
	verifyDurations := [5][]time.Duration{}

	for batch, difficulty := range difficulties {
		solveDurations[batch] = make([]time.Duration, *parallelism)
		verifyDurations[batch] = make([]time.Duration, *parallelism)

		fmt.Println("Running VDF with difficulty =", difficulty)
		wg := sync.WaitGroup{}
		for p := range *parallelism {
			p := p
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i, challenge := range challenges {
					fmt.Printf("Running (%d/10) on core %d...\n", i+1, p)
					start := time.Now()
					solution := vdf.WesolowskiSolve([32]byte(challenge), difficulty)
					solveDurations[batch][p] += time.Since(start)
					start = time.Now()
					isOk := vdf.WesolowskiVerify([32]byte(challenge), difficulty, solution)
					verifyDurations[batch][p] += time.Since(start)
					if !isOk {
						panic("COULD NOT VERIFY SOLUTION")
					}
				}
			}()
		}

		wg.Wait()
	}

	fmt.Println("===========================================")
	fmt.Println("VDF Performance Tester Results")
	fmt.Println("===========================================")
	fmt.Println("Individual Core Results:")
	for p := range *parallelism {
		fmt.Printf("Core %d:\n-------------------------------------------\n", p)
		fmt.Printf("Difficulty %d Average Prove: %v\n", difficulties[0], (solveDurations[0][p] / 10))
		fmt.Printf("Difficulty %d Average Prove: %v\n", difficulties[1], (solveDurations[1][p] / 10))
		fmt.Printf("Difficulty %d Average Prove: %v\n", difficulties[2], (solveDurations[2][p] / 10))
		fmt.Printf("Difficulty %d Average Prove: %v\n", difficulties[3], (solveDurations[3][p] / 10))
		fmt.Printf("Difficulty %d Average Prove: %v\n", difficulties[4], (solveDurations[4][p] / 10))
		fmt.Printf("Difficulty %d Average Verify: %v\n", difficulties[0], (verifyDurations[0][p] / 10))
		fmt.Printf("Difficulty %d Average Verify: %v\n", difficulties[1], (verifyDurations[1][p] / 10))
		fmt.Printf("Difficulty %d Average Verify: %v\n", difficulties[2], (verifyDurations[2][p] / 10))
		fmt.Printf("Difficulty %d Average Verify: %v\n", difficulties[3], (verifyDurations[3][p] / 10))
		fmt.Printf("Difficulty %d Average Verify: %v\n", difficulties[4], (verifyDurations[4][p] / 10))
	}
	fmt.Println("===========================================")
	fmt.Println("Average Results:")
	for i := range 5 {
		solveDuration := time.Duration(0)
		for p := range *parallelism {
			solveDuration += solveDurations[i][p]
		}
		solveDuration = solveDuration / time.Duration(10**parallelism)
		fmt.Printf("Difficulty %d Average Prove: %v\n", difficulties[i], solveDuration)
	}
	for i := range 5 {
		verifyDuration := time.Duration(0)
		for p := range *parallelism {
			verifyDuration += verifyDurations[i][p]
		}
		verifyDuration = verifyDuration / time.Duration(10**parallelism)
		fmt.Printf("Difficulty %d Average Verify: %v\n", difficulties[i], verifyDuration)
	}
	fmt.Println("===========================================")
}
