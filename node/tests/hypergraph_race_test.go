package tests

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	hg "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type vertexSpec struct {
	appAddr  [32]byte
	dataAddr [32]byte
	commit   []byte
	size     *big.Int
}

// TestConcurrentAddVertexAndCommitRace verifies that serializing
// AddVertex batches and Commit calls with a mutex (the commitBarrier
// pattern) prevents partial-state tree roots.
//
// The test applies the same serialization that GlobalConsensusEngine
// uses: a mutex held across the entire AddVertex loop and around each
// Commit call. With this barrier, Commit can never observe a partially
// modified tree.
func TestConcurrentAddVertexAndCommitRace(t *testing.T) {
	const (
		iterations     = 100
		verticesPerRun = 50
		// Multiple concurrent commit goroutines to increase contention.
		commitGoroutines = 4
	)

	// Ensure true parallelism.
	prevProcs := runtime.GOMAXPROCS(runtime.NumCPU())
	defer runtime.GOMAXPROCS(prevProcs)

	logger, _ := zap.NewDevelopment()

	for iter := 0; iter < iterations; iter++ {
		prover := &mocks.MockInclusionProver{}
		mockCommit := make([]byte, 74)
		mockCommit[0] = 0x02
		rand.Read(mockCommit[1:])
		prover.On("CommitRaw", mock.Anything, mock.Anything).Return(mockCommit, nil)

		enc := &mocks.MockVerifiableEncryptor{}
		dbCfg := &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}

		s := store.NewPebbleDB(logger, &config.Config{DB: dbCfg}, 0)
		hgStore := store.NewPebbleHypergraphStore(
			dbCfg, s, logger, enc, prover,
		)
		hgcrdt := hg.NewHypergraph(
			logger,
			hgStore,
			prover,
			[]int{},
			&Nopthenticator{},
			200,
		)

		// All vertices share the same appAddress so they land in the same shard,
		// maximizing tree contention.
		appAddr := [32]byte{0x10}

		// Commit baseline (frame 1) with no vertices — this is the
		// "before" state that a commit goroutine may validly capture
		// if it acquires the barrier before the AddVertex goroutine.
		baselineCommits, err := hgcrdt.Commit(1)
		if err != nil {
			t.Fatalf("iter %d: baseline commit failed: %v", iter, err)
		}

		// Prepare vertices to add.
		specs := make([]vertexSpec, verticesPerRun)
		for i := 0; i < verticesPerRun; i++ {
			dataAddr := [32]byte{byte(i + 1), byte(iter), byte(i >> 8)}
			specs[i] = vertexSpec{
				appAddr:  appAddr,
				dataAddr: dataAddr,
				commit:   mockCommit,
				size:     big.NewInt(55),
			}
		}

		// commitBarrier mirrors the mutex in GlobalConsensusEngine that
		// serializes materialize (AddVertex loop) with
		// rebuildShardCommitments (Commit).
		var commitBarrier sync.Mutex

		var wg sync.WaitGroup
		start := make(chan struct{})

		type commitResult struct {
			commits map[tries.ShardKey][][]byte
			err     error
		}
		results := make([]commitResult, commitGoroutines)

		wg.Add(1 + commitGoroutines)

		// Goroutine A: add vertices one at a time (like materialize does).
		// Holds the barrier across the entire batch.
		go func() {
			defer wg.Done()
			<-start
			commitBarrier.Lock()
			defer commitBarrier.Unlock()
			for _, vs := range specs {
				v := hg.NewVertex(vs.appAddr, vs.dataAddr, vs.commit, vs.size)
				if addErr := hgcrdt.AddVertex(nil, v); addErr != nil {
					t.Errorf("iter %d: AddVertex failed: %v", iter, addErr)
					return
				}
				// Yield between additions — without the barrier this would
				// allow Commit to interleave and capture partial state.
				runtime.Gosched()
			}
		}()

		// Goroutines B: commit the tree concurrently with vertex additions.
		// Each acquires the barrier around Commit, so it waits for any
		// in-progress AddVertex batch to finish.
		for g := 0; g < commitGoroutines; g++ {
			g := g
			go func() {
				defer wg.Done()
				<-start
				// Stagger start to hit different points in the AddVertex sequence.
				for y := 0; y < g*3; y++ {
					runtime.Gosched()
				}
				commitBarrier.Lock()
				results[g].commits, results[g].err = hgcrdt.Commit(
					uint64(iter*10+g+2),
				)
				commitBarrier.Unlock()
			}()
		}

		close(start)
		wg.Wait()

		for g, r := range results {
			if r.err != nil {
				t.Fatalf("iter %d goroutine %d: commit failed: %v", iter, g, r.err)
			}
		}

		// Final commit with ALL vertices present — the canonical state.
		expectedCommits, err := hgcrdt.Commit(uint64(iter*10 + commitGoroutines + 2))
		if err != nil {
			t.Fatalf("iter %d: expected commit failed: %v", iter, err)
		}

		// With the commitBarrier, each concurrent commit must reflect a
		// consistent state: either the baseline (0 vertices, committed
		// before AddVertex batch) or the final state (all vertices,
		// committed after). Any other result means Commit() interleaved
		// with AddVertex calls and captured partial state.
		for g, r := range results {
			matchesBaseline := commitMapsEqual(r.commits, baselineCommits)
			matchesFinal := commitMapsEqual(r.commits, expectedCommits)
			if !matchesBaseline && !matchesFinal {
				t.Fatalf(
					"iter %d goroutine %d: commit captured partial state "+
						"(tree root matches neither baseline nor final — "+
						"divergence detected)",
					iter, g,
				)
			}
		}
	}
}

// commitMapsEqual compares two commit maps for byte-level equality.
func commitMapsEqual(a, b map[tries.ShardKey][][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, aPhases := range a {
		bPhases, ok := b[k]
		if !ok {
			return false
		}
		if len(aPhases) != len(bPhases) {
			return false
		}
		for i := range aPhases {
			if !bytes.Equal(aPhases[i], bPhases[i]) {
				return false
			}
		}
	}
	return true
}
