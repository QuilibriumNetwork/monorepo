//go:build integrationtest
// +build integrationtest

package global_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	"source.quilibrium.com/quilibrium/monorepo/config"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/provers"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/reward"
	tconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/vdf"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

// benchEnv holds the full environment for a benchmark run.
type benchEnv struct {
	logger          *zap.Logger
	hg              hypergraph.Hypergraph
	inclusionProver *bls48581.KZGInclusionProver
	rdfMultiprover  *schema.RDFMultiprover
	frameProver     *vdf.WesolowskiFrameProver
	frameStore      *store.PebbleClockStore
	intrinsic       *global.GlobalIntrinsic
	proverRegistry  tconsensus.ProverRegistry
	frameNumber     uint64
}

func newBenchEnv(t testing.TB) *benchEnv {
	logger := zap.NewNop()
	ip := bls48581.NewKZGInclusionProver(logger)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)

	dbCfg := &config.DBConfig{InMemoryDONOTUSE: true, Path: ".bench/store"}
	pebbleDB := store.NewPebbleDB(logger, &config.Config{DB: dbCfg}, 0)
	hgStore := store.NewPebbleHypergraphStore(dbCfg, pebbleDB, logger, ve, ip)
	hg := hgcrdt.NewHypergraph(logger, hgStore, ip, []int{}, &tests.Nopthenticator{}, 0)
	rm := schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, ip)
	fp := vdf.NewWesolowskiFrameProver(logger)

	frameCfg := &config.DBConfig{InMemoryDONOTUSE: true, Path: ".bench/frames"}
	frameDB := store.NewPebbleDB(logger, &config.Config{DB: frameCfg}, 0)
	frameStore := store.NewPebbleClockStore(frameDB, logger)

	frameNumber := uint64(100)

	// Seed a prior frame so join proofs can reference it
	txn, err := frameStore.NewTransaction(false)
	require.NoError(t, err)
	err = frameStore.PutGlobalClockFrame(&protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber: frameNumber,
			Output:      make([]byte, 516),
			Difficulty:  50000,
		},
	}, txn)
	require.NoError(t, err)
	require.NoError(t, txn.Commit())

	blsConstructor := &bls48581.Bls48581KeyConstructor{}
	keyManager := keys.NewInMemoryKeyManager(blsConstructor, &bulletproofs.Decaf448KeyConstructor{})
	_, _, err = keyManager.CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
	require.NoError(t, err)

	rewardIssuance := reward.NewOptRewardIssuance()
	proverRegistry, err := provers.NewProverRegistry(logger, hg)
	require.NoError(t, err)

	intr, err := global.LoadGlobalIntrinsic(
		logger,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		hg,
		ip,
		keyManager,
		fp,
		frameStore,
		rewardIssuance,
		proverRegistry,
		blsConstructor,
		nil, // shardsStore – not needed for benchmark
	)
	require.NoError(t, err)

	return &benchEnv{
		logger:          logger,
		hg:              hg,
		inclusionProver: ip,
		rdfMultiprover:  rm,
		frameProver:     fp,
		frameStore:      frameStore,
		intrinsic:       intr,
		proverRegistry:  proverRegistry,
		frameNumber:     frameNumber,
	}
}

// proverIdentity holds pre-generated key material for a single prover.
type proverIdentity struct {
	km      *keys.InMemoryKeyManager
	address []byte
	filter  []byte
}

// pregenKeys creates n BLS48581 key pairs up front (not timed).
func pregenKeys(t testing.TB, n int) []proverIdentity {
	blsConstructor := &bls48581.Bls48581KeyConstructor{}
	ids := make([]proverIdentity, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			filter := make([]byte, 38)
			copy(filter, "bench-filter-")
			binary.BigEndian.PutUint32(filter[34:], uint32(idx))

			km := keys.NewInMemoryKeyManager(blsConstructor, &bulletproofs.Decaf448KeyConstructor{})
			signer, _, err := km.CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
			require.NoError(t, err)

			addressBI, err := poseidon.HashBytes(signer.Public().([]byte))
			require.NoError(t, err)

			ids[idx] = proverIdentity{
				km:      km,
				address: addressBI.FillBytes(make([]byte, 32)),
				filter:  filter,
			}
		}(i)
	}
	wg.Wait()
	return ids
}

// generateJoinPayloads creates n join request payloads (setup, not timed).
func generateJoinPayloads(t testing.TB, env *benchEnv, n int) [][]byte {
	ids := pregenKeys(t, n)
	payloads := make([][]byte, n)
	challenge := sha3.Sum256(make([]byte, 516))

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := &ids[idx]

			proverJoin, err := global.NewProverJoin(
				[][]byte{id.filter},
				env.frameNumber,
				nil, nil,
				id.km,
				env.hg,
				env.rdfMultiprover,
				env.frameProver,
				env.frameStore,
			)
			require.NoError(t, err)

			proof := env.frameProver.CalculateMultiProof(
				challenge, 50000,
				[][]byte{slices.Concat(id.address, id.filter, binary.BigEndian.AppendUint32(nil, 0))},
				0,
			)
			proverJoin.Proof = proof[:]

			err = proverJoin.Prove(env.frameNumber)
			require.NoError(t, err)

			payload, err := proverJoin.ToBytes()
			require.NoError(t, err)
			payloads[idx] = payload
		}(i)
	}
	wg.Wait()
	return payloads
}

// TestBenchmarkFrameProvingWithJoins benchmarks the node-side frame proving
// pipeline with 1, 10, and 100 prover join requests. Join payload generation
// (keygen + VDF + sign) is treated as setup — only the node's work is timed:
//
//   - invoke:     verify + hypergraph mutation for all join requests
//   - commit:     flush state + KZG tree commitment
//   - frameProve: VDF solve + BLS sign for the global frame header
//   - total:      wall-clock sum of the above
func TestBenchmarkFrameProvingWithJoins(t *testing.T) {
	for _, count := range []int{1, 10, 100} {
		t.Run(fmt.Sprintf("joins_%d", count), func(t *testing.T) {
			env := newBenchEnv(t)

			// Setup: generate join payloads (not timed — simulates external provers)
			payloads := generateJoinPayloads(t, env, count)

			// Phase 1: invoke all joins through the intrinsic (verify + mutate)
			initialState := hgstate.NewHypergraphState(env.hg)
			invokeStart := time.Now()
			var wg sync.WaitGroup
			for i := 0; i < count; i++ {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					resultState, err := env.intrinsic.InvokeStep(
						env.frameNumber,
						payloads[idx],
						big.NewInt(0),
						big.NewInt(1),
						initialState,
					)
					require.NoError(t, err)
					require.NotNil(t, resultState)
				}(i)
			}
			wg.Wait()
			invokeDuration := time.Since(invokeStart)
			t.Logf("[%3d joins] invoke:     %v", count, invokeDuration)

			// Phase 2: flush state changes to hypergraph, then KZG tree commit
			commitStart := time.Now()
			err := initialState.Commit()
			require.NoError(t, err)
			_, err = env.hg.Commit(env.frameNumber + 1)
			require.NoError(t, err)
			commitDuration := time.Since(commitStart)
			t.Logf("[%3d joins] commit:     %v", count, commitDuration)

			// Phase 3: prove global frame header (VDF + BLS sign)
			requestTree := &tries.VectorCommitmentTree{}
			for _, payload := range payloads {
				id := sha3.Sum256(payload)
				err := requestTree.Insert(id[:], payload, nil, big.NewInt(0))
				require.NoError(t, err)
			}
			requestRoot := requestTree.Commit(env.inclusionProver, false)

			blsConstructor := &bls48581.Bls48581KeyConstructor{}
			km := keys.NewInMemoryKeyManager(blsConstructor, &bulletproofs.Decaf448KeyConstructor{})
			signer, _, err := km.CreateSigningKey("q-frame-prover-key", crypto.KeyTypeBLS48581G1)
			require.NoError(t, err)

			priorHeader := &protobufs.GlobalFrameHeader{
				FrameNumber: env.frameNumber,
				Output:      make([]byte, 516),
				Difficulty:  50000,
			}

			frameProveStart := time.Now()
			newHeader, err := env.frameProver.ProveGlobalFrameHeader(
				priorHeader,
				nil,          // shard commitments
				nil,          // prover root
				requestRoot,  // request root from our joins
				signer,
				time.Now().UnixMilli(),
				50000,
				0, // prover index
			)
			require.NoError(t, err)
			require.NotNil(t, newHeader)
			frameProveDuration := time.Since(frameProveStart)
			t.Logf("[%3d joins] frameProve: %v", count, frameProveDuration)

			total := invokeDuration + commitDuration + frameProveDuration
			t.Logf("[%3d joins] total:      %v", count, total)
			t.Logf("[%3d joins] breakdown:  invoke=%.1f%% commit=%.1f%% frameProve=%.1f%%",
				count,
				float64(invokeDuration)/float64(total)*100,
				float64(commitDuration)/float64(total)*100,
				float64(frameProveDuration)/float64(total)*100,
			)
		})
	}
}

// BenchmarkJoinInvoke benchmarks InvokeStep for sequentially submitted join
// requests (payloads pre-generated).
func BenchmarkJoinInvoke(b *testing.B) {
	env := newBenchEnv(b)
	payloads := generateJoinPayloads(b, env, b.N)
	initialState := hgstate.NewHypergraphState(env.hg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := env.intrinsic.InvokeStep(
			env.frameNumber,
			payloads[i],
			big.NewInt(0),
			big.NewInt(1),
			initialState,
		)
		require.NoError(b, err)
	}
}

// BenchmarkCommitAfterJoins benchmarks the KZG tree commitment after N joins.
func BenchmarkCommitAfterJoins(b *testing.B) {
	for _, count := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("joins_%d", count), func(b *testing.B) {
			for iter := 0; iter < b.N; iter++ {
				b.StopTimer()
				env := newBenchEnv(b)
				payloads := generateJoinPayloads(b, env, count)
				initialState := hgstate.NewHypergraphState(env.hg)
				for j := 0; j < count; j++ {
					_, err := env.intrinsic.InvokeStep(
						env.frameNumber,
						payloads[j],
						big.NewInt(0),
						big.NewInt(1),
						initialState,
					)
					require.NoError(b, err)
				}
				b.StartTimer()

				err := initialState.Commit()
				require.NoError(b, err)
				_, err = env.hg.Commit(env.frameNumber + 1)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkProveGlobalFrameHeader benchmarks the VDF solve + BLS signing for
// the global frame header.
func BenchmarkProveGlobalFrameHeader(b *testing.B) {
	env := newBenchEnv(b)
	blsConstructor := &bls48581.Bls48581KeyConstructor{}
	km := keys.NewInMemoryKeyManager(blsConstructor, &bulletproofs.Decaf448KeyConstructor{})
	signer, _, err := km.CreateSigningKey("q-frame-prover-key", crypto.KeyTypeBLS48581G1)
	require.NoError(b, err)

	priorHeader := &protobufs.GlobalFrameHeader{
		FrameNumber: env.frameNumber,
		Output:      make([]byte, 516),
		Difficulty:  50000,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := env.frameProver.ProveGlobalFrameHeader(
			priorHeader,
			nil,
			nil,
			nil,
			signer,
			time.Now().UnixMilli(),
			50000,
			0,
		)
		require.NoError(b, err)
	}
}

// extractProverRoot finds the prover root commitment (zero L1 shard key,
// phase 0) from a hypergraph commit set.
func extractProverRoot(
	t testing.TB,
	commits map[tries.ShardKey][][]byte,
) []byte {
	var zeroL1 [3]byte
	for sk, phaseCommits := range commits {
		if sk.L1 == zeroL1 {
			require.NotEmpty(t, phaseCommits, "zero-shard key has empty phase commits")
			require.NotEmpty(t, phaseCommits[0], "prover root commitment is empty")
			return slices.Clone(phaseCommits[0])
		}
	}
	t.Fatal("prover root shard (zero L1) not found in commit set")
	return nil
}

// TestProverRootOrdering demonstrates the relationship between tree commit
// timing and prover root values.
//
// The system has two materialization paths:
//
//   - Prover path (archiveMode=true): ProveNextState(N+1) calls
//     rebuildShardCommitments → hypergraph.Commit(N+1) BEFORE frame N is
//     materialized (its transactions haven't been processed yet).
//
//   - Time reel path (archiveMode=false): persistCanonicalFrames materializes
//     frames sequentially, so frame N is fully materialized before frame N+1
//     is processed.
//
// This test constructs proper provers via real join requests and verifies
// whether the prover root differs when computed before vs after a frame's
// transactions are applied. If the roots differ, a leader that computes
// them before materializing the prior frame will produce a stale header
// that validators (who materialized in order) will reject.
func TestProverRootOrdering(t *testing.T) {
	// ---------------------------------------------------------------
	// Phase 0: Establish base state with initial provers so the
	// prover tree is non-empty and has a meaningful root.
	// ---------------------------------------------------------------
	env := newBenchEnv(t)
	frameN := env.frameNumber // 100

	t.Log("generating initial prover joins (base state)...")
	initialPayloads := generateJoinPayloads(t, env, 3)

	initState := hgstate.NewHypergraphState(env.hg)
	for _, p := range initialPayloads {
		_, err := env.intrinsic.InvokeStep(
			frameN, p, big.NewInt(0), big.NewInt(1), initState,
		)
		require.NoError(t, err)
	}
	require.NoError(t, initState.Commit())

	// Commit base state at frame N (as if materialize(N) ran).
	baseCommits, err := env.hg.Commit(frameN)
	require.NoError(t, err)
	baseRoot := extractProverRoot(t, baseCommits)
	t.Logf("base prover root (state after frame %d):  %x", frameN, baseRoot)

	// ---------------------------------------------------------------
	// Phase 1: Generate more join payloads — these represent frame
	// N+1's transactions (the mutations that SHOULD be reflected in
	// frame N+2's header prover root).
	// ---------------------------------------------------------------
	t.Log("generating additional prover joins (frame N+1 transactions)...")
	morePayloads := generateJoinPayloads(t, env, 3)

	// ---------------------------------------------------------------
	// LEADER PATH: Commit BEFORE applying frame N+1's transactions.
	//
	// This mirrors the prover (archiveMode=true) flow where
	// ProveNextState(N+2) → Collect(N+2) → rebuildShardCommitments →
	// hypergraph.Commit(N+2) runs before materialize(N+1) because
	// the HotStuff QC triggers proving before the prior frame's
	// proposal seals and materializes it.
	// ---------------------------------------------------------------
	preCommits, err := env.hg.Commit(frameN + 1)
	require.NoError(t, err)
	preRoot := extractProverRoot(t, preCommits)
	t.Logf("pre-mutation root (leader's Commit before frame %d txns): %x",
		frameN+1, preRoot)

	// ---------------------------------------------------------------
	// Apply frame N+1's transactions (the joins).
	// ---------------------------------------------------------------
	mutState := hgstate.NewHypergraphState(env.hg)
	for _, p := range morePayloads {
		_, err := env.intrinsic.InvokeStep(
			frameN, p, big.NewInt(0), big.NewInt(1), mutState,
		)
		require.NoError(t, err)
	}
	require.NoError(t, mutState.Commit())

	// ---------------------------------------------------------------
	// VALIDATOR / TIME-REEL PATH: Commit AFTER applying frame N+1's
	// transactions.
	//
	// On the time reel path (archiveMode=false), persistCanonicalFrames
	// materializes frames sequentially: materialize(N+1) runs, then
	// materialize(N+2) runs. By the time N+2's prover root is
	// checked, the tree includes N+1's mutations.
	//
	// We use frame N+2 for the commit key to avoid the Pebble cache
	// hit on N+1 (which would return the stale pre-mutation roots).
	// The frame number is only a cache key; the computed tree root is
	// the same regardless of the frame number.
	// ---------------------------------------------------------------
	postCommits, err := env.hg.Commit(frameN + 2)
	require.NoError(t, err)
	postRoot := extractProverRoot(t, postCommits)
	t.Logf("post-mutation root (validator's Commit after frame %d txns): %x",
		frameN+1, postRoot)

	// ---------------------------------------------------------------
	// Verify: pre-mutation root should equal the base root (nothing
	// changed between Commit(N) and Commit(N+1) since we didn't
	// apply transactions in between).
	// ---------------------------------------------------------------
	require.True(t, bytes.Equal(baseRoot, preRoot),
		"pre-mutation root should equal base root (no new mutations applied)\n"+
			"  base: %x\n  pre:  %x", baseRoot, preRoot)

	// ---------------------------------------------------------------
	// Verify: post-mutation root should differ from pre-mutation root
	// because the join transactions added new prover vertices to the
	// tree. This proves the ordering matters — a leader that commits
	// before materializing the prior frame gets a stale root.
	// ---------------------------------------------------------------
	require.False(t, bytes.Equal(preRoot, postRoot),
		"pre vs post mutation roots should differ — proves commit timing matters\n"+
			"  pre:  %x\n  post: %x", preRoot, postRoot)

	t.Logf("CONFIRMED: prover root depends on commit timing relative to mutations")
	t.Logf("  base root (frame %d):       %x", frameN, baseRoot)
	t.Logf("  pre-mutation  (frame %d):    %x", frameN+1, preRoot)
	t.Logf("  post-mutation (frame %d):    %x", frameN+2, postRoot)
	t.Logf("")
	t.Logf("Leader computes frame N+2 header with pre-mutation root (state after N)")
	t.Logf("Validator computes local root with post-mutation root (state after N+1)")
	t.Logf("Mismatch triggers performBlockingProverHypersync")
}

// TestProverRootOrderingTwoEnvironments uses two independent hypergraph
// instances to simulate a leader node and a validator node, demonstrating
// that they produce different prover roots for the same frame because of
// different materialization ordering.
func TestProverRootOrderingTwoEnvironments(t *testing.T) {
	// ---------------------------------------------------------------
	// Setup: two completely independent environments.
	// ---------------------------------------------------------------
	leaderEnv := newBenchEnv(t)
	validatorEnv := newBenchEnv(t)
	frameN := leaderEnv.frameNumber // 100

	// Generate independent join payloads for each environment.
	// They use different keys but produce equivalent tree mutations
	// (same number of prover vertices added).
	t.Log("generating join payloads for leader and validator environments...")
	leaderPayloads := generateJoinPayloads(t, leaderEnv, 3)
	validatorPayloads := generateJoinPayloads(t, validatorEnv, 3)

	// ---------------------------------------------------------------
	// Both environments: establish identical base state.
	// Process initial joins and commit at frame N.
	// ---------------------------------------------------------------
	for _, env := range []*benchEnv{leaderEnv, validatorEnv} {
		var payloads [][]byte
		if env == leaderEnv {
			payloads = leaderPayloads
		} else {
			payloads = validatorPayloads
		}
		s := hgstate.NewHypergraphState(env.hg)
		for _, p := range payloads {
			_, err := env.intrinsic.InvokeStep(
				frameN, p, big.NewInt(0), big.NewInt(1), s,
			)
			require.NoError(t, err)
		}
		require.NoError(t, s.Commit())
		_, err := env.hg.Commit(frameN)
		require.NoError(t, err)
	}

	// Generate "frame N+1" join payloads for each environment.
	t.Log("generating frame N+1 join payloads...")
	leaderNewPayloads := generateJoinPayloads(t, leaderEnv, 3)
	validatorNewPayloads := generateJoinPayloads(t, validatorEnv, 3)

	// ---------------------------------------------------------------
	// LEADER: Commit(N+1) BEFORE materializing frame N+1's joins.
	// This is what happens in ProveNextState → rebuildShardCommitments.
	// ---------------------------------------------------------------
	leaderCommits, err := leaderEnv.hg.Commit(frameN + 1)
	require.NoError(t, err)
	leaderRoot := extractProverRoot(t, leaderCommits)
	t.Logf("leader root for N+1 (pre-mutation): %x", leaderRoot)

	// Leader materializes AFTER proving (when own proposal seals prior frame).
	leaderState := hgstate.NewHypergraphState(leaderEnv.hg)
	for _, p := range leaderNewPayloads {
		_, err := leaderEnv.intrinsic.InvokeStep(
			frameN, p, big.NewInt(0), big.NewInt(1), leaderState,
		)
		require.NoError(t, err)
	}
	require.NoError(t, leaderState.Commit())

	// ---------------------------------------------------------------
	// VALIDATOR (time reel path): materialize frame N+1 FIRST, then
	// compute roots. persistCanonicalFrames materializes sequentially.
	// ---------------------------------------------------------------
	validatorState := hgstate.NewHypergraphState(validatorEnv.hg)
	for _, p := range validatorNewPayloads {
		_, err := validatorEnv.intrinsic.InvokeStep(
			frameN, p, big.NewInt(0), big.NewInt(1), validatorState,
		)
		require.NoError(t, err)
	}
	require.NoError(t, validatorState.Commit())

	// Validator commits AFTER mutations.
	validatorCommits, err := validatorEnv.hg.Commit(frameN + 1)
	require.NoError(t, err)
	validatorRoot := extractProverRoot(t, validatorCommits)
	t.Logf("validator root for N+1 (post-mutation): %x", validatorRoot)

	// ---------------------------------------------------------------
	// Note: leader and validator use different key material, so their
	// absolute roots will differ regardless of ordering. What matters
	// is comparing each environment's pre vs post mutation roots.
	//
	// Check that the leader's Commit(N+1) cache is stale: committing
	// again at N+2 on the leader (after mutations) should differ.
	// ---------------------------------------------------------------
	leaderPostCommits, err := leaderEnv.hg.Commit(frameN + 2)
	require.NoError(t, err)
	leaderPostRoot := extractProverRoot(t, leaderPostCommits)
	t.Logf("leader root at N+2 (post-mutation): %x", leaderPostRoot)

	require.False(t, bytes.Equal(leaderRoot, leaderPostRoot),
		"leader's pre-mutation and post-mutation roots must differ\n"+
			"  pre (N+1):  %x\n  post (N+2): %x", leaderRoot, leaderPostRoot)

	t.Logf("CONFIRMED: leader's Commit(N+1) cached stale roots")
	t.Logf("  Subsequent Commit(N+1) on this node returns the SAME stale roots")
	t.Logf("  But a validator node (time reel) computing Commit(N+1) AFTER")
	t.Logf("  materializing gets fresh (correct) roots → header mismatch")
}
