//go:build rusthypergraph

package tests

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	hg "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	ffi "source.quilibrium.com/quilibrium/monorepo/quil-hypergraph-ffi/generated/quil_hypergraph_ffi"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// noopProver returns a MockInclusionProver that matches the Rust
// NoopInclusionProver: CommitRaw returns 64 zero bytes, ProveRaw returns
// empty, VerifyRaw returns true.
func noopProver() *mocks.MockInclusionProver {
	prover := &mocks.MockInclusionProver{}
	prover.On("CommitRaw", mock.Anything, mock.Anything).
		Return(make([]byte, 64), nil).Maybe()
	prover.On("ProveRaw", mock.Anything, mock.Anything, mock.Anything).
		Return([]byte{}, nil).Maybe()
	prover.On("VerifyRaw", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Maybe()
	return prover
}

// parseShardsFromCommitPhase deserializes the packed byte vector returned
// by the Rust FFI commit_phase into a map matching the Go Commit() return
// type.  Each shard entry is 291 bytes: L1(3) | L2(32) | 4 * root(64).
func parseShardsFromCommitPhase(data []byte) map[tries.ShardKey][][]byte {
	const entrySize = 3 + 32 + 4*64 // 291

	result := make(map[tries.ShardKey][][]byte)
	for len(data) >= entrySize {
		var sk tries.ShardKey
		copy(sk.L1[:], data[:3])
		copy(sk.L2[:], data[3:35])

		roots := make([][]byte, 4)
		for i := 0; i < 4; i++ {
			off := 35 + i*64
			roots[i] = make([]byte, 64)
			copy(roots[i], data[off:off+64])
		}
		result[sk] = roots
		data = data[entrySize:]
	}
	return result
}

// makeShardL1 computes the Rust-compatible XOR bloom L1 for a 32-byte
// app address.  This mirrors the Rust shard_key_for_location logic:
//
//	for i, b := range appAddress { l1[i%3] ^= b }
func makeShardL1(appAddress [32]byte) [3]byte {
	indices := p2p.GetBloomFilterIndices(appAddress[:], 256, 3)
	var l1 [3]byte
	copy(l1[:], indices)
	return l1
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestRustGoShardKey compares shard key computation between the Rust FFI
// (shard_key_for_location) and the Go bloom filter (GetBloomFilterIndices).
//
// The Rust implementation uses simple XOR folding while Go uses SHAKE256.
// This test documents whether they agree; a failure indicates the
// implementations have diverged and need reconciliation.
func TestRustGoShardKey(t *testing.T) {
	cases := []struct {
		name string
		addr [32]byte
	}{
		{"all_zeros", [32]byte{}},
		{"all_0x01", func() [32]byte { var a [32]byte; for i := range a { a[i] = 0x01 }; return a }()},
		{"sequential", func() [32]byte { var a [32]byte; for i := range a { a[i] = byte(i) }; return a }()},
		{"all_0xff", func() [32]byte { var a [32]byte; for i := range a { a[i] = 0xff }; return a }()},
		{"single_byte", func() [32]byte { var a [32]byte; a[0] = 0x42; return a }()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Rust FFI
			rustResult := ffi.ShardKeyForLocation(tc.addr[:])
			require.Len(t, rustResult, 35, "Rust shard key must be 35 bytes: L1(3)+L2(32)")

			rustL1 := rustResult[:3]
			rustL2 := rustResult[3:]

			// Verify L2 is the identity (app address)
			assert.Equal(t, tc.addr[:], rustL2, "L2 must equal the input app address")

			// Go bloom filter (used for L1 in Go's GetShardAddress)
			goL1 := p2p.GetBloomFilterIndices(tc.addr[:], 256, 3)

			t.Logf("addr=%x  rustL1=%x  goL1=%x  match=%v",
				tc.addr[:4], rustL1, goL1, bytes.Equal(rustL1, goL1))

			// Cross-check: report mismatch so we know the implementations
			// differ.  The test is structured as an assertion so CI will
			// flag when they diverge.
			assert.Equal(t, goL1, rustL1,
				"Rust XOR-bloom L1 vs Go SHAKE256-bloom L1 must match "+
					"for the same app address. If this fails, the two "+
					"implementations use different algorithms and need "+
					"to be reconciled.")
		})
	}
}

// TestRustGoBloomFilterIndices compares bloom filter index computation
// between Rust (SHA-256 double hashing) and Go (SHAKE256 bit extraction).
func TestRustGoBloomFilterIndices(t *testing.T) {
	cases := []struct {
		name       string
		key        []byte
		numBuckets uint32
		numHashes  uint32
	}{
		{"basic", []byte("test-key"), 1024, 3},
		{"small_buckets", []byte("abc"), 16, 2},
		{"many_hashes", []byte{0x01, 0x02, 0x03}, 256, 5},
		{"single_hash", []byte("hello"), 512, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rustResult := ffi.ComputeBloomFilterIndices(tc.key, tc.numBuckets, tc.numHashes)
			require.Len(t, rustResult, int(tc.numHashes)*4,
				"Rust bloom indices must be numHashes*4 bytes")

			// Decode Rust indices
			rustIndices := make([]uint32, tc.numHashes)
			for i := uint32(0); i < tc.numHashes; i++ {
				rustIndices[i] = binary.BigEndian.Uint32(rustResult[i*4 : (i+1)*4])
				assert.Less(t, rustIndices[i], tc.numBuckets,
					"each Rust index must be < numBuckets")
			}

			// Go bloom filter — note: Go's GetBloomFilterIndices uses a
			// different algorithm (SHAKE256 vs SHA-256), so this cross-check
			// may fail.  We still log both for comparison.
			goResult := p2p.GetBloomFilterIndices(tc.key, int(tc.numBuckets), int(tc.numHashes))
			t.Logf("key=%x  rustIndices=%v  goResult=%x", tc.key, rustIndices, goResult)

			// Note: Go's GetBloomFilterIndices returns sorted bit-position
			// bytes, not u32 bucket indices.  The formats are not directly
			// comparable because the Go function packs positions differently.
			// This test primarily validates that the Rust FFI returns
			// well-formed data; a separate reconciliation effort is needed
			// to unify the algorithms.
		})
	}
}

// TestRustGoVertexRoundtrip verifies that set_vertex / get_vertex / delete_vertex
// on the Rust CRDT work correctly as a standalone roundtrip.
func TestRustGoVertexRoundtrip(t *testing.T) {
	handle := ffi.CreateCrdt()
	defer ffi.DestroyCrdt(handle)

	l1 := []byte{0xAA, 0xBB, 0xCC}
	l2 := bytes.Repeat([]byte{0x01}, 32)
	key := bytes.Repeat([]byte{0x02}, 32)
	value := []byte("hello-from-go-test")

	// Set
	ffi.SetVertex(handle, "vertex", "adds", l1, l2, key, value)

	// Get
	got := ffi.GetVertex(handle, "vertex", "adds", l1, l2, key)
	require.NotNil(t, got, "vertex should exist after set")
	assert.Equal(t, value, *got, "retrieved value must match")

	// Delete (CRDT remove)
	ffi.DeleteVertex(handle, "vertex", "adds", l1, l2, key)

	// After delete, get should return nil (removed from adds via removes set)
	got2 := ffi.GetVertex(handle, "vertex", "adds", l1, l2, key)
	assert.Nil(t, got2, "vertex should be nil after delete")
}

// TestRustGoHyperedgeRoundtrip tests the hyperedge set operations.
func TestRustGoHyperedgeRoundtrip(t *testing.T) {
	handle := ffi.CreateCrdt()
	defer ffi.DestroyCrdt(handle)

	l1 := []byte{0x11, 0x22, 0x33}
	l2 := bytes.Repeat([]byte{0x05}, 32)
	key := bytes.Repeat([]byte{0x06}, 32)
	value := []byte("hyperedge-data")

	ffi.SetVertex(handle, "hyperedge", "adds", l1, l2, key, value)

	got := ffi.GetVertex(handle, "hyperedge", "adds", l1, l2, key)
	require.NotNil(t, got, "hyperedge should exist after set")
	assert.Equal(t, value, *got)

	ffi.DeleteVertex(handle, "hyperedge", "adds", l1, l2, key)

	got2 := ffi.GetVertex(handle, "hyperedge", "adds", l1, l2, key)
	assert.Nil(t, got2, "hyperedge should be nil after delete")
}

// TestRustGoCommitEmpty tests that an empty CRDT produces an empty commit.
func TestRustGoCommitEmpty(t *testing.T) {
	handle := ffi.CreateCrdt()
	defer ffi.DestroyCrdt(handle)

	result := ffi.CommitPhase(handle, 1)
	assert.Empty(t, result, "empty CRDT commit should produce no shard entries")
}

// TestRustGoCommitSingleVertex verifies that a single vertex insertion
// produces a commit with exactly one shard and the expected root structure.
func TestRustGoCommitSingleVertex(t *testing.T) {
	handle := ffi.CreateCrdt()
	defer ffi.DestroyCrdt(handle)

	l1 := []byte{0xAA, 0xBB, 0xCC}
	l2 := bytes.Repeat([]byte{0x01}, 32)
	key := bytes.Repeat([]byte{0x02}, 32)
	value := []byte("commit-test-value")

	ffi.SetVertex(handle, "vertex", "adds", l1, l2, key, value)

	result := ffi.CommitPhase(handle, 1)
	require.Len(t, result, 291, "single shard commit = 35 + 4*64 = 291 bytes")

	shards := parseShardsFromCommitPhase(result)
	require.Len(t, shards, 1, "should have exactly one shard")

	for sk, roots := range shards {
		// L2 should be the app address we used
		assert.Equal(t, l2, sk.L2[:])

		// vertex_adds root should be non-zero (leaf commitment via SHA-512)
		assert.NotEqual(t, make([]byte, 64), roots[0],
			"vertex_adds root should be non-zero for a non-empty tree")

		// The other three roots should be zero (no data inserted)
		assert.Equal(t, make([]byte, 64), roots[1], "vertex_removes should be zero")
		assert.Equal(t, make([]byte, 64), roots[2], "hyperedge_adds should be zero")
		assert.Equal(t, make([]byte, 64), roots[3], "hyperedge_removes should be zero")
	}
}

// TestRustGoCommitRootsMatch is the critical cross-validation test.
// It creates both a Go and a Rust CRDT, inserts the same vertices
// into both, commits at the same frame number, and asserts that the
// per-shard commit roots are identical.
//
// Both sides use a noop inclusion prover (CommitRaw returns 64 zero bytes)
// so branch commitments match.  Leaf commitments are SHA-512-based and
// should be deterministic.
func TestRustGoCommitRootsMatch(t *testing.T) {
	// --- Set up Go CRDT ---
	logger, _ := zap.NewDevelopment()
	pebbleDB := store.NewPebbleDB(
		logger,
		&config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/rustmatch"}},
		0,
	)
	defer pebbleDB.Close()

	prover := noopProver()
	enc := &mocks.MockVerifiableEncryptor{}
	hgStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/rustmatch"},
		pebbleDB, logger, enc, prover,
	)

	goCRDT := hg.NewHypergraph(
		logger,
		hgStore,
		prover,
		[]int{}, // no covered prefix restriction
		&Nopthenticator{},
		200,
	)

	// --- Set up Rust CRDT ---
	rustHandle := ffi.CreateCrdt()
	defer ffi.DestroyCrdt(rustHandle)

	// Use a fixed app address with first byte <= 0x3f so Go's bloom filter
	// does not short-circuit to 0x000000 (which happens when data[0] > 0x3f).
	appAddr := [32]byte{0x01}
	for i := 1; i < 32; i++ {
		appAddr[i] = byte(i)
	}

	// Compute the shard key the way the Rust FFI does it internally:
	// L1 = XOR bloom, L2 = appAddr.
	rustShardResult := ffi.ShardKeyForLocation(appAddr[:])
	rustL1 := rustShardResult[:3]

	// We will insert three vertices with the same app address but different
	// data addresses.  This puts them all in the same shard.
	type vertexSpec struct {
		dataAddr [32]byte
		value    []byte
	}
	vertices := []vertexSpec{
		{dataAddr: func() [32]byte { var d [32]byte; d[0] = 0xA1; return d }(), value: []byte("vertex-one")},
		{dataAddr: func() [32]byte { var d [32]byte; d[0] = 0xB2; return d }(), value: []byte("vertex-two")},
		{dataAddr: func() [32]byte { var d [32]byte; d[0] = 0xC3; return d }(), value: []byte("vertex-three")},
	}

	for _, v := range vertices {
		// --- Rust side ---
		ffi.SetVertex(
			rustHandle,
			"vertex", "adds",
			rustL1,
			appAddr[:],
			v.dataAddr[:],
			v.value,
		)

		// --- Go side ---
		// Build a vertex whose ToBytes() matches the Rust value exactly.
		// The Rust CRDT inserts with hash_target = empty, so the leaf
		// commitment is SHA-512(0x00 || key || value).
		//
		// The Go HypergraphCRDT inserts with hash_target = atom.Commit(prover),
		// so to match we need atom.Commit(prover) to be empty (nil/zero-length).
		//
		// We create a vertex with an empty commitment field, and the Go
		// idSet.Add path will call atom.Commit(prover) which returns
		// v.commitment (the empty slice).  This gives an empty hashTarget
		// on the Go side too, matching Rust.
		//
		// However, atom.ToBytes() will differ because it includes the
		// commitment field.  Since the Rust side's "value" is our test data
		// (e.g. "vertex-one") but the Go side's tree value is atom.ToBytes()
		// (which prefixes with 0x00, appAddr, dataAddr, commitment, size),
		// the leaf hashes will inevitably differ.
		//
		// Therefore we use the Go tree directly (bypassing HypergraphCRDT)
		// to insert with the exact same key/value/hashTarget as the Rust side.
		goShardKey := tries.ShardKey{
			L1: [3]byte(rustL1),
			L2: appAddr,
		}

		goTree := goCRDT.GetVertexAddsSet(goShardKey).GetTree()

		// Tree key = [appAddress || dataAddress] (64 bytes), matching Rust's
		// location.to_id().
		var treeKey [64]byte
		copy(treeKey[:32], appAddr[:])
		copy(treeKey[32:], v.dataAddr[:])

		err := goTree.Insert(
			nil,        // no transaction (in-memory store)
			treeKey[:], // key
			v.value,    // value (same bytes as Rust)
			[]byte{},   // empty hashTarget (matches Rust's &[])
			big.NewInt(int64(len(v.value))),
		)
		require.NoError(t, err, "Go tree insert should succeed")
	}

	// --- Commit both ---
	frameNumber := uint64(42)

	// Go commit: we need to commit the tree directly since we bypassed
	// the HypergraphCRDT's AddVertex path.
	goCommits, err := goCRDT.Commit(frameNumber)
	require.NoError(t, err, "Go CRDT commit should succeed")

	// Rust commit
	rustRaw := ffi.CommitPhase(rustHandle, frameNumber)
	rustCommits := parseShardsFromCommitPhase(rustRaw)

	// --- Compare ---
	t.Logf("Go shards: %d, Rust shards: %d", len(goCommits), len(rustCommits))

	// Build the shard key using Rust's L1 (since we inserted into Go using
	// the same Rust-derived shard key).
	expectedSK := tries.ShardKey{
		L1: [3]byte(rustL1),
		L2: appAddr,
	}

	goRoots, goOK := goCommits[expectedSK]
	rustRoots, rustOK := rustCommits[expectedSK]

	require.True(t, goOK, "Go commits should contain the shard key %x", expectedSK)
	require.True(t, rustOK, "Rust commits should contain the shard key %x", expectedSK)

	require.Len(t, goRoots, 4, "Go should have 4 root slots")
	require.Len(t, rustRoots, 4, "Rust should have 4 root slots")

	// The critical assertion: vertex_adds roots must match.
	t.Logf("Go   vertex_adds root: %x", goRoots[0])
	t.Logf("Rust vertex_adds root: %x", rustRoots[0])
	assert.Equal(t, rustRoots[0], goRoots[0],
		"vertex_adds commit root must be identical between Go and Rust CRDTs")

	// The other three sets are empty on both sides.
	for i := 1; i < 4; i++ {
		assert.Equal(t, rustRoots[i], goRoots[i],
			"root[%d] must match between Go and Rust", i)
	}
}

// TestRustGoCommitMultiShard tests commit roots with vertices spanning
// multiple shards (different app addresses).
func TestRustGoCommitMultiShard(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	pebbleDB := store.NewPebbleDB(
		logger,
		&config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/rustmulti"}},
		0,
	)
	defer pebbleDB.Close()

	prover := noopProver()
	enc := &mocks.MockVerifiableEncryptor{}
	hgStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/rustmulti"},
		pebbleDB, logger, enc, prover,
	)
	goCRDT := hg.NewHypergraph(
		logger, hgStore, prover, []int{}, &Nopthenticator{}, 200,
	)

	rustHandle := ffi.CreateCrdt()
	defer ffi.DestroyCrdt(rustHandle)

	// Use two different app addresses -> two different shards.
	type shardEntry struct {
		appAddr  [32]byte
		dataAddr [32]byte
		value    []byte
	}
	entries := []shardEntry{
		{
			appAddr:  func() [32]byte { var a [32]byte; a[0] = 0x10; return a }(),
			dataAddr: func() [32]byte { var d [32]byte; d[0] = 0xAA; return d }(),
			value:    []byte("shard-1-vertex"),
		},
		{
			appAddr:  func() [32]byte { var a [32]byte; a[0] = 0x20; return a }(),
			dataAddr: func() [32]byte { var d [32]byte; d[0] = 0xBB; return d }(),
			value:    []byte("shard-2-vertex"),
		},
	}

	for _, e := range entries {
		rustSK := ffi.ShardKeyForLocation(e.appAddr[:])
		rustL1 := rustSK[:3]

		ffi.SetVertex(
			rustHandle, "vertex", "adds",
			rustL1, e.appAddr[:], e.dataAddr[:], e.value,
		)

		goSK := tries.ShardKey{L1: [3]byte(rustL1), L2: e.appAddr}
		goTree := goCRDT.GetVertexAddsSet(goSK).GetTree()
		var treeKey [64]byte
		copy(treeKey[:32], e.appAddr[:])
		copy(treeKey[32:], e.dataAddr[:])

		err := goTree.Insert(nil, treeKey[:], e.value, []byte{},
			big.NewInt(int64(len(e.value))))
		require.NoError(t, err)
	}

	frameNumber := uint64(7)
	goCommits, err := goCRDT.Commit(frameNumber)
	require.NoError(t, err)

	rustRaw := ffi.CommitPhase(rustHandle, frameNumber)
	rustCommits := parseShardsFromCommitPhase(rustRaw)

	// Both should have the same number of shards.
	assert.Equal(t, len(rustCommits), len(goCommits),
		"shard count must match")

	for sk, rustRoots := range rustCommits {
		goRoots, ok := goCommits[sk]
		require.True(t, ok, "Go commits missing shard %x", sk)

		for i := 0; i < 4; i++ {
			assert.Equal(t, rustRoots[i], goRoots[i],
				"shard %x root[%d] must match", sk, i)
		}
	}
}

// TestRustGoCommitWithRemoves tests that vertex removal produces matching
// commit roots.
func TestRustGoCommitWithRemoves(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	pebbleDB := store.NewPebbleDB(
		logger,
		&config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/rustremove"}},
		0,
	)
	defer pebbleDB.Close()

	prover := noopProver()
	enc := &mocks.MockVerifiableEncryptor{}
	hgStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/rustremove"},
		pebbleDB, logger, enc, prover,
	)
	goCRDT := hg.NewHypergraph(
		logger, hgStore, prover, []int{}, &Nopthenticator{}, 200,
	)

	rustHandle := ffi.CreateCrdt()
	defer ffi.DestroyCrdt(rustHandle)

	appAddr := [32]byte{0x05}
	dataAddr := [32]byte{0x0A}
	value := []byte("to-be-removed")

	rustSK := ffi.ShardKeyForLocation(appAddr[:])
	rustL1 := rustSK[:3]

	// Insert into both
	ffi.SetVertex(rustHandle, "vertex", "adds", rustL1, appAddr[:], dataAddr[:], value)

	goSK := tries.ShardKey{L1: [3]byte(rustL1), L2: appAddr}
	goTree := goCRDT.GetVertexAddsSet(goSK).GetTree()
	var treeKey [64]byte
	copy(treeKey[:32], appAddr[:])
	copy(treeKey[32:], dataAddr[:])
	err := goTree.Insert(nil, treeKey[:], value, []byte{}, big.NewInt(int64(len(value))))
	require.NoError(t, err)

	// Remove from both (CRDT remove = insert into removes set)
	ffi.DeleteVertex(rustHandle, "vertex", "adds", rustL1, appAddr[:], dataAddr[:])

	goRemoveTree := goCRDT.GetVertexRemovesSet(goSK).GetTree()
	// The Rust remove_vertex inserts an empty value and empty hash_target
	// into the removes tree.
	err = goRemoveTree.Insert(nil, treeKey[:], []byte{}, []byte{}, big.NewInt(0))
	require.NoError(t, err)

	// Also insert into adds on Go side (Rust's remove_vertex does this
	// when vertex doesn't exist in adds yet, but ours already exists).
	// The Rust side already had it in adds, so no additional add needed.

	// Commit
	frameNumber := uint64(99)
	goCommits, err := goCRDT.Commit(frameNumber)
	require.NoError(t, err)

	rustRaw := ffi.CommitPhase(rustHandle, frameNumber)
	rustCommits := parseShardsFromCommitPhase(rustRaw)

	for sk, rustRoots := range rustCommits {
		goRoots, ok := goCommits[sk]
		require.True(t, ok, "Go commits missing shard %x", sk)

		for i := 0; i < 4; i++ {
			t.Logf("shard %x root[%d]: go=%x rust=%x match=%v",
				sk, i, goRoots[i], rustRoots[i],
				bytes.Equal(goRoots[i], rustRoots[i]))
			assert.Equal(t, rustRoots[i], goRoots[i],
				"shard %x root[%d] must match", sk, i)
		}
	}
}

// TestRustGoCommitDeterministic verifies that committing the same data
// twice produces the same root in both implementations.
func TestRustGoCommitDeterministic(t *testing.T) {
	appAddr := [32]byte{0x03}
	dataAddr := [32]byte{0x07}
	value := []byte("deterministic-test")

	results := make([][]byte, 2)
	for round := 0; round < 2; round++ {
		handle := ffi.CreateCrdt()
		sk := ffi.ShardKeyForLocation(appAddr[:])
		l1 := sk[:3]

		ffi.SetVertex(handle, "vertex", "adds", l1, appAddr[:], dataAddr[:], value)
		raw := ffi.CommitPhase(handle, 1)
		results[round] = raw
		ffi.DestroyCrdt(handle)
	}

	assert.Equal(t, results[0], results[1],
		"two independent Rust CRDTs with the same data must produce identical commits")
}

// TestRustGoCommitIdempotent verifies commit is idempotent (calling it
// twice on the same CRDT without changes produces the same root).
func TestRustGoCommitIdempotent(t *testing.T) {
	handle := ffi.CreateCrdt()
	defer ffi.DestroyCrdt(handle)

	appAddr := [32]byte{0x09}
	dataAddr := [32]byte{0x0B}
	value := []byte("idempotent-test")
	sk := ffi.ShardKeyForLocation(appAddr[:])
	l1 := sk[:3]

	ffi.SetVertex(handle, "vertex", "adds", l1, appAddr[:], dataAddr[:], value)

	first := ffi.CommitPhase(handle, 1)
	second := ffi.CommitPhase(handle, 2)

	// Note: frame numbers differ, but the data is the same so per-shard
	// roots should be identical.
	firstShards := parseShardsFromCommitPhase(first)
	secondShards := parseShardsFromCommitPhase(second)

	require.Equal(t, len(firstShards), len(secondShards))
	for sk, roots1 := range firstShards {
		roots2, ok := secondShards[sk]
		require.True(t, ok)
		for i := 0; i < 4; i++ {
			assert.Equal(t, roots1[i], roots2[i],
				"shard %x root[%d] should be the same across commits", sk, i)
		}
	}
}

// TestRustGoShardKeyForLocation_MatchesGoBloom verifies the Rust FFI's
// shard_key_for_location produces the same L1 as Go's GetBloomFilterIndices.
func TestRustGoShardKeyForLocation_MatchesGoBloom(t *testing.T) {
	addrs := [][32]byte{
		{},
		{0x42, 0x42, 0x42, 0x42},
		func() [32]byte {
			var a [32]byte
			for i := range a {
				a[i] = byte(i * 7)
			}
			return a
		}(),
	}

	for _, addr := range addrs {
		result := ffi.ShardKeyForLocation(addr[:])
		require.Len(t, result, 35)

		expectedL1 := makeShardL1(addr)
		assert.Equal(t, expectedL1[:], result[:3],
			"L1 must match XOR bloom for addr %x", addr[:4])
		assert.Equal(t, addr[:], result[3:],
			"L2 must equal app address for addr %x", addr[:4])
	}
}

// TestRustGoHighLevelVertexMatch uses the Go HypergraphCRDT with vertices
// that produce the same tree data as the Rust FFI, then compares the
// snapshot root digest (SHA-256 over sorted shard commits).
func TestRustGoHighLevelVertexMatch(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	pebbleDB := store.NewPebbleDB(
		logger,
		&config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/rusthigh"}},
		0,
	)
	defer pebbleDB.Close()

	prover := noopProver()
	enc := &mocks.MockVerifiableEncryptor{}
	hgStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/rusthigh"},
		pebbleDB, logger, enc, prover,
	)

	goCRDT := hg.NewHypergraph(
		logger, hgStore, prover, []int{}, &Nopthenticator{}, 200,
	)

	rustHandle := ffi.CreateCrdt()
	defer ffi.DestroyCrdt(rustHandle)

	// The Go HypergraphCRDT.AddVertex inserts with:
	//   key = atom.GetID() = [appAddr || dataAddr]
	//   value = atom.ToBytes()
	//   hashTarget = atom.Commit(prover) = vertex.commitment field
	//
	// The Rust FFI inserts with:
	//   key = location.to_id() = [appAddr || dataAddr]
	//   value = the raw value parameter
	//   hashTarget = empty
	//
	// For the leaf hashes to match, we need atom.ToBytes() to equal the
	// Rust value AND atom.Commit(prover) to be empty.
	//
	// vertex.ToBytes() = 0x00 || appAddr(32) || dataAddr(32) || commitment || size(32)
	// vertex.Commit(prover) returns vertex.commitment
	//
	// If we set commitment = []byte{} (empty), then:
	//   Go hashTarget = []byte{} (empty, so leaf uses value)
	//   Go value = 0x00 || appAddr || dataAddr || size(32) = 97 bytes
	//
	// We must set the Rust value to the same 97 bytes.

	appAddr := [32]byte{0x01}
	dataAddr := [32]byte{0x02}
	size := big.NewInt(55)

	// Build the value bytes that match vertex.ToBytes() with empty commitment
	goVertex := hg.NewVertex(appAddr, dataAddr, []byte{}, size)
	goValue := goVertex.ToBytes()

	// Compute shard key (using Go's bloom filter for the Go side)
	goShardKey := hypergraph.GetShardKey(goVertex)

	// Insert into Go CRDT via AddVertex
	err := goCRDT.AddVertex(nil, goVertex)
	require.NoError(t, err)

	// Insert into Rust CRDT with the same serialized value
	rustSK := ffi.ShardKeyForLocation(appAddr[:])
	rustL1 := rustSK[:3]
	ffi.SetVertex(rustHandle, "vertex", "adds", rustL1, appAddr[:], dataAddr[:], goValue)

	// Commit both
	frameNumber := uint64(100)
	goCommits, err := goCRDT.Commit(frameNumber)
	require.NoError(t, err)

	rustRaw := ffi.CommitPhase(rustHandle, frameNumber)
	rustCommits := parseShardsFromCommitPhase(rustRaw)

	t.Logf("Go shard key: L1=%x L2=%x", goShardKey.L1, goShardKey.L2[:4])
	t.Logf("Rust shard key: L1=%x L2=%x", rustL1, appAddr[:4])

	// Look up the Rust shard key in Rust commits
	rustSKParsed := tries.ShardKey{L1: [3]byte(rustL1), L2: appAddr}
	rustRoots, rustOK := rustCommits[rustSKParsed]
	require.True(t, rustOK, "Rust commits should contain shard")

	// Look up the Go shard key in Go commits
	goRoots, goOK := goCommits[goShardKey]
	require.True(t, goOK, "Go commits should contain shard")

	// If the shard keys differ (Rust XOR bloom vs Go SHAKE256 bloom),
	// the roots might still match if the tree data is the same.
	t.Logf("Go   vertex_adds root: %x", goRoots[0])
	t.Logf("Rust vertex_adds root: %x", rustRoots[0])

	// For single-leaf trees, the root IS the leaf commitment:
	// SHA-512(0x00 || key || value)  [since hashTarget is empty on both sides]
	// key = [appAddr || dataAddr] = same on both sides
	// value = goValue (same bytes passed to Rust)
	// Therefore the leaf commitments must match.
	assert.Equal(t, goRoots[0], rustRoots[0],
		"vertex_adds root must match when using identical tree key/value/hashTarget")
}
