package provers

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"slices"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/config"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

type mockIterator struct {
	nextCalled bool
	empty      bool
}

// Close implements tries.VertexDataIterator.
func (m *mockIterator) Close() error {
	return nil
}

// First implements tries.VertexDataIterator.
func (m *mockIterator) First() bool {
	return !m.empty
}

// Key implements tries.VertexDataIterator.
func (m *mockIterator) Key() []byte {
	return bytes.Repeat([]byte{0x11}, 32)
}

// Last implements tries.VertexDataIterator.
func (m *mockIterator) Last() bool {
	return false
}

// Next implements tries.VertexDataIterator.
func (m *mockIterator) Next() bool {
	if !m.nextCalled {
		m.nextCalled = true
		return true
	}
	return false
}

// Prev implements tries.VertexDataIterator.
func (m *mockIterator) Prev() bool {
	return false
}

// Valid implements tries.VertexDataIterator.
func (m *mockIterator) Valid() bool {
	return !m.nextCalled && !m.empty
}

// Value implements tries.VertexDataIterator.
func (m *mockIterator) Value() *tries.VectorCommitmentTree {
	trie := &tries.VectorCommitmentTree{}
	trie.Insert([]byte{0}, make([]byte, 585), nil, big.NewInt(585))
	trie.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(1))
	trie.Insert([]byte{2 << 2}, []byte{1, 1, 1, 1, 1, 1, 1, 1}, nil, big.NewInt(8))
	trie.Insert([]byte{3 << 2}, []byte{1, 1, 1, 1, 1, 1, 1, 1}, nil, big.NewInt(8))
	trie.Insert([]byte{4 << 2}, bytes.Repeat([]byte{1}, 32), nil, big.NewInt(32))
	trie.Insert([]byte{5 << 2}, []byte{1, 1, 1, 1, 1, 1, 1, 1}, nil, big.NewInt(8))
	typeBI, _ := poseidon.HashBytes(
		slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("prover:Prover")),
	)
	typeBytes := typeBI.FillBytes(make([]byte, 32))
	trie.Insert(bytes.Repeat([]byte{0xff}, 32), typeBytes, nil, big.NewInt(32))
	return trie
}

var _ tries.VertexDataIterator = (*mockIterator)(nil)

func TestProverRegistry(t *testing.T) {
	t.Run("GetProverInfo returns nil for non-existent prover", func(t *testing.T) {
		mockIP := new(mocks.MockInclusionProver)
		mockHG := tests.CreateHypergraphWithInclusionProver(mockIP)
		mockHG.On("GetVertexDataIterator", mock.Anything).Return(&mockIterator{empty: true}, nil)
		registry, err := NewProverRegistry(zap.NewNop(), mockHG)
		require.NoError(t, err)
		info, err := registry.GetProverInfo([]byte("non-existent"))
		require.NoError(t, err)
		assert.Nil(t, info)
	})

	t.Run("GetActiveProvers returns empty for no provers", func(t *testing.T) {
		mockIP := new(mocks.MockInclusionProver)
		mockHG := tests.CreateHypergraphWithInclusionProver(mockIP)
		mockHG.On("GetVertexDataIterator", mock.Anything).Return(&mockIterator{empty: true}, nil)
		registry, err := NewProverRegistry(zap.NewNop(), mockHG)
		require.NoError(t, err)
		provers, err := registry.GetActiveProvers(nil)
		require.NoError(t, err)
		assert.Empty(t, provers)
	})

	t.Run("GetProverCount returns 0 for empty registry", func(t *testing.T) {
		mockIP := new(mocks.MockInclusionProver)
		mockHG := tests.CreateHypergraphWithInclusionProver(mockIP)
		mockHG.On("GetVertexDataIterator", mock.Anything).Return(&mockIterator{empty: true}, nil)
		registry, err := NewProverRegistry(zap.NewNop(), mockHG)
		require.NoError(t, err)
		count, err := registry.GetProverCount(nil)
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})

	t.Run("GetNextProver returns error for empty trie", func(t *testing.T) {
		mockIP := new(mocks.MockInclusionProver)
		mockHG := tests.CreateHypergraphWithInclusionProver(mockIP)
		mockHG.On("GetVertexDataIterator", mock.Anything).Return(&mockIterator{empty: true}, nil)
		registry, err := NewProverRegistry(zap.NewNop(), mockHG)
		require.NoError(t, err)
		input := [32]byte{1, 2, 3}
		next, err := registry.GetNextProver(input, nil)
		require.Error(t, err)
		assert.Nil(t, next)
	})

	t.Run("UpdateProverActivity succeeds even for non-existent prover", func(t *testing.T) {
		mockIP := new(mocks.MockInclusionProver)
		mockHG := tests.CreateHypergraphWithInclusionProver(mockIP)
		mockHG.On("GetVertexDataIterator", mock.Anything).Return(&mockIterator{empty: true}, nil)
		registry, err := NewProverRegistry(zap.NewNop(), mockHG)
		require.NoError(t, err)
		err = registry.UpdateProverActivity([]byte("non-existent"), nil, 100)
		require.NoError(t, err)
	})

	t.Run("GetProversByStatus returns empty for no provers", func(t *testing.T) {
		mockIP := new(mocks.MockInclusionProver)
		mockHG := tests.CreateHypergraphWithInclusionProver(mockIP)
		mockHG.On("GetVertexDataIterator", mock.Anything).Return(&mockIterator{empty: true}, nil)
		registry, err := NewProverRegistry(zap.NewNop(), mockHG)
		require.NoError(t, err)
		provers, err := registry.GetProversByStatus(nil, consensus.ProverStatusActive)
		require.NoError(t, err)
		assert.Empty(t, provers)
	})
}

func TestProverRegistryWithShards(t *testing.T) {
	mockIP := new(mocks.MockInclusionProver)
	mockHG := tests.CreateHypergraphWithInclusionProver(mockIP)

	mockHG.On("GetVertexDataIterator", mock.Anything).Return(&mockIterator{}, nil)
	registry, err := NewProverRegistry(zap.NewNop(), mockHG)
	require.NoError(t, err)

	shard1 := []byte("shard1")
	shard2 := []byte("shard2")

	t.Run("GetActiveProvers returns empty for non-existent shard", func(t *testing.T) {
		provers, err := registry.GetActiveProvers(shard1)
		require.NoError(t, err)
		assert.Empty(t, provers)
	})

	t.Run("GetProverCount returns 0 for non-existent shard", func(t *testing.T) {
		count, err := registry.GetProverCount(shard2)
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})
}

// TestPruneOrphanJoins_Comprehensive tests the pruning of orphan prover joins
// with a comprehensive scenario covering global provers, app shard provers,
// and mixed allocation states.
func TestPruneOrphanJoins_Comprehensive(t *testing.T) {
	logger := zap.NewNop()

	// Create stores with in-memory pebble DB
	pebbleDB := store.NewPebbleDB(
		logger,
		&config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/prune_orphan"}},
		0,
	)
	defer pebbleDB.Close()

	// Create inclusion prover and verifiable encryptor
	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)

	// Create hypergraph store and hypergraph
	hypergraphStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/prune_orphan"},
		pebbleDB,
		logger,
		verifiableEncryptor,
		inclusionProver,
	)
	hg, err := hypergraphStore.LoadHypergraph(&tests.Nopthenticator{}, 1)
	require.NoError(t, err)

	// Create RDF multiprover for setting up test data
	rdfMultiprover := schema.NewRDFMultiprover(
		&schema.TurtleRDFParser{},
		inclusionProver,
	)

	// Current frame for testing - pruning will use cutoff = currentFrame - 760
	// For currentFrame=1000, cutoff = 240
	// Allocations with JoinFrameNumber < 240 will be pruned
	const currentFrame = uint64(1000)
	const oldJoinFrame = uint64(100)          // 100 < 240, will be pruned
	const recentJoinFrame = currentFrame - 10 // 990 > 240, will NOT be pruned

	type allocationSpec struct {
		filter    []byte
		joinFrame uint64
		status    byte // 0=Joining, 1=Active
	}

	// Helper to create a prover with specific allocations
	createProverWithAllocations := func(
		publicKey []byte,
		proverStatus byte,
		allocations []allocationSpec,
	) ([]byte, error) {
		proverAddressBI, err := poseidon.HashBytes(publicKey)
		if err != nil {
			return nil, err
		}
		proverAddress := proverAddressBI.FillBytes(make([]byte, 32))

		hgCRDT := hg.(*hgcrdt.HypergraphCRDT)
		txn, err := hgCRDT.NewTransaction(false)
		if err != nil {
			return nil, err
		}

		// Create prover vertex
		proverTree := &tries.VectorCommitmentTree{}
		err = rdfMultiprover.Set(
			global.GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"prover:Prover",
			"PublicKey",
			publicKey,
			proverTree,
		)
		if err != nil {
			txn.Abort()
			return nil, err
		}

		err = rdfMultiprover.Set(
			global.GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"prover:Prover",
			"Status",
			[]byte{proverStatus},
			proverTree,
		)
		if err != nil {
			txn.Abort()
			return nil, err
		}

		availableStorageBytes := make([]byte, 8)
		err = rdfMultiprover.Set(
			global.GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"prover:Prover",
			"AvailableStorage",
			availableStorageBytes,
			proverTree,
		)
		if err != nil {
			txn.Abort()
			return nil, err
		}

		seniorityBytes := make([]byte, 8)
		err = rdfMultiprover.Set(
			global.GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"prover:Prover",
			"Seniority",
			seniorityBytes,
			proverTree,
		)
		if err != nil {
			txn.Abort()
			return nil, err
		}

		// Add prover vertex to hypergraph
		proverVertex := hgcrdt.NewVertex(
			intrinsics.GLOBAL_INTRINSIC_ADDRESS,
			[32]byte(proverAddress),
			proverTree.Commit(inclusionProver, false),
			big.NewInt(0),
		)
		err = hg.AddVertex(txn, proverVertex)
		if err != nil {
			txn.Abort()
			return nil, err
		}

		// Save prover vertex data
		var proverVertexID [64]byte
		copy(proverVertexID[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(proverVertexID[32:], proverAddress)
		err = hg.SetVertexData(txn, proverVertexID, proverTree)
		if err != nil {
			txn.Abort()
			return nil, err
		}

		// Create hyperedge for prover
		hyperedge := hgcrdt.NewHyperedge(
			intrinsics.GLOBAL_INTRINSIC_ADDRESS,
			[32]byte(proverAddress),
		)

		// Create allocation vertices for each allocation spec
		for _, alloc := range allocations {
			allocationAddressBI, err := poseidon.HashBytes(
				slices.Concat([]byte("PROVER_ALLOCATION"), publicKey, alloc.filter),
			)
			if err != nil {
				txn.Abort()
				return nil, err
			}
			allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))

			allocationTree := &tries.VectorCommitmentTree{}
			err = rdfMultiprover.Set(
				global.GLOBAL_RDF_SCHEMA,
				intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
				"allocation:ProverAllocation",
				"Prover",
				proverAddress,
				allocationTree,
			)
			if err != nil {
				txn.Abort()
				return nil, err
			}

			err = rdfMultiprover.Set(
				global.GLOBAL_RDF_SCHEMA,
				intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
				"allocation:ProverAllocation",
				"Status",
				[]byte{alloc.status},
				allocationTree,
			)
			if err != nil {
				txn.Abort()
				return nil, err
			}

			err = rdfMultiprover.Set(
				global.GLOBAL_RDF_SCHEMA,
				intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
				"allocation:ProverAllocation",
				"ConfirmationFilter",
				alloc.filter,
				allocationTree,
			)
			if err != nil {
				txn.Abort()
				return nil, err
			}

			frameNumberBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(frameNumberBytes, alloc.joinFrame)
			err = rdfMultiprover.Set(
				global.GLOBAL_RDF_SCHEMA,
				intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
				"allocation:ProverAllocation",
				"JoinFrameNumber",
				frameNumberBytes,
				allocationTree,
			)
			if err != nil {
				txn.Abort()
				return nil, err
			}

			// Add allocation vertex
			allocationVertex := hgcrdt.NewVertex(
				intrinsics.GLOBAL_INTRINSIC_ADDRESS,
				[32]byte(allocationAddress),
				allocationTree.Commit(inclusionProver, false),
				big.NewInt(0),
			)
			err = hg.AddVertex(txn, allocationVertex)
			if err != nil {
				txn.Abort()
				return nil, err
			}

			// Save allocation vertex data
			var allocationVertexID [64]byte
			copy(allocationVertexID[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
			copy(allocationVertexID[32:], allocationAddress)
			err = hg.SetVertexData(txn, allocationVertexID, allocationTree)
			if err != nil {
				txn.Abort()
				return nil, err
			}

			// Add allocation to hyperedge
			hyperedge.AddExtrinsic(allocationVertex)
		}

		// Add hyperedge
		err = hg.AddHyperedge(txn, hyperedge)
		if err != nil {
			txn.Abort()
			return nil, err
		}

		err = txn.Commit()
		if err != nil {
			return nil, err
		}

		return proverAddress, nil
	}

	// Helper to check if vertex exists
	vertexExists := func(vertexID [64]byte) bool {
		_, err := hg.GetVertex(vertexID)
		return err == nil
	}

	// Helper to check if vertex data exists
	vertexDataExists := func(vertexID [64]byte) bool {
		data, err := hg.GetVertexData(vertexID)
		return err == nil && data != nil
	}

	// Helper to check if hyperedge exists
	hyperedgeExists := func(hyperedgeID [64]byte) bool {
		_, err := hg.GetHyperedge(hyperedgeID)
		return err == nil
	}

	// Helper to compute prover vertex ID
	getProverVertexID := func(proverAddress []byte) [64]byte {
		var id [64]byte
		copy(id[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(id[32:], proverAddress)
		return id
	}

	// Helper to compute allocation vertex ID
	getAllocationVertexID := func(publicKey, filter []byte) [64]byte {
		allocationHash, _ := poseidon.HashBytes(
			slices.Concat([]byte("PROVER_ALLOCATION"), publicKey, filter),
		)
		var id [64]byte
		copy(id[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(id[32:], allocationHash.FillBytes(make([]byte, 32)))
		return id
	}

	// ===== CREATE TEST DATA =====

	// 1. Create 6 global provers with single allocation each, filter=nil, status=active
	globalProverAddrs := make([][]byte, 6)
	globalProverKeys := make([][]byte, 6)
	for i := 0; i < 6; i++ {
		publicKey := bytes.Repeat([]byte{byte(0x10 + i)}, 585)
		globalProverKeys[i] = publicKey

		proverAddr, err := createProverWithAllocations(
			publicKey,
			1, // Active prover status
			[]allocationSpec{
				{filter: nil, joinFrame: recentJoinFrame, status: 1}, // Active global allocation
			},
		)
		require.NoError(t, err)
		globalProverAddrs[i] = proverAddr
		t.Logf("Created global prover %d at address: %s",
			i, hex.EncodeToString(proverAddr))
	}

	// 2. Create 5 app shard provers with 100 allocations each, ALL with old join frame
	// These should be completely pruned (prover and all allocations)
	allOldProverAddrs := make([][]byte, 5)
	allOldProverKeys := make([][]byte, 5)
	allOldFilters := make([][][]byte, 5) // Store filters for each prover
	for i := 0; i < 5; i++ {
		publicKey := bytes.Repeat([]byte{byte(0x20 + i)}, 585)
		allOldProverKeys[i] = publicKey

		allocations := make([]allocationSpec, 100)
		filters := make([][]byte, 100)
		for j := 0; j < 100; j++ {
			filter := []byte(fmt.Sprintf("shard_%d_%d", i, j))
			filters[j] = filter
			allocations[j] = allocationSpec{
				filter:    filter,
				joinFrame: oldJoinFrame, // All old - will be pruned
				status:    0,            // Joining
			}
		}
		allOldFilters[i] = filters

		proverAddr, err := createProverWithAllocations(
			publicKey,
			0, // Joining prover status
			allocations,
		)
		require.NoError(t, err)
		allOldProverAddrs[i] = proverAddr
		t.Logf("Created all-old app shard prover %d at address: %s",
			i, hex.EncodeToString(proverAddr))
	}

	// 3. Create 5 app shard provers with 100 allocations each:
	//    - 50 with old join frame (will be pruned)
	//    - 50 with recent join frame (will remain)
	// Prover should remain but with only 50 allocations
	mixedProverAddrs := make([][]byte, 5)
	mixedProverKeys := make([][]byte, 5)
	mixedOldFilters := make([][][]byte, 5) // Old filters that should be pruned
	mixedNewFilters := make([][][]byte, 5) // Recent filters that should remain
	for i := 0; i < 5; i++ {
		publicKey := bytes.Repeat([]byte{byte(0x30 + i)}, 585)
		mixedProverKeys[i] = publicKey

		allocations := make([]allocationSpec, 100)
		oldFilters := make([][]byte, 50)
		newFilters := make([][]byte, 50)

		for j := 0; j < 100; j++ {
			filter := []byte(fmt.Sprintf("mixed_shard_%d_%d", i, j))
			if j < 50 {
				// First 50: old join frame - will be pruned
				oldFilters[j] = filter
				allocations[j] = allocationSpec{
					filter:    filter,
					joinFrame: oldJoinFrame,
					status:    0, // Joining
				}
			} else {
				// Last 50: recent join frame - will remain
				newFilters[j-50] = filter
				allocations[j] = allocationSpec{
					filter:    filter,
					joinFrame: recentJoinFrame,
					status:    0, // Joining
				}
			}
		}
		mixedOldFilters[i] = oldFilters
		mixedNewFilters[i] = newFilters

		proverAddr, err := createProverWithAllocations(
			publicKey,
			0, // Joining prover status
			allocations,
		)
		require.NoError(t, err)
		mixedProverAddrs[i] = proverAddr
		t.Logf("Created mixed app shard prover %d at address: %s",
			i, hex.EncodeToString(proverAddr))
	}

	// 4. Create 3 provers with rejected allocations (old join frame)
	// These should be completely pruned like joining allocations
	rejectedProverAddrs := make([][]byte, 3)
	rejectedProverKeys := make([][]byte, 3)
	rejectedFilters := make([][][]byte, 3)
	for i := 0; i < 3; i++ {
		publicKey := bytes.Repeat([]byte{byte(0x40 + i)}, 585)
		rejectedProverKeys[i] = publicKey

		allocations := make([]allocationSpec, 10)
		filters := make([][]byte, 10)
		for j := 0; j < 10; j++ {
			filter := []byte(fmt.Sprintf("rejected_shard_%d_%d", i, j))
			filters[j] = filter
			allocations[j] = allocationSpec{
				filter:    filter,
				joinFrame: oldJoinFrame,
				status:    4, // Rejected
			}
		}
		rejectedFilters[i] = filters

		proverAddr, err := createProverWithAllocations(
			publicKey,
			0, // Joining prover status
			allocations,
		)
		require.NoError(t, err)
		rejectedProverAddrs[i] = proverAddr
		t.Logf("Created rejected prover %d at address: %s",
			i, hex.EncodeToString(proverAddr))
	}

	// 5. Create 3 provers with MIXED Active and Joining allocations (all with old join frame)
	// Active allocations should NOT be pruned even with old join frame
	// Joining allocations should be pruned
	// Prover should remain because it has Active allocations
	mixedActiveJoiningProverAddrs := make([][]byte, 3)
	mixedActiveJoiningProverKeys := make([][]byte, 3)
	mixedActiveFilters := make([][][]byte, 3)  // Active filters that should remain
	mixedJoiningFilters := make([][][]byte, 3) // Joining filters that should be pruned
	for i := 0; i < 3; i++ {
		publicKey := bytes.Repeat([]byte{byte(0x50 + i)}, 585)
		mixedActiveJoiningProverKeys[i] = publicKey

		allocations := make([]allocationSpec, 20)
		activeFilters := make([][]byte, 10)
		joiningFilters := make([][]byte, 10)

		for j := 0; j < 20; j++ {
			filter := []byte(fmt.Sprintf("mixed_active_joining_%d_%d", i, j))
			if j < 10 {
				// First 10: Active status with old join frame - should NOT be pruned
				activeFilters[j] = filter
				allocations[j] = allocationSpec{
					filter:    filter,
					joinFrame: oldJoinFrame, // Old, but Active so should remain
					status:    1,            // Active
				}
			} else {
				// Last 10: Joining status with old join frame - should be pruned
				joiningFilters[j-10] = filter
				allocations[j] = allocationSpec{
					filter:    filter,
					joinFrame: oldJoinFrame, // Old and Joining, so should be pruned
					status:    0,            // Joining
				}
			}
		}
		mixedActiveFilters[i] = activeFilters
		mixedJoiningFilters[i] = joiningFilters

		proverAddr, err := createProverWithAllocations(
			publicKey,
			1, // Active prover status
			allocations,
		)
		require.NoError(t, err)
		mixedActiveJoiningProverAddrs[i] = proverAddr
		t.Logf("Created mixed active/joining prover %d at address: %s",
			i, hex.EncodeToString(proverAddr))
	}

	// 6. Create 2 provers with ALL Active allocations (old join frame)
	// None of these should be pruned - Active status protects them
	allActiveProverAddrs := make([][]byte, 2)
	allActiveProverKeys := make([][]byte, 2)
	allActiveFilters := make([][][]byte, 2)
	for i := 0; i < 2; i++ {
		publicKey := bytes.Repeat([]byte{byte(0x60 + i)}, 585)
		allActiveProverKeys[i] = publicKey

		allocations := make([]allocationSpec, 50)
		filters := make([][]byte, 50)
		for j := 0; j < 50; j++ {
			filter := []byte(fmt.Sprintf("all_active_%d_%d", i, j))
			filters[j] = filter
			allocations[j] = allocationSpec{
				filter:    filter,
				joinFrame: oldJoinFrame, // Old, but Active so should remain
				status:    1,            // Active
			}
		}
		allActiveFilters[i] = filters

		proverAddr, err := createProverWithAllocations(
			publicKey,
			1, // Active prover status
			allocations,
		)
		require.NoError(t, err)
		allActiveProverAddrs[i] = proverAddr
		t.Logf("Created all-active prover %d at address: %s",
			i, hex.EncodeToString(proverAddr))
	}

	// ===== VERIFY INITIAL STATE =====

	// Verify all global provers exist
	for i := 0; i < 6; i++ {
		proverID := getProverVertexID(globalProverAddrs[i])
		allocID := getAllocationVertexID(globalProverKeys[i], nil)

		assert.True(t, vertexExists(proverID),
			"Global prover %d vertex should exist before prune", i)
		assert.True(t, vertexDataExists(proverID),
			"Global prover %d vertex data should exist before prune", i)
		assert.True(t, vertexExists(allocID),
			"Global prover %d allocation should exist before prune", i)
		assert.True(t, hyperedgeExists(proverID),
			"Global prover %d hyperedge should exist before prune", i)
	}

	// Verify all-old provers exist
	for i := 0; i < 5; i++ {
		proverID := getProverVertexID(allOldProverAddrs[i])
		assert.True(t, vertexExists(proverID),
			"All-old prover %d vertex should exist before prune", i)
		assert.True(t, vertexDataExists(proverID),
			"All-old prover %d vertex data should exist before prune", i)
		assert.True(t, hyperedgeExists(proverID),
			"All-old prover %d hyperedge should exist before prune", i)

		// Verify all 100 allocations exist
		for j := 0; j < 100; j++ {
			allocID := getAllocationVertexID(allOldProverKeys[i], allOldFilters[i][j])
			assert.True(t, vertexExists(allocID),
				"All-old prover %d allocation %d should exist before prune", i, j)
		}
	}

	// Verify mixed provers exist
	for i := 0; i < 5; i++ {
		proverID := getProverVertexID(mixedProverAddrs[i])
		assert.True(t, vertexExists(proverID),
			"Mixed prover %d vertex should exist before prune", i)
		assert.True(t, vertexDataExists(proverID),
			"Mixed prover %d vertex data should exist before prune", i)
		assert.True(t, hyperedgeExists(proverID),
			"Mixed prover %d hyperedge should exist before prune", i)

		// Verify all 100 allocations exist
		for j := 0; j < 50; j++ {
			oldAllocID := getAllocationVertexID(mixedProverKeys[i], mixedOldFilters[i][j])
			assert.True(t, vertexExists(oldAllocID),
				"Mixed prover %d old allocation %d should exist before prune", i, j)

			newAllocID := getAllocationVertexID(mixedProverKeys[i], mixedNewFilters[i][j])
			assert.True(t, vertexExists(newAllocID),
				"Mixed prover %d new allocation %d should exist before prune", i, j)
		}
	}

	// Verify rejected provers exist
	for i := 0; i < 3; i++ {
		proverID := getProverVertexID(rejectedProverAddrs[i])
		assert.True(t, vertexExists(proverID),
			"Rejected prover %d vertex should exist before prune", i)
		assert.True(t, vertexDataExists(proverID),
			"Rejected prover %d vertex data should exist before prune", i)
		assert.True(t, hyperedgeExists(proverID),
			"Rejected prover %d hyperedge should exist before prune", i)

		// Verify all 10 rejected allocations exist
		for j := 0; j < 10; j++ {
			allocID := getAllocationVertexID(rejectedProverKeys[i], rejectedFilters[i][j])
			assert.True(t, vertexExists(allocID),
				"Rejected prover %d allocation %d should exist before prune", i, j)
		}
	}

	// Verify mixed active/joining provers exist
	for i := 0; i < 3; i++ {
		proverID := getProverVertexID(mixedActiveJoiningProverAddrs[i])
		assert.True(t, vertexExists(proverID),
			"Mixed active/joining prover %d vertex should exist before prune", i)
		assert.True(t, vertexDataExists(proverID),
			"Mixed active/joining prover %d vertex data should exist before prune", i)
		assert.True(t, hyperedgeExists(proverID),
			"Mixed active/joining prover %d hyperedge should exist before prune", i)

		// Verify all 10 active allocations exist
		for j := 0; j < 10; j++ {
			allocID := getAllocationVertexID(mixedActiveJoiningProverKeys[i], mixedActiveFilters[i][j])
			assert.True(t, vertexExists(allocID),
				"Mixed active/joining prover %d active allocation %d should exist before prune", i, j)
		}
		// Verify all 10 joining allocations exist
		for j := 0; j < 10; j++ {
			allocID := getAllocationVertexID(mixedActiveJoiningProverKeys[i], mixedJoiningFilters[i][j])
			assert.True(t, vertexExists(allocID),
				"Mixed active/joining prover %d joining allocation %d should exist before prune", i, j)
		}
	}

	// Verify all-active provers exist
	for i := 0; i < 2; i++ {
		proverID := getProverVertexID(allActiveProverAddrs[i])
		assert.True(t, vertexExists(proverID),
			"All-active prover %d vertex should exist before prune", i)
		assert.True(t, vertexDataExists(proverID),
			"All-active prover %d vertex data should exist before prune", i)
		assert.True(t, hyperedgeExists(proverID),
			"All-active prover %d hyperedge should exist before prune", i)

		// Verify all 50 active allocations exist
		for j := 0; j < 50; j++ {
			allocID := getAllocationVertexID(allActiveProverKeys[i], allActiveFilters[i][j])
			assert.True(t, vertexExists(allocID),
				"All-active prover %d allocation %d should exist before prune", i, j)
		}
	}

	// ===== CREATE REGISTRY AND PRUNE =====

	registry, err := NewProverRegistry(logger, hg)
	require.NoError(t, err)

	// Run pruning
	err = registry.PruneOrphanJoins(currentFrame)
	require.NoError(t, err)

	// ===== VERIFY POST-PRUNE STATE =====

	// 1. Verify global provers are COMPLETELY UNTOUCHED
	for i := 0; i < 6; i++ {
		proverID := getProverVertexID(globalProverAddrs[i])
		allocID := getAllocationVertexID(globalProverKeys[i], nil)

		assert.True(t, vertexExists(proverID),
			"Global prover %d vertex should STILL exist after prune", i)
		assert.True(t, vertexDataExists(proverID),
			"Global prover %d vertex data should STILL exist after prune", i)
		assert.True(t, vertexExists(allocID),
			"Global prover %d allocation should STILL exist after prune", i)
		assert.True(t, vertexDataExists(allocID),
			"Global prover %d allocation data should STILL exist after prune", i)
		assert.True(t, hyperedgeExists(proverID),
			"Global prover %d hyperedge should STILL exist after prune", i)
	}

	// 2. Verify all-old provers are COMPLETELY PRUNED (prover vertex gone too)
	for i := 0; i < 5; i++ {
		proverID := getProverVertexID(allOldProverAddrs[i])

		assert.False(t, vertexExists(proverID),
			"All-old prover %d vertex should be DELETED after prune", i)
		assert.False(t, vertexDataExists(proverID),
			"All-old prover %d vertex data should be DELETED after prune", i)
		assert.False(t, hyperedgeExists(proverID),
			"All-old prover %d hyperedge should be DELETED after prune", i)

		// Verify all 100 allocations are deleted
		for j := 0; j < 100; j++ {
			allocID := getAllocationVertexID(allOldProverKeys[i], allOldFilters[i][j])
			assert.False(t, vertexExists(allocID),
				"All-old prover %d allocation %d should be DELETED after prune", i, j)
			assert.False(t, vertexDataExists(allocID),
				"All-old prover %d allocation %d data should be DELETED after prune", i, j)
		}
	}

	// 3. Verify mixed provers: prover remains, old allocations pruned, new allocations remain
	for i := 0; i < 5; i++ {
		proverID := getProverVertexID(mixedProverAddrs[i])

		assert.True(t, vertexExists(proverID),
			"Mixed prover %d vertex should STILL exist after prune", i)
		assert.True(t, vertexDataExists(proverID),
			"Mixed prover %d vertex data should STILL exist after prune", i)
		assert.True(t, hyperedgeExists(proverID),
			"Mixed prover %d hyperedge should STILL exist after prune", i)

		// Verify old allocations are deleted
		for j := 0; j < 50; j++ {
			oldAllocID := getAllocationVertexID(mixedProverKeys[i], mixedOldFilters[i][j])
			assert.False(t, vertexExists(oldAllocID),
				"Mixed prover %d old allocation %d should be DELETED after prune", i, j)
			assert.False(t, vertexDataExists(oldAllocID),
				"Mixed prover %d old allocation %d data should be DELETED after prune", i, j)
		}

		// Verify new allocations remain
		for j := 0; j < 50; j++ {
			newAllocID := getAllocationVertexID(mixedProverKeys[i], mixedNewFilters[i][j])
			assert.True(t, vertexExists(newAllocID),
				"Mixed prover %d new allocation %d should STILL exist after prune", i, j)
			assert.True(t, vertexDataExists(newAllocID),
				"Mixed prover %d new allocation %d data should STILL exist after prune", i, j)
		}
	}

	// 4. Verify rejected provers are COMPLETELY PRUNED (prover vertex gone too)
	for i := 0; i < 3; i++ {
		proverID := getProverVertexID(rejectedProverAddrs[i])

		assert.False(t, vertexExists(proverID),
			"Rejected prover %d vertex should be DELETED after prune", i)
		assert.False(t, vertexDataExists(proverID),
			"Rejected prover %d vertex data should be DELETED after prune", i)
		assert.False(t, hyperedgeExists(proverID),
			"Rejected prover %d hyperedge should be DELETED after prune", i)

		// Verify all 10 rejected allocations are deleted
		for j := 0; j < 10; j++ {
			allocID := getAllocationVertexID(rejectedProverKeys[i], rejectedFilters[i][j])
			assert.False(t, vertexExists(allocID),
				"Rejected prover %d allocation %d should be DELETED after prune", i, j)
			assert.False(t, vertexDataExists(allocID),
				"Rejected prover %d allocation %d data should be DELETED after prune", i, j)
		}
	}

	// 5. Verify mixed active/joining provers: prover remains, Active allocations remain,
	// Joining allocations are pruned
	for i := 0; i < 3; i++ {
		proverID := getProverVertexID(mixedActiveJoiningProverAddrs[i])

		assert.True(t, vertexExists(proverID),
			"Mixed active/joining prover %d vertex should STILL exist after prune", i)
		assert.True(t, vertexDataExists(proverID),
			"Mixed active/joining prover %d vertex data should STILL exist after prune", i)
		assert.True(t, hyperedgeExists(proverID),
			"Mixed active/joining prover %d hyperedge should STILL exist after prune", i)

		// Verify Active allocations REMAIN (not pruned despite old join frame)
		for j := 0; j < 10; j++ {
			activeAllocID := getAllocationVertexID(mixedActiveJoiningProverKeys[i], mixedActiveFilters[i][j])
			assert.True(t, vertexExists(activeAllocID),
				"Mixed active/joining prover %d ACTIVE allocation %d should STILL exist after prune", i, j)
			assert.True(t, vertexDataExists(activeAllocID),
				"Mixed active/joining prover %d ACTIVE allocation %d data should STILL exist after prune", i, j)
		}

		// Verify Joining allocations are DELETED
		for j := 0; j < 10; j++ {
			joiningAllocID := getAllocationVertexID(mixedActiveJoiningProverKeys[i], mixedJoiningFilters[i][j])
			assert.False(t, vertexExists(joiningAllocID),
				"Mixed active/joining prover %d JOINING allocation %d should be DELETED after prune", i, j)
			assert.False(t, vertexDataExists(joiningAllocID),
				"Mixed active/joining prover %d JOINING allocation %d data should be DELETED after prune", i, j)
		}
	}

	// 6. Verify all-active provers are COMPLETELY UNTOUCHED
	// Active allocations with old join frame should NOT be pruned
	for i := 0; i < 2; i++ {
		proverID := getProverVertexID(allActiveProverAddrs[i])

		assert.True(t, vertexExists(proverID),
			"All-active prover %d vertex should STILL exist after prune", i)
		assert.True(t, vertexDataExists(proverID),
			"All-active prover %d vertex data should STILL exist after prune", i)
		assert.True(t, hyperedgeExists(proverID),
			"All-active prover %d hyperedge should STILL exist after prune", i)

		// Verify all 50 Active allocations REMAIN
		for j := 0; j < 50; j++ {
			allocID := getAllocationVertexID(allActiveProverKeys[i], allActiveFilters[i][j])
			assert.True(t, vertexExists(allocID),
				"All-active prover %d allocation %d should STILL exist after prune", i, j)
			assert.True(t, vertexDataExists(allocID),
				"All-active prover %d allocation %d data should STILL exist after prune", i, j)
		}
	}

	// ===== VERIFY REGISTRY CACHE STATE =====

	// Global provers should still be in cache
	for i := 0; i < 6; i++ {
		info, err := registry.GetProverInfo(globalProverAddrs[i])
		require.NoError(t, err)
		assert.NotNil(t, info, "Global prover %d should still be in registry cache", i)
		assert.Len(t, info.Allocations, 1, "Global prover %d should have 1 allocation", i)
	}

	// All-old provers should be removed from cache
	for i := 0; i < 5; i++ {
		info, err := registry.GetProverInfo(allOldProverAddrs[i])
		require.NoError(t, err)
		assert.Nil(t, info, "All-old prover %d should be removed from registry cache", i)
	}

	// Mixed provers should still be in cache with only 50 allocations
	for i := 0; i < 5; i++ {
		info, err := registry.GetProverInfo(mixedProverAddrs[i])
		require.NoError(t, err)
		assert.NotNil(t, info, "Mixed prover %d should still be in registry cache", i)
		assert.Len(t, info.Allocations, 50,
			"Mixed prover %d should have 50 allocations after prune", i)
	}

	// Rejected provers should be removed from cache
	for i := 0; i < 3; i++ {
		info, err := registry.GetProverInfo(rejectedProverAddrs[i])
		require.NoError(t, err)
		assert.Nil(t, info, "Rejected prover %d should be removed from registry cache", i)
	}

	// Mixed active/joining provers should still be in cache with only 10 allocations (the Active ones)
	for i := 0; i < 3; i++ {
		info, err := registry.GetProverInfo(mixedActiveJoiningProverAddrs[i])
		require.NoError(t, err)
		assert.NotNil(t, info, "Mixed active/joining prover %d should still be in registry cache", i)
		assert.Len(t, info.Allocations, 10,
			"Mixed active/joining prover %d should have 10 allocations (Active ones) after prune", i)

		// Verify all remaining allocations are Active status
		for _, alloc := range info.Allocations {
			assert.Equal(t, consensus.ProverStatusActive, alloc.Status,
				"Mixed active/joining prover %d should only have Active allocations remaining", i)
		}
	}

	// All-active provers should still be in cache with all 50 allocations
	for i := 0; i < 2; i++ {
		info, err := registry.GetProverInfo(allActiveProverAddrs[i])
		require.NoError(t, err)
		assert.NotNil(t, info, "All-active prover %d should still be in registry cache", i)
		assert.Len(t, info.Allocations, 50,
			"All-active prover %d should still have all 50 allocations after prune", i)

		// Verify all allocations are Active status
		for _, alloc := range info.Allocations {
			assert.Equal(t, consensus.ProverStatusActive, alloc.Status,
				"All-active prover %d should only have Active allocations", i)
		}
	}

	// ===== VERIFY THROUGH ADDITIONAL REGISTRY METHODS =====

	// Verify all-old provers don't appear in GetProversByStatus(Joining)
	joiningProvers, err := registry.GetProversByStatus(nil, consensus.ProverStatusJoining)
	require.NoError(t, err)
	for _, prover := range joiningProvers {
		for i, addr := range allOldProverAddrs {
			assert.NotEqual(t, hex.EncodeToString(addr), hex.EncodeToString(prover.Address),
				"All-old prover %d should not appear in GetProversByStatus(Joining)", i)
		}
		for i, addr := range rejectedProverAddrs {
			assert.NotEqual(t, hex.EncodeToString(addr), hex.EncodeToString(prover.Address),
				"Rejected prover %d should not appear in GetProversByStatus(Joining)", i)
		}
	}

	// Verify all-old provers don't appear in GetProvers for their filters
	for i := 0; i < 5; i++ {
		for j := 0; j < 100; j++ {
			filter := allOldFilters[i][j]
			provers, err := registry.GetProvers(filter)
			require.NoError(t, err)
			for _, p := range provers {
				assert.NotEqual(t, hex.EncodeToString(allOldProverAddrs[i]), hex.EncodeToString(p.Address),
					"All-old prover %d should not appear in GetProvers for filter %d", i, j)
			}
		}
	}

	// Verify all-active provers appear in GetProversByStatus(Active) for their specific filters
	// Note: GetProversByStatus(nil, ...) only returns global provers (filter=nil)
	// The all-active provers are on app shards, so we need to check their specific filters
	for i := 0; i < 2; i++ {
		for j := 0; j < 50; j++ {
			filter := allActiveFilters[i][j]
			activeProvers, err := registry.GetProversByStatus(filter, consensus.ProverStatusActive)
			require.NoError(t, err)
			found := false
			for _, prover := range activeProvers {
				if hex.EncodeToString(allActiveProverAddrs[i]) == hex.EncodeToString(prover.Address) {
					found = true
					break
				}
			}
			assert.True(t, found,
				"All-active prover %d should appear in GetProversByStatus(Active) for filter %d", i, j)
		}
	}

	t.Logf("Prune test completed successfully:")
	t.Logf("  - 6 global provers: untouched")
	t.Logf("  - 5 all-old provers: completely pruned (500 allocations)")
	t.Logf("  - 5 mixed provers: 250 old allocations pruned, 250 recent allocations remain")
	t.Logf("  - 3 rejected provers: completely pruned (30 rejected allocations)")
	t.Logf("  - 3 mixed active/joining provers: 30 Joining allocations pruned, 30 Active allocations remain")
	t.Logf("  - 2 all-active provers: untouched (100 Active allocations remain)")
}

// TestPruneOrphanJoins_IncompleteState tests the scenario where a previous prune
// deleted the vertex ID set entry but not the vertex data (simulating the original bug).
// The registry should still be able to prune these allocations by cleaning up the
// orphaned vertex data.
func TestPruneOrphanJoins_IncompleteState(t *testing.T) {
	logger := zap.NewNop()

	// Create stores with in-memory pebble DB
	pebbleDB := store.NewPebbleDB(
		logger,
		&config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/prune_incomplete"}},
		0,
	)
	defer pebbleDB.Close()

	// Create inclusion prover and verifiable encryptor
	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)

	// Create hypergraph store and hypergraph
	hypergraphStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/prune_incomplete"},
		pebbleDB,
		logger,
		verifiableEncryptor,
		inclusionProver,
	)
	hg, err := hypergraphStore.LoadHypergraph(&tests.Nopthenticator{}, 1)
	require.NoError(t, err)

	// Create RDF multiprover for setting up test data
	rdfMultiprover := schema.NewRDFMultiprover(
		&schema.TurtleRDFParser{},
		inclusionProver,
	)

	const currentFrame = uint64(1000)
	const oldJoinFrame = uint64(100) // Will be pruned

	// Helper to create a prover with allocations, returning the prover address
	createProverWithAllocations := func(
		publicKey []byte,
		filters [][]byte,
		joinFrame uint64,
	) ([]byte, error) {
		proverAddressBI, err := poseidon.HashBytes(publicKey)
		if err != nil {
			return nil, err
		}
		proverAddress := proverAddressBI.FillBytes(make([]byte, 32))

		hgCRDT := hg.(*hgcrdt.HypergraphCRDT)
		txn, err := hgCRDT.NewTransaction(false)
		if err != nil {
			return nil, err
		}

		// Create prover vertex
		proverTree := &tries.VectorCommitmentTree{}
		_ = rdfMultiprover.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"prover:Prover", "PublicKey", publicKey, proverTree)
		_ = rdfMultiprover.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"prover:Prover", "Status", []byte{0}, proverTree)
		_ = rdfMultiprover.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"prover:Prover", "AvailableStorage", make([]byte, 8), proverTree)
		_ = rdfMultiprover.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"prover:Prover", "Seniority", make([]byte, 8), proverTree)

		proverVertex := hgcrdt.NewVertex(
			intrinsics.GLOBAL_INTRINSIC_ADDRESS,
			[32]byte(proverAddress),
			proverTree.Commit(inclusionProver, false),
			big.NewInt(0),
		)
		if err := hg.AddVertex(txn, proverVertex); err != nil {
			txn.Abort()
			return nil, err
		}

		var proverVertexID [64]byte
		copy(proverVertexID[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(proverVertexID[32:], proverAddress)
		if err := hg.SetVertexData(txn, proverVertexID, proverTree); err != nil {
			txn.Abort()
			return nil, err
		}

		hyperedge := hgcrdt.NewHyperedge(
			intrinsics.GLOBAL_INTRINSIC_ADDRESS,
			[32]byte(proverAddress),
		)

		// Create allocation vertices
		for _, filter := range filters {
			allocationAddressBI, _ := poseidon.HashBytes(
				slices.Concat([]byte("PROVER_ALLOCATION"), publicKey, filter),
			)
			allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))

			allocationTree := &tries.VectorCommitmentTree{}
			_ = rdfMultiprover.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
				"allocation:ProverAllocation", "Prover", proverAddress, allocationTree)
			_ = rdfMultiprover.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
				"allocation:ProverAllocation", "Status", []byte{0}, allocationTree)
			_ = rdfMultiprover.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
				"allocation:ProverAllocation", "ConfirmationFilter", filter, allocationTree)

			frameNumberBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(frameNumberBytes, joinFrame)
			_ = rdfMultiprover.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
				"allocation:ProverAllocation", "JoinFrameNumber", frameNumberBytes, allocationTree)

			allocationVertex := hgcrdt.NewVertex(
				intrinsics.GLOBAL_INTRINSIC_ADDRESS,
				[32]byte(allocationAddress),
				allocationTree.Commit(inclusionProver, false),
				big.NewInt(0),
			)
			if err := hg.AddVertex(txn, allocationVertex); err != nil {
				txn.Abort()
				return nil, err
			}

			var allocationVertexID [64]byte
			copy(allocationVertexID[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
			copy(allocationVertexID[32:], allocationAddress)
			if err := hg.SetVertexData(txn, allocationVertexID, allocationTree); err != nil {
				txn.Abort()
				return nil, err
			}

			hyperedge.AddExtrinsic(allocationVertex)
		}

		if err := hg.AddHyperedge(txn, hyperedge); err != nil {
			txn.Abort()
			return nil, err
		}

		if err := txn.Commit(); err != nil {
			return nil, err
		}

		return proverAddress, nil
	}

	// Helper to delete ONLY the vertex ID set entry (not the vertex data)
	// This simulates the state after a previous incomplete prune
	deleteVertexIDSetOnly := func(publicKey []byte, filter []byte) error {
		allocationAddressBI, _ := poseidon.HashBytes(
			slices.Concat([]byte("PROVER_ALLOCATION"), publicKey, filter),
		)
		allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))

		var vertexID [64]byte
		copy(vertexID[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(vertexID[32:], allocationAddress)

		hgCRDT := hg.(*hgcrdt.HypergraphCRDT)
		txn, err := hgCRDT.NewTransaction(false)
		if err != nil {
			return err
		}

		shardKey := tries.ShardKey{
			L1: [3]byte{0x00, 0x00, 0x00},
			L2: [32]byte(bytes.Repeat([]byte{0xff}, 32)),
		}
		vtree := hgCRDT.GetVertexAddsSet(shardKey).GetTree()

		// Delete from ID set only
		if err := vtree.Delete(txn, vertexID[:]); err != nil {
			txn.Abort()
			return err
		}

		return txn.Commit()
	}

	// Helper to check if vertex exists in ID set
	vertexExistsInIDSet := func(vertexID [64]byte) bool {
		_, err := hg.GetVertex(vertexID)
		return err == nil
	}

	// Helper to check if vertex data exists
	vertexDataExists := func(vertexID [64]byte) bool {
		data, err := hg.GetVertexData(vertexID)
		return err == nil && data != nil
	}

	// Helper to compute allocation vertex ID
	getAllocationVertexID := func(publicKey, filter []byte) [64]byte {
		allocationHash, _ := poseidon.HashBytes(
			slices.Concat([]byte("PROVER_ALLOCATION"), publicKey, filter),
		)
		var id [64]byte
		copy(id[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(id[32:], allocationHash.FillBytes(make([]byte, 32)))
		return id
	}

	// Create a prover with 5 allocations
	publicKey := bytes.Repeat([]byte{0x50}, 585)
	filters := [][]byte{
		[]byte("incomplete_filter_0"),
		[]byte("incomplete_filter_1"),
		[]byte("incomplete_filter_2"),
		[]byte("incomplete_filter_3"),
		[]byte("incomplete_filter_4"),
	}

	proverAddr, err := createProverWithAllocations(publicKey, filters, oldJoinFrame)
	require.NoError(t, err)
	t.Logf("Created prover at address: %s", hex.EncodeToString(proverAddr))

	// Verify all allocations exist (both ID set and data)
	for i, filter := range filters {
		allocID := getAllocationVertexID(publicKey, filter)
		assert.True(t, vertexExistsInIDSet(allocID),
			"Allocation %d should exist in ID set before manipulation", i)
		assert.True(t, vertexDataExists(allocID),
			"Allocation %d data should exist before manipulation", i)
	}

	// Now delete the ID set entries for allocations 0, 1, and 2, but leave their vertex data
	// This simulates the state after an incomplete prune (the original bug)
	for i := 0; i < 3; i++ {
		err := deleteVertexIDSetOnly(publicKey, filters[i])
		require.NoError(t, err)
		t.Logf("Deleted ID set entry for allocation %d (leaving vertex data)", i)
	}

	// Verify the incomplete state: ID set entries gone, but data remains
	for i := 0; i < 3; i++ {
		allocID := getAllocationVertexID(publicKey, filters[i])
		assert.False(t, vertexExistsInIDSet(allocID),
			"Allocation %d should NOT exist in ID set after manipulation", i)
		assert.True(t, vertexDataExists(allocID),
			"Allocation %d data should STILL exist after manipulation (orphaned)", i)
	}

	// Allocations 3 and 4 should still be complete
	for i := 3; i < 5; i++ {
		allocID := getAllocationVertexID(publicKey, filters[i])
		assert.True(t, vertexExistsInIDSet(allocID),
			"Allocation %d should still exist in ID set", i)
		assert.True(t, vertexDataExists(allocID),
			"Allocation %d data should still exist", i)
	}

	// Create registry - this will load the prover from vertex data iterator
	// The allocations with missing ID set entries will still be in the cache
	// because extractGlobalState reads from vertex DATA, not ID set
	registry, err := NewProverRegistry(logger, hg)
	require.NoError(t, err)

	// Verify the prover is in cache with all 5 allocations
	// (because extractGlobalState reads from vertex data which still exists)
	info, err := registry.GetProverInfo(proverAddr)
	require.NoError(t, err)
	require.NotNil(t, info)
	t.Logf("Prover in cache has %d allocations", len(info.Allocations))

	// Run pruning - this should handle the incomplete state gracefully
	err = registry.PruneOrphanJoins(currentFrame)
	require.NoError(t, err)

	// After pruning:
	// - All allocation vertex DATA should be deleted (both orphaned and complete ones)
	// - The prover should be removed since all allocations are gone
	for i, filter := range filters {
		allocID := getAllocationVertexID(publicKey, filter)
		assert.False(t, vertexExistsInIDSet(allocID),
			"Allocation %d should not exist in ID set after prune", i)
		assert.False(t, vertexDataExists(allocID),
			"Allocation %d data should be DELETED after prune", i)
	}

	// Prover should be removed from cache via GetProverInfo
	info, err = registry.GetProverInfo(proverAddr)
	require.NoError(t, err)
	assert.Nil(t, info, "Prover should be removed from cache after all allocations pruned")

	// Also verify through GetProvers that the prover is gone from all filters
	for _, filter := range filters {
		provers, err := registry.GetProvers(filter)
		require.NoError(t, err)
		for _, p := range provers {
			assert.NotEqual(t, hex.EncodeToString(proverAddr), hex.EncodeToString(p.Address),
				"Prover should not appear in GetProvers for filter %s", string(filter))
		}
	}

	// Verify through GetProversByStatus that the prover is gone
	joiningProvers, err := registry.GetProversByStatus(nil, consensus.ProverStatusJoining)
	require.NoError(t, err)
	for _, p := range joiningProvers {
		assert.NotEqual(t, hex.EncodeToString(proverAddr), hex.EncodeToString(p.Address),
			"Prover should not appear in GetProversByStatus(Joining)")
	}

	t.Logf("Incomplete state prune test completed successfully")
	t.Logf("  - 3 allocations with missing ID set entries: vertex data cleaned up")
	t.Logf("  - 2 allocations with complete state: fully pruned")
	t.Logf("  - Prover removed after all allocations pruned")
	t.Logf("  - Registry methods confirm prover is gone")
}

// TestPruneOrphanJoins_OrphanedAllocation tests the scenario where an allocation
// vertex exists but the prover vertex is missing. The allocation should still be
// pruned if it's eligible (old join frame, joining status).
func TestPruneOrphanJoins_OrphanedAllocation(t *testing.T) {
	logger := zap.NewNop()

	// Create stores with in-memory pebble DB
	pebbleDB := store.NewPebbleDB(
		logger,
		&config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/prune_orphaned_alloc"}},
		0,
	)
	defer pebbleDB.Close()

	// Create inclusion prover and verifiable encryptor
	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)

	// Create hypergraph store and hypergraph
	hypergraphStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/prune_orphaned_alloc"},
		pebbleDB,
		logger,
		verifiableEncryptor,
		inclusionProver,
	)
	hg, err := hypergraphStore.LoadHypergraph(&tests.Nopthenticator{}, 1)
	require.NoError(t, err)

	// Create RDF multiprover for setting up test data
	rdfMultiprover := schema.NewRDFMultiprover(
		&schema.TurtleRDFParser{},
		inclusionProver,
	)

	const currentFrame = uint64(1000)
	const oldJoinFrame = uint64(100) // Will be pruned

	// Helper to create ONLY an allocation vertex (no prover vertex)
	// This simulates the case where the prover was deleted but the allocation remains
	createOrphanedAllocation := func(
		publicKey []byte,
		filter []byte,
		joinFrame uint64,
	) (proverAddress []byte, allocationAddress []byte, err error) {
		proverAddressBI, err := poseidon.HashBytes(publicKey)
		if err != nil {
			return nil, nil, err
		}
		proverAddr := proverAddressBI.FillBytes(make([]byte, 32))

		allocationAddressBI, err := poseidon.HashBytes(
			slices.Concat([]byte("PROVER_ALLOCATION"), publicKey, filter),
		)
		if err != nil {
			return nil, nil, err
		}
		allocAddr := allocationAddressBI.FillBytes(make([]byte, 32))

		hgCRDT := hg.(*hgcrdt.HypergraphCRDT)
		txn, err := hgCRDT.NewTransaction(false)
		if err != nil {
			return nil, nil, err
		}

		// Create ONLY the allocation vertex (no prover vertex)
		allocationTree := &tries.VectorCommitmentTree{}
		_ = rdfMultiprover.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"allocation:ProverAllocation", "Prover", proverAddr, allocationTree)
		_ = rdfMultiprover.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"allocation:ProverAllocation", "Status", []byte{0}, allocationTree) // Joining
		_ = rdfMultiprover.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"allocation:ProverAllocation", "ConfirmationFilter", filter, allocationTree)

		frameNumberBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(frameNumberBytes, joinFrame)
		_ = rdfMultiprover.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"allocation:ProverAllocation", "JoinFrameNumber", frameNumberBytes, allocationTree)

		allocationVertex := hgcrdt.NewVertex(
			intrinsics.GLOBAL_INTRINSIC_ADDRESS,
			[32]byte(allocAddr),
			allocationTree.Commit(inclusionProver, false),
			big.NewInt(0),
		)
		if err := hg.AddVertex(txn, allocationVertex); err != nil {
			txn.Abort()
			return nil, nil, err
		}

		var allocationVertexID [64]byte
		copy(allocationVertexID[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(allocationVertexID[32:], allocAddr)
		if err := hg.SetVertexData(txn, allocationVertexID, allocationTree); err != nil {
			txn.Abort()
			return nil, nil, err
		}

		if err := txn.Commit(); err != nil {
			return nil, nil, err
		}

		return proverAddr, allocAddr, nil
	}

	// Helper to check if vertex exists
	vertexExists := func(vertexID [64]byte) bool {
		_, err := hg.GetVertex(vertexID)
		return err == nil
	}

	// Helper to check if vertex data exists
	vertexDataExists := func(vertexID [64]byte) bool {
		data, err := hg.GetVertexData(vertexID)
		return err == nil && data != nil
	}

	// Helper to compute vertex ID from address
	getVertexID := func(address []byte) [64]byte {
		var id [64]byte
		copy(id[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(id[32:], address)
		return id
	}

	// Create 5 orphaned allocations (no prover vertex exists)
	publicKeys := make([][]byte, 5)
	proverAddresses := make([][]byte, 5)
	allocationAddresses := make([][]byte, 5)
	filters := make([][]byte, 5)

	for i := 0; i < 5; i++ {
		publicKeys[i] = bytes.Repeat([]byte{byte(0x70 + i)}, 585)
		filters[i] = []byte(fmt.Sprintf("orphan_filter_%d", i))

		proverAddr, allocAddr, err := createOrphanedAllocation(
			publicKeys[i],
			filters[i],
			oldJoinFrame,
		)
		require.NoError(t, err)
		proverAddresses[i] = proverAddr
		allocationAddresses[i] = allocAddr
		t.Logf("Created orphaned allocation %d: prover=%s, allocation=%s",
			i, hex.EncodeToString(proverAddr), hex.EncodeToString(allocAddr))
	}

	// Verify initial state: allocation vertices exist, prover vertices do NOT exist
	for i := 0; i < 5; i++ {
		proverVertexID := getVertexID(proverAddresses[i])
		allocVertexID := getVertexID(allocationAddresses[i])

		assert.False(t, vertexExists(proverVertexID),
			"Prover %d vertex should NOT exist (orphaned allocation)", i)
		assert.False(t, vertexDataExists(proverVertexID),
			"Prover %d vertex data should NOT exist (orphaned allocation)", i)

		assert.True(t, vertexExists(allocVertexID),
			"Allocation %d vertex should exist before prune", i)
		assert.True(t, vertexDataExists(allocVertexID),
			"Allocation %d vertex data should exist before prune", i)
	}

	// Create registry - this will load allocations from vertex data iterator
	// The allocations will be loaded even though their prover vertices don't exist
	registry, err := NewProverRegistry(logger, hg)
	require.NoError(t, err)

	// Verify the allocations created ProverInfo entries in the cache
	// (with Address but no PublicKey since prover vertex doesn't exist)
	for i := 0; i < 5; i++ {
		info, err := registry.GetProverInfo(proverAddresses[i])
		require.NoError(t, err)
		if info != nil {
			t.Logf("Prover %d in cache: address=%s, publicKey len=%d, allocations=%d",
				i, hex.EncodeToString(info.Address), len(info.PublicKey), len(info.Allocations))
			// The prover info should have no public key since the prover vertex doesn't exist
			assert.Empty(t, info.PublicKey,
				"Prover %d should have no public key (prover vertex missing)", i)
			assert.Len(t, info.Allocations, 1,
				"Prover %d should have 1 allocation", i)
			// Verify VertexAddress is set on the allocation
			assert.Len(t, info.Allocations[0].VertexAddress, 32,
				"Allocation %d should have VertexAddress set", i)
		}
	}

	// Run pruning
	err = registry.PruneOrphanJoins(currentFrame)
	require.NoError(t, err)

	// Verify post-prune state: all orphaned allocations should be pruned
	for i := 0; i < 5; i++ {
		allocVertexID := getVertexID(allocationAddresses[i])

		assert.False(t, vertexExists(allocVertexID),
			"Allocation %d vertex should be DELETED after prune", i)
		assert.False(t, vertexDataExists(allocVertexID),
			"Allocation %d vertex data should be DELETED after prune", i)
	}

	// Verify registry cache state: provers should be removed
	for i := 0; i < 5; i++ {
		info, err := registry.GetProverInfo(proverAddresses[i])
		require.NoError(t, err)
		assert.Nil(t, info,
			"Prover %d should be removed from registry cache after prune", i)
	}

	// Verify through GetProvers that the provers are gone from all filters
	for i := 0; i < 5; i++ {
		provers, err := registry.GetProvers(filters[i])
		require.NoError(t, err)
		for _, p := range provers {
			assert.NotEqual(t, hex.EncodeToString(proverAddresses[i]), hex.EncodeToString(p.Address),
				"Prover %d should not appear in GetProvers for filter %s", i, string(filters[i]))
		}
	}

	t.Logf("Orphaned allocation prune test completed successfully")
	t.Logf("  - 5 allocations with missing prover vertices: all pruned using VertexAddress")
	t.Logf("  - Registry cache cleaned up")
}

// TestEvictInactiveProvers tests the eviction of provers whose active
// allocations have been inactive beyond the threshold, while leaving
// recently active provers, exempt-shard provers, and non-active provers
// untouched.
func TestEvictInactiveProvers(t *testing.T) {
	logger := zap.NewNop()

	// Create stores with in-memory pebble DB
	pebbleDB := store.NewPebbleDB(
		logger,
		&config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/evict_inactive"}},
		0,
	)
	defer pebbleDB.Close()

	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)

	hypergraphStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/evict_inactive"},
		pebbleDB,
		logger,
		verifiableEncryptor,
		inclusionProver,
	)
	hg, err := hypergraphStore.LoadHypergraph(&tests.Nopthenticator{}, 1)
	require.NoError(t, err)

	rdfMultiprover := schema.NewRDFMultiprover(
		&schema.TurtleRDFParser{},
		inclusionProver,
	)

	// Frame and threshold parameters
	const currentFrame = uint64(500)
	const inactivityThreshold = uint64(360)

	// Exempt shard filter (math.MaxUint64 = currently halted, fully exempt)
	exemptFilter := []byte("exempt_shard")
	exemptShards := map[string]uint64{string(exemptFilter): math.MaxUint64}

	type allocationSpec struct {
		filter              []byte
		joinFrame           uint64
		status              byte   // 0=Joining, 1=Active
		lastActiveFrame     uint64 // only relevant for Active allocations
	}

	// Helper to create a prover with specific allocations (extended with LastActiveFrameNumber)
	createProverWithAllocations := func(
		publicKey []byte,
		proverStatus byte,
		allocations []allocationSpec,
	) ([]byte, error) {
		proverAddressBI, err := poseidon.HashBytes(publicKey)
		if err != nil {
			return nil, err
		}
		proverAddress := proverAddressBI.FillBytes(make([]byte, 32))

		hgCRDT := hg.(*hgcrdt.HypergraphCRDT)
		txn, err := hgCRDT.NewTransaction(false)
		if err != nil {
			return nil, err
		}

		// Create prover vertex
		proverTree := &tries.VectorCommitmentTree{}
		err = rdfMultiprover.Set(
			global.GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"prover:Prover", "PublicKey", publicKey, proverTree,
		)
		if err != nil {
			txn.Abort()
			return nil, err
		}
		err = rdfMultiprover.Set(
			global.GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"prover:Prover", "Status", []byte{proverStatus}, proverTree,
		)
		if err != nil {
			txn.Abort()
			return nil, err
		}
		err = rdfMultiprover.Set(
			global.GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"prover:Prover", "AvailableStorage", make([]byte, 8), proverTree,
		)
		if err != nil {
			txn.Abort()
			return nil, err
		}
		err = rdfMultiprover.Set(
			global.GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"prover:Prover", "Seniority", make([]byte, 8), proverTree,
		)
		if err != nil {
			txn.Abort()
			return nil, err
		}

		proverVertex := hgcrdt.NewVertex(
			intrinsics.GLOBAL_INTRINSIC_ADDRESS,
			[32]byte(proverAddress),
			proverTree.Commit(inclusionProver, false),
			big.NewInt(0),
		)
		err = hg.AddVertex(txn, proverVertex)
		if err != nil {
			txn.Abort()
			return nil, err
		}

		var proverVertexID [64]byte
		copy(proverVertexID[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(proverVertexID[32:], proverAddress)
		err = hg.SetVertexData(txn, proverVertexID, proverTree)
		if err != nil {
			txn.Abort()
			return nil, err
		}

		hyperedge := hgcrdt.NewHyperedge(
			intrinsics.GLOBAL_INTRINSIC_ADDRESS,
			[32]byte(proverAddress),
		)

		for _, alloc := range allocations {
			allocationAddressBI, err := poseidon.HashBytes(
				slices.Concat([]byte("PROVER_ALLOCATION"), publicKey, alloc.filter),
			)
			if err != nil {
				txn.Abort()
				return nil, err
			}
			allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))

			allocationTree := &tries.VectorCommitmentTree{}
			err = rdfMultiprover.Set(
				global.GLOBAL_RDF_SCHEMA,
				intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
				"allocation:ProverAllocation", "Prover", proverAddress, allocationTree,
			)
			if err != nil {
				txn.Abort()
				return nil, err
			}
			err = rdfMultiprover.Set(
				global.GLOBAL_RDF_SCHEMA,
				intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
				"allocation:ProverAllocation", "Status", []byte{alloc.status}, allocationTree,
			)
			if err != nil {
				txn.Abort()
				return nil, err
			}
			err = rdfMultiprover.Set(
				global.GLOBAL_RDF_SCHEMA,
				intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
				"allocation:ProverAllocation", "ConfirmationFilter", alloc.filter, allocationTree,
			)
			if err != nil {
				txn.Abort()
				return nil, err
			}

			frameNumberBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(frameNumberBytes, alloc.joinFrame)
			err = rdfMultiprover.Set(
				global.GLOBAL_RDF_SCHEMA,
				intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
				"allocation:ProverAllocation", "JoinFrameNumber", frameNumberBytes, allocationTree,
			)
			if err != nil {
				txn.Abort()
				return nil, err
			}

			if alloc.lastActiveFrame > 0 {
				lastActiveBytes := make([]byte, 8)
				binary.BigEndian.PutUint64(lastActiveBytes, alloc.lastActiveFrame)
				err = rdfMultiprover.Set(
					global.GLOBAL_RDF_SCHEMA,
					intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
					"allocation:ProverAllocation", "LastActiveFrameNumber", lastActiveBytes, allocationTree,
				)
				if err != nil {
					txn.Abort()
					return nil, err
				}
			}

			allocationVertex := hgcrdt.NewVertex(
				intrinsics.GLOBAL_INTRINSIC_ADDRESS,
				[32]byte(allocationAddress),
				allocationTree.Commit(inclusionProver, false),
				big.NewInt(0),
			)
			err = hg.AddVertex(txn, allocationVertex)
			if err != nil {
				txn.Abort()
				return nil, err
			}

			var allocationVertexID [64]byte
			copy(allocationVertexID[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
			copy(allocationVertexID[32:], allocationAddress)
			err = hg.SetVertexData(txn, allocationVertexID, allocationTree)
			if err != nil {
				txn.Abort()
				return nil, err
			}

			hyperedge.AddExtrinsic(allocationVertex)
		}

		err = hg.AddHyperedge(txn, hyperedge)
		if err != nil {
			txn.Abort()
			return nil, err
		}

		err = txn.Commit()
		if err != nil {
			return nil, err
		}

		return proverAddress, nil
	}

	// ===== CREATE TEST DATA =====

	// 1. Stale allocation -> should be evicted
	// Active prover, allocation LastActiveFrameNumber=100, frame=500
	// Gap = 500-100 = 400 > 360 threshold -> evicted
	staleKey := bytes.Repeat([]byte{0xA0}, 585)
	staleAddr, err := createProverWithAllocations(staleKey, 1, []allocationSpec{
		{filter: []byte("shard_a"), joinFrame: 50, status: 1, lastActiveFrame: 100},
	})
	require.NoError(t, err)
	t.Logf("Created stale prover: %s", hex.EncodeToString(staleAddr))

	// 2. Recent activity -> should NOT be evicted
	// Active prover, allocation LastActiveFrameNumber=400, frame=500
	// Gap = 500-400 = 100 < 360 -> safe
	recentKey := bytes.Repeat([]byte{0xA1}, 585)
	recentAddr, err := createProverWithAllocations(recentKey, 1, []allocationSpec{
		{filter: []byte("shard_b"), joinFrame: 50, status: 1, lastActiveFrame: 400},
	})
	require.NoError(t, err)
	t.Logf("Created recent prover: %s", hex.EncodeToString(recentAddr))

	// 3. Exempt shard -> should NOT be evicted despite being stale
	// Active prover, stale allocation on exempt shard
	exemptKey := bytes.Repeat([]byte{0xA2}, 585)
	exemptAddr, err := createProverWithAllocations(exemptKey, 1, []allocationSpec{
		{filter: exemptFilter, joinFrame: 50, status: 1, lastActiveFrame: 100},
	})
	require.NoError(t, err)
	t.Logf("Created exempt prover: %s", hex.EncodeToString(exemptAddr))

	// 4. Non-active (joining) prover -> should NOT be evicted
	// Joining prover with stale allocation (status=0 joining, not 1 active)
	// EvictInactiveProvers only checks provers with Status==Active
	joiningKey := bytes.Repeat([]byte{0xA3}, 585)
	joiningAddr, err := createProverWithAllocations(joiningKey, 0, []allocationSpec{
		{filter: []byte("shard_c"), joinFrame: 50, status: 1, lastActiveFrame: 100},
	})
	require.NoError(t, err)
	t.Logf("Created joining prover: %s", hex.EncodeToString(joiningAddr))

	// 5. Multi-allocation mixed: two allocations, one recent + one stale
	// Stale triggers eviction of entire prover
	mixedKey := bytes.Repeat([]byte{0xA4}, 585)
	mixedAddr, err := createProverWithAllocations(mixedKey, 1, []allocationSpec{
		{filter: []byte("shard_d"), joinFrame: 50, status: 1, lastActiveFrame: 400}, // recent
		{filter: []byte("shard_e"), joinFrame: 50, status: 1, lastActiveFrame: 100}, // stale -> triggers eviction
	})
	require.NoError(t, err)
	t.Logf("Created mixed prover: %s", hex.EncodeToString(mixedAddr))

	// ===== CREATE REGISTRY =====
	registry, err := NewProverRegistry(logger, hg)
	require.NoError(t, err)

	// Verify all provers exist in cache before eviction
	for _, addr := range [][]byte{staleAddr, recentAddr, exemptAddr, joiningAddr, mixedAddr} {
		info, err := registry.GetProverInfo(addr)
		require.NoError(t, err)
		require.NotNil(t, info, "prover %s should exist before eviction",
			hex.EncodeToString(addr))
	}

	// ===== EVICT =====
	state := hgstate.NewHypergraphState(hg)
	evicted, err := registry.EvictInactiveProvers(
		currentFrame, inactivityThreshold, exemptShards, state,
	)
	require.NoError(t, err)

	// ===== VERIFY RETURNED EVICTED ADDRESSES =====
	evictedSet := make(map[string]bool)
	for _, addr := range evicted {
		evictedSet[hex.EncodeToString(addr)] = true
	}

	assert.True(t, evictedSet[hex.EncodeToString(staleAddr)],
		"stale prover should be in evicted list")
	assert.True(t, evictedSet[hex.EncodeToString(mixedAddr)],
		"mixed prover should be in evicted list")
	assert.False(t, evictedSet[hex.EncodeToString(recentAddr)],
		"recent prover should NOT be in evicted list")
	assert.False(t, evictedSet[hex.EncodeToString(exemptAddr)],
		"exempt prover should NOT be in evicted list")
	assert.False(t, evictedSet[hex.EncodeToString(joiningAddr)],
		"joining prover should NOT be in evicted list")

	// ===== VERIFY REGISTRY CACHE STATE =====

	// Evicted provers should be removed from cache
	info, err := registry.GetProverInfo(staleAddr)
	require.NoError(t, err)
	assert.Nil(t, info, "stale prover should be removed from cache")

	info, err = registry.GetProverInfo(mixedAddr)
	require.NoError(t, err)
	assert.Nil(t, info, "mixed prover should be removed from cache")

	// Non-evicted provers should still be in cache
	info, err = registry.GetProverInfo(recentAddr)
	require.NoError(t, err)
	assert.NotNil(t, info, "recent prover should still be in cache")

	info, err = registry.GetProverInfo(exemptAddr)
	require.NoError(t, err)
	assert.NotNil(t, info, "exempt prover should still be in cache")

	info, err = registry.GetProverInfo(joiningAddr)
	require.NoError(t, err)
	assert.NotNil(t, info, "joining prover should still be in cache")

	// ===== VERIFY RDF MUTATIONS VIA STATE CHANGESET =====
	changes := state.Changeset()
	assert.NotEmpty(t, changes, "state changeset should have mutations from eviction")

	// Check that prover vertex mutations exist for evicted provers
	// Each evicted prover should have its prover vertex + allocation vertices changed
	evictedVertexChanges := 0
	for _, change := range changes {
		if bytes.Equal(change.Domain, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:]) {
			if bytes.Equal(change.Address, staleAddr) ||
				bytes.Equal(change.Address, mixedAddr) {
				evictedVertexChanges++
			}
		}
	}
	assert.Greater(t, evictedVertexChanges, 0,
		"should have vertex changes for evicted provers")

	// Verify evicted provers' vertex data has Status=4 (kicked)
	for _, addr := range [][]byte{staleAddr, mixedAddr} {
		var fullAddress [64]byte
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], addr)

		tree, err := hg.GetVertexData(fullAddress)
		require.NoError(t, err, "evicted prover vertex data should be readable")
		require.NotNil(t, tree, "evicted prover vertex data should exist")

		statusBytes, err := rdfMultiprover.Get(
			global.GLOBAL_RDF_SCHEMA,
			"prover:Prover", "Status", tree,
		)
		require.NoError(t, err)
		assert.Equal(t, byte(4), statusBytes[0],
			"evicted prover status should be 4 (kicked)")

		kickBytes, err := rdfMultiprover.Get(
			global.GLOBAL_RDF_SCHEMA,
			"prover:Prover", "KickFrameNumber", tree,
		)
		require.NoError(t, err)
		assert.Equal(t, currentFrame, binary.BigEndian.Uint64(kickBytes),
			"evicted prover KickFrameNumber should be set to current frame")
	}

	// Verify non-evicted provers' vertex data is unchanged
	for _, addr := range [][]byte{recentAddr, exemptAddr} {
		var fullAddress [64]byte
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], addr)

		tree, err := hg.GetVertexData(fullAddress)
		require.NoError(t, err)
		require.NotNil(t, tree)

		statusBytes, err := rdfMultiprover.Get(
			global.GLOBAL_RDF_SCHEMA,
			"prover:Prover", "Status", tree,
		)
		require.NoError(t, err)
		assert.Equal(t, byte(1), statusBytes[0],
			"non-evicted prover status should remain 1 (active)")
	}

	t.Logf("EvictInactiveProvers test completed successfully:")
	t.Logf("  - Stale prover (gap 400 > 360): evicted")
	t.Logf("  - Recent prover (gap 100 < 360): safe")
	t.Logf("  - Exempt shard prover: safe")
	t.Logf("  - Joining prover: safe (not Active status)")
	t.Logf("  - Mixed prover (one stale allocation): evicted")
	t.Logf("  - Evicted provers have Status=4, KickFrameNumber=%d", currentFrame)
}
