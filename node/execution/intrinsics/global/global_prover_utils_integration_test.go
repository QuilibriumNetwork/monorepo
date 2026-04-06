//go:build integrationtest
// +build integrationtest

package global_test

import (
	"encoding/binary"
	"math/big"
	"slices"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// setupProverWithAllocations creates a prover vertex with the given number of
// allocations and returns everything needed for UpdateAggregateProverStatus
// tests. Each allocation is created with the given initial status. The prover
// is created with initialProverStatus.
func setupProverWithAllocations(
	t *testing.T,
	hg hypergraph.Hypergraph,
	ip *bls48581.KZGInclusionProver,
	rm *schema.RDFMultiprover,
	initialProverStatus byte,
	allocationStatuses []byte,
) (
	proverAddr []byte,
	proverTree *qcrypto.VectorCommitmentTree,
	allocationAddresses [][]byte,
	allocationTrees []*qcrypto.VectorCommitmentTree,
) {
	// Generate a deterministic public key
	pubKey := make([]byte, 585)
	for i := range pubKey {
		pubKey[i] = byte((i + 7) % 251)
	}
	addrBI, err := poseidon.HashBytes(pubKey)
	require.NoError(t, err)
	proverAddr = addrBI.FillBytes(make([]byte, 32))

	// Create prover tree
	proverTree = &qcrypto.VectorCommitmentTree{}
	err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover", "PublicKey", pubKey, proverTree)
	require.NoError(t, err)
	err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover", "Status", []byte{initialProverStatus}, proverTree)
	require.NoError(t, err)

	// Create hyperedge for prover
	he := hgcrdt.NewHyperedge(
		[32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS),
		[32]byte(proverAddr),
	)

	allocationAddresses = make([][]byte, len(allocationStatuses))
	allocationTrees = make([]*qcrypto.VectorCommitmentTree, len(allocationStatuses))

	for i, status := range allocationStatuses {
		filter := make([]byte, 38)
		copy(filter, []byte("test-filter-"))
		filter[37] = byte(i)

		allocAddrBI, err := poseidon.HashBytes(
			slices.Concat([]byte("PROVER_ALLOCATION"), pubKey, filter),
		)
		require.NoError(t, err)
		allocAddr := allocAddrBI.FillBytes(make([]byte, 32))
		allocationAddresses[i] = allocAddr

		allocTree := &qcrypto.VectorCommitmentTree{}
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"allocation:ProverAllocation", "Prover", proverAddr, allocTree)
		require.NoError(t, err)
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"allocation:ProverAllocation", "ConfirmationFilter", filter, allocTree)
		require.NoError(t, err)
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"allocation:ProverAllocation", "Status", []byte{status}, allocTree)
		require.NoError(t, err)
		joinFrameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(joinFrameBytes, 100)
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"allocation:ProverAllocation", "JoinFrameNumber", joinFrameBytes, allocTree)
		require.NoError(t, err)
		allocationTrees[i] = allocTree

		allocVertex := hgcrdt.NewVertex(
			[32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS),
			[32]byte(allocAddr),
			allocTree.Commit(ip, false),
			big.NewInt(0),
		)
		he.AddExtrinsic(allocVertex)
	}

	// Persist everything in a single transaction
	txn, err := hg.NewTransaction(false)
	require.NoError(t, err)

	// Add prover vertex
	proverVertex := hgcrdt.NewVertex(
		[32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS),
		[32]byte(proverAddr),
		proverTree.Commit(ip, false),
		big.NewInt(0),
	)
	err = hg.AddVertex(txn, proverVertex)
	require.NoError(t, err)
	err = hg.SetVertexData(
		txn,
		[64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], proverAddr)),
		proverTree,
	)
	require.NoError(t, err)

	// Add allocation vertices
	for i, allocAddr := range allocationAddresses {
		allocVertex := hgcrdt.NewVertex(
			[32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS),
			[32]byte(allocAddr),
			allocationTrees[i].Commit(ip, false),
			big.NewInt(0),
		)
		err = hg.AddVertex(txn, allocVertex)
		require.NoError(t, err)
		err = hg.SetVertexData(
			txn,
			[64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], allocAddr)),
			allocationTrees[i],
		)
		require.NoError(t, err)
	}

	// Add hyperedge
	err = hg.AddHyperedge(txn, he)
	require.NoError(t, err)
	err = txn.Commit()
	require.NoError(t, err)

	return proverAddr, proverTree, allocationAddresses, allocationTrees
}

// updateAllocationStatus updates an allocation's status in the hypergraph and
// returns the updated tree.
func updateAllocationStatus(
	t *testing.T,
	hg hypergraph.Hypergraph,
	ip *bls48581.KZGInclusionProver,
	rm *schema.RDFMultiprover,
	allocAddr []byte,
	allocTree *qcrypto.VectorCommitmentTree,
	newStatus byte,
) {
	err := rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation", "Status", []byte{newStatus}, allocTree)
	require.NoError(t, err)

	txn, err := hg.NewTransaction(false)
	require.NoError(t, err)

	allocVertex := hgcrdt.NewVertex(
		[32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS),
		[32]byte(allocAddr),
		allocTree.Commit(ip, false),
		big.NewInt(0),
	)
	err = hg.AddVertex(txn, allocVertex)
	require.NoError(t, err)
	err = hg.SetVertexData(
		txn,
		[64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], allocAddr)),
		allocTree,
	)
	require.NoError(t, err)
	err = txn.Commit()
	require.NoError(t, err)
}

// readProverStatus reads the prover's Status field from the given tree.
func readProverStatus(
	t *testing.T,
	rm *schema.RDFMultiprover,
	proverTree *qcrypto.VectorCommitmentTree,
) byte {
	statusBytes, err := rm.Get(
		global.GLOBAL_RDF_SCHEMA,
		"prover:Prover",
		"Status",
		proverTree,
	)
	require.NoError(t, err)
	require.Len(t, statusBytes, 1)
	return statusBytes[0]
}

func TestUpdateAggregateProverStatus_OneActiveOneJoining(t *testing.T) {
	hg, ip, rm := createHypergraph(t)

	// Two allocations: both start as joining (0), then we confirm one (1)
	proverAddr, proverTree, allocationAddresses, allocationTrees :=
		setupProverWithAllocations(t, hg, ip, rm, 0, []byte{0, 0})

	// Update first allocation to active
	updateAllocationStatus(t, hg, ip, rm, allocationAddresses[0], allocationTrees[0], 1)

	state := hgstate.NewHypergraphState(hg)
	frameNumber := uint64(200)
	err := global.UpdateAggregateProverStatus(state, proverAddr, frameNumber, proverTree, rm)
	require.NoError(t, err)

	// Active (1) beats joining (0)
	assert.Equal(t, byte(1), readProverStatus(t, rm, proverTree))

	// Verify the changeset was recorded
	_ = allocationAddresses
	assert.NotEmpty(t, state.Changeset())
}

func TestUpdateAggregateProverStatus_OneActiveOnePaused(t *testing.T) {
	hg, ip, rm := createHypergraph(t)

	// Two allocations: one active, one paused
	proverAddr, proverTree, _, _ :=
		setupProverWithAllocations(t, hg, ip, rm, 0, []byte{1, 2})

	state := hgstate.NewHypergraphState(hg)
	err := global.UpdateAggregateProverStatus(state, proverAddr, 200, proverTree, rm)
	require.NoError(t, err)

	// Active (1) beats paused (2)
	assert.Equal(t, byte(1), readProverStatus(t, rm, proverTree))
}

func TestUpdateAggregateProverStatus_BothLeft(t *testing.T) {
	hg, ip, rm := createHypergraph(t)

	// Two allocations, both left (4)
	proverAddr, proverTree, _, _ :=
		setupProverWithAllocations(t, hg, ip, rm, 1, []byte{4, 4})

	state := hgstate.NewHypergraphState(hg)
	err := global.UpdateAggregateProverStatus(state, proverAddr, 200, proverTree, rm)
	require.NoError(t, err)

	// All left → prover is left (4)
	assert.Equal(t, byte(4), readProverStatus(t, rm, proverTree))
}

func TestUpdateAggregateProverStatus_MixedThreeAllocations(t *testing.T) {
	hg, ip, rm := createHypergraph(t)

	// Three allocations: left (4), active (1), joining (0)
	proverAddr, proverTree, _, _ :=
		setupProverWithAllocations(t, hg, ip, rm, 0, []byte{4, 1, 0})

	state := hgstate.NewHypergraphState(hg)
	err := global.UpdateAggregateProverStatus(state, proverAddr, 200, proverTree, rm)
	require.NoError(t, err)

	// Active (1) beats everything
	assert.Equal(t, byte(1), readProverStatus(t, rm, proverTree))
}

func TestUpdateAggregateProverStatus_SequentialTransitions(t *testing.T) {
	hg, ip, rm := createHypergraph(t)

	// Start with 2 allocations, both joining (0)
	proverAddr, proverTree, allocAddrs, allocTrees :=
		setupProverWithAllocations(t, hg, ip, rm, 0, []byte{0, 0})

	frameNumber := uint64(200)

	// Step 1: Confirm first allocation → active (1)
	updateAllocationStatus(t, hg, ip, rm, allocAddrs[0], allocTrees[0], 1)
	state := hgstate.NewHypergraphState(hg)
	err := global.UpdateAggregateProverStatus(state, proverAddr, frameNumber, proverTree, rm)
	require.NoError(t, err)
	err = state.Commit()
	require.NoError(t, err)
	assert.Equal(t, byte(1), readProverStatus(t, rm, proverTree),
		"one active + one joining → active")

	// Step 2: Confirm second allocation → active (1)
	frameNumber++
	updateAllocationStatus(t, hg, ip, rm, allocAddrs[1], allocTrees[1], 1)
	state = hgstate.NewHypergraphState(hg)
	err = global.UpdateAggregateProverStatus(state, proverAddr, frameNumber, proverTree, rm)
	require.NoError(t, err)
	err = state.Commit()
	require.NoError(t, err)
	assert.Equal(t, byte(1), readProverStatus(t, rm, proverTree),
		"both active → active")

	// Step 3: Pause first allocation (2)
	frameNumber++
	updateAllocationStatus(t, hg, ip, rm, allocAddrs[0], allocTrees[0], 2)
	state = hgstate.NewHypergraphState(hg)
	err = global.UpdateAggregateProverStatus(state, proverAddr, frameNumber, proverTree, rm)
	require.NoError(t, err)
	err = state.Commit()
	require.NoError(t, err)
	assert.Equal(t, byte(1), readProverStatus(t, rm, proverTree),
		"one paused + one active → active")

	// Step 4: Pause second allocation (2)
	frameNumber++
	updateAllocationStatus(t, hg, ip, rm, allocAddrs[1], allocTrees[1], 2)
	state = hgstate.NewHypergraphState(hg)
	err = global.UpdateAggregateProverStatus(state, proverAddr, frameNumber, proverTree, rm)
	require.NoError(t, err)
	err = state.Commit()
	require.NoError(t, err)
	assert.Equal(t, byte(2), readProverStatus(t, rm, proverTree),
		"both paused → paused")

	// Step 5: Resume first allocation (1)
	frameNumber++
	updateAllocationStatus(t, hg, ip, rm, allocAddrs[0], allocTrees[0], 1)
	state = hgstate.NewHypergraphState(hg)
	err = global.UpdateAggregateProverStatus(state, proverAddr, frameNumber, proverTree, rm)
	require.NoError(t, err)
	err = state.Commit()
	require.NoError(t, err)
	assert.Equal(t, byte(1), readProverStatus(t, rm, proverTree),
		"one active + one paused → active")

	// Step 6: Leave second allocation (3)
	frameNumber++
	updateAllocationStatus(t, hg, ip, rm, allocAddrs[1], allocTrees[1], 3)
	state = hgstate.NewHypergraphState(hg)
	err = global.UpdateAggregateProverStatus(state, proverAddr, frameNumber, proverTree, rm)
	require.NoError(t, err)
	err = state.Commit()
	require.NoError(t, err)
	assert.Equal(t, byte(1), readProverStatus(t, rm, proverTree),
		"one active + one leaving → active")
}
