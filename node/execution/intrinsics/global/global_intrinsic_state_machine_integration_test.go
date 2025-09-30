//go:build integrationtest
// +build integrationtest

package global_test

import (
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	"source.quilibrium.com/quilibrium/monorepo/config"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	tkeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

// Helper function to create test environment
func setupTestEnvironment(t *testing.T) (*keys.InMemoryKeyManager, hypergraph.Hypergraph, *hgstate.HypergraphState, *schema.RDFMultiprover) {
	// Create a key manager with BLS48581 keys
	keyManager := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, &bulletproofs.Decaf448KeyConstructor{})
	_, _, err := keyManager.CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
	require.NoError(t, err)

	// Create a hypergraph
	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hgcrdt.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)

	// Create hypergraph state
	state := hgstate.NewHypergraphState(hg)

	// Create RDFMultiprover with the real inclusion prover
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	return keyManager, hg, state, rdfMultiprover
}

// Helper function to materialize and commit state
func materializeAndCommit(t *testing.T, op intrinsics.IntrinsicOperation, frameNumber uint64, state *hgstate.HypergraphState, hg hypergraph.Hypergraph) *hgstate.HypergraphState {
	newState, err := op.Materialize(frameNumber, state)
	require.NoError(t, err)
	state = newState.(*hgstate.HypergraphState)

	// Commit the state to make changes visible to the hypergraph
	err = state.Commit()
	require.NoError(t, err)

	// Create a fresh state to avoid conflicting changes
	return hgstate.NewHypergraphState(hg)
}

// Helper function to get prover address
func getProverAddress(t *testing.T, keyManager tkeys.KeyManager) []byte {
	signer, err := keyManager.GetSigningKey("q-prover-key")
	require.NoError(t, err)
	addressBI, err := poseidon.HashBytes(signer.Public().([]byte))
	require.NoError(t, err)
	return addressBI.FillBytes(make([]byte, 32))
}

// Helper function to check prover status
func checkProverStatus(t *testing.T, state *hgstate.HypergraphState, address []byte, expectedStatus uint8, rdfMultiprover *schema.RDFMultiprover) {
	fullAddress := [64]byte{}
	copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(fullAddress[32:], address)

	tree, err := state.Get(
		fullAddress[:32],
		fullAddress[32:],
		hgstate.VertexAddsDiscriminator,
	)
	require.NoError(t, err)
	require.NotNil(t, tree)

	statusBytes, err := rdfMultiprover.Get(
		global.GLOBAL_RDF_SCHEMA,
		"prover:Prover",
		"Status",
		tree.(*tries.VectorCommitmentTree),
	)
	require.NoError(t, err)
	require.Len(t, statusBytes, 1)
	assert.Equal(t, expectedStatus, statusBytes[0])
}

// Test the complete join -> confirm flow
func TestProverJoinConfirmFlow(t *testing.T) {
	keyManager, hg, state, rdfMultiprover := setupTestEnvironment(t)
	address := getProverAddress(t, keyManager)
	filter := []byte("test-filter")

	// Test 1: Join at frame 252840
	t.Run("Join and confirm after 360 frames", func(t *testing.T) {
		joinFrame := uint64(252840)

		// Create and prove join
		proverJoin, err := global.NewProverJoin([][]byte{filter}, joinFrame, nil, nil, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverJoin.Prove(joinFrame)
		require.NoError(t, err)

		// Materialize join
		state = materializeAndCommit(t, proverJoin, joinFrame, state, hg)

		// Check status is joining (0)
		checkProverStatus(t, state, address, 0, rdfMultiprover)

		// Try to confirm too early (should fail in verify)
		confirmFrame := joinFrame + 359
		proverConfirm, err := global.NewProverConfirm(filter, confirmFrame, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverConfirm.Prove(confirmFrame)
		require.NoError(t, err)

		valid, err := proverConfirm.Verify(confirmFrame)
		assert.False(t, valid)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must wait 360 frames")

		// Confirm at exactly 360 frames (should succeed)
		confirmFrame = joinFrame + 360
		proverConfirm, err = global.NewProverConfirm(filter, confirmFrame, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverConfirm.Prove(confirmFrame)
		require.NoError(t, err)

		valid, err = proverConfirm.Verify(confirmFrame)
		assert.True(t, valid)
		assert.NoError(t, err)

		// Materialize confirm
		state = materializeAndCommit(t, proverConfirm, confirmFrame, state, hg)

		// Check status is active (1)
		checkProverStatus(t, state, address, 1, rdfMultiprover)
	})
}

// Test the join -> reject flow
func TestProverJoinRejectFlow(t *testing.T) {
	keyManager, hg, state, rdfMultiprover := setupTestEnvironment(t)
	address := getProverAddress(t, keyManager)
	filter := []byte("test-filter")

	t.Run("Join and reject immediately", func(t *testing.T) {
		joinFrame := uint64(252840)

		// Create and prove join
		proverJoin, err := global.NewProverJoin([][]byte{filter}, joinFrame, nil, nil, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverJoin.Prove(joinFrame)
		require.NoError(t, err)

		// Materialize join
		state = materializeAndCommit(t, proverJoin, joinFrame, state, hg)

		// Check status is joining (0)
		checkProverStatus(t, state, address, 0, rdfMultiprover)

		// Reject immediately (should succeed)
		rejectFrame := joinFrame + 10
		proverReject, err := global.NewProverReject(filter, rejectFrame, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverReject.Prove(rejectFrame)
		require.NoError(t, err)

		valid, err := proverReject.Verify(rejectFrame)
		assert.True(t, valid)
		assert.NoError(t, err)

		// Materialize reject
		state = materializeAndCommit(t, proverReject, rejectFrame, state, hg)

		// Check status is left (4)
		checkProverStatus(t, state, address, 4, rdfMultiprover)
	})
}

// Test the pause/resume flow
func TestProverPauseResumeFlow(t *testing.T) {
	keyManager, hg, state, rdfMultiprover := setupTestEnvironment(t)
	address := getProverAddress(t, keyManager)
	filter := []byte("test-filter")

	// First join and confirm to get to active state
	joinFrame := uint64(252840)
	proverJoin, err := global.NewProverJoin([][]byte{filter}, joinFrame, nil, nil, keyManager, hg, rdfMultiprover)
	require.NoError(t, err)
	err = proverJoin.Prove(joinFrame)
	require.NoError(t, err)
	state = materializeAndCommit(t, proverJoin, joinFrame, state, hg)

	confirmFrame := joinFrame + 360
	proverConfirm, err := global.NewProverConfirm(filter, confirmFrame, keyManager, hg, rdfMultiprover)
	require.NoError(t, err)
	err = proverConfirm.Prove(confirmFrame)
	require.NoError(t, err)
	state = materializeAndCommit(t, proverConfirm, confirmFrame, state, hg)

	// Now test pause/resume
	t.Run("Pause and resume within 360 frames", func(t *testing.T) {
		pauseFrame := confirmFrame + 100

		// Pause
		proverPause, err := global.NewProverPause(filter, pauseFrame, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverPause.Prove(pauseFrame)
		require.NoError(t, err)

		valid, err := proverPause.Verify(pauseFrame)
		assert.True(t, valid)
		assert.NoError(t, err)

		// Materialize pause
		state = materializeAndCommit(t, proverPause, pauseFrame, state, hg)

		// Check status is paused (2)
		checkProverStatus(t, state, address, 2, rdfMultiprover)

		// Resume within 360 frames
		resumeFrame := pauseFrame + 300
		proverResume, err := global.NewProverResume(filter, resumeFrame, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverResume.Prove(resumeFrame)
		require.NoError(t, err)

		valid, err = proverResume.Verify(resumeFrame)
		assert.True(t, valid)
		assert.NoError(t, err)

		// Materialize resume
		state = materializeAndCommit(t, proverResume, resumeFrame, state, hg)

		// Check status is active (1)
		checkProverStatus(t, state, address, 1, rdfMultiprover)
	})
}

// Test the leave flow
func TestProverLeaveFlow(t *testing.T) {
	keyManager, hg, state, rdfMultiprover := setupTestEnvironment(t)
	address := getProverAddress(t, keyManager)
	filter := []byte("test-filter")

	// First join and confirm to get to active state
	joinFrame := uint64(252840)
	proverJoin, err := global.NewProverJoin([][]byte{filter}, joinFrame, nil, nil, keyManager, hg, rdfMultiprover)
	require.NoError(t, err)
	err = proverJoin.Prove(joinFrame)
	require.NoError(t, err)
	state = materializeAndCommit(t, proverJoin, joinFrame, state, hg)

	confirmFrame := joinFrame + 360
	proverConfirm, err := global.NewProverConfirm(filter, confirmFrame, keyManager, hg, rdfMultiprover)
	require.NoError(t, err)
	err = proverConfirm.Prove(confirmFrame)
	require.NoError(t, err)
	state = materializeAndCommit(t, proverConfirm, confirmFrame, state, hg)

	t.Run("Leave and confirm after 360 frames", func(t *testing.T) {
		leaveFrame := confirmFrame + 100

		// Leave
		proverLeave, err := global.NewProverLeave([][]byte{filter}, leaveFrame, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverLeave.Prove(leaveFrame)
		require.NoError(t, err)

		valid, err := proverLeave.Verify(leaveFrame)
		assert.True(t, valid)
		assert.NoError(t, err)

		// Materialize leave
		state = materializeAndCommit(t, proverLeave, leaveFrame, state, hg)

		// Check status is leaving (3)
		checkProverStatus(t, state, address, 3, rdfMultiprover)

		// Try to confirm too early
		confirmLeaveFrame := leaveFrame + 359
		proverConfirmLeave, err := global.NewProverConfirm(filter, confirmLeaveFrame, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverConfirmLeave.Prove(confirmLeaveFrame)
		require.NoError(t, err)

		valid, err = proverConfirmLeave.Verify(confirmLeaveFrame)
		assert.False(t, valid)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must wait 360 frames")

		// Confirm leave after 360 frames
		confirmLeaveFrame = leaveFrame + 360
		proverConfirmLeave, err = global.NewProverConfirm(filter, confirmLeaveFrame, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverConfirmLeave.Prove(confirmLeaveFrame)
		require.NoError(t, err)

		valid, err = proverConfirmLeave.Verify(confirmLeaveFrame)
		assert.True(t, valid)
		assert.NoError(t, err)

		// Materialize confirm leave
		state = materializeAndCommit(t, proverConfirmLeave, confirmLeaveFrame, state, hg)

		// Check status is left (4)
		checkProverStatus(t, state, address, 4, rdfMultiprover)
	})
}

// Test the leave -> reject (cancel leave) flow
func TestProverLeaveRejectFlow(t *testing.T) {
	keyManager, hg, state, rdfMultiprover := setupTestEnvironment(t)
	address := getProverAddress(t, keyManager)
	filter := []byte("test-filter")

	// First join and confirm to get to active state
	joinFrame := uint64(252840)
	proverJoin, err := global.NewProverJoin([][]byte{filter}, joinFrame, nil, nil, keyManager, hg, rdfMultiprover)
	require.NoError(t, err)
	err = proverJoin.Prove(joinFrame)
	require.NoError(t, err)
	state = materializeAndCommit(t, proverJoin, joinFrame, state, hg)

	confirmFrame := joinFrame + 360
	proverConfirm, err := global.NewProverConfirm(filter, confirmFrame, keyManager, hg, rdfMultiprover)
	require.NoError(t, err)
	err = proverConfirm.Prove(confirmFrame)
	require.NoError(t, err)
	state = materializeAndCommit(t, proverConfirm, confirmFrame, state, hg)

	t.Run("Leave and reject to stay active", func(t *testing.T) {
		leaveFrame := confirmFrame + 100

		// Leave
		proverLeave, err := global.NewProverLeave([][]byte{filter}, leaveFrame, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverLeave.Prove(leaveFrame)
		require.NoError(t, err)
		state = materializeAndCommit(t, proverLeave, leaveFrame, state, hg)

		// Check status is leaving (3)
		checkProverStatus(t, state, address, 3, rdfMultiprover)

		// Reject leave after 360 frames
		rejectLeaveFrame := leaveFrame + 360
		proverRejectLeave, err := global.NewProverReject(filter, rejectLeaveFrame, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverRejectLeave.Prove(rejectLeaveFrame)
		require.NoError(t, err)

		valid, err := proverRejectLeave.Verify(rejectLeaveFrame)
		assert.True(t, valid)
		assert.NoError(t, err)

		// Materialize reject leave
		state = materializeAndCommit(t, proverRejectLeave, rejectLeaveFrame, state, hg)

		// Check status is back to active (1)
		checkProverStatus(t, state, address, 1, rdfMultiprover)
	})
}

// Test timing edge cases
func TestProverTimingEdgeCases(t *testing.T) {
	keyManager, hg, state, rdfMultiprover := setupTestEnvironment(t)
	filter := []byte("test-filter")

	t.Run("Join before 252840 with special confirmation rules", func(t *testing.T) {
		joinFrame := uint64(252000)

		// Create and prove join
		proverJoin, err := global.NewProverJoin([][]byte{filter}, joinFrame, nil, nil, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverJoin.Prove(joinFrame)
		require.NoError(t, err)

		// Materialize join
		state = materializeAndCommit(t, proverJoin, joinFrame, state, hg)

		// Try to confirm before frame 252840 (should fail)
		confirmFrame := uint64(252839)
		proverConfirm, err := global.NewProverConfirm(filter, confirmFrame, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverConfirm.Prove(confirmFrame)
		require.NoError(t, err)

		valid, err := proverConfirm.Verify(confirmFrame)
		assert.False(t, valid)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot confirm before frame 252840")

		// Confirm at frame 252840 (should succeed even though less than 360 frames)
		confirmFrame = uint64(252840)
		proverConfirm, err = global.NewProverConfirm(filter, confirmFrame, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverConfirm.Prove(confirmFrame)
		require.NoError(t, err)

		valid, err = proverConfirm.Verify(confirmFrame)
		assert.True(t, valid)
		assert.NoError(t, err)
	})

	t.Run("Pause timeout causes implicit leave", func(t *testing.T) {
		// First get to active state
		joinFrame := uint64(252840)
		proverJoin, err := global.NewProverJoin([][]byte{filter}, joinFrame, nil, nil, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverJoin.Prove(joinFrame)
		require.NoError(t, err)
		state = materializeAndCommit(t, proverJoin, joinFrame, state, hg)

		confirmFrame := joinFrame + 360
		proverConfirm, err := global.NewProverConfirm(filter, confirmFrame, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverConfirm.Prove(confirmFrame)
		require.NoError(t, err)
		state = materializeAndCommit(t, proverConfirm, confirmFrame, state, hg)

		// Pause
		pauseFrame := confirmFrame + 100
		proverPause, err := global.NewProverPause(filter, pauseFrame, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverPause.Prove(pauseFrame)
		require.NoError(t, err)
		state = materializeAndCommit(t, proverPause, pauseFrame, state, hg)

		// Try to resume after 361 frames (should fail)
		resumeFrame := pauseFrame + 361
		proverResume, err := global.NewProverResume(filter, resumeFrame, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverResume.Prove(resumeFrame)
		require.NoError(t, err)

		valid, err := proverResume.Verify(resumeFrame)
		assert.False(t, valid)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "pause timeout exceeded")
	})
}

// Test invalid state transitions
func TestProverInvalidStateTransitions(t *testing.T) {
	keyManager, hg, state, rdfMultiprover := setupTestEnvironment(t)
	filter := []byte("test-filter")

	// Join first
	joinFrame := uint64(252840)
	proverJoin, err := global.NewProverJoin([][]byte{filter}, joinFrame, nil, nil, keyManager, hg, rdfMultiprover)
	require.NoError(t, err)
	err = proverJoin.Prove(joinFrame)
	require.NoError(t, err)
	state = materializeAndCommit(t, proverJoin, joinFrame, state, hg)

	t.Run("Cannot pause while joining", func(t *testing.T) {
		pauseFrame := joinFrame + 100
		proverPause, err := global.NewProverPause(filter, pauseFrame, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverPause.Prove(pauseFrame)
		require.NoError(t, err)

		valid, err := proverPause.Verify(pauseFrame)
		assert.False(t, valid)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "can only pause when allocation is active")
	})

	t.Run("Cannot leave while joining", func(t *testing.T) {
		leaveFrame := joinFrame + 100
		proverLeave, err := global.NewProverLeave([][]byte{filter}, leaveFrame, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverLeave.Prove(leaveFrame)
		require.NoError(t, err)

		valid, err := proverLeave.Verify(leaveFrame)
		assert.False(t, valid)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no active allocations found for specified filters")
	})

	t.Run("Cannot resume while joining", func(t *testing.T) {
		resumeFrame := joinFrame + 100
		proverResume, err := global.NewProverResume(filter, resumeFrame, keyManager, hg, rdfMultiprover)
		require.NoError(t, err)
		err = proverResume.Prove(resumeFrame)
		require.NoError(t, err)

		valid, err := proverResume.Verify(resumeFrame)
		assert.False(t, valid)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "can only resume when allocation is paused")
	})
}
