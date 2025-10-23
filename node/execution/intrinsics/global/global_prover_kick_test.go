package global_test

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	thypergraph "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// Helper function to create test frame headers
func createTestFrameHeader(frameNumber uint64, pubKey []byte, bitmask []byte, output []byte) ([]byte, error) {
	header := &protobufs.FrameHeader{
		FrameNumber: frameNumber,
		PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
			PublicKey: &protobufs.BLS48581G2PublicKey{
				KeyValue: pubKey,
			},
			Signature: []byte("test-signature"),
			Bitmask:   bitmask,
		},
		Output: output,
	}
	return header.ToCanonicalBytes()
}

func TestProverKick_Prove(t *testing.T) {
	// Setup
	mockHypergraph := new(mocks.MockHypergraph)
	mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
	mockClockStore := new(mocks.MockClockStore)
	mockClockStore.On("GetGlobalClockFrame", mock.Anything).Return(&protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			ProverTreeCommitment: make([]byte, 64), // just needs to match shape
		},
	}, nil)

	// Test data
	frameNumber := uint64(12345)
	kickedPubKey := make([]byte, 585) // BLS48581G1 public key
	for i := range kickedPubKey {
		kickedPubKey[i] = byte(i % 256)
	}

	out1, out2 := make([]byte, 516), make([]byte, 516)
	out1[0] = 0xff
	out2[0] = 0xaa

	// Create conflicting frames with overlapping bitmasks (equivocation)
	conflictingFrame1, err := createTestFrameHeader(
		100,
		kickedPubKey,
		[]byte{0b00110011}, // Bitmask with some bits set
		out1,
	)
	require.NoError(t, err)

	conflictingFrame2, err := createTestFrameHeader(
		100, // Same frame number
		kickedPubKey,
		[]byte{0b00111100}, // Overlapping bitmask (bit 2 and 3 overlap)
		out2,
	)
	require.NoError(t, err)

	kickedAddressBI, _ := poseidon.HashBytes(kickedPubKey)

	// Setup kicked's tree with active status
	kickedTree := &tries.VectorCommitmentTree{}
	kickedTree.Insert([]byte{0}, kickedPubKey, nil, big.NewInt(585))
	kickedTree.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(1)) // status = active
	mockProver := new(mocks.MockInclusionProver)
	mockProver.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil)
	mockHypergraph.On("GetProver").Return(mockProver)
	mockHypergraph.On("GetVertex", mock.Anything).Return(
		hypergraph.NewVertex(
			[32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS),
			[32]byte(kickedAddressBI.FillBytes(make([]byte, 32))),
			make([]byte, 74),
			big.NewInt(0),
		), nil)
	mockHypergraph.On("CreateTraversalProof", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&tries.TraversalProof{}, nil)
	mockHypergraph.On("GetVertexData", mock.Anything).Return(kickedTree, nil)
	// Create the prover kick operation
	rdfMultiprover := createMockRDFMultiprover()
	proverKick, err := global.NewProverKick(
		frameNumber,
		kickedPubKey,
		conflictingFrame1,
		conflictingFrame2,
		&mocks.MockBlsConstructor{},
		&mocks.MockFrameProver{},
		mockHypergraph,
		rdfMultiprover,
		&mocks.MockProverRegistry{},
		mockClockStore,
	)
	require.NoError(t, err)

	// Call the prove function
	err = proverKick.Prove(0) // Frame number parameter is not used in the Prove method
	require.NoError(t, err)

	// Verify the fields are set correctly
	assert.Equal(t, frameNumber, proverKick.FrameNumber)
	assert.Equal(t, kickedPubKey, proverKick.KickedProverPublicKey)
	assert.Equal(t, conflictingFrame1, proverKick.ConflictingFrame1)
	assert.Equal(t, conflictingFrame2, proverKick.ConflictingFrame2)
}

func TestProverKick_Verify(t *testing.T) {
	t.Run("Valid kick with equivocation", func(t *testing.T) {
		// Setup
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		mockClockStore := new(mocks.MockClockStore)
		mockClockStore.On("GetGlobalClockFrame", mock.Anything).Return(&protobufs.GlobalFrame{
			Header: &protobufs.GlobalFrameHeader{
				ProverTreeCommitment: make([]byte, 64), // just needs to match shape
			},
		}, nil)

		// Test data
		frameNumber := uint64(12345)
		kickedPubKey := make([]byte, 585)
		for i := range kickedPubKey {
			kickedPubKey[i] = byte(i % 256)
		}

		out1, out2 := make([]byte, 516), make([]byte, 516)
		out1[0] = 0xff
		out2[0] = 0xaa

		// Create conflicting frames with overlapping bitmasks
		conflictingFrame1, err := createTestFrameHeader(
			100,
			kickedPubKey,
			[]byte{0b00110011},
			out1,
		)
		require.NoError(t, err)

		conflictingFrame2, err := createTestFrameHeader(
			100,
			kickedPubKey,
			[]byte{0b00111100}, // Overlaps with frame1
			out2,
		)
		require.NoError(t, err)

		kickedAddressBI, _ := poseidon.HashBytes(kickedPubKey)

		// Setup kicked's tree with active status
		kickedTree := &tries.VectorCommitmentTree{}
		kickedTree.Insert([]byte{0}, kickedPubKey, nil, big.NewInt(585))
		kickedTree.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(1)) // status = active
		mockProver := new(mocks.MockInclusionProver)
		mockProver.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil)
		mockMultiproof := &mocks.MockMultiproof{}
		mockMultiproof.On("FromBytes", mock.Anything).Return(nil)
		mockProver.On("NewMultiproof").Return(mockMultiproof)
		mockHypergraph.On("GetProver").Return(mockProver)
		mockHypergraph.On("GetVertex", mock.Anything).Return(
			hypergraph.NewVertex(
				[32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS),
				[32]byte(kickedAddressBI.FillBytes(make([]byte, 32))),
				make([]byte, 74),
				big.NewInt(0),
			), nil)
		mockHypergraph.On("CreateTraversalProof", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&tries.TraversalProof{}, nil)
		mockHypergraph.On("VerifyTraversalProof", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(kickedTree, nil)
		mockFrameProver := &mocks.MockFrameProver{}
		mockFrameProver.On("VerifyFrameHeaderSignature", mock.Anything, mock.Anything).Return(true, nil)
		mockProverRegistry := &mocks.MockProverRegistry{}
		mockProverRegistry.On("GetActiveProvers", mock.Anything).Return([]*consensus.ProverInfo{
			{
				PublicKey:       make([]byte, 585),
				Address:         make([]byte, 32),
				Status:          consensus.ProverStatusActive,
				KickFrameNumber: 0,
			},
			{
				PublicKey:       make([]byte, 585),
				Address:         make([]byte, 32),
				Status:          consensus.ProverStatusActive,
				KickFrameNumber: 0,
			},
			{
				PublicKey:       make([]byte, 585),
				Address:         make([]byte, 32),
				Status:          consensus.ProverStatusActive,
				KickFrameNumber: 0,
			},
			{
				PublicKey:       make([]byte, 585),
				Address:         make([]byte, 32),
				Status:          consensus.ProverStatusActive,
				KickFrameNumber: 0,
			},
			{
				PublicKey:       kickedPubKey,
				Address:         kickedAddressBI.FillBytes(make([]byte, 32)),
				Status:          consensus.ProverStatusActive,
				KickFrameNumber: 0,
			},
		}, nil)

		// Create the prover kick operation
		rdfMultiprover := createMockRDFMultiprover()
		proverKick, err := global.NewProverKick(
			frameNumber,
			kickedPubKey,
			conflictingFrame1,
			conflictingFrame2,
			&mocks.MockBlsConstructor{},
			mockFrameProver,
			mockHypergraph,
			rdfMultiprover,
			mockProverRegistry,
			mockClockStore,
		)
		require.NoError(t, err)

		err = proverKick.Prove(frameNumber)
		require.NoError(t, err)

		// Call the verify function
		valid, err := proverKick.Verify(frameNumber)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("Invalid - no equivocation (same frames)", func(t *testing.T) {
		// Setup
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		mockClockStore := new(mocks.MockClockStore)
		mockClockStore.On("GetGlobalClockFrame", mock.Anything).Return(&protobufs.GlobalFrame{
			Header: &protobufs.GlobalFrameHeader{
				ProverTreeCommitment: make([]byte, 64), // just needs to match shape
			},
		}, nil)

		// Test data
		frameNumber := uint64(12345)
		kickedPubKey := make([]byte, 585)
		for i := range kickedPubKey {
			kickedPubKey[i] = byte(i % 256)
		}

		out1 := make([]byte, 516)
		out1[0] = 0xff

		// Create identical frames (no equivocation)
		conflictingFrame1, err := createTestFrameHeader(
			100,
			kickedPubKey,
			[]byte{0b00110011},
			out1,
		)
		require.NoError(t, err)
		rdfMultiprover := createMockRDFMultiprover()

		// Create the prover kick operation with same frame twice
		proverKick, err := global.NewProverKick(
			frameNumber,
			kickedPubKey,
			conflictingFrame1,
			conflictingFrame1, // Same frame
			&mocks.MockBlsConstructor{},
			&mocks.MockFrameProver{},
			mockHypergraph,
			rdfMultiprover,
			&mocks.MockProverRegistry{},
			mockClockStore,
		)
		require.NoError(t, err)

		// Call the verify function
		valid, err := proverKick.Verify(frameNumber)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no equivocation detected")
		assert.False(t, valid)
	})

	t.Run("Invalid - different frame numbers", func(t *testing.T) {
		// Setup
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		mockClockStore := new(mocks.MockClockStore)
		mockClockStore.On("GetGlobalClockFrame", mock.Anything).Return(&protobufs.GlobalFrame{
			Header: &protobufs.GlobalFrameHeader{
				ProverTreeCommitment: make([]byte, 64), // just needs to match shape
			},
		}, nil)

		// Test data
		frameNumber := uint64(12345)
		kickedPubKey := make([]byte, 585)
		for i := range kickedPubKey {
			kickedPubKey[i] = byte(i % 256)
		}

		out1, out2 := make([]byte, 516), make([]byte, 516)
		out1[0] = 0xff
		out2[0] = 0xaa

		// Create frames at different heights
		conflictingFrame1, err := createTestFrameHeader(
			100,
			kickedPubKey,
			[]byte{0b00110011},
			out1,
		)
		require.NoError(t, err)

		conflictingFrame2, err := createTestFrameHeader(
			101, // Different frame number
			kickedPubKey,
			[]byte{0b00111100},
			out2,
		)
		require.NoError(t, err)

		mockFrameProver := new(mocks.MockFrameProver)
		mockFrameProver.On("VerifyFrameHeaderSignature", mock.Anything, mock.Anything).Return(true, nil)

		// Create the prover kick operation
		rdfMultiprover := createMockRDFMultiprover()
		proverKick, err := global.NewProverKick(
			frameNumber,
			kickedPubKey,
			conflictingFrame1,
			conflictingFrame2,
			&mocks.MockBlsConstructor{},
			mockFrameProver,
			mockHypergraph,
			rdfMultiprover,
			&mocks.MockProverRegistry{},
			mockClockStore,
		)
		require.NoError(t, err)

		// Call the verify function
		valid, err := proverKick.Verify(frameNumber)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no equivocation detected")
		assert.False(t, valid)
	})

	t.Run("Invalid - no overlapping bitmasks", func(t *testing.T) {
		// Setup
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		mockFrameProver := new(mocks.MockFrameProver)
		mockFrameProver.On("VerifyFrameHeaderSignature", mock.Anything, mock.Anything).Return(true, nil)
		mockClockStore := new(mocks.MockClockStore)
		mockClockStore.On("GetGlobalClockFrame", mock.Anything).Return(&protobufs.GlobalFrame{
			Header: &protobufs.GlobalFrameHeader{
				ProverTreeCommitment: make([]byte, 64), // just needs to match shape
			},
		}, nil)

		// Test data
		frameNumber := uint64(12345)
		kickedPubKey := make([]byte, 585)
		for i := range kickedPubKey {
			kickedPubKey[i] = byte(i % 256)
		}

		mockProverRegistry := &mocks.MockProverRegistry{}
		mockProverRegistry.On("GetActiveProvers", mock.Anything).Return([]*consensus.ProverInfo{{
			PublicKey:       kickedPubKey,
			Address:         make([]byte, 32),
			Status:          consensus.ProverStatusActive,
			KickFrameNumber: 0,
		}}, nil)

		out1, out2 := make([]byte, 516), make([]byte, 516)
		out1[0] = 0xff
		out2[0] = 0xaa

		// Create frames with non-overlapping bitmasks
		conflictingFrame1, err := createTestFrameHeader(
			100,
			kickedPubKey,
			[]byte{0b00110000}, // Bits 4-5 set
			out1,
		)
		require.NoError(t, err)

		conflictingFrame2, err := createTestFrameHeader(
			100,
			kickedPubKey,
			[]byte{0b00001100}, // Bits 2-3 set (no overlap)
			out2,
		)
		require.NoError(t, err)

		// Create the prover kick operation
		rdfMultiprover := createMockRDFMultiprover()
		proverKick, err := global.NewProverKick(
			frameNumber,
			kickedPubKey,
			conflictingFrame1,
			conflictingFrame2,
			&mocks.MockBlsConstructor{},
			mockFrameProver,
			mockHypergraph,
			rdfMultiprover,
			mockProverRegistry,
			mockClockStore,
		)
		require.NoError(t, err)

		// Call the verify function
		valid, err := proverKick.Verify(frameNumber)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no equivocation detected")
		assert.False(t, valid)
	})

	t.Run("Invalid - kicked not active", func(t *testing.T) {
		// Setup
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		mockFrameProver := new(mocks.MockFrameProver)
		mockFrameProver.On("VerifyFrameHeaderSignature", mock.Anything, mock.Anything).Return(true, nil)
		mockClockStore := new(mocks.MockClockStore)
		mockClockStore.On("GetGlobalClockFrame", mock.Anything).Return(&protobufs.GlobalFrame{
			Header: &protobufs.GlobalFrameHeader{
				ProverTreeCommitment: make([]byte, 64), // just needs to match shape
			},
		}, nil)

		// Test data
		frameNumber := uint64(12345)
		kickedPubKey := make([]byte, 585)
		for i := range kickedPubKey {
			kickedPubKey[i] = byte(i % 256)
		}

		out1, out2 := make([]byte, 516), make([]byte, 516)
		out1[0] = 0xff
		out2[0] = 0xaa

		// Create valid conflicting frames
		conflictingFrame1, err := createTestFrameHeader(
			100,
			kickedPubKey,
			[]byte{0b00110011},
			out1,
		)
		require.NoError(t, err)

		conflictingFrame2, err := createTestFrameHeader(
			100,
			kickedPubKey,
			[]byte{0b00111100},
			out2,
		)
		require.NoError(t, err)

		// Setup kicked's tree with paused status
		kickedTree := &tries.VectorCommitmentTree{}
		kickedTree.Insert([]byte{0}, kickedPubKey, nil, big.NewInt(585))
		kickedTree.Insert([]byte{1 << 2}, []byte{2}, nil, big.NewInt(3)) // status = paused

		kickedAddressBI, _ := poseidon.HashBytes(kickedPubKey)
		mockProverRegistry := &mocks.MockProverRegistry{}
		mockProverRegistry.On("GetActiveProvers", mock.Anything).Return([]*consensus.ProverInfo{{
			PublicKey:       kickedPubKey,
			Address:         kickedAddressBI.FillBytes(make([]byte, 32)),
			Status:          consensus.ProverStatusPaused,
			KickFrameNumber: 0,
		}}, nil)

		mockHypergraph.On("GetVertex", mock.Anything).Return(
			hypergraph.NewVertex(
				[32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS),
				[32]byte(kickedAddressBI.FillBytes(make([]byte, 32))),
				make([]byte, 74),
				big.NewInt(0),
			), nil)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(kickedTree, nil)
		mockHypergraph.On("VerifyTraversalProof", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)

		// Create the prover kick operation
		rdfMultiprover := createMockRDFMultiprover()
		proverKick, err := global.NewProverKick(
			frameNumber,
			kickedPubKey,
			conflictingFrame1,
			conflictingFrame2,
			&mocks.MockBlsConstructor{},
			mockFrameProver,
			mockHypergraph,
			rdfMultiprover,
			mockProverRegistry,
			mockClockStore,
		)
		require.NoError(t, err)

		// Call the verify function
		valid, err := proverKick.Verify(frameNumber)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no equivocation detected")
		assert.False(t, valid)
	})
}

func TestProverKick_Materialize(t *testing.T) {
	t.Run("Materialize kick - updates status to left", func(t *testing.T) {
		// Setup
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)
		mockClockStore := new(mocks.MockClockStore)
		mockClockStore.On("GetGlobalClockFrame", mock.Anything).Return(&protobufs.GlobalFrame{
			Header: &protobufs.GlobalFrameHeader{
				ProverTreeCommitment: make([]byte, 64), // just needs to match shape
			},
		}, nil)

		// Test data
		frameNumber := uint64(253000)
		kickedPubKey := make([]byte, 585)
		for i := range kickedPubKey {
			kickedPubKey[i] = byte(i % 256)
		}

		// Compute kicked address
		kickedAddressBI, err := poseidon.HashBytes(kickedPubKey)
		require.NoError(t, err)
		kickedAddress := kickedAddressBI.FillBytes(make([]byte, 32))
		mockProverRegistry := &mocks.MockProverRegistry{}
		mockProverRegistry.On("GetActiveProvers", mock.Anything).Return([]*consensus.ProverInfo{{
			PublicKey:       kickedPubKey,
			Address:         kickedAddress,
			Status:          consensus.ProverStatusActive,
			KickFrameNumber: 0,
		}}, nil)

		// Create full address
		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], kickedAddress)

		out1, out2 := make([]byte, 516), make([]byte, 516)
		out1[0] = 0xff
		out2[0] = 0xaa

		// Create conflicting frames
		conflictingFrame1, err := createTestFrameHeader(
			100,
			kickedPubKey,
			[]byte{0b00110011},
			out1,
		)
		require.NoError(t, err)

		conflictingFrame2, err := createTestFrameHeader(
			100,
			kickedPubKey,
			[]byte{0b00111100},
			out2,
		)
		require.NoError(t, err)

		// Setup existing tree with active status (1)
		existingTree := &tries.VectorCommitmentTree{}
		existingTree.Insert([]byte{0}, kickedPubKey, nil, big.NewInt(585))
		existingTree.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(1)) // status = active

		// Create existing vertex
		existingVertex := hypergraph.NewVertex(
			[32]byte(fullAddress[:32]),
			[32]byte(fullAddress[32:]),
			make([]byte, 74),
			big.NewInt(586),
		)

		// Configure mock to return existing vertex and tree
		mockHypergraph.On("GetVertex", fullAddress).Return(existingVertex, nil)
		mockHypergraph.On("GetVertexData", fullAddress).Return(existingTree, nil)
		mockHypergraph.On("GetHyperedge", fullAddress).Return(&mockHyperedge{}, nil)

		// Expect the tree to be updated with left status (4) and kick frame
		mockHypergraph.On("AddVertex",
			mock.MatchedBy(func(v thypergraph.Vertex) bool {
				id := v.GetID()
				return bytes.Equal(id[:], fullAddress[:])
			}),
			mock.MatchedBy(func(tree *tries.VectorCommitmentTree) bool {
				// Check that status was updated to left (4)
				statusBytes, _ := tree.Get([]byte{1 << 2}) // Status (order 1)
				if len(statusBytes) != 1 || statusBytes[0] != 4 {
					return false
				}
				// Check that kick frame was stored at index 5 << 2
				frameBytes, _ := tree.Get([]byte{5 << 2}) // KickFrameNumber (order 5)
				if len(frameBytes) != 8 {
					return false
				}
				storedFrame := binary.BigEndian.Uint64(frameBytes)
				return storedFrame == frameNumber
			}),
		).Return(nil)

		rdfMultiprover := createMockRDFMultiprover()

		// Create the prover kick operation
		proverKick, err := global.NewProverKick(
			frameNumber,
			kickedPubKey,
			conflictingFrame1,
			conflictingFrame2,
			&mocks.MockBlsConstructor{},
			&mocks.MockFrameProver{},
			nil,
			rdfMultiprover,
			&mocks.MockProverRegistry{},
			mockClockStore,
		)
		require.NoError(t, err)

		// Call Materialize
		newState, err := proverKick.Materialize(frameNumber, hypergraphState)
		require.NoError(t, err)
		assert.NotNil(t, newState)
		assert.Equal(t, hypergraphState, newState)
	})

	t.Run("Materialize prover not found - returns error", func(t *testing.T) {
		// Setup
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)
		mockClockStore := new(mocks.MockClockStore)
		mockClockStore.On("GetGlobalClockFrame", mock.Anything).Return(&protobufs.GlobalFrame{
			Header: &protobufs.GlobalFrameHeader{
				ProverTreeCommitment: make([]byte, 64), // just needs to match shape
			},
		}, nil)

		// Test data
		frameNumber := uint64(253000)
		kickedPubKey := make([]byte, 585)
		for i := range kickedPubKey {
			kickedPubKey[i] = byte(i % 256)
		}

		// Compute kicked address
		kickedAddressBI, err := poseidon.HashBytes(kickedPubKey)
		require.NoError(t, err)
		kickedAddress := kickedAddressBI.FillBytes(make([]byte, 32))

		// Technically not a likely situation, this should error first if store is returning errors
		mockProverRegistry := &mocks.MockProverRegistry{}
		mockProverRegistry.On("GetActiveProvers", mock.Anything).Return([]*consensus.ProverInfo{{
			PublicKey:       kickedPubKey,
			Address:         kickedAddress,
			Status:          consensus.ProverStatusActive,
			KickFrameNumber: 0,
		}}, nil)

		// Create full address
		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], kickedAddress)

		out1, out2 := make([]byte, 516), make([]byte, 516)
		out1[0] = 0xff
		out2[0] = 0xaa

		// Create conflicting frames
		conflictingFrame1, _ := createTestFrameHeader(100, kickedPubKey, []byte{0b00110011}, out1)
		conflictingFrame2, _ := createTestFrameHeader(100, kickedPubKey, []byte{0b00111100}, out2)

		// Configure mock to return nil vertex (prover not found)
		mockHypergraph.On("GetVertex", fullAddress).Return(nil, assert.AnError)
		mockHypergraph.On("GetVertexData", fullAddress).Return(nil, assert.AnError)
		mockHypergraph.On("GetHyperedge", fullAddress).Return(nil, assert.AnError)

		// Create the prover kick operation
		proverKick, err := global.NewProverKick(
			frameNumber,
			kickedPubKey,
			conflictingFrame1,
			conflictingFrame2,
			&mocks.MockBlsConstructor{},
			&mocks.MockFrameProver{},
			nil,
			createMockRDFMultiprover(),
			&mocks.MockProverRegistry{},
			mockClockStore,
		)
		require.NoError(t, err)

		// Call Materialize
		newState, err := proverKick.Materialize(frameNumber, hypergraphState)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "prover not found")
		assert.Nil(t, newState)
	})

	t.Run("Materialize hypergraph add error - returns error", func(t *testing.T) {
		// Setup
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)
		mockClockStore := new(mocks.MockClockStore)
		mockClockStore.On("GetGlobalClockFrame", mock.Anything).Return(&protobufs.GlobalFrame{
			Header: &protobufs.GlobalFrameHeader{
				ProverTreeCommitment: make([]byte, 64), // just needs to match shape
			},
		}, nil)

		// Test data
		frameNumber := uint64(253000)
		kickedPubKey := make([]byte, 585)
		for i := range kickedPubKey {
			kickedPubKey[i] = byte(i % 256)
		}

		// Compute kicked address
		kickedAddressBI, err := poseidon.HashBytes(kickedPubKey)
		require.NoError(t, err)
		kickedAddress := kickedAddressBI.FillBytes(make([]byte, 32))
		// Technically not a likely situation, this should error first if store is returning errors
		mockProverRegistry := &mocks.MockProverRegistry{}
		mockProverRegistry.On("GetActiveProvers", mock.Anything).Return([]*consensus.ProverInfo{{
			PublicKey:       kickedPubKey,
			Address:         kickedAddress,
			Status:          consensus.ProverStatusActive,
			KickFrameNumber: 0,
		}}, nil)

		// Create full address
		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], kickedAddress)

		out1, out2 := make([]byte, 516), make([]byte, 516)
		out1[0] = 0xff
		out2[0] = 0xaa

		// Create conflicting frames
		conflictingFrame1, _ := createTestFrameHeader(100, kickedPubKey, []byte{0b00110011}, out1)
		conflictingFrame2, _ := createTestFrameHeader(100, kickedPubKey, []byte{0b00111100}, out2)

		// Setup existing tree with active status (1)
		existingTree := &tries.VectorCommitmentTree{}
		existingTree.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(1)) // status = active

		// Create existing vertex
		existingVertex := hypergraph.NewVertex(
			[32]byte(fullAddress[:32]),
			[32]byte(fullAddress[32:]),
			make([]byte, 74),
			big.NewInt(7),
		)

		// Configure mock to return existing vertex and tree
		mockHypergraph.On("GetVertex", fullAddress).Return(existingVertex, nil)
		mockHypergraph.On("GetVertexData", fullAddress).Return(existingTree, nil)
		mockHypergraph.On("GetHyperedge", fullAddress).Return(&mockHyperedge{}, nil)
		txn := &mocks.MockTransaction{}
		txn.On("Abort").Return(nil)
		mockHypergraph.On("NewTransaction", false).Return(txn, nil)
		mockProver := new(mocks.MockInclusionProver)
		mockProver.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil)
		mockHypergraph.On("GetProver").Return(mockProver)
		// Configure Add to return an error
		mockHypergraph.On("AddVertex",
			mock.Anything,
			mock.Anything,
		).Return(errors.New("hypergraph add error"))

		// Create the prover kick operation
		proverKick, err := global.NewProverKick(
			frameNumber,
			kickedPubKey,
			conflictingFrame1,
			conflictingFrame2,
			&mocks.MockBlsConstructor{},
			&mocks.MockFrameProver{},
			nil,
			createMockRDFMultiprover(),
			&mocks.MockProverRegistry{},
			mockClockStore,
		)
		require.NoError(t, err)

		// Call Materialize
		newState, err := proverKick.Materialize(frameNumber, hypergraphState)
		require.NoError(t, err)

		err = newState.Commit()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hypergraph add error")
	})

	t.Run("Materialize with existing data - preserves other data", func(t *testing.T) {
		// Setup
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)
		mockClockStore := new(mocks.MockClockStore)
		mockClockStore.On("GetGlobalClockFrame", mock.Anything).Return(&protobufs.GlobalFrame{
			Header: &protobufs.GlobalFrameHeader{
				ProverTreeCommitment: make([]byte, 64), // just needs to match shape
			},
		}, nil)

		// Test data
		frameNumber := uint64(253000)
		kickedPubKey := make([]byte, 585)
		for i := range kickedPubKey {
			kickedPubKey[i] = byte(i % 256)
		}

		// Compute kicked address
		kickedAddressBI, err := poseidon.HashBytes(kickedPubKey)
		require.NoError(t, err)
		kickedAddress := kickedAddressBI.FillBytes(make([]byte, 32))
		// Technically not a likely situation, this should error first if store is returning errors
		mockProverRegistry := &mocks.MockProverRegistry{}
		mockProverRegistry.On("GetActiveProvers", mock.Anything).Return([]*consensus.ProverInfo{
			{
				PublicKey:       make([]byte, 585),
				Address:         make([]byte, 32),
				Status:          consensus.ProverStatusActive,
				KickFrameNumber: 0,
			},
			{
				PublicKey:       make([]byte, 585),
				Address:         make([]byte, 32),
				Status:          consensus.ProverStatusActive,
				KickFrameNumber: 0,
			},
			{
				PublicKey:       kickedPubKey,
				Address:         kickedAddress,
				Status:          consensus.ProverStatusActive,
				KickFrameNumber: 0,
			},
		}, nil)

		// Create full address
		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], kickedAddress)

		out1, out2 := make([]byte, 516), make([]byte, 516)
		out1[0] = 0xff
		out2[0] = 0xaa

		// Create conflicting frames
		conflictingFrame1, _ := createTestFrameHeader(100, kickedPubKey, []byte{0b00110011}, out1)
		conflictingFrame2, _ := createTestFrameHeader(100, kickedPubKey, []byte{0b00111100}, out2)

		// Setup existing tree with active status and some other data
		existingTree := &tries.VectorCommitmentTree{}
		existingTree.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(1)) // status = active
		existingTree.Insert([]byte{6 << 2}, []byte("other data"), nil, big.NewInt(10))
		existingTree.Insert([]byte{8 << 2}, []byte("more data"), nil, big.NewInt(9))

		// Create existing vertex
		existingVertex := hypergraph.NewVertex(
			[32]byte(fullAddress[:32]),
			[32]byte(fullAddress[32:]),
			make([]byte, 74),
			big.NewInt(7),
		)

		// Configure mock to return existing vertex and tree
		mockHypergraph.On("GetVertex", fullAddress).Return(existingVertex, nil)
		mockHypergraph.On("GetVertexData", fullAddress).Return(existingTree, nil)
		mockHypergraph.On("GetHyperedge", fullAddress).Return(&mockHyperedge{}, nil)

		// Expect the tree to preserve existing data
		mockHypergraph.On("AddVertex",
			mock.MatchedBy(func(v thypergraph.Vertex) bool {
				id := v.GetID()
				return bytes.Equal(id[:], fullAddress[:])
			}),
			mock.MatchedBy(func(tree *tries.VectorCommitmentTree) bool {
				// Check that other data is preserved
				otherData, _ := tree.Get([]byte{6 << 2})
				if !bytes.Equal(otherData, []byte("other data")) {
					return false
				}
				moreData, _ := tree.Get([]byte{8 << 2})
				return bytes.Equal(moreData, []byte("more data"))
			}),
		).Return(nil)

		// Create the prover kick operation
		proverKick, err := global.NewProverKick(
			frameNumber,
			kickedPubKey,
			conflictingFrame1,
			conflictingFrame2,
			&mocks.MockBlsConstructor{},
			&mocks.MockFrameProver{},
			nil,
			createMockRDFMultiprover(),
			&mocks.MockProverRegistry{},
			mockClockStore,
		)
		require.NoError(t, err)

		// Call Materialize
		newState, err := proverKick.Materialize(frameNumber, hypergraphState)
		require.NoError(t, err)
		assert.NotNil(t, newState)
	})
}

func TestProverKick_GetCost(t *testing.T) {
	// Setup
	mockHypergraph := new(mocks.MockHypergraph)
	mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
	mockClockStore := new(mocks.MockClockStore)
	mockClockStore.On("GetGlobalClockFrame", mock.Anything).Return(&protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			ProverTreeCommitment: make([]byte, 64), // just needs to match shape
		},
	}, nil)

	out1, out2 := make([]byte, 516), make([]byte, 516)
	out1[0] = 0xff
	out2[0] = 0xaa

	// Test data
	frameNumber := uint64(12345)
	kickedPubKey := make([]byte, 585)
	conflictingFrame1, _ := createTestFrameHeader(100, kickedPubKey, []byte{0b00110011}, out1)
	conflictingFrame2, _ := createTestFrameHeader(100, kickedPubKey, []byte{0b00111100}, out2)

	// Create the prover kick operation
	rdfMultiprover := createMockRDFMultiprover()
	proverKick, err := global.NewProverKick(
		frameNumber,
		kickedPubKey,
		conflictingFrame1,
		conflictingFrame2,
		&mocks.MockBlsConstructor{},
		&mocks.MockFrameProver{},
		mockHypergraph,
		rdfMultiprover,
		&mocks.MockProverRegistry{},
		mockClockStore,
	)
	require.NoError(t, err)

	// Call the GetCost function
	cost, err := proverKick.GetCost()
	require.NoError(t, err)
	assert.Equal(t, int64(0), cost.Int64())
}

func TestProverKick_VerifyEquivocation(t *testing.T) {
	t.Run("Different bitmask lengths with overlap", func(t *testing.T) {
		// Setup
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		mockFrameProver := new(mocks.MockFrameProver)
		mockFrameProver.On("VerifyFrameHeaderSignature", mock.Anything, mock.Anything).Return(true, nil)
		mockClockStore := new(mocks.MockClockStore)
		mockClockStore.On("GetGlobalClockFrame", mock.Anything).Return(&protobufs.GlobalFrame{
			Header: &protobufs.GlobalFrameHeader{
				ProverTreeCommitment: make([]byte, 64), // just needs to match shape
			},
		}, nil)

		// Test data
		frameNumber := uint64(12345)
		kickedPubKey := make([]byte, 585)
		for i := range kickedPubKey {
			kickedPubKey[i] = byte(i % 256)
		}

		out1, out2 := make([]byte, 516), make([]byte, 516)
		out1[0] = 0xff
		out2[0] = 0xaa

		// Create frames with different length bitmasks but overlapping
		conflictingFrame1, err := createTestFrameHeader(
			100,
			kickedPubKey,
			[]byte{0b00110011, 0b11110000}, // 2 bytes
			out1,
		)
		require.NoError(t, err)

		conflictingFrame2, err := createTestFrameHeader(
			100,
			kickedPubKey,
			[]byte{0b00110000}, // 1 byte, overlaps with first byte of frame1
			out2,
		)
		require.NoError(t, err)

		// Setup for verify to pass
		kickedTree := &tries.VectorCommitmentTree{}
		kickedTree.Insert([]byte{0}, kickedPubKey, nil, big.NewInt(585))
		kickedTree.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(1)) // status = active
		kickedAddressBI, _ := poseidon.HashBytes(kickedPubKey)

		mockHypergraph.On("GetVertex", mock.Anything).Return(
			hypergraph.NewVertex(
				[32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS),
				[32]byte(kickedAddressBI.FillBytes(make([]byte, 32))),
				make([]byte, 74),
				big.NewInt(0),
			), nil)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(kickedTree, nil)
		mockHypergraph.On("GetHyperedge", mock.Anything).Return(&mockHyperedge{}, nil)
		mockHypergraph.On("VerifyTraversalProof", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)
		mockInclusionProver := &mocks.MockInclusionProver{}
		mp := &mocks.MockMultiproof{}
		mp.On("FromBytes", mock.Anything).Return(nil)
		mockInclusionProver.On("NewMultiproof").Return(mp)
		mockHypergraph.On("GetProver").Return(mockInclusionProver, nil)
		mockProverRegistry := &mocks.MockProverRegistry{}
		mockProverRegistry.On("GetActiveProvers", mock.Anything).Return([]*consensus.ProverInfo{
			{
				PublicKey:       make([]byte, 585),
				Address:         make([]byte, 32),
				Status:          consensus.ProverStatusActive,
				KickFrameNumber: 0,
			},
			{
				PublicKey:       make([]byte, 585),
				Address:         make([]byte, 32),
				Status:          consensus.ProverStatusActive,
				KickFrameNumber: 0,
			},
			{
				PublicKey:       make([]byte, 585),
				Address:         make([]byte, 32),
				Status:          consensus.ProverStatusActive,
				KickFrameNumber: 0,
			},
			{
				PublicKey:       make([]byte, 585),
				Address:         make([]byte, 32),
				Status:          consensus.ProverStatusActive,
				KickFrameNumber: 0,
			},
			{
				PublicKey:       kickedPubKey,
				Address:         kickedAddressBI.FillBytes(make([]byte, 32)),
				Status:          consensus.ProverStatusActive,
				KickFrameNumber: 0,
			},
		}, nil)
		// Create the prover kick operation
		rdfMultiprover := createMockRDFMultiprover()
		proverKick, err := global.NewProverKick(
			frameNumber,
			kickedPubKey,
			conflictingFrame1,
			conflictingFrame2,
			&mocks.MockBlsConstructor{},
			mockFrameProver,
			mockHypergraph,
			rdfMultiprover,
			mockProverRegistry,
			mockClockStore,
		)
		require.NoError(t, err)
		proverKick.Proof = []byte{0x00}
		proverKick.Commitment = []byte{0x00}
		mockHypergraph.On("CreateTraversalProof", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&tries.TraversalProof{}, nil)

		// Call the verify function
		valid, err := proverKick.Verify(frameNumber)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("Missing BLS signature in frame", func(t *testing.T) {
		// Setup
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		mockClockStore := new(mocks.MockClockStore)
		mockClockStore.On("GetGlobalClockFrame", mock.Anything).Return(&protobufs.GlobalFrame{
			Header: &protobufs.GlobalFrameHeader{
				ProverTreeCommitment: make([]byte, 64), // just needs to match shape
			},
		}, nil)

		// Test data
		frameNumber := uint64(12345)
		kickedPubKey := make([]byte, 585)

		out1, out2 := make([]byte, 516), make([]byte, 516)
		out1[0] = 0xff
		out2[0] = 0xaa

		// Create frame without BLS signature
		header1 := &protobufs.FrameHeader{
			FrameNumber: 100,
			// PublicKeySignatureBls48581 is nil
			Output: out1,
		}
		conflictingFrame1, err := proto.Marshal(header1)
		require.NoError(t, err)

		conflictingFrame2, err := createTestFrameHeader(
			100,
			kickedPubKey,
			[]byte{0b00111100},
			out2,
		)
		require.NoError(t, err)

		// Create the prover kick operation
		rdfMultiprover := createMockRDFMultiprover()
		proverKick, err := global.NewProverKick(
			frameNumber,
			kickedPubKey,
			conflictingFrame1,
			conflictingFrame2,
			&mocks.MockBlsConstructor{},
			&mocks.MockFrameProver{},
			mockHypergraph,
			rdfMultiprover,
			&mocks.MockProverRegistry{},
			mockClockStore,
		)
		require.NoError(t, err)

		// Call the verify function
		valid, err := proverKick.Verify(frameNumber)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no equivocation detected")
		assert.False(t, valid)
	})
}
