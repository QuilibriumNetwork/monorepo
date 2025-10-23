package global_test

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"slices"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	thypergraph "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// Helper function to create a mock rdfMultiprover for tests
func createMockRDFMultiprover() *schema.RDFMultiprover {
	mockInclusionProver := new(mocks.MockInclusionProver)
	mockInclusionProver.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil)
	multiproof := &mocks.MockMultiproof{}
	multiproof.On("ToBytes").Return(make([]byte, 74+74), nil)
	multiproof.On("GetMulticommitment").Return(make([]byte, 74))
	multiproof.On("GetProof").Return(make([]byte, 74))
	multiproof.On("FromBytes", mock.Anything).Return(nil)
	mockInclusionProver.On("NewMultiproof").Return(multiproof)
	mockInclusionProver.On("VerifyMultiple", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)
	mockInclusionProver.On("ProveMultiple", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(multiproof, nil)
	parser := &schema.TurtleRDFParser{}
	return schema.NewRDFMultiprover(parser, mockInclusionProver)
}

func TestProverResume_Prove(t *testing.T) {
	// Setup
	mockKeyManager := new(mocks.MockKeyManager)

	// Test data
	filter := []byte("testfilter")
	frameNumber := uint64(12345)
	pubKey := make([]byte, 585) // Simulate a BLS48581G1 public key
	for i := range pubKey {
		pubKey[i] = byte(i % 256)
	}

	// Compute expected address
	addressBI, err := poseidon.HashBytes(pubKey)
	require.NoError(t, err)
	address := addressBI.FillBytes(make([]byte, 32))

	// Create expected domain for resume signature
	resumeDomainPreimage := slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], []byte("PROVER_RESUME"))
	resumeDomain, err := poseidon.HashBytes(resumeDomainPreimage)
	require.NoError(t, err)

	// Create expected message
	expectedMessage := make([]byte, 0, len(filter)+8)
	expectedMessage = append(expectedMessage, filter...)
	frameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameBytes, frameNumber)
	expectedMessage = append(expectedMessage, frameBytes...)

	// Configure mock signer
	mockSigner := &mocks.MockBLSSigner{}
	mockSigner.On("Public").Return(pubKey)
	mockSigner.On("SignWithDomain", expectedMessage, resumeDomain.Bytes()).
		Return([]byte("signature"), nil)

	// Configure mock key manager
	mockKeyManager.On("GetSigningKey", "q-prover-key").Return(mockSigner, nil)

	// Create the prover resume operation
	rdfMultiprover := createMockRDFMultiprover()
	proverResume, err := global.NewProverResume(filter, frameNumber, mockKeyManager, nil, rdfMultiprover)
	require.NoError(t, err)

	// Call the prove function
	err = proverResume.Prove(0) // Frame number parameter is not used in the Prove method
	require.NoError(t, err)

	// Verify the results
	assert.NotNil(t, proverResume.PublicKeySignatureBLS48581)
	assert.Equal(t, []byte("signature"), proverResume.PublicKeySignatureBLS48581.Signature)
	assert.Equal(t, address, proverResume.PublicKeySignatureBLS48581.Address)

	// Verify that all expected methods were called
	mockSigner.AssertExpectations(t)
	mockKeyManager.AssertExpectations(t)
}

func TestProverResume_Verify(t *testing.T) {
	t.Run("Can resume when paused within 360 frames", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)

		// Test data
		filter := []byte("testfilter")
		pauseFrame := uint64(12000)
		resumeFrame := pauseFrame + 300 // Within 360 frames
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		pubkey := make([]byte, 585)
		for i := range pubkey {
			pubkey[i] = byte(i % 256)
		}

		// Setup tree with paused status (2) and pause frame
		tree := &qcrypto.VectorCommitmentTree{}
		tree.Insert([]byte{0}, pubkey, nil, big.NewInt(585))
		tree.Insert([]byte{1 << 2}, []byte{2}, nil, big.NewInt(1)) // status = paused (order 1)
		pauseFrameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(pauseFrameBytes, pauseFrame)
		tree.Insert([]byte{6 << 2}, pauseFrameBytes, nil, big.NewInt(8)) // PauseFrameNumber (order 6)

		mockHypergraph.On("GetVertex", mock.Anything).Return(hypergraph.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(address), make([]byte, 74), big.NewInt(0)), nil)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(tree, nil)

		// Create the prover resume operation
		rdfMultiprover := createMockRDFMultiprover()
		proverResume, err := global.NewProverResume(filter, resumeFrame, mockKeyManager, mockHypergraph, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data manually
		proverResume.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Create expected domain for resume signature
		resumeDomainPreimage := slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], []byte("PROVER_RESUME"))
		resumeDomain, err := poseidon.HashBytes(resumeDomainPreimage)
		require.NoError(t, err)

		// Create expected message
		expectedMessage := make([]byte, 0, len(filter)+8)
		expectedMessage = append(expectedMessage, filter...)
		frameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(frameBytes, resumeFrame)
		expectedMessage = append(expectedMessage, frameBytes...)

		// Configure mock key manager
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeBLS48581G1,
			pubkey,
			expectedMessage,
			[]byte("signature"),
			resumeDomain.Bytes(),
		).Return(true, nil)

		// Call the verify function
		valid, err := proverResume.Verify(resumeFrame)
		require.NoError(t, err)
		assert.True(t, valid)

		// Verify that all expected methods were called
		mockKeyManager.AssertExpectations(t)
	})

	t.Run("Cannot resume after 360 frames timeout", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)

		// Test data
		filter := []byte("testfilter")
		pauseFrame := uint64(12000)
		resumeFrame := pauseFrame + 361 // Too late
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		pubkey := make([]byte, 585)
		for i := range pubkey {
			pubkey[i] = byte(i % 256)
		}

		// Setup tree with paused status (2) and pause frame
		tree := &qcrypto.VectorCommitmentTree{}
		tree.Insert([]byte{0}, pubkey, nil, big.NewInt(585))
		tree.Insert([]byte{1 << 2}, []byte{2}, nil, big.NewInt(1)) // status = paused (order 1)
		pauseFrameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(pauseFrameBytes, pauseFrame)
		tree.Insert([]byte{6 << 2}, pauseFrameBytes, nil, big.NewInt(8)) // PauseFrameNumber (order 6)

		mockHypergraph.On("GetVertex", mock.Anything).Return(hypergraph.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(address), make([]byte, 74), big.NewInt(0)), nil)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(tree, nil)

		// Create the prover resume operation
		rdfMultiprover := createMockRDFMultiprover()
		proverResume, err := global.NewProverResume(filter, resumeFrame, mockKeyManager, mockHypergraph, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data manually
		proverResume.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call the verify function
		valid, err := proverResume.Verify(resumeFrame)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "pause timeout exceeded")
		assert.False(t, valid)
	})

	t.Run("Cannot resume when not paused", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)

		// Test data
		filter := []byte("testfilter")
		frameNumber := uint64(12345)
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		pubkey := make([]byte, 585)
		for i := range pubkey {
			pubkey[i] = byte(i % 256)
		}

		// Setup tree with active status (1)
		tree := &qcrypto.VectorCommitmentTree{}
		tree.Insert([]byte{0}, pubkey, nil, big.NewInt(585))
		tree.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(1)) // status = active (order 1)

		mockHypergraph.On("GetVertex", mock.Anything).Return(hypergraph.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(address), make([]byte, 74), big.NewInt(0)), nil)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(tree, nil)
		mockHypergraph.On("VerifyTraversalProof", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)

		// Create the prover resume operation
		rdfMultiprover := createMockRDFMultiprover()
		proverResume, err := global.NewProverResume(filter, frameNumber, mockKeyManager, mockHypergraph, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data manually
		proverResume.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call the verify function
		valid, err := proverResume.Verify(frameNumber)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "can only resume when allocation is paused")
		assert.False(t, valid)
	})

	t.Run("Invalid signature fails", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)

		// Test data
		filter := []byte("testfilter")
		pauseFrame := uint64(12000)
		resumeFrame := pauseFrame + 100
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		pubkey := make([]byte, 585)
		for i := range pubkey {
			pubkey[i] = byte(i % 256)
		}

		// Setup tree with paused status (2) and pause frame
		tree := &qcrypto.VectorCommitmentTree{}
		tree.Insert([]byte{0}, pubkey, nil, big.NewInt(585))
		tree.Insert([]byte{1 << 2}, []byte{2}, nil, big.NewInt(1)) // status = paused (order 1)
		pauseFrameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(pauseFrameBytes, pauseFrame)
		tree.Insert([]byte{6 << 2}, pauseFrameBytes, nil, big.NewInt(8)) // PauseFrameNumber (order 6)

		mockHypergraph.On("GetVertex", mock.Anything).Return(hypergraph.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(address), make([]byte, 74), big.NewInt(0)), nil)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(tree, nil)

		// Create expected domain for resume signature
		resumeDomainPreimage := slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], []byte("PROVER_RESUME"))
		resumeDomain, err := poseidon.HashBytes(resumeDomainPreimage)
		require.NoError(t, err)

		// Create expected message
		expectedMessage := make([]byte, 0, len(filter)+8)
		expectedMessage = append(expectedMessage, filter...)
		frameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(frameBytes, resumeFrame)
		expectedMessage = append(expectedMessage, frameBytes...)

		// Configure mock key manager to return false
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeBLS48581G1,
			pubkey,
			expectedMessage,
			[]byte("signature"),
			resumeDomain.Bytes(),
		).Return(false, nil)

		// Create the prover resume operation
		rdfMultiprover := createMockRDFMultiprover()
		proverResume, err := global.NewProverResume(filter, resumeFrame, mockKeyManager, mockHypergraph, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data manually
		proverResume.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call the verify function
		valid, err := proverResume.Verify(resumeFrame)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signature")
		assert.False(t, valid)
	})
}

func TestProverResume_Materialize(t *testing.T) {
	t.Run("Materialize resume - updates status to active", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)

		// Test data
		filter := []byte("testfilter")
		frameNumber := uint64(253000)
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		// Create full address
		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], address)

		// Setup existing tree with paused status (2)
		proverTypeBI, _ := poseidon.HashBytes(
			slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("prover:Prover")),
		)
		existingTree := &qcrypto.VectorCommitmentTree{}
		existingTree.Insert([]byte{0}, []byte("pubkey"), nil, big.NewInt(6))
		existingTree.Insert([]byte{1 << 2}, []byte{2}, nil, big.NewInt(1)) // status = paused (order 1)
		existingTree.Insert(bytes.Repeat([]byte{0xff}, 32), proverTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(1))

		// Setup allocation tree
		allocationTypeBI, _ := poseidon.HashBytes(
			slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("allocation:ProverAllocation")),
		)
		existingAllocTree := &qcrypto.VectorCommitmentTree{}
		existingAllocTree.Insert([]byte{0}, address, nil, big.NewInt(32))
		existingAllocTree.Insert([]byte{1 << 2}, []byte{2}, nil, big.NewInt(1)) // status = paused
		existingAllocTree.Insert([]byte{2 << 2}, filter, nil, big.NewInt(32))
		existingAllocTree.Insert(bytes.Repeat([]byte{0xff}, 32), allocationTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(32))

		allocBI, _ := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), []byte("pubkey"), filter))
		alloc := allocBI.FillBytes(make([]byte, 32))
		fullAllocAddr := [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], alloc))

		// Create existing vertex
		existingVertex := hypergraph.NewVertex(
			[32]byte(fullAddress[:32]),
			[32]byte(fullAddress[32:]),
			make([]byte, 74),
			big.NewInt(7),
		)
		existingAllocVertex := hypergraph.NewVertex(
			[32]byte(fullAllocAddr[:32]),
			[32]byte(fullAllocAddr[32:]),
			make([]byte, 74),
			big.NewInt(7),
		)

		// Configure mock to return existing vertex and tree
		mockHypergraph.On("GetVertex", fullAddress).Return(existingVertex, nil)
		mockHypergraph.On("GetVertexData", fullAddress).Return(existingTree, nil)
		mockHypergraph.On("GetVertex", fullAllocAddr).Return(existingAllocVertex, nil)
		mockHypergraph.On("GetVertexData", fullAllocAddr).Return(existingAllocTree, nil)
		mockHypergraph.On("GetHyperedge", mock.Anything).Return(&mockHyperedge{}, nil)

		// Expect the allocation tree to be updated with active status and resume frame
		mockHypergraph.On("AddVertex",
			mock.MatchedBy(func(v thypergraph.Vertex) bool {
				id := v.GetID()
				return bytes.Equal(id[:], fullAllocAddr[:])
			}),
			mock.MatchedBy(func(tree *qcrypto.VectorCommitmentTree) bool {
				// Check that status was updated to active (1)
				statusBytes, _ := tree.Get([]byte{1 << 2}) // Status (order 1)
				if len(statusBytes) != 1 || statusBytes[0] != 1 {
					return false
				}
				// Check that resume frame was stored
				frameBytes, _ := tree.Get([]byte{7 << 2}) // ResumeFrameNumber (order 7)
				if len(frameBytes) != 8 {
					return false
				}
				storedFrame := binary.BigEndian.Uint64(frameBytes)
				return storedFrame == frameNumber
			}),
		).Return(nil)

		// Create the prover resume operation
		rdfMultiprover := createMockRDFMultiprover()
		proverResume, err := global.NewProverResume(filter, frameNumber, mockKeyManager, nil, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data
		proverResume.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call Materialize
		newState, err := proverResume.Materialize(1, hypergraphState)
		require.NoError(t, err)
		assert.NotNil(t, newState)
		assert.Equal(t, hypergraphState, newState)
	})

	t.Run("Materialize prover not found - returns error", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)

		// Test data
		filter := []byte("testfilter")
		frameNumber := uint64(253000)
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		// Create full address
		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], address)

		// Configure mock to return nil vertex (prover not found)
		mockHypergraph.On("GetVertex", fullAddress).Return(nil, assert.AnError)
		mockHypergraph.On("GetVertexData", fullAddress).Return(nil, assert.AnError)
		mockHypergraph.On("GetHyperedge", mock.Anything).Return(nil, assert.AnError)

		// Create the prover resume operation
		rdfMultiprover := createMockRDFMultiprover()
		proverResume, err := global.NewProverResume(filter, frameNumber, mockKeyManager, nil, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data
		proverResume.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call Materialize
		newState, err := proverResume.Materialize(frameNumber, hypergraphState)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "prover not found")
		assert.Nil(t, newState)
	})

	t.Run("Materialize hypergraph get error - returns error", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)

		// Test data
		filter := []byte("testfilter")
		frameNumber := uint64(253000)
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		// Create full address
		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], address)

		// Create existing vertex
		existingVertex := hypergraph.NewVertex(
			[32]byte(fullAddress[:32]),
			[32]byte(fullAddress[32:]),
			make([]byte, 74),
			big.NewInt(7),
		)

		// Configure mock to return vertex but error on data
		mockHypergraph.On("GetVertex", fullAddress).Return(existingVertex, nil)
		mockHypergraph.On("GetVertexData", fullAddress).Return(nil, errors.New("hypergraph get error"))
		mockHypergraph.On("GetHyperedge", mock.Anything).Return(&mockHyperedge{}, nil)

		// Create the prover resume operation
		rdfMultiprover := createMockRDFMultiprover()
		proverResume, err := global.NewProverResume(filter, frameNumber, mockKeyManager, nil, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data
		proverResume.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call Materialize
		newState, err := proverResume.Materialize(frameNumber, hypergraphState)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "prover not found")
		assert.Nil(t, newState)
	})

	t.Run("Materialize hypergraph add error - returns error", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)

		// Test data
		filter := []byte("testfilter")
		frameNumber := uint64(253000)
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		// Create full address
		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], address)

		// Setup existing tree with paused status (2)
		proverTypeBI, _ := poseidon.HashBytes(
			slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("prover:Prover")),
		)
		existingTree := &qcrypto.VectorCommitmentTree{}
		existingTree.Insert([]byte{0}, []byte("pubkey"), nil, big.NewInt(585))
		existingTree.Insert([]byte{1 << 2}, []byte{2}, nil, big.NewInt(1)) // status = paused (order 1)
		existingTree.Insert(bytes.Repeat([]byte{0xff}, 32), proverTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(1))

		// Setup allocation tree
		allocationTypeBI, _ := poseidon.HashBytes(
			slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("allocation:ProverAllocation")),
		)
		existingAllocTree := &qcrypto.VectorCommitmentTree{}
		existingAllocTree.Insert([]byte{0}, address, nil, big.NewInt(32))
		existingAllocTree.Insert([]byte{1 << 2}, []byte{2}, nil, big.NewInt(1)) // status = paused
		existingAllocTree.Insert([]byte{2 << 2}, filter, nil, big.NewInt(32))
		existingAllocTree.Insert(bytes.Repeat([]byte{0xff}, 32), allocationTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(32))

		allocBI, _ := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), []byte("pubkey"), filter))
		alloc := allocBI.FillBytes(make([]byte, 32))
		fullAllocAddr := [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], alloc))

		// Create existing vertex
		existingVertex := hypergraph.NewVertex(
			[32]byte(fullAddress[:32]),
			[32]byte(fullAddress[32:]),
			make([]byte, 74),
			big.NewInt(7),
		)
		existingAllocVertex := hypergraph.NewVertex(
			[32]byte(fullAllocAddr[:32]),
			[32]byte(fullAllocAddr[32:]),
			make([]byte, 74),
			big.NewInt(7),
		)

		// Configure mock to return existing vertex and tree
		mockHypergraph.On("GetVertex", fullAddress).Return(existingVertex, nil)
		mockHypergraph.On("GetVertexData", fullAddress).Return(existingTree, nil)
		mockHypergraph.On("GetVertex", fullAllocAddr).Return(existingAllocVertex, nil)
		mockHypergraph.On("GetVertexData", fullAllocAddr).Return(existingAllocTree, nil)
		mockHypergraph.On("GetHyperedge", mock.Anything).Return(&mockHyperedge{}, nil)
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

		// Create the prover resume operation
		rdfMultiprover := createMockRDFMultiprover()
		proverResume, err := global.NewProverResume(filter, frameNumber, mockKeyManager, nil, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data
		proverResume.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call Materialize
		newState, err := proverResume.Materialize(frameNumber, hypergraphState)
		require.NoError(t, err)

		err = newState.Commit()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hypergraph add error")
	})

	t.Run("Materialize with existing data - preserves other fields", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)

		// Test data
		filter := []byte("testfilter")
		frameNumber := uint64(253000)
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		// Create full address
		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], address)

		// Setup existing tree with paused status and some other data
		proverTypeBI, _ := poseidon.HashBytes(
			slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("prover:Prover")),
		)
		existingTree := &qcrypto.VectorCommitmentTree{}
		existingTree.Insert([]byte{0 << 2}, []byte("pubkey"), nil, big.NewInt(1))
		existingTree.Insert([]byte{1 << 2}, []byte{2}, nil, big.NewInt(1)) // status = paused (order 1)
		existingTree.Insert(bytes.Repeat([]byte{0xff}, 32), proverTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(1))

		// Setup allocation tree with extra data to preserve
		allocationTypeBI, _ := poseidon.HashBytes(
			slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("allocation:ProverAllocation")),
		)
		existingAllocTree := &qcrypto.VectorCommitmentTree{}
		existingAllocTree.Insert([]byte{0}, address, nil, big.NewInt(32))
		existingAllocTree.Insert([]byte{1 << 2}, []byte{2}, nil, big.NewInt(1)) // status = paused
		existingAllocTree.Insert([]byte{2 << 2}, filter, nil, big.NewInt(32))
		existingAllocTree.Insert([]byte{4 << 2}, []byte("join frame"), nil, big.NewInt(10))   // JoinFrameNumber (order 4)
		existingAllocTree.Insert([]byte{6 << 2}, []byte("pause frame"), nil, big.NewInt(11))  // PauseFrameNumber (order 6)
		existingAllocTree.Insert([]byte{10 << 2}, []byte("filter data"), nil, big.NewInt(11)) // ConfirmationFilter (order 10)
		existingAllocTree.Insert(bytes.Repeat([]byte{0xff}, 32), allocationTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(32))

		allocBI, _ := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), []byte("pubkey"), filter))
		alloc := allocBI.FillBytes(make([]byte, 32))
		fullAllocAddr := [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], alloc))

		// Create existing vertex
		existingVertex := hypergraph.NewVertex(
			[32]byte(fullAddress[:32]),
			[32]byte(fullAddress[32:]),
			make([]byte, 74),
			big.NewInt(7),
		)
		existingAllocVertex := hypergraph.NewVertex(
			[32]byte(fullAllocAddr[:32]),
			[32]byte(fullAllocAddr[32:]),
			make([]byte, 74),
			big.NewInt(7),
		)

		// Configure mock to return existing vertex and tree
		mockHypergraph.On("GetVertex", fullAddress).Return(existingVertex, nil)
		mockHypergraph.On("GetVertexData", fullAddress).Return(existingTree, nil)
		mockHypergraph.On("GetVertex", fullAllocAddr).Return(existingAllocVertex, nil)
		mockHypergraph.On("GetVertexData", fullAllocAddr).Return(existingAllocTree, nil)
		mockHypergraph.On("GetHyperedge", mock.Anything).Return(&mockHyperedge{}, nil)

		// Expect the allocation tree to preserve existing data
		mockHypergraph.On("AddVertex",
			mock.MatchedBy(func(v thypergraph.Vertex) bool {
				id := v.GetID()
				return bytes.Equal(id[:], fullAllocAddr[:])
			}),
			mock.MatchedBy(func(tree *qcrypto.VectorCommitmentTree) bool {
				// Check that other data is preserved
				joinFrame, _ := tree.Get([]byte{4 << 2}) // JoinFrameNumber (order 4)
				if !bytes.Equal(joinFrame, []byte("join frame")) {
					return false
				}
				pauseFrame, _ := tree.Get([]byte{6 << 2}) // PauseFrameNumber (order 6)
				if !bytes.Equal(pauseFrame, []byte("pause frame")) {
					return false
				}
				filterData, _ := tree.Get([]byte{10 << 2}) // ConfirmationFilter (order 10)
				return bytes.Equal(filterData, []byte("filter data"))
			}),
		).Return(nil)

		// Create the prover resume operation
		rdfMultiprover := createMockRDFMultiprover()
		proverResume, err := global.NewProverResume(filter, frameNumber, mockKeyManager, nil, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data
		proverResume.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call Materialize
		newState, err := proverResume.Materialize(frameNumber, hypergraphState)
		require.NoError(t, err)
		assert.NotNil(t, newState)
	})
}

func TestProverResume_GetCost(t *testing.T) {
	// Setup
	mockKeyManager := new(mocks.MockKeyManager)

	// Test data
	filter := []byte("testfilter")
	frameNumber := uint64(12345)
	address := make([]byte, 32) // Simulate an address derived from the public key
	for i := range address {
		address[i] = byte(i % 256)
	}

	// Create the prover resume operation
	rdfMultiprover := createMockRDFMultiprover()
	proverResume, err := global.NewProverResume(filter, frameNumber, mockKeyManager, nil, rdfMultiprover)
	require.NoError(t, err)

	// Set up the signature data manually
	proverResume.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
		Signature: []byte("signature"),
		Address:   address,
	}

	// Call the GetCost function
	cost, err := proverResume.GetCost()
	require.NoError(t, err)
	assert.Equal(t, int64(0), cost.Int64())
}
