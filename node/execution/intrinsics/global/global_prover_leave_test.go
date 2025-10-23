package global_test

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"slices"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
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
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func TestProverLeave_Prove(t *testing.T) {
	// Setup
	mockKeyManager := new(mocks.MockKeyManager)
	mockSigner := new(mocks.MockBLSSigner)

	// Test data
	filters := [][]byte{[]byte("testfilter1"), []byte("testfilter2")}
	frameNumber := uint64(12345)
	pubKey := make([]byte, 585) // Simulate a BLS48581G1 public key
	for i := range pubKey {
		pubKey[i] = byte(i % 256)
	}

	// Compute expected address
	addressBI, err := poseidon.HashBytes(pubKey)
	require.NoError(t, err)
	address := addressBI.FillBytes(make([]byte, 32))

	// Create expected domain for leave signature
	leaveDomainPreimage := slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], []byte("PROVER_LEAVE"))
	leaveDomain, err := poseidon.HashBytes(leaveDomainPreimage)
	require.NoError(t, err)

	// Create expected message
	expectedMessage := bytes.Buffer{}
	// Add number of filters
	numFiltersBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(numFiltersBytes, uint32(len(filters)))
	expectedMessage.Write(numFiltersBytes)
	// Add each filter
	for _, filter := range filters {
		filterLenBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(filterLenBytes, uint32(len(filter)))
		expectedMessage.Write(filterLenBytes)
		expectedMessage.Write(filter)
	}
	// Add frame number
	frameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameBytes, frameNumber)
	expectedMessage.Write(frameBytes)

	// Configure mock signer
	mockSigner.On("Public").Return(pubKey)
	mockSigner.On("SignWithDomain", expectedMessage.Bytes(), leaveDomain.Bytes()).
		Return([]byte("signature"), nil)

	// Configure mock key manager
	mockKeyManager.On("GetSigningKey", "q-prover-key").Return(mockSigner, nil)

	// Create the prover leave operation
	rdfMultiprover := createMockRDFMultiprover()
	proverLeave, err := global.NewProverLeave(filters, frameNumber, mockKeyManager, nil, rdfMultiprover)
	require.NoError(t, err)

	// Call the prove function
	err = proverLeave.Prove(0) // Frame number parameter is not used in the Prove method
	require.NoError(t, err)

	// Verify the results
	assert.NotNil(t, proverLeave.PublicKeySignatureBLS48581)
	assert.Equal(t, []byte("signature"), proverLeave.PublicKeySignatureBLS48581.Signature)
	assert.Equal(t, address, proverLeave.PublicKeySignatureBLS48581.Address)

	// Verify that all expected methods were called
	mockSigner.AssertExpectations(t)
	mockKeyManager.AssertExpectations(t)
}

func TestProverLeave_Verify(t *testing.T) {
	t.Run("Can leave when active allocation exists", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)

		// Test data
		filters := [][]byte{[]byte("testfilter1"), []byte("testfilter2")}
		frameNumber := uint64(12345)
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		pubkey := make([]byte, 585)
		for i := range pubkey {
			pubkey[i] = byte(i % 256)
		}

		// Setup prover tree
		proverTree := &qcrypto.VectorCommitmentTree{}
		proverTree.Insert([]byte{0}, pubkey, nil, big.NewInt(585))

		// Setup allocation tree for first filter (active)
		allocationAddressBI1, err := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), pubkey, filters[0]))
		require.NoError(t, err)
		allocationAddress1 := allocationAddressBI1.FillBytes(make([]byte, 32))
		allocationFullAddress1 := [64]byte{}
		copy(allocationFullAddress1[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(allocationFullAddress1[32:], allocationAddress1)

		allocationTree1 := &qcrypto.VectorCommitmentTree{}
		allocationTree1.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(1)) // status = active

		// Setup allocation tree for second filter (also active)
		allocationAddressBI2, err := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), pubkey, filters[1]))
		require.NoError(t, err)
		allocationAddress2 := allocationAddressBI2.FillBytes(make([]byte, 32))
		allocationFullAddress2 := [64]byte{}
		copy(allocationFullAddress2[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(allocationFullAddress2[32:], allocationAddress2)

		allocationTree2 := &qcrypto.VectorCommitmentTree{}
		allocationTree2.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(1)) // status = active

		mockHypergraph.On("GetVertex", mock.Anything).Return(hypergraph.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(address), make([]byte, 74), big.NewInt(0)), nil)
		mockHypergraph.On("GetVertexData", [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], address))).Return(proverTree, nil)
		mockHypergraph.On("GetVertexData", allocationFullAddress1).Return(allocationTree1, nil).Once()
		mockHypergraph.On("GetVertexData", allocationFullAddress2).Return(allocationTree2, nil).Once()
		mockHypergraph.On("GetHyperedge", [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], address))).Return(&mockHyperedge{}, nil)

		// Create the prover leave operation
		rdfMultiprover := createMockRDFMultiprover()
		proverLeave, err := global.NewProverLeave(filters, frameNumber, mockKeyManager, mockHypergraph, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data manually
		proverLeave.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Create expected domain for leave signature
		leaveDomainPreimage := slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], []byte("PROVER_LEAVE"))
		leaveDomain, err := poseidon.HashBytes(leaveDomainPreimage)
		require.NoError(t, err)

		// Create expected message
		expectedMessage := bytes.Buffer{}
		// Add number of filters
		numFiltersBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(numFiltersBytes, uint32(len(filters)))
		expectedMessage.Write(numFiltersBytes)
		// Add each filter
		for _, filter := range filters {
			filterLenBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(filterLenBytes, uint32(len(filter)))
			expectedMessage.Write(filterLenBytes)
			expectedMessage.Write(filter)
		}
		// Add frame number
		frameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(frameBytes, frameNumber)
		expectedMessage.Write(frameBytes)

		// Configure mock key manager
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeBLS48581G1,
			pubkey,
			expectedMessage.Bytes(),
			[]byte("signature"),
			leaveDomain.Bytes(),
		).Return(true, nil)

		// Call the verify function
		valid, err := proverLeave.Verify(frameNumber)
		require.NoError(t, err)
		assert.True(t, valid)

		// Verify that all expected methods were called
		mockKeyManager.AssertExpectations(t)
	})

	t.Run("Cannot leave when no active allocations", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)

		// Test data
		filters := [][]byte{[]byte("testfilter")}
		frameNumber := uint64(12345)
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		pubkey := make([]byte, 585)
		for i := range pubkey {
			pubkey[i] = byte(i % 256)
		}

		// Setup prover tree
		proverTree := &qcrypto.VectorCommitmentTree{}
		proverTree.Insert([]byte{0}, pubkey, nil, big.NewInt(585))

		// Setup allocation tree with joining status (0)
		allocationAddressBI, err := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), pubkey, filters[0]))
		require.NoError(t, err)
		allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))
		allocationFullAddress := [64]byte{}
		copy(allocationFullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(allocationFullAddress[32:], allocationAddress)

		allocationTree := &qcrypto.VectorCommitmentTree{}
		allocationTree.Insert([]byte{1 << 2}, []byte{0}, nil, big.NewInt(1)) // status = joining

		mockHypergraph.On("GetVertex", mock.Anything).Return(hypergraph.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(address), make([]byte, 74), big.NewInt(0)), nil)
		mockHypergraph.On("GetVertexData", [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], address))).Return(proverTree, nil)
		mockHypergraph.On("GetVertexData", allocationFullAddress).Return(allocationTree, nil)

		// Create the prover leave operation
		rdfMultiprover := createMockRDFMultiprover()
		proverLeave, err := global.NewProverLeave(filters, frameNumber, mockKeyManager, mockHypergraph, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data manually
		proverLeave.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call the verify function
		valid, err := proverLeave.Verify(frameNumber)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no active allocations found")
		assert.False(t, valid)
	})

	t.Run("Invalid signature fails", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)

		// Test data
		filters := [][]byte{[]byte("testfilter")}
		frameNumber := uint64(12345)
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		pubkey := make([]byte, 585)
		for i := range pubkey {
			pubkey[i] = byte(i % 256)
		}

		// Setup prover tree
		proverTree := &qcrypto.VectorCommitmentTree{}
		proverTree.Insert([]byte{0}, pubkey, nil, big.NewInt(585))

		// Setup allocation tree with active status
		allocationAddressBI, err := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), pubkey, filters[0]))
		require.NoError(t, err)
		allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))
		allocationFullAddress := [64]byte{}
		copy(allocationFullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(allocationFullAddress[32:], allocationAddress)

		allocationTree := &qcrypto.VectorCommitmentTree{}
		allocationTree.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(1)) // status = active

		mockHypergraph.On("GetVertex", mock.Anything).Return(hypergraph.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(address), make([]byte, 74), big.NewInt(0)), nil)
		mockHypergraph.On("GetVertexData", [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], address))).Return(proverTree, nil)
		mockHypergraph.On("GetVertexData", allocationFullAddress).Return(allocationTree, nil)

		// Create expected domain for leave signature
		leaveDomainPreimage := slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], []byte("PROVER_LEAVE"))
		leaveDomain, err := poseidon.HashBytes(leaveDomainPreimage)
		require.NoError(t, err)

		// Create expected message
		expectedMessage := bytes.Buffer{}
		// Add number of filters
		numFiltersBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(numFiltersBytes, uint32(len(filters)))
		expectedMessage.Write(numFiltersBytes)
		// Add each filter
		for _, filter := range filters {
			filterLenBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(filterLenBytes, uint32(len(filter)))
			expectedMessage.Write(filterLenBytes)
			expectedMessage.Write(filter)
		}
		// Add frame number
		frameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(frameBytes, frameNumber)
		expectedMessage.Write(frameBytes)

		// Configure mock key manager to return false
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeBLS48581G1,
			pubkey,
			expectedMessage.Bytes(),
			[]byte("signature"),
			leaveDomain.Bytes(),
		).Return(false, nil)

		// Create the prover leave operation
		rdfMultiprover := createMockRDFMultiprover()
		proverLeave, err := global.NewProverLeave(filters, frameNumber, mockKeyManager, mockHypergraph, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data manually
		proverLeave.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call the verify function
		valid, err := proverLeave.Verify(frameNumber)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signature")
		assert.False(t, valid)
	})
}

func TestProverLeave_Materialize(t *testing.T) {
	t.Run("Materialize leave - updates allocation status to leaving", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)

		// Test data
		filters := [][]byte{[]byte("testfilter")}
		frameNumber := uint64(253000)
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		pubkey := make([]byte, 585)
		for i := range pubkey {
			pubkey[i] = byte(i % 256)
		}

		// Create full addresses
		proverFullAddress := [64]byte{}
		copy(proverFullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(proverFullAddress[32:], address)

		// Setup existing prover tree
		proverTree := &qcrypto.VectorCommitmentTree{}
		proverTree.Insert([]byte{0}, pubkey, nil, big.NewInt(585))

		// Calculate allocation address
		allocationAddressBI, err := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), pubkey, filters[0]))
		require.NoError(t, err)
		allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))
		allocationFullAddress := [64]byte{}
		copy(allocationFullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(allocationFullAddress[32:], allocationAddress)

		// Setup existing allocation tree with active status
		allocationTree := &qcrypto.VectorCommitmentTree{}
		allocationTree.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(1)) // status = active

		// Create existing vertices
		proverVertex := hypergraph.NewVertex(
			[32]byte(proverFullAddress[:32]),
			[32]byte(proverFullAddress[32:]),
			make([]byte, 74),
			big.NewInt(7),
		)
		allocationVertex := hypergraph.NewVertex(
			[32]byte(allocationFullAddress[:32]),
			[32]byte(allocationFullAddress[32:]),
			make([]byte, 74),
			big.NewInt(7),
		)

		// Configure mock to return existing vertices and trees
		mockHypergraph.On("GetVertex", proverFullAddress).Return(proverVertex, nil)
		mockHypergraph.On("GetVertexData", proverFullAddress).Return(proverTree, nil)
		mockHypergraph.On("GetVertex", allocationFullAddress).Return(allocationVertex, nil)
		mockHypergraph.On("GetVertexData", allocationFullAddress).Return(allocationTree, nil)
		mockHypergraph.On("GetHyperedge", proverFullAddress).Return(&mockHyperedge{}, nil)

		// Expect the allocation tree to be updated with leaving status and leave frame
		mockHypergraph.On("AddVertex",
			mock.MatchedBy(func(v thypergraph.Vertex) bool {
				id := v.GetID()
				return bytes.Equal(id[:], allocationFullAddress[:])
			}),
			mock.MatchedBy(func(tree *qcrypto.VectorCommitmentTree) bool {
				// Check that status was updated to leaving (3)
				statusBytes, _ := tree.Get([]byte{1 << 2}) // status (order 1)
				if len(statusBytes) != 1 || statusBytes[0] != 3 {
					return false
				}
				// Check that leave frame was stored
				frameBytes, _ := tree.Get([]byte{5 << 2}) // leave frame number (order 5)
				if len(frameBytes) != 8 {
					return false
				}
				storedFrame := binary.BigEndian.Uint64(frameBytes)
				return storedFrame == frameNumber
			}),
		).Return(nil)

		// Create the prover leave operation
		proverLeave, err := global.NewProverLeave(filters, frameNumber, mockKeyManager, nil, createMockRDFMultiprover())
		require.NoError(t, err)

		// Set up the signature data
		proverLeave.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call Materialize
		newState, err := proverLeave.Materialize(frameNumber, hypergraphState)
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
		filters := [][]byte{[]byte("testfilter")}
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

		// Create the prover leave operation
		proverLeave, err := global.NewProverLeave(filters, frameNumber, mockKeyManager, nil, createMockRDFMultiprover())
		require.NoError(t, err)

		// Set up the signature data
		proverLeave.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call Materialize
		newState, err := proverLeave.Materialize(frameNumber, hypergraphState)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "prover not found")
		assert.Nil(t, newState)
	})
}

func TestProverLeave_GetCost(t *testing.T) {
	// Setup
	mockKeyManager := new(mocks.MockKeyManager)

	// Test data
	filters := [][]byte{[]byte("testfilter")}
	frameNumber := uint64(12345)
	address := make([]byte, 32) // Simulate an address derived from the public key
	for i := range address {
		address[i] = byte(i % 256)
	}

	// Create the prover leave operation
	rdfMultiprover := createMockRDFMultiprover()
	proverLeave, err := global.NewProverLeave(filters, frameNumber, mockKeyManager, nil, rdfMultiprover)
	require.NoError(t, err)

	// Set up the signature data manually
	proverLeave.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
		Signature: []byte("signature"),
		Address:   address,
	}

	// Call the GetCost function
	cost, err := proverLeave.GetCost()
	require.NoError(t, err)
	assert.Equal(t, int64(0), cost.Int64())
}
