package global_test

import (
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
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func TestProverReject_Prove(t *testing.T) {
	// Setup
	mockKeyManager := new(mocks.MockKeyManager)
	mockSigner := new(mocks.MockBLSSigner)

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

	// Create expected domain for reject signature
	rejectDomainPreimage := slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], []byte("PROVER_REJECT"))
	rejectDomain, err := poseidon.HashBytes(rejectDomainPreimage)
	require.NoError(t, err)

	// Create expected message
	expectedMessage := make([]byte, 0, len(filter)+8)
	expectedMessage = append(expectedMessage, filter...)
	frameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameBytes, frameNumber)
	expectedMessage = append(expectedMessage, frameBytes...)

	// Configure mock signer
	mockSigner.On("Public").Return(pubKey)
	mockSigner.On("SignWithDomain", expectedMessage, rejectDomain.Bytes()).
		Return([]byte("signature"), nil)

	// Configure mock key manager
	mockKeyManager.On("GetSigningKey", "q-prover-key").Return(mockSigner, nil)

	// Create the prover reject operation
	rdfMultiprover := createMockRDFMultiprover()
	proverReject, err := global.NewProverReject(filter, frameNumber, mockKeyManager, nil, rdfMultiprover)
	require.NoError(t, err)

	// Call the prove function
	err = proverReject.Prove(0) // Frame number parameter is not used in the Prove method
	require.NoError(t, err)

	// Verify the results
	assert.NotNil(t, proverReject.PublicKeySignatureBLS48581)
	assert.Equal(t, []byte("signature"), proverReject.PublicKeySignatureBLS48581.Signature)
	assert.Equal(t, address, proverReject.PublicKeySignatureBLS48581.Address)

	// Verify that all expected methods were called
	mockSigner.AssertExpectations(t)
	mockKeyManager.AssertExpectations(t)
}

func TestProverReject_Verify(t *testing.T) {
	t.Run("Can reject join before confirmation", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)

		// Test data
		filter := []byte("testfilter")
		joinFrame := uint64(252840)
		rejectFrame := joinFrame + 100 // Before confirmation window
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		pubkey := make([]byte, 585)
		for i := range pubkey {
			pubkey[i] = byte(i % 256)
		}

		// Setup tree with joining status (0) and join frame
		tree := &qcrypto.VectorCommitmentTree{}
		tree.Insert([]byte{0}, pubkey, nil, big.NewInt(585))
		tree.Insert([]byte{1 << 2}, []byte{0}, nil, big.NewInt(1)) // status = joining (order 1)
		joinFrameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(joinFrameBytes, joinFrame)
		tree.Insert([]byte{4 << 2}, joinFrameBytes, nil, big.NewInt(8)) // JoinFrameNumber (order 4)

		mockHypergraph.On("GetVertex", mock.Anything).Return(hypergraph.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(address), make([]byte, 74), big.NewInt(0)), nil)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(tree, nil)

		// Create the prover reject operation
		rdfMultiprover := createMockRDFMultiprover()
		proverReject, err := global.NewProverReject(filter, rejectFrame, mockKeyManager, mockHypergraph, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data manually
		proverReject.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Create expected domain for reject signature
		rejectDomainPreimage := slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], []byte("PROVER_REJECT"))
		rejectDomain, err := poseidon.HashBytes(rejectDomainPreimage)
		require.NoError(t, err)

		// Create expected message
		expectedMessage := make([]byte, 0, len(filter)+8)
		expectedMessage = append(expectedMessage, filter...)
		frameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(frameBytes, rejectFrame)
		expectedMessage = append(expectedMessage, frameBytes...)

		// Configure mock key manager
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeBLS48581G1,
			pubkey,
			expectedMessage,
			[]byte("signature"),
			rejectDomain.Bytes(),
		).Return(true, nil)

		// Call the verify function
		valid, err := proverReject.Verify(rejectFrame)
		require.NoError(t, err)
		assert.True(t, valid)

		// Verify that all expected methods were called
		mockKeyManager.AssertExpectations(t)
	})

	t.Run("Can reject leave after 360 frames", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)

		// Test data
		filter := []byte("testfilter")
		leaveFrame := uint64(253000)
		rejectFrame := leaveFrame + 360 // Minimum wait time
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		pubkey := make([]byte, 585)
		for i := range pubkey {
			pubkey[i] = byte(i % 256)
		}

		// Setup tree with leaving status (3) and leave frame
		tree := &qcrypto.VectorCommitmentTree{}
		tree.Insert([]byte{0}, pubkey, nil, big.NewInt(585))
		tree.Insert([]byte{1 << 2}, []byte{3}, nil, big.NewInt(1)) // status = leaving (order 1)
		leaveFrameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(leaveFrameBytes, leaveFrame)
		tree.Insert([]byte{5 << 2}, leaveFrameBytes, nil, big.NewInt(8)) // LeaveFrameNumber (order 5)

		mockHypergraph.On("GetVertex", mock.Anything).Return(hypergraph.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(address), make([]byte, 74), big.NewInt(0)), nil)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(tree, nil)

		// Create the prover reject operation
		rdfMultiprover := createMockRDFMultiprover()
		proverReject, err := global.NewProverReject(filter, rejectFrame, mockKeyManager, mockHypergraph, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data manually
		proverReject.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Create expected domain for reject signature
		rejectDomainPreimage := slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], []byte("PROVER_REJECT"))
		rejectDomain, err := poseidon.HashBytes(rejectDomainPreimage)
		require.NoError(t, err)

		// Create expected message
		expectedMessage := make([]byte, 0, len(filter)+8)
		expectedMessage = append(expectedMessage, filter...)
		frameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(frameBytes, rejectFrame)
		expectedMessage = append(expectedMessage, frameBytes...)

		// Configure mock key manager
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeBLS48581G1,
			pubkey,
			expectedMessage,
			[]byte("signature"),
			rejectDomain.Bytes(),
		).Return(true, nil)

		// Call the verify function
		valid, err := proverReject.Verify(rejectFrame)
		require.NoError(t, err)
		assert.True(t, valid)

		// Verify that all expected methods were called
		mockKeyManager.AssertExpectations(t)
	})

	t.Run("Cannot reject leave before 360 frames", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)

		// Test data
		filter := []byte("testfilter")
		leaveFrame := uint64(253000)
		rejectFrame := leaveFrame + 359 // Too early
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		pubkey := make([]byte, 585)
		for i := range pubkey {
			pubkey[i] = byte(i % 256)
		}

		// Setup tree with leaving status (3) and leave frame
		tree := &qcrypto.VectorCommitmentTree{}
		tree.Insert([]byte{0}, pubkey, nil, big.NewInt(585))
		tree.Insert([]byte{1 << 2}, []byte{3}, nil, big.NewInt(1)) // status = leaving (order 1)
		leaveFrameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(leaveFrameBytes, leaveFrame)
		tree.Insert([]byte{5 << 2}, leaveFrameBytes, nil, big.NewInt(8)) // LeaveFrameNumber (order 5)

		mockHypergraph.On("GetVertex", mock.Anything).Return(hypergraph.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(address), make([]byte, 74), big.NewInt(0)), nil)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(tree, nil)

		// Create the prover reject operation
		rdfMultiprover := createMockRDFMultiprover()
		proverReject, err := global.NewProverReject(filter, rejectFrame, mockKeyManager, mockHypergraph, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data manually
		proverReject.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call the verify function
		valid, err := proverReject.Verify(rejectFrame)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must wait 360 frames after leave to reject")
		assert.False(t, valid)
	})

	t.Run("Cannot reject when already active", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)

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

		// Create the prover reject operation
		rdfMultiprover := createMockRDFMultiprover()
		proverReject, err := global.NewProverReject(filter, frameNumber, mockKeyManager, mockHypergraph, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data manually
		proverReject.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call the verify function
		valid, err := proverReject.Verify(frameNumber)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid allocation state for rejection")
		assert.False(t, valid)
	})

	t.Run("Invalid signature fails", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)

		// Test data
		filter := []byte("testfilter")
		joinFrame := uint64(252840)
		rejectFrame := joinFrame + 100
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		pubkey := make([]byte, 585)
		for i := range pubkey {
			pubkey[i] = byte(i % 256)
		}

		// Setup tree with joining status (0) and join frame
		tree := &qcrypto.VectorCommitmentTree{}
		tree.Insert([]byte{0}, pubkey, nil, big.NewInt(585))
		tree.Insert([]byte{1 << 2}, []byte{0}, nil, big.NewInt(1)) // status = joining (order 1)
		joinFrameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(joinFrameBytes, joinFrame)
		tree.Insert([]byte{4 << 2}, joinFrameBytes, nil, big.NewInt(8)) // JoinFrameNumber (order 4)

		mockHypergraph.On("GetVertex", mock.Anything).Return(hypergraph.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(address), make([]byte, 74), big.NewInt(0)), nil)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(tree, nil)

		// Create expected domain for reject signature
		rejectDomainPreimage := slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], []byte("PROVER_REJECT"))
		rejectDomain, err := poseidon.HashBytes(rejectDomainPreimage)
		require.NoError(t, err)

		// Create expected message
		expectedMessage := make([]byte, 0, len(filter)+8)
		expectedMessage = append(expectedMessage, filter...)
		frameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(frameBytes, rejectFrame)
		expectedMessage = append(expectedMessage, frameBytes...)

		// Configure mock key manager to return false
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeBLS48581G1,
			pubkey,
			expectedMessage,
			[]byte("signature"),
			rejectDomain.Bytes(),
		).Return(false, nil)

		// Create the prover reject operation
		rdfMultiprover := createMockRDFMultiprover()
		proverReject, err := global.NewProverReject(filter, rejectFrame, mockKeyManager, mockHypergraph, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data manually
		proverReject.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call the verify function
		valid, err := proverReject.Verify(rejectFrame)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signature")
		assert.False(t, valid)
	})
}

func TestProverReject_GetCost(t *testing.T) {
	// Setup
	mockKeyManager := new(mocks.MockKeyManager)

	// Test data
	filter := []byte("testfilter")
	frameNumber := uint64(12345)
	address := make([]byte, 32) // Simulate an address derived from the public key
	for i := range address {
		address[i] = byte(i % 256)
	}

	// Create the prover reject operation
	rdfMultiprover := createMockRDFMultiprover()
	proverReject, err := global.NewProverReject(filter, frameNumber, mockKeyManager, nil, rdfMultiprover)
	require.NoError(t, err)

	// Set up the signature data manually
	proverReject.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
		Signature: []byte("signature"),
		Address:   address,
	}

	// Call the GetCost function
	cost, err := proverReject.GetCost()
	require.NoError(t, err)
	assert.Equal(t, int64(0), cost.Int64())
}
