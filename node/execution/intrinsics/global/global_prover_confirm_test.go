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
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// Mock implementation of Hyperedge for testing
type mockHyperedge struct {
	id          [64]byte
	connections []thypergraph.Atom
}

// GetExtrinsicTree implements hypergraph.Hyperedge.
func (m *mockHyperedge) GetExtrinsicTree() *qcrypto.VectorCommitmentTree {
	tree := &qcrypto.VectorCommitmentTree{}
	for _, conn := range m.connections {
		key := conn.GetID()
		tree.Insert(key[:], conn.ToBytes(), nil, conn.GetSize())
	}
	return tree
}

func (m *mockHyperedge) GetID() [64]byte {
	return [64]byte(m.id)
}

func (m *mockHyperedge) GetAppAddress() [32]byte {
	return [32]byte(m.id[:32])
}

func (m *mockHyperedge) GetDataAddress() [32]byte {
	return [32]byte(m.id[32:])
}

func (m *mockHyperedge) GetSize() *big.Int {
	return big.NewInt(int64(len(m.connections) * 64))
}

func (m *mockHyperedge) ToBytes() []byte {
	return m.id[:]
}

func (m *mockHyperedge) AddExtrinsic(a thypergraph.Atom) {
	m.connections = append(m.connections, a)
}

func (m *mockHyperedge) RemoveExtrinsic(a thypergraph.Atom) {
	i := slices.Index(m.connections, a)
	if i < len(m.connections)-1 && i > 0 {
		m.connections = slices.Concat(m.connections[:i], m.connections[i+1:])
	} else if i == 0 {
		m.connections = m.connections[1:]
	} else if i == len(m.connections)-1 {
		m.connections = m.connections[:len(m.connections)-2]
	}
}

func (m *mockHyperedge) Commit(_ crypto.InclusionProver) []byte {
	return m.id[:]
}

func (m *mockHyperedge) GetAtomType() thypergraph.AtomType {
	return thypergraph.HyperedgeAtomType
}

func TestProverConfirm_Prove(t *testing.T) {
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

	// Create expected domain for confirm signature
	confirmDomainPreimage := slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], []byte("PROVER_CONFIRM"))
	confirmDomain, err := poseidon.HashBytes(confirmDomainPreimage)
	require.NoError(t, err)

	// Create expected message
	expectedMessage := make([]byte, 0, len(filter)+8)
	expectedMessage = append(expectedMessage, filter...)
	frameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameBytes, frameNumber)
	expectedMessage = append(expectedMessage, frameBytes...)

	// Configure mock signer
	mockSigner.On("Public").Return(pubKey)
	mockSigner.On("SignWithDomain", expectedMessage, confirmDomain.Bytes()).
		Return([]byte("signature"), nil)

	// Configure mock key manager
	mockKeyManager.On("GetSigningKey", "q-prover-key").Return(mockSigner, nil)

	// Create the prover confirm operation
	rdfMultiprover := createMockRDFMultiprover()
	proverConfirm, err := global.NewProverConfirm(filter, frameNumber, mockKeyManager, nil, rdfMultiprover)
	require.NoError(t, err)

	// Call the prove function
	err = proverConfirm.Prove(0) // Frame number parameter is not used in the Prove method
	require.NoError(t, err)

	// Verify the results
	assert.NotNil(t, proverConfirm.PublicKeySignatureBLS48581)
	assert.Equal(t, []byte("signature"), proverConfirm.PublicKeySignatureBLS48581.Signature)
	assert.Equal(t, address, proverConfirm.PublicKeySignatureBLS48581.Address)

	// Verify that all expected methods were called
	mockSigner.AssertExpectations(t)
	mockKeyManager.AssertExpectations(t)
}

func TestProverConfirm_Verify(t *testing.T) {
	t.Run("Confirming join after 360 frames", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)

		// Test data
		filter := []byte("testfilter")
		joinFrame := uint64(252840)
		confirmFrame := joinFrame + 360
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
		joinFrameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(joinFrameBytes, joinFrame)
		tree.Insert([]byte{4 << 2}, joinFrameBytes, nil, big.NewInt(8)) // JoinFrameNumber (order 4)
		tree.Insert([]byte{1 << 2}, []byte{0}, nil, big.NewInt(1))      // Status = joining (order 1)

		mockHypergraph.On("GetVertex", mock.Anything).Return(hypergraph.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(address), make([]byte, 74), big.NewInt(0)), nil)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(tree, nil)

		// Create the prover confirm operation
		rdfMultiprover := createMockRDFMultiprover()
		proverConfirm, err := global.NewProverConfirm(filter, confirmFrame, mockKeyManager, mockHypergraph, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data manually
		proverConfirm.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Create expected domain for confirm signature
		confirmDomainPreimage := slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], []byte("PROVER_CONFIRM"))
		confirmDomain, err := poseidon.HashBytes(confirmDomainPreimage)
		require.NoError(t, err)

		// Create expected message
		expectedMessage := make([]byte, 0, len(filter)+8)
		expectedMessage = append(expectedMessage, filter...)
		frameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(frameBytes, confirmFrame)
		expectedMessage = append(expectedMessage, frameBytes...)

		// Configure mock key manager
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeBLS48581G1,
			pubkey,
			expectedMessage,
			[]byte("signature"),
			confirmDomain.Bytes(),
		).Return(true, nil)

		// Call the verify function
		valid, err := proverConfirm.Verify(confirmFrame)
		require.NoError(t, err)
		assert.True(t, valid)

		// Verify that all expected methods were called
		mockKeyManager.AssertExpectations(t)
	})

	t.Run("Cannot confirm join before 360 frames", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)

		// Test data
		filter := []byte("testfilter")
		joinFrame := uint64(252840)
		confirmFrame := joinFrame + 359 // Too early
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
		joinFrameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(joinFrameBytes, joinFrame)
		tree.Insert([]byte{4 << 2}, joinFrameBytes, nil, big.NewInt(8)) // JoinFrameNumber (order 4)
		tree.Insert([]byte{1 << 2}, []byte{0}, nil, big.NewInt(1))      // Status = joining (order 1)

		mockHypergraph.On("GetVertex", mock.Anything).Return(hypergraph.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(address), make([]byte, 74), big.NewInt(0)), nil)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(tree, nil)

		// Create the prover confirm operation
		rdfMultiprover := createMockRDFMultiprover()
		proverConfirm, err := global.NewProverConfirm(filter, confirmFrame, mockKeyManager, mockHypergraph, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data manually
		proverConfirm.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call the verify function
		valid, err := proverConfirm.Verify(confirmFrame)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must wait 360 frames")
		assert.False(t, valid)
	})

	t.Run("Cannot confirm join before frame 252840", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)

		// Test data
		filter := []byte("testfilter")
		joinFrame := uint64(252000)
		confirmFrame := uint64(252839) // Before 252840
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
		joinFrameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(joinFrameBytes, joinFrame)
		tree.Insert([]byte{4 << 2}, joinFrameBytes, nil, big.NewInt(8)) // JoinFrameNumber (order 4)
		tree.Insert([]byte{1 << 2}, []byte{0}, nil, big.NewInt(1))      // Status = joining (order 1)

		mockHypergraph.On("GetVertex", mock.Anything).Return(hypergraph.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(address), make([]byte, 74), big.NewInt(0)), nil)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(tree, nil)

		// Create the prover confirm operation
		rdfMultiprover := createMockRDFMultiprover()
		proverConfirm, err := global.NewProverConfirm(filter, confirmFrame, mockKeyManager, mockHypergraph, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data manually
		proverConfirm.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call the verify function
		valid, err := proverConfirm.Verify(confirmFrame)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot confirm before frame 252840")
		assert.False(t, valid)
	})

	t.Run("Confirming leave after 360 frames", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)

		// Test data
		filter := []byte("testfilter")
		leaveFrame := uint64(253000)
		confirmFrame := leaveFrame + 360
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
		leaveFrameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(leaveFrameBytes, leaveFrame)
		tree.Insert([]byte{5 << 2}, leaveFrameBytes, nil, big.NewInt(8)) // LeaveFrameNumber (order 5)
		tree.Insert([]byte{1 << 2}, []byte{3}, nil, big.NewInt(1))       // Status = leaving (order 1)

		mockHypergraph.On("GetVertex", mock.Anything).Return(hypergraph.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(address), make([]byte, 74), big.NewInt(0)), nil)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(tree, nil)

		// Create the prover confirm operation
		rdfMultiprover := createMockRDFMultiprover()
		proverConfirm, err := global.NewProverConfirm(filter, confirmFrame, mockKeyManager, mockHypergraph, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data manually
		proverConfirm.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Create expected domain for confirm signature
		confirmDomainPreimage := slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], []byte("PROVER_CONFIRM"))
		confirmDomain, err := poseidon.HashBytes(confirmDomainPreimage)
		require.NoError(t, err)

		// Create expected message
		expectedMessage := make([]byte, 0, len(filter)+8)
		expectedMessage = append(expectedMessage, filter...)
		frameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(frameBytes, confirmFrame)
		expectedMessage = append(expectedMessage, frameBytes...)

		// Configure mock key manager
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeBLS48581G1,
			pubkey,
			expectedMessage,
			[]byte("signature"),
			confirmDomain.Bytes(),
		).Return(true, nil)

		// Call the verify function
		valid, err := proverConfirm.Verify(confirmFrame)
		require.NoError(t, err)
		assert.True(t, valid)

		// Verify that all expected methods were called
		mockKeyManager.AssertExpectations(t)
	})
}

func TestProverConfirm_Materialize(t *testing.T) {
	t.Run("Materialize confirm join - updates status to active", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)

		// Test data
		filter := []byte("testfilter")
		frameNumber := uint64(252900)

		// Calculate prover address from pubkey
		pubkey := make([]byte, 585)
		addressBI, _ := poseidon.HashBytes(pubkey)
		address := addressBI.FillBytes(make([]byte, 32))
		proverFullAddr := [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], address))

		// Setup prover tree with type hash
		proverTypeBI, _ := poseidon.HashBytes(
			slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("prover:Prover")),
		)
		// Setup existing tree with joining status (0)
		proverTrie := &qcrypto.VectorCommitmentTree{}
		proverTrie.Insert([]byte{0}, pubkey, nil, big.NewInt(585))
		proverTrie.Insert([]byte{1 << 2}, []byte{0}, nil, big.NewInt(585))
		proverTrie.Insert(bytes.Repeat([]byte{0xff}, 32), proverTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(1))

		// Configure mock to return existing vertex
		existingVertex := hypergraph.NewVertex(
			[32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS),
			[32]byte(address),
			make([]byte, 74),
			big.NewInt(0),
		)

		mockHypergraph.On("GetVertex", proverFullAddr).Return(existingVertex, nil)
		mockHypergraph.On("GetVertexData", proverFullAddr).Return(proverTrie, nil)
		// Setup allocation tree for confirm
		allocationTypeBI, _ := poseidon.HashBytes(
			slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("allocation:ProverAllocation")),
		)

		allocTrie := &qcrypto.VectorCommitmentTree{}
		allocTrie.Insert([]byte{0}, address, nil, big.NewInt(32))
		allocTrie.Insert([]byte{1 << 2}, []byte{0}, nil, big.NewInt(1))                            // status = joining
		allocTrie.Insert([]byte{4 << 2}, []byte{0, 0, 0, 0, 0, 3, 0xDA, 0x30}, nil, big.NewInt(8)) // join frame
		allocTrie.Insert(bytes.Repeat([]byte{0xff}, 32), allocationTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(32))

		// Calculate allocation address
		allocBI, _ := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), pubkey, filter))
		alloc := allocBI.FillBytes(make([]byte, 32))
		allocFullAddr := [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], alloc))

		// Mock allocation vertex data
		mockHypergraph.On("GetVertex", allocFullAddr).Return(nil, nil).Maybe()
		mockHypergraph.On("GetVertexData", allocFullAddr).Return(allocTrie, nil).Maybe()
		mockHypergraph.On("GetHyperedge", mock.Anything).Return(&mockHyperedge{}, nil)

		// Mock the Add method to capture the new tree
		mockHypergraph.On("AddVertex", mock.MatchedBy(func(atom thypergraph.Atom) bool {
			vertex, ok := atom.(thypergraph.Vertex)
			if !ok {
				return false
			}

			// Verify it's a vertex add for our address
			appAddress := vertex.GetAppAddress()
			if !bytes.Equal(appAddress[:], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:]) {
				return false
			}
			dataAddress := vertex.GetDataAddress()
			if !bytes.Equal(dataAddress[:], address) {
				return false
			}

			return true
		}), mock.MatchedBy(func(tree *qcrypto.VectorCommitmentTree) bool {
			// Check that status was updated to active (1)
			statusBytes, _ := tree.Get([]byte{1 << 2}) // Status (order 1)
			if len(statusBytes) != 1 || statusBytes[0] != 1 {
				return false
			}
			// Check that join confirmation frame was stored
			frameBytes, _ := tree.Get([]byte{9 << 2}) // JoinConfirmFrameNumber (order 9)
			if len(frameBytes) != 8 {
				return false
			}
			storedFrame := binary.BigEndian.Uint64(frameBytes)
			// Check filter data was stored
			filterData, _ := tree.Get([]byte{10 << 2}) // ConfirmationFilter (order 10)
			return storedFrame == frameNumber && bytes.Equal(filterData, filter)
		})).Return(nil)

		// Create the prover confirm operation
		rdfMultiprover := createMockRDFMultiprover()
		proverConfirm, err := global.NewProverConfirm(filter, frameNumber, mockKeyManager, nil, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data
		proverConfirm.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call Materialize
		newState, err := proverConfirm.Materialize(frameNumber, hypergraphState)
		require.NoError(t, err)
		assert.NotNil(t, newState)
	})

	t.Run("Materialize confirm leave - updates status to left", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)

		// Test data
		filter := []byte("testfilter")
		frameNumber := uint64(253500)

		// Calculate prover address from pubkey
		pubkey := make([]byte, 585)
		addressBI, _ := poseidon.HashBytes(pubkey)
		address := addressBI.FillBytes(make([]byte, 32))
		proverFullAddr := [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], address))

		// Setup prover tree with type hash
		proverTypeBI, _ := poseidon.HashBytes(
			slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("prover:Prover")),
		)
		// Setup existing tree with leaving status (3)
		proverTrie := &qcrypto.VectorCommitmentTree{}
		proverTrie.Insert([]byte{0}, pubkey, nil, big.NewInt(585))
		proverTrie.Insert([]byte{1 << 2}, []byte{3}, nil, big.NewInt(585))
		proverTrie.Insert(bytes.Repeat([]byte{0xff}, 32), proverTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(1))

		// Configure mock to return existing vertex
		existingVertex := hypergraph.NewVertex(
			[32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS),
			[32]byte(address),
			make([]byte, 74),
			big.NewInt(0),
		)

		mockHypergraph.On("GetVertex", proverFullAddr).Return(existingVertex, nil)
		mockHypergraph.On("GetVertexData", proverFullAddr).Return(proverTrie, nil)
		// Setup allocation tree for confirm
		allocationTypeBI, _ := poseidon.HashBytes(
			slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("allocation:ProverAllocation")),
		)

		allocTrie := &qcrypto.VectorCommitmentTree{}
		allocTrie.Insert([]byte{0}, address, nil, big.NewInt(32))
		allocTrie.Insert([]byte{1 << 2}, []byte{3}, nil, big.NewInt(1))                            // status = leaving
		allocTrie.Insert([]byte{5 << 2}, []byte{0, 0, 0, 0, 0, 3, 0xDA, 0x30}, nil, big.NewInt(8)) // leave frame
		allocTrie.Insert(bytes.Repeat([]byte{0xff}, 32), allocationTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(32))

		// Calculate allocation address
		allocBI, _ := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), pubkey, filter))
		alloc := allocBI.FillBytes(make([]byte, 32))
		allocFullAddr := [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], alloc))

		// Mock allocation vertex data
		mockHypergraph.On("GetVertex", allocFullAddr).Return(nil, nil).Maybe()
		mockHypergraph.On("GetVertexData", allocFullAddr).Return(allocTrie, nil).Maybe()
		mockHypergraph.On("GetHyperedge", mock.Anything).Return(&mockHyperedge{}, nil)

		// Mock the Add method
		mockHypergraph.On("AddVertex", mock.MatchedBy(func(atom thypergraph.Atom) bool {
			vertex, ok := atom.(thypergraph.Vertex)
			if !ok {
				return false
			}

			// Verify it's a vertex add for our address
			appAddress := vertex.GetAppAddress()
			if !bytes.Equal(appAddress[:], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:]) {
				return false
			}
			dataAddress := vertex.GetDataAddress()
			if !bytes.Equal(dataAddress[:], address) {
				return false
			}

			return true
		}), mock.MatchedBy(func(tree *qcrypto.VectorCommitmentTree) bool {
			// Check that status was updated to left (4)
			statusBytes, _ := tree.Get([]byte{1 << 2}) // Status (order 1)
			if len(statusBytes) != 1 || statusBytes[0] != 4 {
				return false
			}
			// Check that leave confirmation frame was stored
			frameBytes, _ := tree.Get([]byte{11 << 2}) // LeaveConfirmFrameNumber (order 11)
			if len(frameBytes) != 8 {
				return false
			}
			storedFrame := binary.BigEndian.Uint64(frameBytes)
			return storedFrame == frameNumber
		})).Return(nil)

		// Create the prover confirm operation
		rdfMultiprover := createMockRDFMultiprover()
		proverConfirm, err := global.NewProverConfirm(filter, frameNumber, mockKeyManager, nil, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data
		proverConfirm.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call Materialize
		newState, err := proverConfirm.Materialize(frameNumber, hypergraphState)
		require.NoError(t, err)
		assert.NotNil(t, newState)
	})

	t.Run("Materialize stores filter data when provided", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)

		// Test data
		filter := []byte("myfilterdata123")
		frameNumber := uint64(252900)

		// Calculate prover address from pubkey
		pubkey := make([]byte, 585)
		addressBI, _ := poseidon.HashBytes(pubkey)
		address := addressBI.FillBytes(make([]byte, 32))
		proverFullAddr := [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], address))

		// Setup prover tree with type hash
		proverTypeBI, _ := poseidon.HashBytes(
			slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("prover:Prover")),
		)
		// Setup existing tree with joining status (0)
		proverTrie := &qcrypto.VectorCommitmentTree{}
		proverTrie.Insert([]byte{0}, pubkey, nil, big.NewInt(585))
		proverTrie.Insert([]byte{1 << 2}, []byte{0}, nil, big.NewInt(585))
		proverTrie.Insert(bytes.Repeat([]byte{0xff}, 32), proverTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(1))

		// Configure mock to return existing vertex
		existingVertex := hypergraph.NewVertex(
			[32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS),
			[32]byte(address),
			make([]byte, 74),
			big.NewInt(0),
		)

		mockHypergraph.On("GetVertex", proverFullAddr).Return(existingVertex, nil)
		mockHypergraph.On("GetVertexData", proverFullAddr).Return(proverTrie, nil)
		// Setup allocation tree for confirm
		allocationTypeBI, _ := poseidon.HashBytes(
			slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("allocation:ProverAllocation")),
		)

		allocTrie := &qcrypto.VectorCommitmentTree{}
		allocTrie.Insert([]byte{0}, address, nil, big.NewInt(32))
		allocTrie.Insert([]byte{1 << 2}, []byte{0}, nil, big.NewInt(1))                            // status = joining
		allocTrie.Insert([]byte{4 << 2}, []byte{0, 0, 0, 0, 0, 3, 0xDA, 0x30}, nil, big.NewInt(8)) // join frame
		allocTrie.Insert(bytes.Repeat([]byte{0xff}, 32), allocationTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(32))

		// Calculate allocation address
		allocBI, _ := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), pubkey, filter))
		alloc := allocBI.FillBytes(make([]byte, 32))
		allocFullAddr := [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], alloc))

		// Mock allocation vertex data
		mockHypergraph.On("GetVertex", allocFullAddr).Return(nil, nil).Maybe()
		mockHypergraph.On("GetVertexData", allocFullAddr).Return(allocTrie, nil).Maybe()
		mockHypergraph.On("GetHyperedge", mock.Anything).Return(&mockHyperedge{}, nil)

		// Mock the Add method - verify filter data is stored
		mockHypergraph.On("AddVertex", mock.Anything, mock.MatchedBy(func(tree *qcrypto.VectorCommitmentTree) bool {
			filterData, _ := tree.Get([]byte{10 << 2}) // ConfirmationFilter (order 10)
			return bytes.Equal(filterData, filter)
		})).Return(nil)

		// Create the prover confirm operation
		rdfMultiprover := createMockRDFMultiprover()
		proverConfirm, err := global.NewProverConfirm(filter, frameNumber, mockKeyManager, nil, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data
		proverConfirm.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call Materialize
		newState, err := proverConfirm.Materialize(frameNumber, hypergraphState)
		require.NoError(t, err)
		assert.NotNil(t, newState)
	})

	t.Run("Materialize error - prover not found", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)

		// Test data
		filter := []byte("testfilter")
		frameNumber := uint64(252900)
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		// Configure mock to return nil vertex (not found)
		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], address)

		mockHypergraph.On("GetVertex", fullAddress).Return(nil, errors.New("not found"))
		mockHypergraph.On("GetVertexData", fullAddress).Return(nil, errors.New("not found"))

		// Create the prover confirm operation
		rdfMultiprover := createMockRDFMultiprover()
		proverConfirm, err := global.NewProverConfirm(filter, frameNumber, mockKeyManager, nil, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data
		proverConfirm.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call Materialize - should fail
		newState, err := proverConfirm.Materialize(frameNumber, hypergraphState)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "prover not found")
		assert.Nil(t, newState)
	})

	t.Run("Materialize error - status retrieval fails", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)

		// Test data
		filter := []byte("testfilter")
		frameNumber := uint64(252900)
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		// Setup tree without status
		existingTree := &qcrypto.VectorCommitmentTree{}
		// No status inserted

		// Configure mock to return existing vertex
		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], address)

		existingVertex := hypergraph.NewVertex(
			[32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS),
			[32]byte(address),
			make([]byte, 74),
			big.NewInt(0),
		)

		mockHypergraph.On("GetVertex", mock.Anything).Return(existingVertex, nil)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(existingTree, nil)
		mockHypergraph.On("GetHyperedge", mock.Anything).Return(&mockHyperedge{}, nil)

		// Create the prover confirm operation
		rdfMultiprover := createMockRDFMultiprover()
		proverConfirm, err := global.NewProverConfirm(filter, frameNumber, mockKeyManager, nil, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data
		proverConfirm.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call Materialize - should fail
		newState, err := proverConfirm.Materialize(frameNumber, hypergraphState)
		require.Error(t, err)
		assert.Nil(t, newState)
	})

	t.Run("Materialize error - hypergraph set fails", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)

		// Test data
		filter := []byte("testfilter")
		frameNumber := uint64(252900)

		// Calculate prover address from pubkey
		pubkey := make([]byte, 585)
		addressBI, _ := poseidon.HashBytes(pubkey)
		address := addressBI.FillBytes(make([]byte, 32))
		proverFullAddr := [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], address))

		// Setup prover tree with type hash
		proverTypeBI, _ := poseidon.HashBytes(
			slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("prover:Prover")),
		)
		// Setup existing tree with joining status (0)
		proverTrie := &qcrypto.VectorCommitmentTree{}
		proverTrie.Insert([]byte{0}, pubkey, nil, big.NewInt(585))
		proverTrie.Insert([]byte{1 << 2}, []byte{0}, nil, big.NewInt(585))
		proverTrie.Insert(bytes.Repeat([]byte{0xff}, 32), proverTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(1))

		// Configure mock to return existing vertex
		existingVertex := hypergraph.NewVertex(
			[32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS),
			[32]byte(address),
			make([]byte, 74),
			big.NewInt(0),
		)

		mockHypergraph.On("GetVertex", proverFullAddr).Return(existingVertex, nil)
		mockHypergraph.On("GetVertexData", proverFullAddr).Return(proverTrie, nil)
		// Setup allocation tree for confirm
		allocationTypeBI, _ := poseidon.HashBytes(
			slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("allocation:ProverAllocation")),
		)

		allocTrie := &qcrypto.VectorCommitmentTree{}
		allocTrie.Insert([]byte{0}, address, nil, big.NewInt(32))
		allocTrie.Insert([]byte{1 << 2}, []byte{0}, nil, big.NewInt(1))                            // status = joining
		allocTrie.Insert([]byte{4 << 2}, []byte{0, 0, 0, 0, 0, 3, 0xDA, 0x30}, nil, big.NewInt(8)) // join frame
		allocTrie.Insert(bytes.Repeat([]byte{0xff}, 32), allocationTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(32))

		// Calculate allocation address
		allocBI, _ := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), pubkey, filter))
		alloc := allocBI.FillBytes(make([]byte, 32))
		allocFullAddr := [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], alloc))

		// Mock allocation vertex data
		mockHypergraph.On("GetVertex", allocFullAddr).Return(nil, nil).Maybe()
		mockHypergraph.On("GetVertexData", allocFullAddr).Return(allocTrie, nil).Maybe()
		mockHypergraph.On("GetHyperedge", mock.Anything).Return(&mockHyperedge{}, nil)

		// Mock the Add method to fail
		mockHypergraph.On("AddVertex", mock.Anything, mock.Anything).Return(errors.New("hypergraph error"))

		// Create the prover confirm operation
		rdfMultiprover := createMockRDFMultiprover()
		proverConfirm, err := global.NewProverConfirm(filter, frameNumber, mockKeyManager, nil, rdfMultiprover)
		require.NoError(t, err)

		// Set up the signature data
		proverConfirm.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call Materialize
		_, err = proverConfirm.Materialize(frameNumber, hypergraphState)
		require.NoError(t, err)
	})
}
