package hypergraph_test

import (
	"math/big"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	hgnode "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func TestVertexAddSerialization(t *testing.T) {
	// Setup mocks
	hg := &mocks.MockHypergraph{}
	hg.On("GetProver").Return(&mocks.MockInclusionProver{})
	verenc := &mocks.MockVerifiableEncryptor{}
	proof := &mocks.MockVerEncProof{}
	proof.On("GetEncryptionKey").Return(make([]byte, 57))
	proof.On("Verify").Return(true)
	proof.On("ToBytes").Return(make([]byte, 1100))
	ve := &mocks.MockVerEnc{}
	ve.On("ToBytes").Return(make([]byte, 1000))
	ve.On("GetStatement").Return(make([]byte, 57))
	proof.On("Compress").Return(ve)
	verenc.On("ProofFromBytes", mock.Anything).Return(proof)
	verenc.On("Encrypt", mock.Anything, mock.Anything).Return([]crypto.VerEncProof{proof})

	// Create a test domain and data address
	domain := [32]byte{1, 2, 3, 4, 5}
	dataAddress := [32]byte{6, 7, 8, 9, 10}

	// Create a signer
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)

	// Create a VertexAdd instance
	vertexAdd := hypergraph.NewVertexAdd(
		domain,
		dataAddress,
		[]byte{0, 1, 2, 3},
		signer.Public().([]byte),
		hg.GetProver(),
		signer,
		&hypergraph.HypergraphIntrinsicConfiguration{
			ReadPublicKey:  signer.Public().([]byte),
			WritePublicKey: signer.Public().([]byte),
		},
		verenc,
		keys.NewInMemoryKeyManager(nil, nil),
	)

	err = vertexAdd.Prove(0)
	require.NoError(t, err)

	// Serialize the VertexAdd
	bytes, err := vertexAdd.ToBytes()
	require.NoError(t, err)
	require.NotNil(t, bytes)

	// Deserialize and verify
	newVertexAdd := hypergraph.NewVertexAdd(domain, dataAddress, nil, nil, nil, nil, nil, verenc, nil)
	err = newVertexAdd.FromBytes(
		bytes,
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, vertexAdd.Domain, newVertexAdd.Domain)
	assert.Equal(t, vertexAdd.DataAddress, newVertexAdd.DataAddress)
	assert.NotNil(t, newVertexAdd.Data)

	// Verify serialization with nil Data
	vertexAddNilData := hypergraph.NewVertexAdd(
		domain,
		dataAddress,
		nil,
		signer.Public().([]byte),
		hg.GetProver(),
		signer,
		&hypergraph.HypergraphIntrinsicConfiguration{
			ReadPublicKey:  signer.Public().([]byte),
			WritePublicKey: signer.Public().([]byte),
		},
		verenc,
		keys.NewInMemoryKeyManager(nil, nil),
	)

	bytesNilData, err := vertexAddNilData.ToBytes()
	require.Error(t, err)
	require.Nil(t, bytesNilData)
}

func TestVertexRemoveSerialization(t *testing.T) {
	// Create a test domain, data address, and other required fields
	domain := [32]byte{1, 2, 3, 4, 5}
	dataAddress := [32]byte{6, 7, 8, 9, 10}

	// Create a signer
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)

	// Create a VertexRemove instance
	vertexRemove := hypergraph.NewVertexRemove(
		domain,
		dataAddress,
		signer,
	)

	// Serialize the VertexRemove
	bytes, err := vertexRemove.ToBytes()
	require.NoError(t, err)
	require.NotNil(t, bytes)

	// Deserialize and verify
	newVertexRemove := &hypergraph.VertexRemove{}
	err = newVertexRemove.FromBytes(
		bytes,
		nil,
		nil,
		nil,
	)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, vertexRemove.Domain, newVertexRemove.Domain)
	assert.Equal(t, vertexRemove.DataAddress, newVertexRemove.DataAddress)
	// originalSize and commitment are private fields, but we can verify
	// they're properly initialized by using GetCost and Verify

	// No need to test with nil since the new constructor doesn't take those parameters
}

func TestHyperedgeAddSerialization(t *testing.T) {
	// Setup mocks

	mockHg := &mocks.MockHypergraph{}
	mockHg.On("GetProver").Return(&mocks.MockInclusionProver{})
	mockHyperedge := &mocks.MockHyperedge{}

	vert := hgnode.NewVertex([32]byte(make([]byte, 32)), [32]byte(make([]byte, 32)), make([]byte, 74), big.NewInt(74))
	tree := &qcrypto.VectorCommitmentTree{}
	tree.Insert(make([]byte, 64), vert.ToBytes(), nil, vert.GetSize())
	tbytes, err := qcrypto.SerializeNonLazyTree(tree)
	require.NoError(t, err)

	// Setup hyperedge mock
	hyperedgeID := [64]byte{1, 2, 3, 4, 5, 6, 7, 8}
	mockHyperedge.On("GetID").Return(hyperedgeID)
	mockHyperedge.On("GetSize").Return(big.NewInt(42))
	mockHyperedge.On("ToBytes").Return(slices.Concat([]byte{0x01}, hyperedgeID[:], tbytes), nil)
	mockHg.On("NewHyperedge").Return(mockHyperedge, nil)
	mockHyperedge.On("FromBytes", mock.Anything).Return(nil)

	// Create a test domain
	domain := [32]byte{1, 2, 3, 4, 5}

	// Create mock prover and signer
	mockProver := &mocks.MockInclusionProver{}
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)

	// Create a HyperedgeAdd instance
	hyperedgeAdd := hypergraph.NewHyperedgeAdd(
		domain,
		mockHyperedge,
		mockProver,
		signer,
	)

	// Serialize the HyperedgeAdd
	bytes, err := hyperedgeAdd.ToBytes()
	require.NoError(t, err)
	require.NotNil(t, bytes)
	// Deserialize and verify
	newHyperedgeAdd := &hypergraph.HyperedgeAdd{}
	err = newHyperedgeAdd.FromBytes(
		bytes,
		nil,
		nil,
		nil,
		nil,
	)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, hyperedgeAdd.Domain, newHyperedgeAdd.Domain)
	assert.NotNil(t, newHyperedgeAdd.Value)

	// Test with nil Value
	hyperedgeAddNil := hypergraph.NewHyperedgeAdd(
		domain,
		nil,
		mockProver,
		signer,
	)

	bytesNil, err := hyperedgeAddNil.ToBytes()
	require.NoError(t, err)
	require.NotNil(t, bytesNil)

	newHyperedgeAddNil := &hypergraph.HyperedgeAdd{}
	err = newHyperedgeAddNil.FromBytes(
		bytesNil,
		nil,
		nil,
		nil,
		nil,
	)
	require.NoError(t, err)

	assert.Equal(t, hyperedgeAddNil.Domain, newHyperedgeAddNil.Domain)
	assert.Nil(t, newHyperedgeAddNil.Value)
}

func TestHyperedgeRemoveSerialization(t *testing.T) {
	// Setup mocks
	mockHg := &mocks.MockHypergraph{}
	mockHyperedge := &mocks.MockHyperedge{}

	vert := hgnode.NewVertex([32]byte(make([]byte, 32)), [32]byte(make([]byte, 32)), make([]byte, 74), big.NewInt(74))
	tree := &qcrypto.VectorCommitmentTree{}
	tree.Insert(make([]byte, 64), vert.ToBytes(), nil, vert.GetSize())
	tbytes, err := qcrypto.SerializeNonLazyTree(tree)
	require.NoError(t, err)

	// Setup hyperedge mock
	hyperedgeID := [64]byte{1, 2, 3, 4, 5, 6, 7, 8}
	mockHyperedge.On("GetID").Return(hyperedgeID)
	mockHyperedge.On("ToBytes").Return(slices.Concat([]byte{0x01}, hyperedgeID[:], tbytes), nil)
	mockHg.On("NewHyperedge").Return(mockHyperedge, nil)
	mockHyperedge.On("FromBytes", mock.Anything).Return(nil)

	// Create a test domain
	domain := [32]byte{1, 2, 3, 4, 5}

	// Create signer
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)

	// Create a HyperedgeRemove instance
	hyperedgeRemove := hypergraph.NewHyperedgeRemove(
		domain,
		mockHyperedge,
		signer,
	)

	// Serialize the HyperedgeRemove
	bytes, err := hyperedgeRemove.ToBytes()
	require.NoError(t, err)
	require.NotNil(t, bytes)

	// Deserialize and verify
	newHyperedgeRemove := &hypergraph.HyperedgeRemove{}
	err = newHyperedgeRemove.FromBytes(
		bytes,
		nil,
		nil,
		nil,
	)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, hyperedgeRemove.Domain, newHyperedgeRemove.Domain)
	assert.NotNil(t, newHyperedgeRemove.Value)

	// Test with nil Value
	hyperedgeRemoveNil := hypergraph.NewHyperedgeRemove(
		domain,
		nil,
		signer,
	)

	bytesNil, err := hyperedgeRemoveNil.ToBytes()
	require.NoError(t, err)
	require.NotNil(t, bytesNil)

	newHyperedgeRemoveNil := &hypergraph.HyperedgeRemove{}
	err = newHyperedgeRemoveNil.FromBytes(
		bytesNil,
		nil,
		nil,
		nil,
	)
	require.NoError(t, err)

	assert.Equal(t, hyperedgeRemoveNil.Domain, newHyperedgeRemoveNil.Domain)
	assert.Nil(t, newHyperedgeRemoveNil.Value)
}

func TestInvalidSerialization(t *testing.T) {
	// Setup mocks
	mockInclusionProver := &mocks.MockInclusionProver{}
	mockVerenc := &mocks.MockVerifiableEncryptor{}
	proof := &mocks.MockVerEncProof{}
	proof.On("GetEncryptionKey").Return(make([]byte, 57))
	proof.On("Verify").Return(true)
	proof.On("ToBytes").Return(make([]byte, 1100))
	ve := &mocks.MockVerEnc{}
	ve.On("ToBytes").Return(make([]byte, 1000))
	ve.On("GetStatement").Return(make([]byte, 57))
	mockVerenc.On("Encrypt", mock.Anything, mock.Anything).Return([]crypto.VerEncProof{proof})
	proof.On("Compress").Return(ve)
	mockVerenc.On("ProofFromBytes", mock.Anything).Return(proof)

	// Create a test domain and data address
	domain := [32]byte{1, 2, 3, 4, 5}
	dataAddress := [32]byte{6, 7, 8, 9, 10}

	// Create a signer
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)

	// Create a VertexAdd instance
	vertexAdd := hypergraph.NewVertexAdd(
		domain,
		dataAddress,
		make([]byte, 32),
		signer.Public().([]byte),
		mockInclusionProver,
		signer,
		&hypergraph.HypergraphIntrinsicConfiguration{
			ReadPublicKey:  signer.Public().([]byte),
			WritePublicKey: signer.Public().([]byte),
		},
		mockVerenc,
		keys.NewInMemoryKeyManager(nil, nil),
	)

	err = vertexAdd.Prove(0)
	require.NoError(t, err)

	// Serialize the VertexAdd
	bytes, err := vertexAdd.ToBytes()
	require.NoError(t, err)

	// Test with truncated data
	truncatedBytes := bytes[:len(bytes)/2]
	newVertexAdd := &hypergraph.VertexAdd{}
	err = newVertexAdd.FromBytes(
		truncatedBytes,
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "from bytes")

	// Test with empty data
	emptyVertexAdd := &hypergraph.VertexAdd{}
	err = emptyVertexAdd.FromBytes(
		[]byte{},
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	assert.Error(t, err)

	// Test with corrupted data - wrong type
	corruptedBytes := make([]byte, len(bytes))
	copy(corruptedBytes, bytes)
	corruptedBytes[0] = 0xFF // Set invalid type
	corruptedVertexAdd := &hypergraph.VertexAdd{}
	err = corruptedVertexAdd.FromBytes(
		corruptedBytes,
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid type")

	mockhe := &mocks.MockHyperedge{}
	mockhe.On("ToBytes").Return([]byte("invalid-data"))
	// Test HyperedgeAdd deserialization with invalid data
	hyperedgeAdd := hypergraph.NewHyperedgeAdd(
		domain,
		mockhe,
		mockInclusionProver,
		signer,
	)

	hyperedgeBytes, err := hyperedgeAdd.ToBytes()
	require.NoError(t, err)

	corruptedHyperedgeBytes := make([]byte, len(hyperedgeBytes))
	copy(corruptedHyperedgeBytes, hyperedgeBytes)
	corruptedHyperedgeBytes[0] = 0xFF // Set invalid type
	corruptedHyperedgeAdd := &hypergraph.HyperedgeAdd{}
	err = corruptedHyperedgeAdd.FromBytes(
		corruptedHyperedgeBytes,
		nil,
		nil,
		nil,
		nil,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid type")
}
