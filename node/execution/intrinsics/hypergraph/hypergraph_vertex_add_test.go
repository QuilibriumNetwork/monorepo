package hypergraph_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/hypergraph"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func TestVertexAdd_GetCost(t *testing.T) {
	// Setup
	domain := [32]byte{1, 2, 3}
	dataAddress := [32]byte{4, 5, 6}
	mockInclusionProver := &mocks.MockInclusionProver{}
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)
	verenc := &mocks.MockVerifiableEncryptor{}

	// Test with nil data
	vertexAdd := hypergraph.NewVertexAdd(domain, dataAddress, nil, signer.Public().([]byte), mockInclusionProver, signer, &hypergraph.HypergraphIntrinsicConfiguration{ReadPublicKey: signer.Public().([]byte), WritePublicKey: signer.Public().([]byte)}, verenc, keys.NewInMemoryKeyManager(nil, nil))
	cost, err := vertexAdd.GetCost()
	assert.Error(t, err)
	assert.Equal(t, big.NewInt(0), cost)

	// Test with data – should round up to nearest multiple of 55
	expectedSize := big.NewInt(110)
	data := make([]byte, 100)
	vertexAdd = hypergraph.NewVertexAdd(domain, dataAddress, data, signer.Public().([]byte), mockInclusionProver, signer, &hypergraph.HypergraphIntrinsicConfiguration{ReadPublicKey: signer.Public().([]byte), WritePublicKey: signer.Public().([]byte)}, verenc, keys.NewInMemoryKeyManager(nil, nil))
	cost, err = vertexAdd.GetCost()
	assert.NoError(t, err)
	assert.Equal(t, expectedSize, cost)
}

func TestVertexAdd_Prove(t *testing.T) {
	// Setup
	domain := [32]byte{1, 2, 3}
	dataAddress := [32]byte{4, 5, 6}
	mockInclusionProver := &mocks.MockInclusionProver{}
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)
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

	// Test with nil data
	vertexAdd := hypergraph.NewVertexAdd(domain, dataAddress, nil, signer.Public().([]byte), mockInclusionProver, signer, &hypergraph.HypergraphIntrinsicConfiguration{ReadPublicKey: signer.Public().([]byte), WritePublicKey: signer.Public().([]byte)}, verenc, keys.NewInMemoryKeyManager(nil, nil))
	err = vertexAdd.Prove(1)
	assert.Error(t, err)

	// Test with valid data
	data := make([]byte, 100)
	vertexAdd = hypergraph.NewVertexAdd(domain, dataAddress, data, signer.Public().([]byte), mockInclusionProver, signer, &hypergraph.HypergraphIntrinsicConfiguration{ReadPublicKey: signer.Public().([]byte), WritePublicKey: signer.Public().([]byte)}, verenc, keys.NewInMemoryKeyManager(nil, nil))

	err = vertexAdd.Prove(1)
	assert.NoError(t, err)

	// Verify the signature was set (signature should be valid since we're using a Ed448 key)
	assert.NotEmpty(t, vertexAdd.Signature)
}

func TestVertexAdd_Verify(t *testing.T) {
	// For the unit test, we'll test the behavior when these fields are not set
	domain := [32]byte{1, 2, 3}
	dataAddress := [32]byte{4, 5, 6}
	mockInclusionProver := &mocks.MockInclusionProver{}
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)
	verenc := &mocks.MockVerifiableEncryptor{}
	proof := &mocks.MockVerEncProof{}
	proof.On("GetEncryptionKey").Return(signer.Public().([]byte))
	proof.On("Verify").Return(true)
	proof.On("ToBytes").Return(make([]byte, 1100))
	ve := &mocks.MockVerEnc{}
	ve.On("ToBytes").Return(make([]byte, 1000))
	ve.On("GetStatement").Return(make([]byte, 57))
	proof.On("Compress").Return(ve)
	verenc.On("ProofFromBytes", mock.Anything).Return(proof)
	verenc.On("Encrypt", mock.Anything, mock.Anything).Return([]crypto.VerEncProof{proof})

	// Test with valid data
	data := make([]byte, 100)
	vertexAdd := hypergraph.NewVertexAdd(domain, dataAddress, data, signer.Public().([]byte), mockInclusionProver, signer, &hypergraph.HypergraphIntrinsicConfiguration{ReadPublicKey: signer.Public().([]byte), WritePublicKey: signer.Public().([]byte)}, verenc, keys.NewInMemoryKeyManager(nil, nil))

	err = vertexAdd.Prove(1)
	assert.NoError(t, err)

	valid, err := vertexAdd.Verify(1)
	assert.True(t, valid)
	assert.NoError(t, err)
}

func TestVertexAdd_Materialize(t *testing.T) {
	// Setup
	domain := [32]byte{1, 2, 3}
	dataAddress := [32]byte{4, 5, 6}
	mockHypergraph := &mocks.MockHypergraph{}
	mockHypergraph.On("GetVertex", mock.Anything).Return(nil, nil)
	mockHypergraph.On("GetVertexData", mock.Anything).Return(&tries.VectorCommitmentTree{}, nil)
	mockInclusionProver := &mocks.MockInclusionProver{}
	verenc := &mocks.MockVerifiableEncryptor{}
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)
	proof := &mocks.MockVerEncProof{}
	proof.On("GetEncryptionKey").Return(signer.Public().([]byte))
	proof.On("Verify").Return(true)
	proof.On("ToBytes").Return(make([]byte, 1100))
	ve := &mocks.MockVerEnc{}
	ve.On("ToBytes").Return(make([]byte, 1000))
	ve.On("GetStatement").Return(make([]byte, 57))
	proof.On("Compress").Return(ve)
	verenc.On("ProofFromBytes", mock.Anything).Return(proof)
	verenc.On("Encrypt", mock.Anything, mock.Anything).Return([]crypto.VerEncProof{proof})

	hgState := hgstate.NewHypergraphState(mockHypergraph)
	vertexAdd := hypergraph.NewVertexAdd(domain, dataAddress, make([]byte, 100), signer.Public().([]byte), mockInclusionProver, signer, &hypergraph.HypergraphIntrinsicConfiguration{ReadPublicKey: signer.Public().([]byte), WritePublicKey: signer.Public().([]byte)}, verenc, keys.NewInMemoryKeyManager(nil, nil))
	err = vertexAdd.Prove(1)
	assert.NoError(t, err)

	// Test materialization
	resultState, err := vertexAdd.Materialize(1, hgState)
	require.NoError(t, err)
	assert.Equal(t, hgState, resultState)
}
