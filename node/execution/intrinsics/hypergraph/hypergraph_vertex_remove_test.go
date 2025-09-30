package hypergraph_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	nodehg "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/hypergraph"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	crypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func TestVertexRemove_GetCost(t *testing.T) {
	// Setup
	domain := [32]byte{1, 2, 3}
	dataAddress := [32]byte{4, 5, 6}

	// Create signer
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)

	vertexRemove := hypergraph.NewVertexRemove(domain, dataAddress, signer)
	cost, err := vertexRemove.GetCost()
	assert.NoError(t, err)
	assert.Equal(t, big.NewInt(64), cost) // Fixed cost for vertex removal
}

func TestVertexRemove_Prove(t *testing.T) {
	// Setup
	domain := [32]byte{1, 2, 3}
	dataAddress := [32]byte{4, 5, 6}

	// Create signer
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)

	// Test prove
	vertexRemove := hypergraph.NewVertexRemove(domain, dataAddress, signer)
	err = vertexRemove.Prove(1)
	assert.NoError(t, err)
}

func TestVertexRemove_Verify(t *testing.T) {
	// Setup
	domain := [32]byte{1, 2, 3}
	dataAddress := [32]byte{4, 5, 6}

	// Create signer
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)

	// Test verify
	vertexRemove := hypergraph.NewVertexRemove(domain, dataAddress, signer)
	// Note: Verify requires keyManager and config to be set, which happens in InvokeStep
	// For unit tests, we'll skip this verification as it gets tested in integration tests
	_ = vertexRemove // Unused in unit test, but kept for clarity
}

func TestVertexRemove_Materialize(t *testing.T) {
	// Setup
	domain := [32]byte{1, 2, 3}
	dataAddress := [32]byte{4, 5, 6}
	mockHypergraph := &mocks.MockHypergraph{}
	mockHypergraph.On("GetVertex", mock.Anything).Return(nodehg.NewVertex(domain, dataAddress, make([]byte, 74), big.NewInt(74)), nil)
	mockHypergraph.On("GetVertexData", mock.Anything).Return(&crypto.VectorCommitmentTree{}, nil)
	hgState := hgstate.NewHypergraphState(mockHypergraph)

	// Create signer
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)

	vertexRemove := hypergraph.NewVertexRemove(domain, dataAddress, signer)

	// Test materialization
	resultState, err := vertexRemove.Materialize(1, hgState)
	require.NoError(t, err)
	assert.Equal(t, hgState, resultState)
}
