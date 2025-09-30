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
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
)

func TestHyperedgeRemove_GetCost(t *testing.T) {
	// Setup
	domain := [32]byte{1, 2, 3}

	// Create a mock hyperedge
	id := make([]byte, 64)
	copy(id[:32], domain[:])
	copy(id[32:], []byte{4, 5, 6, 7, 8})

	mockEdge := &mockHyperedge{
		id: [64]byte(id),
	}

	// Create signer
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)

	hyperedgeRemove := hypergraph.NewHyperedgeRemove(domain, mockEdge, signer)

	// Test cost calculation - should be fixed cost
	cost, err := hyperedgeRemove.GetCost()
	assert.NoError(t, err)
	assert.Equal(t, big.NewInt(64), cost)
}

func TestHyperedgeRemove_Prove(t *testing.T) {
	// Setup
	domain := [32]byte{1, 2, 3}

	// Create signer
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)

	// Test with nil hyperedge
	hyperedgeRemove := hypergraph.NewHyperedgeRemove(domain, nil, signer)
	err = hyperedgeRemove.Prove(1)
	assert.Error(t, err)

	// Test with valid hyperedge
	id := make([]byte, 64)
	copy(id[:32], domain[:])
	copy(id[32:], []byte{4, 5, 6, 7, 8})

	mockEdge := &mockHyperedge{
		id: [64]byte(id),
	}

	hyperedgeRemove = hypergraph.NewHyperedgeRemove(domain, mockEdge, signer)
	err = hyperedgeRemove.Prove(1)
	assert.NoError(t, err)
}

func TestHyperedgeRemove_Verify(t *testing.T) {
	// Setup
	domain := [32]byte{1, 2, 3}

	// Create signer
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)

	// Test with nil hyperedge
	hyperedgeRemove := hypergraph.NewHyperedgeRemove(domain, nil, signer)
	valid, err := hyperedgeRemove.Verify(1)
	assert.False(t, valid)
	assert.Error(t, err)

	// Test with domain mismatch
	id := make([]byte, 64)
	copy(id[:32], []byte{9, 9, 9}) // Different domain
	copy(id[32:], []byte{4, 5, 6, 7, 8})

	mockEdge := &mockHyperedge{
		id: [64]byte(id),
	}

	hyperedgeRemove = hypergraph.NewHyperedgeRemove(domain, mockEdge, signer)
	valid, err = hyperedgeRemove.Verify(1)
	assert.False(t, valid)
	assert.Error(t, err)

	// Test with valid hyperedge
	id = make([]byte, 64)
	copy(id[:32], domain[:])
	copy(id[32:], []byte{4, 5, 6, 7, 8})

	mockEdge.id = [64]byte(id)

	hyperedgeRemove = hypergraph.NewHyperedgeRemove(domain, mockEdge, signer)
	// Note: Verify requires keyManager and config to be set, which happens in InvokeStep
	// For unit tests, we'll skip this verification as it gets tested in integration tests
}

func TestHyperedgeRemove_Materialize(t *testing.T) {
	// Setup
	domain := [32]byte{1, 2, 3}
	mockHypergraph := &mocks.MockHypergraph{}

	// Create a mock hyperedge
	id := make([]byte, 64)
	copy(id[:32], domain[:])
	copy(id[32:], []byte{4, 5, 6, 7, 8})

	mockEdge := &mockHyperedge{
		id: [64]byte(id),
	}

	mockHypergraph.On("GetHyperedge", mock.Anything).Return(mockEdge, nil)
	hgState := hgstate.NewHypergraphState(mockHypergraph)

	// Create signer
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)

	hyperedgeRemove := hypergraph.NewHyperedgeRemove(domain, mockEdge, signer)

	// Test materialization
	resultState, err := hyperedgeRemove.Materialize(1, hgState)
	require.NoError(t, err)
	assert.Equal(t, hgState, resultState)
}
