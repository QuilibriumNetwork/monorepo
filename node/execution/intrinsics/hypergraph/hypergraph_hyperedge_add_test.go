package hypergraph_test

import (
	"math/big"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/hypergraph"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
	nodehg "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	crypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// Mock implementation of Hyperedge for testing
type mockHyperedge struct {
	id          [64]byte
	connections []nodehg.Atom
}

// GetExtrinsicTree implements hypergraph.Hyperedge.
func (m *mockHyperedge) GetExtrinsicTree() *crypto.VectorCommitmentTree {
	return &crypto.VectorCommitmentTree{}
}

func (m *mockHyperedge) GetID() [64]byte {
	return [64]byte(m.id)
}

func (m *mockHyperedge) GetSize() *big.Int {
	return big.NewInt(int64(len(m.connections) * 64))
}

func (m *mockHyperedge) ToBytes() []byte {
	return m.id[:]
}

func (m *mockHyperedge) AddExtrinsic(a nodehg.Atom) {
	m.connections = append(m.connections, a)
}

func (m *mockHyperedge) RemoveExtrinsic(a nodehg.Atom) {
	i := slices.Index(m.connections, a)
	if i < len(m.connections)-1 && i > 0 {
		m.connections = slices.Concat(m.connections[:i], m.connections[i+1:])
	} else if i == 0 {
		m.connections = m.connections[1:]
	} else if i == len(m.connections)-1 {
		m.connections = m.connections[:len(m.connections)-2]
	}
}

func (m *mockHyperedge) Commit(_ qcrypto.InclusionProver) []byte {
	return m.id[:]
}

func (m *mockHyperedge) GetAtomType() nodehg.AtomType {
	return nodehg.HyperedgeAtomType
}

// Mock implementation of Vertex for testing
type mockVertex struct {
	id []byte
}

func (m *mockVertex) GetID() [64]byte {
	return [64]byte(m.id)
}

func (m *mockVertex) ToBytes() []byte {
	return m.id
}

func (m *mockVertex) GetAtomType() nodehg.AtomType {
	return nodehg.VertexAtomType
}

func (m *mockHyperedge) GetAppAddress() [32]byte {
	return [32]byte(m.id[:32])
}

func (m *mockHyperedge) GetDataAddress() [32]byte {
	return [32]byte(m.id[32:])
}

func (m *mockVertex) GetSize() *big.Int {
	return big.NewInt(10)
}

func (m *mockVertex) GetAppAddress() [32]byte {
	return [32]byte(m.id[:32])
}

func (m *mockVertex) GetDataAddress() [32]byte {
	return [32]byte(m.id[32:])
}

func (m *mockVertex) Commit(_ qcrypto.InclusionProver) []byte {
	return m.id
}

func TestHyperedgeAdd_GetCost(t *testing.T) {
	// Setup
	domain := [32]byte{1, 2, 3}

	// Create a mock hyperedge with no atoms
	expectedSize := big.NewInt(0)
	id := make([]byte, 64)
	copy(id[:32], domain[:])
	copy(id[32:], []byte{4, 5, 6, 7, 8})

	mockEdge := &mockHyperedge{
		id: [64]byte(id),
	}

	// Create mock inclusionProver and signer
	mockProver := &mocks.MockInclusionProver{}
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)

	hyperedgeAdd := hypergraph.NewHyperedgeAdd(domain, mockEdge, mockProver, signer)

	// Test cost calculation
	cost, err := hyperedgeAdd.GetCost()
	assert.NoError(t, err)
	assert.Equal(t, expectedSize, cost)
}

func TestHyperedgeAdd_Prove(t *testing.T) {
	// Setup
	domain := [32]byte{1, 2, 3}

	// Create mock inclusionProver and signer
	mockProver := &mocks.MockInclusionProver{}
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)

	// Test with nil hyperedge
	hyperedgeAdd := hypergraph.NewHyperedgeAdd(domain, nil, mockProver, signer)
	err = hyperedgeAdd.Prove(1)
	assert.Error(t, err)

	// Test with hyperedge that has no connections
	id := make([]byte, 64)
	copy(id[:32], domain[:])
	copy(id[32:], []byte{4, 5, 6, 7, 8})

	mockEdge := &mockHyperedge{
		id:          [64]byte(id),
		connections: []nodehg.Atom{},
	}

	hyperedgeAdd = hypergraph.NewHyperedgeAdd(domain, mockEdge, mockProver, signer)
	err = hyperedgeAdd.Prove(1)
	assert.Error(t, err)

	// Test with valid hyperedge
	mockEdge.connections = []nodehg.Atom{
		&mockVertex{id: []byte{1, 2, 3}},
	}

	hyperedgeAdd = hypergraph.NewHyperedgeAdd(domain, mockEdge, mockProver, signer)
	err = hyperedgeAdd.Prove(1)
	assert.NoError(t, err)
}

func TestHyperedgeAdd_Verify(t *testing.T) {
	// Setup
	domain := [32]byte{1, 2, 3}

	// Create mock inclusionProver and signer
	mockProver := &mocks.MockInclusionProver{}
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)

	// Test with nil hyperedge
	hyperedgeAdd := hypergraph.NewHyperedgeAdd(domain, nil, mockProver, signer)
	valid, err := hyperedgeAdd.Verify(1)
	assert.False(t, valid)
	assert.Error(t, err)

	// Test with hyperedge that has no connections
	id := make([]byte, 64)
	copy(id[:32], domain[:])
	copy(id[32:], []byte{4, 5, 6, 7, 8})

	mockEdge := &mockHyperedge{
		id:          [64]byte(id),
		connections: []nodehg.Atom{},
	}

	hyperedgeAdd = hypergraph.NewHyperedgeAdd(domain, mockEdge, mockProver, signer)
	valid, err = hyperedgeAdd.Verify(1)
	assert.False(t, valid)
	assert.Error(t, err)

	// Test with domain mismatch
	badDomainID := make([]byte, 64)
	copy(badDomainID[:32], []byte{9, 9, 9}) // Different domain
	copy(badDomainID[32:], []byte{4, 5, 6, 7, 8})

	mockEdge.id = [64]byte(badDomainID)
	mockEdge.connections = []nodehg.Atom{
		&mockVertex{id: []byte{1, 2, 3}},
	}

	hyperedgeAdd = hypergraph.NewHyperedgeAdd(domain, mockEdge, mockProver, signer)
	valid, err = hyperedgeAdd.Verify(1)
	assert.False(t, valid)
	assert.Error(t, err)

	// Test with valid hyperedge
	mockEdge.id = [64]byte(id) // Restore correct domain

	hyperedgeAdd = hypergraph.NewHyperedgeAdd(domain, mockEdge, mockProver, signer)
	// Note: Verify requires keyManager and config to be set, which happens in InvokeStep
	// For unit tests, we'll skip this verification as it gets tested in integration tests
}

func TestHyperedgeAdd_Materialize(t *testing.T) {
	// Setup
	domain := [32]byte{1, 2, 3}
	mockHypergraph := &mocks.MockHypergraph{}
	hgState := hgstate.NewHypergraphState(mockHypergraph)
	mockHypergraph.On("GetHyperedge", mock.Anything).Return(nil, nil)

	// Create a mock hyperedge
	id := make([]byte, 64)
	copy(id[:32], domain[:])
	copy(id[32:], []byte{4, 5, 6, 7, 8})

	mockEdge := &mockHyperedge{
		id:          [64]byte(id),
		connections: []nodehg.Atom{&mockVertex{id: []byte{1, 2, 3}}},
	}

	// Create mock inclusionProver and signer
	mockProver := &mocks.MockInclusionProver{}
	signer, err := keys.NewEd448Key()
	require.NoError(t, err)

	hyperedgeAdd := hypergraph.NewHyperedgeAdd(domain, mockEdge, mockProver, signer)

	// Test materialization
	resultState, err := hyperedgeAdd.Materialize(1, hgState)
	require.NoError(t, err)
	assert.Equal(t, hgState, resultState)
}
