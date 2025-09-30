package provers

import (
	"bytes"
	"math/big"
	"slices"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type mockIterator struct {
	nextCalled bool
	empty      bool
}

// Close implements tries.VertexDataIterator.
func (m *mockIterator) Close() error {
	return nil
}

// First implements tries.VertexDataIterator.
func (m *mockIterator) First() bool {
	return !m.empty
}

// Key implements tries.VertexDataIterator.
func (m *mockIterator) Key() []byte {
	return bytes.Repeat([]byte{0x11}, 32)
}

// Last implements tries.VertexDataIterator.
func (m *mockIterator) Last() bool {
	return false
}

// Next implements tries.VertexDataIterator.
func (m *mockIterator) Next() bool {
	if !m.nextCalled {
		m.nextCalled = true
		return true
	}
	return false
}

// Prev implements tries.VertexDataIterator.
func (m *mockIterator) Prev() bool {
	return false
}

// Valid implements tries.VertexDataIterator.
func (m *mockIterator) Valid() bool {
	return !m.nextCalled && !m.empty
}

// Value implements tries.VertexDataIterator.
func (m *mockIterator) Value() *tries.VectorCommitmentTree {
	trie := &tries.VectorCommitmentTree{}
	trie.Insert([]byte{0}, make([]byte, 585), nil, big.NewInt(585))
	trie.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(1))
	trie.Insert([]byte{2 << 2}, []byte{1, 1, 1, 1, 1, 1, 1, 1}, nil, big.NewInt(8))
	trie.Insert([]byte{3 << 2}, []byte{1, 1, 1, 1, 1, 1, 1, 1}, nil, big.NewInt(8))
	trie.Insert([]byte{4 << 2}, bytes.Repeat([]byte{1}, 32), nil, big.NewInt(32))
	trie.Insert([]byte{5 << 2}, []byte{1, 1, 1, 1, 1, 1, 1, 1}, nil, big.NewInt(8))
	typeBI, _ := poseidon.HashBytes(
		slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("prover:Prover")),
	)
	typeBytes := typeBI.FillBytes(make([]byte, 32))
	trie.Insert(bytes.Repeat([]byte{0xff}, 32), typeBytes, nil, big.NewInt(32))
	return trie
}

var _ tries.VertexDataIterator = (*mockIterator)(nil)

func TestProverRegistry(t *testing.T) {
	t.Run("GetProverInfo returns nil for non-existent prover", func(t *testing.T) {
		mockIP := new(mocks.MockInclusionProver)
		mockHG := tests.CreateHypergraphWithInclusionProver(mockIP)
		mockHG.On("GetVertexDataIterator", mock.Anything).Return(&mockIterator{empty: true}, nil)
		registry, err := NewProverRegistry(zap.NewNop(), mockHG)
		require.NoError(t, err)
		info, err := registry.GetProverInfo([]byte("non-existent"))
		require.NoError(t, err)
		assert.Nil(t, info)
	})

	t.Run("GetActiveProvers returns empty for no provers", func(t *testing.T) {
		mockIP := new(mocks.MockInclusionProver)
		mockHG := tests.CreateHypergraphWithInclusionProver(mockIP)
		mockHG.On("GetVertexDataIterator", mock.Anything).Return(&mockIterator{empty: true}, nil)
		registry, err := NewProverRegistry(zap.NewNop(), mockHG)
		require.NoError(t, err)
		provers, err := registry.GetActiveProvers(nil)
		require.NoError(t, err)
		assert.Empty(t, provers)
	})

	t.Run("GetProverCount returns 0 for empty registry", func(t *testing.T) {
		mockIP := new(mocks.MockInclusionProver)
		mockHG := tests.CreateHypergraphWithInclusionProver(mockIP)
		mockHG.On("GetVertexDataIterator", mock.Anything).Return(&mockIterator{empty: true}, nil)
		registry, err := NewProverRegistry(zap.NewNop(), mockHG)
		require.NoError(t, err)
		count, err := registry.GetProverCount(nil)
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})

	t.Run("GetNextProver returns error for empty trie", func(t *testing.T) {
		mockIP := new(mocks.MockInclusionProver)
		mockHG := tests.CreateHypergraphWithInclusionProver(mockIP)
		mockHG.On("GetVertexDataIterator", mock.Anything).Return(&mockIterator{empty: true}, nil)
		registry, err := NewProverRegistry(zap.NewNop(), mockHG)
		require.NoError(t, err)
		input := [32]byte{1, 2, 3}
		next, err := registry.GetNextProver(input, nil)
		require.Error(t, err)
		assert.Nil(t, next)
	})

	t.Run("UpdateProverActivity succeeds even for non-existent prover", func(t *testing.T) {
		mockIP := new(mocks.MockInclusionProver)
		mockHG := tests.CreateHypergraphWithInclusionProver(mockIP)
		mockHG.On("GetVertexDataIterator", mock.Anything).Return(&mockIterator{empty: true}, nil)
		registry, err := NewProverRegistry(zap.NewNop(), mockHG)
		require.NoError(t, err)
		err = registry.UpdateProverActivity([]byte("non-existent"), nil, 100)
		require.NoError(t, err)
	})

	t.Run("GetProversByStatus returns empty for no provers", func(t *testing.T) {
		mockIP := new(mocks.MockInclusionProver)
		mockHG := tests.CreateHypergraphWithInclusionProver(mockIP)
		mockHG.On("GetVertexDataIterator", mock.Anything).Return(&mockIterator{empty: true}, nil)
		registry, err := NewProverRegistry(zap.NewNop(), mockHG)
		require.NoError(t, err)
		provers, err := registry.GetProversByStatus(nil, consensus.ProverStatusActive)
		require.NoError(t, err)
		assert.Empty(t, provers)
	})
}

func TestProverRegistryWithShards(t *testing.T) {
	mockIP := new(mocks.MockInclusionProver)
	mockHG := tests.CreateHypergraphWithInclusionProver(mockIP)

	mockHG.On("GetVertexDataIterator", mock.Anything).Return(&mockIterator{}, nil)
	registry, err := NewProverRegistry(zap.NewNop(), mockHG)
	require.NoError(t, err)

	shard1 := []byte("shard1")
	shard2 := []byte("shard2")

	t.Run("GetActiveProvers returns empty for non-existent shard", func(t *testing.T) {
		provers, err := registry.GetActiveProvers(shard1)
		require.NoError(t, err)
		assert.Empty(t, provers)
	})

	t.Run("GetProverCount returns 0 for non-existent shard", func(t *testing.T) {
		count, err := registry.GetProverCount(shard2)
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})
}
