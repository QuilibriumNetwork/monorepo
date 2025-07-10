package mocks

import (
	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
)

type MockShardExecutionEngine struct {
	mock.Mock
}

// GetBulletproofProver implements execution.ShardExecutionEngine.
func (
	m *MockShardExecutionEngine,
) GetBulletproofProver() crypto.BulletproofProver {
	args := m.Called()
	return args.Get(0).(crypto.BulletproofProver)
}

// GetDecafConstructor implements execution.ShardExecutionEngine.
func (
	m *MockShardExecutionEngine,
) GetDecafConstructor() crypto.DecafConstructor {
	args := m.Called()
	return args.Get(0).(crypto.DecafConstructor)
}

// GetHypergraph implements execution.ShardExecutionEngine.
func (m *MockShardExecutionEngine) GetHypergraph() hypergraph.Hypergraph {
	args := m.Called()
	return args.Get(0).(hypergraph.Hypergraph)
}

// GetInclusionProver implements execution.ShardExecutionEngine.
func (m *MockShardExecutionEngine) GetInclusionProver() crypto.InclusionProver {
	args := m.Called()
	return args.Get(0).(crypto.InclusionProver)
}

// GetName implements execution.ShardExecutionEngine.
func (m *MockShardExecutionEngine) GetName() string {
	args := m.Called()
	return args.String(0)
}

// GetVerifiableEncryptor implements execution.ShardExecutionEngine.
func (
	m *MockShardExecutionEngine,
) GetVerifiableEncryptor() crypto.VerifiableEncryptor {
	args := m.Called()
	return args.Get(0).(crypto.VerifiableEncryptor)
}

// ProcessMessage implements execution.ShardExecutionEngine.
func (m *MockShardExecutionEngine) ProcessMessage(
	address []byte,
	message *protobufs.Message,
) ([]*protobufs.Message, error) {
	args := m.Called(address, message)
	return args.Get(0).([]*protobufs.Message), args.Error(1)
}

// Start implements execution.ShardExecutionEngine.
func (m *MockShardExecutionEngine) Start(in chan struct{}) <-chan error {
	args := m.Called(in)
	return args.Get(0).(chan error)
}

// Stop implements execution.ShardExecutionEngine.
func (m *MockShardExecutionEngine) Stop(force bool) <-chan error {
	args := m.Called(force)
	return args.Get(0).(chan error)
}

var _ execution.ShardExecutionEngine = (*MockShardExecutionEngine)(nil)
