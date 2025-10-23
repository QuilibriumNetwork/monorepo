package mocks

import (
	"math/big"

	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
)

type MockShardExecutionEngine struct {
	mock.Mock
}

// Lock implements execution.ShardExecutionEngine.
func (m *MockShardExecutionEngine) Lock(
	frameNumber uint64,
	address []byte,
	message []byte,
) ([][]byte, error) {
	args := m.Called(frameNumber, address, message)
	return args.Get(0).([][]byte), args.Error(1)
}

// Unlock implements execution.ShardExecutionEngine.
func (m *MockShardExecutionEngine) Unlock() error {
	args := m.Called()
	return args.Error(0)
}

// Prove implements execution.ShardExecutionEngine.
func (m *MockShardExecutionEngine) Prove(
	domain []byte,
	frameNumber uint64,
	message []byte,
) (*protobufs.MessageRequest, error) {
	args := m.Called(domain, frameNumber, message)
	return args.Get(0).(*protobufs.MessageRequest), args.Error(1)
}

func (m *MockShardExecutionEngine) GetCost(message []byte) (*big.Int, error) {
	args := m.Called(message)
	return args.Get(0).(*big.Int), args.Error(1)
}

// GetCapabilities implements execution.ShardExecutionEngine.
func (m *MockShardExecutionEngine) GetCapabilities() []*protobufs.Capability {
	args := m.Called()
	return args.Get(0).([]*protobufs.Capability)
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

// ValidateMessage implements execution.ShardExecutionEngine.
func (m *MockShardExecutionEngine) ValidateMessage(
	frameNumber uint64,
	address []byte,
	message []byte,
) error {
	args := m.Called(frameNumber, address, message)
	return args.Error(0)
}

// ProcessMessage implements execution.ShardExecutionEngine.
func (m *MockShardExecutionEngine) ProcessMessage(
	frameNumber uint64,
	feeMultipler *big.Int,
	address []byte,
	message []byte,
	state state.State,
) (*execution.ProcessMessageResult, error) {
	args := m.Called(frameNumber, address, message, state)
	return args.Get(0).(*execution.ProcessMessageResult), args.Error(1)
}

// Start implements execution.ShardExecutionEngine.
func (m *MockShardExecutionEngine) Start() <-chan error {
	args := m.Called()
	return args.Get(0).(chan error)
}

// Stop implements execution.ShardExecutionEngine.
func (m *MockShardExecutionEngine) Stop(force bool) <-chan error {
	args := m.Called(force)
	return args.Get(0).(chan error)
}

var _ execution.ShardExecutionEngine = (*MockShardExecutionEngine)(nil)
