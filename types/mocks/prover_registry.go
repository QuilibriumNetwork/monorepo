package mocks

import (
	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
)

type MockProverRegistry struct {
	mock.Mock
}

var _ consensus.ProverRegistry = (*MockProverRegistry)(nil)

// CurrentFrame implements consensus.ProverRegistry.
func (m *MockProverRegistry) CurrentFrame() uint64 {
	args := m.Called()
	return args.Get(0).(uint64)
}

// PruneOrphanJoins implements consensus.ProverRegistry.
func (m *MockProverRegistry) PruneOrphanJoins(frameNumber uint64) error {
	args := m.Called(frameNumber)
	return args.Error(0)
}

// GetProvers implements consensus.ProverRegistry.
func (m *MockProverRegistry) GetProvers(filter []byte) (
	[]*consensus.ProverInfo,
	error,
) {
	args := m.Called(filter)
	return args.Get(0).([]*consensus.ProverInfo), args.Error(1)
}

// GetAllActiveAppShardProvers implements consensus.ProverRegistry.
func (m *MockProverRegistry) GetAllActiveAppShardProvers() (
	[]*consensus.ProverInfo,
	error,
) {
	args := m.Called()
	return args.Get(0).([]*consensus.ProverInfo), args.Error(1)
}

// GetProverShardSummaries implements consensus.ProverRegistry.
func (m *MockProverRegistry) GetProverShardSummaries() (
	[]*consensus.ProverShardSummary,
	error,
) {
	args := m.Called()
	return args.Get(0).([]*consensus.ProverShardSummary), args.Error(1)
}

func (m *MockProverRegistry) ProcessStateTransition(
	state state.State,
	frameNumber uint64,
) error {
	args := m.Called(state, frameNumber)
	return args.Error(0)
}

func (m *MockProverRegistry) GetProverInfo(address []byte) (
	*consensus.ProverInfo,
	error,
) {
	args := m.Called(address)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*consensus.ProverInfo), args.Error(1)
}

func (m *MockProverRegistry) GetNextProver(
	input [32]byte,
	filter []byte,
) ([]byte, error) {
	args := m.Called(input, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockProverRegistry) GetActiveProvers(filter []byte) (
	[]*consensus.ProverInfo,
	error,
) {
	args := m.Called(filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*consensus.ProverInfo), args.Error(1)
}

func (m *MockProverRegistry) GetOrderedProvers(
	input [32]byte,
	filter []byte,
) ([][]byte, error) {
	args := m.Called(input, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([][]byte), args.Error(1)
}

func (m *MockProverRegistry) GetProverCount(filter []byte) (int, error) {
	args := m.Called(filter)
	return args.Int(0), args.Error(1)
}

func (m *MockProverRegistry) GetProversByStatus(
	filter []byte,
	status consensus.ProverStatus,
) ([]*consensus.ProverInfo, error) {
	args := m.Called(filter, status)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*consensus.ProverInfo), args.Error(1)
}

func (m *MockProverRegistry) UpdateProverActivity(
	address []byte,
	filter []byte,
	frameNumber uint64,
) error {
	args := m.Called(address, filter, frameNumber)
	return args.Error(0)
}

func (m *MockProverRegistry) Refresh() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockProverRegistry) ExtractProversFromTransactions(
	transactions []state.StateChange,
) error {
	args := m.Called(transactions)
	return args.Error(0)
}

// EvictInactiveProvers implements consensus.ProverRegistry.
func (m *MockProverRegistry) EvictInactiveProvers(
	frameNumber uint64,
	inactivityThreshold uint64,
	shardHaltDurations map[string]uint64,
	state state.State,
) ([][]byte, error) {
	args := m.Called(frameNumber, inactivityThreshold, shardHaltDurations, state)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([][]byte), args.Error(1)
}
