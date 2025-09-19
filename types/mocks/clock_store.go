package mocks

import (
	"math/big"

	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

var _ store.ClockStore = (*MockClockStore)(nil)

// MockClockStore is a minimal mock for store.ClockStore
type MockClockStore struct {
	mock.Mock
}

// CommitShardClockFrame implements store.ClockStore.
func (m *MockClockStore) CommitShardClockFrame(
	filter []byte,
	frameNumber uint64,
	selector []byte,
	proverTries []*tries.RollingFrecencyCritbitTrie,
	txn store.Transaction,
	backfill bool,
) error {
	args := m.Called(
		filter,
		frameNumber,
		selector,
		proverTries,
		txn,
		backfill,
	)
	return args.Error(0)
}

// Compact implements store.ClockStore.
func (m *MockClockStore) Compact(dataFilter []byte) error {
	args := m.Called(dataFilter)
	return args.Error(0)
}

// DeleteShardClockFrameRange implements store.ClockStore.
func (m *MockClockStore) DeleteShardClockFrameRange(
	filter []byte,
	minFrameNumber uint64,
	maxFrameNumber uint64,
) error {
	args := m.Called(filter, minFrameNumber, maxFrameNumber)
	return args.Error(0)
}

// DeleteGlobalClockFrameRange implements store.ClockStore.
func (m *MockClockStore) DeleteGlobalClockFrameRange(
	minFrameNumber uint64,
	maxFrameNumber uint64,
) error {
	args := m.Called(minFrameNumber, maxFrameNumber)
	return args.Error(0)
}

// GetEarliestGlobalClockFrame implements store.ClockStore.
func (m *MockClockStore) GetEarliestGlobalClockFrame() (
	*protobufs.GlobalFrame,
	error,
) {
	args := m.Called()
	return args.Get(0).(*protobufs.GlobalFrame), args.Error(1)
}

// GetEarliestShardClockFrame implements store.ClockStore.
func (m *MockClockStore) GetEarliestShardClockFrame(filter []byte) (
	*protobufs.AppShardFrame,
	error,
) {
	args := m.Called(filter)
	return args.Get(0).(*protobufs.AppShardFrame), args.Error(1)
}

// GetGlobalClockFrame implements store.ClockStore.
func (m *MockClockStore) GetGlobalClockFrame(
	frameNumber uint64,
) (*protobufs.GlobalFrame, error) {
	args := m.Called(frameNumber)
	return args.Get(0).(*protobufs.GlobalFrame), args.Error(1)
}

// GetLatestGlobalClockFrame implements store.ClockStore.
func (m *MockClockStore) GetLatestGlobalClockFrame() (
	*protobufs.GlobalFrame,
	error,
) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, store.ErrNotFound
	}
	return args.Get(0).(*protobufs.GlobalFrame), args.Error(1)
}

// GetLatestShardClockFrame implements store.ClockStore.
func (m *MockClockStore) GetLatestShardClockFrame(filter []byte) (
	*protobufs.AppShardFrame,
	[]*tries.RollingFrecencyCritbitTrie,
	error,
) {
	args := m.Called(filter)
	return args.Get(0).(*protobufs.AppShardFrame),
		args.Get(1).([]*tries.RollingFrecencyCritbitTrie),
		args.Error(2)
}

// GetPeerSeniorityMap implements store.ClockStore.
func (m *MockClockStore) GetPeerSeniorityMap(filter []byte) (
	map[string]uint64,
	error,
) {
	args := m.Called(filter)
	return args.Get(0).(map[string]uint64), args.Error(1)
}

// GetShardClockFrame implements store.ClockStore.
func (m *MockClockStore) GetShardClockFrame(
	filter []byte,
	frameNumber uint64,
	truncate bool,
) (*protobufs.AppShardFrame, []*tries.RollingFrecencyCritbitTrie, error) {
	args := m.Called(filter, frameNumber, truncate)
	return args.Get(0).(*protobufs.AppShardFrame),
		args.Get(1).([]*tries.RollingFrecencyCritbitTrie),
		args.Error(2)
}

// GetShardStateTree implements store.ClockStore.
func (m *MockClockStore) GetShardStateTree(filter []byte) (
	*tries.VectorCommitmentTree,
	error,
) {
	args := m.Called(filter)
	return args.Get(0).(*tries.VectorCommitmentTree), args.Error(1)
}

// GetStagedShardClockFrame implements store.ClockStore.
func (m *MockClockStore) GetStagedShardClockFrame(
	filter []byte,
	frameNumber uint64,
	parentSelector []byte,
	truncate bool,
) (*protobufs.AppShardFrame, error) {
	args := m.Called(filter, frameNumber, parentSelector, truncate)
	return args.Get(0).(*protobufs.AppShardFrame), args.Error(1)
}

// GetStagedShardClockFramesForFrameNumber implements store.ClockStore.
func (m *MockClockStore) GetStagedShardClockFramesForFrameNumber(
	filter []byte,
	frameNumber uint64,
) ([]*protobufs.AppShardFrame, error) {
	args := m.Called(filter, frameNumber)
	return args.Get(0).([]*protobufs.AppShardFrame), args.Error(1)
}

// GetTotalDistance implements store.ClockStore.
func (m *MockClockStore) GetTotalDistance(
	filter []byte,
	frameNumber uint64,
	selector []byte,
) (*big.Int, error) {
	args := m.Called(filter, frameNumber, selector)
	return args.Get(0).(*big.Int), args.Error(1)
}

// NewTransaction implements store.ClockStore.
func (m *MockClockStore) NewTransaction(
	indexed bool,
) (store.Transaction, error) {
	args := m.Called(indexed)
	return args.Get(0).(store.Transaction), args.Error(1)
}

// PutGlobalClockFrame implements store.ClockStore.
func (m *MockClockStore) PutGlobalClockFrame(
	frame *protobufs.GlobalFrame,
	txn store.Transaction,
) error {
	args := m.Called(frame, txn)
	return args.Error(0)
}

// PutPeerSeniorityMap implements store.ClockStore.
func (m *MockClockStore) PutPeerSeniorityMap(
	txn store.Transaction,
	filter []byte,
	seniorityMap map[string]uint64,
) error {
	args := m.Called(txn, filter, seniorityMap)
	return args.Error(0)
}

// RangeGlobalClockFrames implements store.ClockStore.
func (m *MockClockStore) RangeGlobalClockFrames(
	startFrameNumber uint64,
	endFrameNumber uint64,
) (store.TypedIterator[*protobufs.GlobalFrame], error) {
	args := m.Called(startFrameNumber, endFrameNumber)
	return args.Get(0).(store.TypedIterator[*protobufs.GlobalFrame]),
		args.Error(1)
}

// RangeShardClockFrames implements store.ClockStore.
func (m *MockClockStore) RangeShardClockFrames(
	filter []byte,
	startFrameNumber uint64,
	endFrameNumber uint64,
) (store.TypedIterator[*protobufs.AppShardFrame], error) {
	args := m.Called(filter, startFrameNumber, endFrameNumber)
	return args.Get(0).(store.TypedIterator[*protobufs.AppShardFrame]),
		args.Error(1)
}

// ResetGlobalClockFrames implements store.ClockStore.
func (m *MockClockStore) ResetGlobalClockFrames() error {
	args := m.Called()
	return args.Error(0)
}

// ResetShardClockFrames implements store.ClockStore.
func (m *MockClockStore) ResetShardClockFrames(filter []byte) error {
	args := m.Called(filter)
	return args.Error(0)
}

// SetLatestShardClockFrameNumber implements store.ClockStore.
func (m *MockClockStore) SetLatestShardClockFrameNumber(
	filter []byte,
	frameNumber uint64,
) error {
	args := m.Called(filter, frameNumber)
	return args.Error(0)
}

// SetProverTriesForGlobalFrame implements store.ClockStore.
func (m *MockClockStore) SetProverTriesForGlobalFrame(
	frame *protobufs.GlobalFrame,
	tries []*tries.RollingFrecencyCritbitTrie,
) error {
	args := m.Called(frame, tries)
	return args.Error(0)
}

// SetProverTriesForShardFrame implements store.ClockStore.
func (m *MockClockStore) SetProverTriesForShardFrame(
	frame *protobufs.AppShardFrame,
	tries []*tries.RollingFrecencyCritbitTrie,
) error {
	args := m.Called(frame, tries)
	return args.Error(0)
}

// SetShardStateTree implements store.ClockStore.
func (m *MockClockStore) SetShardStateTree(
	txn store.Transaction,
	filter []byte,
	tree *tries.VectorCommitmentTree,
) error {
	args := m.Called(txn, filter, tree)
	return args.Error(0)
}

// SetTotalDistance implements store.ClockStore.
func (m *MockClockStore) SetTotalDistance(
	filter []byte,
	frameNumber uint64,
	selector []byte,
	totalDistance *big.Int,
) error {
	args := m.Called(filter, frameNumber, selector, totalDistance)
	return args.Error(0)
}

// StageShardClockFrame implements store.ClockStore.
func (m *MockClockStore) StageShardClockFrame(
	selector []byte,
	frame *protobufs.AppShardFrame,
	txn store.Transaction,
) error {
	args := m.Called(selector, frame, txn)
	return args.Error(0)
}
