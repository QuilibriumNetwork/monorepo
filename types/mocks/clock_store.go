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

// RangeStagedShardClockFrames implements store.ClockStore.
func (m *MockClockStore) RangeStagedShardClockFrames(
	filter []byte,
	startFrameNumber uint64,
	endFrameNumber uint64,
) (store.TypedIterator[*protobufs.AppShardFrame], error) {
	args := m.Called(
		filter,
		startFrameNumber,
		endFrameNumber,
	)

	return args.Get(0).(store.TypedIterator[*protobufs.AppShardFrame]),
		args.Error(1)
}

// RangeGlobalClockFrameCandidates implements store.ClockStore.
func (m *MockClockStore) RangeGlobalClockFrameCandidates(
	startFrameNumber uint64,
	endFrameNumber uint64,
) (store.TypedIterator[*protobufs.GlobalFrame], error) {
	args := m.Called(
		startFrameNumber,
		endFrameNumber,
	)

	return args.Get(0).(store.TypedIterator[*protobufs.GlobalFrame]),
		args.Error(1)
}

// GetGlobalClockFrameCandidate implements store.ClockStore.
func (m *MockClockStore) GetGlobalClockFrameCandidate(
	frameNumber uint64,
	selector []byte,
) (*protobufs.GlobalFrame, error) {
	args := m.Called(
		frameNumber,
		selector,
	)

	return args.Get(0).(*protobufs.GlobalFrame), args.Error(1)
}

// PutGlobalClockFrameCandidate implements store.ClockStore.
func (m *MockClockStore) PutGlobalClockFrameCandidate(
	frame *protobufs.GlobalFrame,
	txn store.Transaction,
) error {
	args := m.Called(
		frame,
		txn,
	)

	return args.Error(0)
}

// GetProposalVote implements store.ClockStore.
func (m *MockClockStore) GetProposalVote(
	filter []byte,
	rank uint64,
	identity []byte,
) (*protobufs.ProposalVote, error) {
	args := m.Called(
		filter,
		rank,
		identity,
	)
	return args.Get(0).(*protobufs.ProposalVote), args.Error(1)
}

// GetProposalVotes implements store.ClockStore.
func (m *MockClockStore) GetProposalVotes(
	filter []byte,
	rank uint64,
) ([]*protobufs.ProposalVote, error) {
	args := m.Called(
		filter,
		rank,
	)
	return args.Get(0).([]*protobufs.ProposalVote), args.Error(1)
}

// GetTimeoutVote implements store.ClockStore.
func (m *MockClockStore) GetTimeoutVote(
	filter []byte,
	rank uint64,
	identity []byte,
) (*protobufs.TimeoutState, error) {
	args := m.Called(
		filter,
		rank,
		identity,
	)
	return args.Get(0).(*protobufs.TimeoutState), args.Error(1)
}

// GetTimeoutVotes implements store.ClockStore.
func (m *MockClockStore) GetTimeoutVotes(
	filter []byte,
	rank uint64,
) ([]*protobufs.TimeoutState, error) {
	args := m.Called(
		filter,
		rank,
	)
	return args.Get(0).([]*protobufs.TimeoutState), args.Error(1)
}

// PutProposalVote implements store.ClockStore.
func (m *MockClockStore) PutProposalVote(
	txn store.Transaction,
	vote *protobufs.ProposalVote,
) error {
	args := m.Called(
		txn,
		vote,
	)
	return args.Error(0)
}

// PutTimeoutVote implements store.ClockStore.
func (m *MockClockStore) PutTimeoutVote(
	txn store.Transaction,
	vote *protobufs.TimeoutState,
) error {
	args := m.Called(
		txn,
		vote,
	)
	return args.Error(0)
}

// GetCertifiedAppShardState implements store.ClockStore.
func (m *MockClockStore) GetCertifiedAppShardState(
	filter []byte,
	rank uint64,
) (*protobufs.AppShardProposal, error) {
	args := m.Called(
		filter,
		rank,
	)
	return args.Get(0).(*protobufs.AppShardProposal), args.Error(1)
}

// GetCertifiedGlobalState implements store.ClockStore.
func (m *MockClockStore) GetCertifiedGlobalState(rank uint64) (
	*protobufs.GlobalProposal,
	error,
) {
	args := m.Called(
		rank,
	)
	return args.Get(0).(*protobufs.GlobalProposal), args.Error(1)
}

// GetEarliestCertifiedAppShardState implements store.ClockStore.
func (m *MockClockStore) GetEarliestCertifiedAppShardState(
	filter []byte,
) (*protobufs.AppShardProposal, error) {
	args := m.Called(
		filter,
	)
	return args.Get(0).(*protobufs.AppShardProposal), args.Error(1)
}

// GetEarliestCertifiedGlobalState implements store.ClockStore.
func (m *MockClockStore) GetEarliestCertifiedGlobalState() (
	*protobufs.GlobalProposal,
	error,
) {
	args := m.Called()
	return args.Get(0).(*protobufs.GlobalProposal), args.Error(1)
}

// GetEarliestQuorumCertificate implements store.ClockStore.
func (m *MockClockStore) GetEarliestQuorumCertificate(filter []byte) (
	*protobufs.QuorumCertificate,
	error,
) {
	args := m.Called(
		filter,
	)
	return args.Get(0).(*protobufs.QuorumCertificate), args.Error(1)
}

// GetEarliestTimeoutCertificate implements store.ClockStore.
func (m *MockClockStore) GetEarliestTimeoutCertificate(filter []byte) (
	*protobufs.TimeoutCertificate,
	error,
) {
	args := m.Called(
		filter,
	)
	return args.Get(0).(*protobufs.TimeoutCertificate), args.Error(1)
}

// GetLatestCertifiedAppShardState implements store.ClockStore.
func (m *MockClockStore) GetLatestCertifiedAppShardState(filter []byte) (
	*protobufs.AppShardProposal,
	error,
) {
	args := m.Called(
		filter,
	)
	return args.Get(0).(*protobufs.AppShardProposal), args.Error(1)
}

// GetLatestCertifiedGlobalState implements store.ClockStore.
func (m *MockClockStore) GetLatestCertifiedGlobalState() (
	*protobufs.GlobalProposal,
	error,
) {
	args := m.Called()
	return args.Get(0).(*protobufs.GlobalProposal), args.Error(1)
}

// GetLatestQuorumCertificate implements store.ClockStore.
func (m *MockClockStore) GetLatestQuorumCertificate(filter []byte) (
	*protobufs.QuorumCertificate,
	error,
) {
	args := m.Called(
		filter,
	)
	return args.Get(0).(*protobufs.QuorumCertificate), args.Error(1)
}

// GetLatestTimeoutCertificate implements store.ClockStore.
func (m *MockClockStore) GetLatestTimeoutCertificate(filter []byte) (
	*protobufs.TimeoutCertificate,
	error,
) {
	args := m.Called(
		filter,
	)
	return args.Get(0).(*protobufs.TimeoutCertificate), args.Error(1)
}

// GetQuorumCertificate implements store.ClockStore.
func (m *MockClockStore) GetQuorumCertificate(filter []byte, rank uint64) (
	*protobufs.QuorumCertificate,
	error,
) {
	args := m.Called(
		filter,
		rank,
	)
	return args.Get(0).(*protobufs.QuorumCertificate), args.Error(1)
}

// GetTimeoutCertificate implements store.ClockStore.
func (m *MockClockStore) GetTimeoutCertificate(filter []byte, rank uint64) (
	*protobufs.TimeoutCertificate,
	error,
) {
	args := m.Called(
		filter,
		rank,
	)
	return args.Get(0).(*protobufs.TimeoutCertificate), args.Error(1)
}

// PutCertifiedAppShardState implements store.ClockStore.
func (m *MockClockStore) PutCertifiedAppShardState(
	state *protobufs.AppShardProposal,
	txn store.Transaction,
) error {
	args := m.Called(
		state,
		txn,
	)
	return args.Error(0)
}

// PutCertifiedGlobalState implements store.ClockStore.
func (m *MockClockStore) PutCertifiedGlobalState(
	state *protobufs.GlobalProposal,
	txn store.Transaction,
) error {
	args := m.Called(
		state,
		txn,
	)
	return args.Error(0)
}

// PutQuorumCertificate implements store.ClockStore.
func (m *MockClockStore) PutQuorumCertificate(
	qc *protobufs.QuorumCertificate,
	txn store.Transaction,
) error {
	args := m.Called(
		qc,
		txn,
	)
	return args.Error(0)
}

// PutTimeoutCertificate implements store.ClockStore.
func (m *MockClockStore) PutTimeoutCertificate(
	timeoutCertificate *protobufs.TimeoutCertificate,
	txn store.Transaction,
) error {
	args := m.Called(
		timeoutCertificate,
		txn,
	)
	return args.Error(0)
}

// RangeCertifiedAppShardStates implements store.ClockStore.
func (m *MockClockStore) RangeCertifiedAppShardStates(
	filter []byte,
	startRank uint64,
	endRank uint64,
) (store.TypedIterator[*protobufs.AppShardProposal], error) {
	args := m.Called(
		filter,
		startRank,
		endRank,
	)
	return args.Get(0).(store.TypedIterator[*protobufs.AppShardProposal]),
		args.Error(1)
}

// RangeCertifiedGlobalStates implements store.ClockStore.
func (m *MockClockStore) RangeCertifiedGlobalStates(
	startRank uint64,
	endRank uint64,
) (store.TypedIterator[*protobufs.GlobalProposal], error) {
	args := m.Called(
		startRank,
		endRank,
	)
	return args.Get(0).(store.TypedIterator[*protobufs.GlobalProposal]),
		args.Error(1)
}

// RangeQuorumCertificates implements store.ClockStore.
func (m *MockClockStore) RangeQuorumCertificates(
	filter []byte,
	startRank uint64,
	endRank uint64,
) (store.TypedIterator[*protobufs.QuorumCertificate], error) {
	args := m.Called(
		filter,
		startRank,
		endRank,
	)
	return args.Get(0).(store.TypedIterator[*protobufs.QuorumCertificate]),
		args.Error(1)
}

// RangeTimeoutCertificates implements store.ClockStore.
func (m *MockClockStore) RangeTimeoutCertificates(
	filter []byte,
	startRank uint64,
	endRank uint64,
) (store.TypedIterator[*protobufs.TimeoutCertificate], error) {
	args := m.Called(
		filter,
		startRank,
		endRank,
	)
	return args.Get(0).(store.TypedIterator[*protobufs.TimeoutCertificate]),
		args.Error(1)
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
