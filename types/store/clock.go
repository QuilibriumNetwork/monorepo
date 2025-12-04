package store

import (
	"math/big"

	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type ClockStore interface {
	NewTransaction(indexed bool) (Transaction, error)
	GetLatestGlobalClockFrame() (*protobufs.GlobalFrame, error)
	GetEarliestGlobalClockFrame() (*protobufs.GlobalFrame, error)
	GetGlobalClockFrame(frameNumber uint64) (*protobufs.GlobalFrame, error)
	RangeGlobalClockFrames(
		startFrameNumber uint64,
		endFrameNumber uint64,
	) (TypedIterator[*protobufs.GlobalFrame], error)
	RangeGlobalClockFrameCandidates(
		startFrameNumber uint64,
		endFrameNumber uint64,
	) (TypedIterator[*protobufs.GlobalFrame], error)
	PutGlobalClockFrame(frame *protobufs.GlobalFrame, txn Transaction) error
	PutGlobalClockFrameCandidate(
		frame *protobufs.GlobalFrame,
		txn Transaction,
	) error
	GetGlobalClockFrameCandidate(
		frameNumber uint64,
		selector []byte,
	) (*protobufs.GlobalFrame, error)
	GetLatestCertifiedGlobalState() (*protobufs.GlobalProposal, error)
	GetEarliestCertifiedGlobalState() (*protobufs.GlobalProposal, error)
	GetCertifiedGlobalState(rank uint64) (*protobufs.GlobalProposal, error)
	RangeCertifiedGlobalStates(
		startRank uint64,
		endRank uint64,
	) (TypedIterator[*protobufs.GlobalProposal], error)
	PutCertifiedGlobalState(
		state *protobufs.GlobalProposal,
		txn Transaction,
	) error
	GetLatestQuorumCertificate(
		filter []byte,
	) (*protobufs.QuorumCertificate, error)
	GetEarliestQuorumCertificate(
		filter []byte,
	) (*protobufs.QuorumCertificate, error)
	GetQuorumCertificate(
		filter []byte,
		rank uint64,
	) (*protobufs.QuorumCertificate, error)
	RangeQuorumCertificates(
		filter []byte,
		startRank uint64,
		endRank uint64,
	) (TypedIterator[*protobufs.QuorumCertificate], error)
	PutQuorumCertificate(
		qc *protobufs.QuorumCertificate,
		txn Transaction,
	) error
	GetLatestTimeoutCertificate(
		filter []byte,
	) (*protobufs.TimeoutCertificate, error)
	GetEarliestTimeoutCertificate(
		filter []byte,
	) (*protobufs.TimeoutCertificate, error)
	GetTimeoutCertificate(
		filter []byte,
		rank uint64,
	) (*protobufs.TimeoutCertificate, error)
	RangeTimeoutCertificates(
		filter []byte,
		startRank uint64,
		endRank uint64,
	) (TypedIterator[*protobufs.TimeoutCertificate], error)
	PutTimeoutCertificate(
		timeoutCertificate *protobufs.TimeoutCertificate,
		txn Transaction,
	) error
	GetLatestShardClockFrame(
		filter []byte,
	) (*protobufs.AppShardFrame, []*tries.RollingFrecencyCritbitTrie, error)
	GetEarliestShardClockFrame(filter []byte) (*protobufs.AppShardFrame, error)
	GetShardClockFrame(
		filter []byte,
		frameNumber uint64,
		truncate bool,
	) (*protobufs.AppShardFrame, []*tries.RollingFrecencyCritbitTrie, error)
	RangeShardClockFrames(
		filter []byte,
		startFrameNumber uint64,
		endFrameNumber uint64,
	) (TypedIterator[*protobufs.AppShardFrame], error)
	CommitShardClockFrame(
		filter []byte,
		frameNumber uint64,
		selector []byte,
		proverTries []*tries.RollingFrecencyCritbitTrie,
		txn Transaction,
		backfill bool,
	) error
	StageShardClockFrame(
		selector []byte,
		frame *protobufs.AppShardFrame,
		txn Transaction,
	) error
	GetStagedShardClockFrame(
		filter []byte,
		frameNumber uint64,
		parentSelector []byte,
		truncate bool,
	) (*protobufs.AppShardFrame, error)
	RangeStagedShardClockFrames(
		filter []byte,
		startFrameNumber uint64,
		endFrameNumber uint64,
	) (TypedIterator[*protobufs.AppShardFrame], error)
	GetStagedShardClockFramesForFrameNumber(
		filter []byte,
		frameNumber uint64,
	) ([]*protobufs.AppShardFrame, error)
	SetLatestShardClockFrameNumber(
		filter []byte,
		frameNumber uint64,
	) error
	GetLatestCertifiedAppShardState(
		filter []byte,
	) (*protobufs.AppShardProposal, error)
	GetEarliestCertifiedAppShardState(
		filter []byte,
	) (*protobufs.AppShardProposal, error)
	GetCertifiedAppShardState(
		filter []byte,
		rank uint64,
	) (*protobufs.AppShardProposal, error)
	RangeCertifiedAppShardStates(
		filter []byte,
		startRank uint64,
		endRank uint64,
	) (TypedIterator[*protobufs.AppShardProposal], error)
	PutCertifiedAppShardState(
		state *protobufs.AppShardProposal,
		txn Transaction,
	) error
	ResetGlobalClockFrames() error
	ResetShardClockFrames(filter []byte) error
	Compact(
		dataFilter []byte,
	) error
	GetTotalDistance(
		filter []byte,
		frameNumber uint64,
		selector []byte,
	) (*big.Int, error)
	SetTotalDistance(
		filter []byte,
		frameNumber uint64,
		selector []byte,
		totalDistance *big.Int,
	) error
	GetPeerSeniorityMap(filter []byte) (map[string]uint64, error)
	PutPeerSeniorityMap(
		txn Transaction,
		filter []byte,
		seniorityMap map[string]uint64,
	) error
	SetProverTriesForGlobalFrame(
		frame *protobufs.GlobalFrame,
		tries []*tries.RollingFrecencyCritbitTrie,
	) error
	SetProverTriesForShardFrame(
		frame *protobufs.AppShardFrame,
		tries []*tries.RollingFrecencyCritbitTrie,
	) error
	DeleteGlobalClockFrameRange(
		minFrameNumber uint64,
		maxFrameNumber uint64,
	) error
	DeleteShardClockFrameRange(
		filter []byte,
		minFrameNumber uint64,
		maxFrameNumber uint64,
	) error
	GetShardStateTree(filter []byte) (*tries.VectorCommitmentTree, error)
	SetShardStateTree(
		txn Transaction,
		filter []byte,
		tree *tries.VectorCommitmentTree,
	) error
	PutProposalVote(txn Transaction, vote *protobufs.ProposalVote) error
	GetProposalVote(filter []byte, rank uint64, identity []byte) (
		*protobufs.ProposalVote,
		error,
	)
	GetProposalVotes(filter []byte, rank uint64) (
		[]*protobufs.ProposalVote,
		error,
	)
	PutTimeoutVote(txn Transaction, vote *protobufs.TimeoutState) error
	GetTimeoutVote(filter []byte, rank uint64, identity []byte) (
		*protobufs.TimeoutState,
		error,
	)
	GetTimeoutVotes(filter []byte, rank uint64) (
		[]*protobufs.TimeoutState,
		error,
	)
}
