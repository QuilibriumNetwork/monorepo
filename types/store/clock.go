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
	PutGlobalClockFrame(frame *protobufs.GlobalFrame, txn Transaction) error
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
	GetStagedShardClockFramesForFrameNumber(
		filter []byte,
		frameNumber uint64,
	) ([]*protobufs.AppShardFrame, error)
	SetLatestShardClockFrameNumber(
		filter []byte,
		frameNumber uint64,
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
}
