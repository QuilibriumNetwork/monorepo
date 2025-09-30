package store

import (
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type HypergraphStore interface {
	NewTransaction(indexed bool) (tries.TreeBackingStoreTransaction, error)
	LoadVertexTree(id []byte) (
		*tries.VectorCommitmentTree,
		error,
	)
	SaveVertexTree(
		txn tries.TreeBackingStoreTransaction,
		id []byte,
		vertTree *tries.VectorCommitmentTree,
	) error
	GetVertexDataIterator(
		prefix tries.ShardKey,
	) (tries.VertexDataIterator, error)
	SetCoveredPrefix(coveredPrefix []int) error
	LoadHypergraph(
		authenticationProvider channel.AuthenticationProvider,
	) (
		hypergraph.Hypergraph,
		error,
	)
	GetNodeByKey(
		setType string,
		phaseType string,
		shardKey tries.ShardKey,
		key []byte,
	) (tries.LazyVectorCommitmentNode, error)
	GetNodeByPath(
		setType string,
		phaseType string,
		shardKey tries.ShardKey,
		path []int,
	) (tries.LazyVectorCommitmentNode, error)
	InsertNode(
		txn tries.TreeBackingStoreTransaction,
		setType string,
		phaseType string,
		shardKey tries.ShardKey,
		key []byte,
		path []int,
		node tries.LazyVectorCommitmentNode,
	) error
	SaveRoot(
		setType string,
		phaseType string,
		shardKey tries.ShardKey,
		node tries.LazyVectorCommitmentNode,
	) error
	DeleteNode(
		txn tries.TreeBackingStoreTransaction,
		setType string,
		phaseType string,
		shardKey tries.ShardKey,
		key []byte,
		path []int,
	) error
	DeleteUncoveredPrefix(
		setType string,
		phaseType string,
		shardKey tries.ShardKey,
		prefix []int,
	) error
	ReapOldChangesets(
		txn tries.TreeBackingStoreTransaction,
		frameNumber uint64,
	) error
	TrackChange(
		txn tries.TreeBackingStoreTransaction,
		key []byte,
		oldValue *tries.VectorCommitmentTree,
		frameNumber uint64,
		phaseType string,
		setType string,
		shardKey tries.ShardKey,
	) error
	GetChanges(
		frameStart uint64,
		frameEnd uint64,
		phaseType string,
		setType string,
		shardKey tries.ShardKey,
	) ([]*tries.ChangeRecord, error)
	UntrackChange(
		txn tries.TreeBackingStoreTransaction,
		key []byte,
		frameNumber uint64,
		phaseType string,
		setType string,
		shardKey tries.ShardKey,
	) error
	MarkHypergraphAsComplete()
	ApplySnapshot(dbPath string) error
}
