package store

import (
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
	TombstoneVertexTree(
		txn tries.TreeBackingStoreTransaction,
		deleteAt int64,
		id []byte,
	) error
	UndoTombstoneVertexTree(
		txn tries.TreeBackingStoreTransaction,
		deleteAt int64,
		id []byte,
	) error
	ReapVertexTrees(txn tries.TreeBackingStoreTransaction) error
	GetVertexDataIterator(
		prefix tries.ShardKey,
	) (tries.VertexDataIterator, error)
	LoadHypergraph() (
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
	MarkHypergraphAsComplete()
}
