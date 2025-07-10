package store

import (
	"math/big"

	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

type DataProofStore interface {
	NewTransaction() (Transaction, error)
	GetAggregateProof(
		filter []byte,
		commitment []byte,
		frameNumber uint64,
	) (
		*protobufs.InclusionAggregateProof,
		error,
	)
	PutAggregateProof(
		txn Transaction,
		aggregateProof *protobufs.InclusionAggregateProof,
		commitment []byte,
	) error
	GetDataTimeProof(
		peerId []byte,
		increment uint32,
	) (difficulty, parallelism uint32, input, output []byte, err error)
	GetTotalReward(
		peerId []byte,
	) (*big.Int, error)
	PutDataTimeProof(
		txn Transaction,
		parallelism uint32,
		peerId []byte,
		increment uint32,
		input []byte,
		output []byte,
	) error
	GetLatestDataTimeProof(peerId []byte) (
		increment uint32,
		parallelism uint32,
		output []byte,
		err error,
	)
	RewindToIncrement(peerId []byte, increment uint32) error
}
