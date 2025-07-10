package store

import (
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

type KeyStore interface {
	NewTransaction() (Transaction, error)
	StageProvingKey(provingKey *protobufs.ProvingKeyAnnouncement) error
	IncludeProvingKey(
		inclusionCommitment *protobufs.InclusionCommitment,
		txn Transaction,
	) error
	GetStagedProvingKey(
		provingKey []byte,
	) (*protobufs.ProvingKeyAnnouncement, error)
	GetProvingKey(provingKey []byte) (*protobufs.InclusionCommitment, error)
	GetKeyBundle(
		provingKey []byte,
		frameNumber uint64,
	) (*protobufs.InclusionCommitment, error)
	GetLatestKeyBundle(provingKey []byte) (*protobufs.InclusionCommitment, error)
	PutKeyBundle(
		provingKey []byte,
		keyBundleCommitment *protobufs.InclusionCommitment,
		txn Transaction,
	) error
	RangeProvingKeys() (
		TypedIterator[*protobufs.InclusionCommitment],
		error,
	)
	RangeStagedProvingKeys() (
		TypedIterator[*protobufs.ProvingKeyAnnouncement],
		error,
	)
	RangeKeyBundleKeys(provingKey []byte) (
		TypedIterator[*protobufs.InclusionCommitment],
		error,
	)
}
