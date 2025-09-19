package state

import (
	"errors"

	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type Iterator interface {
	Key() []byte
	First() bool
	Next() bool
	Prev() bool
	Valid() bool
	Value() []byte
	Close() error
	SeekLT([]byte) bool
	SeekGE([]byte) bool
	Last() bool
}

type MaterializedState interface {
	DataValue() *tries.VectorCommitmentTree
	Commit(txn tries.TreeBackingStoreTransaction) error
}

type StateChangeEvent uint8

const (
	CreateStateChangeEvent StateChangeEvent = iota
	UpdateStateChangeEvent
	DeleteStateChangeEvent
	InitializeStateChangeEvent
)

var ErrAlreadyInitialized = errors.New("already initialized")
var ErrNotInitialized = errors.New("not initialized")
var ErrInvalidDomain = errors.New("invalid domain")
var ErrInvalidData = errors.New("invalid data")
var ErrInvalidDiscriminator = errors.New("invalid discriminator")
var ErrConflictingChange = errors.New("conflicting change")

type StateChange struct {
	Domain        []byte
	Address       []byte
	Discriminator []byte
	StateChange   StateChangeEvent
	Value         MaterializedState
}

type State interface {
	Init(
		domain []byte,
		consensusMetadata *tries.VectorCommitmentTree,
		sumcheckInfo *tries.VectorCommitmentTree,
		rdfSchema string,
		additionalData []*tries.VectorCommitmentTree,
		intrinsicType []byte,
	) error
	Get(domain []byte, address []byte, discriminator []byte) (
		interface{},
		error,
	)
	Set(
		domain []byte,
		address []byte,
		discriminator []byte,
		frameNumber uint64,
		value MaterializedState,
	) error
	Delete(
		domain []byte,
		address []byte,
		discriminator []byte,
		frameNumber uint64,
	) error
	Changeset() []StateChange
	Commit() error
	Abort() error
}
