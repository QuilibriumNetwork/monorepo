package consensus

import (
	"errors"

	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// MixnetState represents the state of the mixnet
type MixnetState int

const (
	// MixnetStateIdle indicates the mixnet is idle and not processing
	MixnetStateIdle MixnetState = iota
	// MixnetStatePreparing indicates the mixnet is preparing for mixing
	MixnetStatePreparing
	// MixnetStateCollecting indicates the mixnet is ready for receiving messages
	MixnetStateCollecting
	// MixnetStateMixing indicates the mixnet is actively mixing messages
	MixnetStateMixing
	// MixnetStateReady indicates mixing is complete and messages are ready
	MixnetStateReady
	// MixnetStateError indicates an error occurred during mixing
	MixnetStateError
)

var (
	ErrNoActiveRound       = errors.New("no active round, call PrepareMixnet first")
	ErrRoundMismatch       = errors.New("round_identifier does not match active round")
	ErrTooManyTags         = errors.New("tag requests exceed round capacity")
	ErrIndexOutOfRange     = errors.New("tag index out of range")
	ErrAlreadySet          = errors.New("value already set for this index/party")
	ErrInvalidRequest      = errors.New("invalid request")
	ErrMissingEphemeralKey = errors.New("missing ephemeral public key")
	ErrConsensusFault      = errors.New("consensus fault")
)

// Mixnet defines the interface for a mixnet-based transaction mempool
// It handles the collection, mixing, and retrieval of transaction messages
// with privacy-preserving properties
type Mixnet interface {
	protobufs.MixnetServiceServer

	// PrepareMixnet prepares the mixnet
	// This should be called before messages can be retrieved
	PrepareMixnet() error

	// GetState returns the current state of the mixnet
	GetState() MixnetState

	// GetMessages retrieves the mixed messages from the mixnet
	// Returns an empty slice if the mixnet is not in the ready state
	GetMessages() []*protobufs.Message
}
