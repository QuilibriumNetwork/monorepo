package consensus

import "source.quilibrium.com/quilibrium/monorepo/protobufs"

// MixnetState represents the state of the mixnet
type MixnetState int

const (
	// MixnetStateIdle indicates the mixnet is idle and not processing
	MixnetStateIdle MixnetState = iota
	// MixnetStatePreparing indicates the mixnet is preparing for mixing
	MixnetStatePreparing
	// MixnetStateMixing indicates the mixnet is actively mixing messages
	MixnetStateMixing
	// MixnetStateReady indicates mixing is complete and messages are ready
	MixnetStateReady
	// MixnetStateError indicates an error occurred during mixing
	MixnetStateError
)

// Mixnet defines the interface for a mixnet-based transaction mempool
// It handles the collection, mixing, and retrieval of transaction messages
// with privacy-preserving properties
type Mixnet interface {
	// PrepareMixnet prepares the mixnet
	// This should be called before messages can be retrieved
	PrepareMixnet() error

	// GetState returns the current state of the mixnet
	GetState() MixnetState

	// GetMessages retrieves the mixed messages from the mixnet
	// Returns an empty slice if the mixnet is not in the ready state
	GetMessages() []*protobufs.Message
}
