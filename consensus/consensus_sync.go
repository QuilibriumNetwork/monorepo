package consensus

import (
	"context"

	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// SyncProvider handles synchronization management
type SyncProvider[StateT models.Unique] interface {
	// Performs synchronization to set internal state. Note that it is assumed
	// that errors are transient and synchronization should be reattempted on
	// failure. If some other process for synchronization is used and this should
	// be bypassed, send nil on the error channel. Provided context may be
	// canceled, should be used to halt long-running sync operations.
	Synchronize(
		ctx context.Context,
		existing *StateT,
	) (<-chan *StateT, <-chan error)

	// Initiates hypersync with a prover.
	HyperSync(
		ctx context.Context,
		prover []byte,
		shardKey tries.ShardKey,
	)

	// Enqueues state information to begin synchronization with a given peer. If
	// expectedIdentity is provided, may use this to determine if the initial
	// frameNumber for which synchronization begins is the correct fork.
	AddState(
		sourcePeerID []byte,
		frameNumber uint64,
		expectedIdentity []byte,
	)
}
