package consensus

import (
	"context"

	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// LeaderProvider handles leader selection. State is provided, if relevant to
// the upstream consensus engine.
type LeaderProvider[
	StateT models.Unique,
	PeerIDT models.Unique,
	CollectedT models.Unique,
] interface {
	// GetNextLeaders returns a list of node indices, in priority order. Note that
	// it is assumed that if no error is returned, GetNextLeaders should produce
	// a non-empty list. If a list of size smaller than minimumProvers is
	// provided, the liveness check will loop until the list is greater than that.
	GetNextLeaders(ctx context.Context, prior *StateT) ([]PeerIDT, error)
	// ProveNextState prepares a non-finalized new state from the prior, to be
	// proposed and voted upon. Provided context may be canceled, should be used
	// to halt long-running prover operations.
	ProveNextState(
		ctx context.Context,
		rank uint64,
		filter []byte,
		priorState models.Identity,
	) (*StateT, error)
}
