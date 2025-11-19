package consensus

import (
	"context"

	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// LivenessProvider handles liveness announcements ahead of proving, to
// pre-emptively choose the next prover. In expected leader scenarios, this
// enables a peer to determine if an honest next prover is offline, so that it
// can publish the next state without waiting.
type LivenessProvider[
	StateT models.Unique,
	PeerIDT models.Unique,
	CollectedT models.Unique,
] interface {
	// Collect returns the collected mutation operations ahead of liveness
	// announcements.
	Collect(
		ctx context.Context,
		frameNumber uint64,
		rank uint64,
	) (CollectedT, error)
	// SendLiveness announces liveness ahead of the next prover deterimination and
	// subsequent proving. Provides prior state and collected mutation operations
	// if relevant.
	SendLiveness(ctx context.Context, prior *StateT, collected CollectedT) error
}
