package consensus

import (
	"context"

	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// VotingProvider handles voting logic by deferring decisions, collection, and
// state finalization to an outside implementation.
type VotingProvider[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
] interface {
	// SignVote signs a proposal, produces an output vote for aggregation and
	// broadcasting.
	SignVote(
		ctx context.Context,
		state *models.State[StateT],
	) (*VoteT, error)
	// SignVote signs a proposal, produces an output vote for aggregation and
	// broadcasting.
	SignTimeoutVote(
		ctx context.Context,
		filter []byte,
		currentRank uint64,
		newestQuorumCertificateRank uint64,
	) (*VoteT, error)
	FinalizeQuorumCertificate(
		ctx context.Context,
		state *models.State[StateT],
		aggregatedSignature models.AggregatedSignature,
	) (models.QuorumCertificate, error)
	// Produces a timeout certificate. Assumes VotingProvider will reorganize
	// latestQuorumCertificateRanks in signer order.
	FinalizeTimeout(
		ctx context.Context,
		rank uint64,
		latestQuorumCertificate models.QuorumCertificate,
		latestQuorumCertificateRanks []TimeoutSignerInfo,
		aggregatedSignature models.AggregatedSignature,
	) (models.TimeoutCertificate, error)
}
