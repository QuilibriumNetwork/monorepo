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
	// Sends a proposal for voting.
	SendProposal(ctx context.Context, proposal *StateT) error
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
	// Produces a timeout certificate
	FinalizeTimeout(
		ctx context.Context,
		filter []byte,
		rank uint64,
		latestQuorumCertificateRanks []uint64,
		aggregatedSignature models.AggregatedSignature,
	) (models.TimeoutCertificate, error)
	// Re-publishes a vote message, used to help lagging peers catch up.
	SendVote(ctx context.Context, vote *VoteT) (PeerIDT, error)
	// IsQuorum returns a response indicating whether or not quorum has been
	// reached.
	IsQuorum(
		ctx context.Context,
		proposalVotes map[models.Identity]*VoteT,
	) (bool, error)
	// FinalizeVotes performs any folding of proposed state required from VoteT
	// onto StateT, proposed states and votes matched by PeerIDT, returns
	// finalized state, chosen proposer PeerIDT.
	FinalizeVotes(
		ctx context.Context,
		proposals map[models.Identity]*StateT,
		proposalVotes map[models.Identity]*VoteT,
	) (*StateT, PeerIDT, error)
	// SendConfirmation sends confirmation of the finalized state.
	SendConfirmation(ctx context.Context, finalized *StateT) error
}
