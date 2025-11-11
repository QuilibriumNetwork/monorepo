package consensus

import (
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
)

// VoteAggregator verifies and aggregates votes to build QC. When enough votes
// have been collected, it builds a QC and send it to the EventLoop.
// VoteAggregator also detects protocol violation, including invalid votes,
// double voting etc, and notifies a HotStuff consumer for slashing.
type VoteAggregator[StateT models.Unique, VoteT models.Unique] interface {
	lifecycle.Component

	// AddVote verifies and aggregates a vote. The voting state could either be
	// known or unknown. If the voting state is unknown, the vote won't be
	// processed until AddState is called with the state. This method can be
	// called concurrently, votes will be queued and processed asynchronously.
	AddVote(vote *VoteT)

	// AddState notifies the VoteAggregator that it should start processing votes
	// for the given state. The input state is queued internally within the
	// `VoteAggregator` and processed _asynchronously_ by the VoteAggregator's
	// internal worker routines.
	// CAUTION: we expect that the input state's validity has been confirmed prior
	// to calling AddState, including the proposer's consensus. Otherwise,
	// VoteAggregator might crash or exhibit undefined behaviour.
	AddState(state *models.SignedProposal[StateT, VoteT])

	// InvalidState notifies the VoteAggregator about an invalid proposal, so that
	// it can process votes for the invalid state and slash the voters. No errors
	// are expected during normal operations.
	InvalidState(state *models.SignedProposal[StateT, VoteT]) error

	// PruneUpToRank deletes all votes _below_ to the given rank, as well as
	// related indices. We only retain and process whose rank is equal or larger
	// than `lowestRetainedRank`. If `lowestRetainedRank` is smaller than the
	// previous value, the previous value is kept and the method call is a NoOp.
	PruneUpToRank(rank uint64)
}
