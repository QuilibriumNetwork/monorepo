package integration

import (
	"math/rand"

	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// VoteFilter is a filter function for dropping Votes.
// Return value `true` implies that the given Vote should be
// dropped, while `false` indicates that the Vote should be received.
type VoteFilter func(*helper.TestVote) bool

func DropNoVotes(*helper.TestVote) bool {
	return false
}

func DropAllVotes(*helper.TestVote) bool {
	return true
}

// DropVoteRandomly drops votes randomly with a probability of `dropProbability` ∈ [0,1]
func DropVoteRandomly(dropProbability float64) VoteFilter {
	return func(*helper.TestVote) bool {
		return rand.Float64() < dropProbability
	}
}

func DropVotesBy(voterID models.Identity) VoteFilter {
	return func(vote *helper.TestVote) bool {
		return vote.ID == voterID
	}
}

// ProposalFilter is a filter function for dropping Proposals.
// Return value `true` implies that the given SignedProposal should be
// dropped, while `false` indicates that the SignedProposal should be received.
type ProposalFilter func(*models.SignedProposal[*helper.TestState, *helper.TestVote]) bool

func DropNoProposals(*models.SignedProposal[*helper.TestState, *helper.TestVote]) bool {
	return false
}

func DropAllProposals(*models.SignedProposal[*helper.TestState, *helper.TestVote]) bool {
	return true
}

// DropProposalRandomly drops proposals randomly with a probability of `dropProbability` ∈ [0,1]
func DropProposalRandomly(dropProbability float64) ProposalFilter {
	return func(*models.SignedProposal[*helper.TestState, *helper.TestVote]) bool {
		return rand.Float64() < dropProbability
	}
}

// DropProposalsBy drops all proposals originating from the specified `proposerID`
func DropProposalsBy(proposerID models.Identity) ProposalFilter {
	return func(proposal *models.SignedProposal[*helper.TestState, *helper.TestVote]) bool {
		return proposal.State.ProposerID == proposerID
	}
}

// TimeoutStateFilter is a filter function for dropping TimeoutStates.
// Return value `true` implies that the given TimeoutState should be
// dropped, while `false` indicates that the TimeoutState should be received.
type TimeoutStateFilter func(*models.TimeoutState[*helper.TestVote]) bool

// DropAllTimeoutStates always returns `true`, i.e. drops all TimeoutStates
func DropAllTimeoutStates(*models.TimeoutState[*helper.TestVote]) bool {
	return true
}

// DropNoTimeoutStates always returns `false`, i.e. it lets all TimeoutStates pass.
func DropNoTimeoutStates(*models.TimeoutState[*helper.TestVote]) bool {
	return false
}
