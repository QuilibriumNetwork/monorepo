package voteaggregator

import "source.quilibrium.com/quilibrium/monorepo/consensus/models"

// PendingVotes stores all the pending votes for different state proposals
type PendingVotes[VoteT models.Unique] struct {
	// maps state ID to pending status for that state
	votes map[models.Identity]*PendingStatus[VoteT]
}

// PendingStatus keeps track of pending votes for the same state
type PendingStatus[VoteT models.Unique] struct {
	// When receiving missing state, first received votes will be accumulated
	orderedVotes []*VoteT
	// For avoiding duplicate votes
	voteMap map[models.Identity]struct{}
}

// AddVote adds a vote as a pending vote
// returns true if it can be added to a PendingStatus successfully
// returns false otherwise
func (pv *PendingVotes[VoteT]) AddVote(vote *VoteT) bool {
	status, exists := pv.votes[(*vote).Source()]
	if !exists {
		status = NewPendingStatus[VoteT]()
		pv.votes[(*vote).Source()] = status
	}
	return status.AddVote(vote)
}

// AddVote adds a vote as a pending vote
// returns false if it has been added before
// returns true otherwise
func (ps *PendingStatus[VoteT]) AddVote(vote *VoteT) bool {
	_, exists := ps.voteMap[(*vote).Identity()]
	if exists {
		return false
	}
	ps.voteMap[(*vote).Identity()] = struct{}{}
	ps.orderedVotes = append(ps.orderedVotes, vote)
	return true
}

// NewPendingVotes creates a PendingVotes instance
func NewPendingVotes[VoteT models.Unique]() *PendingVotes[VoteT] {
	return &PendingVotes[VoteT]{
		votes: make(map[models.Identity]*PendingStatus[VoteT]),
	}
}

// NewPendingStatus creates a PendingStatus instance
func NewPendingStatus[VoteT models.Unique]() *PendingStatus[VoteT] {
	return &PendingStatus[VoteT]{voteMap: make(map[models.Identity]struct{})}
}
