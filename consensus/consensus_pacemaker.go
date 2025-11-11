package consensus

import (
	"context"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// Pacemaker defines a standard set of methods for handling pacemaker behaviors
// in the consensus engine.
type Pacemaker interface {
	ProposalDurationProvider
	// CurrentRank returns the current rank
	CurrentRank() uint64
	// LatestQuorumCertificate returns the latest quorum certificate seen.
	LatestQuorumCertificate() models.QuorumCertificate
	// PriorRankTimeoutCertificate returns the prior rank's timeout certificate,
	// if it exists.
	PriorRankTimeoutCertificate() models.TimeoutCertificate
	// ReceiveQuorumCertificate handles an incoming quorum certificate, advancing
	// to a new rank if applicable.
	ReceiveQuorumCertificate(
		quorumCertificate models.QuorumCertificate,
	) (*models.NextRank, error)
	// ReceiveTimeoutCertificate handles an incoming timeout certificate,
	// advancing to a new rank if applicable.
	ReceiveTimeoutCertificate(
		timeoutCertificate models.TimeoutCertificate,
	) (*models.NextRank, error)
	// TimeoutCh provides a channel for timing out on the current rank.
	TimeoutCh() <-chan time.Time
	// Start starts the pacemaker, takes a cancellable context.
	Start(ctx context.Context)
}

// ProposalDurationProvider generates the target publication time for state
// proposals.
type ProposalDurationProvider interface {

	// TargetPublicationTime is intended to be called by the EventHandler,
	// whenever it wants to publish a new proposal. The event handler inputs
	//  - proposalRank: the rank it is proposing for,
	//  - timeRankEntered: the time when the EventHandler entered this rank
	//  - parentStateId: the ID of the parent state, which the EventHandler is
	//    building on
	// TargetPublicationTime returns the time stamp when the new proposal should
	// be broadcasted. For a given rank where we are the primary, suppose the
	// actual time we are done building our proposal is P:
	//   - if P < TargetPublicationTime(..), then the EventHandler should wait
	//     until `TargetPublicationTime` to broadcast the proposal
	//   - if P >= TargetPublicationTime(..), then the EventHandler should
	//     immediately broadcast the proposal
	//
	// Note: Technically, our metrics capture the publication delay relative to
	// this function's _latest_ call. Currently, the EventHandler is the only
	// caller of this function, and only calls it once.
	//
	// Concurrency safe.
	TargetPublicationTime(
		proposalRank uint64,
		timeRankEntered time.Time,
		parentStateId models.Identity,
	) time.Time
}
