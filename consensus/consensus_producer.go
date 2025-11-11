package consensus

import "source.quilibrium.com/quilibrium/monorepo/consensus/models"

// StateProducer is responsible for producing new state proposals. It is a
// service component to HotStuff's main state machine (implemented in the
// EventHandler). The StateProducer's central purpose is to mediate concurrent
// signing requests to its embedded `hotstuff.SafetyRules` during state
// production. The actual work of producing a state proposal is delegated to the
// embedded `consensus.LeaderProvider`.
type StateProducer[StateT models.Unique, VoteT models.Unique] interface {
	// MakeStateProposal builds a new HotStuff state proposal using the given
	// rank, the given quorum certificate for its parent and [optionally] a
	// timeout certificate for last rank (could be nil).
	// Error Returns:
	//   - model.NoVoteError if it is not safe for us to vote (our proposal
	//     includes our vote) for this rank. This can happen if we have already
	//     proposed or timed out this rank.
	//   - generic error in case of unexpected failure
	MakeStateProposal(
		rank uint64,
		qc models.QuorumCertificate,
		lastRankTC models.TimeoutCertificate,
	) (*models.SignedProposal[StateT, VoteT], error)
}
