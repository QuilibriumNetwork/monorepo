package stateproducer

import (
	"context"
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// StateProducer is responsible for producing new state proposals. It is a
// service component to HotStuff's main state machine (implemented in the
// EventHandler). The StateProducer's central purpose is to mediate concurrent
// signing requests to its embedded `consensus.SafetyRules` during state
// production. The actual work of producing a state proposal is delegated to the
// embedded `consensus.LeaderProvider`.
type StateProducer[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
	CollectedT models.Unique,
] struct {
	safetyRules consensus.SafetyRules[StateT, VoteT]
	committee   consensus.Replicas
	builder     consensus.LeaderProvider[StateT, PeerIDT, CollectedT]
}

var _ consensus.StateProducer[*nilUnique, *nilUnique] = (*StateProducer[*nilUnique, *nilUnique, *nilUnique, *nilUnique])(nil)

// New creates a new StateProducer, which mediates concurrent signing requests
// to the embedded `consensus.SafetyRules` during state production, delegated to
// `consensus.LeaderProvider`. No errors are expected during normal operation.
func NewStateProducer[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
	CollectedT models.Unique,
](
	safetyRules consensus.SafetyRules[StateT, VoteT],
	committee consensus.Replicas,
	builder consensus.LeaderProvider[StateT, PeerIDT, CollectedT],
) (*StateProducer[StateT, VoteT, PeerIDT, CollectedT], error) {
	bp := &StateProducer[StateT, VoteT, PeerIDT, CollectedT]{
		safetyRules: safetyRules,
		committee:   committee,
		builder:     builder,
	}
	return bp, nil
}

// MakeStateProposal builds a new HotStuff state proposal using the given rank,
// the given quorum certificate for its parent and [optionally] a timeout
// certificate for last rank(could be nil).
// Error Returns:
//   - models.NoVoteError if it is not safe for us to vote (our proposal
//     includes our vote) for this rank. This can happen if we have already
//     proposed or timed out this rank.
//   - generic error in case of unexpected failure
func (bp *StateProducer[StateT, VoteT, PeerIDT, CollectedT]) MakeStateProposal(
	rank uint64,
	qc models.QuorumCertificate,
	previousRankTimeoutCert models.TimeoutCertificate,
) (*models.SignedProposal[StateT, VoteT], error) {
	newState, err := bp.builder.ProveNextState(
		context.TODO(),
		rank,
		qc.GetFilter(),
		qc.Identity(),
	)
	if err != nil {
		if models.IsNoVoteError(err) {
			return nil, fmt.Errorf(
				"unsafe to vote for own proposal on top of %x: %w",
				qc.Identity(),
				err,
			)
		}
		return nil, fmt.Errorf(
			"could not build state proposal on top of %x: %w",
			qc.Identity(),
			err,
		)
	}

	proposal := models.ProposalFrom(
		models.StateFrom(newState, qc),
		previousRankTimeoutCert,
	)

	signer := newSafetyRulesConcurrencyWrapper(bp.safetyRules)
	vote, err := signer.Sign(proposal)
	if err != nil {
		return nil, fmt.Errorf(
			"could not vote on state proposal on top of %x: %w",
			qc.Identity(),
			err,
		)
	}

	signedProposal := models.SignedProposalFromState(proposal, vote)

	return signedProposal, nil
}

// Type used to satisfy generic arguments in compiler time type assertion check
type nilUnique struct{}

// GetSignature implements models.Unique.
func (n *nilUnique) GetSignature() []byte {
	panic("unimplemented")
}

// GetTimestamp implements models.Unique.
func (n *nilUnique) GetTimestamp() uint64 {
	panic("unimplemented")
}

// Source implements models.Unique.
func (n *nilUnique) Source() models.Identity {
	panic("unimplemented")
}

// Clone implements models.Unique.
func (n *nilUnique) Clone() models.Unique {
	panic("unimplemented")
}

// GetRank implements models.Unique.
func (n *nilUnique) GetRank() uint64 {
	panic("unimplemented")
}

// Identity implements models.Unique.
func (n *nilUnique) Identity() models.Identity {
	panic("unimplemented")
}

var _ models.Unique = (*nilUnique)(nil)
