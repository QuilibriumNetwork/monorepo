package votecollector

import (
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// baseFactory instantiates VerifyingVoteProcessors. Depending on the specific
// signing scheme, a different baseFactory can be used.
// CAUTION: the baseFactory creates the VerifyingVoteProcessor for the given
// state. It does _not_ check the proposer's vote for its own state. The API
// reflects this by expecting a `models.State` as input (which does _not_
// contain the proposer vote) as opposed to `models.SignedProposal` (combines
// state with proposer's vote). Therefore, baseFactory does _not_ implement
// `consensus.VoteProcessorFactory` by itself. The VoteProcessorFactory adds the
// missing logic to verify the proposer's vote, by wrapping the baseFactory
// (decorator pattern).
type baseFactory[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
] func(
	tracer consensus.TraceLogger,
	filter []byte,
	state *models.State[StateT],
	dsTag []byte,
	aggregator consensus.SignatureAggregator,
	votingProvider consensus.VotingProvider[StateT, VoteT, PeerIDT],
) (consensus.VerifyingVoteProcessor[StateT, VoteT], error)

// VoteProcessorFactory implements `consensus.VoteProcessorFactory`. Its main
// purpose is to construct instances of VerifyingVoteProcessors for a given
// state proposal.
// VoteProcessorFactory
// * delegates the creation of the actual instances to baseFactory
// * adds the logic to verify the proposer's vote for its own state
// Thereby, VoteProcessorFactory guarantees that only proposals with valid
// proposer vote are accepted (as per API specification). Otherwise, an
// `models.InvalidProposalError` is returned.
type VoteProcessorFactory[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
] struct {
	baseFactory baseFactory[StateT, VoteT, PeerIDT]
}

var _ consensus.VoteProcessorFactory[*nilUnique, *nilUnique, *nilUnique] = (*VoteProcessorFactory[*nilUnique, *nilUnique, *nilUnique])(nil)

// Create instantiates a VerifyingVoteProcessor for the given state proposal.
// A VerifyingVoteProcessor are only created for proposals with valid proposer
// votes. Expected error returns during normal operations:
// * models.InvalidProposalError - proposal has invalid proposer vote
func (f *VoteProcessorFactory[StateT, VoteT, PeerIDT]) Create(
	tracer consensus.TraceLogger,
	filter []byte,
	proposal *models.SignedProposal[StateT, VoteT],
	dsTag []byte,
	aggregator consensus.SignatureAggregator,
	votingProvider consensus.VotingProvider[StateT, VoteT, PeerIDT],
) (consensus.VerifyingVoteProcessor[StateT, VoteT], error) {
	processor, err := f.baseFactory(
		tracer,
		filter,
		proposal.State,
		dsTag,
		aggregator,
		votingProvider,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"instantiating vote processor for state %x failed: %w",
			proposal.State.Identifier,
			err,
		)
	}

	vote, err := proposal.ProposerVote()
	if err != nil {
		return nil, fmt.Errorf("could not get vote from proposer vote: %w", err)
	}

	err = processor.Process(vote)
	if err != nil {
		if models.IsInvalidVoteError[VoteT](err) {
			return nil, models.NewInvalidProposalErrorf(
				proposal,
				"invalid proposer vote: %w",
				err,
			)
		}
		return nil, fmt.Errorf(
			"processing proposer's vote for state %x failed: %w",
			proposal.State.Identifier,
			err,
		)
	}
	return processor, nil
}

// NewVoteProcessorFactory implements consensus.VoteProcessorFactory.
func NewVoteProcessorFactory[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
](
	committee consensus.DynamicCommittee,
	onQCCreated consensus.OnQuorumCertificateCreated,
) *VoteProcessorFactory[StateT, VoteT, PeerIDT] {
	base := &provingVoteProcessorFactoryBase[StateT, VoteT, PeerIDT]{
		committee:   committee,
		onQCCreated: onQCCreated,
	}
	return &VoteProcessorFactory[StateT, VoteT, PeerIDT]{
		baseFactory: base.Create,
	}
}

/* ***************************** VerifyingVoteProcessor constructors for bootstrapping ***************************** */

// NewBootstrapVoteProcessor directly creates a `VoteProcessor`,
// suitable for the collector's local cluster consensus.
// Intended use: only for bootstrapping.
// UNSAFE: the proposer vote for `state` is _not_ validated or included
func NewBootstrapVoteProcessor[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
](
	tracer consensus.TraceLogger,
	filter []byte,
	committee consensus.DynamicCommittee,
	state *models.State[StateT],
	onQCCreated consensus.OnQuorumCertificateCreated,
	dsTag []byte,
	aggregator consensus.SignatureAggregator,
	votingProvider consensus.VotingProvider[StateT, VoteT, PeerIDT],
) (consensus.VerifyingVoteProcessor[StateT, VoteT], error) {
	factory := &provingVoteProcessorFactoryBase[StateT, VoteT, PeerIDT]{
		committee:   committee,
		onQCCreated: onQCCreated,
	}
	return factory.Create(tracer, filter, state, dsTag, aggregator, votingProvider)
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
