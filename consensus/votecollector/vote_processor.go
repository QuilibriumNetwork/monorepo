package votecollector

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/atomic"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/signature"
	"source.quilibrium.com/quilibrium/monorepo/consensus/verification"
)

/* ***************** Base-Factory for VoteProcessor ****************** */

// provingVoteProcessorFactoryBase implements a factory for creating
// VoteProcessor holds needed dependencies to initialize VoteProcessor.
// CAUTION:
// this base factory only creates the VerifyingVoteProcessor for the given
// state. It does _not_ check the proposer's vote for its own state, i.e. it
// does _not_ implement `consensus.VoteProcessorFactory`. This base factory
// should be wrapped by `votecollector.VoteProcessorFactory` which adds the
// logic to verify the proposer's vote (decorator pattern).
type provingVoteProcessorFactoryBase[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
] struct {
	committee   consensus.DynamicCommittee
	onQCCreated consensus.OnQuorumCertificateCreated
}

// Create creates VoteProcessor for processing votes for the given state.
// Caller must treat all errors as exceptions
func (f *provingVoteProcessorFactoryBase[StateT, VoteT, PeerIDT]) Create(
	tracer consensus.TraceLogger,
	filter []byte,
	state *models.State[StateT],
	dsTag []byte,
	aggregator consensus.SignatureAggregator,
	votingProvider consensus.VotingProvider[StateT, VoteT, PeerIDT],
) (consensus.VerifyingVoteProcessor[StateT, VoteT], error) {
	allParticipants, err := f.committee.IdentitiesByState(state.Identifier)
	if err != nil {
		return nil, fmt.Errorf("error retrieving consensus participants: %w", err)
	}

	// message that has to be verified against aggregated signature
	msg := verification.MakeVoteMessage(filter, state.Rank, state.Identifier)

	// prepare the proving public keys of participants
	provingKeys := make([][]byte, 0, len(allParticipants))
	for _, participant := range allParticipants {
		provingKeys = append(provingKeys, participant.PublicKey())
	}

	provingSigAggtor, err := signature.NewWeightedSignatureAggregator(
		allParticipants,
		provingKeys,
		msg,
		dsTag,
		aggregator,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"could not create aggregator for proving signatures: %w",
			err,
		)
	}

	minRequiredWeight, err := f.committee.QuorumThresholdForRank(state.Rank)
	if err != nil {
		return nil, fmt.Errorf(
			"could not get weight threshold for rank %d: %w",
			state.Rank,
			err,
		)
	}

	return &VoteProcessor[StateT, VoteT, PeerIDT]{
		tracer:            tracer,
		state:             state,
		provingSigAggtor:  provingSigAggtor,
		votingProvider:    votingProvider,
		onQCCreated:       f.onQCCreated,
		minRequiredWeight: minRequiredWeight,
		done:              *atomic.NewBool(false),
		allParticipants:   allParticipants,
	}, nil
}

/* ****************** VoteProcessor Implementation ******************* */

// VoteProcessor implements the consensus.VerifyingVoteProcessor interface.
// It processes hotstuff votes from a collector cluster, where participants vote
// in favour of a state by proving their proving key consensus.
// Concurrency safe.
type VoteProcessor[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
] struct {
	tracer            consensus.TraceLogger
	state             *models.State[StateT]
	provingSigAggtor  consensus.WeightedSignatureAggregator
	onQCCreated       consensus.OnQuorumCertificateCreated
	votingProvider    consensus.VotingProvider[StateT, VoteT, PeerIDT]
	minRequiredWeight uint64
	done              atomic.Bool
	allParticipants   []models.WeightedIdentity
}

// State returns state that is part of proposal that we are processing votes for.
func (p *VoteProcessor[StateT, VoteT, PeerIDT]) State() *models.State[StateT] {
	return p.state
}

// Status returns status of this vote processor, it's always verifying.
func (p *VoteProcessor[
	StateT,
	VoteT,
	PeerIDT,
]) Status() consensus.VoteCollectorStatus {
	return consensus.VoteCollectorStatusVerifying
}

// Process performs processing of single vote in concurrent safe way. This
// function is implemented to be called by multiple goroutines at the same time.
// Supports processing of both proving and threshold signatures. Design of this
// function is event driven, as soon as we collect enough weight to create a QC
// we will immediately do this and submit it via callback for further
// processing.
// Expected error returns during normal operations:
// * VoteForIncompatibleStateError - submitted vote for incompatible state
// * VoteForIncompatibleRankError - submitted vote for incompatible rank
// * models.InvalidVoteError - submitted vote with invalid signature
// All other errors should be treated as exceptions.
func (p *VoteProcessor[StateT, VoteT, PeerIDT]) Process(vote *VoteT) error {
	err := EnsureVoteForState[StateT, VoteT](vote, p.state)
	if err != nil {
		return fmt.Errorf("received incompatible vote: %w", err)
	}

	// Vote Processing state machine
	if p.done.Load() {
		return nil
	}
	err = p.provingSigAggtor.Verify((*vote).Identity(), (*vote).GetSignature())
	if err != nil {
		if models.IsInvalidSignerError(err) {
			return models.NewInvalidVoteErrorf(
				vote,
				"vote %x for rank %d is not signed by an authorized consensus participant: %w",
				(*vote).Identity(),
				(*vote).GetRank(),
				err,
			)
		}
		if errors.Is(err, models.ErrInvalidSignature) {
			return models.NewInvalidVoteErrorf(
				vote,
				"vote %x for rank %d has an invalid proving signature: %w",
				(*vote).Identity(),
				(*vote).GetRank(),
				err,
			)
		}
		return fmt.Errorf("internal error checking signature validity: %w", err)
	}

	if p.done.Load() {
		return nil
	}
	totalWeight, err := p.provingSigAggtor.TrustedAdd(
		(*vote).Identity(),
		(*vote).GetSignature(),
	)
	if err != nil {
		// we don't expect any errors here during normal operation, as we previously
		// checked for duplicated votes from the same signer and verified the
		// signer+signature
		return fmt.Errorf(
			"unexpected exception adding signature from vote %x to proving aggregator: %w",
			(*vote).Identity(),
			err,
		)
	}

	p.tracer.Trace(fmt.Sprintf(
		"processed vote, total weight=(%d), required=(%d)",
		totalWeight,
		p.minRequiredWeight,
	))

	// checking of conditions for building QC are satisfied
	if totalWeight < p.minRequiredWeight {
		return nil
	}

	// At this point, we have enough signatures to build a QC. Another routine
	// might just be at this point. To avoid duplicate work, only one routine can
	// pass:
	if !p.done.CompareAndSwap(false, true) {
		return nil
	}
	qc, err := p.buildQC()
	if err != nil {
		return fmt.Errorf("internal error constructing QC from votes: %w", err)
	}

	p.tracer.Trace("new QC has been created")
	p.onQCCreated(qc)

	return nil
}

// buildQC performs aggregation of signatures when we have collected enough
// weight for building QC. This function is run only once by single worker.
// Any error should be treated as exception.
func (p *VoteProcessor[StateT, VoteT, PeerIDT]) buildQC() (
	models.QuorumCertificate,
	error,
) {
	_, aggregatedSig, err := p.provingSigAggtor.Aggregate()
	if err != nil {
		return nil, fmt.Errorf("could not aggregate proving signature: %w", err)
	}

	qc, err := p.votingProvider.FinalizeQuorumCertificate(
		context.Background(),
		p.state,
		aggregatedSig,
	)
	if err != nil {
		return nil, fmt.Errorf("could not build quorum certificate: %w", err)
	}

	return qc, nil
}
