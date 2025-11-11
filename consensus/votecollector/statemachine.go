package votecollector

import (
	"errors"
	"fmt"
	"sync"

	"go.uber.org/atomic"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/voteaggregator"
)

var (
	ErrDifferentCollectorState = errors.New("different state")
)

// VerifyingVoteProcessorFactory generates consensus.VerifyingVoteCollector
// instances
type VerifyingVoteProcessorFactory[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
] = func(
	tracer consensus.TraceLogger,
	filter []byte,
	proposal *models.SignedProposal[StateT, VoteT],
	dsTag []byte,
	aggregator consensus.SignatureAggregator,
	votingProvider consensus.VotingProvider[StateT, VoteT, PeerIDT],
) (consensus.VerifyingVoteProcessor[StateT, VoteT], error)

// VoteCollector implements a state machine for transition between different
// states of vote collector
type VoteCollector[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
] struct {
	sync.Mutex
	tracer                   consensus.TraceLogger
	filter                   []byte
	workers                  consensus.Workers
	notifier                 consensus.VoteAggregationConsumer[StateT, VoteT]
	createVerifyingProcessor VerifyingVoteProcessorFactory[StateT, VoteT, PeerIDT]
	dsTag                    []byte
	aggregator               consensus.SignatureAggregator
	voter                    consensus.VotingProvider[StateT, VoteT, PeerIDT]

	votesCache     VotesCache[VoteT]
	votesProcessor atomic.Value
}

var _ consensus.VoteCollector[*nilUnique, *nilUnique] = (*VoteCollector[*nilUnique, *nilUnique, *nilUnique])(nil)

func (
	m *VoteCollector[StateT, VoteT, PeerIDT],
) atomicLoadProcessor() consensus.VoteProcessor[VoteT] {
	return m.votesProcessor.Load().(*atomicValueWrapper[VoteT]).processor
}

// atomic.Value doesn't allow storing interfaces as atomic values,
// it requires that stored type is always the same, so we need a wrapper that
// will mitigate this restriction
// https://github.com/golang/go/issues/22550
type atomicValueWrapper[VoteT models.Unique] struct {
	processor consensus.VoteProcessor[VoteT]
}

func NewStateMachineFactory[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
](
	tracer consensus.TraceLogger,
	filter []byte,
	notifier consensus.VoteAggregationConsumer[StateT, VoteT],
	verifyingVoteProcessorFactory VerifyingVoteProcessorFactory[
		StateT,
		VoteT,
		PeerIDT,
	],
	dsTag []byte,
	aggregator consensus.SignatureAggregator,
	voter consensus.VotingProvider[StateT, VoteT, PeerIDT],
) voteaggregator.NewCollectorFactoryMethod[StateT, VoteT] {
	return func(rank uint64, workers consensus.Workers) (
		consensus.VoteCollector[StateT, VoteT],
		error,
	) {
		return NewStateMachine[StateT, VoteT](
			rank,
			filter,
			tracer,
			workers,
			notifier,
			verifyingVoteProcessorFactory,
			dsTag,
			aggregator,
			voter,
		), nil
	}
}

func NewStateMachine[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
](
	rank uint64,
	filter []byte,
	tracer consensus.TraceLogger,
	workers consensus.Workers,
	notifier consensus.VoteAggregationConsumer[StateT, VoteT],
	verifyingVoteProcessorFactory VerifyingVoteProcessorFactory[
		StateT,
		VoteT,
		PeerIDT,
	],
	dsTag []byte,
	aggregator consensus.SignatureAggregator,
	voter consensus.VotingProvider[StateT, VoteT, PeerIDT],
) *VoteCollector[StateT, VoteT, PeerIDT] {
	sm := &VoteCollector[StateT, VoteT, PeerIDT]{
		tracer:                   tracer,
		filter:                   filter,
		workers:                  workers,
		notifier:                 notifier,
		createVerifyingProcessor: verifyingVoteProcessorFactory,
		votesCache:               *NewVotesCache[VoteT](rank),
		dsTag:                    dsTag,
		aggregator:               aggregator,
		voter:                    voter,
	}

	// without a state, we don't process votes (only cache them)
	sm.votesProcessor.Store(&atomicValueWrapper[VoteT]{
		processor: NewNoopCollector[VoteT](consensus.VoteCollectorStatusCaching),
	})
	return sm
}

// AddVote adds a vote to current vote collector
// All expected errors are handled via callbacks to notifier.
// Under normal execution only exceptions are propagated to caller.
func (m *VoteCollector[StateT, VoteT, PeerIDT]) AddVote(vote *VoteT) error {
	// Cache vote
	err := m.votesCache.AddVote(vote)
	if err != nil {
		if errors.Is(err, RepeatedVoteErr) {
			return nil
		}
		doubleVoteErr, isDoubleVoteErr := models.AsDoubleVoteError[VoteT](err)
		if isDoubleVoteErr {
			m.notifier.OnDoubleVotingDetected(
				doubleVoteErr.FirstVote,
				doubleVoteErr.ConflictingVote,
			)
			return nil
		}
		return fmt.Errorf(
			"internal error adding vote %x to cache for state %x: %w",
			(*vote).Identity(),
			(*vote).Source(),
			err,
		)
	}

	err = m.processVote(vote)
	if err != nil {
		if errors.Is(err, VoteForIncompatibleStateError) {
			// For honest nodes, there should be only a single proposal per rank and
			// all votes should be for this proposal. However, byzantine nodes might
			// deviate from this happy path:
			// * A malicious leader might create multiple (individually valid)
			//   conflicting proposals for the same rank. Honest replicas will send
			//   correct votes for whatever proposal they see first. We only accept
			//   the first valid state and reject any other conflicting states that
			//   show up later.
			// * Alternatively, malicious replicas might send votes with the expected
			//   rank, but for states that don't exist.
			// In either case, receiving votes for the same rank but for different
			// state IDs is a symptom of malicious consensus participants. Hence, we
			// log it here as a warning:
			m.tracer.Error("received vote for incompatible state", err)

			return nil
		}
		return fmt.Errorf(
			"internal error processing vote %x for state %x: %w",
			(*vote).Identity(),
			(*vote).Source(),
			err,
		)
	}
	return nil
}

// processVote uses compare-and-repeat pattern to process vote with underlying
// vote processor
func (m *VoteCollector[StateT, VoteT, PeerIDT]) processVote(vote *VoteT) error {
	for {
		processor := m.atomicLoadProcessor()
		currentState := processor.Status()
		err := processor.Process(vote)
		if err != nil {
			if invalidVoteErr, ok := models.AsInvalidVoteError[VoteT](err); ok {
				m.notifier.OnInvalidVoteDetected(*invalidVoteErr)
				return nil
			}
			// ATTENTION: due to how our logic is designed this situation is only
			// possible where we receive the same vote twice, this is not a case of
			// double voting. This scenario is possible if leader submits their vote
			// additionally to the vote in proposal.
			if models.IsDuplicatedSignerError(err) {
				m.tracer.Trace(fmt.Sprintf("duplicated signer %x", (*vote).Identity()))
				return nil
			}
			return err
		}

		if currentState != m.Status() {
			continue
		}

		m.notifier.OnVoteProcessed(vote)
		return nil
	}
}

// Status returns the status of underlying vote processor
func (m *VoteCollector[StateT, VoteT, PeerIDT]) Status() consensus.VoteCollectorStatus {
	return m.atomicLoadProcessor().Status()
}

// Rank returns rank associated with this collector
func (m *VoteCollector[StateT, VoteT, PeerIDT]) Rank() uint64 {
	return m.votesCache.Rank()
}

// ProcessState performs validation of state signature and processes state with
// respected collector. In case we have received double proposal, we will stop
// attempting to build a QC for this rank, because we don't want to build on any
// proposal from an equivocating primary. Note: slashing challenges for proposal
// equivocation are triggered by consensus.Forks, so we don't have to do
// anything else here.
//
// The internal state change is implemented as an atomic compare-and-swap, i.e.
// the state transition is only executed if VoteCollector's internal state is
// equal to `expectedValue`. The implementation only allows the transitions
//
//	CachingVotes   -> VerifyingVotes
//	CachingVotes   -> Invalid
//	VerifyingVotes -> Invalid
func (m *VoteCollector[StateT, VoteT, PeerIDT]) ProcessState(
	proposal *models.SignedProposal[StateT, VoteT],
) error {

	if proposal.State.Rank != m.Rank() {
		return fmt.Errorf(
			"this VoteCollector requires a proposal for rank %d but received state %x with rank %d",
			m.votesCache.Rank(),
			proposal.State.Identifier,
			proposal.State.Rank,
		)
	}

	for {
		proc := m.atomicLoadProcessor()

		switch proc.Status() {
		// first valid state for this rank: commence state transition from caching
		// to verifying
		case consensus.VoteCollectorStatusCaching:
			err := m.caching2Verifying(proposal)
			if errors.Is(err, ErrDifferentCollectorState) {
				continue // concurrent state update by other thread => restart our logic
			}

			if err != nil {
				return fmt.Errorf(
					"internal error updating VoteProcessor's status from %s to %s for state %x: %w",
					proc.Status().String(),
					consensus.VoteCollectorStatusVerifying.String(),
					proposal.State.Identifier,
					err,
				)
			}

			m.tracer.Trace("vote collector status changed from caching to verifying")

			m.processCachedVotes(proposal.State)

		// We already received a valid state for this rank. Check whether the
		// proposer is equivocating and terminate vote processing in this case.
		// Note: proposal equivocation is handled by consensus.Forks, so we don't
		// have to do anything else here.
		case consensus.VoteCollectorStatusVerifying:
			verifyingProc, ok := proc.(consensus.VerifyingVoteProcessor[StateT, VoteT])
			if !ok {
				return fmt.Errorf(
					"while processing state %x, found that VoteProcessor reports status %s but has an incompatible implementation type %T",
					proposal.State.Identifier,
					proc.Status(),
					verifyingProc,
				)
			}
			if verifyingProc.State().Identifier != proposal.State.Identifier {
				m.terminateVoteProcessing()
			}

		// Vote processing for this rank has already been terminated. Note: proposal
		// equivocation is handled by consensus.Forks, so we don't have anything to
		// do here.
		case consensus.VoteCollectorStatusInvalid: /* no op */

		default:
			return fmt.Errorf(
				"while processing state %x, found that VoteProcessor reported unknown status %s",
				proposal.State.Identifier,
				proc.Status(),
			)
		}

		return nil
	}
}

// RegisterVoteConsumer registers a VoteConsumer. Upon registration, the
// collector feeds all cached votes into the consumer in the order they arrived.
// CAUTION, VoteConsumer implementations must be
//   - NON-BLOCKING and consume the votes without noteworthy delay, and
//   - CONCURRENCY SAFE
func (m *VoteCollector[StateT, VoteT, PeerIDT]) RegisterVoteConsumer(
	consumer consensus.VoteConsumer[VoteT],
) {
	m.votesCache.RegisterVoteConsumer(consumer)
}

// caching2Verifying ensures that the VoteProcessor is currently in state
// `VoteCollectorStatusCaching` and replaces it by a newly-created
// VerifyingVoteProcessor.
// Error returns:
//   - ErrDifferentCollectorState if the VoteCollector's state is _not_
//     `CachingVotes`
//   - all other errors are unexpected and potential symptoms of internal bugs
//     or state corruption (fatal)
func (m *VoteCollector[StateT, VoteT, PeerIDT]) caching2Verifying(
	proposal *models.SignedProposal[StateT, VoteT],
) error {
	stateID := proposal.State.Identifier
	newProc, err := m.createVerifyingProcessor(
		m.tracer,
		m.filter,
		proposal,
		m.dsTag,
		m.aggregator,
		m.voter,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to create VerifyingVoteProcessor for state %x: %w",
			stateID,
			err,
		)
	}
	newProcWrapper := &atomicValueWrapper[VoteT]{processor: newProc}

	m.Lock()
	defer m.Unlock()
	proc := m.atomicLoadProcessor()
	if proc.Status() != consensus.VoteCollectorStatusCaching {
		return fmt.Errorf(
			"processors's current state is %s: %w",
			proc.Status().String(),
			ErrDifferentCollectorState,
		)
	}
	m.votesProcessor.Store(newProcWrapper)
	return nil
}

func (m *VoteCollector[StateT, VoteT, PeerIDT]) terminateVoteProcessing() {
	if m.Status() == consensus.VoteCollectorStatusInvalid {
		return
	}
	newProcWrapper := &atomicValueWrapper[VoteT]{
		processor: NewNoopCollector[VoteT](consensus.VoteCollectorStatusInvalid),
	}

	m.Lock()
	defer m.Unlock()
	m.votesProcessor.Store(newProcWrapper)
}

// processCachedVotes feeds all cached votes into the VoteProcessor
func (m *VoteCollector[StateT, VoteT, PeerIDT]) processCachedVotes(
	state *models.State[StateT],
) {
	cachedVotes := m.votesCache.All()
	m.tracer.Trace(fmt.Sprintf("processing %d cached votes", len(cachedVotes)))
	for _, vote := range cachedVotes {
		if (*vote).Source() != state.Identifier {
			continue
		}

		stateVote := vote
		voteProcessingTask := func() {
			err := m.processVote(stateVote)
			if err != nil {
				m.tracer.Error("internal error processing cached vote", err)
			}
		}
		m.workers.Submit(voteProcessingTask)
	}
}
