package votecollector

import (
	"errors"
	"fmt"

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
// states of vote collector.
//
// Byzantine nodes might mount the following attacks on the vote-processing logic:
//  1. The leader might send a state proposal and equivocate by sending a different
//     conflicting vote as an independent message.
//  2. The leader might send a state proposal and (repeatedly) send the same vote
//     again as an independent message.
//  3. Any byzantine replica might send multiple individual vote messages.
//
// Detecting vote equivocation is a collaborative effort of votesCache and the
// VoteProcessor:
//   - The votesCache is the primary uniqueness filter. It caches the first vote
//     from each signer and detects equivocation (same signer, different vote).
//   - The VoteProcessor provides a secondary defense. If a vote somehow reaches
//     the processor despite being a duplicate (e.g., race between proposal
//     processing and standalone vote), it returns a DuplicatedSignerError which
//     is handled gracefully.
//
// ATTENTION: ensureVoteUnique MUST be called for every vote — both standalone
// votes (AddVote) and proposer votes embedded in proposals (ProcessState) — to
// guarantee that all equivocation attempts are caught.
type VoteCollector[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
] struct {
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
		filter:                   filter, // buildutils:allow-slice-alias static value
		workers:                  workers,
		notifier:                 notifier,
		createVerifyingProcessor: verifyingVoteProcessorFactory,
		votesCache:               *NewVotesCache[VoteT](rank),
		dsTag:                    dsTag, // buildutils:allow-slice-alias static value
		aggregator:               aggregator,
		voter:                    voter,
	}

	// without a state, we don't process votes (only cache them)
	sm.votesProcessor.Store(&atomicValueWrapper[VoteT]{
		processor: NewNoopCollector[VoteT](consensus.VoteCollectorStatusCaching),
	})
	return sm
}

// ensureVoteUnique caches the vote in the votesCache (or rejects it).
// Reports byzantine behavior when a leader or replica sends an equivocating vote.
//
// ATTENTION: To guarantee all equivocation attempts are caught, this function
// must be called consistently before processing individual votes _and_ state proposals.
//
// Returns:
//   - (true, nil) if vote is first from given signer
//   - (false, nil) if an identical or equivocating vote was already cached
//   - (false, error) if exception during processing
func (m *VoteCollector[StateT, VoteT, PeerIDT]) ensureVoteUnique(vote *VoteT) (bool, error) {
	err := m.votesCache.AddVote(vote)
	if err != nil {
		if errors.Is(err, RepeatedVoteErr) {
			return false, nil
		}
		doubleVoteErr, isDoubleVoteErr := models.AsDoubleVoteError[VoteT](err)
		if isDoubleVoteErr {
			m.notifier.OnDoubleVotingDetected(
				doubleVoteErr.FirstVote,
				doubleVoteErr.ConflictingVote,
			)
			return false, nil
		}
		return false, fmt.Errorf(
			"internal error adding vote %x to cache for state %x: %w",
			(*vote).Identity(),
			(*vote).Source(),
			err,
		)
	}
	return true, nil
}

// AddVote adds a vote to current vote collector.
// All expected errors are handled via callbacks to notifier.
// Under normal execution only exceptions are propagated to caller.
func (m *VoteCollector[StateT, VoteT, PeerIDT]) AddVote(vote *VoteT) error {
	unique, err := m.ensureVoteUnique(vote)
	if err != nil {
		return err
	}
	if !unique {
		return nil
	}

	err = m.processVote(vote)
	if err != nil {
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
// vote processor.
//
// Liveness argument: We need to ensure that every vote eventually gets processed
// by the VerifyingVoteProcessor (if the VoteCollector has transitioned to that
// state). The key insight is:
//
//  1. The VoteCollector's state only moves forward: CachingVotes → VerifyingVotes
//     → Invalid. Once it leaves a state, it never returns.
//
//  2. When we load the processor and call Process(vote), the vote is processed by
//     whatever processor was active at that instant. If the processor's status has
//     changed by the time Process returns (checked via currentState != m.Status()),
//     it means a state transition occurred concurrently. In that case, we retry
//     with the new processor.
//
//  3. The retry loop terminates because:
//     - There are at most 2 state transitions (Caching→Verifying→Invalid).
//     - Each transition changes the status, so the CAS comparison
//       `currentState != m.Status()` can only trigger a retry a bounded number
//       of times.
//     - The NoopProcessor (used for Caching and Invalid states) and the
//       VerifyingVoteProcessor both return in bounded time.
//
//  4. Votes cached _before_ the Caching→Verifying transition are replayed by
//     processCachedVotes. Votes arriving _during_ or _after_ the transition are
//     handled by this retry loop, which will eventually see the
//     VerifyingVoteProcessor.
//
// Therefore, no vote is lost: it is either processed by the VerifyingVoteProcessor
// directly, replayed from cache, or dropped only after being identified as invalid,
// duplicate, or for an incompatible state.
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
	proposerVote, err := proposal.ProposerVote()
	if err != nil {
		return models.NewInvalidProposalErrorf(proposal, "invalid proposer vote")
	}
	// Cache proposer's vote to detect equivocation. We proceed regardless of
	// whether the vote is unique, a duplicate, or equivocating — the VoteProcessor
	// is robust against all byzantine edge cases.
	_, err = m.ensureVoteUnique(proposerVote)
	if err != nil {
		return err
	}

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

	currentProcWrapper := m.votesProcessor.Load().(*atomicValueWrapper[VoteT])
	currentState := currentProcWrapper.processor.Status()
	if currentState != consensus.VoteCollectorStatusCaching {
		return fmt.Errorf(
			"processors's current state is %s: %w",
			currentState.String(),
			ErrDifferentCollectorState,
		)
	}
	if !m.votesProcessor.CompareAndSwap(currentProcWrapper, newProcWrapper) {
		return fmt.Errorf(
			"CAS failed, processors's current state is %s: %w",
			m.Status(),
			ErrDifferentCollectorState,
		)
	}
	return nil
}

func (m *VoteCollector[StateT, VoteT, PeerIDT]) terminateVoteProcessing() {
	currentProcWrapper := m.votesProcessor.Load().(*atomicValueWrapper[VoteT])
	if currentProcWrapper.processor.Status() == consensus.VoteCollectorStatusInvalid {
		return
	}
	newProcWrapper := &atomicValueWrapper[VoteT]{
		processor: NewNoopCollector[VoteT](consensus.VoteCollectorStatusInvalid),
	}
	for {
		if m.votesProcessor.CompareAndSwap(currentProcWrapper, newProcWrapper) {
			return
		}
		currentProcWrapper = m.votesProcessor.Load().(*atomicValueWrapper[VoteT])
		if currentProcWrapper.processor.Status() == consensus.VoteCollectorStatusInvalid {
			return
		}
	}
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
