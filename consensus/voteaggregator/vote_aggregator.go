package voteaggregator

import (
	"context"
	"fmt"
	"sync/atomic"

	"golang.org/x/sync/errgroup"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// defaultVoteAggregatorWorkers number of workers to dispatch events for vote
// aggregators
const defaultVoteAggregatorWorkers = 8

// defaultVoteQueueCapacity maximum capacity of buffering unprocessed votes
const defaultVoteQueueCapacity = 1000

// defaultStateQueueCapacity maximum capacity of buffering unprocessed states
const defaultStateQueueCapacity = 1000

// VoteAggregator stores the votes and aggregates them into a QC when enough
// votes have been collected.
type VoteAggregator[StateT models.Unique, VoteT models.Unique] struct {
	tracer   consensus.TraceLogger
	notifier consensus.VoteAggregationViolationConsumer[
		StateT,
		VoteT,
	]
	lowestRetainedRank         atomic.Uint64 // lowest rank, for which we still process votes
	collectors                 consensus.VoteCollectors[StateT, VoteT]
	queuedMessagesNotifier     chan struct{}
	finalizationEventsNotifier chan struct{}
	finalizedRank              atomic.Uint64 // cache the last finalized rank to queue up the pruning work, and unstate the caller who's delivering the finalization event.
	queuedVotes                chan *VoteT
	queuedStates               chan *models.SignedProposal[StateT, VoteT]
	wg                         errgroup.Group
}

var _ consensus.VoteAggregator[*nilUnique, *nilUnique] = (*VoteAggregator[*nilUnique, *nilUnique])(nil)

// NewVoteAggregator creates an instance of vote aggregator
func NewVoteAggregator[StateT models.Unique, VoteT models.Unique](
	tracer consensus.TraceLogger,
	notifier consensus.VoteAggregationViolationConsumer[StateT, VoteT],
	lowestRetainedRank uint64,
	collectors consensus.VoteCollectors[StateT, VoteT],
) (*VoteAggregator[StateT, VoteT], error) {

	queuedVotes := make(chan *VoteT, defaultVoteQueueCapacity)
	queuedStates := make(
		chan *models.SignedProposal[StateT, VoteT],
		defaultStateQueueCapacity,
	)

	aggregator := &VoteAggregator[StateT, VoteT]{
		tracer:                     tracer,
		notifier:                   notifier,
		lowestRetainedRank:         atomic.Uint64{},
		finalizedRank:              atomic.Uint64{},
		collectors:                 collectors,
		queuedVotes:                queuedVotes,
		queuedStates:               queuedStates,
		queuedMessagesNotifier:     make(chan struct{}, 1),
		finalizationEventsNotifier: make(chan struct{}, 1),
		wg:                         errgroup.Group{},
	}

	aggregator.lowestRetainedRank.Store(lowestRetainedRank)
	aggregator.finalizedRank.Store(lowestRetainedRank)

	return aggregator, nil
}

func (va *VoteAggregator[StateT, VoteT]) Start(ctx context.Context) error {
	internalCtx, internalCancel := context.WithCancel(ctx)
	va.wg.SetLimit(defaultVoteAggregatorWorkers + 1)
	for i := 0; i < defaultVoteAggregatorWorkers; i++ {
		// manager for worker routines that process inbound messages
		va.wg.Go(func() error {
			err := va.queuedMessagesProcessingLoop(internalCtx)
			if err != nil {
				internalCancel()
			}
			return err
		})
	}
	va.wg.Go(func() error {
		// create new context which is not connected to parent
		// we need to ensure that our internal workers stop before asking
		// vote collectors to stop. We want to avoid delivering events to already
		// stopped vote collectors
		innerCtx, cancel := context.WithCancel(context.Background())

		// start vote collectors
		err := va.collectors.Start(innerCtx)
		if err != nil {
			internalCancel()
			return err
		}

		// Handle the component lifecycle in a separate goroutine so we can capture
		// any errors thrown during initialization in the main goroutine.
		go func() {
			select {
			case <-internalCtx.Done():
				// wait for internal workers to stop, then signal vote collectors to
				// stop
				va.wg.Wait()
				cancel()
			}
		}()

		va.finalizationProcessingLoop(internalCtx)
		return nil
	})
	return va.wg.Wait()
}

func (va *VoteAggregator[StateT, VoteT]) queuedMessagesProcessingLoop(
	ctx context.Context,
) error {
	notifier := va.queuedMessagesNotifier
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-notifier:
			err := va.processQueuedMessages(ctx)
			if err != nil {
				va.tracer.Error(
					"stopping mesage processing loop",
					fmt.Errorf("internal error processing queued messages: %w", err),
				)
				return err
			}
		}
	}
}

// processQueuedMessages is a function which dispatches previously queued
// messages on worker thread. This function is called whenever we have queued
// messages ready to be dispatched. No errors are expected during normal
// operations.
func (va *VoteAggregator[StateT, VoteT]) processQueuedMessages(
	ctx context.Context,
) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		state, ok := <-va.queuedStates
		if ok {
			err := va.processQueuedState(state)
			if err != nil {
				return fmt.Errorf(
					"could not process pending state %v: %w",
					state.State.Identifier,
					err,
				)
			}

			continue
		}

		vote, ok := <-va.queuedVotes
		if ok {
			err := va.processQueuedVote(vote)

			if err != nil {
				return fmt.Errorf(
					"could not process pending vote %v for state %v: %w",
					(*vote).Identity(),
					(*vote).Source(),
					err,
				)
			}

			continue
		}

		// when there is no more messages in the queue, back to the loop to wait
		// for the next incoming message to arrive.
		return nil
	}
}

// processQueuedVote performs actual processing of queued votes, this method is
// called from multiple concurrent goroutines.
func (va *VoteAggregator[StateT, VoteT]) processQueuedVote(vote *VoteT) error {
	collector, created, err := va.collectors.GetOrCreateCollector(
		(*vote).GetRank(),
	)
	if err != nil {
		// ignore if our routine is outdated and some other one has pruned
		// collectors
		if models.IsBelowPrunedThresholdError(err) {
			return nil
		}
		return fmt.Errorf(
			"could not get collector for rank %d: %w",
			(*vote).GetRank(),
			err,
		)
	}
	if created {
		va.tracer.Trace("vote collector is created by processing vote")
	}

	err = collector.AddVote(vote)
	if err != nil {
		return fmt.Errorf(
			"could not process vote for rank %d, stateID %v: %w",
			(*vote).GetRank(),
			(*vote).Source(),
			err,
		)
	}

	va.tracer.Trace("vote has been processed successfully")

	return nil
}

// processQueuedState performs actual processing of queued state proposals, this
// method is called from multiple concurrent goroutines.
// CAUTION: we expect that the input state's validity has been confirmed prior
// to calling AddState, including the proposer's consensus. Otherwise,
// VoteAggregator might crash or exhibit undefined behaviour. No errors are
// expected during normal operation.
func (va *VoteAggregator[StateT, VoteT]) processQueuedState(
	state *models.SignedProposal[StateT, VoteT],
) error {
	// check if the state is for a rank that has already been pruned (and is thus
	// stale)
	if state.State.Rank < va.lowestRetainedRank.Load() {
		return nil
	}

	collector, created, err := va.collectors.GetOrCreateCollector(
		state.State.Rank,
	)
	if err != nil {
		if models.IsBelowPrunedThresholdError(err) {
			return nil
		}
		return fmt.Errorf(
			"could not get or create collector for state %v: %w",
			state.State.Identifier,
			err,
		)
	}
	if created {
		va.tracer.Trace("vote collector is created by processing state")
	}

	err = collector.ProcessState(state)
	if err != nil {
		if models.IsInvalidProposalError[StateT, VoteT](err) {
			// We are attempting process a state which is invalid
			// This should never happen, because any component that feeds states into
			// VoteAggregator needs to make sure that it's submitting for processing
			// ONLY valid states.
			return fmt.Errorf(
				"received invalid state for processing %v at rank %d",
				state.State.Identifier,
				state.State.Rank,
			)
		}
		return fmt.Errorf(
			"could not process state: %v, %w",
			state.State.Identifier,
			err,
		)
	}

	va.tracer.Trace("state has been processed successfully")

	return nil
}

// AddVote checks if vote is stale and appends vote into processing queue
// actual vote processing will be called in other dispatching goroutine.
func (va *VoteAggregator[StateT, VoteT]) AddVote(vote *VoteT) {
	// drop stale votes
	if (*vote).GetRank() < va.lowestRetainedRank.Load() {
		va.tracer.Trace("drop stale votes")
		return
	}

	// It's ok to silently drop votes in case our processing pipeline is full.
	// It means that we are probably catching up.
	select {
	case va.queuedVotes <- vote:
		va.queuedMessagesNotifier <- struct{}{}
	default:
		va.tracer.Trace("no queue capacity, dropping vote")
	}
}

// AddState notifies the VoteAggregator that it should start processing votes
// for the given state. The input state is queued internally within the
// `VoteAggregator` and processed _asynchronously_ by the VoteAggregator's
// internal worker routines.
// CAUTION: we expect that the input state's validity has been confirmed prior
// to calling AddState, including the proposer's consensus. Otherwise,
// VoteAggregator might crash or exhibit undefined behaviour.
func (va *VoteAggregator[StateT, VoteT]) AddState(
	state *models.SignedProposal[StateT, VoteT],
) {
	// It's ok to silently drop states in case our processing pipeline is full.
	// It means that we are probably catching up.
	select {
	case va.queuedStates <- state:
		va.queuedMessagesNotifier <- struct{}{}
	default:
		va.tracer.Trace(fmt.Sprintf(
			"dropping state %x because queue is full",
			state.State.Identifier,
		))
	}
}

// InvalidState notifies the VoteAggregator about an invalid proposal, so that
// it can process votes for the invalid state and slash the voters.
// No errors are expected during normal operations
func (va *VoteAggregator[StateT, VoteT]) InvalidState(
	proposal *models.SignedProposal[StateT, VoteT],
) error {
	slashingVoteConsumer := func(vote *VoteT) {
		if proposal.State.Identifier == (*vote).Source() {
			va.notifier.OnVoteForInvalidStateDetected(vote, proposal)
		}
	}

	state := proposal.State
	collector, _, err := va.collectors.GetOrCreateCollector(state.Rank)
	if err != nil {
		// ignore if our routine is outdated and some other one has pruned
		// collectors
		if models.IsBelowPrunedThresholdError(err) {
			return nil
		}
		return fmt.Errorf(
			"could not retrieve vote collector for rank %d: %w",
			state.Rank,
			err,
		)
	}

	// registering vote consumer will deliver all previously cached votes in
	// strict order and will keep delivering votes if more are collected
	collector.RegisterVoteConsumer(slashingVoteConsumer)
	return nil
}

// PruneUpToRank deletes all votes _below_ to the given rank, as well as
// related indices. We only retain and process whose rank is equal or larger
// than `lowestRetainedRank`. If `lowestRetainedRank` is smaller than the
// previous value, the previous value is kept and the method call is a NoOp.
func (va *VoteAggregator[StateT, VoteT]) PruneUpToRank(
	lowestRetainedRank uint64,
) {
	if va.lowestRetainedRank.Load() < lowestRetainedRank {
		va.lowestRetainedRank.Store(lowestRetainedRank)
		va.collectors.PruneUpToRank(lowestRetainedRank)
	}
}

// OnFinalizedState implements the `OnFinalizedState` callback from the
// `consensus.FinalizationConsumer`. It informs sealing.Core about finalization
// of respective state.
//
// CAUTION: the input to this callback is treated as trusted; precautions should
// be taken that messages from external nodes cannot be considered as inputs to
// this function
func (va *VoteAggregator[StateT, VoteT]) OnFinalizedState(
	state *models.State[StateT],
) {
	if va.finalizedRank.Load() < state.Rank {
		va.finalizedRank.Store(state.Rank)
		va.finalizationEventsNotifier <- struct{}{}
	}
}

// finalizationProcessingLoop is a separate goroutine that performs processing
// of finalization events
func (va *VoteAggregator[StateT, VoteT]) finalizationProcessingLoop(
	ctx context.Context,
) {
	finalizationNotifier := va.finalizationEventsNotifier
	for {
		select {
		case <-ctx.Done():
			return
		case <-finalizationNotifier:
			va.PruneUpToRank(va.finalizedRank.Load())
		}
	}
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
