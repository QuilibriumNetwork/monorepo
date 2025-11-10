package voteaggregator

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/sync/errgroup"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/counters"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
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
	*lifecycle.ComponentManager
	tracer   consensus.TraceLogger
	notifier consensus.VoteAggregationViolationConsumer[
		StateT,
		VoteT,
	]
	lowestRetainedRank         counters.StrictMonotonicCounter // lowest rank, for which we still process votes
	collectors                 consensus.VoteCollectors[StateT, VoteT]
	queuedMessagesNotifier     chan struct{}
	finalizationEventsNotifier chan struct{}
	finalizedRank              counters.StrictMonotonicCounter // cache the last finalized rank to queue up the pruning work, and unstate the caller who's delivering the finalization event.
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
		tracer:   tracer,
		notifier: notifier,
		lowestRetainedRank: counters.NewMonotonicCounter(
			lowestRetainedRank,
		),
		finalizedRank: counters.NewMonotonicCounter(
			lowestRetainedRank,
		),
		collectors:                 collectors,
		queuedVotes:                queuedVotes,
		queuedStates:               queuedStates,
		queuedMessagesNotifier:     make(chan struct{}, 1),
		finalizationEventsNotifier: make(chan struct{}, 1),
		wg:                         errgroup.Group{},
	}

	componentBuilder := lifecycle.NewComponentManagerBuilder()
	var wg sync.WaitGroup
	wg.Add(defaultVoteAggregatorWorkers)
	for i := 0; i < defaultVoteAggregatorWorkers; i++ {
		// manager for worker routines that process inbound messages
		componentBuilder.AddWorker(func(
			ctx lifecycle.SignalerContext,
			ready lifecycle.ReadyFunc,
		) {
			defer wg.Done()
			ready()
			aggregator.queuedMessagesProcessingLoop(ctx)
		})
	}
	componentBuilder.AddWorker(func(
		parentCtx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		// Create new context which is not connected to parent. We need to
		// ensure that our internal workers stop before asking vote collectors
		// to stop. We want to avoid delivering events to already stopped vote
		// collectors.
		ctx, cancel := context.WithCancel(context.Background())
		signalerCtx, errCh := lifecycle.WithSignaler(ctx)

		// start vote collectors
		aggregator.collectors.Start(signalerCtx)

		// Handle the component lifecycle in a separate goroutine so we can
		// capture any errors thrown during initialization in the main
		// goroutine.
		go func() {
			if err := lifecycle.WaitClosed(
				parentCtx,
				aggregator.collectors.Ready(),
			); err == nil {
				// only signal ready when collectors are ready, but always handle
				// shutdown
				ready()
			}

			// wait for internal workers to stop, then signal vote collectors to stop
			wg.Wait()
			cancel()
		}()

		// since we are breaking the connection between parentCtx and signalerCtx,
		// we need to explicitly rethrow any errors from signalerCtx to parentCtx,
		// otherwise they are dropped. Handle errors in the main worker goroutine to
		// guarantee that they are rethrown to the parent before the component is
		// marked done.
		if err := lifecycle.WaitError(
			errCh,
			aggregator.collectors.Done(),
		); err != nil {
			parentCtx.Throw(err)
		}
	})
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		aggregator.finalizationProcessingLoop(ctx)
	})

	aggregator.ComponentManager = componentBuilder.Build()
	return aggregator, nil
}

func (va *VoteAggregator[StateT, VoteT]) queuedMessagesProcessingLoop(
	ctx lifecycle.SignalerContext,
) {
	notifier := va.queuedMessagesNotifier
	for {
		select {
		case <-ctx.Done():
			return
		case <-notifier:
			err := va.processQueuedMessages(ctx)
			if err != nil {
				ctx.Throw(fmt.Errorf(
					"internal error processing queued messages: %w",
					err,
				))
				return
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

		case state, ok := <-va.queuedStates:
			if ok {
				err := va.processQueuedState(state)
				if err != nil {
					return fmt.Errorf(
						"could not process pending state %x: %w",
						state.State.Identifier,
						err,
					)
				}

				continue
			}

		case vote, ok := <-va.queuedVotes:
			if ok {
				err := va.processQueuedVote(vote)

				if err != nil {
					return fmt.Errorf(
						"could not process pending vote %x for state %x: %w",
						(*vote).Identity(),
						(*vote).Source(),
						err,
					)
				}

				continue
			}

		default:
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
			"could not process vote for rank %d, stateID %x: %w",
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
	if state.State.Rank < va.lowestRetainedRank.Value() {
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
			"could not get or create collector for state %x: %w",
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
				"received invalid state for processing %x at rank %d: %+w",
				state.State.Identifier,
				state.State.Rank,
				err,
			)
		}
		return fmt.Errorf(
			"could not process state: %x, %w",
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
	if (*vote).GetRank() < va.lowestRetainedRank.Value() {
		va.tracer.Trace("drop stale votes")
		return
	}

	// It's ok to silently drop votes in case our processing pipeline is full.
	// It means that we are probably catching up.
	select {
	case va.queuedVotes <- vote:
		select {
		case va.queuedMessagesNotifier <- struct{}{}:
		default:
		}
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
		select {
		case va.queuedMessagesNotifier <- struct{}{}:
		default:
		}
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
	if va.lowestRetainedRank.Set(lowestRetainedRank) {
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
	if va.finalizedRank.Set(state.Rank) {
		select {
		case va.finalizationEventsNotifier <- struct{}{}:
		default:
		}
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
			va.PruneUpToRank(va.finalizedRank.Value())
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
