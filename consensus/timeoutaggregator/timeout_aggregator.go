package timeoutaggregator

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/counters"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
)

// defaultTimeoutAggregatorWorkers number of workers to dispatch events for
// timeout aggregator
const defaultTimeoutAggregatorWorkers = 4

// defaultTimeoutQueueCapacity maximum capacity for buffering unprocessed
// timeouts
const defaultTimeoutQueueCapacity = 1000

// TimeoutAggregator stores the timeout states and aggregates them into a TC
// when enough TSs have been collected. It's safe to use in concurrent
// environment.
type TimeoutAggregator[VoteT models.Unique] struct {
	*lifecycle.ComponentManager
	tracer                 consensus.TraceLogger
	lowestRetainedRank     counters.StrictMonotonicCounter
	collectors             consensus.TimeoutCollectors[VoteT]
	queuedTimeoutsNotifier chan struct{}
	enteringRankNotifier   chan struct{}
	queuedTimeouts         chan *models.TimeoutState[VoteT]
	wg                     sync.WaitGroup
}

var _ consensus.TimeoutAggregator[*nilUnique] = (*TimeoutAggregator[*nilUnique])(nil)

// NewTimeoutAggregator creates an instance of timeout aggregator.
// No errors are expected during normal operations.
func NewTimeoutAggregator[VoteT models.Unique](
	tracer consensus.TraceLogger,
	lowestRetainedRank uint64,
	collectors consensus.TimeoutCollectors[VoteT],
) (*TimeoutAggregator[VoteT], error) {
	queuedTimeouts := make(
		chan *models.TimeoutState[VoteT],
		defaultTimeoutQueueCapacity,
	)

	aggregator := &TimeoutAggregator[VoteT]{
		tracer:                 tracer,
		lowestRetainedRank:     counters.NewMonotonicCounter(lowestRetainedRank),
		collectors:             collectors,
		queuedTimeoutsNotifier: make(chan struct{}, 1),
		enteringRankNotifier:   make(chan struct{}, 1),
		queuedTimeouts:         queuedTimeouts,
		wg:                     sync.WaitGroup{},
	}

	aggregator.wg.Add(defaultTimeoutAggregatorWorkers + 1)
	componentBuilder := lifecycle.NewComponentManagerBuilder()
	for i := 0; i < defaultTimeoutAggregatorWorkers; i++ {
		// manager for worker routines that process inbound events
		componentBuilder.AddWorker(func(
			ctx lifecycle.SignalerContext,
			ready lifecycle.ReadyFunc,
		) {
			ready()
			aggregator.queuedTimeoutsProcessingLoop(ctx)
		})
	}
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		aggregator.enteringRankProcessingLoop(ctx)
	})

	aggregator.ComponentManager = componentBuilder.Build()

	return aggregator, nil
}

// queuedTimeoutsProcessingLoop is the event loop which waits for notification
// about pending work and as soon as there is some it triggers processing.
func (
	t *TimeoutAggregator[VoteT],
) queuedTimeoutsProcessingLoop(ctx lifecycle.SignalerContext) {
	defer t.wg.Done()
	notifier := t.queuedTimeoutsNotifier
	for {
		select {
		case <-ctx.Done():
			return
		case <-notifier:
			t.tracer.Trace("notified for queued timeout state")
			err := t.processQueuedTimeoutStates(ctx)
			if err != nil {
				ctx.Throw(fmt.Errorf(
					"internal error processing queued timeout events: %w",
					err,
				))
				return
			}
		}
	}
}

// processQueuedTimeoutStates sequentially processes items from `queuedTimeouts`
// until the queue returns 'empty'. Only when there are no more queued up
// TimeoutStates, this function call returns.  No errors are expected during
// normal operations.
func (t *TimeoutAggregator[VoteT]) processQueuedTimeoutStates(
	ctx context.Context,
) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case timeoutState, ok := <-t.queuedTimeouts:
			if !ok {
				return nil
			}

			err := t.processQueuedTimeout(timeoutState)

			if err != nil {
				return fmt.Errorf("could not process pending TO: %d: %w",
					timeoutState.Rank,
					err,
				)
			}

			t.tracer.Trace("TimeoutState processed successfully")
		default:
			// when there is no more messages in the queue, back to the loop to wait
			// for the next incoming message to arrive.
			return nil
		}
	}
}

// processQueuedTimeout performs actual processing of queued timeouts, this
// method is called from multiple concurrent goroutines. No errors are expected
// during normal operation
func (t *TimeoutAggregator[VoteT]) processQueuedTimeout(
	timeoutState *models.TimeoutState[VoteT],
) error {
	// We create a timeout collector before validating the first TO, so processing
	// an invalid TO will result in a collector being added, until the
	// corresponding rank is pruned.
	collector, _, err := t.collectors.GetOrCreateCollector(timeoutState.Rank)
	if err != nil {
		if errors.Is(err, models.ErrRankUnknown) {
			t.tracer.Error("discarding TO for unknown rank", err)
			return nil
		}
		return fmt.Errorf("could not get collector for rank %d: %w",
			timeoutState.Rank, err)
	}

	err = collector.AddTimeout(timeoutState)
	if err != nil {
		return fmt.Errorf("could not process TO for rank %d: %w",
			timeoutState.Rank, err)
	}
	return nil
}

// AddTimeout checks if TO is stale and appends TO to processing queue.
// The actual processing will be done asynchronously by the
// `TimeoutAggregator`'s internal worker routines.
func (t *TimeoutAggregator[VoteT]) AddTimeout(
	timeoutState *models.TimeoutState[VoteT],
) {
	// drop stale objects
	if timeoutState.Rank < t.lowestRetainedRank.Value() {
		return
	}

	select {
	case t.queuedTimeouts <- timeoutState:
		select {
		case t.queuedTimeoutsNotifier <- struct{}{}:
		default:
		}
	default:
		// processing pipeline `queuedTimeouts` is full
		// It's ok to silently drop timeouts, because we are probably catching up.
		t.tracer.Trace("no queue capacity, dropping timeout")
	}
}

// PruneUpToRank deletes all `TimeoutCollector`s _below_ to the given rank, as
// well as related indices. We only retain and process `TimeoutCollector`s,
// whose rank is equal or larger than `lowestRetainedRank`. If
// `lowestRetainedRank` is smaller than the previous value, the previous value
// is kept and the method call is a NoOp.
func (t *TimeoutAggregator[VoteT]) PruneUpToRank(lowestRetainedRank uint64) {
	t.collectors.PruneUpToRank(lowestRetainedRank)
}

// OnRankChange implements the `OnRankChange` callback from the
// `consensus.Consumer`. We notify the enteringRankProcessingLoop worker, which
// then prunes up to the active rank. CAUTION: the input to this callback is
// treated as trusted; precautions should be taken that messages from external
// nodes cannot be considered as inputs to this function
func (t *TimeoutAggregator[VoteT]) OnRankChange(oldRank, newRank uint64) {
	if t.lowestRetainedRank.Set(newRank) {
		select {
		case t.enteringRankNotifier <- struct{}{}:
		default:
		}
	}
}

// enteringRankProcessingLoop is a separate goroutine that performs processing
// of entering rank events
func (t *TimeoutAggregator[VoteT]) enteringRankProcessingLoop(
	ctx context.Context,
) {
	defer t.wg.Done()
	notifier := t.enteringRankNotifier
	for {
		select {
		case <-ctx.Done():
			return
		case <-notifier:
			t.PruneUpToRank(t.lowestRetainedRank.Value())
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
