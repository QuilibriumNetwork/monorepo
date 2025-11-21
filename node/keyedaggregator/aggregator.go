package keyedaggregator

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/counters"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
)

const (
	defaultWorkerCount = 4
	defaultQueueSize   = 1000
)

// SequenceExtractor returns the sequence identifier for a given item. The
// sequence is typically the logical round/rank/height that an item belongs to.
type SequenceExtractor[ItemT any] func(*ItemT) uint64

// SequencedAggregator is a generic event dispatcher that fans out sequenced
// items to lazily-created collectors keyed by the item's sequence. Items are
// processed asynchronously by worker goroutines. The aggregator drops stale
// items (items whose sequence is below the currently retained threshold) and
// relies on the CollectorCache implementation to prune old collectors.
type SequencedAggregator[ItemT any] struct {
	*lifecycle.ComponentManager

	tracer            consensus.TraceLogger
	lowestRetained    counters.StrictMonotonicCounter
	collectors        CollectorCache[ItemT]
	sequenceExtractor SequenceExtractor[ItemT]
	queuedItems       chan *ItemT
	itemsNotifier     chan struct{}
	sequenceNotifier  chan struct{}
	wg                sync.WaitGroup
	workerCount       int
	queueCapacity     int
}

// AggregatorOption customizes the behaviour of the SequencedAggregator.
type AggregatorOption func(*aggregatorConfig)

type aggregatorConfig struct {
	workerCount   int
	queueCapacity int
}

// WithWorkerCount overrides the default number of worker goroutines used to
// drain the inbound queue. Values smaller than one are ignored.
func WithWorkerCount(count int) AggregatorOption {
	return func(cfg *aggregatorConfig) {
		if count > 0 {
			cfg.workerCount = count
		}
	}
}

// WithQueueCapacity overrides the size of the buffered queue that stores
// pending items. Values smaller than one are ignored.
func WithQueueCapacity(capacity int) AggregatorOption {
	return func(cfg *aggregatorConfig) {
		if capacity > 0 {
			cfg.queueCapacity = capacity
		}
	}
}

// NewSequencedAggregator wires a SequencedAggregator using the provided
// CollectorCache and SequenceExtractor. The aggregator starts workers via the
// lifecycle.ComponentManager built during construction.
func NewSequencedAggregator[ItemT any](
	tracer consensus.TraceLogger,
	lowestRetained uint64,
	collectors CollectorCache[ItemT],
	extractor SequenceExtractor[ItemT],
	opts ...AggregatorOption,
) (*SequencedAggregator[ItemT], error) {
	if collectors == nil {
		return nil, fmt.Errorf("collector cache is required")
	}
	if extractor == nil {
		return nil, fmt.Errorf("sequence extractor is required")
	}

	cfg := aggregatorConfig{
		workerCount:   defaultWorkerCount,
		queueCapacity: defaultQueueSize,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.workerCount <= 0 {
		cfg.workerCount = defaultWorkerCount
	}
	if cfg.queueCapacity <= 0 {
		cfg.queueCapacity = defaultQueueSize
	}

	aggregator := &SequencedAggregator[ItemT]{
		tracer:            tracer,
		lowestRetained:    counters.NewMonotonicCounter(lowestRetained),
		collectors:        collectors,
		sequenceExtractor: extractor,
		queuedItems:       make(chan *ItemT, cfg.queueCapacity),
		itemsNotifier:     make(chan struct{}, 1),
		sequenceNotifier:  make(chan struct{}, 1),
		workerCount:       cfg.workerCount,
		queueCapacity:     cfg.queueCapacity,
	}

	aggregator.wg.Add(aggregator.workerCount + 1)
	builder := lifecycle.NewComponentManagerBuilder()
	for i := 0; i < aggregator.workerCount; i++ {
		builder.AddWorker(func(
			ctx lifecycle.SignalerContext,
			ready lifecycle.ReadyFunc,
		) {
			ready()
			aggregator.queuedItemsProcessingLoop(ctx)
		})
	}
	builder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		aggregator.sequenceProcessingLoop(ctx)
	})

	aggregator.ComponentManager = builder.Build()
	return aggregator, nil
}

// Add enqueues an item for asynchronous processing. Items whose sequence is
// below the retained threshold are silently discarded.
func (a *SequencedAggregator[ItemT]) Add(item *ItemT) {
	if item == nil {
		return
	}
	sequence := a.sequenceExtractor(item)
	if sequence < a.lowestRetained.Value() {
		a.tracer.Trace(
			"dropping item added below lowest retained value",
			consensus.Uint64Param("lowest_retained", a.lowestRetained.Value()),
			consensus.Uint64Param("sequence", sequence),
		)
		return
	}

	select {
	case a.queuedItems <- item:
		select {
		case a.itemsNotifier <- struct{}{}:
		default:
		}
	default:
		a.tracer.Trace("dropping sequenced item: queue at capacity")
	}
}

// PruneUpToSequence prunes all collectors with sequence lower than the provided
// threshold. If the provided threshold is behind the current value, this call
// is treated as a no-op.
func (a *SequencedAggregator[ItemT]) PruneUpToSequence(sequence uint64) {
	a.collectors.PruneUpToSequence(sequence)
}

// OnSequenceChange notifies the aggregator that the active sequence advanced.
// When the internal counter is updated the pruning worker is notified to prune
// the collector cache.
func (a *SequencedAggregator[ItemT]) OnSequenceChange(oldSeq, newSeq uint64) {
	if a.lowestRetained.Set(newSeq) {
		select {
		case a.sequenceNotifier <- struct{}{}:
		default:
		}
	}
}

func (a *SequencedAggregator[ItemT]) queuedItemsProcessingLoop(
	ctx lifecycle.SignalerContext,
) {
	defer a.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.itemsNotifier:
			a.tracer.Trace("processing queued sequenced items")
			if err := a.processQueuedItems(ctx); err != nil {
				ctx.Throw(fmt.Errorf("processing queued items failed: %w", err))
				return
			}
		}
	}
}

func (a *SequencedAggregator[ItemT]) processQueuedItems(
	ctx context.Context,
) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case item, ok := <-a.queuedItems:
			if !ok {
				return nil
			}
			if item == nil {
				continue
			}
			if err := a.processQueuedItem(item); err != nil {
				return err
			}
			a.tracer.Trace("sequenced item processed successfully")
		default:
			return nil
		}
	}
}

func (a *SequencedAggregator[ItemT]) processQueuedItem(item *ItemT) error {
	sequence := a.sequenceExtractor(item)
	collector, _, err := a.collectors.GetOrCreateCollector(sequence)
	if err != nil {
		switch {
		case errors.Is(err, ErrSequenceUnknown):
			a.tracer.Error("dropping item for unknown sequence", err)
			return nil
		case errors.Is(err, ErrSequenceBelowRetention):
			return nil
		default:
			return fmt.Errorf("could not get collector for sequence %d: %w",
				sequence,
				err,
			)
		}
	}

	if err := collector.Add(item); err != nil {
		return fmt.Errorf("collector processing failed for sequence %d: %w",
			sequence,
			err,
		)
	}
	return nil
}

func (a *SequencedAggregator[ItemT]) sequenceProcessingLoop(
	ctx context.Context,
) {
	defer a.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.sequenceNotifier:
			a.PruneUpToSequence(a.lowestRetained.Value())
		}
	}
}
