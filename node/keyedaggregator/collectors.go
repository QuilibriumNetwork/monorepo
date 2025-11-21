package keyedaggregator

import (
	"fmt"
	"sync"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
)

// Collector represents a per-sequence worker that processes items belonging to
// that sequence.
type Collector[ItemT any] interface {
	Add(*ItemT) error
	Records() []*ItemT
	Remove(*ItemT)
}

// CollectorFactory constructs collectors for a specific sequence.
type CollectorFactory[ItemT any] interface {
	Create(sequence uint64) (Collector[ItemT], error)
}

// CollectorCache provides lazy access to collectors keyed by sequence and
// pruning of stale sequences.
type CollectorCache[ItemT any] interface {
	GetOrCreateCollector(sequence uint64) (Collector[ItemT], bool, error)
	GetCollector(sequence uint64) (Collector[ItemT], bool, error)
	PruneUpToSequence(sequence uint64)
}

// SequencedCollectors is a threadsafe CollectorCache implementation that
// lazily instantiates collectors and prunes them when the retained sequence
// advances.
type SequencedCollectors[ItemT any] struct {
	tracer           consensus.TraceLogger
	lock             sync.RWMutex
	lowestRetained   uint64
	highestCached    uint64
	collectors       map[uint64]Collector[ItemT]
	collectorFactory CollectorFactory[ItemT]
}

// NewSequencedCollectors creates a SequencedCollectors backed by the provided
// factory. The lowestRetained sequence is kept even if pruning is invoked with
// smaller values.
func NewSequencedCollectors[ItemT any](
	tracer consensus.TraceLogger,
	lowestRetained uint64,
	factory CollectorFactory[ItemT],
) *SequencedCollectors[ItemT] {
	if factory == nil {
		panic("collector factory is required")
	}
	return &SequencedCollectors[ItemT]{
		tracer:           tracer,
		lowestRetained:   lowestRetained,
		highestCached:    lowestRetained,
		collectors:       make(map[uint64]Collector[ItemT]),
		collectorFactory: factory,
	}
}

// GetOrCreateCollector retrieves the collector for the provided sequence. If no
// collector exists, one is created using the factory.
func (c *SequencedCollectors[ItemT]) GetOrCreateCollector(
	sequence uint64,
) (Collector[ItemT], bool, error) {
	cached, found, err := c.getCollector(sequence)
	if err != nil {
		return nil, false, err
	}
	if found {
		return cached, false, nil
	}

	col, err := c.collectorFactory.Create(sequence)
	if err != nil {
		return nil, false, fmt.Errorf(
			"could not create collector for sequence %d: %w",
			sequence,
			err,
		)
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	if existing, ok := c.collectors[sequence]; ok {
		return existing, false, nil
	}
	c.collectors[sequence] = col
	if c.highestCached < sequence {
		c.highestCached = sequence
	}
	return col, true, nil
}

func (c *SequencedCollectors[ItemT]) getCollector(
	sequence uint64,
) (Collector[ItemT], bool, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	if sequence < c.lowestRetained {
		return nil, false, ErrSequenceBelowRetention
	}
	col, found := c.collectors[sequence]
	return col, found, nil
}

// GetCollector retrieves a collector for the provided sequence without creating
// a new one.
func (c *SequencedCollectors[ItemT]) GetCollector(
	sequence uint64,
) (Collector[ItemT], bool, error) {
	return c.getCollector(sequence)
}

// PruneUpToSequence removes collectors whose sequence is below the provided
// threshold.
func (c *SequencedCollectors[ItemT]) PruneUpToSequence(sequence uint64) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.lowestRetained >= sequence {
		return
	}
	before := len(c.collectors)
	if before == 0 {
		c.lowestRetained = sequence
		return
	}

	if uint64(before) < sequence-c.lowestRetained {
		for seq := range c.collectors {
			if seq < sequence {
				delete(c.collectors, seq)
			}
		}
	} else {
		for seq := c.lowestRetained; seq < sequence; seq++ {
			delete(c.collectors, seq)
		}
	}
	c.lowestRetained = sequence
}
