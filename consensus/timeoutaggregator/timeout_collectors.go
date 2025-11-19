package timeoutaggregator

import (
	"fmt"
	"sync"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// TimeoutCollectors implements management of multiple timeout collectors
// indexed by rank. Implements consensus.TimeoutCollectors interface. Creating a
// TimeoutCollector for a particular rank is lazy (instances are created on
// demand). This structure is concurrently safe.
type TimeoutCollectors[VoteT models.Unique] struct {
	tracer                    consensus.TraceLogger
	lock                      sync.RWMutex
	lowestRetainedRank        uint64                                       // lowest rank, for which we still retain a TimeoutCollector and process timeouts
	newestRankCachedCollector uint64                                       // highest rank, for which we have created a TimeoutCollector
	collectors                map[uint64]consensus.TimeoutCollector[VoteT] // rank -> TimeoutCollector
	collectorFactory          consensus.TimeoutCollectorFactory[VoteT]     // factor for creating collectors
}

var _ consensus.TimeoutCollectors[*nilUnique] = (*TimeoutCollectors[*nilUnique])(nil)

func NewTimeoutCollectors[VoteT models.Unique](
	tracer consensus.TraceLogger,
	lowestRetainedRank uint64,
	collectorFactory consensus.TimeoutCollectorFactory[VoteT],
) *TimeoutCollectors[VoteT] {
	return &TimeoutCollectors[VoteT]{
		tracer:                    tracer,
		lowestRetainedRank:        lowestRetainedRank,
		newestRankCachedCollector: lowestRetainedRank,
		collectors:                make(map[uint64]consensus.TimeoutCollector[VoteT]),
		collectorFactory:          collectorFactory,
	}
}

// GetOrCreateCollector retrieves the consensus.TimeoutCollector for the
// specified rank or creates one if none exists.
//   - (collector, true, nil) if no collector can be found by the rank, and a
//     new collector was created.
//   - (collector, false, nil) if the collector can be found by the rank
//   - (nil, false, error) if running into any exception creating the timeout
//     collector state machine
//
// Expected error returns during normal operations:
//   - models.BelowPrunedThresholdError if rank is below the pruning threshold
//   - models.ErrRankUnknown if rank is not yet pruned but no rank containing
//     the given rank is known, this error
//
// can be returned from factory method.
func (t *TimeoutCollectors[VoteT]) GetOrCreateCollector(rank uint64) (
	consensus.TimeoutCollector[VoteT],
	bool,
	error,
) {
	cachedCollector, hasCachedCollector, err := t.getCollector(rank)
	if err != nil {
		return nil, false, err
	}
	if hasCachedCollector {
		return cachedCollector, false, nil
	}

	collector, err := t.collectorFactory.Create(rank)
	if err != nil {
		return nil, false, fmt.Errorf(
			"could not create timeout collector for rank %d: %w",
			rank,
			err,
		)
	}

	// Initial check showed that there was no collector. However, it's possible
	// that after the initial check but before acquiring the lock to add the
	// newly-created collector, another goroutine already added the needed
	// collector. Hence, check again after acquiring the lock:
	t.lock.Lock()
	clr, found := t.collectors[rank]
	if found {
		t.lock.Unlock()
		return clr, false, nil
	}
	t.collectors[rank] = collector
	if t.newestRankCachedCollector < rank {
		t.newestRankCachedCollector = rank
	}
	t.lock.Unlock()

	return collector, true, nil
}

// getCollector retrieves consensus.TimeoutCollector from local cache in
// concurrent safe way. Performs check for lowestRetainedRank.
// Expected error returns during normal operations:
//   - models.BelowPrunedThresholdError - in case rank is lower than
//     lowestRetainedRank
func (t *TimeoutCollectors[VoteT]) getCollector(rank uint64) (
	consensus.TimeoutCollector[VoteT],
	bool,
	error,
) {
	t.lock.RLock()
	defer t.lock.RUnlock()
	if rank < t.lowestRetainedRank {
		return nil, false, models.NewBelowPrunedThresholdErrorf(
			"cannot retrieve collector for pruned rank %d (lowest retained rank %d)",
			rank,
			t.lowestRetainedRank,
		)
	}

	clr, found := t.collectors[rank]
	return clr, found, nil
}

// PruneUpToRank prunes the timeout collectors with ranks _below_ the given
// value, i.e. we only retain and process whose rank is equal or larger than
// `lowestRetainedRank`. If `lowestRetainedRank` is smaller than the previous
// value, the previous value is kept and the method call is a NoOp.
func (t *TimeoutCollectors[VoteT]) PruneUpToRank(lowestRetainedRank uint64) {
	t.lock.Lock()
	if t.lowestRetainedRank >= lowestRetainedRank {
		t.lock.Unlock()
		return
	}
	sizeBefore := len(t.collectors)
	if sizeBefore == 0 {
		t.lowestRetainedRank = lowestRetainedRank
		t.lock.Unlock()
		return
	}

	// to optimize the pruning of large rank-ranges, we compare:
	//  * the number of ranks for which we have collectors: len(t.collectors)
	//  * the number of ranks that need to be pruned: rank-t.lowestRetainedRank
	// We iterate over the dimension which is smaller.
	if uint64(sizeBefore) < lowestRetainedRank-t.lowestRetainedRank {
		for w := range t.collectors {
			if w < lowestRetainedRank {
				delete(t.collectors, w)
			}
		}
	} else {
		for w := t.lowestRetainedRank; w < lowestRetainedRank; w++ {
			delete(t.collectors, w)
		}
	}
	t.lowestRetainedRank = lowestRetainedRank
	t.lock.Unlock()
}
