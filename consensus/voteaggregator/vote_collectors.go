package voteaggregator

import (
	"fmt"
	"sync"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
)

// NewCollectorFactoryMethod is a factory method to generate a VoteCollector for
// concrete rank
type NewCollectorFactoryMethod[StateT models.Unique, VoteT models.Unique] = func(
	rank uint64,
	workers consensus.Workers,
) (consensus.VoteCollector[StateT, VoteT], error)

// VoteCollectors implements management of multiple vote collectors indexed by
// rank. Implements consensus.VoteCollectors interface. Creating a VoteCollector
// for a particular rank is lazy (instances are created on demand).
// This structure is concurrency safe.
type VoteCollectors[StateT models.Unique, VoteT models.Unique] struct {
	*lifecycle.ComponentManager
	tracer             consensus.TraceLogger
	lock               sync.RWMutex
	lowestRetainedRank uint64                                            // lowest rank, for which we still retain a VoteCollector and process votes
	collectors         map[uint64]consensus.VoteCollector[StateT, VoteT] // rank -> VoteCollector
	workerPool         consensus.Workerpool                              // for processing votes that are already cached in VoteCollectors and waiting for respective state
	createCollector    NewCollectorFactoryMethod[StateT, VoteT]          // factory method for creating collectors
}

var _ consensus.VoteCollectors[*nilUnique, *nilUnique] = (*VoteCollectors[*nilUnique, *nilUnique])(nil)

func NewVoteCollectors[StateT models.Unique, VoteT models.Unique](
	tracer consensus.TraceLogger,
	lowestRetainedRank uint64,
	workerPool consensus.Workerpool,
	factoryMethod NewCollectorFactoryMethod[StateT, VoteT],
) *VoteCollectors[StateT, VoteT] {
	v := &VoteCollectors[StateT, VoteT]{
		tracer:             tracer,
		lowestRetainedRank: lowestRetainedRank,
		collectors:         make(map[uint64]consensus.VoteCollector[StateT, VoteT]),
		workerPool:         workerPool,
		createCollector:    factoryMethod,
	}
	// Component manager for wrapped worker pool
	componentBuilder := lifecycle.NewComponentManagerBuilder()
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		<-ctx.Done()            // wait for parent context to signal shutdown
		v.workerPool.StopWait() // wait till all workers exit
	})
	v.ComponentManager = componentBuilder.Build()
	return v
}

// GetOrCreateCollector retrieves the consensus.VoteCollector for the specified
// rank or creates one if none exists.
//   - (collector, true, nil) if no collector can be found by the rank, and a
//     new collector was created.
//   - (collector, false, nil) if the collector can be found by the rank
//   - (nil, false, error) if running into any exception creating the vote
//     collector state machine
//
// Expected error returns during normal operations:
//   - models.BelowPrunedThresholdError - in case rank is lower than
//     lowestRetainedRank
func (v *VoteCollectors[StateT, VoteT]) GetOrCreateCollector(rank uint64) (
	consensus.VoteCollector[StateT, VoteT],
	bool,
	error,
) {
	cachedCollector, hasCachedCollector, err := v.getCollector(rank)
	if err != nil {
		return nil, false, err
	}

	if hasCachedCollector {
		return cachedCollector, false, nil
	}

	collector, err := v.createCollector(rank, v.workerPool)
	if err != nil {
		return nil, false, fmt.Errorf(
			"could not create vote collector for rank %d: %w",
			rank,
			err,
		)
	}

	// Initial check showed that there was no collector. However, it's possible
	// that after the initial check but before acquiring the lock to add the
	// newly-created collector, another goroutine already added the needed
	// collector. Hence, check again after acquiring the lock:
	v.lock.Lock()
	defer v.lock.Unlock()

	clr, found := v.collectors[rank]
	if found {
		return clr, false, nil
	}

	v.collectors[rank] = collector
	return collector, true, nil
}

// getCollector retrieves consensus.VoteCollector from local cache in
// concurrency safe way. Performs check for lowestRetainedRank.
// Expected error returns during normal operations:
//   - models.BelowPrunedThresholdError - in case rank is lower than
//     lowestRetainedRank
func (v *VoteCollectors[StateT, VoteT]) getCollector(rank uint64) (
	consensus.VoteCollector[StateT, VoteT],
	bool,
	error,
) {
	v.lock.RLock()
	defer v.lock.RUnlock()
	if rank < v.lowestRetainedRank {
		return nil, false, models.NewBelowPrunedThresholdErrorf(
			"cannot retrieve collector for pruned rank %d (lowest retained rank %d)",
			rank,
			v.lowestRetainedRank,
		)
	}

	clr, found := v.collectors[rank]

	return clr, found, nil
}

// PruneUpToRank prunes the vote collectors with ranks _below_ the given value,
// i.e. we only retain and process whose rank is equal or larger than
// `lowestRetainedRank`. If `lowestRetainedRank` is smaller than the previous
// value, the previous value is kept and the method call is a NoOp.
func (v *VoteCollectors[StateT, VoteT]) PruneUpToRank(
	lowestRetainedRank uint64,
) {
	v.lock.Lock()
	defer v.lock.Unlock()
	if v.lowestRetainedRank >= lowestRetainedRank {
		return
	}
	if len(v.collectors) == 0 {
		v.lowestRetainedRank = lowestRetainedRank
		return
	}

	// to optimize the pruning of large rank-ranges, we compare:
	//  * the number of ranks for which we have collectors: len(v.collectors)
	//  * the number of ranks that need to be pruned: rank-v.lowestRetainedRank
	// We iterate over the dimension which is smaller.
	if uint64(len(v.collectors)) < lowestRetainedRank-v.lowestRetainedRank {
		for w := range v.collectors {
			if w < lowestRetainedRank {
				delete(v.collectors, w)
			}
		}
	} else {
		for w := v.lowestRetainedRank; w < lowestRetainedRank; w++ {
			delete(v.collectors, w)
		}
	}

	v.lowestRetainedRank = lowestRetainedRank
	v.tracer.Trace("pruned vote collectors")
}
