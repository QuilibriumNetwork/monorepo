package consensus

import (
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
)

// VoteCollectors is an interface which allows VoteAggregator to interact with
// collectors structured by rank.
// Implementations of this interface are responsible for state transitions of
// `VoteCollector`s and pruning of stale and outdated collectors by rank.
type VoteCollectors[StateT models.Unique, VoteT models.Unique] interface {
	lifecycle.Component

	// GetOrCreateCollector retrieves the consensus.VoteCollector for the specified
	// rank or creates one if none exists.
	// It returns:
	//  -  (collector, true, nil) if no collector can be found by the rank, and a
	//     new collector was created.
	//  -  (collector, false, nil) if the collector can be found by the rank
	//  -  (nil, false, error) if running into any exception creating the vote
	//     collector state machine
	// Expected error returns during normal operations:
	//  * models.BelowPrunedThresholdError - in case rank is lower than last
	// pruned rank
	GetOrCreateCollector(rank uint64) (
		collector VoteCollector[StateT, VoteT],
		created bool,
		err error,
	)

	// PruneUpToRank prunes the vote collectors with ranks _below_ the given
	// value, i.e. we only retain and process whose rank is equal or larger than
	// `lowestRetainedRank`. If `lowestRetainedRank` is smaller than the previous
	// value, the previous value is kept and the method call is a NoOp.
	PruneUpToRank(lowestRetainedRank uint64)
}

// Workers queues and processes submitted tasks. We explicitly do not
// expose any functionality to terminate the worker pool.
type Workers interface {
	// Submit enqueues a function for a worker to execute. Submit will not block
	// regardless of the number of tasks submitted. Each task is immediately
	// given to an available worker or queued otherwise. Tasks are processed in
	// FiFO order.
	Submit(task func())
}

// Workerpool adds the functionality to terminate the workers to the
// Workers interface.
type Workerpool interface {
	Workers

	// StopWait stops the worker pool and waits for all queued tasks to
	// complete.  No additional tasks may be submitted, but all pending tasks are
	// executed by workers before this function returns.
	StopWait()
}
