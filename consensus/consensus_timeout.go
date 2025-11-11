package consensus

import (
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
)

// TimeoutAggregator verifies and aggregates timeout states to build timeout
// certificates [TCs]. When enough timeout states are collected, it builds a TC
// and sends it to the EventLoop TimeoutAggregator also detects protocol
// violation, including invalid timeouts, double timeout, etc and notifies a
// HotStuff consumer for slashing.
type TimeoutAggregator[VoteT models.Unique] interface {
	lifecycle.Component

	// AddTimeout verifies and aggregates a timeout state.
	// This method can be called concurrently, timeouts will be queued and
	// processed asynchronously.
	AddTimeout(timeoutState *models.TimeoutState[VoteT])

	// PruneUpToRank deletes all `TimeoutCollector`s _below_ to the given rank, as
	// well as related indices. We only retain and process `TimeoutCollector`s,
	// whose rank is equal or larger than `lowestRetainedRank`. If
	// `lowestRetainedRank` is smaller than the previous value, the previous value
	// is kept and the method call is a NoOp. This value should be set to the
	// latest active rank maintained by `Pacemaker`.
	PruneUpToRank(lowestRetainedRank uint64)
}

// TimeoutCollector collects all timeout states for a specified rank. On the
// happy path, it generates a TimeoutCertificate when enough timeouts have been
// collected. The TimeoutCollector is a higher-level structure that orchestrates
// deduplication, caching and processing of timeouts, delegating those tasks to
// underlying modules (such as TimeoutProcessor). Implementations of
// TimeoutCollector must be concurrency safe.
type TimeoutCollector[VoteT models.Unique] interface {
	// AddTimeout adds a Timeout State  to the collector. When TSs from
	// strictly more than 1/3 of consensus participants (measured by weight) were
	// collected, the callback for partial TC will be triggered. After collecting
	// TSs from a supermajority, a TC will be created and passed to the EventLoop.
	// Expected error returns during normal operations:
	// * timeoutcollector.ErrTimeoutForIncompatibleRank - submitted timeout for
	//   incompatible rank
	// All other exceptions are symptoms of potential state corruption.
	AddTimeout(timeoutState *models.TimeoutState[VoteT]) error

	// Rank returns the rank that this instance is collecting timeouts for.
	// This method is useful when adding the newly created timeout collector to
	// timeout collectors map.
	Rank() uint64
}

// TimeoutProcessor ingests Timeout States  for a particular rank. It
// implements the algorithms for validating TSs, orchestrates their low-level
// aggregation and emits `OnPartialTimeoutCertificateCreated` and `OnTimeoutCertificateConstructedFromTimeouts`
// notifications. TimeoutProcessor cannot deduplicate TSs (this should be
// handled by the higher-level TimeoutCollector) and errors instead. Depending
// on their implementation, a TimeoutProcessor might drop timeouts or attempt to
// construct a TC.
type TimeoutProcessor[VoteT models.Unique] interface {
	// Process performs processing of single timeout state. This function is safe
	// to call from multiple goroutines. Expected error returns during normal
	// operations:
	// * timeoutcollector.ErrTimeoutForIncompatibleRank - submitted timeout for
	//   incompatible rank
	// * models.InvalidTimeoutError - submitted invalid timeout(invalid structure
	//   or invalid signature)
	// * models.DuplicatedSignerError if a timeout from the same signer was
	//   previously already added. It does _not necessarily_ imply that the
	//   timeout is invalid or the sender is equivocating.
	// All other errors should be treated as exceptions.
	Process(timeout *models.TimeoutState[VoteT]) error
}

// TimeoutCollectorFactory performs creation of TimeoutCollector for a given
// rank
type TimeoutCollectorFactory[VoteT models.Unique] interface {
	// Create is a factory method to generate a TimeoutCollector for a given rank
	// Expected error returns during normal operations:
	//  * models.ErrRankUnknown no rank containing the given rank is known
	// All other errors should be treated as exceptions.
	Create(rank uint64) (TimeoutCollector[VoteT], error)
}

// TimeoutProcessorFactory performs creation of TimeoutProcessor for a given
// rank
type TimeoutProcessorFactory[VoteT models.Unique] interface {
	// Create is a factory method to generate a TimeoutProcessor for a given rank
	// Expected error returns during normal operations:
	//  * models.ErrRankUnknown no rank containing the given rank is known
	// All other errors should be treated as exceptions.
	Create(rank uint64) (TimeoutProcessor[VoteT], error)
}

// TimeoutCollectors encapsulates the functionality to generate, store and prune
// `TimeoutCollector` instances (one per rank). Its main purpose is to provide a
// higher-level API to `TimeoutAggregator` for managing and interacting with the
// rank-specific `TimeoutCollector` instances. Implementations are concurrency
// safe.
type TimeoutCollectors[VoteT models.Unique] interface {
	// GetOrCreateCollector retrieves the TimeoutCollector for the specified
	// rank or creates one if none exists.  When creating a timeout collector,
	// the rank is used to query the consensus committee for the respective
	// Rank the rank belongs to.
	// It returns:
	//  -  (collector, true, nil) if no collector can be found by the rank, and a
	//     new collector was created.
	//  -  (collector, false, nil) if the collector can be found by the rank.
	//  -  (nil, false, error) if running into any exception creating the timeout
	//     collector.
	// Expected error returns during normal operations:
	//  * models.BelowPrunedThresholdError if rank is below the pruning threshold
	//  * models.ErrRankUnknown if rank is not yet pruned but no rank containing
	//   the given rank is known
	GetOrCreateCollector(rank uint64) (
		collector TimeoutCollector[VoteT],
		created bool,
		err error,
	)

	// PruneUpToRank prunes the timeout collectors with ranks _below_ the given
	// value, i.e. we only retain and process timeout collectors, whose ranks are
	// equal or larger than `lowestRetainedRank`. If `lowestRetainedRank` is
	// smaller than the previous value, the previous value is kept and the method
	// call is a NoOp.
	PruneUpToRank(lowestRetainedRank uint64)
}
