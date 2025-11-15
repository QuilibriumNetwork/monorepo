package timeoutcollector

import (
	"errors"
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/counters"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// TimeoutCollector implements logic for collecting timeout states. Performs
// deduplication, caching and processing of timeouts, delegating those tasks to
// underlying modules. Emits notifications about verified QCs and TCs, if their
// rank is newer than any QC or TC previously known to the TimeoutCollector.
// This module is safe to use in concurrent environment.
type TimeoutCollector[VoteT models.Unique] struct {
	tracer           consensus.TraceLogger
	timeoutsCache    *TimeoutStatesCache[VoteT] // cache for tracking double timeout and timeout equivocation
	notifier         consensus.TimeoutAggregationConsumer[VoteT]
	processor        consensus.TimeoutProcessor[VoteT]
	newestReportedQC counters.StrictMonotonicCounter // rank of newest QC that was reported
	newestReportedTC counters.StrictMonotonicCounter // rank of newest TC that was reported
}

var _ consensus.TimeoutCollector[*nilUnique] = (*TimeoutCollector[*nilUnique])(nil)

// NewTimeoutCollector creates new instance of TimeoutCollector
func NewTimeoutCollector[VoteT models.Unique](
	tracer consensus.TraceLogger,
	rank uint64,
	notifier consensus.TimeoutAggregationConsumer[VoteT],
	processor consensus.TimeoutProcessor[VoteT],
) *TimeoutCollector[VoteT] {
	tc := &TimeoutCollector[VoteT]{
		tracer:           tracer,
		notifier:         notifier,
		timeoutsCache:    NewTimeoutStatesCache[VoteT](rank),
		processor:        processor,
		newestReportedQC: counters.NewMonotonicCounter(0),
		newestReportedTC: counters.NewMonotonicCounter(0),
	}

	return tc
}

// AddTimeout adds a Timeout State  to the collector. When TSs from
// strictly more than 1/3 of consensus participants (measured by weight) were
// collected, the callback for partial TC will be triggered. After collecting
// TSs from a supermajority, a TC will be created and passed to the EventLoop.
// Expected error returns during normal operations:
//   - timeoutcollector.ErrTimeoutForIncompatibleRank - submitted timeout for
//     incompatible rank
//
// All other exceptions are symptoms of potential state corruption.
func (c *TimeoutCollector[VoteT]) AddTimeout(
	timeout *models.TimeoutState[VoteT],
) error {
	// cache timeout
	err := c.timeoutsCache.AddTimeoutState(timeout)
	if err != nil {
		if errors.Is(err, ErrRepeatedTimeout) {
			return nil
		}
		doubleTimeoutErr, isDoubleTimeoutErr :=
			models.AsDoubleTimeoutError[VoteT](err)
		if isDoubleTimeoutErr {
			c.notifier.OnDoubleTimeoutDetected(
				doubleTimeoutErr.FirstTimeout,
				doubleTimeoutErr.ConflictingTimeout,
			)
			return nil
		}
		return fmt.Errorf("internal error adding timeout to cache: %d: %w",
			timeout.Rank,
			err,
		)
	}

	err = c.processTimeout(timeout)
	if err != nil {
		return fmt.Errorf("internal error processing TO: %d: %w",
			timeout.Rank,
			err,
		)
	}
	return nil
}

// processTimeout delegates TO processing to TimeoutProcessor, handles sentinel
// errors expected errors are handled and reported to notifier. Notifies
// listeners about validates QCs and TCs. No errors are expected during normal
// flow of operations.
func (c *TimeoutCollector[VoteT]) processTimeout(
	timeout *models.TimeoutState[VoteT],
) error {
	err := c.processor.Process(timeout)
	if err != nil {
		if invalidTimeoutErr, ok := models.AsInvalidTimeoutError[VoteT](err); ok {
			c.tracer.Error(
				"invalid timeout detected",
				err,
				consensus.Uint64Param("timeout_rank", timeout.Rank),
				consensus.IdentityParam("timeout_voter", (*timeout.Vote).Identity()),
			)
			c.notifier.OnInvalidTimeoutDetected(*invalidTimeoutErr)
			return nil
		}
		return fmt.Errorf("internal error while processing timeout: %w", err)
	}

	// TODO: consider moving OnTimeoutProcessed to TimeoutAggregationConsumer,
	// need to fix telemetry for this.
	c.notifier.OnTimeoutProcessed(timeout)

	// In the following, we emit notifications about new QCs, if their rank is
	// newer than any QC previously known to the TimeoutCollector. Note that our
	// implementation only provides weak ordering:
	//  * Over larger time scales, the emitted events are for statistically
	//    increasing ranks.
	//  * However, on short time scales there are _no_ monotonicity guarantees
	//    w.r.t. the ranks.
	// Explanation:
	// While only QCs with strict monotonicly increasing ranks pass the
	// `if c.newestReportedQC.Set(timeout.NewestQC.Rank)` statement, we emit the
	// notification in a separate step. Therefore, emitting the notifications is
	// subject to races, where on very short time-scales the notifications can be
	// out of order. Nevertheless, we note that notifications are only created for
	// QCs that are strictly newer than any other known QC at the time we check
	// via the `if ... Set(..)` statement. Thereby, we implement the desired
	// filtering behaviour, i.e. that the recipient of the notifications is not
	// spammed by old (or repeated) QCs. Reasoning for this approach:
	// The current implementation is completely lock-free without noteworthy risk
	// of congestion. For the recipient of the notifications, the weak ordering is
	// of no concern, because it anyway is only interested in the newest QC.
	// Time-localized disorder is irrelevant, because newer QCs that would arrive
	// later in a strongly ordered system can only arrive earlier in our weakly
	// ordered implementation. Hence, if anything, the recipient receives the
	// desired information _earlier_ but not later.
	if c.newestReportedQC.Set(timeout.LatestQuorumCertificate.GetRank()) {
		c.notifier.OnNewQuorumCertificateDiscovered(timeout.LatestQuorumCertificate)
	}
	// Same explanation for weak ordering of QCs also applies to TCs.
	if timeout.PriorRankTimeoutCertificate != nil {
		if c.newestReportedTC.Set(timeout.PriorRankTimeoutCertificate.GetRank()) {
			c.notifier.OnNewTimeoutCertificateDiscovered(
				timeout.PriorRankTimeoutCertificate,
			)
		}
	}

	return nil
}

// Rank returns rank which is associated with this timeout collector
func (c *TimeoutCollector[VoteT]) Rank() uint64 {
	return c.timeoutsCache.Rank()
}
