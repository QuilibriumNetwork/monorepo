package pubsub

import (
	"sync"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// TimeoutAggregationViolationDistributor ingests notifications about timeout
// aggregation violations and distributes them to consumers. Such notifications
// are produced by the timeout aggregation logic. Concurrency safe.
type TimeoutAggregationViolationDistributor[VoteT models.Unique] struct {
	consumers []consensus.TimeoutAggregationViolationConsumer[VoteT]
	lock      sync.RWMutex
}

var _ consensus.TimeoutAggregationViolationConsumer[*nilUnique] = (*TimeoutAggregationViolationDistributor[*nilUnique])(nil)

func NewTimeoutAggregationViolationDistributor[
	VoteT models.Unique,
]() *TimeoutAggregationViolationDistributor[VoteT] {
	return &TimeoutAggregationViolationDistributor[VoteT]{}
}

func (
	d *TimeoutAggregationViolationDistributor[VoteT],
) AddTimeoutAggregationViolationConsumer(
	consumer consensus.TimeoutAggregationViolationConsumer[VoteT],
) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.consumers = append(d.consumers, consumer)
}

func (
	d *TimeoutAggregationViolationDistributor[VoteT],
) OnDoubleTimeoutDetected(
	timeout *models.TimeoutState[VoteT],
	altTimeout *models.TimeoutState[VoteT],
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnDoubleTimeoutDetected(timeout, altTimeout)
	}
}

func (
	d *TimeoutAggregationViolationDistributor[VoteT],
) OnInvalidTimeoutDetected(
	err models.InvalidTimeoutError[VoteT],
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnInvalidTimeoutDetected(err)
	}
}
