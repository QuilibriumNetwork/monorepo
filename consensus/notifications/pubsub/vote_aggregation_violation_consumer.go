package pubsub

import (
	"sync"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// VoteAggregationViolationDistributor ingests notifications about vote
// aggregation violations and distributes them to consumers. Such notifications
// are produced by the vote aggregation logic. Concurrency safe.
type VoteAggregationViolationDistributor[
	StateT models.Unique,
	VoteT models.Unique,
] struct {
	consumers []consensus.VoteAggregationViolationConsumer[StateT, VoteT]
	lock      sync.RWMutex
}

var _ consensus.VoteAggregationViolationConsumer[*nilUnique, *nilUnique] = (*VoteAggregationViolationDistributor[*nilUnique, *nilUnique])(nil)

func NewVoteAggregationViolationDistributor[
	StateT models.Unique,
	VoteT models.Unique,
]() *VoteAggregationViolationDistributor[StateT, VoteT] {
	return &VoteAggregationViolationDistributor[StateT, VoteT]{}
}

func (d *VoteAggregationViolationDistributor[
	StateT,
	VoteT,
]) AddVoteAggregationViolationConsumer(
	consumer consensus.VoteAggregationViolationConsumer[StateT, VoteT],
) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.consumers = append(d.consumers, consumer)
}

func (d *VoteAggregationViolationDistributor[
	StateT,
	VoteT,
]) OnDoubleVotingDetected(vote1, vote2 *VoteT) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnDoubleVotingDetected(vote1, vote2)
	}
}

func (d *VoteAggregationViolationDistributor[
	StateT,
	VoteT,
]) OnInvalidVoteDetected(err models.InvalidVoteError[VoteT]) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnInvalidVoteDetected(err)
	}
}

func (d *VoteAggregationViolationDistributor[
	StateT,
	VoteT,
]) OnVoteForInvalidStateDetected(
	vote *VoteT,
	invalidProposal *models.SignedProposal[StateT, VoteT],
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnVoteForInvalidStateDetected(vote, invalidProposal)
	}
}
