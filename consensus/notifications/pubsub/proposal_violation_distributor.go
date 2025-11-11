package pubsub

import (
	"sync"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// ProposalViolationDistributor ingests notifications about HotStuff-protocol
// violations and distributes them to consumers. Such notifications are produced
// by the active consensus participants and the consensus follower. Concurrently
// safe.
type ProposalViolationDistributor[
	StateT models.Unique,
	VoteT models.Unique,
] struct {
	consumers []consensus.ProposalViolationConsumer[StateT, VoteT]
	lock      sync.RWMutex
}

var _ consensus.ProposalViolationConsumer[*nilUnique, *nilUnique] = (*ProposalViolationDistributor[*nilUnique, *nilUnique])(nil)

func NewProposalViolationDistributor[
	StateT models.Unique,
	VoteT models.Unique,
]() *ProposalViolationDistributor[StateT, VoteT] {
	return &ProposalViolationDistributor[StateT, VoteT]{}
}

func (
	d *ProposalViolationDistributor[StateT, VoteT],
) AddProposalViolationConsumer(
	consumer consensus.ProposalViolationConsumer[StateT, VoteT],
) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.consumers = append(d.consumers, consumer)
}

func (
	d *ProposalViolationDistributor[StateT, VoteT],
) OnInvalidStateDetected(err *models.InvalidProposalError[StateT, VoteT]) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnInvalidStateDetected(err)
	}
}

func (
	d *ProposalViolationDistributor[StateT, VoteT],
) OnDoubleProposeDetected(state1, state2 *models.State[StateT]) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnDoubleProposeDetected(state1, state2)
	}
}
