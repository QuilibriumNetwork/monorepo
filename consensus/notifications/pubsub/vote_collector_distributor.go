package pubsub

import (
	"sync"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// VoteCollectorDistributor ingests notifications about vote aggregation and
// distributes them to consumers. Such notifications are produced by the vote
// aggregation logic. Concurrency safe.
type VoteCollectorDistributor[VoteT models.Unique] struct {
	consumers []consensus.VoteCollectorConsumer[VoteT]
	lock      sync.RWMutex
}

var _ consensus.VoteCollectorConsumer[*nilUnique] = (*VoteCollectorDistributor[*nilUnique])(nil)

func NewQCCreatedDistributor[
	VoteT models.Unique,
]() *VoteCollectorDistributor[VoteT] {
	return &VoteCollectorDistributor[VoteT]{}
}

func (d *VoteCollectorDistributor[VoteT]) AddVoteCollectorConsumer(
	consumer consensus.VoteCollectorConsumer[VoteT],
) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.consumers = append(d.consumers, consumer)
}

func (
	d *VoteCollectorDistributor[VoteT],
) OnQuorumCertificateConstructedFromVotes(
	qc models.QuorumCertificate,
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, consumer := range d.consumers {
		consumer.OnQuorumCertificateConstructedFromVotes(qc)
	}
}

func (d *VoteCollectorDistributor[VoteT]) OnVoteProcessed(vote *VoteT) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnVoteProcessed(vote)
	}
}
