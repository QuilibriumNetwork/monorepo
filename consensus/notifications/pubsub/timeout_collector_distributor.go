package pubsub

import (
	"sync"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// TimeoutCollectorDistributor ingests notifications about timeout aggregation
// and distributes them to consumers. Such notifications are produced by the
// timeout aggregation logic. Concurrency safe.
type TimeoutCollectorDistributor[VoteT models.Unique] struct {
	lock      sync.RWMutex
	consumers []consensus.TimeoutCollectorConsumer[VoteT]
}

var _ consensus.TimeoutCollectorConsumer[*nilUnique] = (*TimeoutCollectorDistributor[*nilUnique])(nil)

func NewTimeoutCollectorDistributor[VoteT models.Unique]() *TimeoutCollectorDistributor[VoteT] {
	return &TimeoutCollectorDistributor[VoteT]{}
}

func (d *TimeoutCollectorDistributor[VoteT]) AddTimeoutCollectorConsumer(
	consumer consensus.TimeoutCollectorConsumer[VoteT],
) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.consumers = append(d.consumers, consumer)
}

func (
	d *TimeoutCollectorDistributor[VoteT],
) OnTimeoutCertificateConstructedFromTimeouts(
	tc models.TimeoutCertificate,
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, consumer := range d.consumers {
		consumer.OnTimeoutCertificateConstructedFromTimeouts(tc)
	}
}

func (d *TimeoutCollectorDistributor[VoteT]) OnPartialTimeoutCertificateCreated(
	rank uint64,
	newestQC models.QuorumCertificate,
	previousRankTimeoutCert models.TimeoutCertificate,
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, consumer := range d.consumers {
		consumer.OnPartialTimeoutCertificateCreated(
			rank,
			newestQC,
			previousRankTimeoutCert,
		)
	}
}

func (d *TimeoutCollectorDistributor[VoteT]) OnNewQuorumCertificateDiscovered(
	qc models.QuorumCertificate,
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, consumer := range d.consumers {
		consumer.OnNewQuorumCertificateDiscovered(qc)
	}
}

func (d *TimeoutCollectorDistributor[VoteT]) OnNewTimeoutCertificateDiscovered(
	tc models.TimeoutCertificate,
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, consumer := range d.consumers {
		consumer.OnNewTimeoutCertificateDiscovered(tc)
	}
}

func (d *TimeoutCollectorDistributor[VoteT]) OnTimeoutProcessed(
	timeout *models.TimeoutState[VoteT],
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnTimeoutProcessed(timeout)
	}
}
