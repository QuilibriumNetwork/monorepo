package pubsub

import (
	"sync"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// ParticipantDistributor ingests events from HotStuff's core logic and
// distributes them to consumers. This logic only runs inside active consensus
// participants proposing states, voting, collecting + aggregating votes to QCs,
// and participating in the pacemaker (sending timeouts, collecting +
// aggregating timeouts to TCs). Concurrency safe.
type ParticipantDistributor[
	StateT models.Unique,
	VoteT models.Unique,
] struct {
	consumers []consensus.ParticipantConsumer[StateT, VoteT]
	lock      sync.RWMutex
}

var _ consensus.ParticipantConsumer[*nilUnique, *nilUnique] = (*ParticipantDistributor[*nilUnique, *nilUnique])(nil)

func NewParticipantDistributor[
	StateT models.Unique,
	VoteT models.Unique,
]() *ParticipantDistributor[StateT, VoteT] {
	return &ParticipantDistributor[StateT, VoteT]{}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) AddParticipantConsumer(
	consumer consensus.ParticipantConsumer[StateT, VoteT],
) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.consumers = append(d.consumers, consumer)
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnEventProcessed() {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnEventProcessed()
	}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnStart(currentView uint64) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnStart(currentView)
	}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnReceiveProposal(
	currentView uint64,
	proposal *models.SignedProposal[StateT, VoteT],
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnReceiveProposal(currentView, proposal)
	}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnReceiveQuorumCertificate(currentView uint64, qc models.QuorumCertificate) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnReceiveQuorumCertificate(currentView, qc)
	}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnReceiveTimeoutCertificate(
	currentView uint64,
	tc models.TimeoutCertificate,
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnReceiveTimeoutCertificate(currentView, tc)
	}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnPartialTimeoutCertificate(
	currentView uint64,
	partialTc *consensus.PartialTimeoutCertificateCreated,
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnPartialTimeoutCertificate(currentView, partialTc)
	}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnLocalTimeout(currentView uint64) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnLocalTimeout(currentView)
	}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnRankChange(oldView, newView uint64) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnRankChange(oldView, newView)
	}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnQuorumCertificateTriggeredRankChange(
	oldView uint64,
	newView uint64,
	qc models.QuorumCertificate,
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnQuorumCertificateTriggeredRankChange(oldView, newView, qc)
	}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnTimeoutCertificateTriggeredRankChange(
	oldView uint64,
	newView uint64,
	tc models.TimeoutCertificate,
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnTimeoutCertificateTriggeredRankChange(oldView, newView, tc)
	}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnStartingTimeout(start time.Time, end time.Time) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnStartingTimeout(start, end)
	}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnCurrentRankDetails(
	currentView, finalizedView uint64,
	currentLeader models.Identity,
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnCurrentRankDetails(currentView, finalizedView, currentLeader)
	}
}
