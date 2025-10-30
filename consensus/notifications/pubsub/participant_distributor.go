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
) OnStart(currentRank uint64) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnStart(currentRank)
	}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnReceiveProposal(
	currentRank uint64,
	proposal *models.SignedProposal[StateT, VoteT],
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnReceiveProposal(currentRank, proposal)
	}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnReceiveQuorumCertificate(currentRank uint64, qc models.QuorumCertificate) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnReceiveQuorumCertificate(currentRank, qc)
	}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnReceiveTimeoutCertificate(
	currentRank uint64,
	tc models.TimeoutCertificate,
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnReceiveTimeoutCertificate(currentRank, tc)
	}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnPartialTimeoutCertificate(
	currentRank uint64,
	partialTimeoutCertificate *consensus.PartialTimeoutCertificateCreated,
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnPartialTimeoutCertificate(currentRank, partialTimeoutCertificate)
	}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnLocalTimeout(currentRank uint64) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnLocalTimeout(currentRank)
	}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnRankChange(oldRank, newRank uint64) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnRankChange(oldRank, newRank)
	}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnQuorumCertificateTriggeredRankChange(
	oldRank uint64,
	newRank uint64,
	qc models.QuorumCertificate,
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnQuorumCertificateTriggeredRankChange(oldRank, newRank, qc)
	}
}

func (
	d *ParticipantDistributor[StateT, VoteT],
) OnTimeoutCertificateTriggeredRankChange(
	oldRank uint64,
	newRank uint64,
	tc models.TimeoutCertificate,
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnTimeoutCertificateTriggeredRankChange(oldRank, newRank, tc)
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
	currentRank, finalizedRank uint64,
	currentLeader models.Identity,
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, subscriber := range d.consumers {
		subscriber.OnCurrentRankDetails(currentRank, finalizedRank, currentLeader)
	}
}
