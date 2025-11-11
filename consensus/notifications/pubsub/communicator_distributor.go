package pubsub

import (
	"sync"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// CommunicatorDistributor ingests outbound consensus messages from HotStuff's
// core logic and distributes them to consumers. This logic only runs inside
// active consensus participants proposing states, voting, collecting +
// aggregating votes to QCs, and participating in the pacemaker (sending
// timeouts, collecting + aggregating timeouts to TCs).
// Concurrency safe.
type CommunicatorDistributor[StateT models.Unique, VoteT models.Unique] struct {
	consumers []consensus.CommunicatorConsumer[StateT, VoteT]
	lock      sync.RWMutex
}

var _ consensus.CommunicatorConsumer[*nilUnique, *nilUnique] = (*CommunicatorDistributor[*nilUnique, *nilUnique])(nil)

func NewCommunicatorDistributor[
	StateT models.Unique,
	VoteT models.Unique,
]() *CommunicatorDistributor[StateT, VoteT] {
	return &CommunicatorDistributor[StateT, VoteT]{}
}

func (d *CommunicatorDistributor[StateT, VoteT]) AddCommunicatorConsumer(
	consumer consensus.CommunicatorConsumer[StateT, VoteT],
) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.consumers = append(d.consumers, consumer)
}

func (d *CommunicatorDistributor[StateT, VoteT]) OnOwnVote(
	vote *VoteT,
	recipientID models.Identity,
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, s := range d.consumers {
		s.OnOwnVote(vote, recipientID)
	}
}

func (d *CommunicatorDistributor[StateT, VoteT]) OnOwnTimeout(
	timeout *models.TimeoutState[VoteT],
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, s := range d.consumers {
		s.OnOwnTimeout(timeout)
	}
}

func (d *CommunicatorDistributor[StateT, VoteT]) OnOwnProposal(
	proposal *models.SignedProposal[StateT, VoteT],
	targetPublicationTime time.Time,
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, s := range d.consumers {
		s.OnOwnProposal(proposal, targetPublicationTime)
	}
}

// Type used to satisfy generic arguments in compiler time type assertion check
type nilUnique struct{}

// GetSignature implements models.Unique.
func (n *nilUnique) GetSignature() []byte {
	panic("unimplemented")
}

// GetTimestamp implements models.Unique.
func (n *nilUnique) GetTimestamp() uint64 {
	panic("unimplemented")
}

// Source implements models.Unique.
func (n *nilUnique) Source() models.Identity {
	panic("unimplemented")
}

// Clone implements models.Unique.
func (n *nilUnique) Clone() models.Unique {
	panic("unimplemented")
}

// GetRank implements models.Unique.
func (n *nilUnique) GetRank() uint64 {
	panic("unimplemented")
}

// Identity implements models.Unique.
func (n *nilUnique) Identity() models.Identity {
	panic("unimplemented")
}

var _ models.Unique = (*nilUnique)(nil)
