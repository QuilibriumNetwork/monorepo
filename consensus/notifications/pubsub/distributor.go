package pubsub

import (
	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// Distributor distributes notifications to a list of consumers (event
// consumers).
//
// It allows thread-safe subscription of multiple consumers to events.
type Distributor[StateT models.Unique, VoteT models.Unique] struct {
	*FollowerDistributor[StateT, VoteT]
	*CommunicatorDistributor[StateT, VoteT]
	*ParticipantDistributor[StateT, VoteT]
}

var _ consensus.Consumer[*nilUnique, *nilUnique] = (*Distributor[*nilUnique, *nilUnique])(nil)

func NewDistributor[
	StateT models.Unique,
	VoteT models.Unique,
]() *Distributor[StateT, VoteT] {
	return &Distributor[StateT, VoteT]{
		FollowerDistributor:     NewFollowerDistributor[StateT, VoteT](),
		CommunicatorDistributor: NewCommunicatorDistributor[StateT, VoteT](),
		ParticipantDistributor:  NewParticipantDistributor[StateT, VoteT](),
	}
}

// AddConsumer adds an event consumer to the Distributor
func (p *Distributor[StateT, VoteT]) AddConsumer(
	consumer consensus.Consumer[StateT, VoteT],
) {
	p.FollowerDistributor.AddFollowerConsumer(consumer)
	p.CommunicatorDistributor.AddCommunicatorConsumer(consumer)
	p.ParticipantDistributor.AddParticipantConsumer(consumer)
}

// FollowerDistributor ingests consensus follower events and distributes it to
// consumers. It allows thread-safe subscription of multiple consumers to
// events.
type FollowerDistributor[StateT models.Unique, VoteT models.Unique] struct {
	*ProposalViolationDistributor[StateT, VoteT]
	*FinalizationDistributor[StateT]
}

var _ consensus.FollowerConsumer[*nilUnique, *nilUnique] = (*FollowerDistributor[*nilUnique, *nilUnique])(nil)

func NewFollowerDistributor[
	StateT models.Unique,
	VoteT models.Unique,
]() *FollowerDistributor[StateT, VoteT] {
	return &FollowerDistributor[StateT, VoteT]{
		ProposalViolationDistributor: NewProposalViolationDistributor[StateT, VoteT](),
		FinalizationDistributor:      NewFinalizationDistributor[StateT](),
	}
}

// AddFollowerConsumer registers the input `consumer` to be notified on
// `consensus.ConsensusFollowerConsumer` events.
func (d *FollowerDistributor[StateT, VoteT]) AddFollowerConsumer(
	consumer consensus.FollowerConsumer[StateT, VoteT],
) {
	d.FinalizationDistributor.AddFinalizationConsumer(consumer)
	d.ProposalViolationDistributor.AddProposalViolationConsumer(consumer)
}

// TimeoutAggregationDistributor ingests timeout aggregation events and
// distributes it to consumers. It allows thread-safe subscription of multiple
// consumers to events.
type TimeoutAggregationDistributor[VoteT models.Unique] struct {
	*TimeoutAggregationViolationDistributor[VoteT]
	*TimeoutCollectorDistributor[VoteT]
}

var _ consensus.TimeoutAggregationConsumer[*nilUnique] = (*TimeoutAggregationDistributor[*nilUnique])(nil)

func NewTimeoutAggregationDistributor[
	VoteT models.Unique,
]() *TimeoutAggregationDistributor[VoteT] {
	return &TimeoutAggregationDistributor[VoteT]{
		TimeoutAggregationViolationDistributor: NewTimeoutAggregationViolationDistributor[VoteT](),
		TimeoutCollectorDistributor:            NewTimeoutCollectorDistributor[VoteT](),
	}
}

func (d *TimeoutAggregationDistributor[VoteT]) AddTimeoutAggregationConsumer(
	consumer consensus.TimeoutAggregationConsumer[VoteT],
) {
	d.TimeoutAggregationViolationDistributor.
		AddTimeoutAggregationViolationConsumer(consumer)
	d.TimeoutCollectorDistributor.AddTimeoutCollectorConsumer(consumer)
}

// VoteAggregationDistributor ingests vote aggregation events and distributes it
// to consumers. It allows thread-safe subscription of multiple consumers to
// events.
type VoteAggregationDistributor[
	StateT models.Unique,
	VoteT models.Unique,
] struct {
	*VoteAggregationViolationDistributor[StateT, VoteT]
	*VoteCollectorDistributor[VoteT]
}

var _ consensus.VoteAggregationConsumer[*nilUnique, *nilUnique] = (*VoteAggregationDistributor[*nilUnique, *nilUnique])(nil)

func NewVoteAggregationDistributor[
	StateT models.Unique,
	VoteT models.Unique,
]() *VoteAggregationDistributor[StateT, VoteT] {
	return &VoteAggregationDistributor[StateT, VoteT]{
		VoteAggregationViolationDistributor: NewVoteAggregationViolationDistributor[StateT, VoteT](),
		VoteCollectorDistributor:            NewQCCreatedDistributor[VoteT](),
	}
}

func (
	d *VoteAggregationDistributor[StateT, VoteT],
) AddVoteAggregationConsumer(
	consumer consensus.VoteAggregationConsumer[StateT, VoteT],
) {
	d.VoteAggregationViolationDistributor.
		AddVoteAggregationViolationConsumer(consumer)
	d.VoteCollectorDistributor.AddVoteCollectorConsumer(consumer)
}
