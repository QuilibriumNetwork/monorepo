package pubsub

import (
	"sync"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

type OnStateFinalizedConsumer[StateT models.Unique] = func(
	state *models.State[StateT],
)

type OnStateIncorporatedConsumer[StateT models.Unique] = func(
	state *models.State[StateT],
)

// FinalizationDistributor ingests events from HotStuff's logic for tracking
// forks + finalization and distributes them to consumers. This logic generally
// runs inside all nodes (irrespectively whether they are active consensus
// participants or or only consensus followers). Concurrency safe.
type FinalizationDistributor[StateT models.Unique] struct {
	stateFinalizedConsumers    []OnStateFinalizedConsumer[StateT]
	stateIncorporatedConsumers []OnStateIncorporatedConsumer[StateT]
	consumers                  []consensus.FinalizationConsumer[StateT]
	lock                       sync.RWMutex
}

var _ consensus.FinalizationConsumer[*nilUnique] = (*FinalizationDistributor[*nilUnique])(nil)

func NewFinalizationDistributor[StateT models.Unique]() *FinalizationDistributor[StateT] {
	return &FinalizationDistributor[StateT]{}
}

func (d *FinalizationDistributor[StateT]) AddOnStateFinalizedConsumer(
	consumer OnStateFinalizedConsumer[StateT],
) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.stateFinalizedConsumers = append(d.stateFinalizedConsumers, consumer)
}

func (d *FinalizationDistributor[StateT]) AddOnStateIncorporatedConsumer(
	consumer OnStateIncorporatedConsumer[StateT],
) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.stateIncorporatedConsumers = append(d.stateIncorporatedConsumers, consumer)
}

func (d *FinalizationDistributor[StateT]) AddFinalizationConsumer(
	consumer consensus.FinalizationConsumer[StateT],
) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.consumers = append(d.consumers, consumer)
}

func (d *FinalizationDistributor[StateT]) OnStateIncorporated(
	state *models.State[StateT],
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, consumer := range d.stateIncorporatedConsumers {
		consumer(state)
	}
	for _, consumer := range d.consumers {
		consumer.OnStateIncorporated(state)
	}
}

func (d *FinalizationDistributor[StateT]) OnFinalizedState(
	state *models.State[StateT],
) {
	d.lock.RLock()
	defer d.lock.RUnlock()
	for _, consumer := range d.stateFinalizedConsumers {
		consumer(state)
	}
	for _, consumer := range d.consumers {
		consumer.OnFinalizedState(state)
	}
}
