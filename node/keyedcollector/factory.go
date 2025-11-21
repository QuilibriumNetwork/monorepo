package keyedcollector

import (
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/keyedaggregator"
)

// ProcessorFactory creates processors for a given sequence.
type ProcessorFactory[RecordT any] interface {
	Create(sequence uint64) (Processor[RecordT], error)
}

// Factory produces collectors for a given sequence, satisfying the
// keyedaggregator.CollectorFactory interface.
type Factory[RecordT any] struct {
	tracer           consensus.TraceLogger
	traits           RecordTraits[RecordT]
	consumer         CollectorConsumer[RecordT]
	processorFactory ProcessorFactory[RecordT]
}

func NewFactory[RecordT any](
	tracer consensus.TraceLogger,
	traits RecordTraits[RecordT],
	consumer CollectorConsumer[RecordT],
	processorFactory ProcessorFactory[RecordT],
) (*Factory[RecordT], error) {
	if err := traits.validate(); err != nil {
		return nil, err
	}
	if processorFactory == nil {
		return nil, fmt.Errorf("processor factory is required")
	}
	return &Factory[RecordT]{
		tracer:           tracer,
		traits:           traits,
		consumer:         consumer,
		processorFactory: processorFactory,
	}, nil
}

func (f *Factory[RecordT]) Create(
	sequence uint64,
) (keyedaggregator.Collector[RecordT], error) {
	processor, err := f.processorFactory.Create(sequence)
	if err != nil {
		return nil, fmt.Errorf("could not create processor for sequence %d: %w", sequence, err)
	}
	return NewCollector(
		f.tracer,
		sequence,
		f.traits,
		processor,
		f.consumer,
	)
}
