package keyedcollector

import (
	"errors"
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
)

// Processor handles validated records. Implementations are expected to be
// concurrency-safe.
type Processor[RecordT any] interface {
	Process(record *RecordT) error
}

// CollectorConsumer receives notifications about collector events, such as
// conflicting records or invalid records detected by the Processor.
type CollectorConsumer[RecordT any] interface {
	OnRecordProcessed(record *RecordT)
	OnConflictingRecords(first, second *RecordT)
	OnInvalidRecord(err *InvalidRecordError[RecordT])
}

// Collector implements the record caching/deduplication flow for a single
// sequence. It stores the first record per identity, detects equivocations, and
// delegates valid records to the configured Processor.
type Collector[RecordT any] struct {
	tracer    consensus.TraceLogger
	cache     *RecordCache[RecordT]
	processor Processor[RecordT]
	consumer  CollectorConsumer[RecordT]
	traits    RecordTraits[RecordT]
}

func NewCollector[RecordT any](
	tracer consensus.TraceLogger,
	sequence uint64,
	traits RecordTraits[RecordT],
	processor Processor[RecordT],
	consumer CollectorConsumer[RecordT],
) (*Collector[RecordT], error) {
	if err := traits.validate(); err != nil {
		return nil, err
	}
	if processor == nil {
		return nil, fmt.Errorf("processor is required")
	}
	cache := NewRecordCache(sequence, traits)
	return &Collector[RecordT]{
		tracer:    tracer,
		cache:     cache,
		processor: processor,
		consumer:  consumer,
		traits:    traits,
	}, nil
}

func (c *Collector[RecordT]) Sequence() uint64 {
	return c.cache.Sequence()
}

// Add inserts the record into the cache and triggers processing. Duplicate
// records are ignored, conflicting records are surfaced to the consumer, and
// invalid records (as indicated by the Processor) are reported via
// CollectorConsumer.OnInvalidRecord.
func (c *Collector[RecordT]) Add(record *RecordT) error {
	err := c.cache.Add(record)
	if err != nil {
		switch {
		case errors.Is(err, ErrRepeatedRecord):
			return nil
		case errors.Is(err, ErrRecordForDifferentSequence):
			return fmt.Errorf("record sequence mismatch: %w", err)
		default:
			var conflict *ConflictingRecordError[RecordT]
			if errors.As(err, &conflict) {
				if c.consumer != nil {
					c.consumer.OnConflictingRecords(conflict.First(), conflict.Second())
				}
				return nil
			}
			return fmt.Errorf("adding record to cache failed: %w", err)
		}
	}

	if err := c.processor.Process(record); err != nil {
		if invalid, ok := AsInvalidRecordError[RecordT](err); ok {
			c.tracer.Error("invalid record detected", err)
			if c.consumer != nil {
				c.consumer.OnInvalidRecord(invalid)
			}
			return nil
		}
		return fmt.Errorf("processing record failed: %w", err)
	}

	if c.consumer != nil {
		c.consumer.OnRecordProcessed(record)
	}
	return nil
}

// Records returns a snapshot of all cached records.
func (c *Collector[RecordT]) Records() []*RecordT {
	return c.cache.All()
}

// Remove deletes the provided record from the cache.
func (c *Collector[RecordT]) Remove(record *RecordT) {
	c.cache.Remove(record)
}
