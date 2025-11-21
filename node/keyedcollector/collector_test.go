package keyedcollector

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/node/keyedaggregator"
)

type fakeRecord struct {
	sequence uint64
	identity models.Identity
	payload  string
}

func recordTraits() RecordTraits[fakeRecord] {
	return RecordTraits[fakeRecord]{
		Sequence: func(r *fakeRecord) uint64 { return r.sequence },
		Identity: func(r *fakeRecord) models.Identity { return r.identity },
		Equals: func(a, b *fakeRecord) bool {
			if a == nil || b == nil {
				return a == b
			}
			return a.payload == b.payload
		},
	}
}

type noopProcessor struct {
	mu      sync.Mutex
	records []*fakeRecord
	err     error
}

func (p *noopProcessor) Process(record *fakeRecord) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.records = append(p.records, record)
	return p.err
}

type capturingConsumer struct {
	mu        sync.Mutex
	processed []*fakeRecord
	conflicts [][2]*fakeRecord
	invalid   []*InvalidRecordError[fakeRecord]
}

func (c *capturingConsumer) OnRecordProcessed(record *fakeRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.processed = append(c.processed, record)
}

func (c *capturingConsumer) OnConflictingRecords(first, second *fakeRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conflicts = append(c.conflicts, [2]*fakeRecord{first, second})
}

func (c *capturingConsumer) OnInvalidRecord(err *InvalidRecordError[fakeRecord]) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invalid = append(c.invalid, err)
}

type noopTracer struct{}

func (noopTracer) Trace(string, ...consensus.LogParam)              {}
func (noopTracer) Error(string, error, ...consensus.LogParam)       {}
func (noopTracer) With(...consensus.LogParam) consensus.TraceLogger { return noopTracer{} }

func TestCollectorProcessesRecord(t *testing.T) {
	t.Parallel()
	processor := &noopProcessor{}
	consumer := &capturingConsumer{}
	collector, err := NewCollector[fakeRecord](
		noopTracer{},
		1,
		recordTraits(),
		processor,
		consumer,
	)
	require.NoError(t, err)

	record := &fakeRecord{sequence: 1, identity: "id", payload: "a"}
	require.NoError(t, collector.Add(record))

	require.Len(t, consumer.processed, 1)
	require.Equal(t, record, consumer.processed[0])
	require.Len(t, processor.records, 1)
	require.Equal(t, record, processor.records[0])
}

func TestCollectorIgnoresDuplicates(t *testing.T) {
	t.Parallel()
	processor := &noopProcessor{}
	collector, err := NewCollector[fakeRecord](
		noopTracer{},
		1,
		recordTraits(),
		processor,
		nil,
	)
	require.NoError(t, err)

	record := &fakeRecord{sequence: 1, identity: "id", payload: "a"}
	require.NoError(t, collector.Add(record))
	require.NoError(t, collector.Add(&fakeRecord{sequence: 1, identity: "id", payload: "a"}))
	require.Len(t, processor.records, 1)
}

func TestCollectorNotifiesConflicts(t *testing.T) {
	t.Parallel()
	processor := &noopProcessor{}
	consumer := &capturingConsumer{}
	collector, err := NewCollector[fakeRecord](
		noopTracer{},
		1,
		recordTraits(),
		processor,
		consumer,
	)
	require.NoError(t, err)

	require.NoError(t, collector.Add(&fakeRecord{sequence: 1, identity: "id", payload: "a"}))
	require.NoError(t, collector.Add(&fakeRecord{sequence: 1, identity: "id", payload: "b"}))

	require.Len(t, consumer.conflicts, 1)
	require.Equal(t, "a", consumer.conflicts[0][0].payload)
	require.Equal(t, "b", consumer.conflicts[0][1].payload)
	require.Len(t, processor.records, 1)
}

func TestCollectorHandlesInvalidRecords(t *testing.T) {
	t.Parallel()
	invalid := NewInvalidRecordError(&fakeRecord{sequence: 1}, errors.New("boom"))
	processor := &noopProcessor{err: invalid}
	consumer := &capturingConsumer{}
	collector, err := NewCollector[fakeRecord](
		noopTracer{},
		1,
		recordTraits(),
		processor,
		consumer,
	)
	require.NoError(t, err)

	require.NoError(t, collector.Add(&fakeRecord{sequence: 1, identity: "id"}))
	require.Len(t, consumer.invalid, 1)
}

func TestCollectorPropagatesProcessorErrors(t *testing.T) {
	t.Parallel()
	processor := &noopProcessor{err: errors.New("fatal")}
	collector, err := NewCollector[fakeRecord](
		noopTracer{},
		1,
		recordTraits(),
		processor,
		nil,
	)
	require.NoError(t, err)

	err = collector.Add(&fakeRecord{sequence: 1, identity: "id"})
	require.Error(t, err)
	require.ErrorContains(t, err, "processing record failed")
}

func TestCollectorRejectsIncompatibleSequence(t *testing.T) {
	t.Parallel()
	processor := &noopProcessor{}
	collector, err := NewCollector[fakeRecord](
		noopTracer{},
		2,
		recordTraits(),
		processor,
		nil,
	)
	require.NoError(t, err)

	err = collector.Add(&fakeRecord{sequence: 1, identity: "id"})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrRecordForDifferentSequence)
}

type mockProcessorFactory struct {
	mu        sync.Mutex
	sequences []uint64
	processor Processor[fakeRecord]
	err       error
}

func (f *mockProcessorFactory) Create(sequence uint64) (Processor[fakeRecord], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.sequences = append(f.sequences, sequence)
	if f.processor != nil {
		return f.processor, nil
	}
	return &noopProcessor{}, nil
}

func TestFactoryCreatesCollector(t *testing.T) {
	t.Parallel()
	processorFactory := &mockProcessorFactory{}
	factory, err := NewFactory[fakeRecord](
		noopTracer{},
		recordTraits(),
		nil,
		processorFactory,
	)
	require.NoError(t, err)

	collectorIface, err := factory.Create(3)
	require.NoError(t, err)
	require.NotNil(t, collectorIface)
	require.Len(t, processorFactory.sequences, 1)
	require.Equal(t, uint64(3), processorFactory.sequences[0])
}

func TestFactorySatisfiesKeyedAggregatorInterface(t *testing.T) {
	t.Parallel()
	processorFactory := &mockProcessorFactory{}
	factory, err := NewFactory[fakeRecord](
		noopTracer{},
		recordTraits(),
		nil,
		processorFactory,
	)
	require.NoError(t, err)

	collectors := keyedaggregator.NewSequencedCollectors[fakeRecord](
		noopTracer{},
		0,
		factory,
	)
	aggregator, err := keyedaggregator.NewSequencedAggregator(
		noopTracer{},
		0,
		collectors,
		func(r *fakeRecord) uint64 { return r.sequence },
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signalCtx, _ := lifecycle.WithSignaler(ctx)
	require.NoError(t, aggregator.ComponentManager.Start(signalCtx))
	<-aggregator.ComponentManager.Ready()

	record := &fakeRecord{sequence: 0, identity: "id"}
	aggregator.Add(record)

	require.Eventually(t, func() bool {
		return len(processorFactory.sequences) == 1
	}, time.Second, 10*time.Millisecond)

	cancel()
	<-aggregator.ComponentManager.Done()
}
