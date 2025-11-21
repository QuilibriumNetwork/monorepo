package keyedaggregator

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
)

type testItem struct {
	sequence uint64
	value    string
}

type stubCollector struct {
	mu    sync.Mutex
	items []*testItem
}

func (c *stubCollector) Add(item *testItem) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = append(c.items, item)
	return nil
}

func (c *stubCollector) Records() []*testItem {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*testItem, len(c.items))
	copy(out, c.items)
	return out
}

func (c *stubCollector) Remove(item *testItem) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, existing := range c.items {
		if existing == item {
			c.items = append(c.items[:i], c.items[i+1:]...)
			break
		}
	}
}

type trackingFactory struct {
	mu         sync.Mutex
	collectors map[uint64]*stubCollector
}

func newTrackingFactory() *trackingFactory {
	return &trackingFactory{
		collectors: make(map[uint64]*stubCollector),
	}
}

func (f *trackingFactory) Create(
	sequence uint64,
) (Collector[testItem], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	collector := &stubCollector{}
	f.collectors[sequence] = collector
	return collector, nil
}

func (f *trackingFactory) collector(sequence uint64) *stubCollector {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.collectors[sequence]
}

type noopTracer struct{}

func (noopTracer) Trace(string, ...consensus.LogParam)              {}
func (noopTracer) Error(string, error, ...consensus.LogParam)       {}
func (noopTracer) With(...consensus.LogParam) consensus.TraceLogger { return noopTracer{} }

func startTestAggregator(
	t *testing.T,
	aggregator *SequencedAggregator[testItem],
) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	signalCtx, _ := lifecycle.WithSignaler(ctx)
	require.NoError(t, aggregator.ComponentManager.Start(signalCtx))
	<-aggregator.ComponentManager.Ready()
	return func() {
		cancel()
		<-aggregator.ComponentManager.Done()
	}
}

func TestSequencedAggregatorDispatchesItems(t *testing.T) {
	t.Parallel()
	factory := newTrackingFactory()
	collectors := NewSequencedCollectors[testItem](noopTracer{}, 0, factory)
	aggregator, err := NewSequencedAggregator[testItem](
		noopTracer{},
		0,
		collectors,
		func(item *testItem) uint64 { return item.sequence },
	)
	require.NoError(t, err)
	stop := startTestAggregator(t, aggregator)
	defer stop()

	expected := &testItem{sequence: 2, value: "payload"}
	aggregator.Add(expected)

	require.Eventually(t, func() bool {
		c := factory.collector(2)
		if c == nil {
			return false
		}
		items := c.Records()
		return len(items) == 1 && items[0] == expected
	}, time.Second, 10*time.Millisecond)
}

func TestSequencedAggregatorDropsStaleItems(t *testing.T) {
	t.Parallel()
	factory := newTrackingFactory()
	collectors := NewSequencedCollectors[testItem](noopTracer{}, 5, factory)
	aggregator, err := NewSequencedAggregator[testItem](
		noopTracer{},
		5,
		collectors,
		func(item *testItem) uint64 { return item.sequence },
	)
	require.NoError(t, err)
	stop := startTestAggregator(t, aggregator)
	defer stop()

	aggregator.Add(&testItem{sequence: 2})

	// Item is dropped before it ever enters the queue, so no collector
	// should have been created for the stale sequence.
	time.Sleep(50 * time.Millisecond)
	require.Nil(t, factory.collector(2))
}

func TestSequencedAggregatorPrunesCollectorsOnSequenceChange(t *testing.T) {
	t.Parallel()
	factory := newTrackingFactory()
	collectors := NewSequencedCollectors[testItem](noopTracer{}, 0, factory)
	aggregator, err := NewSequencedAggregator[testItem](
		noopTracer{},
		0,
		collectors,
		func(item *testItem) uint64 { return item.sequence },
	)
	require.NoError(t, err)
	stop := startTestAggregator(t, aggregator)
	defer stop()

	aggregator.Add(&testItem{sequence: 1})
	require.Eventually(t, func() bool {
		_, found, err := collectors.getCollector(1)
		return err == nil && found
	}, time.Second, 10*time.Millisecond)

	aggregator.OnSequenceChange(0, 3)
	require.Eventually(t, func() bool {
		_, _, err := collectors.getCollector(1)
		return errors.Is(err, ErrSequenceBelowRetention)
	}, time.Second, 10*time.Millisecond)
}

func TestSequencedCollectorsGetOrCreateReusesInstances(t *testing.T) {
	t.Parallel()
	collectors := NewSequencedCollectors[testItem](noopTracer{}, 0, newTrackingFactory())

	first, created, err := collectors.GetOrCreateCollector(4)
	require.NoError(t, err)
	require.True(t, created)

	second, created, err := collectors.GetOrCreateCollector(4)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, first, second)
}

func TestSequencedCollectorsPruneRemovesOldSequences(t *testing.T) {
	t.Parallel()
	collectors := NewSequencedCollectors[testItem](noopTracer{}, 0, newTrackingFactory())

	_, _, err := collectors.GetOrCreateCollector(2)
	require.NoError(t, err)

	collectors.PruneUpToSequence(5)

	_, _, err = collectors.GetOrCreateCollector(2)
	require.ErrorIs(t, err, ErrSequenceBelowRetention)
}
