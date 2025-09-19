package events

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
)

// Helper function to create a test global event
func createTestGlobalEvent(eventType consensustime.TimeReelEventType, frameNumber uint64) consensustime.GlobalEvent {
	frameHeader := &protobufs.GlobalFrameHeader{
		FrameNumber: frameNumber,
		Timestamp:   time.Now().UnixMilli(),
		Output:      []byte("test-output"),
	}
	frame := &protobufs.GlobalFrame{
		Header: frameHeader,
	}

	event := consensustime.GlobalEvent{
		Type:    eventType,
		Frame:   frame,
		Message: "test message",
	}

	if eventType == consensustime.TimeReelEventForkDetected {
		event.OldHead = &protobufs.GlobalFrame{
			Header: &protobufs.GlobalFrameHeader{
				FrameNumber: frameNumber - 1,
				Timestamp:   time.Now().UnixMilli() - 10000,
				Output:      []byte("old-output"),
			},
		}
	}

	return event
}

// Helper function to create a test app event
func createTestAppEvent(eventType consensustime.TimeReelEventType, frameNumber uint64) consensustime.AppEvent {
	frame := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			FrameNumber: frameNumber,
			Timestamp:   time.Now().UnixMilli(),
			Prover:      []byte("test-prover"),
			Output:      []byte("test-output"),
			Address:     []byte("test-address"),
		},
	}

	event := consensustime.AppEvent{
		Type:    eventType,
		Frame:   frame,
		Message: "test message",
	}

	if eventType == consensustime.TimeReelEventForkDetected {
		event.OldHead = &protobufs.AppShardFrame{
			Header: &protobufs.FrameHeader{
				FrameNumber: frameNumber - 1,
				Timestamp:   time.Now().UnixMilli() - 10000,
				Prover:      []byte("test-prover"),
				Output:      []byte("old-output"),
				Address:     []byte("test-address"),
			},
		}
	}

	return event
}

func TestGlobalEventDistributor_StartStop(t *testing.T) {
	globalEventCh := make(chan consensustime.GlobalEvent, 10)
	distributor := NewGlobalEventDistributor(globalEventCh)

	ctx := context.Background()

	// Test starting
	err := distributor.Start(ctx)
	require.NoError(t, err)

	// Test starting again (should be idempotent)
	err = distributor.Start(ctx)
	require.NoError(t, err)

	// Test stopping
	err = distributor.Stop()
	require.NoError(t, err)

	// Test stopping again (should be idempotent)
	err = distributor.Stop()
	require.NoError(t, err)

	close(globalEventCh)
}

func TestGlobalEventDistributor_Subscribe(t *testing.T) {
	globalEventCh := make(chan consensustime.GlobalEvent, 10)
	distributor := NewGlobalEventDistributor(globalEventCh)

	// Subscribe multiple subscribers
	sub1Ch := distributor.Subscribe("subscriber1")
	sub2Ch := distributor.Subscribe("subscriber2")
	sub3Ch := distributor.Subscribe("subscriber3")

	assert.NotNil(t, sub1Ch)
	assert.NotNil(t, sub2Ch)
	assert.NotNil(t, sub3Ch)

	// Start the distributor
	ctx := context.Background()
	err := distributor.Start(ctx)
	require.NoError(t, err)

	// Send a test event
	testEvent := createTestGlobalEvent(consensustime.TimeReelEventNewHead, 100)
	globalEventCh <- testEvent

	// All subscribers should receive the event
	timeout := time.After(1 * time.Second)
	for i := 0; i < 3; i++ {
		select {
		case event1 := <-sub1Ch:
			assert.Equal(t, consensus.ControlEventGlobalNewHead, event1.Type)
			eventData := event1.Data.(*consensustime.GlobalEvent)
			assert.Equal(t, testEvent, *eventData)
		case event2 := <-sub2Ch:
			assert.Equal(t, consensus.ControlEventGlobalNewHead, event2.Type)
			eventData := event2.Data.(*consensustime.GlobalEvent)
			assert.Equal(t, testEvent, *eventData)
		case event3 := <-sub3Ch:
			assert.Equal(t, consensus.ControlEventGlobalNewHead, event3.Type)
			eventData := event3.Data.(*consensustime.GlobalEvent)
			assert.Equal(t, testEvent, *eventData)
		case <-timeout:
			t.Fatal("Timeout waiting for events")
		}
	}

	// Stop the distributor
	err = distributor.Stop()
	require.NoError(t, err)
	close(globalEventCh)
}

func TestGlobalEventDistributor_Unsubscribe(t *testing.T) {
	globalEventCh := make(chan consensustime.GlobalEvent, 10)
	distributor := NewGlobalEventDistributor(globalEventCh)

	// Subscribe
	sub1Ch := distributor.Subscribe("subscriber1")
	sub2Ch := distributor.Subscribe("subscriber2")

	// Start the distributor
	ctx := context.Background()
	err := distributor.Start(ctx)
	require.NoError(t, err)

	// Unsubscribe subscriber1
	distributor.Unsubscribe("subscriber1")

	// Give a moment for the unsubscribe to take effect
	time.Sleep(10 * time.Millisecond)

	// Send a test event
	testEvent := createTestGlobalEvent(consensustime.TimeReelEventNewHead, 100)
	globalEventCh <- testEvent

	// Only subscriber2 should receive the event
	timeout := time.After(100 * time.Millisecond)
	select {
	case event := <-sub2Ch:
		assert.Equal(t, consensus.ControlEventGlobalNewHead, event.Type)
	case <-timeout:
		t.Fatal("Timeout waiting for event on subscriber2")
	}

	// Verify sub1Ch doesn't receive the event
	select {
	case _, ok := <-sub1Ch:
		if ok {
			t.Fatal("Unsubscribed channel should not receive events")
		}
	case <-time.After(50 * time.Millisecond):
		// Expected - no event received
	}

	// Verify sub1Ch is closed
	_, ok := <-sub1Ch
	assert.False(t, ok, "Unsubscribed channel should be closed")

	// Stop the distributor
	err = distributor.Stop()
	require.NoError(t, err)
	close(globalEventCh)
}

func TestGlobalEventDistributor_EventTypes(t *testing.T) {
	globalEventCh := make(chan consensustime.GlobalEvent, 10)
	distributor := NewGlobalEventDistributor(globalEventCh)

	// Subscribe
	subCh := distributor.Subscribe("test-subscriber")

	// Start the distributor
	ctx := context.Background()
	err := distributor.Start(ctx)
	require.NoError(t, err)

	// Test NewHead event
	newHeadEvent := createTestGlobalEvent(consensustime.TimeReelEventNewHead, 100)
	globalEventCh <- newHeadEvent

	event := <-subCh
	assert.Equal(t, consensus.ControlEventGlobalNewHead, event.Type)
	eventData := event.Data.(*consensustime.GlobalEvent)
	assert.Equal(t, newHeadEvent, *eventData)

	// Test Fork event
	forkEvent := createTestGlobalEvent(consensustime.TimeReelEventForkDetected, 101)
	globalEventCh <- forkEvent

	event = <-subCh
	assert.Equal(t, consensus.ControlEventGlobalFork, event.Type)
	eventData = event.Data.(*consensustime.GlobalEvent)
	assert.Equal(t, forkEvent, *eventData)

	// Test Equivocation event
	equivocationEvent := createTestGlobalEvent(consensustime.TimeReelEventEquivocationDetected, 102)
	globalEventCh <- equivocationEvent

	event = <-subCh
	assert.Equal(t, consensus.ControlEventGlobalEquivocation, event.Type)
	eventData = event.Data.(*consensustime.GlobalEvent)
	assert.Equal(t, equivocationEvent, *eventData)

	// Stop the distributor
	err = distributor.Stop()
	require.NoError(t, err)
	close(globalEventCh)
}

func TestGlobalEventDistributor_ContextCancellation(t *testing.T) {
	globalEventCh := make(chan consensustime.GlobalEvent, 10)
	distributor := NewGlobalEventDistributor(globalEventCh)

	// Create a cancellable context
	ctx, cancel := context.WithCancel(context.Background())

	// Start the distributor
	err := distributor.Start(ctx)
	require.NoError(t, err)

	// Subscribe
	subCh := distributor.Subscribe("test-subscriber")

	// Cancel the context
	cancel()

	// Give some time for the goroutine to exit
	time.Sleep(100 * time.Millisecond)

	// Stop should work gracefully
	err = distributor.Stop()
	require.NoError(t, err)

	// Channel should be closed
	_, ok := <-subCh
	assert.False(t, ok)

	close(globalEventCh)
}

func TestAppEventDistributor_StartStop(t *testing.T) {
	globalEventCh := make(chan consensustime.GlobalEvent, 10)
	appEventCh := make(chan consensustime.AppEvent, 10)
	distributor := NewAppEventDistributor(globalEventCh, appEventCh)

	ctx := context.Background()

	// Test starting
	err := distributor.Start(ctx)
	require.NoError(t, err)

	// Test starting again (should be idempotent)
	err = distributor.Start(ctx)
	require.NoError(t, err)

	// Test stopping
	err = distributor.Stop()
	require.NoError(t, err)

	// Test stopping again (should be idempotent)
	err = distributor.Stop()
	require.NoError(t, err)

	close(globalEventCh)
	close(appEventCh)
}

func TestAppEventDistributor_GlobalAndAppEvents(t *testing.T) {
	globalEventCh := make(chan consensustime.GlobalEvent, 10)
	appEventCh := make(chan consensustime.AppEvent, 10)
	distributor := NewAppEventDistributor(globalEventCh, appEventCh)

	// Subscribe
	subCh := distributor.Subscribe("test-subscriber")

	// Start the distributor
	ctx := context.Background()
	err := distributor.Start(ctx)
	require.NoError(t, err)

	// Test Global event
	globalEvent := createTestGlobalEvent(consensustime.TimeReelEventNewHead, 100)
	globalEventCh <- globalEvent

	event := <-subCh
	assert.Equal(t, consensus.ControlEventGlobalNewHead, event.Type)
	globalEventData := event.Data.(*consensustime.GlobalEvent)
	assert.Equal(t, globalEvent, *globalEventData)

	// Test App event
	appEvent := createTestAppEvent(consensustime.TimeReelEventNewHead, 200)
	appEventCh <- appEvent

	event = <-subCh
	assert.Equal(t, consensus.ControlEventAppNewHead, event.Type)
	appEventData := event.Data.(*consensustime.AppEvent)
	assert.Equal(t, appEvent, *appEventData)

	// Stop the distributor
	err = distributor.Stop()
	require.NoError(t, err)
	close(globalEventCh)
	close(appEventCh)
}

func TestAppEventDistributor_AllEventTypes(t *testing.T) {
	globalEventCh := make(chan consensustime.GlobalEvent, 10)
	appEventCh := make(chan consensustime.AppEvent, 10)
	distributor := NewAppEventDistributor(globalEventCh, appEventCh)

	// Subscribe
	subCh := distributor.Subscribe("test-subscriber")

	// Start the distributor
	ctx := context.Background()
	err := distributor.Start(ctx)
	require.NoError(t, err)

	// Test all global event types
	globalNewHead := createTestGlobalEvent(consensustime.TimeReelEventNewHead, 100)
	globalEventCh <- globalNewHead
	event := <-subCh
	assert.Equal(t, consensus.ControlEventGlobalNewHead, event.Type)

	globalFork := createTestGlobalEvent(consensustime.TimeReelEventForkDetected, 101)
	globalEventCh <- globalFork
	event = <-subCh
	assert.Equal(t, consensus.ControlEventGlobalFork, event.Type)

	globalEquivocation := createTestGlobalEvent(consensustime.TimeReelEventEquivocationDetected, 102)
	globalEventCh <- globalEquivocation
	event = <-subCh
	assert.Equal(t, consensus.ControlEventGlobalEquivocation, event.Type)

	// Test all app event types
	appNewHead := createTestAppEvent(consensustime.TimeReelEventNewHead, 200)
	appEventCh <- appNewHead
	event = <-subCh
	assert.Equal(t, consensus.ControlEventAppNewHead, event.Type)

	appFork := createTestAppEvent(consensustime.TimeReelEventForkDetected, 201)
	appEventCh <- appFork
	event = <-subCh
	assert.Equal(t, consensus.ControlEventAppFork, event.Type)

	appEquivocation := createTestAppEvent(consensustime.TimeReelEventEquivocationDetected, 202)
	appEventCh <- appEquivocation
	event = <-subCh
	assert.Equal(t, consensus.ControlEventAppEquivocation, event.Type)

	// Stop the distributor
	err = distributor.Stop()
	require.NoError(t, err)
	close(globalEventCh)
	close(appEventCh)
}

func TestAppEventDistributor_MultipleSubscribers(t *testing.T) {
	globalEventCh := make(chan consensustime.GlobalEvent, 10)
	appEventCh := make(chan consensustime.AppEvent, 10)
	distributor := NewAppEventDistributor(globalEventCh, appEventCh)

	// Subscribe multiple subscribers
	sub1Ch := distributor.Subscribe("subscriber1")
	sub2Ch := distributor.Subscribe("subscriber2")

	// Start the distributor
	ctx := context.Background()
	err := distributor.Start(ctx)
	require.NoError(t, err)

	// Send events
	globalEvent := createTestGlobalEvent(consensustime.TimeReelEventNewHead, 100)
	appEvent := createTestAppEvent(consensustime.TimeReelEventNewHead, 200)

	globalEventCh <- globalEvent
	appEventCh <- appEvent

	// Both subscribers should receive both events
	receivedGlobal := 0
	receivedApp := 0
	timeout := time.After(1 * time.Second)

	for receivedGlobal < 2 || receivedApp < 2 {
		select {
		case event := <-sub1Ch:
			if event.Type == consensus.ControlEventGlobalNewHead {
				receivedGlobal++
			} else if event.Type == consensus.ControlEventAppNewHead {
				receivedApp++
			}
		case event := <-sub2Ch:
			if event.Type == consensus.ControlEventGlobalNewHead {
				receivedGlobal++
			} else if event.Type == consensus.ControlEventAppNewHead {
				receivedApp++
			}
		case <-timeout:
			t.Fatal("Timeout waiting for events")
		}
	}

	assert.Equal(t, 2, receivedGlobal)
	assert.Equal(t, 2, receivedApp)

	// Stop the distributor
	err = distributor.Stop()
	require.NoError(t, err)
	close(globalEventCh)
	close(appEventCh)
}

func TestAppEventDistributor_ChannelClosure(t *testing.T) {
	globalEventCh := make(chan consensustime.GlobalEvent, 10)
	appEventCh := make(chan consensustime.AppEvent, 10)
	distributor := NewAppEventDistributor(globalEventCh, appEventCh)

	// Subscribe
	subCh := distributor.Subscribe("test-subscriber")

	// Start the distributor
	ctx := context.Background()
	err := distributor.Start(ctx)
	require.NoError(t, err)

	// Close the input channels
	close(globalEventCh)

	// Give some time for the goroutine to exit
	time.Sleep(100 * time.Millisecond)

	// Stop should work gracefully
	err = distributor.Stop()
	require.NoError(t, err)

	// Subscriber channel should be closed
	_, ok := <-subCh
	assert.False(t, ok)

	close(appEventCh)
}

func TestControlEventDataTypes(t *testing.T) {
	// Test that all event data types implement the interface
	var _ consensus.ControlEventData = StartEventData{}
	var _ consensus.ControlEventData = StopEventData{}
	var _ consensus.ControlEventData = HaltEventData{}
	var _ consensus.ControlEventData = ResumeEventData{}
	var _ consensus.ControlEventData = &consensustime.GlobalEvent{}
	var _ consensus.ControlEventData = &consensustime.AppEvent{}
}

func TestConcurrentSubscribeUnsubscribe(t *testing.T) {
	globalEventCh := make(chan consensustime.GlobalEvent, 10)
	distributor := NewGlobalEventDistributor(globalEventCh)

	ctx := context.Background()
	err := distributor.Start(ctx)
	require.NoError(t, err)

	// Concurrently subscribe and unsubscribe
	done := make(chan bool)

	// Subscriber goroutines
	for i := 0; i < 10; i++ {
		go func(id int) {
			subID := fmt.Sprintf("subscriber%d", id)
			ch := distributor.Subscribe(subID)

			// Wait for an event
			select {
			case <-ch:
			case <-time.After(100 * time.Millisecond):
			}

			distributor.Unsubscribe(subID)
			done <- true
		}(i)
	}

	// Send events while subscribing/unsubscribing
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			event := createTestGlobalEvent(consensustime.TimeReelEventNewHead, uint64(i))
			globalEventCh <- event
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Stop the distributor
	err = distributor.Stop()
	require.NoError(t, err)
	wg.Wait()

	close(globalEventCh)
}

// Benchmark tests
func BenchmarkGlobalEventDistributor_Broadcast(b *testing.B) {
	globalEventCh := make(chan consensustime.GlobalEvent, 1000)
	distributor := NewGlobalEventDistributor(globalEventCh)

	// Subscribe 100 subscribers with consumers
	var wg sync.WaitGroup
	done := make(chan struct{})

	for i := 0; i < 100; i++ {
		ch := distributor.Subscribe(fmt.Sprintf("subscriber%d", i))
		wg.Add(1)
		go func(subCh <-chan consensus.ControlEvent) {
			defer wg.Done()
			for {
				select {
				case <-subCh:
				case <-done:
					return
				}
			}
		}(ch)
	}

	ctx := context.Background()
	err := distributor.Start(ctx)
	require.NoError(b, err)

	b.ResetTimer()

	// Send b.N events
	for i := 0; i < b.N; i++ {
		event := createTestGlobalEvent(consensustime.TimeReelEventNewHead, uint64(i))
		globalEventCh <- event
	}

	// Wait a bit for events to be processed
	time.Sleep(100 * time.Millisecond)

	b.StopTimer()

	// Signal consumers to stop
	close(done)

	err = distributor.Stop()
	require.NoError(b, err)
	close(globalEventCh)

	// Wait for all consumers to finish
	wg.Wait()
}

func BenchmarkAppEventDistributor_MixedEvents(b *testing.B) {
	globalEventCh := make(chan consensustime.GlobalEvent, 1000)
	appEventCh := make(chan consensustime.AppEvent, 1000)
	distributor := NewAppEventDistributor(globalEventCh, appEventCh)

	// Subscribe 100 subscribers with consumers
	var wg sync.WaitGroup
	done := make(chan struct{})

	for i := 0; i < 100; i++ {
		ch := distributor.Subscribe(fmt.Sprintf("subscriber%d", i))
		wg.Add(1)
		go func(subCh <-chan consensus.ControlEvent) {
			defer wg.Done()
			for {
				select {
				case <-subCh:
				case <-done:
					return
				}
			}
		}(ch)
	}

	ctx := context.Background()
	err := distributor.Start(ctx)
	require.NoError(b, err)

	b.ResetTimer()

	// Send b.N/2 events of each type
	for i := 0; i < b.N/2; i++ {
		globalEvent := createTestGlobalEvent(consensustime.TimeReelEventNewHead, uint64(i))
		appEvent := createTestAppEvent(consensustime.TimeReelEventNewHead, uint64(i))
		globalEventCh <- globalEvent
		appEventCh <- appEvent
	}

	// Wait a bit for events to be processed
	time.Sleep(100 * time.Millisecond)

	b.StopTimer()

	// Signal consumers to stop
	close(done)

	err = distributor.Stop()
	require.NoError(b, err)
	close(globalEventCh)
	close(appEventCh)

	// Wait for all consumers to finish
	wg.Wait()
}
