package time

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

func setupTestClockStore(t *testing.T) *store.PebbleClockStore {
	logger, _ := zap.NewDevelopment()
	tempDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/store"}, 0)
	return store.NewPebbleClockStore(tempDB, logger)
}

func TestGlobalTimeReel_BasicOperations(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	s := setupTestClockStore(t)
	atr, err := NewGlobalTimeReel(logger, createTestProverRegistry(true), s, 99, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()

	// Test inserting genesis frame
	genesis := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("global_genesis_output"),
			ParentSelector: []byte{}, // Empty for genesis
		},
	}

	err = atr.Insert(ctx, genesis)
	assert.NoError(t, err)

	// Check that genesis became head
	head, err := atr.GetHead()
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), head.Header.FrameNumber)

	assertLatestNumOutput(t, s, 0, genesis.Header.Output)
	assertStoreNumOutput(t, s, 0, genesis.Header.Output)

	// Test inserting next frame
	frame1 := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("global_frame1_output"),
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
		},
	}

	err = atr.Insert(ctx, frame1)
	assert.NoError(t, err)

	// Check new head
	head, err = atr.GetHead()
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), head.Header.FrameNumber)
	assertLatestNumOutput(t, s, 1, frame1.Header.Output)
	assertStoreNumOutput(t, s, 1, frame1.Header.Output)

	// Test retrieving frames by frame number
	framesAtZero, err := atr.GetFramesByNumber(0)
	assert.NoError(t, err)
	assert.Len(t, framesAtZero, 1)
	assert.Equal(t, genesis.Header.FrameNumber, framesAtZero[0].Header.FrameNumber)

	framesAtOne, err := atr.GetFramesByNumber(1)
	assert.NoError(t, err)
	assert.Len(t, framesAtOne, 1)
	assert.Equal(t, frame1.Header.FrameNumber, framesAtOne[0].Header.FrameNumber)

	// Test lineage (head lineage)
	lineage, err := atr.GetLineage()
	assert.NoError(t, err)
	assert.Len(t, lineage, 2)
	assert.Equal(t, uint64(0), lineage[0].Header.FrameNumber)
	assert.Equal(t, uint64(1), lineage[1].Header.FrameNumber)

	// Test child frames - we need to get the frameID of genesis first
	genesisID := atr.ComputeFrameID(genesis)
	children, err := atr.GetChildFrames(genesisID)
	assert.NoError(t, err)
	assert.Len(t, children, 1)
	assert.Equal(t, uint64(1), children[0].Header.FrameNumber)
}

func TestGlobalTimeReel_Equivocation(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	s := setupTestClockStore(t)
	atr, err := NewGlobalTimeReel(logger, createTestProverRegistry(true), s, 99, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()

	// Subscribe to events
	eventCh := atr.GetEventCh()

	// Drain any existing events
	select {
	case <-eventCh:
	default:
	}

	// Insert genesis
	genesis := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis_output"),
			ParentSelector: []byte{},
		},
	}

	err = atr.Insert(ctx, genesis)
	assert.NoError(t, err)

	// Drain any events
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Insert valid frame 1 with BLS signature
	frame1 := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1_output"),
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00001111}, // First 4 signers
			},
		},
	}

	err = atr.Insert(ctx, frame1)
	assert.NoError(t, err)

	// Drain any events
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	assertLatestNumOutput(t, s, 1, frame1.Header.Output)
	assertStoreNumOutput(t, s, 1, frame1.Header.Output)

	// Try to insert equivocating frame 1 with overlapping bitmask
	frame1Equivocation := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("different_output"), // Different output
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00000011}, // First 2 signers - overlaps with frame1
			},
		},
	}

	err = atr.Insert(ctx, frame1Equivocation)
	assert.NoError(t, err)

	// Give the goroutine time to send the event
	time.Sleep(50 * time.Millisecond)

	// Check for equivocation event
	select {
	case event := <-eventCh:
		t.Logf("Received event: Type=%d, Message=%s", event.Type, event.Message)
		assert.Equal(t, TimeReelEventEquivocationDetected, event.Type)
		assert.Contains(t, event.Message, "equivocation at frame 1")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for equivocation event")
	}

	assertLatestNumOutput(t, s, 1, frame1.Header.Output)
}

func TestGlobalTimeReel_Fork(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	s := setupTestClockStore(t)
	atr, err := NewGlobalTimeReel(logger, createTestProverRegistry(true), s, 99, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()

	// Insert genesis
	genesis := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis_output"),
			ParentSelector: []byte{},
		},
	}

	err = atr.Insert(ctx, genesis)
	assert.NoError(t, err)

	// Insert valid frame 1 with BLS signature
	frame1 := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1_output"),
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00001111}, // First 4 signers
			},
		},
	}

	err = atr.Insert(ctx, frame1)
	assert.NoError(t, err)
	assertLatestNumOutput(t, s, 1, frame1.Header.Output)
	assertStoreNumOutput(t, s, 1, frame1.Header.Output)

	// Try to insert forking frame 1 with non-overlapping bitmask (different signers)
	frame1Fork := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("fork_output"), // Different output
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11110000}, // Different signers - no overlap
			},
		},
	}

	// This should succeed - it's a fork, not equivocation
	err = atr.Insert(ctx, frame1Fork)
	assert.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	head, err := atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, frame1.Header.Output, head.Header.Output)
	assertLatestNumOutput(t, s, 1, frame1.Header.Output)
	assertStoreNumOutput(t, s, 1, frame1.Header.Output)
}

func TestGlobalTimeReel_ParentValidation(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	s := setupTestClockStore(t)
	atr, err := NewGlobalTimeReel(logger, createTestProverRegistry(true), s, 99, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()

	// Insert genesis
	genesis := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis_output"),
			ParentSelector: []byte{},
		},
	}

	err = atr.Insert(ctx, genesis)
	assert.NoError(t, err)

	// Insert valid frame 1
	frame1 := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1_output"),
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
		},
	}

	err = atr.Insert(ctx, frame1)
	assert.NoError(t, err)
	assertLatestNumOutput(t, s, 1, frame1.Header.Output)

	// Try to insert frame with a completely invalid parent selector that doesn't match any existing frame
	badFrame := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    2,
			Timestamp:      3000,
			Difficulty:     120,
			Output:         []byte("bad_frame"),
			ParentSelector: []byte("completely_invalid_parent_selector_that_matches_no_frame"),
		},
	}

	// This should succeed (goes to pending since parent not found)
	err = atr.Insert(ctx, badFrame)
	assert.NoError(t, err)
	assertNoGlobalAt(t, s, 2)

	// Check that it's in pending frames
	pending := atr.GetPendingFrames()
	assert.True(t, len(pending) > 0, "Frame should be in pending queue")
}

func TestGlobalTimeReel_ForkDetection(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	s := setupTestClockStore(t)
	atr, err := NewGlobalTimeReel(logger, createTestProverRegistry(true), s, 99, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()
	eventCh := atr.GetEventCh()

	// Collect events
	var eventsMu sync.Mutex
	events := make([]GlobalEvent, 0)
	go func() {
		for event := range eventCh {
			eventsMu.Lock()
			events = append(events, event)
			eventsMu.Unlock()
		}
	}()

	// Build a chain: 0 -> 1 -> 2
	frames := []*protobufs.GlobalFrame{
		{
			Header: &protobufs.GlobalFrameHeader{
				FrameNumber:    0,
				Timestamp:      1000,
				Difficulty:     100,
				Output:         []byte("genesis"),
				ParentSelector: []byte{},
			},
		},
		{
			Header: &protobufs.GlobalFrameHeader{
				FrameNumber:    1,
				Timestamp:      2000,
				Difficulty:     110,
				Output:         []byte("frame1"),
				ParentSelector: nil,
			},
		},
		{
			Header: &protobufs.GlobalFrameHeader{
				FrameNumber:    2,
				Timestamp:      3000,
				Difficulty:     120,
				Output:         []byte("frame2"),
				ParentSelector: nil,
			},
		},
	}

	// Set parent selectors
	frames[1].Header.ParentSelector = computeGlobalPoseidonHash(frames[0].Header.Output)
	frames[2].Header.ParentSelector = computeGlobalPoseidonHash(frames[1].Header.Output)

	// Insert chain
	for _, frame := range frames {
		err := atr.Insert(ctx, frame)
		require.NoError(t, err)
	}

	// Verify head is frame 2
	head, err := atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(2), head.Header.FrameNumber)

	// Should have received new head events
	assert.Eventually(t, func() bool {
		eventsMu.Lock()
		defer eventsMu.Unlock()
		return len(events) >= 3 // One for each frame becoming head
	}, time.Second, 10*time.Millisecond, "should have received new head events")

	assertLatestNumOutput(t, s, 2, frames[2].Header.Output)
	assertStoreNumOutput(t, s, 2, frames[2].Header.Output)
}

func TestGlobalTimeReel_ForkChoice_MoreSignatures(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	s := setupTestClockStore(t)
	atr, err := NewGlobalTimeReel(logger, createTestProverRegistry(true), s, 99, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()
	eventCh := atr.GetEventCh()

	// Drain any existing events
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Insert genesis
	genesis := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis_output"),
			ParentSelector: []byte{},
		},
	}

	err = atr.Insert(ctx, genesis)
	require.NoError(t, err)

	// Drain genesis event
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Insert frame 1 with 2 signatures
	frame1Weak := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("weak_frame"),
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11000000}, // 2 signers
			},
		},
	}

	err = atr.Insert(ctx, frame1Weak)
	require.NoError(t, err)

	// Verify weak frame is initially head
	head, err := atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(1), head.Header.FrameNumber)
	assert.Equal(t, []byte("weak_frame"), head.Header.Output)
	assertLatestNumOutput(t, s, 1, frame1Weak.Header.Output)

	// Drain frame1 event
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Insert competing frame 1 with 4 signatures (should replace weak frame)
	frame1Strong := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      2100, // Later timestamp
			Difficulty:     110,
			Output:         []byte("strong_frame"),
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00001111}, // 4 signers (more than weak frame)
			},
		},
	}

	err = atr.Insert(ctx, frame1Strong)
	require.NoError(t, err)

	// Verify strong frame is now head
	head, err = atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(1), head.Header.FrameNumber)
	assert.Equal(t, []byte("strong_frame"), head.Header.Output, "should choose frame with more signatures")

	// Check for reorganization event
	select {
	case event := <-eventCh:
		assert.Equal(t, TimeReelEventForkDetected, event.Type)
		assert.Contains(t, event.Message, "fork detected")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for reorganization event")
	}

	// Check for new head event
	select {
	case event := <-eventCh:
		assert.Equal(t, TimeReelEventNewHead, event.Type)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for reorganization event")
	}

	assertStoreNumOutput(t, s, 1, frame1Strong.Header.Output)
	assertLatestNumOutput(t, s, 1, frame1Strong.Header.Output)
}

func TestGlobalTimeReel_ForkChoice_NoReplacement(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	s := setupTestClockStore(t)
	atr, err := NewGlobalTimeReel(logger, createTestProverRegistry(true), s, 99, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()
	eventCh := atr.GetEventCh()

	// Drain any existing events
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Insert genesis
	genesis := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis_output"),
			ParentSelector: []byte{},
		},
	}

	err = atr.Insert(ctx, genesis)
	require.NoError(t, err)

	// Drain genesis event
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Insert frame 1 with more signatures and earlier timestamp
	frame1Strong := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      2000, // Earlier timestamp
			Difficulty:     110,
			Output:         []byte("strong_frame"),
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00001111}, // 4 signers
			},
		},
	}

	err = atr.Insert(ctx, frame1Strong)
	require.NoError(t, err)

	// Verify strong frame is head
	head, err := atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(1), head.Header.FrameNumber)
	assert.Equal(t, []byte("strong_frame"), head.Header.Output)
	assertLatestNumOutput(t, s, 1, frame1Strong.Header.Output)

	// Drain frame1 event
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Insert competing frame 1 with fewer signatures (should NOT replace)
	frame1Weak := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      1900, // Even earlier timestamp but fewer signatures
			Difficulty:     110,
			Output:         []byte("weak_frame"),
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00110000}, // 2 signers (fewer than strong frame)
			},
		},
	}

	err = atr.Insert(ctx, frame1Weak)
	require.NoError(t, err)

	// Give some time for any potential events
	time.Sleep(50 * time.Millisecond)

	// Verify strong frame is still head (not replaced)
	head, err = atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(1), head.Header.FrameNumber)
	assert.Equal(t, []byte("strong_frame"), head.Header.Output, "should not replace frame with more signatures")
	assertStoreNumOutput(t, s, 1, frame1Strong.Header.Output)

	// Should not receive reorganization event since no replacement occurred
	select {
	case event := <-eventCh:
		t.Fatalf("unexpected event received: %+v", event)
	case <-time.After(50 * time.Millisecond):
		// Expected - no event should be received
	}
}

func TestGlobalTimeReel_DeepForkChoice_ReverseInsertion(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	s := setupTestClockStore(t)
	atr, err := NewGlobalTimeReel(logger, createTestProverRegistry(true), s, 99, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()
	eventCh := atr.GetEventCh()

	// Drain any existing events
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Insert genesis
	genesis := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis_output"),
			ParentSelector: []byte{},
		},
	}

	err = atr.Insert(ctx, genesis)
	require.NoError(t, err)

	// Drain genesis event
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Insert frame 1 (shared by both chains initially)
	frame1 := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1_output"),
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00001111}, // 4 signers
			},
		},
	}

	err = atr.Insert(ctx, frame1)
	require.NoError(t, err)
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Build chain A: 1 -> 2A -> 3A -> 4A (fewer signatures initially)
	frame2A := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    2,
			Timestamp:      3000,
			Difficulty:     120,
			Output:         []byte("frame2A_output"),
			ParentSelector: computeGlobalPoseidonHash(frame1.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00000011}, // 2 signers (weaker)
			},
		},
	}

	frame3A := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    3,
			Timestamp:      4000,
			Difficulty:     130,
			Output:         []byte("frame3A_output"),
			ParentSelector: computeGlobalPoseidonHash(frame2A.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00001111}, // 4 signers
			},
		},
	}

	frame4A := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    4,
			Timestamp:      5000,
			Difficulty:     140,
			Output:         []byte("frame4A_output"),
			ParentSelector: computeGlobalPoseidonHash(frame3A.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00001111}, // 4 signers
			},
		},
	}

	// Insert chain A frames in order: 2A, 3A, 4A
	err = atr.Insert(ctx, frame2A)
	require.NoError(t, err)
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	err = atr.Insert(ctx, frame3A)
	require.NoError(t, err)
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	err = atr.Insert(ctx, frame4A)
	require.NoError(t, err)
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Verify chain A is the current head
	head, err := atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(4), head.Header.FrameNumber)
	assert.Equal(t, []byte("frame4A_output"), head.Header.Output)
	assertLatestNumOutput(t, s, 4, frame4A.Header.Output)

	// Now create chain B: 1 -> 2B -> 3B -> 4B (stronger chain)
	frame2B := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    2,
			Timestamp:      2900, // Earlier timestamp than 2A
			Difficulty:     120,
			Output:         []byte("frame2B_output"),
			ParentSelector: computeGlobalPoseidonHash(frame1.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11110000}, // 4 signers (stronger than frame2A)
			},
		},
	}

	frame3B := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    3,
			Timestamp:      3900, // Earlier timestamp than 3A
			Difficulty:     130,
			Output:         []byte("frame3B_output"),
			ParentSelector: computeGlobalPoseidonHash(frame2B.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11110000}, // 4 signers (same count as 3A, different bits, earlier timestamp)
			},
		},
	}

	frame4B := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    4,
			Timestamp:      4900, // Earlier timestamp than 4A
			Difficulty:     140,
			Output:         []byte("frame4B_output"),
			ParentSelector: computeGlobalPoseidonHash(frame3B.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11110000}, // 4 signers (same count as 4A, different bits, earlier timestamp)
			},
		},
	}

	// Insert chain B in REVERSE order: 4B, 3B, 2B
	// This should work because the time reel should handle out-of-order insertion

	// Insert frame 4B first
	err = atr.Insert(ctx, frame4B)
	require.NoError(t, err, "inserting 4B should succeed even without its parents")
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Head should still be chain A since 4B's lineage is incomplete
	head, err = atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(4), head.Header.FrameNumber)
	assert.Equal(t, []byte("frame4A_output"), head.Header.Output, "should still be chain A")

	// Insert frame 3B
	err = atr.Insert(ctx, frame3B)
	require.NoError(t, err, "inserting 3B should succeed")
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Head should still be chain A
	head, err = atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(4), head.Header.FrameNumber)
	assert.Equal(t, []byte("frame4A_output"), head.Header.Output, "should still be chain A")

	// Insert frame 2B - this completes the chain B lineage
	err = atr.Insert(ctx, frame2B)
	require.NoError(t, err, "inserting 2B should succeed and complete chain B")

	// Give time for reorganization
	time.Sleep(50 * time.Millisecond)

	// Now chain B should be head (stronger at frame 2, with complete lineage)
	head, err = atr.GetHead()
	require.NoError(t, err)

	// Debug: Print what frames exist
	t.Logf("Current head: frame %d, output: %s", head.Header.FrameNumber, head.Header.Output)

	assert.Equal(t, uint64(4), head.Header.FrameNumber)
	assert.Equal(t, []byte("frame4B_output"), head.Header.Output, "chain B should become head after complete insertion")

	// Check for reorganization event
	select {
	case event := <-eventCh:
		assert.Equal(t, TimeReelEventForkDetected, event.Type)
		assert.Contains(t, event.Message, "fork detected")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for reorganization event")
	}
	assertStoreNumOutput(t, s, 2, frame2B.Header.Output)
	assertStoreNumOutput(t, s, 3, frame3B.Header.Output)
	assertStoreNumOutput(t, s, 4, frame4B.Header.Output)
	assertLatestNumOutput(t, s, 4, frame4B.Header.Output)
}

func TestGlobalTimeReel_TreePruning(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	s := setupTestClockStore(t)
	atr, err := NewGlobalTimeReel(logger, createTestProverRegistry(true), s, 99, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()

	// Insert genesis
	genesis := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis"),
			ParentSelector: []byte{},
		},
	}

	err = atr.Insert(ctx, genesis)
	require.NoError(t, err)

	// Build a long chain that will trigger pruning (370 frames total)
	prevOutput := genesis.Header.Output
	for i := 1; i <= 370; i++ {
		frame := &protobufs.GlobalFrame{
			Header: &protobufs.GlobalFrameHeader{
				FrameNumber:    uint64(i),
				Timestamp:      int64(1000 + i*1000),
				Difficulty:     uint32(100 + i),
				Output:         []byte(fmt.Sprintf("frame%d", i)),
				ParentSelector: computeGlobalPoseidonHash(prevOutput),
			},
		}

		err = atr.Insert(ctx, frame)
		require.NoError(t, err)

		prevOutput = frame.Header.Output
	}

	// Verify head is at frame 370
	head, err := atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(370), head.Header.FrameNumber)

	// Get tree info to verify pruning occurred
	info := atr.GetTreeInfo()
	t.Logf("Tree info: %+v", info)

	// Verify tree span is at most 360 frames
	treeSpan := info["tree_span"].(uint64)
	assert.LessOrEqual(t, treeSpan, uint64(360), "tree span should not exceed 360 frames")

	// Verify minimum depth is reasonable (should have pruned old frames)
	minDepth := info["min_depth"].(uint64)
	maxDepth := info["max_depth"].(uint64)
	headDepth := info["head_depth"].(uint64)

	assert.Equal(t, uint64(370), headDepth, "head depth should be 370")
	assert.Equal(t, headDepth, maxDepth, "max depth should equal head depth")
	assert.GreaterOrEqual(t, minDepth, uint64(11), "min depth should be at least 11 (370-360+1)")

	// Verify we can still get lineage (should be limited to available frames)
	lineage, err := atr.GetLineage()
	require.NoError(t, err)
	assert.LessOrEqual(t, len(lineage), 360, "lineage should not exceed 360 frames")

	// Verify we can't get very old frames
	oldFrames, err := atr.GetFramesByNumber(0)
	assert.Error(t, err, "should not be able to get genesis frame after pruning")
	assert.Nil(t, oldFrames)

	// Verify we can get recent frames
	recentFrames, err := atr.GetFramesByNumber(370)
	require.NoError(t, err)
	assert.Len(t, recentFrames, 1)
	assert.Equal(t, uint64(370), recentFrames[0].Header.FrameNumber)
}

func TestGlobalTimeReel_TreePruningWithForks(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	s := setupTestClockStore(t)
	atr, err := NewGlobalTimeReel(logger, createTestProverRegistry(true), s, 99, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()

	// Insert genesis
	genesis := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis"),
			ParentSelector: []byte{},
		},
	}

	err = atr.Insert(ctx, genesis)
	require.NoError(t, err)

	// Build main chain for 365 frames
	prevOutput := genesis.Header.Output
	var frame5 *protobufs.GlobalFrame
	for i := 1; i <= 365; i++ {
		frame := &protobufs.GlobalFrame{
			Header: &protobufs.GlobalFrameHeader{
				FrameNumber:    uint64(i),
				Timestamp:      int64(1000 + i*1000),
				Difficulty:     uint32(100 + i),
				Output:         []byte(fmt.Sprintf("main_frame%d", i)),
				ParentSelector: computeGlobalPoseidonHash(prevOutput),
			},
		}

		err = atr.Insert(ctx, frame)
		require.NoError(t, err)

		if i == 5 {
			frame5 = frame
		}

		prevOutput = frame.Header.Output
	}

	// Create a fork at frame 6 that branches from frame 5
	// This fork gets pruned when we continue the main chain past 365+360
	forkFrame := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    6,
			Timestamp:      6000,
			Difficulty:     106,
			Output:         []byte("fork_frame6"),
			ParentSelector: computeGlobalPoseidonHash(frame5.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00000001}, // Fewer signatures than main chain
			},
		},
	}

	err = atr.Insert(ctx, forkFrame)
	require.NoError(t, err)

	// Continue main chain for 375 more frames to trigger deep pruning
	for i := 366; i <= 740; i++ {
		frame := &protobufs.GlobalFrame{
			Header: &protobufs.GlobalFrameHeader{
				FrameNumber:    uint64(i),
				Timestamp:      int64(1000 + i*1000),
				Difficulty:     uint32(100 + i),
				Output:         []byte(fmt.Sprintf("main_frame%d", i)),
				ParentSelector: computeGlobalPoseidonHash(prevOutput),
			},
		}

		err = atr.Insert(ctx, frame)
		require.NoError(t, err)

		prevOutput = frame.Header.Output
	}

	// Verify pruning occurred and old fork was removed
	info := atr.GetTreeInfo()
	t.Logf("Tree info after deep pruning: %+v", info)

	// Tree span should be exactly 360
	treeSpan := info["tree_span"].(uint64)
	assert.Equal(t, uint64(360), treeSpan, "tree span should be exactly 360 frames")

	// Should have only one branch (old fork should be pruned)
	branchCount := info["branch_count"].(int)
	assert.Equal(t, 1, branchCount, "should have only one branch after pruning old forks")

	// Minimum depth should be well past the old fork
	minDepth := info["min_depth"].(uint64)
	assert.Greater(t, minDepth, uint64(6), "minimum depth should be past the old fork depth")

	// Head should still be the main chain
	head, err := atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(740), head.Header.FrameNumber)
	assert.Equal(t, []byte("main_frame740"), head.Header.Output)
}

// TestGlobalTimeReel_ForkChoiceInsertionOrder tests that fork choice works regardless of insertion order
func TestGlobalTimeReel_ForkChoiceInsertionOrder(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	s := setupTestClockStore(t)
	atr, err := NewGlobalTimeReel(logger, createTestProverRegistry(true), s, 99, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()
	eventCh := atr.GetEventCh()

	// Drain any existing events
loop:
	for {
		select {
		case <-eventCh:
		case <-time.After(10 * time.Millisecond):
			break loop
		}
	}

	// Insert genesis
	genesis := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis_output"),
			ParentSelector: []byte{},
		},
	}

	err = atr.Insert(ctx, genesis)
	require.NoError(t, err)

	// Drain genesis event
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Create two competing branches:
	// Branch A: 0 -> 1A -> 2A (weaker)
	// Branch B: 0 -> 1B -> 2B (stronger)
	// Insert in REVERSE order to test fork choice works regardless of order

	// First, insert the STRONGER branch tip (2B) without its parent
	frame2B := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    2,
			Timestamp:      3000,
			Difficulty:     120,
			Output:         []byte("frame2B_output"),
			ParentSelector: []byte("placeholder_for_1B"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11111100}, // 6 signers (very strong)
			},
		},
	}

	// Insert the WEAKER branch (1A -> 2A) first, which should become head initially
	frame1A := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1A_output"),
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00000011}, // 2 signers (weak)
			},
		},
	}

	frame2A := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    2,
			Timestamp:      3000,
			Difficulty:     120,
			Output:         []byte("frame2A_output"),
			ParentSelector: computeGlobalPoseidonHash(frame1A.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00000011}, // 2 signers (weak)
			},
		},
	}

	// Insert weak branch first
	err = atr.Insert(ctx, frame1A)
	require.NoError(t, err)
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	err = atr.Insert(ctx, frame2A)
	require.NoError(t, err)
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Verify weak branch is head initially
	head, err := atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(2), head.Header.FrameNumber)
	assert.Equal(t, []byte("frame2A_output"), head.Header.Output)

	// Now insert stronger branch 1B (which will allow 2B to be processed)
	frame1B := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      2100,
			Difficulty:     110,
			Output:         []byte("frame1B_output"),
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11111100}, // 6 signers (strong)
			},
		},
	}

	// Update frame2B's parent selector now that we know frame1B's output
	frame2B.Header.ParentSelector = computeGlobalPoseidonHash(frame1B.Header.Output)

	// Insert stronger branch out of order: first 2B (goes to pending), then 1B
	err = atr.Insert(ctx, frame2B)
	require.NoError(t, err, "should accept frame 2B into pending")

	// Head should still be weak branch
	head, err = atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, []byte("frame2A_output"), head.Header.Output, "head should still be weak branch")

	// Now insert 1B, which should complete the strong branch and trigger fork choice
	err = atr.Insert(ctx, frame1B)
	require.NoError(t, err)

	// Give time for fork choice to process
	time.Sleep(100 * time.Millisecond)

	// Verify strong branch is now head
	head, err = atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(2), head.Header.FrameNumber)
	assert.Equal(t, []byte("frame2B_output"), head.Header.Output, "should switch to stronger branch")

	// Check for fork choice event
	select {
	case event := <-eventCh:
		assert.Equal(t, TimeReelEventForkDetected, event.Type)
		assert.Contains(t, event.Message, "fork detected")
		t.Logf("Fork choice event: %s", event.Message)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for fork choice event")
	}
}

// TestGlobalTimeReel_ForkEventsWithReplay tests that fork events include common ancestor and replay
func TestGlobalTimeReel_ForkEventsWithReplay(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	s := setupTestClockStore(t)
	atr, err := NewGlobalTimeReel(logger, createTestProverRegistry(true), s, 99, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()
	eventCh := atr.GetEventCh()

	// Collect all events
	var eventsMu sync.Mutex
	events := make([]GlobalEvent, 0)
	go func() {
		for event := range eventCh {
			eventsMu.Lock()
			events = append(events, event)
			eventsMu.Unlock()
		}
	}()

	// Build initial chain: 0 -> 1 -> 2 -> 3
	genesis := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis"),
			ParentSelector: []byte{},
		},
	}

	frame1 := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1"),
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
		},
	}

	frame2 := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    2,
			Timestamp:      3000,
			Difficulty:     120,
			Output:         []byte("frame2"),
			ParentSelector: computeGlobalPoseidonHash(frame1.Header.Output),
		},
	}

	frame3 := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    3,
			Timestamp:      4000,
			Difficulty:     130,
			Output:         []byte("frame3"),
			ParentSelector: computeGlobalPoseidonHash(frame2.Header.Output),
		},
	}

	// Insert initial chain
	for _, frame := range []*protobufs.GlobalFrame{genesis, frame1, frame2, frame3} {
		err = atr.Insert(ctx, frame)
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond) // Allow events to be sent
	}

	// Clear events up to this point
	eventsMu.Lock()
	events = events[:0]
	eventsMu.Unlock()

	// Now create a stronger fork that branches from frame1: 1 -> 2' -> 3' -> 4'
	// This should trigger a reorg back to frame1 (common ancestor)
	frame2Prime := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    2,
			Timestamp:      2900, // Earlier timestamp
			Difficulty:     120,
			Output:         []byte("frame2_prime"),
			ParentSelector: computeGlobalPoseidonHash(frame1.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11111111}, // 8 signers (much stronger)
			},
		},
	}

	frame3Prime := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    3,
			Timestamp:      3900,
			Difficulty:     130,
			Output:         []byte("frame3_prime"),
			ParentSelector: computeGlobalPoseidonHash(frame2Prime.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11111111}, // 8 signers
			},
		},
	}

	frame4Prime := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    4,
			Timestamp:      4900,
			Difficulty:     140,
			Output:         []byte("frame4_prime"),
			ParentSelector: computeGlobalPoseidonHash(frame3Prime.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11111111}, // 8 signers
			},
		},
	}

	// Insert stronger fork - this should trigger a reorganization
	for _, frame := range []*protobufs.GlobalFrame{frame2Prime, frame3Prime, frame4Prime} {
		err = atr.Insert(ctx, frame)
		require.NoError(t, err)
		time.Sleep(50 * time.Millisecond) // Allow events to propagate
	}

	// Verify final head is the stronger branch
	head, err := atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(4), head.Header.FrameNumber)
	assert.Equal(t, []byte("frame4_prime"), head.Header.Output)

	// Wait for all events to be processed
	time.Sleep(100 * time.Millisecond)

	// Check events - should include:
	// 1. Fork detected event indicating the reorg
	// 2. The event should reference the common ancestor (frame1)
	// 3. Should see new head events for frames 2', 3', 4'
	eventsMu.Lock()
	collectedEvents := make([]GlobalEvent, len(events))
	copy(collectedEvents, events)
	eventsMu.Unlock()

	t.Logf("Collected %d events after fork insertion", len(collectedEvents))
	for i, event := range collectedEvents {
		t.Logf("Event %d: Type=%d, Message=%s", i, event.Type, event.Message)
	}

	// Find the fork detected event
	forkEventFound := false
	newHeadEventsCount := 0
	for _, event := range collectedEvents {
		if event.Type == TimeReelEventForkDetected {
			forkEventFound = true
			// The message should indicate this is a reorganization
			assert.Contains(t, event.Message, "fork detected", "fork event should mention fork detected")
			// Should have old head reference
			assert.NotNil(t, event.OldHead, "fork event should have old head reference")
		} else if event.Type == TimeReelEventNewHead {
			newHeadEventsCount++
		}
	}

	assert.True(t, forkEventFound, "should have received a fork detected event")
	assert.GreaterOrEqual(t, newHeadEventsCount, 3, "should have received new head events for the replayed frames")
}

// TestGlobalTimeReel_ComprehensiveEquivocation tests equivocation detection thoroughly
func TestGlobalTimeReel_ComprehensiveEquivocation(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	s := setupTestClockStore(t)
	atr, err := NewGlobalTimeReel(logger, createTestProverRegistry(true), s, 99, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()
	eventCh := atr.GetEventCh()

	// Collect equivocation events
	var equivocationEvents []GlobalEvent
	var eventsMu sync.Mutex
	go func() {
		for event := range eventCh {
			if event.Type == TimeReelEventEquivocationDetected {
				eventsMu.Lock()
				equivocationEvents = append(equivocationEvents, event)
				eventsMu.Unlock()
			}
		}
	}()

	// Insert genesis
	genesis := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis"),
			ParentSelector: []byte{},
		},
	}

	err = atr.Insert(ctx, genesis)
	require.NoError(t, err)

	// Insert valid frame 1
	frame1Valid := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1_valid"),
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00001111}, // Signers 0,1,2,3
			},
		},
	}

	err = atr.Insert(ctx, frame1Valid)
	require.NoError(t, err)

	// Test Case 1: Complete overlap - same signers, different content
	frame1Equivocation1 := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1_evil_complete"), // Different output
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00001111}, // Same signers 0,1,2,3
			},
		},
	}

	err = atr.Insert(ctx, frame1Equivocation1)
	assert.NoError(t, err)

	// Test Case 2: Partial overlap - some same signers
	frame1Equivocation2 := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1_evil_partial"),
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11000011}, // Signers 0,1,6,7 - overlap with 0,1
			},
		},
	}

	err = atr.Insert(ctx, frame1Equivocation2)
	assert.NoError(t, err)

	// Test Case 3: No overlap - should be allowed (fork)
	frame1Fork := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1_fork"),
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00110000}, // Signers 4,5 - no overlap
			},
		},
	}

	err = atr.Insert(ctx, frame1Fork)
	assert.NoError(t, err, "should allow fork with no overlapping signers")

	// Wait for events to be processed
	time.Sleep(100 * time.Millisecond)

	// Verify we received exactly 3 equivocation events
	eventsMu.Lock()
	equivCount := len(equivocationEvents)
	eventsMu.Unlock()

	assert.Equal(t, 3, equivCount, "should have received exactly 3 equivocation events")

	// Verify event details
	if len(equivocationEvents) >= 3 {
		for i, event := range equivocationEvents {
			assert.Equal(t, TimeReelEventEquivocationDetected, event.Type)
			assert.Contains(t, event.Message, "equivocation at frame 1")
			assert.NotNil(t, event.Frame)
			assert.Equal(t, uint64(1), event.Frame.Header.FrameNumber)
			t.Logf("Equivocation event %d: %s", i+1, event.Message)
		}
	}
}

func mustLatestGlobal(t *testing.T, s *store.PebbleClockStore) *protobufs.GlobalFrame {
	t.Helper()
	f, err := s.GetLatestGlobalClockFrame()
	require.NoError(t, err)
	return f
}

func mustGlobalAt(t *testing.T, s *store.PebbleClockStore, n uint64) *protobufs.GlobalFrame {
	t.Helper()
	f, err := s.GetGlobalClockFrame(n)
	require.NoError(t, err)
	return f
}

func assertNoGlobalAt(t *testing.T, s *store.PebbleClockStore, n uint64) {
	t.Helper()
	_, err := s.GetGlobalClockFrame(n)
	require.Error(t, err, "expected no canonical frame at height %d in store", n)
}

func assertStoreNumOutput(t *testing.T, s *store.PebbleClockStore, n uint64, output []byte) {
	t.Helper()
	f := mustGlobalAt(t, s, n)
	assert.Equal(t, n, f.Header.FrameNumber)
	assert.Equal(t, output, f.Header.Output)
}

func assertLatestNumOutput(t *testing.T, s *store.PebbleClockStore, n uint64, output []byte) {
	t.Helper()
	f := mustLatestGlobal(t, s)
	assert.Equal(t, n, f.Header.FrameNumber)
	assert.Equal(t, output, f.Header.Output)
}
