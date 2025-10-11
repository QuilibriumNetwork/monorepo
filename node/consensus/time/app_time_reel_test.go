package time

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
)

// createTestProverRegistry creates a mock ProverRegistry that returns expected provers
func createTestProverRegistry(defaultReturn bool) *mocks.MockProverRegistry {
	proverRegistry := new(mocks.MockProverRegistry)
	if defaultReturn {
		// By default, allow any prover (return the same prover that was in the frame)
		proverRegistry.On("GetNextProver", mock.Anything, mock.Anything).Return(nil, errors.New("no specific prover required"))
		proverRegistry.On("GetOrderedProvers", mock.Anything, mock.Anything).Return(nil, errors.New("no ordered provers"))
	}
	return proverRegistry
}

// createStrictProverRegistry creates a mock ProverRegistry that expects specific provers
func createStrictProverRegistry(expectedProvers map[string][]byte) *mocks.MockProverRegistry {
	proverRegistry := new(mocks.MockProverRegistry)
	// Set up expectations for specific parent selectors
	for parentSelectorStr, expectedProver := range expectedProvers {
		var parentSelector [32]byte
		copy(parentSelector[:], []byte(parentSelectorStr))
		proverRegistry.On("GetNextProver", parentSelector, mock.Anything).Return(expectedProver, nil)
		// Also set up GetOrderedProvers to return the expected prover as the first in the list
		proverRegistry.On("GetOrderedProvers", parentSelector, mock.Anything).Return([][]byte{expectedProver}, nil)
	}
	// Default behavior for unknown parent selectors
	proverRegistry.On("GetNextProver", mock.Anything, mock.Anything).Return(nil, errors.New("unknown parent selector"))
	proverRegistry.On("GetOrderedProvers", mock.Anything, mock.Anything).Return(nil, errors.New("unknown parent selector"))
	return proverRegistry
}

func TestAppTimeReel_BasicOperations(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	address := []byte("test_app_address")
	s := setupTestClockStore(t)
	atr, err := NewAppTimeReel(logger, address, createTestProverRegistry(true), s, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()

	// Test address getter
	assert.Equal(t, address, atr.GetAddress())

	// Test inserting genesis frame
	genesis := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("app_genesis_output"),
			ParentSelector: []byte{}, // Empty for genesis
			Prover:         []byte("prover1"),
		},
	}

	err = atr.Insert(ctx, genesis)
	assert.NoError(t, err)

	// Check that genesis became head
	head, err := atr.GetHead()
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), head.Header.FrameNumber)

	// Test inserting next frame
	frame1 := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("app_frame1_output"),
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Prover:         []byte("prover2"),
		},
	}

	err = atr.Insert(ctx, frame1)
	assert.NoError(t, err)

	// Check new head
	head, err = atr.GetHead()
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), head.Header.FrameNumber)

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

func TestAppTimeReel_WrongAddress(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	address := []byte("correct_address")
	s := setupTestClockStore(t)
	atr, err := NewAppTimeReel(logger, address, createTestProverRegistry(true), s, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()

	// Try to insert frame with wrong address
	wrongFrame := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        []byte("wrong_address"),
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("output"),
			ParentSelector: []byte{},
			Prover:         []byte("prover"),
		},
	}

	err = atr.Insert(ctx, wrongFrame)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "frame address does not match reel address")
}

func TestAppTimeReel_Equivocation(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	address := []byte("test_app_address")
	s := setupTestClockStore(t)
	atr, err := NewAppTimeReel(logger, address, createTestProverRegistry(true), s, true)
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
	genesis := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis_output"),
			ParentSelector: []byte{},
			Prover:         []byte("prover1"),
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
	frame1 := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1_output"),
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Prover:         []byte("prover2"),
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

	// Try to insert equivocating frame 1 with overlapping bitmask
	frame1Equivocation := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("different_output"), // Different output
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Prover:         []byte("prover3"), // Different prover
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
}

func TestAppTimeReel_Fork(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	address := []byte("test_app_address")
	s := setupTestClockStore(t)
	atr, err := NewAppTimeReel(logger, address, createTestProverRegistry(true), s, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()

	// Insert genesis
	genesis := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis_output"),
			ParentSelector: []byte{},
			Prover:         []byte("prover1"),
		},
	}

	err = atr.Insert(ctx, genesis)
	assert.NoError(t, err)

	// Insert valid frame 1 with BLS signature
	frame1 := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1_output"),
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Prover:         []byte("prover2"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00001111}, // First 4 signers
			},
		},
	}

	err = atr.Insert(ctx, frame1)
	assert.NoError(t, err)

	// Try to insert forking frame 1 with non-overlapping bitmask (different signers)
	frame1Fork := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("fork_output"), // Different output
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Prover:         []byte("prover3"), // Different prover
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11110000}, // Different signers - no overlap
			},
		},
	}

	// This should succeed - it's a fork, not equivocation
	err = atr.Insert(ctx, frame1Fork)
	assert.NoError(t, err)

	// Head should still be the original frame1
	head, err := atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, frame1.Header.Output, head.Header.Output)
}

func TestAppTimeReel_ParentValidation(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	address := []byte("test_app_address")
	s := setupTestClockStore(t)
	atr, err := NewAppTimeReel(logger, address, createTestProverRegistry(true), s, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()

	// Insert genesis
	genesis := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis_output"),
			ParentSelector: []byte{},
			Prover:         []byte("prover1"),
		},
	}

	err = atr.Insert(ctx, genesis)
	assert.NoError(t, err)

	// Insert valid frame 1
	frame1 := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1_output"),
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Prover:         []byte("prover2"),
		},
	}

	err = atr.Insert(ctx, frame1)
	assert.NoError(t, err)

	// Try to insert frame with a completely invalid parent selector that doesn't match any existing frame
	badFrame := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    2,
			Timestamp:      3000,
			Difficulty:     120,
			Output:         []byte("bad_frame"),
			ParentSelector: []byte("completely_invalid_parent_selector_that_matches_no_frame"),
			Prover:         []byte("prover3"),
		},
	}

	// This should succeed (goes to pending since parent not found)
	err = atr.Insert(ctx, badFrame)
	assert.NoError(t, err)

	// Check that it's in pending frames
	pending := atr.GetPendingFrames()
	assert.True(t, len(pending) > 0, "Frame should be in pending queue")
}

func TestAppTimeReel_ForkDetection(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	address := []byte("test_app_address")
	s := setupTestClockStore(t)
	atr, err := NewAppTimeReel(logger, address, createTestProverRegistry(true), s, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()
	eventCh := atr.GetEventCh()

	// Collect events
	var eventsMu sync.Mutex
	events := make([]AppEvent, 0)
	go func() {
		for event := range eventCh {
			eventsMu.Lock()
			events = append(events, event)
			eventsMu.Unlock()
		}
	}()

	// Build a chain: 0 -> 1 -> 2
	frames := []*protobufs.AppShardFrame{
		{
			Header: &protobufs.FrameHeader{
				Address:        address,
				FrameNumber:    0,
				Timestamp:      1000,
				Difficulty:     100,
				Output:         []byte("genesis"),
				ParentSelector: []byte{},
				Prover:         []byte("prover1"),
			},
		},
		{Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1"),
			ParentSelector: nil,
			Prover:         []byte("prover2"),
		},
		},
		{Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    2,
			Timestamp:      3000,
			Difficulty:     120,
			Output:         []byte("frame2"),
			ParentSelector: nil,
			Prover:         []byte("prover3"),
		},
		},
	}

	// Set parent selectors
	frames[1].Header.ParentSelector = computeAppPoseidonHash(frames[0].Header.Output)
	frames[2].Header.ParentSelector = computeAppPoseidonHash(frames[1].Header.Output)

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
}

func TestAppTimeReel_ForkChoice_MoreSignatures(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	address := []byte("test_app_address")
	s := setupTestClockStore(t)
	atr, err := NewAppTimeReel(logger, address, createTestProverRegistry(true), s, true)
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
	genesis := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis_output"),
			ParentSelector: []byte{},
			Prover:         []byte("prover1"),
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
	frame1Weak := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("weak_frame"),
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Prover:         []byte("prover2"),
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

	// Drain frame1 event
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Insert competing frame 1 with 4 signatures (should replace weak frame)
	frame1Strong := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2100, // Later timestamp
			Difficulty:     110,
			Output:         []byte("strong_frame"),
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Prover:         []byte("prover3"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00001111}, // 4 signers (more than weak frame)
			},
		},
	}

	err = atr.Insert(ctx, frame1Strong)
	require.NoError(t, err)

	// Give the goroutine time to send the event
	time.Sleep(50 * time.Millisecond)

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
}

func TestAppTimeReel_ForkChoice_NoReplacement(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	address := []byte("test_app_address")
	s := setupTestClockStore(t)
	atr, err := NewAppTimeReel(logger, address, createTestProverRegistry(true), s, true)
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
	genesis := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis_output"),
			ParentSelector: []byte{},
			Prover:         []byte("prover1"),
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
	frame1Strong := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000, // Earlier timestamp
			Difficulty:     110,
			Output:         []byte("strong_frame"),
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Prover:         []byte("prover2"),
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

	// Drain frame1 event
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Insert competing frame 1 with fewer signatures (should NOT replace)
	frame1Weak := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      1900, // Even earlier timestamp but fewer signatures
			Difficulty:     110,
			Output:         []byte("weak_frame"),
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Prover:         []byte("prover3"),
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

	// Should not receive reorganization event since no replacement occurred
	select {
	case event := <-eventCh:
		t.Fatalf("unexpected event received: %+v", event)
	case <-time.After(50 * time.Millisecond):
		// Expected - no event should be received
	}
}

func TestAppTimeReel_DeepForkChoice_ReverseInsertion(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	address := []byte("test_app_address")
	reg := createTestProverRegistry(false)
	s := setupTestClockStore(t)
	atr, err := NewAppTimeReel(logger, address, reg, s, true)
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
	genesis := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis_output"),
			ParentSelector: []byte{},
			Prover:         []byte("prover1"),
		},
	}

	reg.On("GetNextProver", [32]byte{}, mock.Anything).Return([]byte("prover1"), nil)
	reg.On("GetOrderedProvers", [32]byte{}, mock.Anything).Return([][]byte{
		[]byte("prover1"),
		[]byte("prover2"),
		[]byte("prover3"),
		[]byte("prover4"),
		[]byte("prover5"),
		[]byte("prover6"),
		[]byte("prover7"),
		[]byte("prover8"),
	}, nil)

	err = atr.Insert(ctx, genesis)
	require.NoError(t, err)

	// Drain genesis event
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Insert frame 1 (shared by both chains initially)
	frame1 := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1_output"),
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Prover:         []byte("prover1"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11111111}, // 4 signers
			},
		},
	}

	reg.On("GetNextProver", [32]byte(computeAppPoseidonHash(genesis.Header.Output)), mock.Anything).Return([]byte("prover1"), nil)
	reg.On("GetOrderedProvers", [32]byte(computeAppPoseidonHash(genesis.Header.Output)), mock.Anything).Return([][]byte{
		[]byte("prover1"),
		[]byte("prover2"),
		[]byte("prover3"),
		[]byte("prover4"),
		[]byte("prover5"),
		[]byte("prover6"),
		[]byte("prover7"),
		[]byte("prover8"),
	}, nil)

	err = atr.Insert(ctx, frame1)
	require.NoError(t, err)
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Build chain A: 1 -> 2A -> 3A -> 4A (fewer signatures initially)
	frame2A := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    2,
			Timestamp:      3000,
			Difficulty:     120,
			Output:         []byte("frame2A_output"),
			ParentSelector: computeAppPoseidonHash(frame1.Header.Output),
			Prover:         []byte("prover8"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00000011}, // 2 signers (weaker)
			},
		},
	}

	reg.On("GetNextProver", [32]byte(computeAppPoseidonHash(frame1.Header.Output)), mock.Anything).Return([]byte("prover2"), nil)
	reg.On("GetOrderedProvers", [32]byte(computeAppPoseidonHash(frame1.Header.Output)), mock.Anything).Return([][]byte{
		[]byte("prover2"),
		[]byte("prover1"),
		[]byte("prover3"),
		[]byte("prover4"),
		[]byte("prover5"),
		[]byte("prover6"),
		[]byte("prover7"),
		[]byte("prover8"),
	}, nil)

	frame3A := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    3,
			Timestamp:      4000,
			Difficulty:     130,
			Output:         []byte("frame3A_output"),
			ParentSelector: computeAppPoseidonHash(frame2A.Header.Output),
			Prover:         []byte("prover7"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00001111}, // 4 signers
			},
		},
	}

	reg.On("GetNextProver", [32]byte(computeAppPoseidonHash(frame2A.Header.Output)), mock.Anything).Return([]byte("prover7"), nil)
	reg.On("GetOrderedProvers", [32]byte(computeAppPoseidonHash(frame2A.Header.Output)), mock.Anything).Return([][]byte{
		[]byte("prover7"),
		[]byte("prover5"),
		[]byte("prover6"),
		[]byte("prover8"),
		[]byte("prover2"),
		[]byte("prover1"),
		[]byte("prover3"),
		[]byte("prover4"),
	}, nil)

	frame4A := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    4,
			Timestamp:      5000,
			Difficulty:     140,
			Output:         []byte("frame4A_output"),
			ParentSelector: computeAppPoseidonHash(frame3A.Header.Output),
			Prover:         []byte("prover6"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00001111}, // 4 signers
			},
		},
	}

	reg.On("GetNextProver", [32]byte(computeAppPoseidonHash(frame3A.Header.Output)), mock.Anything).Return([]byte("prover6"), nil)
	reg.On("GetOrderedProvers", [32]byte(computeAppPoseidonHash(frame3A.Header.Output)), mock.Anything).Return([][]byte{
		[]byte("prover6"),
		[]byte("prover7"),
		[]byte("prover8"),
		[]byte("prover2"),
		[]byte("prover1"),
		[]byte("prover3"),
		[]byte("prover4"),
		[]byte("prover5"),
	}, nil)

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

	// Now create chain B: 1 -> 2B -> 3B -> 4B (stronger chain)
	frame2B := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    2,
			Timestamp:      2900, // Earlier timestamp than 2A
			Difficulty:     120,
			Output:         []byte("frame2B_output"),
			ParentSelector: computeAppPoseidonHash(frame1.Header.Output),
			Prover:         []byte("prover2"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11110000}, // 4 signers (stronger than frame2A)
			},
		},
	}

	frame3B := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    3,
			Timestamp:      3900, // Earlier timestamp than 3A
			Difficulty:     130,
			Output:         []byte("frame3B_output"),
			ParentSelector: computeAppPoseidonHash(frame2B.Header.Output),
			Prover:         []byte("prover3"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11110000}, // 4 signers (same count as 3A, different bits, earlier timestamp)
			},
		},
	}

	reg.On("GetNextProver", [32]byte(computeAppPoseidonHash(frame2B.Header.Output)), mock.Anything).Return([]byte("prover2"), nil)
	reg.On("GetOrderedProvers", [32]byte(computeAppPoseidonHash(frame2B.Header.Output)), mock.Anything).Return([][]byte{
		[]byte("prover3"),
		[]byte("prover2"),
		[]byte("prover1"),
		[]byte("prover4"),
		[]byte("prover5"),
		[]byte("prover6"),
		[]byte("prover7"),
		[]byte("prover8"),
	}, nil)

	frame4B := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    4,
			Timestamp:      4900, // Earlier timestamp than 4A
			Difficulty:     140,
			Output:         []byte("frame4B_output"),
			ParentSelector: computeAppPoseidonHash(frame3B.Header.Output),
			Prover:         []byte("prover4"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11110000}, // 4 signers (same count as 4A, different bits, earlier timestamp)
			},
		},
	}

	reg.On("GetNextProver", [32]byte(computeAppPoseidonHash(frame3B.Header.Output)), mock.Anything).Return([]byte("prover2"), nil)
	reg.On("GetOrderedProvers", [32]byte(computeAppPoseidonHash(frame3B.Header.Output)), mock.Anything).Return([][]byte{
		[]byte("prover4"),
		[]byte("prover2"),
		[]byte("prover1"),
		[]byte("prover3"),
		[]byte("prover5"),
		[]byte("prover6"),
		[]byte("prover7"),
		[]byte("prover8"),
	}, nil)

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

	// Check for reorganization event
	headFrameNumber := uint64(2)
outer:
	for {
		select {
		case event := <-eventCh:
			if event.Type == TimeReelEventForkDetected {
				assert.Contains(t, event.Message, "fork detected")
			} else {
				assert.Equal(t, TimeReelEventNewHead, event.Type)
				assert.Equal(t, headFrameNumber, event.Frame.Header.FrameNumber)
				headFrameNumber++
			}
		case <-time.After(200 * time.Millisecond):
			break outer
		}
	}

	// Now chain B should be head (stronger at frame 2, with complete lineage)
	head, err = atr.GetHead()
	require.NoError(t, err)

	assert.Equal(t, uint64(4), head.Header.FrameNumber)
	assert.Equal(t, []byte("frame4B_output"), head.Header.Output, "chain B should become head after complete insertion")
}

func TestAppTimeReel_MultipleProvers(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	address := []byte("test_app_address")
	s := setupTestClockStore(t)
	atr, err := NewAppTimeReel(logger, address, createTestProverRegistry(true), s, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()

	// Different provers create frames
	provers := [][]byte{
		[]byte("prover1"),
		[]byte("prover2"),
		[]byte("prover3"),
	}

	// Insert genesis
	genesis := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis"),
			ParentSelector: []byte{},
			Prover:         provers[0],
		},
	}

	err = atr.Insert(ctx, genesis)
	require.NoError(t, err)

	// Build chain with alternating provers
	prevOutput := genesis.Header.Output
	for i := 1; i <= 3; i++ {
		frame := &protobufs.AppShardFrame{
			Header: &protobufs.FrameHeader{
				Address:        address,
				FrameNumber:    uint64(i),
				Timestamp:      int64(1000 + i*1000),
				Difficulty:     uint32(100 + i*10),
				Output:         []byte(fmt.Sprintf("frame%d", i)),
				ParentSelector: computeAppPoseidonHash(prevOutput),
				Prover:         provers[i%len(provers)],
			},
		}

		err = atr.Insert(ctx, frame)
		require.NoError(t, err)

		prevOutput = frame.Header.Output
	}

	// Verify final head
	head, err := atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(3), head.Header.FrameNumber)

	// Verify lineage
	lineage, err := atr.GetLineage()
	require.NoError(t, err)
	assert.Len(t, lineage, 4)

	// Check prover rotation
	for i, frame := range lineage {
		assert.Equal(t, provers[i%len(provers)], frame.Header.Prover)
	}
}

// TestAppTimeReel_ComplexForkWithOutOfOrderInsertion tests the scenario:
// Insert 1, then insert 3', then insert 3, then insert 2, then insert 3”, then insert 2'.
// Expected: 1 -> 2' -> 3' should win with perfect prover distances
func TestAppTimeReel_ComplexForkWithOutOfOrderInsertion(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	address := []byte("test_app_address")

	// Set up prover registry with specific expected provers for each parent
	proverRegistry := new(mocks.MockProverRegistry)

	// For genesis (empty parent selector), frame 1's prover is expected
	var genesisSelector [32]byte
	proverRegistry.On("GetNextProver", genesisSelector, mock.Anything).Return([]byte("prover1"), nil)
	proverRegistry.On("GetOrderedProvers", genesisSelector, mock.Anything).Return([][]byte{[]byte("prover1")}, nil)

	// For frame 1's output as parent, frame 2' prover is the expected one
	frame1Output := []byte("frame1_output")
	computedSelector1 := computeAppPoseidonHash(frame1Output)
	var selector1 [32]byte
	copy(selector1[:], computedSelector1)
	proverRegistry.On("GetNextProver", selector1, mock.Anything).Return([]byte("prover2prime"), nil)
	proverRegistry.On("GetOrderedProvers", selector1, mock.Anything).Return([][]byte{
		[]byte("prover2prime"),       // distance 0
		[]byte("prover2"),            // distance 1
		[]byte("prover3"),            // distance 2
		[]byte("prover3doubleprime"), // distance 3
	}, nil)

	// For frame 2's output as parent, frame 3 prover is expected
	frame2Output := []byte("frame2_output")
	computedSelector2 := computeAppPoseidonHash(frame2Output)
	var selector2 [32]byte
	copy(selector2[:], computedSelector2)
	proverRegistry.On("GetNextProver", selector2, mock.Anything).Return([]byte("prover3"), nil)
	proverRegistry.On("GetOrderedProvers", selector2, mock.Anything).Return([][]byte{
		[]byte("prover3"),            // distance 0
		[]byte("prover3doubleprime"), // distance 1
		[]byte("prover2prime"),       // distance 2
		[]byte("prover2"),            // distance 3
	}, nil)

	// For frame 2' output as parent, frame 3' prover is expected
	frame2PrimeOutput := []byte("frame2prime_output")
	computedSelector2Prime := computeAppPoseidonHash(frame2PrimeOutput)
	var selector2Prime [32]byte
	copy(selector2Prime[:], computedSelector2Prime)
	proverRegistry.On("GetNextProver", selector2Prime, mock.Anything).Return([]byte("prover3prime"), nil)
	proverRegistry.On("GetOrderedProvers", selector2Prime, mock.Anything).Return([][]byte{
		[]byte("prover3prime"),       // distance 0
		[]byte("prover3doubleprime"), // distance 1
		[]byte("prover2prime"),       // distance 2
		[]byte("prover2"),            // distance 3
	}, nil)

	// Default behavior for unknown parent selectors
	proverRegistry.On("GetNextProver", mock.Anything, mock.Anything).Return(nil, errors.New("unknown parent selector"))
	proverRegistry.On("GetOrderedProvers", mock.Anything, mock.Anything).Return(nil, errors.New("unknown parent selector"))

	s := setupTestClockStore(t)
	atr, err := NewAppTimeReel(logger, address, proverRegistry, s, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()
	eventCh := atr.GetEventCh()

	// Collect all events
	var eventsMu sync.Mutex
	events := make([]AppEvent, 0)
	go func() {
		for event := range eventCh {
			eventsMu.Lock()
			events = append(events, event)
			eventsMu.Unlock()
			t.Logf("Event: Type=%d, Frame=%d, Message=%s",
				event.Type,
				event.Frame.Header.FrameNumber,
				event.Message)
		}
	}()

	// Create all frames first
	genesis := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    0,
			Timestamp:      time.Now().UnixMilli() - 5000,
			Difficulty:     100,
			Output:         []byte("genesis_output"),
			ParentSelector: []byte{},
			Prover:         []byte("prover0"),
		},
	}

	frame1 := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      time.Now().UnixMilli() - 4000,
			Difficulty:     110,
			Output:         frame1Output,
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Prover:         []byte("prover1"), // Expected prover (distance 0)
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00001111}, // 4 signers
			},
		},
	}

	frame2 := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    2,
			Timestamp:      time.Now().UnixMilli() - 3000,
			Difficulty:     120,
			Output:         frame2Output,
			ParentSelector: computeAppPoseidonHash(frame1.Header.Output),
			Prover:         []byte("prover2"), // Not expected prover (distance 1)
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00000011}, // 4 signers
			},
		},
	}

	frame2Prime := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    2,
			Timestamp:      time.Now().UnixMilli() - 2900, // Later timestamp but expected prover
			Difficulty:     120,
			Output:         frame2PrimeOutput,
			ParentSelector: computeAppPoseidonHash(frame1.Header.Output),
			Prover:         []byte("prover2prime"), // Expected prover (distance 0)
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11110000}, // 4 signers, different bits to avoid equivocation
			},
		},
	}

	frame3 := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    3,
			Timestamp:      time.Now().UnixMilli() - 2000,
			Difficulty:     130,
			Output:         []byte("frame3_output"),
			ParentSelector: computeAppPoseidonHash(frame2.Header.Output),
			Prover:         []byte("prover3"), // Expected prover for frame2 (distance 0)
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00001100}, // 2 signers
			},
		},
	}

	frame3Prime := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    3,
			Timestamp:      time.Now().UnixMilli() - 1900,
			Difficulty:     130,
			Output:         []byte("frame3prime_output"),
			ParentSelector: computeAppPoseidonHash(frame2Prime.Header.Output),
			Prover:         []byte("prover3prime"), // Expected prover for frame2' (distance 0)
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11110000}, // 4 signers, different bits
			},
		},
	}

	frame3DoublePrime := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    3,
			Timestamp:      time.Now().UnixMilli() - 1900,
			Difficulty:     130,
			Output:         []byte("frame3doubleprime_output"),
			ParentSelector: computeAppPoseidonHash(frame2Prime.Header.Output),
			Prover:         []byte("prover3doubleprime"), // Not expected prover for frame2' (distance 1)
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00000011}, // 2 signers
			},
		},
	}

	// Now insert in the specified order: 1, 3', 3, 2, 3'', 2'

	// Step 1: Insert genesis first (needed as base)
	err = atr.Insert(ctx, genesis)
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	// Step 2: Insert frame 1
	t.Log("Inserting frame 1")
	err = atr.Insert(ctx, frame1)
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	// Step 3: Insert frame 3' (should go to pending since 2' doesn't exist yet)
	t.Log("Inserting frame 3'")
	err = atr.Insert(ctx, frame3Prime)
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	// Verify 3' is in pending
	pending := atr.GetPendingFrames()
	assert.True(t, len(pending) > 0, "frame 3' should be in pending")

	// Step 4: Insert frame 3 (should also go to pending since 2 doesn't exist yet)
	t.Log("Inserting frame 3")
	err = atr.Insert(ctx, frame3)
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	// Step 5: Insert frame 2 (this should complete the 1->2->3 chain)
	t.Log("Inserting frame 2")
	err = atr.Insert(ctx, frame2)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond) // Give more time for processing

	// Check head should be 3 now
	head, err := atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(3), head.Header.FrameNumber)
	assert.Equal(t, []byte("frame3_output"), head.Header.Output, "chain 1->2->3 should be head")

	// Step 6: Insert frame 3'' (another competing frame on 2')
	t.Log("Inserting frame 3''")
	err = atr.Insert(ctx, frame3DoublePrime)
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	// Step 7: Insert frame 2' (this completes the 1->2'->3' and 1->2'->3'' chains)
	t.Log("Inserting frame 2'")
	err = atr.Insert(ctx, frame2Prime)
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond) // Give ample time for fork choice evaluation

	// Final verification: 1->2'->3' should win because:
	// - Frame 1: distance 0 (expected prover)
	// - Frame 2': distance 0 (expected prover) vs Frame 2: distance 1
	// - Frame 3': distance 0 (expected prover) with 4 signers vs Frame 3'': distance 1 with 2 signers
	head, err = atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(3), head.Header.FrameNumber)
	assert.Equal(t, []byte("frame3prime_output"), head.Header.Output, "chain 1->2'->3' should win")

	// Verify the lineage is correct
	lineage, err := atr.GetLineage()
	require.NoError(t, err)
	require.Len(t, lineage, 4) // genesis -> 1 -> 2' -> 3'
	assert.Equal(t, []byte("genesis_output"), lineage[0].Header.Output)
	assert.Equal(t, frame1Output, lineage[1].Header.Output)
	assert.Equal(t, frame2PrimeOutput, lineage[2].Header.Output)
	assert.Equal(t, []byte("frame3prime_output"), lineage[3].Header.Output)

	// Check that we got fork detection events
	eventsMu.Lock()
	forkEvents := 0
	for _, event := range events {
		if event.Type == TimeReelEventForkDetected {
			forkEvents++
			t.Logf("Fork event: %s", event.Message)
		}
	}
	eventsMu.Unlock()

	assert.Greater(t, forkEvents, 0, "should have detected at least one fork")
}

func TestAppTimeReel_TreePruning(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	address := []byte("test_app_address")
	s := setupTestClockStore(t)
	atr, err := NewAppTimeReel(logger, address, createTestProverRegistry(true), s, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()

	// Insert genesis
	genesis := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis"),
			ParentSelector: []byte{},
			Prover:         []byte("prover1"),
		},
	}

	err = atr.Insert(ctx, genesis)
	require.NoError(t, err)

	// Build a long chain that will trigger pruning (370 frames total)
	prevOutput := genesis.Header.Output
	for i := 1; i <= 370; i++ {
		frame := &protobufs.AppShardFrame{
			Header: &protobufs.FrameHeader{
				Address:        address,
				FrameNumber:    uint64(i),
				Timestamp:      int64(1000 + i*1000),
				Difficulty:     uint32(100 + i),
				Output:         []byte(fmt.Sprintf("frame%d", i)),
				ParentSelector: computeAppPoseidonHash(prevOutput),
				Prover:         []byte(fmt.Sprintf("prover%d", i%3+1)),
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

func TestAppTimeReel_TreePruningWithForks(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	address := []byte("test_app_address")
	s := setupTestClockStore(t)
	atr, err := NewAppTimeReel(logger, address, createTestProverRegistry(true), s, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()

	// Insert genesis
	genesis := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis"),
			ParentSelector: []byte{},
			Prover:         []byte("prover1"),
		},
	}

	err = atr.Insert(ctx, genesis)
	require.NoError(t, err)

	// Build main chain for 365 frames
	prevOutput := genesis.Header.Output
	var frame5 *protobufs.AppShardFrame
	for i := 1; i <= 365; i++ {
		frame := &protobufs.AppShardFrame{
			Header: &protobufs.FrameHeader{
				Address:        address,
				FrameNumber:    uint64(i),
				Timestamp:      int64(1000 + i*1000),
				Difficulty:     uint32(100 + i),
				Output:         []byte(fmt.Sprintf("main_frame%d", i)),
				ParentSelector: computeAppPoseidonHash(prevOutput),
				Prover:         []byte("main_prover"),
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
	forkFrame := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    6,
			Timestamp:      6000,
			Difficulty:     106,
			Output:         []byte("fork_frame6"),
			ParentSelector: computeAppPoseidonHash(frame5.Header.Output),
			Prover:         []byte("fork_prover"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00000001}, // Fewer signatures than main chain
			},
		},
	}

	err = atr.Insert(ctx, forkFrame)
	require.NoError(t, err)

	// Continue main chain for 375 more frames to trigger deep pruning
	for i := 366; i <= 740; i++ {
		frame := &protobufs.AppShardFrame{
			Header: &protobufs.FrameHeader{
				Address:        address,
				FrameNumber:    uint64(i),
				Timestamp:      int64(1000 + i*1000),
				Difficulty:     uint32(100 + i),
				Output:         []byte(fmt.Sprintf("main_frame%d", i)),
				ParentSelector: computeAppPoseidonHash(prevOutput),
				Prover:         []byte("main_prover"),
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

// TestAppTimeReel_ForkChoiceInsertionOrder tests that fork choice works regardless of insertion order
func TestAppTimeReel_ForkChoiceInsertionOrder(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	address := []byte("test_app_address")
	reg := createTestProverRegistry(false)
	s := setupTestClockStore(t)
	atr, err := NewAppTimeReel(logger, address, reg, s, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()
	eventCh := atr.GetEventCh()

	// Drain any existing events
	for {
		select {
		case <-eventCh:
		case <-time.After(10 * time.Millisecond):
			goto drained
		}
	}
drained:

	// Insert genesis
	genesis := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis_output"),
			ParentSelector: []byte{},
			Prover:         []byte("prover1"),
		},
	}
	reg.On("GetNextProver", [32]byte{}, mock.Anything).Return([]byte("prover1"), nil)
	reg.On("GetOrderedProvers", [32]byte{}, mock.Anything).Return([][]byte{
		[]byte("prover1"),
		[]byte("prover2"),
		[]byte("prover3"),
		[]byte("prover4"),
		[]byte("prover5"),
		[]byte("prover6"),
		[]byte("prover7"),
		[]byte("prover8"),
	}, nil)

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
	frame2B := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    2,
			Timestamp:      3000,
			Difficulty:     120,
			Output:         []byte("frame2B_output"),
			ParentSelector: []byte("placeholder_for_1B"),
			Prover:         []byte("prover2"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11111100}, // 6 signers (very strong)
			},
		},
	}

	// Insert the WEAKER branch (1A -> 2A) first, which should become head initially
	frame1A := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1A_output"),
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Prover:         []byte("prover8"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00000011}, // 2 signers (weak)
			},
		},
	}
	reg.On("GetNextProver", [32]byte(computeAppPoseidonHash(genesis.Header.Output)), mock.Anything).Return([]byte("prover2"), nil)
	reg.On("GetOrderedProvers", [32]byte(computeAppPoseidonHash(genesis.Header.Output)), mock.Anything).Return([][]byte{
		[]byte("prover2"),
		[]byte("prover1"),
		[]byte("prover3"),
		[]byte("prover4"),
		[]byte("prover5"),
		[]byte("prover6"),
		[]byte("prover7"),
		[]byte("prover8"),
	}, nil)

	frame2A := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    2,
			Timestamp:      3000,
			Difficulty:     120,
			Output:         []byte("frame2A_output"),
			ParentSelector: computeAppPoseidonHash(frame1A.Header.Output),
			Prover:         []byte("prover7"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00000011}, // 2 signers (weak)
			},
		},
	}
	reg.On("GetNextProver", [32]byte(computeAppPoseidonHash(frame1A.Header.Output)), mock.Anything).Return([]byte("prover2"), nil)
	reg.On("GetOrderedProvers", [32]byte(computeAppPoseidonHash(frame1A.Header.Output)), mock.Anything).Return([][]byte{
		[]byte("prover2"),
		[]byte("prover1"),
		[]byte("prover3"),
		[]byte("prover4"),
		[]byte("prover5"),
		[]byte("prover6"),
		[]byte("prover7"),
		[]byte("prover8"),
	}, nil)

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
	frame1B := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2100,
			Difficulty:     110,
			Output:         []byte("frame1B_output"),
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Prover:         []byte("prover2"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11111100}, // 6 signers (strong)
			},
		},
	}

	// Update frame2B's parent selector now that we know frame1B's output
	frame2B.Header.ParentSelector = computeAppPoseidonHash(frame1B.Header.Output)
	reg.On("GetNextProver", [32]byte(computeAppPoseidonHash(frame1B.Header.Output)), mock.Anything).Return([]byte("prover2"), nil)
	reg.On("GetOrderedProvers", [32]byte(computeAppPoseidonHash(frame1B.Header.Output)), mock.Anything).Return([][]byte{
		[]byte("prover2"),
		[]byte("prover1"),
		[]byte("prover3"),
		[]byte("prover4"),
		[]byte("prover5"),
		[]byte("prover6"),
		[]byte("prover7"),
		[]byte("prover8"),
	}, nil)

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

// TestAppTimeReel_ForkEventsWithReplay tests that fork events include common ancestor and replay
func TestAppTimeReel_ForkEventsWithReplay(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	address := []byte("test_app_address")
	s := setupTestClockStore(t)
	atr, err := NewAppTimeReel(logger, address, createTestProverRegistry(true), s, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()
	eventCh := atr.GetEventCh()

	// Collect all events
	var eventsMu sync.Mutex
	events := make([]AppEvent, 0)
	go func() {
		for event := range eventCh {
			eventsMu.Lock()
			events = append(events, event)
			eventsMu.Unlock()
		}
	}()

	// Build initial chain: 0 -> 1 -> 2 -> 3
	genesis := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis"),
			ParentSelector: []byte{},
			Prover:         []byte("prover1"),
		},
	}

	frame1 := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1"),
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Prover:         []byte("prover1"),
		},
	}

	frame2 := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    2,
			Timestamp:      3000,
			Difficulty:     120,
			Output:         []byte("frame2"),
			ParentSelector: computeAppPoseidonHash(frame1.Header.Output),
			Prover:         []byte("prover1"),
		},
	}

	frame3 := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    3,
			Timestamp:      4000,
			Difficulty:     130,
			Output:         []byte("frame3"),
			ParentSelector: computeAppPoseidonHash(frame2.Header.Output),
			Prover:         []byte("prover1"),
		},
	}

	// Insert initial chain
	for _, frame := range []*protobufs.AppShardFrame{genesis, frame1, frame2, frame3} {
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
	frame2Prime := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    2,
			Timestamp:      2900, // Earlier timestamp
			Difficulty:     120,
			Output:         []byte("frame2_prime"),
			ParentSelector: computeAppPoseidonHash(frame1.Header.Output),
			Prover:         []byte("prover2"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11111111}, // 8 signers (much stronger)
			},
		},
	}

	frame3Prime := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    3,
			Timestamp:      3900,
			Difficulty:     130,
			Output:         []byte("frame3_prime"),
			ParentSelector: computeAppPoseidonHash(frame2Prime.Header.Output),
			Prover:         []byte("prover2"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11111111}, // 8 signers
			},
		},
	}

	frame4Prime := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    4,
			Timestamp:      4900,
			Difficulty:     140,
			Output:         []byte("frame4_prime"),
			ParentSelector: computeAppPoseidonHash(frame3Prime.Header.Output),
			Prover:         []byte("prover2"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11111111}, // 8 signers
			},
		},
	}

	// Insert stronger fork - this should trigger a reorganization
	for _, frame := range []*protobufs.AppShardFrame{frame2Prime, frame3Prime, frame4Prime} {
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
	collectedEvents := make([]AppEvent, len(events))
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

// TestAppTimeReel_ComprehensiveEquivocation tests equivocation detection thoroughly
func TestAppTimeReel_ComprehensiveEquivocation(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	address := []byte("test_app_address")
	s := setupTestClockStore(t)
	atr, err := NewAppTimeReel(logger, address, createTestProverRegistry(true), s, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()
	eventCh := atr.GetEventCh()

	// Collect equivocation events
	var equivocationEvents []AppEvent
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
	genesis := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    0,
			Timestamp:      1000,
			Difficulty:     100,
			Output:         []byte("genesis"),
			ParentSelector: []byte{},
			Prover:         []byte("prover1"),
		},
	}

	err = atr.Insert(ctx, genesis)
	require.NoError(t, err)

	// Insert valid frame 1
	frame1Valid := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1_valid"),
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Prover:         []byte("prover1"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00001111}, // Signers 0,1,2,3
			},
		},
	}

	err = atr.Insert(ctx, frame1Valid)
	require.NoError(t, err)

	// Test Case 1: Complete overlap - same signers, different content
	frame1Equivocation1 := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1_evil_complete"), // Different output
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Prover:         []byte("prover1"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00001111}, // Same signers 0,1,2,3
			},
		},
	}

	err = atr.Insert(ctx, frame1Equivocation1)
	assert.NoError(t, err)

	// Test Case 2: Partial overlap - some same signers
	frame1Equivocation2 := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1_evil_partial"),
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Prover:         []byte("prover2"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11000011}, // Signers 0,1,6,7 - overlap with 0,1
			},
		},
	}

	err = atr.Insert(ctx, frame1Equivocation2)
	assert.NoError(t, err)

	// Test Case 3: No overlap - should be allowed (fork)
	frame1Fork := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1_fork"),
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Prover:         []byte("prover3"),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00110000}, // Signers 4,5 - no overlap
			},
		},
	}

	err = atr.Insert(ctx, frame1Fork)
	assert.NoError(t, err, "should allow fork with no overlapping signers")

	// Wait for events to be processed
	time.Sleep(100 * time.Millisecond)

	// Verify we received exactly 2 equivocation events
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

// TestAppTimeReel_ProverRegistryForkChoice tests that fork choice prefers frames from expected provers
func TestAppTimeReel_ProverRegistryForkChoice(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	address := []byte("test_app_address")

	// Create a prover registry that expects specific provers
	proverRegistry := new(mocks.MockProverRegistry)

	// We'll compute the parent selector from genesis output
	genesisOutput := []byte("genesis")
	computedParentSelector := computeAppPoseidonHash(genesisOutput)
	var parentSelector [32]byte
	copy(parentSelector[:], computedParentSelector)

	t.Logf("Genesis output: %x", genesisOutput)
	t.Logf("Computed parent selector: %x", parentSelector)

	// For genesis parent selector, prover1 is the expected prover
	proverRegistry.On("GetNextProver", parentSelector, mock.Anything).Return([]byte("prover1"), nil)
	proverRegistry.On("GetOrderedProvers", parentSelector, mock.Anything).Return([][]byte{[]byte("prover1")}, nil)
	// Default behavior for unknown parent selectors
	proverRegistry.On("GetNextProver", mock.Anything, mock.Anything).Return(nil, errors.New("unknown parent selector"))
	proverRegistry.On("GetOrderedProvers", mock.Anything, mock.Anything).Return(nil, errors.New("unknown parent selector"))

	s := setupTestClockStore(t)
	atr, err := NewAppTimeReel(logger, address, proverRegistry, s, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()
	eventCh := atr.GetEventCh()

	// Create genesis frame
	genesis := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:     address,
			FrameNumber: 0,
			Timestamp:   1000,
			Difficulty:  100,
			Output:      []byte("genesis"),
		},
	}

	err = atr.Insert(ctx, genesis)
	require.NoError(t, err)

	// Drain genesis event
	select {
	case <-eventCh:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for genesis event")
	}

	// Create two competing frames at frame 1
	frame1a := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     100,
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Output:         []byte("frame1a"),
			Prover:         []byte("prover1"), // Expected prover
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Signature: make([]byte, 74),
				PublicKey: &protobufs.BLS48581G2PublicKey{
					KeyValue: make([]byte, 585),
				},
				Bitmask: []byte{0xff, 0xff}, // 16 signers
			},
		},
	}

	frame1b := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     100,
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Output:         []byte("frame1b"),
			Prover:         []byte("wrong_prover"), // Not the expected prover
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Signature: make([]byte, 74),
				PublicKey: &protobufs.BLS48581G2PublicKey{
					KeyValue: make([]byte, 585),
				},
				Bitmask: []byte{0x00, 0x00, 0xff}, // Completely different signers to avoid equivocation
			},
		},
	}

	// Insert frame with wrong prover first
	err = atr.Insert(ctx, frame1b)
	require.NoError(t, err)

	// Should become head initially
	select {
	case event := <-eventCh:
		assert.Equal(t, TimeReelEventNewHead, event.Type)
		assert.Equal(t, frame1b.Header.Output, event.Frame.Header.Output)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for frame1b event")
	}

	// Insert frame with correct prover
	err = atr.Insert(ctx, frame1a)
	require.NoError(t, err)

	// Should trigger fork choice and frame1a should win
	select {
	case event := <-eventCh:
		assert.Equal(t, TimeReelEventForkDetected, event.Type)
		assert.Equal(t, frame1a.Header.Output, event.Frame.Header.Output)
		assert.Equal(t, frame1b.Header.Output, event.OldHead.Header.Output)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for fork event")
	}

	// Verify head is now frame1a
	head, err := atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, frame1a.Header.Output, head.Header.Output)
}

// TestAppTimeReel_ProverRegistryWithOrderedProvers tests fork choice with ordered provers
func TestAppTimeReel_ProverRegistryWithOrderedProvers(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	address := []byte("test_app_address")

	// Create a prover registry that returns ordered provers
	proverRegistry := new(mocks.MockProverRegistry)

	// For parent1, prover1 is the primary, prover2 is secondary, prover3 is tertiary
	orderedProvers := [][]byte{
		[]byte("prover1"),
		[]byte("prover2"),
		[]byte("prover3"),
	}

	// The parent selector gets computed from genesis output
	genesisOutput := []byte("genesis")
	computedParentSelector := computeAppPoseidonHash(genesisOutput)
	var parentSelector [32]byte
	copy(parentSelector[:], computedParentSelector)

	proverRegistry.On("GetNextProver", parentSelector, mock.Anything).Return([]byte("prover1"), nil)
	proverRegistry.On("GetOrderedProvers", parentSelector, mock.Anything).Return(orderedProvers, nil)
	// For any other parent selector (like empty for genesis), return a default
	proverRegistry.On("GetNextProver", mock.Anything, mock.Anything).Return([]byte("default_prover"), nil)
	proverRegistry.On("GetOrderedProvers", mock.Anything, mock.Anything).Return([][]byte{[]byte("default_prover")}, nil)

	s := setupTestClockStore(t)
	atr, err := NewAppTimeReel(logger, address, proverRegistry, s, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()

	// Create genesis frame
	genesis := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:     address,
			FrameNumber: 0,
			Timestamp:   1000,
			Difficulty:  100,
			Output:      []byte("genesis"),
		},
	}

	err = atr.Insert(ctx, genesis)
	require.NoError(t, err)

	// Create three competing frames with different provers from the ordered list
	frame1a := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     100,
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Output:         []byte("frame1a"),
			Prover:         []byte("prover3"), // Tertiary prover - highest distance
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Signature: make([]byte, 74),
				PublicKey: &protobufs.BLS48581G2PublicKey{
					KeyValue: make([]byte, 585),
				},
				Bitmask: []byte{0x00, 0x0f}, // Different signers to avoid equivocation
			},
		},
	}

	frame1b := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     100,
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Output:         []byte("frame1b"),
			Prover:         []byte("prover2"), // Secondary prover - medium distance
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Signature: make([]byte, 74),
				PublicKey: &protobufs.BLS48581G2PublicKey{
					KeyValue: make([]byte, 585),
				},
				Bitmask: []byte{0x0f, 0x00}, // Different signers to avoid equivocation
			},
		},
	}

	frame1c := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:        address,
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     100,
			ParentSelector: computeAppPoseidonHash(genesis.Header.Output),
			Output:         []byte("frame1c"),
			Prover:         []byte("prover1"), // Primary prover - lowest distance (best)
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Signature: make([]byte, 74),
				PublicKey: &protobufs.BLS48581G2PublicKey{
					KeyValue: make([]byte, 585),
				},
				Bitmask: []byte{0xf0, 0x00}, // Different signers to avoid equivocation
			},
		},
	}

	// Get event channel to monitor fork events
	eventCh := atr.GetEventCh()

	// Insert in reverse order of preference
	t.Logf("Inserting frame1a with prover: %s", frame1a.Header.Prover)
	err = atr.Insert(ctx, frame1a)
	require.NoError(t, err)

	// Drain events for frame1a
	drainEvents := func(label string) {
		for {
			select {
			case event := <-eventCh:
				t.Logf("Event after %s: Type=%d, Frame=%s", label, event.Type, event.Frame.Header.Output)
			case <-time.After(50 * time.Millisecond):
				t.Logf("No more events after %s", label)
				return
			}
		}
	}

	drainEvents("frame1a")

	// Check head after frame1a
	head1, _ := atr.GetHead()
	t.Logf("Head after frame1a: %s", head1.Header.Output)

	t.Logf("Inserting frame1b with prover: %s", frame1b.Header.Prover)
	err = atr.Insert(ctx, frame1b)
	require.NoError(t, err)

	drainEvents("frame1b")

	// Check head after frame1b
	head2, _ := atr.GetHead()
	t.Logf("Head after frame1b: %s", head2.Header.Output)

	t.Logf("Inserting frame1c with prover: %s", frame1c.Header.Prover)
	err = atr.Insert(ctx, frame1c)
	require.NoError(t, err)

	drainEvents("frame1c")

	// Check head after frame1c
	head3, _ := atr.GetHead()
	t.Logf("Head after frame1c: %s", head3.Header.Output)

	// After inserting all three frames, fork choice should have selected frame1c
	// because prover1 is the primary prover (distance 0)
	head, err := atr.GetHead()
	require.NoError(t, err)
	t.Logf("Final head output: %s", head.Header.Output)
	t.Logf("Expected output: %s", frame1c.Header.Output)

	// Verify frame1c is the head
	assert.Equal(t, frame1c.Header.Output, head.Header.Output, "frame1c should be selected as head due to lower prover distance")
}
