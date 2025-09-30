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
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// TestGlobalTimeReel_MassiveEquivocationForkChoice tests a scenario where:
// - 200 frames are produced by one set of signers (bitmask 0b11100011)
// - Then 200 conflicting frames are produced by another set (bitmask 0b11111100)
// - The overlapping signers (0b11100000) should be detected as equivocating
// - Fork choice should still work, ignoring the equivocating signers
func TestGlobalTimeReel_MassiveEquivocationForkChoice(t *testing.T) {
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
	var equivocationEvents []GlobalEvent
	var forkEvents []GlobalEvent
	stopCollecting := make(chan struct{})

	go func() {
		for {
			select {
			case event := <-eventCh:
				eventsMu.Lock()
				switch event.Type {
				case TimeReelEventEquivocationDetected:
					equivocationEvents = append(equivocationEvents, event)
				case TimeReelEventForkDetected:
					forkEvents = append(forkEvents, event)
				}
				eventsMu.Unlock()
			case <-stopCollecting:
				return
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

	// Build chain A: 200 frames with bitmask 0b11100011 (signers 0,1,5,6,7)
	prevOutput := genesis.Header.Output
	for i := 1; i <= 200; i++ {
		frameA := &protobufs.GlobalFrame{
			Header: &protobufs.GlobalFrameHeader{
				FrameNumber:    uint64(i),
				Timestamp:      int64(1000 + i*1000),
				Difficulty:     uint32(100 + i),
				Output:         []byte(fmt.Sprintf("frameA_%d", i)),
				ParentSelector: computeGlobalPoseidonHash(prevOutput),
				PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
					Bitmask: []byte{0b11100011}, // Signers 0,1,5,6,7
				},
			},
		}

		err = atr.Insert(ctx, frameA)
		require.NoError(t, err)
		prevOutput = frameA.Header.Output
	}

	// Verify chain A is the head
	head, err := atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(200), head.Header.FrameNumber)
	assert.Equal(t, []byte("frameA_200"), head.Header.Output)

	// Now build chain B: 200 frames with bitmask 0b11111100 (signers 2,3,4,5,6,7)
	// This overlaps with chain A on signers 5,6,7 (0b11100000)
	prevOutput = genesis.Header.Output

	for i := 1; i <= 200; i++ {
		frameB := &protobufs.GlobalFrame{
			Header: &protobufs.GlobalFrameHeader{
				FrameNumber:    uint64(i),
				Timestamp:      int64(1000 + i*1000), // Same timestamps
				Difficulty:     uint32(100 + i),      // Same difficulty
				Output:         []byte(fmt.Sprintf("frameB_%d", i)),
				ParentSelector: computeGlobalPoseidonHash(prevOutput),
				PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
					Bitmask: []byte{0b11111100}, // Signers 2,3,4,5,6,7
				},
			},
		}

		err = atr.Insert(ctx, frameB)
		// Should now succeed even with equivocation
		assert.NoError(t, err, "Should accept frame despite equivocation at frame %d", i)
		prevOutput = frameB.Header.Output
	}

	// Wait for events to be processed
	time.Sleep(500 * time.Millisecond)
	close(stopCollecting)

	// Check equivocation events
	eventsMu.Lock()
	t.Logf("Received %d equivocation events", len(equivocationEvents))
	assert.Equal(t, 200, len(equivocationEvents), "should have 200 equivocation events")
	eventsMu.Unlock()

	// Fork choice should favor chain B
	// Chain A has 5 signers (0,1,5,6,7) but 5,6,7 equivocated = 2 valid signers
	// Chain B has 6 signers (2,3,4,5,6,7) but 5,6,7 equivocated = 3 valid signers
	// So chain B should win
	head, err = atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(200), head.Header.FrameNumber)
	// Check it's from chain B (output contains "frameB")
	assert.Contains(t, string(head.Header.Output), "frameB", "Head should be from chain B")

	// Check tree info
	info := atr.GetTreeInfo()
	t.Logf("Tree info after equivocation: %+v", info)
}

// TestGlobalTimeReel_EquivocationWithForkChoice tests fork choice when equivocating signers are excluded
func TestGlobalTimeReel_EquivocationWithForkChoice(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	s := setupTestClockStore(t)
	atr, err := NewGlobalTimeReel(logger, createTestProverRegistry(true), s, 99, true)
	require.NoError(t, err)

	err = atr.Start()
	require.NoError(t, err)
	defer atr.Stop()

	ctx := context.Background()
	eventCh := atr.GetEventCh()

	// Drain initial events
	select {
	case <-eventCh:
	case <-time.After(10 * time.Millisecond):
	}

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

	// Drain genesis event
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Create frame 1A with signers 0,1,2,3 (4 signers)
	frame1A := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1A"),
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b00001111}, // Signers 0,1,2,3
			},
		},
	}

	err = atr.Insert(ctx, frame1A)
	require.NoError(t, err)

	// Drain new head event
	select {
	case <-eventCh:
	case <-time.After(50 * time.Millisecond):
	}

	// Create frame 1B with signers 2,3,4,5,6,7 (6 signers, 2 overlap with 1A)
	frame1B := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			Timestamp:      2000,
			Difficulty:     110,
			Output:         []byte("frame1B"),
			ParentSelector: computeGlobalPoseidonHash(genesis.Header.Output),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11111100}, // Signers 2,3,4,5,6,7
			},
		},
	}

	// This should succeed now, but generate an equivocation event
	err = atr.Insert(ctx, frame1B)
	assert.NoError(t, err)

	// Wait for equivocation event
	select {
	case event := <-eventCh:
		assert.Equal(t, TimeReelEventEquivocationDetected, event.Type)
		assert.Contains(t, event.Message, "equivocation at frame 1")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for equivocation event")
	}

	// Fork choice should favor frame 1B
	// Frame 1A: 4 signers (0,1,2,3) but 2,3 equivocated = 2 valid signers
	// Frame 1B: 6 signers (2,3,4,5,6,7) but 2,3 equivocated = 4 valid signers
	// So frame 1B should win
	head, err := atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(1), head.Header.FrameNumber)
	assert.Equal(t, []byte("frame1B"), head.Header.Output, "Head should be frame 1B with more non-equivocating signers")
}

// TestGlobalTimeReel_NonOverlappingForks tests that non-overlapping forks work correctly
func TestGlobalTimeReel_NonOverlappingForks(t *testing.T) {
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

	// Build two non-overlapping chains
	// Chain A: signers 0,1,2,3 (lower half)
	// Chain B: signers 4,5,6,7 (upper half)

	// Chain A
	prevOutputA := genesis.Header.Output
	for i := 1; i <= 10; i++ {
		frameA := &protobufs.GlobalFrame{
			Header: &protobufs.GlobalFrameHeader{
				FrameNumber:    uint64(i),
				Timestamp:      int64(1000 + i*1000),
				Difficulty:     uint32(100 + i),
				Output:         []byte(fmt.Sprintf("frameA_%d", i)),
				ParentSelector: computeGlobalPoseidonHash(prevOutputA),
				PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
					Bitmask: []byte{0b00001111}, // Signers 0,1,2,3
				},
			},
		}
		err = atr.Insert(ctx, frameA)
		require.NoError(t, err)
		prevOutputA = frameA.Header.Output
	}

	// Chain B - should be allowed as there's no overlap
	prevOutputB := genesis.Header.Output
	for i := 1; i <= 10; i++ {
		frameB := &protobufs.GlobalFrame{
			Header: &protobufs.GlobalFrameHeader{
				FrameNumber:    uint64(i),
				Timestamp:      int64(1000 + i*1000),
				Difficulty:     uint32(100 + i),
				Output:         []byte(fmt.Sprintf("frameB_%d", i)),
				ParentSelector: computeGlobalPoseidonHash(prevOutputB),
				PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
					Bitmask: []byte{0b11110000}, // Signers 4,5,6,7
				},
			},
		}
		err = atr.Insert(ctx, frameB)
		require.NoError(t, err, "non-overlapping fork should be allowed")
		prevOutputB = frameB.Header.Output
	}

	// Both chains should exist
	framesAt10, err := atr.GetFramesByNumber(10)
	require.NoError(t, err)
	assert.Equal(t, 2, len(framesAt10), "should have 2 competing frames at height 10")

	// Head should be one of them (both have same number of signers)
	head, err := atr.GetHead()
	require.NoError(t, err)
	assert.Equal(t, uint64(10), head.Header.FrameNumber)
}
