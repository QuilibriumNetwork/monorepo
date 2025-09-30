package time

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// TestGlobalTimeReel_SimpleEquivocation tests a simple equivocation scenario
func TestGlobalTimeReel_SimpleEquivocation(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	s := setupTestClockStore(t)
	globalReel, err := NewGlobalTimeReel(logger, createTestProverRegistry(true), s, 99, true)
	require.NoError(t, err)

	err = globalReel.Start()
	require.NoError(t, err)
	defer globalReel.Stop()

	// Insert genesis
	genesis := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    0,
			ParentSelector: []byte{},
			Output:         []byte{0},
		},
	}

	err = globalReel.Insert(context.Background(), genesis)
	require.NoError(t, err)

	parentSelector := computeGlobalPoseidonHash(genesis.Header.Output)

	// Insert frame 1A with signers 0,1,5,6,7 (bitmask 0b11100011)
	frame1A := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			ParentSelector: parentSelector,
			Output:         []byte{1},
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11100011},
			},
		},
	}

	err = globalReel.Insert(context.Background(), frame1A)
	require.NoError(t, err)

	// Insert frame 1B with signers 2,3,4,5,6,7 (bitmask 0b11111100)
	// This should cause equivocation for signers 5,6,7
	frame1B := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:    1,
			ParentSelector: parentSelector,
			Output:         []byte{2},
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Bitmask: []byte{0b11111100},
			},
		},
	}

	err = globalReel.Insert(context.Background(), frame1B)
	require.NoError(t, err, "Should accept frame despite equivocation")

	// Check equivocators are tracked
	globalReel.mu.RLock()
	equivocators := globalReel.equivocators[1]
	globalReel.mu.RUnlock()

	// Signers 5,6,7 should be marked as equivocators
	assert.True(t, equivocators[5], "Signer 5 should be equivocator")
	assert.True(t, equivocators[6], "Signer 6 should be equivocator")
	assert.True(t, equivocators[7], "Signer 7 should be equivocator")
	assert.False(t, equivocators[0], "Signer 0 should not be equivocator")
	assert.False(t, equivocators[1], "Signer 1 should not be equivocator")
	assert.False(t, equivocators[2], "Signer 2 should not be equivocator")
	assert.False(t, equivocators[3], "Signer 3 should not be equivocator")
	assert.False(t, equivocators[4], "Signer 4 should not be equivocator")

	// Check head - should be frame 1B
	// Frame 1A: 5 signers, but 3 equivocated = 2 valid
	// Frame 1B: 6 signers, but 3 equivocated = 3 valid
	head, err := globalReel.GetHead()
	require.NotNil(t, head)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), head.Header.FrameNumber)
	assert.Equal(t, []byte{2}, head.Header.Output, "Head should be frame 1B")
}
