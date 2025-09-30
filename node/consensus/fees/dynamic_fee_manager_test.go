package fees

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
)

func TestDynamicFeeManager_BasicOperations(t *testing.T) {
	logger := zap.NewNop()
	inclusionProver := new(mocks.MockInclusionProver)
	manager := NewDynamicFeeManager(logger, inclusionProver)

	filter := []byte{0x01, 0x02, 0x03}

	// Test default fee when no votes
	fee, err := manager.GetNextFeeMultiplier(filter)
	require.NoError(t, err)
	assert.Equal(t, uint64(defaultFeeMultiplier), fee)

	// Add some votes
	votes := []uint64{10000, 12000, 11000, 10500, 11500}
	for i, vote := range votes {
		err = manager.AddFrameFeeVote(filter, uint64(i+1), vote)
		require.NoError(t, err)
	}

	// Check average
	fee, err = manager.GetNextFeeMultiplier(filter)
	require.NoError(t, err)
	expectedAvg := uint64(11000) // (10000 + 12000 + 11000 + 10500 + 11500) / 5
	assert.Equal(t, expectedAvg, fee)

	// Check window size
	size, err := manager.GetAverageWindowSize(filter)
	require.NoError(t, err)
	assert.Equal(t, 5, size)

	// Check history
	history, err := manager.GetVoteHistory(filter)
	require.NoError(t, err)
	assert.Equal(t, votes, history)
}

func TestDynamicFeeManager_SlidingWindow(t *testing.T) {
	logger := zap.NewNop()
	inclusionProver := new(mocks.MockInclusionProver)
	manager := NewDynamicFeeManager(logger, inclusionProver)

	filter := []byte{0x04, 0x05, 0x06}

	// Fill the window to capacity
	for i := uint64(1); i <= maxWindowSize; i++ {
		err := manager.AddFrameFeeVote(filter, i, i*1000)
		require.NoError(t, err)
	}

	size, err := manager.GetAverageWindowSize(filter)
	require.NoError(t, err)
	assert.Equal(t, maxWindowSize, size)

	// Add one more vote - should drop the oldest
	err = manager.AddFrameFeeVote(filter, maxWindowSize+1, 999999)
	require.NoError(t, err)

	size, err = manager.GetAverageWindowSize(filter)
	require.NoError(t, err)
	assert.Equal(t, maxWindowSize, size)

	// Verify oldest vote was dropped
	history, err := manager.GetVoteHistory(filter)
	require.NoError(t, err)
	assert.Equal(t, maxWindowSize, len(history))
	assert.Equal(t, uint64(2000), history[0])                 // First vote should now be frame 2
	assert.Equal(t, uint64(999999), history[maxWindowSize-1]) // Last vote should be the new one
}

func TestDynamicFeeManager_OutOfOrderFrames(t *testing.T) {
	logger := zap.NewNop()
	inclusionProver := new(mocks.MockInclusionProver)
	manager := NewDynamicFeeManager(logger, inclusionProver)

	filter := []byte{0x07, 0x08, 0x09}

	// Add initial votes
	err := manager.AddFrameFeeVote(filter, 10, 10000)
	require.NoError(t, err)
	err = manager.AddFrameFeeVote(filter, 20, 20000)
	require.NoError(t, err)

	// Try to add an out-of-order frame
	err = manager.AddFrameFeeVote(filter, 15, 15000)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "is not newer than last frame")

	// Try to add duplicate frame
	err = manager.AddFrameFeeVote(filter, 20, 25000)
	assert.Error(t, err)
}

func TestDynamicFeeManager_MultipleFilters(t *testing.T) {
	logger := zap.NewNop()
	inclusionProver := new(mocks.MockInclusionProver)
	manager := NewDynamicFeeManager(logger, inclusionProver)

	filter1 := []byte{0x01}
	filter2 := []byte{0x02}
	filter3 := []byte{0x03}

	// Add different votes to different filters
	filters := [][]byte{filter1, filter2, filter3}
	baseVotes := []uint64{10000, 20000, 30000}

	for i, filter := range filters {
		for j := uint64(1); j <= 10; j++ {
			err := manager.AddFrameFeeVote(filter, j, baseVotes[i]+j*100)
			require.NoError(t, err)
		}
	}

	// Check that each filter has its own average
	expectedAvgs := []uint64{10550, 20550, 30550} // Average of base + (1+2+...+10)*100/10

	for i, filter := range filters {
		fee, err := manager.GetNextFeeMultiplier(filter)
		require.NoError(t, err)
		assert.Equal(t, expectedAvgs[i], fee)
	}
}

func TestDynamicFeeManager_PruneOldData(t *testing.T) {
	logger := zap.NewNop()
	impl := &DynamicFeeManager{
		logger:     logger,
		filterData: make(map[string]*filterFeeData),
	}

	// Add data with different last updated times
	now := time.Now()

	// Recent filter
	impl.filterData["recent"] = &filterFeeData{
		votes:       []feeVote{{frameNumber: 1, feeMultiplierVote: 10000}},
		sumVotes:    10000,
		lastUpdated: now,
	}

	// Old filter (2 hours ago)
	impl.filterData["old"] = &filterFeeData{
		votes:       []feeVote{{frameNumber: 1, feeMultiplierVote: 20000}},
		sumVotes:    20000,
		lastUpdated: now.Add(-2 * time.Hour),
	}

	// Very old filter (5 hours ago)
	impl.filterData["very_old"] = &filterFeeData{
		votes:       []feeVote{{frameNumber: 1, feeMultiplierVote: 30000}},
		sumVotes:    30000,
		lastUpdated: now.Add(-5 * time.Hour),
	}

	// Prune data older than 1 hour (to keep "recent" but remove "old" and "very_old")
	err := impl.PruneOldData(1 * 60 * 60 * 1000) // 1 hour in milliseconds
	require.NoError(t, err)

	// Check that only recent filter remains
	assert.Equal(t, 1, len(impl.filterData))
	_, exists := impl.filterData["recent"]
	assert.True(t, exists)
	_, exists = impl.filterData["old"]
	assert.False(t, exists)
	_, exists = impl.filterData["very_old"]
	assert.False(t, exists)
}

func TestDynamicFeeManager_AccuracyWithLargeNumbers(t *testing.T) {
	logger := zap.NewNop()
	inclusionProver := new(mocks.MockInclusionProver)
	manager := NewDynamicFeeManager(logger, inclusionProver)

	filter := []byte{0x0A, 0x0B}

	// Test with large fee multipliers to ensure no overflow
	largeVotes := []uint64{
		1000000000, // 1 billion
		2000000000, // 2 billion
		1500000000, // 1.5 billion
		1800000000, // 1.8 billion
		1200000000, // 1.2 billion
	}

	for i, vote := range largeVotes {
		err := manager.AddFrameFeeVote(filter, uint64(i+1), vote)
		require.NoError(t, err)
	}

	fee, err := manager.GetNextFeeMultiplier(filter)
	require.NoError(t, err)

	// Expected average: (1 + 2 + 1.5 + 1.8 + 1.2) billion / 5 = 1.5 billion
	expectedAvg := uint64(1500000000)
	assert.Equal(t, expectedAvg, fee)
}

func TestDynamicFeeManager_MinimalRoundingError(t *testing.T) {
	logger := zap.NewNop()
	inclusionProver := new(mocks.MockInclusionProver)
	manager := NewDynamicFeeManager(logger, inclusionProver)

	filter := []byte{0x0C, 0x0D}

	// Test with numbers that would cause rounding in floating point
	// but should be exact with integer arithmetic
	votes := []uint64{
		10001, 10002, 10003, 10004, 10005,
	}

	for i, vote := range votes {
		err := manager.AddFrameFeeVote(filter, uint64(i+1), vote)
		require.NoError(t, err)
	}

	fee, err := manager.GetNextFeeMultiplier(filter)
	require.NoError(t, err)

	// Expected average: (10001 + 10002 + 10003 + 10004 + 10005) / 5 = 10003
	expectedAvg := uint64(10003)
	assert.Equal(t, expectedAvg, fee)
}

func TestDynamicFeeManager_EmptyFilter(t *testing.T) {
	logger := zap.NewNop()
	inclusionProver := new(mocks.MockInclusionProver)
	manager := NewDynamicFeeManager(logger, inclusionProver)

	// Test with empty filter (global)
	emptyFilter := []byte{}

	err := manager.AddFrameFeeVote(emptyFilter, 1, 15000)
	require.NoError(t, err)

	fee, err := manager.GetNextFeeMultiplier(emptyFilter)
	require.NoError(t, err)
	assert.Equal(t, uint64(15000), fee)
}

func TestDynamicFeeManager_RewindToFrame(t *testing.T) {
	logger := zap.NewNop()
	inclusionProver := new(mocks.MockInclusionProver)
	manager := NewDynamicFeeManager(logger, inclusionProver)

	filter := []byte{0x10, 0x11}

	// Add votes for frames 1-10
	for i := uint64(1); i <= 10; i++ {
		err := manager.AddFrameFeeVote(filter, i, i*1000)
		require.NoError(t, err)
	}

	// Verify initial state
	size, err := manager.GetAverageWindowSize(filter)
	require.NoError(t, err)
	assert.Equal(t, 10, size)

	// Rewind to frame 7 (should remove frames 8, 9, 10)
	removed, err := manager.RewindToFrame(filter, 7)
	require.NoError(t, err)
	assert.Equal(t, 3, removed)

	// Verify remaining votes
	size, err = manager.GetAverageWindowSize(filter)
	require.NoError(t, err)
	assert.Equal(t, 7, size)

	// Verify history contains only frames 1-7
	history, err := manager.GetVoteHistory(filter)
	require.NoError(t, err)
	assert.Equal(t, []uint64{1000, 2000, 3000, 4000, 5000, 6000, 7000}, history)

	// Verify average is correct
	fee, err := manager.GetNextFeeMultiplier(filter)
	require.NoError(t, err)
	expectedAvg := uint64(4000) // (1+2+3+4+5+6+7)*1000 / 7 = 28000/7 = 4000
	assert.Equal(t, expectedAvg, fee)
}

func TestDynamicFeeManager_RewindToFrame_EdgeCases(t *testing.T) {
	logger := zap.NewNop()
	inclusionProver := new(mocks.MockInclusionProver)
	manager := NewDynamicFeeManager(logger, inclusionProver)

	filter := []byte{0x12, 0x13}

	// Test: Rewind from empty filter
	removed, err := manager.RewindToFrame(filter, 100)
	require.NoError(t, err)
	assert.Equal(t, 0, removed)

	// Add some votes
	for i := uint64(1); i <= 5; i++ {
		err = manager.AddFrameFeeVote(filter, i*10, i*10000)
		require.NoError(t, err)
	}

	// Test: Rewind to a frame number higher than all votes (nothing removed)
	removed, err = manager.RewindToFrame(filter, 100)
	require.NoError(t, err)
	assert.Equal(t, 0, removed)

	size, err := manager.GetAverageWindowSize(filter)
	require.NoError(t, err)
	assert.Equal(t, 5, size)

	// Test: Rewind to frame 0 (remove all)
	removed, err = manager.RewindToFrame(filter, 0)
	require.NoError(t, err)
	assert.Equal(t, 5, removed)

	size, err = manager.GetAverageWindowSize(filter)
	require.NoError(t, err)
	assert.Equal(t, 0, size)

	// Verify default fee is returned when empty
	fee, err := manager.GetNextFeeMultiplier(filter)
	require.NoError(t, err)
	assert.Equal(t, uint64(defaultFeeMultiplier), fee)
}

func TestDynamicFeeManager_RewindToFrame_WithGaps(t *testing.T) {
	logger := zap.NewNop()
	inclusionProver := new(mocks.MockInclusionProver)
	manager := NewDynamicFeeManager(logger, inclusionProver)

	filter := []byte{0x14, 0x15}

	// Add votes with gaps in frame numbers
	frameNumbers := []uint64{5, 10, 15, 20, 25, 30}
	for _, fn := range frameNumbers {
		err := manager.AddFrameFeeVote(filter, fn, fn*1000)
		require.NoError(t, err)
	}

	// Rewind to frame 17 (should remove frames 20, 25, 30)
	removed, err := manager.RewindToFrame(filter, 17)
	require.NoError(t, err)
	assert.Equal(t, 3, removed)

	// Verify remaining votes
	history, err := manager.GetVoteHistory(filter)
	require.NoError(t, err)
	assert.Equal(t, []uint64{5000, 10000, 15000}, history)

	// Rewind to frame 12 (should remove frame 15)
	removed, err = manager.RewindToFrame(filter, 12)
	require.NoError(t, err)
	assert.Equal(t, 1, removed)

	history, err = manager.GetVoteHistory(filter)
	require.NoError(t, err)
	assert.Equal(t, []uint64{5000, 10000}, history)
}

func TestDynamicFeeManager_RewindToFrame_FullWindow(t *testing.T) {
	logger := zap.NewNop()
	inclusionProver := new(mocks.MockInclusionProver)
	manager := NewDynamicFeeManager(logger, inclusionProver)

	filter := []byte{0x16, 0x17}

	// Fill window to capacity
	for i := uint64(1); i <= 360; i++ {
		err := manager.AddFrameFeeVote(filter, i, 10000+i)
		require.NoError(t, err)
	}

	// Calculate sum before rewind
	sumBefore := uint64(0)
	for i := uint64(1); i <= 360; i++ {
		sumBefore += 10000 + i
	}
	avgBefore := sumBefore / 360

	fee, err := manager.GetNextFeeMultiplier(filter)
	require.NoError(t, err)
	assert.Equal(t, avgBefore, fee)

	// Rewind to frame 300 (remove newest 60 frames)
	removed, err := manager.RewindToFrame(filter, 300)
	require.NoError(t, err)
	assert.Equal(t, 60, removed)

	// Verify size
	size, err := manager.GetAverageWindowSize(filter)
	require.NoError(t, err)
	assert.Equal(t, 300, size)

	// Verify average updated correctly
	sumAfter := uint64(0)
	for i := uint64(1); i <= 300; i++ {
		sumAfter += 10000 + i
	}
	avgAfter := sumAfter / 300

	fee, err = manager.GetNextFeeMultiplier(filter)
	require.NoError(t, err)
	assert.Equal(t, avgAfter, fee)
}

func TestDynamicFeeManager_WindowFull360Frames(t *testing.T) {
	logger := zap.NewNop()
	inclusionProver := new(mocks.MockInclusionProver)
	manager := NewDynamicFeeManager(logger, inclusionProver)

	filter := []byte{0x0E, 0x0F}

	// Add exactly 360 frames with predictable values
	sum := uint64(0)
	for i := uint64(1); i <= 360; i++ {
		vote := i * 100
		sum += vote
		err := manager.AddFrameFeeVote(filter, i, vote)
		require.NoError(t, err)
	}

	// Verify average
	fee, err := manager.GetNextFeeMultiplier(filter)
	require.NoError(t, err)
	expectedAvg := sum / 360
	assert.Equal(t, expectedAvg, fee)

	// Verify window size
	size, err := manager.GetAverageWindowSize(filter)
	require.NoError(t, err)
	assert.Equal(t, 360, size)

	// Add one more frame
	newVote := uint64(100000)
	err = manager.AddFrameFeeVote(filter, 361, newVote)
	require.NoError(t, err)

	// Verify oldest was dropped
	fee, err = manager.GetNextFeeMultiplier(filter)
	require.NoError(t, err)
	// New sum = old sum - first vote + new vote
	newSum := sum - 100 + newVote
	newExpectedAvg := newSum / 360
	assert.Equal(t, newExpectedAvg, fee)
}
