package difficulty

import (
	"testing"
	"time"
)

func TestAsertDifficultyAdjuster_GetNextDifficulty(t *testing.T) {
	// Initialize with the specified anchor values
	anchorDifficulty := uint32(160000)
	anchorFrameNumber := uint64(244200)
	anchorParentTime := time.Now().Add(-15 * time.Second).UnixMilli()

	adjuster := &AsertDifficultyAdjuster{
		anchorFrameNumber: anchorFrameNumber,
		anchorParentTime:  anchorParentTime,
		anchorDifficulty:  anchorDifficulty,
	}

	tests := []struct {
		name               string
		currentFrameNumber uint64
		currentTime        int64
		expectedRange      [2]uint64 // min and max expected values
	}{
		{
			name:               "Same frame, same time - should return anchor difficulty",
			currentFrameNumber: anchorFrameNumber,
			currentTime:        anchorParentTime,
			expectedRange:      [2]uint64{159800, 160200}, // Allow small variance due to algorithm
		},
		{
			name:               "Next frame, ideal time elapsed",
			currentFrameNumber: anchorFrameNumber + 1,
			currentTime:        anchorParentTime + IDEAL_FRAME_TIME,
			expectedRange:      [2]uint64{159800, 160200}, // Should stay close to anchor
		},
		{
			name:               "10 frames later, ideal time elapsed",
			currentFrameNumber: anchorFrameNumber + 10,
			currentTime:        anchorParentTime + 10*IDEAL_FRAME_TIME,
			expectedRange:      [2]uint64{159800, 160200}, // Should stay close to anchor
		},
		{
			name:               "Next frame, double time elapsed (too slow)",
			currentFrameNumber: anchorFrameNumber + 1,
			currentTime:        anchorParentTime + 2*IDEAL_FRAME_TIME,
			expectedRange:      [2]uint64{159500, 160000}, // Difficulty should barely be impacted
		},
		{
			name:               "Next frame, half time elapsed (too fast)",
			currentFrameNumber: anchorFrameNumber + 1,
			currentTime:        anchorParentTime + IDEAL_FRAME_TIME/2,
			expectedRange:      [2]uint64{160000, 160500}, // Difficulty should barely be impacted
		},
		{
			name:               "100 frames later, significantly slower",
			currentFrameNumber: anchorFrameNumber + 100,
			currentTime:        anchorParentTime + 500*IDEAL_FRAME_TIME, // 500% slower
			expectedRange:      [2]uint64{100000, 110000},               // Difficulty should decrease significantly
		},
		{
			name:               "100 frames later, significantly faster",
			currentFrameNumber: anchorFrameNumber + 1000,
			currentTime:        anchorParentTime + 50*IDEAL_FRAME_TIME, // 500% faster
			expectedRange:      [2]uint64{380000, 400000},              // Difficulty should increase significantly
		},
		{
			name:               "Extreme case - very slow progress",
			currentFrameNumber: anchorFrameNumber + 100,
			currentTime:        anchorParentTime + 100000*IDEAL_FRAME_TIME,
			expectedRange:      [2]uint64{50000, 100000}, // Should decrease towards minimum
		},
		{
			name:               "Edge case - minimum difficulty clamp",
			currentFrameNumber: anchorFrameNumber + 1,
			currentTime:        anchorParentTime + 100000*IDEAL_FRAME_TIME, // Extremely slow
			expectedRange:      [2]uint64{50000, 50001},                    // Should clamp to minimum
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := adjuster.GetNextDifficulty(tt.currentFrameNumber, tt.currentTime)
			if result < tt.expectedRange[0] || result > tt.expectedRange[1] {
				t.Errorf("GetNextDifficulty() = %d, expected between %d and %d",
					result, tt.expectedRange[0], tt.expectedRange[1])
			}
		})
	}
}

func TestAsertDifficultyAdjuster_ExponentCalculation(t *testing.T) {
	// Test the exponent calculation specifically
	anchorDifficulty := uint32(160000)
	anchorFrameNumber := uint64(244200)
	anchorParentTime := time.Now().Add(-15 * time.Second).UnixMilli()

	adjuster := &AsertDifficultyAdjuster{
		anchorFrameNumber: anchorFrameNumber,
		anchorParentTime:  anchorParentTime,
		anchorDifficulty:  anchorDifficulty,
	}

	// Test case where exponent should be positive (time elapsed > expected)
	slowFrame := anchorFrameNumber + 100
	slowTime := anchorParentTime + 200*IDEAL_FRAME_TIME // Double the expected time
	slowDifficulty := adjuster.GetNextDifficulty(slowFrame, slowTime)

	// Test case where exponent should be negative (time elapsed < expected)
	fastFrame := anchorFrameNumber + 100
	fastTime := anchorParentTime + 50*IDEAL_FRAME_TIME // Half the expected time
	fastDifficulty := adjuster.GetNextDifficulty(fastFrame, fastTime)

	// Fast mining should result in higher difficulty
	if fastDifficulty <= slowDifficulty {
		t.Errorf("Fast mining difficulty (%d) should be higher than slow mining difficulty (%d)",
			fastDifficulty, slowDifficulty)
	}
}

func TestAsertDifficultyAdjuster_ConsistentBehavior(t *testing.T) {
	// Test that the algorithm produces consistent results
	anchorDifficulty := uint32(160000)
	anchorFrameNumber := uint64(244200)
	anchorParentTime := time.Now().Add(-15 * time.Second).UnixMilli()

	adjuster := &AsertDifficultyAdjuster{
		anchorFrameNumber: anchorFrameNumber,
		anchorParentTime:  anchorParentTime,
		anchorDifficulty:  anchorDifficulty,
	}

	// Run the same calculation multiple times to ensure deterministic behavior
	testFrame := anchorFrameNumber + 50
	testTime := anchorParentTime + 50*IDEAL_FRAME_TIME + 5000 // Slightly off ideal

	results := make([]uint64, 5)
	for i := 0; i < 5; i++ {
		results[i] = adjuster.GetNextDifficulty(testFrame, testTime)
	}

	// All results should be identical
	for i := 1; i < len(results); i++ {
		if results[i] != results[0] {
			t.Errorf("Inconsistent results: run %d returned %d, expected %d",
				i, results[i], results[0])
		}
	}
}

func TestAsertDifficultyAdjuster_LargeFrameJumps(t *testing.T) {
	// Test behavior with large frame number jumps
	anchorDifficulty := uint32(160000)
	anchorFrameNumber := uint64(244200)
	anchorParentTime := time.Now().Add(-15 * time.Second).UnixMilli()

	adjuster := &AsertDifficultyAdjuster{
		anchorFrameNumber: anchorFrameNumber,
		anchorParentTime:  anchorParentTime,
		anchorDifficulty:  anchorDifficulty,
	}

	// Test with a very large frame jump but proportional time
	largeJump := uint64(10000)
	largeJumpFrame := anchorFrameNumber + largeJump
	largeJumpTime := anchorParentTime + int64(largeJump)*IDEAL_FRAME_TIME

	result := adjuster.GetNextDifficulty(largeJumpFrame, largeJumpTime)

	// Should stay close to anchor difficulty since time is proportional
	if result < 159000 || result > 161000 {
		t.Errorf("Large proportional jump resulted in unexpected difficulty: %d", result)
	}
}

func TestAsertDifficultyAdjuster_NegativeTimeDelta(t *testing.T) {
	// Test edge case where current time might be before anchor time
	// (shouldn't happen in practice but good to test)
	anchorDifficulty := uint32(160000)
	anchorFrameNumber := uint64(244200)
	anchorParentTime := time.Now().Add(-15 * time.Second).UnixMilli()

	adjuster := &AsertDifficultyAdjuster{
		anchorFrameNumber: anchorFrameNumber,
		anchorParentTime:  anchorParentTime,
		anchorDifficulty:  anchorDifficulty,
	}

	// Current time is before anchor time
	result := adjuster.GetNextDifficulty(anchorFrameNumber+1, anchorParentTime-IDEAL_FRAME_TIME)

	// Should result in very high difficulty (frames coming too fast)
	if result <= uint64(anchorDifficulty) {
		t.Errorf("Negative time delta should increase difficulty, got %d", result)
	}
}

func BenchmarkAsertDifficultyAdjuster_GetNextDifficulty(b *testing.B) {
	anchorDifficulty := uint32(160000)
	anchorFrameNumber := uint64(244200)
	anchorParentTime := time.Now().Add(-15 * time.Second).UnixMilli()

	adjuster := &AsertDifficultyAdjuster{
		anchorFrameNumber: anchorFrameNumber,
		anchorParentTime:  anchorParentTime,
		anchorDifficulty:  anchorDifficulty,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = adjuster.GetNextDifficulty(
			anchorFrameNumber+uint64(i%1000),
			anchorParentTime+int64(i%1000)*IDEAL_FRAME_TIME,
		)
	}
}
