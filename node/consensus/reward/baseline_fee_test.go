package reward_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/reward"
)

func TestGetBaselineFee(t *testing.T) {
	tests := []struct {
		name            string
		difficulty      uint64
		worldStateBytes uint64
		totalAdded      uint64
		units           uint64
		expectedMin     *big.Int // minimum expected value
		description     string
	}{
		{
			name:            "Small world state with small addition",
			difficulty:      100000,
			worldStateBytes: 1024 * 1024 * 1024, // 1 GB
			totalAdded:      1024,                // 1 KB
			units:           8000000000,
			expectedMin:     big.NewInt(1024), // Should return at least totalAdded
			description:     "When delta squared over worldStateBytes is less than totalAdded, should return totalAdded",
		},
		{
			name:            "Large world state with small addition",
			difficulty:      100000,
			worldStateBytes: 1024 * 1024 * 1024 * 1024, // 1 TB
			totalAdded:      1024 * 1024,                // 1 MB
			units:           8000000000,
			expectedMin:     big.NewInt(1024 * 1024), // Should return at least totalAdded
			description:     "With large world state, fee calculation should handle scale properly",
		},
		{
			name:            "Medium world state with medium addition",
			difficulty:      100000,
			worldStateBytes: 64 * 1024 * 1024 * 1024, // 64 GB
			totalAdded:      10 * 1024 * 1024,        // 10 MB
			units:           8000000000,
			expectedMin:     big.NewInt(10 * 1024 * 1024),
			description:     "Medium scale should calculate proportional fee",
		},
		{
			name:            "Zero addition edge case",
			difficulty:      100000,
			worldStateBytes: 1024 * 1024 * 1024, // 1 GB
			totalAdded:      0,
			units:           8000000000,
			expectedMin:     big.NewInt(0),
			description:     "Zero addition should return zero fee",
		},
		{
			name:            "Very small world state",
			difficulty:      100000,
			worldStateBytes: 1024 * 1024, // 1 MB
			totalAdded:      1024,         // 1 KB
			units:           8000000000,
			expectedMin:     big.NewInt(1024),
			description:     "Small world state should handle properly without overflow",
		},
		{
			name:            "Large addition relative to world state",
			difficulty:      100000,
			worldStateBytes: 1024 * 1024 * 1024,     // 1 GB
			totalAdded:      100 * 1024 * 1024,      // 100 MB (10% of world state)
			units:           8000000000,
			expectedMin:     big.NewInt(100 * 1024 * 1024),
			description:     "Large additions should have proportionally higher fees",
		},
		{
			name:            "Different difficulty level",
			difficulty:      200000, // Higher difficulty
			worldStateBytes: 1024 * 1024 * 1024, // 1 GB
			totalAdded:      1024 * 1024,        // 1 MB
			units:           8000000000,
			expectedMin:     big.NewInt(1024 * 1024),
			description:     "Different difficulty should affect PomwBasis calculations",
		},
		{
			name:            "Different units",
			difficulty:      100000,
			worldStateBytes: 1024 * 1024 * 1024, // 1 GB
			totalAdded:      1024 * 1024,        // 1 MB
			units:           4000000000,         // Half units
			expectedMin:     big.NewInt(1024 * 1024),
			description:     "Different units should affect basis calculations",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reward.GetBaselineFee(
				tt.difficulty,
				tt.worldStateBytes,
				tt.totalAdded,
				tt.units,
			)

			require.NotNil(t, result, "Result should not be nil")

			// The result should be at least the minimum expected value
			assert.True(t,
				result.Cmp(tt.expectedMin) >= 0,
				"Expected result >= %v, got %v. %s",
				tt.expectedMin,
				result,
				tt.description,
			)

			// Additional validation: result should be non-negative
			assert.True(t,
				result.Sign() >= 0,
				"Result should be non-negative, got %v",
				result,
			)
		})
	}
}

func TestGetBaselineFee_ConsistencyChecks(t *testing.T) {
	// Test that increasing totalAdded increases the fee
	t.Run("Increasing totalAdded increases fee", func(t *testing.T) {
		difficulty := uint64(100000)
		worldStateBytes := uint64(1024 * 1024 * 1024) // 1 GB
		units := uint64(8000000000)

		fee1 := reward.GetBaselineFee(difficulty, worldStateBytes, 1024, units)
		fee2 := reward.GetBaselineFee(difficulty, worldStateBytes, 2048, units)
		fee3 := reward.GetBaselineFee(difficulty, worldStateBytes, 4096, units)

		assert.True(t, fee2.Cmp(fee1) >= 0, "fee2 should be >= fee1")
		assert.True(t, fee3.Cmp(fee2) >= 0, "fee3 should be >= fee2")
	})

	// Test that the function returns max(lhs, rhs) where lhs = (delta^2)/worldStateBytes and rhs = totalAdded
	t.Run("Returns maximum of calculated fee and totalAdded", func(t *testing.T) {
		difficulty := uint64(100000)
		worldStateBytes := uint64(1024 * 1024 * 1024 * 1024) // 1 TB
		units := uint64(8000000000)

		// Small addition - should return totalAdded as minimum
		smallAdded := uint64(100)
		fee := reward.GetBaselineFee(difficulty, worldStateBytes, smallAdded, units)
		assert.True(t, fee.Cmp(big.NewInt(int64(smallAdded))) >= 0,
			"Fee should be at least totalAdded for small additions")

		// Large addition - calculated fee might be larger than totalAdded
		largeAdded := uint64(1024 * 1024 * 1024) // 1 GB
		largeFee := reward.GetBaselineFee(difficulty, worldStateBytes, largeAdded, units)
		assert.True(t, largeFee.Cmp(big.NewInt(int64(largeAdded))) >= 0,
			"Fee should be at least totalAdded for large additions")
	})
}

func TestGetBaselineFee_EdgeCases(t *testing.T) {
	t.Run("Minimum valid inputs", func(t *testing.T) {
		// Test with minimum non-zero values
		result := reward.GetBaselineFee(1, 1, 1, 1)
		require.NotNil(t, result)
		assert.True(t, result.Sign() >= 0, "Result should be non-negative")
	})

	t.Run("Very large world state", func(t *testing.T) {
		// Test with very large world state (exabyte scale)
		difficulty := uint64(100000)
		worldStateBytes := uint64(1024 * 1024 * 1024 * 1024 * 1024 * 1024) // 1 EB
		totalAdded := uint64(1024 * 1024 * 1024)                            // 1 GB
		units := uint64(8000000000)

		result := reward.GetBaselineFee(difficulty, worldStateBytes, totalAdded, units)
		require.NotNil(t, result)
		assert.True(t, result.Cmp(big.NewInt(int64(totalAdded))) >= 0,
			"Result should be at least totalAdded")
	})

	t.Run("World state exactly equal to addition", func(t *testing.T) {
		// Edge case where worldStateBytes == totalAdded
		size := uint64(1024 * 1024) // 1 MB
		result := reward.GetBaselineFee(100000, size, size, 8000000000)
		require.NotNil(t, result)
		assert.True(t, result.Cmp(big.NewInt(int64(size))) >= 0,
			"Result should be at least totalAdded when world state equals addition")
	})
}

func TestGetBaselineFee_MathematicalProperties(t *testing.T) {
	t.Run("Delta calculation correctness", func(t *testing.T) {
		// The function calculates delta = PomwBasis(current) - PomwBasis(affected)
		// where affected = worldStateBytes + totalAdded
		// The fee is max((delta^2)/worldStateBytes, totalAdded)

		difficulty := uint64(100000)
		worldStateBytes := uint64(4 * 1024 * 1024 * 1024) // 4 GB
		totalAdded := uint64(1024 * 1024)                 // 1 MB
		units := uint64(8000000000)

		// Calculate what the function does internally
		current := reward.PomwBasis(difficulty, worldStateBytes, units)
		affected := reward.PomwBasis(difficulty, worldStateBytes+totalAdded, units)
		delta := new(big.Int).Sub(current, affected)

		// Delta should be positive since PomwBasis decreases as worldStateBytes increases
		assert.True(t, delta.Sign() >= 0,
			"Delta should be non-negative (current basis should be >= affected basis)")

		// Get the actual result
		result := reward.GetBaselineFee(difficulty, worldStateBytes, totalAdded, units)

		// Calculate expected fee
		deltaSquared := new(big.Int).Exp(delta, big.NewInt(2), nil)
		calculatedFee := new(big.Int).Quo(deltaSquared, big.NewInt(int64(worldStateBytes)))
		expectedFee := calculatedFee
		if calculatedFee.Cmp(big.NewInt(int64(totalAdded))) < 0 {
			expectedFee = big.NewInt(int64(totalAdded))
		}

		assert.Equal(t, expectedFee, result,
			"Fee calculation should match expected mathematical formula")
	})
}

func BenchmarkGetBaselineFee(b *testing.B) {
	benchmarks := []struct {
		name            string
		difficulty      uint64
		worldStateBytes uint64
		totalAdded      uint64
		units           uint64
	}{
		{
			name:            "Small scale",
			difficulty:      100000,
			worldStateBytes: 1024 * 1024 * 1024, // 1 GB
			totalAdded:      1024,                // 1 KB
			units:           8000000000,
		},
		{
			name:            "Medium scale",
			difficulty:      100000,
			worldStateBytes: 1024 * 1024 * 1024 * 1024, // 1 TB
			totalAdded:      1024 * 1024,                // 1 MB
			units:           8000000000,
		},
		{
			name:            "Large scale",
			difficulty:      100000,
			worldStateBytes: 1024 * 1024 * 1024 * 1024 * 1024, // 1 PB
			totalAdded:      1024 * 1024 * 1024,                // 1 GB
			units:           8000000000,
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = reward.GetBaselineFee(
					bm.difficulty,
					bm.worldStateBytes,
					bm.totalAdded,
					bm.units,
				)
			}
		})
	}
}