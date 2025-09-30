package reward_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/reward"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
)

func TestLargeShardValues(t *testing.T) {
	original := &reward.ProofOfMeaningfulWorkRewardIssuance{}
	exactOpt := reward.NewOptRewardIssuance()
	minimalOpt := reward.NewMinOptRewardIssuance()

	// Test with various shard values including large ones
	shardValues := []uint64{1, 2, 3, 4, 10, 50, 100, 500, 1000, 5000, 10000}

	for _, shards := range shardValues {
		t.Run(fmt.Sprintf("Shards_%d", shards), func(t *testing.T) {
			provers := []map[string]*consensus.ProverAllocation{
				{
					"test": &consensus.ProverAllocation{
						Ring:      0,
						StateSize: 4 * 1024 * 1024 * 1024,
						Shards:    shards,
					},
				},
			}

			difficulty := uint64(100000)
			worldStateBytes := uint64(4 * 1024 * 1024 * 1024)
			units := uint64(8000000000)

			originalRewards, err := original.Calculate(difficulty, worldStateBytes, units, provers)
			assert.NoError(t, err)

			exactRewards, err := exactOpt.Calculate(difficulty, worldStateBytes, units, provers)
			assert.NoError(t, err)

			minimalRewards, err := minimalOpt.Calculate(difficulty, worldStateBytes, units, provers)
			assert.NoError(t, err)

			// Verify exact match for exact implementations
			assert.Equal(t, originalRewards[0].String(), exactRewards[0].String(),
				"Optimized mismatch for shards=%d", shards)
			assert.Equal(t, originalRewards[0].String(), minimalRewards[0].String(),
				"MinimalAllocationOptimized mismatch for shards=%d", shards)
		})
	}
}

func TestMixedShardValues(t *testing.T) {
	original := &reward.ProofOfMeaningfulWorkRewardIssuance{}
	exactOpt := reward.NewOptRewardIssuance()
	minimalOpt := reward.NewMinOptRewardIssuance()

	// Test with mixed shard values in a single calculation
	provers := []map[string]*consensus.ProverAllocation{
		{
			"small": &consensus.ProverAllocation{
				Ring:      0,
				StateSize: 1 * 1024 * 1024 * 1024,
				Shards:    4,
			},
			"medium": &consensus.ProverAllocation{
				Ring:      1,
				StateSize: 2 * 1024 * 1024 * 1024,
				Shards:    100,
			},
			"large": &consensus.ProverAllocation{
				Ring:      2,
				StateSize: 4 * 1024 * 1024 * 1024,
				Shards:    1000,
			},
		},
		{
			"very_large": &consensus.ProverAllocation{
				Ring:      0,
				StateSize: 8 * 1024 * 1024 * 1024,
				Shards:    10000,
			},
		},
	}

	difficulty := uint64(100000)
	worldStateBytes := uint64(16 * 1024 * 1024 * 1024)
	units := uint64(8000000000)

	originalRewards, err := original.Calculate(difficulty, worldStateBytes, units, provers)
	assert.NoError(t, err)

	exactRewards, err := exactOpt.Calculate(difficulty, worldStateBytes, units, provers)
	assert.NoError(t, err)

	minimalRewards, err := minimalOpt.Calculate(difficulty, worldStateBytes, units, provers)
	assert.NoError(t, err)

	// Verify exact match
	for i := range originalRewards {
		assert.Equal(t, originalRewards[i].String(), exactRewards[i].String(),
			"Optimized mismatch at index %d", i)
		assert.Equal(t, originalRewards[i].String(), minimalRewards[i].String(),
			"MinimalAllocationOptimized mismatch at index %d", i)
	}
}

func BenchmarkLargeShards(b *testing.B) {
	implementations := []struct {
		name string
		impl interface {
			Calculate(uint64, uint64, uint64, []map[string]*consensus.ProverAllocation) ([]*big.Int, error)
		}
	}{
		{"Original", &reward.ProofOfMeaningfulWorkRewardIssuance{}},
		{"Optimized", reward.NewOptRewardIssuance()},
		{"MinimalAllocationOptimized", reward.NewMinOptRewardIssuance()},
	}

	difficulty := uint64(100000)
	worldStateBytes := uint64(4 * 1024 * 1024 * 1024)
	units := uint64(8000000000)

	// Test with 100 provers, 10 allocations each, with varying shard values
	proverCount := 100
	allocCount := 10

	for _, impl := range implementations {
		b.Run(impl.name, func(b *testing.B) {
			provers := make([]map[string]*consensus.ProverAllocation, proverCount)

			for i := 0; i < proverCount; i++ {
				allocations := make(map[string]*consensus.ProverAllocation)

				for j := 0; j < allocCount; j++ {
					// Use a variety of shard values including large ones
					shardValues := []uint64{1, 2, 3, 4, 10, 50, 100, 500, 1000, 5000}
					shards := shardValues[j%len(shardValues)]

					allocName := fmt.Sprintf("alloc_%d", j)
					allocations[allocName] = &consensus.ProverAllocation{
						Ring:      uint8(j % 4),
						StateSize: uint64((j%8 + 1) * 512 * 1024 * 1024),
						Shards:    shards,
					}
				}

				provers[i] = allocations
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, err := impl.impl.Calculate(
					difficulty,
					worldStateBytes,
					units,
					provers,
				)

				if err != nil {
					b.Fatalf("Calculate failed: %v", err)
				}
			}
		})
	}
}
