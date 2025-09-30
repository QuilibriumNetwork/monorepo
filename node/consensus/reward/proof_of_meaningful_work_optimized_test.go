package reward_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/reward"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
)

func TestOptimizedCalculate(t *testing.T) {
	original := &reward.ProofOfMeaningfulWorkRewardIssuance{}
	exactOpt := reward.NewOptRewardIssuance()
	minimalOpt := reward.NewMinOptRewardIssuance()

	testCases := []struct {
		name    string
		provers []map[string]*consensus.ProverAllocation
	}{
		{
			name: "Single prover with mixed allocations",
			provers: []map[string]*consensus.ProverAllocation{
				{
					"alloc1": &consensus.ProverAllocation{
						Ring:      0,
						StateSize: 2 * 1024 * 1024 * 1024,
						Shards:    1,
					},
					"alloc2": &consensus.ProverAllocation{
						Ring:      1,
						StateSize: 1 * 1024 * 1024 * 1024,
						Shards:    4,
					},
				},
			},
		},
		{
			name: "Multiple provers with all shard values",
			provers: []map[string]*consensus.ProverAllocation{
				{
					"alloc1": &consensus.ProverAllocation{
						Ring:      2,
						StateSize: 4 * 1024 * 1024 * 1024,
						Shards:    2,
					},
					"alloc2": &consensus.ProverAllocation{
						Ring:      0,
						StateSize: 1 * 1024 * 1024 * 1024,
						Shards:    3,
					},
				},
				{
					"alloc1": &consensus.ProverAllocation{
						Ring:      1,
						StateSize: 2 * 1024 * 1024 * 1024,
						Shards:    1,
					},
					"alloc2": &consensus.ProverAllocation{
						Ring:      3,
						StateSize: 8 * 1024 * 1024 * 1024,
						Shards:    4,
					},
				},
			},
		},
		{
			name: "Edge case: single allocation",
			provers: []map[string]*consensus.ProverAllocation{
				{
					"only": &consensus.ProverAllocation{
						Ring:      0,
						StateSize: 4 * 1024 * 1024 * 1024,
						Shards:    1,
					},
				},
			},
		},
	}

	difficulty := uint64(100000)
	worldStateBytes := uint64(4 * 1024 * 1024 * 1024)
	units := uint64(8000000000)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			originalRewards, err := original.Calculate(difficulty, worldStateBytes, units, tc.provers)
			assert.NoError(t, err)

			exactRewards, err := exactOpt.Calculate(difficulty, worldStateBytes, units, tc.provers)
			assert.NoError(t, err)

			minimalRewards, err := minimalOpt.Calculate(difficulty, worldStateBytes, units, tc.provers)
			assert.NoError(t, err)

			// Verify exact match
			for i := range originalRewards {
				assert.Equal(t, originalRewards[i].String(), exactRewards[i].String(),
					"Optimized mismatch at index %d", i)
				assert.Equal(t, originalRewards[i].String(), minimalRewards[i].String(),
					"MinimalAllocationOptimized mismatch at index %d", i)
			}
		})
	}
}

func TestOptimizedWithTestCalculateCases(t *testing.T) {
	// Run all the test cases from TestCalculate with exact optimized versions
	original := &reward.ProofOfMeaningfulWorkRewardIssuance{}
	exactOpt := reward.NewOptRewardIssuance()
	minimalOpt := reward.NewMinOptRewardIssuance()

	// Copy all test cases from TestCalculate
	testCases := []struct {
		name            string
		provers         []map[string]*consensus.ProverAllocation
		difficulty      uint64
		worldStateBytes uint64
		units           uint64
		expectError     bool
	}{
		{
			name: "Single prover single allocation",
			provers: []map[string]*consensus.ProverAllocation{
				{
					"range1": &consensus.ProverAllocation{
						Ring:      0,
						StateSize: 4 * 1024 * 1024 * 1024,
						Shards:    1,
					},
				},
			},
			difficulty:      100000,
			worldStateBytes: 4 * 1024 * 1024 * 1024,
			units:           8000000000,
		},
		{
			name: "Single prover with ring scaling",
			provers: []map[string]*consensus.ProverAllocation{
				{
					"range1": &consensus.ProverAllocation{
						Ring:      2,
						StateSize: 4 * 1024 * 1024 * 1024,
						Shards:    1,
					},
				},
			},
			difficulty:      100000,
			worldStateBytes: 4 * 1024 * 1024 * 1024,
			units:           8000000000,
		},
		{
			name: "Multiple allocations per prover",
			provers: []map[string]*consensus.ProverAllocation{
				{
					"allocation1": &consensus.ProverAllocation{
						Ring:      0,
						StateSize: 1 * 1024 * 1024 * 1024,
						Shards:    1,
					},
					"allocation2": &consensus.ProverAllocation{
						Ring:      1,
						StateSize: 1 * 1024 * 1024 * 1024,
						Shards:    1,
					},
				},
			},
			difficulty:      100000,
			worldStateBytes: 4 * 1024 * 1024 * 1024,
			units:           8000000000,
		},
		{
			name: "Zero shards should return error",
			provers: []map[string]*consensus.ProverAllocation{
				{
					"range1": &consensus.ProverAllocation{
						Ring:      0,
						StateSize: 4 * 1024 * 1024 * 1024,
						Shards:    0,
					},
				},
			},
			difficulty:      100000,
			worldStateBytes: 4 * 1024 * 1024 * 1024,
			units:           8000000000,
			expectError:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			originalRewards, originalErr := original.Calculate(tc.difficulty, tc.worldStateBytes, tc.units, tc.provers)
			exactRewards, exactErr := exactOpt.Calculate(tc.difficulty, tc.worldStateBytes, tc.units, tc.provers)
			minimalRewards, minimalErr := minimalOpt.Calculate(tc.difficulty, tc.worldStateBytes, tc.units, tc.provers)

			if tc.expectError {
				assert.Error(t, originalErr)
				assert.Error(t, exactErr)
				assert.Error(t, minimalErr)
				return
			}

			assert.NoError(t, originalErr)
			assert.NoError(t, exactErr)
			assert.NoError(t, minimalErr)

			// Verify exact match
			for i := range originalRewards {
				assert.Equal(t, originalRewards[i].String(), exactRewards[i].String(),
					"Optimized mismatch at index %d", i)
				assert.Equal(t, originalRewards[i].String(), minimalRewards[i].String(),
					"MinimalAllocationOptimized mismatch at index %d", i)
			}
		})
	}
}

func BenchmarkOptimizedImplementations(b *testing.B) {
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

	proverCounts := []int{1, 10, 100, 1000}
	allocCount := 10

	for _, impl := range implementations {
		for _, proverCount := range proverCounts {
			benchName := fmt.Sprintf("%s/Provers_%d_Allocations_%d", impl.name, proverCount, allocCount)

			b.Run(benchName, func(b *testing.B) {
				provers := make([]map[string]*consensus.ProverAllocation, proverCount)

				for i := 0; i < proverCount; i++ {
					allocations := make(map[string]*consensus.ProverAllocation)

					for j := 0; j < allocCount; j++ {
						allocName := fmt.Sprintf("alloc_%d", j)
						allocations[allocName] = &consensus.ProverAllocation{
							Ring:      uint8(j % 4),
							StateSize: uint64((j%8 + 1) * 512 * 1024 * 1024),
							Shards:    uint64((j % 4) + 1),
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
}
