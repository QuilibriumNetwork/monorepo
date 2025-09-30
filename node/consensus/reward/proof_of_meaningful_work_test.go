package reward_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/reward"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
)

func TestPomwBasis(t *testing.T) {
	out := reward.PomwBasis(100000, 4*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(4096000000000))

	out = reward.PomwBasis(100000, 16*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(2048000000000))

	out = reward.PomwBasis(100000, 64*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(1024000000000))

	out = reward.PomwBasis(100000, 256*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(512000000000))

	out = reward.PomwBasis(100000, 1024*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(256000000000))

	out = reward.PomwBasis(100000, 4096*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(128000000000))

	out = reward.PomwBasis(100000, 16384*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(64000000000))

	out = reward.PomwBasis(100000, 65536*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(32000000000))

	out = reward.PomwBasis(100000, 262144*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(16000000000))

	out = reward.PomwBasis(100000, 1024*1024*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(8000000000))

	out = reward.PomwBasis(100000, 4*1024*1024*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(4000000000))

	out = reward.PomwBasis(100000, 16*1024*1024*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(2000000000))

	out = reward.PomwBasis(100000, 64*1024*1024*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(1000000000))

	// gen 2 – amongst expected gen 1 storage values, reduced and tapering output,
	// amongst expected gen 1 storage values, increased but tapering output:
	out = reward.PomwBasis(100000000, 4*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(181019335983))

	out = reward.PomwBasis(100000000, 16*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(128000000000))

	out = reward.PomwBasis(100000000, 64*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(90509667991))

	out = reward.PomwBasis(100000000, 256*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(64000000000))

	out = reward.PomwBasis(100000000, 1024*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(45254833995))

	out = reward.PomwBasis(100000000, 4096*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(32000000000))

	// intersection at 1PB
	out = reward.PomwBasis(100000000, 1024*1024*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(8000000000))

	out = reward.PomwBasis(100000000, 4*1024*1024*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(5656854249))

	out = reward.PomwBasis(100000000, 16*1024*1024*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(4000000000))

	out = reward.PomwBasis(100000000, 64*1024*1024*1024*1024*1024, 8000000000)
	assert.Equal(t, out, big.NewInt(2828427124))
}

func TestCalculate(t *testing.T) {
	rewardIssuance := reward.NewOptRewardIssuance()

	t.Run("Single prover single allocation", func(t *testing.T) {
		provers := []map[string]*consensus.ProverAllocation{
			{
				"range1": &consensus.ProverAllocation{
					Ring:      0,
					StateSize: 4 * 1024 * 1024 * 1024, // 4GB
					Shards:    1,
				},
			},
		}

		rewards, err := rewardIssuance.Calculate(
			100000,           // difficulty
			4*1024*1024*1024, // worldStateBytes (4GB)
			8000000000,       // units
			provers,
		)

		assert.NoError(t, err)
		assert.Len(t, rewards, 1)

		// When StateSize equals worldStateBytes and Ring=0, Shards=1
		// basis = 4096000000000
		// factor = 4GB/4GB = 1
		// result = 1 * 4096000000000 / 2^1 / sqrt(1) = 2048000000000
		assert.Equal(t, big.NewInt(2048000000000), rewards[0])
	})

	t.Run("Single prover with ring scaling", func(t *testing.T) {
		provers := []map[string]*consensus.ProverAllocation{
			{
				"range1": &consensus.ProverAllocation{
					Ring:      2,                      // Ring 2 means divide by 8
					StateSize: 4 * 1024 * 1024 * 1024, // 4GB
					Shards:    1,
				},
			},
		}

		rewards, err := rewardIssuance.Calculate(
			100000,           // difficulty
			4*1024*1024*1024, // worldStateBytes (4GB)
			8000000000,       // units
			provers,
		)

		assert.NoError(t, err)
		assert.Len(t, rewards, 1)

		// basis = 4096000000000
		// divisor = 2^2 = 4
		// factor = 4GB/4GB = 1
		// result = 1 * 4096000000000 / 8 / sqrt(1) = 512000000000
		assert.Equal(t, big.NewInt(512000000000), rewards[0])
	})

	t.Run("Single prover with partial state", func(t *testing.T) {
		provers := []map[string]*consensus.ProverAllocation{
			{
				"range1": &consensus.ProverAllocation{
					Ring:      0,
					StateSize: 2 * 1024 * 1024 * 1024, // 2GB (half of world state)
					Shards:    1,
				},
			},
		}

		rewards, err := rewardIssuance.Calculate(
			100000,           // difficulty
			4*1024*1024*1024, // worldStateBytes (4GB)
			8000000000,       // units
			provers,
		)

		assert.NoError(t, err)
		assert.Len(t, rewards, 1)

		// basis = 4096000000000
		// factor = 2GB/4GB = 0.5
		// result = 0.5 * 4096000000000 / 2 / sqrt(1) = 1024000000000
		assert.Equal(t, big.NewInt(1024000000000), rewards[0])
	})

	t.Run("Single prover with multiple shards", func(t *testing.T) {
		provers := []map[string]*consensus.ProverAllocation{
			{
				"range1": &consensus.ProverAllocation{
					Ring:      0,
					StateSize: 4 * 1024 * 1024 * 1024, // 4GB
					Shards:    4,
				},
			},
		}

		rewards, err := rewardIssuance.Calculate(
			100000,           // difficulty
			4*1024*1024*1024, // worldStateBytes (4GB)
			8000000000,       // units
			provers,
		)

		assert.NoError(t, err)
		assert.Len(t, rewards, 1)

		// basis = 4096000000000
		// factor = 4GB/4GB = 1
		// shardFactor = sqrt(4) = 2
		// result = 1 * 4096000000000 / 2 / 2 = 1024000000000
		assert.Equal(t, big.NewInt(1024000000000), rewards[0])
	})

	t.Run("Multiple provers", func(t *testing.T) {
		provers := []map[string]*consensus.ProverAllocation{
			{
				"range1": &consensus.ProverAllocation{
					Ring:      0,
					StateSize: 2 * 1024 * 1024 * 1024, // 2GB
					Shards:    1,
				},
			},
			{
				"range2": &consensus.ProverAllocation{
					Ring:      1,                      // Ring 1 means divide by 4
					StateSize: 1 * 1024 * 1024 * 1024, // 1GB
					Shards:    1,
				},
			},
			{
				"range3": &consensus.ProverAllocation{
					Ring:      0,
					StateSize: 1 * 1024 * 1024 * 1024, // 1GB
					Shards:    4,
				},
			},
		}

		rewards, err := rewardIssuance.Calculate(
			100000,           // difficulty
			4*1024*1024*1024, // worldStateBytes (4GB)
			8000000000,       // units
			provers,
		)

		assert.NoError(t, err)
		assert.Len(t, rewards, 3)

		// Prover 1: factor = 2GB/4GB = 0.5, ring = 1, shards = 1
		// result = 0.5 * 4096000000000 / 2 / 1 = 1024000000000
		assert.Equal(t, big.NewInt(1024000000000), rewards[0])

		// Prover 2: factor = 1GB/4GB = 0.25, ring = 2, shards = 1
		// result = 0.25 * 4096000000000 / 4 / 1 = 256000000000
		assert.Equal(t, big.NewInt(256000000000), rewards[1])

		// Prover 3: factor = 1GB/4GB = 0.25, ring = 1, shards = 4
		// result = 0.25 * 4096000000000 / 2 / 2 = 256000000000
		assert.Equal(t, big.NewInt(256000000000), rewards[2])
	})

	t.Run("Multiple allocations per prover", func(t *testing.T) {
		provers := []map[string]*consensus.ProverAllocation{
			{
				"allocation1": &consensus.ProverAllocation{
					Ring:      0,
					StateSize: 1 * 1024 * 1024 * 1024, // 1GB
					Shards:    1,
				},
				"allocation2": &consensus.ProverAllocation{
					Ring:      1,
					StateSize: 1 * 1024 * 1024 * 1024, // 1GB
					Shards:    1,
				},
			},
		}

		rewards, err := rewardIssuance.Calculate(
			100000,           // difficulty
			4*1024*1024*1024, // worldStateBytes (4GB)
			8000000000,       // units
			provers,
		)

		assert.NoError(t, err)
		assert.Len(t, rewards, 1)

		// The implementation sums up all allocations for each prover:
		// allocation1: 0.25 * 4096000000000 / 2 / 1 = 512000000000
		// allocation2: 0.25 * 4096000000000 / 4 / 1 = 256000000000
		// Total: 512000000000 + 256000000000 = 768000000000
		assert.Equal(t, big.NewInt(768000000000), rewards[0])
	})

	t.Run("Empty provers", func(t *testing.T) {
		provers := []map[string]*consensus.ProverAllocation{}

		rewards, err := rewardIssuance.Calculate(
			100000,           // difficulty
			4*1024*1024*1024, // worldStateBytes (4GB)
			8000000000,       // units
			provers,
		)

		assert.NoError(t, err)
		assert.Len(t, rewards, 0)
	})

	t.Run("Zero shards should return error", func(t *testing.T) {
		provers := []map[string]*consensus.ProverAllocation{
			{
				"range1": &consensus.ProverAllocation{
					Ring:      0,
					StateSize: 4 * 1024 * 1024 * 1024, // 4GB
					Shards:    0,                      // This should cause a division by zero
				},
			},
		}

		rewards, err := rewardIssuance.Calculate(
			100000,           // difficulty
			4*1024*1024*1024, // worldStateBytes (4GB)
			8000000000,       // units
			provers,
		)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "divisor is zero")
		assert.Nil(t, rewards)
	})

	t.Run("Concurrent execution for multiple provers", func(t *testing.T) {
		// Create many provers to test concurrent execution
		numProvers := 100
		provers := make([]map[string]*consensus.ProverAllocation, numProvers)

		for i := 0; i < numProvers; i++ {
			provers[i] = map[string]*consensus.ProverAllocation{
				"prover": {
					Ring:      uint8(i % 3),                           // Vary ring 0-2
					StateSize: uint64((i%4 + 1) * 1024 * 1024 * 1024), // 1-4 GB
					Shards:    uint64((i % 4) + 1),                    // 1-4 shards
				},
			}
		}

		rewards, err := rewardIssuance.Calculate(
			100000,           // difficulty
			4*1024*1024*1024, // worldStateBytes (4GB)
			8000000000,       // units
			provers,
		)

		assert.NoError(t, err)
		assert.Len(t, rewards, numProvers)

		// Verify all rewards are non-zero
		for i, reward := range rewards {
			assert.NotNil(t, reward, "Reward %d is nil", i)
			assert.True(t, reward.Cmp(big.NewInt(0)) > 0, "Reward %d is not positive: %v", i, reward)
		}
	})

	t.Run("Full shard division allocation, all provers online", func(t *testing.T) {
		// Create many provers to test concurrent execution
		numProvers := 20
		provers := make([]map[string]*consensus.ProverAllocation, numProvers)

		for i := 0; i < numProvers; i++ {
			provers[i] = map[string]*consensus.ProverAllocation{
				"prover": {
					Ring:      uint8(0),
					StateSize: uint64(5 * 1024 * 1024 * 1024 / 10), // .5 GB
					Shards:    uint64(1),                           // 1 shard
				},
			}
		}

		rewards, err := rewardIssuance.Calculate(
			100000,            // difficulty
			10*1024*1024*1024, // worldStateBytes (10GB)
			8000000000,        // units
			provers,
		)

		assert.NoError(t, err)
		assert.Len(t, rewards, numProvers)

		// Verify all rewards are non-zero
		sum := new(big.Int)
		for i, reward := range rewards {
			sum.Add(sum, reward)
			assert.NotNil(t, reward, "Reward %d is nil", i)
			assert.True(t, reward.Cmp(big.NewInt(0)) > 0, "Reward %d is not positive: %v", i, reward)
		}

		// (1295268929600 / 8000000000)*2 = 323.8172324 QUIL
		assert.True(t, big.NewInt(1295268929600).Cmp(sum) == 0, "mismatch on sum")
	})

	t.Run("Large world state, gen 2", func(t *testing.T) {
		provers := []map[string]*consensus.ProverAllocation{
			{
				"range1": &consensus.ProverAllocation{
					Ring:      0,
					StateSize: 1024 * 1024 * 1024 * 1024, // 1TB
					Shards:    1,
				},
			},
		}

		rewards, err := rewardIssuance.Calculate(
			100000000,                // difficulty to move to generation 2
			1024*1024*1024*1024*1024, // worldStateBytes (1PB)
			8000000000,               // units
			provers,
		)

		assert.NoError(t, err)
		assert.Len(t, rewards, 1)

		// With 1TB state in 1PB world (1/1024), basis = 8000000000
		// result = (1/1024) * 8000000000 / 2 / 1 = 3906250
		assert.Equal(t, big.NewInt(3906250), rewards[0])
	})
}

func BenchmarkCalculate(b *testing.B) {
	rewardIssuance := reward.NewOptRewardIssuance()

	// Test with increasing powers of two provers
	proverCounts := []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}

	// Test with different allocation counts per prover
	allocationCounts := []int{10, 25, 50, 100, 250, 500, 10000}

	// Standard test parameters
	difficulty := uint64(100000)
	worldStateBytes := uint64(4 * 1024 * 1024 * 1024) // 4GB
	units := uint64(8000000000)

	for _, proverCount := range proverCounts {
		for _, allocCount := range allocationCounts {
			benchName := fmt.Sprintf("Provers_%d_Allocations_%d", proverCount, allocCount)

			b.Run(benchName, func(b *testing.B) {
				// Pre-generate provers to avoid including generation time in benchmark
				provers := make([]map[string]*consensus.ProverAllocation, proverCount)

				for i := 0; i < proverCount; i++ {
					allocations := make(map[string]*consensus.ProverAllocation)

					for j := 0; j < allocCount; j++ {
						allocName := fmt.Sprintf("alloc_%d", j)
						allocations[allocName] = &consensus.ProverAllocation{
							Ring:      uint8(j % 4),                          // Vary ring 0-3
							StateSize: uint64((j%8 + 1) * 512 * 1024 * 1024), // 512MB to 4GB
							Shards:    uint64((j % 4) + 1),                   // 1-4 shards
						}
					}

					provers[i] = allocations
				}

				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					rewards, err := rewardIssuance.Calculate(
						difficulty,
						worldStateBytes,
						units,
						provers,
					)

					if err != nil {
						b.Fatalf("Calculate failed: %v", err)
					}

					if len(rewards) != proverCount {
						b.Fatalf("Expected %d rewards, got %d", proverCount, len(rewards))
					}
				}
			})
		}
	}
}
