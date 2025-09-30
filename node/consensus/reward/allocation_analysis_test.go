package reward_test

import (
	"math/big"
	"testing"

	"github.com/shopspring/decimal"
)

// These tests serve to determine the ideal profile for optimizing the PoMW
// evaluator

// BenchmarkPowWithPrecision tests the cost of the power operation
func BenchmarkPowWithPrecision(b *testing.B) {
	testCases := []struct {
		name   string
		shards uint64
	}{
		{"Shards_1", 1},
		{"Shards_2", 2},
		{"Shards_3", 3},
		{"Shards_4", 4},
	}

	halfRat := big.NewRat(1, 2)
	halfDecimal := decimal.NewFromBigRat(halfRat, 53)

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				shardFactor := decimal.NewFromUint64(tc.shards)
				_, err := shardFactor.PowWithPrecision(halfDecimal, 53)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDecimalOperations tests individual decimal operations
func BenchmarkDecimalOperations(b *testing.B) {
	// Setup test values
	stateSize := decimal.NewFromUint64(2 * 1024 * 1024 * 1024)
	worldStateBytes := decimal.NewFromUint64(4 * 1024 * 1024 * 1024)
	basis := decimal.NewFromInt(4096000000000)
	divisor := decimal.NewFromInt(2)

	b.Run("NewFromUint64", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = decimal.NewFromUint64(2 * 1024 * 1024 * 1024)
		}
	})

	b.Run("Div", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = stateSize.Div(worldStateBytes)
		}
	})

	b.Run("Mul", func(b *testing.B) {
		b.ReportAllocs()
		factor := stateSize.Div(worldStateBytes)
		for i := 0; i < b.N; i++ {
			_ = factor.Mul(basis)
		}
	})

	b.Run("BigInt_Conversion", func(b *testing.B) {
		b.ReportAllocs()
		result := basis.Div(divisor)
		for i := 0; i < b.N; i++ {
			_ = result.BigInt()
		}
	})

	b.Run("Full_Calculation_Sequence", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			// Simulate one allocation calculation
			factor := stateSize.Div(worldStateBytes)
			result := factor.Mul(basis)
			result = result.Div(divisor)
			_ = result.BigInt()
		}
	})
}

// BenchmarkBigRatCreation tests BigRat creation cost
func BenchmarkBigRatCreation(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = big.NewRat(1, 2)
	}
}

// BenchmarkSingleAllocationCalculation breaks down the cost of calculating one allocation
func BenchmarkSingleAllocationCalculation(b *testing.B) {
	// Pre-computed values
	worldStateBytes := uint64(4 * 1024 * 1024 * 1024)
	basis := big.NewInt(4096000000000)

	alloc := &struct {
		Ring      uint8
		StateSize uint64
		Shards    uint64
	}{
		Ring:      1,
		StateSize: 2 * 1024 * 1024 * 1024,
		Shards:    2,
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// 1. Calculate ring divisor
		divisor := int64(1)
		for j := uint8(0); j < alloc.Ring+1; j++ {
			divisor *= 2
		}

		ringScaled := decimal.NewFromInt(divisor)

		// 2. Calculate state size factor
		factor := decimal.NewFromUint64(alloc.StateSize)
		factor = factor.Div(decimal.NewFromUint64(worldStateBytes))

		// 3. Apply basis
		result := factor.Mul(decimal.NewFromBigInt(basis, 0))
		result = result.Div(ringScaled)

		// 4. Calculate shard factor (the expensive part)
		shardFactor := decimal.NewFromUint64(alloc.Shards)
		shardFactor, err := shardFactor.PowWithPrecision(
			decimal.NewFromBigRat(big.NewRat(1, 2), 53),
			53,
		)
		if err != nil {
			b.Fatal(err)
		}

		// 5. Final division and conversion
		result = result.Div(shardFactor)
		_ = result.BigInt()
	}
}
