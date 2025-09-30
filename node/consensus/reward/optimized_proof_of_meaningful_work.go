package reward

import (
	"math/big"
	"runtime"
	"sync"

	"github.com/pkg/errors"
	"github.com/shopspring/decimal"
	"golang.org/x/sync/errgroup"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
)

// OptimizedProofOfMeaningfulWorkRewardIssuance is optimized by caching the
// decimal square root calculations
type OptimizedProofOfMeaningfulWorkRewardIssuance struct {
	sqrtCache     map[uint64]decimal.Decimal
	sqrtCacheLock sync.RWMutex
	halfDecimal   decimal.Decimal
}

func NewOptRewardIssuance() *OptimizedProofOfMeaningfulWorkRewardIssuance {
	halfRat := big.NewRat(1, 2)
	return &OptimizedProofOfMeaningfulWorkRewardIssuance{
		sqrtCache:   make(map[uint64]decimal.Decimal),
		halfDecimal: decimal.NewFromBigRat(halfRat, 53),
	}
}

func (p *OptimizedProofOfMeaningfulWorkRewardIssuance) getSqrt(
	shards uint64,
) (decimal.Decimal, error) {
	p.sqrtCacheLock.RLock()
	if sqrt, exists := p.sqrtCache[shards]; exists {
		p.sqrtCacheLock.RUnlock()
		return sqrt, nil
	}
	p.sqrtCacheLock.RUnlock()

	p.sqrtCacheLock.Lock()
	defer p.sqrtCacheLock.Unlock()

	if sqrt, exists := p.sqrtCache[shards]; exists {
		return sqrt, nil
	}

	shardFactor := decimal.NewFromUint64(shards)
	sqrt, err := shardFactor.PowWithPrecision(p.halfDecimal, 53)
	if err != nil {
		return decimal.Zero, err
	}

	p.sqrtCache[shards] = sqrt
	return sqrt, nil
}

func (p *OptimizedProofOfMeaningfulWorkRewardIssuance) Calculate(
	difficulty uint64,
	worldStateBytes uint64,
	units uint64,
	provers []map[string]*consensus.ProverAllocation,
) ([]*big.Int, error) {
	basis := PomwBasis(difficulty, worldStateBytes, units)

	output := make([]*big.Int, len(provers))

	eg := errgroup.Group{}
	eg.SetLimit(runtime.GOMAXPROCS(0))

	for i := range provers {
		proverIndex := i
		eg.Go(func() error {
			output[proverIndex] = big.NewInt(0)

			for _, alloc := range provers[proverIndex] {
				// Divide by 2^s
				divisor := int64(1)
				for i := uint8(0); i < alloc.Ring+1; i++ {
					divisor *= 2
				}

				ringScaled := decimal.NewFromInt(divisor)

				factor := decimal.NewFromUint64(alloc.StateSize)
				factor = factor.Div(decimal.NewFromUint64(worldStateBytes))

				result := factor.Mul(decimal.NewFromBigInt(basis, 0))
				result = result.Div(ringScaled)

				shardFactor, err := p.getSqrt(alloc.Shards)
				if err != nil {
					return err
				}

				if shardFactor.IsZero() {
					return errors.New("divisor is zero")
				}

				result = result.Div(shardFactor)
				output[proverIndex] = output[proverIndex].Add(
					output[proverIndex],
					result.BigInt(),
				)
			}

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return nil, errors.Wrap(err, "calculate")
	}

	return output, nil
}

// MinimalAllocationOptimizedProofOfMeaningfulWorkRewardIssuance reduces
// allocations while maintaining compatibility – low memory environments may
// want to use this, but it is left unused.
type MinimalAllocationOptimizedProofOfMeaningfulWorkRewardIssuance struct {
	sqrtCache       map[uint64]decimal.Decimal
	halfDecimal     decimal.Decimal
	worldStateCache map[uint64]decimal.Decimal
	cacheLock       sync.RWMutex
}

func NewMinOptRewardIssuance() *MinimalAllocationOptimizedProofOfMeaningfulWorkRewardIssuance {
	halfRat := big.NewRat(1, 2)
	return &MinimalAllocationOptimizedProofOfMeaningfulWorkRewardIssuance{
		sqrtCache:       make(map[uint64]decimal.Decimal),
		halfDecimal:     decimal.NewFromBigRat(halfRat, 53),
		worldStateCache: make(map[uint64]decimal.Decimal),
	}
}

func (p *MinimalAllocationOptimizedProofOfMeaningfulWorkRewardIssuance) Calculate(
	difficulty uint64,
	worldStateBytes uint64,
	units uint64,
	provers []map[string]*consensus.ProverAllocation,
) ([]*big.Int, error) {
	basis := PomwBasis(difficulty, worldStateBytes, units)
	basisDecimal := decimal.NewFromBigInt(basis, 0)

	p.cacheLock.RLock()
	worldStateBytesDecimal, exists := p.worldStateCache[worldStateBytes]
	p.cacheLock.RUnlock()

	if !exists {
		p.cacheLock.Lock()
		worldStateBytesDecimal = decimal.NewFromUint64(worldStateBytes)
		p.worldStateCache[worldStateBytes] = worldStateBytesDecimal
		p.cacheLock.Unlock()
	}

	uniqueShards := make(map[uint64]bool)
	for _, prover := range provers {
		for _, alloc := range prover {
			uniqueShards[alloc.Shards] = true
		}
	}

	missingSqrts := make(map[uint64]decimal.Decimal)
	p.cacheLock.RLock()
	for shards := range uniqueShards {
		if _, exists := p.sqrtCache[shards]; !exists {
			missingSqrts[shards] = decimal.Zero // Mark as needing computation
		}
	}
	p.cacheLock.RUnlock()

	if len(missingSqrts) > 0 {
		for shards := range missingSqrts {
			shardFactor := decimal.NewFromUint64(shards)
			sqrt, err := shardFactor.PowWithPrecision(p.halfDecimal, 53)
			if err != nil {
				return nil, err
			}
			missingSqrts[shards] = sqrt
		}

		p.cacheLock.Lock()
		for shards, sqrt := range missingSqrts {
			p.sqrtCache[shards] = sqrt
		}
		p.cacheLock.Unlock()
	}

	output := make([]*big.Int, len(provers))

	eg := errgroup.Group{}
	eg.SetLimit(runtime.GOMAXPROCS(0))

	ringDivisors := make([]decimal.Decimal, 256)
	ringDivisors[0] = decimal.NewFromInt(1)
	for i := uint8(1); i < 255; i++ {
		ringDivisors[i] = decimal.NewFromInt(int64(1) << i)
	}

	for i := range provers {
		proverIndex := i
		eg.Go(func() error {
			accumulator := decimal.Zero

			for _, alloc := range provers[proverIndex] {
				factor := decimal.NewFromUint64(alloc.StateSize)
				factor = factor.Div(worldStateBytesDecimal)

				result := factor.Mul(basisDecimal)
				result = result.Div(ringDivisors[alloc.Ring+1])

				p.cacheLock.RLock()
				shardFactor := p.sqrtCache[alloc.Shards]
				p.cacheLock.RUnlock()

				if shardFactor.IsZero() {
					return errors.New("divisor is zero")
				}

				result = result.Div(shardFactor)
				accumulator = accumulator.Add(result)
			}

			output[proverIndex] = accumulator.BigInt()
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return nil, errors.Wrap(err, "calculate")
	}

	return output, nil
}
