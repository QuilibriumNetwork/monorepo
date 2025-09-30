package reward

import (
	"math/big"

	"github.com/pkg/errors"
	"github.com/shopspring/decimal"
	"golang.org/x/sync/errgroup"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
)

// A pure reference implementation of PoMW reward issuance – exists to compare
// for tests to ensure accuracy of optimized approaches, and be more
// straightforward for alternative language implementations that don't have
// to worry about fighting the GC.
type ProofOfMeaningfulWorkRewardIssuance struct{}

func (p *ProofOfMeaningfulWorkRewardIssuance) Calculate(
	difficulty uint64,
	worldStateBytes uint64,
	units uint64,
	provers []map[string]*consensus.ProverAllocation,
) ([]*big.Int, error) {
	basis := PomwBasis(difficulty, worldStateBytes, units)

	output := make([]*big.Int, len(provers))

	eg := errgroup.Group{}
	eg.SetLimit(1)

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

				shardFactor := decimal.NewFromUint64(alloc.Shards)
				shardFactor, err := shardFactor.PowWithPrecision(
					decimal.NewFromBigRat(big.NewRat(1, 2), 53),
					53,
				)
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

func PomwBasis(
	difficulty uint64,
	worldStateBytes uint64,
	units uint64,
) *big.Int {
	// The world state divisor is the PoMW divisor (1048576) scaled by the number
	// of bytes in a GB (1048576*1073741824). We invert the relation ahead of time
	// for fewer steps and higher precision.
	normalized := decimal.NewFromInt(1_125_899_906_842_624)
	normalized = normalized.Div(decimal.NewFromUint64(worldStateBytes))

	// 1/2^n
	generation := 0
	difflog := difficulty
	for difflog >= 10000 {
		difflog /= 10000
		generation++
	}

	// (d/1048576)^(1/2^n)
	result := normalized
	expdenom := int64(1)
	if generation > 0 {
		for i := 0; i < generation; i++ {
			expdenom *= 2
		}
	}

	exp := decimal.NewFromInt(1)
	exp = exp.Div(decimal.NewFromInt(expdenom))
	result, err := result.PowWithPrecision(exp, 53)
	if err != nil {
		return big.NewInt(0)
	}

	// Scale by units
	result = result.Mul(decimal.NewFromUint64(units))

	return result.BigInt()
}
