package reward

import "math/big"

// GetBaselineFee returns the scaled baseline fee derived from world state
// impact
func GetBaselineFee(
	difficulty uint64,
	worldStateBytes uint64,
	totalAdded uint64,
	units uint64,
) *big.Int {
	current := PomwBasis(difficulty, worldStateBytes, units)
	affected := PomwBasis(difficulty, worldStateBytes+totalAdded, units)

	delta := new(big.Int).Sub(current, affected)
	num := new(big.Int).Exp(delta, big.NewInt(2), big.NewInt(0))
	denom := big.NewInt(int64(worldStateBytes))

	lhs := new(big.Int).Quo(num, denom)
	rhs := big.NewInt(int64(totalAdded))

	if lhs.Cmp(rhs) >= 0 {
		return lhs
	}

	return rhs
}
