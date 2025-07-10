package utils

import "math/big"

// AbsoluteModularMinimumDistance calculates modular distance:
// min(|a-b|, modulus-|a-b|)
func AbsoluteModularMinimumDistance(
	targetInt *big.Int,
	keyInt *big.Int,
	modulus *big.Int,
) *big.Int {
	diff := new(big.Int).Sub(targetInt, keyInt)
	diff.Abs(diff)

	// Modular complement distance
	modComplement := new(big.Int).Sub(modulus, diff)

	// Take minimum of two distances
	var dist *big.Int
	if diff.Cmp(modComplement) > 0 {
		dist = modComplement
	} else {
		dist = diff
	}
	return dist
}
