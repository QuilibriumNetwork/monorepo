package vdf

import (
	generated "source.quilibrium.com/quilibrium/monorepo/vdf/generated/vdf"
)

//go:generate ./generate.sh

const intSizeBits = uint16(2048)

// WesolowskiSolve Solve and prove with the Wesolowski VDF using the given parameters.
// Outputs the concatenated solution and proof (in this order).
func WesolowskiSolve(challenge [32]byte, difficulty uint32) [516]byte {
	return [516]byte(
		generated.WesolowskiSolve(intSizeBits, challenge[:], difficulty),
	)
}

// WesolowskiVerify Verify with the Wesolowski VDF using the given parameters.
// `allegedSolution` is the output of `WesolowskiSolve`.
func WesolowskiVerify(
	challenge [32]byte,
	difficulty uint32,
	allegedSolution [516]byte,
) bool {
	return generated.WesolowskiVerify(
		intSizeBits,
		challenge[:],
		difficulty,
		allegedSolution[:],
	)
}
