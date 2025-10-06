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

// WesolowskiSolveMulti produces a single worker-i blob ([y_i | π_i]) using ID-bound bases.
func WesolowskiSolveMulti(
	challenge [32]byte,
	difficulty uint32,
	ids [][]byte,
	i uint32,
) [516]byte {
	return [516]byte(
		generated.WesolowskiSolveMulti(
			intSizeBits,
			challenge[:],
			difficulty,
			ids,
			i,
		),
	)
}

// WesolowskiVerifyMulti verifies *all* workers in one shot (verifier-side aggregation).
// `allegedSolutions` must be parallel to `ids`; each entry is a 516-byte blob from WesolowskiSolveMulti.
func WesolowskiVerifyMulti(
	challenge [32]byte,
	difficulty uint32,
	ids [][]byte,
	allegedSolutions [][516]byte,
) bool {
	// Convert [][516]byte -> [][]byte for the generated binding
	as := make([][]byte, len(allegedSolutions))
	for idx := range allegedSolutions {
		as[idx] = allegedSolutions[idx][:]
	}

	if len(ids) != len(as) {
		return false
	}

	return generated.WesolowskiVerifyMulti(
		intSizeBits,
		challenge[:],
		difficulty,
		ids,
		as,
	)
}
