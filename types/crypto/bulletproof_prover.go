package crypto

import "math/big"

// RangeProofResult contains the range proof, commitment, and blinding factor
type RangeProofResult struct {
	Proof      []byte
	Commitment []byte
	Blinding   []byte
}

type BulletproofProver interface {
	GenerateRangeProof(
		values []uint64,
		blinding []byte,
		bitSize uint64,
	) (RangeProofResult, error)
	GenerateInputCommitmentsFromBig(values []*big.Int, blinding []byte) []byte
	GenerateRangeProofFromBig(
		values []*big.Int,
		blinding []byte,
		bitSize uint64,
	) (
		RangeProofResult,
		error,
	)
	VerifyRangeProof(proof []byte, commitment []byte, bitSize uint64) bool
	SumCheck(
		inputs [][]byte,
		additionalInputs []*big.Int,
		outputs [][]byte,
		additionalOutputs []*big.Int,
	) bool
	SignHidden(
		sharedSecret []byte,
		spendKey []byte,
		extTranscript []byte,
		amount []byte,
		blind []byte,
	) []byte
	VerifyHidden(
		challenge []byte,
		extTranscript []byte,
		s1, s2, s3 []byte,
		point []byte,
		commitment []byte,
	) bool
	SimpleSign(
		secretKey []byte,
		message []byte,
	) []byte
	SimpleVerify(
		message []byte,
		signature []byte,
		point []byte,
	) bool
}
