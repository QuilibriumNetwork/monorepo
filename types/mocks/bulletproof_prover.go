package mocks

import (
	"math/big"

	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

// MockBulletproofProver mocks the BulletproofProver interface for testing
type MockBulletproofProver struct {
	mock.Mock
}

// SimpleVerify implements crypto.BulletproofProver.
func (b *MockBulletproofProver) SimpleVerify(
	message []byte,
	signature []byte,
	point []byte,
) bool {
	args := b.Called(message, signature, point)
	return args.Bool(0)
}

// SimpleSign implements crypto.BulletproofProver.
func (b *MockBulletproofProver) SimpleSign(
	secretKey []byte,
	message []byte,
) []byte {
	args := b.Called(secretKey, message)
	return args.Get(0).([]byte)
}

// SignHidden implements crypto.BulletproofProver.
func (b *MockBulletproofProver) SignHidden(
	sharedSecret []byte,
	spendKey []byte,
	transcript []byte,
	amount []byte,
	blind []byte,
) []byte {
	args := b.Called(sharedSecret, spendKey, transcript, amount, blind)
	return args.Get(0).([]byte)
}

// VerifyHidden implements crypto.BulletproofProver.
func (b *MockBulletproofProver) VerifyHidden(
	challenge []byte,
	transcript []byte,
	s1 []byte,
	s2 []byte,
	s3 []byte,
	point []byte,
	commitment []byte,
) bool {
	args := b.Called(challenge, transcript, s1, s2, s3, point, commitment)
	return args.Bool(0)
}

// GenerateInputCommitmentsFromBig implements crypto.BulletproofProver.
func (b *MockBulletproofProver) GenerateInputCommitmentsFromBig(
	values []*big.Int,
	blinding []byte,
) []byte {
	args := b.Called(values, blinding)
	return args.Get(0).([]byte)
}

// GenerateRangeProof implements crypto.BulletproofProver.
func (b *MockBulletproofProver) GenerateRangeProof(
	values []uint64,
	blinding []byte,
	bitSize uint64,
) (crypto.RangeProofResult, error) {
	args := b.Called(values, blinding, bitSize)
	return args.Get(0).(crypto.RangeProofResult), args.Error(1)
}

// GenerateRangeProofFromBig implements crypto.BulletproofProver.
func (b *MockBulletproofProver) GenerateRangeProofFromBig(
	values []*big.Int,
	blinding []byte,
	bitSize uint64,
) (crypto.RangeProofResult, error) {
	args := b.Called(values, blinding, bitSize)
	return args.Get(0).(crypto.RangeProofResult), args.Error(1)
}

// SumCheck implements crypto.BulletproofProver.
func (b *MockBulletproofProver) SumCheck(
	inputs [][]byte,
	additionalInputs []*big.Int,
	outputs [][]byte,
	additionalOutputs []*big.Int,
) bool {
	args := b.Called(inputs, additionalInputs, outputs, additionalOutputs)
	return args.Bool(0)
}

// VerifyRangeProof implements crypto.BulletproofProver.
func (b *MockBulletproofProver) VerifyRangeProof(
	proof []byte,
	commitment []byte,
	bitSize uint64,
) bool {
	args := b.Called(proof, commitment, bitSize)
	return args.Bool(0)
}

// Ensure MockBulletproofProver implements BulletproofProver
var _ crypto.BulletproofProver = (*MockBulletproofProver)(nil)
