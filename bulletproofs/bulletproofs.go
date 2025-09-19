package bulletproofs

import (
	"encoding/binary"
	"math/big"
	"slices"

	"github.com/pkg/errors"
	generated "source.quilibrium.com/quilibrium/monorepo/bulletproofs/generated/bulletproofs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

//go:generate ./generate.sh

type Decaf448BulletproofProver struct{}

// NewBulletproofProver creates a new bulletproof prover instance
func NewBulletproofProver() *Decaf448BulletproofProver {
	return &Decaf448BulletproofProver{}
}

// SimpleSign implements crypto.BulletProver.
func (d *Decaf448BulletproofProver) SimpleSign(
	secretKey []byte,
	message []byte,
) []byte {
	sig := generated.SignSimple(secretKey, message)
	if len(sig) != 112 {
		return nil
	}

	return sig
}

// SimpleVerify implements crypto.BulletproofProver.
func (d *Decaf448BulletproofProver) SimpleVerify(
	message []byte,
	signature []byte,
	point []byte,
) bool {
	if len(signature) != 112 || len(point) != 56 {
		return false
	}

	return generated.VerifySimple(message, signature, point)
}

// SignHidden implements crypto.BulletproofProver.
func (d *Decaf448BulletproofProver) SignHidden(
	sharedSecret []byte,
	spendKey []byte,
	extTranscript []byte,
	amount []byte,
	blind []byte,
) []byte {
	x := generated.ScalarAddition(sharedSecret, spendKey)
	if len(x) != 56 {
		return nil
	}

	paddedAmount := make([]byte, 56)
	copy(paddedAmount, amount)

	return generated.SignHidden(x, extTranscript, paddedAmount, blind)
}

// VerifyHidden implements crypto.BulletproofProver.
func (d *Decaf448BulletproofProver) VerifyHidden(
	challenge []byte,
	extTranscript []byte,
	s1 []byte,
	s2 []byte,
	s3 []byte,
	point []byte,
	commitment []byte,
) bool {
	return generated.VerifyHidden(
		challenge,
		extTranscript,
		s1,
		s2,
		s3,
		point,
		commitment,
	)
}

// GenerateRangeProof implements crypto.BulletproofProver.
func (*Decaf448BulletproofProver) GenerateRangeProof(
	values []uint64,
	blinding []byte,
	bitSize uint64,
) (
	crypto.RangeProofResult,
	error,
) {
	valsc := [][]byte{}
	for _, v := range values {
		b := binary.LittleEndian.AppendUint64([]byte{}, v)
		b = append(b, make([]byte, 48)...)
		valsc = append(valsc, b)
	}
	result := generated.GenerateRangeProof(valsc, blinding, bitSize)
	if len(result.Proof) == 0 {
		return crypto.RangeProofResult{}, errors.New("invalid input")
	}

	return crypto.RangeProofResult{
		Proof:      result.Proof,
		Commitment: result.Commitment,
		Blinding:   result.Blinding,
	}, nil
}

// GenerateInputCommitmentsFromBig implements crypto.BulletproofProver.
func (*Decaf448BulletproofProver) GenerateInputCommitmentsFromBig(
	values []*big.Int,
	blinding []byte,
) []byte {
	valsc := [][]byte{}
	for _, v := range values {
		b := make([]byte, 56)
		v.FillBytes(b)
		slices.Reverse(b)
		valsc = append(valsc, b)
	}
	return generated.GenerateInputCommitments(valsc, blinding)
}

// GenerateRangeProofFromBig implements crypto.BulletproofProver.
func (*Decaf448BulletproofProver) GenerateRangeProofFromBig(
	values []*big.Int,
	blinding []byte,
	bitSize uint64,
) (
	crypto.RangeProofResult,
	error,
) {
	valsc := [][]byte{}
	for _, v := range values {
		b := make([]byte, 56)
		v.FillBytes(b)
		slices.Reverse(b)
		valsc = append(valsc, b)
	}
	result := generated.GenerateRangeProof(valsc, blinding, bitSize)
	if len(result.Proof) == 0 {
		return crypto.RangeProofResult{}, errors.New("invalid input")
	}

	return crypto.RangeProofResult{
		Proof:      result.Proof,
		Commitment: result.Commitment,
		Blinding:   result.Blinding,
	}, nil
}

// VerifyRangeProof implements crypto.BulletproofProver.
func (*Decaf448BulletproofProver) VerifyRangeProof(
	proof []byte,
	commitment []byte,
	bitSize uint64,
) bool {
	return generated.VerifyRangeProof(proof, commitment, bitSize)
}

// SumCheck implements crypto.BulletproofProver.
func (*Decaf448BulletproofProver) SumCheck(
	inputs [][]byte,
	additionalInputs []*big.Int,
	outputs [][]byte,
	additionalOutputs []*big.Int,
) bool {
	invalsc := [][]byte{}
	for _, v := range additionalInputs {
		b := make([]byte, 56)
		v.FillBytes(b)
		slices.Reverse(b)
		invalsc = append(invalsc, b)
	}
	outvalsc := [][]byte{}
	for _, v := range additionalOutputs {
		b := make([]byte, 56)
		v.FillBytes(b)
		slices.Reverse(b)
		outvalsc = append(outvalsc, b)
	}
	return generated.SumCheck(inputs, invalsc, outputs, outvalsc)
}

var _ crypto.BulletproofProver = (*Decaf448BulletproofProver)(nil)

type Decaf448KeyConstructor struct{}

type Decaf448Key struct {
	privateKey []byte
	publicKey  []byte
}

// ScalarMult implements crypto.DecafAgreement.
func (d *Decaf448Key) ScalarMult(scalar []byte) (
	product crypto.DecafAgreement,
	err error,
) {
	out := generated.ScalarMult(d.privateKey, scalar)
	if len(out) != 112 {
		return nil, errors.Wrap(errors.New("unknown"), "scalar mult")
	}

	return &Decaf448Key{
		privateKey: out[:56],
		publicKey:  out[56:],
	}, nil
}

func (d *Decaf448Key) AddScalar(scalar []byte) ([]byte, error) {
	out := generated.ScalarAddition(d.privateKey, scalar)
	if len(out) == 0 {
		return nil, errors.Wrap(errors.New("unknown"), "add scalar")
	}

	return out, nil
}

// Add implements crypto.DecafAgreement.
func (d *Decaf448Key) Add(publicKey []byte) (point []byte, err error) {
	out := generated.PointAddition(d.publicKey, publicKey)
	if len(out) == 0 {
		return nil, errors.Wrap(errors.New("unknown"), "add")
	}

	return out, nil
}

// AgreeWithAndHashToScalar implements crypto.DecafAgreement.
func (d *Decaf448Key) AgreeWithAndHashToScalar(publicKey []byte) (
	shared crypto.DecafAgreement,
	err error,
) {
	out := generated.ScalarMultHashToScalar(d.privateKey, publicKey)
	if len(out) != 112 {
		return nil, errors.Wrap(
			errors.New("unknown"),
			"agree with and hash to scalar",
		)
	}

	return &Decaf448Key{
		privateKey: out[:56],
		publicKey:  out[56:],
	}, nil
}

// AgreeWith implements crypto.Agreement.
func (d *Decaf448Key) AgreeWith(publicKey []byte) (shared []byte, err error) {
	out := generated.ScalarMultPoint(d.privateKey, publicKey)
	if len(out) == 0 {
		return nil, errors.Wrap(errors.New("unknown"), "agree with")
	}

	return out, nil
}

// AgreeWith implements crypto.Agreement.
func (d *Decaf448Key) InverseScalar() (inv crypto.DecafAgreement, err error) {
	out := generated.ScalarInverse(d.privateKey)
	if len(out) != 112 {
		return nil, errors.Wrap(
			errors.New("unknown"),
			"inverse scalar",
		)
	}

	return &Decaf448Key{
		privateKey: out[:56],
		publicKey:  out[56:],
	}, nil
}

// Private implements crypto.Agreement.
func (d *Decaf448Key) Private() []byte {
	return slices.Clone(d.privateKey)
}

// Public implements crypto.Agreement.
func (d *Decaf448Key) Public() []byte {
	return slices.Clone(d.publicKey)
}

// FromBytes implements crypto.DecafConstructor.
func (d *Decaf448KeyConstructor) FromBytes(
	privateKey []byte,
	publicKey []byte,
) (crypto.DecafAgreement, error) {
	return &Decaf448Key{
		privateKey,
		publicKey,
	}, nil
}

// HashToScalar implements crypto.DecafConstructor.
func (d *Decaf448KeyConstructor) HashToScalar(
	input []byte,
) (crypto.DecafAgreement, error) {
	out := generated.HashToScalar(input)
	if len(out) != 112 {
		return nil, errors.Wrap(errors.New("unknown"), "hash to scalar")
	}

	return &Decaf448Key{
		privateKey: out[:56],
		publicKey:  out[56:],
	}, nil
}

// NewFromScalar implements crypto.DecafConstructor.
func (d *Decaf448KeyConstructor) NewFromScalar(
	input []byte,
) (crypto.DecafAgreement, error) {
	out := generated.ScalarToPoint(input)
	if len(out) != 56 {
		return nil, errors.Wrap(errors.New("unknown"), "new from scalar")
	}

	priv := slices.Clone(input)
	return &Decaf448Key{
		privateKey: priv,
		publicKey:  out,
	}, nil
}

// New implements crypto.DecafConstructor.
func (d *Decaf448KeyConstructor) New() (crypto.DecafAgreement, error) {
	out := generated.Keygen()
	if len(out) != 112 {
		return nil, errors.Wrap(errors.New("unknown"), "new")
	}

	return &Decaf448Key{
		privateKey: out[:56],
		publicKey:  out[56:],
	}, nil
}

// AltGenerator implements crypto.DecafConstructor.
func (d *Decaf448KeyConstructor) AltGenerator() []byte {
	return generated.AltGenerator()
}

var _ crypto.BulletproofProver = (*Decaf448BulletproofProver)(nil)
var _ crypto.DecafConstructor = (*Decaf448KeyConstructor)(nil)
