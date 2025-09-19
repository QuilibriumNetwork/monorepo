package mocks

import (
	"bytes"
	"crypto/rand"
	"math/big"

	"golang.org/x/crypto/sha3"

	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

var _ qcrypto.DecafConstructor = (*MockDecafConstructor)(nil)
var _ qcrypto.DecafAgreement = (*MockDecafAgreement)(nil)

// MockDecafConstructor is a non-overrideable mock that basically cheats at
// confirming arithmetic by simply using integers modulo 56-byte max
type MockDecafConstructor struct{}

// AltGenerator implements crypto.DecafConstructor.
func (m *MockDecafConstructor) AltGenerator() []byte {
	out := make([]byte, 56)
	out[0] = 0xff
	return out
}

// NewFromScalar implements crypto.DecafConstructor.
func (m *MockDecafConstructor) NewFromScalar(input []byte) (
	qcrypto.DecafAgreement,
	error,
) {
	return &MockDecafAgreement{
		privateKey: input,
		publicKey:  input,
	}, nil
}

// New implements crypto.DecafConstructor.
func (m *MockDecafConstructor) New() (qcrypto.DecafAgreement, error) {
	b := make([]byte, 56)
	rand.Read(b)
	return &MockDecafAgreement{
		privateKey: b,
		publicKey:  b,
	}, nil
}

// FromBytes implements crypto.DecafConstructor.
func (m *MockDecafConstructor) FromBytes(
	privKey, pubKey []byte,
) (qcrypto.DecafAgreement, error) {
	return &MockDecafAgreement{
		privateKey: privKey,
		publicKey:  pubKey,
	}, nil
}

// HashToScalar implements crypto.DecafConstructor.
func (m *MockDecafConstructor) HashToScalar(input []byte) (
	qcrypto.DecafAgreement,
	error,
) {
	h := sha3.NewShake256()
	h.Write(input)
	out := make([]byte, 112)
	h.Read(out)

	return &MockDecafAgreement{
		privateKey: out[:56],
		publicKey:  out[:56],
	}, nil
}

// Mock Decaf agreement implementation
type MockDecafAgreement struct {
	privateKey []byte
	publicKey  []byte
}

// ScalarMult implements crypto.DecafAgreement.
func (m *MockDecafAgreement) ScalarMult(scalar []byte) (product qcrypto.DecafAgreement, err error) {
	out := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).SetBytes(m.privateKey),
			new(big.Int).SetBytes(scalar),
		),
		new(big.Int).SetBytes(bytes.Repeat([]byte{0xff}, 56)),
	).FillBytes(make([]byte, 56))

	return &MockDecafAgreement{
		privateKey: out,
		publicKey:  out,
	}, nil
}

// Add implements crypto.DecafAgreement.
func (m *MockDecafAgreement) Add(publicKey []byte) (point []byte, err error) {
	return new(big.Int).Mod(
		new(big.Int).Add(
			new(big.Int).SetBytes(m.publicKey),
			new(big.Int).SetBytes(publicKey),
		),
		new(big.Int).SetBytes(bytes.Repeat([]byte{0xff}, 56)),
	).FillBytes(make([]byte, 56)), nil
}

// InverseScalar implements crypto.DecafAgreement.
func (m *MockDecafAgreement) InverseScalar() (
	inv qcrypto.DecafAgreement,
	err error,
) {
	invert := new(big.Int).ModInverse(
		new(big.Int).SetBytes(m.privateKey),
		new(big.Int).SetBytes(bytes.Repeat([]byte{0xff}, 56)),
	).FillBytes(make([]byte, 56))

	return &MockDecafAgreement{
		privateKey: invert,
		publicKey:  invert,
	}, nil
}

// AgreeWithAndHashToScalar implements crypto.DecafAgreement.
func (m *MockDecafAgreement) AgreeWithAndHashToScalar(
	publicKey []byte,
) (shared qcrypto.DecafAgreement, err error) {
	h := sha3.Sum512(
		new(big.Int).Mod(
			new(big.Int).Mul(
				new(big.Int).SetBytes(m.privateKey),
				new(big.Int).SetBytes(publicKey),
			),
			new(big.Int).SetBytes(bytes.Repeat([]byte{0xff}, 56)),
		).FillBytes(make([]byte, 56)),
	)

	return &MockDecafAgreement{
		privateKey: h[:56],
		publicKey:  h[:56],
	}, nil
}

// AgreeWith implements crypto.Agreement.
func (m *MockDecafAgreement) AgreeWith(
	publicKey []byte,
) (shared []byte, err error) {
	return new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).SetBytes(m.privateKey),
			new(big.Int).SetBytes(publicKey),
		),
		new(big.Int).SetBytes(bytes.Repeat([]byte{0xff}, 56)),
	).FillBytes(make([]byte, 56)), nil
}

// Private implements crypto.Agreement.
func (m *MockDecafAgreement) Private() []byte {
	return m.privateKey
}

// Public implements crypto.Agreement.
func (m *MockDecafAgreement) Public() []byte {
	return m.publicKey
}
