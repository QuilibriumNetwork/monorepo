package mocks

import (
	"crypto"
	"io"

	"github.com/stretchr/testify/mock"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

type MockBlsConstructor struct {
	mock.Mock
}

// VerifySignatureRaw implements crypto.BlsConstructor.
func (m *MockBlsConstructor) VerifySignatureRaw(
	publicKeyG2 []byte,
	signatureG1 []byte,
	message []byte,
	context []byte,
) bool {
	args := m.Called(publicKeyG2, signatureG1, message, context)
	return args.Bool(0)
}

func (m *MockBlsConstructor) New() (qcrypto.Signer, []byte, error) {
	args := m.Called()
	return args.Get(0).(qcrypto.Signer), args.Get(1).([]byte), args.Error(2)
}

func (m *MockBlsConstructor) FromBytes(
	privKey, pubKey []byte,
) (qcrypto.Signer, error) {
	args := m.Called(privKey, pubKey)
	return args.Get(0).(qcrypto.Signer), args.Error(1)
}

func (m *MockBlsConstructor) Aggregate(
	publicKeys [][]byte,
	signatures [][]byte,
) (
	qcrypto.BlsAggregateOutput,
	error,
) {
	args := m.Called(publicKeys, signatures)
	return args.Get(0).(qcrypto.BlsAggregateOutput), args.Error(1)
}

type MockBLSSigner struct {
	mock.Mock
}

// GetType implements crypto.Signer.
func (m *MockBLSSigner) GetType() qcrypto.KeyType {
	return qcrypto.KeyTypeBLS48581G1
}

// Private implements crypto.Signer.
func (m *MockBLSSigner) Private() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

// Public implements crypto.Signer.
func (m *MockBLSSigner) Public() crypto.PublicKey {
	args := m.Called()
	return args.Get(0).(crypto.PublicKey)
}

// Sign implements crypto.Signer.
func (m *MockBLSSigner) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
) (signature []byte, err error) {
	args := m.Called(rand, digest, opts)
	return args.Get(0).([]byte), args.Error(1)
}

// SignWithDomain implements crypto.Signer.
func (m *MockBLSSigner) SignWithDomain(
	message []byte,
	domain []byte,
) (signature []byte, err error) {
	args := m.Called(message, domain)
	return args.Get(0).([]byte), args.Error(1)
}

type MockBlsAggregateOutput struct {
	mock.Mock
}

// GetAggregatePublicKey implements crypto.BlsAggregateOutput.
func (m *MockBlsAggregateOutput) GetAggregatePublicKey() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

// GetAggregateSignature implements crypto.BlsAggregateOutput.
func (m *MockBlsAggregateOutput) GetAggregateSignature() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

// Verify implements crypto.BlsAggregateOutput.
func (m *MockBlsAggregateOutput) Verify(msg []byte, domain []byte) bool {
	args := m.Called(msg, domain)
	return args.Bool(0)
}

var _ qcrypto.BlsConstructor = (*MockBlsConstructor)(nil)
var _ qcrypto.Signer = (*MockBLSSigner)(nil)
var _ qcrypto.BlsAggregateOutput = (*MockBlsAggregateOutput)(nil)
