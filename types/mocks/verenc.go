package mocks

import (
	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

type MockVerifiableEncryptor struct {
	mock.Mock
}

type MockVerEncProof struct {
	mock.Mock
}

type MockVerEnc struct {
	mock.Mock
}

// GetStatement implements crypto.VerEnc.
func (m *MockVerEnc) GetStatement() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

// ToBytes implements crypto.VerEnc.
func (m *MockVerEnc) ToBytes() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

// Verify implements crypto.VerEnc.
func (m *MockVerEnc) Verify(proof []byte) bool {
	args := m.Called(proof)
	return args.Bool(0)
}

// Compress implements crypto.VerEncProof.
func (m *MockVerEncProof) Compress() crypto.VerEnc {
	args := m.Called()
	return args.Get(0).(crypto.VerEnc)
}

// ToBytes implements crypto.VerEncProof.
func (m *MockVerEncProof) ToBytes() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

// GetEncryptionKey implements crypto.VerEncProof.
func (m *MockVerEncProof) GetEncryptionKey() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

// Verify implements crypto.VerEncProof.
func (m *MockVerEncProof) Verify() bool {
	args := m.Called()
	return args.Bool(0)
}

// VerifyStatement implements crypto.VerEncProof.
func (m *MockVerEncProof) VerifyStatement(input []byte) bool {
	args := m.Called(input)
	return args.Bool(0)
}

// GetStatement implements crypto.VerEncProof.
func (m *MockVerEncProof) GetStatement() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

// Decrypt implements crypto.VerifiableEncryptor.
func (m *MockVerifiableEncryptor) Decrypt(
	encrypted []crypto.VerEnc,
	decryptionKey []byte,
) []byte {
	args := m.Called(encrypted, decryptionKey)
	return args.Get(0).([]byte)
}

// Encrypt implements crypto.VerifiableEncryptor.
func (m *MockVerifiableEncryptor) Encrypt(
	data []byte,
	publicKey []byte,
) []crypto.VerEncProof {
	args := m.Called(data, publicKey)
	return args.Get(0).([]crypto.VerEncProof)
}

// EncryptAndCompress implements crypto.VerifiableEncryptor.
func (m *MockVerifiableEncryptor) EncryptAndCompress(
	data []byte,
	publicKey []byte,
) []crypto.VerEnc {
	args := m.Called(data, publicKey)
	return args.Get(0).([]crypto.VerEnc)
}

// FromBytes implements crypto.VerifiableEncryptor.
func (m *MockVerifiableEncryptor) FromBytes(data []byte) crypto.VerEnc {
	args := m.Called(data)
	return args.Get(0).(crypto.VerEnc)
}

// ProofFromBytes implements crypto.VerifiableEncryptor.
func (m *MockVerifiableEncryptor) ProofFromBytes(
	data []byte,
) crypto.VerEncProof {
	args := m.Called(data)
	return args.Get(0).(crypto.VerEncProof)
}

var _ crypto.VerifiableEncryptor = (*MockVerifiableEncryptor)(nil)
var _ crypto.VerEncProof = (*MockVerEncProof)(nil)
var _ crypto.VerEnc = (*MockVerEnc)(nil)
