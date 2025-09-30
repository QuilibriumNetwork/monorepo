package mocks

import (
	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
)

// MockKeyManager mocks the KeyManager interface for testing
type MockKeyRing struct {
	mock.Mock
}

// GetAgreementKey implements keys.KeyRing.
func (m *MockKeyRing) GetAgreementKey(
	reference string,
	address []byte,
	keyType crypto.KeyType,
) (crypto.Agreement, error) {
	args := m.Called(reference, address, keyType)
	return args.Get(0).(crypto.Agreement), args.Error(1)
}

// GetSigningKey implements keys.KeyRing.
func (m *MockKeyRing) GetSigningKey(
	id string,
	keyType crypto.KeyType,
) (crypto.Signer, error) {
	args := m.Called(id, keyType)
	return args.Get(0).(crypto.Signer), args.Error(1)
}

// ValidateSignature implements keys.KeyRing.
func (m *MockKeyRing) ValidateSignature(
	keyType crypto.KeyType,
	publicKey []byte,
	message []byte,
	signature []byte,
	domain []byte,
) (bool, error) {
	args := m.Called(
		keyType,
		publicKey,
		message,
		signature,
		domain,
	)
	return args.Bool(0), args.Error(1)
}

// MockKeyManager mocks the KeyManager interface for testing
type MockKeyManager struct {
	mock.Mock
}

// Aggregate implements keys.KeyManager.
func (k *MockKeyManager) Aggregate(
	publicKeys [][]byte,
	signatures [][]byte,
) (crypto.BlsAggregateOutput, error) {
	args := k.Called(publicKeys, signatures)
	return args.Get(0).(crypto.BlsAggregateOutput), args.Error(1)
}

// ValidateSignature implements keys.KeyManager.
func (k *MockKeyManager) ValidateSignature(
	keyType crypto.KeyType,
	publicKey []byte,
	message []byte,
	signature []byte,
	domain []byte,
) (bool, error) {
	args := k.Called(keyType, publicKey, message, signature, domain)
	return args.Bool(0), args.Error(1)
}

// CreateAgreementKey implements keys.KeyManager.
func (k *MockKeyManager) CreateAgreementKey(
	id string,
	keyType crypto.KeyType,
) (crypto.Agreement, error) {
	args := k.Called(id, keyType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(crypto.Agreement), args.Error(1)
}

// CreateSigningKey implements keys.KeyManager.
func (k *MockKeyManager) CreateSigningKey(
	id string,
	keyType crypto.KeyType,
) (crypto.Signer, []byte, error) {
	args := k.Called(id, keyType)
	if args.Get(0) == nil {
		return nil, nil, args.Error(1)
	}
	return args.Get(0).(crypto.Signer), args.Get(1).([]byte), args.Error(2)
}

// DeleteKey implements keys.KeyManager.
func (k *MockKeyManager) DeleteKey(id string) error {
	args := k.Called(id)
	return args.Error(0)
}

// GetAgreementKey implements keys.KeyManager.
func (k *MockKeyManager) GetAgreementKey(id string) (crypto.Agreement, error) {
	args := k.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(crypto.Agreement), args.Error(1)
}

// GetRawKey implements keys.KeyManager.
func (k *MockKeyManager) GetRawKey(id string) (*keys.Key, error) {
	args := k.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keys.Key), args.Error(1)
}

// GetSigningKey implements keys.KeyManager.
func (k *MockKeyManager) GetSigningKey(id string) (crypto.Signer, error) {
	args := k.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(crypto.Signer), args.Error(1)
}

// ListKeys implements keys.KeyManager.
func (k *MockKeyManager) ListKeys() ([]*keys.Key, error) {
	args := k.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*keys.Key), args.Error(1)
}

// PutRawKey implements keys.KeyManager.
func (k *MockKeyManager) PutRawKey(key *keys.Key) error {
	args := k.Called(key)
	return args.Error(0)
}

var _ keys.KeyManager = (*MockKeyManager)(nil)
var _ keys.KeyRing = (*MockKeyRing)(nil)
