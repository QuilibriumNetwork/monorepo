package mocks

import (
	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

var _ store.KeyStore = (*MockKeyStore)(nil)

// MockKeyStore is a minimal mock for store.KeyStore
type MockKeyStore struct {
	mock.Mock
}

// NewTransaction implements store.KeyStore.
func (m *MockKeyStore) NewTransaction() (store.Transaction, error) {
	args := m.Called()
	return args.Get(0).(store.Transaction), args.Error(1)
}

// PutIdentityKey implements store.KeyStore.
func (m *MockKeyStore) PutIdentityKey(
	txn store.Transaction,
	address []byte,
	identityKey *protobufs.Ed448PublicKey,
) error {
	args := m.Called(txn, address, identityKey)
	return args.Error(0)
}

// GetIdentityKey implements store.KeyStore.
func (m *MockKeyStore) GetIdentityKey(address []byte) (
	*protobufs.Ed448PublicKey,
	error,
) {
	args := m.Called(address)
	return args.Get(0).(*protobufs.Ed448PublicKey), args.Error(1)
}

// PutProvingKey implements store.KeyStore.
func (m *MockKeyStore) PutProvingKey(
	txn store.Transaction,
	address []byte,
	provingKey *protobufs.BLS48581SignatureWithProofOfPossession,
) error {
	args := m.Called(txn, address, provingKey)
	return args.Error(0)
}

// GetProvingKey implements store.KeyStore.
func (m *MockKeyStore) GetProvingKey(
	address []byte,
) (*protobufs.BLS48581SignatureWithProofOfPossession, error) {
	args := m.Called(address)
	return args.Get(0).(*protobufs.BLS48581SignatureWithProofOfPossession),
		args.Error(1)
}

// PutCrossSignature implements store.KeyStore.
func (m *MockKeyStore) PutCrossSignature(
	txn store.Transaction,
	identityKeyAddress []byte,
	provingKeyAddress []byte,
	identityKeySignatureOfProvingKey []byte,
	provingKeySignatureOfIdentityKey []byte,
) error {
	args := m.Called(
		txn,
		identityKeyAddress,
		provingKeyAddress,
		identityKeySignatureOfProvingKey,
		provingKeySignatureOfIdentityKey,
	)
	return args.Error(0)
}

// GetCrossSignatureByIdentityKey implements store.KeyStore.
func (m *MockKeyStore) GetCrossSignatureByIdentityKey(
	identityKeyAddress []byte,
) ([]byte, error) {
	args := m.Called(identityKeyAddress)
	return args.Get(0).([]byte), args.Error(1)
}

// GetCrossSignatureByProvingKey implements store.KeyStore.
func (m *MockKeyStore) GetCrossSignatureByProvingKey(
	provingKeyAddress []byte,
) ([]byte, error) {
	args := m.Called(provingKeyAddress)
	return args.Get(0).([]byte), args.Error(1)
}

// PutSignedX448Key implements store.KeyStore.
func (m *MockKeyStore) PutSignedX448Key(
	txn store.Transaction,
	address []byte,
	key *protobufs.SignedX448Key,
) error {
	args := m.Called(txn, address, key)
	return args.Error(0)
}

// GetSignedX448Key implements store.KeyStore.
func (m *MockKeyStore) GetSignedX448Key(
	address []byte,
) (*protobufs.SignedX448Key, error) {
	args := m.Called(address)
	return args.Get(0).(*protobufs.SignedX448Key), args.Error(1)
}

// GetSignedX448KeysByParent implements store.KeyStore.
func (m *MockKeyStore) GetSignedX448KeysByParent(
	parentKeyAddress []byte,
	keyPurpose string,
) ([]*protobufs.SignedX448Key, error) {
	args := m.Called(parentKeyAddress, keyPurpose)
	return args.Get(0).([]*protobufs.SignedX448Key), args.Error(1)
}

// DeleteSignedX448Key implements store.KeyStore.
func (m *MockKeyStore) DeleteSignedX448Key(
	txn store.Transaction,
	address []byte,
) error {
	args := m.Called(txn, address)
	return args.Error(0)
}

// PutSignedDecaf448Key implements store.KeyStore.
func (m *MockKeyStore) PutSignedDecaf448Key(
	txn store.Transaction,
	address []byte,
	key *protobufs.SignedDecaf448Key,
) error {
	args := m.Called(txn, address, key)
	return args.Error(0)
}

// GetSignedDecaf448Key implements store.KeyStore.
func (m *MockKeyStore) GetSignedDecaf448Key(
	address []byte,
) (*protobufs.SignedDecaf448Key, error) {
	args := m.Called(address)
	return args.Get(0).(*protobufs.SignedDecaf448Key), args.Error(1)
}

// GetSignedDecaf448KeysByParent implements store.KeyStore.
func (m *MockKeyStore) GetSignedDecaf448KeysByParent(
	parentKeyAddress []byte,
	keyPurpose string,
) ([]*protobufs.SignedDecaf448Key, error) {
	args := m.Called(parentKeyAddress, keyPurpose)
	return args.Get(0).([]*protobufs.SignedDecaf448Key), args.Error(1)
}

// DeleteSignedDecaf448Key implements store.KeyStore.
func (m *MockKeyStore) DeleteSignedDecaf448Key(
	txn store.Transaction,
	address []byte,
) error {
	args := m.Called(txn, address)
	return args.Error(0)
}

// ReapExpiredKeys implements store.KeyStore.
func (m *MockKeyStore) ReapExpiredKeys() error {
	args := m.Called()
	return args.Error(0)
}

// GetKeyRegistry implements store.KeyStore.
func (m *MockKeyStore) GetKeyRegistry(
	identityKeyAddress []byte,
) (*protobufs.KeyRegistry, error) {
	args := m.Called(identityKeyAddress)
	return args.Get(0).(*protobufs.KeyRegistry), args.Error(1)
}

// GetKeyRegistryByProver implements store.KeyStore.
func (m *MockKeyStore) GetKeyRegistryByProver(
	proverKeyAddress []byte,
) (*protobufs.KeyRegistry, error) {
	args := m.Called(proverKeyAddress)
	return args.Get(0).(*protobufs.KeyRegistry), args.Error(1)
}

// RangeProvingKeys implements store.KeyStore.
func (m *MockKeyStore) RangeProvingKeys() (
	store.TypedIterator[*protobufs.BLS48581SignatureWithProofOfPossession],
	error,
) {
	args := m.Called()
	return args.Get(0).(store.TypedIterator[*protobufs.BLS48581SignatureWithProofOfPossession]),
		args.Error(1)
}

// RangeIdentityKeys implements store.KeyStore.
func (m *MockKeyStore) RangeIdentityKeys() (
	store.TypedIterator[*protobufs.Ed448PublicKey],
	error,
) {
	args := m.Called()
	return args.Get(0).(store.TypedIterator[*protobufs.Ed448PublicKey]),
		args.Error(1)
}

// RangeSignedX448Keys implements store.KeyStore.
func (m *MockKeyStore) RangeSignedX448Keys(
	parentKeyAddress []byte,
	keyPurpose string,
) (store.TypedIterator[*protobufs.SignedX448Key], error) {
	args := m.Called(parentKeyAddress, keyPurpose)
	return args.Get(0).(store.TypedIterator[*protobufs.SignedX448Key]),
		args.Error(1)
}

// RangeSignedKeys implements store.KeyStore.
func (m *MockKeyStore) RangeSignedDecaf448Keys(
	parentKeyAddress []byte,
	keyPurpose string,
) (store.TypedIterator[*protobufs.SignedDecaf448Key], error) {
	args := m.Called(parentKeyAddress, keyPurpose)
	return args.Get(0).(store.TypedIterator[*protobufs.SignedDecaf448Key]),
		args.Error(1)
}
