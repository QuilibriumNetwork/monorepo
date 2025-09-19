package mocks

import (
	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

type MockSignerRegistry struct {
	mock.Mock
}

// GetKeyRegistry retrieves the complete key registry for an identity key
// address
func (m *MockSignerRegistry) GetKeyRegistry(identityKeyAddress []byte) (
	*protobufs.KeyRegistry,
	error,
) {
	args := m.Called(identityKeyAddress)
	return args.Get(0).(*protobufs.KeyRegistry), args.Error(1)
}

// GetKeyRegistryByProver retrieves the complete key registry for a prover key
// address
func (m *MockSignerRegistry) GetKeyRegistryByProver(proverKeyAddress []byte) (
	*protobufs.KeyRegistry,
	error,
) {
	args := m.Called(proverKeyAddress)
	return args.Get(0).(*protobufs.KeyRegistry), args.Error(1)
}

// ValidateIdentityKey validates an Ed448 identity key
func (m *MockSignerRegistry) ValidateIdentityKey(
	identityKey *protobufs.Ed448PublicKey,
) error {
	args := m.Called(identityKey)
	return args.Error(0)
}

// ValidateProvingKey validates a BLS48581 proving key with proof of possession
func (m *MockSignerRegistry) ValidateProvingKey(
	provingKey *protobufs.BLS48581SignatureWithProofOfPossession,
) error {
	args := m.Called(provingKey)
	return args.Error(0)
}

// ValidateSignedKey validates a signed X448 key
func (m *MockSignerRegistry) ValidateSignedKey(
	signedKey *protobufs.SignedX448Key,
) error {
	args := m.Called(signedKey)
	return args.Error(0)
}

// PutIdentityKey stores an identity key
func (m *MockSignerRegistry) PutIdentityKey(
	txn store.Transaction,
	address []byte,
	identityKey *protobufs.Ed448PublicKey,
) error {
	args := m.Called(txn, address, identityKey)
	return args.Error(0)
}

// PutProvingKey stores a proving key with proof of possession
func (m *MockSignerRegistry) PutProvingKey(
	txn store.Transaction,
	address []byte,
	provingKey *protobufs.BLS48581SignatureWithProofOfPossession,
) error {
	args := m.Called(txn, address, provingKey)
	return args.Error(0)
}

// PutCrossSignature stores cross signatures between identity and proving keys
func (m *MockSignerRegistry) PutCrossSignature(
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

// PutSignedKey stores a signed X448 key
func (m *MockSignerRegistry) PutSignedKey(
	txn store.Transaction,
	address []byte,
	key *protobufs.SignedX448Key,
) error {
	args := m.Called(txn, address, key)
	return args.Error(0)
}

// GetIdentityKey retrieves an identity key by address
func (m *MockSignerRegistry) GetIdentityKey(address []byte) (
	*protobufs.Ed448PublicKey,
	error,
) {
	args := m.Called(address)
	return args.Get(0).(*protobufs.Ed448PublicKey), args.Error(1)
}

// GetProvingKey retrieves a proving key by address
func (m *MockSignerRegistry) GetProvingKey(address []byte) (
	*protobufs.BLS48581SignatureWithProofOfPossession,
	error,
) {
	args := m.Called(address)
	return args.Get(0).(*protobufs.BLS48581SignatureWithProofOfPossession),
		args.Error(1)
}

// GetSignedKey retrieves a signed key by address
func (m *MockSignerRegistry) GetSignedKey(address []byte) (
	*protobufs.SignedX448Key,
	error,
) {
	args := m.Called(address)
	return args.Get(0).(*protobufs.SignedX448Key), args.Error(1)
}

// GetSignedKeysByParent retrieves all signed keys for a parent key
func (m *MockSignerRegistry) GetSignedKeysByParent(
	parentKeyAddress []byte,
	keyPurpose string,
) ([]*protobufs.SignedX448Key, error) {
	args := m.Called(parentKeyAddress, keyPurpose)
	return args.Get(0).([]*protobufs.SignedX448Key), args.Error(1)
}

// RangeProvingKeys returns an iterator over all proving keys
func (m *MockSignerRegistry) RangeProvingKeys() (
	store.TypedIterator[*protobufs.BLS48581SignatureWithProofOfPossession],
	error,
) {
	args := m.Called()
	return args.Get(0).(store.TypedIterator[*protobufs.BLS48581SignatureWithProofOfPossession]),
		args.Error(1)
}

// RangeIdentityKeys returns an iterator over all identity keys
func (m *MockSignerRegistry) RangeIdentityKeys() (
	store.TypedIterator[*protobufs.Ed448PublicKey],
	error,
) {
	args := m.Called()
	return args.Get(0).(store.TypedIterator[*protobufs.Ed448PublicKey]),
		args.Error(1)
}

// RangeSignedKeys returns an iterator over signed keys
func (m *MockSignerRegistry) RangeSignedKeys(
	parentKeyAddress []byte,
	keyPurpose string,
) (store.TypedIterator[*protobufs.SignedX448Key], error) {
	args := m.Called(parentKeyAddress, keyPurpose)
	return args.Get(0).(store.TypedIterator[*protobufs.SignedX448Key]),
		args.Error(1)
}
