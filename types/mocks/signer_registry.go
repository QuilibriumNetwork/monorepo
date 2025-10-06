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

// ValidateSignedX448Key validates a signed X448 key
func (m *MockSignerRegistry) ValidateSignedX448Key(
	signedKey *protobufs.SignedX448Key,
) error {
	args := m.Called(signedKey)
	return args.Error(0)
}

// ValidateSignedDecaf448Key validates a signed Decaf448 key
func (m *MockSignerRegistry) ValidateSignedDecaf448Key(
	signedKey *protobufs.SignedDecaf448Key,
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

// PutSignedX448Key stores a signed X448 key
func (m *MockSignerRegistry) PutSignedX448Key(
	txn store.Transaction,
	address []byte,
	key *protobufs.SignedX448Key,
) error {
	args := m.Called(txn, address, key)
	return args.Error(0)
}

// PutSignedDecaf448Key stores a signed Decaf448 key
func (m *MockSignerRegistry) PutSignedDecaf448Key(
	txn store.Transaction,
	address []byte,
	key *protobufs.SignedDecaf448Key,
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

// GetSignedX448Key retrieves a signed key by address
func (m *MockSignerRegistry) GetSignedX448Key(address []byte) (
	*protobufs.SignedX448Key,
	error,
) {
	args := m.Called(address)
	return args.Get(0).(*protobufs.SignedX448Key), args.Error(1)
}

// GetSignedX448KeysByParent retrieves all signed keys for a parent key
func (m *MockSignerRegistry) GetSignedX448KeysByParent(
	parentKeyAddress []byte,
	keyPurpose string,
) ([]*protobufs.SignedX448Key, error) {
	args := m.Called(parentKeyAddress, keyPurpose)
	return args.Get(0).([]*protobufs.SignedX448Key), args.Error(1)
}

// GetSignedDecaf448Key retrieves a signed key by address
func (m *MockSignerRegistry) GetSignedDecaf448Key(address []byte) (
	*protobufs.SignedDecaf448Key,
	error,
) {
	args := m.Called(address)
	return args.Get(0).(*protobufs.SignedDecaf448Key), args.Error(1)
}

// GetSignedDecaf448KeysByParent retrieves all signed keys for a parent key
func (m *MockSignerRegistry) GetSignedDecaf448KeysByParent(
	parentKeyAddress []byte,
	keyPurpose string,
) ([]*protobufs.SignedDecaf448Key, error) {
	args := m.Called(parentKeyAddress, keyPurpose)
	return args.Get(0).([]*protobufs.SignedDecaf448Key), args.Error(1)
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

// RangeSignedX448Keys returns an iterator over signed keys
func (m *MockSignerRegistry) RangeSignedX448Keys(
	parentKeyAddress []byte,
	keyPurpose string,
) (store.TypedIterator[*protobufs.SignedX448Key], error) {
	args := m.Called(parentKeyAddress, keyPurpose)
	return args.Get(0).(store.TypedIterator[*protobufs.SignedX448Key]),
		args.Error(1)
}

// RangeSignedDecaf448Keys returns an iterator over signed keys
func (m *MockSignerRegistry) RangeSignedDecaf448Keys(
	parentKeyAddress []byte,
	keyPurpose string,
) (store.TypedIterator[*protobufs.SignedDecaf448Key], error) {
	args := m.Called(parentKeyAddress, keyPurpose)
	return args.Get(0).(store.TypedIterator[*protobufs.SignedDecaf448Key]),
		args.Error(1)
}
