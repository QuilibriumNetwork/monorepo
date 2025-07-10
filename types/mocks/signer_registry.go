package mocks

import (
	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

type MockSignerRegistry struct {
	mock.Mock
}

func (m *MockSignerRegistry) GetSigner(address [32]byte) (interface{}, error) {
	args := m.Called(address)
	return args.Get(0), args.Error(1)
}

func (m *MockSignerRegistry) GetSignerByPublicKey(
	publicKey []byte,
) (interface{}, error) {
	args := m.Called(publicKey)
	return args.Get(0), args.Error(1)
}

func (m *MockSignerRegistry) ValidateProvingKey(
	provingKey *protobufs.ProvingKeyAnnouncement,
) error {
	args := m.Called(provingKey)
	return args.Error(0)
}

func (m *MockSignerRegistry) ValidateKeyBundle(
	bundle *protobufs.KeyBundleAnnouncement,
) error {
	args := m.Called(bundle)
	return args.Error(0)
}

func (m *MockSignerRegistry) IncludeProvingKey(
	inclusionCommitment *protobufs.InclusionCommitment,
	txn store.Transaction,
) error {
	args := m.Called(inclusionCommitment, txn)
	return args.Error(0)
}

func (m *MockSignerRegistry) StageProvingKey(
	provingKey *protobufs.ProvingKeyAnnouncement,
) error {
	args := m.Called(provingKey)
	return args.Error(0)
}

func (m *MockSignerRegistry) PutKeyBundle(
	provingKey []byte,
	keyBundle *protobufs.InclusionCommitment,
	txn store.Transaction,
) error {
	args := m.Called(provingKey, keyBundle, txn)
	return args.Error(0)
}

func (m *MockSignerRegistry) GetProvingKey(
	provingKey []byte,
) (*protobufs.InclusionCommitment, error) {
	args := m.Called(provingKey)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*protobufs.InclusionCommitment), args.Error(1)
}

func (m *MockSignerRegistry) GetLatestKeyBundle(
	provingKey []byte,
) (*protobufs.InclusionCommitment, error) {
	args := m.Called(provingKey)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*protobufs.InclusionCommitment), args.Error(1)
}

func (m *MockSignerRegistry) GetKeyBundle(
	provingKey []byte,
	frameNumber uint64,
) (*protobufs.InclusionCommitment, error) {
	args := m.Called(provingKey, frameNumber)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*protobufs.InclusionCommitment), args.Error(1)
}

func (m *MockSignerRegistry) GetStagedProvingKey(
	provingKey []byte,
) (*protobufs.ProvingKeyAnnouncement, error) {
	args := m.Called(provingKey)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*protobufs.ProvingKeyAnnouncement), args.Error(1)
}
