package mocks

import (
	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

type MockInclusionProver struct {
	mock.Mock
}

type MockMultiproof struct {
	mock.Mock
}

// FromBytes implements crypto.Multiproof.
func (m *MockMultiproof) FromBytes(buf []byte) error {
	args := m.Called(buf)
	return args.Error(0)
}

// ToBytes implements crypto.Multiproof.
func (m *MockMultiproof) ToBytes() ([]byte, error) {
	args := m.Called()
	return args.Get(0).([]byte), args.Error(1)
}

// GetMulticommitment implements crypto.Multiproof.
func (m *MockMultiproof) GetMulticommitment() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

// GetProof implements crypto.Multiproof.
func (m *MockMultiproof) GetProof() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

// CommitRaw implements crypto.InclusionProver.
func (m *MockInclusionProver) CommitRaw(
	data []byte,
	polySize uint64,
) ([]byte, error) {
	args := m.Called(data, polySize)
	return args.Get(0).([]byte), args.Error(1)
}

// ProveMultiple implements crypto.InclusionProver.
func (m *MockInclusionProver) ProveMultiple(
	commitments [][]byte,
	polys [][]byte,
	indices []uint64,
	polySize uint64,
) crypto.Multiproof {
	args := m.Called(commitments, polys, indices, polySize)
	return args.Get(0).(crypto.Multiproof)
}

// ProveRaw implements crypto.InclusionProver.
func (m *MockInclusionProver) ProveRaw(
	data []byte,
	index int,
	polySize uint64,
) ([]byte, error) {
	args := m.Called(data, index, polySize)
	return args.Get(0).([]byte), args.Error(1)
}

// VerifyMultiple implements crypto.InclusionProver.
func (m *MockInclusionProver) VerifyMultiple(
	commitments [][]byte,
	evaluations [][]byte,
	indices []uint64,
	polySize uint64,
	multiCommitment []byte,
	proof []byte,
) bool {
	args := m.Called(
		commitments,
		evaluations,
		indices,
		polySize,
		multiCommitment,
		proof,
	)
	return args.Bool(0)
}

// VerifyRaw implements crypto.InclusionProver.
func (m *MockInclusionProver) VerifyRaw(
	data []byte,
	commit []byte,
	index uint64,
	proof []byte,
	polySize uint64,
) (bool, error) {
	args := m.Called(data, commit, index, proof, polySize)
	return args.Bool(0), args.Error(1)
}

// NewMultiproof implements crypto.InclusionProver.
func (m *MockInclusionProver) NewMultiproof() crypto.Multiproof {
	args := m.Called()
	return args.Get(0).(crypto.Multiproof)
}

var _ crypto.InclusionProver = (*MockInclusionProver)(nil)
var _ crypto.Multiproof = (*MockMultiproof)(nil)
