package mocks

import (
	"github.com/stretchr/testify/mock"

	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

type MockFrameProver struct {
	mock.Mock
}

func (m *MockFrameProver) ProveFrameHeaderGenesis(
	address []byte,
	difficulty uint32,
	input []byte,
	feeMultiplierVote uint64,
) (*protobufs.FrameHeader, error) {
	args := m.Called(address, difficulty, input, feeMultiplierVote)
	return args.Get(0).(*protobufs.FrameHeader), args.Error(1)
}

// GetFrameSignaturePayload implements crypto.FrameProver.
func (m *MockFrameProver) GetFrameSignaturePayload(
	frame *protobufs.FrameHeader,
) ([]byte, error) {
	args := m.Called(frame)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockFrameProver) VerifyFrameHeaderSignature(
	frame *protobufs.FrameHeader,
	bls crypto.BlsConstructor,
) (bool, error) {
	args := m.Called(frame, bls)
	return args.Bool(0), args.Error(1)
}

// GetGlobalFrameSignaturePayload implements crypto.FrameProver.
func (m *MockFrameProver) GetGlobalFrameSignaturePayload(
	frame *protobufs.GlobalFrameHeader,
) ([]byte, error) {
	args := m.Called(frame)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockFrameProver) VerifyGlobalHeaderSignature(
	frame *protobufs.GlobalFrameHeader,
	bls crypto.BlsConstructor,
) (bool, error) {
	args := m.Called(frame, bls)
	return args.Bool(0), args.Error(1)
}

func (m *MockFrameProver) ProveFrameHeader(
	previousFrame *protobufs.FrameHeader,
	address []byte,
	requestsRoot []byte,
	stateRoots [][]byte,
	prover []byte,
	provingKey crypto.Signer,
	timestamp int64,
	difficulty uint32,
	feeMultiplierVote uint64,
	proverIndex uint8,
) (*protobufs.FrameHeader, error) {
	args := m.Called(
		previousFrame,
		address,
		requestsRoot,
		stateRoots,
		prover,
		provingKey,
		timestamp,
		difficulty,
		feeMultiplierVote,
		proverIndex,
	)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*protobufs.FrameHeader), args.Error(1)
}

func (m *MockFrameProver) VerifyFrameHeader(
	frame *protobufs.FrameHeader,
	bls crypto.BlsConstructor,
) ([]uint8, error) {
	args := m.Called(frame, bls)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uint8), args.Error(1)
}

func (m *MockFrameProver) ProveGlobalFrameHeader(
	previousFrame *protobufs.GlobalFrameHeader,
	commitments [][]byte,
	proverRoot []byte,
	provingKey crypto.Signer,
	timestamp int64,
	difficulty uint32,
	proverIndex uint8,
) (*protobufs.GlobalFrameHeader, error) {
	args := m.Called(
		previousFrame,
		commitments,
		proverRoot,
		provingKey,
		timestamp,
		difficulty,
		proverIndex,
	)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*protobufs.GlobalFrameHeader), args.Error(1)
}

func (m *MockFrameProver) VerifyGlobalFrameHeader(
	frame *protobufs.GlobalFrameHeader,
	bls crypto.BlsConstructor,
) ([]uint8, error) {
	args := m.Called(frame, bls)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uint8), args.Error(1)
}
