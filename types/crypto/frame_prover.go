package crypto

import (
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

type FrameProver interface {
	ProveFrameHeaderGenesis(
		address []byte,
		difficulty uint32,
		input []byte,
		feeMultiplierVote uint64,
	) (*protobufs.FrameHeader, error)
	ProveFrameHeader(
		previousFrame *protobufs.FrameHeader,
		address []byte,
		requestsRoot []byte,
		stateRoots [][]byte,
		prover []byte,
		provingKey Signer,
		timestamp int64,
		difficulty uint32,
		feeMultiplierVote uint64,
		proverIndex uint8,
	) (*protobufs.FrameHeader, error)
	VerifyFrameHeader(
		frame *protobufs.FrameHeader,
		bls BlsConstructor,
	) ([]uint8, error)
	VerifyFrameHeaderSignature(
		frame *protobufs.FrameHeader,
		bls BlsConstructor,
	) (bool, error)
	GetFrameSignaturePayload(
		frame *protobufs.FrameHeader,
	) ([]byte, error)
	ProveGlobalFrameHeader(
		previousFrame *protobufs.GlobalFrameHeader,
		commitments [][]byte,
		proverRoot []byte,
		provingKey Signer,
		timestamp int64,
		difficulty uint32,
		proverIndex uint8,
	) (*protobufs.GlobalFrameHeader, error)
	VerifyGlobalFrameHeader(
		frame *protobufs.GlobalFrameHeader,
		bls BlsConstructor,
	) ([]uint8, error)
	VerifyGlobalHeaderSignature(
		frame *protobufs.GlobalFrameHeader,
		bls BlsConstructor,
	) (bool, error)
	GetGlobalFrameSignaturePayload(
		frame *protobufs.GlobalFrameHeader,
	) ([]byte, error)
}
