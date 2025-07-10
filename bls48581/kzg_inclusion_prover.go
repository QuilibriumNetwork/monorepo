package bls48581

import (
	"go.uber.org/zap"

	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

type KZGInclusionProver struct {
	logger *zap.Logger
}

func NewKZGInclusionProver(logger *zap.Logger) *KZGInclusionProver {
	// Rather than put this in an init() function and eat the time cost for
	// non-proving applications, we call this here so if it's explicitly wired in
	// it runs the initialization.
	Init()
	return &KZGInclusionProver{
		logger: logger,
	}
}

func (k *KZGInclusionProver) CommitRaw(
	data []byte,
	polySize uint64,
) ([]byte, error) {
	return CommitRaw(data, polySize), nil
}

func (k *KZGInclusionProver) ProveRaw(
	data []byte,
	index int,
	polySize uint64,
) ([]byte, error) {
	return ProveRaw(data, uint64(index), polySize), nil
}

func (k *KZGInclusionProver) VerifyRaw(
	data []byte,
	commit []byte,
	index uint64,
	proof []byte,
	polySize uint64,
) (bool, error) {
	return VerifyRaw(data, commit, index, proof, polySize), nil
}

func (k *KZGInclusionProver) ProveMultiple(
	commitments [][]byte,
	polys [][]byte,
	indices []uint64,
	polySize uint64,
) crypto.Multiproof {
	return ProveMultiple(commitments, polys, indices, polySize)
}

func (k *KZGInclusionProver) VerifyMultiple(
	commitments [][]byte,
	evaluations [][]byte,
	indices []uint64,
	polySize uint64,
	multiCommitment []byte,
	proof []byte,
) bool {
	return VerifyMultiple(
		commitments,
		evaluations,
		indices,
		polySize,
		multiCommitment,
		proof,
	)
}

func (k *KZGInclusionProver) NewMultiproof() crypto.Multiproof {
	return &Multiproof{}
}
