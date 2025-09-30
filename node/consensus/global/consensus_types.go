package global

import (
	"encoding/binary"
	"encoding/hex"
	"slices"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
)

// Type aliases for consensus types
type GlobalPeerID struct {
	ID []byte
}

func (p GlobalPeerID) Identity() consensus.Identity {
	return hex.EncodeToString(p.ID)
}

func (p GlobalPeerID) Rank() uint64 {
	return 0
}

func (p GlobalPeerID) Clone() consensus.Unique {
	return GlobalPeerID{
		ID: slices.Clone(p.ID),
	}
}

// GlobalCollectedCommitments represents collected commitments
type GlobalCollectedCommitments struct {
	frameNumber    uint64
	commitmentHash []byte
	prover         []byte
}

func (c GlobalCollectedCommitments) Identity() consensus.Identity {
	return hex.EncodeToString(
		slices.Concat(
			binary.BigEndian.AppendUint64(nil, c.frameNumber),
			c.commitmentHash,
			c.prover,
		),
	)
}

func (c GlobalCollectedCommitments) Rank() uint64 {
	return c.frameNumber
}

func (c GlobalCollectedCommitments) Clone() consensus.Unique {
	return GlobalCollectedCommitments{
		frameNumber:    c.frameNumber,
		commitmentHash: slices.Clone(c.commitmentHash),
		prover:         slices.Clone(c.prover),
	}
}
