package app

import (
	"encoding/binary"
	"encoding/hex"
	"slices"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
)

// Type aliases for consensus types
type PeerID struct {
	ID []byte
}

func (p PeerID) Identity() consensus.Identity {
	return hex.EncodeToString(p.ID)
}

func (p PeerID) Rank() uint64 {
	return 0
}

func (p PeerID) Clone() consensus.Unique {
	return PeerID{
		ID: slices.Clone(p.ID),
	}
}

// CollectedCommitments represents collected mutation commitments
type CollectedCommitments struct {
	frameNumber    uint64
	commitmentHash []byte
	prover         []byte
}

func (c CollectedCommitments) Identity() consensus.Identity {
	return hex.EncodeToString(
		slices.Concat(
			binary.BigEndian.AppendUint64(nil, c.frameNumber),
			c.commitmentHash,
			c.prover,
		),
	)
}

func (c CollectedCommitments) Rank() uint64 {
	return c.frameNumber
}

func (c CollectedCommitments) Clone() consensus.Unique {
	return CollectedCommitments{
		frameNumber:    c.frameNumber,
		commitmentHash: slices.Clone(c.commitmentHash),
		prover:         slices.Clone(c.prover),
	}
}
