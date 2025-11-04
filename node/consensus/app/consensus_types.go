package app

import (
	"encoding/binary"
	"encoding/hex"
	"slices"

	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// Type aliases for consensus types
type PeerID struct {
	ID []byte
}

// GetRank implements models.Unique.
func (p PeerID) GetRank() uint64 {
	return 0
}

// GetSignature implements models.Unique.
func (p PeerID) GetSignature() []byte {
	return []byte{}
}

// GetTimestamp implements models.Unique.
func (p PeerID) GetTimestamp() uint64 {
	return 0
}

// Source implements models.Unique.
func (p PeerID) Source() models.Identity {
	return ""
}

func (p PeerID) Identity() models.Identity {
	return models.Identity(p.ID)
}

func (p PeerID) Rank() uint64 {
	return 0
}

func (p PeerID) Clone() models.Unique {
	return PeerID{
		ID: slices.Clone(p.ID),
	}
}

// CollectedCommitments represents collected mutation commitments
type CollectedCommitments struct {
	rank           uint64
	frameNumber    uint64
	commitmentHash []byte
	prover         []byte
}

// GetRank implements models.Unique.
func (c CollectedCommitments) GetRank() uint64 {
	return c.rank
}

// GetSignature implements models.Unique.
func (c CollectedCommitments) GetSignature() []byte {
	return []byte{}
}

// GetTimestamp implements models.Unique.
func (c CollectedCommitments) GetTimestamp() uint64 {
	return 0
}

// Source implements models.Unique.
func (c CollectedCommitments) Source() models.Identity {
	return models.Identity(c.prover)
}

func (c CollectedCommitments) Identity() models.Identity {
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

func (c CollectedCommitments) Clone() models.Unique {
	return CollectedCommitments{
		frameNumber:    c.frameNumber,
		commitmentHash: slices.Clone(c.commitmentHash),
		prover:         slices.Clone(c.prover),
	}
}
