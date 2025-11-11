package global

import (
	"encoding/binary"
	"encoding/hex"
	"slices"

	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// Type aliases for consensus types
type GlobalPeerID struct {
	ID []byte
}

// GetRank implements models.Unique.
func (p GlobalPeerID) GetRank() uint64 {
	return 0
}

// GetSignature implements models.Unique.
func (p GlobalPeerID) GetSignature() []byte {
	return []byte{}
}

// GetTimestamp implements models.Unique.
func (p GlobalPeerID) GetTimestamp() uint64 {
	return 0
}

// Source implements models.Unique.
func (p GlobalPeerID) Source() models.Identity {
	return ""
}

func (p GlobalPeerID) Identity() models.Identity {
	return models.Identity(p.ID)
}

func (p GlobalPeerID) Rank() uint64 {
	return 0
}

func (p GlobalPeerID) Clone() models.Unique {
	return GlobalPeerID{
		ID: slices.Clone(p.ID),
	}
}

// GlobalCollectedCommitments represents collected commitments
type GlobalCollectedCommitments struct {
	rank           uint64
	frameNumber    uint64
	commitmentHash []byte
	prover         []byte
}

// GetRank implements models.Unique.
func (c GlobalCollectedCommitments) GetRank() uint64 {
	return c.rank
}

// GetSignature implements models.Unique.
func (c GlobalCollectedCommitments) GetSignature() []byte {
	return []byte{}
}

// GetTimestamp implements models.Unique.
func (c GlobalCollectedCommitments) GetTimestamp() uint64 {
	return 0
}

// Source implements models.Unique.
func (c GlobalCollectedCommitments) Source() models.Identity {
	return models.Identity(c.prover)
}

func (c GlobalCollectedCommitments) Identity() models.Identity {
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

func (c GlobalCollectedCommitments) Clone() models.Unique {
	return GlobalCollectedCommitments{
		frameNumber:    c.frameNumber,
		commitmentHash: slices.Clone(c.commitmentHash),
		prover:         slices.Clone(c.prover),
	}
}
