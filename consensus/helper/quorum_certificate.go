package helper

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"math/rand"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

type TestAggregatedSignature struct {
	Signature []byte
	PublicKey []byte
	Bitmask   []byte
}

func (t *TestAggregatedSignature) GetSignature() []byte {
	return t.Signature
}

func (t *TestAggregatedSignature) GetPubKey() []byte {
	return t.PublicKey
}

func (t *TestAggregatedSignature) GetBitmask() []byte {
	return t.Bitmask
}

type TestQuorumCertificate struct {
	Filter              []byte
	Rank                uint64
	FrameNumber         uint64
	Selector            models.Identity
	Timestamp           uint64
	AggregatedSignature models.AggregatedSignature
}

func (t *TestQuorumCertificate) GetFilter() []byte {
	return t.Filter
}

func (t *TestQuorumCertificate) GetRank() uint64 {
	return t.Rank
}

func (t *TestQuorumCertificate) GetFrameNumber() uint64 {
	return t.FrameNumber
}

func (t *TestQuorumCertificate) Identity() models.Identity {
	return t.Selector
}

func (t *TestQuorumCertificate) GetTimestamp() uint64 {
	return t.Timestamp
}

func (t *TestQuorumCertificate) GetAggregatedSignature() models.AggregatedSignature {
	return t.AggregatedSignature
}

func (t *TestQuorumCertificate) Equals(other models.QuorumCertificate) bool {
	return bytes.Equal(t.Filter, other.GetFilter()) &&
		t.Rank == other.GetRank() &&
		t.FrameNumber == other.GetFrameNumber() &&
		t.Selector == other.Identity() &&
		t.Timestamp == other.GetTimestamp() &&
		bytes.Equal(
			t.AggregatedSignature.GetBitmask(),
			other.GetAggregatedSignature().GetBitmask(),
		) &&
		bytes.Equal(
			t.AggregatedSignature.GetPubKey(),
			other.GetAggregatedSignature().GetPubKey(),
		) &&
		bytes.Equal(
			t.AggregatedSignature.GetSignature(),
			other.GetAggregatedSignature().GetSignature(),
		)
}

func MakeQC(options ...func(*TestQuorumCertificate)) models.QuorumCertificate {
	s := make([]byte, 32)
	crand.Read(s)
	qc := &TestQuorumCertificate{
		Rank:        rand.Uint64(),
		FrameNumber: rand.Uint64() + 1,
		Selector:    string(s),
		Timestamp:   uint64(time.Now().UnixMilli()),
		AggregatedSignature: &TestAggregatedSignature{
			PublicKey: make([]byte, 585),
			Signature: make([]byte, 74),
			Bitmask:   []byte{0x01},
		},
	}
	for _, option := range options {
		option(qc)
	}
	return qc
}

func WithQCState[StateT models.Unique](state *models.State[StateT]) func(*TestQuorumCertificate) {
	return func(qc *TestQuorumCertificate) {
		qc.Rank = state.Rank
		qc.Selector = state.Identifier
	}
}

func WithQCSigners(signerIndices []byte) func(*TestQuorumCertificate) {
	return func(qc *TestQuorumCertificate) {
		qc.AggregatedSignature.(*TestAggregatedSignature).Bitmask = signerIndices // buildutils:allow-slice-alias
	}
}

func WithQCRank(rank uint64) func(*TestQuorumCertificate) {
	return func(qc *TestQuorumCertificate) {
		qc.Rank = rank
		qc.Selector = fmt.Sprintf("%d", rank)
	}
}
