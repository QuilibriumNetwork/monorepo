package helper

import (
	"bytes"
	crand "crypto/rand"
	"math/rand"
	"slices"

	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

type TestTimeoutCertificate struct {
	Filter              []byte
	Rank                uint64
	LatestRanks         []uint64
	LatestQuorumCert    models.QuorumCertificate
	AggregatedSignature models.AggregatedSignature
}

func (t *TestTimeoutCertificate) GetFilter() []byte {
	return t.Filter
}

func (t *TestTimeoutCertificate) GetRank() uint64 {
	return t.Rank
}

func (t *TestTimeoutCertificate) GetLatestRanks() []uint64 {
	return t.LatestRanks
}

func (t *TestTimeoutCertificate) GetLatestQuorumCert() models.QuorumCertificate {
	return t.LatestQuorumCert
}

func (t *TestTimeoutCertificate) GetAggregatedSignature() models.AggregatedSignature {
	return t.AggregatedSignature
}

func (t *TestTimeoutCertificate) Equals(other models.TimeoutCertificate) bool {
	return bytes.Equal(t.Filter, other.GetFilter()) &&
		t.Rank == other.GetRank() &&
		slices.Equal(t.LatestRanks, other.GetLatestRanks()) &&
		t.LatestQuorumCert.Equals(other.GetLatestQuorumCert()) &&
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

func MakeTC(options ...func(*TestTimeoutCertificate)) models.TimeoutCertificate {
	tcRank := rand.Uint64()
	s := make([]byte, 32)
	crand.Read(s)
	qc := MakeQC(WithQCRank(tcRank - 1))
	highQCRanks := make([]uint64, 3)
	for i := range highQCRanks {
		highQCRanks[i] = qc.GetRank()
	}
	tc := &TestTimeoutCertificate{
		Rank:             tcRank,
		LatestQuorumCert: qc,
		LatestRanks:      highQCRanks,
		AggregatedSignature: &TestAggregatedSignature{
			Signature: make([]byte, 74),
			PublicKey: make([]byte, 585),
			Bitmask:   []byte{0x01},
		},
	}
	for _, option := range options {
		option(tc)
	}
	return tc
}

func WithTCNewestQC(qc models.QuorumCertificate) func(*TestTimeoutCertificate) {
	return func(tc *TestTimeoutCertificate) {
		tc.LatestQuorumCert = qc
		tc.LatestRanks = []uint64{qc.GetRank()}
	}
}

func WithTCSigners(signerIndices []byte) func(*TestTimeoutCertificate) {
	return func(tc *TestTimeoutCertificate) {
		tc.AggregatedSignature.(*TestAggregatedSignature).Bitmask = signerIndices // buildutils:allow-slice-alias
	}
}

func WithTCRank(rank uint64) func(*TestTimeoutCertificate) {
	return func(tc *TestTimeoutCertificate) {
		tc.Rank = rank
	}
}

func WithTCHighQCRanks(highQCRanks []uint64) func(*TestTimeoutCertificate) {
	return func(tc *TestTimeoutCertificate) {
		tc.LatestRanks = highQCRanks // buildutils:allow-slice-alias
	}
}

func TimeoutStateFixture[VoteT models.Unique](
	opts ...func(TimeoutState *models.TimeoutState[VoteT]),
) *models.TimeoutState[VoteT] {
	timeoutRank := uint64(rand.Uint32())
	newestQC := MakeQC(WithQCRank(timeoutRank - 10))

	timeout := &models.TimeoutState[VoteT]{
		Rank:                    timeoutRank,
		LatestQuorumCertificate: newestQC,
		PriorRankTimeoutCertificate: MakeTC(
			WithTCRank(timeoutRank-1),
			WithTCNewestQC(MakeQC(WithQCRank(newestQC.GetRank()))),
		),
	}

	for _, opt := range opts {
		opt(timeout)
	}

	if timeout.Vote == nil {
		panic("WithTimeoutVote must be called")
	}

	return timeout
}

func WithTimeoutVote[VoteT models.Unique](
	vote VoteT,
) func(*models.TimeoutState[VoteT]) {
	return func(state *models.TimeoutState[VoteT]) {
		state.Vote = &vote
	}
}

func WithTimeoutNewestQC[VoteT models.Unique](
	newestQC models.QuorumCertificate,
) func(*models.TimeoutState[VoteT]) {
	return func(timeout *models.TimeoutState[VoteT]) {
		timeout.LatestQuorumCertificate = newestQC
	}
}

func WithTimeoutPreviousRankTimeoutCertificate[VoteT models.Unique](
	previousRankTimeoutCert models.TimeoutCertificate,
) func(*models.TimeoutState[VoteT]) {
	return func(timeout *models.TimeoutState[VoteT]) {
		timeout.PriorRankTimeoutCertificate = previousRankTimeoutCert
	}
}

func WithTimeoutStateRank[VoteT models.Unique](
	rank uint64,
) func(*models.TimeoutState[VoteT]) {
	return func(timeout *models.TimeoutState[VoteT]) {
		timeout.Rank = rank
		if timeout.LatestQuorumCertificate != nil {
			timeout.LatestQuorumCertificate.(*TestQuorumCertificate).Rank = rank
		}
		if timeout.PriorRankTimeoutCertificate != nil {
			timeout.PriorRankTimeoutCertificate.(*TestTimeoutCertificate).Rank = rank - 1
		}
	}
}
