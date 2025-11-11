package consensus

import (
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// Signer is responsible for creating votes, proposals for a given state.
type Signer[StateT models.Unique, VoteT models.Unique] interface {
	// CreateVote creates a vote for the given state. No error returns are
	// expected during normal operations (incl. presence of byz. actors).
	CreateVote(state *models.State[StateT]) (*VoteT, error)

	// CreateTimeout creates a timeout for given rank. No errors return are
	// expected during normal operations(incl presence of byz. actors).
	CreateTimeout(
		curRank uint64,
		newestQC models.QuorumCertificate,
		previousRankTimeoutCert models.TimeoutCertificate,
	) (*models.TimeoutState[VoteT], error)
}

type SignatureAggregator interface {
	VerifySignatureMultiMessage(
		publicKeys [][]byte,
		signature []byte,
		messages [][]byte,
		context []byte,
	) bool
	VerifySignatureRaw(
		publicKey []byte,
		signature []byte,
		message []byte,
		context []byte,
	) bool
	Aggregate(
		publicKeys [][]byte,
		signatures [][]byte,
	) (models.AggregatedSignature, error)
}
