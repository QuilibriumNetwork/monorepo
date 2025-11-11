package models

// TimeoutCertificate defines the minimum properties required of a consensus
// clique's invalidating set of data for a frame.
type TimeoutCertificate interface {
	// GetFilter returns the applicable filter for the consensus clique.
	GetFilter() []byte
	// GetRank returns the rank of the consensus loop.
	GetRank() uint64
	// GetLatestRanks returns the latest ranks seen by members of clique, in
	// matching order to the clique's prover set (in ascending ring order).
	GetLatestRanks() []uint64
	// GetLatestQuorumCert returns the latest quorum certificate accepted.
	GetLatestQuorumCert() QuorumCertificate
	// GetAggregatedSignature returns the set of signers who voted on the round.
	GetAggregatedSignature() AggregatedSignature
	// Equals compares inner equality with another timeout certificate.
	Equals(other TimeoutCertificate) bool
}
