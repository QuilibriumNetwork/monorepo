package models

// QuorumCertificate defines the minimum properties required of a consensus
// clique's validating set of data for a frame.
type QuorumCertificate interface {
	// GetFilter returns the applicable filter for the consensus clique.
	GetFilter() []byte
	// GetRank returns the rank of the consensus loop.
	GetRank() uint64
	// GetFrameNumber returns the frame number applied to the round.
	GetFrameNumber() uint64
	// Identity returns the selector of the frame.
	Identity() Identity
	// GetTimestamp returns the timestamp of the certificate.
	GetTimestamp() uint64
	// GetAggregatedSignature returns the set of signers who voted on the round.
	GetAggregatedSignature() AggregatedSignature
	// Equals compares inner equality with another quorum certificate.
	Equals(other QuorumCertificate) bool
}
