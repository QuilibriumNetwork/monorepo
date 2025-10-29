package models

// ConsensusState defines the core minimum data required to maintain consensus
// safety betwixt the core consensus state machine and the deriving users of the
// state machine, different from StateT (the object being built by the user).
type ConsensusState[VoteT Unique] struct {
	// The filter scope of the consensus state.
	Filter []byte
	// The latest rank that has been finalized (e.g. cannot be forked below).
	FinalizedRank uint64
	// The latest rank voted on in a quorum certificate or timeout certificate.
	LatestAcknowledgedRank uint64
	// The latest timeout data produced by this instance.
	LatestTimeout *TimeoutState[VoteT]
}
