package models

// LivenessState defines the core minimum data required to maintain liveness
// of the pacemaker of the consensus state machine.
type LivenessState struct {
	// The filter scope of the consensus state.
	Filter []byte
	// The current rank of the pacemaker.
	CurrentRank uint64
	// The latest quorum certificate seen by the pacemaker.
	LatestQuorumCertificate QuorumCertificate
	// The previous rank's timeout certificate, if applicable.
	PriorRankTimeoutCertificate TimeoutCertificate
}
