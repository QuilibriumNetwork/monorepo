package consensus

import "source.quilibrium.com/quilibrium/monorepo/consensus/models"

// ConsensusStore defines the methods required for internal state that should
// persist between restarts of the consensus engine.
type ConsensusStore[VoteT models.Unique] interface {
	ReadOnlyConsensusStore[VoteT]
	PutConsensusState(state *models.ConsensusState[VoteT]) error
	PutLivenessState(state *models.LivenessState) error
}

// ReadOnlyConsensusStore defines the methods required for reading internal
// state persisted between restarts of the consensus engine.
type ReadOnlyConsensusStore[VoteT models.Unique] interface {
	GetConsensusState(filter []byte) (*models.ConsensusState[VoteT], error)
	GetLivenessState(filter []byte) (*models.LivenessState, error)
}
