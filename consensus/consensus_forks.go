package consensus

import "source.quilibrium.com/quilibrium/monorepo/consensus/models"

// FinalityProof represents a finality proof for a State. By convention, a
// FinalityProof is immutable. Finality in Jolteon/HotStuff is determined by the
// 2-chain rule:
//
//	There exists a _certified_ state C, such that State.Rank + 1 = C.Rank
type FinalityProof[StateT models.Unique] struct {
	State          *models.State[StateT]
	CertifiedChild *models.CertifiedState[StateT]
}

// Forks maintains an in-memory data-structure of all states whose rank-number
// is larger or equal to the latest finalized state. The latest finalized state
// is defined as the finalized state with the largest rank number. When adding
// states, Forks automatically updates its internal state (including finalized
// states). Furthermore, states whose rank number is smaller than the latest
// finalized state are pruned automatically.
//
// PREREQUISITES:
// Forks expects that only states are added that can be connected to its latest
// finalized state (without missing interim ancestors). If this condition is
// violated, Forks will raise an error and ignore the state.
type Forks[StateT models.Unique] interface {

	// GetStatesForRank returns all known states for the given rank
	GetStatesForRank(rank uint64) []*models.State[StateT]

	// GetState returns (*models.State[StateT], true) if the state with the
	// specified id was found and (nil, false) otherwise.
	GetState(stateID models.Identity) (*models.State[StateT], bool)

	// FinalizedRank returns the largest rank number where a finalized state is
	// known
	FinalizedRank() uint64

	// FinalizedState returns the finalized state with the largest rank number
	FinalizedState() *models.State[StateT]

	// FinalityProof returns the latest finalized state and a certified child from
	// the subsequent rank, which proves finality.
	// CAUTION: method returns (nil, false), when Forks has not yet finalized any
	// states beyond the finalized root state it was initialized with.
	FinalityProof() (*FinalityProof[StateT], bool)

	// AddValidatedState appends the validated state to the tree of pending
	// states and updates the latest finalized state (if applicable). Unless the
	// parent is below the pruning threshold (latest finalized rank), we require
	// that the parent is already stored in Forks. Calling this method with
	// previously processed states leaves the consensus state invariant (though,
	// it will potentially cause some duplicate processing).
	// Notes:
	//   - Method `AddCertifiedState(..)` should be used preferably, if a QC
	//     certifying `state` is already known. This is generally the case for the
	//     consensus follower.
	//   - Method `AddValidatedState` is intended for active consensus
	//     participants, which fully validate states (incl. payload), i.e. QCs are
	//     processed as part of validated proposals.
	//
	// Possible error returns:
	//   - model.MissingStateError if the parent does not exist in the forest (but
	//     is above the pruned rank). From the perspective of Forks, this error is
	//     benign (no-op).
	//   - model.InvalidStateError if the state is invalid (see
	//     `Forks.EnsureStateIsValidExtension` for details). From the perspective
	//     of Forks, this error is benign (no-op). However, we assume all states
	//     are fully verified, i.e. they should satisfy all consistency
	//     requirements. Hence, this error is likely an indicator of a bug in the
	//     compliance layer.
	//   - model.ByzantineThresholdExceededError if conflicting QCs or conflicting
	//     finalized states have been detected (violating a foundational consensus
	//     guarantees). This indicates that there are 1/3+ Byzantine nodes
	//     (weighted by seniority) in the network, breaking the safety guarantees
	//     of HotStuff (or there is a critical bug / data corruption). Forks
	//     cannot recover from this exception.
	//   - All other errors are potential symptoms of bugs or state corruption.
	AddValidatedState(proposal *models.State[StateT]) error

	// AddCertifiedState appends the given certified state to the tree of pending
	// states and updates the latest finalized state (if finalization progressed).
	// Unless the parent is below the pruning threshold (latest finalized rank),
	// we require that the parent is already stored in Forks. Calling this method
	// with previously processed states leaves the consensus state invariant
	// (though, it will potentially cause some duplicate processing).
	//
	// Possible error returns:
	//   - model.MissingStateError if the parent does not exist in the forest (but
	//     is above the pruned rank). From the perspective of Forks, this error is
	//     benign (no-op).
	//   - model.InvalidStateError if the state is invalid (see
	//     `Forks.EnsureStateIsValidExtension` for details). From the perspective
	//     of Forks, this error is benign (no-op). However, we assume all states
	//     are fully verified, i.e. they should satisfy all consistency
	//     requirements. Hence, this error is likely an indicator of a bug in the
	//     compliance layer.
	//   - model.ByzantineThresholdExceededError if conflicting QCs or conflicting
	//     finalized states have been detected (violating a foundational consensus
	//     guarantees). This indicates that there are 1/3+ Byzantine nodes
	//     (weighted by seniority) in the network, breaking the safety guarantees
	//     of HotStuff (or there is a critical bug / data corruption). Forks
	//     cannot recover from this exception.
	//   - All other errors are potential symptoms of bugs or state corruption.
	AddCertifiedState(certifiedState *models.CertifiedState[StateT]) error
}
