package forks

import (
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/forest"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// Forks enforces structural validity of the consensus state and implements
// finalization rules as defined in Jolteon consensus
// https://arxiv.org/abs/2106.10362 The same approach has later been adopted by
// the Diem team resulting in DiemBFT v4:
// https://developers.diem.com/papers/diem-consensus-state-machine-replication-in-the-diem-blockchain/2021-08-17.pdf
// Forks is NOT safe for concurrent use by multiple goroutines.
type Forks[StateT models.Unique, VoteT models.Unique] struct {
	finalizationCallback consensus.Finalizer
	notifier             consensus.FollowerConsumer[StateT, VoteT]
	forest               forest.LevelledForest
	trustedRoot          *models.CertifiedState[StateT]

	// finalityProof holds the latest finalized state including the certified
	// child as proof of finality. CAUTION: is nil, when Forks has not yet
	// finalized any states beyond the finalized root state it was initialized
	// with
	finalityProof *consensus.FinalityProof[StateT]
}

var _ consensus.Forks[*nilUnique] = (*Forks[*nilUnique, *nilUnique])(nil)

func NewForks[StateT models.Unique, VoteT models.Unique](
	trustedRoot *models.CertifiedState[StateT],
	finalizationCallback consensus.Finalizer,
	notifier consensus.FollowerConsumer[StateT, VoteT],
) (*Forks[StateT, VoteT], error) {
	if trustedRoot == nil {
		return nil,
			models.NewConfigurationErrorf("invalid root: root is nil")
	}

	if (trustedRoot.State.Identifier != trustedRoot.CertifyingQuorumCertificate.Identity()) ||
		(trustedRoot.State.Rank != trustedRoot.CertifyingQuorumCertificate.GetRank()) {
		return nil,
			models.NewConfigurationErrorf(
				"invalid root: root QC is not pointing to root state",
			)
	}

	forks := Forks[StateT, VoteT]{
		finalizationCallback: finalizationCallback,
		notifier:             notifier,
		forest:               *forest.NewLevelledForest(trustedRoot.State.Rank),
		trustedRoot:          trustedRoot,
		finalityProof:        nil,
	}

	// verify and add root state to levelled forest
	err := forks.EnsureStateIsValidExtension(trustedRoot.State)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid root state %x: %w",
			trustedRoot.Identifier(),
			err,
		)
	}
	forks.forest.AddVertex(ToStateContainer2[StateT](trustedRoot.State))
	return &forks, nil
}

// FinalizedRank returns the largest rank number where a finalized state is
// known
func (f *Forks[StateT, VoteT]) FinalizedRank() uint64 {
	if f.finalityProof == nil {
		return f.trustedRoot.State.Rank
	}
	return f.finalityProof.State.Rank
}

// FinalizedState returns the finalized state with the largest rank number
func (f *Forks[StateT, VoteT]) FinalizedState() *models.State[StateT] {
	if f.finalityProof == nil {
		return f.trustedRoot.State
	}
	return f.finalityProof.State
}

// FinalityProof returns the latest finalized state and a certified child from
// the subsequent rank, which proves finality.
// CAUTION: method returns (nil, false), when Forks has not yet finalized any
// states beyond the finalized root state it was initialized with.
func (f *Forks[StateT, VoteT]) FinalityProof() (
	*consensus.FinalityProof[StateT],
	bool,
) {
	return f.finalityProof, f.finalityProof != nil
}

// GetState returns (*models.State, true) if the state with the specified
// id was found and (nil, false) otherwise.
func (f *Forks[StateT, VoteT]) GetState(stateID models.Identity) (
	*models.State[StateT],
	bool,
) {
	stateContainer, hasState := f.forest.GetVertex(stateID)
	if !hasState {
		return nil, false
	}
	return stateContainer.(*StateContainer[StateT]).GetState(), true
}

// GetStatesForRank returns all known states for the given rank
func (f *Forks[StateT, VoteT]) GetStatesForRank(
	rank uint64,
) []*models.State[StateT] {
	vertexIterator := f.forest.GetVerticesAtLevel(rank)
	// in the vast majority of cases, there will only be one proposal for a
	// particular rank
	states := make([]*models.State[StateT], 0, 1)
	for vertexIterator.HasNext() {
		v := vertexIterator.NextVertex()
		states = append(states, v.(*StateContainer[StateT]).GetState())
	}
	return states
}

// IsKnownState checks whether state is known.
func (f *Forks[StateT, VoteT]) IsKnownState(stateID models.Identity) bool {
	_, hasState := f.forest.GetVertex(stateID)
	return hasState
}

// IsProcessingNeeded determines whether the given state needs processing,
// based on the state's rank and hash.
// Returns false if any of the following conditions applies
//   - state rank is _below_ the most recently finalized state
//   - the state already exists in the consensus state
//
// UNVALIDATED: expects state to pass Forks.EnsureStateIsValidExtension(state)
func (f *Forks[StateT, VoteT]) IsProcessingNeeded(state *models.State[StateT]) bool {
	if state.Rank < f.FinalizedRank() || f.IsKnownState(state.Identifier) {
		return false
	}
	return true
}

// EnsureStateIsValidExtension checks that the given state is a valid extension
// to the tree of states already stored (no state modifications). Specifically,
// the following conditions are enforced, which are critical to the correctness
// of Forks:
//
//  1. If a state with the same ID is already stored, their ranks must be
//     identical.
//  2. The state's rank must be strictly larger than the rank of its parent.
//  3. The parent must already be stored (or below the pruning height).
//
// Exclusions to these rules (by design):
// Let W denote the rank of state's parent (i.e. W := state.QC.Rank) and F the
// latest finalized rank.
//
//		  (i) If state.Rank < F, adding the state would be a no-op. Such states are
//	       considered compatible (principle of vacuous truth), i.e. we skip
//	       checking 1, 2, 3.
//		 (ii) If state.Rank == F, we do not inspect the QC / parent at all (skip 2
//	       and 3). This exception is important for compatability with genesis or
//	       spork-root states, which do not contain a QC.
//		(iii) If state.Rank > F, but state.QC.Rank < F the parent has already been
//	       pruned. In this case, we omit rule 3. (principle of vacuous truth
//	       applied to the parent)
//
// We assume that all states are fully verified. A valid state must satisfy all
// consistency requirements; otherwise we have a bug in the compliance layer.
//
// Error returns:
//   - models.MissingStateError if the parent of the input proposal does not
//     exist in the forest (but is above the pruned rank). Represents violation
//     of condition 3.
//   - models.InvalidStateError if the state violates condition 1. or 2.
//   - generic error in case of unexpected bug or internal state corruption
func (f *Forks[StateT, VoteT]) EnsureStateIsValidExtension(
	state *models.State[StateT],
) error {
	if state.Rank < f.forest.LowestLevel { // exclusion (i)
		return nil
	}

	// LevelledForest enforces conditions 1. and 2. including the respective
	// exclusions (ii) and (iii).
	stateContainer := ToStateContainer2[StateT](state)
	err := f.forest.VerifyVertex(stateContainer)
	if err != nil {
		if forest.IsInvalidVertexError(err) {
			return models.NewInvalidStateErrorf(
				state,
				"not a valid vertex for state tree: %w",
				err,
			)
		}
		return fmt.Errorf(
			"state tree generated unexpected error validating vertex: %w",
			err,
		)
	}

	// Condition 3:
	// LevelledForest implements a more generalized algorithm that also works for
	// disjoint graphs. Therefore, LevelledForest _not_ enforce condition 3. Here,
	// we additionally require that the pending states form a tree (connected
	// graph), i.e. we need to enforce condition 3
	if (state.Rank == f.forest.LowestLevel) ||
		(state.ParentQuorumCertificate.GetRank() < f.forest.LowestLevel) { // exclusion (ii) and (iii)
		return nil
	}
	// For a state whose parent is _not_ below the pruning height, we expect the
	// parent to be known.
	_, isParentKnown := f.forest.GetVertex(
		state.ParentQuorumCertificate.Identity(),
	)
	if !isParentKnown { // missing parent
		return models.MissingStateError{
			Rank:       state.ParentQuorumCertificate.GetRank(),
			Identifier: state.ParentQuorumCertificate.Identity(),
		}
	}
	return nil
}

// AddCertifiedState[StateT] appends the given certified state to the tree of
// pending states and updates the latest finalized state (if finalization
// progressed). Unless the parent is below the pruning threshold (latest
// finalized rank), we require that the parent is already stored in Forks.
// Calling this method with previously processed states leaves the consensus
// state invariant (though, it will potentially cause some duplicate
// processing).
//
// Possible error returns:
//   - models.MissingStateError if the parent does not exist in the forest (but
//     is above the pruned rank). From the perspective of Forks, this error is
//     benign (no-op).
//   - models.InvalidStateError if the state is invalid (see
//     `Forks.EnsureStateIsValidExtension` for details). From the perspective of
//     Forks, this error is benign (no-op). However, we assume all states are
//     fully verified, i.e. they should satisfy all consistency requirements.
//     Hence, this error is likely an indicator of a bug in the compliance
//     layer.
//   - models.ByzantineThresholdExceededError if conflicting QCs or conflicting
//     finalized states have been detected (violating a foundational consensus
//     guarantees). This indicates that there are 1/3+ Byzantine nodes (weighted
//     by seniority) in the network, breaking the safety guarantees of HotStuff
//     (or there is a critical bug / data corruption). Forks cannot recover from
//     this exception.
//   - All other errors are potential symptoms of bugs or state corruption.
func (f *Forks[StateT, VoteT]) AddCertifiedState(
	certifiedState *models.CertifiedState[StateT],
) error {
	if !f.IsProcessingNeeded(certifiedState.State) {
		return nil
	}

	// Check proposal for byzantine evidence, store it and emit
	// `OnStateIncorporated` notification. Note: `checkForByzantineEvidence` only
	// inspects the state, but _not_ its certifying QC. Hence, we have to
	// additionally check here, whether the certifying QC conflicts with any known
	// QCs.
	err := f.checkForByzantineEvidence(certifiedState.State)
	if err != nil {
		return fmt.Errorf(
			"cannot check for Byzantine evidence in certified state %x: %w",
			certifiedState.State.Identifier,
			err,
		)
	}
	err = f.checkForConflictingQCs(&certifiedState.CertifyingQuorumCertificate)
	if err != nil {
		return fmt.Errorf(
			"certifying QC for state %x failed check for conflicts: %w",
			certifiedState.State.Identifier,
			err,
		)
	}
	f.forest.AddVertex(ToStateContainer2[StateT](certifiedState.State))
	f.notifier.OnStateIncorporated(certifiedState.State)

	// Update finality status:
	err = f.checkForAdvancingFinalization(certifiedState)
	if err != nil {
		return fmt.Errorf("updating finalization failed: %w", err)
	}
	return nil
}

// AddValidatedState appends the validated state to the tree of pending
// states and updates the latest finalized state (if applicable). Unless the
// parent is below the pruning threshold (latest finalized rank), we require
// that the parent is already stored in Forks. Calling this method with
// previously processed states leaves the consensus state invariant (though, it
// will potentially cause some duplicate processing).
// Notes:
//   - Method `AddCertifiedState[StateT](..)` should be used preferably, if a QC
//     certifying `state` is already known. This is generally the case for the
//     consensus follower. Method `AddValidatedState` is intended for active
//     consensus participants, which fully validate states (incl. payload), i.e.
//     QCs are processed as part of validated proposals.
//
// Possible error returns:
//   - models.MissingStateError if the parent does not exist in the forest (but
//     is above the pruned rank). From the perspective of Forks, this error is
//     benign (no-op).
//   - models.InvalidStateError if the state is invalid (see
//     `Forks.EnsureStateIsValidExtension` for details). From the perspective of
//     Forks, this error is benign (no-op). However, we assume all states are
//     fully verified, i.e. they should satisfy all consistency requirements.
//     Hence, this error is likely an indicator of a bug in the compliance
//     layer.
//   - models.ByzantineThresholdExceededError if conflicting QCs or conflicting
//     finalized states have been detected (violating a foundational consensus
//     guarantees). This indicates that there are 1/3+ Byzantine nodes (weighted
//     by seniority) in the network, breaking the safety guarantees of HotStuff
//     (or there is a critical bug / data corruption). Forks cannot recover from
//     this exception.
//   - All other errors are potential symptoms of bugs or state corruption.
func (f *Forks[StateT, VoteT]) AddValidatedState(
	proposal *models.State[StateT],
) error {
	if !f.IsProcessingNeeded(proposal) {
		return nil
	}

	// Check proposal for byzantine evidence, store it and emit
	// `OnStateIncorporated` notification:
	err := f.checkForByzantineEvidence(proposal)
	if err != nil {
		return fmt.Errorf(
			"cannot check Byzantine evidence for state %x: %w",
			proposal.Identifier,
			err,
		)
	}
	f.forest.AddVertex(ToStateContainer2[StateT](proposal))
	f.notifier.OnStateIncorporated(proposal)

	// Update finality status: In the implementation, our notion of finality is
	// based on certified states.
	// The certified parent essentially combines the parent, with the QC contained
	// in state, to drive finalization.
	parent, found := f.GetState(proposal.ParentQuorumCertificate.Identity())
	if !found {
		// Not finding the parent means it is already pruned; hence this state does
		// not change the finalization state.
		return nil
	}
	certifiedParent, err := models.NewCertifiedState[StateT](
		parent,
		proposal.ParentQuorumCertificate,
	)
	if err != nil {
		return fmt.Errorf(
			"mismatching QC with parent (corrupted Forks state):%w",
			err,
		)
	}
	err = f.checkForAdvancingFinalization(certifiedParent)
	if err != nil {
		return fmt.Errorf("updating finalization failed: %w", err)
	}
	return nil
}

// checkForByzantineEvidence inspects whether the given `state` together with
// the already known information yields evidence of byzantine behaviour.
// Furthermore, the method enforces that `state` is a valid extension of the
// tree of pending states. If the state is a double proposal, we emit an
// `OnStateIncorporated` notification. Though, provided the state is a valid
// extension of the state tree by itself, it passes this method without an
// error.
//
// Possible error returns:
//   - models.MissingStateError if the parent does not exist in the forest (but
//     is above the pruned rank). From the perspective of Forks, this error is
//     benign (no-op).
//   - models.InvalidStateError if the state is invalid (see
//     `Forks.EnsureStateIsValidExtension` for details). From the perspective of
//     Forks, this error is benign (no-op). However, we assume all states are
//     fully verified, i.e. they should satisfy all consistency requirements.
//     Hence, this error is likely an indicator of a bug in the compliance
//     layer.
//   - models.ByzantineThresholdExceededError if conflicting QCs have been
//     detected. Forks cannot recover from this exception.
//   - All other errors are potential symptoms of bugs or state corruption.
func (f *Forks[StateT, VoteT]) checkForByzantineEvidence(
	state *models.State[StateT],
) error {
	err := f.EnsureStateIsValidExtension(state)
	if err != nil {
		return fmt.Errorf("consistency check on state failed: %w", err)
	}
	err = f.checkForConflictingQCs(&state.ParentQuorumCertificate)
	if err != nil {
		return fmt.Errorf("checking QC for conflicts failed: %w", err)
	}
	f.checkForDoubleProposal(state)
	return nil
}

// checkForConflictingQCs checks if QC conflicts with a stored Quorum
// Certificate. In case a conflicting QC is found, an
// ByzantineThresholdExceededError is returned. Two Quorum Certificates q1 and
// q2 are defined as conflicting iff:
//
//	q1.Rank == q2.Rank AND q1.Identifier ≠ q2.Identifier
//
// This means there are two Quorums for conflicting states at the same rank.
// Per 'Observation 1' from the Jolteon paper https://arxiv.org/pdf/2106.10362v1.pdf,
// two conflicting QCs can exist if and only if the Byzantine threshold is
// exceeded.
// Error returns:
//   - models.ByzantineThresholdExceededError if conflicting QCs have been
//     detected. Forks cannot recover from this exception.
//   - All other errors are potential symptoms of bugs or state corruption.
func (f *Forks[StateT, VoteT]) checkForConflictingQCs(
	qc *models.QuorumCertificate,
) error {
	it := f.forest.GetVerticesAtLevel((*qc).GetRank())
	for it.HasNext() {
		otherState := it.NextVertex() // by construction, must have same rank as qc.Rank
		if (*qc).Identity() != otherState.VertexID() {
			// * we have just found another state at the same rank number as qc.Rank
			//   but with different hash
			// * if this state has a child c, this child will have
			//   c.qc.rank = parentRank
			//   c.qc.ID != parentIdentifier
			// => conflicting qc
			otherChildren := f.forest.GetChildren(otherState.VertexID())
			if otherChildren.HasNext() {
				otherChild := otherChildren.NextVertex().(*StateContainer[StateT]).GetState()
				conflictingQC := otherChild.ParentQuorumCertificate
				return models.ByzantineThresholdExceededError{Evidence: fmt.Sprintf(
					"conflicting QCs at rank %d: %x and %x",
					(*qc).GetRank(), (*qc).Identity(), conflictingQC.Identity(),
				)}
			}
		}
	}
	return nil
}

// checkForDoubleProposal checks if the input proposal is a double proposal.
// A double proposal occurs when two proposals with the same rank exist in
// Forks. If there is a double proposal, notifier.OnDoubleProposeDetected is
// triggered.
func (f *Forks[StateT, VoteT]) checkForDoubleProposal(
	state *models.State[StateT],
) {
	it := f.forest.GetVerticesAtLevel(state.Rank)
	for it.HasNext() {
		otherVertex := it.NextVertex() // by construction, must have same rank as state
		otherState := otherVertex.(*StateContainer[StateT]).GetState()
		if state.Identifier != otherState.Identifier {
			f.notifier.OnDoubleProposeDetected(state, otherState)
		}
	}
}

// checkForAdvancingFinalization checks whether observing certifiedState leads
// to progress of finalization. This function should be called every time a new
// state is added to Forks. If the new state is the head of a 2-chain satisfying
// the finalization rule, we update `Forks.finalityProof` to the new latest
// finalized state. Calling this method with previously-processed states leaves
// the consensus state invariant.
// UNVALIDATED: assumes that relevant state properties are consistent with
// previous states
// Error returns:
//   - models.MissingStateError if the parent does not exist in the forest (but
//     is above the pruned rank). From the perspective of Forks, this error is
//     benign (no-op).
//   - models.ByzantineThresholdExceededError in case we detect a finalization
//     fork (violating a foundational consensus guarantee). This indicates that
//     there are 1/3+ Byzantine nodes (weighted by seniority) in the network,
//     breaking the safety guarantees of HotStuff (or there is a critical bug /
//     data corruption). Forks cannot recover from this exception.
//   - generic error in case of unexpected bug or internal state corruption
func (f *Forks[StateT, VoteT]) checkForAdvancingFinalization(
	certifiedState *models.CertifiedState[StateT],
) error {
	// We prune all states in forest which are below the most recently finalized
	// state. Hence, we have a pruned ancestry if and only if either of the
	// following conditions applies:
	//    (a) If a state's parent rank (i.e. state.QC.Rank) is below the most
	//        recently finalized state.
	//    (b) If a state's rank is equal to the most recently finalized state.
	// Caution:
	// * Under normal operation, case (b) is covered by the logic for case (a)
	// * However, the existence of a genesis state requires handling case (b)
	//   explicitly:
	//   The root state is specified and trusted by the node operator. If the root
	//   state is the genesis state, it might not contain a QC pointing to a
	//   parent (as there is no parent). In this case, condition (a) cannot be
	//   evaluated.
	lastFinalizedRank := f.FinalizedRank()
	if (certifiedState.Rank() <= lastFinalizedRank) ||
		(certifiedState.State.ParentQuorumCertificate.GetRank() < lastFinalizedRank) {
		// Repeated states are expected during normal operations. We enter this code
		// state if and only if the parent's rank is _below_ the last finalized
		// state. It is straight forward to show:
		// Lemma: Let B be a state whose 2-chain reaches beyond the last finalized
		//        state => B will not update the locked or finalized state
		return nil
	}

	// retrieve parent; always expected to succeed, because we passed the checks
	// above
	qcForParent := certifiedState.State.ParentQuorumCertificate
	parentVertex, parentStateKnown := f.forest.GetVertex(
		qcForParent.Identity(),
	)
	if !parentStateKnown {
		return models.MissingStateError{
			Rank:       qcForParent.GetRank(),
			Identifier: qcForParent.Identity(),
		}
	}
	parentState := parentVertex.(*StateContainer[StateT]).GetState()

	// Note: we assume that all stored states pass
	//       Forks.EnsureStateIsValidExtension(state); specifically, that state's
	//       RankNumber is strictly monotonically increasing which is enforced by
	//       LevelledForest.VerifyVertex(...)
	// We denote:
	//  * a DIRECT 1-chain as '<-'
	//  * a general 1-chain as '<~' (direct or indirect)
	// Jolteon's rule for finalizing `parentState` is
	//     parentState <- State <~ certifyingQC    (i.e. a DIRECT 1-chain PLUS
	//                   ╰─────────────────────╯     any 1-chain)
	//                       certifiedState
	// Hence, we can finalize `parentState` as head of a 2-chain,
	// if and only if `State.Rank` is exactly 1 higher than the rank of
	// `parentState`
	if parentState.Rank+1 != certifiedState.Rank() {
		return nil
	}

	// `parentState` is now finalized:
	//  * While Forks is single-threaded, there is still the possibility of
	//    reentrancy. Specifically, the consumers of our finalization events are
	//    served by the goroutine executing Forks. It is conceivable that a
	//    consumer might access Forks and query the latest finalization proof.
	//    This would be legal, if the component supplying the goroutine to Forks
	//    also consumes the notifications.
	//  * Therefore, for API safety, we want to first update Fork's
	//    `finalityProof` before we emit any notifications.

	// Advancing finalization step (i): we collect all states for finalization (no
	// notifications are emitted)
	statesToBeFinalized, err := f.collectStatesForFinalization(&qcForParent)
	if err != nil {
		return fmt.Errorf(
			"advancing finalization to state %x from rank %d failed: %w",
			qcForParent.Identity(),
			qcForParent.GetRank(),
			err,
		)
	}

	// Advancing finalization step (ii): update `finalityProof` and prune
	// `LevelledForest`
	f.finalityProof = &consensus.FinalityProof[StateT]{
		State:          parentState,
		CertifiedChild: certifiedState,
	}
	err = f.forest.PruneUpToLevel(f.FinalizedRank())
	if err != nil {
		return fmt.Errorf("pruning levelled forest failed unexpectedly: %w", err)
	}

	// Advancing finalization step (iii): iterate over the states from (i) and
	// emit finalization events
	for _, b := range statesToBeFinalized {
		// first notify other critical components about finalized state - all errors
		// returned here are fatal exceptions
		err = f.finalizationCallback.MakeFinal(b.Identifier)
		if err != nil {
			return fmt.Errorf("finalization error in other component: %w", err)
		}

		// notify less important components about finalized state
		f.notifier.OnFinalizedState(b)
	}
	return nil
}

// collectStatesForFinalization collects and returns all newly finalized states
// up to (and including) the state pointed to by `qc`. The states are listed in
// order of increasing height.
// Error returns:
//   - models.ByzantineThresholdExceededError in case we detect a finalization
//     fork (violating a foundational consensus guarantee). This indicates that
//     there are 1/3+ Byzantine nodes (weighted by seniority) in the network,
//     breaking the safety guarantees of HotStuff (or there is a critical bug /
//     data corruption). Forks cannot recover from this exception.
//   - generic error in case of bug or internal state corruption
func (f *Forks[StateT, VoteT]) collectStatesForFinalization(
	qc *models.QuorumCertificate,
) ([]*models.State[StateT], error) {
	lastFinalized := f.FinalizedState()
	if (*qc).GetRank() < lastFinalized.Rank {
		return nil, models.ByzantineThresholdExceededError{Evidence: fmt.Sprintf(
			"finalizing state with rank %d which is lower than previously finalized state at rank %d",
			(*qc).GetRank(), lastFinalized.Rank,
		)}
	}
	if (*qc).GetRank() == lastFinalized.Rank { // no new states to be finalized
		return nil, nil
	}

	// Collect all states that are pending finalization in slice. While we crawl
	// the states starting from the newest finalized state backwards (decreasing
	// ranks), we would like to return them in order of _increasing_ rank.
	// Therefore, we fill the slice starting with the highest index.
	l := (*qc).GetRank() - lastFinalized.Rank // l is an upper limit to the number of states that can be maximally finalized
	statesToBeFinalized := make([]*models.State[StateT], l)
	for (*qc).GetRank() > lastFinalized.Rank {
		b, ok := f.GetState((*qc).Identity())
		if !ok {
			return nil, fmt.Errorf(
				"failed to get state (rank=%d, stateID=%x) for finalization",
				(*qc).GetRank(),
				(*qc).Identity(),
			)
		}
		l--
		statesToBeFinalized[l] = b
		qc = &b.ParentQuorumCertificate // move to parent
	}
	// Now, `l` is the index where we stored the oldest state that should be
	// finalized. Note that `l` might be larger than zero, if some ranks have no
	// finalized states. Hence, `statesToBeFinalized` might start with nil
	// entries, which we remove:
	statesToBeFinalized = statesToBeFinalized[l:]

	// qc should now point to the latest finalized state. Otherwise, the
	// consensus committee is compromised (or we have a critical internal bug).
	if (*qc).GetRank() < lastFinalized.Rank {
		return nil, models.ByzantineThresholdExceededError{Evidence: fmt.Sprintf(
			"finalizing state with rank %d which is lower than previously finalized state at rank %d",
			(*qc).GetRank(), lastFinalized.Rank,
		)}
	}
	if (*qc).GetRank() == lastFinalized.Rank &&
		lastFinalized.Identifier != (*qc).Identity() {
		return nil, models.ByzantineThresholdExceededError{Evidence: fmt.Sprintf(
			"finalizing states with rank %d at conflicting forks: %x and %x",
			(*qc).GetRank(), (*qc).Identity(), lastFinalized.Identifier,
		)}
	}

	return statesToBeFinalized, nil
}
