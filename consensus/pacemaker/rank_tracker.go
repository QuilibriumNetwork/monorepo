package pacemaker

import (
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// rankTracker is a sub-component of the PaceMaker, which encapsulates the logic
// for tracking and updating the current rank. For crash resilience, the
// rankTracker persists its latest internal state.
//
// In addition, rankTracker maintains and persists a proof to show that it
// entered the current rank according to protocol rules. To enter a new rank
// `r`, the Pacemaker must observe a valid QC or TC for rank `r-1`. Per
// convention, the proof has the following structure:
//   - If the current rank was entered by observing a QC, this QC is returned by
//     `NewestQC()`.
//     Furthermore, `PriorRankTimeoutCertificate()` returns nil.
//   - If the current rank was entered by observing a TC, `NewestQC()` returns
//     the newest QC known. `PriorRankTimeoutCertificate()` returns the TC that
//     triggered the rank change
type rankTracker[StateT models.Unique, VoteT models.Unique] struct {
	livenessState models.LivenessState
	store         consensus.ConsensusStore[VoteT]
}

// newRankTracker instantiates a rankTracker.
func newRankTracker[StateT models.Unique, VoteT models.Unique](
	filter []byte,
	store consensus.ConsensusStore[VoteT],
) (rankTracker[StateT, VoteT], error) {
	livenessState, err := store.GetLivenessState(filter)
	if err != nil {
		return rankTracker[StateT, VoteT]{},
			fmt.Errorf("could not load liveness data: %w", err)
	}

	return rankTracker[StateT, VoteT]{
		livenessState: *livenessState,
		store:         store,
	}, nil
}

// CurrentRank returns the current rank.
func (vt *rankTracker[StateT, VoteT]) CurrentRank() uint64 {
	return vt.livenessState.CurrentRank
}

// LatestQuorumCertificate returns the QC with the highest rank known.
func (
	vt *rankTracker[StateT, VoteT],
) LatestQuorumCertificate() models.QuorumCertificate {
	return vt.livenessState.LatestQuorumCertificate
}

// PriorRankTimeoutCertificate returns TC for last rank, this is nil if and only
// of the current rank was entered with a QC.
func (
	vt *rankTracker[StateT, VoteT],
) PriorRankTimeoutCertificate() models.TimeoutCertificate {
	return vt.livenessState.PriorRankTimeoutCertificate
}

// ReceiveQuorumCertificate ingests a QC, which might advance the current rank.
// Panics for nil input! QCs with ranks smaller or equal to the newest QC known
// are a no-op. ReceiveQuorumCertificate returns the resulting rank after
// processing the QC. No errors are expected, any error should be treated as
// exception.
func (vt *rankTracker[StateT, VoteT]) ReceiveQuorumCertificate(
	qc models.QuorumCertificate,
) (
	uint64,
	error,
) {
	rank := vt.livenessState.CurrentRank
	if qc.GetRank() < rank {
		// If the QC is for a past rank, our rank does not change. Nevertheless, the
		// QC might be newer than the newest QC we know, since rank changes can
		// happen through TCs as well. While not very likely, is is possible that
		// individual replicas know newer QCs than the ones previously included in
		// TCs. E.g. a primary that crashed before it could construct its state is
		// has rebooted and is now sharing its newest QC as part of a TimeoutState.
		err := vt.updateNewestQC(qc)
		if err != nil {
			return rank, fmt.Errorf("could not update tracked newest QC: %w", err)
		}
		return rank, nil
	}

	// supermajority of replicas have already voted during round `qc.rank`, hence
	// it is safe to proceed to subsequent rank
	newRank := qc.GetRank() + 1
	err := vt.updateLivenessState(newRank, qc, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to update liveness data: %w", err)
	}
	return newRank, nil
}

// ReceiveTimeoutCertificate ingests a TC, which might advance the current rank.
// A nil TC is accepted as input, so that callers may pass in e.g.
// `Proposal.PriorRankTimeoutCertificate`, which may or may not have a value. It
// returns the resulting rank after processing the TC and embedded QC. No errors
// are expected, any error should be treated as exception.
func (vt *rankTracker[StateT, VoteT]) ReceiveTimeoutCertificate(
	tc models.TimeoutCertificate,
) (uint64, error) {
	rank := vt.livenessState.CurrentRank

	if tc == nil {
		return rank, nil
	}

	if tc.GetRank() < rank {
		// TC and the embedded QC are for a past rank, hence our rank does not
		// change. Nevertheless, the QC might be newer than the newest QC we know.
		// While not very likely, is is possible that individual replicas know newer
		// QCs than the ones previously included in any TCs. E.g. a primary that
		// crashed before it could construct its state is has rebooted and now
		// contributed its newest QC to this TC.
		err := vt.updateNewestQC(tc.GetLatestQuorumCert())
		if err != nil {
			return 0, fmt.Errorf("could not update tracked newest QC: %w", err)
		}
		return rank, nil
	}

	// supermajority of replicas have already reached their timeout for rank
	// `tc.GetRank()`, hence it is safe to proceed to subsequent rank
	newRank := tc.GetRank() + 1
	err := vt.updateLivenessState(newRank, tc.GetLatestQuorumCert(), tc)
	if err != nil {
		return 0, fmt.Errorf("failed to update liveness state: %w", err)
	}
	return newRank, nil
}

// updateLivenessState updates the current rank, qc, tc. We want to avoid
// unnecessary database writes, which we enforce by requiring that the rank
// number is STRICTLY monotonicly increasing. Otherwise, an exception is
// returned. No errors are expected, any error should be treated as exception.
func (vt *rankTracker[StateT, VoteT]) updateLivenessState(
	newRank uint64,
	qc models.QuorumCertificate,
	tc models.TimeoutCertificate,
) error {
	if newRank <= vt.livenessState.CurrentRank {
		// This should never happen: in the current implementation, it is trivially
		// apparent that newRank is _always_ larger than currentRank. This check is
		// to protect the code from future modifications that violate the necessary
		// condition for STRICTLY monotonicly increasing rank numbers.
		return fmt.Errorf(
			"cannot move from rank %d to %d: currentRank must be strictly monotonicly increasing",
			vt.livenessState.CurrentRank,
			newRank,
		)
	}

	vt.livenessState.CurrentRank = newRank
	if vt.livenessState.LatestQuorumCertificate.GetRank() < qc.GetRank() {
		vt.livenessState.LatestQuorumCertificate = qc
	}
	vt.livenessState.PriorRankTimeoutCertificate = tc
	err := vt.store.PutLivenessState(&vt.livenessState)
	if err != nil {
		return fmt.Errorf("could not persist liveness state: %w", err)
	}
	return nil
}

// updateNewestQC updates the highest QC tracked by rank, iff `qc` has a larger
// rank than the newest stored QC. Otherwise, this method is a no-op.
// No errors are expected, any error should be treated as exception.
func (vt *rankTracker[StateT, VoteT]) updateNewestQC(
	qc models.QuorumCertificate,
) error {
	if vt.livenessState.LatestQuorumCertificate.GetRank() >= qc.GetRank() {
		return nil
	}

	vt.livenessState.LatestQuorumCertificate = qc
	err := vt.store.PutLivenessState(&vt.livenessState)
	if err != nil {
		return fmt.Errorf("could not persist liveness state: %w", err)
	}

	return nil
}
