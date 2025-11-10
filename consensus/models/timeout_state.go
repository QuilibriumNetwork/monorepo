package models

import (
	"bytes"
)

// TimeoutState represents the stored state change step relevant to the point of
// rank of a given instance of the consensus state machine.
type TimeoutState[VoteT Unique] struct {
	// The rank of the timeout data.
	Rank uint64
	// The latest quorum certificate seen by the pacemaker.
	LatestQuorumCertificate QuorumCertificate
	// The previous rank's timeout certificate, if applicable.
	PriorRankTimeoutCertificate TimeoutCertificate
	// The signed payload which will become part of the new timeout certificate.
	Vote *VoteT
	// TimeoutTick is the number of times the `timeout.Controller` has
	// (re-)emitted the timeout for this rank. When the timer for the rank's
	// original duration expires, a `TimeoutState` with `TimeoutTick = 0` is
	// broadcast. Subsequently, `timeout.Controller` re-broadcasts the
	// `TimeoutState` periodically  based on some internal heuristic. Each time
	// we attempt a re-broadcast, the `TimeoutTick` is incremented. Incrementing
	// the field prevents de-duplicated within the network layer, which in turn
	// guarantees quick delivery of the `TimeoutState` after GST and facilitates
	// recovery.
	TimeoutTick uint64
}

func (t *TimeoutState[VoteT]) Equals(other *TimeoutState[VoteT]) bool {
	// Shortcut if `t` and `other` point to the same object; covers case where
	// both are nil.
	if t == other {
		return true
	}
	if t == nil || other == nil {
		// only one is nil, the other not (otherwise we would have returned above)
		return false
	}

	if t.Vote != other.Vote && (other.Vote == nil || t.Vote == nil) {
		return false
	}

	if (t.PriorRankTimeoutCertificate != nil &&
		other.PriorRankTimeoutCertificate == nil) ||
		(t.PriorRankTimeoutCertificate == nil &&
			other.PriorRankTimeoutCertificate != nil) {
		return false
	}

	// both are not nil, so we can compare the fields
	return t.Rank == other.Rank &&
		((t.LatestQuorumCertificate == nil &&
			other.LatestQuorumCertificate == nil) ||
			t.LatestQuorumCertificate.Equals(other.LatestQuorumCertificate)) &&
		((t.PriorRankTimeoutCertificate == nil &&
			other.PriorRankTimeoutCertificate == nil) ||
			t.PriorRankTimeoutCertificate.Equals(
				other.PriorRankTimeoutCertificate,
			)) &&
		((t.Vote == other.Vote) ||
			((*t.Vote).Source() == (*other.Vote).Source()) &&
				bytes.Equal((*t.Vote).GetSignature(), (*other.Vote).GetSignature()))
}
