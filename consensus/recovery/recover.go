package recovery

import (
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// StateScanner describes a function for ingesting pending states.
// Any returned errors are considered fatal.
type StateScanner[StateT models.Unique, VoteT models.Unique] func(
	proposal *models.SignedProposal[StateT, VoteT],
) error

// Recover is a utility method for recovering the HotStuff state after a
// restart. It receives the list `pending` containing _all_ states that
//   - have passed the compliance layer and stored in the protocol state
//   - descend from the latest finalized state
//   - are listed in ancestor-first order (i.e. for any state B ∈ pending, B's
//     parent must be listed before B, unless B's parent is the latest finalized
//     state)
//
// CAUTION: all pending states are required to be valid (guaranteed if the state
// passed the compliance layer)
func Recover[StateT models.Unique, VoteT models.Unique](
	log consensus.TraceLogger,
	pending []*models.SignedProposal[StateT, VoteT],
	scanners ...StateScanner[StateT, VoteT],
) error {
	log.Trace(
		"recovery started",
		consensus.Int64Param("total", int64(len(pending))),
	)

	// add all pending states to forks
	for _, proposal := range pending {
		for _, s := range scanners {
			err := s(proposal)
			if err != nil {
				return fmt.Errorf("scanner failed to ingest proposal: %w", err)
			}
		}
		log.Trace(
			"state recovered",
			consensus.Uint64Param("rank", proposal.State.Rank),
			consensus.IdentityParam("state_id", proposal.State.Identifier),
		)
	}

	log.Trace("recovery completed")
	return nil
}

// ForksState recovers Forks' internal state of states descending from the
// latest finalized state. Caution, input states must be valid and in
// parent-first order (unless parent is the latest finalized state).
func ForksState[StateT models.Unique, VoteT models.Unique](
	forks consensus.Forks[StateT],
) StateScanner[StateT, VoteT] {
	return func(proposal *models.SignedProposal[StateT, VoteT]) error {
		err := forks.AddValidatedState(proposal.State)
		if err != nil {
			return fmt.Errorf(
				"could not add state %x to forks: %w",
				proposal.State.Identifier,
				err,
			)
		}
		return nil
	}
}

// VoteAggregatorState recovers the VoteAggregator's internal state as follows:
//   - Add all states descending from the latest finalized state to accept
//     votes. Those states should be rapidly pruned as the node catches up.
//
// Caution: input states must be valid.
func VoteAggregatorState[StateT models.Unique, VoteT models.Unique](
	voteAggregator consensus.VoteAggregator[StateT, VoteT],
) StateScanner[StateT, VoteT] {
	return func(proposal *models.SignedProposal[StateT, VoteT]) error {
		voteAggregator.AddState(proposal)
		return nil
	}
}

// CollectParentQCs collects all parent QCs included in the states descending
// from the latest finalized state. Caution, input states must be valid.
func CollectParentQCs[StateT models.Unique, VoteT models.Unique](
	collector Collector[models.QuorumCertificate],
) StateScanner[StateT, VoteT] {
	return func(proposal *models.SignedProposal[StateT, VoteT]) error {
		qc := proposal.State.ParentQuorumCertificate
		if qc != nil {
			collector.Append(qc)
		}
		return nil
	}
}

// CollectTCs collect all TCs included in the states descending from the
// latest finalized state. Caution, input states must be valid.
func CollectTCs[StateT models.Unique, VoteT models.Unique](
	collector Collector[models.TimeoutCertificate],
) StateScanner[StateT, VoteT] {
	return func(proposal *models.SignedProposal[StateT, VoteT]) error {
		tc := proposal.PreviousRankTimeoutCertificate
		if tc != nil {
			collector.Append(tc)
		}
		return nil
	}
}

// Collector for objects of generic type. Essentially, it is a stateful list.
// Safe to be passed by value. Retrieve() returns the current state of the list
// and is unaffected by subsequent appends.
type Collector[T any] struct {
	list *[]T
}

func NewCollector[T any]() Collector[T] {
	list := make([]T, 0, 5) // heuristic: pre-allocate with some basic capacity
	return Collector[T]{list: &list}
}

// Append adds new elements to the end of the list.
func (c Collector[T]) Append(t ...T) {
	*c.list = append(*c.list, t...)
}

// Retrieve returns the current state of the list (unaffected by subsequent
// append)
func (c Collector[T]) Retrieve() []T {
	// Under the hood, the slice is a struct containing a pointer to an underlying
	// array and a `len` variable indicating how many of the array elements are
	// occupied. Here, we are returning the slice struct by value, i.e. we _copy_
	// the array pointer and the `len` value and return the copy. Therefore, the
	// returned slice is unaffected by subsequent append.
	return *c.list
}
