package votecollector

import (
	"errors"
	"fmt"
	"sync"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

var (
	VoteForIncompatibleRankError  = errors.New("vote for incompatible rank")
	VoteForIncompatibleStateError = errors.New("vote for incompatible state")
)

/******************************* NoopProcessor *******************************/

// NoopProcessor implements consensus.VoteProcessor. It drops all votes.
type NoopProcessor[VoteT models.Unique] struct {
	status consensus.VoteCollectorStatus
}

func NewNoopCollector[VoteT models.Unique](
	status consensus.VoteCollectorStatus,
) *NoopProcessor[VoteT] {
	return &NoopProcessor[VoteT]{status}
}

func (c *NoopProcessor[VoteT]) Process(*VoteT) error {
	return nil
}

func (c *NoopProcessor[VoteT]) Status() consensus.VoteCollectorStatus {
	return c.status
}

/************************ enforcing vote is for state ************************/

// EnsureVoteForState verifies that the vote is for the given state.
// Returns nil on success and sentinel errors:
//   - models.VoteForIncompatibleRankError if the vote is from a different rank
//     than state
//   - models.VoteForIncompatibleStateError if the vote is from the same rank as
//     state but for a different stateID
func EnsureVoteForState[StateT models.Unique, VoteT models.Unique](
	vote *VoteT,
	state *models.State[StateT],
) error {
	if (*vote).GetRank() != state.Rank {
		return fmt.Errorf(
			"vote %x has rank %d while state's rank is %d: %w ",
			(*vote).Identity(),
			(*vote).GetRank(),
			state.Rank,
			VoteForIncompatibleRankError,
		)
	}
	if (*vote).Source() != state.Identifier {
		return fmt.Errorf(
			"expecting only votes for state %x, but vote %x is for state %x: %w ",
			state.Identifier,
			(*vote).Identity(),
			(*vote).Source(),
			VoteForIncompatibleStateError,
		)
	}
	return nil
}

/********************* AppendOnlyIdentifierSet *********************/

// AppendOnlyIdentifierSet implements a simple set for tracking unique entries by
// identifier. Removal is not supported — append-only guarantees. Concurrency safe.
type AppendOnlyIdentifierSet struct {
	set  map[models.Identity]struct{}
	lock sync.Mutex
}

// NewConcurrentIdentifierSet creates a new AppendOnlyIdentifierSet.
func NewConcurrentIdentifierSet() *AppendOnlyIdentifierSet {
	return &AppendOnlyIdentifierSet{
		set: make(map[models.Identity]struct{}),
	}
}

// Add adds identifier to the internal set. Returns true when added, false if already present.
func (s *AppendOnlyIdentifierSet) Add(identifier models.Identity) bool {
	s.lock.Lock()
	defer s.lock.Unlock()
	_, exists := s.set[identifier]
	if !exists {
		s.set[identifier] = struct{}{}
	}
	return !exists
}
