package timeoutcollector

import (
	"errors"
	"sync"

	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

var (
	// ErrRepeatedTimeout is emitted, when we receive an identical timeout state
	// for the same state from the same voter multiple times. This error does
	// _not_ indicate equivocation.
	ErrRepeatedTimeout            = errors.New("duplicated timeout")
	ErrTimeoutForIncompatibleRank = errors.New("timeout for incompatible rank")
)

// TimeoutStatesCache maintains a _concurrency safe_ cache of timeouts for one
// particular rank. The cache memorizes the order in which the timeouts were
// received. Timeouts are de-duplicated based on the following rules:
//   - For each voter (i.e. SignerID), we store the _first_ timeout t0.
//   - For any subsequent timeout t, we check whether t equals t0.
//     If this is the case, we consider the timeout a duplicate and drop it.
//     If t and t0 have different contents, the voter is equivocating, and
//     we return a models.DoubleTimeoutError.
type TimeoutStatesCache[VoteT models.Unique] struct {
	lock     sync.RWMutex
	rank     uint64
	timeouts map[models.Identity]*models.TimeoutState[VoteT] // signerID -> first timeout
}

// NewTimeoutStatesCache instantiates a TimeoutStatesCache for the given rank
func NewTimeoutStatesCache[VoteT models.Unique](
	rank uint64,
) *TimeoutStatesCache[VoteT] {
	return &TimeoutStatesCache[VoteT]{
		rank:     rank,
		timeouts: make(map[models.Identity]*models.TimeoutState[VoteT]),
	}
}

func (vc *TimeoutStatesCache[VoteT]) Rank() uint64 { return vc.rank }

// AddTimeoutState stores a timeout in the cache. The following errors are
// expected during normal operations:
//   - nil: if the timeout was successfully added
//   - models.DoubleTimeoutError is returned if the replica is equivocating
//   - RepeatedTimeoutErr is returned when adding an _identical_ timeout for the
//     same rank from the same voter multiple times.
//   - TimeoutForIncompatibleRankError is returned if the timeout is for a
//     different rank.
//
// When AddTimeoutState returns an error, the timeout is _not_ stored.
func (vc *TimeoutStatesCache[VoteT]) AddTimeoutState(
	timeout *models.TimeoutState[VoteT],
) error {
	if timeout.Rank != vc.rank {
		return ErrTimeoutForIncompatibleRank
	}
	vc.lock.Lock()

	// De-duplicated timeouts based on the following rules:
	//  * For each voter (i.e. SignerID), we store the _first_  t0.
	//  * For any subsequent timeout t, we check whether t equals t0.
	//    If this is the case, we consider the timeout a duplicate and drop it.
	//    If t and t0 have different contents, the voter is equivocating, and
	//    we return a models.DoubleTimeoutError.
	firstTimeout, exists := vc.timeouts[(*timeout.Vote).Identity()]
	if exists {
		vc.lock.Unlock()
		if !firstTimeout.Equals(timeout) {
			return models.NewDoubleTimeoutErrorf(
				firstTimeout,
				timeout,
				"detected timeout equivocation by replica %x at rank: %d",
				(*timeout.Vote).Identity(),
				vc.rank,
			)
		}
		return ErrRepeatedTimeout
	}
	vc.timeouts[(*timeout.Vote).Identity()] = timeout
	vc.lock.Unlock()

	return nil
}

// GetTimeoutState returns the stored timeout for the given `signerID`. Returns:
//   - (timeout, true) if a timeout state from signerID is known
//   - (nil, false) no timeout state from signerID is known
func (vc *TimeoutStatesCache[VoteT]) GetTimeoutState(
	signerID models.Identity,
) (*models.TimeoutState[VoteT], bool) {
	vc.lock.RLock()
	timeout, exists := vc.timeouts[signerID] // if signerID is unknown, its `Vote` pointer is nil
	vc.lock.RUnlock()
	return timeout, exists
}

// Size returns the number of cached timeout states
func (vc *TimeoutStatesCache[VoteT]) Size() int {
	vc.lock.RLock()
	s := len(vc.timeouts)
	vc.lock.RUnlock()
	return s
}

// All returns all currently cached timeout states. Concurrency safe.
func (vc *TimeoutStatesCache[VoteT]) All() []*models.TimeoutState[VoteT] {
	vc.lock.RLock()
	defer vc.lock.RUnlock()
	return vc.all()
}

// all returns all currently cached timeout states. NOT concurrency safe
func (vc *TimeoutStatesCache[VoteT]) all() []*models.TimeoutState[VoteT] {
	timeoutStates := make([]*models.TimeoutState[VoteT], 0, len(vc.timeouts))
	for _, t := range vc.timeouts {
		timeoutStates = append(timeoutStates, t)
	}
	return timeoutStates
}
