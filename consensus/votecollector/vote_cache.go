package votecollector

import (
	"bytes"
	"errors"
	"sync"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

var (
	// RepeatedVoteErr is emitted, when we receive a vote for the same state
	// from the same voter multiple times. This error does _not_ indicate
	// equivocation.
	RepeatedVoteErr = errors.New("duplicated vote")
)

// voteContainer container stores the vote and in index representing
// the order in which the votes were received
type voteContainer[VoteT models.Unique] struct {
	Vote  *VoteT
	index int
}

// VotesCache maintains a _concurrency safe_ cache of votes for one particular
// rank. The cache memorizes the order in which the votes were received. Votes
// are de-duplicated based on the following rules:
//   - Vor each voter (i.e. SignerID), we store the _first_ vote v0.
//   - For any subsequent vote v, we check whether v.Identifier == v0.Identifier.
//     If this is the case, we consider the vote a duplicate and drop it.
//     If v and v0 have different Identifiers, the voter is equivocating and
//     we return a models.DoubleVoteError
type VotesCache[VoteT models.Unique] struct {
	// CAUTION: In the VoteCollector's liveness proof, we utilized that reading the VotesCache
	// happens before writing to it. Only locks are agnostic to the performed operation being a
	// read or a write. Atomic variables only establish a 'synchronized before' relation when a
	// preceding write is observed by a subsequent read. However, the VoteProcessor first reads
	// and then writes. For atomic variables, this order does not induce any synchronization
	// guarantees per Go Memory Model (https://go.dev/ref/mem). Hence, utilizing locks here is
	// critical for the correctness of the VoteCollector.
	lock sync.RWMutex
	rank          uint64
	votes         map[models.Identity]voteContainer[VoteT] // signerID -> first vote
	voteConsumers []consensus.VoteConsumer[VoteT]
}

// NewVotesCache instantiates a VotesCache for the given rank
func NewVotesCache[VoteT models.Unique](rank uint64) *VotesCache[VoteT] {
	return &VotesCache[VoteT]{
		rank:  rank,
		votes: make(map[models.Identity]voteContainer[VoteT]),
	}
}

func (vc *VotesCache[VoteT]) Rank() uint64 { return vc.rank }

// AddVote stores a vote in the cache. The following errors are expected during
// normal operations:
//   - nil: if the vote was successfully added
//   - models.DoubleVoteError is returned if the voter is equivocating
//     (i.e. voting in the same rank for different states).
//   - RepeatedVoteErr is returned when adding a vote for the same state from
//     the same voter multiple times.
//   - IncompatibleRankErr is returned if the vote is for a different rank.
//
// When AddVote returns an error, the vote is _not_ stored.
func (vc *VotesCache[VoteT]) AddVote(vote *VoteT) error {
	if (*vote).GetRank() != vc.rank {
		return VoteForIncompatibleRankError
	}
	vc.lock.Lock()
	defer vc.lock.Unlock()

	// De-duplicated votes based on the following rules:
	//  * Vor each voter (i.e. SignerID), we store the _first_ vote v0.
	//  * For any subsequent vote v, we check whether
	//    v.Identifier == v0.Identifier.
	//    If this is the case, we consider the vote a duplicate and drop it.
	//    If v and v0 have different Identifiers, the voter is equivocating and
	//    we return a models.DoubleVoteError
	firstVote, exists := vc.votes[(*vote).Identity()]
	if exists {
		// Check if votes are identical (exact same source AND signature)
		if (*firstVote.Vote).Source() == (*vote).Source() &&
			bytes.Equal((*firstVote.Vote).GetSignature(), (*vote).GetSignature()) {
			return RepeatedVoteErr
		}
		if (*firstVote.Vote).Source() != (*vote).Source() {
			// voting for different states → vote equivocation
			return models.NewDoubleVoteErrorf(
				firstVote.Vote,
				vote,
				"replica voted for different states in rank %d",
				vc.rank,
			)
		}
		// Same source but different signature → equivocation
		return models.NewDoubleVoteErrorf(
			firstVote.Vote,
			vote,
			"detected vote equivocation at rank: %d",
			vc.rank,
		)
	}

	// previously unknown vote: (1) store and (2) forward to consumers
	vc.votes[(*vote).Identity()] = voteContainer[VoteT]{vote, len(vc.votes)}
	for _, consumer := range vc.voteConsumers {
		consumer(vote)
	}
	return nil
}

// GetVote returns the stored vote for the given `signerID`. Returns:
//   - (vote, true) if a vote from signerID is known
//   - (false, nil) no vote from signerID is known
func (vc *VotesCache[VoteT]) GetVote(signerID models.Identity) (*VoteT, bool) {
	vc.lock.RLock()
	container, exists := vc.votes[signerID] // if signerID is unknown, its `Vote` pointer is nil
	vc.lock.RUnlock()
	return container.Vote, exists
}

// Size returns the number of cached votes
func (vc *VotesCache[VoteT]) Size() int {
	vc.lock.RLock()
	s := len(vc.votes)
	vc.lock.RUnlock()
	return s
}

// RegisterVoteConsumer registers a VoteConsumer. Upon registration, the cache
// feeds all cached votes into the consumer in the order they arrived.
// CAUTION: a consumer _must_ be non-stateing and consume the votes without
// noteworthy delay. Otherwise, consensus speed is impacted.
//
// Expected usage patter: During happy-path operations, the state arrives in a
// timely manner. Hence, we expect that only a few votes are cached when a
// consumer is registered. For the purpose of forensics, we might register a
// consumer later, when already lots of votes are cached. However, this should
// be a rare occurrence (we except moderate performance overhead in this case).
func (vc *VotesCache[VoteT]) RegisterVoteConsumer(
	consumer consensus.VoteConsumer[VoteT],
) {
	vc.lock.Lock()
	defer vc.lock.Unlock()

	vc.voteConsumers = append(vc.voteConsumers, consumer)
	for _, vote := range vc.all() { // feed the consumer with the cached votes
		consumer(vote) // non-stateing per API contract
	}
}

// All returns all currently cached votes. Concurrency safe.
func (vc *VotesCache[VoteT]) All() []*VoteT {
	vc.lock.Lock()
	defer vc.lock.Unlock()
	return vc.all()
}

// all returns all currently cached votes. NOT concurrency safe
func (vc *VotesCache[VoteT]) all() []*VoteT {
	orderedVotes := make([]*VoteT, len(vc.votes))
	for _, v := range vc.votes {
		orderedVotes[v.index] = v.Vote
	}
	return orderedVotes
}
