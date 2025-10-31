package votecollector

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// TestVotesCache_Rank tests that Rank returns same value that was set by constructor
func TestVotesCache_Rank(t *testing.T) {
	rank := uint64(100)
	cache := NewVotesCache[*helper.TestVote](rank)
	require.Equal(t, rank, cache.Rank())
}

// TestVotesCache_AddVoteRepeatedVote tests that AddVote skips duplicated votes
func TestVotesCache_AddVoteRepeatedVote(t *testing.T) {
	t.Parallel()

	rank := uint64(100)
	cache := NewVotesCache[*helper.TestVote](rank)
	vote := helper.VoteFixture(func(v **helper.TestVote) {
		(*v).Rank = rank
	})

	require.NoError(t, cache.AddVote(&vote))
	err := cache.AddVote(&vote)
	require.ErrorIs(t, err, RepeatedVoteErr)
}

// TestVotesCache_AddVoteIncompatibleRank tests that adding vote with incompatible rank results in error
func TestVotesCache_AddVoteIncompatibleRank(t *testing.T) {
	t.Parallel()

	rank := uint64(100)
	cache := NewVotesCache[*helper.TestVote](rank)
	vote := helper.VoteFixture(func(v **helper.TestVote) {
		(*v).Rank = rank + 1
	})
	err := cache.AddVote(&vote)
	require.ErrorIs(t, err, VoteForIncompatibleRankError)
}

// TestVotesCache_GetVote tests that GetVote method
func TestVotesCache_GetVote(t *testing.T) {
	rank := uint64(100)
	knownVote := helper.VoteFixture(func(v **helper.TestVote) {
		(*v).Rank = rank
	})
	doubleVote := helper.VoteFixture(func(v **helper.TestVote) {
		(*v).Rank = rank
		(*v).ID = knownVote.ID
	})

	cache := NewVotesCache[*helper.TestVote](rank)

	// unknown vote
	vote, found := cache.GetVote(helper.MakeIdentity())
	assert.Nil(t, vote)
	assert.False(t, found)

	// known vote
	err := cache.AddVote(&knownVote)
	assert.NoError(t, err)
	vote, found = cache.GetVote(knownVote.ID)
	assert.Equal(t, &knownVote, vote)
	assert.True(t, found)

	// for a signer ID with a known vote, the cache should memorize the _first_ encountered vote
	err = cache.AddVote(&doubleVote)
	assert.True(t, models.IsDoubleVoteError[*helper.TestVote](err))
	vote, found = cache.GetVote(doubleVote.ID)
	assert.Equal(t, &knownVote, vote)
	assert.True(t, found)
}

// TestVotesCache_All tests that All returns previously added votes in same order
func TestVotesCache_All(t *testing.T) {
	t.Parallel()

	rank := uint64(100)
	cache := NewVotesCache[*helper.TestVote](rank)
	expectedVotes := make([]**helper.TestVote, 0, 5)
	for i := range expectedVotes {
		vote := helper.VoteFixture(func(v **helper.TestVote) {
			(*v).Rank = rank
		})
		expectedVotes[i] = &vote
		require.NoError(t, cache.AddVote(&vote))
	}
	require.Equal(t, expectedVotes, cache.All())
}

// TestVotesCache_RegisterVoteConsumer tests that registered vote consumer receives all previously added votes as well as
// new ones in expected order.
func TestVotesCache_RegisterVoteConsumer(t *testing.T) {
	t.Parallel()

	rank := uint64(100)
	cache := NewVotesCache[*helper.TestVote](rank)
	votesBatchSize := 5
	expectedVotes := make([]*helper.TestVote, 0, votesBatchSize)
	// produce first batch before registering vote consumer
	for i := range expectedVotes {
		vote := helper.VoteFixture(func(v **helper.TestVote) {
			(*v).Rank = rank
		})
		expectedVotes[i] = vote
		require.NoError(t, cache.AddVote(&vote))
	}

	consumedVotes := make([]*helper.TestVote, 0)
	voteConsumer := func(vote **helper.TestVote) {
		consumedVotes = append(consumedVotes, *vote)
	}

	// registering vote consumer has to fill consumedVotes using callback
	cache.RegisterVoteConsumer(voteConsumer)
	// all cached votes should be fed into the consumer right away
	require.Equal(t, expectedVotes, consumedVotes)

	// produce second batch after registering vote consumer
	for i := 0; i < votesBatchSize; i++ {
		vote := helper.VoteFixture(func(v **helper.TestVote) {
			(*v).Rank = rank
		})
		expectedVotes = append(expectedVotes, vote)
		require.NoError(t, cache.AddVote(&vote))
	}

	// at this point consumedVotes has to have all votes created before and after registering vote
	// consumer, and they must be in same order
	require.Equal(t, expectedVotes, consumedVotes)
}

// BenchmarkAdd measured the time it takes to add `numberVotes` concurrently to the VotesCache.
// On MacBook with Intel i7-7820HQ CPU @ 2.90GHz:
// adding 1 million votes in total, with 20 threads concurrently, took 0.48s
func BenchmarkAdd(b *testing.B) {
	numberVotes := 1_000_000
	threads := 20

	// Setup: create worker routines and votes to feed
	rank := uint64(10)
	cache := NewVotesCache[*helper.TestVote](rank)

	var start sync.WaitGroup
	start.Add(threads)
	var done sync.WaitGroup
	done.Add(threads)

	stateID := helper.MakeIdentity()
	n := numberVotes / threads

	for ; threads > 0; threads-- {
		go func(i int) {
			// create votes and signal ready
			votes := make([]*helper.TestVote, 0, n)
			for len(votes) < n {
				v := helper.VoteFixture(func(v **helper.TestVote) {
					(*v).Rank = rank
					(*v).StateID = stateID
				})
				votes = append(votes, v)
			}
			start.Done()

			// Wait for last worker routine to signal ready. Then,
			// feed all votes into cache
			start.Wait()
			for _, v := range votes {
				err := cache.AddVote(&v)
				assert.NoError(b, err)
			}
			done.Done()
		}(threads)
	}
	start.Wait()
	t1 := time.Now()
	done.Wait()
	duration := time.Since(t1)
	fmt.Printf("=> adding %d votes to Cache took %f seconds\n", cache.Size(), duration.Seconds())
}
