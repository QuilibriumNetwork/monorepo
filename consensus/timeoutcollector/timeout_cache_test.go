package timeoutcollector

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// TestTimeoutStatesCache_Rank tests that Rank returns same value that was set by constructor
func TestTimeoutStatesCache_Rank(t *testing.T) {
	rank := uint64(100)
	cache := NewTimeoutStatesCache[*helper.TestVote](rank)
	require.Equal(t, rank, cache.Rank())
}

// TestTimeoutStatesCache_AddTimeoutStateRepeatedTimeout tests that AddTimeoutState skips duplicated timeouts
func TestTimeoutStatesCache_AddTimeoutStateRepeatedTimeout(t *testing.T) {
	t.Parallel()

	rank := uint64(100)
	cache := NewTimeoutStatesCache[*helper.TestVote](rank)
	timeout := helper.TimeoutStateFixture(
		helper.WithTimeoutStateRank[*helper.TestVote](rank),
		helper.WithTimeoutVote[*helper.TestVote](&helper.TestVote{
			ID:   "1",
			Rank: rank,
		}),
	)

	require.NoError(t, cache.AddTimeoutState(timeout))
	err := cache.AddTimeoutState(timeout)
	require.ErrorIs(t, err, ErrRepeatedTimeout)
	require.Len(t, cache.All(), 1)
}

// TestTimeoutStatesCache_AddTimeoutStateIncompatibleRank tests that adding timeout with incompatible rank results in error
func TestTimeoutStatesCache_AddTimeoutStateIncompatibleRank(t *testing.T) {
	t.Parallel()

	rank := uint64(100)
	cache := NewTimeoutStatesCache[*helper.TestVote](rank)
	timeout := helper.TimeoutStateFixture(
		helper.WithTimeoutStateRank[*helper.TestVote](rank+1),
		helper.WithTimeoutVote[*helper.TestVote](&helper.TestVote{
			ID:   "1",
			Rank: rank,
		}),
	)
	err := cache.AddTimeoutState(timeout)
	require.ErrorIs(t, err, ErrTimeoutForIncompatibleRank)
}

// TestTimeoutStatesCache_GetTimeout tests that GetTimeout method returns the first added timeout
// for a given signer, if any timeout has been added.
func TestTimeoutStatesCache_GetTimeout(t *testing.T) {
	rank := uint64(100)
	knownTimeout := helper.TimeoutStateFixture(
		helper.WithTimeoutStateRank[*helper.TestVote](rank),
		helper.WithTimeoutVote[*helper.TestVote](&helper.TestVote{
			ID:   "1",
			Rank: rank,
		}),
	)
	doubleTimeout := helper.TimeoutStateFixture(
		helper.WithTimeoutStateRank[*helper.TestVote](rank),
		helper.WithTimeoutVote[*helper.TestVote](&helper.TestVote{
			ID:   "1",
			Rank: rank,
		}),
	)

	cache := NewTimeoutStatesCache[*helper.TestVote](rank)

	// unknown timeout
	timeout, found := cache.GetTimeoutState(helper.MakeIdentity())
	require.Nil(t, timeout)
	require.False(t, found)

	// known timeout
	err := cache.AddTimeoutState(knownTimeout)
	require.NoError(t, err)
	timeout, found = cache.GetTimeoutState((*knownTimeout.Vote).ID)
	require.Equal(t, knownTimeout, timeout)
	require.True(t, found)

	// for a signer ID with a known timeout, the cache should memorize the _first_ encountered timeout
	err = cache.AddTimeoutState(doubleTimeout)
	require.True(t, models.IsDoubleTimeoutError[*helper.TestVote](err))
	timeout, found = cache.GetTimeoutState((*doubleTimeout.Vote).ID)
	require.Equal(t, knownTimeout, timeout)
	require.True(t, found)
}

// TestTimeoutStatesCache_All tests that All returns previously added timeouts.
func TestTimeoutStatesCache_All(t *testing.T) {
	t.Parallel()

	rank := uint64(100)
	cache := NewTimeoutStatesCache[*helper.TestVote](rank)
	expectedTimeouts := make([]*models.TimeoutState[*helper.TestVote], 5)
	for i := range expectedTimeouts {
		timeout := helper.TimeoutStateFixture(
			helper.WithTimeoutStateRank[*helper.TestVote](rank),
			helper.WithTimeoutVote[*helper.TestVote](&helper.TestVote{
				ID:   fmt.Sprintf("%d", i),
				Rank: rank,
			}),
		)
		expectedTimeouts[i] = timeout
		require.NoError(t, cache.AddTimeoutState(timeout))
	}
	require.ElementsMatch(t, expectedTimeouts, cache.All())
}

// BenchmarkAdd measured the time it takes to add `numberTimeouts` concurrently to the TimeoutStatesCache.
// On MacBook with Intel i7-7820HQ CPU @ 2.90GHz:
// adding 1 million timeouts in total, with 20 threads concurrently, took 0.48s
func BenchmarkAdd(b *testing.B) {
	numberTimeouts := 1_000_000
	threads := 20

	// Setup: create worker routines and timeouts to feed
	rank := uint64(10)
	cache := NewTimeoutStatesCache[*helper.TestVote](rank)

	var start sync.WaitGroup
	start.Add(threads)
	var done sync.WaitGroup
	done.Add(threads)

	n := numberTimeouts / threads

	for ; threads > 0; threads-- {
		go func(i int) {
			// create timeouts and signal ready
			timeouts := make([]models.TimeoutState[*helper.TestVote], 0, n)
			for len(timeouts) < n {
				t := helper.TimeoutStateFixture(
					helper.WithTimeoutStateRank[*helper.TestVote](rank),
					helper.WithTimeoutVote[*helper.TestVote](&helper.TestVote{
						ID:   helper.MakeIdentity(),
						Rank: rank,
					}),
				)
				timeouts = append(timeouts, *t)
			}

			start.Done()

			// Wait for last worker routine to signal ready. Then,
			// feed all timeouts into cache
			start.Wait()

			for _, v := range timeouts {
				err := cache.AddTimeoutState(&v)
				require.NoError(b, err)
			}
			done.Done()
		}(threads)
	}
	start.Wait()
	t1 := time.Now()
	done.Wait()
	duration := time.Since(t1)
	fmt.Printf("=> adding %d timeouts to Cache took %f seconds\n", cache.Size(), duration.Seconds())
}
