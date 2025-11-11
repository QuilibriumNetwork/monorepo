package tracker

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// TestNewNewestQCTracker checks that new instance returns nil tracked value.
func TestNewNewestQCTracker(t *testing.T) {
	tracker := NewNewestQCTracker()
	require.Nil(t, tracker.NewestQC())
}

// TestNewestQCTracker_Track this test is needed to make sure that concurrent updates on NewestQCTracker are performed correctly,
// and it always tracks the newest QC, especially in scenario of shared access. This test is structured in a way that it
// starts multiple goroutines that will try to submit their QCs simultaneously to the tracker. Once all goroutines are started
// we will use a wait group to execute all operations as concurrent as possible, after that we will observe if resulted value
// is indeed expected. This test will run multiple times.
func TestNewestQCTracker_Track(t *testing.T) {
	tracker := NewNewestQCTracker()
	samples := 20 // number of concurrent updates per test case
	times := 20   // number of times we run the test case

	// setup initial value
	initialQC := helper.MakeQC(helper.WithQCRank(0))
	tracker.Track(&initialQC)

	for i := 0; i < times; i++ {
		startRank := (*tracker.NewestQC()).GetRank()
		var readyWg, startWg, doneWg sync.WaitGroup
		startWg.Add(1)
		readyWg.Add(samples)
		doneWg.Add(samples)
		for s := 0; s < samples; s++ {
			qc := helper.MakeQC(helper.WithQCRank(startRank + uint64(s+1)))
			go func(newestQC *models.QuorumCertificate) {
				defer doneWg.Done()
				readyWg.Done()
				startWg.Wait()
				tracker.Track(newestQC)
			}(&qc)
		}

		// wait for all goroutines to be ready
		readyWg.Wait()
		// since we have waited for all goroutines to be ready this `Done` will start all goroutines
		startWg.Done()
		// wait for all of them to finish execution
		doneWg.Wait()

		// at this point tracker MUST have the newest QC
		require.Equal(t, startRank+uint64(samples), (*tracker.NewestQC()).GetRank())
	}
}

// TestNewNewestTCTracker checks that new instance returns nil tracked value.
func TestNewNewestTCTracker(t *testing.T) {
	tracker := NewNewestTCTracker()
	require.Nil(t, tracker.NewestTC())
}

// TestNewestTCTracker_Track this test is needed to make sure that concurrent updates on NewestTCTracker are performed correctly,
// and it always tracks the newest TC, especially in scenario of shared access. This test is structured in a way that it
// starts multiple goroutines that will try to submit their TCs simultaneously to the tracker. Once all goroutines are started
// we will use a wait group to execute all operations as concurrent as possible, after that we will observe if resulted value
// is indeed expected. This test will run multiple times.
func TestNewestTCTracker_Track(t *testing.T) {
	tracker := NewNewestTCTracker()
	samples := 20
	times := 20

	// setup initial value
	initialTc := helper.MakeTC(helper.WithTCRank(0))
	tracker.Track(&initialTc)

	for i := 0; i < times; i++ {
		startRank := (*tracker.NewestTC()).GetRank()
		var readyWg, startWg, doneWg sync.WaitGroup
		startWg.Add(1)
		readyWg.Add(samples)
		doneWg.Add(samples)
		for s := 0; s < samples; s++ {
			tc := helper.MakeTC(helper.WithTCRank(startRank + uint64(s+1)))
			go func(newestTC *models.TimeoutCertificate) {
				defer doneWg.Done()
				readyWg.Done()
				startWg.Wait()
				tracker.Track(newestTC)
			}(&tc)
		}

		// wait for all goroutines to be ready
		readyWg.Wait()
		// since we have waited for all goroutines to be ready this `Done` will start all goroutines
		startWg.Done()
		// wait for all of them to finish execution
		doneWg.Wait()

		// at this point tracker MUST have the newest TC
		require.Equal(t, startRank+uint64(samples), (*tracker.NewestTC()).GetRank())
	}
}

// TestNewNewestStateTracker checks that new instance returns nil tracked value.
func TestNewNewestStateTracker(t *testing.T) {
	tracker := NewNewestStateTracker[*helper.TestState]()
	require.Nil(t, tracker.NewestState())
}

// TestNewestStateTracker_Track this test is needed to make sure that concurrent updates on NewestStateTracker are performed correctly,
// and it always tracks the newest state, especially in scenario of shared access. This test is structured in a way that it
// starts multiple goroutines that will try to submit their states simultaneously to the tracker. Once all goroutines are started
// we will use a wait group to execute all operations as concurrent as possible, after that we will observe if resulted value
// is indeed expected. This test will run multiple times.
func TestNewestStateTracker_Track(t *testing.T) {
	tracker := NewNewestStateTracker[*helper.TestState]()
	samples := 20 // number of concurrent updates per test case
	times := 20   // number of times we run the test case

	// setup initial value
	tracker.Track(helper.MakeState(helper.WithStateRank[*helper.TestState](0)))

	for i := 0; i < times; i++ {
		startRank := tracker.NewestState().Rank
		var readyWg, startWg, doneWg sync.WaitGroup
		startWg.Add(1)
		readyWg.Add(samples)
		doneWg.Add(samples)
		for s := 0; s < samples; s++ {
			state := helper.MakeState(helper.WithStateRank[*helper.TestState](startRank + uint64(s+1)))
			go func(newestState *models.State[*helper.TestState]) {
				defer doneWg.Done()
				readyWg.Done()
				startWg.Wait()
				tracker.Track(newestState)
			}(state)
		}

		// wait for all goroutines to be ready
		readyWg.Wait()
		// since we have waited for all goroutines to be ready this `Done` will start all goroutines
		startWg.Done()
		// wait for all of them to finish execution
		doneWg.Wait()

		// at this point tracker MUST have the newest state
		require.Equal(t, startRank+uint64(samples), tracker.NewestState().Rank)
	}
}
