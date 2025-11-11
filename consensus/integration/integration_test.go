package integration

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
)

// a pacemaker timeout to wait for proposals. Usually 10 ms is enough,
// but for slow environment like CI, a longer one is needed.
const safeTimeout = 2 * time.Second

// number of failed rounds before first timeout increase
const happyPathMaxRoundFailures = 6

func TestSingleInstance(t *testing.T) {
	fmt.Println("starting single instance test")
	// set up a single instance to run
	finalRank := uint64(10)
	in := NewInstance(t,
		WithStopCondition(RankFinalized(finalRank)),
	)

	// run the event handler until we reach a stop condition
	err := in.Run(t)
	require.ErrorIs(t, err, errStopCondition, "should run until stop condition")

	// check if forks and pacemaker are in expected rank state
	assert.Equal(t, finalRank, in.forks.FinalizedRank(), "finalized rank should be three lower than current rank")
	fmt.Println("ending single instance test")
}

func TestThreeInstances(t *testing.T) {
	fmt.Println("starting three instance test")
	// test parameters
	num := 3
	finalRank := uint64(100)

	// generate three hotstuff participants
	participants := helper.WithWeightedIdentityList(num)
	root := DefaultRoot()

	// set up three instances that are exactly the same
	// since we don't drop any messages we should have enough data to advance in happy path
	// for that reason we will drop all TO related communication.
	instances := make([]*Instance, 0, num)
	for n := 0; n < num; n++ {
		in := NewInstance(t,
			WithRoot(root),
			WithParticipants(participants),
			WithLocalID(participants[n].Identity()),
			WithStopCondition(RankFinalized(finalRank)),
			WithIncomingTimeoutStates(DropAllTimeoutStates),
		)
		instances = append(instances, in)
	}

	// connect the communicators of the instances together
	Connect(t, instances)

	// start the instances and wait for them to finish
	var wg sync.WaitGroup
	for _, in := range instances {
		wg.Add(1)
		go func(in *Instance) {
			err := in.Run(t)
			require.True(t, errors.Is(err, errStopCondition), "should run until stop condition")
			wg.Done()
		}(in)
	}
	wg.Wait()

	// check that all instances have the same finalized state
	in1 := instances[0]
	in2 := instances[1]
	in3 := instances[2]
	// verify progress has been made
	assert.GreaterOrEqual(t, in1.forks.FinalizedState().Rank, finalRank, "the first instance 's finalized rank should be four lower than current rank")
	// verify same progresses have been made
	assert.Equal(t, in1.forks.FinalizedState(), in2.forks.FinalizedState(), "second instance should have same finalized state as first instance")
	assert.Equal(t, in1.forks.FinalizedState(), in3.forks.FinalizedState(), "third instance should have same finalized state as first instance")
	assert.Equal(t, FinalizedRanks(in1), FinalizedRanks(in2))
	assert.Equal(t, FinalizedRanks(in1), FinalizedRanks(in3))
	fmt.Println("ending three instance test")
}

func TestSevenInstances(t *testing.T) {
	fmt.Println("starting seven instance test")
	// test parameters
	numPass := 5
	numFail := 2
	finalRank := uint64(30)

	// generate the seven hotstuff participants
	participants := helper.WithWeightedIdentityList(numPass + numFail)
	instances := make([]*Instance, 0, numPass+numFail)
	root := DefaultRoot()

	// set up five instances that work fully
	for n := 0; n < numPass; n++ {
		in := NewInstance(t,
			WithRoot(root),
			WithParticipants(participants),
			WithLocalID(participants[n].Identity()),
			WithStopCondition(RankFinalized(finalRank)),
		)
		instances = append(instances, in)
	}

	// set up two instances which can't vote
	for n := numPass; n < numPass+numFail; n++ {
		in := NewInstance(t,
			WithRoot(root),
			WithParticipants(participants),
			WithLocalID(participants[n].Identity()),
			WithStopCondition(RankFinalized(finalRank)),
			WithOutgoingVotes(DropAllVotes),
		)
		instances = append(instances, in)
	}

	// connect the communicators of the instances together
	Connect(t, instances)

	// start all seven instances and wait for them to wrap up
	var wg sync.WaitGroup
	for _, in := range instances {
		wg.Add(1)
		go func(in *Instance) {
			err := in.Run(t)
			require.True(t, errors.Is(err, errStopCondition), "should run until stop condition")
			wg.Done()
		}(in)
	}
	wg.Wait()

	// check that all instances have the same finalized state
	ref := instances[0]
	assert.Less(t, finalRank-uint64(2*numPass+numFail), ref.forks.FinalizedState().Rank, "expect instance 0 should made enough progress, but didn't")
	finalizedRanks := FinalizedRanks(ref)
	for i := 1; i < numPass; i++ {
		assert.Equal(t, ref.forks.FinalizedState(), instances[i].forks.FinalizedState(), "instance %d should have same finalized state as first instance")
		assert.Equal(t, finalizedRanks, FinalizedRanks(instances[i]), "instance %d should have same finalized rank as first instance")
	}
	fmt.Println("ending seven instance test")
}
