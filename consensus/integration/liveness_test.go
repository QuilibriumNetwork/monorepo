package integration

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/pacemaker/timeout"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle/unittest"
)

// pacemaker timeout
// if your laptop is fast enough, 10 ms is enough
const pmTimeout = 100 * time.Millisecond

// maxTimeoutRebroadcast specifies how often the PaceMaker rebroadcasts
// its timeout state in case there is no progress. We keep the value
// small so we have smaller latency
const maxTimeoutRebroadcast = 1 * time.Second

// If 2 nodes are down in a 7 nodes cluster, the rest of 5 nodes can
// still make progress and reach consensus
func Test2TimeoutOutof7Instances(t *testing.T) {

	healthyReplicas := 5
	notVotingReplicas := 2
	finalRank := uint64(30)

	// generate the seven hotstuff participants
	participants := helper.WithWeightedIdentityList(healthyReplicas + notVotingReplicas)
	instances := make([]*Instance, 0, healthyReplicas+notVotingReplicas)
	root := DefaultRoot()
	timeouts, err := timeout.NewConfig(pmTimeout, pmTimeout, 1.5, happyPathMaxRoundFailures, maxTimeoutRebroadcast)
	require.NoError(t, err)

	// set up five instances that work fully
	for n := 0; n < healthyReplicas; n++ {
		in := NewInstance(t,
			WithRoot(root),
			WithParticipants(participants),
			WithTimeouts(timeouts),
			WithBufferLogger(),
			WithLocalID(participants[n].Identity()),
			WithLoggerParams(consensus.StringParam("status", "healthy")),
			WithStopCondition(RankFinalized(finalRank)),
		)
		instances = append(instances, in)
	}

	// set up two instances which can't vote, nor propose
	for n := healthyReplicas; n < healthyReplicas+notVotingReplicas; n++ {
		in := NewInstance(t,
			WithRoot(root),
			WithParticipants(participants),
			WithTimeouts(timeouts),
			WithBufferLogger(),
			WithLocalID(participants[n].Identity()),
			WithLoggerParams(consensus.StringParam("status", "unhealthy")),
			WithStopCondition(RankFinalized(finalRank)),
			WithOutgoingVotes(DropAllVotes),
			WithOutgoingProposals(DropAllProposals),
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
			require.ErrorIs(t, err, errStopCondition)
			wg.Done()
		}(in)
	}
	unittest.AssertReturnsBefore(t, wg.Wait, 20*time.Second, "expect to finish before timeout")

	for i, in := range instances {
		fmt.Println("=============================================================================")
		fmt.Println("INSTANCE", i, "-", hex.EncodeToString([]byte(in.localID)))
		fmt.Println("=============================================================================")
		in.logger.(*helper.BufferLog).Flush()
	}

	// check that all instances have the same finalized state
	ref := instances[0]
	assert.Equal(t, finalRank, ref.forks.FinalizedState().Rank, "expect instance 0 should made enough progress, but didn't")
	finalizedRanks := FinalizedRanks(ref)
	for i := 1; i < healthyReplicas; i++ {
		assert.Equal(t, ref.forks.FinalizedState(), instances[i].forks.FinalizedState(), "instance %d should have same finalized state as first instance")
		assert.Equal(t, finalizedRanks, FinalizedRanks(instances[i]), "instance %d should have same finalized rank as first instance")
	}
}

// 2 nodes in a 4-node cluster are configured to be able only to send timeout messages (no voting or proposing).
// The other 2 unconstrained nodes should be able to make progress through the recovery path by creating TCs
// for every round, but no state will be finalized, because finalization requires direct 1-chain and QC.
func Test2TimeoutOutof4Instances(t *testing.T) {

	healthyReplicas := 2
	replicasDroppingHappyPathMsgs := 2
	finalRank := uint64(30)

	// generate the 4 hotstuff participants
	participants := helper.WithWeightedIdentityList(healthyReplicas + replicasDroppingHappyPathMsgs)
	instances := make([]*Instance, 0, healthyReplicas+replicasDroppingHappyPathMsgs)
	root := DefaultRoot()
	timeouts, err := timeout.NewConfig(10*time.Millisecond, 50*time.Millisecond, 1.5, happyPathMaxRoundFailures, maxTimeoutRebroadcast)
	require.NoError(t, err)

	// set up two instances that work fully
	for n := 0; n < healthyReplicas; n++ {
		in := NewInstance(t,
			WithRoot(root),
			WithParticipants(participants),
			WithLocalID(participants[n].Identity()),
			WithTimeouts(timeouts),
			WithLoggerParams(consensus.StringParam("status", "healthy")),
			WithStopCondition(RankReached(finalRank)),
		)
		instances = append(instances, in)
	}

	// set up instances which can't vote, nor propose
	for n := healthyReplicas; n < healthyReplicas+replicasDroppingHappyPathMsgs; n++ {
		in := NewInstance(t,
			WithRoot(root),
			WithParticipants(participants),
			WithLocalID(participants[n].Identity()),
			WithTimeouts(timeouts),
			WithLoggerParams(consensus.StringParam("status", "unhealthy")),
			WithStopCondition(RankReached(finalRank)),
			WithOutgoingVotes(DropAllVotes),
			WithIncomingVotes(DropAllVotes),
			WithOutgoingProposals(DropAllProposals),
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
	unittest.AssertReturnsBefore(t, wg.Wait, 10*time.Second, "expect to finish before timeout")

	// check that all instances have the same finalized state
	ref := instances[0]
	finalizedRanks := FinalizedRanks(ref)
	assert.Equal(t, []uint64{0}, finalizedRanks, "no rank was finalized, because finalization requires 2 direct chain plus a QC which never happen in this case")
	assert.Equal(t, finalRank, ref.pacemaker.CurrentRank(), "expect instance 0 should made enough progress, but didn't")
	for i := 1; i < healthyReplicas; i++ {
		assert.Equal(t, ref.forks.FinalizedState(), instances[i].forks.FinalizedState(), "instance %d should have same finalized state as first instance", i)
		assert.Equal(t, finalizedRanks, FinalizedRanks(instances[i]), "instance %d should have same finalized rank as first instance", i)
		assert.Equal(t, finalRank, instances[i].pacemaker.CurrentRank(), "instance %d should have same active rank as first instance", i)
	}
}

// If 1 node is down in a 5 nodes cluster, the rest of 4 nodes can
// make progress and reach consensus
func Test1TimeoutOutof5Instances(t *testing.T) {

	healthyReplicas := 4
	stateedReplicas := 1
	finalRank := uint64(30)

	// generate the seven hotstuff participants
	participants := helper.WithWeightedIdentityList(healthyReplicas + stateedReplicas)
	instances := make([]*Instance, 0, healthyReplicas+stateedReplicas)
	root := DefaultRoot()
	timeouts, err := timeout.NewConfig(pmTimeout, pmTimeout, 1.5, happyPathMaxRoundFailures, maxTimeoutRebroadcast)
	require.NoError(t, err)

	// set up instances that work fully
	for n := 0; n < healthyReplicas; n++ {
		in := NewInstance(t,
			WithRoot(root),
			WithParticipants(participants),
			WithLocalID(participants[n].Identity()),
			WithTimeouts(timeouts),
			WithLoggerParams(consensus.StringParam("status", "healthy")),
			WithStopCondition(RankFinalized(finalRank)),
		)
		instances = append(instances, in)
	}

	// set up one instance which can't vote, nor propose
	for n := healthyReplicas; n < healthyReplicas+stateedReplicas; n++ {
		in := NewInstance(t,
			WithRoot(root),
			WithParticipants(participants),
			WithLocalID(participants[n].Identity()),
			WithTimeouts(timeouts),
			WithLoggerParams(consensus.StringParam("status", "unhealthy")),
			WithStopCondition(RankReached(finalRank)),
			WithOutgoingVotes(DropAllVotes),
			WithOutgoingProposals(DropAllProposals),
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
			require.ErrorIs(t, err, errStopCondition)
			wg.Done()
		}(in)
	}
	success := unittest.AssertReturnsBefore(t, wg.Wait, 10*time.Second, "expect to finish before timeout")
	if !success {
		t.Logf("dumping state of system:")
		for i, inst := range instances {
			t.Logf(
				"instance %d: %d %d %d",
				i,
				inst.pacemaker.CurrentRank(),
				inst.pacemaker.LatestQuorumCertificate().GetRank(),
				inst.forks.FinalizedState().Rank,
			)
		}
	}

	// check that all instances have the same finalized state
	ref := instances[0]
	finalizedRanks := FinalizedRanks(ref)
	assert.Equal(t, finalRank, ref.forks.FinalizedState().Rank, "expect instance 0 should made enough progress, but didn't")
	for i := 1; i < healthyReplicas; i++ {
		assert.Equal(t, ref.forks.FinalizedState(), instances[i].forks.FinalizedState(), "instance %d should have same finalized state as first instance")
		assert.Equal(t, finalizedRanks, FinalizedRanks(instances[i]), "instance %d should have same finalized rank as first instance")
	}
}

// TestStateDelayIsHigherThanTimeout tests an edge case protocol edge case, where
//   - The state arrives in time for replicas to vote.
//   - The next primary does not respond in time with a follow-up proposal,
//     so nodes start sending TimeoutStates.
//   - However, eventually, the next primary successfully constructs a QC and a new
//     state before a TC leads to the round timing out.
//
// This test verifies that nodes still make progress on the happy path (QC constructed),
// despite already having initiated the timeout.
// Example scenarios, how this timing edge case could manifest:
//   - state delay is very close (or larger) than round duration
//   - delayed message transmission (specifically votes) within network
//   - overwhelmed / slowed-down primary
//   - byzantine primary
//
// Implementation:
//   - We have 4 nodes in total where the TimeoutStates from two of them are always
//     discarded. Therefore, no TC can be constructed.
//   - To force nodes to initiate the timeout (i.e. send TimeoutStates), we set
//     the `stateRateDelay` to _twice_ the PaceMaker Timeout. Furthermore, we configure
//     the PaceMaker to only increase timeout duration after 6 successive round failures.
func TestStateDelayIsHigherThanTimeout(t *testing.T) {
	healthyReplicas := 2
	replicasNotGeneratingTimeouts := 2
	finalRank := uint64(20)

	// generate the 4 hotstuff participants
	participants := helper.WithWeightedIdentityList(healthyReplicas + replicasNotGeneratingTimeouts)
	instances := make([]*Instance, 0, healthyReplicas+replicasNotGeneratingTimeouts)
	root := DefaultRoot()
	timeouts, err := timeout.NewConfig(pmTimeout, pmTimeout, 1.5, happyPathMaxRoundFailures, maxTimeoutRebroadcast)
	require.NoError(t, err)

	// set up 2 instances that fully work (incl. sending TimeoutStates)
	for n := 0; n < healthyReplicas; n++ {
		in := NewInstance(t,
			WithRoot(root),
			WithParticipants(participants),
			WithLocalID(participants[n].Identity()),
			WithTimeouts(timeouts),
			WithStopCondition(RankFinalized(finalRank)),
		)
		instances = append(instances, in)
	}

	// set up two instances which don't generate and receive timeout states
	for n := healthyReplicas; n < healthyReplicas+replicasNotGeneratingTimeouts; n++ {
		in := NewInstance(t,
			WithRoot(root),
			WithParticipants(participants),
			WithLocalID(participants[n].Identity()),
			WithTimeouts(timeouts),
			WithStopCondition(RankFinalized(finalRank)),
			WithIncomingTimeoutStates(DropAllTimeoutStates),
			WithOutgoingTimeoutStates(DropAllTimeoutStates),
		)
		instances = append(instances, in)
	}

	// connect the communicators of the instances together
	Connect(t, instances)

	// start all 4 instances and wait for them to wrap up
	var wg sync.WaitGroup
	for _, in := range instances {
		wg.Add(1)
		go func(in *Instance) {
			err := in.Run(t)
			require.ErrorIs(t, err, errStopCondition)
			wg.Done()
		}(in)
	}
	unittest.AssertReturnsBefore(t, wg.Wait, 10*time.Second, "expect to finish before timeout")

	// check that all instances have the same finalized state
	ref := instances[0]
	assert.Equal(t, finalRank, ref.forks.FinalizedState().Rank, "expect instance 0 should made enough progress, but didn't")
	finalizedRanks := FinalizedRanks(ref)
	// in this test we rely on QC being produced in each rank
	// make sure that all ranks are strictly in increasing order with no gaps
	for i := 1; i < len(finalizedRanks); i++ {
		// finalized ranks are sorted in descending order
		if finalizedRanks[i-1] != finalizedRanks[i]+1 {
			t.Fatalf("finalized ranks series has gap, this is not expected: %v", finalizedRanks)
			return
		}
	}
	for i := 1; i < healthyReplicas; i++ {
		assert.Equal(t, ref.forks.FinalizedState(), instances[i].forks.FinalizedState(), "instance %d should have same finalized state as first instance")
		assert.Equal(t, finalizedRanks, FinalizedRanks(instances[i]), "instance %d should have same finalized rank as first instance")
	}
}

// TestAsyncClusterStartup tests a realistic scenario where nodes are started asynchronously:
//   - Replicas are started in sequential order
//   - Each replica skips voting for first state(emulating message omission).
//   - Each replica skips first Timeout State  (emulating message omission).
//   - At this point protocol loses liveness unless a timeout rebroadcast happens from super-majority of replicas.
//
// This test verifies that nodes still make progress, despite first TO messages being lost.
// Implementation:
//   - We have 4 replicas in total, each of them skips voting for first rank to force a timeout
//   - State TSs for whole committee until each replica has generated its first TO.
//   - After each replica has generated a timeout allow subsequent timeout rebroadcasts to make progress.
func TestAsyncClusterStartup(t *testing.T) {
	replicas := 4
	finalRank := uint64(20)

	// generate the four hotstuff participants
	participants := helper.WithWeightedIdentityList(replicas)
	instances := make([]*Instance, 0, replicas)
	root := DefaultRoot()
	timeouts, err := timeout.NewConfig(pmTimeout, pmTimeout, 1.5, 6, maxTimeoutRebroadcast)
	require.NoError(t, err)

	// set up instances that work fully
	var lock sync.Mutex
	timeoutStateGenerated := make(map[models.Identity]struct{}, 0)
	for n := 0; n < replicas; n++ {
		in := NewInstance(t,
			WithRoot(root),
			WithParticipants(participants),
			WithLocalID(participants[n].Identity()),
			WithTimeouts(timeouts),
			WithStopCondition(RankFinalized(finalRank)),
			WithOutgoingVotes(func(vote *helper.TestVote) bool {
				return vote.Rank == 1
			}),
			WithOutgoingTimeoutStates(func(object *models.TimeoutState[*helper.TestVote]) bool {
				lock.Lock()
				defer lock.Unlock()
				timeoutStateGenerated[(*object.Vote).ID] = struct{}{}
				// start allowing timeouts when every node has generated one
				// when nodes will broadcast again, it will go through
				return len(timeoutStateGenerated) != replicas
			}),
		)
		instances = append(instances, in)
	}

	// connect the communicators of the instances together
	Connect(t, instances)

	// start each node only after previous one has started
	var wg sync.WaitGroup
	for _, in := range instances {
		wg.Add(1)
		go func(in *Instance) {
			err := in.Run(t)
			require.ErrorIs(t, err, errStopCondition)
			wg.Done()
		}(in)
	}
	unittest.AssertReturnsBefore(t, wg.Wait, 20*time.Second, "expect to finish before timeout")

	// check that all instances have the same finalized state
	ref := instances[0]
	assert.Equal(t, finalRank, ref.forks.FinalizedState().Rank, "expect instance 0 should made enough progress, but didn't")
	finalizedRanks := FinalizedRanks(ref)
	for i := 1; i < replicas; i++ {
		assert.Equal(t, ref.forks.FinalizedState(), instances[i].forks.FinalizedState(), "instance %d should have same finalized state as first instance")
		assert.Equal(t, finalizedRanks, FinalizedRanks(instances[i]), "instance %d should have same finalized rank as first instance")
	}
}
