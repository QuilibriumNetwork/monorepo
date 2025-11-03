package forks

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/mocks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

/*****************************************************************************
 * NOTATION:                                                                 *
 * A state is denoted as [◄(<qc_number>) <state_rank_number>].               *
 * For example, [◄(1) 2] means: a state of rank 2 that has a QC for rank 1.  *
 *****************************************************************************/

// TestInitialization verifies that at initialization, Forks reports:
//   - the root / genesis state as finalized
//   - it has no finalization proof for the root / genesis state (state and its finalization is trusted)
func TestInitialization(t *testing.T) {
	forks, _ := newForks(t)
	requireOnlyGenesisStateFinalized(t, forks)
	_, hasProof := forks.FinalityProof()
	require.False(t, hasProof)
}

// TestFinalize_Direct1Chain tests adding a direct 1-chain on top of the genesis state:
//   - receives [◄(1) 2] [◄(2) 5]
//
// Expected behaviour:
//   - On the one hand, Forks should not finalize any _additional_ states, because there is
//     no finalizable 2-chain for [◄(1) 2]. Hence, finalization no events should be emitted.
//   - On the other hand, after adding the two states, Forks has enough knowledge to construct
//     a FinalityProof for the genesis state.
func TestFinalize_Direct1Chain(t *testing.T) {
	builder := NewStateBuilder().
		Add(1, 2).
		Add(2, 3)
	states, err := builder.States()
	require.NoError(t, err)

	t.Run("consensus participant mode: ingest validated states", func(t *testing.T) {
		forks, _ := newForks(t)

		// adding state [◄(1) 2] should not finalize anything
		// as the genesis state is trusted, there should be no FinalityProof available for it
		require.NoError(t, forks.AddValidatedState(states[0]))
		requireOnlyGenesisStateFinalized(t, forks)
		_, hasProof := forks.FinalityProof()
		require.False(t, hasProof)

		// After adding state [◄(2) 3], Forks has enough knowledge to construct a FinalityProof for the
		// genesis state. However, finalization remains at the genesis state, so no events should be emitted.
		expectedFinalityProof := makeFinalityProof(t, builder.GenesisState().State, states[0], states[1].ParentQuorumCertificate)
		require.NoError(t, forks.AddValidatedState(states[1]))
		requireLatestFinalizedState(t, forks, builder.GenesisState().State)
		requireFinalityProof(t, forks, expectedFinalityProof)
	})

	t.Run("consensus follower mode: ingest certified states", func(t *testing.T) {
		forks, _ := newForks(t)

		// After adding CertifiedState [◄(1) 2] ◄(2), Forks has enough knowledge to construct a FinalityProof for
		// the genesis state. However, finalization remains at the genesis state, so no events should be emitted.
		expectedFinalityProof := makeFinalityProof(t, builder.GenesisState().State, states[0], states[1].ParentQuorumCertificate)
		c, err := models.NewCertifiedState(states[0], states[1].ParentQuorumCertificate)
		require.NoError(t, err)

		require.NoError(t, forks.AddCertifiedState(c))
		requireLatestFinalizedState(t, forks, builder.GenesisState().State)
		requireFinalityProof(t, forks, expectedFinalityProof)
	})
}

// TestFinalize_Direct2Chain tests adding a direct 1-chain on a direct 1-chain (direct 2-chain).
//   - receives [◄(1) 2] [◄(2) 3] [◄(3) 4]
//   - Forks should finalize [◄(1) 2]
func TestFinalize_Direct2Chain(t *testing.T) {
	states, err := NewStateBuilder().
		Add(1, 2).
		Add(2, 3).
		Add(3, 4).
		States()
	require.NoError(t, err)
	expectedFinalityProof := makeFinalityProof(t, states[0], states[1], states[2].ParentQuorumCertificate)

	t.Run("consensus participant mode: ingest validated states", func(t *testing.T) {
		forks, _ := newForks(t)
		require.Nil(t, addValidatedStateToForks(forks, states))

		requireLatestFinalizedState(t, forks, states[0])
		requireFinalityProof(t, forks, expectedFinalityProof)
	})

	t.Run("consensus follower mode: ingest certified states", func(t *testing.T) {
		forks, _ := newForks(t)
		require.Nil(t, addCertifiedStatesToForks(forks, states))

		requireLatestFinalizedState(t, forks, states[0])
		requireFinalityProof(t, forks, expectedFinalityProof)
	})
}

// TestFinalize_DirectIndirect2Chain tests adding an indirect 1-chain on a direct 1-chain.
// receives [◄(1) 2] [◄(2) 3] [◄(3) 5]
// it should finalize [◄(1) 2]
func TestFinalize_DirectIndirect2Chain(t *testing.T) {
	states, err := NewStateBuilder().
		Add(1, 2).
		Add(2, 3).
		Add(3, 5).
		States()
	require.NoError(t, err)
	expectedFinalityProof := makeFinalityProof(t, states[0], states[1], states[2].ParentQuorumCertificate)

	t.Run("consensus participant mode: ingest validated states", func(t *testing.T) {
		forks, _ := newForks(t)
		require.Nil(t, addValidatedStateToForks(forks, states))

		requireLatestFinalizedState(t, forks, states[0])
		requireFinalityProof(t, forks, expectedFinalityProof)
	})

	t.Run("consensus follower mode: ingest certified states", func(t *testing.T) {
		forks, _ := newForks(t)
		require.Nil(t, addCertifiedStatesToForks(forks, states))

		requireLatestFinalizedState(t, forks, states[0])
		requireFinalityProof(t, forks, expectedFinalityProof)
	})
}

// TestFinalize_IndirectDirect2Chain tests adding a direct 1-chain on an indirect 1-chain.
//   - Forks receives [◄(1) 3] [◄(3) 5] [◄(7) 7]
//   - it should not finalize any states because there is no finalizable 2-chain.
func TestFinalize_IndirectDirect2Chain(t *testing.T) {
	states, err := NewStateBuilder().
		Add(1, 3).
		Add(3, 5).
		Add(5, 7).
		States()
	require.NoError(t, err)

	t.Run("consensus participant mode: ingest validated states", func(t *testing.T) {
		forks, _ := newForks(t)
		require.Nil(t, addValidatedStateToForks(forks, states))

		requireOnlyGenesisStateFinalized(t, forks)
		_, hasProof := forks.FinalityProof()
		require.False(t, hasProof)
	})

	t.Run("consensus follower mode: ingest certified states", func(t *testing.T) {
		forks, _ := newForks(t)
		require.Nil(t, addCertifiedStatesToForks(forks, states))

		requireOnlyGenesisStateFinalized(t, forks)
		_, hasProof := forks.FinalityProof()
		require.False(t, hasProof)
	})
}

// TestFinalize_Direct2ChainOnIndirect tests adding a direct 2-chain on an indirect 2-chain:
//   - ingesting [◄(1) 3] [◄(3) 5] [◄(5) 6] [◄(6) 7] [◄(7) 8]
//   - should result in finalization of [◄(5) 6]
func TestFinalize_Direct2ChainOnIndirect(t *testing.T) {
	states, err := NewStateBuilder().
		Add(1, 3).
		Add(3, 5).
		Add(5, 6).
		Add(6, 7).
		Add(7, 8).
		States()
	require.NoError(t, err)
	expectedFinalityProof := makeFinalityProof(t, states[2], states[3], states[4].ParentQuorumCertificate)

	t.Run("consensus participant mode: ingest validated states", func(t *testing.T) {
		forks, _ := newForks(t)
		require.Nil(t, addValidatedStateToForks(forks, states))

		requireLatestFinalizedState(t, forks, states[2])
		requireFinalityProof(t, forks, expectedFinalityProof)
	})

	t.Run("consensus follower mode: ingest certified states", func(t *testing.T) {
		forks, _ := newForks(t)
		require.Nil(t, addCertifiedStatesToForks(forks, states))

		requireLatestFinalizedState(t, forks, states[2])
		requireFinalityProof(t, forks, expectedFinalityProof)
	})
}

// TestFinalize_Direct2ChainOnDirect tests adding a sequence of direct 2-chains:
//   - ingesting [◄(1) 2] [◄(2) 3] [◄(3) 4] [◄(4) 5] [◄(5) 6]
//   - should result in finalization of [◄(3) 4]
func TestFinalize_Direct2ChainOnDirect(t *testing.T) {
	states, err := NewStateBuilder().
		Add(1, 2).
		Add(2, 3).
		Add(3, 4).
		Add(4, 5).
		Add(5, 6).
		States()
	require.NoError(t, err)
	expectedFinalityProof := makeFinalityProof(t, states[2], states[3], states[4].ParentQuorumCertificate)

	t.Run("consensus participant mode: ingest validated states", func(t *testing.T) {
		forks, _ := newForks(t)
		require.Nil(t, addValidatedStateToForks(forks, states))

		requireLatestFinalizedState(t, forks, states[2])
		requireFinalityProof(t, forks, expectedFinalityProof)
	})

	t.Run("consensus follower mode: ingest certified states", func(t *testing.T) {
		forks, _ := newForks(t)
		require.Nil(t, addCertifiedStatesToForks(forks, states))

		requireLatestFinalizedState(t, forks, states[2])
		requireFinalityProof(t, forks, expectedFinalityProof)
	})
}

// TestFinalize_Multiple2Chains tests the case where a state can be finalized by different 2-chains.
//   - ingesting [◄(1) 2] [◄(2) 3] [◄(3) 5] [◄(3) 6] [◄(3) 7]
//   - should result in finalization of [◄(1) 2]
func TestFinalize_Multiple2Chains(t *testing.T) {
	states, err := NewStateBuilder().
		Add(1, 2).
		Add(2, 3).
		Add(3, 5).
		Add(3, 6).
		Add(3, 7).
		States()
	require.NoError(t, err)
	expectedFinalityProof := makeFinalityProof(t, states[0], states[1], states[2].ParentQuorumCertificate)

	t.Run("consensus participant mode: ingest validated states", func(t *testing.T) {
		forks, _ := newForks(t)
		require.Nil(t, addValidatedStateToForks(forks, states))

		requireLatestFinalizedState(t, forks, states[0])
		requireFinalityProof(t, forks, expectedFinalityProof)
	})

	t.Run("consensus follower mode: ingest certified states", func(t *testing.T) {
		forks, _ := newForks(t)
		require.Nil(t, addCertifiedStatesToForks(forks, states))

		requireLatestFinalizedState(t, forks, states[0])
		requireFinalityProof(t, forks, expectedFinalityProof)
	})
}

// TestFinalize_OrphanedFork tests that we can finalize a state which causes a conflicting fork to be orphaned.
// We ingest the following state tree:
//
//	[◄(1) 2] [◄(2) 3]
//	         [◄(2) 4] [◄(4) 5] [◄(5) 6]
//
// which should result in finalization of [◄(2) 4] and pruning of [◄(2) 3]
func TestFinalize_OrphanedFork(t *testing.T) {
	states, err := NewStateBuilder().
		Add(1, 2). // [◄(1) 2]
		Add(2, 3). // [◄(2) 3], should eventually be pruned
		Add(2, 4). // [◄(2) 4], should eventually be finalized
		Add(4, 5). // [◄(4) 5]
		Add(5, 6). // [◄(5) 6]
		States()
	require.NoError(t, err)
	expectedFinalityProof := makeFinalityProof(t, states[2], states[3], states[4].ParentQuorumCertificate)

	t.Run("consensus participant mode: ingest validated states", func(t *testing.T) {
		forks, _ := newForks(t)
		require.Nil(t, addValidatedStateToForks(forks, states))

		require.False(t, forks.IsKnownState(states[1].Identifier))
		requireLatestFinalizedState(t, forks, states[2])
		requireFinalityProof(t, forks, expectedFinalityProof)
	})

	t.Run("consensus follower mode: ingest certified states", func(t *testing.T) {
		forks, _ := newForks(t)
		require.Nil(t, addCertifiedStatesToForks(forks, states))

		require.False(t, forks.IsKnownState(states[1].Identifier))
		requireLatestFinalizedState(t, forks, states[2])
		requireFinalityProof(t, forks, expectedFinalityProof)
	})
}

// TestDuplication tests that delivering the same state/qc multiple times has
// the same end state as delivering the state/qc once.
//   - Forks receives [◄(1) 2] [◄(2) 3] [◄(2) 3] [◄(3) 4] [◄(3) 4] [◄(4) 5] [◄(4) 5]
//   - it should finalize [◄(2) 3]
func TestDuplication(t *testing.T) {
	states, err := NewStateBuilder().
		Add(1, 2).
		Add(2, 3).
		Add(2, 3).
		Add(3, 4).
		Add(3, 4).
		Add(4, 5).
		Add(4, 5).
		States()
	require.NoError(t, err)
	expectedFinalityProof := makeFinalityProof(t, states[1], states[3], states[5].ParentQuorumCertificate)

	t.Run("consensus participant mode: ingest validated states", func(t *testing.T) {
		forks, _ := newForks(t)
		require.Nil(t, addValidatedStateToForks(forks, states))

		requireLatestFinalizedState(t, forks, states[1])
		requireFinalityProof(t, forks, expectedFinalityProof)
	})

	t.Run("consensus follower mode: ingest certified states", func(t *testing.T) {
		forks, _ := newForks(t)
		require.Nil(t, addCertifiedStatesToForks(forks, states))

		requireLatestFinalizedState(t, forks, states[1])
		requireFinalityProof(t, forks, expectedFinalityProof)
	})
}

// TestIgnoreStatesBelowFinalizedRank tests that states below finalized rank are ignored.
//   - Forks receives [◄(1) 2] [◄(2) 3] [◄(3) 4] [◄(1) 5]
//   - it should finalize [◄(1) 2]
func TestIgnoreStatesBelowFinalizedRank(t *testing.T) {
	builder := NewStateBuilder().
		Add(1, 2). // [◄(1) 2]
		Add(2, 3). // [◄(2) 3]
		Add(3, 4). // [◄(3) 4]
		Add(1, 5)  // [◄(1) 5]
	states, err := builder.States()
	require.NoError(t, err)
	expectedFinalityProof := makeFinalityProof(t, states[0], states[1], states[2].ParentQuorumCertificate)

	t.Run("consensus participant mode: ingest validated states", func(t *testing.T) {
		// initialize forks and add first 3 states:
		//  * state [◄(1) 2] should then be finalized
		//  * and state [1] should be pruned
		forks, _ := newForks(t)
		require.Nil(t, addValidatedStateToForks(forks, states[:3]))

		// sanity checks to confirm correct test setup
		requireLatestFinalizedState(t, forks, states[0])
		requireFinalityProof(t, forks, expectedFinalityProof)
		require.False(t, forks.IsKnownState(builder.GenesisState().Identifier()))

		// adding state [◄(1) 5]: note that QC is _below_ the pruning threshold, i.e. cannot resolve the parent
		// * Forks should store state, despite the parent already being pruned
		// * finalization should not change
		orphanedState := states[3]
		require.Nil(t, forks.AddValidatedState(orphanedState))
		require.True(t, forks.IsKnownState(orphanedState.Identifier))
		requireLatestFinalizedState(t, forks, states[0])
		requireFinalityProof(t, forks, expectedFinalityProof)
	})

	t.Run("consensus follower mode: ingest certified states", func(t *testing.T) {
		// initialize forks and add first 3 states:
		//  * state [◄(1) 2] should then be finalized
		//  * and state [1] should be pruned
		forks, _ := newForks(t)
		require.Nil(t, addCertifiedStatesToForks(forks, states[:3]))
		// sanity checks to confirm correct test setup
		requireLatestFinalizedState(t, forks, states[0])
		requireFinalityProof(t, forks, expectedFinalityProof)
		require.False(t, forks.IsKnownState(builder.GenesisState().Identifier()))

		// adding state [◄(1) 5]: note that QC is _below_ the pruning threshold, i.e. cannot resolve the parent
		// * Forks should store state, despite the parent already being pruned
		// * finalization should not change
		certStateWithUnknownParent := toCertifiedState(t, states[3])
		require.Nil(t, forks.AddCertifiedState(certStateWithUnknownParent))
		require.True(t, forks.IsKnownState(certStateWithUnknownParent.State.Identifier))
		requireLatestFinalizedState(t, forks, states[0])
		requireFinalityProof(t, forks, expectedFinalityProof)
	})
}

// TestDoubleProposal tests that the DoubleProposal notification is emitted when two different
// states for the same rank are added. We ingest the following state tree:
//
//	               / [◄(1) 2]
//			[1]
//	               \ [◄(1) 2']
//
// which should result in a DoubleProposal event referencing the states [◄(1) 2] and [◄(1) 2']
func TestDoubleProposal(t *testing.T) {
	states, err := NewStateBuilder().
		Add(1, 2).                // [◄(1) 2]
		AddVersioned(1, 2, 0, 1). // [◄(1) 2']
		States()
	require.NoError(t, err)

	t.Run("consensus participant mode: ingest validated states", func(t *testing.T) {
		forks, notifier := newForks(t)
		notifier.On("OnDoubleProposeDetected", states[1], states[0]).Once()

		err = addValidatedStateToForks(forks, states)
		require.NoError(t, err)
	})

	t.Run("consensus follower mode: ingest certified states", func(t *testing.T) {
		forks, notifier := newForks(t)
		notifier.On("OnDoubleProposeDetected", states[1], states[0]).Once()

		err = forks.AddCertifiedState(toCertifiedState(t, states[0])) // add [◄(1) 2]  as certified state
		require.NoError(t, err)
		err = forks.AddCertifiedState(toCertifiedState(t, states[1])) // add [◄(1) 2']  as certified state
		require.NoError(t, err)
	})
}

// TestConflictingQCs checks that adding 2 conflicting QCs should return models.ByzantineThresholdExceededError
// We ingest the following state tree:
//
//	[◄(1) 2] [◄(2) 3]   [◄(3) 4]  [◄(4) 6]
//	         [◄(2) 3']  [◄(3') 5]
//
// which should result in a `ByzantineThresholdExceededError`, because conflicting states 3 and 3' both have QCs
func TestConflictingQCs(t *testing.T) {
	states, err := NewStateBuilder().
		Add(1, 2).                // [◄(1) 2]
		Add(2, 3).                // [◄(2) 3]
		AddVersioned(2, 3, 0, 1). // [◄(2) 3']
		Add(3, 4).                // [◄(3) 4]
		Add(4, 6).                // [◄(4) 6]
		AddVersioned(3, 5, 1, 0). // [◄(3') 5]
		States()
	require.NoError(t, err)

	t.Run("consensus participant mode: ingest validated states", func(t *testing.T) {
		forks, notifier := newForks(t)
		notifier.On("OnDoubleProposeDetected", states[2], states[1]).Return(nil)

		err = addValidatedStateToForks(forks, states)
		assert.True(t, models.IsByzantineThresholdExceededError(err))
	})

	t.Run("consensus follower mode: ingest certified states", func(t *testing.T) {
		forks, notifier := newForks(t)
		notifier.On("OnDoubleProposeDetected", states[2], states[1]).Return(nil)

		// As [◄(3') 5] is not certified, it will not be added to Forks. However, its QC ◄(3') is
		// delivered to Forks as part of the *certified* state [◄(2) 3'].
		err = addCertifiedStatesToForks(forks, states)
		assert.True(t, models.IsByzantineThresholdExceededError(err))
	})
}

// TestConflictingFinalizedForks checks that finalizing 2 conflicting forks should return models.ByzantineThresholdExceededError
// We ingest the following state tree:
//
//	[◄(1) 2] [◄(2) 3] [◄(3) 4] [◄(4) 5]
//	         [◄(2) 6] [◄(6) 7] [◄(7) 8]
//
// Here, both states [◄(2) 3] and [◄(2) 6] satisfy the finalization condition, i.e. we have a fork
// in the finalized states, which should result in a models.ByzantineThresholdExceededError exception.
func TestConflictingFinalizedForks(t *testing.T) {
	states, err := NewStateBuilder().
		Add(1, 2).
		Add(2, 3).
		Add(3, 4).
		Add(4, 5). // finalizes [◄(2) 3]
		Add(2, 6).
		Add(6, 7).
		Add(7, 8). // finalizes [◄(2) 6], conflicting with conflicts with [◄(2) 3]
		States()
	require.NoError(t, err)

	t.Run("consensus participant mode: ingest validated states", func(t *testing.T) {
		forks, _ := newForks(t)
		err = addValidatedStateToForks(forks, states)
		assert.True(t, models.IsByzantineThresholdExceededError(err))
	})

	t.Run("consensus follower mode: ingest certified states", func(t *testing.T) {
		forks, _ := newForks(t)
		err = addCertifiedStatesToForks(forks, states)
		assert.True(t, models.IsByzantineThresholdExceededError(err))
	})
}

// TestAddDisconnectedState checks that adding a state which does not connect to the
// latest finalized state returns a `models.MissingStateError`
//   - receives [◄(2) 3]
//   - should return `models.MissingStateError`, because the parent is above the pruning
//     threshold, but Forks does not know its parent
func TestAddDisconnectedState(t *testing.T) {
	states, err := NewStateBuilder().
		Add(1, 2). // we will skip this state [◄(1) 2]
		Add(2, 3). // [◄(2) 3]
		States()
	require.NoError(t, err)

	t.Run("consensus participant mode: ingest validated states", func(t *testing.T) {
		forks, _ := newForks(t)
		err := forks.AddValidatedState(states[1])
		require.Error(t, err)
		assert.True(t, models.IsMissingStateError(err))
	})

	t.Run("consensus follower mode: ingest certified states", func(t *testing.T) {
		forks, _ := newForks(t)
		err := forks.AddCertifiedState(toCertifiedState(t, states[1]))
		require.Error(t, err)
		assert.True(t, models.IsMissingStateError(err))
	})
}

// TestGetState tests that we can retrieve stored states. Here, we test that
// attempting to retrieve nonexistent or pruned states fails without causing an exception.
//   - Forks receives [◄(1) 2] [◄(2) 3] [◄(3) 4], then [◄(4) 5]
//   - should finalize [◄(1) 2], then [◄(2) 3]
func TestGetState(t *testing.T) {
	states, err := NewStateBuilder().
		Add(1, 2). // [◄(1) 2]
		Add(2, 3). // [◄(2) 3]
		Add(3, 4). // [◄(3) 4]
		Add(4, 5). // [◄(4) 5]
		States()
	require.NoError(t, err)

	t.Run("consensus participant mode: ingest validated states", func(t *testing.T) {
		statesAddedFirst := states[:3] // [◄(1) 2] [◄(2) 3] [◄(3) 4]
		remainingState := states[3]    // [◄(4) 5]
		forks, _ := newForks(t)

		// should be unable to retrieve a state before it is added
		_, ok := forks.GetState(states[0].Identifier)
		assert.False(t, ok)

		// add first 3 states - should finalize [◄(1) 2]
		err = addValidatedStateToForks(forks, statesAddedFirst)
		require.NoError(t, err)

		// should be able to retrieve all stored states
		for _, state := range statesAddedFirst {
			b, ok := forks.GetState(state.Identifier)
			assert.True(t, ok)
			assert.Equal(t, state, b)
		}

		// add remaining state [◄(4) 5] - should finalize [◄(2) 3] and prune [◄(1) 2]
		require.Nil(t, forks.AddValidatedState(remainingState))

		// should be able to retrieve just added state
		b, ok := forks.GetState(remainingState.Identifier)
		assert.True(t, ok)
		assert.Equal(t, remainingState, b)

		// should be unable to retrieve pruned state
		_, ok = forks.GetState(statesAddedFirst[0].Identifier)
		assert.False(t, ok)
	})

	// Caution: finalization is driven by QCs. Therefore, we include the QC for state 3
	// in the first batch of states that we add. This is analogous to previous test case,
	// except that we are delivering the QC ◄(3) as part of the certified state of rank 2
	//   [◄(2) 3] ◄(3)
	// while in the previous sub-test, the QC ◄(3) was delivered as part of state [◄(3) 4]
	t.Run("consensus follower mode: ingest certified states", func(t *testing.T) {
		statesAddedFirst := toCertifiedStates(t, states[:2]...) // [◄(1) 2] [◄(2) 3] ◄(3)
		remainingState := toCertifiedState(t, states[2])        // [◄(3) 4] ◄(4)
		forks, _ := newForks(t)

		// should be unable to retrieve a state before it is added
		_, ok := forks.GetState(states[0].Identifier)
		assert.False(t, ok)

		// add first states - should finalize [◄(1) 2]
		err := forks.AddCertifiedState(statesAddedFirst[0])
		require.NoError(t, err)
		err = forks.AddCertifiedState(statesAddedFirst[1])
		require.NoError(t, err)

		// should be able to retrieve all stored states
		for _, state := range statesAddedFirst {
			b, ok := forks.GetState(state.State.Identifier)
			assert.True(t, ok)
			assert.Equal(t, state.State, b)
		}

		// add remaining state [◄(4) 5] - should finalize [◄(2) 3] and prune [◄(1) 2]
		require.Nil(t, forks.AddCertifiedState(remainingState))

		// should be able to retrieve just added state
		b, ok := forks.GetState(remainingState.State.Identifier)
		assert.True(t, ok)
		assert.Equal(t, remainingState.State, b)

		// should be unable to retrieve pruned state
		_, ok = forks.GetState(statesAddedFirst[0].State.Identifier)
		assert.False(t, ok)
	})
}

// TestGetStatesForRank tests retrieving states for a rank (also including double proposals).
//   - Forks receives [◄(1) 2] [◄(2) 4] [◄(2) 4'],
//     where [◄(2) 4'] is a double proposal, because it has the same rank as [◄(2) 4]
//
// Expected behaviour:
//   - Forks should store all the states
//   - Forks should emit a `OnDoubleProposeDetected` notification
//   - we can retrieve all states, including the double proposals
func TestGetStatesForRank(t *testing.T) {
	states, err := NewStateBuilder().
		Add(1, 2).                // [◄(1) 2]
		Add(2, 4).                // [◄(2) 4]
		AddVersioned(2, 4, 0, 1). // [◄(2) 4']
		States()
	require.NoError(t, err)

	t.Run("consensus participant mode: ingest validated states", func(t *testing.T) {
		forks, notifier := newForks(t)
		notifier.On("OnDoubleProposeDetected", states[2], states[1]).Once()

		err = addValidatedStateToForks(forks, states)
		require.NoError(t, err)

		// expect 1 state at rank 2
		storedStates := forks.GetStatesForRank(2)
		assert.Len(t, storedStates, 1)
		assert.Equal(t, states[0], storedStates[0])

		// expect 2 states at rank 4
		storedStates = forks.GetStatesForRank(4)
		assert.Len(t, storedStates, 2)
		assert.ElementsMatch(t, states[1:], storedStates)

		// expect 0 states at rank 3
		storedStates = forks.GetStatesForRank(3)
		assert.Len(t, storedStates, 0)
	})

	t.Run("consensus follower mode: ingest certified states", func(t *testing.T) {
		forks, notifier := newForks(t)
		notifier.On("OnDoubleProposeDetected", states[2], states[1]).Once()

		err := forks.AddCertifiedState(toCertifiedState(t, states[0]))
		require.NoError(t, err)
		err = forks.AddCertifiedState(toCertifiedState(t, states[1]))
		require.NoError(t, err)
		err = forks.AddCertifiedState(toCertifiedState(t, states[2]))
		require.NoError(t, err)

		// expect 1 state at rank 2
		storedStates := forks.GetStatesForRank(2)
		assert.Len(t, storedStates, 1)
		assert.Equal(t, states[0], storedStates[0])

		// expect 2 states at rank 4
		storedStates = forks.GetStatesForRank(4)
		assert.Len(t, storedStates, 2)
		assert.ElementsMatch(t, states[1:], storedStates)

		// expect 0 states at rank 3
		storedStates = forks.GetStatesForRank(3)
		assert.Len(t, storedStates, 0)
	})
}

// TestNotifications tests that Forks emits the expected events:
//   - Forks receives [◄(1) 2] [◄(2) 3] [◄(3) 4]
//
// Expected Behaviour:
//   - Each of the ingested states should result in an `OnStateIncorporated` notification
//   - Forks should finalize [◄(1) 2], resulting in a `MakeFinal` event and an `OnFinalizedState` event
func TestNotifications(t *testing.T) {
	builder := NewStateBuilder().
		Add(1, 2).
		Add(2, 3).
		Add(3, 4)
	states, err := builder.States()
	require.NoError(t, err)

	t.Run("consensus participant mode: ingest validated states", func(t *testing.T) {
		notifier := &mocks.Consumer[*helper.TestState, *helper.TestVote]{}
		// 4 states including the genesis are incorporated
		notifier.On("OnStateIncorporated", mock.Anything).Return(nil).Times(4)
		notifier.On("OnFinalizedState", states[0]).Once()
		finalizationCallback := mocks.NewFinalizer(t)
		finalizationCallback.On("MakeFinal", states[0].Identifier).Return(nil).Once()

		forks, err := NewForks(builder.GenesisState(), finalizationCallback, notifier)
		require.NoError(t, err)
		require.NoError(t, addValidatedStateToForks(forks, states))
	})

	t.Run("consensus follower mode: ingest certified states", func(t *testing.T) {
		notifier := &mocks.Consumer[*helper.TestState, *helper.TestVote]{}
		// 4 states including the genesis are incorporated
		notifier.On("OnStateIncorporated", mock.Anything).Return(nil).Times(4)
		notifier.On("OnFinalizedState", states[0]).Once()
		finalizationCallback := mocks.NewFinalizer(t)
		finalizationCallback.On("MakeFinal", states[0].Identifier).Return(nil).Once()

		forks, err := NewForks(builder.GenesisState(), finalizationCallback, notifier)
		require.NoError(t, err)
		require.NoError(t, addCertifiedStatesToForks(forks, states))
	})
}

// TestFinalizingMultipleStates tests that `OnFinalizedState` notifications are emitted in correct order
// when there are multiple states finalized by adding a _single_ state.
//   - receiving [◄(1) 3] [◄(3) 5] [◄(5) 7] [◄(7) 11] [◄(11) 12] should not finalize any states,
//     because there is no 2-chain with the first chain link being a _direct_ 1-chain
//   - adding [◄(12) 22] should finalize up to state [◄(6) 11]
//
// This test verifies the following expected properties:
//  1. Safety under reentrancy:
//     While Forks is single-threaded, there is still the possibility of reentrancy. Specifically, the
//     consumers of our finalization events are served by the goroutine executing Forks. It is conceivable
//     that a consumer might access Forks and query the latest finalization proof. This would be legal, if
//     the component supplying the goroutine to Forks also consumes the notifications. Therefore, for API
//     safety, we require forks to _first update_ its `FinalityProof()` before it emits _any_ events.
//  2. For each finalized state, `finalizationCallback` event is executed _before_ `OnFinalizedState` notifications.
//  3. States are finalized in order of increasing height (without skipping any states).
func TestFinalizingMultipleStates(t *testing.T) {
	builder := NewStateBuilder().
		Add(1, 3).   // index 0: [◄(1) 2]
		Add(3, 5).   // index 1: [◄(2) 4]
		Add(5, 7).   // index 2: [◄(4) 6]
		Add(7, 11).  // index 3: [◄(6) 11] -- expected to be finalized
		Add(11, 12). // index 4: [◄(11) 12]
		Add(12, 22)  // index 5: [◄(12) 22]
	states, err := builder.States()
	require.NoError(t, err)

	// The Finality Proof should right away point to the _latest_ finalized state. Subsequently emitting
	// Finalization events for lower states is fine, because notifications are guaranteed to be
	// _eventually_ arriving. I.e. consumers expect notifications / events to be potentially lagging behind.
	expectedFinalityProof := makeFinalityProof(t, states[3], states[4], states[5].ParentQuorumCertificate)

	setupForksAndAssertions := func() (*Forks[*helper.TestState, *helper.TestVote], *mocks.Finalizer, *mocks.Consumer[*helper.TestState, *helper.TestVote]) {
		// initialize Forks with custom event consumers so we can check order of emitted events
		notifier := &mocks.Consumer[*helper.TestState, *helper.TestVote]{}
		finalizationCallback := mocks.NewFinalizer(t)
		notifier.On("OnStateIncorporated", mock.Anything).Return(nil)
		forks, err := NewForks(builder.GenesisState(), finalizationCallback, notifier)
		require.NoError(t, err)

		// expecting finalization of [◄(1) 2] [◄(2) 4] [◄(4) 6] [◄(6) 11] in this order
		statesAwaitingFinalization := toStateAwaitingFinalization(states[:4])

		finalizationCallback.On("MakeFinal", mock.Anything).Run(func(args mock.Arguments) {
			requireFinalityProof(t, forks, expectedFinalityProof) // Requirement 1: forks should _first update_ its `FinalityProof()` before it emits _any_ events

			// Requirement 3: finalized in order of increasing height (without skipping any states).
			expectedNextFinalizationEvents := statesAwaitingFinalization[0]
			require.Equal(t, expectedNextFinalizationEvents.State.Identifier, args[0])

			// Requirement 2: finalized state, `finalizationCallback` event is executed _before_ `OnFinalizedState` notifications.
			// no duplication of events under normal operations expected
			require.False(t, expectedNextFinalizationEvents.MakeFinalCalled)
			require.False(t, expectedNextFinalizationEvents.OnFinalizedStateEmitted)
			expectedNextFinalizationEvents.MakeFinalCalled = true
		}).Return(nil).Times(4)

		notifier.On("OnFinalizedState", mock.Anything).Run(func(args mock.Arguments) {
			requireFinalityProof(t, forks, expectedFinalityProof) // Requirement 1: forks should _first update_ its `FinalityProof()` before it emits _any_ events

			// Requirement 3: finalized in order of increasing height (without skipping any states).
			expectedNextFinalizationEvents := statesAwaitingFinalization[0]
			require.Equal(t, expectedNextFinalizationEvents.State, args[0])

			// Requirement 2: finalized state, `finalizationCallback` event is executed _before_ `OnFinalizedState` notifications.
			// no duplication of events under normal operations expected
			require.True(t, expectedNextFinalizationEvents.MakeFinalCalled)
			require.False(t, expectedNextFinalizationEvents.OnFinalizedStateEmitted)
			expectedNextFinalizationEvents.OnFinalizedStateEmitted = true

			// At this point, `MakeFinal` and `OnFinalizedState` have both been emitted for the state, so we are done with it
			statesAwaitingFinalization = statesAwaitingFinalization[1:]
		}).Times(4)

		return forks, finalizationCallback, notifier
	}

	t.Run("consensus participant mode: ingest validated states", func(t *testing.T) {
		forks, finalizationCallback, notifier := setupForksAndAssertions()
		err = addValidatedStateToForks(forks, states[:5]) // adding [◄(1) 2] [◄(2) 4] [◄(4) 6] [◄(6) 11] [◄(11) 12]
		require.NoError(t, err)
		requireOnlyGenesisStateFinalized(t, forks) // finalization should still be at the genesis state

		require.NoError(t, forks.AddValidatedState(states[5])) // adding [◄(12) 22] should trigger finalization events
		requireFinalityProof(t, forks, expectedFinalityProof)
		finalizationCallback.AssertExpectations(t)
		notifier.AssertExpectations(t)
	})

	t.Run("consensus follower mode: ingest certified states", func(t *testing.T) {
		forks, finalizationCallback, notifier := setupForksAndAssertions()
		// adding [◄(1) 2] [◄(2) 4] [◄(4) 6] [◄(6) 11] ◄(11)
		require.NoError(t, forks.AddCertifiedState(toCertifiedState(t, states[0])))
		require.NoError(t, forks.AddCertifiedState(toCertifiedState(t, states[1])))
		require.NoError(t, forks.AddCertifiedState(toCertifiedState(t, states[2])))
		require.NoError(t, forks.AddCertifiedState(toCertifiedState(t, states[3])))
		require.NoError(t, err)
		requireOnlyGenesisStateFinalized(t, forks) // finalization should still be at the genesis state

		// adding certified state [◄(11) 12] ◄(12) should trigger finalization events
		require.NoError(t, forks.AddCertifiedState(toCertifiedState(t, states[4])))
		requireFinalityProof(t, forks, expectedFinalityProof)
		finalizationCallback.AssertExpectations(t)
		notifier.AssertExpectations(t)
	})
}

//* ************************************* internal functions ************************************* */

func newForks(t *testing.T) (*Forks[*helper.TestState, *helper.TestVote], *mocks.Consumer[*helper.TestState, *helper.TestVote]) {
	notifier := mocks.NewConsumer[*helper.TestState, *helper.TestVote](t)
	notifier.On("OnStateIncorporated", mock.Anything).Return(nil).Maybe()
	notifier.On("OnFinalizedState", mock.Anything).Maybe()
	finalizationCallback := mocks.NewFinalizer(t)
	finalizationCallback.On("MakeFinal", mock.Anything).Return(nil).Maybe()

	genesisBQ := makeGenesis()

	forks, err := NewForks(genesisBQ, finalizationCallback, notifier)

	require.NoError(t, err)
	return forks, notifier
}

// addValidatedStateToForks adds all the given states to Forks, in order.
// If any errors occur, returns the first one.
func addValidatedStateToForks(forks *Forks[*helper.TestState, *helper.TestVote], states []*models.State[*helper.TestState]) error {
	for _, state := range states {
		err := forks.AddValidatedState(state)
		if err != nil {
			return fmt.Errorf("test failed to add state for rank %d: %w", state.Rank, err)
		}
	}
	return nil
}

// addCertifiedStatesToForks iterates over all states, caches them locally in a map,
// constructs certified states whenever possible and adds the certified states to forks,
// Note: if states is a single fork, the _last state_ in the slice will not be added,
//
//	because there is no qc for it
//
// If any errors occur, returns the first one.
func addCertifiedStatesToForks(forks *Forks[*helper.TestState, *helper.TestVote], states []*models.State[*helper.TestState]) error {
	uncertifiedStates := make(map[models.Identity]*models.State[*helper.TestState])
	for _, b := range states {
		uncertifiedStates[b.Identifier] = b
		parentID := b.ParentQuorumCertificate.Identity()
		parent, found := uncertifiedStates[parentID]
		if !found {
			continue
		}
		delete(uncertifiedStates, parentID)

		certParent, err := models.NewCertifiedState(parent, b.ParentQuorumCertificate)
		if err != nil {
			return fmt.Errorf("test failed to creat certified state for rank %d: %w", certParent.State.Rank, err)
		}
		err = forks.AddCertifiedState(certParent)
		if err != nil {
			return fmt.Errorf("test failed to add certified state for rank %d: %w", certParent.State.Rank, err)
		}
	}

	return nil
}

// requireLatestFinalizedState asserts that the latest finalized state has the given rank and qc rank.
func requireLatestFinalizedState(t *testing.T, forks *Forks[*helper.TestState, *helper.TestVote], expectedFinalized *models.State[*helper.TestState]) {
	require.Equal(t, expectedFinalized, forks.FinalizedState(), "finalized state is not as expected")
	require.Equal(t, forks.FinalizedRank(), expectedFinalized.Rank, "FinalizedRank returned wrong value")
}

// requireOnlyGenesisStateFinalized asserts that no states have been finalized beyond the genesis state.
// Caution: does not inspect output of `forks.FinalityProof()`
func requireOnlyGenesisStateFinalized(t *testing.T, forks *Forks[*helper.TestState, *helper.TestVote]) {
	genesis := makeGenesis()
	require.Equal(t, forks.FinalizedState(), genesis.State, "finalized state is not the genesis state")
	require.Equal(t, forks.FinalizedState().Rank, genesis.State.Rank)
	require.Equal(t, forks.FinalizedState().Rank, genesis.CertifyingQuorumCertificate.GetRank())
	require.Equal(t, forks.FinalizedRank(), genesis.State.Rank, "finalized state has wrong qc")

	finalityProof, isKnown := forks.FinalityProof()
	require.Nil(t, finalityProof, "expecting finality proof to be nil for genesis state at initialization")
	require.False(t, isKnown, "no finality proof should be known for genesis state at initialization")
}

// requireNoStatesFinalized asserts that no states have been finalized (genesis is latest finalized state).
func requireFinalityProof(t *testing.T, forks *Forks[*helper.TestState, *helper.TestVote], expectedFinalityProof *consensus.FinalityProof[*helper.TestState]) {
	finalityProof, isKnown := forks.FinalityProof()
	require.True(t, isKnown)
	require.Equal(t, expectedFinalityProof, finalityProof)
	require.Equal(t, forks.FinalizedState(), expectedFinalityProof.State)
	require.Equal(t, forks.FinalizedRank(), expectedFinalityProof.State.Rank)
}

// toCertifiedState generates a QC for the given state and returns their combination as a certified state
func toCertifiedState(t *testing.T, state *models.State[*helper.TestState]) *models.CertifiedState[*helper.TestState] {
	qc := &helper.TestQuorumCertificate{
		Rank:     state.Rank,
		Selector: state.Identifier,
	}
	cb, err := models.NewCertifiedState(state, qc)
	require.NoError(t, err)
	return cb
}

// toCertifiedStates generates a QC for the given state and returns their combination as a certified states
func toCertifiedStates(t *testing.T, states ...*models.State[*helper.TestState]) []*models.CertifiedState[*helper.TestState] {
	certStates := make([]*models.CertifiedState[*helper.TestState], 0, len(states))
	for _, b := range states {
		certStates = append(certStates, toCertifiedState(t, b))
	}
	return certStates
}

func makeFinalityProof(t *testing.T, state *models.State[*helper.TestState], directChild *models.State[*helper.TestState], qcCertifyingChild models.QuorumCertificate) *consensus.FinalityProof[*helper.TestState] {
	c, err := models.NewCertifiedState(directChild, qcCertifyingChild) // certified child of FinalizedState
	require.NoError(t, err)
	return &consensus.FinalityProof[*helper.TestState]{State: state, CertifiedChild: c}
}

// stateAwaitingFinalization is intended for tracking finalization events and their order for a specific state
type stateAwaitingFinalization struct {
	State                   *models.State[*helper.TestState]
	MakeFinalCalled         bool // indicates whether `Finalizer.MakeFinal` was called
	OnFinalizedStateEmitted bool // indicates whether `OnFinalizedStateCalled` notification was emitted
}

// toStateAwaitingFinalization creates a `stateAwaitingFinalization` tracker for each input state
func toStateAwaitingFinalization(states []*models.State[*helper.TestState]) []*stateAwaitingFinalization {
	trackers := make([]*stateAwaitingFinalization, 0, len(states))
	for _, b := range states {
		tracker := &stateAwaitingFinalization{b, false, false}
		trackers = append(trackers, tracker)
	}
	return trackers
}
