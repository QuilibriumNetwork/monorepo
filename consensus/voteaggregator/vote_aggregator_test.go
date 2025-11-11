package voteaggregator

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/mocks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle/unittest"
)

func TestVoteAggregator(t *testing.T) {
	ts := new(VoteAggregatorTestSuite)
	ts.errs = make(chan error, 1)
	suite.Run(t, ts)
}

// VoteAggregatorTestSuite is a test suite for isolated testing of VoteAggregator.
// Contains mocked state which is used to verify correct behavior of VoteAggregator.
// Automatically starts and stops module.Startable in SetupTest and TearDownTest respectively.
type VoteAggregatorTestSuite struct {
	suite.Suite

	aggregator     *VoteAggregator[*helper.TestState, *helper.TestVote]
	collectors     *mocks.VoteCollectors[*helper.TestState, *helper.TestVote]
	consumer       *mocks.VoteAggregationConsumer[*helper.TestState, *helper.TestVote]
	stopAggregator context.CancelFunc
	errs           <-chan error
}

func (s *VoteAggregatorTestSuite) SetupTest() {
	var err error
	s.collectors = mocks.NewVoteCollectors[*helper.TestState, *helper.TestVote](s.T())
	s.consumer = mocks.NewVoteAggregationConsumer[*helper.TestState, *helper.TestVote](s.T())

	s.collectors.On("Start", mock.Anything).Return(nil).Once()
	unittest.Componentify(&s.collectors.Mock)
	s.aggregator, err = NewVoteAggregator(
		helper.Logger(),
		s.consumer,
		0,
		s.collectors,
	)
	require.NoError(s.T(), err)

	ctx, cancel := context.WithCancel(context.Background())
	signalerCtx, errs := lifecycle.WithSignaler(ctx)
	s.stopAggregator = cancel
	s.errs = errs
	s.aggregator.Start(signalerCtx)
	unittest.RequireCloseBefore(s.T(), s.aggregator.Ready(), 100*time.Millisecond, "should close before timeout")
}

func (s *VoteAggregatorTestSuite) TearDownTest() {
	s.stopAggregator()
	unittest.RequireCloseBefore(s.T(), s.aggregator.Done(), 10*time.Second, "should close before timeout")
}

// TestOnFinalizedState tests if finalized state gets processed when send through `VoteAggregator`.
// Tests the whole processing pipeline.
func (s *VoteAggregatorTestSuite) TestOnFinalizedState() {
	finalizedState := helper.MakeState(helper.WithStateRank[*helper.TestState](100))
	done := make(chan struct{})
	s.collectors.On("PruneUpToRank", uint64(100)).Run(func(args mock.Arguments) {
		close(done)
	}).Once()
	s.aggregator.OnFinalizedState(finalizedState)
	unittest.AssertClosesBefore(s.T(), done, time.Second)
}

// TestProcessInvalidState tests that processing invalid state results in exception, when given as
// an input to AddState (only expects _valid_ states per API contract).
// The exception should be propagated to the VoteAggregator's internal `ComponentManager`.
func (s *VoteAggregatorTestSuite) TestProcessInvalidState() {
	state := helper.MakeSignedProposal(helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(
		helper.WithState(
			helper.MakeState(
				helper.WithStateRank[*helper.TestState](100),
			),
		),
	)))
	processed := make(chan struct{})
	collector := mocks.NewVoteCollector[*helper.TestState, *helper.TestVote](s.T())
	collector.On("ProcessState", state).Run(func(_ mock.Arguments) {
		close(processed)
	}).Return(models.InvalidProposalError[*helper.TestState, *helper.TestVote]{})
	s.collectors.On("GetOrCreateCollector", state.State.Rank).Return(collector, true, nil).Once()

	// submit state for processing
	s.aggregator.AddState(state)
	unittest.RequireCloseBefore(s.T(), processed, 100*time.Millisecond, "should close before timeout")

	// expect a thrown error
	select {
	case err := <-s.errs:
		require.Error(s.T(), err)
		require.True(s.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err))
	case <-time.After(100 * time.Millisecond):
		s.T().Fatalf("expected error but haven't received anything")
	}
}
