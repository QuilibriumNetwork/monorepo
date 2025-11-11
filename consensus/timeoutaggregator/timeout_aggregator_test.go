package timeoutaggregator

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/atomic"

	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/mocks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle/unittest"
)

func TestTimeoutAggregator(t *testing.T) {
	suite.Run(t, new(TimeoutAggregatorTestSuite))
}

// TimeoutAggregatorTestSuite is a test suite for isolated testing of TimeoutAggregator.
// Contains mocked state which is used to verify correct behavior of TimeoutAggregator.
// Automatically starts and stops module.Startable in SetupTest and TearDownTest respectively.
type TimeoutAggregatorTestSuite struct {
	suite.Suite

	lowestRetainedRank uint64
	highestKnownRank   uint64
	aggregator         *TimeoutAggregator[*helper.TestVote]
	collectors         *mocks.TimeoutCollectors[*helper.TestVote]
	stopAggregator     context.CancelFunc
}

func (s *TimeoutAggregatorTestSuite) SetupTest() {
	var err error
	s.collectors = mocks.NewTimeoutCollectors[*helper.TestVote](s.T())

	s.lowestRetainedRank = 100

	s.aggregator, err = NewTimeoutAggregator(
		helper.Logger(),
		s.lowestRetainedRank,
		s.collectors,
	)
	require.NoError(s.T(), err)

	ctx, cancel := context.WithCancel(context.Background())
	signalerCtx := unittest.NewMockSignalerContext(s.T(), ctx)
	s.stopAggregator = cancel
	s.aggregator.Start(signalerCtx)
	unittest.RequireCloseBefore(s.T(), s.aggregator.Ready(), 100*time.Millisecond, "should close before timeout")
}

func (s *TimeoutAggregatorTestSuite) TearDownTest() {
	s.stopAggregator()
	unittest.RequireCloseBefore(s.T(), s.aggregator.Done(), time.Second, "should close before timeout")
}

// TestAddTimeout_HappyPath tests a happy path when multiple threads are adding timeouts for processing
// Eventually every timeout has to be processed by TimeoutCollector
func (s *TimeoutAggregatorTestSuite) TestAddTimeout_HappyPath() {
	timeoutsCount := 20
	collector := mocks.NewTimeoutCollector[*helper.TestVote](s.T())
	callCount := atomic.NewUint64(0)
	collector.On("AddTimeout", mock.Anything).Run(func(mock.Arguments) {
		callCount.Add(1)
	}).Return(nil).Times(timeoutsCount)
	s.collectors.On("GetOrCreateCollector", s.lowestRetainedRank).Return(collector, true, nil).Times(timeoutsCount)

	var start sync.WaitGroup
	start.Add(timeoutsCount)
	for i := 0; i < timeoutsCount; i++ {
		go func() {
			timeout := helper.TimeoutStateFixture[*helper.TestVote](helper.WithTimeoutStateRank[*helper.TestVote](s.lowestRetainedRank), helper.WithTimeoutVote(&helper.TestVote{Rank: s.lowestRetainedRank, ID: helper.MakeIdentity()}))

			start.Done()
			// Wait for last worker routine to signal ready. Then,
			// feed all timeouts into cache
			start.Wait()

			s.aggregator.AddTimeout(timeout)
		}()
	}

	start.Wait()

	require.Eventually(s.T(), func() bool {
		return callCount.Load() == uint64(timeoutsCount)
	}, time.Second, time.Millisecond*20)
}

// TestAddTimeout_RankUnknown tests if timeout states targeting unknown rank should be ignored
func (s *TimeoutAggregatorTestSuite) TestAddTimeout_RankUnknown() {
	timeout := helper.TimeoutStateFixture(helper.WithTimeoutStateRank[*helper.TestVote](s.lowestRetainedRank), helper.WithTimeoutVote(&helper.TestVote{Rank: s.lowestRetainedRank, ID: helper.MakeIdentity()}))
	*s.collectors = *mocks.NewTimeoutCollectors[*helper.TestVote](s.T())
	done := make(chan struct{})
	s.collectors.On("GetOrCreateCollector", timeout.Rank).Return(nil, false, models.ErrRankUnknown).Run(func(args mock.Arguments) {
		close(done)
	}).Once()
	s.aggregator.AddTimeout(timeout)
	unittest.AssertClosesBefore(s.T(), done, time.Second)
}

// TestPruneUpToRank tests that pruning removes collectors lower that retained rank
func (s *TimeoutAggregatorTestSuite) TestPruneUpToRank() {
	s.collectors.On("PruneUpToRank", s.lowestRetainedRank+1).Once()
	s.aggregator.PruneUpToRank(s.lowestRetainedRank + 1)
}

// TestOnQuorumCertificateTriggeredRankChange tests if entering rank event gets processed when send through `TimeoutAggregator`.
// Tests the whole processing pipeline.
func (s *TimeoutAggregatorTestSuite) TestOnQuorumCertificateTriggeredRankChange() {
	done := make(chan struct{})
	s.collectors.On("PruneUpToRank", s.lowestRetainedRank+1).Run(func(args mock.Arguments) {
		close(done)
	}).Once()
	qc := helper.MakeQC(helper.WithQCRank(s.lowestRetainedRank))
	s.aggregator.OnRankChange(qc.GetRank(), qc.GetRank()+1)
	unittest.AssertClosesBefore(s.T(), done, time.Second)
}

// TestOnTimeoutCertificateTriggeredRankChange tests if entering rank event gets processed when send through `TimeoutAggregator`.
// Tests the whole processing pipeline.
func (s *TimeoutAggregatorTestSuite) TestOnTimeoutCertificateTriggeredRankChange() {
	rank := s.lowestRetainedRank + 1
	done := make(chan struct{})
	s.collectors.On("PruneUpToRank", rank).Run(func(args mock.Arguments) {
		close(done)
	}).Once()
	tc := helper.MakeTC(helper.WithTCRank(s.lowestRetainedRank))
	s.aggregator.OnRankChange(tc.GetRank(), tc.GetRank()+1)
	unittest.AssertClosesBefore(s.T(), done, time.Second)
}
