package timeoutaggregator

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/gammazero/workerpool"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/atomic"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/mocks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

var factoryError = errors.New("factory error")

func TestTimeoutCollectors(t *testing.T) {
	suite.Run(t, new(TimeoutCollectorsTestSuite))
}

// TimeoutCollectorsTestSuite is a test suite for isolated testing of TimeoutCollectors.
// Contains helper methods and mocked state which is used to verify correct behavior of TimeoutCollectors.
type TimeoutCollectorsTestSuite struct {
	suite.Suite

	mockedCollectors map[uint64]*mocks.TimeoutCollector[*helper.TestVote]
	factoryMethod    *mocks.TimeoutCollectorFactory[*helper.TestVote]
	collectors       *TimeoutCollectors[*helper.TestVote]
	lowestRank       uint64
	workerPool       *workerpool.WorkerPool
}

func (s *TimeoutCollectorsTestSuite) SetupTest() {
	s.lowestRank = 1000
	s.mockedCollectors = make(map[uint64]*mocks.TimeoutCollector[*helper.TestVote])
	s.workerPool = workerpool.New(2)
	s.factoryMethod = mocks.NewTimeoutCollectorFactory[*helper.TestVote](s.T())
	s.factoryMethod.On("Create", mock.Anything).Return(func(rank uint64) consensus.TimeoutCollector[*helper.TestVote] {
		if collector, found := s.mockedCollectors[rank]; found {
			return collector
		}
		return nil
	}, func(rank uint64) error {
		if _, found := s.mockedCollectors[rank]; found {
			return nil
		}
		return fmt.Errorf("mocked collector %v not found: %w", rank, factoryError)
	}).Maybe()
	s.collectors = NewTimeoutCollectors(helper.Logger(), s.lowestRank, s.factoryMethod)
}

func (s *TimeoutCollectorsTestSuite) TearDownTest() {
	s.workerPool.StopWait()
}

// prepareMockedCollector prepares a mocked collector and stores it in map, later it will be used
// to mock behavior of timeout collectors.
func (s *TimeoutCollectorsTestSuite) prepareMockedCollector(rank uint64) *mocks.TimeoutCollector[*helper.TestVote] {
	collector := mocks.NewTimeoutCollector[*helper.TestVote](s.T())
	collector.On("Rank").Return(rank).Maybe()
	s.mockedCollectors[rank] = collector
	return collector
}

// TestGetOrCreateCollector_RankLowerThanLowest tests a scenario where caller tries to create a collector with rank
// lower than already pruned one. This should result in sentinel error `BelowPrunedThresholdError`
func (s *TimeoutCollectorsTestSuite) TestGetOrCreateCollector_RankLowerThanLowest() {
	collector, created, err := s.collectors.GetOrCreateCollector(s.lowestRank - 10)
	require.Nil(s.T(), collector)
	require.False(s.T(), created)
	require.Error(s.T(), err)
	require.True(s.T(), models.IsBelowPrunedThresholdError(err))
}

// TestGetOrCreateCollector_UnknownRank tests a scenario where caller tries to create a collector with rank referring rank
// that we don't know about. This should result in sentinel error `
func (s *TimeoutCollectorsTestSuite) TestGetOrCreateCollector_UnknownRank() {
	*s.factoryMethod = *mocks.NewTimeoutCollectorFactory[*helper.TestVote](s.T())
	s.factoryMethod.On("Create", mock.Anything).Return(nil, models.ErrRankUnknown)
	collector, created, err := s.collectors.GetOrCreateCollector(s.lowestRank + 100)
	require.Nil(s.T(), collector)
	require.False(s.T(), created)
	require.ErrorIs(s.T(), err, models.ErrRankUnknown)
}

// TestGetOrCreateCollector_ValidCollector tests a happy path scenario where we try first to create and then retrieve cached collector.
func (s *TimeoutCollectorsTestSuite) TestGetOrCreateCollector_ValidCollector() {
	rank := s.lowestRank + 10
	s.prepareMockedCollector(rank)
	collector, created, err := s.collectors.GetOrCreateCollector(rank)
	require.NoError(s.T(), err)
	require.True(s.T(), created)
	require.Equal(s.T(), rank, collector.Rank())

	cached, cachedCreated, err := s.collectors.GetOrCreateCollector(rank)
	require.NoError(s.T(), err)
	require.False(s.T(), cachedCreated)
	require.Equal(s.T(), collector, cached)
}

// TestGetOrCreateCollector_FactoryError tests that error from factory method is propagated to caller.
func (s *TimeoutCollectorsTestSuite) TestGetOrCreateCollector_FactoryError() {
	// creating collector without calling prepareMockedCollector will yield factoryError.
	collector, created, err := s.collectors.GetOrCreateCollector(s.lowestRank + 10)
	require.Nil(s.T(), collector)
	require.False(s.T(), created)
	require.ErrorIs(s.T(), err, factoryError)
}

// TestGetOrCreateCollectors_ConcurrentAccess tests that concurrently accessing of GetOrCreateCollector creates
// only one collector and all other instances are retrieved from cache.
func (s *TimeoutCollectorsTestSuite) TestGetOrCreateCollectors_ConcurrentAccess() {
	createdTimes := atomic.NewUint64(0)
	rank := s.lowestRank + 10
	s.prepareMockedCollector(rank)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, created, err := s.collectors.GetOrCreateCollector(rank)
			require.NoError(s.T(), err)
			if created {
				createdTimes.Add(1)
			}
		}()
	}
	wg.Wait()

	require.Equal(s.T(), uint64(1), createdTimes.Load())
}

// TestPruneUpToRank tests pruning removes item below pruning height and leaves unmodified other items.
func (s *TimeoutCollectorsTestSuite) TestPruneUpToRank() {
	numberOfCollectors := uint64(10)
	prunedRanks := make([]uint64, 0)
	for i := uint64(0); i < numberOfCollectors; i++ {
		rank := s.lowestRank + i
		s.prepareMockedCollector(rank)
		_, _, err := s.collectors.GetOrCreateCollector(rank)
		require.NoError(s.T(), err)
		prunedRanks = append(prunedRanks, rank)
	}

	pruningHeight := s.lowestRank + numberOfCollectors

	expectedCollectors := make([]consensus.TimeoutCollector[*helper.TestVote], 0)
	for i := uint64(0); i < numberOfCollectors; i++ {
		rank := pruningHeight + i
		s.prepareMockedCollector(rank)
		collector, _, err := s.collectors.GetOrCreateCollector(rank)
		require.NoError(s.T(), err)
		expectedCollectors = append(expectedCollectors, collector)
	}

	// after this operation collectors below pruning height should be pruned and everything higher
	// should be left unmodified
	s.collectors.PruneUpToRank(pruningHeight)

	for _, prunedRank := range prunedRanks {
		_, _, err := s.collectors.GetOrCreateCollector(prunedRank)
		require.Error(s.T(), err)
		require.True(s.T(), models.IsBelowPrunedThresholdError(err))
	}

	for _, collector := range expectedCollectors {
		cached, _, _ := s.collectors.GetOrCreateCollector(collector.Rank())
		require.Equal(s.T(), collector, cached)
	}
}
