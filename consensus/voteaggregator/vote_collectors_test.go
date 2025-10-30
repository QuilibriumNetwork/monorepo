package voteaggregator

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/gammazero/workerpool"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/atomic"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/mocks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

var factoryError = errors.New("factory error")

func TestVoteCollectors(t *testing.T) {
	suite.Run(t, new(VoteCollectorsTestSuite))
}

// VoteCollectorsTestSuite is a test suite for isolated testing of VoteCollectors.
// Contains helper methods and mocked state which is used to verify correct behavior of VoteCollectors.
type VoteCollectorsTestSuite struct {
	suite.Suite

	mockedCollectors map[uint64]*mocks.VoteCollector[*helper.TestState, *helper.TestVote]
	factoryMethod    NewCollectorFactoryMethod[*helper.TestState, *helper.TestVote]
	collectors       *VoteCollectors[*helper.TestState, *helper.TestVote]
	lowestLevel      uint64
	workerPool       *workerpool.WorkerPool
}

func (s *VoteCollectorsTestSuite) SetupTest() {
	s.lowestLevel = 1000
	s.mockedCollectors = make(map[uint64]*mocks.VoteCollector[*helper.TestState, *helper.TestVote])
	s.workerPool = workerpool.New(2)
	s.factoryMethod = func(rank uint64, _ consensus.Workers) (consensus.VoteCollector[*helper.TestState, *helper.TestVote], error) {
		if collector, found := s.mockedCollectors[rank]; found {
			return collector, nil
		}
		return nil, fmt.Errorf("mocked collector %v not found: %w", rank, factoryError)
	}
	s.collectors = NewVoteCollectors(helper.Logger(), s.lowestLevel, s.workerPool, s.factoryMethod)
}

func (s *VoteCollectorsTestSuite) TearDownTest() {
	s.workerPool.StopWait()
}

// prepareMockedCollector prepares a mocked collector and stores it in map, later it will be used
// to mock behavior of vote collectors.
func (s *VoteCollectorsTestSuite) prepareMockedCollector(rank uint64) *mocks.VoteCollector[*helper.TestState, *helper.TestVote] {
	collector := &mocks.VoteCollector[*helper.TestState, *helper.TestVote]{}
	collector.On("Rank").Return(rank).Maybe()
	s.mockedCollectors[rank] = collector
	return collector
}

// TestGetOrCreatorCollector_RankLowerThanLowest tests a scenario where caller tries to create a collector with rank
// lower than already pruned one. This should result in sentinel error `BelowPrunedThresholdError`
func (s *VoteCollectorsTestSuite) TestGetOrCreatorCollector_RankLowerThanLowest() {
	collector, created, err := s.collectors.GetOrCreateCollector(s.lowestLevel - 10)
	require.Nil(s.T(), collector)
	require.False(s.T(), created)
	require.Error(s.T(), err)
	require.True(s.T(), models.IsBelowPrunedThresholdError(err))
}

// TestGetOrCreateCollector_ValidCollector tests a happy path scenario where we try first to create and then retrieve cached collector.
func (s *VoteCollectorsTestSuite) TestGetOrCreateCollector_ValidCollector() {
	rank := s.lowestLevel + 10
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
func (s *VoteCollectorsTestSuite) TestGetOrCreateCollector_FactoryError() {
	// creating collector without calling prepareMockedCollector will yield factoryError.
	collector, created, err := s.collectors.GetOrCreateCollector(s.lowestLevel + 10)
	require.Nil(s.T(), collector)
	require.False(s.T(), created)
	require.ErrorIs(s.T(), err, factoryError)
}

// TestGetOrCreateCollectors_ConcurrentAccess tests that concurrently accessing of GetOrCreateCollector creates
// only one collector and all other instances are retrieved from cache.
func (s *VoteCollectorsTestSuite) TestGetOrCreateCollectors_ConcurrentAccess() {
	createdTimes := atomic.NewUint64(0)
	rank := s.lowestLevel + 10
	s.prepareMockedCollector(rank)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			_, created, err := s.collectors.GetOrCreateCollector(rank)
			require.NoError(s.T(), err)
			if created {
				createdTimes.Add(1)
			}
			wg.Done()
		}()
	}

	wg.Wait()
	require.Equal(s.T(), uint64(1), createdTimes.Load())
}

// TestPruneUpToRank tests pruning removes item below pruning height and leaves unmodified other items.
func (s *VoteCollectorsTestSuite) TestPruneUpToRank() {
	numberOfCollectors := uint64(10)
	prunedRanks := make([]uint64, 0)
	for i := uint64(0); i < numberOfCollectors; i++ {
		rank := s.lowestLevel + i
		s.prepareMockedCollector(rank)
		_, _, err := s.collectors.GetOrCreateCollector(rank)
		require.NoError(s.T(), err)
		prunedRanks = append(prunedRanks, rank)
	}

	pruningHeight := s.lowestLevel + numberOfCollectors

	expectedCollectors := make([]consensus.VoteCollector[*helper.TestState, *helper.TestVote], 0)
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
