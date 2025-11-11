package timeoutcollector

import (
	"errors"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/mocks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

func TestTimeoutCollector(t *testing.T) {
	suite.Run(t, new(TimeoutCollectorTestSuite))
}

// TimeoutCollectorTestSuite is a test suite for testing TimeoutCollector. It stores mocked
// state internally for testing behavior.
type TimeoutCollectorTestSuite struct {
	suite.Suite

	rank      uint64
	notifier  *mocks.TimeoutAggregationConsumer[*helper.TestVote]
	processor *mocks.TimeoutProcessor[*helper.TestVote]
	collector *TimeoutCollector[*helper.TestVote]
}

func (s *TimeoutCollectorTestSuite) SetupTest() {
	s.rank = 1000
	s.notifier = mocks.NewTimeoutAggregationConsumer[*helper.TestVote](s.T())
	s.processor = mocks.NewTimeoutProcessor[*helper.TestVote](s.T())

	s.notifier.On("OnNewQuorumCertificateDiscovered", mock.Anything).Maybe()
	s.notifier.On("OnNewTimeoutCertificateDiscovered", mock.Anything).Maybe()

	s.collector = NewTimeoutCollector(helper.Logger(), s.rank, s.notifier, s.processor)
}

// TestRank tests that `Rank` returns the same value that was passed in constructor
func (s *TimeoutCollectorTestSuite) TestRank() {
	require.Equal(s.T(), s.rank, s.collector.Rank())
}

// TestAddTimeout_HappyPath tests that process in happy path executed by multiple workers deliver expected results
// all operations should be successful, no errors expected
func (s *TimeoutCollectorTestSuite) TestAddTimeout_HappyPath() {
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			timeout := helper.TimeoutStateFixture(
				helper.WithTimeoutStateRank[*helper.TestVote](s.rank),
				helper.WithTimeoutVote[*helper.TestVote](&helper.TestVote{
					ID:   helper.MakeIdentity(),
					Rank: s.rank,
				}),
			)
			s.notifier.On("OnTimeoutProcessed", timeout).Once()
			s.processor.On("Process", timeout).Return(nil).Once()
			err := s.collector.AddTimeout(timeout)
			require.NoError(s.T(), err)
		}()
	}

	s.processor.AssertExpectations(s.T())
}

// TestAddTimeout_DoubleTimeout tests that submitting two different timeouts for same rank ends with reporting
// double timeout to notifier which can be slashed later.
func (s *TimeoutCollectorTestSuite) TestAddTimeout_DoubleTimeout() {
	timeout := helper.TimeoutStateFixture(
		helper.WithTimeoutStateRank[*helper.TestVote](s.rank),
		helper.WithTimeoutVote[*helper.TestVote](&helper.TestVote{
			ID:   "1",
			Rank: s.rank,
		}),
	)
	s.notifier.On("OnTimeoutProcessed", timeout).Once()
	s.processor.On("Process", timeout).Return(nil).Once()
	err := s.collector.AddTimeout(timeout)
	require.NoError(s.T(), err)

	otherTimeout := helper.TimeoutStateFixture(
		helper.WithTimeoutStateRank[*helper.TestVote](s.rank),
		helper.WithTimeoutVote[*helper.TestVote](&helper.TestVote{
			ID:   "1",
			Rank: s.rank,
		}),
	)

	s.notifier.On("OnDoubleTimeoutDetected", timeout, otherTimeout).Once()

	err = s.collector.AddTimeout(otherTimeout)
	require.NoError(s.T(), err)
	s.notifier.AssertExpectations(s.T())
	s.processor.AssertNumberOfCalls(s.T(), "Process", 1)
}

// TestAddTimeout_RepeatedTimeout checks that repeated timeouts are silently dropped without any errors.
func (s *TimeoutCollectorTestSuite) TestAddTimeout_RepeatedTimeout() {
	timeout := helper.TimeoutStateFixture(
		helper.WithTimeoutStateRank[*helper.TestVote](s.rank),
		helper.WithTimeoutVote[*helper.TestVote](&helper.TestVote{
			ID:   helper.MakeIdentity(),
			Rank: s.rank,
		}),
	)
	s.notifier.On("OnTimeoutProcessed", timeout).Once()
	s.processor.On("Process", timeout).Return(nil).Once()
	err := s.collector.AddTimeout(timeout)
	require.NoError(s.T(), err)
	err = s.collector.AddTimeout(timeout)
	require.NoError(s.T(), err)
	s.processor.AssertNumberOfCalls(s.T(), "Process", 1)
}

// TestAddTimeout_TimeoutCacheException tests that submitting timeout state for rank which is not designated for this
// collector results in ErrTimeoutForIncompatibleRank.
func (s *TimeoutCollectorTestSuite) TestAddTimeout_TimeoutCacheException() {
	// incompatible rank is an exception and not handled by timeout collector
	timeout := helper.TimeoutStateFixture(
		helper.WithTimeoutStateRank[*helper.TestVote](s.rank+1),
		helper.WithTimeoutVote[*helper.TestVote](&helper.TestVote{
			ID:   helper.MakeIdentity(),
			Rank: s.rank + 1,
		}),
	)
	err := s.collector.AddTimeout(timeout)
	require.ErrorIs(s.T(), err, ErrTimeoutForIncompatibleRank)
	s.processor.AssertNotCalled(s.T(), "Process")
}

// TestAddTimeout_InvalidTimeout tests that sentinel errors while processing timeouts are correctly handled and reported
// to notifier, but exceptions are propagated to caller.
func (s *TimeoutCollectorTestSuite) TestAddTimeout_InvalidTimeout() {
	s.Run("invalid-timeout", func() {
		timeout := helper.TimeoutStateFixture(
			helper.WithTimeoutStateRank[*helper.TestVote](s.rank),
			helper.WithTimeoutVote[*helper.TestVote](&helper.TestVote{
				ID:   helper.MakeIdentity(),
				Rank: s.rank,
			}),
		)
		s.processor.On("Process", timeout).Return(models.NewInvalidTimeoutErrorf(timeout, "")).Once()
		s.notifier.On("OnInvalidTimeoutDetected", mock.Anything).Run(func(args mock.Arguments) {
			invalidTimeoutErr := args.Get(0).(models.InvalidTimeoutError[*helper.TestVote])
			require.Equal(s.T(), timeout, invalidTimeoutErr.Timeout)
		}).Once()
		err := s.collector.AddTimeout(timeout)
		require.NoError(s.T(), err)

		time.Sleep(100 * time.Millisecond)
		s.notifier.AssertCalled(s.T(), "OnInvalidTimeoutDetected", mock.Anything)
	})
	s.Run("process-exception", func() {
		exception := errors.New("invalid-signature")
		timeout := helper.TimeoutStateFixture(
			helper.WithTimeoutStateRank[*helper.TestVote](s.rank),
			helper.WithTimeoutVote[*helper.TestVote](&helper.TestVote{
				ID:   helper.MakeIdentity(),
				Rank: s.rank,
			}),
		)
		s.processor.On("Process", timeout).Return(exception).Once()
		err := s.collector.AddTimeout(timeout)
		require.ErrorIs(s.T(), err, exception)
	})
}

// TestAddTimeout_TONotifications tests that TimeoutCollector in happy path reports the newest discovered QC and TC
func (s *TimeoutCollectorTestSuite) TestAddTimeout_TONotifications() {
	qcCount := 100
	// generate QCs with increasing rank numbers
	if s.rank < uint64(qcCount) {
		s.T().Fatal("invalid test configuration")
	}

	*s.notifier = *mocks.NewTimeoutAggregationConsumer[*helper.TestVote](s.T())

	var highestReportedQC models.QuorumCertificate
	s.notifier.On("OnNewQuorumCertificateDiscovered", mock.Anything).Run(func(args mock.Arguments) {
		qc := args.Get(0).(models.QuorumCertificate)
		if highestReportedQC == nil || highestReportedQC.GetRank() < qc.GetRank() {
			highestReportedQC = qc
		}
	})

	previousRankTimeoutCert := helper.MakeTC(helper.WithTCRank(s.rank - 1))
	s.notifier.On("OnNewTimeoutCertificateDiscovered", previousRankTimeoutCert).Once()

	timeouts := make([]*models.TimeoutState[*helper.TestVote], 0, qcCount)
	for i := 0; i < qcCount; i++ {
		qc := helper.MakeQC(helper.WithQCRank(uint64(i)))
		timeout := helper.TimeoutStateFixture(func(timeout *models.TimeoutState[*helper.TestVote]) {
			timeout.Rank = s.rank
			timeout.LatestQuorumCertificate = qc
			timeout.PriorRankTimeoutCertificate = previousRankTimeoutCert
		}, helper.WithTimeoutVote(&helper.TestVote{Rank: s.rank, ID: helper.MakeIdentity()}))
		timeouts = append(timeouts, timeout)
		s.notifier.On("OnTimeoutProcessed", timeout).Once()
		s.processor.On("Process", timeout).Return(nil).Once()
	}

	expectedHighestQC := timeouts[len(timeouts)-1].LatestQuorumCertificate

	// shuffle timeouts in random order
	rand.Shuffle(len(timeouts), func(i, j int) {
		timeouts[i], timeouts[j] = timeouts[j], timeouts[i]
	})

	var wg sync.WaitGroup
	wg.Add(len(timeouts))
	for _, timeout := range timeouts {
		go func(timeout *models.TimeoutState[*helper.TestVote]) {
			defer wg.Done()
			err := s.collector.AddTimeout(timeout)
			require.NoError(s.T(), err)
		}(timeout)
	}
	wg.Wait()

	require.Equal(s.T(), expectedHighestQC, highestReportedQC)
}
