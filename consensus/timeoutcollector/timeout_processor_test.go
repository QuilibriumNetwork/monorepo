package timeoutcollector

import (
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/atomic"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/mocks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/validator"
	"source.quilibrium.com/quilibrium/monorepo/consensus/verification"
	"source.quilibrium.com/quilibrium/monorepo/consensus/votecollector"
)

func TestTimeoutProcessor(t *testing.T) {
	suite.Run(t, new(TimeoutProcessorTestSuite))
}

// TimeoutProcessorTestSuite is a test suite that holds mocked state for isolated testing of TimeoutProcessor.
type TimeoutProcessorTestSuite struct {
	suite.Suite

	participants  []models.WeightedIdentity
	signer        models.WeightedIdentity
	rank          uint64
	sigWeight     uint64
	totalWeight   atomic.Uint64
	committee     *mocks.Replicas
	validator     *mocks.Validator[*helper.TestState, *helper.TestVote]
	sigAggregator *mocks.TimeoutSignatureAggregator
	notifier      *mocks.TimeoutCollectorConsumer[*helper.TestVote]
	processor     *TimeoutProcessor[*helper.TestState, *helper.TestVote, *helper.TestPeer]
	voting        *mocks.VotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer]
}

func (s *TimeoutProcessorTestSuite) SetupTest() {
	var err error
	s.sigWeight = 1000
	s.committee = mocks.NewReplicas(s.T())
	s.validator = mocks.NewValidator[*helper.TestState, *helper.TestVote](s.T())
	s.sigAggregator = mocks.NewTimeoutSignatureAggregator(s.T())
	s.notifier = mocks.NewTimeoutCollectorConsumer[*helper.TestVote](s.T())
	s.participants = helper.WithWeightedIdentityList(11)
	s.signer = s.participants[0]
	s.rank = (uint64)(rand.Uint32() + 100)
	s.totalWeight = *atomic.NewUint64(0)
	s.voting = mocks.NewVotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer](s.T())

	s.committee.On("QuorumThresholdForRank", mock.Anything).Return(uint64(8000), nil).Maybe()
	s.committee.On("TimeoutThresholdForRank", mock.Anything).Return(uint64(8000), nil).Maybe()
	s.committee.On("IdentityByRank", mock.Anything, mock.Anything).Return(s.signer, nil).Maybe()
	s.sigAggregator.On("Rank").Return(s.rank).Maybe()
	s.sigAggregator.On("VerifyAndAdd", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		s.totalWeight.Add(s.sigWeight)
	}).Return(func(signerID models.Identity, sig []byte, newestQCRank uint64) uint64 {
		return s.totalWeight.Load()
	}, func(signerID models.Identity, sig []byte, newestQCRank uint64) error {
		return nil
	}).Maybe()
	s.sigAggregator.On("TotalWeight").Return(func() uint64 {
		return s.totalWeight.Load()
	}).Maybe()

	s.processor, err = NewTimeoutProcessor[*helper.TestState, *helper.TestVote, *helper.TestPeer](
		helper.Logger(),
		s.committee,
		s.validator,
		s.sigAggregator,
		s.notifier,
		s.voting,
	)
	require.NoError(s.T(), err)
}

// TimeoutLastRankSuccessfulFixture creates a valid timeout if last rank has ended with QC.
func (s *TimeoutProcessorTestSuite) TimeoutLastRankSuccessfulFixture(opts ...func(*models.TimeoutState[*helper.TestVote])) *models.TimeoutState[*helper.TestVote] {
	timeout := helper.TimeoutStateFixture(
		helper.WithTimeoutStateRank[*helper.TestVote](s.rank),
		helper.WithTimeoutNewestQC[*helper.TestVote](helper.MakeQC(helper.WithQCRank(s.rank-1))),
		helper.WithTimeoutVote(&helper.TestVote{ID: helper.MakeIdentity(), Rank: s.rank}),
		helper.WithTimeoutPreviousRankTimeoutCertificate[*helper.TestVote](nil),
	)

	for _, opt := range opts {
		opt(timeout)
	}

	return timeout
}

// TimeoutLastRankFailedFixture creates a valid timeout if last rank has ended with TC.
func (s *TimeoutProcessorTestSuite) TimeoutLastRankFailedFixture(opts ...func(*models.TimeoutState[*helper.TestVote])) *models.TimeoutState[*helper.TestVote] {
	newestQC := helper.MakeQC(helper.WithQCRank(s.rank - 10))
	timeout := helper.TimeoutStateFixture(
		helper.WithTimeoutStateRank[*helper.TestVote](s.rank),
		helper.WithTimeoutNewestQC[*helper.TestVote](newestQC),
		helper.WithTimeoutVote(&helper.TestVote{ID: helper.MakeIdentity(), Rank: s.rank}),
		helper.WithTimeoutPreviousRankTimeoutCertificate[*helper.TestVote](helper.MakeTC(
			helper.WithTCRank(s.rank-1),
			helper.WithTCNewestQC(helper.MakeQC(helper.WithQCRank(newestQC.GetRank()))))),
	)

	for _, opt := range opts {
		opt(timeout)
	}

	return timeout
}

// TestProcess_TimeoutNotForRank tests that TimeoutProcessor accepts only timeouts for the rank it was initialized with
// We expect dedicated sentinel errors for timeouts for different ranks (`ErrTimeoutForIncompatibleRank`).
func (s *TimeoutProcessorTestSuite) TestProcess_TimeoutNotForRank() {
	err := s.processor.Process(s.TimeoutLastRankSuccessfulFixture(func(t *models.TimeoutState[*helper.TestVote]) {
		t.Rank++
	}))
	require.ErrorIs(s.T(), err, ErrTimeoutForIncompatibleRank)
	require.False(s.T(), models.IsInvalidTimeoutError[*helper.TestVote](err))

	s.sigAggregator.AssertNotCalled(s.T(), "Verify")
}

// TestProcess_TimeoutWithoutQC tests that TimeoutProcessor fails with models.InvalidTimeoutError if
// timeout doesn't contain QC.
func (s *TimeoutProcessorTestSuite) TestProcess_TimeoutWithoutQC() {
	err := s.processor.Process(s.TimeoutLastRankSuccessfulFixture(func(t *models.TimeoutState[*helper.TestVote]) {
		t.LatestQuorumCertificate = nil
	}))
	require.True(s.T(), models.IsInvalidTimeoutError[*helper.TestVote](err))
}

// TestProcess_TimeoutNewerHighestQC tests that TimeoutProcessor fails with models.InvalidTimeoutError if
// timeout contains a QC with QC.Rank > timeout.Rank, QC can be only with lower rank than timeout.
func (s *TimeoutProcessorTestSuite) TestProcess_TimeoutNewerHighestQC() {
	s.Run("t.Rank == t.LatestQuorumCertificate.(*helper.TestQuorumCertificate).Rank", func() {
		err := s.processor.Process(s.TimeoutLastRankSuccessfulFixture(func(t *models.TimeoutState[*helper.TestVote]) {
			t.LatestQuorumCertificate.(*helper.TestQuorumCertificate).Rank = t.Rank
		}))
		require.True(s.T(), models.IsInvalidTimeoutError[*helper.TestVote](err))
	})
	s.Run("t.Rank < t.LatestQuorumCertificate.(*helper.TestQuorumCertificate).Rank", func() {
		err := s.processor.Process(s.TimeoutLastRankSuccessfulFixture(func(t *models.TimeoutState[*helper.TestVote]) {
			t.LatestQuorumCertificate.(*helper.TestQuorumCertificate).Rank = t.Rank + 1
		}))
		require.True(s.T(), models.IsInvalidTimeoutError[*helper.TestVote](err))
	})
}

// TestProcess_PreviousRankTimeoutCertificateWrongRank tests that TimeoutProcessor fails with models.InvalidTimeoutError if
// timeout contains a proof that sender legitimately entered timeout.Rank but it has wrong rank meaning he used TC from previous rounds.
func (s *TimeoutProcessorTestSuite) TestProcess_PreviousRankTimeoutCertificateWrongRank() {
	// if TC is included it must have timeout.Rank == timeout.PriorRankTimeoutCertificate.(*helper.TestTimeoutCertificate).Rank+1
	err := s.processor.Process(s.TimeoutLastRankFailedFixture(func(t *models.TimeoutState[*helper.TestVote]) {
		t.PriorRankTimeoutCertificate.(*helper.TestTimeoutCertificate).Rank = t.Rank - 10
	}))
	require.True(s.T(), models.IsInvalidTimeoutError[*helper.TestVote](err))
}

// TestProcess_LastRankHighestQCInvalidRank tests that TimeoutProcessor fails with models.InvalidTimeoutError if
// timeout contains a proof that sender legitimately entered timeout.Rank but included HighestQC has older rank
// than QC included in TC. For honest nodes this shouldn't happen.
func (s *TimeoutProcessorTestSuite) TestProcess_LastRankHighestQCInvalidRank() {
	err := s.processor.Process(s.TimeoutLastRankFailedFixture(func(t *models.TimeoutState[*helper.TestVote]) {
		t.PriorRankTimeoutCertificate.(*helper.TestTimeoutCertificate).LatestQuorumCert.(*helper.TestQuorumCertificate).Rank = t.LatestQuorumCertificate.(*helper.TestQuorumCertificate).Rank + 1 // TC contains newer QC than Timeout State
	}))
	require.True(s.T(), models.IsInvalidTimeoutError[*helper.TestVote](err))
}

// TestProcess_PreviousRankTimeoutCertificateRequiredButNotPresent tests that TimeoutProcessor fails with models.InvalidTimeoutError if
// timeout must contain a proof that sender legitimately entered timeout.Rank but doesn't have it.
func (s *TimeoutProcessorTestSuite) TestProcess_PreviousRankTimeoutCertificateRequiredButNotPresent() {
	// if last rank is not successful(timeout.Rank != timeout.HighestQC.Rank+1) then this
	// timeout must contain valid timeout.PriorRankTimeoutCertificate
	err := s.processor.Process(s.TimeoutLastRankFailedFixture(func(t *models.TimeoutState[*helper.TestVote]) {
		t.PriorRankTimeoutCertificate = nil
	}))
	require.True(s.T(), models.IsInvalidTimeoutError[*helper.TestVote](err))
}

// TestProcess_IncludedQCInvalid tests that TimeoutProcessor correctly handles validation errors if
// timeout is well-formed but included QC is invalid
func (s *TimeoutProcessorTestSuite) TestProcess_IncludedQCInvalid() {
	timeout := s.TimeoutLastRankSuccessfulFixture()

	s.Run("invalid-qc-sentinel", func() {
		*s.validator = *mocks.NewValidator[*helper.TestState, *helper.TestVote](s.T())
		s.validator.On("ValidateQuorumCertificate", timeout.LatestQuorumCertificate).Return(models.InvalidQuorumCertificateError{}).Once()

		err := s.processor.Process(timeout)
		require.True(s.T(), models.IsInvalidTimeoutError[*helper.TestVote](err))
		require.True(s.T(), models.IsInvalidQuorumCertificateError(err))
	})
	s.Run("invalid-qc-exception", func() {
		exception := errors.New("validate-qc-failed")
		*s.validator = *mocks.NewValidator[*helper.TestState, *helper.TestVote](s.T())
		s.validator.On("ValidateQuorumCertificate", timeout.LatestQuorumCertificate).Return(exception).Once()

		err := s.processor.Process(timeout)
		require.ErrorIs(s.T(), err, exception)
		require.False(s.T(), models.IsInvalidTimeoutError[*helper.TestVote](err))
	})
	s.Run("invalid-qc-err-rank-for-unknown-rank", func() {
		*s.validator = *mocks.NewValidator[*helper.TestState, *helper.TestVote](s.T())
		s.validator.On("ValidateQuorumCertificate", timeout.LatestQuorumCertificate).Return(models.ErrRankUnknown).Once()

		err := s.processor.Process(timeout)
		require.False(s.T(), models.IsInvalidTimeoutError[*helper.TestVote](err))
		require.NotErrorIs(s.T(), err, models.ErrRankUnknown)
	})
}

// TestProcess_IncludedTCInvalid tests that TimeoutProcessor correctly handles validation errors if
// timeout is well-formed but included TC is invalid
func (s *TimeoutProcessorTestSuite) TestProcess_IncludedTCInvalid() {
	timeout := s.TimeoutLastRankFailedFixture()

	s.Run("invalid-tc-sentinel", func() {
		*s.validator = *mocks.NewValidator[*helper.TestState, *helper.TestVote](s.T())
		s.validator.On("ValidateQuorumCertificate", timeout.LatestQuorumCertificate).Return(nil)
		s.validator.On("ValidateTimeoutCertificate", timeout.PriorRankTimeoutCertificate).Return(models.InvalidTimeoutCertificateError{})

		err := s.processor.Process(timeout)
		require.True(s.T(), models.IsInvalidTimeoutError[*helper.TestVote](err))
		require.True(s.T(), models.IsInvalidTimeoutCertificateError(err))
	})
	s.Run("invalid-tc-exception", func() {
		exception := errors.New("validate-tc-failed")
		*s.validator = *mocks.NewValidator[*helper.TestState, *helper.TestVote](s.T())
		s.validator.On("ValidateQuorumCertificate", timeout.LatestQuorumCertificate).Return(nil)
		s.validator.On("ValidateTimeoutCertificate", timeout.PriorRankTimeoutCertificate).Return(exception).Once()

		err := s.processor.Process(timeout)
		require.ErrorIs(s.T(), err, exception)
		require.False(s.T(), models.IsInvalidTimeoutError[*helper.TestVote](err))
	})
	s.Run("invalid-tc-err-rank-for-unknown-rank", func() {
		*s.validator = *mocks.NewValidator[*helper.TestState, *helper.TestVote](s.T())
		s.validator.On("ValidateQuorumCertificate", timeout.LatestQuorumCertificate).Return(nil)
		s.validator.On("ValidateTimeoutCertificate", timeout.PriorRankTimeoutCertificate).Return(models.ErrRankUnknown).Once()

		err := s.processor.Process(timeout)
		require.False(s.T(), models.IsInvalidTimeoutError[*helper.TestVote](err))
		require.NotErrorIs(s.T(), err, models.ErrRankUnknown)
	})
}

// TestProcess_ValidTimeout tests that processing a valid timeout succeeds without error
func (s *TimeoutProcessorTestSuite) TestProcess_ValidTimeout() {
	s.Run("happy-path", func() {
		timeout := s.TimeoutLastRankSuccessfulFixture()
		s.validator.On("ValidateQuorumCertificate", timeout.LatestQuorumCertificate).Return(nil).Once()
		err := s.processor.Process(timeout)
		require.NoError(s.T(), err)
		s.sigAggregator.AssertCalled(s.T(), "VerifyAndAdd", (*timeout.Vote).ID, (*timeout.Vote).Signature, timeout.LatestQuorumCertificate.(*helper.TestQuorumCertificate).Rank)
	})
	s.Run("recovery-path", func() {
		timeout := s.TimeoutLastRankFailedFixture()
		s.validator.On("ValidateQuorumCertificate", timeout.LatestQuorumCertificate).Return(nil).Once()
		s.validator.On("ValidateTimeoutCertificate", timeout.PriorRankTimeoutCertificate).Return(nil).Once()
		err := s.processor.Process(timeout)
		require.NoError(s.T(), err)
		s.sigAggregator.AssertCalled(s.T(), "VerifyAndAdd", (*timeout.Vote).ID, (*timeout.Vote).Signature, timeout.LatestQuorumCertificate.(*helper.TestQuorumCertificate).Rank)
	})
}

// TestProcess_VerifyAndAddFailed tests different scenarios when TimeoutSignatureAggregator fails with error.
// We check all sentinel errors and exceptions in this scenario.
func (s *TimeoutProcessorTestSuite) TestProcess_VerifyAndAddFailed() {
	timeout := s.TimeoutLastRankSuccessfulFixture()
	s.validator.On("ValidateQuorumCertificate", timeout.LatestQuorumCertificate).Return(nil)
	s.Run("invalid-signer", func() {
		*s.sigAggregator = *mocks.NewTimeoutSignatureAggregator(s.T())
		s.sigAggregator.On("VerifyAndAdd", mock.Anything, mock.Anything, mock.Anything).
			Return(uint64(0), models.NewInvalidSignerError(fmt.Errorf(""))).Once()
		err := s.processor.Process(timeout)
		require.True(s.T(), models.IsInvalidTimeoutError[*helper.TestVote](err))
		require.True(s.T(), models.IsInvalidSignerError(err))
	})
	s.Run("invalid-signature", func() {
		*s.sigAggregator = *mocks.NewTimeoutSignatureAggregator(s.T())
		s.sigAggregator.On("VerifyAndAdd", mock.Anything, mock.Anything, mock.Anything).
			Return(uint64(0), models.ErrInvalidSignature).Once()
		err := s.processor.Process(timeout)
		require.True(s.T(), models.IsInvalidTimeoutError[*helper.TestVote](err))
		require.ErrorIs(s.T(), err, models.ErrInvalidSignature)
	})
	s.Run("duplicated-signer", func() {
		*s.sigAggregator = *mocks.NewTimeoutSignatureAggregator(s.T())
		s.sigAggregator.On("VerifyAndAdd", mock.Anything, mock.Anything, mock.Anything).
			Return(uint64(0), models.NewDuplicatedSignerErrorf("")).Once()
		err := s.processor.Process(timeout)
		require.True(s.T(), models.IsDuplicatedSignerError(err))
		// this shouldn't be wrapped in invalid timeout
		require.False(s.T(), models.IsInvalidTimeoutError[*helper.TestVote](err))
	})
	s.Run("verify-exception", func() {
		*s.sigAggregator = *mocks.NewTimeoutSignatureAggregator(s.T())
		exception := errors.New("verify-exception")
		s.sigAggregator.On("VerifyAndAdd", mock.Anything, mock.Anything, mock.Anything).
			Return(uint64(0), exception).Once()
		err := s.processor.Process(timeout)
		require.False(s.T(), models.IsInvalidTimeoutError[*helper.TestVote](err))
		require.ErrorIs(s.T(), err, exception)
	})
}

// TestProcess_CreatingTC is a test for happy path single threaded signature aggregation and TC creation
// Each replica commits unique timeout state, this object gets processed by TimeoutProcessor. After collecting
// enough weight we expect a TC to be created. All further operations should be no-op, only one TC should be created.
func (s *TimeoutProcessorTestSuite) TestProcess_CreatingTC() {
	// consider next situation:
	// last successful rank was N, after this we weren't able to get a proposal with QC for
	// len(participants) ranks, but in each rank QC was created(but not distributed).
	// In rank N+len(participants) each replica contributes with unique highest QC.
	lastSuccessfulQC := helper.MakeQC(helper.WithQCRank(s.rank - uint64(len(s.participants))))
	previousRankTimeoutCert := helper.MakeTC(helper.WithTCRank(s.rank-1),
		helper.WithTCNewestQC(lastSuccessfulQC))

	var highQCRanks []uint64
	var timeouts []*models.TimeoutState[*helper.TestVote]
	signers := s.participants[1:]
	for i, signer := range signers {
		qc := helper.MakeQC(helper.WithQCRank(lastSuccessfulQC.GetRank() + uint64(i+1)))
		highQCRanks = append(highQCRanks, qc.GetRank())

		timeout := helper.TimeoutStateFixture(
			helper.WithTimeoutStateRank[*helper.TestVote](s.rank),
			helper.WithTimeoutNewestQC[*helper.TestVote](qc),
			helper.WithTimeoutVote(&helper.TestVote{ID: signer.Identity(), Rank: s.rank}),
			helper.WithTimeoutPreviousRankTimeoutCertificate[*helper.TestVote](previousRankTimeoutCert),
		)
		timeouts = append(timeouts, timeout)
	}

	// change tracker to require all except one signer to create TC
	s.processor.tcTracker.minRequiredWeight = s.sigWeight * uint64(len(highQCRanks))

	expectedSigBytes := make([]byte, 74)
	expectedSig := &helper.TestAggregatedSignature{
		Signature: expectedSigBytes,
		Bitmask:   []byte{0b11111111, 0b00000111},
		PublicKey: make([]byte, 585),
	}
	s.validator.On("ValidateQuorumCertificate", mock.Anything).Return(nil)
	s.validator.On("ValidateTimeoutCertificate", mock.Anything).Return(nil)
	s.notifier.On("OnPartialTimeoutCertificateCreated", s.rank, mock.Anything, previousRankTimeoutCert).Return(nil).Once()
	s.notifier.On("OnTimeoutCertificateConstructedFromTimeouts", mock.Anything).Run(func(args mock.Arguments) {
		newestQC := timeouts[len(timeouts)-1].LatestQuorumCertificate
		tc := args.Get(0).(models.TimeoutCertificate)
		// ensure that TC contains correct fields
		expectedTC := &helper.TestTimeoutCertificate{
			Rank:                s.rank,
			LatestRanks:         highQCRanks,
			LatestQuorumCert:    newestQC,
			AggregatedSignature: expectedSig,
		}
		require.Equal(s.T(), expectedTC, tc)
	}).Return(nil).Once()
	s.voting.On("FinalizeTimeout", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&helper.TestTimeoutCertificate{
		Filter:           nil,
		Rank:             s.rank,
		LatestRanks:      highQCRanks,
		LatestQuorumCert: timeouts[len(timeouts)-1].LatestQuorumCertificate,
		AggregatedSignature: &helper.TestAggregatedSignature{
			PublicKey: make([]byte, 585),
			Signature: make([]byte, 74),
			Bitmask:   []byte{0b11111111, 0b00000111},
		},
	}, nil)

	signersData := make([]consensus.TimeoutSignerInfo, 0)
	for i, signer := range signers {
		signersData = append(signersData, consensus.TimeoutSignerInfo{
			NewestQCRank: highQCRanks[i],
			Signer:       signer.Identity(),
		})
	}
	s.sigAggregator.On("Aggregate").Return(signersData, expectedSig, nil)

	for _, timeout := range timeouts {
		err := s.processor.Process(timeout)
		require.NoError(s.T(), err)
	}
	s.notifier.AssertExpectations(s.T())
	s.sigAggregator.AssertExpectations(s.T())

	// add extra timeout, make sure we don't create another TC
	// should be no-op
	timeout := helper.TimeoutStateFixture(
		helper.WithTimeoutStateRank[*helper.TestVote](s.rank),
		helper.WithTimeoutNewestQC[*helper.TestVote](helper.MakeQC(helper.WithQCRank(lastSuccessfulQC.GetRank()))),
		helper.WithTimeoutVote(&helper.TestVote{
			ID:   s.participants[0].Identity(),
			Rank: s.rank,
		}),
		helper.WithTimeoutPreviousRankTimeoutCertificate[*helper.TestVote](nil),
	)
	err := s.processor.Process(timeout)
	require.NoError(s.T(), err)

	s.notifier.AssertExpectations(s.T())
	s.validator.AssertExpectations(s.T())
}

// TestProcess_ConcurrentCreatingTC tests a scenario where multiple goroutines process timeout at same time,
// we expect only one TC created in this scenario.
func (s *TimeoutProcessorTestSuite) TestProcess_ConcurrentCreatingTC() {
	s.validator.On("ValidateQuorumCertificate", mock.Anything).Return(nil)
	s.notifier.On("OnPartialTimeoutCertificateCreated", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	s.notifier.On("OnTimeoutCertificateConstructedFromTimeouts", mock.Anything).Return(nil).Once()

	signersData := make([]consensus.TimeoutSignerInfo, 0, len(s.participants))
	for _, signer := range s.participants {
		signersData = append(signersData, consensus.TimeoutSignerInfo{
			NewestQCRank: 0,
			Signer:       signer.Identity(),
		})
	}
	// don't care about actual data
	s.sigAggregator.On("Aggregate").Return(signersData, &helper.TestAggregatedSignature{PublicKey: make([]byte, 585), Signature: make([]byte, 74), Bitmask: []byte{0b11111111, 0b00000111}}, nil)
	var startupWg, shutdownWg sync.WaitGroup

	newestQC := helper.MakeQC(helper.WithQCRank(s.rank - 1))
	s.voting.On("FinalizeTimeout", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&helper.TestTimeoutCertificate{
		Filter:           nil,
		Rank:             s.rank,
		LatestRanks:      []uint64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		LatestQuorumCert: newestQC,
		AggregatedSignature: &helper.TestAggregatedSignature{
			PublicKey: make([]byte, 585),
			Signature: make([]byte, 74),
			Bitmask:   []byte{0b11111111, 0b00000111},
		},
	}, nil)

	startupWg.Add(1)
	// prepare goroutines, so they are ready to submit a timeout at roughly same time
	for i, signer := range s.participants {
		shutdownWg.Add(1)
		timeout := helper.TimeoutStateFixture(
			helper.WithTimeoutStateRank[*helper.TestVote](s.rank),
			helper.WithTimeoutNewestQC[*helper.TestVote](newestQC),
			helper.WithTimeoutVote(&helper.TestVote{
				ID:   signer.Identity(),
				Rank: s.rank,
			}),
			helper.WithTimeoutPreviousRankTimeoutCertificate[*helper.TestVote](nil),
		)
		go func(i int, timeout *models.TimeoutState[*helper.TestVote]) {
			defer shutdownWg.Done()
			startupWg.Wait()
			err := s.processor.Process(timeout)
			require.NoError(s.T(), err)
		}(i, timeout)
	}

	startupWg.Done()

	// wait for all routines to finish
	shutdownWg.Wait()
}

// TestTimeoutProcessor_BuildVerifyTC tests a complete path from creating timeouts to collecting timeouts and then
// building & verifying TC.
// This test emulates the most complex scenario where TC consists of TimeoutStates that are structurally different.
// Let's consider a case where at some rank N consensus committee generated both QC and TC, resulting in nodes differently entering rank N+1.
// When constructing TC for rank N+1 some replicas will contribute with TO{Rank:N+1, NewestQC.Rank: N, PreviousRankTimeoutCertificate: nil}
// while others with TO{Rank:N+1, NewestQC.Rank: N-1, PreviousRankTimeoutCertificate: TC{Rank: N, NewestQC.Rank: N-1}}.
// This results in multi-message BLS signature with messages picked from set M={N-1,N}.
// We have to be able to construct a valid TC for rank N+1 and successfully validate it.
// We start by building a valid QC for rank N-1, that will be included in every TimeoutState at rank N.
// Right after we create a valid QC for rank N. We need to have valid QCs since TimeoutProcessor performs complete validation of TimeoutState.
// Then we create a valid cryptographically signed timeout for each signer. Created timeouts are feed to TimeoutProcessor
// which eventually creates a TC after seeing processing enough objects. After we verify if TC was correctly constructed
// and if it doesn't violate protocol rules. At this point we have QC for rank N-1, both QC and TC for rank N.
// After constructing valid objects we will repeat TC creation process and create a TC for rank N+1 where replicas contribute
// with structurally different TimeoutStates to make sure that TC is correctly built and can be successfully validated.
func TestTimeoutProcessor_BuildVerifyTC(t *testing.T) {
	// signers hold objects that are created with private key and can sign votes and proposals
	signers := make(map[models.Identity]*verification.Signer[*helper.TestState, *helper.TestVote, *helper.TestPeer])
	// prepare proving signers, each signer has its own private/public key pair
	// identities must be in canonical order
	provingSigners := helper.WithWeightedIdentityList(11)
	leader := provingSigners[0]
	rank := uint64(rand.Uint32() + 100)

	state := helper.MakeState(helper.WithStateRank[*helper.TestState](rank-1),
		helper.WithStateProposer[*helper.TestState](leader.Identity()))
	votingProviders := []*mocks.VotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer]{}
	for _, s := range provingSigners {
		v := mocks.NewVotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer](t)
		votingProviders = append(votingProviders, v)
		vote := &helper.TestVote{
			ID:        s.Identity(),
			Rank:      rank - 1,
			Signature: make([]byte, 74),
			Timestamp: uint64(time.Now().UnixMilli()),
			StateID:   state.Identifier,
		}
		v.On("SignVote", mock.Anything, mock.Anything).Return(&vote, nil).Once()
		signers[s.Identity()] = verification.NewSigner[*helper.TestState, *helper.TestVote, *helper.TestPeer](v)
	}

	// utility function which generates a valid timeout for every signer
	createTimeouts := func(participants []models.WeightedIdentity, rank uint64, newestQC models.QuorumCertificate, previousRankTimeoutCert models.TimeoutCertificate) []*models.TimeoutState[*helper.TestVote] {
		timeouts := make([]*models.TimeoutState[*helper.TestVote], 0, len(participants))
		for _, signer := range participants {
			timeout, err := signers[signer.Identity()].CreateTimeout(rank, newestQC, previousRankTimeoutCert)
			require.NoError(t, err)
			timeouts = append(timeouts, timeout)
		}
		return timeouts
	}

	provingSignersSkeleton := provingSigners

	committee := mocks.NewDynamicCommittee(t)
	committee.On("IdentitiesByRank", mock.Anything).Return(provingSignersSkeleton, nil)
	committee.On("IdentitiesByState", mock.Anything).Return(provingSigners, nil)
	committee.On("QuorumThresholdForRank", mock.Anything).Return(uint64(8000), nil)
	committee.On("TimeoutThresholdForRank", mock.Anything).Return(uint64(8000), nil)

	// create first QC for rank N-1, this will be our olderQC
	olderQC := createRealQC(t, committee, provingSignersSkeleton, signers, state)
	// now create a second QC for rank N, this will be our newest QC
	nextState := helper.MakeState(
		helper.WithStateRank[*helper.TestState](rank),
		helper.WithStateProposer[*helper.TestState](leader.Identity()),
		helper.WithStateQC[*helper.TestState](olderQC))

	for i, vp := range votingProviders {
		vote := &helper.TestVote{
			ID:        provingSigners[i].Identity(),
			Rank:      rank,
			Signature: make([]byte, 74),
			Timestamp: uint64(time.Now().UnixMilli()),
			StateID:   nextState.Identifier,
		}
		vp.On("SignVote", mock.Anything, mock.Anything).Return(&vote, nil).Once()
		tvote := &helper.TestVote{
			ID:        provingSigners[i].Identity(),
			Rank:      rank,
			Signature: make([]byte, 74),
			Timestamp: uint64(time.Now().UnixMilli()),
		}
		vp.On("SignTimeoutVote", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&tvote, nil)
	}
	newestQC := createRealQC(t, committee, provingSignersSkeleton, signers, nextState)

	// At this point we have created two QCs for round N-1 and N.
	// Next step is create a TC for rank N.

	// create verifier that will do crypto checks of created TC
	verifier := &mocks.Verifier[*helper.TestVote]{}
	verifier.On("VerifyQuorumCertificate", mock.Anything).Return(nil)
	verifier.On("VerifyTimeoutCertificate", mock.Anything).Return(nil)

	// create validator which will do compliance and crypto checks of created TC
	validator := validator.NewValidator[*helper.TestState, *helper.TestVote](committee, verifier)

	var previousRankTimeoutCert models.TimeoutCertificate
	onTCCreated := func(args mock.Arguments) {
		tc := args.Get(0).(models.TimeoutCertificate)
		// check if resulted TC is valid
		err := validator.ValidateTimeoutCertificate(tc)
		require.NoError(t, err)
		previousRankTimeoutCert = tc
	}

	sigagg := mocks.NewSignatureAggregator(t)
	sigagg.On("VerifySignatureRaw", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true)
	sigagg.On("Aggregate", mock.Anything, mock.Anything).Return(&helper.TestAggregatedSignature{PublicKey: make([]byte, 585), Signature: make([]byte, 74), Bitmask: []byte{0b11111111, 0b00000111}}, nil)

	aggregator, err := NewTimeoutSignatureAggregator(sigagg, []byte{}, rank, provingSignersSkeleton, []byte{})
	require.NoError(t, err)

	notifier := mocks.NewTimeoutCollectorConsumer[*helper.TestVote](t)
	notifier.On("OnPartialTimeoutCertificateCreated", rank, olderQC, nil).Return().Once()
	notifier.On("OnTimeoutCertificateConstructedFromTimeouts", mock.Anything).Run(onTCCreated).Return().Once()
	voting := mocks.NewVotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer](t)
	voting.On("FinalizeTimeout", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&helper.TestTimeoutCertificate{
		Filter:              nil,
		Rank:                rank,
		LatestRanks:         []uint64{rank - 1, rank - 1, rank - 1, rank - 1, rank - 1, rank - 1, rank - 1, rank - 1},
		LatestQuorumCert:    olderQC,
		AggregatedSignature: &helper.TestAggregatedSignature{PublicKey: make([]byte, 585), Signature: make([]byte, 74), Bitmask: []byte{0b11111111, 0b00000111}},
	}, nil)
	processor, err := NewTimeoutProcessor[*helper.TestState, *helper.TestVote, *helper.TestPeer](helper.Logger(), committee, validator, aggregator, notifier, voting)
	require.NoError(t, err)

	// last rank was successful, no previousRankTimeoutCert in this case
	timeouts := createTimeouts(provingSignersSkeleton, rank, olderQC, nil)
	for _, timeout := range timeouts {
		err := processor.Process(timeout)
		require.NoError(t, err)
	}

	notifier.AssertExpectations(t)

	// at this point we have created QCs for rank N-1 and N additionally a TC for rank N, we can create TC for rank N+1
	// with timeout states containing both QC and TC for rank N

	aggregator, err = NewTimeoutSignatureAggregator(sigagg, []byte{}, rank+1, provingSignersSkeleton, []byte{})
	require.NoError(t, err)

	notifier = mocks.NewTimeoutCollectorConsumer[*helper.TestVote](t)
	notifier.On("OnPartialTimeoutCertificateCreated", rank+1, newestQC, mock.Anything).Return()
	notifier.On("OnTimeoutCertificateConstructedFromTimeouts", mock.Anything).Run(onTCCreated).Return().Once()
	processor, err = NewTimeoutProcessor[*helper.TestState, *helper.TestVote, *helper.TestPeer](helper.Logger(), committee, validator, aggregator, notifier, voting)
	require.NoError(t, err)

	// part of committee will use QC, another part TC, this will result in aggregated signature consisting
	// of two types of messages with ranks N-1 and N representing the newest QC known to replicas.
	timeoutsWithQC := createTimeouts(provingSignersSkeleton[:len(provingSignersSkeleton)/2], rank+1, newestQC, nil)
	timeoutsWithTC := createTimeouts(provingSignersSkeleton[len(provingSignersSkeleton)/2:], rank+1, olderQC, previousRankTimeoutCert)
	timeouts = append(timeoutsWithQC, timeoutsWithTC...)
	for _, timeout := range timeouts {
		err := processor.Process(timeout)
		require.NoError(t, err)
	}

	notifier.AssertExpectations(t)
}

// createRealQC is a helper function which generates a properly signed QC with real signatures for given state.
func createRealQC(
	t *testing.T,
	committee consensus.DynamicCommittee,
	signers []models.WeightedIdentity,
	signerObjects map[models.Identity]*verification.Signer[*helper.TestState, *helper.TestVote, *helper.TestPeer],
	state *models.State[*helper.TestState],
) models.QuorumCertificate {
	leader := signers[0]
	leaderVote, err := signerObjects[leader.Identity()].CreateVote(state)
	require.NoError(t, err)
	proposal := helper.MakeSignedProposal(helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(helper.WithState(state))), helper.WithVote[*helper.TestState](leaderVote))

	var createdQC *models.QuorumCertificate
	onQCCreated := func(qc models.QuorumCertificate) {
		createdQC = &qc
	}

	voteProcessorFactory := votecollector.NewVoteProcessorFactory[*helper.TestState, *helper.TestVote, *helper.TestPeer](committee, onQCCreated)
	sigagg := mocks.NewSignatureAggregator(t)
	sigagg.On("VerifySignatureRaw", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true)
	sigagg.On("Aggregate", mock.Anything, mock.Anything).Return(&helper.TestAggregatedSignature{PublicKey: make([]byte, 585), Signature: make([]byte, 74), Bitmask: []byte{0b11111111, 0b00000111}}, nil)

	votingProvider := mocks.NewVotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer](t)
	votingProvider.On("FinalizeQuorumCertificate", mock.Anything, mock.Anything, mock.Anything).Return(&helper.TestQuorumCertificate{
		Filter:              nil,
		Rank:                state.Rank,
		FrameNumber:         state.Rank,
		Selector:            state.Identifier,
		Timestamp:           uint64(time.Now().UnixMilli()),
		AggregatedSignature: &helper.TestAggregatedSignature{PublicKey: make([]byte, 585), Signature: make([]byte, 74), Bitmask: []byte{0b11111111, 0b00000111}},
	}, nil)
	voteProcessor, err := voteProcessorFactory.Create(helper.Logger(), []byte{}, proposal, []byte{}, sigagg, votingProvider)
	require.NoError(t, err)

	for _, signer := range signers[1:] {
		vote, err := signerObjects[signer.Identity()].CreateVote(state)
		require.NoError(t, err)
		err = voteProcessor.Process(vote)
		require.NoError(t, err)
	}

	require.NotNil(t, createdQC, "vote processor must create a valid QC at this point")
	return *createdQC
}
