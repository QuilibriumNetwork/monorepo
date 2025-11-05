package pacemaker

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/mocks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

func TestRankTracker(t *testing.T) {
	suite.Run(t, new(RankTrackerTestSuite))
}

type RankTrackerTestSuite struct {
	suite.Suite

	initialRank uint64
	initialQC   models.QuorumCertificate
	initialTC   models.TimeoutCertificate

	livenessState *models.LivenessState // Caution: we hand the memory address to rankTracker, which could modify this
	store         *mocks.ConsensusStore[*helper.TestVote]
	tracker       rankTracker[*helper.TestState, *helper.TestVote]
}

func (s *RankTrackerTestSuite) SetupTest() {
	s.initialRank = 5
	s.initialQC = helper.MakeQC(helper.WithQCRank(4))
	s.initialTC = nil

	s.livenessState = &models.LivenessState{
		LatestQuorumCertificate:     s.initialQC,
		PriorRankTimeoutCertificate: s.initialTC,
		CurrentRank:                 s.initialRank, // we entered rank 5 by observing a QC for rank 4
	}
	s.store = mocks.NewConsensusStore[*helper.TestVote](s.T())
	s.store.On("GetLivenessState", mock.Anything).Return(s.livenessState, nil).Once()

	var err error
	s.tracker, err = newRankTracker[*helper.TestState, *helper.TestVote](nil, s.store)
	require.NoError(s.T(), err)
}

// confirmResultingState asserts that the rank tracker's stored LivenessState reflects the provided
// current rank, newest QC, and last rank TC.
func (s *RankTrackerTestSuite) confirmResultingState(curRank uint64, qc models.QuorumCertificate, tc models.TimeoutCertificate) {
	require.Equal(s.T(), curRank, s.tracker.CurrentRank())
	require.Equal(s.T(), qc, s.tracker.LatestQuorumCertificate())
	if tc == nil {
		require.Nil(s.T(), s.tracker.PriorRankTimeoutCertificate())
	} else {
		require.Equal(s.T(), tc, s.tracker.PriorRankTimeoutCertificate())
	}
}

// TestReceiveQuorumCertificate_SkipIncreaseRankThroughQC tests that rankTracker increases rank when receiving QC,
// if applicable, by skipping ranks
func (s *RankTrackerTestSuite) TestReceiveQuorumCertificate_SkipIncreaseRankThroughQC() {
	// seeing a QC for the current rank should advance the rank by one
	qc := QC(s.initialRank)
	expectedResultingRank := s.initialRank + 1
	s.store.On("PutLivenessState", LivenessState(qc)).Return(nil).Once()
	resultingCurrentRank, err := s.tracker.ReceiveQuorumCertificate(qc)
	require.NoError(s.T(), err)
	require.Equal(s.T(), expectedResultingRank, resultingCurrentRank)
	s.confirmResultingState(expectedResultingRank, qc, nil)

	// seeing a QC for 10 ranks in the future should advance to rank +11
	curRank := s.tracker.CurrentRank()
	qc = QC(curRank + 10)
	expectedResultingRank = curRank + 11
	s.store.On("PutLivenessState", LivenessState(qc)).Return(nil).Once()
	resultingCurrentRank, err = s.tracker.ReceiveQuorumCertificate(qc)
	require.NoError(s.T(), err)
	require.Equal(s.T(), expectedResultingRank, resultingCurrentRank)
	s.confirmResultingState(expectedResultingRank, qc, nil)
}

// TestReceiveTimeoutCertificate_SkipIncreaseRankThroughTC tests that rankTracker increases rank when receiving TC,
// if applicable, by skipping ranks
func (s *RankTrackerTestSuite) TestReceiveTimeoutCertificate_SkipIncreaseRankThroughTC() {
	// seeing a TC for the current rank should advance the rank by one
	qc := s.initialQC
	tc := helper.MakeTC(helper.WithTCRank(s.initialRank), helper.WithTCNewestQC(qc))
	expectedResultingRank := s.initialRank + 1
	expectedLivenessState := &models.LivenessState{
		CurrentRank:                 expectedResultingRank,
		PriorRankTimeoutCertificate: tc,
		LatestQuorumCertificate:     qc,
	}
	s.store.On("PutLivenessState", expectedLivenessState).Return(nil).Once()
	resultingCurrentRank, err := s.tracker.ReceiveTimeoutCertificate(tc)
	require.NoError(s.T(), err)
	require.Equal(s.T(), expectedResultingRank, resultingCurrentRank)
	s.confirmResultingState(expectedResultingRank, qc, tc)

	// seeing a TC for 10 ranks in the future should advance to rank +11
	curRank := s.tracker.CurrentRank()
	tc = helper.MakeTC(helper.WithTCRank(curRank+10), helper.WithTCNewestQC(qc))
	expectedResultingRank = curRank + 11
	expectedLivenessState = &models.LivenessState{
		CurrentRank:                 expectedResultingRank,
		PriorRankTimeoutCertificate: tc,
		LatestQuorumCertificate:     qc,
	}
	s.store.On("PutLivenessState", expectedLivenessState).Return(nil).Once()
	resultingCurrentRank, err = s.tracker.ReceiveTimeoutCertificate(tc)
	require.NoError(s.T(), err)
	require.Equal(s.T(), expectedResultingRank, resultingCurrentRank)
	s.confirmResultingState(expectedResultingRank, qc, tc)
}

// TestReceiveTimeoutCertificate_IgnoreOldTC tests that rankTracker ignores old TC and doesn't advance round.
func (s *RankTrackerTestSuite) TestReceiveTimeoutCertificate_IgnoreOldTC() {
	curRank := s.tracker.CurrentRank()
	tc := helper.MakeTC(
		helper.WithTCRank(curRank-1),
		helper.WithTCNewestQC(QC(curRank-2)))
	resultingCurrentRank, err := s.tracker.ReceiveTimeoutCertificate(tc)
	require.NoError(s.T(), err)
	require.Equal(s.T(), curRank, resultingCurrentRank)
	s.confirmResultingState(curRank, s.initialQC, s.initialTC)
}

// TestReceiveTimeoutCertificate_IgnoreNilTC tests that rankTracker accepts nil TC as allowed input but doesn't trigger a new rank event
func (s *RankTrackerTestSuite) TestReceiveTimeoutCertificate_IgnoreNilTC() {
	curRank := s.tracker.CurrentRank()
	resultingCurrentRank, err := s.tracker.ReceiveTimeoutCertificate(nil)
	require.NoError(s.T(), err)
	require.Equal(s.T(), curRank, resultingCurrentRank)
	s.confirmResultingState(curRank, s.initialQC, s.initialTC)
}

// TestReceiveQuorumCertificate_PersistException tests that rankTracker propagates exception
// when processing QC
func (s *RankTrackerTestSuite) TestReceiveQuorumCertificate_PersistException() {
	qc := QC(s.initialRank)
	exception := errors.New("store-exception")
	s.store.On("PutLivenessState", mock.Anything).Return(exception).Once()

	_, err := s.tracker.ReceiveQuorumCertificate(qc)
	require.ErrorIs(s.T(), err, exception)
}

// TestReceiveTimeoutCertificate_PersistException tests that rankTracker propagates exception
// when processing TC
func (s *RankTrackerTestSuite) TestReceiveTimeoutCertificate_PersistException() {
	tc := helper.MakeTC(helper.WithTCRank(s.initialRank))
	exception := errors.New("store-exception")
	s.store.On("PutLivenessState", mock.Anything).Return(exception).Once()

	_, err := s.tracker.ReceiveTimeoutCertificate(tc)
	require.ErrorIs(s.T(), err, exception)
}

// TestReceiveQuorumCertificate_InvalidatesPriorRankTimeoutCertificate verifies that rankTracker does not retain any old
// TC if the last rank change was triggered by observing a QC from the previous rank.
func (s *RankTrackerTestSuite) TestReceiveQuorumCertificate_InvalidatesPriorRankTimeoutCertificate() {
	initialRank := s.tracker.CurrentRank()
	tc := helper.MakeTC(helper.WithTCRank(initialRank),
		helper.WithTCNewestQC(s.initialQC))
	s.store.On("PutLivenessState", mock.Anything).Return(nil).Twice()
	resultingCurrentRank, err := s.tracker.ReceiveTimeoutCertificate(tc)
	require.NoError(s.T(), err)
	require.Equal(s.T(), initialRank+1, resultingCurrentRank)
	require.NotNil(s.T(), s.tracker.PriorRankTimeoutCertificate())

	qc := QC(initialRank + 1)
	resultingCurrentRank, err = s.tracker.ReceiveQuorumCertificate(qc)
	require.NoError(s.T(), err)
	require.Equal(s.T(), initialRank+2, resultingCurrentRank)
	require.Nil(s.T(), s.tracker.PriorRankTimeoutCertificate())
}

// TestReceiveQuorumCertificate_IgnoreOldQC tests that rankTracker ignores old QC and doesn't advance round
func (s *RankTrackerTestSuite) TestReceiveQuorumCertificate_IgnoreOldQC() {
	qc := QC(s.initialRank - 1)
	resultingCurrentRank, err := s.tracker.ReceiveQuorumCertificate(qc)
	require.NoError(s.T(), err)
	require.Equal(s.T(), s.initialRank, resultingCurrentRank)
	s.confirmResultingState(s.initialRank, s.initialQC, s.initialTC)
}

// TestReceiveQuorumCertificate_UpdateLatestQuorumCertificate tests that rankTracker tracks the newest QC even if it has advanced past this rank.
// The only one scenario, where it is possible to receive a QC for a rank that we already has passed, yet this QC
// being newer than any known one is:
//   - We advance ranks via TC.
//   - A QC for a passed rank that is newer than any known one can arrive in 3 ways:
//     1. A QC (e.g. from the vote aggregator)
//     2. A QC embedded into a TC, where the TC is for a passed rank
//     3. A QC embedded into a TC, where the TC is for the current or newer rank
func (s *RankTrackerTestSuite) TestReceiveQuorumCertificate_UpdateLatestQuorumCertificate() {
	// Setup
	// * we start in rank 5
	// * newest known QC is for rank 4
	// * we receive a TC for rank 55, which results in entering rank 56
	initialRank := s.tracker.CurrentRank() //
	tc := helper.MakeTC(helper.WithTCRank(initialRank+50), helper.WithTCNewestQC(s.initialQC))
	s.store.On("PutLivenessState", mock.Anything).Return(nil).Once()
	expectedRank := uint64(56) // processing the TC should results in entering rank 56
	resultingCurrentRank, err := s.tracker.ReceiveTimeoutCertificate(tc)
	require.NoError(s.T(), err)
	require.Equal(s.T(), expectedRank, resultingCurrentRank)
	s.confirmResultingState(expectedRank, s.initialQC, tc)

	// Test 1: add QC for rank 9, which is newer than our initial QC - it should become our newest QC
	qc := QC(s.tracker.LatestQuorumCertificate().GetRank() + 2)
	expectedLivenessState := &models.LivenessState{
		CurrentRank:                 expectedRank,
		PriorRankTimeoutCertificate: tc,
		LatestQuorumCertificate:     qc,
	}
	s.store.On("PutLivenessState", expectedLivenessState).Return(nil).Once()
	resultingCurrentRank, err = s.tracker.ReceiveQuorumCertificate(qc)
	require.NoError(s.T(), err)
	require.Equal(s.T(), expectedRank, resultingCurrentRank)
	s.confirmResultingState(expectedRank, qc, tc)

	// Test 2: receiving a TC for a passed rank, but the embedded QC is newer than the one we know
	qc2 := QC(s.tracker.LatestQuorumCertificate().GetRank() + 4)
	olderTC := helper.MakeTC(helper.WithTCRank(qc2.GetRank()+3), helper.WithTCNewestQC(qc2))
	expectedLivenessState = &models.LivenessState{
		CurrentRank:                 expectedRank,
		PriorRankTimeoutCertificate: tc,
		LatestQuorumCertificate:     qc2,
	}
	s.store.On("PutLivenessState", expectedLivenessState).Return(nil).Once()
	resultingCurrentRank, err = s.tracker.ReceiveTimeoutCertificate(olderTC)
	require.NoError(s.T(), err)
	require.Equal(s.T(), expectedRank, resultingCurrentRank)
	s.confirmResultingState(expectedRank, qc2, tc)

	// Test 3: receiving a TC for a newer rank, the embedded QC is newer than the one we know, but still for a passed rank
	qc3 := QC(s.tracker.LatestQuorumCertificate().GetRank() + 7)
	finalRank := expectedRank + 1
	newestTC := helper.MakeTC(helper.WithTCRank(expectedRank), helper.WithTCNewestQC(qc3))
	expectedLivenessState = &models.LivenessState{
		CurrentRank:                 finalRank,
		PriorRankTimeoutCertificate: newestTC,
		LatestQuorumCertificate:     qc3,
	}
	s.store.On("PutLivenessState", expectedLivenessState).Return(nil).Once()
	resultingCurrentRank, err = s.tracker.ReceiveTimeoutCertificate(newestTC)
	require.NoError(s.T(), err)
	require.Equal(s.T(), finalRank, resultingCurrentRank)
	s.confirmResultingState(finalRank, qc3, newestTC)
}
