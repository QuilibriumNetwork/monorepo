package pacemaker

import (
	"context"
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/mocks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/pacemaker/timeout"
)

const (
	minRepTimeout             float64 = 100.0 // Milliseconds
	maxRepTimeout             float64 = 600.0 // Milliseconds
	multiplicativeIncrease    float64 = 1.5   // multiplicative factor
	happyPathMaxRoundFailures uint64  = 6     // number of failed rounds before first timeout increase
)

func TestPacemaker(t *testing.T) {
	suite.Run(t, new(PacemakerTestSuite))
}

type PacemakerTestSuite struct {
	suite.Suite

	initialRank uint64
	initialQC   models.QuorumCertificate
	initialTC   models.TimeoutCertificate

	notifier                 *mocks.Consumer[*helper.TestState, *helper.TestVote]
	proposalDurationProvider consensus.ProposalDurationProvider
	store                    *mocks.ConsensusStore[*helper.TestVote]
	pacemaker                *Pacemaker[*helper.TestState, *helper.TestVote]
	stop                     context.CancelFunc
	timeoutConf              timeout.Config
}

func (s *PacemakerTestSuite) SetupTest() {
	s.initialRank = 3
	s.initialQC = QC(2)
	s.initialTC = nil
	var err error

	s.timeoutConf, err = timeout.NewConfig(time.Duration(minRepTimeout*1e6), time.Duration(maxRepTimeout*1e6), multiplicativeIncrease, happyPathMaxRoundFailures, time.Duration(maxRepTimeout*1e6))
	require.NoError(s.T(), err)

	// init consumer for notifications emitted by Pacemaker
	s.notifier = mocks.NewConsumer[*helper.TestState, *helper.TestVote](s.T())
	s.notifier.On("OnStartingTimeout", mock.Anything, mock.Anything).Return().Once()

	// init Persister dependency for Pacemaker
	// CAUTION: The Persister hands a pointer to `livenessState` to the Pacemaker, which means the Pacemaker
	// could modify our struct in-place. `livenessState` should not be used by tests to determine expected values!
	s.store = mocks.NewConsensusStore[*helper.TestVote](s.T())
	livenessState := &models.LivenessState{
		CurrentRank:                 3,
		PriorRankTimeoutCertificate: nil,
		LatestQuorumCertificate:     s.initialQC,
	}
	s.store.On("GetLivenessState", mock.Anything).Return(livenessState, nil)

	// init Pacemaker and start
	s.pacemaker, err = NewPacemaker(nil, timeout.NewController(s.timeoutConf), NoProposalDelay(), s.notifier, s.store, helper.Logger())
	require.NoError(s.T(), err)

	var ctx context.Context
	ctx, s.stop = context.WithCancel(context.Background())
	s.pacemaker.Start(ctx)
}

func (s *PacemakerTestSuite) TearDownTest() {
	s.stop()
}

func QC(rank uint64) models.QuorumCertificate {
	return helper.MakeQC(helper.WithQCRank(rank))
}

func LivenessState(qc models.QuorumCertificate) *models.LivenessState {
	return &models.LivenessState{
		CurrentRank:                 qc.GetRank() + 1,
		PriorRankTimeoutCertificate: nil,
		LatestQuorumCertificate:     qc,
	}
}

// TestReceiveQuorumCertificate_SkipIncreaseRankThroughQC tests that Pacemaker increases rank when receiving QC,
// if applicable, by skipping ranks
func (s *PacemakerTestSuite) TestReceiveQuorumCertificate_SkipIncreaseRankThroughQC() {
	// seeing a QC for the current rank should advance the rank by one
	qc := QC(s.initialRank)
	s.store.On("PutLivenessState", LivenessState(qc)).Return(nil).Once()
	s.notifier.On("OnStartingTimeout", mock.Anything, mock.Anything).Return().Once()
	s.notifier.On("OnQuorumCertificateTriggeredRankChange", s.initialRank, uint64(4), qc).Return().Once()
	s.notifier.On("OnRankChange", s.initialRank, qc.GetRank()+1).Once()
	nve, err := s.pacemaker.ReceiveQuorumCertificate(qc)
	require.NoError(s.T(), err)
	require.Equal(s.T(), qc.GetRank()+1, s.pacemaker.CurrentRank())
	require.True(s.T(), nve.Rank == qc.GetRank()+1)
	require.Equal(s.T(), qc, s.pacemaker.LatestQuorumCertificate())
	require.Nil(s.T(), s.pacemaker.PriorRankTimeoutCertificate())

	// seeing a QC for 10 ranks in the future should advance to rank +11
	curRank := s.pacemaker.CurrentRank()
	qc = QC(curRank + 10)
	s.store.On("PutLivenessState", LivenessState(qc)).Return(nil).Once()
	s.notifier.On("OnStartingTimeout", mock.Anything, mock.Anything).Return().Once()
	s.notifier.On("OnQuorumCertificateTriggeredRankChange", curRank, qc.GetRank()+1, qc).Return().Once()
	s.notifier.On("OnRankChange", curRank, qc.GetRank()+1).Once()
	nve, err = s.pacemaker.ReceiveQuorumCertificate(qc)
	require.NoError(s.T(), err)
	require.True(s.T(), nve.Rank == qc.GetRank()+1)
	require.Equal(s.T(), qc, s.pacemaker.LatestQuorumCertificate())
	require.Nil(s.T(), s.pacemaker.PriorRankTimeoutCertificate())

	require.Equal(s.T(), qc.GetRank()+1, s.pacemaker.CurrentRank())
}

// TestReceiveTimeoutCertificate_SkipIncreaseRankThroughTC tests that Pacemaker increases rank when receiving TC,
// if applicable, by skipping ranks
func (s *PacemakerTestSuite) TestReceiveTimeoutCertificate_SkipIncreaseRankThroughTC() {
	// seeing a TC for the current rank should advance the rank by one
	tc := helper.MakeTC(helper.WithTCRank(s.initialRank), helper.WithTCNewestQC(s.initialQC))
	expectedLivenessState := &models.LivenessState{
		CurrentRank:                 tc.GetRank() + 1,
		PriorRankTimeoutCertificate: tc,
		LatestQuorumCertificate:     s.initialQC,
	}
	s.store.On("PutLivenessState", expectedLivenessState).Return(nil).Once()
	s.notifier.On("OnStartingTimeout", mock.Anything, mock.Anything).Return().Once()
	s.notifier.On("OnTimeoutCertificateTriggeredRankChange", s.initialRank, tc.GetRank()+1, tc).Return().Once()
	s.notifier.On("OnRankChange", s.initialRank, tc.GetRank()+1).Once()
	nve, err := s.pacemaker.ReceiveTimeoutCertificate(tc)
	require.NoError(s.T(), err)
	require.Equal(s.T(), tc.GetRank()+1, s.pacemaker.CurrentRank())
	require.True(s.T(), nve.Rank == tc.GetRank()+1)
	require.Equal(s.T(), tc, s.pacemaker.PriorRankTimeoutCertificate())

	// seeing a TC for 10 ranks in the future should advance to rank +11
	curRank := s.pacemaker.CurrentRank()
	tc = helper.MakeTC(helper.WithTCRank(curRank+10), helper.WithTCNewestQC(s.initialQC))
	expectedLivenessState = &models.LivenessState{
		CurrentRank:                 tc.GetRank() + 1,
		PriorRankTimeoutCertificate: tc,
		LatestQuorumCertificate:     s.initialQC,
	}
	s.store.On("PutLivenessState", expectedLivenessState).Return(nil).Once()
	s.notifier.On("OnStartingTimeout", mock.Anything, mock.Anything).Return().Once()
	s.notifier.On("OnTimeoutCertificateTriggeredRankChange", curRank, tc.GetRank()+1, tc).Return().Once()
	s.notifier.On("OnRankChange", curRank, tc.GetRank()+1).Once()
	nve, err = s.pacemaker.ReceiveTimeoutCertificate(tc)
	require.NoError(s.T(), err)
	require.True(s.T(), nve.Rank == tc.GetRank()+1)
	require.Equal(s.T(), tc, s.pacemaker.PriorRankTimeoutCertificate())
	require.Equal(s.T(), tc.GetLatestQuorumCert(), s.pacemaker.LatestQuorumCertificate())

	require.Equal(s.T(), tc.GetRank()+1, s.pacemaker.CurrentRank())
}

// TestReceiveTimeoutCertificate_IgnoreOldTC tests that Pacemaker ignores old TC and doesn't advance round.
func (s *PacemakerTestSuite) TestReceiveTimeoutCertificate_IgnoreOldTC() {
	nve, err := s.pacemaker.ReceiveTimeoutCertificate(helper.MakeTC(helper.WithTCRank(s.initialRank-1),
		helper.WithTCNewestQC(s.initialQC)))
	require.NoError(s.T(), err)
	require.Nil(s.T(), nve)
	require.Equal(s.T(), s.initialRank, s.pacemaker.CurrentRank())
}

// TestReceiveTimeoutCertificate_IgnoreNilTC tests that Pacemaker accepts nil TC as allowed input but doesn't trigger a new rank event
func (s *PacemakerTestSuite) TestReceiveTimeoutCertificate_IgnoreNilTC() {
	nve, err := s.pacemaker.ReceiveTimeoutCertificate(nil)
	require.NoError(s.T(), err)
	require.Nil(s.T(), nve)
	require.Equal(s.T(), s.initialRank, s.pacemaker.CurrentRank())
}

// TestReceiveQuorumCertificate_PersistException tests that Pacemaker propagates exception
// when processing QC
func (s *PacemakerTestSuite) TestReceiveQuorumCertificate_PersistException() {
	exception := errors.New("persist-exception")
	qc := QC(s.initialRank)
	s.store.On("PutLivenessState", mock.Anything).Return(exception).Once()
	nve, err := s.pacemaker.ReceiveQuorumCertificate(qc)
	require.Nil(s.T(), nve)
	require.ErrorIs(s.T(), err, exception)
}

// TestReceiveTimeoutCertificate_PersistException tests that Pacemaker propagates exception
// when processing TC
func (s *PacemakerTestSuite) TestReceiveTimeoutCertificate_PersistException() {
	exception := errors.New("persist-exception")
	tc := helper.MakeTC(helper.WithTCRank(s.initialRank))
	s.store.On("PutLivenessState", mock.Anything).Return(exception).Once()
	nve, err := s.pacemaker.ReceiveTimeoutCertificate(tc)
	require.Nil(s.T(), nve)
	require.ErrorIs(s.T(), err, exception)
}

// TestReceiveQuorumCertificate_InvalidatesPriorRankTimeoutCertificate verifies that Pacemaker does not retain any old
// TC if the last rank change was triggered by observing a QC from the previous rank.
func (s *PacemakerTestSuite) TestReceiveQuorumCertificate_InvalidatesPriorRankTimeoutCertificate() {
	tc := helper.MakeTC(helper.WithTCRank(s.initialRank+1), helper.WithTCNewestQC(s.initialQC))
	s.store.On("PutLivenessState", mock.Anything).Return(nil).Times(2)
	s.notifier.On("OnStartingTimeout", mock.Anything, mock.Anything).Return().Times(2)
	s.notifier.On("OnTimeoutCertificateTriggeredRankChange", mock.Anything, mock.Anything, mock.Anything).Return().Once()
	s.notifier.On("OnQuorumCertificateTriggeredRankChange", mock.Anything, mock.Anything, mock.Anything).Return().Once()
	s.notifier.On("OnRankChange", s.initialRank, tc.GetRank()+1).Once()
	nve, err := s.pacemaker.ReceiveTimeoutCertificate(tc)
	require.NotNil(s.T(), nve)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), s.pacemaker.PriorRankTimeoutCertificate())

	qc := QC(tc.GetRank() + 1)
	s.notifier.On("OnRankChange", tc.GetRank()+1, qc.GetRank()+1).Once()
	nve, err = s.pacemaker.ReceiveQuorumCertificate(qc)
	require.NotNil(s.T(), nve)
	require.NoError(s.T(), err)
	require.Nil(s.T(), s.pacemaker.PriorRankTimeoutCertificate())
}

// TestReceiveQuorumCertificate_IgnoreOldQC tests that Pacemaker ignores old QC and doesn't advance round
func (s *PacemakerTestSuite) TestReceiveQuorumCertificate_IgnoreOldQC() {
	qc := QC(s.initialRank - 1)
	nve, err := s.pacemaker.ReceiveQuorumCertificate(qc)
	require.NoError(s.T(), err)
	require.Nil(s.T(), nve)
	require.Equal(s.T(), s.initialRank, s.pacemaker.CurrentRank())
	require.NotEqual(s.T(), qc, s.pacemaker.LatestQuorumCertificate())
}

// TestReceiveQuorumCertificate_UpdateLatestQuorumCertificate tests that Pacemaker tracks the newest QC even if it has advanced past this rank.
// In this test, we feed a newer QC as part of a TC into the Pacemaker.
func (s *PacemakerTestSuite) TestReceiveQuorumCertificate_UpdateLatestQuorumCertificate() {
	tc := helper.MakeTC(helper.WithTCRank(s.initialRank+10), helper.WithTCNewestQC(s.initialQC))
	expectedRank := tc.GetRank() + 1
	s.notifier.On("OnTimeoutCertificateTriggeredRankChange", mock.Anything, mock.Anything, mock.Anything).Return().Once()
	s.notifier.On("OnRankChange", s.initialRank, expectedRank).Once()
	s.notifier.On("OnStartingTimeout", mock.Anything, mock.Anything).Return().Once()
	s.store.On("PutLivenessState", mock.Anything).Return(nil).Once()
	nve, err := s.pacemaker.ReceiveTimeoutCertificate(tc)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), nve)

	qc := QC(s.initialRank + 5)
	expectedLivenessState := &models.LivenessState{
		CurrentRank:                 expectedRank,
		PriorRankTimeoutCertificate: tc,
		LatestQuorumCertificate:     qc,
	}
	s.store.On("PutLivenessState", expectedLivenessState).Return(nil).Once()

	nve, err = s.pacemaker.ReceiveQuorumCertificate(qc)
	require.NoError(s.T(), err)
	require.Nil(s.T(), nve)
	require.Equal(s.T(), qc, s.pacemaker.LatestQuorumCertificate())
}

// TestReceiveTimeoutCertificate_UpdateLatestQuorumCertificate tests that Pacemaker tracks the newest QC included in TC even if it has advanced past this rank.
func (s *PacemakerTestSuite) TestReceiveTimeoutCertificate_UpdateLatestQuorumCertificate() {
	tc := helper.MakeTC(helper.WithTCRank(s.initialRank+10), helper.WithTCNewestQC(s.initialQC))
	expectedRank := tc.GetRank() + 1
	s.notifier.On("OnTimeoutCertificateTriggeredRankChange", mock.Anything, mock.Anything, mock.Anything).Return().Once()
	s.notifier.On("OnRankChange", s.initialRank, expectedRank).Once()
	s.notifier.On("OnStartingTimeout", mock.Anything, mock.Anything).Return().Once()
	s.store.On("PutLivenessState", mock.Anything).Return(nil).Once()
	nve, err := s.pacemaker.ReceiveTimeoutCertificate(tc)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), nve)

	qc := QC(s.initialRank + 5)
	olderTC := helper.MakeTC(helper.WithTCRank(s.pacemaker.CurrentRank()-1), helper.WithTCNewestQC(qc))
	expectedLivenessState := &models.LivenessState{
		CurrentRank:                 expectedRank,
		PriorRankTimeoutCertificate: tc,
		LatestQuorumCertificate:     qc,
	}
	s.store.On("PutLivenessState", expectedLivenessState).Return(nil).Once()

	nve, err = s.pacemaker.ReceiveTimeoutCertificate(olderTC)
	require.NoError(s.T(), err)
	require.Nil(s.T(), nve)
	require.Equal(s.T(), qc, s.pacemaker.LatestQuorumCertificate())
}

// Test_Initialization tests QCs and TCs provided as optional constructor arguments.
// We want to test that nil, old and duplicate TCs & QCs are accepted in arbitrary order.
// The constructed Pacemaker should be in the state:
//   - in rank V+1, where V is the _largest rank of _any_ of the ingested QCs and TCs
//   - method `LatestQuorumCertificate` should report the QC with the highest Rank in _any_ of the inputs
func (s *PacemakerTestSuite) Test_Initialization() {
	highestRank := uint64(0) // highest Rank of any QC or TC constructed below

	// Randomly create 80 TCs:
	//  * their rank is randomly sampled from the range [3, 103)
	//  * as we sample 80 times, probability of creating 2 TCs for the same
	//    rank is practically 1 (-> birthday problem)
	//  * we place the TCs in a slice of length 110, i.e. some elements are guaranteed to be nil
	//  * Note: we specifically allow for the TC to have the same rank as the highest QC.
	//    This is useful as a fallback, because it allows replicas other than the designated
	//     leader to also collect votes and generate a QC.
	tcs := make([]models.TimeoutCertificate, 110)
	for i := 0; i < 80; i++ {
		tcRank := s.initialRank + uint64(rand.Intn(100))
		qcRank := 1 + uint64(rand.Intn(int(tcRank)))
		tcs[i] = helper.MakeTC(helper.WithTCRank(tcRank), helper.WithTCNewestQC(QC(qcRank)))
		highestRank = max(highestRank, tcRank, qcRank)
	}
	rand.Shuffle(len(tcs), func(i, j int) {
		tcs[i], tcs[j] = tcs[j], tcs[i]
	})

	// randomly create 80 QCs (same logic as above)
	qcs := make([]models.QuorumCertificate, 110)
	for i := 0; i < 80; i++ {
		qcs[i] = QC(s.initialRank + uint64(rand.Intn(100)))
		highestRank = max(highestRank, qcs[i].GetRank())
	}
	rand.Shuffle(len(qcs), func(i, j int) {
		qcs[i], qcs[j] = qcs[j], qcs[i]
	})

	// set up mocks
	s.store.On("PutLivenessState", mock.Anything).Return(nil)

	// test that the constructor finds the newest QC and TC
	s.Run("Random TCs and QCs combined", func() {
		pm, err := NewPacemaker(
			nil,
			timeout.NewController(s.timeoutConf), NoProposalDelay(), s.notifier, s.store, helper.Logger(),
			WithQCs[*helper.TestState, *helper.TestVote](qcs...), WithTCs[*helper.TestState, *helper.TestVote](tcs...),
		)
		require.NoError(s.T(), err)

		require.Equal(s.T(), highestRank+1, pm.CurrentRank())
		if tc := pm.PriorRankTimeoutCertificate(); tc != nil {
			require.Equal(s.T(), highestRank, tc.GetRank())
		} else {
			require.Equal(s.T(), highestRank, pm.LatestQuorumCertificate().GetRank())
		}
	})

	// We specifically test an edge case: an outdated TC can still contain a QC that
	// is newer than the newest QC the pacemaker knows so far.
	s.Run("Newest QC in older TC", func() {
		tcs[17] = helper.MakeTC(helper.WithTCRank(highestRank+20), helper.WithTCNewestQC(QC(highestRank+5)))
		tcs[45] = helper.MakeTC(helper.WithTCRank(highestRank+15), helper.WithTCNewestQC(QC(highestRank+12)))

		pm, err := NewPacemaker(
			nil,
			timeout.NewController(s.timeoutConf), NoProposalDelay(), s.notifier, s.store, helper.Logger(),
			WithTCs[*helper.TestState, *helper.TestVote](tcs...), WithQCs[*helper.TestState, *helper.TestVote](qcs...),
		)
		require.NoError(s.T(), err)

		// * when observing tcs[17], which is newer than any other QC or TC, the pacemaker should enter rank tcs[17].Rank + 1
		// * when observing tcs[45], which is older than tcs[17], the Pacemaker should notice that the QC in tcs[45]
		//   is newer than its local QC and update it
		require.Equal(s.T(), tcs[17].GetRank()+1, pm.CurrentRank())
		require.Equal(s.T(), tcs[17], pm.PriorRankTimeoutCertificate())
		require.Equal(s.T(), tcs[45].GetLatestQuorumCert(), pm.LatestQuorumCertificate())
	})

	// Another edge case: a TC from a past rank contains QC for the same rank.
	// While is TC is outdated, the contained QC is still newer that the QC the pacemaker knows so far.
	s.Run("Newest QC in older TC", func() {
		tcs[17] = helper.MakeTC(helper.WithTCRank(highestRank+20), helper.WithTCNewestQC(QC(highestRank+5)))
		tcs[45] = helper.MakeTC(helper.WithTCRank(highestRank+15), helper.WithTCNewestQC(QC(highestRank+15)))

		pm, err := NewPacemaker(
			nil,
			timeout.NewController(s.timeoutConf), NoProposalDelay(), s.notifier, s.store, helper.Logger(),
			WithTCs[*helper.TestState, *helper.TestVote](tcs...), WithQCs[*helper.TestState, *helper.TestVote](qcs...),
		)
		require.NoError(s.T(), err)

		// * when observing tcs[17], which is newer than any other QC or TC, the pacemaker should enter rank tcs[17].Rank + 1
		// * when observing tcs[45], which is older than tcs[17], the Pacemaker should notice that the QC in tcs[45]
		//   is newer than its local QC and update it
		require.Equal(s.T(), tcs[17].GetRank()+1, pm.CurrentRank())
		require.Equal(s.T(), tcs[17], pm.PriorRankTimeoutCertificate())
		require.Equal(s.T(), tcs[45].GetLatestQuorumCert(), pm.LatestQuorumCertificate())
	})

	// Verify that WithTCs still works correctly if no TCs are given:
	// the list of TCs is empty or all contained TCs are nil
	s.Run("Only nil TCs", func() {
		pm, err := NewPacemaker(nil, timeout.NewController(s.timeoutConf), NoProposalDelay(), s.notifier, s.store, helper.Logger(), WithTCs[*helper.TestState, *helper.TestVote]())
		require.NoError(s.T(), err)
		require.Equal(s.T(), s.initialRank, pm.CurrentRank())

		pm, err = NewPacemaker(nil, timeout.NewController(s.timeoutConf), NoProposalDelay(), s.notifier, s.store, helper.Logger(), WithTCs[*helper.TestState, *helper.TestVote](nil, nil, nil))
		require.NoError(s.T(), err)
		require.Equal(s.T(), s.initialRank, pm.CurrentRank())
	})

	// Verify that WithQCs still works correctly if no QCs are given:
	// the list of QCs is empty or all contained QCs are nil
	s.Run("Only nil QCs", func() {
		pm, err := NewPacemaker(nil, timeout.NewController(s.timeoutConf), NoProposalDelay(), s.notifier, s.store, helper.Logger(), WithQCs[*helper.TestState, *helper.TestVote]())
		require.NoError(s.T(), err)
		require.Equal(s.T(), s.initialRank, pm.CurrentRank())

		pm, err = NewPacemaker(nil, timeout.NewController(s.timeoutConf), NoProposalDelay(), s.notifier, s.store, helper.Logger(), WithQCs[*helper.TestState, *helper.TestVote](nil, nil, nil))
		require.NoError(s.T(), err)
		require.Equal(s.T(), s.initialRank, pm.CurrentRank())
	})

}

// TestProposalDuration tests that the active pacemaker forwards proposal duration values from the provider.
func (s *PacemakerTestSuite) TestProposalDuration() {
	proposalDurationProvider := NewStaticProposalDurationProvider(time.Millisecond * 500)
	pm, err := NewPacemaker(nil, timeout.NewController(s.timeoutConf), &proposalDurationProvider, s.notifier, s.store, helper.Logger())
	require.NoError(s.T(), err)

	now := time.Now().UTC()
	assert.Equal(s.T(), now.Add(time.Millisecond*500), pm.TargetPublicationTime(117, now, helper.MakeIdentity()))
	proposalDurationProvider.dur = time.Second
	assert.Equal(s.T(), now.Add(time.Second), pm.TargetPublicationTime(117, now, helper.MakeIdentity()))
}

func max(a uint64, values ...uint64) uint64 {
	for _, v := range values {
		if v > a {
			a = v
		}
	}
	return a
}
