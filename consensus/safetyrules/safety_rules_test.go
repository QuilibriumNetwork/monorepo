package safetyrules

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

func TestSafetyRules(t *testing.T) {
	suite.Run(t, new(SafetyRulesTestSuite))
}

// SafetyRulesTestSuite is a test suite for testing SafetyRules related functionality.
// SafetyRulesTestSuite setups mocks for injected modules and creates models.ConsensusState[*helper.TestVote]
// based on next configuration:
// R <- B[QC_R] <- P[QC_B]
// B.Rank = S.Rank + 1
// B - bootstrapped state, we are creating SafetyRules at state B
// Based on this LatestAcknowledgedRank = B.Rank and
type SafetyRulesTestSuite struct {
	suite.Suite

	bootstrapState   *models.State[*helper.TestState]
	proposal         *models.SignedProposal[*helper.TestState, *helper.TestVote]
	proposerIdentity models.Identity
	ourIdentity      models.Identity
	signer           *mocks.Signer[*helper.TestState, *helper.TestVote]
	persister        *mocks.ConsensusStore[*helper.TestVote]
	committee        *mocks.DynamicCommittee
	safetyData       *models.ConsensusState[*helper.TestVote]
	safety           *SafetyRules[*helper.TestState, *helper.TestVote]
}

func (s *SafetyRulesTestSuite) SetupTest() {
	s.ourIdentity = helper.MakeIdentity()
	s.signer = &mocks.Signer[*helper.TestState, *helper.TestVote]{}
	s.persister = &mocks.ConsensusStore[*helper.TestVote]{}
	s.committee = &mocks.DynamicCommittee{}
	s.proposerIdentity = helper.MakeIdentity()

	// bootstrap at random bootstrapState
	s.bootstrapState = helper.MakeState(helper.WithStateRank[*helper.TestState](100))
	s.proposal = helper.MakeSignedProposal(helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(
		helper.WithState[*helper.TestState](
			helper.MakeState[*helper.TestState](
				helper.WithParentState[*helper.TestState](s.bootstrapState),
				helper.WithStateRank[*helper.TestState](s.bootstrapState.Rank+1),
				helper.WithStateProposer[*helper.TestState](s.proposerIdentity)),
		))))

	s.committee.On("Self").Return(s.ourIdentity).Maybe()
	s.committee.On("LeaderForRank", mock.Anything).Return(s.proposerIdentity, nil).Maybe()
	s.committee.On("IdentityByState", mock.Anything, s.ourIdentity).Return(&helper.TestWeightedIdentity{ID: s.ourIdentity}, nil).Maybe()
	s.committee.On("IdentityByState", s.proposal.State.Identifier, s.proposal.State.ProposerID).Return(&helper.TestWeightedIdentity{ID: s.proposerIdentity}, nil).Maybe()
	s.committee.On("IdentityByRank", mock.Anything, s.ourIdentity).Return(&helper.TestWeightedIdentity{ID: s.ourIdentity}, nil).Maybe()

	s.safetyData = &models.ConsensusState[*helper.TestVote]{
		FinalizedRank:          s.bootstrapState.Rank,
		LatestAcknowledgedRank: s.bootstrapState.Rank,
	}

	s.persister.On("GetConsensusState", mock.Anything).Return(s.safetyData, nil).Once()
	var err error
	s.safety, err = NewSafetyRules(nil, s.signer, s.persister, s.committee)
	require.NoError(s.T(), err)
}

// TestProduceVote_ShouldVote test basic happy path scenario where we vote for first state after bootstrap
// and next rank ended with TC
func (s *SafetyRulesTestSuite) TestProduceVote_ShouldVote() {
	expectedSafetyData := &models.ConsensusState[*helper.TestVote]{
		FinalizedRank:          s.proposal.State.ParentQuorumCertificate.GetRank(),
		LatestAcknowledgedRank: s.proposal.State.Rank,
	}

	expectedVote := makeVote(s.proposal.State)
	s.signer.On("CreateVote", s.proposal.State).Return(&expectedVote, nil).Once()
	s.persister.On("PutConsensusState", expectedSafetyData).Return(nil).Once()

	vote, err := s.safety.ProduceVote(s.proposal, s.proposal.State.Rank)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), vote)
	require.Equal(s.T(), &expectedVote, vote)

	s.persister.AssertCalled(s.T(), "PutConsensusState", expectedSafetyData)

	// producing vote for same rank yields an error since we have voted already for this rank
	otherVote, err := s.safety.ProduceVote(s.proposal, s.proposal.State.Rank)
	require.True(s.T(), models.IsNoVoteError(err))
	require.Nil(s.T(), otherVote)

	previousRankTimeoutCert := helper.MakeTC(
		helper.WithTCRank(s.proposal.State.Rank+1),
		helper.WithTCNewestQC(s.proposal.State.ParentQuorumCertificate))

	// voting on proposal where last rank ended with TC
	proposalWithTC := helper.MakeSignedProposal(helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal[*helper.TestState](
		helper.WithState[*helper.TestState](
			helper.MakeState[*helper.TestState](
				helper.WithParentState[*helper.TestState](s.bootstrapState),
				helper.WithStateRank[*helper.TestState](s.proposal.State.Rank+2),
				helper.WithStateProposer[*helper.TestState](s.proposerIdentity))),
		helper.WithPreviousRankTimeoutCertificate[*helper.TestState](previousRankTimeoutCert))))

	expectedSafetyData = &models.ConsensusState[*helper.TestVote]{
		FinalizedRank:          s.proposal.State.ParentQuorumCertificate.GetRank(),
		LatestAcknowledgedRank: proposalWithTC.State.Rank,
	}

	expectedVote = makeVote(proposalWithTC.State)
	s.signer.On("CreateVote", proposalWithTC.State).Return(&expectedVote, nil).Once()
	s.persister.On("PutConsensusState", expectedSafetyData).Return(nil).Once()
	s.committee.On("IdentityByState", proposalWithTC.State.Identifier, proposalWithTC.State.ProposerID).Return(&helper.TestWeightedIdentity{ID: s.proposerIdentity}, nil).Maybe()

	vote, err = s.safety.ProduceVote(proposalWithTC, proposalWithTC.State.Rank)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), vote)
	require.Equal(s.T(), &expectedVote, vote)
	s.signer.AssertExpectations(s.T())
	s.persister.AssertCalled(s.T(), "PutConsensusState", expectedSafetyData)
}

// TestProduceVote_IncludedQCHigherThanTCsQC checks specific scenario where previous round resulted in TC and leader
// knows about QC which is not part of TC and qc.Rank > tc.NewestQC.Rank. We want to allow this, in this case leader
// includes their QC into proposal satisfies next condition: State.ParentQuorumCertificate.GetRank() > previousRankTimeoutCert.NewestQC.Rank
func (s *SafetyRulesTestSuite) TestProduceVote_IncludedQCHigherThanTCsQC() {
	previousRankTimeoutCert := helper.MakeTC(
		helper.WithTCRank(s.proposal.State.Rank+1),
		helper.WithTCNewestQC(s.proposal.State.ParentQuorumCertificate))

	// voting on proposal where last rank ended with TC
	proposalWithTC := helper.MakeSignedProposal(helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal[*helper.TestState](
		helper.WithState[*helper.TestState](
			helper.MakeState[*helper.TestState](
				helper.WithParentState[*helper.TestState](s.proposal.State),
				helper.WithStateRank[*helper.TestState](s.proposal.State.Rank+2),
				helper.WithStateProposer[*helper.TestState](s.proposerIdentity))),
		helper.WithPreviousRankTimeoutCertificate[*helper.TestState](previousRankTimeoutCert))))

	expectedSafetyData := &models.ConsensusState[*helper.TestVote]{
		FinalizedRank:          proposalWithTC.State.ParentQuorumCertificate.GetRank(),
		LatestAcknowledgedRank: proposalWithTC.State.Rank,
	}

	require.Greater(s.T(), proposalWithTC.State.ParentQuorumCertificate.GetRank(), proposalWithTC.PreviousRankTimeoutCertificate.GetLatestQuorumCert().GetRank(),
		"for this test case we specifically require that qc.Rank > previousRankTimeoutCert.NewestQC.Rank")

	expectedVote := makeVote(proposalWithTC.State)
	s.signer.On("CreateVote", proposalWithTC.State).Return(&expectedVote, nil).Once()
	s.persister.On("PutConsensusState", expectedSafetyData).Return(nil).Once()
	s.committee.On("IdentityByState", proposalWithTC.State.Identifier, proposalWithTC.State.ProposerID).Return(&helper.TestWeightedIdentity{ID: s.proposerIdentity}, nil).Maybe()

	vote, err := s.safety.ProduceVote(proposalWithTC, proposalWithTC.State.Rank)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), vote)
	require.Equal(s.T(), &expectedVote, vote)
	s.signer.AssertExpectations(s.T())
	s.persister.AssertCalled(s.T(), "PutConsensusState", expectedSafetyData)
}

// TestProduceVote_UpdateFinalizedRank tests that FinalizedRank is updated when sees a higher QC.
// Note: `FinalizedRank` is only updated when the replica votes.
func (s *SafetyRulesTestSuite) TestProduceVote_UpdateFinalizedRank() {
	s.safety.consensusState.FinalizedRank = 0

	require.NotEqual(s.T(), s.safety.consensusState.FinalizedRank, s.proposal.State.ParentQuorumCertificate.GetRank(),
		"in this test FinalizedRank is lower so it needs to be updated")

	expectedSafetyData := &models.ConsensusState[*helper.TestVote]{
		FinalizedRank:          s.proposal.State.ParentQuorumCertificate.GetRank(),
		LatestAcknowledgedRank: s.proposal.State.Rank,
	}

	expectedVote := makeVote(s.proposal.State)
	s.signer.On("CreateVote", s.proposal.State).Return(&expectedVote, nil).Once()
	s.persister.On("PutConsensusState", expectedSafetyData).Return(nil).Once()

	vote, err := s.safety.ProduceVote(s.proposal, s.proposal.State.Rank)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), vote)
	require.Equal(s.T(), &expectedVote, vote)
	s.signer.AssertExpectations(s.T())
	s.persister.AssertCalled(s.T(), "PutConsensusState", expectedSafetyData)
}

// TestProduceVote_InvalidCurrentRank tests that no vote is created if `curRank` has invalid values.
// In particular, `SafetyRules` requires that:
//   - the state's rank matches `curRank`
//   - that values for `curRank` are monotonicly increasing
//
// Failing any of these conditions is a symptom of an internal bug; hence `SafetyRules` should
// _not_ return a `NoVoteError`.
func (s *SafetyRulesTestSuite) TestProduceVote_InvalidCurrentRank() {

	s.Run("state-rank-does-not-match", func() {
		vote, err := s.safety.ProduceVote(s.proposal, s.proposal.State.Rank+1)
		require.Nil(s.T(), vote)
		require.Error(s.T(), err)
		require.False(s.T(), models.IsNoVoteError(err))
	})
	s.Run("rank-not-monotonicly-increasing", func() {
		// create state with rank < LatestAcknowledgedRank
		proposal := helper.MakeSignedProposal(helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(
			helper.WithState(
				helper.MakeState(
					func(state *models.State[*helper.TestState]) {
						state.ParentQuorumCertificate = helper.MakeQC(helper.WithQCRank(s.safetyData.LatestAcknowledgedRank - 2))
					},
					helper.WithStateRank[*helper.TestState](s.safetyData.LatestAcknowledgedRank-1))))))
		vote, err := s.safety.ProduceVote(proposal, proposal.State.Rank)
		require.Nil(s.T(), vote)
		require.Error(s.T(), err)
		require.False(s.T(), models.IsNoVoteError(err))
	})

	s.persister.AssertNotCalled(s.T(), "PutConsensusState")
}

// TestProduceVote_CommitteeLeaderException verifies that SafetyRules handles unexpected error returns from
// the DynamicCommittee correctly. Specifically, generic exceptions and `models.ErrRankUnknown`
// returned by the committee when requesting the leader for the state's rank is propagated up the call stack.
// SafetyRules should *not* wrap unexpected exceptions into an expected NoVoteError.
func (s *SafetyRulesTestSuite) TestProduceVote_CommitteeLeaderException() {
	*s.committee = mocks.DynamicCommittee{}
	for _, exception := range []error{
		errors.New("invalid-leader-identity"),
		models.ErrRankUnknown,
	} {
		s.committee.On("LeaderForRank", s.proposal.State.Rank).Return("", exception).Once()
		vote, err := s.safety.ProduceVote(s.proposal, s.proposal.State.Rank)
		require.Nil(s.T(), vote)
		require.ErrorIs(s.T(), err, exception)
		require.False(s.T(), models.IsNoVoteError(err))
		s.persister.AssertNotCalled(s.T(), "PutConsensusState")
	}
}

// TestProduceVote_DifferentProposerFromLeader tests that no vote is created if the proposer is different from the leader for
// current rank. This is a byzantine behavior and should be handled by the compliance layer but nevertheless we want to
// have a sanity check for other code paths like voting on an own proposal created by the current leader.
func (s *SafetyRulesTestSuite) TestProduceVote_DifferentProposerFromLeader() {
	s.proposal.State.ProposerID = helper.MakeIdentity()
	vote, err := s.safety.ProduceVote(s.proposal, s.proposal.State.Rank)
	require.Error(s.T(), err)
	require.False(s.T(), models.IsNoVoteError(err))
	require.Nil(s.T(), vote)
	s.persister.AssertNotCalled(s.T(), "PutConsensusState")
}

// TestProduceVote_NodeEjected tests that no vote is created if state proposer is ejected
func (s *SafetyRulesTestSuite) TestProduceVote_ProposerEjected() {
	*s.committee = mocks.DynamicCommittee{}
	s.committee.On("Self").Return(s.ourIdentity).Maybe()
	s.committee.On("IdentityByState", s.proposal.State.Identifier, s.proposal.State.ProposerID).Return(nil, models.NewInvalidSignerErrorf("node-ejected")).Once()
	s.committee.On("LeaderForRank", s.proposal.State.Rank).Return(s.proposerIdentity, nil).Once()

	vote, err := s.safety.ProduceVote(s.proposal, s.proposal.State.Rank)
	require.Nil(s.T(), vote)
	require.True(s.T(), models.IsNoVoteError(err))
	s.persister.AssertNotCalled(s.T(), "PutConsensusState")
}

// TestProduceVote_InvalidProposerIdentity tests that no vote is created if there was an exception retrieving proposer identity
// We are specifically testing that unexpected errors are handled correctly, i.e.
// that SafetyRules does not erroneously wrap unexpected exceptions into the expected NoVoteError.
func (s *SafetyRulesTestSuite) TestProduceVote_InvalidProposerIdentity() {
	*s.committee = mocks.DynamicCommittee{}
	exception := errors.New("invalid-signer-identity")
	s.committee.On("Self").Return(s.ourIdentity).Maybe()
	s.committee.On("LeaderForRank", s.proposal.State.Rank).Return(s.proposerIdentity, nil).Once()
	s.committee.On("IdentityByState", s.proposal.State.Identifier, s.proposal.State.ProposerID).Return(nil, exception).Once()

	vote, err := s.safety.ProduceVote(s.proposal, s.proposal.State.Rank)
	require.Nil(s.T(), vote)
	require.ErrorIs(s.T(), err, exception)
	require.False(s.T(), models.IsNoVoteError(err))
	s.persister.AssertNotCalled(s.T(), "PutConsensusState")
}

// TestProduceVote_NodeNotAuthorizedToVote tests that no vote is created if the voter is not authorized to vote.
// Nodes have zero weight in the grace periods around the ranks where they are authorized to participate.
// We don't want zero-weight nodes to vote in the first place, to avoid unnecessary traffic.
// Note: this also covers ejected nodes. In both cases, the committee will return an `InvalidSignerError`.
func (s *SafetyRulesTestSuite) TestProduceVote_NodeEjected() {
	*s.committee = mocks.DynamicCommittee{}
	s.committee.On("Self").Return(s.ourIdentity)
	s.committee.On("LeaderForRank", s.proposal.State.Rank).Return(s.proposerIdentity, nil).Once()
	s.committee.On("IdentityByState", s.proposal.State.Identifier, s.proposal.State.ProposerID).Return(&helper.TestWeightedIdentity{ID: s.proposerIdentity}, nil).Maybe()
	s.committee.On("IdentityByState", s.proposal.State.Identifier, s.ourIdentity).Return(nil, models.NewInvalidSignerErrorf("node-ejected")).Once()

	vote, err := s.safety.ProduceVote(s.proposal, s.proposal.State.Rank)
	require.Nil(s.T(), vote)
	require.True(s.T(), models.IsNoVoteError(err))
	s.persister.AssertNotCalled(s.T(), "PutConsensusState")
}

// TestProduceVote_InvalidVoterIdentity tests that no vote is created if there was an exception retrieving voter identity
// We are specifically testing that unexpected errors are handled correctly, i.e.
// that SafetyRules does not erroneously wrap unexpected exceptions into the expected NoVoteError.
func (s *SafetyRulesTestSuite) TestProduceVote_InvalidVoterIdentity() {
	*s.committee = mocks.DynamicCommittee{}
	s.committee.On("Self").Return(s.ourIdentity)
	exception := errors.New("invalid-signer-identity")
	s.committee.On("LeaderForRank", s.proposal.State.Rank).Return(s.proposerIdentity, nil).Once()
	s.committee.On("IdentityByState", s.proposal.State.Identifier, s.proposal.State.ProposerID).Return(&helper.TestWeightedIdentity{ID: s.proposerIdentity}, nil).Maybe()
	s.committee.On("IdentityByState", s.proposal.State.Identifier, s.ourIdentity).Return(nil, exception).Once()

	vote, err := s.safety.ProduceVote(s.proposal, s.proposal.State.Rank)
	require.Nil(s.T(), vote)
	require.ErrorIs(s.T(), err, exception)
	require.False(s.T(), models.IsNoVoteError(err))
	s.persister.AssertNotCalled(s.T(), "PutConsensusState")
}

// TestProduceVote_CreateVoteException tests that no vote is created if vote creation raised an exception
func (s *SafetyRulesTestSuite) TestProduceVote_CreateVoteException() {
	exception := errors.New("create-vote-exception")
	s.signer.On("CreateVote", s.proposal.State).Return(nil, exception).Once()
	vote, err := s.safety.ProduceVote(s.proposal, s.proposal.State.Rank)
	require.Nil(s.T(), vote)
	require.ErrorIs(s.T(), err, exception)
	require.False(s.T(), models.IsNoVoteError(err))
	s.persister.AssertNotCalled(s.T(), "PutConsensusState")
}

// TestProduceVote_PersistStateException tests that no vote is created if persisting state failed
func (s *SafetyRulesTestSuite) TestProduceVote_PersistStateException() {
	exception := errors.New("persister-exception")
	s.persister.On("PutConsensusState", mock.Anything).Return(exception)

	vote := makeVote(s.proposal.State)
	s.signer.On("CreateVote", s.proposal.State).Return(&vote, nil).Once()
	votePtr, err := s.safety.ProduceVote(s.proposal, s.proposal.State.Rank)
	require.Nil(s.T(), votePtr)
	require.ErrorIs(s.T(), err, exception)
}

// TestProduceVote_VotingOnInvalidProposals tests different scenarios where we try to vote on unsafe states
// SafetyRules contain a variety of checks to confirm that QC and TC have the desired relationship to each other.
// In particular, we test:
//
//	  (i) A TC should be included in a proposal, if and only of the QC is not the prior rank.
//	 (ii) When the proposal includes a TC (i.e. the QC not being for the prior rank), the TC must be for the prior rank.
//	(iii) The QC in the state must have a smaller rank than the state.
//	 (iv) If the state contains a TC, the TC cannot contain a newer QC than the state itself.
//
// Conditions (i) - (iv) are validity requirements for the state and all states that SafetyRules processes
// are supposed to be pre-validated. Hence, failing any of those conditions means we have an internal bug.
// Consequently, we expect SafetyRules to return exceptions but _not_ `NoVoteError`, because the latter
// indicates that the input state was valid, but we didn't want to vote.
func (s *SafetyRulesTestSuite) TestProduceVote_VotingOnInvalidProposals() {

	// a proposal which includes a QC for the previous round should not contain a TC
	s.Run("proposal-includes-last-rank-qc-and-tc", func() {
		proposal := helper.MakeSignedProposal(helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(
			helper.WithState(
				helper.MakeState(
					helper.WithParentState(s.bootstrapState),
					helper.WithStateRank[*helper.TestState](s.bootstrapState.Rank+1))),
			helper.WithPreviousRankTimeoutCertificate[*helper.TestState](helper.MakeTC()))))
		s.committee.On("IdentityByState", proposal.State.Identifier, proposal.State.ProposerID).Return(&helper.TestWeightedIdentity{ID: s.proposerIdentity}, nil).Maybe()
		vote, err := s.safety.ProduceVote(proposal, proposal.State.Rank)
		require.Error(s.T(), err)
		require.False(s.T(), models.IsNoVoteError(err))
		require.Nil(s.T(), vote)
	})
	s.Run("no-last-rank-tc", func() {
		// create state where State.Rank != State.ParentQuorumCertificate.GetRank()+1 and PreviousRankTimeoutCertificate = nil
		proposal := helper.MakeSignedProposal(helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(
			helper.WithState(
				helper.MakeState(
					helper.WithParentState(s.bootstrapState),
					helper.WithStateRank[*helper.TestState](s.bootstrapState.Rank+2))))))
		vote, err := s.safety.ProduceVote(proposal, proposal.State.Rank)
		require.Error(s.T(), err)
		require.False(s.T(), models.IsNoVoteError(err))
		require.Nil(s.T(), vote)
	})
	s.Run("last-rank-tc-invalid-rank", func() {
		// create state where State.Rank != State.ParentQuorumCertificate.GetRank()+1 and
		// State.Rank != PreviousRankTimeoutCertificate.Rank+1
		proposal := helper.MakeSignedProposal(helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(
			helper.WithState(
				helper.MakeState(
					helper.WithParentState(s.bootstrapState),
					helper.WithStateRank[*helper.TestState](s.bootstrapState.Rank+2))),
			helper.WithPreviousRankTimeoutCertificate[*helper.TestState](
				helper.MakeTC(
					helper.WithTCRank(s.bootstrapState.Rank))))))
		vote, err := s.safety.ProduceVote(proposal, proposal.State.Rank)
		require.Error(s.T(), err)
		require.False(s.T(), models.IsNoVoteError(err))
		require.Nil(s.T(), vote)
	})
	s.Run("proposal-includes-QC-for-higher-rank", func() {
		// create state where State.Rank != State.ParentQuorumCertificate.GetRank()+1 and
		// State.Rank == PreviousRankTimeoutCertificate.Rank+1 and State.ParentQuorumCertificate.GetRank() >= State.Rank
		// in this case state is not safe to extend since proposal includes QC which is newer than the proposal itself.
		proposal := helper.MakeSignedProposal(helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(
			helper.WithState(
				helper.MakeState(
					helper.WithParentState(s.bootstrapState),
					helper.WithStateRank[*helper.TestState](s.bootstrapState.Rank+2),
					func(state *models.State[*helper.TestState]) {
						state.ParentQuorumCertificate = helper.MakeQC(helper.WithQCRank(s.bootstrapState.Rank + 10))
					})),
			helper.WithPreviousRankTimeoutCertificate[*helper.TestState](
				helper.MakeTC(
					helper.WithTCRank(s.bootstrapState.Rank+1))))))
		vote, err := s.safety.ProduceVote(proposal, proposal.State.Rank)
		require.Error(s.T(), err)
		require.False(s.T(), models.IsNoVoteError(err))
		require.Nil(s.T(), vote)
	})
	s.Run("last-rank-tc-invalid-highest-qc", func() {
		// create state where State.Rank != State.ParentQuorumCertificate.GetRank()+1 and
		// State.Rank == PreviousRankTimeoutCertificate.Rank+1 and State.ParentQuorumCertificate.GetRank() < PreviousRankTimeoutCertificate.NewestQC.Rank
		// in this case state is not safe to extend since proposal is built on top of QC, which is lower
		// than QC presented in PreviousRankTimeoutCertificate.
		TONewestQC := helper.MakeQC(helper.WithQCRank(s.bootstrapState.Rank + 1))
		proposal := helper.MakeSignedProposal(helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(
			helper.WithState(
				helper.MakeState(
					helper.WithParentState(s.bootstrapState),
					helper.WithStateRank[*helper.TestState](s.bootstrapState.Rank+2))),
			helper.WithPreviousRankTimeoutCertificate[*helper.TestState](
				helper.MakeTC(
					helper.WithTCRank(s.bootstrapState.Rank+1),
					helper.WithTCNewestQC(TONewestQC))))))
		vote, err := s.safety.ProduceVote(proposal, proposal.State.Rank)
		require.Error(s.T(), err)
		require.False(s.T(), models.IsNoVoteError(err))
		require.Nil(s.T(), vote)
	})

	s.signer.AssertNotCalled(s.T(), "CreateVote")
	s.persister.AssertNotCalled(s.T(), "PutConsensusState")
}

// TestProduceVote_VoteEquivocation tests scenario when we try to vote twice in same rank. We require that replica
// follows next rules:
//   - replica votes once per rank
//   - replica votes in monotonicly increasing ranks
//
// Voting twice per round on equivocating proposals is considered a byzantine behavior.
// Expect a `models.NoVoteError` sentinel in such scenario.
func (s *SafetyRulesTestSuite) TestProduceVote_VoteEquivocation() {
	expectedVote := makeVote(s.proposal.State)
	s.signer.On("CreateVote", s.proposal.State).Return(&expectedVote, nil).Once()
	s.persister.On("PutConsensusState", mock.Anything).Return(nil).Once()

	vote, err := s.safety.ProduceVote(s.proposal, s.proposal.State.Rank)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), vote)
	require.Equal(s.T(), &expectedVote, vote)

	equivocatingProposal := helper.MakeSignedProposal(helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(
		helper.WithState(
			helper.MakeState(
				helper.WithParentState(s.bootstrapState),
				helper.WithStateRank[*helper.TestState](s.bootstrapState.Rank+1),
				helper.WithStateProposer[*helper.TestState](s.proposerIdentity)),
		))))

	// voting at same rank(even different proposal) should result in NoVoteError
	vote, err = s.safety.ProduceVote(equivocatingProposal, s.proposal.State.Rank)
	require.True(s.T(), models.IsNoVoteError(err))
	require.Nil(s.T(), vote)

	s.proposal.State.ProposerID = s.ourIdentity

	// proposing at the same rank should result in NoVoteError since we have already voted
	vote, err = s.safety.SignOwnProposal(&s.proposal.Proposal)
	require.True(s.T(), models.IsNoVoteError(err))
	require.Nil(s.T(), vote)
}

// TestProduceVote_AfterTimeout tests a scenario where we first timeout for rank and then try to produce a vote for
// same rank, this should result in error since producing a timeout means that we have given up on this rank
// and are in process of moving forward, no vote should be created.
func (s *SafetyRulesTestSuite) TestProduceVote_AfterTimeout() {
	rank := s.proposal.State.Rank
	newestQC := helper.MakeQC(helper.WithQCRank(rank - 1))
	expectedTimeout := &models.TimeoutState[*helper.TestVote]{
		Rank:                    rank,
		LatestQuorumCertificate: newestQC,
	}
	s.signer.On("CreateTimeout", rank, newestQC, nil).Return(expectedTimeout, nil).Once()
	s.persister.On("PutConsensusState", mock.Anything).Return(nil).Once()

	// first timeout, then try to vote
	timeout, err := s.safety.ProduceTimeout(rank, newestQC, nil)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), timeout)

	// voting in same rank after producing timeout is not allowed
	vote, err := s.safety.ProduceVote(s.proposal, rank)
	require.True(s.T(), models.IsNoVoteError(err))
	require.Nil(s.T(), vote)

	s.signer.AssertExpectations(s.T())
	s.persister.AssertExpectations(s.T())
}

// TestProduceTimeout_ShouldTimeout tests that we can produce timeout in cases where
// last rank was successful or not. Also tests last timeout caching.
func (s *SafetyRulesTestSuite) TestProduceTimeout_ShouldTimeout() {
	rank := s.proposal.State.Rank
	newestQC := helper.MakeQC(helper.WithQCRank(rank - 1))
	expectedTimeout := &models.TimeoutState[*helper.TestVote]{
		Rank:                    rank,
		LatestQuorumCertificate: newestQC,
		// don't care about actual data
		Vote: helper.MakeVote[*helper.TestVote](),
	}

	expectedSafetyData := &models.ConsensusState[*helper.TestVote]{
		FinalizedRank:          s.safetyData.FinalizedRank,
		LatestAcknowledgedRank: rank,
		LatestTimeout:          expectedTimeout,
	}
	s.signer.On("CreateTimeout", rank, newestQC, nil).Return(expectedTimeout, nil).Once()
	s.persister.On("PutConsensusState", expectedSafetyData).Return(nil).Once()
	timeout, err := s.safety.ProduceTimeout(rank, newestQC, nil)
	require.NoError(s.T(), err)
	require.Equal(s.T(), expectedTimeout, timeout)

	s.persister.AssertCalled(s.T(), "PutConsensusState", expectedSafetyData)

	s.persister.On("PutConsensusState", mock.MatchedBy(func(s *models.ConsensusState[*helper.TestVote]) bool {
		return s.LatestTimeout.TimeoutTick == 1
	})).Return(nil).Once()

	otherTimeout, err := s.safety.ProduceTimeout(rank, newestQC, nil)
	require.NoError(s.T(), err)
	require.True(s.T(), timeout.Equals(otherTimeout))
	require.Equal(s.T(), timeout.TimeoutTick+1, otherTimeout.TimeoutTick)

	// to create new TO we need to provide a TC
	previousRankTimeoutCert := helper.MakeTC(helper.WithTCRank(rank),
		helper.WithTCNewestQC(newestQC))

	expectedTimeout = &models.TimeoutState[*helper.TestVote]{
		Rank:                        rank + 1,
		LatestQuorumCertificate:     newestQC,
		PriorRankTimeoutCertificate: previousRankTimeoutCert,
	}
	s.signer.On("CreateTimeout", rank+1, newestQC, previousRankTimeoutCert).Return(expectedTimeout, nil).Once()
	expectedSafetyData = &models.ConsensusState[*helper.TestVote]{
		FinalizedRank:          s.safetyData.FinalizedRank,
		LatestAcknowledgedRank: rank + 1,
		LatestTimeout:          expectedTimeout,
	}
	s.persister.On("PutConsensusState", expectedSafetyData).Return(nil).Once()

	// creating new timeout should invalidate cache
	otherTimeout, err = s.safety.ProduceTimeout(rank+1, newestQC, previousRankTimeoutCert)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), otherTimeout)
}

// TestProduceTimeout_NotSafeToTimeout tests that we don't produce a timeout when it's not safe
// We expect that the EventHandler to feed only request timeouts for the current rank, providing valid set of inputs.
// Hence, the cases tested here would be symptoms of an internal bugs, and therefore should not result in an NoVoteError.
func (s *SafetyRulesTestSuite) TestProduceTimeout_NotSafeToTimeout() {

	s.Run("newest-qc-nil", func() {
		// newestQC cannot be nil
		timeout, err := s.safety.ProduceTimeout(s.safetyData.FinalizedRank, nil, nil)
		require.Error(s.T(), err)
		require.Nil(s.T(), timeout)
	})
	// if a QC for the previous rank is provided, a last rank TC is unnecessary and must not be provided
	s.Run("includes-last-rank-qc-and-tc", func() {
		newestQC := helper.MakeQC(helper.WithQCRank(s.safetyData.FinalizedRank))

		// tc not needed but included
		timeout, err := s.safety.ProduceTimeout(newestQC.GetRank()+1, newestQC, helper.MakeTC())
		require.Error(s.T(), err)
		require.Nil(s.T(), timeout)
	})
	s.Run("last-rank-tc-nil", func() {
		newestQC := helper.MakeQC(helper.WithQCRank(s.safetyData.FinalizedRank))

		// tc needed but not included
		timeout, err := s.safety.ProduceTimeout(newestQC.GetRank()+2, newestQC, nil)
		require.Error(s.T(), err)
		require.Nil(s.T(), timeout)
	})
	s.Run("last-rank-tc-for-wrong-rank", func() {
		newestQC := helper.MakeQC(helper.WithQCRank(s.safetyData.FinalizedRank))
		// previousRankTimeoutCert should be for newestQC.GetRank()+1
		previousRankTimeoutCert := helper.MakeTC(helper.WithTCRank(newestQC.GetRank()))

		timeout, err := s.safety.ProduceTimeout(newestQC.GetRank()+2, newestQC, previousRankTimeoutCert)
		require.Error(s.T(), err)
		require.Nil(s.T(), timeout)
	})
	s.Run("cur-rank-equal-to-highest-QC", func() {
		newestQC := helper.MakeQC(helper.WithQCRank(s.safetyData.FinalizedRank))
		previousRankTimeoutCert := helper.MakeTC(helper.WithTCRank(s.safetyData.FinalizedRank - 1))

		timeout, err := s.safety.ProduceTimeout(s.safetyData.FinalizedRank, newestQC, previousRankTimeoutCert)
		require.Error(s.T(), err)
		require.Nil(s.T(), timeout)
	})
	s.Run("cur-rank-below-highest-QC", func() {
		newestQC := helper.MakeQC(helper.WithQCRank(s.safetyData.FinalizedRank))
		previousRankTimeoutCert := helper.MakeTC(helper.WithTCRank(newestQC.GetRank() - 2))

		timeout, err := s.safety.ProduceTimeout(newestQC.GetRank()-1, newestQC, previousRankTimeoutCert)
		require.Error(s.T(), err)
		require.Nil(s.T(), timeout)
	})
	s.Run("last-rank-tc-is-newer", func() {
		newestQC := helper.MakeQC(helper.WithQCRank(s.safetyData.FinalizedRank))
		// newest QC included in TC cannot be higher than the newest QC known to replica
		previousRankTimeoutCert := helper.MakeTC(helper.WithTCRank(newestQC.GetRank()+1),
			helper.WithTCNewestQC(helper.MakeQC(helper.WithQCRank(newestQC.GetRank()+1))))

		timeout, err := s.safety.ProduceTimeout(newestQC.GetRank()+2, newestQC, previousRankTimeoutCert)
		require.Error(s.T(), err)
		require.Nil(s.T(), timeout)
	})
	s.Run("highest-qc-below-locked-round", func() {
		newestQC := helper.MakeQC(helper.WithQCRank(s.safetyData.FinalizedRank - 1))

		timeout, err := s.safety.ProduceTimeout(newestQC.GetRank()+1, newestQC, nil)
		require.Error(s.T(), err)
		require.Nil(s.T(), timeout)
	})
	s.Run("cur-rank-below-highest-acknowledged-rank", func() {
		newestQC := helper.MakeQC(helper.WithQCRank(s.safetyData.FinalizedRank))
		// modify highest acknowledged rank in a way that it's definitely bigger than the newest QC rank
		s.safetyData.LatestAcknowledgedRank = newestQC.GetRank() + 10

		timeout, err := s.safety.ProduceTimeout(newestQC.GetRank()+1, newestQC, nil)
		require.Error(s.T(), err)
		require.Nil(s.T(), timeout)
	})

	s.signer.AssertNotCalled(s.T(), "CreateTimeout")
	s.signer.AssertNotCalled(s.T(), "PutConsensusState")
}

// TestProduceTimeout_CreateTimeoutException tests that no timeout is created if timeout creation raised an exception
func (s *SafetyRulesTestSuite) TestProduceTimeout_CreateTimeoutException() {
	rank := s.proposal.State.Rank
	newestQC := helper.MakeQC(helper.WithQCRank(rank - 1))

	exception := errors.New("create-timeout-exception")
	s.signer.On("CreateTimeout", rank, newestQC, nil).Return(nil, exception).Once()
	vote, err := s.safety.ProduceTimeout(rank, newestQC, nil)
	require.Nil(s.T(), vote)
	require.ErrorIs(s.T(), err, exception)
	require.False(s.T(), models.IsNoVoteError(err))
	s.persister.AssertNotCalled(s.T(), "PutConsensusState")
}

// TestProduceTimeout_PersistStateException tests that no timeout is created if persisting state failed
func (s *SafetyRulesTestSuite) TestProduceTimeout_PersistStateException() {
	exception := errors.New("persister-exception")
	s.persister.On("PutConsensusState", mock.Anything).Return(exception)

	rank := s.proposal.State.Rank
	newestQC := helper.MakeQC(helper.WithQCRank(rank - 1))
	expectedTimeout := &models.TimeoutState[*helper.TestVote]{
		Rank:                    rank,
		LatestQuorumCertificate: newestQC,
	}

	s.signer.On("CreateTimeout", rank, newestQC, nil).Return(expectedTimeout, nil).Once()
	timeout, err := s.safety.ProduceTimeout(rank, newestQC, nil)
	require.Nil(s.T(), timeout)
	require.ErrorIs(s.T(), err, exception)
}

// TestProduceTimeout_AfterVote tests a case where we first produce a vote and then try to timeout
// for same rank. This behavior is expected and should result in valid timeout without any errors.
func (s *SafetyRulesTestSuite) TestProduceTimeout_AfterVote() {
	expectedVote := makeVote(s.proposal.State)
	s.signer.On("CreateVote", s.proposal.State).Return(&expectedVote, nil).Once()
	s.persister.On("PutConsensusState", mock.Anything).Return(nil).Times(2)

	rank := s.proposal.State.Rank

	// first produce vote, then try to timeout
	vote, err := s.safety.ProduceVote(s.proposal, rank)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), vote)

	newestQC := helper.MakeQC(helper.WithQCRank(rank - 1))

	expectedTimeout := &models.TimeoutState[*helper.TestVote]{
		Rank:                    rank,
		LatestQuorumCertificate: newestQC,
	}

	s.signer.On("CreateTimeout", rank, newestQC, nil).Return(expectedTimeout, nil).Once()

	// timing out for same rank should be possible
	timeout, err := s.safety.ProduceTimeout(rank, newestQC, nil)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), timeout)

	s.persister.AssertExpectations(s.T())
	s.signer.AssertExpectations(s.T())
}

// TestProduceTimeout_InvalidProposerIdentity tests that no timeout is created if there was an exception retrieving proposer identity
// We are specifically testing that unexpected errors are handled correctly, i.e.
// that SafetyRules does not erroneously wrap unexpected exceptions into the expected models.NoTimeoutError.
func (s *SafetyRulesTestSuite) TestProduceTimeout_InvalidProposerIdentity() {
	rank := s.proposal.State.Rank
	newestQC := helper.MakeQC(helper.WithQCRank(rank - 1))
	*s.committee = mocks.DynamicCommittee{}
	exception := errors.New("invalid-signer-identity")
	s.committee.On("IdentityByRank", rank, s.ourIdentity).Return(nil, exception).Once()
	s.committee.On("Self").Return(s.ourIdentity)

	timeout, err := s.safety.ProduceTimeout(rank, newestQC, nil)
	require.Nil(s.T(), timeout)
	require.ErrorIs(s.T(), err, exception)
	require.False(s.T(), models.IsNoTimeoutError(err))
	s.persister.AssertNotCalled(s.T(), "PutConsensusState")
}

// TestProduceTimeout_NodeEjected tests that no timeout is created if the replica is not authorized to create timeout.
// Nodes have zero weight in the grace periods around the ranks where they are authorized to participate.
// We don't want zero-weight nodes to participate in the first place, to avoid unnecessary traffic.
// Note: this also covers ejected nodes. In both cases, the committee will return an `InvalidSignerError`.
func (s *SafetyRulesTestSuite) TestProduceTimeout_NodeEjected() {
	rank := s.proposal.State.Rank
	newestQC := helper.MakeQC(helper.WithQCRank(rank - 1))
	*s.committee = mocks.DynamicCommittee{}
	s.committee.On("Self").Return(s.ourIdentity)
	s.committee.On("IdentityByRank", rank, s.ourIdentity).Return(nil, models.NewInvalidSignerErrorf("")).Maybe()

	timeout, err := s.safety.ProduceTimeout(rank, newestQC, nil)
	require.Nil(s.T(), timeout)
	require.True(s.T(), models.IsNoTimeoutError(err))
	s.persister.AssertNotCalled(s.T(), "PutConsensusState")
}

// TestSignOwnProposal tests a happy path scenario where leader can sign their own proposal.
func (s *SafetyRulesTestSuite) TestSignOwnProposal() {
	s.proposal.State.ProposerID = s.ourIdentity
	expectedSafetyData := &models.ConsensusState[*helper.TestVote]{
		FinalizedRank:          s.proposal.State.ParentQuorumCertificate.GetRank(),
		LatestAcknowledgedRank: s.proposal.State.Rank,
	}
	expectedVote := makeVote(s.proposal.State)
	s.committee.On("LeaderForRank").Unset()
	s.committee.On("LeaderForRank", s.proposal.State.Rank).Return(s.ourIdentity, nil).Once()
	s.signer.On("CreateVote", s.proposal.State).Return(&expectedVote, nil).Once()
	s.persister.On("PutConsensusState", expectedSafetyData).Return(nil).Once()
	vote, err := s.safety.SignOwnProposal(&s.proposal.Proposal)
	require.NoError(s.T(), err)
	require.Equal(s.T(), vote, &expectedVote)
}

// TestSignOwnProposal_ProposalNotSelf tests that we cannot sign a proposal that is not ours. We
// verify that SafetyRules returns an exception and not the benign sentinel error NoVoteError.
func (s *SafetyRulesTestSuite) TestSignOwnProposal_ProposalNotSelf() {
	vote, err := s.safety.SignOwnProposal(&s.proposal.Proposal)
	require.Error(s.T(), err)
	require.False(s.T(), models.IsNoVoteError(err))
	require.Nil(s.T(), vote)
}

// TestSignOwnProposal_SelfInvalidLeader tests that we cannot sign a proposal if we are not the leader for the rank.
// We verify that SafetyRules returns and exception and does not the benign sentinel error NoVoteError.
func (s *SafetyRulesTestSuite) TestSignOwnProposal_SelfInvalidLeader() {
	s.proposal.State.ProposerID = s.ourIdentity
	otherID := helper.MakeIdentity()
	require.NotEqual(s.T(), otherID, s.ourIdentity)
	s.committee.On("LeaderForRank").Unset()
	s.committee.On("LeaderForRank", s.proposal.State.Rank).Return(otherID, nil).Once()
	vote, err := s.safety.SignOwnProposal(&s.proposal.Proposal)
	require.Error(s.T(), err)
	require.False(s.T(), models.IsNoVoteError(err))
	require.Nil(s.T(), vote)
}

// TestSignOwnProposal_ProposalEquivocation verifies that SafetyRules will refuse to sign multiple proposals for the same rank.
// We require that leader complies with the following next rules:
//   - leader proposes once per rank
//   - leader's proposals follow safety rules
//
// Signing repeatedly for one rank (either proposals or voting) can lead to equivocating (byzantine behavior).
// Expect a `models.NoVoteError` sentinel in such scenario.
func (s *SafetyRulesTestSuite) TestSignOwnProposal_ProposalEquivocation() {
	s.proposal.State.ProposerID = s.ourIdentity
	expectedSafetyData := &models.ConsensusState[*helper.TestVote]{
		FinalizedRank:          s.proposal.State.ParentQuorumCertificate.GetRank(),
		LatestAcknowledgedRank: s.proposal.State.Rank,
	}
	expectedVote := makeVote(s.proposal.State)
	s.committee.On("LeaderForRank").Unset()
	s.committee.On("LeaderForRank", s.proposal.State.Rank).Return(s.ourIdentity, nil).Once()
	s.signer.On("CreateVote", s.proposal.State).Return(&expectedVote, nil).Once()
	s.persister.On("PutConsensusState", expectedSafetyData).Return(nil).Once()

	vote, err := s.safety.SignOwnProposal(&s.proposal.Proposal)
	require.NoError(s.T(), err)
	require.Equal(s.T(), &expectedVote, vote)

	// signing same proposal again should return an error since we have already created a proposal for this rank
	vote, err = s.safety.SignOwnProposal(&s.proposal.Proposal)
	require.Error(s.T(), err)
	require.True(s.T(), models.IsNoVoteError(err))
	require.Nil(s.T(), vote)

	// voting for same rank should also return an error since we have already proposed
	vote, err = s.safety.ProduceVote(s.proposal, s.proposal.State.Rank)
	require.Error(s.T(), err)
	require.True(s.T(), models.IsNoVoteError(err))
	require.Nil(s.T(), vote)
}

func makeVote(state *models.State[*helper.TestState]) *helper.TestVote {
	return &helper.TestVote{
		StateID: state.Identifier,
		Rank:    state.Rank,
		ID:      helper.MakeIdentity(),
	}
}
