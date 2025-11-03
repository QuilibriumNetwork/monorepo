package votecollector

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/atomic"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/mocks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

func TestVoteProcessor(t *testing.T) {
	suite.Run(t, new(VoteProcessorTestSuite))
}

// VoteProcessorTestSuite is a test suite that holds mocked state for isolated testing of VoteProcessor.
type VoteProcessorTestSuite struct {
	VoteProcessorTestSuiteBase

	processor       *VoteProcessor[*helper.TestState, *helper.TestVote, *helper.TestPeer]
	allParticipants []models.WeightedIdentity
}

func (s *VoteProcessorTestSuite) SetupTest() {
	s.VoteProcessorTestSuiteBase.SetupTest()
	s.allParticipants = helper.WithWeightedIdentityList(14)
	votingProvider := mocks.NewVotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer](s.T())
	s.processor = &VoteProcessor[*helper.TestState, *helper.TestVote, *helper.TestPeer]{
		tracer:            helper.Logger(),
		state:             s.proposal.State,
		provingSigAggtor:  s.provingAggregator,
		onQCCreated:       s.onQCCreated,
		minRequiredWeight: s.minRequiredWeight,
		done:              *atomic.NewBool(false),
		allParticipants:   s.allParticipants,
		votingProvider:    votingProvider,
	}
}

// TestInitialState tests that State() and Status() return correct values after calling constructor
func (s *VoteProcessorTestSuite) TestInitialState() {
	require.Equal(s.T(), s.proposal.State, s.processor.State())
	require.Equal(s.T(), consensus.VoteCollectorStatusVerifying, s.processor.Status())
}

// TestProcess_VoteNotForProposal tests that vote should pass to validation only if it has correct
// rank and state ID matching proposal that is locked in VoteProcessor
func (s *VoteProcessorTestSuite) TestProcess_VoteNotForProposal() {
	v := helper.VoteForStateFixture(s.proposal.State)
	v.StateID = ""
	err := s.processor.Process(&v)
	require.ErrorAs(s.T(), err, &VoteForIncompatibleStateError)
	require.False(s.T(), models.IsInvalidVoteError[*helper.TestVote](err))

	v = helper.VoteForStateFixture(s.proposal.State)
	v.Rank = 0
	err = s.processor.Process(&v)
	require.ErrorAs(s.T(), err, &VoteForIncompatibleRankError)
	require.False(s.T(), models.IsInvalidVoteError[*helper.TestVote](err))

	s.provingAggregator.AssertNotCalled(s.T(), "Verify")
}

// TestProcess_InvalidSignature tests that VoteProcessor doesn't collect signatures for votes with invalid consensus.
// Checks are made for cases where both proving and threshold signatures were submitted.
func (s *VoteProcessorTestSuite) TestProcess_InvalidSignature() {
	exception := errors.New("unexpected-exception")

	// sentinel error from `InvalidSignerError` should be wrapped as `InvalidVoteError`
	voteA := helper.VoteForStateFixture(s.proposal.State)
	s.provingAggregator.On("Verify", voteA.ID, mock.Anything).Return(models.NewInvalidSignerErrorf("")).Once()
	err := s.processor.Process(&voteA)
	require.Error(s.T(), err)
	require.True(s.T(), models.IsInvalidVoteError[*helper.TestVote](err))
	require.True(s.T(), models.IsInvalidSignerError(err))

	// sentinel error from `ErrInvalidSignature` should be wrapped as `InvalidVoteError`
	voteB := helper.VoteForStateFixture(s.proposal.State)
	s.provingAggregator.On("Verify", voteB.ID, mock.Anything).Return(models.ErrInvalidSignature).Once()
	err = s.processor.Process(&voteB)
	require.Error(s.T(), err)
	require.True(s.T(), models.IsInvalidVoteError[*helper.TestVote](err))
	require.ErrorAs(s.T(), err, &models.ErrInvalidSignature)

	// unexpected errors from `Verify` should be propagated, but should _not_ be wrapped as `InvalidVoteError`
	voteC := helper.VoteForStateFixture(s.proposal.State)
	s.provingAggregator.On("Verify", voteC.ID, mock.Anything).Return(exception)
	err = s.processor.Process(&voteC)
	require.ErrorIs(s.T(), err, exception)                                 // unexpected errors from verifying the vote signature should be propagated
	require.False(s.T(), models.IsInvalidVoteError[*helper.TestVote](err)) // but not interpreted as an invalid vote

	s.provingAggregator.AssertNotCalled(s.T(), "TrustedAdd")
}

// TestProcess_TrustedAdd_Exception tests that unexpected exceptions returned by
// WeightedSignatureAggregator.TrustedAdd(..) are _not_ interpreted as invalid votes
func (s *VoteProcessorTestSuite) TestProcess_TrustedAdd_Exception() {
	exception := errors.New("unexpected-exception")
	provingVote := helper.VoteForStateFixture(s.proposal.State)
	s.provingAggregator = mocks.NewWeightedSignatureAggregator(s.T())
	s.provingAggregator.On("Verify", provingVote.ID, mock.Anything).Return(nil).Once()
	s.provingAggregator.On("TrustedAdd", provingVote.ID, mock.Anything).Return(uint64(0), exception).Once()
	s.processor.provingSigAggtor = s.provingAggregator
	err := s.processor.Process(&provingVote)
	require.ErrorIs(s.T(), err, exception)
	require.False(s.T(), models.IsInvalidVoteError[*helper.TestVote](err))
	s.provingAggregator.AssertExpectations(s.T())
}

// TestProcess_BuildQCError tests error path during process of building QC.
// Building QC is a one time operation, we need to make sure that failing in one of the steps leads to exception.
func (s *VoteProcessorTestSuite) TestProcess_BuildQCError() {
	// In this test we will mock all dependencies for happy path, and replace some branches with unhappy path
	// to simulate errors along the branches.
	vote := helper.VoteForStateFixture(s.proposal.State)

	// in this test case we aren't able to aggregate proving signature
	exception := errors.New("proving-aggregate-exception")
	provingSigAggregator := mocks.NewWeightedSignatureAggregator(s.T())
	provingSigAggregator.On("Verify", mock.Anything, mock.Anything).Return(nil).Once()
	provingSigAggregator.On("TrustedAdd", mock.Anything, mock.Anything).Return(s.minRequiredWeight, nil).Once()
	provingSigAggregator.On("Aggregate").Return(nil, nil, exception).Once()

	s.processor.provingSigAggtor = provingSigAggregator
	err := s.processor.Process(&vote)
	require.ErrorIs(s.T(), err, exception)
	provingSigAggregator.AssertExpectations(s.T())
}

// TestProcess_NotEnoughWeight tests a scenario where we first don't have enough weight,
// then we iteratively increase it to the point where we have enough proving weight. No QC should be created.
func (s *VoteProcessorTestSuite) TestProcess_NotEnoughWeight() {
	for i := s.sigWeight; i < s.minRequiredWeight; i += s.sigWeight {
		vote := helper.VoteForStateFixture(s.proposal.State)
		s.provingAggregator.On("Verify", vote.ID, []byte(vote.Signature)).Return(nil).Once()
		err := s.processor.Process(&vote)
		require.NoError(s.T(), err)
	}
	require.False(s.T(), s.processor.done.Load())
	s.onQCCreatedState.AssertNotCalled(s.T(), "onQCCreated")
	s.provingAggregator.AssertExpectations(s.T())
}

// TestProcess_CreatingQC tests a scenario when we have collected enough proving weight
// and proceed to build QC. Created QC has to have all signatures and identities aggregated by
// aggregator.
func (s *VoteProcessorTestSuite) TestProcess_CreatingQC() {
	// prepare test setup: 13 votes with proving sigs
	provingSigners := s.allParticipants[:14]
	signerIndices := []byte{0b11111111, 0b00011111}

	// setup aggregator
	s.provingAggregator = mocks.NewWeightedSignatureAggregator(s.T())
	expectedSig := &helper.TestAggregatedSignature{
		Signature: make([]byte, 74),
		PublicKey: make([]byte, 585),
		Bitmask:   signerIndices,
	}
	s.provingAggregator.On("Aggregate").Return(provingSigners, expectedSig, nil).Once()
	s.processor.provingSigAggtor = s.provingAggregator
	s.processor.votingProvider.(*mocks.VotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer]).On(
		"FinalizeQuorumCertificate",
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(&helper.TestQuorumCertificate{
		Filter:              nil,
		Rank:                s.proposal.State.Rank,
		Selector:            s.proposal.State.Identifier,
		AggregatedSignature: expectedSig,
	}, nil)
	// expected QC
	s.onQCCreatedState.On("onQCCreated", mock.Anything).Run(func(args mock.Arguments) {
		qc := args.Get(0).(models.QuorumCertificate)
		// ensure that QC contains correct field
		expectedQC := &helper.TestQuorumCertificate{
			Rank:                s.proposal.State.Rank,
			Selector:            s.proposal.State.Identifier,
			AggregatedSignature: expectedSig,
		}
		require.Equal(s.T(), expectedQC, qc)
	}).Return(nil).Once()

	// add votes
	for _, signer := range provingSigners {
		vote := helper.VoteForStateFixture(s.proposal.State)
		vote.ID = signer.Identity()
		expectedSig := []byte(vote.Signature)
		s.provingAggregator.On("Verify", vote.ID, expectedSig).Return(nil).Once()
		s.provingAggregator.On("TrustedAdd", vote.ID, expectedSig).Run(func(args mock.Arguments) {
			s.provingTotalWeight += s.sigWeight
		}).Return(s.provingTotalWeight, nil).Once()
		err := s.processor.Process(&vote)
		require.NoError(s.T(), err)
	}

	require.True(s.T(), s.processor.done.Load())
	s.onQCCreatedState.AssertExpectations(s.T())
	s.provingAggregator.AssertExpectations(s.T())

	// processing extra votes shouldn't result in creating new QCs
	vote := helper.VoteForStateFixture(s.proposal.State)
	err := s.processor.Process(&vote)
	require.NoError(s.T(), err)

	s.onQCCreatedState.AssertExpectations(s.T())
}

// TestProcess_ConcurrentCreatingQC tests a scenario where multiple goroutines process vote at same time,
// we expect only one QC created in this scenario.
func (s *VoteProcessorTestSuite) TestProcess_ConcurrentCreatingQC() {
	provingSigners := s.allParticipants[:10]
	// mock aggregators, so we have enough weight and shares for creating QC
	s.provingAggregator = mocks.NewWeightedSignatureAggregator(s.T())
	s.provingAggregator.On("Verify", mock.Anything, mock.Anything).Return(nil)
	s.provingAggregator.On("TrustedAdd", mock.Anything, mock.Anything).Return(s.minRequiredWeight, nil)
	expectedSig := &helper.TestAggregatedSignature{
		Signature: make([]byte, 74),
		PublicKey: make([]byte, 585),
		Bitmask:   []byte{0b11111111, 0b00000011},
	}
	s.provingAggregator.On("Aggregate").Return(provingSigners, expectedSig, nil)
	s.processor.provingSigAggtor = s.provingAggregator

	// at this point sending any vote should result in creating QC.
	s.onQCCreatedState.On("onQCCreated", mock.Anything).Return(nil).Once()

	s.processor.votingProvider.(*mocks.VotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer]).On(
		"FinalizeQuorumCertificate",
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(&helper.TestQuorumCertificate{
		Filter:              nil,
		Rank:                s.proposal.State.Rank,
		Selector:            s.proposal.State.Identifier,
		FrameNumber:         s.proposal.State.Rank,
		Timestamp:           uint64(s.proposal.State.Timestamp),
		AggregatedSignature: expectedSig,
	}, nil)
	var startupWg, shutdownWg sync.WaitGroup

	vote := helper.VoteForStateFixture(s.proposal.State)
	startupWg.Add(1)
	// prepare goroutines, so they are ready to submit a vote at roughly same time
	for i := 0; i < 5; i++ {
		shutdownWg.Add(1)
		go func() {
			defer shutdownWg.Done()
			startupWg.Wait()
			err := s.processor.Process(&vote)
			require.NoError(s.T(), err)
		}()
	}

	startupWg.Done()

	// wait for all routines to finish
	shutdownWg.Wait()

	s.onQCCreatedState.AssertNumberOfCalls(s.T(), "onQCCreated", 1)
}
