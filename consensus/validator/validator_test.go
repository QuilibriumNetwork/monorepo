package validator

import (
	"errors"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/mocks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

func TestValidateProposal(t *testing.T) {
	suite.Run(t, new(ProposalSuite))
}

type ProposalSuite struct {
	suite.Suite
	participants []models.WeightedIdentity
	indices      []byte
	leader       models.WeightedIdentity
	finalized    uint64
	parent       *models.State[*helper.TestState]
	state        *models.State[*helper.TestState]
	voters       []models.WeightedIdentity
	proposal     *models.SignedProposal[*helper.TestState, *helper.TestVote]
	vote         *helper.TestVote
	voter        models.WeightedIdentity
	committee    *mocks.Replicas
	verifier     *mocks.Verifier[*helper.TestVote]
	validator    *Validator[*helper.TestState, *helper.TestVote]
}

func (ps *ProposalSuite) SetupTest() {
	// the leader is a random node for now
	ps.finalized = uint64(rand.Uint32() + 1)
	ps.participants = helper.WithWeightedIdentityList(8)
	ps.leader = ps.participants[0]

	// the parent is the last finalized state, followed directly by a state from the leader
	ps.parent = helper.MakeState[*helper.TestState](
		helper.WithStateRank[*helper.TestState](ps.finalized),
	)

	var err error

	ps.indices = []byte{0b11111111}

	ps.state = helper.MakeState(
		helper.WithStateRank[*helper.TestState](ps.finalized+1),
		helper.WithStateProposer[*helper.TestState](ps.leader.Identity()),
		helper.WithParentState(ps.parent),
		helper.WithParentSigners[*helper.TestState](ps.indices),
	)

	ps.voters = ps.participants
	vt := &helper.TestVote{
		Rank:      ps.state.Rank,
		ID:        ps.leader.Identity(),
		Signature: make([]byte, 74),
		StateID:   ps.state.Identifier,
	}
	ps.proposal = helper.MakeSignedProposal(
		helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(helper.WithState(ps.state))),
		helper.WithVote[*helper.TestState, *helper.TestVote](&vt),
	)
	vote, err := ps.proposal.ProposerVote()
	require.NoError(ps.T(), err)
	ps.vote = *vote
	ps.voter = ps.leader

	// set up the mocked hotstuff Replicas state
	ps.committee = &mocks.Replicas{}
	ps.committee.On("LeaderForRank", ps.state.Rank).Return(ps.leader.Identity(), nil)
	ps.committee.On("QuorumThresholdForRank", mock.Anything).Return(uint64(8000), nil)
	ps.committee.On("IdentitiesByRank", mock.Anything).Return(
		func(_ uint64) []models.WeightedIdentity {
			return ps.participants
		},
		nil,
	)
	for _, participant := range ps.participants {
		ps.committee.On("IdentityByRank", mock.Anything, participant.Identity()).Return(participant, nil)
	}

	// set up the mocked verifier
	ps.verifier = &mocks.Verifier[*helper.TestVote]{}
	ps.verifier.On("VerifyQuorumCertificate", ps.state.ParentQuorumCertificate).Return(nil).Maybe()
	ps.verifier.On("VerifyVote", &ps.vote).Return(nil).Maybe()

	// set up the validator with the mocked dependencies
	ps.validator = NewValidator[*helper.TestState, *helper.TestVote](ps.committee, ps.verifier)
}

func (ps *ProposalSuite) TestProposalOK() {
	err := ps.validator.ValidateProposal(ps.proposal)
	assert.NoError(ps.T(), err, "a valid proposal should be accepted")
}

func (ps *ProposalSuite) TestProposalSignatureError() {

	// change the verifier to error on signature validation with unspecific error
	*ps.verifier = mocks.Verifier[*helper.TestVote]{}
	ps.verifier.On("VerifyQuorumCertificate", ps.state.ParentQuorumCertificate).Return(nil)
	ps.verifier.On("VerifyVote", &ps.vote).Return(errors.New("dummy error"))

	// check that validation now fails
	err := ps.validator.ValidateProposal(ps.proposal)
	assert.Error(ps.T(), err, "a proposal should be rejected if signature check fails")

	// check that the error is not one that leads to invalid
	assert.False(ps.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err), "if signature check fails, we should not receive an ErrorInvalidState")
}

func (ps *ProposalSuite) TestProposalSignatureInvalidFormat() {

	// change the verifier to fail signature validation with InvalidFormatError error
	*ps.verifier = mocks.Verifier[*helper.TestVote]{}
	ps.verifier.On("VerifyQuorumCertificate", ps.state.ParentQuorumCertificate).Return(nil)
	ps.verifier.On("VerifyVote", &ps.vote).Return(models.NewInvalidFormatErrorf(""))

	// check that validation now fails
	err := ps.validator.ValidateProposal(ps.proposal)
	assert.Error(ps.T(), err, "a proposal with an invalid signature should be rejected")

	// check that the error is an invalid proposal error to allow creating slashing challenge
	assert.True(ps.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err), "if signature is invalid, we should generate an invalid error")
}

func (ps *ProposalSuite) TestProposalSignatureInvalid() {

	// change the verifier to fail signature validation
	*ps.verifier = mocks.Verifier[*helper.TestVote]{}
	ps.verifier.On("VerifyQuorumCertificate", ps.state.ParentQuorumCertificate).Return(nil)
	ps.verifier.On("VerifyVote", &ps.vote).Return(models.ErrInvalidSignature)

	// check that validation now fails
	err := ps.validator.ValidateProposal(ps.proposal)
	assert.Error(ps.T(), err, "a proposal with an invalid signature should be rejected")

	// check that the error is an invalid proposal error to allow creating slashing challenge
	assert.True(ps.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err), "if signature is invalid, we should generate an invalid error")
}

func (ps *ProposalSuite) TestProposalWrongLeader() {

	// change the consensus.Replicas to return a different leader
	*ps.committee = mocks.Replicas{}
	ps.committee.On("LeaderForRank", ps.state.Rank).Return(ps.participants[1].Identity(), nil)
	for _, participant := range ps.participants {
		ps.committee.On("IdentityByRank", mock.Anything, participant.Identity()).Return(participant, nil)
	}

	// check that validation fails now
	err := ps.validator.ValidateProposal(ps.proposal)
	assert.Error(ps.T(), err, "a proposal from the wrong proposer should be rejected")

	// check that the error is an invalid proposal error to allow creating slashing challenge
	assert.True(ps.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err), "if the proposal has wrong proposer, we should generate a invalid error")
}

// TestProposalQCInvalid checks that Validator handles the verifier's error returns correctly.
// In case of `models.InvalidFormatError` and models.ErrInvalidSignature`, we expect the Validator
// to recognize those as an invalid QC, i.e. returns an `models.InvalidProposalError`.
// In contrast, unexpected exceptions and `models.InvalidSignerError` should _not_ be
// interpreted as a sign of an invalid QC.
func (ps *ProposalSuite) TestProposalQCInvalid() {
	ps.Run("invalid-signature", func() {
		*ps.verifier = mocks.Verifier[*helper.TestVote]{}
		ps.verifier.On("VerifyQuorumCertificate", ps.state.ParentQuorumCertificate).Return(
			fmt.Errorf("invalid qc: %w", models.ErrInvalidSignature))
		ps.verifier.On("VerifyVote", &ps.vote).Return(nil)

		// check that validation fails and the failure case is recognized as an invalid state
		err := ps.validator.ValidateProposal(ps.proposal)
		assert.True(ps.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err), "if the state's QC signature is invalid, an ErrorInvalidState error should be raised")
	})

	ps.Run("invalid-format", func() {
		*ps.verifier = mocks.Verifier[*helper.TestVote]{}
		ps.verifier.On("VerifyQuorumCertificate", ps.state.ParentQuorumCertificate).Return(models.NewInvalidFormatErrorf("invalid qc"))
		ps.verifier.On("VerifyVote", &ps.vote).Return(nil)

		// check that validation fails and the failure case is recognized as an invalid state
		err := ps.validator.ValidateProposal(ps.proposal)
		assert.True(ps.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err), "if the state's QC has an invalid format, an ErrorInvalidState error should be raised")
	})

	ps.Run("invalid-signer", func() {
		*ps.verifier = mocks.Verifier[*helper.TestVote]{}
		ps.verifier.On("VerifyQuorumCertificate", ps.state.ParentQuorumCertificate).Return(
			fmt.Errorf("invalid qc: %w", models.NewInvalidSignerErrorf("")))
		ps.verifier.On("VerifyVote", &ps.vote).Return(nil)

		// check that validation fails and the failure case is recognized as an invalid state
		err := ps.validator.ValidateProposal(ps.proposal)
		assert.Error(ps.T(), err)
		assert.False(ps.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err))
	})

	ps.Run("unknown-exception", func() {
		exception := errors.New("exception")
		*ps.verifier = mocks.Verifier[*helper.TestVote]{}
		ps.verifier.On("VerifyQuorumCertificate", ps.state.ParentQuorumCertificate).Return(exception)
		ps.verifier.On("VerifyVote", &ps.vote).Return(nil)

		// check that validation fails and the failure case is recognized as an invalid state
		err := ps.validator.ValidateProposal(ps.proposal)
		assert.ErrorIs(ps.T(), err, exception)
		assert.False(ps.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err))
	})

	ps.Run("verify-qc-err-rank-for-unknown-rank", func() {
		*ps.verifier = mocks.Verifier[*helper.TestVote]{}
		ps.verifier.On("VerifyQuorumCertificate", ps.state.ParentQuorumCertificate).Return(models.ErrRankUnknown)
		ps.verifier.On("VerifyVote", &ps.vote).Return(nil)

		// check that validation fails and the failure is considered internal exception and NOT an InvalidProposal error
		err := ps.validator.ValidateProposal(ps.proposal)
		assert.Error(ps.T(), err)
		assert.NotErrorIs(ps.T(), err, models.ErrRankUnknown)
		assert.False(ps.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err))
	})
}

func (ps *ProposalSuite) TestProposalQCError() {

	// change verifier to fail on QC validation
	*ps.verifier = mocks.Verifier[*helper.TestVote]{}
	ps.verifier.On("VerifyQuorumCertificate", ps.state.ParentQuorumCertificate).Return(fmt.Errorf("some exception"))
	ps.verifier.On("VerifyVote", &ps.vote).Return(nil)

	// check that validation fails now
	err := ps.validator.ValidateProposal(ps.proposal)
	assert.Error(ps.T(), err, "a proposal with an invalid QC should be rejected")

	// check that the error is an invalid proposal error to allow creating slashing challenge
	assert.False(ps.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err), "if we can't verify the QC, we should not generate a invalid error")
}

// TestProposalWithPreviousRankTimeoutCertificate tests different scenarios where last rank has ended with TC
// this requires including a valid PreviousRankTimeoutCertificate.
func (ps *ProposalSuite) TestProposalWithPreviousRankTimeoutCertificate() {
	// assume all proposals are created by valid leader
	ps.verifier.On("VerifyVote", mock.Anything).Return(nil)
	ps.committee.On("LeaderForRank", mock.Anything).Return(ps.leader.Identity(), nil)

	ps.Run("happy-path", func() {
		state := helper.MakeState(
			helper.WithStateRank[*helper.TestState](ps.state.Rank+2),
			helper.WithStateProposer[*helper.TestState](ps.leader.Identity()),
			helper.WithParentSigners[*helper.TestState](ps.indices),
			helper.WithStateQC[*helper.TestState](ps.state.ParentQuorumCertificate))
		vote := &helper.TestVote{
			Rank:      ps.state.Rank + 2,
			ID:        ps.leader.Identity(),
			StateID:   state.Identifier,
			Signature: make([]byte, 74),
		}
		proposal := helper.MakeSignedProposal(helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(
			helper.WithState(state),
			helper.WithPreviousRankTimeoutCertificate[*helper.TestState](helper.MakeTC(
				helper.WithTCSigners(ps.indices),
				helper.WithTCRank(ps.state.Rank+1),
				helper.WithTCNewestQC(ps.state.ParentQuorumCertificate))),
		)), helper.WithVote[*helper.TestState, *helper.TestVote](&vote))
		ps.verifier.On("VerifyTimeoutCertificate", proposal.PreviousRankTimeoutCertificate).Return(nil).Once()
		err := ps.validator.ValidateProposal(proposal)
		require.NoError(ps.T(), err)
	})
	ps.Run("no-tc", func() {
		state := helper.MakeState(
			helper.WithStateRank[*helper.TestState](ps.state.Rank+2),
			helper.WithStateProposer[*helper.TestState](ps.leader.Identity()),
			helper.WithParentSigners[*helper.TestState](ps.indices),
			helper.WithStateQC[*helper.TestState](ps.state.ParentQuorumCertificate))
		vote := &helper.TestVote{
			Rank:      ps.state.Rank + 2,
			ID:        ps.leader.Identity(),
			StateID:   state.Identifier,
			Signature: make([]byte, 74),
		}
		proposal := helper.MakeSignedProposal(helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(
			helper.WithState(state),
			// in this case proposal without PreviousRankTimeoutCertificate is considered invalid
		)), helper.WithVote[*helper.TestState, *helper.TestVote](&vote))
		err := ps.validator.ValidateProposal(proposal)
		require.True(ps.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err))
		ps.verifier.AssertNotCalled(ps.T(), "VerifyQuorumCertificate")
		ps.verifier.AssertNotCalled(ps.T(), "VerifyTimeoutCertificate")
	})
	ps.Run("tc-for-wrong-rank", func() {
		state := helper.MakeState[*helper.TestState](
			helper.WithStateRank[*helper.TestState](ps.state.Rank+2),
			helper.WithStateProposer[*helper.TestState](ps.leader.Identity()),
			helper.WithParentSigners[*helper.TestState](ps.indices),
			helper.WithStateQC[*helper.TestState](ps.state.ParentQuorumCertificate))
		vote := &helper.TestVote{
			Rank:      ps.state.Rank + 2,
			ID:        ps.leader.Identity(),
			StateID:   state.Identifier,
			Signature: make([]byte, 74),
		}
		proposal := helper.MakeSignedProposal[*helper.TestState, *helper.TestVote](helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(
			helper.WithState(state),
			helper.WithPreviousRankTimeoutCertificate[*helper.TestState](helper.MakeTC(
				helper.WithTCSigners(ps.indices),
				helper.WithTCRank(ps.state.Rank+10), // PreviousRankTimeoutCertificate.Rank must be equal to State.Rank-1
				helper.WithTCNewestQC(ps.state.ParentQuorumCertificate))),
		)), helper.WithVote[*helper.TestState, *helper.TestVote](&vote))
		err := ps.validator.ValidateProposal(proposal)
		require.True(ps.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err))
		ps.verifier.AssertNotCalled(ps.T(), "VerifyQuorumCertificate")
		ps.verifier.AssertNotCalled(ps.T(), "VerifyTimeoutCertificate")
	})
	ps.Run("proposal-not-safe-to-extend", func() {
		state := helper.MakeState[*helper.TestState](
			helper.WithStateRank[*helper.TestState](ps.state.Rank+2),
			helper.WithStateProposer[*helper.TestState](ps.leader.Identity()),
			helper.WithParentSigners[*helper.TestState](ps.indices),
			helper.WithStateQC[*helper.TestState](ps.state.ParentQuorumCertificate))
		vote := &helper.TestVote{
			Rank:      state.Rank,
			ID:        ps.leader.Identity(),
			StateID:   state.Identifier,
			Signature: make([]byte, 74),
		}
		proposal := helper.MakeSignedProposal[*helper.TestState, *helper.TestVote](helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(
			helper.WithState(state),
			helper.WithPreviousRankTimeoutCertificate[*helper.TestState](helper.MakeTC(
				helper.WithTCSigners(ps.indices),
				helper.WithTCRank(ps.state.Rank+1),
				// proposal is not safe to extend because included QC.Rank is higher that State.QC.Rank
				helper.WithTCNewestQC(helper.MakeQC(helper.WithQCRank(ps.state.Rank+1))))),
		)), helper.WithVote[*helper.TestState, *helper.TestVote](&vote))
		err := ps.validator.ValidateProposal(proposal)
		require.True(ps.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err))
		ps.verifier.AssertNotCalled(ps.T(), "VerifyQuorumCertificate")
		ps.verifier.AssertNotCalled(ps.T(), "VerifyTimeoutCertificate")
	})
	ps.Run("included-tc-highest-qc-not-highest", func() {
		state := helper.MakeState[*helper.TestState](
			helper.WithStateRank[*helper.TestState](ps.state.Rank+2),
			helper.WithStateProposer[*helper.TestState](ps.leader.Identity()),
			helper.WithParentSigners[*helper.TestState](ps.indices),
			helper.WithStateQC[*helper.TestState](ps.state.ParentQuorumCertificate))
		vote := &helper.TestVote{
			Rank:      state.Rank,
			ID:        ps.leader.Identity(),
			StateID:   state.Identifier,
			Signature: make([]byte, 74),
		}
		proposal := helper.MakeSignedProposal[*helper.TestState, *helper.TestVote](helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(
			helper.WithState(state),
			helper.WithPreviousRankTimeoutCertificate[*helper.TestState](helper.MakeTC(
				helper.WithTCSigners(ps.indices),
				helper.WithTCRank(ps.state.Rank+1),
				helper.WithTCNewestQC(ps.state.ParentQuorumCertificate),
			)),
		)), helper.WithVote[*helper.TestState, *helper.TestVote](&vote))
		ps.verifier.On("VerifyTimeoutCertificate", proposal.PreviousRankTimeoutCertificate).Return(nil).Once()

		// this is considered an invalid TC, because highest QC's rank is not equal to max{NewestQCRanks}
		proposal.PreviousRankTimeoutCertificate.(*helper.TestTimeoutCertificate).LatestRanks[0] = proposal.PreviousRankTimeoutCertificate.GetLatestQuorumCert().GetRank() + 1
		err := ps.validator.ValidateProposal(proposal)
		require.True(ps.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err) && models.IsInvalidTimeoutCertificateError(err))
		ps.verifier.AssertNotCalled(ps.T(), "VerifyTimeoutCertificate")
	})
	ps.Run("included-tc-threshold-not-reached", func() {
		state := helper.MakeState[*helper.TestState](
			helper.WithStateRank[*helper.TestState](ps.state.Rank+2),
			helper.WithStateProposer[*helper.TestState](ps.leader.Identity()),
			helper.WithParentSigners[*helper.TestState](ps.indices),
			helper.WithStateQC[*helper.TestState](ps.state.ParentQuorumCertificate))
		vote := &helper.TestVote{
			Rank:      state.Rank,
			ID:        ps.leader.Identity(),
			StateID:   state.Identifier,
			Signature: make([]byte, 74),
		}
		// TC is signed by only one signer - insufficient to reach weight threshold
		insufficientSignerIndices := []byte{0b00000001}
		proposal := helper.MakeSignedProposal[*helper.TestState, *helper.TestVote](helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(
			helper.WithState(state),
			helper.WithPreviousRankTimeoutCertificate[*helper.TestState](helper.MakeTC(
				helper.WithTCSigners(insufficientSignerIndices), // one signer is not enough to reach threshold
				helper.WithTCRank(ps.state.Rank+1),
				helper.WithTCNewestQC(ps.state.ParentQuorumCertificate),
			)),
		)), helper.WithVote[*helper.TestState, *helper.TestVote](&vote))
		err := ps.validator.ValidateProposal(proposal)
		require.True(ps.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err) && models.IsInvalidTimeoutCertificateError(err))
		ps.verifier.AssertNotCalled(ps.T(), "VerifyTimeoutCertificate")
	})
	ps.Run("included-tc-highest-qc-invalid", func() {
		state := helper.MakeState[*helper.TestState](
			helper.WithStateRank[*helper.TestState](ps.state.Rank+2),
			helper.WithStateProposer[*helper.TestState](ps.leader.Identity()),
			helper.WithParentSigners[*helper.TestState](ps.indices),
			helper.WithStateQC[*helper.TestState](ps.state.ParentQuorumCertificate))
		vote := &helper.TestVote{
			Rank:      state.Rank,
			ID:        ps.leader.Identity(),
			StateID:   state.Identifier,
			Signature: make([]byte, 74),
		}
		// QC included in TC has rank below QC included in proposal
		qc := helper.MakeQC(
			helper.WithQCRank(ps.state.ParentQuorumCertificate.GetRank()-1),
			helper.WithQCSigners(ps.indices))

		proposal := helper.MakeSignedProposal[*helper.TestState, *helper.TestVote](helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(
			helper.WithState(state),
			helper.WithPreviousRankTimeoutCertificate[*helper.TestState](helper.MakeTC(
				helper.WithTCSigners(ps.indices),
				helper.WithTCRank(ps.state.Rank+1),
				helper.WithTCNewestQC(qc))),
		)), helper.WithVote[*helper.TestState, *helper.TestVote](&vote))
		ps.verifier.On("VerifyTimeoutCertificate", proposal.PreviousRankTimeoutCertificate).Return(nil).Once()
		ps.verifier.On("VerifyQuorumCertificate", qc).Return(models.ErrInvalidSignature).Once()
		err := ps.validator.ValidateProposal(proposal)
		require.True(ps.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err) && models.IsInvalidTimeoutCertificateError(err))
	})
	ps.Run("verify-qc-err-rank-for-unknown-rank", func() {
		state := helper.MakeState[*helper.TestState](
			helper.WithStateRank[*helper.TestState](ps.state.Rank+2),
			helper.WithStateProposer[*helper.TestState](ps.leader.Identity()),
			helper.WithParentSigners[*helper.TestState](ps.indices),
			helper.WithStateQC[*helper.TestState](ps.state.ParentQuorumCertificate))
		newestQC := helper.MakeQC(
			helper.WithQCRank(ps.state.ParentQuorumCertificate.GetRank()-2),
			helper.WithQCSigners(ps.indices))
		vote := &helper.TestVote{
			Rank:      state.Rank,
			ID:        ps.leader.Identity(),
			StateID:   state.Identifier,
			Signature: make([]byte, 74),
		}
		proposal := helper.MakeSignedProposal[*helper.TestState, *helper.TestVote](helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(
			helper.WithState(state),
			helper.WithPreviousRankTimeoutCertificate[*helper.TestState](helper.MakeTC(
				helper.WithTCSigners(ps.indices),
				helper.WithTCRank(ps.state.Rank+1),
				helper.WithTCNewestQC(newestQC))),
		)), helper.WithVote[*helper.TestState, *helper.TestVote](&vote))
		ps.verifier.On("VerifyTimeoutCertificate", proposal.PreviousRankTimeoutCertificate).Return(nil).Once()
		// Validating QC included in TC returns ErrRankUnknown
		ps.verifier.On("VerifyQuorumCertificate", newestQC).Return(models.ErrRankUnknown).Once()
		err := ps.validator.ValidateProposal(proposal)
		require.Error(ps.T(), err)
		require.False(ps.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err))
		require.False(ps.T(), models.IsInvalidTimeoutCertificateError(err))
		require.NotErrorIs(ps.T(), err, models.ErrRankUnknown)
	})
	ps.Run("included-tc-invalid-sig", func() {
		state := helper.MakeState[*helper.TestState](
			helper.WithStateRank[*helper.TestState](ps.state.Rank+2),
			helper.WithStateProposer[*helper.TestState](ps.leader.Identity()),
			helper.WithParentSigners[*helper.TestState](ps.indices),
			helper.WithStateQC[*helper.TestState](ps.state.ParentQuorumCertificate))
		vote := &helper.TestVote{
			Rank:      state.Rank,
			ID:        ps.leader.Identity(),
			StateID:   state.Identifier,
			Signature: make([]byte, 74),
		}
		proposal := helper.MakeSignedProposal[*helper.TestState, *helper.TestVote](helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(
			helper.WithState(state),
			helper.WithPreviousRankTimeoutCertificate[*helper.TestState](helper.MakeTC(
				helper.WithTCSigners(ps.indices),
				helper.WithTCRank(ps.state.Rank+1),
				helper.WithTCNewestQC(ps.state.ParentQuorumCertificate))),
		)), helper.WithVote[*helper.TestState, *helper.TestVote](&vote))
		ps.verifier.On("VerifyTimeoutCertificate", proposal.PreviousRankTimeoutCertificate).Return(models.ErrInvalidSignature).Once()
		err := ps.validator.ValidateProposal(proposal)
		require.True(ps.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err) && models.IsInvalidTimeoutCertificateError(err))
		ps.verifier.AssertCalled(ps.T(), "VerifyTimeoutCertificate", proposal.PreviousRankTimeoutCertificate)
	})
	ps.Run("last-rank-successful-but-includes-tc", func() {
		state := helper.MakeState[*helper.TestState](
			helper.WithStateRank[*helper.TestState](ps.finalized+1),
			helper.WithStateProposer[*helper.TestState](ps.leader.Identity()),
			helper.WithParentSigners[*helper.TestState](ps.indices),
			helper.WithParentState(ps.parent))
		vote := &helper.TestVote{
			Rank:      state.Rank,
			ID:        ps.leader.Identity(),
			StateID:   state.Identifier,
			Signature: make([]byte, 74),
		}
		proposal := helper.MakeSignedProposal[*helper.TestState, *helper.TestVote](helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(
			helper.WithState(state),
			helper.WithPreviousRankTimeoutCertificate[*helper.TestState](helper.MakeTC()),
		)), helper.WithVote[*helper.TestState, *helper.TestVote](&vote))
		err := ps.validator.ValidateProposal(proposal)
		require.True(ps.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err))
		ps.verifier.AssertNotCalled(ps.T(), "VerifyTimeoutCertificate")
	})
	ps.verifier.AssertExpectations(ps.T())
}

func TestValidateVote(t *testing.T) {
	suite.Run(t, new(VoteSuite))
}

type VoteSuite struct {
	suite.Suite
	signer    models.WeightedIdentity
	state     *models.State[*helper.TestState]
	vote      *helper.TestVote
	verifier  *mocks.Verifier[*helper.TestVote]
	committee *mocks.Replicas
	validator *Validator[*helper.TestState, *helper.TestVote]
}

func (vs *VoteSuite) SetupTest() {

	// create a random signing identity
	vs.signer = helper.WithWeightedIdentityList(1)[0]

	// create a state that should be signed
	vs.state = helper.MakeState[*helper.TestState]()

	// create a vote for this state
	vs.vote = &helper.TestVote{
		Rank:      vs.state.Rank,
		ID:        vs.signer.Identity(),
		StateID:   vs.state.Identifier,
		Signature: []byte{},
	}

	// set up the mocked verifier
	vs.verifier = &mocks.Verifier[*helper.TestVote]{}
	vs.verifier.On("VerifyVote", &vs.vote).Return(nil)

	// the leader for the state rank is the correct one
	vs.committee = &mocks.Replicas{}
	vs.committee.On("IdentityByRank", mock.Anything, vs.signer.Identity()).Return(vs.signer, nil)

	// set up the validator with the mocked dependencies
	vs.validator = NewValidator[*helper.TestState, *helper.TestVote](vs.committee, vs.verifier)
}

// TestVoteOK checks the happy case, which is the default for the suite
func (vs *VoteSuite) TestVoteOK() {
	_, err := vs.validator.ValidateVote(&vs.vote)
	assert.NoError(vs.T(), err, "a valid vote should be accepted")
}

// TestVoteSignatureError checks that the Validator does not misinterpret
// unexpected exceptions for invalid votes.
func (vs *VoteSuite) TestVoteSignatureError() {
	*vs.verifier = mocks.Verifier[*helper.TestVote]{}
	vs.verifier.On("VerifyVote", &vs.vote).Return(fmt.Errorf("some exception"))

	// check that the vote is no longer validated
	_, err := vs.validator.ValidateVote(&vs.vote)
	assert.Error(vs.T(), err, "a vote with error on signature validation should be rejected")
	assert.False(vs.T(), models.IsInvalidVoteError[*helper.TestVote](err), "internal exception should not be interpreted as invalid vote")
}

// TestVoteVerifyVote_ErrRankUnknown tests if ValidateVote correctly handles VerifyVote's ErrRankUnknown sentinel error
// Validator shouldn't return a sentinel error here because this behavior is a symptom of internal bug, this behavior is not expected.
func (vs *VoteSuite) TestVoteVerifyVote_ErrRankUnknown() {
	*vs.verifier = mocks.Verifier[*helper.TestVote]{}
	vs.verifier.On("VerifyVote", &vs.vote).Return(models.ErrRankUnknown)

	// check that the vote is no longer validated
	_, err := vs.validator.ValidateVote(&vs.vote)
	assert.Error(vs.T(), err)
	assert.False(vs.T(), models.IsInvalidVoteError[*helper.TestVote](err), "internal exception should not be interpreted as invalid vote")
	assert.NotErrorIs(vs.T(), err, models.ErrRankUnknown, "we don't expect a sentinel error here")
}

// TestVoteInvalidSignerID checks that the Validator correctly handles a vote
// with a SignerID that does not correspond to a valid consensus participant.
// In this case, the `consensus.DynamicCommittee` returns a `models.InvalidSignerError`,
// which the Validator should recognize as a symptom for an invalid vote.
// Hence, we expect the validator to return a `models.InvalidVoteError`.
func (vs *VoteSuite) TestVoteInvalidSignerID() {
	*vs.committee = mocks.Replicas{}
	vs.committee.On("IdentityByRank", vs.state.Rank, vs.vote.ID).Return(nil, models.NewInvalidSignerErrorf(""))

	// A `models.InvalidSignerError` from the committee should be interpreted as
	// the Vote being invalid, i.e. we expect an InvalidVoteError to be returned
	_, err := vs.validator.ValidateVote(&vs.vote)
	assert.Error(vs.T(), err, "a vote with unknown SignerID should be rejected")
	assert.True(vs.T(), models.IsInvalidVoteError[*helper.TestVote](err), "a vote with unknown SignerID should be rejected")
}

// TestVoteSignatureInvalid checks that the Validator correctly handles votes
// with cryptographically invalid consensus. In this case, the `consensus.Verifier`
// returns a `models.ErrInvalidSignature`, which the Validator should recognize as
// a symptom for an invalid vote.
// Hence, we expect the validator to return a `models.InvalidVoteError`.
func (vs *VoteSuite) TestVoteSignatureInvalid() {
	*vs.verifier = mocks.Verifier[*helper.TestVote]{}
	vs.verifier.On("VerifyVote", &vs.vote).Return(fmt.Errorf("staking sig is invalid: %w", models.ErrInvalidSignature))

	// A `models.ErrInvalidSignature` from the `consensus.Verifier` should be interpreted as
	// the Vote being invalid, i.e. we expect an InvalidVoteError to be returned
	_, err := vs.validator.ValidateVote(&vs.vote)
	assert.Error(vs.T(), err, "a vote with an invalid signature should be rejected")
	assert.True(vs.T(), models.IsInvalidVoteError[*helper.TestVote](err), "a vote with an invalid signature should be rejected")
}

func TestValidateQuorumCertificate(t *testing.T) {
	suite.Run(t, new(QCSuite))
}

type QCSuite struct {
	suite.Suite
	participants []models.WeightedIdentity
	signers      []models.WeightedIdentity
	state        *models.State[*helper.TestState]
	qc           models.QuorumCertificate
	committee    *mocks.Replicas
	verifier     *mocks.Verifier[*helper.TestVote]
	validator    *Validator[*helper.TestState, *helper.TestVote]
}

func (qs *QCSuite) SetupTest() {
	// create a list of 10 nodes with 1-weight each
	qs.participants = helper.WithWeightedIdentityList(10)

	// signers are a qualified majority at 7
	qs.signers = qs.participants[:7]

	// create a state that has the signers in its QC
	qs.state = helper.MakeState[*helper.TestState]()
	indices := []byte{0b01111111, 0b00000000}

	qs.qc = helper.MakeQC(helper.WithQCState[*helper.TestState](qs.state), helper.WithQCSigners(indices))

	// return the correct participants and identities from rank state
	qs.committee = &mocks.Replicas{}
	qs.committee.On("IdentitiesByRank", mock.Anything).Return(
		func(_ uint64) []models.WeightedIdentity {
			return qs.participants
		},
		nil,
	)
	qs.committee.On("QuorumThresholdForRank", mock.Anything).Return(uint64(7000), nil)

	// set up the mocked verifier to verify the QC correctly
	qs.verifier = &mocks.Verifier[*helper.TestVote]{}
	qs.verifier.On("VerifyQuorumCertificate", qs.qc).Return(nil)

	// set up the validator with the mocked dependencies
	qs.validator = NewValidator[*helper.TestState, *helper.TestVote](qs.committee, qs.verifier)
}

// TestQCOK verifies the default happy case
func (qs *QCSuite) TestQCOK() {

	// check the default happy case passes
	err := qs.validator.ValidateQuorumCertificate(qs.qc)
	assert.NoError(qs.T(), err, "a valid QC should be accepted")
}

// TestQCRetrievingParticipantsError tests that validation errors if:
// there is an error retrieving identities of consensus participants
func (qs *QCSuite) TestQCRetrievingParticipantsError() {
	// change the consensus.DynamicCommittee to fail on retrieving participants
	*qs.committee = mocks.Replicas{}
	qs.committee.On("IdentitiesByRank", mock.Anything).Return(qs.participants, errors.New("FATAL internal error"))

	// verifier should escalate unspecific internal error to surrounding logic, but NOT as ErrorInvalidQC
	err := qs.validator.ValidateQuorumCertificate(qs.qc)
	assert.Error(qs.T(), err, "unspecific error when retrieving consensus participants should be escalated to surrounding logic")
	assert.False(qs.T(), models.IsInvalidQuorumCertificateError(err), "unspecific internal errors should not result in ErrorInvalidQC error")
}

// TestQCSignersError tests that a qc fails validation if:
// QC signer's have insufficient weight (but are all valid consensus participants otherwise)
func (qs *QCSuite) TestQCInsufficientWeight() {
	// signers only have weight 6 out of 10 total (NOT have a supermajority)
	qs.signers = qs.participants[:6]
	indices := []byte{0b00111111, 0b00000000}

	qs.qc = helper.MakeQC(helper.WithQCState[*helper.TestState](qs.state), helper.WithQCSigners(indices))

	// the QC should not be validated anymore
	err := qs.validator.ValidateQuorumCertificate(qs.qc)
	assert.Error(qs.T(), err, "a QC should be rejected if it has insufficient voted weight")

	// we should get a threshold error to bubble up for extra info
	assert.True(qs.T(), models.IsInvalidQuorumCertificateError(err), "if there is insufficient voted weight, an invalid state error should be raised")
}

// TestQCSignatureError tests that validation errors if:
// there is an unspecific internal error while validating the signature
func (qs *QCSuite) TestQCSignatureError() {

	// set up the verifier to fail QC verification
	*qs.verifier = mocks.Verifier[*helper.TestVote]{}
	qs.verifier.On("VerifyQuorumCertificate", qs.qc).Return(errors.New("dummy error"))

	// verifier should escalate unspecific internal error to surrounding logic, but NOT as ErrorInvalidQC
	err := qs.validator.ValidateQuorumCertificate(qs.qc)
	assert.Error(qs.T(), err, "unspecific sig verification error should be escalated to surrounding logic")
	assert.False(qs.T(), models.IsInvalidQuorumCertificateError(err), "unspecific internal errors should not result in ErrorInvalidQC error")
}

// TestQCSignatureInvalid verifies that the Validator correctly handles the models.ErrInvalidSignature.
// This error return from `Verifier.VerifyQuorumCertificate` is an expected failure case in case of a byzantine input, where
// one of the signatures in the QC is broken. Hence, the Validator should wrap it as InvalidProposalError.
func (qs *QCSuite) TestQCSignatureInvalid() {
	// change the verifier to fail the QC signature
	*qs.verifier = mocks.Verifier[*helper.TestVote]{}
	qs.verifier.On("VerifyQuorumCertificate", qs.qc).Return(fmt.Errorf("invalid qc: %w", models.ErrInvalidSignature))

	// the QC should no longer pass validation
	err := qs.validator.ValidateQuorumCertificate(qs.qc)
	assert.True(qs.T(), models.IsInvalidQuorumCertificateError(err), "if the signature is invalid an ErrorInvalidQC error should be raised")
}

// TestQCVerifyQuorumCertificate_ErrRankUnknown tests if ValidateQuorumCertificate correctly handles VerifyQuorumCertificate's ErrRankUnknown sentinel error
// Validator shouldn't return a sentinel error here because this behavior is a symptom of internal bug, this behavior is not expected.
func (qs *QCSuite) TestQCVerifyQuorumCertificate_ErrRankUnknown() {
	*qs.verifier = mocks.Verifier[*helper.TestVote]{}
	qs.verifier.On("VerifyQuorumCertificate", qs.qc).Return(models.ErrRankUnknown)
	err := qs.validator.ValidateQuorumCertificate(qs.qc)
	assert.Error(qs.T(), err)
	assert.False(qs.T(), models.IsInvalidQuorumCertificateError(err), "we don't expect a sentinel error here")
	assert.NotErrorIs(qs.T(), err, models.ErrRankUnknown, "we don't expect a sentinel error here")
}

// TestQCSignatureInvalidFormat verifies that the Validator correctly handles the models.InvalidFormatError.
// This error return from `Verifier.VerifyQuorumCertificate` is an expected failure case in case of a byzantine input, where
// some binary vector (e.g. `sigData`) is broken. Hence, the Validator should wrap it as InvalidProposalError.
func (qs *QCSuite) TestQCSignatureInvalidFormat() {
	// change the verifier to fail the QC signature
	*qs.verifier = mocks.Verifier[*helper.TestVote]{}
	qs.verifier.On("VerifyQuorumCertificate", qs.qc).Return(models.NewInvalidFormatErrorf("invalid sigType"))

	// the QC should no longer pass validation
	err := qs.validator.ValidateQuorumCertificate(qs.qc)
	assert.True(qs.T(), models.IsInvalidQuorumCertificateError(err), "if the signature has an invalid format, an ErrorInvalidQC error should be raised")
}

// TestQCEmptySigners verifies that the Validator correctly handles the models.InsufficientSignaturesError:
// In the validator, we previously checked the total weight of all signers meets the supermajority threshold,
// which is a _positive_ number. Hence, there must be at least one signer. Hence, `Verifier.VerifyQuorumCertificate`
// returning this error would be a symptom of a fatal internal bug. The Validator should _not_ interpret
// this error as an invalid QC / invalid state, i.e. it should _not_ return an `InvalidProposalError`.
func (qs *QCSuite) TestQCEmptySigners() {
	*qs.verifier = mocks.Verifier[*helper.TestVote]{}
	qs.verifier.On("VerifyQuorumCertificate", qs.qc).Return(
		fmt.Errorf("%w", models.NewInsufficientSignaturesErrorf("")))

	// the Validator should _not_ interpret this as a invalid QC, but as an internal error
	err := qs.validator.ValidateQuorumCertificate(qs.qc)
	assert.True(qs.T(), models.IsInsufficientSignaturesError(err)) // unexpected error should be wrapped and propagated upwards
	assert.False(qs.T(), models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err), err, "should _not_ interpret this as a invalid QC, but as an internal error")
}

func TestValidateTimeoutCertificate(t *testing.T) {
	suite.Run(t, new(TCSuite))
}

type TCSuite struct {
	suite.Suite
	participants []models.WeightedIdentity
	signers      []models.WeightedIdentity
	indices      []byte
	state        *models.State[*helper.TestState]
	tc           models.TimeoutCertificate
	committee    *mocks.DynamicCommittee
	verifier     *mocks.Verifier[*helper.TestVote]
	validator    *Validator[*helper.TestState, *helper.TestVote]
}

func (s *TCSuite) SetupTest() {

	// create a list of 10 nodes with 1-weight each
	s.participants = helper.WithWeightedIdentityList(10)

	// signers are a qualified majority at 7
	s.signers = s.participants[:7]

	var err error
	s.indices = []byte{0b01111111, 0b00000000}
	require.NoError(s.T(), err)

	rank := uint64(int(rand.Uint32()) + len(s.participants))

	highQCRanks := make([]uint64, 0, len(s.signers))
	for i := range s.signers {
		highQCRanks = append(highQCRanks, rank-uint64(i)-1)
	}

	rand.Shuffle(len(highQCRanks), func(i, j int) {
		highQCRanks[i], highQCRanks[j] = highQCRanks[j], highQCRanks[i]
	})

	// create a state that has the signers in its QC
	parent := helper.MakeState[*helper.TestState](helper.WithStateRank[*helper.TestState](rank - 1))
	s.state = helper.MakeState[*helper.TestState](helper.WithStateRank[*helper.TestState](rank),
		helper.WithParentState(parent),
		helper.WithParentSigners[*helper.TestState](s.indices))
	s.tc = helper.MakeTC(helper.WithTCNewestQC(s.state.ParentQuorumCertificate),
		helper.WithTCRank(rank+1),
		helper.WithTCSigners(s.indices),
		helper.WithTCHighQCRanks(highQCRanks))

	// return the correct participants and identities from rank state
	s.committee = &mocks.DynamicCommittee{}
	s.committee.On("IdentitiesByRank", mock.Anything, mock.Anything).Return(
		func(rank uint64) []models.WeightedIdentity {
			return s.participants
		},
		nil,
	)
	s.committee.On("QuorumThresholdForRank", mock.Anything).Return(uint64(7000), nil)

	s.verifier = &mocks.Verifier[*helper.TestVote]{}
	s.verifier.On("VerifyQuorumCertificate", s.state.ParentQuorumCertificate).Return(nil)

	// set up the validator with the mocked dependencies
	s.validator = NewValidator[*helper.TestState, *helper.TestVote](s.committee, s.verifier)
}

// TestTCOk tests if happy-path returns correct result
func (s *TCSuite) TestTCOk() {
	s.verifier.On("VerifyTimeoutCertificate", s.tc).Return(nil).Once()

	// check the default happy case passes
	err := s.validator.ValidateTimeoutCertificate(s.tc)
	assert.NoError(s.T(), err, "a valid TC should be accepted")
}

// TestTCNewestQCFromFuture tests if correct error is returned when included QC is higher than TC's rank
func (s *TCSuite) TestTCNewestQCFromFuture() {
	// highest QC from future rank
	s.tc.(*helper.TestTimeoutCertificate).LatestQuorumCert.(*helper.TestQuorumCertificate).Rank = s.tc.GetRank() + 1
	err := s.validator.ValidateTimeoutCertificate(s.tc) // the QC should not be validated anymore
	assert.True(s.T(), models.IsInvalidTimeoutCertificateError(err), "if NewestQC.Rank > TC.Rank, an ErrorInvalidTC error should be raised")
}

// TestTCNewestQCIsNotHighest tests if correct error is returned when included QC is not highest
func (s *TCSuite) TestTCNewestQCIsNotHighest() {
	s.verifier.On("VerifyTimeoutCertificate", s.tc).Return(nil).Once()

	// highest QC rank is not equal to max(TONewestQCRanks)
	s.tc.(*helper.TestTimeoutCertificate).LatestRanks[0] = s.tc.GetLatestQuorumCert().GetRank() + 1
	err := s.validator.ValidateTimeoutCertificate(s.tc) // the QC should not be validated anymore
	assert.True(s.T(), models.IsInvalidTimeoutCertificateError(err), "if max(highQCRanks) != NewestQC.Rank, an ErrorInvalidTC error should be raised")
}

// TestTCInvalidSigners tests if correct error is returned when signers are invalid
func (s *TCSuite) TestTCInvalidSigners() {
	s.participants = s.participants[:6]                 // remove participant[6+] from the list of valid consensus participant
	err := s.validator.ValidateTimeoutCertificate(s.tc) // the QC should not be validated anymore
	assert.True(s.T(), models.IsInvalidTimeoutCertificateError(err), "if some signers are invalid consensus participants, an ErrorInvalidTC error should be raised")
}

// TestTCThresholdNotReached tests if correct error is returned when TC's singers don't have enough weight
func (s *TCSuite) TestTCThresholdNotReached() {
	// signers only have weight 1 out of 10 total (NOT have a supermajority)
	s.signers = s.participants[:1]
	indices := []byte{0b00000001, 0b00000000}

	s.tc.(*helper.TestTimeoutCertificate).AggregatedSignature.(*helper.TestAggregatedSignature).Bitmask = indices

	// adjust signers to be less than total weight
	err := s.validator.ValidateTimeoutCertificate(s.tc) // the QC should not be validated anymore
	assert.True(s.T(), models.IsInvalidTimeoutCertificateError(err), "if signers don't have enough weight, an ErrorInvalidTC error should be raised")
}

// TestTCInvalidNewestQC tests if correct error is returned when included highest QC is invalid
func (s *TCSuite) TestTCInvalidNewestQC() {
	*s.verifier = mocks.Verifier[*helper.TestVote]{}
	s.verifier.On("VerifyTimeoutCertificate", s.tc).Return(nil).Once()
	s.verifier.On("VerifyQuorumCertificate", s.tc.GetLatestQuorumCert()).Return(models.NewInvalidFormatErrorf("invalid qc")).Once()
	err := s.validator.ValidateTimeoutCertificate(s.tc) // the QC should not be validated anymore
	assert.True(s.T(), models.IsInvalidTimeoutCertificateError(err), "if included QC is invalid, an ErrorInvalidTC error should be raised")
}

// TestTCVerifyQuorumCertificate_ErrRankUnknown tests if ValidateTimeoutCertificate correctly handles VerifyQuorumCertificate's ErrRankUnknown sentinel error
// Validator shouldn't return a sentinel error here because this behavior is a symptom of internal bug, this behavior is not expected.
func (s *TCSuite) TestTCVerifyQuorumCertificate_ErrRankUnknown() {
	*s.verifier = mocks.Verifier[*helper.TestVote]{}
	s.verifier.On("VerifyTimeoutCertificate", s.tc).Return(nil).Once()
	s.verifier.On("VerifyQuorumCertificate", s.tc.GetLatestQuorumCert()).Return(models.ErrRankUnknown).Once()
	err := s.validator.ValidateTimeoutCertificate(s.tc) // the QC should not be validated anymore
	assert.Error(s.T(), err)
	assert.False(s.T(), models.IsInvalidTimeoutCertificateError(err), "we don't expect a sentinel error here")
	assert.NotErrorIs(s.T(), err, models.ErrRankUnknown, "we don't expect a sentinel error here")
}

// TestTCInvalidSignature tests a few scenarios when the signature is invalid or TC signers is malformed
func (s *TCSuite) TestTCInvalidSignature() {
	s.Run("insufficient-signatures", func() {
		*s.verifier = mocks.Verifier[*helper.TestVote]{}
		s.verifier.On("VerifyQuorumCertificate", mock.Anything).Return(nil).Once()
		s.verifier.On("VerifyTimeoutCertificate", s.tc).Return(models.NewInsufficientSignaturesErrorf("")).Once()

		// the Validator should _not_ interpret this as an invalid TC, but as an internal error
		err := s.validator.ValidateTimeoutCertificate(s.tc)
		assert.True(s.T(), models.IsInsufficientSignaturesError(err)) // unexpected error should be wrapped and propagated upwards
		assert.False(s.T(), models.IsInvalidTimeoutCertificateError(err), "should _not_ interpret this as a invalid TC, but as an internal error")
	})
	s.Run("invalid-format", func() {
		*s.verifier = mocks.Verifier[*helper.TestVote]{}
		s.verifier.On("VerifyQuorumCertificate", mock.Anything).Return(nil).Once()
		s.verifier.On("VerifyTimeoutCertificate", s.tc).Return(models.NewInvalidFormatErrorf("")).Once()
		err := s.validator.ValidateTimeoutCertificate(s.tc)
		assert.True(s.T(), models.IsInvalidTimeoutCertificateError(err), "if included TC's inputs are invalid, an ErrorInvalidTC error should be raised")
	})
	s.Run("invalid-signature", func() {
		*s.verifier = mocks.Verifier[*helper.TestVote]{}
		s.verifier.On("VerifyQuorumCertificate", mock.Anything).Return(nil).Once()
		s.verifier.On("VerifyTimeoutCertificate", s.tc).Return(models.ErrInvalidSignature).Once()
		err := s.validator.ValidateTimeoutCertificate(s.tc)
		assert.True(s.T(), models.IsInvalidTimeoutCertificateError(err), "if included TC's signature is invalid, an ErrorInvalidTC error should be raised")
	})
	s.Run("verify-sig-exception", func() {
		exception := errors.New("verify-sig-exception")
		*s.verifier = mocks.Verifier[*helper.TestVote]{}
		s.verifier.On("VerifyQuorumCertificate", mock.Anything).Return(nil).Once()
		s.verifier.On("VerifyTimeoutCertificate", s.tc).Return(exception).Once()
		err := s.validator.ValidateTimeoutCertificate(s.tc)
		assert.ErrorIs(s.T(), err, exception, "if included TC's signature is invalid, an exception should be propagated")
		assert.False(s.T(), models.IsInvalidTimeoutCertificateError(err))
	})
}
