package votecollector

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/mocks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// TestVoteProcessorFactory_CreateWithValidProposal checks if
// VoteProcessorFactory checks the proposer vote based on submitted proposal
func TestVoteProcessorFactory_CreateWithValidProposal(t *testing.T) {
	mockedFactory := mocks.VoteProcessorFactory[*helper.TestState, *helper.TestVote, *helper.TestPeer]{}

	proposal := helper.MakeSignedProposal[*helper.TestState, *helper.TestVote]()
	mockedProcessor := &mocks.VerifyingVoteProcessor[*helper.TestState, *helper.TestVote]{}
	vote, err := proposal.ProposerVote()
	require.NoError(t, err)
	mockedProcessor.On("Process", vote).Return(nil).Once()
	mockedFactory.On("Create", helper.Logger(), []byte{}, proposal, mock.Anything, mock.Anything, mock.Anything).Return(mockedProcessor, nil).Once()

	voteProcessorFactory := &VoteProcessorFactory[*helper.TestState, *helper.TestVote, *helper.TestPeer]{
		baseFactory: func(log consensus.TraceLogger, filter []byte, state *models.State[*helper.TestState], dsTag []byte, aggregator consensus.SignatureAggregator, votingProvider consensus.VotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer]) (consensus.VerifyingVoteProcessor[*helper.TestState, *helper.TestVote], error) {
			return mockedFactory.Create(log, filter, proposal, dsTag, aggregator, votingProvider)
		},
	}

	processor, err := voteProcessorFactory.Create(helper.Logger(), []byte{}, proposal, []byte{}, mocks.NewSignatureAggregator(t), mocks.NewVotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer](t))
	require.NoError(t, err)
	require.NotNil(t, processor)

	mockedProcessor.AssertExpectations(t)
	mockedFactory.AssertExpectations(t)
}

// TestVoteProcessorFactory_CreateWithInvalidVote tests that processing proposal with invalid vote doesn't return
// vote processor and returns correct error(sentinel or exception).
func TestVoteProcessorFactory_CreateWithInvalidVote(t *testing.T) {
	mockedFactory := mocks.VoteProcessorFactory[*helper.TestState, *helper.TestVote, *helper.TestPeer]{}

	t.Run("invalid-vote", func(t *testing.T) {
		proposal := helper.MakeSignedProposal[*helper.TestState, *helper.TestVote]()
		mockedProcessor := &mocks.VerifyingVoteProcessor[*helper.TestState, *helper.TestVote]{}
		vote, err := proposal.ProposerVote()
		require.NoError(t, err)
		mockedProcessor.On("Process", vote).Return(models.NewInvalidVoteErrorf(vote, "")).Once()
		mockedFactory.On("Create", helper.Logger(), []byte{}, proposal, mock.Anything, mock.Anything, mock.Anything).Return(mockedProcessor, nil).Once()

		voteProcessorFactory := &VoteProcessorFactory[*helper.TestState, *helper.TestVote, *helper.TestPeer]{
			baseFactory: func(log consensus.TraceLogger, filter []byte, state *models.State[*helper.TestState], dsTag []byte, aggregator consensus.SignatureAggregator, votingProvider consensus.VotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer]) (consensus.VerifyingVoteProcessor[*helper.TestState, *helper.TestVote], error) {
				return mockedFactory.Create(log, filter, proposal, dsTag, aggregator, votingProvider)
			},
		}

		processor, err := voteProcessorFactory.Create(helper.Logger(), []byte{}, proposal, []byte{}, mocks.NewSignatureAggregator(t), mocks.NewVotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer](t))
		require.Error(t, err)
		require.Nil(t, processor)
		require.True(t, models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err))

		mockedProcessor.AssertExpectations(t)
	})
	t.Run("process-vote-exception", func(t *testing.T) {
		proposal := helper.MakeSignedProposal[*helper.TestState, *helper.TestVote]()
		mockedProcessor := &mocks.VerifyingVoteProcessor[*helper.TestState, *helper.TestVote]{}
		exception := errors.New("process-exception")
		vote, err := proposal.ProposerVote()
		require.NoError(t, err)
		mockedProcessor.On("Process", vote).Return(exception).Once()

		mockedFactory.On("Create", helper.Logger(), []byte{}, proposal, mock.Anything, mock.Anything, mock.Anything).Return(mockedProcessor, nil).Once()

		voteProcessorFactory := &VoteProcessorFactory[*helper.TestState, *helper.TestVote, *helper.TestPeer]{
			baseFactory: func(log consensus.TraceLogger, filter []byte, state *models.State[*helper.TestState], dsTag []byte, aggregator consensus.SignatureAggregator, votingProvider consensus.VotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer]) (consensus.VerifyingVoteProcessor[*helper.TestState, *helper.TestVote], error) {
				return mockedFactory.Create(log, filter, proposal, dsTag, aggregator, votingProvider)
			},
		}

		processor, err := voteProcessorFactory.Create(helper.Logger(), []byte{}, proposal, []byte{}, mocks.NewSignatureAggregator(t), mocks.NewVotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer](t))
		require.ErrorIs(t, err, exception)
		require.Nil(t, processor)
		// an unexpected exception should _not_ be interpreted as the state being invalid
		require.False(t, models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err))

		mockedProcessor.AssertExpectations(t)
	})

	mockedFactory.AssertExpectations(t)
}

// TestVoteProcessorFactory_CreateProcessException tests that VoteProcessorFactory correctly handles exception
// while creating processor for requested proposal.
func TestVoteProcessorFactory_CreateProcessException(t *testing.T) {
	mockedFactory := mocks.VoteProcessorFactory[*helper.TestState, *helper.TestVote, *helper.TestPeer]{}

	proposal := helper.MakeSignedProposal[*helper.TestState, *helper.TestVote]()
	exception := errors.New("create-exception")

	mockedFactory.On("Create", helper.Logger(), []byte{}, proposal, mock.Anything, mock.Anything, mock.Anything).Return(nil, exception).Once()
	voteProcessorFactory := &VoteProcessorFactory[*helper.TestState, *helper.TestVote, *helper.TestPeer]{
		baseFactory: func(log consensus.TraceLogger, filter []byte, state *models.State[*helper.TestState], dsTag []byte, aggregator consensus.SignatureAggregator, votingProvider consensus.VotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer]) (consensus.VerifyingVoteProcessor[*helper.TestState, *helper.TestVote], error) {
			return mockedFactory.Create(log, filter, proposal, dsTag, aggregator, votingProvider)
		},
	}

	processor, err := voteProcessorFactory.Create(helper.Logger(), []byte{}, proposal, []byte{}, mocks.NewSignatureAggregator(t), mocks.NewVotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer](t))
	require.ErrorIs(t, err, exception)
	require.Nil(t, processor)
	// an unexpected exception should _not_ be interpreted as the state being invalid
	require.False(t, models.IsInvalidProposalError[*helper.TestState, *helper.TestVote](err))

	mockedFactory.AssertExpectations(t)
}
