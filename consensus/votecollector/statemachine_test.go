package votecollector

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gammazero/workerpool"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/mocks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

func TestStateMachine(t *testing.T) {
	suite.Run(t, new(StateMachineTestSuite))
}

var factoryError = errors.New("factory error")

// StateMachineTestSuite is a test suite for testing VoteCollector. It stores mocked
// VoteProcessors internally for testing behavior and state transitions for VoteCollector.
type StateMachineTestSuite struct {
	suite.Suite

	rank             uint64
	notifier         *mocks.VoteAggregationConsumer[*helper.TestState, *helper.TestVote]
	workerPool       *workerpool.WorkerPool
	factoryMethod    VerifyingVoteProcessorFactory[*helper.TestState, *helper.TestVote, *helper.TestPeer]
	mockedProcessors map[models.Identity]*mocks.VerifyingVoteProcessor[*helper.TestState, *helper.TestVote]
	collector        *VoteCollector[*helper.TestState, *helper.TestVote, *helper.TestPeer]
}

func (s *StateMachineTestSuite) TearDownTest() {
	// Without this line we are risking running into weird situations where one test has finished but there are active workers
	// that are executing some work on the shared pool. Need to ensure that all pending work has been executed before
	// starting next test.
	s.workerPool.StopWait()
}

func (s *StateMachineTestSuite) SetupTest() {
	s.rank = 1000
	s.mockedProcessors = make(map[models.Identity]*mocks.VerifyingVoteProcessor[*helper.TestState, *helper.TestVote])
	s.notifier = mocks.NewVoteAggregationConsumer[*helper.TestState, *helper.TestVote](s.T())

	s.factoryMethod = func(log consensus.TraceLogger, filter []byte, state *models.SignedProposal[*helper.TestState, *helper.TestVote], dsTag []byte, aggregator consensus.SignatureAggregator, voter consensus.VotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer]) (consensus.VerifyingVoteProcessor[*helper.TestState, *helper.TestVote], error) {
		if processor, found := s.mockedProcessors[state.State.Identifier]; found {
			return processor, nil
		}
		return nil, fmt.Errorf("mocked processor %v not found: %w", state.State.Identifier, factoryError)
	}

	s.workerPool = workerpool.New(4)
	s.collector = NewStateMachine(s.rank, []byte{}, helper.Logger(), s.workerPool, s.notifier, s.factoryMethod, []byte{}, consensus.SignatureAggregator(mocks.NewSignatureAggregator(s.T())), mocks.NewVotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer](s.T()))
}

// prepareMockedProcessor prepares a mocked processor and stores it in map, later it will be used
// to mock behavior of verifying vote processor.
func (s *StateMachineTestSuite) prepareMockedProcessor(proposal *models.SignedProposal[*helper.TestState, *helper.TestVote]) *mocks.VerifyingVoteProcessor[*helper.TestState, *helper.TestVote] {
	processor := &mocks.VerifyingVoteProcessor[*helper.TestState, *helper.TestVote]{}
	processor.On("State").Return(func() *models.State[*helper.TestState] {
		return proposal.State
	}).Maybe()
	processor.On("Status").Return(consensus.VoteCollectorStatusVerifying)
	s.mockedProcessors[proposal.State.Identifier] = processor
	return processor
}

// TestStatus_StateTransitions tests that Status returns correct state of VoteCollector in different scenarios
// when proposal processing can possibly change state of collector
func (s *StateMachineTestSuite) TestStatus_StateTransitions() {
	state := helper.MakeState(helper.WithStateRank[*helper.TestState](s.rank))
	proposerVote := helper.VoteForStateFixture(state)
	proposal := helper.MakeSignedProposal(
		helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(helper.WithState(state))),
		helper.WithVote[*helper.TestState, *helper.TestVote](&proposerVote),
	)
	processor := s.prepareMockedProcessor(proposal)
	processor.On("Process", mock.Anything).Return(nil).Maybe()
	s.notifier.On("OnVoteProcessed", mock.Anything).Maybe()

	// by default, we should create in caching status
	require.Equal(s.T(), consensus.VoteCollectorStatusCaching, s.collector.Status())

	// after processing state we should get into verifying status
	err := s.collector.ProcessState(proposal)
	require.NoError(s.T(), err)
	require.Equal(s.T(), consensus.VoteCollectorStatusVerifying, s.collector.Status())

	// after submitting double proposal we should transfer into invalid state
	err = s.collector.ProcessState(makeSignedProposalWithRank(s.rank))
	require.NoError(s.T(), err)
	require.Equal(s.T(), consensus.VoteCollectorStatusInvalid, s.collector.Status())
}

// TestStatus_FactoryErrorPropagation verifies that errors from the injected
// factory are handed through (potentially wrapped), but are not replaced.
func (s *StateMachineTestSuite) Test_FactoryErrorPropagation() {
	factoryError := errors.New("factory error")
	factory := func(log consensus.TraceLogger, filter []byte, state *models.SignedProposal[*helper.TestState, *helper.TestVote], dsTag []byte, aggregator consensus.SignatureAggregator, voter consensus.VotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer]) (consensus.VerifyingVoteProcessor[*helper.TestState, *helper.TestVote], error) {
		return nil, factoryError
	}
	s.collector.createVerifyingProcessor = factory

	// failing to create collector has to result in error and won't change state
	proposal := makeSignedProposalWithRank(s.rank)
	err := s.collector.ProcessState(proposal)
	require.ErrorIs(s.T(), err, factoryError)
	require.Equal(s.T(), consensus.VoteCollectorStatusCaching, s.collector.Status())
}

// TestAddVote_VerifyingState tests that AddVote correctly process valid and invalid votes as well
// as repeated, invalid and double votes in verifying state
func (s *StateMachineTestSuite) TestAddVote_VerifyingState() {
	proposal := makeSignedProposalWithRank(s.rank)
	state := proposal.State
	processor := s.prepareMockedProcessor(proposal)
	// The proposer vote embedded in the proposal will be cached and processed
	s.notifier.On("OnVoteProcessed", proposal.Vote).Maybe()
	processor.On("Process", proposal.Vote).Return(nil).Maybe()
	err := s.collector.ProcessState(proposal)
	require.NoError(s.T(), err)
	s.T().Run("add-valid-vote", func(t *testing.T) {
		vote := helper.VoteForStateFixture(state)
		s.notifier.On("OnVoteProcessed", &vote).Once()
		processor.On("Process", &vote).Return(nil).Once()
		err := s.collector.AddVote(&vote)
		require.NoError(t, err)
		processor.AssertCalled(t, "Process", &vote)
	})
	s.T().Run("add-double-vote", func(t *testing.T) {
		firstVote := helper.VoteForStateFixture(state)
		s.notifier.On("OnVoteProcessed", &firstVote).Once()
		processor.On("Process", &firstVote).Return(nil).Once()
		err := s.collector.AddVote(&firstVote)
		require.NoError(t, err)

		secondVote := helper.VoteFixture(func(vote **helper.TestVote) {
			(*vote).Rank = firstVote.Rank
			(*vote).ID = firstVote.ID
		}) // voted stateID is randomly sampled, i.e. it will be different from firstVote
		s.notifier.On("OnDoubleVotingDetected", &firstVote, &secondVote).Return(nil).Once()

		err = s.collector.AddVote(&secondVote)
		// we shouldn't get an error
		require.NoError(t, err)

		// but should get notified about double voting
		s.notifier.AssertCalled(t, "OnDoubleVotingDetected", &firstVote, &secondVote)
		processor.AssertCalled(t, "Process", &firstVote)
	})
	s.T().Run("add-invalid-vote", func(t *testing.T) {
		vote := helper.VoteForStateFixture(state, func(vote **helper.TestVote) {
			(*vote).Rank = s.rank
		})
		processor.On("Process", &vote).Return(models.NewInvalidVoteErrorf[*helper.TestVote](&vote, "")).Once()
		s.notifier.On("OnInvalidVoteDetected", mock.Anything).Run(func(args mock.Arguments) {
			invalidVoteErr := args.Get(0).(models.InvalidVoteError[*helper.TestVote])
			require.Equal(s.T(), &vote, invalidVoteErr.Vote)
		}).Return(nil).Once()
		err := s.collector.AddVote(&vote)
		// in case process returns models.InvalidVoteError we should silently ignore this error
		require.NoError(t, err)

		// but should get notified about invalid vote
		s.notifier.AssertCalled(t, "OnInvalidVoteDetected", mock.Anything)
		processor.AssertCalled(t, "Process", &vote)
	})
	s.T().Run("add-repeated-vote", func(t *testing.T) {
		vote := helper.VoteForStateFixture(state)
		s.notifier.On("OnVoteProcessed", &vote).Once()
		processor.On("Process", &vote).Return(nil).Once()
		err := s.collector.AddVote(&vote)
		require.NoError(t, err)

		// calling with same vote should exit early without error and don't do any extra processing
		err = s.collector.AddVote(&vote)
		require.NoError(t, err)

		processor.AssertCalled(t, "Process", &vote)
	})
	s.T().Run("add-incompatible-rank-vote", func(t *testing.T) {
		vote := helper.VoteForStateFixture(state, func(vote **helper.TestVote) {
			(*vote).Rank = s.rank + 1
		})
		err := s.collector.AddVote(&vote)
		require.ErrorIs(t, err, VoteForIncompatibleRankError)
	})
	s.T().Run("add-incompatible-state-vote", func(t *testing.T) {
		vote := helper.VoteForStateFixture(state, func(vote **helper.TestVote) {
			(*vote).Rank = s.rank
		})
		processor.On("Process", &vote).Return(VoteForIncompatibleStateError).Once()
		err := s.collector.AddVote(&vote)
		// in case process returns VoteForIncompatibleStateError we should silently ignore this error
		require.NoError(t, err)
		processor.AssertCalled(t, "Process", &vote)
	})
	s.T().Run("unexpected-VoteProcessor-errors-are-passed-up", func(t *testing.T) {
		unexpectedError := errors.New("some unexpected error")
		vote := helper.VoteForStateFixture(state, func(vote **helper.TestVote) {
			(*vote).Rank = s.rank
		})
		processor.On("Process", &vote).Return(unexpectedError).Once()
		err := s.collector.AddVote(&vote)
		require.ErrorIs(t, err, unexpectedError)
	})
}

// TestProcessState_ProcessingOfCachedVotes tests that after processing state proposal are cached votes
// are sent to vote processor
func (s *StateMachineTestSuite) TestProcessState_ProcessingOfCachedVotes() {
	votes := 10
	proposal := makeSignedProposalWithRank(s.rank)
	state := proposal.State
	processor := s.prepareMockedProcessor(proposal)
	// The proposer vote embedded in the proposal will be cached and processed
	s.notifier.On("OnVoteProcessed", proposal.Vote).Maybe()
	processor.On("Process", proposal.Vote).Return(nil).Maybe()
	for i := 0; i < votes; i++ {
		vote := helper.VoteForStateFixture(state)
		// once when caching vote, and once when processing cached vote
		s.notifier.On("OnVoteProcessed", &vote).Twice()
		// eventually it has to be processed by processor
		processor.On("Process", &vote).Return(nil).Once()
		require.NoError(s.T(), s.collector.AddVote(&vote))
	}

	err := s.collector.ProcessState(proposal)
	require.NoError(s.T(), err)

	time.Sleep(100 * time.Millisecond)

	processor.AssertExpectations(s.T())
}

// Test_VoteProcessorErrorPropagation verifies that unexpected errors from the `VoteProcessor`
// are propagated up the call stack (potentially wrapped), but are not replaced.
func (s *StateMachineTestSuite) Test_VoteProcessorErrorPropagation() {
	proposal := makeSignedProposalWithRank(s.rank)
	state := proposal.State
	processor := s.prepareMockedProcessor(proposal)

	proposerVote := helper.VoteForStateFixture(state)
	processor.On("Process", &proposerVote).Return(nil).Maybe()
	s.notifier.On("OnVoteProcessed", &proposerVote).Maybe()
	err := s.collector.ProcessState(helper.MakeSignedProposal[*helper.TestState, *helper.TestVote](
		helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(helper.WithState[*helper.TestState](state))),
		helper.WithVote[*helper.TestState, *helper.TestVote](&proposerVote)))
	require.NoError(s.T(), err)

	unexpectedError := errors.New("some unexpected error")
	vote := helper.VoteForStateFixture(state, func(vote **helper.TestVote) {
		(*vote).Rank = s.rank
	})
	processor.On("Process", &vote).Return(unexpectedError).Once()
	err = s.collector.AddVote(&vote)
	require.ErrorIs(s.T(), err, unexpectedError)
}

// RegisterVoteConsumer verifies that after registering vote consumer we are receiving all new and past votes
// in strict ordering of arrival.
func (s *StateMachineTestSuite) RegisterVoteConsumer() {
	votes := 10
	proposal := makeSignedProposalWithRank(s.rank)
	state := proposal.State
	processor := s.prepareMockedProcessor(proposal)
	expectedVotes := make([]*helper.TestVote, 0)
	for i := 0; i < votes; i++ {
		vote := helper.VoteForStateFixture(state)
		// eventually it has to be process by processor
		processor.On("Process", &vote).Return(nil).Once()
		require.NoError(s.T(), s.collector.AddVote(&vote))
		expectedVotes = append(expectedVotes, vote)
	}

	actualVotes := make([]*helper.TestVote, 0)
	consumer := func(vote **helper.TestVote) {
		actualVotes = append(actualVotes, *vote)
	}

	s.collector.RegisterVoteConsumer(consumer)

	for i := 0; i < votes; i++ {
		vote := helper.VoteForStateFixture(state)
		// eventually it has to be process by processor
		processor.On("Process", &vote).Return(nil).Once()
		require.NoError(s.T(), s.collector.AddVote(&vote))
		expectedVotes = append(expectedVotes, vote)
	}

	require.Equal(s.T(), expectedVotes, actualVotes)
}

func makeSignedProposalWithRank(rank uint64) *models.SignedProposal[*helper.TestState, *helper.TestVote] {
	state := helper.MakeState(helper.WithStateRank[*helper.TestState](rank))
	vote := helper.VoteForStateFixture(state)
	return helper.MakeSignedProposal(
		helper.WithProposal[*helper.TestState, *helper.TestVote](helper.MakeProposal(helper.WithState(state))),
		helper.WithVote[*helper.TestState, *helper.TestVote](&vote),
	)
}
