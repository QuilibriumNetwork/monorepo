package eventhandler

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/mocks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/pacemaker"
	"source.quilibrium.com/quilibrium/monorepo/consensus/pacemaker/timeout"
)

const (
	minRepTimeout             float64 = 100.0 // Milliseconds
	maxRepTimeout             float64 = 600.0 // Milliseconds
	multiplicativeIncrease    float64 = 1.5   // multiplicative factor
	happyPathMaxRoundFailures uint64  = 6     // number of failed rounds before first timeout increase
)

// TestPacemaker is a real pacemaker module with logging for rank changes
type TestPacemaker[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
	CollectedT models.Unique,
] struct {
	consensus.Pacemaker
}

var _ consensus.Pacemaker = (*TestPacemaker[*nilUnique, *nilUnique, *nilUnique, *nilUnique])(nil)

func NewTestPacemaker[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
	CollectedT models.Unique,
](
	timeoutController *timeout.Controller,
	proposalDelayProvider consensus.ProposalDurationProvider,
	notifier consensus.Consumer[StateT, VoteT],
	store consensus.ConsensusStore[VoteT],
) *TestPacemaker[StateT, VoteT, PeerIDT, CollectedT] {
	p, err := pacemaker.NewPacemaker[StateT, VoteT](nil, timeoutController, proposalDelayProvider, notifier, store, helper.Logger())
	if err != nil {
		panic(err)
	}
	return &TestPacemaker[StateT, VoteT, PeerIDT, CollectedT]{p}
}

func (p *TestPacemaker[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) ReceiveQuorumCertificate(qc models.QuorumCertificate) (*models.NextRank, error) {
	oldRank := p.CurrentRank()
	newRank, err := p.Pacemaker.ReceiveQuorumCertificate(qc)
	fmt.Printf("pacemaker.ReceiveQuorumCertificate old rank: %v, new rank: %v\n", oldRank, p.CurrentRank())
	return newRank, err
}

func (p *TestPacemaker[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) ReceiveTimeoutCertificate(tc models.TimeoutCertificate) (*models.NextRank, error) {
	oldRank := p.CurrentRank()
	newRank, err := p.Pacemaker.ReceiveTimeoutCertificate(tc)
	fmt.Printf("pacemaker.ReceiveTimeoutCertificate old rank: %v, new rank: %v\n", oldRank, p.CurrentRank())
	return newRank, err
}

func (p *TestPacemaker[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) LatestQuorumCertificate() models.QuorumCertificate {
	return p.Pacemaker.LatestQuorumCertificate()
}

func (p *TestPacemaker[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) PriorRankTimeoutCertificate() models.TimeoutCertificate {
	return p.Pacemaker.PriorRankTimeoutCertificate()
}

type nodelay struct{}

// TargetPublicationTime implements consensus.ProposalDurationProvider.
func (n *nodelay) TargetPublicationTime(proposalRank uint64, timeRankEntered time.Time, parentStateId models.Identity) time.Time {
	return timeRankEntered
}

var _ consensus.ProposalDurationProvider = (*nodelay)(nil)

// using a real pacemaker for testing event handler
func initPacemaker(t require.TestingT, ctx context.Context, livenessData *models.LivenessState) consensus.Pacemaker {
	notifier := &mocks.Consumer[*helper.TestState, *helper.TestVote]{}
	tc, err := timeout.NewConfig(time.Duration(minRepTimeout*1e6), time.Duration(maxRepTimeout*1e6), multiplicativeIncrease, happyPathMaxRoundFailures, time.Duration(maxRepTimeout*1e6))
	require.NoError(t, err)
	persist := &mocks.ConsensusStore[*helper.TestVote]{}
	persist.On("PutLivenessState", mock.Anything).Return(nil).Maybe()
	persist.On("GetLivenessState", mock.Anything).Return(livenessData, nil).Once()
	pm := NewTestPacemaker[*helper.TestState, *helper.TestVote, *helper.TestPeer, *helper.TestCollected](timeout.NewController(tc), pacemaker.NoProposalDelay(), notifier, persist)
	notifier.On("OnStartingTimeout", mock.Anything, mock.Anything).Return()
	notifier.On("OnQuorumCertificateTriggeredRankChange", mock.Anything, mock.Anything, mock.Anything).Return()
	notifier.On("OnTimeoutCertificateTriggeredRankChange", mock.Anything, mock.Anything, mock.Anything).Return()
	notifier.On("OnRankChange", mock.Anything, mock.Anything).Maybe()
	pm.Start(ctx)
	return pm
}

// Committee mocks hotstuff.DynamicCommittee and allows to easily control leader for some rank.
type Committee struct {
	*mocks.Replicas
	// to mock I'm the leader of a certain rank, add the rank into the keys of leaders field
	leaders map[uint64]struct{}
}

func NewCommittee(t *testing.T) *Committee {
	committee := &Committee{
		Replicas: mocks.NewReplicas(t),
		leaders:  make(map[uint64]struct{}),
	}
	committee.On("LeaderForRank", mock.Anything).Return(func(rank uint64) models.Identity {
		_, isLeader := committee.leaders[rank]
		if isLeader {
			return "1"
		}
		return "0"
	}, func(rank uint64) error {
		return nil
	}).Maybe()

	committee.On("Self").Return("1").Maybe()

	return committee
}

// The SafetyRules mock will not vote for any state unless the state's ID exists in votable field's key
type SafetyRules struct {
	*mocks.SafetyRules[*helper.TestState, *helper.TestVote]
	votable map[models.Identity]struct{}
}

func NewSafetyRules(t *testing.T) *SafetyRules {
	safetyRules := &SafetyRules{
		SafetyRules: mocks.NewSafetyRules[*helper.TestState, *helper.TestVote](t),
		votable:     make(map[models.Identity]struct{}),
	}

	// SafetyRules will not vote for any state, unless the stateID exists in votable map
	safetyRules.On("ProduceVote", mock.Anything, mock.Anything).Return(
		func(state *models.SignedProposal[*helper.TestState, *helper.TestVote], _ uint64) **helper.TestVote {
			_, ok := safetyRules.votable[state.State.Identifier]
			if !ok {
				return nil
			}
			v := createVote(state.State)
			return &v
		},
		func(state *models.SignedProposal[*helper.TestState, *helper.TestVote], _ uint64) error {
			_, ok := safetyRules.votable[state.State.Identifier]
			if !ok {
				return models.NewNoVoteErrorf("state not found")
			}
			return nil
		}).Maybe()

	safetyRules.On("ProduceTimeout", mock.Anything, mock.Anything, mock.Anything).Return(
		func(curRank uint64, newestQC models.QuorumCertificate, lastRankTC models.TimeoutCertificate) *models.TimeoutState[*helper.TestVote] {
			return helper.TimeoutStateFixture(func(timeout *models.TimeoutState[*helper.TestVote]) {
				timeout.Rank = curRank
				timeout.LatestQuorumCertificate = newestQC
				timeout.PriorRankTimeoutCertificate = lastRankTC
			}, helper.WithTimeoutVote(&helper.TestVote{Rank: curRank, ID: helper.MakeIdentity()}))
		},
		func(uint64, models.QuorumCertificate, models.TimeoutCertificate) error { return nil }).Maybe()

	return safetyRules
}

// Forks mock allows to customize the AddState function by specifying the addProposal callbacks
type Forks struct {
	*mocks.Forks[*helper.TestState]
	// proposals stores all the proposals that have been added to the forks
	proposals map[models.Identity]*models.State[*helper.TestState]
	finalized uint64
	t         require.TestingT
	// addProposal is to customize the logic to change finalized rank
	addProposal func(state *models.State[*helper.TestState]) error
}

func NewForks(t *testing.T, finalized uint64) *Forks {
	f := &Forks{
		Forks:     mocks.NewForks[*helper.TestState](t),
		proposals: make(map[models.Identity]*models.State[*helper.TestState]),
		finalized: finalized,
	}

	f.On("AddValidatedState", mock.Anything).Return(func(proposal *models.State[*helper.TestState]) error {
		fmt.Printf("forks.AddValidatedState received State proposal for rank: %v, QC: %v\n", proposal.Rank, proposal.ParentQuorumCertificate.GetRank())
		return f.addProposal(proposal)
	}).Maybe()

	f.On("FinalizedRank").Return(func() uint64 {
		return f.finalized
	}).Maybe()

	f.On("GetState", mock.Anything).Return(func(stateID models.Identity) *models.State[*helper.TestState] {
		b := f.proposals[stateID]
		return b
	}, func(stateID models.Identity) bool {
		b, ok := f.proposals[stateID]
		var rank uint64
		if ok {
			rank = b.Rank
		}
		fmt.Printf("forks.GetState found %v: rank: %v\n", ok, rank)
		return ok
	}).Maybe()

	f.On("GetStatesForRank", mock.Anything).Return(func(rank uint64) []*models.State[*helper.TestState] {
		proposals := make([]*models.State[*helper.TestState], 0)
		for _, b := range f.proposals {
			if b.Rank == rank {
				proposals = append(proposals, b)
			}
		}
		fmt.Printf("forks.GetStatesForRank found %v state(s) for rank %v\n", len(proposals), rank)
		return proposals
	}).Maybe()

	f.addProposal = func(state *models.State[*helper.TestState]) error {
		f.proposals[state.Identifier] = state
		if state.ParentQuorumCertificate == nil {
			panic(fmt.Sprintf("state has no QC: %v", state.Rank))
		}
		return nil
	}

	return f
}

// StateProducer mock will always make a valid state, exactly once per rank.
// If it is requested to make a state twice for the same rank, returns models.NoVoteError
type StateProducer struct {
	proposerID           models.Identity
	producedStateForRank map[uint64]bool
}

func NewStateProducer(proposerID models.Identity) *StateProducer {
	return &StateProducer{
		proposerID:           proposerID,
		producedStateForRank: make(map[uint64]bool),
	}
}

func (b *StateProducer) MakeStateProposal(rank uint64, qc models.QuorumCertificate, lastRankTC models.TimeoutCertificate) (*models.SignedProposal[*helper.TestState, *helper.TestVote], error) {
	if b.producedStateForRank[rank] {
		return nil, models.NewNoVoteErrorf("state already produced")
	}
	b.producedStateForRank[rank] = true
	return helper.MakeSignedProposal[*helper.TestState, *helper.TestVote](
		helper.WithProposal[*helper.TestState, *helper.TestVote](
			helper.MakeProposal(helper.WithState(helper.MakeState(
				helper.WithStateRank[*helper.TestState](rank),
				helper.WithStateQC[*helper.TestState](qc),
				helper.WithStateProposer[*helper.TestState](b.proposerID))),
				helper.WithPreviousRankTimeoutCertificate[*helper.TestState](lastRankTC)))), nil
}

func TestEventHandler(t *testing.T) {
	suite.Run(t, new(EventHandlerSuite))
}

// EventHandlerSuite contains mocked state for testing event handler under different scenarios.
type EventHandlerSuite struct {
	suite.Suite

	eventhandler *EventHandler[*helper.TestState, *helper.TestVote, *helper.TestPeer, *helper.TestCollected]

	paceMaker     consensus.Pacemaker
	forks         *Forks
	persist       *mocks.ConsensusStore[*helper.TestVote]
	stateProducer *StateProducer
	committee     *Committee
	notifier      *mocks.Consumer[*helper.TestState, *helper.TestVote]
	safetyRules   *SafetyRules

	initRank       uint64 // the current rank at the beginning of the test case
	endRank        uint64 // the expected current rank at the end of the test case
	parentProposal *models.SignedProposal[*helper.TestState, *helper.TestVote]
	votingProposal *models.SignedProposal[*helper.TestState, *helper.TestVote]
	qc             models.QuorumCertificate
	tc             models.TimeoutCertificate
	newrank        *models.NextRank
	ctx            context.Context
	stop           context.CancelFunc
}

func (es *EventHandlerSuite) SetupTest() {
	finalized := uint64(3)

	es.parentProposal = createProposal(4, 3)
	newestQC := createQC(es.parentProposal.State)

	livenessData := &models.LivenessState{
		CurrentRank:             newestQC.GetRank() + 1,
		LatestQuorumCertificate: newestQC,
	}

	es.ctx, es.stop = context.WithCancel(context.Background())

	es.committee = NewCommittee(es.T())
	es.paceMaker = initPacemaker(es.T(), es.ctx, livenessData)
	es.forks = NewForks(es.T(), finalized)
	es.persist = mocks.NewConsensusStore[*helper.TestVote](es.T())
	es.persist.On("PutStarted", mock.Anything).Return(nil).Maybe()
	es.stateProducer = NewStateProducer(es.committee.Self())
	es.safetyRules = NewSafetyRules(es.T())
	es.notifier = mocks.NewConsumer[*helper.TestState, *helper.TestVote](es.T())
	es.notifier.On("OnEventProcessed").Maybe()
	es.notifier.On("OnEnteringRank", mock.Anything, mock.Anything).Maybe()
	es.notifier.On("OnStart", mock.Anything).Maybe()
	es.notifier.On("OnReceiveProposal", mock.Anything, mock.Anything).Maybe()
	es.notifier.On("OnReceiveQuorumCertificate", mock.Anything, mock.Anything).Maybe()
	es.notifier.On("OnReceiveTimeoutCertificate", mock.Anything, mock.Anything).Maybe()
	es.notifier.On("OnPartialTimeoutCertificate", mock.Anything, mock.Anything).Maybe()
	es.notifier.On("OnLocalTimeout", mock.Anything).Maybe()
	es.notifier.On("OnCurrentRankDetails", mock.Anything, mock.Anything, mock.Anything).Maybe()

	eventhandler, err := NewEventHandler[*helper.TestState, *helper.TestVote, *helper.TestPeer, *helper.TestCollected](
		es.paceMaker,
		es.stateProducer,
		es.forks,
		es.persist,
		es.committee,
		es.safetyRules,
		es.notifier,
		helper.Logger(),
	)
	require.NoError(es.T(), err)

	es.eventhandler = eventhandler

	es.initRank = livenessData.CurrentRank
	es.endRank = livenessData.CurrentRank
	// voting state is a state for the current rank, which will trigger rank change
	es.votingProposal = createProposal(es.paceMaker.CurrentRank(), es.parentProposal.State.Rank)
	es.qc = helper.MakeQC(helper.WithQCState[*helper.TestState](es.votingProposal.State))

	// create a TC that will trigger rank change for current rank, based on newest QC
	es.tc = helper.MakeTC(helper.WithTCRank(es.paceMaker.CurrentRank()),
		helper.WithTCNewestQC(es.votingProposal.State.ParentQuorumCertificate))
	es.newrank = &models.NextRank{
		Rank: es.votingProposal.State.Rank + 1, // the vote for the voting proposals will trigger a rank change to the next rank
	}

	// add es.parentProposal into forks, otherwise we won't vote or propose based on it's QC sicne the parent is unknown
	es.forks.proposals[es.parentProposal.State.Identifier] = es.parentProposal.State
}

// TestStartNewRank_ParentProposalNotFound tests next scenario: constructed TC, it contains NewestQC that references state that we
// don't know about, proposal can't be generated because we can't be sure that resulting state payload is valid.
func (es *EventHandlerSuite) TestStartNewRank_ParentProposalNotFound() {
	newestQC := helper.MakeQC(helper.WithQCRank(es.initRank + 10))
	tc := helper.MakeTC(helper.WithTCRank(newestQC.GetRank()+1),
		helper.WithTCNewestQC(newestQC))

	es.endRank = tc.GetRank() + 1

	// I'm leader for next state
	es.committee.leaders[es.endRank] = struct{}{}

	err := es.eventhandler.OnReceiveTimeoutCertificate(tc)
	require.NoError(es.T(), err)

	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "incorrect rank change")
	es.forks.AssertCalled(es.T(), "GetState", newestQC.Identity())
	es.notifier.AssertNotCalled(es.T(), "OnOwnProposal", mock.Anything, mock.Anything)
}

// TestOnReceiveProposal_StaleProposal test that proposals lower than finalized rank are not processed at all
// we are not interested in this data because we already performed finalization of that height.
func (es *EventHandlerSuite) TestOnReceiveProposal_StaleProposal() {
	proposal := createProposal(es.forks.FinalizedRank()-1, es.forks.FinalizedRank()-2)
	err := es.eventhandler.OnReceiveProposal(proposal)
	require.NoError(es.T(), err)
	es.forks.AssertNotCalled(es.T(), "AddState", proposal)
}

// TestOnReceiveProposal_QCOlderThanCurrentRank tests scenario: received a valid proposal with QC that has older rank,
// the proposal's QC shouldn't trigger rank change.
func (es *EventHandlerSuite) TestOnReceiveProposal_QCOlderThanCurrentRank() {
	proposal := createProposal(es.initRank-1, es.initRank-2)

	// should not trigger rank change
	err := es.eventhandler.OnReceiveProposal(proposal)
	require.NoError(es.T(), err)
	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "incorrect rank change")
	es.forks.AssertCalled(es.T(), "AddValidatedState", proposal.State)
}

// TestOnReceiveProposal_TCOlderThanCurrentRank tests scenario: received a valid proposal with QC and TC that has older rank,
// the proposal's QC shouldn't trigger rank change.
func (es *EventHandlerSuite) TestOnReceiveProposal_TCOlderThanCurrentRank() {
	proposal := createProposal(es.initRank-1, es.initRank-3)
	proposal.PreviousRankTimeoutCertificate = helper.MakeTC(helper.WithTCRank(proposal.State.Rank-1), helper.WithTCNewestQC(proposal.State.ParentQuorumCertificate))

	// should not trigger rank change
	err := es.eventhandler.OnReceiveProposal(proposal)
	require.NoError(es.T(), err)
	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "incorrect rank change")
	es.forks.AssertCalled(es.T(), "AddValidatedState", proposal.State)
}

// TestOnReceiveProposal_NoVote tests scenario: received a valid proposal for cur rank, but not a safe node to vote, and I'm the next leader
// should not vote.
func (es *EventHandlerSuite) TestOnReceiveProposal_NoVote() {
	proposal := createProposal(es.initRank, es.initRank-1)

	// I'm the next leader
	es.committee.leaders[es.initRank+1] = struct{}{}
	// no vote for this proposal
	err := es.eventhandler.OnReceiveProposal(proposal)
	require.NoError(es.T(), err)
	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "incorrect rank change")
	es.forks.AssertCalled(es.T(), "AddValidatedState", proposal.State)
}

// TestOnReceiveProposal_NoVote_ParentProposalNotFound tests scenario: received a valid proposal for cur rank, no parent for this proposal found
// should not vote.
func (es *EventHandlerSuite) TestOnReceiveProposal_NoVote_ParentProposalNotFound() {
	proposal := createProposal(es.initRank, es.initRank-1)

	// remove parent from known proposals
	delete(es.forks.proposals, proposal.State.ParentQuorumCertificate.Identity())

	// no vote for this proposal, no parent found
	err := es.eventhandler.OnReceiveProposal(proposal)
	require.Error(es.T(), err)
	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "incorrect rank change")
	es.forks.AssertCalled(es.T(), "AddValidatedState", proposal.State)
}

// TestOnReceiveProposal_Vote_NextLeader tests scenario: received a valid proposal for cur rank, safe to vote, I'm the next leader
// should vote and add vote to VoteAggregator.
func (es *EventHandlerSuite) TestOnReceiveProposal_Vote_NextLeader() {
	proposal := createProposal(es.initRank, es.initRank-1)

	// I'm the next leader
	es.committee.leaders[es.initRank+1] = struct{}{}

	// proposal is safe to vote
	es.safetyRules.votable[proposal.State.Identifier] = struct{}{}

	vote := &helper.TestVote{
		StateID: proposal.State.Identifier,
		Rank:    proposal.State.Rank,
	}

	es.notifier.On("OnOwnVote", mock.MatchedBy(func(v **helper.TestVote) bool { return vote.Rank == (*v).Rank && vote.StateID == (*v).StateID }), mock.Anything).Once()

	// vote should be created for this proposal
	err := es.eventhandler.OnReceiveProposal(proposal)
	require.NoError(es.T(), err)
	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "incorrect rank change")
}

// TestOnReceiveProposal_Vote_NotNextLeader tests scenario: received a valid proposal for cur rank, safe to vote, I'm not the next leader
// should vote and send vote to next leader.
func (es *EventHandlerSuite) TestOnReceiveProposal_Vote_NotNextLeader() {
	proposal := createProposal(es.initRank, es.initRank-1)

	// proposal is safe to vote
	es.safetyRules.votable[proposal.State.Identifier] = struct{}{}

	vote := &helper.TestVote{
		StateID: proposal.State.Identifier,
		Rank:    proposal.State.Rank,
		ID:      "0",
	}

	es.notifier.On("OnOwnVote", mock.MatchedBy(func(v **helper.TestVote) bool {
		return vote.Rank == (*v).Rank && vote.StateID == (*v).StateID && vote.ID == (*v).ID
	}), mock.Anything).Once()

	// vote should be created for this proposal
	err := es.eventhandler.OnReceiveProposal(proposal)
	require.NoError(es.T(), err)
	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "incorrect rank change")
}

// TestOnReceiveProposal_ProposeAfterReceivingTC tests a scenario where we have received TC which advances to rank where we are
// leader but no proposal can be created because we don't have parent proposal. After receiving missing parent proposal we have
// all available data to construct a valid proposal. We need to ensure this.
func (es *EventHandlerSuite) TestOnReceiveProposal_ProposeAfterReceivingQC() {

	qc := es.qc

	// first process QC this should advance rank
	err := es.eventhandler.OnReceiveQuorumCertificate(qc)
	require.NoError(es.T(), err)
	require.Equal(es.T(), qc.GetRank()+1, es.paceMaker.CurrentRank(), "expect a rank change")
	es.notifier.AssertNotCalled(es.T(), "OnOwnProposal", mock.Anything, mock.Anything)

	// we are leader for current rank
	es.committee.leaders[es.paceMaker.CurrentRank()] = struct{}{}

	es.notifier.On("OnOwnProposal", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		proposal, ok := args[0].(*models.SignedProposal[*helper.TestState, *helper.TestVote])
		require.True(es.T(), ok)
		// it should broadcast a header as the same as current rank
		require.Equal(es.T(), es.paceMaker.CurrentRank(), proposal.State.Rank)
	}).Once()

	// processing this proposal shouldn't trigger rank change since we have already seen QC.
	// we have used QC to advance rounds, but no proposal was made because we were missing parent state
	// when we have received parent state we can try proposing again.
	err = es.eventhandler.OnReceiveProposal(es.votingProposal)
	require.NoError(es.T(), err)

	require.Equal(es.T(), qc.GetRank()+1, es.paceMaker.CurrentRank(), "expect a rank change")
}

// TestOnReceiveProposal_ProposeAfterReceivingTC tests a scenario where we have received TC which advances to rank where we are
// leader but no proposal can be created because we don't have parent proposal. After receiving missing parent proposal we have
// all available data to construct a valid proposal. We need to ensure this.
func (es *EventHandlerSuite) TestOnReceiveProposal_ProposeAfterReceivingTC() {

	// TC contains a QC.StateID == es.votingProposal
	tc := helper.MakeTC(helper.WithTCRank(es.votingProposal.State.Rank+1),
		helper.WithTCNewestQC(es.qc))

	// first process TC this should advance rank
	err := es.eventhandler.OnReceiveTimeoutCertificate(tc)
	require.NoError(es.T(), err)
	require.Equal(es.T(), tc.GetRank()+1, es.paceMaker.CurrentRank(), "expect a rank change")
	es.notifier.AssertNotCalled(es.T(), "OnOwnProposal", mock.Anything, mock.Anything)

	// we are leader for current rank
	es.committee.leaders[es.paceMaker.CurrentRank()] = struct{}{}

	es.notifier.On("OnOwnProposal", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		proposal, ok := args[0].(*models.SignedProposal[*helper.TestState, *helper.TestVote])
		require.True(es.T(), ok)
		// it should broadcast a header as the same as current rank
		require.Equal(es.T(), es.paceMaker.CurrentRank(), proposal.State.Rank)
	}).Once()

	// processing this proposal shouldn't trigger rank change, since we have already seen QC.
	// we have used QC to advance rounds, but no proposal was made because we were missing parent state
	// when we have received parent state we can try proposing again.
	err = es.eventhandler.OnReceiveProposal(es.votingProposal)
	require.NoError(es.T(), err)

	require.Equal(es.T(), tc.GetRank()+1, es.paceMaker.CurrentRank(), "expect a rank change")
}

// TestOnReceiveQuorumCertificate_HappyPath tests that building a QC for current rank triggers rank change. We are not leader for next
// round, so no proposal is expected.
func (es *EventHandlerSuite) TestOnReceiveQuorumCertificate_HappyPath() {
	// voting state exists
	es.forks.proposals[es.votingProposal.State.Identifier] = es.votingProposal.State

	// a qc is built
	qc := createQC(es.votingProposal.State)

	// new qc is added to forks
	// rank changed
	// I'm not the next leader
	// haven't received state for next rank
	// goes to the new rank
	es.endRank++
	// not the leader of the newrank
	// don't have state for the newrank

	err := es.eventhandler.OnReceiveQuorumCertificate(qc)
	require.NoError(es.T(), err, "if a vote can trigger a QC to be built,"+
		"and the QC triggered a rank change, then start new rank")
	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "incorrect rank change")
	es.notifier.AssertNotCalled(es.T(), "OnOwnProposal", mock.Anything, mock.Anything)
}

// TestOnReceiveQuorumCertificate_FutureRank tests that building a QC for future rank triggers rank change
func (es *EventHandlerSuite) TestOnReceiveQuorumCertificate_FutureRank() {
	// voting state exists
	curRank := es.paceMaker.CurrentRank()

	// b1 is for current rank
	// b2 and b3 is for future rank, but branched out from the same parent as b1
	b1 := createProposal(curRank, curRank-1)
	b2 := createProposal(curRank+1, curRank-1)
	b3 := createProposal(curRank+2, curRank-1)

	// a qc is built
	// qc3 is for future rank
	// qc2 is an older than qc3
	// since vote aggregator can concurrently process votes and build qcs,
	// we prepare qcs at different rank to be processed, and verify the rank change.
	qc1 := createQC(b1.State)
	qc2 := createQC(b2.State)
	qc3 := createQC(b3.State)

	// all three proposals are known
	es.forks.proposals[b1.State.Identifier] = b1.State
	es.forks.proposals[b2.State.Identifier] = b2.State
	es.forks.proposals[b3.State.Identifier] = b3.State

	// test that qc for future rank should trigger rank change
	err := es.eventhandler.OnReceiveQuorumCertificate(qc3)
	endRank := b3.State.Rank + 1 // next rank
	require.NoError(es.T(), err, "if a vote can trigger a QC to be built,"+
		"and the QC triggered a rank change, then start new rank")
	require.Equal(es.T(), endRank, es.paceMaker.CurrentRank(), "incorrect rank change")

	// the same qc would not trigger rank change
	err = es.eventhandler.OnReceiveQuorumCertificate(qc3)
	endRank = b3.State.Rank + 1 // next rank
	require.NoError(es.T(), err, "same qc should not trigger rank change")
	require.Equal(es.T(), endRank, es.paceMaker.CurrentRank(), "incorrect rank change")

	// old QCs won't trigger rank change
	err = es.eventhandler.OnReceiveQuorumCertificate(qc2)
	require.NoError(es.T(), err)
	require.Equal(es.T(), endRank, es.paceMaker.CurrentRank(), "incorrect rank change")

	err = es.eventhandler.OnReceiveQuorumCertificate(qc1)
	require.NoError(es.T(), err)
	require.Equal(es.T(), endRank, es.paceMaker.CurrentRank(), "incorrect rank change")
}

// TestOnReceiveQuorumCertificate_NextLeaderProposes tests that after receiving a valid proposal for cur rank, and I'm the next leader,
// a QC can be built for the state, triggered rank change, and I will propose
func (es *EventHandlerSuite) TestOnReceiveQuorumCertificate_NextLeaderProposes() {
	proposal := createProposal(es.initRank, es.initRank-1)
	qc := createQC(proposal.State)
	// I'm the next leader
	es.committee.leaders[es.initRank+1] = struct{}{}
	// qc triggered rank change
	es.endRank++
	// I'm the leader of cur rank (7)
	// I'm not the leader of next rank (8), trigger rank change

	err := es.eventhandler.OnReceiveProposal(proposal)
	require.NoError(es.T(), err)

	es.notifier.On("OnOwnProposal", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		proposal, ok := args[0].(*models.SignedProposal[*helper.TestState, *helper.TestVote])
		require.True(es.T(), ok)
		// it should broadcast a header as the same as endRank
		require.Equal(es.T(), es.endRank, proposal.State.Rank)
	}).Once()

	// after receiving proposal build QC and deliver it to event handler
	err = es.eventhandler.OnReceiveQuorumCertificate(qc)
	require.NoError(es.T(), err)

	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "incorrect rank change")
	es.forks.AssertCalled(es.T(), "AddValidatedState", proposal.State)
}

// TestOnReceiveQuorumCertificate_ProposeOnce tests that after constructing proposal we don't attempt to create another
// proposal for same rank.
func (es *EventHandlerSuite) TestOnReceiveQuorumCertificate_ProposeOnce() {
	// I'm the next leader
	es.committee.leaders[es.initRank+1] = struct{}{}

	es.endRank++

	es.notifier.On("OnOwnProposal", mock.Anything, mock.Anything).Once()

	err := es.eventhandler.OnReceiveProposal(es.votingProposal)
	require.NoError(es.T(), err)

	// constructing QC triggers making state proposal
	err = es.eventhandler.OnReceiveQuorumCertificate(es.qc)
	require.NoError(es.T(), err)

	// receiving same proposal again triggers proposing logic
	err = es.eventhandler.OnReceiveProposal(es.votingProposal)
	require.NoError(es.T(), err)

	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "incorrect rank change")
	es.notifier.AssertNumberOfCalls(es.T(), "OnOwnProposal", 1)
}

// TestOnTCConstructed_HappyPath tests that building a TC for current rank triggers rank change
func (es *EventHandlerSuite) TestOnReceiveTimeoutCertificate_HappyPath() {
	// voting state exists
	es.forks.proposals[es.votingProposal.State.Identifier] = es.votingProposal.State

	// a tc is built
	tc := helper.MakeTC(helper.WithTCRank(es.initRank), helper.WithTCNewestQC(es.votingProposal.State.ParentQuorumCertificate))

	// expect a rank change
	es.endRank++

	err := es.eventhandler.OnReceiveTimeoutCertificate(tc)
	require.NoError(es.T(), err, "TC should trigger a rank change and start of new rank")
	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "incorrect rank change")
}

// TestOnTCConstructed_NextLeaderProposes tests that after receiving TC and advancing rank we as next leader create a proposal
// and broadcast it
func (es *EventHandlerSuite) TestOnReceiveTimeoutCertificate_NextLeaderProposes() {
	es.committee.leaders[es.tc.GetRank()+1] = struct{}{}
	es.endRank++

	es.notifier.On("OnOwnProposal", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		proposal, ok := args[0].(*models.SignedProposal[*helper.TestState, *helper.TestVote])
		require.True(es.T(), ok)
		// it should broadcast a header as the same as endRank
		require.Equal(es.T(), es.endRank, proposal.State.Rank)

		// proposed state should contain valid newest QC and lastRankTC
		expectedNewestQC := es.paceMaker.LatestQuorumCertificate()
		require.Equal(es.T(), expectedNewestQC, proposal.State.ParentQuorumCertificate)
		require.Equal(es.T(), es.paceMaker.PriorRankTimeoutCertificate(), proposal.PreviousRankTimeoutCertificate)
	}).Once()

	err := es.eventhandler.OnReceiveTimeoutCertificate(es.tc)
	require.NoError(es.T(), err)
	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "TC didn't trigger rank change")
}

// TestOnTimeout tests that event handler produces TimeoutState and broadcasts it to other members of consensus
// committee. Additionally, It has to contribute TimeoutState to timeout aggregation process by sending it to TimeoutAggregator.
func (es *EventHandlerSuite) TestOnTimeout() {
	es.notifier.On("OnOwnTimeout", mock.Anything).Run(func(args mock.Arguments) {
		timeoutState, ok := args[0].(*models.TimeoutState[*helper.TestVote])
		require.True(es.T(), ok)
		// it should broadcast a TO with same rank as endRank
		require.Equal(es.T(), es.endRank, timeoutState.Rank)
	}).Once()

	err := es.eventhandler.OnLocalTimeout()
	require.NoError(es.T(), err)

	// TimeoutState shouldn't trigger rank change
	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "incorrect rank change")
}

// TestOnTimeout_SanityChecks tests a specific scenario where pacemaker have seen both QC and TC for previous rank
// and EventHandler tries to produce a timeout state, such timeout state is invalid if both QC and TC is present, we
// need to make sure that EventHandler filters out TC for last rank if we know about QC for same rank.
func (es *EventHandlerSuite) TestOnTimeout_SanityChecks() {
	// voting state exists
	es.forks.proposals[es.votingProposal.State.Identifier] = es.votingProposal.State

	// a tc is built
	tc := helper.MakeTC(helper.WithTCRank(es.initRank), helper.WithTCNewestQC(es.votingProposal.State.ParentQuorumCertificate))

	// expect a rank change
	es.endRank++

	err := es.eventhandler.OnReceiveTimeoutCertificate(tc)
	require.NoError(es.T(), err, "TC should trigger a rank change and start of new rank")
	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "incorrect rank change")

	// receive a QC for the same rank as the TC
	qc := helper.MakeQC(helper.WithQCRank(tc.GetRank()))
	err = es.eventhandler.OnReceiveQuorumCertificate(qc)
	require.NoError(es.T(), err)
	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "QC shouldn't trigger rank change")
	require.Equal(es.T(), tc, es.paceMaker.PriorRankTimeoutCertificate(), "invalid last rank TC")
	require.Equal(es.T(), qc, es.paceMaker.LatestQuorumCertificate(), "invalid newest QC")

	es.notifier.On("OnOwnTimeout", mock.Anything).Run(func(args mock.Arguments) {
		timeoutState, ok := args[0].(*models.TimeoutState[*helper.TestVote])
		require.True(es.T(), ok)
		require.Equal(es.T(), es.endRank, timeoutState.Rank)
		require.Equal(es.T(), qc, timeoutState.LatestQuorumCertificate)
		require.Nil(es.T(), timeoutState.PriorRankTimeoutCertificate)
	}).Once()

	err = es.eventhandler.OnLocalTimeout()
	require.NoError(es.T(), err)
}

// TestOnTimeout_ReplicaEjected tests that EventHandler correctly handles possible errors from SafetyRules and doesn't broadcast
// timeout states when replica is ejected.
func (es *EventHandlerSuite) TestOnTimeout_ReplicaEjected() {
	es.Run("no-timeout", func() {
		*es.safetyRules.SafetyRules = *mocks.NewSafetyRules[*helper.TestState, *helper.TestVote](es.T())
		es.safetyRules.On("ProduceTimeout", mock.Anything, mock.Anything, mock.Anything).Return(nil, models.NewNoTimeoutErrorf(""))
		err := es.eventhandler.OnLocalTimeout()
		require.NoError(es.T(), err, "should be handled as sentinel error")
	})
	es.Run("create-timeout-exception", func() {
		*es.safetyRules.SafetyRules = *mocks.NewSafetyRules[*helper.TestState, *helper.TestVote](es.T())
		exception := errors.New("produce-timeout-exception")
		es.safetyRules.On("ProduceTimeout", mock.Anything, mock.Anything, mock.Anything).Return(nil, exception)
		err := es.eventhandler.OnLocalTimeout()
		require.ErrorIs(es.T(), err, exception, "expect a wrapped exception")
	})
	es.notifier.AssertNotCalled(es.T(), "OnOwnTimeout", mock.Anything)
}

// Test100Timeout tests that receiving 100 TCs for increasing ranks advances rounds
func (es *EventHandlerSuite) Test100Timeout() {
	for i := 0; i < 100; i++ {
		tc := helper.MakeTC(helper.WithTCRank(es.initRank + uint64(i)))
		err := es.eventhandler.OnReceiveTimeoutCertificate(tc)
		es.endRank++
		require.NoError(es.T(), err)
	}
	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "incorrect rank change")
}

// TestLeaderBuild100States tests scenario where leader builds 100 proposals one after another
func (es *EventHandlerSuite) TestLeaderBuild100States() {
	require.Equal(es.T(), 1, len(es.forks.proposals), "expect Forks to contain only root state")

	// I'm the leader for the first rank
	es.committee.leaders[es.initRank] = struct{}{}

	totalRank := 100
	for i := 0; i < totalRank; i++ {
		// I'm the leader for 100 ranks
		// I'm the next leader
		es.committee.leaders[es.initRank+uint64(i+1)] = struct{}{}
		// I can build qc for all 100 ranks
		proposal := createProposal(es.initRank+uint64(i), es.initRank+uint64(i)-1)
		qc := createQC(proposal.State)

		// for first proposal we need to store the parent otherwise it won't be voted for
		if i == 0 {
			parentState := helper.MakeState(func(state *models.State[*helper.TestState]) {
				state.Identifier = proposal.State.ParentQuorumCertificate.Identity()
				state.Rank = proposal.State.ParentQuorumCertificate.GetRank()
			})
			es.forks.proposals[parentState.Identifier] = parentState
		}

		es.safetyRules.votable[proposal.State.Identifier] = struct{}{}
		// should trigger 100 rank change
		es.endRank++

		es.notifier.On("OnOwnProposal", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
			ownProposal, ok := args[0].(*models.SignedProposal[*helper.TestState, *helper.TestVote])
			require.True(es.T(), ok)
			require.Equal(es.T(), proposal.State.Rank+1, ownProposal.State.Rank)
		}).Once()
		vote := &helper.TestVote{
			Rank:    proposal.State.Rank,
			StateID: proposal.State.Identifier,
		}
		es.notifier.On("OnOwnVote", mock.MatchedBy(func(v **helper.TestVote) bool { return vote.Rank == (*v).Rank && vote.StateID == (*v).StateID }), mock.Anything).Once()

		err := es.eventhandler.OnReceiveProposal(proposal)
		require.NoError(es.T(), err)
		err = es.eventhandler.OnReceiveQuorumCertificate(qc)
		require.NoError(es.T(), err)
	}

	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "incorrect rank change")
	require.Equal(es.T(), totalRank+1, len(es.forks.proposals), "expect Forks to contain root state + 100 proposed states")
	es.notifier.AssertExpectations(es.T())
}

// TestFollowerFollows100States tests scenario where follower receives 100 proposals one after another
func (es *EventHandlerSuite) TestFollowerFollows100States() {
	// add parent proposal otherwise we can't propose
	parentProposal := createProposal(es.initRank, es.initRank-1)
	es.forks.proposals[parentProposal.State.Identifier] = parentProposal.State
	for i := 0; i < 100; i++ {
		// create each proposal as if they are created by some leader
		proposal := createProposal(es.initRank+uint64(i)+1, es.initRank+uint64(i))
		// as a follower, I receive these proposals
		err := es.eventhandler.OnReceiveProposal(proposal)
		require.NoError(es.T(), err)
		es.endRank++
	}
	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "incorrect rank change")
	require.Equal(es.T(), 100, len(es.forks.proposals)-2)
}

// TestFollowerReceives100Forks tests scenario where follower receives 100 forks built on top of the same state
func (es *EventHandlerSuite) TestFollowerReceives100Forks() {
	for i := 0; i < 100; i++ {
		// create each proposal as if they are created by some leader
		proposal := createProposal(es.initRank+uint64(i)+1, es.initRank-1)
		proposal.PreviousRankTimeoutCertificate = helper.MakeTC(helper.WithTCRank(es.initRank+uint64(i)),
			helper.WithTCNewestQC(proposal.State.ParentQuorumCertificate))
		// expect a rank change since fork can be made only if last rank has ended with TC.
		es.endRank++
		// as a follower, I receive these proposals
		err := es.eventhandler.OnReceiveProposal(proposal)
		require.NoError(es.T(), err)
	}
	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "incorrect rank change")
	require.Equal(es.T(), 100, len(es.forks.proposals)-1)
}

// TestStart_ProposeOnce tests that after starting event handler we don't create proposal in case we have already proposed
// for this rank.
func (es *EventHandlerSuite) TestStart_ProposeOnce() {
	// I'm the next leader
	es.committee.leaders[es.initRank+1] = struct{}{}
	es.endRank++

	// STEP 1: simulating events _before_ a crash: EventHandler receives proposal and then a QC for the proposal (from VoteAggregator)
	es.notifier.On("OnOwnProposal", mock.Anything, mock.Anything).Once()
	err := es.eventhandler.OnReceiveProposal(es.votingProposal)
	require.NoError(es.T(), err)

	// constructing QC triggers making state proposal
	err = es.eventhandler.OnReceiveQuorumCertificate(es.qc)
	require.NoError(es.T(), err)
	es.notifier.AssertNumberOfCalls(es.T(), "OnOwnProposal", 1)

	// Here, a hypothetical crash would happen.
	// During crash recovery, Forks and Pacemaker are recovered to have exactly the same in-memory state as before
	// Start triggers proposing logic. But as our own proposal for the rank is already in Forks, we should not propose again.
	err = es.eventhandler.Start(es.ctx)
	require.NoError(es.T(), err)
	require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "incorrect rank change")

	// assert that broadcast wasn't trigger again, i.e. there should have been only one event `OnOwnProposal` in total
	es.notifier.AssertNumberOfCalls(es.T(), "OnOwnProposal", 1)
}

// TestCreateProposal_SanityChecks tests that proposing logic performs sanity checks when creating new state proposal.
// Specifically it tests a case where TC contains QC which: TC.Rank == TC.NewestQC.Rank
func (es *EventHandlerSuite) TestCreateProposal_SanityChecks() {
	// round ended with TC where TC.Rank == TC.NewestQC.Rank
	tc := helper.MakeTC(helper.WithTCRank(es.initRank),
		helper.WithTCNewestQC(helper.MakeQC(helper.WithQCState(es.votingProposal.State))))

	es.forks.proposals[es.votingProposal.State.Identifier] = es.votingProposal.State

	// I'm the next leader
	es.committee.leaders[tc.GetRank()+1] = struct{}{}

	es.notifier.On("OnOwnProposal", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		proposal, ok := args[0].(*models.SignedProposal[*helper.TestState, *helper.TestVote])
		require.True(es.T(), ok)
		// we need to make sure that produced proposal contains only QC even if there is TC for previous rank as well
		require.Nil(es.T(), proposal.PreviousRankTimeoutCertificate)
	}).Once()

	err := es.eventhandler.OnReceiveTimeoutCertificate(tc)
	require.NoError(es.T(), err)

	require.Equal(es.T(), tc.GetLatestQuorumCert(), es.paceMaker.LatestQuorumCertificate())
	require.Equal(es.T(), tc, es.paceMaker.PriorRankTimeoutCertificate())
	require.Equal(es.T(), tc.GetRank()+1, es.paceMaker.CurrentRank(), "incorrect rank change")
}

// TestOnReceiveProposal_ProposalForActiveRank tests that when receiving proposal for active we don't attempt to create a proposal
// Receiving proposal can trigger proposing logic only in case we have received missing state for past ranks.
func (es *EventHandlerSuite) TestOnReceiveProposal_ProposalForActiveRank() {
	// receive proposal where we are leader, meaning that we have produced this proposal
	es.committee.leaders[es.votingProposal.State.Rank] = struct{}{}

	err := es.eventhandler.OnReceiveProposal(es.votingProposal)
	require.NoError(es.T(), err)

	es.notifier.AssertNotCalled(es.T(), "OnOwnProposal", mock.Anything, mock.Anything)
}

// TestOnPartialTimeoutCertificateCreated_ProducedTimeout tests that when receiving partial TC for active rank we will create a timeout state
// immediately.
func (es *EventHandlerSuite) TestOnPartialTimeoutCertificateCreated_ProducedTimeout() {
	partialTimeoutCertificate := &consensus.PartialTimeoutCertificateCreated{
		Rank:                        es.initRank,
		NewestQuorumCertificate:     es.parentProposal.State.ParentQuorumCertificate,
		PriorRankTimeoutCertificate: nil,
	}

	es.notifier.On("OnOwnTimeout", mock.Anything).Run(func(args mock.Arguments) {
		timeoutState, ok := args[0].(*models.TimeoutState[*helper.TestVote])
		require.True(es.T(), ok)
		// it should broadcast a TO with same rank as partialTimeoutCertificate.Rank
		require.Equal(es.T(), partialTimeoutCertificate.Rank, timeoutState.Rank)
	}).Once()

	err := es.eventhandler.OnPartialTimeoutCertificateCreated(partialTimeoutCertificate)
	require.NoError(es.T(), err)

	// partial TC shouldn't trigger rank change
	require.Equal(es.T(), partialTimeoutCertificate.Rank, es.paceMaker.CurrentRank(), "incorrect rank change")
}

// TestOnPartialTimeoutCertificateCreated_NotActiveRank tests that we don't create timeout state if partial TC was delivered for a past, non-current rank.
// NOTE: it is not possible to receive a partial timeout for a FUTURE rank, unless the partial timeout contains
// either a QC/TC allowing us to enter that rank, therefore that case is not covered here.
// See TestOnPartialTimeoutCertificateCreated_QcAndTimeoutCertificateProcessing instead.
func (es *EventHandlerSuite) TestOnPartialTimeoutCertificateCreated_NotActiveRank() {
	partialTimeoutCertificate := &consensus.PartialTimeoutCertificateCreated{
		Rank:                    es.initRank - 1,
		NewestQuorumCertificate: es.parentProposal.State.ParentQuorumCertificate,
	}

	err := es.eventhandler.OnPartialTimeoutCertificateCreated(partialTimeoutCertificate)
	require.NoError(es.T(), err)

	// partial TC shouldn't trigger rank change
	require.Equal(es.T(), es.initRank, es.paceMaker.CurrentRank(), "incorrect rank change")
	// we don't want to create timeout if partial TC was delivered for rank different than active one.
	es.notifier.AssertNotCalled(es.T(), "OnOwnTimeout", mock.Anything)
}

// TestOnPartialTimeoutCertificateCreated_QcAndTimeoutCertificateProcessing tests that EventHandler processes QC and TC included in consensus.PartialTimeoutCertificateCreated
// data structure. This tests cases like the following example:
// * the pacemaker is in rank 10
// * we observe a partial timeout for rank 11 with a QC for rank 10
// * we should change to rank 11 using the QC, then broadcast a timeout for rank 11
func (es *EventHandlerSuite) TestOnPartialTimeoutCertificateCreated_QcAndTimeoutCertificateProcessing() {

	testOnPartialTimeoutCertificateCreated := func(partialTimeoutCertificate *consensus.PartialTimeoutCertificateCreated) {
		es.endRank++

		es.notifier.On("OnOwnTimeout", mock.Anything).Run(func(args mock.Arguments) {
			timeoutState, ok := args[0].(*models.TimeoutState[*helper.TestVote])
			require.True(es.T(), ok)
			// it should broadcast a TO with same rank as partialTimeoutCertificate.Rank
			require.Equal(es.T(), partialTimeoutCertificate.Rank, timeoutState.Rank)
		}).Once()

		err := es.eventhandler.OnPartialTimeoutCertificateCreated(partialTimeoutCertificate)
		require.NoError(es.T(), err)

		require.Equal(es.T(), es.endRank, es.paceMaker.CurrentRank(), "incorrect rank change")
	}

	es.Run("qc-triggered-rank-change", func() {
		partialTimeoutCertificate := &consensus.PartialTimeoutCertificateCreated{
			Rank:                    es.qc.GetRank() + 1,
			NewestQuorumCertificate: es.qc,
		}
		testOnPartialTimeoutCertificateCreated(partialTimeoutCertificate)
	})
	es.Run("tc-triggered-rank-change", func() {
		tc := helper.MakeTC(helper.WithTCRank(es.endRank), helper.WithTCNewestQC(es.qc))
		partialTimeoutCertificate := &consensus.PartialTimeoutCertificateCreated{
			Rank:                        tc.GetRank() + 1,
			NewestQuorumCertificate:     tc.GetLatestQuorumCert(),
			PriorRankTimeoutCertificate: tc,
		}
		testOnPartialTimeoutCertificateCreated(partialTimeoutCertificate)
	})
}

func createState(rank uint64) *models.State[*helper.TestState] {
	return &models.State[*helper.TestState]{
		Identifier: fmt.Sprintf("%d", rank),
		Rank:       rank,
	}
}

func createStateWithQC(rank uint64, qcrank uint64) *models.State[*helper.TestState] {
	state := createState(rank)
	parent := createState(qcrank)
	state.ParentQuorumCertificate = createQC(parent)
	return state
}

func createQC(parent *models.State[*helper.TestState]) models.QuorumCertificate {
	qc := &helper.TestQuorumCertificate{
		Selector:    parent.Identifier,
		Rank:        parent.Rank,
		FrameNumber: parent.Rank,
		AggregatedSignature: &helper.TestAggregatedSignature{
			Signature: make([]byte, 74),
			Bitmask:   []byte{0x1},
			PublicKey: make([]byte, 585),
		},
	}
	return qc
}

func createVote(state *models.State[*helper.TestState]) *helper.TestVote {
	return &helper.TestVote{
		Rank:      state.Rank,
		StateID:   state.Identifier,
		ID:        "0",
		Signature: make([]byte, 74),
	}
}

func createProposal(rank uint64, qcrank uint64) *models.SignedProposal[*helper.TestState, *helper.TestVote] {
	state := createStateWithQC(rank, qcrank)
	return helper.MakeSignedProposal[*helper.TestState, *helper.TestVote](
		helper.WithProposal[*helper.TestState, *helper.TestVote](
			helper.MakeProposal(helper.WithState(state))))
}
