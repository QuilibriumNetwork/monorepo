package integration

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/gammazero/workerpool"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/counters"
	"source.quilibrium.com/quilibrium/monorepo/consensus/eventhandler"
	"source.quilibrium.com/quilibrium/monorepo/consensus/forks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/mocks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/notifications"
	"source.quilibrium.com/quilibrium/monorepo/consensus/notifications/pubsub"
	"source.quilibrium.com/quilibrium/monorepo/consensus/pacemaker"
	"source.quilibrium.com/quilibrium/monorepo/consensus/pacemaker/timeout"
	"source.quilibrium.com/quilibrium/monorepo/consensus/safetyrules"
	"source.quilibrium.com/quilibrium/monorepo/consensus/stateproducer"
	"source.quilibrium.com/quilibrium/monorepo/consensus/timeoutaggregator"
	"source.quilibrium.com/quilibrium/monorepo/consensus/timeoutcollector"
	"source.quilibrium.com/quilibrium/monorepo/consensus/validator"
	"source.quilibrium.com/quilibrium/monorepo/consensus/voteaggregator"
	"source.quilibrium.com/quilibrium/monorepo/consensus/votecollector"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle/unittest"
)

type Instance struct {

	// instance parameters
	logger              consensus.TraceLogger
	participants        []models.WeightedIdentity
	localID             models.Identity
	dropVoteIn          VoteFilter
	dropVoteOut         VoteFilter
	dropPropIn          ProposalFilter
	dropPropOut         ProposalFilter
	dropTimeoutStateIn  TimeoutStateFilter
	dropTimeoutStateOut TimeoutStateFilter
	stop                Condition

	// instance data
	queue          chan interface{}
	updatingStates sync.RWMutex
	headers        map[models.Identity]*models.State[*helper.TestState]
	pendings       map[models.Identity]*models.SignedProposal[*helper.TestState, *helper.TestVote] // indexed by parent ID

	// mocked dependencies
	committee *mocks.DynamicCommittee
	builder   *mocks.LeaderProvider[*helper.TestState, *helper.TestPeer, *helper.TestCollected]
	finalizer *mocks.Finalizer
	persist   *mocks.ConsensusStore[*helper.TestVote]
	signer    *mocks.Signer[*helper.TestState, *helper.TestVote]
	verifier  *mocks.Verifier[*helper.TestVote]
	notifier  *MockedCommunicatorConsumer
	voting    *mocks.VotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer]

	// real dependencies
	pacemaker         consensus.Pacemaker
	producer          *stateproducer.StateProducer[*helper.TestState, *helper.TestVote, *helper.TestPeer, *helper.TestCollected]
	forks             *forks.Forks[*helper.TestState, *helper.TestVote]
	voteAggregator    *voteaggregator.VoteAggregator[*helper.TestState, *helper.TestVote]
	timeoutAggregator *timeoutaggregator.TimeoutAggregator[*helper.TestVote]
	safetyRules       *safetyrules.SafetyRules[*helper.TestState, *helper.TestVote]
	validator         *validator.Validator[*helper.TestState, *helper.TestVote]

	// main logic
	handler *eventhandler.EventHandler[*helper.TestState, *helper.TestVote, *helper.TestPeer, *helper.TestCollected]
}

type MockedCommunicatorConsumer struct {
	notifications.NoopProposalViolationConsumer[*helper.TestState, *helper.TestVote]
	notifications.NoopParticipantConsumer[*helper.TestState, *helper.TestVote]
	notifications.NoopFinalizationConsumer[*helper.TestState]
	*mocks.CommunicatorConsumer[*helper.TestState, *helper.TestVote]
}

func NewMockedCommunicatorConsumer() *MockedCommunicatorConsumer {
	return &MockedCommunicatorConsumer{
		CommunicatorConsumer: &mocks.CommunicatorConsumer[*helper.TestState, *helper.TestVote]{},
	}
}

var _ consensus.Consumer[*helper.TestState, *helper.TestVote] = (*MockedCommunicatorConsumer)(nil)
var _ consensus.TimeoutCollectorConsumer[*helper.TestVote] = (*Instance)(nil)

func NewInstance(t *testing.T, options ...Option) *Instance {

	// generate random default identity
	identity := helper.MakeIdentity()

	// initialize the default configuration
	cfg := Config{
		Logger: helper.Logger(),
		Root:   DefaultRoot(),
		Participants: []models.WeightedIdentity{&helper.TestWeightedIdentity{
			ID: identity,
		}},
		LocalID:               identity,
		Timeouts:              timeout.DefaultConfig,
		IncomingVotes:         DropNoVotes,
		OutgoingVotes:         DropNoVotes,
		IncomingProposals:     DropNoProposals,
		OutgoingProposals:     DropNoProposals,
		IncomingTimeoutStates: DropNoTimeoutStates,
		OutgoingTimeoutStates: DropNoTimeoutStates,
		StopCondition:         RightAway,
	}

	// apply the custom options
	for _, option := range options {
		option(&cfg)
	}

	// check the local ID is a participant
	takesPart := false
	for _, participant := range cfg.Participants {
		if participant.Identity() == cfg.LocalID {
			takesPart = true
			break
		}
	}
	require.True(t, takesPart)

	// initialize the instance
	in := Instance{

		// instance parameters
		logger:              cfg.Logger,
		participants:        cfg.Participants,
		localID:             cfg.LocalID,
		dropVoteIn:          cfg.IncomingVotes,
		dropVoteOut:         cfg.OutgoingVotes,
		dropPropIn:          cfg.IncomingProposals,
		dropPropOut:         cfg.OutgoingProposals,
		dropTimeoutStateIn:  cfg.IncomingTimeoutStates,
		dropTimeoutStateOut: cfg.OutgoingTimeoutStates,
		stop:                cfg.StopCondition,

		// instance data
		pendings: make(map[models.Identity]*models.SignedProposal[*helper.TestState, *helper.TestVote]),
		headers:  make(map[models.Identity]*models.State[*helper.TestState]),
		queue:    make(chan interface{}, 1024),

		// instance mocks
		committee: &mocks.DynamicCommittee{},
		builder:   &mocks.LeaderProvider[*helper.TestState, *helper.TestPeer, *helper.TestCollected]{},
		persist:   &mocks.ConsensusStore[*helper.TestVote]{},
		signer:    &mocks.Signer[*helper.TestState, *helper.TestVote]{},
		verifier:  &mocks.Verifier[*helper.TestVote]{},
		notifier:  NewMockedCommunicatorConsumer(),
		finalizer: &mocks.Finalizer{},
		voting:    &mocks.VotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer]{},
	}

	// insert root state into headers register
	in.headers[cfg.Root.Identifier] = cfg.Root

	// program the hotstuff committee state
	in.committee.On("IdentitiesByRank", mock.Anything).Return(
		func(_ uint64) []models.WeightedIdentity {
			return in.participants
		},
		nil,
	)
	in.committee.On("IdentitiesByState", mock.Anything).Return(
		func(_ models.Identity) []models.WeightedIdentity {
			return in.participants
		},
		nil,
	)
	for _, participant := range in.participants {
		in.committee.On("IdentityByState", mock.Anything, participant.Identity()).Return(participant, nil)
		in.committee.On("IdentityByRank", mock.Anything, participant.Identity()).Return(participant, nil)
	}
	in.committee.On("Self").Return(in.localID)
	in.committee.On("LeaderForRank", mock.Anything).Return(
		func(rank uint64) models.Identity {
			return in.participants[int(rank)%len(in.participants)].Identity()
		}, nil,
	)
	in.committee.On("QuorumThresholdForRank", mock.Anything).Return(uint64(len(in.participants)*2000/3), nil)
	in.committee.On("TimeoutThresholdForRank", mock.Anything).Return(uint64(len(in.participants)*2000/3), nil)

	// program the builder module behaviour
	in.builder.On("ProveNextState", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		func(ctx context.Context, rank uint64, filter []byte, parentID models.Identity) **helper.TestState {
			in.updatingStates.Lock()
			defer in.updatingStates.Unlock()

			_, ok := in.headers[parentID]
			if !ok {
				return nil
			}
			s := &helper.TestState{
				Rank:      rank,
				Signature: []byte{},
				Timestamp: uint64(time.Now().UnixMilli()),
				ID:        helper.MakeIdentity(),
				Prover:    in.localID,
			}
			return &s
		},
		func(ctx context.Context, rank uint64, filter []byte, parentID models.Identity) error {
			in.updatingStates.RLock()
			_, ok := in.headers[parentID]
			in.updatingStates.RUnlock()
			if !ok {
				return fmt.Errorf("parent state not found (parent: %x)", parentID)
			}
			return nil
		},
	)

	// check on stop condition, stop the tests as soon as entering a certain rank
	in.persist.On("PutConsensusState", mock.Anything).Return(nil)
	in.persist.On("PutLivenessState", mock.Anything).Return(nil)

	// program the hotstuff signer behaviour
	in.signer.On("CreateVote", mock.Anything).Return(
		func(state *models.State[*helper.TestState]) **helper.TestVote {
			vote := &helper.TestVote{
				Rank:      state.Rank,
				StateID:   state.Identifier,
				ID:        in.localID,
				Signature: make([]byte, 74),
			}
			return &vote
		},
		nil,
	)
	in.signer.On("CreateTimeout", mock.Anything, mock.Anything, mock.Anything).Return(
		func(curRank uint64, newestQC models.QuorumCertificate, previousRankTimeoutCert models.TimeoutCertificate) *models.TimeoutState[*helper.TestVote] {
			v := &helper.TestVote{
				Rank:      curRank,
				Signature: make([]byte, 74),
				Timestamp: uint64(time.Now().UnixMilli()),
				ID:        in.localID,
			}
			timeoutState := &models.TimeoutState[*helper.TestVote]{
				Rank:                        curRank,
				LatestQuorumCertificate:     newestQC,
				PriorRankTimeoutCertificate: previousRankTimeoutCert,
				Vote:                        &v,
			}
			return timeoutState
		},
		nil,
	)
	in.signer.On("CreateQuorumCertificate", mock.Anything).Return(
		func(votes []*helper.TestVote) models.QuorumCertificate {
			voterIDs := make([]models.Identity, 0, len(votes))
			bitmask := []byte{0, 0}
			for i, vote := range votes {
				bitmask[i/8] |= 1 << (i % 8)
				voterIDs = append(voterIDs, vote.ID)
			}

			qc := &helper.TestQuorumCertificate{
				Rank:        votes[0].Rank,
				FrameNumber: votes[0].Rank,
				Selector:    votes[0].StateID,
				Timestamp:   uint64(time.Now().UnixMilli()),
				AggregatedSignature: &helper.TestAggregatedSignature{
					Signature: make([]byte, 74),
					Bitmask:   bitmask,
					PublicKey: make([]byte, 585),
				},
			}
			return qc
		},
		nil,
	)

	// program the hotstuff verifier behaviour
	in.verifier.On("VerifyVote", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	in.verifier.On("VerifyQuorumCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	in.verifier.On("VerifyTimeoutCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	// program the hotstuff communicator behaviour
	in.notifier.CommunicatorConsumer.On("OnOwnProposal", mock.Anything, mock.Anything).Run(
		func(args mock.Arguments) {
			proposal, ok := args[0].(*models.SignedProposal[*helper.TestState, *helper.TestVote])
			require.True(t, ok)

			// sender should always have the parent
			in.updatingStates.RLock()
			_, exists := in.headers[proposal.State.ParentQuorumCertificate.Identity()]
			in.updatingStates.RUnlock()

			if !exists {
				t.Fatalf("parent for proposal not found parent: %x", proposal.State.ParentQuorumCertificate.Identity())
			}

			// store locally and loop back to engine for processing
			in.ProcessState(proposal)
		},
	)
	in.notifier.CommunicatorConsumer.On("OnOwnTimeout", mock.Anything).Run(func(args mock.Arguments) {
		timeoutState, ok := args[0].(*models.TimeoutState[*helper.TestVote])
		require.True(t, ok)
		in.queue <- timeoutState
	},
	)
	// in case of single node setup we should just forward vote to our own node
	// for multi-node setup this method will be overridden
	in.notifier.CommunicatorConsumer.On("OnOwnVote", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		vote, ok := args[0].(**helper.TestVote)
		require.True(t, ok)
		in.queue <- *vote
	})

	// program the finalizer module behaviour
	in.finalizer.On("MakeFinal", mock.Anything).Return(
		func(stateID models.Identity) error {

			// as we don't use mocks to assert expectations, but only to
			// simulate behaviour, we should drop the call data regularly
			in.updatingStates.RLock()
			state, found := in.headers[stateID]
			in.updatingStates.RUnlock()
			if !found {
				return fmt.Errorf("can't broadcast with unknown parent")
			}
			if state.Rank%100 == 0 {
				in.committee.Calls = nil
				in.builder.Calls = nil
				in.signer.Calls = nil
				in.verifier.Calls = nil
				in.notifier.CommunicatorConsumer.Calls = nil
				in.finalizer.Calls = nil
			}

			return nil
		},
	)

	// initialize error handling and logging
	var err error

	notifier := pubsub.NewDistributor[*helper.TestState, *helper.TestVote]()
	notifier.AddConsumer(in.notifier)
	logConsumer := notifications.NewLogConsumer[*helper.TestState, *helper.TestVote](in.logger)
	notifier.AddConsumer(logConsumer)

	// initialize the finalizer
	var rootState *models.State[*helper.TestState]
	if cfg.Root.ParentQuorumCertificate != nil {
		rootState = models.StateFrom(cfg.Root.State, cfg.Root.ParentQuorumCertificate)
	} else {
		rootState = models.GenesisStateFrom(cfg.Root.State)
	}

	rootQC := &helper.TestQuorumCertificate{
		Rank:        rootState.Rank,
		FrameNumber: rootState.Rank,
		Selector:    rootState.Identifier,
		Timestamp:   uint64(time.Now().UnixMilli()),
		AggregatedSignature: &helper.TestAggregatedSignature{
			Signature: make([]byte, 74),
			Bitmask:   []byte{0b11111111, 0b00000000},
			PublicKey: make([]byte, 585),
		},
	}
	certifiedRootState, err := models.NewCertifiedState(rootState, rootQC)
	require.NoError(t, err)

	livenessData := &models.LivenessState{
		CurrentRank:             rootQC.Rank + 1,
		LatestQuorumCertificate: rootQC,
	}

	in.persist.On("GetLivenessState", mock.Anything).Return(livenessData, nil).Once()

	// initialize the pacemaker
	controller := timeout.NewController(cfg.Timeouts)
	in.pacemaker, err = pacemaker.NewPacemaker[*helper.TestState, *helper.TestVote](nil, controller, pacemaker.NoProposalDelay(), notifier, in.persist, in.logger)
	require.NoError(t, err)

	// initialize the forks handler
	in.forks, err = forks.NewForks(certifiedRootState, in.finalizer, notifier)
	require.NoError(t, err)

	// initialize the validator
	in.validator = validator.NewValidator[*helper.TestState, *helper.TestVote](in.committee, in.verifier)

	packer := &mocks.Packer{}
	packer.On("Pack", mock.Anything, mock.Anything).Return(
		func(rank uint64, sig *consensus.StateSignatureData) ([]byte, []byte, error) {
			indices := []byte{0, 0}
			for i := range sig.Signers {
				indices[i/8] |= 1 << (i % 8)
			}

			return indices, make([]byte, 74), nil
		},
	).Maybe()

	onQCCreated := func(qc models.QuorumCertificate) {
		in.queue <- qc
	}

	voteProcessorFactory := mocks.NewVoteProcessorFactory[*helper.TestState, *helper.TestVote, *helper.TestPeer](t)
	voteProcessorFactory.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		func(tracer consensus.TraceLogger, filter []byte, proposal *models.SignedProposal[*helper.TestState, *helper.TestVote], dsTag []byte, aggregator consensus.SignatureAggregator, votingProvider consensus.VotingProvider[*helper.TestState, *helper.TestVote, *helper.TestPeer]) consensus.VerifyingVoteProcessor[*helper.TestState, *helper.TestVote] {
			processor, err := votecollector.NewBootstrapVoteProcessor[*helper.TestState, *helper.TestVote, *helper.TestPeer](
				in.logger,
				filter,
				in.committee,
				proposal.State,
				onQCCreated,
				[]byte{},
				aggregator,
				in.voting,
			)
			require.NoError(t, err)

			vote, err := proposal.ProposerVote()
			require.NoError(t, err)

			err = processor.Process(vote)
			if err != nil {
				t.Fatalf("invalid vote for own proposal: %v", err)
			}
			return processor
		}, nil).Maybe()
	in.voting.On("FinalizeQuorumCertificate", mock.Anything, mock.Anything, mock.Anything).Return(
		func(
			ctx context.Context,
			state *models.State[*helper.TestState],
			aggregatedSignature models.AggregatedSignature,
		) (models.QuorumCertificate, error) {
			return &helper.TestQuorumCertificate{
				Rank:                state.Rank,
				Timestamp:           state.Timestamp,
				FrameNumber:         state.Rank,
				Selector:            state.Identifier,
				AggregatedSignature: aggregatedSignature,
			}, nil
		},
	)
	in.voting.On("FinalizeTimeout", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		func(ctx context.Context, rank uint64, latestQuorumCertificate models.QuorumCertificate, latestQuorumCertificateRanks []consensus.TimeoutSignerInfo, aggregatedSignature models.AggregatedSignature) (models.TimeoutCertificate, error) {
			ranks := []uint64{}
			for _, i := range latestQuorumCertificateRanks {
				ranks = append(ranks, i.NewestQCRank)
			}
			return &helper.TestTimeoutCertificate{
				Filter:              nil,
				Rank:                rank,
				LatestRanks:         ranks,
				LatestQuorumCert:    latestQuorumCertificate,
				AggregatedSignature: aggregatedSignature,
			}, nil
		},
	)

	voteAggregationDistributor := pubsub.NewVoteAggregationDistributor[*helper.TestState, *helper.TestVote]()
	sigAgg := mocks.NewSignatureAggregator(t)
	sigAgg.On("Aggregate", mock.Anything, mock.Anything).Return(
		func(publicKeys [][]byte, signatures [][]byte) (models.AggregatedSignature, error) {
			bitmask := []byte{0, 0}
			for i := range publicKeys {
				bitmask[i/8] |= 1 << (i % 8)
			}
			return &helper.TestAggregatedSignature{
				Signature: make([]byte, 74),
				Bitmask:   bitmask,
				PublicKey: make([]byte, 585),
			}, nil
		}).Maybe()
	sigAgg.On("VerifySignatureRaw", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
	createCollectorFactoryMethod := votecollector.NewStateMachineFactory(in.logger, []byte{}, voteAggregationDistributor, voteProcessorFactory.Create, []byte{}, sigAgg, in.voting)
	voteCollectors := voteaggregator.NewVoteCollectors[*helper.TestState, *helper.TestVote](in.logger, livenessData.CurrentRank, workerpool.New(2), createCollectorFactoryMethod)

	// initialize the vote aggregator
	in.voteAggregator, err = voteaggregator.NewVoteAggregator[*helper.TestState, *helper.TestVote](
		in.logger,
		voteAggregationDistributor,
		livenessData.CurrentRank,
		voteCollectors,
	)
	require.NoError(t, err)

	// initialize factories for timeout collector and timeout processor
	timeoutAggregationDistributor := pubsub.NewTimeoutAggregationDistributor[*helper.TestVote]()
	timeoutProcessorFactory := mocks.NewTimeoutProcessorFactory[*helper.TestVote](t)
	timeoutProcessorFactory.On("Create", mock.Anything).Return(
		func(rank uint64) consensus.TimeoutProcessor[*helper.TestVote] {
			// mock signature aggregator which doesn't perform any crypto operations and just tracks total weight
			aggregator := &mocks.TimeoutSignatureAggregator{}
			totalWeight := atomic.NewUint64(0)
			newestRank := counters.NewMonotonicCounter(0)
			bits := counters.NewMonotonicCounter(0)
			aggregator.On("Rank").Return(rank).Maybe()
			aggregator.On("TotalWeight").Return(func() uint64 {
				return totalWeight.Load()
			}).Maybe()
			aggregator.On("VerifyAndAdd", mock.Anything, mock.Anything, mock.Anything).Return(
				func(signerID models.Identity, _ []byte, newestQCRank uint64) uint64 {
					newestRank.Set(newestQCRank)
					var signer models.WeightedIdentity
					for _, p := range in.participants {
						if p.Identity() == signerID {
							signer = p
						}
					}
					require.NotNil(t, signer)
					bits.Increment()
					return totalWeight.Add(signer.Weight())
				}, nil,
			).Maybe()
			aggregator.On("Aggregate").Return(
				func() []consensus.TimeoutSignerInfo {
					signersData := make([]consensus.TimeoutSignerInfo, 0, len(in.participants))
					newestQCRank := newestRank.Value()
					for _, signer := range in.participants {
						signersData = append(signersData, consensus.TimeoutSignerInfo{
							NewestQCRank: newestQCRank,
							Signer:       signer.Identity(),
						})
					}
					return signersData
				},
				func() models.AggregatedSignature {
					bitCount := bits.Value()
					bitmask := []byte{0, 0}
					for i := range bitCount {
						pos := i / 8
						bitmask[pos] |= 1 << (i % 8)
					}
					return &helper.TestAggregatedSignature{
						Signature: make([]byte, 74),
						Bitmask:   bitmask,
						PublicKey: make([]byte, 585),
					}
				},
				nil,
			).Maybe()

			p, err := timeoutcollector.NewTimeoutProcessor[*helper.TestState, *helper.TestVote, *helper.TestPeer](
				in.logger,
				in.committee,
				in.validator,
				aggregator,
				timeoutAggregationDistributor,
				in.voting,
			)
			require.NoError(t, err)
			return p
		}, nil).Maybe()
	timeoutCollectorFactory := timeoutcollector.NewTimeoutCollectorFactory(
		in.logger,
		timeoutAggregationDistributor,
		timeoutProcessorFactory,
	)
	timeoutCollectors := timeoutaggregator.NewTimeoutCollectors(
		in.logger,
		livenessData.CurrentRank,
		timeoutCollectorFactory,
	)

	// initialize the timeout aggregator
	in.timeoutAggregator, err = timeoutaggregator.NewTimeoutAggregator(
		in.logger,
		livenessData.CurrentRank,
		timeoutCollectors,
	)
	require.NoError(t, err)

	safetyData := &models.ConsensusState[*helper.TestVote]{
		FinalizedRank:          rootState.Rank,
		LatestAcknowledgedRank: rootState.Rank,
	}
	in.persist.On("GetConsensusState", mock.Anything).Return(safetyData, nil).Once()

	// initialize the safety rules
	in.safetyRules, err = safetyrules.NewSafetyRules(nil, in.signer, in.persist, in.committee)
	require.NoError(t, err)

	// initialize the state producer
	in.producer, err = stateproducer.NewStateProducer[*helper.TestState, *helper.TestVote, *helper.TestPeer, *helper.TestCollected](in.safetyRules, in.committee, in.builder)
	require.NoError(t, err)

	// initialize the event handler
	in.handler, err = eventhandler.NewEventHandler[*helper.TestState, *helper.TestVote, *helper.TestPeer, *helper.TestCollected](
		in.pacemaker,
		in.producer,
		in.forks,
		in.persist,
		in.committee,
		in.safetyRules,
		notifier,
		in.logger,
	)
	require.NoError(t, err)

	timeoutAggregationDistributor.AddTimeoutCollectorConsumer(logConsumer)
	timeoutAggregationDistributor.AddTimeoutCollectorConsumer(&in)
	voteAggregationDistributor.AddVoteCollectorConsumer(logConsumer)

	return &in
}

func (in *Instance) Run(t *testing.T) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		<-lifecycle.AllDone(in.voteAggregator, in.timeoutAggregator)
	}()
	signalerCtx := unittest.NewMockSignalerContext(t, ctx)
	in.voteAggregator.Start(signalerCtx)
	in.timeoutAggregator.Start(signalerCtx)
	<-lifecycle.AllReady(in.voteAggregator, in.timeoutAggregator)

	// start the event handler
	err := in.handler.Start(ctx)
	if err != nil {
		return fmt.Errorf("could not start event handler: %w", err)
	}

	// run until an error or stop condition is reached
	for {
		// check on stop conditions
		if in.stop(in) {
			return errStopCondition
		}

		// we handle timeouts with priority
		select {
		case <-in.handler.TimeoutChannel():
			err := in.handler.OnLocalTimeout()
			if err != nil {
				panic(fmt.Errorf("could not process timeout: %w", err))
			}
		default:
		}

		// check on stop conditions
		if in.stop(in) {
			return errStopCondition
		}

		// otherwise, process first received event
		select {
		case <-in.handler.TimeoutChannel():
			err := in.handler.OnLocalTimeout()
			if err != nil {
				return fmt.Errorf("could not process timeout: %w", err)
			}
		case msg := <-in.queue:
			switch m := msg.(type) {
			case *models.SignedProposal[*helper.TestState, *helper.TestVote]:
				// add state to aggregator
				in.voteAggregator.AddState(m)
				// then pass to event handler
				err := in.handler.OnReceiveProposal(m)
				if err != nil {
					return fmt.Errorf("could not process proposal: %w", err)
				}
			case *helper.TestVote:
				in.voteAggregator.AddVote(&m)
			case *models.TimeoutState[*helper.TestVote]:
				in.timeoutAggregator.AddTimeout(m)
			case models.QuorumCertificate:
				err := in.handler.OnReceiveQuorumCertificate(m)
				if err != nil {
					return fmt.Errorf("could not process received QC: %w", err)
				}
			case models.TimeoutCertificate:
				err := in.handler.OnReceiveTimeoutCertificate(m)
				if err != nil {
					return fmt.Errorf("could not process received TC: %w", err)
				}
			case *consensus.PartialTimeoutCertificateCreated:
				err := in.handler.OnPartialTimeoutCertificateCreated(m)
				if err != nil {
					return fmt.Errorf("could not process partial TC: %w", err)
				}
			default:
				fmt.Printf("unhandled queue event: %s\n", reflect.ValueOf(msg).Type().String())
			}
		}
	}
}

func (in *Instance) ProcessState(proposal *models.SignedProposal[*helper.TestState, *helper.TestVote]) {
	in.updatingStates.Lock()
	defer in.updatingStates.Unlock()
	_, parentExists := in.headers[proposal.State.ParentQuorumCertificate.Identity()]

	if parentExists {
		next := proposal
		for next != nil {
			in.headers[next.State.Identifier] = next.State

			in.queue <- next
			// keep processing the pending states
			next = in.pendings[next.State.ParentQuorumCertificate.Identity()]
		}
	} else {
		// cache it in pendings by ParentID
		in.pendings[proposal.State.ParentQuorumCertificate.Identity()] = proposal
	}
}

func (in *Instance) OnTimeoutCertificateConstructedFromTimeouts(tc models.TimeoutCertificate) {
	in.queue <- tc
}

func (in *Instance) OnPartialTimeoutCertificateCreated(rank uint64, newestQC models.QuorumCertificate, previousRankTimeoutCert models.TimeoutCertificate) {
	in.queue <- &consensus.PartialTimeoutCertificateCreated{
		Rank:                        rank,
		NewestQuorumCertificate:     newestQC,
		PriorRankTimeoutCertificate: previousRankTimeoutCert,
	}
}

func (in *Instance) OnNewQuorumCertificateDiscovered(qc models.QuorumCertificate) {
	in.queue <- qc
}

func (in *Instance) OnNewTimeoutCertificateDiscovered(tc models.TimeoutCertificate) {
	in.queue <- tc
}

func (in *Instance) OnTimeoutProcessed(*models.TimeoutState[*helper.TestVote]) {
}
