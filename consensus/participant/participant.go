package participant

import (
	"fmt"
	"time"

	"github.com/gammazero/workerpool"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/eventhandler"
	"source.quilibrium.com/quilibrium/monorepo/consensus/eventloop"
	"source.quilibrium.com/quilibrium/monorepo/consensus/forks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/notifications/pubsub"
	"source.quilibrium.com/quilibrium/monorepo/consensus/pacemaker"
	"source.quilibrium.com/quilibrium/monorepo/consensus/pacemaker/timeout"
	"source.quilibrium.com/quilibrium/monorepo/consensus/safetyrules"
	"source.quilibrium.com/quilibrium/monorepo/consensus/stateproducer"
	"source.quilibrium.com/quilibrium/monorepo/consensus/timeoutaggregator"
	"source.quilibrium.com/quilibrium/monorepo/consensus/timeoutcollector"
	"source.quilibrium.com/quilibrium/monorepo/consensus/validator"
	"source.quilibrium.com/quilibrium/monorepo/consensus/verification"
	"source.quilibrium.com/quilibrium/monorepo/consensus/voteaggregator"
	"source.quilibrium.com/quilibrium/monorepo/consensus/votecollector"
)

// NewParticipant initializes the EventLoop instance with needed dependencies
func NewParticipant[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
	CollectedT models.Unique,
](
	logger consensus.TraceLogger,
	committee consensus.DynamicCommittee,
	prover consensus.LeaderProvider[StateT, PeerIDT, CollectedT],
	voter consensus.VotingProvider[StateT, VoteT, PeerIDT],
	voteProcessorFactory consensus.VoteProcessorFactory[StateT, VoteT, PeerIDT],
	consensusStore consensus.ConsensusStore[VoteT],
	signatureAggregator consensus.SignatureAggregator,
	consensusVerifier consensus.Verifier[VoteT],
	voteNotifier pubsub.VoteAggregationDistributor[StateT, VoteT],
	timeoutNotifier *pubsub.TimeoutCollectorDistributor[VoteT],
	consumer consensus.Consumer[StateT, VoteT],
	finalizer consensus.Finalizer,
	filter []byte,
	trustedRoot *models.CertifiedState[StateT],
	proposalDomain []byte,
	timeoutDomain []byte,
) (*eventloop.EventLoop[StateT, VoteT], error) {
	cfg, err := timeout.NewConfig(
		1*time.Second,
		3*time.Second,
		1.2,
		6,
		10*time.Second,
	)
	if err != nil {
		return nil, err
	}

	livenessState, err := consensusStore.GetLivenessState()
	if err != nil {
		livenessState = &models.LivenessState{
			Filter:                      filter,
			CurrentRank:                 0,
			LatestQuorumCertificate:     trustedRoot.CertifyingQuorumCertificate,
			PriorRankTimeoutCertificate: nil,
		}
		err = consensusStore.PutLivenessState(livenessState)
		if err != nil {
			return nil, err
		}
	}

	voteAggregationDistributor := pubsub.NewVoteAggregationDistributor[
		StateT,
		VoteT,
	]()
	createCollectorFactoryMethod := votecollector.NewStateMachineFactory(
		logger,
		voteAggregationDistributor,
		votecollector.VerifyingVoteProcessorFactory[StateT, VoteT, PeerIDT](
			voteProcessorFactory.Create,
		),
		proposalDomain,
		signatureAggregator,
		voter,
	)
	voteCollectors := voteaggregator.NewVoteCollectors(
		logger,
		livenessState.CurrentRank,
		workerpool.New(2),
		createCollectorFactoryMethod,
	)

	// initialize the vote aggregator
	voteAggregator, err := voteaggregator.NewVoteAggregator(
		logger,
		voteAggregationDistributor,
		livenessState.CurrentRank,
		voteCollectors,
	)

	// initialize the Validator
	validator := validator.NewValidator[StateT, VoteT](committee, consensusVerifier)

	// initialize factories for timeout collector and timeout processor
	timeoutAggregationDistributor := pubsub.NewTimeoutAggregationDistributor[VoteT]()
	timeoutProcessorFactory := timeoutcollector.NewTimeoutProcessorFactory[StateT, VoteT, PeerIDT](
		logger,
		signatureAggregator,
		timeoutNotifier,
		committee,
		validator,
		timeoutDomain,
	)

	timeoutCollectorFactory := timeoutcollector.NewTimeoutCollectorFactory(
		logger,
		timeoutAggregationDistributor,
		timeoutProcessorFactory,
	)
	timeoutCollectors := timeoutaggregator.NewTimeoutCollectors(
		logger,
		livenessState.CurrentRank,
		timeoutCollectorFactory,
	)

	// initialize the timeout aggregator
	timeoutAggregator, err := timeoutaggregator.NewTimeoutAggregator(
		logger,
		livenessState.CurrentRank,
		timeoutCollectors,
	)

	consensusState, err := consensusStore.GetConsensusState()
	if err != nil {
		consensusState = &models.ConsensusState[VoteT]{
			FinalizedRank:          trustedRoot.Rank(),
			LatestAcknowledgedRank: trustedRoot.Rank(),
		}
		err = consensusStore.PutConsensusState(consensusState)
		if err != nil {
			return nil, err
		}
	}

	// prune vote aggregator to initial rank
	voteAggregator.PruneUpToRank(trustedRoot.Rank())
	timeoutAggregator.PruneUpToRank(trustedRoot.Rank())

	// initialize dynamically updatable timeout config
	timeoutConfig, err := timeout.NewConfig(
		time.Duration(cfg.MinReplicaTimeout),
		time.Duration(cfg.MaxReplicaTimeout),
		cfg.TimeoutAdjustmentFactor,
		cfg.HappyPathMaxRoundFailures,
		time.Duration(cfg.MaxTimeoutStateRebroadcastInterval),
	)
	if err != nil {
		return nil, fmt.Errorf("could not initialize timeout config: %w", err)
	}

	// initialize the pacemaker
	controller := timeout.NewController(timeoutConfig)
	pacemaker, err := pacemaker.NewPacemaker(
		controller,
		pacemaker.NoProposalDelay(),
		consumer,
		consensusStore,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("could not initialize flow pacemaker: %w", err)
	}

	signer := verification.NewSigner[StateT, VoteT, PeerIDT](voter)
	// initialize the safetyRules
	safetyRules, err := safetyrules.NewSafetyRules[StateT, VoteT](
		signer,
		consensusStore,
		committee,
	)
	if err != nil {
		return nil, fmt.Errorf("could not initialize safety rules: %w", err)
	}

	// initialize state producer
	producer, err := stateproducer.NewStateProducer[
		StateT,
		VoteT,
		PeerIDT,
		CollectedT,
	](safetyRules, committee, prover)
	if err != nil {
		return nil, fmt.Errorf("could not initialize state producer: %w", err)
	}

	forks, err := forks.NewForks[StateT, VoteT](trustedRoot, finalizer, consumer)
	if err != nil {
		return nil, fmt.Errorf("could not initialize forks: %w", err)
	}

	// initialize the event handler
	eventHandler, err := eventhandler.NewEventHandler[
		StateT,
		VoteT,
		PeerIDT,
		CollectedT,
	](
		pacemaker,
		producer,
		forks,
		consensusStore,
		committee,
		safetyRules,
		consumer,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("could not initialize event handler: %w", err)
	}

	// initialize and return the event loop
	loop, err := eventloop.NewEventLoop(
		logger,
		eventHandler,
		time.Now().Add(10*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("could not initialize event loop: %w", err)
	}

	// add observer, event loop needs to receive events from distributor
	voteNotifier.AddVoteCollectorConsumer(loop)
	timeoutNotifier.AddTimeoutCollectorConsumer(loop)

	return loop, nil
}
