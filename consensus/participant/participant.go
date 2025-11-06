package participant

import (
	"fmt"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/eventhandler"
	"source.quilibrium.com/quilibrium/monorepo/consensus/eventloop"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/notifications/pubsub"
	"source.quilibrium.com/quilibrium/monorepo/consensus/pacemaker"
	"source.quilibrium.com/quilibrium/monorepo/consensus/pacemaker/timeout"
	"source.quilibrium.com/quilibrium/monorepo/consensus/safetyrules"
	"source.quilibrium.com/quilibrium/monorepo/consensus/stateproducer"
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
	signer consensus.Signer[StateT, VoteT],
	prover consensus.LeaderProvider[StateT, PeerIDT, CollectedT],
	voter consensus.VotingProvider[StateT, VoteT, PeerIDT],
	notifier *pubsub.Distributor[StateT, VoteT],
	consensusStore consensus.ConsensusStore[VoteT],
	signatureAggregator consensus.SignatureAggregator,
	consensusVerifier consensus.Verifier[VoteT],
	voteCollectorDistributor *pubsub.VoteCollectorDistributor[VoteT],
	timeoutCollectorDistributor *pubsub.TimeoutCollectorDistributor[VoteT],
	forks consensus.Forks[StateT],
	validator consensus.Validator[StateT, VoteT],
	voteAggregator consensus.VoteAggregator[StateT, VoteT],
	timeoutAggregator consensus.TimeoutAggregator[VoteT],
	finalizer consensus.Finalizer,
	filter []byte,
	trustedRoot *models.CertifiedState[StateT],
) (*eventloop.EventLoop[StateT, VoteT], error) {
	cfg, err := timeout.NewConfig(
		10*time.Second,
		30*time.Second,
		1.2,
		6,
		10*time.Second,
	)
	if err != nil {
		return nil, err
	}

	livenessState, err := consensusStore.GetLivenessState(filter)
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

	consensusState, err := consensusStore.GetConsensusState(filter)
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

	// initialize the pacemaker
	controller := timeout.NewController(cfg)
	pacemaker, err := pacemaker.NewPacemaker[StateT, VoteT](
		filter,
		controller,
		pacemaker.NoProposalDelay(),
		notifier,
		consensusStore,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("could not initialize flow pacemaker: %w", err)
	}

	// initialize the safetyRules
	safetyRules, err := safetyrules.NewSafetyRules[StateT, VoteT](
		filter,
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
		notifier,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("could not initialize event handler: %w", err)
	}

	// initialize and return the event loop
	loop, err := eventloop.NewEventLoop(
		logger,
		eventHandler,
		time.Now(),
	)
	if err != nil {
		return nil, fmt.Errorf("could not initialize event loop: %w", err)
	}

	// add observer, event loop needs to receive events from distributor
	voteCollectorDistributor.AddVoteCollectorConsumer(loop)
	timeoutCollectorDistributor.AddTimeoutCollectorConsumer(loop)

	return loop, nil
}
