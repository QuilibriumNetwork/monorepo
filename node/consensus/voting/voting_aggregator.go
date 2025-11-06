package voting

import (
	"github.com/gammazero/workerpool"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/notifications/pubsub"
	"source.quilibrium.com/quilibrium/monorepo/consensus/timeoutaggregator"
	"source.quilibrium.com/quilibrium/monorepo/consensus/timeoutcollector"
	"source.quilibrium.com/quilibrium/monorepo/consensus/validator"
	"source.quilibrium.com/quilibrium/monorepo/consensus/voteaggregator"
	"source.quilibrium.com/quilibrium/monorepo/consensus/votecollector"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

func NewAppShardVoteAggregationDistributor() *pubsub.VoteAggregationDistributor[
	*protobufs.AppShardFrame,
	*protobufs.ProposalVote,
] {
	return pubsub.NewVoteAggregationDistributor[
		*protobufs.AppShardFrame,
		*protobufs.ProposalVote,
	]()
}

func NewAppShardVoteAggregator[PeerIDT models.Unique](
	logger consensus.TraceLogger,
	filter []byte,
	committee consensus.DynamicCommittee,
	voteAggregationDistributor *pubsub.VoteAggregationDistributor[
		*protobufs.AppShardFrame,
		*protobufs.ProposalVote,
	],
	signatureAggregator consensus.SignatureAggregator,
	votingProvider consensus.VotingProvider[
		*protobufs.AppShardFrame,
		*protobufs.ProposalVote,
		PeerIDT,
	],
	onQCCreated consensus.OnQuorumCertificateCreated,
	currentRank uint64,
) (
	consensus.VoteAggregator[*protobufs.AppShardFrame, *protobufs.ProposalVote],
	error,
) {
	voteProcessorFactory := votecollector.NewVoteProcessorFactory[
		*protobufs.AppShardFrame,
		*protobufs.ProposalVote,
		PeerIDT,
	](committee, onQCCreated)

	createCollectorFactoryMethod := votecollector.NewStateMachineFactory(
		logger,
		filter,
		voteAggregationDistributor,
		votecollector.VerifyingVoteProcessorFactory[
			*protobufs.AppShardFrame,
			*protobufs.ProposalVote,
			PeerIDT,
		](
			voteProcessorFactory.Create,
		),
		[]byte("appshard"),
		signatureAggregator,
		votingProvider,
	)
	voteCollectors := voteaggregator.NewVoteCollectors(
		logger,
		currentRank,
		workerpool.New(2),
		createCollectorFactoryMethod,
	)

	// initialize the vote aggregator
	voteAggregator, err := voteaggregator.NewVoteAggregator(
		logger,
		voteAggregationDistributor,
		currentRank,
		voteCollectors,
	)

	return voteAggregator, errors.Wrap(err, "new global vote aggregator")
}

func NewAppShardTimeoutAggregationDistributor() *pubsub.TimeoutAggregationDistributor[*protobufs.ProposalVote] {
	return pubsub.NewTimeoutAggregationDistributor[*protobufs.ProposalVote]()
}

func NewAppShardTimeoutAggregator[PeerIDT models.Unique](
	logger consensus.TraceLogger,
	filter []byte,
	committee consensus.DynamicCommittee,
	consensusVerifier consensus.Verifier[*protobufs.ProposalVote],
	signatureAggregator consensus.SignatureAggregator,
	timeoutAggregationDistributor *pubsub.TimeoutAggregationDistributor[*protobufs.ProposalVote],
	votingProvider consensus.VotingProvider[
		*protobufs.AppShardFrame,
		*protobufs.ProposalVote,
		PeerIDT,
	],
	currentRank uint64,
) (consensus.TimeoutAggregator[*protobufs.ProposalVote], error) {
	// initialize the Validator
	validator := validator.NewValidator[
		*protobufs.AppShardFrame,
		*protobufs.ProposalVote,
	](committee, consensusVerifier)

	timeoutProcessorFactory := timeoutcollector.NewTimeoutProcessorFactory[
		*protobufs.AppShardFrame,
		*protobufs.ProposalVote,
		PeerIDT,
	](
		logger,
		filter,
		signatureAggregator,
		timeoutAggregationDistributor,
		committee,
		validator,
		votingProvider,
		[]byte("appshardtimeout"),
	)

	timeoutCollectorFactory := timeoutcollector.NewTimeoutCollectorFactory(
		logger,
		timeoutAggregationDistributor,
		timeoutProcessorFactory,
	)
	timeoutCollectors := timeoutaggregator.NewTimeoutCollectors(
		logger,
		currentRank,
		timeoutCollectorFactory,
	)

	// initialize the timeout aggregator
	timeoutAggregator, err := timeoutaggregator.NewTimeoutAggregator(
		logger,
		currentRank,
		timeoutCollectors,
	)

	return timeoutAggregator, errors.Wrap(err, "new global timeout aggregator")
}

func NewGlobalVoteAggregationDistributor() *pubsub.VoteAggregationDistributor[
	*protobufs.GlobalFrame,
	*protobufs.ProposalVote,
] {
	return pubsub.NewVoteAggregationDistributor[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
	]()
}

func NewGlobalVoteAggregator[PeerIDT models.Unique](
	logger consensus.TraceLogger,
	committee consensus.DynamicCommittee,
	voteAggregationDistributor *pubsub.VoteAggregationDistributor[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
	],
	signatureAggregator consensus.SignatureAggregator,
	votingProvider consensus.VotingProvider[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
		PeerIDT,
	],
	onQCCreated consensus.OnQuorumCertificateCreated,
	currentRank uint64,
) (
	consensus.VoteAggregator[*protobufs.GlobalFrame, *protobufs.ProposalVote],
	error,
) {
	voteProcessorFactory := votecollector.NewVoteProcessorFactory[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
		PeerIDT,
	](committee, onQCCreated)

	createCollectorFactoryMethod := votecollector.NewStateMachineFactory(
		logger,
		nil,
		voteAggregationDistributor,
		votecollector.VerifyingVoteProcessorFactory[
			*protobufs.GlobalFrame,
			*protobufs.ProposalVote,
			PeerIDT,
		](
			voteProcessorFactory.Create,
		),
		[]byte("global"),
		signatureAggregator,
		votingProvider,
	)
	voteCollectors := voteaggregator.NewVoteCollectors(
		logger,
		currentRank,
		workerpool.New(2),
		createCollectorFactoryMethod,
	)

	// initialize the vote aggregator
	voteAggregator, err := voteaggregator.NewVoteAggregator(
		logger,
		voteAggregationDistributor,
		currentRank,
		voteCollectors,
	)

	return voteAggregator, errors.Wrap(err, "new global vote aggregator")
}

func NewGlobalTimeoutAggregationDistributor() *pubsub.TimeoutAggregationDistributor[*protobufs.ProposalVote] {
	return pubsub.NewTimeoutAggregationDistributor[*protobufs.ProposalVote]()
}

func NewGlobalTimeoutAggregator[PeerIDT models.Unique](
	logger consensus.TraceLogger,
	committee consensus.DynamicCommittee,
	consensusVerifier consensus.Verifier[*protobufs.ProposalVote],
	signatureAggregator consensus.SignatureAggregator,
	timeoutAggregationDistributor *pubsub.TimeoutAggregationDistributor[*protobufs.ProposalVote],
	votingProvider consensus.VotingProvider[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
		PeerIDT,
	],
	currentRank uint64,
) (consensus.TimeoutAggregator[*protobufs.ProposalVote], error) {
	// initialize the Validator
	validator := validator.NewValidator[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
	](committee, consensusVerifier)

	timeoutProcessorFactory := timeoutcollector.NewTimeoutProcessorFactory[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
		PeerIDT,
	](
		logger,
		nil,
		signatureAggregator,
		timeoutAggregationDistributor,
		committee,
		validator,
		votingProvider,
		[]byte("globaltimeout"),
	)

	timeoutCollectorFactory := timeoutcollector.NewTimeoutCollectorFactory(
		logger,
		timeoutAggregationDistributor,
		timeoutProcessorFactory,
	)
	timeoutCollectors := timeoutaggregator.NewTimeoutCollectors(
		logger,
		currentRank,
		timeoutCollectorFactory,
	)

	// initialize the timeout aggregator
	timeoutAggregator, err := timeoutaggregator.NewTimeoutAggregator(
		logger,
		currentRank,
		timeoutCollectors,
	)

	return timeoutAggregator, errors.Wrap(err, "new global timeout aggregator")
}
