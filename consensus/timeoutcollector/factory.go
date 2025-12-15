package timeoutcollector

import (
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// TimeoutCollectorFactory implements consensus.TimeoutCollectorFactory, it is
// responsible for creating timeout collector for given rank.
type TimeoutCollectorFactory[VoteT models.Unique] struct {
	tracer           consensus.TraceLogger
	notifier         consensus.TimeoutAggregationConsumer[VoteT]
	processorFactory consensus.TimeoutProcessorFactory[VoteT]
}

var _ consensus.TimeoutCollectorFactory[*nilUnique] = (*TimeoutCollectorFactory[*nilUnique])(nil)

// NewTimeoutCollectorFactory creates new instance of TimeoutCollectorFactory.
// No error returns are expected during normal operations.
func NewTimeoutCollectorFactory[VoteT models.Unique](
	tracer consensus.TraceLogger,
	notifier consensus.TimeoutAggregationConsumer[VoteT],
	createProcessor consensus.TimeoutProcessorFactory[VoteT],
) *TimeoutCollectorFactory[VoteT] {
	return &TimeoutCollectorFactory[VoteT]{
		tracer:           tracer,
		notifier:         notifier,
		processorFactory: createProcessor,
	}
}

// Create is a factory method to generate a TimeoutCollector for a given rank
// Expected error returns during normal operations:
//   - models.ErrRankUnknown if rank is not yet pruned but no rank containing
//     the given rank is known
//
// All other errors should be treated as exceptions.
func (f *TimeoutCollectorFactory[VoteT]) Create(rank uint64) (
	consensus.TimeoutCollector[VoteT],
	error,
) {
	processor, err := f.processorFactory.Create(rank)
	if err != nil {
		return nil, fmt.Errorf(
			"could not create TimeoutProcessor at rank %d: %w",
			rank,
			err,
		)
	}
	return NewTimeoutCollector(f.tracer, rank, f.notifier, processor), nil
}

// TimeoutProcessorFactory implements consensus.TimeoutProcessorFactory, it is
// responsible for creating timeout processor for given rank.
type TimeoutProcessorFactory[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
] struct {
	tracer              consensus.TraceLogger
	filter              []byte
	aggregator          consensus.SignatureAggregator
	committee           consensus.Replicas
	notifier            consensus.TimeoutCollectorConsumer[VoteT]
	validator           consensus.Validator[StateT, VoteT]
	voting              consensus.VotingProvider[StateT, VoteT, PeerIDT]
	domainSeparationTag []byte
}

var _ consensus.TimeoutProcessorFactory[*nilUnique] = (*TimeoutProcessorFactory[*nilUnique, *nilUnique, *nilUnique])(nil)

// NewTimeoutProcessorFactory creates new instance of TimeoutProcessorFactory.
// No error returns are expected during normal operations.
func NewTimeoutProcessorFactory[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
](
	tracer consensus.TraceLogger,
	filter []byte,
	aggregator consensus.SignatureAggregator,
	notifier consensus.TimeoutCollectorConsumer[VoteT],
	committee consensus.Replicas,
	validator consensus.Validator[StateT, VoteT],
	voting consensus.VotingProvider[StateT, VoteT, PeerIDT],
	domainSeparationTag []byte,
) *TimeoutProcessorFactory[StateT, VoteT, PeerIDT] {
	return &TimeoutProcessorFactory[StateT, VoteT, PeerIDT]{
		tracer:              tracer,
		filter:              filter, // buildutils:allow-slice-alias static value
		aggregator:          aggregator,
		committee:           committee,
		notifier:            notifier,
		validator:           validator,
		voting:              voting,
		domainSeparationTag: domainSeparationTag, // buildutils:allow-slice-alias static value
	}
}

// Create is a factory method to generate a TimeoutProcessor for a given rank
// Expected error returns during normal operations:
//   - models.ErrRankUnknown no rank containing the given rank is known
//
// All other errors should be treated as exceptions.
func (f *TimeoutProcessorFactory[StateT, VoteT, PeerIDT]) Create(rank uint64) (
	consensus.TimeoutProcessor[VoteT],
	error,
) {
	allParticipants, err := f.committee.IdentitiesByRank(rank)
	if err != nil {
		return nil, fmt.Errorf("error retrieving consensus participants: %w", err)
	}

	sigAggregator, err := NewTimeoutSignatureAggregator(
		f.aggregator,
		f.filter,
		rank,
		allParticipants,
		f.domainSeparationTag,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"could not create TimeoutSignatureAggregator at rank %d: %w",
			rank,
			err,
		)
	}

	return NewTimeoutProcessor[StateT, VoteT, PeerIDT](
		f.tracer,
		f.committee,
		f.validator,
		sigAggregator,
		f.notifier,
		f.voting,
	)
}

// Type used to satisfy generic arguments in compiler time type assertion check
type nilUnique struct{}

// GetSignature implements models.Unique.
func (n *nilUnique) GetSignature() []byte {
	panic("unimplemented")
}

// GetTimestamp implements models.Unique.
func (n *nilUnique) GetTimestamp() uint64 {
	panic("unimplemented")
}

// Source implements models.Unique.
func (n *nilUnique) Source() models.Identity {
	panic("unimplemented")
}

// Clone implements models.Unique.
func (n *nilUnique) Clone() models.Unique {
	panic("unimplemented")
}

// GetRank implements models.Unique.
func (n *nilUnique) GetRank() uint64 {
	panic("unimplemented")
}

// Identity implements models.Unique.
func (n *nilUnique) Identity() models.Identity {
	panic("unimplemented")
}

var _ models.Unique = (*nilUnique)(nil)
