package consensus

import (
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// VoteConsumer consumes all votes for one specific rank. It is registered with
// the `VoteCollector` for the respective rank. Upon registration, the
// `VoteCollector` feeds votes into the consumer in the order they are received
// (already cached votes as well as votes received in the future). Only votes
// that pass de-duplication and equivocation detection are passed on. CAUTION,
// VoteConsumer implementations must be
//   - NON-BLOCKING and consume the votes without noteworthy delay, and
//   - CONCURRENCY SAFE
type VoteConsumer[VoteT models.Unique] func(vote *VoteT)

// OnQuorumCertificateCreated is a callback which will be used by VoteCollector
// to submit a QuorumCertificate when it's able to create it
type OnQuorumCertificateCreated func(models.QuorumCertificate)

// VoteCollectorStatus indicates the VoteCollector's status
// It has three different status.
type VoteCollectorStatus int

const (
	// VoteCollectorStatusCaching is for the status when the state has not been
	// received. The vote collector in this status will cache all the votes
	// without verifying them.
	VoteCollectorStatusCaching VoteCollectorStatus = iota

	// VoteCollectorStatusVerifying is for the status when the state has been
	// received, and is able to process all votes for it.
	VoteCollectorStatusVerifying

	// VoteCollectorStatusInvalid is for the status when the state has been
	// verified and is invalid. All votes to this state will be collected to slash
	// the voter.
	VoteCollectorStatusInvalid
)

// VoteCollector collects votes for the same state, produces QuorumCertificate
// when enough votes are collected VoteCollector takes a callback function to
// report the event that a QuorumCertificate has been produced.
var collectorStatusNames = [...]string{"VoteCollectorStatusCaching",
	"VoteCollectorStatusVerifying",
	"VoteCollectorStatusInvalid"}

func (ps VoteCollectorStatus) String() string {
	if ps < 0 || int(ps) > len(collectorStatusNames) {
		return "UNKNOWN"
	}
	return collectorStatusNames[ps]
}

// VoteCollector collects all votes for a specified rank. On the happy path, it
// generates a QuorumCertificate when enough votes have been collected.
// The VoteCollector internally delegates the vote-format specific processing
// to the VoteProcessor.
type VoteCollector[StateT models.Unique, VoteT models.Unique] interface {
	// ProcessState performs validation of state signature and processes state
	// with respected collector. Calling this function will mark conflicting
	// collector as stale and change state of valid collectors. It returns nil if
	// the state is valid. It returns models.InvalidProposalError if state is
	// invalid. It returns other error if there is exception processing the state.
	ProcessState(state *models.SignedProposal[StateT, VoteT]) error

	// AddVote adds a vote to the collector. When enough votes have been added to
	// produce a QuorumCertificate, the QuorumCertificate will be created
	// asynchronously, and passed to EventLoop through a callback. No errors are
	// expected during normal operations.
	AddVote(vote *VoteT) error

	// RegisterVoteConsumer registers a VoteConsumer. Upon registration, the
	// collector feeds all cached votes into the consumer in the order they
	// arrived.
	// CAUTION, VoteConsumer implementations must be
	//  * NON-BLOCKING and consume the votes without noteworthy delay, and
	//  * CONCURRENCY SAFE
	RegisterVoteConsumer(consumer VoteConsumer[VoteT])

	// Rank returns the rank that this instance is collecting votes for.
	// This method is useful when adding the newly created vote collector to vote
	// collectors map.
	Rank() uint64

	// Status returns the status of the vote collector
	Status() VoteCollectorStatus
}

// VoteProcessor processes votes. It implements the vote-format specific
// processing logic. Depending on their implementation, a VoteProcessor might
// drop votes or attempt to construct a QuorumCertificate.
type VoteProcessor[VoteT models.Unique] interface {
	// Process performs processing of single vote. This function is safe to call
	// from multiple goroutines.
	// Expected error returns during normal operations:
	// * VoteForIncompatibleStateError - submitted vote for incompatible state
	// * VoteForIncompatibleRankError - submitted vote for incompatible rank
	// * models.InvalidVoteError - submitted vote with invalid signature
	// * models.DuplicatedSignerError - vote from a signer whose vote was
	//   previously already processed
	// All other errors should be treated as exceptions.
	Process(vote *VoteT) error

	// Status returns the status of the vote processor
	Status() VoteCollectorStatus
}

// VerifyingVoteProcessor is a VoteProcessor that attempts to construct a
// QuorumCertificate for the given state.
type VerifyingVoteProcessor[
	StateT models.Unique,
	VoteT models.Unique,
] interface {
	VoteProcessor[VoteT]

	// State returns which state that will be used to collector votes for.
	// Transition to VerifyingVoteCollector can occur only when we have received
	// state proposal so this information has to be available.
	State() *models.State[StateT]
}

// VoteProcessorFactory is a factory that can be used to create a verifying vote
// processors for a specific proposal. Depending on factory implementation it
// will return processors for consensus or collection clusters
type VoteProcessorFactory[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
] interface {
	// Create instantiates a VerifyingVoteProcessor for processing votes for a
	// specific proposal. Caller can be sure that proposal vote was successfully
	// verified and processed. Expected error returns during normal operations:
	// * models.InvalidProposalError - proposal has invalid proposer vote
	Create(
		tracer TraceLogger,
		filter []byte,
		proposal *models.SignedProposal[StateT, VoteT],
		dsTag []byte,
		aggregator SignatureAggregator,
		votingProvider VotingProvider[StateT, VoteT, PeerIDT],
	) (
		VerifyingVoteProcessor[StateT, VoteT],
		error,
	)
}
