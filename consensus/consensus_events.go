package consensus

import (
	"context"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
)

// PartialTimeoutCertificateCreated represents a notification emitted by the
// TimeoutProcessor component, whenever it has collected TimeoutStates from a
// superminority of consensus participants for a specific rank. Along with the
// rank, it reports the newest QuorumCertificate and TimeoutCertificate (for
// previous rank) discovered during timeout collection. Per convention, the
// newest QuorumCertificate is never nil, while the TimeoutCertificate for the
// previous rank might be nil.
type PartialTimeoutCertificateCreated struct {
	Rank                        uint64
	NewestQuorumCertificate     models.QuorumCertificate
	PriorRankTimeoutCertificate models.TimeoutCertificate
}

// EventHandler runs a state machine to process proposals, QuorumCertificate and
// local timeouts. Not concurrency safe.
type EventHandler[StateT models.Unique, VoteT models.Unique] interface {
	// OnReceiveQuorumCertificate processes a valid quorumCertificate constructed
	// by internal vote aggregator or discovered in TimeoutState. All inputs
	// should be validated before feeding into this function. Assuming trusted
	// data. No errors are expected during normal operation.
	OnReceiveQuorumCertificate(quorumCertificate models.QuorumCertificate) error

	// OnReceiveTimeoutCertificate processes a valid timeoutCertificate
	// constructed by internal timeout aggregator, discovered in TimeoutState or
	// broadcast over the network. All inputs should be validated before feeding
	// into this function. Assuming trusted data. No errors are expected during
	// normal operation.
	OnReceiveTimeoutCertificate(
		timeoutCertificate models.TimeoutCertificate,
	) error

	// OnReceiveProposal processes a state proposal received from another HotStuff
	// consensus participant. All inputs should be validated before feeding into
	// this function. Assuming trusted data. No errors are expected during normal
	// operation.
	OnReceiveProposal(proposal *models.SignedProposal[StateT, VoteT]) error

	// OnLocalTimeout handles a local timeout event by creating a
	// models.TimeoutState and broadcasting it. No errors are expected during
	// normal operation.
	OnLocalTimeout() error

	// OnPartialTimeoutCertificateCreated handles notification produces by the
	// internal timeout aggregator. If the notification is for the current rank,
	// a corresponding models.TimeoutState is broadcast to the consensus
	// committee. No errors are expected during normal operation.
	OnPartialTimeoutCertificateCreated(
		partialTimeoutCertificate *PartialTimeoutCertificateCreated,
	) error

	// TimeoutChannel returns a channel that sends a signal on timeout.
	TimeoutChannel() <-chan time.Time

	// Start starts the event handler. No errors are expected during normal
	// operation.
	// CAUTION: EventHandler is not concurrency safe. The Start method must be
	// executed by the same goroutine that also calls the other business logic
	// methods, or concurrency safety has to be implemented externally.
	Start(ctx context.Context) error
}

// EventLoop performs buffer and processing of incoming proposals and QCs.
type EventLoop[StateT models.Unique, VoteT models.Unique] interface {
	lifecycle.Component
	TimeoutCollectorConsumer[VoteT]
	VoteCollectorConsumer[VoteT]
	SubmitProposal(proposal *models.SignedProposal[StateT, VoteT])
}

// FollowerLoop only follows certified states, does not actively process the
// collection of proposals and QC/TCs.
type FollowerLoop[StateT models.Unique, VoteT models.Unique] interface {
	AddCertifiedState(certifiedState *models.CertifiedState[StateT])
}
