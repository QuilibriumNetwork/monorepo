package eventloop

import (
	"context"
	"fmt"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/tracker"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
)

// queuedProposal is a helper structure that is used to transmit proposal in
// channel it contains an attached insertionTime that is used to measure how
// long we have waited between queening proposal and actually processing by
// `EventHandler`.
type queuedProposal[StateT models.Unique, VoteT models.Unique] struct {
	proposal      *models.SignedProposal[StateT, VoteT]
	insertionTime time.Time
}

// EventLoop buffers all incoming events to the hotstuff EventHandler, and feeds
// EventHandler one event at a time.
type EventLoop[StateT models.Unique, VoteT models.Unique] struct {
	*lifecycle.ComponentManager
	eventHandler                             consensus.EventHandler[StateT, VoteT]
	proposals                                chan queuedProposal[StateT, VoteT]
	newestSubmittedTimeoutCertificate        *tracker.NewestTCTracker
	newestSubmittedQc                        *tracker.NewestQCTracker
	newestSubmittedPartialTimeoutCertificate *tracker.NewestPartialTimeoutCertificateTracker
	tcSubmittedNotifier                      chan struct{}
	qcSubmittedNotifier                      chan struct{}
	partialTimeoutCertificateCreatedNotifier chan struct{}
	startTime                                time.Time
	tracer                                   consensus.TraceLogger
}

var _ consensus.EventLoop[*nilUnique, *nilUnique] = (*EventLoop[*nilUnique, *nilUnique])(nil)

// NewEventLoop creates an instance of EventLoop.
func NewEventLoop[StateT models.Unique, VoteT models.Unique](
	tracer consensus.TraceLogger,
	eventHandler consensus.EventHandler[StateT, VoteT],
	startTime time.Time,
) (*EventLoop[StateT, VoteT], error) {
	// we will use a buffered channel to avoid blocking of caller
	// we can't afford to drop messages since it undermines liveness, but we also
	// want to avoid blocking of compliance engine. We assume that we should be
	// able to process proposals faster than compliance engine feeds them, worst
	// case we will fill the buffer and state compliance engine worker but that
	// should happen only if compliance engine receives large number of states in
	// short period of time(when catching up for instance).
	proposals := make(chan queuedProposal[StateT, VoteT], 1000)

	el := &EventLoop[StateT, VoteT]{
		tracer:                                   tracer,
		eventHandler:                             eventHandler,
		proposals:                                proposals,
		tcSubmittedNotifier:                      make(chan struct{}, 1),
		qcSubmittedNotifier:                      make(chan struct{}, 1),
		partialTimeoutCertificateCreatedNotifier: make(chan struct{}, 1),
		newestSubmittedTimeoutCertificate:        tracker.NewNewestTCTracker(),
		newestSubmittedQc:                        tracker.NewNewestQCTracker(),
		newestSubmittedPartialTimeoutCertificate: tracker.NewNewestPartialTimeoutCertificateTracker(),
		startTime:                                startTime,
	}

	componentBuilder := lifecycle.NewComponentManagerBuilder()
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()

		// launch when scheduled by el.startTime
		el.tracer.Trace(fmt.Sprintf("event loop will start at: %v", el.startTime))
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(el.startTime)):
			el.tracer.Trace("starting event loop")
			err := el.loop(ctx)
			if err != nil {
				el.tracer.Error("irrecoverable event loop error", err)
				ctx.Throw(err)
			}
		}
	})
	el.ComponentManager = componentBuilder.Build()

	return el, nil
}

// loop executes the core HotStuff logic in a single thread. It picks inputs
// from the various inbound channels and executes the EventHandler's respective
// method for processing this input. During normal operations, the EventHandler
// is not expected to return any errors, as all inputs are assumed to be fully
// validated (or produced by trusted components within the node). Therefore,
// any error is a symptom of state corruption, bugs or violation of API
// contracts. In all cases, continuing operations is not an option, i.e. we exit
// the event loop and return an exception.
func (el *EventLoop[StateT, VoteT]) loop(ctx context.Context) error {
	err := el.eventHandler.Start(ctx)
	if err != nil {
		return fmt.Errorf("could not start event handler: %w", err)
	}

	shutdownSignaled := ctx.Done()
	timeoutCertificates := el.tcSubmittedNotifier
	quorumCertificates := el.qcSubmittedNotifier
	partialTCs := el.partialTimeoutCertificateCreatedNotifier

	for {
		// Giving timeout events the priority to be processed first.
		// This is to prevent attacks from malicious nodes that attempt
		// to block honest nodes' pacemaker from progressing by sending
		// other events.
		timeoutChannel := el.eventHandler.TimeoutChannel()

		// the first select makes sure we process timeouts with priority
		select {

		// if we receive the shutdown signal, exit the loop
		case <-shutdownSignaled:
			el.tracer.Trace("shutting down event loop")
			return nil

		// processing timeout or partial TC event are top priority since
		// they allow node to contribute to TC aggregation when replicas can't
		// make progress on happy path
		case <-timeoutChannel:
			el.tracer.Trace("received timeout")
			err = el.eventHandler.OnLocalTimeout()
			if err != nil {
				return fmt.Errorf("could not process timeout: %w", err)
			}

			// At this point, we have received and processed an event from the timeout
			// channel. A timeout also means that we have made progress. A new timeout
			// will have been started and el.eventHandler.TimeoutChannel() will be a
			// NEW channel (for the just-started timeout). Very important to start the
			// for loop from the beginning, to continue the with the new timeout
			// channel!
			continue

		case <-partialTCs:
			el.tracer.Trace("received partial timeout")
			err = el.eventHandler.OnPartialTimeoutCertificateCreated(
				el.newestSubmittedPartialTimeoutCertificate.NewestPartialTimeoutCertificate(),
			)
			if err != nil {
				return fmt.Errorf("could not process partial created TC event: %w", err)
			}

			// At this point, we have received and processed partial TC event, it
			// could have resulted in several scenarios:
			// 1. a rank change with potential voting or proposal creation
			// 2. a created and broadcast timeout state
			// 3. QC and TC didn't result in rank change and no timeout was created
			// since we have already timed out or the partial TC was created for rank
			// different from current one.
			continue

		default:
			el.tracer.Trace("non-priority event")

			// fall through to non-priority events
		}

		// select for state headers/QCs here
		select {

		// same as before
		case <-shutdownSignaled:
			el.tracer.Trace("shutting down event loop")
			return nil

		// same as before
		case <-timeoutChannel:
			el.tracer.Trace("received timeout")

			err = el.eventHandler.OnLocalTimeout()
			if err != nil {
				return fmt.Errorf("could not process timeout: %w", err)
			}

		// if we have a new proposal, process it
		case queuedItem := <-el.proposals:
			el.tracer.Trace("received proposal")

			proposal := queuedItem.proposal
			err = el.eventHandler.OnReceiveProposal(proposal)
			if err != nil {
				return fmt.Errorf(
					"could not process proposal %x: %w",
					proposal.State.Identifier,
					err,
				)
			}

			el.tracer.Trace(
				"state proposal has been processed successfully",
				consensus.Uint64Param("rank", proposal.State.Rank),
			)

		// if we have a new QC, process it
		case <-quorumCertificates:
			el.tracer.Trace("received quorum certificate")
			err = el.eventHandler.OnReceiveQuorumCertificate(
				*el.newestSubmittedQc.NewestQC(),
			)
			if err != nil {
				return fmt.Errorf("could not process QC: %w", err)
			}

			// if we have a new TC, process it
		case <-timeoutCertificates:
			el.tracer.Trace("received timeout certificate")
			err = el.eventHandler.OnReceiveTimeoutCertificate(
				*el.newestSubmittedTimeoutCertificate.NewestTC(),
			)
			if err != nil {
				return fmt.Errorf("could not process TC: %w", err)
			}

		case <-partialTCs:
			el.tracer.Trace("received partial timeout certificate")
			err = el.eventHandler.OnPartialTimeoutCertificateCreated(
				el.newestSubmittedPartialTimeoutCertificate.NewestPartialTimeoutCertificate(),
			)
			if err != nil {
				return fmt.Errorf("could no process partial created TC event: %w", err)
			}
		}
	}
}

// SubmitProposal pushes the received state to the proposals channel
func (el *EventLoop[StateT, VoteT]) SubmitProposal(
	proposal *models.SignedProposal[StateT, VoteT],
) {
	queueItem := queuedProposal[StateT, VoteT]{
		proposal:      proposal,
		insertionTime: time.Now(),
	}
	select {
	case el.proposals <- queueItem:
	case <-el.ComponentManager.ShutdownSignal():
		return
	}
}

// onTrustedQC pushes the received QC (which MUST be validated) to the
// quorumCertificates channel
func (el *EventLoop[StateT, VoteT]) onTrustedQC(qc *models.QuorumCertificate) {
	if el.newestSubmittedQc.Track(qc) {
		select {
		case el.qcSubmittedNotifier <- struct{}{}:
		default:
		}
	}
}

// onTrustedTC pushes the received TC (which MUST be validated) to the
// timeoutCertificates channel
func (el *EventLoop[StateT, VoteT]) onTrustedTC(tc *models.TimeoutCertificate) {
	if el.newestSubmittedTimeoutCertificate.Track(tc) {
		select {
		case el.tcSubmittedNotifier <- struct{}{}:
		default:
		}
	} else {
		qc := (*tc).GetLatestQuorumCert()
		if el.newestSubmittedQc.Track(&qc) {
			select {
			case el.qcSubmittedNotifier <- struct{}{}:
			default:
			}
		}
	}
}

// OnTimeoutCertificateConstructedFromTimeouts pushes the received TC to the
// timeoutCertificates channel
func (el *EventLoop[StateT, VoteT]) OnTimeoutCertificateConstructedFromTimeouts(
	tc models.TimeoutCertificate,
) {
	el.onTrustedTC(&tc)
}

// OnPartialTimeoutCertificateCreated created a
// consensus.PartialTimeoutCertificateCreated payload and pushes it into
// partialTimeoutCertificateCreated buffered channel for further processing by
// EventHandler. Since we use buffered channel this function can block if buffer
// is full.
func (el *EventLoop[StateT, VoteT]) OnPartialTimeoutCertificateCreated(
	rank uint64,
	newestQC models.QuorumCertificate,
	previousRankTimeoutCert models.TimeoutCertificate,
) {
	event := &consensus.PartialTimeoutCertificateCreated{
		Rank:                        rank,
		NewestQuorumCertificate:     newestQC,
		PriorRankTimeoutCertificate: previousRankTimeoutCert,
	}
	if el.newestSubmittedPartialTimeoutCertificate.Track(event) {
		select {
		case el.partialTimeoutCertificateCreatedNotifier <- struct{}{}:
		default:
		}
	}
}

// OnNewQuorumCertificateDiscovered pushes already validated QCs that were
// submitted from TimeoutAggregator to the event handler
func (el *EventLoop[StateT, VoteT]) OnNewQuorumCertificateDiscovered(
	qc models.QuorumCertificate,
) {
	el.onTrustedQC(&qc)
}

// OnNewTimeoutCertificateDiscovered pushes already validated TCs that were
// submitted from TimeoutAggregator to the event handler
func (el *EventLoop[StateT, VoteT]) OnNewTimeoutCertificateDiscovered(
	tc models.TimeoutCertificate,
) {
	el.onTrustedTC(&tc)
}

// OnQuorumCertificateConstructedFromVotes implements
// consensus.VoteCollectorConsumer and pushes received qc into processing
// pipeline.
func (el *EventLoop[StateT, VoteT]) OnQuorumCertificateConstructedFromVotes(
	qc models.QuorumCertificate,
) {
	el.onTrustedQC(&qc)
}

// OnTimeoutProcessed implements consensus.TimeoutCollectorConsumer and is no-op
func (el *EventLoop[StateT, VoteT]) OnTimeoutProcessed(
	timeout *models.TimeoutState[VoteT],
) {
}

// OnVoteProcessed implements consensus.VoteCollectorConsumer and is no-op
func (el *EventLoop[StateT, VoteT]) OnVoteProcessed(vote *VoteT) {}

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
