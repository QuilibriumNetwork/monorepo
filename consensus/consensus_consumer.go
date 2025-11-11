package consensus

import (
	"time"

	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// ProposalViolationConsumer consumes outbound notifications about
// HotStuff-protocol violations. Such notifications are produced by the active
// consensus participants and consensus follower.
//
// Implementations must:
//   - be concurrency safe
//   - be non-blocking
//   - handle repetition of the same events (with some processing overhead).
type ProposalViolationConsumer[
	StateT models.Unique,
	VoteT models.Unique,
] interface {
	// OnInvalidStateDetected notifications are produced by components that have
	// detected that a state proposal is invalid and need to report it. Most of
	// the time such state can be detected by calling Validator.ValidateProposal.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking;
	// and must handle repetition of the same events (with some processing
	// overhead).
	OnInvalidStateDetected(err *models.InvalidProposalError[StateT, VoteT])

	// OnDoubleProposeDetected notifications are produced by the Finalization
	// Logic whenever a double state proposal (equivocation) was detected.
	// Equivocation occurs when the same leader proposes two different states for
	// the same rank.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking;
	// and must handle repetition of the same events (with some processing
	// overhead).
	OnDoubleProposeDetected(*models.State[StateT], *models.State[StateT])
}

// VoteAggregationViolationConsumer consumes outbound notifications about
// HotStuff-protocol violations specifically invalid votes during processing.
// Such notifications are produced by the Vote Aggregation logic.
//
// Implementations must:
//   - be concurrency safe
//   - be non-blocking
//   - handle repetition of the same events (with some processing overhead).
type VoteAggregationViolationConsumer[
	StateT models.Unique,
	VoteT models.Unique,
] interface {
	// OnDoubleVotingDetected notifications are produced by the Vote Aggregation
	// logic whenever a double voting (same voter voting for different states at
	// the same rank) was detected.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnDoubleVotingDetected(*VoteT, *VoteT)

	// OnInvalidVoteDetected notifications are produced by the Vote Aggregation
	// logic whenever an invalid vote was detected.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnInvalidVoteDetected(err models.InvalidVoteError[VoteT])

	// OnVoteForInvalidStateDetected notifications are produced by the Vote
	// Aggregation logic whenever vote for invalid proposal was detected.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnVoteForInvalidStateDetected(
		vote *VoteT,
		invalidProposal *models.SignedProposal[StateT, VoteT],
	)
}

// TimeoutAggregationViolationConsumer consumes outbound notifications about
// Active Pacemaker violations specifically invalid timeouts during processing.
// Such notifications are produced by the Timeout Aggregation logic.
//
// Implementations must:
//   - be concurrency safe
//   - be non-blocking
//   - handle repetition of the same events (with some processing overhead).
type TimeoutAggregationViolationConsumer[VoteT models.Unique] interface {
	// OnDoubleTimeoutDetected notifications are produced by the Timeout
	// Aggregation logic whenever a double timeout (same replica producing two
	// different timeouts at the same rank) was detected.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnDoubleTimeoutDetected(
		*models.TimeoutState[VoteT],
		*models.TimeoutState[VoteT],
	)

	// OnInvalidTimeoutDetected notifications are produced by the Timeout
	// Aggregation logic whenever an invalid timeout was detected.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnInvalidTimeoutDetected(err models.InvalidTimeoutError[VoteT])
}

// FinalizationConsumer consumes outbound notifications produced by the logic
// tracking forks and finalization. Such notifications are produced by the
// active consensus participants, and generally potentially relevant to the
// larger node. The notifications are emitted in the order in which the
// finalization algorithm makes the respective steps.
//
// Implementations must:
//   - be concurrency safe
//   - be non-blocking
//   - handle repetition of the same events (with some processing overhead).
type FinalizationConsumer[StateT models.Unique] interface {
	// OnStateIncorporated notifications are produced by the Finalization Logic
	// whenever a state is incorporated into the consensus state.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnStateIncorporated(*models.State[StateT])

	// OnFinalizedState notifications are produced by the Finalization Logic
	// whenever a state has been finalized. They are emitted in the order the
	// states are finalized.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnFinalizedState(*models.State[StateT])
}

// ParticipantConsumer consumes outbound notifications produced by consensus
// participants actively proposing states, voting, collecting & aggregating
// votes to QCs, and participating in the pacemaker (sending timeouts,
// collecting & aggregating timeouts to TCs).
// Implementations must:
//   - be concurrency safe
//   - be non-blocking
//   - handle repetition of the same events (with some processing overhead).
type ParticipantConsumer[
	StateT models.Unique,
	VoteT models.Unique,
] interface {
	// OnEventProcessed notifications are produced by the EventHandler when it is
	// done processing and hands control back to the EventLoop to wait for the
	// next event.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnEventProcessed()

	// OnStart notifications are produced by the EventHandler when it starts
	// blocks recovery and prepares for handling incoming events from EventLoop.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnStart(currentRank uint64)

	// OnReceiveProposal notifications are produced by the EventHandler when it
	// starts processing a state.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnReceiveProposal(
		currentRank uint64,
		proposal *models.SignedProposal[StateT, VoteT],
	)

	// OnReceiveQuorumCertificate notifications are produced by the EventHandler
	// when it starts processing a QuorumCertificate [QC] constructed by the
	// node's internal vote aggregator.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnReceiveQuorumCertificate(currentRank uint64, qc models.QuorumCertificate)

	// OnReceiveTimeoutCertificate notifications are produced by the EventHandler
	// when it starts processing a TimeoutCertificate [TC] constructed by the
	// node's internal timeout aggregator.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnReceiveTimeoutCertificate(currentRank uint64, tc models.TimeoutCertificate)

	// OnPartialTimeoutCertificate notifications are produced by the EventHandler
	// when it starts processing partial TC constructed by local timeout
	// aggregator.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnPartialTimeoutCertificate(
		currentRank uint64,
		partialTimeoutCertificate *PartialTimeoutCertificateCreated,
	)

	// OnLocalTimeout notifications are produced by the EventHandler when it
	// reacts to expiry of round duration timer. Such a notification indicates
	// that the Pacemaker's timeout was processed by the system.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnLocalTimeout(currentRank uint64)

	// OnRankChange notifications are produced by Pacemaker when it transitions to
	// a new rank based on processing a QC or TC. The arguments specify the
	// oldRank (first argument), and the newRank to which the Pacemaker
	// transitioned (second argument).
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnRankChange(oldRank, newRank uint64)

	// OnQuorumCertificateTriggeredRankChange notifications are produced by
	// Pacemaker when it moves to a new rank based on processing a QC. The
	// arguments specify the qc (first argument), which triggered the rank change,
	// and the newRank to which the Pacemaker transitioned (second argument).
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking;
	// and must handle repetition of the same events (with some processing
	// overhead).
	OnQuorumCertificateTriggeredRankChange(
		oldRank uint64,
		newRank uint64,
		qc models.QuorumCertificate,
	)

	// OnTimeoutCertificateTriggeredRankChange notifications are produced by
	// Pacemaker when it moves to a new rank based on processing a TC. The
	// arguments specify the tc (first argument), which triggered the rank change,
	// and the newRank to which the Pacemaker transitioned (second argument).
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnTimeoutCertificateTriggeredRankChange(
		oldRank uint64,
		newRank uint64,
		tc models.TimeoutCertificate,
	)

	// OnStartingTimeout notifications are produced by Pacemaker. Such a
	// notification indicates that the Pacemaker is now waiting for the system to
	// (receive and) process states or votes. The specific timeout type is
	// contained in the TimerInfo.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnStartingTimeout(startTime, endTime time.Time)

	// OnCurrentRankDetails notifications are produced by the EventHandler during
	// the course of a rank with auxiliary information. These notifications are
	// generally not produced for all ranks (for example skipped ranks). These
	// notifications are guaranteed to be produced for all ranks we enter after
	// fully processing a message.
	// Example 1:
	//   - We are in rank 8. We process a QC with rank 10, causing us to enter
	//     rank 11.
	//   - Then this notification will be produced for rank 11.
	// Example 2:
	//   - We are in rank 8. We process a proposal with rank 10, which contains a
	//     TC for rank 9 and TC.NewestQC for rank 8.
	//   - The QC would allow us to enter rank 9 and the TC would allow us to
	//     enter rank 10, so after fully processing the message we are in rank 10.
	//   - Then this notification will be produced for rank 10, but not rank 9
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnCurrentRankDetails(
		currentRank, finalizedRank uint64,
		currentLeader models.Identity,
	)
}

// VoteCollectorConsumer consumes outbound notifications produced by HotStuff's
// vote aggregation component. These events are primarily intended for the
// HotStuff-internal state machine (EventHandler), but might also be relevant to
// the larger node in which HotStuff is running.
//
// Implementations must:
//   - be concurrency safe
//   - be non-blocking
//   - handle repetition of the same events (with some processing overhead).
type VoteCollectorConsumer[VoteT models.Unique] interface {
	// OnQuorumCertificateConstructedFromVotes notifications are produced by the
	// VoteAggregator component, whenever it constructs a QC from votes.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnQuorumCertificateConstructedFromVotes(models.QuorumCertificate)

	// OnVoteProcessed notifications are produced by the Vote Aggregation logic,
	// each time we successfully ingest a valid vote.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnVoteProcessed(vote *VoteT)
}

// TimeoutCollectorConsumer consumes outbound notifications produced by
// HotStuff's timeout aggregation component. These events are primarily intended
// for the HotStuff-internal state machine (EventHandler), but might also be
// relevant to the larger node in which HotStuff is running.
//
// Caution: the events are not strictly ordered by increasing ranks! The
// notifications are emitted by concurrent processing logic. Over larger time
// scales, the emitted events are for statistically increasing ranks. However,
// on short time scales there are _no_ monotonicity guarantees w.r.t. the
// events' ranks.
//
// Implementations must:
//   - be concurrency safe
//   - be non-blocking
//   - handle repetition of the same events (with some processing overhead).
type TimeoutCollectorConsumer[VoteT models.Unique] interface {
	// OnTimeoutCertificateConstructedFromTimeouts notifications are produced by
	// the TimeoutProcessor component, whenever it constructs a TC based on
	// TimeoutStates from a supermajority of consensus participants.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnTimeoutCertificateConstructedFromTimeouts(
		certificate models.TimeoutCertificate,
	)

	// OnPartialTimeoutCertificateCreated notifications are produced by the
	// TimeoutProcessor component, whenever it collected TimeoutStates from a
	// superminority of consensus participants for a specific rank. Along with the
	// rank, it reports the newest QC and TC (for previous rank) discovered in
	// process of timeout collection. Per convention, the newest QC is never nil,
	// while the TC for the previous rank might be nil.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnPartialTimeoutCertificateCreated(
		rank uint64,
		newestQC models.QuorumCertificate,
		lastRankTC models.TimeoutCertificate,
	)

	// OnNewQuorumCertificateDiscovered notifications are produced by the
	// TimeoutCollector component, whenever it discovers new QC included in
	// timeout state.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnNewQuorumCertificateDiscovered(certificate models.QuorumCertificate)

	// OnNewTimeoutCertificateDiscovered notifications are produced by the
	// TimeoutCollector component, whenever it discovers new TC included in
	// timeout state.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnNewTimeoutCertificateDiscovered(certificate models.TimeoutCertificate)

	// OnTimeoutProcessed notifications are produced by the Timeout Aggregation
	// logic, each time we successfully ingest a valid timeout.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnTimeoutProcessed(timeout *models.TimeoutState[VoteT])
}

// CommunicatorConsumer consumes outbound notifications produced by HotStuff and
// it's components. Notifications allow the HotStuff core algorithm to
// communicate with the other actors of the consensus process.
// Implementations must:
//   - be concurrency safe
//   - be non-blocking
//   - handle repetition of the same events (with some processing overhead).
type CommunicatorConsumer[StateT models.Unique, VoteT models.Unique] interface {
	// OnOwnVote notifies about intent to send a vote for the given parameters to
	// the specified recipient.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnOwnVote(vote *VoteT, recipientID models.Identity)

	// OnOwnTimeout notifies about intent to broadcast the given timeout
	// state  to all actors of the consensus process.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking; and must handle
	// repetition of the same events (with some processing overhead).
	OnOwnTimeout(timeout *models.TimeoutState[VoteT])

	// OnOwnProposal notifies about intent to broadcast the given state proposal
	// to all actors of the consensus process. delay is to hold the proposal
	// before broadcasting it. Useful to control the state production rate.
	// Prerequisites:
	// Implementation must be concurrency safe; Non-blocking;
	// and must handle repetition of the same events (with some processing
	// overhead).
	OnOwnProposal(
		proposal *models.SignedProposal[StateT, VoteT],
		targetPublicationTime time.Time,
	)
}

// FollowerConsumer consumes outbound notifications produced by consensus
// followers. It is a subset of the notifications produced by consensus
// participants.
// Implementations must:
//   - be concurrency safe
//   - be non-blocking
//   - handle repetition of the same events (with some processing overhead).
type FollowerConsumer[StateT models.Unique, VoteT models.Unique] interface {
	ProposalViolationConsumer[StateT, VoteT]
	FinalizationConsumer[StateT]
}

// Consumer consumes outbound notifications produced by consensus participants.
// Notifications are consensus-internal state changes which are potentially
// relevant to the larger node in which HotStuff is running. The notifications
// are emitted in the order in which the HotStuff algorithm makes the respective
// steps.
//
// Implementations must:
//   - be concurrency safe
//   - be non-blocking
//   - handle repetition of the same events (with some processing overhead).
type Consumer[StateT models.Unique, VoteT models.Unique] interface {
	FollowerConsumer[StateT, VoteT]
	CommunicatorConsumer[StateT, VoteT]
	ParticipantConsumer[StateT, VoteT]
}

// VoteAggregationConsumer consumes outbound notifications produced by Vote
// Aggregation logic. It is a subset of the notifications produced by consensus
// participants.
// Implementations must:
//   - be concurrency safe
//   - be non-blocking
//   - handle repetition of the same events (with some processing overhead).
type VoteAggregationConsumer[
	StateT models.Unique,
	VoteT models.Unique,
] interface {
	VoteAggregationViolationConsumer[StateT, VoteT]
	VoteCollectorConsumer[VoteT]
}

// TimeoutAggregationConsumer consumes outbound notifications produced by Vote
// Aggregation logic. It is a subset of the notifications produced by consensus
// participants.
// Implementations must:
//   - be concurrency safe
//   - be non-blocking
//   - handle repetition of the same events (with some processing overhead).
type TimeoutAggregationConsumer[VoteT models.Unique] interface {
	TimeoutAggregationViolationConsumer[VoteT]
	TimeoutCollectorConsumer[VoteT]
}
