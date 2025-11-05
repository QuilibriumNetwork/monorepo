package eventhandler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// EventHandler is the main handler for individual events that trigger state
// transition. It exposes API to handle one event at a time synchronously.
// EventHandler is *not concurrency safe*. Please use the EventLoop to ensure
// that only a single go-routine executes the EventHandler's algorithms.
// EventHandler is implemented in event-driven way, it reacts to incoming events
// and performs certain actions. It doesn't perform any actions on its own.
// There are 3 main responsibilities of EventHandler, vote, propose, timeout.
// There are specific scenarios that lead to each of those actions.
//   - create vote: voting logic is triggered by OnReceiveProposal, after
//     receiving proposal we have all required information to create a valid
//     vote. Compliance engine makes sure that we receive proposals, whose
//     parents are known. Creating a vote can be triggered ONLY by receiving
//     proposal.
//   - create timeout: creating models.TimeoutState is triggered by
//     OnLocalTimeout, after reaching deadline for current round. EventHandler
//     gets notified about it and has to create a models.TimeoutState and
//     broadcast it to other replicas. Creating a TO can be triggered by
//     reaching round deadline or triggered as part of Bracha broadcast when
//     superminority of replicas have contributed to TC creation and created a
//     partial TC.
//   - create a proposal: proposing logic is more complicated. Creating a
//     proposal is triggered by the EventHandler receiving a QC or TC that
//     induces a rank change to a rank where the replica is primary. As an edge
//     case, the EventHandler can receive a QC or TC that triggers the rank
//     change, but we can't create a proposal in case we are missing parent
//     state the newest QC refers to. In case we already have the QC, but are
//     still missing the respective parent, OnReceiveProposal can trigger the
//     proposing logic as well, but only when receiving proposal for rank lower
//     than active rank. To summarize, to make a valid proposal for rank N we
//     need to have a QC or TC for N-1 and know the proposal with stateID
//     NewestQC.Identifier.
//
// Not concurrency safe.
type EventHandler[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
	CollectedT models.Unique,
] struct {
	tracer        consensus.TraceLogger
	paceMaker     consensus.Pacemaker
	stateProducer consensus.StateProducer[StateT, VoteT]
	forks         consensus.Forks[StateT]
	store         consensus.ConsensusStore[VoteT]
	committee     consensus.Replicas
	safetyRules   consensus.SafetyRules[StateT, VoteT]
	notifier      consensus.Consumer[StateT, VoteT]
}

var _ consensus.EventHandler[*nilUnique, *nilUnique] = (*EventHandler[
	*nilUnique, *nilUnique, *nilUnique, *nilUnique,
])(nil)

// NewEventHandler creates an EventHandler instance with initial components.
func NewEventHandler[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
	CollectedT models.Unique,
](
	paceMaker consensus.Pacemaker,
	stateProducer consensus.StateProducer[StateT, VoteT],
	forks consensus.Forks[StateT],
	store consensus.ConsensusStore[VoteT],
	committee consensus.Replicas,
	safetyRules consensus.SafetyRules[StateT, VoteT],
	notifier consensus.Consumer[StateT, VoteT],
	tracer consensus.TraceLogger,
) (*EventHandler[StateT, VoteT, PeerIDT, CollectedT], error) {
	e := &EventHandler[StateT, VoteT, PeerIDT, CollectedT]{
		paceMaker:     paceMaker,
		stateProducer: stateProducer,
		forks:         forks,
		store:         store,
		safetyRules:   safetyRules,
		committee:     committee,
		notifier:      notifier,
		tracer:        tracer,
	}
	return e, nil
}

// OnReceiveQuorumCertificate processes a valid qc constructed by internal vote
// aggregator or discovered in TimeoutState. All inputs should be validated
// before feeding into this function. Assuming trusted data. No errors are
// expected during normal operation.
func (e *EventHandler[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) OnReceiveQuorumCertificate(qc models.QuorumCertificate) error {
	curRank := e.paceMaker.CurrentRank()

	e.tracer.Trace(
		"received QC",
		consensus.Uint64Param("current_rank", curRank),
		consensus.Uint64Param("qc_rank", qc.GetRank()),
		consensus.IdentityParam("state_id", qc.Identity()),
	)
	e.notifier.OnReceiveQuorumCertificate(curRank, qc)
	defer e.notifier.OnEventProcessed()

	newRankEvent, err := e.paceMaker.ReceiveQuorumCertificate(qc)
	if err != nil {
		return fmt.Errorf("could not process QC: %w", err)
	}
	if newRankEvent == nil {
		e.tracer.Trace("QC didn't trigger rank change, nothing to do")
		return nil
	}

	// current rank has changed, go to new rank
	e.tracer.Trace("QC triggered rank change, starting new rank now")
	return e.proposeForNewRankIfPrimary()
}

// OnReceiveTimeoutCertificate processes a valid tc constructed by internal
// timeout aggregator, discovered in TimeoutState or broadcast over the network.
// All inputs should be validated before feeding into this function. Assuming
// trusted data. No errors are expected during normal operation.
func (e *EventHandler[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) OnReceiveTimeoutCertificate(tc models.TimeoutCertificate) error {
	curRank := e.paceMaker.CurrentRank()
	e.tracer.Trace(
		"received TC",
		consensus.Uint64Param("current_rank", curRank),
		consensus.Uint64Param("tc_rank", tc.GetRank()),
		consensus.Uint64Param(
			"tc_newest_qc_rank",
			tc.GetLatestQuorumCert().GetRank(),
		),
		consensus.IdentityParam(
			"tc_newest_qc_state_id",
			tc.GetLatestQuorumCert().Identity(),
		),
	)
	e.notifier.OnReceiveTimeoutCertificate(curRank, tc)
	defer e.notifier.OnEventProcessed()

	newRankEvent, err := e.paceMaker.ReceiveTimeoutCertificate(tc)
	if err != nil {
		return fmt.Errorf("could not process TC for rank %d: %w", tc.GetRank(), err)
	}
	if newRankEvent == nil {
		e.tracer.Trace("TC didn't trigger rank change, nothing to do",
			consensus.Uint64Param("current_rank", curRank),
			consensus.Uint64Param("tc_rank", tc.GetRank()),
			consensus.Uint64Param(
				"tc_newest_qc_rank",
				tc.GetLatestQuorumCert().GetRank(),
			),
			consensus.IdentityParam(
				"tc_newest_qc_state_id",
				tc.GetLatestQuorumCert().Identity(),
			))
		return nil
	}

	// current rank has changed, go to new rank
	e.tracer.Trace("TC triggered rank change, starting new rank now",
		consensus.Uint64Param("current_rank", curRank),
		consensus.Uint64Param("tc_rank", tc.GetRank()),
		consensus.Uint64Param(
			"tc_newest_qc_rank",
			tc.GetLatestQuorumCert().GetRank(),
		),
		consensus.IdentityParam(
			"tc_newest_qc_state_id",
			tc.GetLatestQuorumCert().Identity(),
		))
	return e.proposeForNewRankIfPrimary()
}

// OnReceiveProposal processes a state proposal received from another HotStuff
// consensus participant.
// All inputs should be validated before feeding into this function. Assuming
// trusted data. No errors are expected during normal operation.
func (e *EventHandler[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) OnReceiveProposal(proposal *models.SignedProposal[StateT, VoteT]) error {
	state := proposal.State
	curRank := e.paceMaker.CurrentRank()
	e.tracer.Trace(
		"proposal received from compliance engine",
		consensus.Uint64Param("current_rank", curRank),
		consensus.Uint64Param("state_rank", state.Rank),
		consensus.IdentityParam("state_id", state.Identifier),
		consensus.Uint64Param("qc_rank", state.ParentQuorumCertificate.GetRank()),
		consensus.IdentityParam("proposer_id", state.ProposerID),
	)
	e.notifier.OnReceiveProposal(curRank, proposal)
	defer e.notifier.OnEventProcessed()

	// ignore stale proposals
	if (*state).Rank < e.forks.FinalizedRank() {
		e.tracer.Trace(
			"stale proposal",
			consensus.Uint64Param("current_rank", curRank),
			consensus.Uint64Param("state_rank", state.Rank),
			consensus.IdentityParam("state_id", state.Identifier),
			consensus.Uint64Param("qc_rank", state.ParentQuorumCertificate.GetRank()),
			consensus.IdentityParam("proposer_id", state.ProposerID),
		)
		return nil
	}

	// store the state.
	err := e.forks.AddValidatedState(proposal.State)
	if err != nil {
		return fmt.Errorf(
			"cannot add proposal to forks (%x): %w",
			state.Identifier,
			err,
		)
	}

	_, err = e.paceMaker.ReceiveQuorumCertificate(
		proposal.State.ParentQuorumCertificate,
	)
	if err != nil {
		return fmt.Errorf(
			"could not process QC for state %x: %w",
			state.Identifier,
			err,
		)
	}

	_, err = e.paceMaker.ReceiveTimeoutCertificate(
		proposal.PreviousRankTimeoutCertificate,
	)
	if err != nil {
		return fmt.Errorf(
			"could not process TC for state %x: %w",
			state.Identifier,
			err,
		)
	}

	// if the state is for the current rank, then try voting for this state
	err = e.processStateForCurrentRank(proposal)
	if err != nil {
		return fmt.Errorf("failed processing current state: %w", err)
	}
	e.tracer.Trace(
		"proposal processed from compliance engine",
		consensus.Uint64Param("current_rank", curRank),
		consensus.Uint64Param("state_rank", state.Rank),
		consensus.IdentityParam("state_id", state.Identifier),
		consensus.Uint64Param("qc_rank", state.ParentQuorumCertificate.GetRank()),
		consensus.IdentityParam("proposer_id", state.ProposerID),
	)

	// nothing to do if this proposal is for current rank
	if proposal.State.Rank == e.paceMaker.CurrentRank() {
		return nil
	}

	return e.proposeForNewRankIfPrimary()
}

// TimeoutChannel returns the channel for subscribing the waiting timeout on
// receiving state or votes for the current rank.
func (e *EventHandler[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) TimeoutChannel() <-chan time.Time {
	return e.paceMaker.TimeoutCh()
}

// OnLocalTimeout handles a local timeout event by creating a
// models.TimeoutState and broadcasting it. No errors are expected during normal
// operation.
func (e *EventHandler[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) OnLocalTimeout() error {
	curRank := e.paceMaker.CurrentRank()
	e.tracer.Trace(
		"timeout received from event loop",
		consensus.Uint64Param("current_rank", curRank),
	)
	e.notifier.OnLocalTimeout(curRank)
	defer e.notifier.OnEventProcessed()

	err := e.broadcastTimeoutStateIfAuthorized()
	if err != nil {
		return fmt.Errorf(
			"unexpected exception while processing timeout in rank %d: %w",
			curRank,
			err,
		)
	}
	return nil
}

// OnPartialTimeoutCertificateCreated handles notification produces by the
// internal timeout aggregator. If the notification is for the current rank, a
// corresponding models.TimeoutState is broadcast to the consensus committee. No
// errors are expected during normal operation.
func (e *EventHandler[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) OnPartialTimeoutCertificateCreated(
	partialTC *consensus.PartialTimeoutCertificateCreated,
) error {
	curRank := e.paceMaker.CurrentRank()
	previousRankTimeoutCert := partialTC.PriorRankTimeoutCertificate
	e.tracer.Trace(
		"constructed partial TC",
		consensus.Uint64Param("current_rank", curRank),
		consensus.Uint64Param(
			"qc_rank",
			partialTC.NewestQuorumCertificate.GetRank(),
		),
	)

	e.notifier.OnPartialTimeoutCertificate(curRank, partialTC)
	defer e.notifier.OnEventProcessed()

	// process QC, this might trigger rank change
	_, err := e.paceMaker.ReceiveQuorumCertificate(
		partialTC.NewestQuorumCertificate,
	)
	if err != nil {
		return fmt.Errorf("could not process newest QC: %w", err)
	}

	// process TC, this might trigger rank change
	_, err = e.paceMaker.ReceiveTimeoutCertificate(previousRankTimeoutCert)
	if err != nil {
		return fmt.Errorf(
			"could not process TC for rank %d: %w",
			previousRankTimeoutCert.GetRank(),
			err,
		)
	}

	// NOTE: in other cases when we have observed a rank change we will trigger
	// proposing logic, this is desired logic for handling proposal, QC and TC.
	// However, observing a partial TC means that superminority have timed out and
	// there was at least one honest replica in that set. Honest replicas will
	// never vote after timing out for current rank meaning we won't be able to
	// collect supermajority of votes for a proposal made after observing partial
	// TC.

	// by definition, we are allowed to produce timeout state if we have received
	// partial TC for current rank
	if e.paceMaker.CurrentRank() != partialTC.Rank {
		return nil
	}

	e.tracer.Trace(
		"partial TC generated for current rank, broadcasting timeout",
		consensus.Uint64Param("current_rank", curRank),
		consensus.Uint64Param(
			"qc_rank",
			partialTC.NewestQuorumCertificate.GetRank(),
		),
	)
	err = e.broadcastTimeoutStateIfAuthorized()
	if err != nil {
		return fmt.Errorf(
			"unexpected exception while processing partial TC in rank %d: %w",
			partialTC.Rank,
			err,
		)
	}
	return nil
}

// Start starts the event handler. No errors are expected during normal
// operation. CAUTION: EventHandler is not concurrency safe. The Start method
// must be executed by the same goroutine that also calls the other business
// logic methods, or concurrency safety has to be implemented externally.
func (e *EventHandler[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) Start(ctx context.Context) error {
	e.notifier.OnStart(e.paceMaker.CurrentRank())
	defer e.notifier.OnEventProcessed()
	e.paceMaker.Start(ctx)
	err := e.proposeForNewRankIfPrimary()
	if err != nil {
		return fmt.Errorf("could not start new rank: %w", err)
	}
	return nil
}

// broadcastTimeoutStateIfAuthorized attempts to generate a
// models.TimeoutState, adds it to `timeoutAggregator` and broadcasts it to the
// consensus commettee. We check, whether this node, at the current rank, is
// part of the consensus committee. Otherwise, this method is functionally a
// no-op. For example, right after an rank switchover a consensus node might
// still be online but not part of the _active_ consensus committee anymore.
// Consequently, it should not broadcast timeouts anymore. No errors are
// expected during normal operation.
func (e *EventHandler[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) broadcastTimeoutStateIfAuthorized() error {
	curRank := e.paceMaker.CurrentRank()
	newestQC := e.paceMaker.LatestQuorumCertificate()
	previousRankTimeoutCert := e.paceMaker.PriorRankTimeoutCertificate()

	if newestQC.GetRank()+1 == curRank {
		// in case last rank has ended with QC and TC, make sure that only QC is
		// included otherwise such timeout is invalid. This case is possible if TC
		// has included QC with the same rank as the TC itself, meaning that
		// newestQC.Rank == previousRankTimeoutCert.Rank
		previousRankTimeoutCert = nil
	}

	timeout, err := e.safetyRules.ProduceTimeout(
		curRank,
		newestQC,
		previousRankTimeoutCert,
	)
	if err != nil {
		if models.IsNoTimeoutError(err) {
			e.tracer.Error(
				"not generating timeout as this node is not part of the active committee",
				err,
				consensus.Uint64Param("current_rank", curRank),
			)
			return nil
		}
		return fmt.Errorf("could not produce timeout: %w", err)
	}

	// raise a notification to broadcast timeout
	e.notifier.OnOwnTimeout(timeout)
	e.tracer.Trace(
		"broadcast TimeoutState done",
		consensus.Uint64Param("current_rank", curRank),
	)

	return nil
}

// proposeForNewRankIfPrimary will only be called when we may be able to propose
// a state, after processing a new event.
//   - after entering a new rank as a result of processing a QC or TC, then we
//     may propose for the newly entered rank
//   - after receiving a proposal (but not changing rank), if that proposal is
//     referenced by our highest known QC, and the proposal was previously
//     unknown, then we can propose a state in the current rank
//
// Enforced INVARIANTS:
//   - There will at most be `OnOwnProposal` notification emitted for ranks
//     where this node is the leader, and none if another node is the leader.
//     This holds irrespective of restarts. Formally, this prevents proposal
//     equivocation.
//
// It reads the current rank, and generates a proposal if we are the leader.
// No errors are expected during normal operation.
func (e *EventHandler[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) proposeForNewRankIfPrimary() error {
	start := time.Now() // track the start time
	curRank := e.paceMaker.CurrentRank()
	e.tracer.Trace(
		"deciding to propose",
		consensus.Uint64Param("current_rank", curRank),
		consensus.IdentityParam("self", e.committee.Self()),
	)
	currentLeader, err := e.committee.LeaderForRank(curRank)
	if err != nil {
		return fmt.Errorf(
			"failed to determine primary for new rank %d: %w",
			curRank,
			err,
		)
	}
	finalizedRank := e.forks.FinalizedRank()

	e.notifier.OnCurrentRankDetails(curRank, finalizedRank, currentLeader)

	// check that I am the primary for this rank
	if e.committee.Self() != currentLeader {
		e.tracer.Trace(
			"not current leader, waiting",
			consensus.Uint64Param("current_rank", curRank),
			consensus.Uint64Param("finalized_rank", finalizedRank),
			consensus.IdentityParam("leader_id", currentLeader),
		)
		return nil
	}

	// attempt to generate proposal:
	newestQC := e.paceMaker.LatestQuorumCertificate()
	previousRankTimeoutCert := e.paceMaker.PriorRankTimeoutCertificate()

	_, found := e.forks.GetState(newestQC.Identity())
	if !found {
		// we don't know anything about state referenced by our newest QC, in this
		// case we can't create a valid proposal since we can't guarantee validity
		// of state payload.
		e.tracer.Trace(
			"haven't synced the latest state yet; can't propose",
			consensus.Uint64Param("current_rank", curRank),
			consensus.Uint64Param("finalized_rank", finalizedRank),
			consensus.IdentityParam("leader_id", currentLeader),
		)
		return nil
	}
	e.tracer.Trace(
		"generating proposal as leader",
		consensus.Uint64Param("current_rank", curRank),
		consensus.Uint64Param("finalized_rank", finalizedRank),
		consensus.IdentityParam("leader_id", currentLeader),
	)

	// Sanity checks to make sure that resulting proposal is valid:
	// In its proposal, the leader for rank N needs to present evidence that it
	// has legitimately entered rank N. As evidence, we include a QC or TC for
	// rank N-1, which should always be available as the PaceMaker advances to
	// rank N only after observing a QC or TC from rank N-1. Moreover, QC and TC
	// are always processed together. As EventHandler is strictly single-threaded
	// without reentrancy, we must have a QC or TC for the prior rank (curRank-1).
	// Failing one of these sanity checks is a symptom of state corruption or a
	// severe implementation bug.
	if newestQC.GetRank()+1 != curRank {
		if previousRankTimeoutCert == nil {
			return fmt.Errorf("possible state corruption, expected previousRankTimeoutCert to be not nil")
		}
		if previousRankTimeoutCert.GetRank()+1 != curRank {
			return fmt.Errorf(
				"possible state corruption, don't have QC(rank=%d) and TC(rank=%d) for previous rank(currentRank=%d)",
				newestQC.GetRank(),
				previousRankTimeoutCert.GetRank(),
				curRank,
			)
		}
	} else {
		// In case last rank has ended with QC and TC, make sure that only QC is
		// included, otherwise such proposal is invalid. This case is possible if TC
		// has included QC with the same rank as the TC itself, meaning that
		// newestQC.Rank == previousRankTimeoutCert.Rank
		previousRankTimeoutCert = nil
	}

	// Construct Own SignedProposal
	// CAUTION, design constraints:
	//    (i) We cannot process our own proposal within the `EventHandler` right
	//        away.
	//   (ii) We cannot add our own proposal to Forks here right away.
	//  (iii) Metrics for the PaceMaker/CruiseControl assume that the EventHandler
	//        is the only caller of `TargetPublicationTime`. Technically,
	//        `TargetPublicationTime` records the publication delay relative to
	//        its _latest_ call.
	//
	// To satisfy all constraints, we construct the proposal here and query
	// (once!) its `TargetPublicationTime`. Though, we do _not_ process our own
	// states right away and instead ingest them into the EventHandler the same
	// way as proposals from other consensus participants. Specifically, on the
	// path through the HotStuff state machine leading to state construction, the
	// node's own proposal is largely ephemeral. The proposal is handed to the
	// `MessageHub` (via the `OnOwnProposal` notification including the
	// `TargetPublicationTime`). The `MessageHub` waits until
	// `TargetPublicationTime` and only then broadcast the proposal and puts it
	// into the EventLoop's queue for inbound states. This is exactly the same way
	// as proposals from other nodes are ingested by the `EventHandler`, except
	// that we are skipping the ComplianceEngine (assuming that our own proposals
	// are protocol-compliant).
	//
	// Context:
	//  • On constraint (i): We want to support consensus committees only
	//    consisting of a *single* node. If the EventHandler internally processed
	//    the state right away via a direct message call, the call-stack would be
	//    ever-growing and the node would crash eventually (we experienced this
	//    with a very early HotStuff implementation). Specifically, if we wanted
	//    to process the state directly without taking a detour through the
	//    EventLoop's inbound queue, we would call `OnReceiveProposal` here. The
	//    function `OnReceiveProposal` would then end up calling
	//    `proposeForNewRankIfPrimary` (this function) to generate the next
	//    proposal, which again would result in calling `OnReceiveProposal` and so
	//    on so forth until the call stack or memory limit is reached and the node
	//    crashes. This is only a problem for consensus committees of size 1.
	//  • On constraint (ii): When adding a proposal to Forks, Forks emits a
	//    `StateIncorporatedEvent` notification, which is observed by Cruise
	//    Control and would change its state. However, note that Cruise Control
	//    is trying to estimate the point in time when _other_ nodes are observing
	//    the proposal. The time when we broadcast the proposal (i.e.
	//    `TargetPublicationTime`) is a reasonably good estimator, but *not* the
	//    time the proposer constructed the state (because there is potentially
	//    still a significant wait until `TargetPublicationTime`).
	//
	// The current approach is for a node to process its own proposals at the same
	// time and through the same code path as proposals from other nodes. This
	// satisfies constraints (i) and (ii) and generates very strong consistency,
	// from a software design perspective.
	//    Just hypothetically, if we changed Cruise Control to be notified about
	// own state proposals _only_ when they are broadcast (satisfying constraint
	// (ii) without relying on the EventHandler), then we could add a proposal to
	// Forks here right away. Nevertheless, the restriction remains that we cannot
	// process that proposal right away within the EventHandler and instead need
	// to put it into the EventLoop's inbound queue to support consensus
	// committees of size 1.
	stateProposal, err := e.stateProducer.MakeStateProposal(
		curRank,
		newestQC,
		previousRankTimeoutCert,
	)
	if err != nil {
		if models.IsNoVoteError(err) {
			e.tracer.Error(
				"aborting state proposal to prevent equivocation (likely re-entered proposal logic due to crash)",
				err,
				consensus.Uint64Param("current_rank", curRank),
				consensus.Uint64Param("finalized_rank", finalizedRank),
				consensus.IdentityParam("leader_id", currentLeader),
			)
			return nil
		}
		return fmt.Errorf(
			"can not make state proposal for curRank %d: %w",
			curRank,
			err,
		)
	}
	targetPublicationTime := e.paceMaker.TargetPublicationTime(
		stateProposal.State.Rank,
		start,
		stateProposal.State.ParentQuorumCertificate.Identity(),
	) // determine target publication time
	e.tracer.Trace(
		"forwarding proposal to communicator for broadcasting",
		consensus.Uint64Param("state_rank", stateProposal.State.Rank),
		consensus.TimeParam("target_publication", targetPublicationTime),
		consensus.IdentityParam("state_id", stateProposal.State.Identifier),
		consensus.Uint64Param("parent_rank", newestQC.GetRank()),
		consensus.IdentityParam("parent_id", newestQC.Identity()),
		consensus.IdentityParam("signer", stateProposal.State.ProposerID),
	)

	// emit notification with own proposal (also triggers broadcast)
	e.notifier.OnOwnProposal(stateProposal, targetPublicationTime)
	return nil
}

// processStateForCurrentRank processes the state for the current rank.
// It is called AFTER the state has been stored or found in Forks
// It checks whether to vote for this state.
// No errors are expected during normal operation.
func (e *EventHandler[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) processStateForCurrentRank(
	proposal *models.SignedProposal[StateT, VoteT],
) error {
	// sanity check that state is really for the current rank:
	curRank := e.paceMaker.CurrentRank()
	state := proposal.State
	if state.Rank != curRank {
		// ignore outdated proposals in case we have moved forward
		return nil
	}
	// leader (node ID) for next rank
	nextLeader, err := e.committee.LeaderForRank(curRank + 1)
	if errors.Is(err, models.ErrRankUnknown) {
		// We are attempting process a state in an unknown rank
		// This should never happen, because:
		// * the compliance layer ensures proposals are passed to the event loop
		//   strictly after their parent
		// * the protocol state ensures that, before incorporating the first state
		//   of an rank R, either R is known or we have triggered fallback mode - in
		//   either case the current rank is known
		return fmt.Errorf("attempting to process a state for unknown rank")
	}
	if err != nil {
		return fmt.Errorf(
			"failed to determine primary for next rank %d: %w",
			curRank+1,
			err,
		)
	}

	// safetyRules performs all the checks to decide whether to vote for this
	// state or not.
	err = e.ownVote(proposal, curRank, nextLeader)
	if err != nil {
		return fmt.Errorf("unexpected error in voting logic: %w", err)
	}

	return nil
}

// ownVote generates and forwards the own vote, if we decide to vote.
// Any errors are potential symptoms of uncovered edge cases or corrupted
// internal state (fatal). No errors are expected during normal operation.
func (e *EventHandler[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) ownVote(
	proposal *models.SignedProposal[StateT, VoteT],
	curRank uint64,
	nextLeader models.Identity,
) error {
	_, found := e.forks.GetState(
		proposal.State.ParentQuorumCertificate.Identity(),
	)
	if !found {
		// we don't have parent for this proposal, we can't vote since we can't
		// guarantee validity of proposals payload. Strictly speaking this shouldn't
		// ever happen because compliance engine makes sure that we receive
		// proposals with valid parents.
		return fmt.Errorf(
			"won't vote for proposal, no parent state for this proposal",
		)
	}

	// safetyRules performs all the checks to decide whether to vote for this
	// state or not.
	ownVote, err := e.safetyRules.ProduceVote(proposal, curRank)
	if err != nil {
		if !models.IsNoVoteError(err) {
			// unknown error, exit the event loop
			return fmt.Errorf("could not produce vote: %w", err)
		}
		e.tracer.Trace(
			"should not vote for this state",
			consensus.Uint64Param("state_rank", proposal.State.Rank),
			consensus.IdentityParam("state_id", proposal.State.Identifier),
			consensus.Uint64Param(
				"parent_rank",
				proposal.State.ParentQuorumCertificate.GetRank(),
			),
			consensus.IdentityParam(
				"parent_id",
				proposal.State.ParentQuorumCertificate.Identity(),
			),
			consensus.IdentityParam("signer", proposal.State.ProposerID[:]),
		)
		return nil
	}

	e.tracer.Trace(
		"forwarding vote to compliance engine",
		consensus.Uint64Param("state_rank", proposal.State.Rank),
		consensus.IdentityParam("state_id", proposal.State.Identifier),
		consensus.Uint64Param(
			"parent_rank",
			proposal.State.ParentQuorumCertificate.GetRank(),
		),
		consensus.IdentityParam(
			"parent_id",
			proposal.State.ParentQuorumCertificate.Identity(),
		),
		consensus.IdentityParam("signer", proposal.State.ProposerID[:]),
	)
	e.notifier.OnOwnVote(ownVote, nextLeader)
	return nil
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
