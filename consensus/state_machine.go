package consensus

// import (
// 	"context"
// 	"fmt"
// 	"sync"
// 	"sync/atomic"
// 	"time"

// 	"github.com/pkg/errors"
// 	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
// )

// // // TransitionGuard is a function that determines if a transition should occur
// // type TransitionGuard[
// // 	StateT Unique,
// // 	VoteT Unique,
// // 	PeerIDT Unique,
// // 	CollectedT Unique,
// // ] func(sm *StateMachine[StateT, VoteT, PeerIDT, CollectedT]) bool

// // // Transition defines a state transition
// // type Transition[
// // 	StateT Unique,
// // 	VoteT Unique,
// // 	PeerIDT Unique,
// // 	CollectedT Unique,
// // ] struct {
// // 	From  State
// // 	Event Event
// // 	To    State
// // 	Guard TransitionGuard[StateT, VoteT, PeerIDT, CollectedT]
// // }

// // // TransitionListener is notified of state transitions
// // type TransitionListener[StateT Unique] interface {
// // 	OnTransition(
// // 		from State,
// // 		to State,
// // 		event Event,
// // 	)
// // }

// // type eventWrapper struct {
// // 	event    Event
// // 	response chan error
// // }

// type proposal[StateT Unique] struct {
// 	proposal StateT
// 	time     time.Time
// }

// // StateMachine manages consensus engine state transitions with generic state
// // tracking. T represents the raw state bearing type, the implementation details
// // are left to callers, who may augment their transitions to utilize the data
// // if needed. If no method of fork choice is utilized external to this machine,
// // this state machine provides BFT consensus (e.g. < 1/3 byzantine behaviors)
// // provided assumptions outlined in interface types are fulfilled. The state
// // transition patterns strictly assume a round-based state transition using
// // cryptographic proofs.
// //
// // This implementation requires implementations of specific patterns:
// //   - A need to synchronize state from peers (SyncProvider)
// //   - A need to record voting from the upstream consumer to decide on consensus
// //     changes during the voting period (VotingProvider)
// //   - A need to decide on the next leader and prove (LeaderProvider)
// //   - A need to announce liveness ahead of long-running proof operations
// //     (LivenessProvider)
// type StateMachine[
// 	StateT Unique,
// 	VoteT Unique,
// 	PeerIDT Unique,
// 	CollectedT Unique,
// ] struct {
// 	mu sync.RWMutex
// 	// transitions map[State]map[Event]*Transition[
// 	// 	StateT, VoteT, PeerIDT, CollectedT,
// 	// ]
// 	// stateConfigs map[State]*StateConfig[
// 	// 	StateT, VoteT, PeerIDT, CollectedT,
// 	// ]
// 	eventChan      chan eventWrapper
// 	ctx            context.Context
// 	cancel         context.CancelFunc
// 	timeoutTimer   *time.Timer
// 	behaviorCancel context.CancelFunc

// 	// Internal state
// 	machineState State
// 	activeState  *StateT
// 	nextState    *StateT
// 	collected    *CollectedT
// 	id           PeerIDT
// 	nextProvers  []PeerIDT
// 	// liveness                       map[uint64]map[Identity]CollectedT
// 	// votes                          map[uint64]map[Identity]*VoteT
// 	// proposals                      map[uint64]map[Identity]*StateT
// 	// confirmations                  map[uint64]map[Identity]*StateT
// 	chosenProposer  *PeerIDT
// 	stateStartTime  time.Time
// 	transitionCount uint64
// 	// listeners                       []TransitionListener[StateT]
// 	shouldEmitReceiveEventsOnSends  bool
// 	minimumProvers                  func() uint64
// 	proposals                       chan proposal[StateT]
// 	latestTimeoutCertificate        *atomic.Value
// 	latestQuorumCertificate         *atomic.Value
// 	latestPartialTimeoutCertificate *atomic.Value
// 	timeoutCertificateCh            chan models.TimeoutCertificate
// 	quorumCertificateCh             chan models.QuorumCertificate
// 	partialTimeoutCertificateCh     chan models.TimeoutCertificate
// 	startTime                       time.Time

// 	// Dependencies
// 	syncProvider      SyncProvider[StateT]
// 	votingProvider    VotingProvider[StateT, VoteT, PeerIDT]
// 	leaderProvider    LeaderProvider[StateT, PeerIDT, CollectedT]
// 	livenessProvider  LivenessProvider[StateT, PeerIDT, CollectedT]
// 	pacemakerProvider PacemakerProvider
// 	traceLogger       TraceLogger
// }

// // StateConfig defines configuration for a state with generic behaviors
// // type StateConfig[
// // 	StateT Unique,
// // 	VoteT Unique,
// // 	PeerIDT Unique,
// // 	CollectedT Unique,
// // ] struct {
// // 	// Callbacks for state entry/exit
// // 	OnEnter StateCallback[StateT, VoteT, PeerIDT, CollectedT]
// // 	OnExit  StateCallback[StateT, VoteT, PeerIDT, CollectedT]

// // 	// State behavior - runs continuously while in state
// // 	Behavior StateBehavior[StateT, VoteT, PeerIDT, CollectedT]

// // 	// Timeout configuration
// // 	Timeout   time.Duration
// // 	OnTimeout Event
// // }

// // // StateCallback is called when entering or exiting a state
// // type StateCallback[
// // 	StateT Unique,
// // 	VoteT Unique,
// // 	PeerIDT Unique,
// // 	CollectedT Unique,
// // ] func(
// // 	sm *StateMachine[StateT, VoteT, PeerIDT, CollectedT],
// // 	data *StateT,
// // 	event Event,
// // )

// // // StateBehavior defines the behavior while in a state
// // type StateBehavior[
// // 	StateT Unique,
// // 	VoteT Unique,
// // 	PeerIDT Unique,
// // 	CollectedT Unique,
// // ] func(
// // 	sm *StateMachine[StateT, VoteT, PeerIDT, CollectedT],
// // 	data *StateT,
// // 	ctx context.Context,
// // )

// // NewStateMachine creates a new generic state machine for consensus.
// // `initialState` should be provided if available, this does not set the
// // position of the state machine however, consumers will need to manually force
// // a state machine's internal state if desired. Assumes some variety of pubsub-
// // based semantics are used in send/receive based operations, if the pubsub
// // implementation chosen does not receive messages published by itself, set
// // shouldEmitReceiveEventsOnSends to true.
// func NewStateMachine[
// 	StateT Unique,
// 	VoteT Unique,
// 	PeerIDT Unique,
// 	CollectedT Unique,
// ](
// 	id PeerIDT,
// 	shouldEmitReceiveEventsOnSends bool,
// 	minimumProvers func() uint64,
// 	syncProvider SyncProvider[StateT],
// 	votingProvider VotingProvider[StateT, VoteT, PeerIDT],
// 	leaderProvider LeaderProvider[StateT, PeerIDT, CollectedT],
// 	livenessProvider LivenessProvider[StateT, PeerIDT, CollectedT],
// 	pacemakerProvider PacemakerProvider,
// 	traceLogger TraceLogger,
// ) *StateMachine[StateT, VoteT, PeerIDT, CollectedT] {
// 	ctx, cancel := context.WithCancel(context.Background())
// 	if traceLogger == nil {
// 		traceLogger = nilTracer{}
// 	}
// 	sm := &StateMachine[StateT, VoteT, PeerIDT, CollectedT]{
// 		// transitions: make(
// 		// 	map[State]map[Event]*Transition[StateT, VoteT, PeerIDT, CollectedT],
// 		// ),
// 		// stateConfigs: make(
// 		// 	map[State]*StateConfig[StateT, VoteT, PeerIDT, CollectedT],
// 		// ),
// 		ctx:    ctx,
// 		cancel: cancel,
// 		id:     id,
// 		// votes:                          make(map[uint64]map[Identity]*VoteT),
// 		// proposals:                      make(map[uint64]map[Identity]*StateT),
// 		// liveness:                       make(map[uint64]map[Identity]CollectedT),
// 		// confirmations:                  make(map[uint64]map[Identity]*StateT),
// 		// listeners:                       make([]TransitionListener[StateT], 0),
// 		proposals:                       make(chan proposal[StateT], 1000),
// 		shouldEmitReceiveEventsOnSends:  shouldEmitReceiveEventsOnSends,
// 		minimumProvers:                  minimumProvers,
// 		syncProvider:                    syncProvider,
// 		votingProvider:                  votingProvider,
// 		leaderProvider:                  leaderProvider,
// 		livenessProvider:                livenessProvider,
// 		pacemakerProvider:               pacemakerProvider,
// 		latestTimeoutCertificate:        &atomic.Value{},
// 		latestQuorumCertificate:         &atomic.Value{},
// 		latestPartialTimeoutCertificate: &atomic.Value{},
// 		timeoutCertificateCh:            make(chan models.TimeoutCertificate),
// 		quorumCertificateCh:             make(chan models.QuorumCertificate),
// 		partialTimeoutCertificateCh:     make(chan models.TimeoutCertificate),
// 		traceLogger:                     traceLogger,
// 	}

// 	// // Define state configurations
// 	// sm.defineStateConfigs()

// 	// // Define transitions
// 	// sm.defineTransitions()

// 	// // Start event processor
// 	// go sm.processEvents()

// 	return sm
// }

// // Start begins the state machine
// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) Start() error {
// 	sm.traceLogger.Trace("enter start")
// 	defer sm.traceLogger.Trace("exit start")
// 	select {
// 	case <-sm.ctx.Done():
// 		return nil
// 	case <-time.After(time.Until(sm.startTime)):
// 		sm.traceLogger.Trace("starting state machine")
// 		err := sm.runLoop(sm.ctx)
// 		if err != nil {
// 			sm.traceLogger.Error("error in run loop", err)
// 			return err
// 		}
// 	}
// 	return nil
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) runLoop(ctx context.Context) error {
// 	err := sm.pacemakerProvider.Start(ctx)
// 	if err != nil {
// 		return fmt.Errorf("could not start event handler: %w", err)
// 	}

// 	for {
// 		timeoutChannel := sm.pacemakerProvider.TimeoutCh()

// 		// the first select makes sure we process timeouts with priority
// 		select {

// 		// if we receive the shutdown signal, exit the loop
// 		case <-ctx.Done():
// 			return nil

// 		// processing timeout or partial TC event are top priority since
// 		// they allow node to contribute to TC aggregation when replicas can't
// 		// make progress on happy path
// 		case <-timeoutChannel:
// 			processStart := time.Now()
// 			curRank := e.paceMaker.CurRank()
// 			e.log.Debug().Uint64("cur_rank", curRank).Msg("timeout received from event loop")
// 			e.notifier.OnLocalTimeout(curRank)
// 			defer e.notifier.OnEventProcessed()

// 			err := e.broadcastTimeoutStateIfAuthorized()
// 			if err != nil {
// 				return fmt.Errorf("unexpected exception while processing timeout in rank %d: %w", curRank, err)
// 			}

// 			// At this point, we have received and processed an event from the timeout channel.
// 			// A timeout also means that we have made progress. A new timeout will have
// 			// been started and el.eventHandler.TimeoutChannel() will be a NEW channel (for the just-started timeout).
// 			// Very important to start the for loop from the beginning, to continue the with the new timeout channel!
// 			continue

// 		case <-partialTCs:

// 			processStart := time.Now()
// 			err = el.eventHandler.OnPartialTimeoutCertificateCreated(el.newestSubmittedPartialTimeoutCertificate.NewestPartialTimeoutCertificate())
// 			if err != nil {
// 				return fmt.Errorf("could no process partial created TC event: %w", err)
// 			}

// 			// At this point, we have received and processed partial TC event, it could have resulted in several scenarios:
// 			// 1. a rank change with potential voting or proposal creation
// 			// 2. a created and broadcast timeout state
// 			// 3. QC and TC didn't result in rank change and no timeout was created since we have already timed out or
// 			// the partial TC was created for rank different from current one.
// 			continue

// 		default:
// 			// fall through to non-priority events
// 		}

// 		idleStart := time.Now()

// 		// select for state headers/QCs here
// 		select {

// 		// same as before
// 		case <-shutdownSignaled:
// 			return nil

// 		// same as before
// 		case <-timeoutChannel:
// 			err = el.eventHandler.OnLocalTimeout()
// 			if err != nil {
// 				return fmt.Errorf("could not process timeout: %w", err)
// 			}

// 		// if we have a new proposal, process it
// 		case queuedItem := <-el.proposals:
// 			processStart := time.Now()
// 			proposal := queuedItem.proposal
// 			err = el.eventHandler.OnReceiveProposal(proposal)
// 			if err != nil {
// 				return fmt.Errorf("could not process proposal %v: %w", proposal.State.Identifier, err)
// 			}

// 			el.log.Info().
// 				Dur("dur_ms", time.Since(processStart)).
// 				Uint64("rank", proposal.State.Rank).
// 				Hex("state_id", proposal.State.Identifier[:]).
// 				Msg("state proposal has been processed successfully")

// 		// if we have a new QC, process it
// 		case <-quorumCertificates:
// 			processStart := time.Now()
// 			err = el.eventHandler.OnReceiveQuorumCertificate(el.newestSubmittedQc.NewestQC())
// 			if err != nil {
// 				return fmt.Errorf("could not process QC: %w", err)
// 			}

// 			// if we have a new TC, process it
// 		case <-timeoutCertificates:
// 			// measure how long the event loop was idle waiting for an
// 			// incoming event
// 			el.metrics.HotStuffIdleDuration(time.Since(idleStart))

// 			processStart := time.Now()
// 			err = el.eventHandler.OnReceiveTimeoutCertificate(el.newestSubmittedTimeoutCertificate.NewestTC())
// 			if err != nil {
// 				return fmt.Errorf("could not process TC: %w", err)
// 			}

// 		case <-partialTCs:
// 			// measure how long the event loop was idle waiting for an
// 			// incoming event
// 			el.metrics.HotStuffIdleDuration(time.Since(idleStart))

// 			processStart := time.Now()
// 			err = el.eventHandler.OnPartialTimeoutCertificateCreated(el.newestSubmittedPartialTimeoutCertificate.NewestPartialTimeoutCertificate())
// 			if err != nil {
// 				return fmt.Errorf("could no process partial created TC event: %w", err)
// 			}
// 		}
// 	}
// }

// // Stop halts the state machine
// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) Stop() error {
// 	sm.traceLogger.Trace("enter stop")
// 	defer sm.traceLogger.Trace("exit stop")
// 	sm.cancel()
// 	return nil
// }

// // ReceiveLivenessCheck receives a liveness announcement and captures
// // collected mutation operations reported by the peer if relevant.
// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveLivenessCheck(peer PeerIDT, collected CollectedT) error {
// 	sm.traceLogger.Trace(
// 		fmt.Sprintf(
// 			"enter receivelivenesscheck, peer: %s, rank: %d",
// 			peer.Identity(),
// 			collected.GetRank(),
// 		),
// 	)
// 	defer sm.traceLogger.Trace("exit receivelivenesscheck")
// 	sm.mu.Lock()
// 	if _, ok := sm.liveness[collected.GetRank()]; !ok {
// 		sm.liveness[collected.GetRank()] = make(map[Identity]CollectedT)
// 	}
// 	if _, ok := sm.liveness[collected.GetRank()][peer.Identity()]; !ok {
// 		sm.liveness[collected.GetRank()][peer.Identity()] = collected
// 	}
// 	sm.mu.Unlock()

// 	sm.SendEvent(EventLivenessCheckReceived)
// 	return nil
// }

// // ReceiveProposal receives a proposed new state.
// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveProposal(currentRank uint64, peer PeerIDT, proposal *StateT) error {
// 	sm.traceLogger.Trace("enter receiveproposal")
// 	defer sm.traceLogger.Trace("exit receiveproposal")
// 	sm.mu.Lock()
// 	if _, ok := sm.proposals[(*proposal).GetRank()]; !ok {
// 		sm.proposals[(*proposal).GetRank()] = make(map[Identity]*StateT)
// 	}
// 	if _, ok := sm.proposals[(*proposal).GetRank()][peer.Identity()]; !ok {
// 		sm.proposals[(*proposal).GetRank()][peer.Identity()] = proposal
// 	}
// 	sm.mu.Unlock()

// 	sm.SendEvent(EventProposalReceived)
// 	return nil
// }

// // ReceiveVote captures a vote. Presumes structural and protocol validity of a
// // vote has already been evaluated.
// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveVote(proposer PeerIDT, voter PeerIDT, vote *VoteT) error {
// 	sm.traceLogger.Trace("enter receivevote")
// 	defer sm.traceLogger.Trace("exit receivevote")
// 	sm.mu.Lock()

// 	if _, ok := sm.votes[(*vote).GetRank()]; !ok {
// 		sm.votes[(*vote).GetRank()] = make(map[Identity]*VoteT)
// 	}
// 	if _, ok := sm.votes[(*vote).GetRank()][voter.Identity()]; !ok {
// 		sm.votes[(*vote).GetRank()][voter.Identity()] = vote
// 	} else if (*sm.votes[(*vote).GetRank()][voter.Identity()]).Identity() !=
// 		(*vote).Identity() {
// 		sm.mu.Unlock()
// 		return errors.Wrap(errors.New("received conflicting vote"), "receive vote")
// 	}
// 	sm.mu.Unlock()

// 	sm.SendEvent(EventVoteReceived)
// 	return nil
// }

// // ReceiveConfirmation captures a confirmation. Presumes structural and protocol
// // validity of the state has already been evaluated.
// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveConfirmation(
// 	peer PeerIDT,
// 	confirmation *StateT,
// ) error {
// 	sm.traceLogger.Trace("enter receiveconfirmation")
// 	defer sm.traceLogger.Trace("exit receiveconfirmation")
// 	sm.mu.Lock()
// 	if _, ok := sm.confirmations[(*confirmation).GetRank()]; !ok {
// 		sm.confirmations[(*confirmation).GetRank()] = make(map[Identity]*StateT)
// 	}
// 	if _, ok := sm.confirmations[(*confirmation).GetRank()][peer.Identity()]; !ok {
// 		sm.confirmations[(*confirmation).GetRank()][peer.Identity()] = confirmation
// 	}
// 	sm.mu.Unlock()

// 	sm.SendEvent(EventConfirmationReceived)
// 	return nil
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveInvalidProposal(peer PeerIDT, proposal *StateT) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveEquivocatingProposals(
// 	peer PeerIDT,
// 	proposal1 *StateT,
// 	proposal2 *StateT,
// ) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveInvalidVote(peer PeerIDT, vote *VoteT) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveEquivocatingVotes(peer PeerIDT, vote1 *VoteT, vote2 *VoteT) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveVoteForInvalidProposal(peer PeerIDT, proposal *StateT, vote *VoteT) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveInvalidTimeout(peer PeerIDT, timeout *models.TimeoutState) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveEquivocatingTimeout(
// 	peer PeerIDT,
// 	timeout1 *models.TimeoutState,
// 	timeout2 *models.TimeoutState,
// ) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveState(peer PeerIDT, state *StateT) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveFinalizedState(peer PeerIDT, finalized *StateT) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) EventProcessed() {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) Started(currentRank uint64) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveQuorumCertificate(
// 	currentRank uint64,
// 	peer PeerIDT,
// 	cert models.QuorumCertificate,
// ) error {
// 	return nil
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveTimeoutCertificate(
// 	currentRank uint64,
// 	peer PeerIDT,
// 	cert models.TimeoutCertificate,
// ) error {
// 	return nil
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveLocalTimeout(currentRank uint64) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveNewRank(oldRank uint64, newRank uint64) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveQuorumCertificateWithNewRank(
// 	oldRank uint64,
// 	newRank uint64,
// 	cert models.QuorumCertificate,
// ) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveTimeoutCertificateWithNewRank(
// 	oldRank uint64,
// 	newRank uint64,
// 	cert models.TimeoutCertificate,
// ) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveNewTimeout(start time.Time, end time.Time) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveAggregatedQuorumCertificate(
// 	peer PeerIDT,
// 	cert models.QuorumCertificate,
// ) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) VoteProcessed(peer PeerIDT, vote *VoteT) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveAggregatedTimeoutCertificate(
// 	peer PeerIDT,
// 	cert models.TimeoutCertificate,
// ) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveIncompleteTimeoutCertificate(
// 	rank uint64,
// 	peer PeerIDT,
// 	latestQuorumCert models.QuorumCertificate,
// 	previousRankTimeoutCert models.TimeoutCertificate,
// ) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveNewQuorumCertificateFromTimeout(cert models.QuorumCertificate) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) ReceiveNewTimeoutCertificateFromTimeout(cert models.TimeoutCertificate) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) TimeoutProcessed(timeout *models.TimeoutState) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) SendingVote(vote *VoteT) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) SendingTimeout(timeout *models.TimeoutState) {
// }

// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) SendingProposal(proposal *StateT, target time.Time) {
// }

// // // SendEvent sends an event to the state machine
// // func (sm *StateMachine[
// // 	StateT,
// // 	VoteT,
// // 	PeerIDT,
// // 	CollectedT,
// // ]) SendEvent(event Event) {
// // 	sm.traceLogger.Trace(fmt.Sprintf("enter sendEvent: %s", event))
// // 	defer sm.traceLogger.Trace(fmt.Sprintf("exit sendEvent: %s", event))
// // 	response := make(chan error, 1)
// // 	go func() {
// // 		select {
// // 		case sm.eventChan <- eventWrapper{event: event, response: response}:
// // 			<-response
// // 		case <-sm.ctx.Done():
// // 			return
// // 		}
// // 	}()
// // }

// // // processEvents handles events and transitions
// // func (sm *StateMachine[
// // 	StateT,
// // 	VoteT,
// // 	PeerIDT,
// // 	CollectedT,
// // ]) processEvents() {
// // 	defer func() {
// // 		if r := recover(); r != nil {
// // 			sm.traceLogger.Error(
// // 				"fatal error encountered",
// // 				errors.New(fmt.Sprintf("%+v", r)),
// // 			)
// // 			sm.Close()
// // 		}
// // 	}()

// // 	sm.traceLogger.Trace("enter processEvents")
// // 	defer sm.traceLogger.Trace("exit processEvents")
// // 	for {
// // 		select {
// // 		case <-sm.ctx.Done():
// // 			return
// // 		case wrapper := <-sm.eventChan:
// // 			err := sm.handleEvent(wrapper.event)
// // 			wrapper.response <- err
// // 		}
// // 	}
// // }

// // // handleEvent processes a single event
// // func (sm *StateMachine[
// // 	StateT,
// // 	VoteT,
// // 	PeerIDT,
// // 	CollectedT,
// // ]) handleEvent(event Event) error {
// // 	sm.traceLogger.Trace(fmt.Sprintf("enter handleEvent: %s", event))
// // 	defer sm.traceLogger.Trace(fmt.Sprintf("exit handleEvent: %s", event))
// // 	sm.mu.Lock()

// // 	currentState := sm.machineState
// // 	transitions, exists := sm.transitions[currentState]
// // 	if !exists {
// // 		sm.mu.Unlock()

// // 		return errors.Wrap(
// // 			fmt.Errorf("no transitions defined for state %s", currentState),
// // 			"handle event",
// // 		)
// // 	}

// // 	transition, exists := transitions[event]
// // 	if !exists {
// // 		sm.mu.Unlock()

// // 		return errors.Wrap(
// // 			fmt.Errorf(
// // 				"no transition for event %s in state %s",
// // 				event,
// // 				currentState,
// // 			),
// // 			"handle event",
// // 		)
// // 	}

// // 	// Check guard condition with the actual state
// // 	if transition.Guard != nil && !transition.Guard(sm) {
// // 		sm.mu.Unlock()

// // 		return errors.Wrap(
// // 			fmt.Errorf(
// // 				"transition guard failed for %s -> %s on %s",
// // 				currentState,
// // 				transition.To,
// // 				event,
// // 			),
// // 			"handle event",
// // 		)
// // 	}

// // 	sm.mu.Unlock()

// // 	// Execute transition
// // 	sm.executeTransition(currentState, transition.To, event)
// // 	return nil
// // }

// // // executeTransition performs the state transition
// // func (sm *StateMachine[
// // 	StateT,
// // 	VoteT,
// // 	PeerIDT,
// // 	CollectedT,
// // ]) executeTransition(
// // 	from State,
// // 	to State,
// // 	event Event,
// // ) {
// // 	sm.traceLogger.Trace(
// // 		fmt.Sprintf("enter executeTransition: %s -> %s [%s]", from, to, event),
// // 	)
// // 	defer sm.traceLogger.Trace(
// // 		fmt.Sprintf("exit executeTransition: %s -> %s [%s]", from, to, event),
// // 	)
// // 	sm.mu.Lock()

// // 	// Cancel any existing timeout and behavior
// // 	if sm.timeoutTimer != nil {
// // 		sm.timeoutTimer.Stop()
// // 		sm.timeoutTimer = nil
// // 	}

// // 	// Cancel existing behavior if any
// // 	if sm.behaviorCancel != nil {
// // 		sm.behaviorCancel()
// // 		sm.behaviorCancel = nil
// // 	}

// // 	// Call exit callback for current state
// // 	if config, exists := sm.stateConfigs[from]; exists && config.OnExit != nil {
// // 		sm.mu.Unlock()
// // 		config.OnExit(sm, sm.activeState, event)
// // 		sm.mu.Lock()
// // 	}

// // 	// Update state
// // 	sm.machineState = to
// // 	sm.stateStartTime = time.Now()
// // 	sm.transitionCount++

// // 	// Notify listeners
// // 	for _, listener := range sm.listeners {
// // 		listener.OnTransition(from, to, event)
// // 	}

// // 	// Call enter callback for new state
// // 	if config, exists := sm.stateConfigs[to]; exists {
// // 		if config.OnEnter != nil {
// // 			sm.mu.Unlock()
// // 			config.OnEnter(sm, sm.activeState, event)
// // 			sm.mu.Lock()
// // 		}

// // 		// Start state behavior if defined
// // 		if config.Behavior != nil {
// // 			behaviorCtx, cancel := context.WithCancel(sm.ctx)
// // 			sm.behaviorCancel = cancel
// // 			sm.mu.Unlock()
// // 			config.Behavior(sm, sm.activeState, behaviorCtx)
// // 			sm.mu.Lock()
// // 		}

// // 		// Set up timeout for new state
// // 		if config.Timeout > 0 && config.OnTimeout != "" {
// // 			sm.timeoutTimer = time.AfterFunc(config.Timeout, func() {
// // 				sm.SendEvent(config.OnTimeout)
// // 			})
// // 		}
// // 	}
// // 	sm.mu.Unlock()
// // }

// // // GetState returns the current state
// // func (sm *StateMachine[
// // 	StateT,
// // 	VoteT,
// // 	PeerIDT,
// // 	CollectedT,
// // ]) GetState() State {
// // 	sm.traceLogger.Trace("enter getstate")
// // 	defer sm.traceLogger.Trace("exit getstate")
// // 	sm.mu.Lock()
// // 	defer sm.mu.Unlock()
// // 	return sm.machineState
// // }

// // // Additional methods for compatibility
// // func (sm *StateMachine[
// // 	StateT,
// // 	VoteT,
// // 	PeerIDT,
// // 	CollectedT,
// // ]) GetStateTime() time.Duration {
// // 	sm.traceLogger.Trace("enter getstatetime")
// // 	defer sm.traceLogger.Trace("exit getstatetime")
// // 	return time.Since(sm.stateStartTime)
// // }

// // func (sm *StateMachine[
// // 	StateT,
// // 	VoteT,
// // 	PeerIDT,
// // 	CollectedT,
// // ]) GetTransitionCount() uint64 {
// // 	sm.traceLogger.Trace("enter transitioncount")
// // 	defer sm.traceLogger.Trace("exit transitioncount")
// // 	return sm.transitionCount
// // }

// // func (sm *StateMachine[
// // 	StateT,
// // 	VoteT,
// // 	PeerIDT,
// // 	CollectedT,
// // ]) AddListener(listener TransitionListener[StateT]) {
// // 	sm.traceLogger.Trace("enter addlistener")
// // 	defer sm.traceLogger.Trace("exit addlistener")
// // 	sm.mu.Lock()
// // 	defer sm.mu.Unlock()
// // 	sm.listeners = append(sm.listeners, listener)
// // }

// // func (sm *StateMachine[
// // 	StateT,
// // 	VoteT,
// // 	PeerIDT,
// // 	CollectedT,
// // ]) Close() {
// // 	sm.traceLogger.Trace("enter close")
// // 	defer sm.traceLogger.Trace("exit close")
// // 	sm.mu.Lock()
// // 	defer sm.mu.Unlock()
// // 	sm.cancel()
// // 	if sm.timeoutTimer != nil {
// // 		sm.timeoutTimer.Stop()
// // 	}
// // 	if sm.behaviorCancel != nil {
// // 		sm.behaviorCancel()
// // 	}
// // 	sm.machineState = StateStopped
// // }

// // Type used to satisfy generic arguments in compiler time type assertion check
// type nilUnique struct{}

// // GetTimestamp implements models.Unique.
// func (n *nilUnique) GetTimestamp() uint64 {
// 	panic("unimplemented")
// }

// // Source implements models.Unique.
// func (n *nilUnique) Source() models.Identity {
// 	panic("unimplemented")
// }

// // Clone implements models.Unique.
// func (n *nilUnique) Clone() models.Unique {
// 	panic("unimplemented")
// }

// // GetRank implements models.Unique.
// func (n *nilUnique) GetRank() uint64 {
// 	panic("unimplemented")
// }

// // Identity implements models.Unique.
// func (n *nilUnique) Identity() models.Identity {
// 	panic("unimplemented")
// }

// var _ models.Unique = (*nilUnique)(nil)

// /*
// // defineStateConfigs sets up state configurations with behaviors
// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) defineStateConfigs() {
// 	sm.traceLogger.Trace("enter defineStateConfigs")
// 	defer sm.traceLogger.Trace("exit defineStateConfigs")
// 	// Starting state - just timeout to complete initialization
// 	sm.stateConfigs[StateStarting] = &StateConfig[
// 		StateT,
// 		VoteT,
// 		PeerIDT,
// 		CollectedT,
// 	]{
// 		Timeout:   1 * time.Second,
// 		OnTimeout: EventInitComplete,
// 	}

// 	type Config = StateConfig[
// 		StateT,
// 		VoteT,
// 		PeerIDT,
// 		CollectedT,
// 	]

// 	type SMT = StateMachine[StateT, VoteT, PeerIDT, CollectedT]

// 	// Loading state - synchronize with network
// 	sm.stateConfigs[StateLoading] = &Config{
// 		Behavior: func(sm *SMT, data *StateT, ctx context.Context) {
// 			sm.traceLogger.Trace("enter Loading behavior")
// 			defer sm.traceLogger.Trace("exit Loading behavior")
// 			if sm.syncProvider != nil {
// 				newStateCh, errCh := sm.syncProvider.Synchronize(ctx, sm.activeState)
// 				select {
// 				case newState := <-newStateCh:
// 					sm.mu.Lock()
// 					sm.activeState = newState
// 					sm.mu.Unlock()
// 					nextLeaders, err := sm.leaderProvider.GetNextLeaders(ctx, newState)
// 					if err != nil {
// 						sm.traceLogger.Error(
// 							fmt.Sprintf("error encountered in %s", sm.machineState),
// 							err,
// 						)
// 						time.Sleep(10 * time.Second)
// 						sm.SendEvent(EventSyncTimeout)
// 						return
// 					}
// 					found := false
// 					for _, leader := range nextLeaders {
// 						if leader.Identity() == sm.id.Identity() {
// 							found = true
// 							break
// 						}
// 					}
// 					if found {
// 						sm.SendEvent(EventSyncComplete)
// 					} else {
// 						time.Sleep(10 * time.Second)
// 						sm.SendEvent(EventSyncTimeout)
// 					}
// 				case <-errCh:
// 					time.Sleep(10 * time.Second)
// 					sm.SendEvent(EventSyncTimeout)
// 				case <-ctx.Done():
// 					return
// 				}
// 			}
// 		},
// 		Timeout:   10 * time.Hour,
// 		OnTimeout: EventSyncTimeout,
// 	}

// 	// Collecting state - wait for frame or timeout
// 	sm.stateConfigs[StateCollecting] = &Config{
// 		Behavior: func(sm *SMT, data *StateT, ctx context.Context) {
// 			sm.traceLogger.Trace("enter Collecting behavior")
// 			defer sm.traceLogger.Trace("exit Collecting behavior")
// 			collected, err := sm.livenessProvider.Collect(ctx)
// 			if err != nil {
// 				sm.traceLogger.Error(
// 					fmt.Sprintf("error encountered in %s", sm.machineState),
// 					err,
// 				)
// 				sm.SendEvent(EventInduceSync)
// 				return
// 			}

// 			sm.mu.Lock()
// 			sm.nextProvers = []PeerIDT{}
// 			sm.chosenProposer = nil
// 			sm.collected = &collected
// 			sm.mu.Unlock()

// 			nextProvers, err := sm.leaderProvider.GetNextLeaders(ctx, data)
// 			if err != nil {
// 				sm.traceLogger.Error(
// 					fmt.Sprintf("error encountered in %s", sm.machineState),
// 					err,
// 				)
// 				sm.SendEvent(EventInduceSync)
// 				return
// 			}

// 			sm.mu.Lock()
// 			sm.nextProvers = nextProvers
// 			sm.mu.Unlock()

// 			err = sm.livenessProvider.SendLiveness(ctx, data, collected)
// 			if err != nil {
// 				sm.traceLogger.Error(
// 					fmt.Sprintf("error encountered in %s", sm.machineState),
// 					err,
// 				)
// 				sm.SendEvent(EventInduceSync)
// 				return
// 			}

// 			sm.mu.Lock()
// 			if sm.shouldEmitReceiveEventsOnSends {
// 				if _, ok := sm.liveness[collected.GetRank()]; !ok {
// 					sm.liveness[collected.GetRank()] = make(map[Identity]CollectedT)
// 				}
// 				sm.liveness[collected.GetRank()][sm.id.Identity()] = *sm.collected
// 			}
// 			sm.mu.Unlock()

// 			if sm.shouldEmitReceiveEventsOnSends {
// 				sm.SendEvent(EventLivenessCheckReceived)
// 			}

// 			sm.SendEvent(EventCollectionDone)
// 		},
// 		Timeout:   10 * time.Second,
// 		OnTimeout: EventInduceSync,
// 	}

// 	// Liveness check state
// 	sm.stateConfigs[StateLivenessCheck] = &Config{
// 		Behavior: func(sm *SMT, data *StateT, ctx context.Context) {
// 			sm.traceLogger.Trace("enter Liveness behavior")
// 			defer sm.traceLogger.Trace("exit Liveness behavior")
// 			sm.mu.Lock()
// 			nextProversLen := len(sm.nextProvers)
// 			sm.mu.Unlock()

// 			// If we're not meeting the minimum prover count, we should loop.
// 			if nextProversLen < int(sm.minimumProvers()) {
// 				sm.traceLogger.Trace("insufficient provers, re-fetching leaders")
// 				var err error
// 				nextProvers, err := sm.leaderProvider.GetNextLeaders(ctx, data)
// 				if err != nil {
// 					sm.traceLogger.Error(
// 						fmt.Sprintf("error encountered in %s", sm.machineState),
// 						err,
// 					)
// 					sm.SendEvent(EventInduceSync)
// 					return
// 				}
// 				sm.mu.Lock()
// 				sm.nextProvers = nextProvers
// 				sm.mu.Unlock()
// 			}

// 			sm.mu.Lock()
// 			collected := *sm.collected
// 			sm.mu.Unlock()

// 			sm.mu.Lock()
// 			livenessLen := len(sm.liveness[(*sm.activeState).GetRank()+1])
// 			sm.mu.Unlock()

// 			// We have enough checks for consensus:
// 			if livenessLen >= int(sm.minimumProvers()) {
// 				sm.traceLogger.Trace(
// 					"sufficient liveness checks, sending prover signal",
// 				)
// 				sm.SendEvent(EventProverSignal)
// 				return
// 			}

// 			sm.traceLogger.Trace(
// 				fmt.Sprintf(
// 					"insufficient liveness checks: need %d, have %d",
// 					sm.minimumProvers(),
// 					livenessLen,
// 				),
// 			)

// 			select {
// 			case <-time.After(1 * time.Second):
// 				err := sm.livenessProvider.SendLiveness(ctx, data, collected)
// 				if err != nil {
// 					sm.traceLogger.Error(
// 						fmt.Sprintf("error encountered in %s", sm.machineState),
// 						err,
// 					)
// 					sm.SendEvent(EventInduceSync)
// 					return
// 				}
// 			case <-ctx.Done():
// 			}
// 		},
// 		Timeout:   2 * time.Second,
// 		OnTimeout: EventLivenessTimeout,
// 	}

// 	// Proving state - generate proof
// 	sm.stateConfigs[StateProving] = &Config{
// 		Behavior: func(sm *SMT, data *StateT, ctx context.Context) {
// 			sm.traceLogger.Trace("enter Proving behavior")
// 			defer sm.traceLogger.Trace("exit Proving behavior")
// 			sm.mu.Lock()
// 			collected := sm.collected
// 			sm.collected = nil
// 			sm.mu.Unlock()

// 			if collected == nil {
// 				sm.SendEvent(EventInduceSync)
// 				return
// 			}

// 			proposal, err := sm.leaderProvider.ProveNextState(
// 				ctx,
// 				data,
// 				*collected,
// 			)
// 			if err != nil {
// 				sm.traceLogger.Error(
// 					fmt.Sprintf("error encountered in %s", sm.machineState),
// 					err,
// 				)

// 				sm.SendEvent(EventInduceSync)
// 				return
// 			}

// 			sm.mu.Lock()
// 			sm.traceLogger.Trace(
// 				fmt.Sprintf("adding proposal with rank %d", (*proposal).GetRank()),
// 			)
// 			if _, ok := sm.proposals[(*proposal).GetRank()]; !ok {
// 				sm.proposals[(*proposal).GetRank()] = make(map[Identity]*StateT)
// 			}
// 			sm.proposals[(*proposal).GetRank()][sm.id.Identity()] = proposal
// 			sm.mu.Unlock()

// 			sm.SendEvent(EventProofComplete)
// 		},
// 		Timeout:   120 * time.Second,
// 		OnTimeout: EventPublishTimeout,
// 	}

// 	// Publishing state - publish frame
// 	sm.stateConfigs[StatePublishing] = &Config{
// 		Behavior: func(sm *SMT, data *StateT, ctx context.Context) {
// 			sm.traceLogger.Trace("enter Publishing behavior")
// 			defer sm.traceLogger.Trace("exit Publishing behavior")
// 			sm.mu.Lock()
// 			if _, ok := sm.proposals[(*data).GetRank()+1][sm.id.Identity()]; ok {
// 				proposal := sm.proposals[(*data).GetRank()+1][sm.id.Identity()]
// 				sm.mu.Unlock()

// 				err := sm.votingProvider.SendProposal(
// 					ctx,
// 					proposal,
// 				)
// 				if err != nil {
// 					sm.traceLogger.Error(
// 						fmt.Sprintf("error encountered in %s", sm.machineState),
// 						err,
// 					)
// 					sm.SendEvent(EventInduceSync)
// 					return
// 				}
// 				sm.SendEvent(EventPublishComplete)
// 			} else {
// 				sm.mu.Unlock()
// 			}
// 		},
// 		Timeout:   1 * time.Second,
// 		OnTimeout: EventPublishTimeout,
// 	}

// 	// Voting state - monitor for quorum
// 	sm.stateConfigs[StateVoting] = &Config{
// 		Behavior: func(sm *SMT, data *StateT, ctx context.Context) {
// 			sm.traceLogger.Trace("enter Voting behavior")
// 			defer sm.traceLogger.Trace("exit Voting behavior")

// 			sm.mu.Lock()

// 			if sm.chosenProposer == nil {
// 				// We haven't voted yet
// 				sm.traceLogger.Trace("proposer not yet chosen")
// 				perfect := map[int]PeerIDT{} // all provers
// 				live := map[int]PeerIDT{}    // the provers who told us they're alive
// 				for i, p := range sm.nextProvers {
// 					perfect[i] = p
// 					if _, ok := sm.liveness[(*sm.activeState).GetRank()+1][p.Identity()]; ok {
// 						live[i] = p
// 					}
// 				}

// 				if len(sm.proposals[(*sm.activeState).GetRank()+1]) < int(sm.minimumProvers()) {
// 					sm.traceLogger.Trace(
// 						fmt.Sprintf(
// 							"insufficient proposal count: %d, need %d",
// 							len(sm.proposals[(*sm.activeState).GetRank()+1]),
// 							int(sm.minimumProvers()),
// 						),
// 					)
// 					sm.mu.Unlock()
// 					return
// 				}

// 				if ctx == nil {
// 					sm.traceLogger.Trace("context null")
// 					sm.mu.Unlock()
// 					return
// 				}

// 				select {
// 				case <-ctx.Done():
// 					sm.traceLogger.Trace("context canceled")
// 					sm.mu.Unlock()
// 					return
// 				default:
// 					sm.traceLogger.Trace("choosing proposal")
// 					proposals := map[Identity]*StateT{}
// 					for k, v := range sm.proposals[(*sm.activeState).GetRank()+1] {
// 						state := (*v).Clone().(StateT)
// 						proposals[k] = &state
// 					}

// 					sm.mu.Unlock()
// 					selectedPeer, vote, err := sm.votingProvider.DecideAndSendVote(
// 						ctx,
// 						proposals,
// 					)
// 					if err != nil {
// 						sm.traceLogger.Error(
// 							fmt.Sprintf("error encountered in %s", sm.machineState),
// 							err,
// 						)
// 						sm.SendEvent(EventInduceSync)
// 						break
// 					}
// 					sm.mu.Lock()
// 					sm.chosenProposer = &selectedPeer

// 					if sm.shouldEmitReceiveEventsOnSends {
// 						if _, ok := sm.votes[(*sm.activeState).GetRank()+1]; !ok {
// 							sm.votes[(*sm.activeState).GetRank()+1] = make(map[Identity]*VoteT)
// 						}
// 						sm.votes[(*sm.activeState).GetRank()+1][sm.id.Identity()] = vote
// 						sm.mu.Unlock()
// 						sm.SendEvent(EventVoteReceived)
// 						return
// 					}
// 					sm.mu.Unlock()
// 				}
// 			} else {
// 				sm.traceLogger.Trace("proposal chosen, checking for quorum")
// 				proposalVotes := map[Identity]*VoteT{}
// 				for p, vp := range sm.votes[(*sm.activeState).GetRank()+1] {
// 					vclone := (*vp).Clone().(VoteT)
// 					proposalVotes[p] = &vclone
// 				}
// 				haveEnoughProposals := len(sm.proposals[(*sm.activeState).GetRank()+1]) >=
// 					int(sm.minimumProvers())
// 				sm.mu.Unlock()
// 				isQuorum, err := sm.votingProvider.IsQuorum(ctx, proposalVotes)
// 				if err != nil {
// 					sm.traceLogger.Error(
// 						fmt.Sprintf("error encountered in %s", sm.machineState),
// 						err,
// 					)
// 					sm.SendEvent(EventInduceSync)
// 					return
// 				}

// 				if isQuorum && haveEnoughProposals {
// 					sm.traceLogger.Trace("quorum reached")
// 					sm.SendEvent(EventQuorumReached)
// 				} else {
// 					sm.traceLogger.Trace(
// 						fmt.Sprintf(
// 							"quorum not reached: proposals: %d, needed: %d",
// 							len(sm.proposals[(*sm.activeState).GetRank()+1]),
// 							sm.minimumProvers(),
// 						),
// 					)
// 				}
// 			}
// 		},
// 		Timeout:   1 * time.Second,
// 		OnTimeout: EventVotingTimeout,
// 	}

// 	// Finalizing state
// 	sm.stateConfigs[StateFinalizing] = &Config{
// 		Behavior: func(sm *SMT, data *StateT, ctx context.Context) {
// 			sm.mu.Lock()
// 			proposals := map[Identity]*StateT{}
// 			for k, v := range sm.proposals[(*sm.activeState).GetRank()+1] {
// 				state := (*v).Clone().(StateT)
// 				proposals[k] = &state
// 			}
// 			proposalVotes := map[Identity]*VoteT{}
// 			for p, vp := range sm.votes[(*sm.activeState).GetRank()+1] {
// 				vclone := (*vp).Clone().(VoteT)
// 				proposalVotes[p] = &vclone
// 			}
// 			sm.mu.Unlock()
// 			finalized, _, err := sm.votingProvider.FinalizeVotes(
// 				ctx,
// 				proposals,
// 				proposalVotes,
// 			)
// 			if err != nil {
// 				sm.traceLogger.Error(
// 					fmt.Sprintf("error encountered in %s", sm.machineState),
// 					err,
// 				)
// 				sm.SendEvent(EventInduceSync)
// 				return
// 			}
// 			next := (*finalized).Clone().(StateT)
// 			sm.mu.Lock()
// 			sm.nextState = &next
// 			sm.mu.Unlock()
// 			sm.SendEvent(EventAggregationDone)
// 		},
// 		Timeout:   1 * time.Second,
// 		OnTimeout: EventAggregationTimeout,
// 	}

// 	// Verifying state
// 	sm.stateConfigs[StateVerifying] = &Config{
// 		Behavior: func(sm *SMT, data *StateT, ctx context.Context) {
// 			sm.traceLogger.Trace("enter Verifying behavior")
// 			defer sm.traceLogger.Trace("exit Verifying behavior")
// 			sm.mu.Lock()
// 			if _, ok := sm.confirmations[(*sm.activeState).GetRank()+1][sm.id.Identity()]; !ok &&
// 				sm.nextState != nil {
// 				nextState := sm.nextState
// 				sm.mu.Unlock()
// 				err := sm.votingProvider.SendConfirmation(ctx, nextState)
// 				if err != nil {
// 					sm.traceLogger.Error(
// 						fmt.Sprintf("error encountered in %s", sm.machineState),
// 						err,
// 					)
// 					sm.SendEvent(EventInduceSync)
// 					return
// 				}
// 				sm.mu.Lock()
// 			}

// 			progressed := false
// 			if sm.nextState != nil {
// 				sm.activeState = sm.nextState
// 				progressed = true
// 			}
// 			if progressed {
// 				sm.nextState = nil
// 				sm.collected = nil
// 				delete(sm.liveness, (*sm.activeState).GetRank())
// 				delete(sm.proposals, (*sm.activeState).GetRank())
// 				delete(sm.votes, (*sm.activeState).GetRank())
// 				delete(sm.confirmations, (*sm.activeState).GetRank())
// 				sm.mu.Unlock()
// 				sm.SendEvent(EventVerificationDone)
// 			} else {
// 				sm.mu.Unlock()
// 			}
// 		},
// 		Timeout:   1 * time.Second,
// 		OnTimeout: EventVerificationTimeout,
// 	}

// 	// Stopping state
// 	sm.stateConfigs[StateStopping] = &Config{
// 		Behavior: func(sm *SMT, data *StateT, ctx context.Context) {
// 			sm.SendEvent(EventCleanupComplete)
// 		},
// 		Timeout:   30 * time.Second,
// 		OnTimeout: EventCleanupComplete,
// 	}
// }

// // defineTransitions sets up all possible state transitions
// func (sm *StateMachine[
// 	StateT,
// 	VoteT,
// 	PeerIDT,
// 	CollectedT,
// ]) defineTransitions() {
// 	sm.traceLogger.Trace("enter defineTransitions")
// 	defer sm.traceLogger.Trace("exit defineTransitions")

// 	// Helper to add transition
// 	addTransition := func(
// 		from State,
// 		event Event,
// 		to State,
// 		guard TransitionGuard[StateT, VoteT, PeerIDT, CollectedT],
// 	) {
// 		if sm.transitions[from] == nil {
// 			sm.transitions[from] = make(map[Event]*Transition[
// 				StateT,
// 				VoteT,
// 				PeerIDT,
// 				CollectedT,
// 			])
// 		}
// 		sm.transitions[from][event] = &Transition[
// 			StateT,
// 			VoteT,
// 			PeerIDT,
// 			CollectedT,
// 		]{
// 			From:  from,
// 			Event: event,
// 			To:    to,
// 			Guard: guard,
// 		}
// 	}

// 	// Basic flow transitions
// 	addTransition(StateStopped, EventStart, StateStarting, nil)
// 	addTransition(StateStarting, EventInitComplete, StateLoading, nil)
// 	addTransition(StateLoading, EventSyncTimeout, StateLoading, nil)
// 	addTransition(StateLoading, EventSyncComplete, StateCollecting, nil)
// 	addTransition(StateCollecting, EventCollectionDone, StateLivenessCheck, nil)
// 	addTransition(StateLivenessCheck, EventProverSignal, StateProving, nil)

// 	// Loop indefinitely if nobody can be found
// 	addTransition(
// 		StateLivenessCheck,
// 		EventLivenessTimeout,
// 		StateLivenessCheck,
// 		nil,
// 	)
// 	// // Loop until we get enough of these
// 	// addTransition(
// 	// 	StateLivenessCheck,
// 	// 	EventLivenessCheckReceived,
// 	// 	StateLivenessCheck,
// 	// 	nil,
// 	// )

// 	// Prover flow
// 	addTransition(StateProving, EventProofComplete, StatePublishing, nil)
// 	addTransition(StateProving, EventPublishTimeout, StateVoting, nil)
// 	addTransition(StatePublishing, EventPublishComplete, StateVoting, nil)
// 	addTransition(StatePublishing, EventPublishTimeout, StateVoting, nil)

// 	// Common voting flow
// 	addTransition(StateVoting, EventProposalReceived, StateVoting, nil)
// 	// addTransition(StateVoting, EventVoteReceived, StateVoting, nil)
// 	addTransition(StateVoting, EventQuorumReached, StateFinalizing, nil)
// 	addTransition(StateVoting, EventVotingTimeout, StateVoting, nil)
// 	addTransition(StateFinalizing, EventAggregationDone, StateVerifying, nil)
// 	addTransition(StateFinalizing, EventAggregationTimeout, StateFinalizing, nil)
// 	addTransition(StateVerifying, EventVerificationDone, StateCollecting, nil)
// 	addTransition(StateVerifying, EventVerificationTimeout, StateVerifying, nil)

// 	// Stop or induce Sync transitions from any state
// 	for _, state := range []State{
// 		StateStarting,
// 		StateLoading,
// 		StateCollecting,
// 		StateLivenessCheck,
// 		StateProving,
// 		StatePublishing,
// 		StateVoting,
// 		StateFinalizing,
// 		StateVerifying,
// 	} {
// 		addTransition(state, EventStop, StateStopping, nil)
// 		addTransition(state, EventInduceSync, StateLoading, nil)
// 	}

// 	addTransition(StateStopping, EventCleanupComplete, StateStopped, nil)
// }
// */
