package consensus

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pkg/errors"
)

// State represents a consensus engine state
type State string

const (
	// StateStopped - Initial state, engine is not running
	StateStopped State = "stopped"
	// StateStarting - Engine is initializing
	StateStarting State = "starting"
	// StateLoading - Loading data and syncing with network
	StateLoading State = "loading"
	// StateCollecting - Collecting data for consensus round, prepares proposal
	StateCollecting State = "collecting"
	// StateLivenessCheck - Announces and awaits prover liveness
	StateLivenessCheck State = "liveness_check"
	// StateProving - Generating proof (prover only)
	StateProving State = "proving"
	// StatePublishing - Publishing relevant state
	StatePublishing State = "publishing"
	// StateVoting - Voting on proposals
	StateVoting State = "voting"
	// StateFinalizing - Finalizing consensus round
	StateFinalizing State = "finalizing"
	// StateVerifying - Verifying and publishing results
	StateVerifying State = "verifying"
	// StateStopping - Engine is shutting down
	StateStopping State = "stopping"
)

// Event represents an event that can trigger state transitions
type Event string

const (
	EventStart                 Event = "start"
	EventStop                  Event = "stop"
	EventSyncTimeout           Event = "sync_timeout"
	EventInduceSync            Event = "induce_sync"
	EventSyncComplete          Event = "sync_complete"
	EventInitComplete          Event = "init_complete"
	EventCollectionDone        Event = "collection_done"
	EventLivenessCheckReceived Event = "liveness_check_received"
	EventLivenessTimeout       Event = "liveness_timeout"
	EventProverSignal          Event = "prover_signal"
	EventProofComplete         Event = "proof_complete"
	EventPublishComplete       Event = "publish_complete"
	EventPublishTimeout        Event = "publish_timeout"
	EventProposalReceived      Event = "proposal_received"
	EventVoteReceived          Event = "vote_received"
	EventQuorumReached         Event = "quorum_reached"
	EventVotingTimeout         Event = "voting_timeout"
	EventAggregationDone       Event = "aggregation_done"
	EventAggregationTimeout    Event = "aggregation_timeout"
	EventConfirmationReceived  Event = "confirmation_received"
	EventVerificationDone      Event = "verification_done"
	EventVerificationTimeout   Event = "verification_timeout"
	EventCleanupComplete       Event = "cleanup_complete"
)

type Identity = string

// Unique defines important attributes for distinguishing relative basis of
// items.
type Unique interface {
	// Provides the relevant identity of the given Unique.
	Identity() Identity
	// Clone should provide a shallow clone of the Unique.
	Clone() Unique
	// Rank indicates the ordinal basis of comparison, e.g. a frame number, a
	// height.
	Rank() uint64
}

// TransitionGuard is a function that determines if a transition should occur
type TransitionGuard[
	StateT Unique,
	VoteT Unique,
	PeerIDT Unique,
	CollectedT Unique,
] func(sm *StateMachine[StateT, VoteT, PeerIDT, CollectedT]) bool

// Transition defines a state transition
type Transition[
	StateT Unique,
	VoteT Unique,
	PeerIDT Unique,
	CollectedT Unique,
] struct {
	From  State
	Event Event
	To    State
	Guard TransitionGuard[StateT, VoteT, PeerIDT, CollectedT]
}

// TransitionListener is notified of state transitions
type TransitionListener[StateT Unique] interface {
	OnTransition(
		from State,
		to State,
		event Event,
	)
}

type eventWrapper struct {
	event    Event
	response chan error
}

// SyncProvider handles synchronization management
type SyncProvider[StateT Unique] interface {
	// Performs synchronization to set internal state. Note that it is assumed
	// that errors are transient and synchronization should be reattempted on
	// failure. If some other process for synchronization is used and this should
	// be bypassed, send nil on the error channel. Provided context may be
	// canceled, should be used to halt long-running sync operations.
	Synchronize(
		existing *StateT,
		ctx context.Context,
	) (<-chan *StateT, <-chan error)
}

// VotingProvider handles voting logic by deferring decisions, collection, and
// state finalization to an outside implementation.
type VotingProvider[StateT Unique, VoteT Unique, PeerIDT Unique] interface {
	// Sends a proposal for voting.
	SendProposal(proposal *StateT, ctx context.Context) error
	// DecideAndSendVote makes a decision, mapped by leader, and should handle any
	// side effects (like publishing vote messages).
	DecideAndSendVote(
		proposals map[Identity]*StateT,
		ctx context.Context,
	) (PeerIDT, *VoteT, error)
	// IsQuorum returns a response indicating whether or not quorum has been
	// reached.
	IsQuorum(
		proposalVotes map[Identity]*VoteT,
		ctx context.Context,
	) (bool, error)
	// FinalizeVotes performs any folding of proposed state required from VoteT
	// onto StateT, proposed states and votes matched by PeerIDT, returns
	// finalized state, chosen proposer PeerIDT.
	FinalizeVotes(
		proposals map[Identity]*StateT,
		proposalVotes map[Identity]*VoteT,
		ctx context.Context,
	) (*StateT, PeerIDT, error)
	// SendConfirmation sends confirmation of the finalized state.
	SendConfirmation(finalized *StateT, ctx context.Context) error
}

// LeaderProvider handles leader selection. State is provided, if relevant to
// the upstream consensus engine.
type LeaderProvider[
	StateT Unique,
	PeerIDT Unique,
	CollectedT Unique,
] interface {
	// GetNextLeaders returns a list of node indices, in priority order. Note that
	// it is assumed that if no error is returned, GetNextLeaders should produce
	// a non-empty list. If a list of size smaller than minimumProvers is
	// provided, the liveness check will loop until the list is greater than that.
	GetNextLeaders(prior *StateT, ctx context.Context) ([]PeerIDT, error)
	// ProveNextState prepares a non-finalized new state from the prior, to be
	// proposed and voted upon. Provided context may be canceled, should be used
	// to halt long-running prover operations.
	ProveNextState(
		prior *StateT,
		collected CollectedT,
		ctx context.Context,
	) (*StateT, error)
}

// LivenessProvider handles liveness announcements ahead of proving, to
// pre-emptively choose the next prover. In expected leader scenarios, this
// enables a peer to determine if an honest next prover is offline, so that it
// can publish the next state without waiting.
type LivenessProvider[
	StateT Unique,
	PeerIDT Unique,
	CollectedT Unique,
] interface {
	// Collect returns the collected mutation operations ahead of liveness
	// announcements.
	Collect(ctx context.Context) (CollectedT, error)
	// SendLiveness announces liveness ahead of the next prover deterimination and
	// subsequent proving. Provides prior state and collected mutation operations
	// if relevant.
	SendLiveness(prior *StateT, collected CollectedT, ctx context.Context) error
}

// TraceLogger defines a simple tracing interface
type TraceLogger interface {
	Trace(message string)
	Error(message string, err error)
}

type nilTracer struct{}

func (nilTracer) Trace(message string)            {}
func (nilTracer) Error(message string, err error) {}

// StateMachine manages consensus engine state transitions with generic state
// tracking. T represents the raw state bearing type, the implementation details
// are left to callers, who may augment their transitions to utilize the data
// if needed. If no method of fork choice is utilized external to this machine,
// this state machine provides BFT consensus (e.g. < 1/3 byzantine behaviors)
// provided assumptions outlined in interface types are fulfilled. The state
// transition patterns strictly assume a round-based state transition using
// cryptographic proofs.
//
// This implementation requires implementations of specific patterns:
//   - A need to synchronize state from peers (SyncProvider)
//   - A need to record voting from the upstream consumer to decide on consensus
//     changes during the voting period (VotingProvider)
//   - A need to decide on the next leader and prove (LeaderProvider)
//   - A need to announce liveness ahead of long-running proof operations
//     (LivenessProvider)
type StateMachine[
	StateT Unique,
	VoteT Unique,
	PeerIDT Unique,
	CollectedT Unique,
] struct {
	mu          sync.RWMutex
	transitions map[State]map[Event]*Transition[
		StateT, VoteT, PeerIDT, CollectedT,
	]
	stateConfigs map[State]*StateConfig[
		StateT, VoteT, PeerIDT, CollectedT,
	]
	eventChan      chan eventWrapper
	ctx            context.Context
	cancel         context.CancelFunc
	timeoutTimer   *time.Timer
	behaviorCancel context.CancelFunc

	// Internal state
	machineState                   State
	activeState                    *StateT
	nextState                      *StateT
	collected                      *CollectedT
	id                             PeerIDT
	nextProvers                    []PeerIDT
	liveness                       map[uint64]map[Identity]CollectedT
	votes                          map[uint64]map[Identity]*VoteT
	proposals                      map[uint64]map[Identity]*StateT
	confirmations                  map[uint64]map[Identity]*StateT
	chosenProposer                 *PeerIDT
	stateStartTime                 time.Time
	transitionCount                uint64
	listeners                      []TransitionListener[StateT]
	shouldEmitReceiveEventsOnSends bool
	minimumProvers                 func() uint64

	// Dependencies
	syncProvider     SyncProvider[StateT]
	votingProvider   VotingProvider[StateT, VoteT, PeerIDT]
	leaderProvider   LeaderProvider[StateT, PeerIDT, CollectedT]
	livenessProvider LivenessProvider[StateT, PeerIDT, CollectedT]
	traceLogger      TraceLogger
}

// StateConfig defines configuration for a state with generic behaviors
type StateConfig[
	StateT Unique,
	VoteT Unique,
	PeerIDT Unique,
	CollectedT Unique,
] struct {
	// Callbacks for state entry/exit
	OnEnter StateCallback[StateT, VoteT, PeerIDT, CollectedT]
	OnExit  StateCallback[StateT, VoteT, PeerIDT, CollectedT]

	// State behavior - runs continuously while in state
	Behavior StateBehavior[StateT, VoteT, PeerIDT, CollectedT]

	// Timeout configuration
	Timeout   time.Duration
	OnTimeout Event
}

// StateCallback is called when entering or exiting a state
type StateCallback[
	StateT Unique,
	VoteT Unique,
	PeerIDT Unique,
	CollectedT Unique,
] func(
	sm *StateMachine[StateT, VoteT, PeerIDT, CollectedT],
	data *StateT,
	event Event,
)

// StateBehavior defines the behavior while in a state
type StateBehavior[
	StateT Unique,
	VoteT Unique,
	PeerIDT Unique,
	CollectedT Unique,
] func(
	sm *StateMachine[StateT, VoteT, PeerIDT, CollectedT],
	data *StateT,
	ctx context.Context,
)

// NewStateMachine creates a new generic state machine for consensus.
// `initialState` should be provided if available, this does not set the
// position of the state machine however, consumers will need to manually force
// a state machine's internal state if desired. Assumes some variety of pubsub-
// based semantics are used in send/receive based operations, if the pubsub
// implementation chosen does not receive messages published by itself, set
// shouldEmitReceiveEventsOnSends to true.
func NewStateMachine[
	StateT Unique,
	VoteT Unique,
	PeerIDT Unique,
	CollectedT Unique,
](
	id PeerIDT,
	initialState *StateT,
	shouldEmitReceiveEventsOnSends bool,
	minimumProvers func() uint64,
	syncProvider SyncProvider[StateT],
	votingProvider VotingProvider[StateT, VoteT, PeerIDT],
	leaderProvider LeaderProvider[StateT, PeerIDT, CollectedT],
	livenessProvider LivenessProvider[StateT, PeerIDT, CollectedT],
	traceLogger TraceLogger,
) *StateMachine[StateT, VoteT, PeerIDT, CollectedT] {
	ctx, cancel := context.WithCancel(context.Background())
	if traceLogger == nil {
		traceLogger = nilTracer{}
	}
	sm := &StateMachine[StateT, VoteT, PeerIDT, CollectedT]{
		machineState: StateStopped,
		transitions: make(
			map[State]map[Event]*Transition[StateT, VoteT, PeerIDT, CollectedT],
		),
		stateConfigs: make(
			map[State]*StateConfig[StateT, VoteT, PeerIDT, CollectedT],
		),
		eventChan:                      make(chan eventWrapper, 100),
		ctx:                            ctx,
		cancel:                         cancel,
		activeState:                    initialState,
		id:                             id,
		votes:                          make(map[uint64]map[Identity]*VoteT),
		proposals:                      make(map[uint64]map[Identity]*StateT),
		liveness:                       make(map[uint64]map[Identity]CollectedT),
		confirmations:                  make(map[uint64]map[Identity]*StateT),
		listeners:                      make([]TransitionListener[StateT], 0),
		shouldEmitReceiveEventsOnSends: shouldEmitReceiveEventsOnSends,
		minimumProvers:                 minimumProvers,
		syncProvider:                   syncProvider,
		votingProvider:                 votingProvider,
		leaderProvider:                 leaderProvider,
		livenessProvider:               livenessProvider,
		traceLogger:                    traceLogger,
	}

	// Define state configurations
	sm.defineStateConfigs()

	// Define transitions
	sm.defineTransitions()

	// Start event processor
	go sm.processEvents()

	return sm
}

// defineStateConfigs sets up state configurations with behaviors
func (sm *StateMachine[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) defineStateConfigs() {
	sm.traceLogger.Trace("enter defineStateConfigs")
	defer sm.traceLogger.Trace("exit defineStateConfigs")
	// Starting state - just timeout to complete initialization
	sm.stateConfigs[StateStarting] = &StateConfig[
		StateT,
		VoteT,
		PeerIDT,
		CollectedT,
	]{
		Timeout:   1 * time.Second,
		OnTimeout: EventInitComplete,
	}

	type Config = StateConfig[
		StateT,
		VoteT,
		PeerIDT,
		CollectedT,
	]

	type SMT = StateMachine[StateT, VoteT, PeerIDT, CollectedT]

	// Loading state - synchronize with network
	sm.stateConfigs[StateLoading] = &Config{
		Behavior: func(sm *SMT, data *StateT, ctx context.Context) {
			sm.traceLogger.Trace("enter Loading behavior")
			defer sm.traceLogger.Trace("exit Loading behavior")
			if sm.syncProvider != nil {
				newStateCh, errCh := sm.syncProvider.Synchronize(sm.activeState, ctx)
				select {
				case newState := <-newStateCh:
					sm.mu.Lock()
					sm.activeState = newState
					sm.mu.Unlock()
					nextLeaders, err := sm.leaderProvider.GetNextLeaders(newState, ctx)
					if err != nil {
						sm.traceLogger.Error(
							fmt.Sprintf("error encountered in %s", sm.machineState),
							err,
						)
						return
					}
					found := false
					for _, leader := range nextLeaders {
						if leader.Identity() == sm.id.Identity() {
							found = true
							break
						}
					}
					if found {
						sm.SendEvent(EventSyncComplete)
					} else {
						time.Sleep(10 * time.Second)
						sm.SendEvent(EventSyncTimeout)
					}
				case <-errCh:
					time.Sleep(10 * time.Second)
					sm.SendEvent(EventSyncTimeout)
				case <-ctx.Done():
					return
				}
			}
		},
		Timeout:   10 * time.Hour,
		OnTimeout: EventSyncTimeout,
	}

	// Collecting state - wait for frame or timeout
	sm.stateConfigs[StateCollecting] = &Config{
		Behavior: func(sm *SMT, data *StateT, ctx context.Context) {
			sm.traceLogger.Trace("enter Collecting behavior")
			defer sm.traceLogger.Trace("exit Collecting behavior")
			collected, err := sm.livenessProvider.Collect(ctx)
			if err != nil {
				sm.traceLogger.Error(
					fmt.Sprintf("error encountered in %s", sm.machineState),
					err,
				)
				sm.SendEvent(EventInduceSync)
				return
			}

			sm.mu.Lock()
			sm.nextProvers = []PeerIDT{}
			sm.chosenProposer = nil
			sm.collected = &collected
			sm.mu.Unlock()

			nextProvers, err := sm.leaderProvider.GetNextLeaders(data, ctx)
			if err != nil {
				sm.traceLogger.Error(
					fmt.Sprintf("error encountered in %s", sm.machineState),
					err,
				)
				sm.SendEvent(EventInduceSync)
				return
			}

			sm.mu.Lock()
			sm.nextProvers = nextProvers
			sm.mu.Unlock()

			err = sm.livenessProvider.SendLiveness(data, collected, ctx)
			if err != nil {
				sm.traceLogger.Error(
					fmt.Sprintf("error encountered in %s", sm.machineState),
					err,
				)
				sm.SendEvent(EventInduceSync)
				return
			}

			sm.mu.Lock()
			if sm.shouldEmitReceiveEventsOnSends {
				if _, ok := sm.liveness[collected.Rank()]; !ok {
					sm.liveness[collected.Rank()] = make(map[Identity]CollectedT)
				}
				sm.liveness[collected.Rank()][sm.id.Identity()] = *sm.collected
			}
			sm.mu.Unlock()

			if sm.shouldEmitReceiveEventsOnSends {
				sm.SendEvent(EventLivenessCheckReceived)
			}

			sm.SendEvent(EventCollectionDone)
		},
		Timeout:   10 * time.Second,
		OnTimeout: EventInduceSync,
	}

	// Liveness check state
	sm.stateConfigs[StateLivenessCheck] = &Config{
		Behavior: func(sm *SMT, data *StateT, ctx context.Context) {
			sm.traceLogger.Trace("enter Liveness behavior")
			defer sm.traceLogger.Trace("exit Liveness behavior")
			sm.mu.Lock()
			nextProversLen := len(sm.nextProvers)
			sm.mu.Unlock()

			// If we're not meeting the minimum prover count, we should loop.
			if nextProversLen < int(sm.minimumProvers()) {
				sm.traceLogger.Trace("insufficient provers, re-fetching leaders")
				var err error
				nextProvers, err := sm.leaderProvider.GetNextLeaders(data, ctx)
				if err != nil {
					sm.traceLogger.Error(
						fmt.Sprintf("error encountered in %s", sm.machineState),
						err,
					)
					return
				}
				sm.mu.Lock()
				sm.nextProvers = nextProvers
				sm.mu.Unlock()
			}

			sm.mu.Lock()
			collected := *sm.collected
			sm.mu.Unlock()

			sm.mu.Lock()
			livenessLen := len(sm.liveness[(*sm.activeState).Rank()+1])
			sm.mu.Unlock()

			// We have enough checks for consensus:
			if livenessLen >= int(sm.minimumProvers()) {
				sm.traceLogger.Trace(
					"sufficient liveness checks, sending prover signal",
				)
				sm.SendEvent(EventProverSignal)
				return
			}

			sm.traceLogger.Trace(
				fmt.Sprintf(
					"insufficient liveness checks: need %d, have %d",
					sm.minimumProvers(),
					livenessLen,
				),
			)

			err := sm.livenessProvider.SendLiveness(data, collected, ctx)
			if err != nil {
				sm.traceLogger.Error(
					fmt.Sprintf("error encountered in %s", sm.machineState),
					err,
				)
				return
			}
		},
		Timeout:   1 * time.Second,
		OnTimeout: EventLivenessTimeout,
	}

	// Proving state - generate proof
	sm.stateConfigs[StateProving] = &Config{
		Behavior: func(sm *SMT, data *StateT, ctx context.Context) {
			sm.traceLogger.Trace("enter Proving behavior")
			defer sm.traceLogger.Trace("exit Proving behavior")
			sm.mu.Lock()
			collected := sm.collected
			sm.mu.Unlock()

			if collected == nil {
				return
			}

			proposal, err := sm.leaderProvider.ProveNextState(
				data,
				*collected,
				ctx,
			)
			if err != nil {
				sm.traceLogger.Error(
					fmt.Sprintf("error encountered in %s", sm.machineState),
					err,
				)

				return
			}

			sm.mu.Lock()
			sm.traceLogger.Trace(
				fmt.Sprintf("adding proposal with rank %d", (*proposal).Rank()),
			)
			if _, ok := sm.proposals[(*proposal).Rank()]; !ok {
				sm.proposals[(*proposal).Rank()] = make(map[Identity]*StateT)
			}
			sm.proposals[(*proposal).Rank()][sm.id.Identity()] = proposal
			sm.mu.Unlock()

			sm.SendEvent(EventProofComplete)
		},
		Timeout:   120 * time.Second,
		OnTimeout: EventPublishTimeout,
	}

	// Publishing state - publish frame
	sm.stateConfigs[StatePublishing] = &Config{
		Behavior: func(sm *SMT, data *StateT, ctx context.Context) {
			sm.traceLogger.Trace("enter Publishing behavior")
			defer sm.traceLogger.Trace("exit Publishing behavior")
			sm.mu.Lock()
			if _, ok := sm.proposals[(*data).Rank()+1][sm.id.Identity()]; ok {
				proposal := sm.proposals[(*data).Rank()+1][sm.id.Identity()]
				sm.mu.Unlock()

				err := sm.votingProvider.SendProposal(
					proposal,
					ctx,
				)
				if err != nil {
					sm.traceLogger.Error(
						fmt.Sprintf("error encountered in %s", sm.machineState),
						err,
					)
					return
				}
				sm.SendEvent(EventPublishComplete)
			}
		},
		Timeout:   1 * time.Second,
		OnTimeout: EventPublishTimeout,
	}

	// Voting state - monitor for quorum
	sm.stateConfigs[StateVoting] = &Config{
		Behavior: func(sm *SMT, data *StateT, ctx context.Context) {
			sm.traceLogger.Trace("enter Voting behavior")
			defer sm.traceLogger.Trace("exit Voting behavior")

			sm.mu.Lock()

			if sm.chosenProposer == nil {
				// We haven't voted yet
				sm.traceLogger.Trace("proposer not yet chosen")
				perfect := map[int]PeerIDT{} // all provers
				live := map[int]PeerIDT{}    // the provers who told us they're alive
				for i, p := range sm.nextProvers {
					perfect[i] = p
					if _, ok := sm.liveness[(*sm.activeState).Rank()+1][p.Identity()]; ok {
						live[i] = p
					}
				}

				if len(sm.proposals[(*sm.activeState).Rank()+1]) < int(sm.minimumProvers()) {
					sm.traceLogger.Trace("insufficient proposal count")
					sm.mu.Unlock()
					return
				}

				if ctx == nil {
					sm.traceLogger.Trace("context null")
					sm.mu.Unlock()
					return
				}

				select {
				case <-ctx.Done():
					sm.traceLogger.Trace("context canceled")
					sm.mu.Unlock()
					return
				default:
					sm.traceLogger.Trace("choosing proposal")
					proposals := map[Identity]*StateT{}
					for k, v := range sm.proposals[(*sm.activeState).Rank()+1] {
						state := (*v).Clone().(StateT)
						proposals[k] = &state
					}

					sm.mu.Unlock()
					selectedPeer, vote, err := sm.votingProvider.DecideAndSendVote(
						proposals,
						ctx,
					)
					if err != nil {
						sm.traceLogger.Error(
							fmt.Sprintf("error encountered in %s", sm.machineState),
							err,
						)
						break
					}
					sm.mu.Lock()
					sm.chosenProposer = &selectedPeer

					if sm.shouldEmitReceiveEventsOnSends {
						if _, ok := sm.votes[(*sm.activeState).Rank()+1]; !ok {
							sm.votes[(*sm.activeState).Rank()+1] = make(map[Identity]*VoteT)
						}
						sm.votes[(*sm.activeState).Rank()+1][sm.id.Identity()] = vote
						sm.mu.Unlock()
						sm.SendEvent(EventVoteReceived)
						return
					}
					sm.mu.Unlock()
				}
			} else {
				sm.traceLogger.Trace("proposal chosen, checking for quorum")
				proposalVotes := map[Identity]*VoteT{}
				for p, vp := range sm.votes[(*sm.activeState).Rank()+1] {
					vclone := (*vp).Clone().(VoteT)
					proposalVotes[p] = &vclone
				}
				haveEnoughProposals := len(sm.proposals[(*sm.activeState).Rank()+1]) >=
					int(sm.minimumProvers())
				sm.mu.Unlock()
				isQuorum, err := sm.votingProvider.IsQuorum(proposalVotes, ctx)
				if err != nil {
					sm.traceLogger.Error(
						fmt.Sprintf("error encountered in %s", sm.machineState),
						err,
					)
					return
				}

				if isQuorum && haveEnoughProposals {
					sm.traceLogger.Trace("quorum reached")
					sm.SendEvent(EventQuorumReached)
				} else {
					sm.traceLogger.Trace(
						fmt.Sprintf(
							"quorum not reached: proposals: %d, needed: %d",
							len(sm.proposals[(*sm.activeState).Rank()+1]),
							sm.minimumProvers(),
						),
					)
				}
			}
		},
		Timeout:   1 * time.Second,
		OnTimeout: EventVotingTimeout,
	}

	// Finalizing state
	sm.stateConfigs[StateFinalizing] = &Config{
		Behavior: func(sm *SMT, data *StateT, ctx context.Context) {
			sm.mu.Lock()
			proposals := map[Identity]*StateT{}
			for k, v := range sm.proposals[(*sm.activeState).Rank()+1] {
				state := (*v).Clone().(StateT)
				proposals[k] = &state
			}
			proposalVotes := map[Identity]*VoteT{}
			for p, vp := range sm.votes[(*sm.activeState).Rank()+1] {
				vclone := (*vp).Clone().(VoteT)
				proposalVotes[p] = &vclone
			}
			sm.mu.Unlock()
			finalized, _, err := sm.votingProvider.FinalizeVotes(
				proposals,
				proposalVotes,
				ctx,
			)
			if err != nil {
				sm.traceLogger.Error(
					fmt.Sprintf("error encountered in %s", sm.machineState),
					err,
				)
				return
			}
			next := (*finalized).Clone().(StateT)
			sm.mu.Lock()
			sm.nextState = &next
			sm.mu.Unlock()
			sm.SendEvent(EventAggregationDone)
		},
		Timeout:   1 * time.Second,
		OnTimeout: EventAggregationTimeout,
	}

	// Verifying state
	sm.stateConfigs[StateVerifying] = &Config{
		Behavior: func(sm *SMT, data *StateT, ctx context.Context) {
			sm.traceLogger.Trace("enter Verifying behavior")
			defer sm.traceLogger.Trace("exit Verifying behavior")
			sm.mu.Lock()
			if _, ok := sm.confirmations[(*sm.activeState).Rank()+1][sm.id.Identity()]; !ok &&
				sm.nextState != nil {
				nextState := sm.nextState
				sm.mu.Unlock()
				err := sm.votingProvider.SendConfirmation(nextState, ctx)
				if err != nil {
					sm.traceLogger.Error(
						fmt.Sprintf("error encountered in %s", sm.machineState),
						err,
					)
				}
				sm.mu.Lock()
			}

			progressed := false
			if sm.nextState != nil {
				sm.activeState = sm.nextState
				progressed = true
			}
			if progressed {
				sm.nextState = nil
				sm.collected = nil
				delete(sm.liveness, (*sm.activeState).Rank())
				delete(sm.proposals, (*sm.activeState).Rank())
				delete(sm.votes, (*sm.activeState).Rank())
				delete(sm.confirmations, (*sm.activeState).Rank())
				sm.mu.Unlock()
				sm.SendEvent(EventVerificationDone)
			} else {
				sm.mu.Unlock()
			}
		},
		Timeout:   1 * time.Second,
		OnTimeout: EventVerificationTimeout,
	}

	// Stopping state
	sm.stateConfigs[StateStopping] = &Config{
		Behavior: func(sm *SMT, data *StateT, ctx context.Context) {
			sm.SendEvent(EventCleanupComplete)
		},
		Timeout:   30 * time.Second,
		OnTimeout: EventCleanupComplete,
	}
}

// defineTransitions sets up all possible state transitions
func (sm *StateMachine[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) defineTransitions() {
	sm.traceLogger.Trace("enter defineTransitions")
	defer sm.traceLogger.Trace("exit defineTransitions")

	// Helper to add transition
	addTransition := func(
		from State,
		event Event,
		to State,
		guard TransitionGuard[StateT, VoteT, PeerIDT, CollectedT],
	) {
		if sm.transitions[from] == nil {
			sm.transitions[from] = make(map[Event]*Transition[
				StateT,
				VoteT,
				PeerIDT,
				CollectedT,
			])
		}
		sm.transitions[from][event] = &Transition[
			StateT,
			VoteT,
			PeerIDT,
			CollectedT,
		]{
			From:  from,
			Event: event,
			To:    to,
			Guard: guard,
		}
	}

	// Basic flow transitions
	addTransition(StateStopped, EventStart, StateStarting, nil)
	addTransition(StateStarting, EventInitComplete, StateLoading, nil)
	addTransition(StateLoading, EventSyncTimeout, StateLoading, nil)
	addTransition(StateLoading, EventSyncComplete, StateCollecting, nil)
	addTransition(StateCollecting, EventCollectionDone, StateLivenessCheck, nil)
	addTransition(StateLivenessCheck, EventProverSignal, StateProving, nil)

	// Loop indefinitely if nobody can be found
	addTransition(
		StateLivenessCheck,
		EventLivenessTimeout,
		StateLivenessCheck,
		nil,
	)
	// Loop until we get enough of these
	addTransition(
		StateLivenessCheck,
		EventLivenessCheckReceived,
		StateLivenessCheck,
		nil,
	)

	// Prover flow
	addTransition(StateProving, EventProofComplete, StatePublishing, nil)
	addTransition(StateProving, EventPublishTimeout, StateVoting, nil)
	addTransition(StatePublishing, EventPublishComplete, StateVoting, nil)
	addTransition(StatePublishing, EventPublishTimeout, StateVoting, nil)

	// Common voting flow
	addTransition(StateVoting, EventProposalReceived, StateVoting, nil)
	addTransition(StateVoting, EventVoteReceived, StateVoting, nil)
	addTransition(StateVoting, EventQuorumReached, StateFinalizing, nil)
	addTransition(StateVoting, EventVotingTimeout, StateVoting, nil)
	addTransition(StateFinalizing, EventAggregationDone, StateVerifying, nil)
	addTransition(StateFinalizing, EventAggregationTimeout, StateFinalizing, nil)
	addTransition(StateVerifying, EventVerificationDone, StateCollecting, nil)
	addTransition(StateVerifying, EventVerificationTimeout, StateVerifying, nil)

	// Stop or induce Sync transitions from any state
	for _, state := range []State{
		StateStarting,
		StateLoading,
		StateCollecting,
		StateLivenessCheck,
		StateProving,
		StatePublishing,
		StateVoting,
		StateFinalizing,
		StateVerifying,
	} {
		addTransition(state, EventStop, StateStopping, nil)
		addTransition(state, EventInduceSync, StateLoading, nil)
	}

	addTransition(StateStopping, EventCleanupComplete, StateStopped, nil)
}

// Start begins the state machine
func (sm *StateMachine[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) Start() error {
	sm.traceLogger.Trace("enter start")
	defer sm.traceLogger.Trace("exit start")
	sm.SendEvent(EventStart)
	return nil
}

// Stop halts the state machine
func (sm *StateMachine[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) Stop() error {
	sm.traceLogger.Trace("enter stop")
	defer sm.traceLogger.Trace("exit stop")
	sm.SendEvent(EventStop)
	return nil
}

// SendEvent sends an event to the state machine
func (sm *StateMachine[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) SendEvent(event Event) {
	sm.traceLogger.Trace(fmt.Sprintf("enter sendEvent: %s", event))
	defer sm.traceLogger.Trace(fmt.Sprintf("exit sendEvent: %s", event))
	response := make(chan error, 1)
	go func() {
		select {
		case sm.eventChan <- eventWrapper{event: event, response: response}:
			<-response
		case <-sm.ctx.Done():
			return
		}
	}()
}

// processEvents handles events and transitions
func (sm *StateMachine[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) processEvents() {
	defer func() {
		if r := recover(); r != nil {
			sm.traceLogger.Error(
				"fatal error encountered",
				errors.New(fmt.Sprintf("%+v", r)),
			)
			sm.Close()
		}
	}()

	sm.traceLogger.Trace("enter processEvents")
	defer sm.traceLogger.Trace("exit processEvents")
	for {
		select {
		case <-sm.ctx.Done():
			return
		case wrapper := <-sm.eventChan:
			err := sm.handleEvent(wrapper.event)
			wrapper.response <- err
		}
	}
}

// handleEvent processes a single event
func (sm *StateMachine[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) handleEvent(event Event) error {
	sm.traceLogger.Trace(fmt.Sprintf("enter handleEvent: %s", event))
	defer sm.traceLogger.Trace(fmt.Sprintf("exit handleEvent: %s", event))
	sm.mu.Lock()

	currentState := sm.machineState
	transitions, exists := sm.transitions[currentState]
	if !exists {
		sm.mu.Unlock()

		return errors.Wrap(
			fmt.Errorf("no transitions defined for state %s", currentState),
			"handle event",
		)
	}

	transition, exists := transitions[event]
	if !exists {
		sm.mu.Unlock()

		return errors.Wrap(
			fmt.Errorf(
				"no transition for event %s in state %s",
				event,
				currentState,
			),
			"handle event",
		)
	}

	// Check guard condition with the actual state
	if transition.Guard != nil && !transition.Guard(sm) {
		sm.mu.Unlock()

		return errors.Wrap(
			fmt.Errorf(
				"transition guard failed for %s -> %s on %s",
				currentState,
				transition.To,
				event,
			),
			"handle event",
		)
	}

	sm.mu.Unlock()

	// Execute transition
	sm.executeTransition(currentState, transition.To, event)
	return nil
}

// executeTransition performs the state transition
func (sm *StateMachine[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) executeTransition(
	from State,
	to State,
	event Event,
) {
	sm.traceLogger.Trace(
		fmt.Sprintf("enter executeTransition: %s -> %s [%s]", from, to, event),
	)
	defer sm.traceLogger.Trace(
		fmt.Sprintf("exit executeTransition: %s -> %s [%s]", from, to, event),
	)
	sm.mu.Lock()

	// Cancel any existing timeout and behavior
	if sm.timeoutTimer != nil {
		sm.timeoutTimer.Stop()
		sm.timeoutTimer = nil
	}

	// Cancel existing behavior if any
	if sm.behaviorCancel != nil {
		sm.behaviorCancel()
		sm.behaviorCancel = nil
	}

	// Call exit callback for current state
	if config, exists := sm.stateConfigs[from]; exists && config.OnExit != nil {
		sm.mu.Unlock()
		config.OnExit(sm, sm.activeState, event)
		sm.mu.Lock()
	}

	// Update state
	sm.machineState = to
	sm.stateStartTime = time.Now()
	sm.transitionCount++

	// Notify listeners
	for _, listener := range sm.listeners {
		listener.OnTransition(from, to, event)
	}

	// Call enter callback for new state
	if config, exists := sm.stateConfigs[to]; exists {
		if config.OnEnter != nil {
			sm.mu.Unlock()
			config.OnEnter(sm, sm.activeState, event)
			sm.mu.Lock()
		}

		// Start state behavior if defined
		if config.Behavior != nil {
			behaviorCtx, cancel := context.WithCancel(sm.ctx)
			sm.behaviorCancel = cancel
			sm.mu.Unlock()
			config.Behavior(sm, sm.activeState, behaviorCtx)
			sm.mu.Lock()
		}

		// Set up timeout for new state
		if config.Timeout > 0 && config.OnTimeout != "" {
			sm.timeoutTimer = time.AfterFunc(config.Timeout, func() {
				sm.SendEvent(config.OnTimeout)
			})
		}
	}
	sm.mu.Unlock()
}

// GetState returns the current state
func (sm *StateMachine[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) GetState() State {
	sm.traceLogger.Trace("enter getstate")
	defer sm.traceLogger.Trace("exit getstate")
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.machineState
}

// Additional methods for compatibility
func (sm *StateMachine[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) GetStateTime() time.Duration {
	sm.traceLogger.Trace("enter getstatetime")
	defer sm.traceLogger.Trace("exit getstatetime")
	return time.Since(sm.stateStartTime)
}

func (sm *StateMachine[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) GetTransitionCount() uint64 {
	sm.traceLogger.Trace("enter transitioncount")
	defer sm.traceLogger.Trace("exit transitioncount")
	return sm.transitionCount
}

func (sm *StateMachine[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) AddListener(listener TransitionListener[StateT]) {
	sm.traceLogger.Trace("enter addlistener")
	defer sm.traceLogger.Trace("exit addlistener")
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.listeners = append(sm.listeners, listener)
}

func (sm *StateMachine[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) Close() {
	sm.traceLogger.Trace("enter close")
	defer sm.traceLogger.Trace("exit close")
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.cancel()
	if sm.timeoutTimer != nil {
		sm.timeoutTimer.Stop()
	}
	if sm.behaviorCancel != nil {
		sm.behaviorCancel()
	}
	sm.machineState = StateStopped
}

// ReceiveLivenessCheck receives a liveness announcement and captures
// collected mutation operations reported by the peer if relevant.
func (sm *StateMachine[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) ReceiveLivenessCheck(peer PeerIDT, collected CollectedT) error {
	sm.traceLogger.Trace(
		fmt.Sprintf(
			"enter receivelivenesscheck, peer: %s, rank: %d",
			peer.Identity(),
			collected.Rank(),
		),
	)
	defer sm.traceLogger.Trace("exit receivelivenesscheck")
	sm.mu.Lock()
	if _, ok := sm.liveness[collected.Rank()]; !ok {
		sm.liveness[collected.Rank()] = make(map[Identity]CollectedT)
	}
	if _, ok := sm.liveness[collected.Rank()][peer.Identity()]; !ok {
		sm.liveness[collected.Rank()][peer.Identity()] = collected
	}
	sm.mu.Unlock()

	sm.SendEvent(EventLivenessCheckReceived)
	return nil
}

// ReceiveProposal receives a proposed new state.
func (sm *StateMachine[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) ReceiveProposal(peer PeerIDT, proposal *StateT) error {
	sm.traceLogger.Trace("enter receiveproposal")
	defer sm.traceLogger.Trace("exit receiveproposal")
	sm.mu.Lock()
	if _, ok := sm.proposals[(*proposal).Rank()]; !ok {
		sm.proposals[(*proposal).Rank()] = make(map[Identity]*StateT)
	}
	if _, ok := sm.proposals[(*proposal).Rank()][peer.Identity()]; !ok {
		sm.proposals[(*proposal).Rank()][peer.Identity()] = proposal
	}
	sm.mu.Unlock()

	sm.SendEvent(EventProposalReceived)
	return nil
}

// ReceiveVote captures a vote. Presumes structural and protocol validity of a
// vote has already been evaluated.
func (sm *StateMachine[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) ReceiveVote(proposer PeerIDT, voter PeerIDT, vote *VoteT) error {
	sm.traceLogger.Trace("enter receivevote")
	defer sm.traceLogger.Trace("exit receivevote")
	sm.mu.Lock()

	if _, ok := sm.votes[(*vote).Rank()]; !ok {
		sm.votes[(*vote).Rank()] = make(map[Identity]*VoteT)
	}
	if _, ok := sm.votes[(*vote).Rank()][voter.Identity()]; !ok {
		sm.votes[(*vote).Rank()][voter.Identity()] = vote
	} else if (*sm.votes[(*vote).Rank()][voter.Identity()]).Identity() !=
		(*vote).Identity() {
		sm.mu.Unlock()
		return errors.Wrap(errors.New("received conflicting vote"), "receive vote")
	}
	sm.mu.Unlock()

	sm.SendEvent(EventVoteReceived)
	return nil
}

// ReceiveConfirmation captures a confirmation. Presumes structural and protocol
// validity of the state has already been evaluated.
func (sm *StateMachine[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) ReceiveConfirmation(
	peer PeerIDT,
	confirmation *StateT,
) error {
	sm.traceLogger.Trace("enter receiveconfirmation")
	defer sm.traceLogger.Trace("exit receiveconfirmation")
	sm.mu.Lock()
	if _, ok := sm.confirmations[(*confirmation).Rank()]; !ok {
		sm.confirmations[(*confirmation).Rank()] = make(map[Identity]*StateT)
	}
	if _, ok := sm.confirmations[(*confirmation).Rank()][peer.Identity()]; !ok {
		sm.confirmations[(*confirmation).Rank()][peer.Identity()] = confirmation
	}
	sm.mu.Unlock()

	sm.SendEvent(EventConfirmationReceived)
	return nil
}
