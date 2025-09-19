# Consensus State Machine

A generic, extensible state machine implementation for building Byzantine Fault
Tolerant (BFT) consensus protocols. This library provides a framework for
implementing round-based consensus algorithms with cryptographic proofs.

## Overview

The state machine manages consensus engine state transitions through a
well-defined set of states and events. It supports generic type parameters to
allow different implementations of state data, votes, peer identities, and
collected mutations.

## Features

- **Generic Implementation**: Supports custom types for state data, votes, peer
  IDs, and collected data
- **Byzantine Fault Tolerance**: Provides BFT consensus with < 1/3 byzantine
  nodes, flexible to other probabilistic BFT implementations
- **Round-based Consensus**: Implements a round-based state transition pattern
- **Pluggable Providers**: Extensible through provider interfaces for different
  consensus behaviors
- **Event-driven Architecture**: State transitions triggered by events with
  optional guard conditions
- **Concurrent Safe**: Thread-safe implementation with proper mutex usage
- **Timeout Support**: Configurable timeouts for each state with automatic
  transitions
- **Transition Listeners**: Observable state transitions for monitoring and
  debugging

## Core Concepts

### States

The state machine progresses through the following states:

1. **StateStopped**: Initial state, engine is not running
2. **StateStarting**: Engine is initializing
3. **StateLoading**: Loading data and syncing with network
4. **StateCollecting**: Collecting data/mutations for consensus round
5. **StateLivenessCheck**: Checking peer liveness before proving
6. **StateProving**: Generating cryptographic proof (leader only)
7. **StatePublishing**: Publishing proposed state
8. **StateVoting**: Voting on proposals
9. **StateFinalizing**: Finalizing consensus round
10. **StateVerifying**: Verifying and publishing results
11. **StateStopping**: Engine is shutting down

### Events

Events trigger state transitions:
- `EventStart`, `EventStop`: Lifecycle events
- `EventSyncComplete`: Synchronization finished
- `EventCollectionDone`: Mutation collection complete
- `EventLivenessCheckReceived`: Peer liveness confirmed
- `EventProverSignal`: Leader selection complete
- `EventProofComplete`: Proof generation finished
- `EventProposalReceived`: New proposal received
- `EventVoteReceived`: Vote received
- `EventQuorumReached`: Voting quorum achieved
- `EventConfirmationReceived`: State confirmation received
- And more...

### Type Constraints

All generic type parameters must implement the `Unique` interface:

```go
type Unique interface {
    Identity() Identity  // Returns a unique string identifier
}
```

## Provider Interfaces

### SyncProvider

Handles initial state synchronization:

```go
type SyncProvider[StateT Unique] interface {
    Synchronize(
        existing *StateT,
        ctx context.Context,
    ) (<-chan *StateT, <-chan error)
}
```

### VotingProvider

Manages the voting process:

```go
type VotingProvider[StateT Unique, VoteT Unique, PeerIDT Unique] interface {
    SendProposal(proposal *StateT, ctx context.Context) error
    DecideAndSendVote(
        proposals map[Identity]*StateT,
        ctx context.Context,
    ) (PeerIDT, *VoteT, error)
    IsQuorum(votes map[Identity]*VoteT, ctx context.Context) (bool, error)
    FinalizeVotes(
        proposals map[Identity]*StateT,
        votes map[Identity]*VoteT,
        ctx context.Context,
    ) (*StateT, PeerIDT, error)
    SendConfirmation(finalized *StateT, ctx context.Context) error
}
```

### LeaderProvider

Handles leader selection and proof generation:

```go
type LeaderProvider[
    StateT Unique,
    PeerIDT Unique,
    CollectedT Unique,
] interface {
    GetNextLeaders(prior *StateT, ctx context.Context) ([]PeerIDT, error)
    ProveNextState(
        prior *StateT,
        collected CollectedT,
        ctx context.Context,
    ) (*StateT, error)
}
```

### LivenessProvider

Manages peer liveness checks:

```go
type LivenessProvider[
    StateT Unique,
    PeerIDT Unique,
    CollectedT Unique,
] interface {
    Collect(ctx context.Context) (CollectedT, error)
    SendLiveness(prior *StateT, collected CollectedT, ctx context.Context) error
}
```

## Usage

### Basic Setup

```go
// Define your types implementing Unique
type MyState struct {
    Round uint64
    Hash  string
}
func (s MyState) Identity() string { return s.Hash }

type MyVote struct {
    Voter string
    Value bool
}
func (v MyVote) Identity() string { return v.Voter }

type MyPeerID struct {
    ID string
}
func (p MyPeerID) Identity() string { return p.ID }

type MyCollected struct {
    Data []byte
}
func (c MyCollected) Identity() string { return string(c.Data) }

// Implement providers
syncProvider := &MySyncProvider{}
votingProvider := &MyVotingProvider{}
leaderProvider := &MyLeaderProvider{}
livenessProvider := &MyLivenessProvider{}

// Create state machine
sm := consensus.NewStateMachine[MyState, MyVote, MyPeerID, MyCollected](
    MyPeerID{ID: "node1"},           // This node's ID
    &MyState{Round: 0, Hash: "genesis"}, // Initial state
    true,                            // shouldEmitReceiveEventsOnSends
    3,                              // minimumProvers
    syncProvider,
    votingProvider,
    leaderProvider,
    livenessProvider,
    nil,                            // Optional trace logger
)

// Add transition listener
sm.AddListener(&MyTransitionListener{})

// Start the state machine
if err := sm.Start(); err != nil {
    log.Fatal(err)
}

// Receive external events
sm.ReceiveProposal(peer, proposal)
sm.ReceiveVote(voter, vote)
sm.ReceiveLivenessCheck(peer, collected)
sm.ReceiveConfirmation(peer, confirmation)

// Stop the state machine
if err := sm.Stop(); err != nil {
    log.Fatal(err)
}
```

### Implementing Providers

See the `example/generic_consensus_example.go` for a complete working example
with mock provider implementations.

## State Flow

The typical consensus flow:

1. **Start** → **Starting** → **Loading**
2. **Loading**: Synchronize with network
3. **Collecting**: Gather mutations/changes
4. **LivenessCheck**: Verify peer availability
5. **Proving**: Leader generates proof
6. **Publishing**: Leader publishes proposal
7. **Voting**: All nodes vote on proposals
8. **Finalizing**: Aggregate votes and determine outcome
9. **Verifying**: Confirm and apply state changes
10. Loop back to **Collecting** for next round

## Configuration

### Constructor Parameters

- `id`: This node's peer ID
- `initialState`: Starting state (can be nil)
- `shouldEmitReceiveEventsOnSends`: Whether to emit receive events for own
  messages
- `minimumProvers`: Minimum number of active provers required
- `traceLogger`: Optional logger for debugging state transitions

### State Timeouts

Each state can have a configured timeout that triggers an automatic transition:

- **Starting**: 1 second → `EventInitComplete`
- **Loading**: 10 minutes → `EventSyncComplete`
- **Collecting**: 1 second → `EventCollectionDone`
- **LivenessCheck**: 1 second → `EventLivenessTimeout`
- **Proving**: 120 seconds → `EventPublishTimeout`
- **Publishing**: 1 second → `EventPublishTimeout`
- **Voting**: 10 seconds → `EventVotingTimeout`
- **Finalizing**: 1 second → `EventAggregationDone`
- **Verifying**: 1 second → `EventVerificationDone`
- **Stopping**: 30 seconds → `EventCleanupComplete`

## Thread Safety

The state machine is thread-safe. All public methods properly handle concurrent
access through mutex locks. State behaviors run in separate goroutines with
proper cancellation support.

## Error Handling

- Provider errors are logged but don't crash the state machine
- The state machine continues operating and may retry operations
- Critical errors during state transitions are returned to callers
- Use the `TraceLogger` interface for debugging

## Best Practices

1. **Message Isolation**: When implementing providers, always deep-copy data
   before sending to prevent shared state between state machine and other
   handlers
2. **Nil Handling**: Provider implementations should handle nil prior states
   gracefully
3. **Context Usage**: Respect context cancellation in long-running operations
4. **Quorum Size**: Set appropriate quorum size based on your network (typically
   2f+1 for f failures)
5. **Timeout Configuration**: Adjust timeouts based on network conditions and
   proof generation time

## Example

See `example/generic_consensus_example.go` for a complete working example
demonstrating:
- Mock provider implementations
- Multi-node consensus network
- Byzantine node behavior
- Message passing between nodes
- State transition monitoring

## Testing

The package includes comprehensive tests in `state_machine_test.go` covering:
- State transitions
- Event handling
- Concurrent operations
- Byzantine scenarios
- Timeout behavior
