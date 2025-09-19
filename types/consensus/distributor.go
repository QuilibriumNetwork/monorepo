package consensus

import (
	"context"
)

type ControlEventType int

const (
	// ControlEventStart indicates frame processing should start
	ControlEventStart ControlEventType = iota
	// ControlEventStop indicates frame processing should stop
	ControlEventStop
	// ControlEventHalt indicates frame processing should halt
	ControlEventHalt
	// ControlEventResume indicates frame processing should resume
	ControlEventResume
	// ControlEventGlobalNewHead indicates a new global head frame
	ControlEventGlobalNewHead
	// ControlEventGlobalFork indicates a global fork has been detected
	ControlEventGlobalFork
	// ControlEventGlobalEquivocation indicates a global equivocation has been
	// detected
	ControlEventGlobalEquivocation
	// ControlEventAppNewHead indicates a new app head frame
	ControlEventAppNewHead
	// ControlEventAppFork indicates an app fork has been detected
	ControlEventAppFork
	// ControlEventAppEquivocation indicates an app equivocation has been detected
	ControlEventAppEquivocation
	// ControlEventCoverageHalt indicates network-wide halt due to insufficient
	// coverage
	ControlEventCoverageHalt
	// ControlEventCoverageWarn indicates a shard has low coverage
	ControlEventCoverageWarn
	// ControlEventCoverageResume indicates a shard has sufficient coverage to
	// resume
	ControlEventCoverageResume
	// ControlEventShardMergeEligible indicates shards can be merged
	ControlEventShardMergeEligible
	// ControlEventShardSplitEligible indicates a shard can be split
	ControlEventShardSplitEligible
)

// ControlEvent represents control events sent to frame producers
type ControlEvent struct {
	Type ControlEventType
	Data ControlEventData
}

// ControlEventData holds the specific data for each control event type
type ControlEventData interface {
	ControlEventData()
}

// EventType represents the type of control event
type EventType int

const (
	EventTypeNewFrame EventType = iota
	EventTypeStateChange
	EventTypeError
)

// NewFrameEventData contains data for a new frame event
type NewFrameEventData struct {
	Frame interface{} // Can be AppShardFrame or GlobalFrame
}

func (n *NewFrameEventData) ControlEventData() {}

// StateChangeEventData contains data for a state change event
type StateChangeEventData struct {
	OldState EngineState
	NewState EngineState
}

func (s *StateChangeEventData) ControlEventData() {}

// ErrorEventData contains data for an error event
type ErrorEventData struct {
	Error error
}

func (e *ErrorEventData) ControlEventData() {}

// CoverageEventData contains data for coverage-related events
type CoverageEventData struct {
	ShardAddress    []byte
	ProverCount     int
	RequiredProvers int
	AttestedStorage uint64
	TreeMetadata    []TreeMetadata
	Message         string
}

func (c *CoverageEventData) ControlEventData() {}

// TreeMetadata represents hypergraph ID set metadata
type TreeMetadata struct {
	CommitmentRoot []byte // 74 bytes
	TotalSize      uint64
	TotalLeaves    uint64
}

// ShardMergeEventData contains data for shard merge eligibility
type ShardMergeEventData struct {
	ShardAddresses  [][]byte
	TotalProvers    int
	AttestedStorage uint64
	RequiredStorage uint64
}

func (s *ShardMergeEventData) ControlEventData() {}

// ShardSplitEventData contains data for shard split eligibility
type ShardSplitEventData struct {
	ShardAddress    []byte
	ProverCount     int
	AttestedStorage uint64
	ProposedShards  [][]byte
}

func (s *ShardSplitEventData) ControlEventData() {}

// EventDistributor defines the interface for event distribution systems
type EventDistributor interface {
	// Start begins the event processing loop with a cancelable context
	Start(ctx context.Context) error

	// Stop gracefully shuts down the event distributor
	Stop() error

	// Subscribe registers a new subscriber with a unique ID and returns their
	// control event channel
	Subscribe(id string) <-chan ControlEvent

	// Publish manually publishes a new event to all subscribers
	Publish(event ControlEvent)

	// Unsubscribe removes a subscriber by ID
	Unsubscribe(id string)
}
