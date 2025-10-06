package consensus

import (
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
)

// ProverStatus represents the current status of a prover
type ProverStatus uint8

const (
	ProverStatusUnknown ProverStatus = iota
	ProverStatusJoining
	ProverStatusActive
	ProverStatusPaused
	ProverStatusLeaving
	ProverStatusRejected
	ProverStatusKicked
)

// ProverAllocationInfo represents the information of a prover's specific
// allocation to a shard
type ProverAllocationInfo struct {
	// Current status of the allocation
	Status ProverStatus
	// Confirmed filter
	ConfirmationFilter []byte
	// Rejected filter
	RejectionFilter []byte
	// Frame number when the prover has joined
	JoinFrameNumber uint64
	// Frame number when the prover has left
	LeaveFrameNumber uint64
	// Frame number if the prover has paused
	PauseFrameNumber uint64
	// Frame number if the prover has resumed
	ResumeFrameNumber uint64
	// Frame number if the prover has been kicked
	KickFrameNumber uint64
	// Frame number of the prover's confirmation of joining
	JoinConfirmFrameNumber uint64
	// Frame number of the prover's rejection of joining
	JoinRejectFrameNumber uint64
	// Frame number of the prover's confirmation of leaving
	LeaveConfirmFrameNumber uint64
	// Frame number of the prover's rejection of leaving
	LeaveRejectFrameNumber uint64
	// Last frame number the prover had proved
	LastActiveFrameNumber uint64
}

// ProverInfo represents information about a prover
type ProverInfo struct {
	// The BLS48-581 public key of the prover
	PublicKey []byte
	// The poseidon hash address derived from the public key
	Address []byte
	// Current status of the prover
	Status ProverStatus
	// Frame number if the prover has been kicked
	KickFrameNumber uint64
	// The shards this prover is assigned to
	Allocations []ProverAllocationInfo
	// Available storage capacity in bytes
	AvailableStorage uint64
	// Seniority value
	Seniority uint64
	// Delegate address for rewards
	DelegateAddress []byte
}

// ProverRegistry is an interface for tracking prover information from
// hypergraph state transitions.
type ProverRegistry interface {
	// ProcessStateTransition processes a state transition to update prover
	// information. This should be called whenever the hypergraph state changes.
	// It does not commit the state, only reads it to update internal tracking.
	ProcessStateTransition(state state.State, frameNumber uint64) error

	// GetProverInfo returns information about a specific prover by address.
	GetProverInfo(address []byte) (*ProverInfo, error)

	// GetNextProver returns the next prover address based on input value. Uses
	// FindNearest internally.
	GetNextProver(input [32]byte, filter []byte) ([]byte, error)

	// GetOrderedProvers returns the next prover address based on input value.
	// Uses FindNearestAndApproximateNeighbors internally.
	GetOrderedProvers(input [32]byte, filter []byte) ([][]byte, error)

	// GetActiveProvers returns all active provers for a given filter/shard. If
	// filter is nil, returns global provers. List is lexicographically sorted.
	GetActiveProvers(filter []byte) ([]*ProverInfo, error)

	// GetProverCount returns the number of active provers for a filter/shard.
	GetProverCount(filter []byte) (int, error)

	// GetProvers returns all provers for a filter/shard
	GetProvers(filter []byte) ([]*ProverInfo, error)

	// GetProversByStatus returns all provers with a specific status for a
	// filter/shard.
	GetProversByStatus(filter []byte, status ProverStatus) ([]*ProverInfo, error)

	// UpdateProverActivity updates the last active frame for a prover.
	UpdateProverActivity(address []byte, filter []byte, frameNumber uint64) error

	// Refresh re-reads the hypergraph state to update prover information. This is
	// useful for periodic refreshes or after known state changes.
	Refresh() error

	// ExtractProversFromTransactions processes historical transactions to
	// discover prover addresses. This can be used during initial sync to build
	// the prover registry from past state changes.
	ExtractProversFromTransactions(transactions []state.StateChange) error

	// GetAllActiveAppShardProvers returns all active provers across all app
	// shards (i.e., all provers with non-nil filters). This is used for global
	// coordination and coverage checks.
	GetAllActiveAppShardProvers() ([]*ProverInfo, error)
}
