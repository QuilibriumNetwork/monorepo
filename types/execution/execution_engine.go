package execution

import (
	"math/big"

	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
)

type ProcessMessageResult struct {
	Messages []*protobufs.Message
	State    state.State
}

type ShardExecutionEngine interface {
	GetName() string
	Start(chan struct{}) <-chan error
	Stop(force bool) <-chan error
	ValidateMessage(frameNumber uint64, address []byte, message []byte) error
	ProcessMessage(
		frameNumber uint64,
		feeMultiplier *big.Int,
		address []byte,
		message []byte,
		state state.State,
	) (*ProcessMessageResult, error)
	GetCapabilities() []*protobufs.Capability
}
