package consensus

import (
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution"
)

type EngineState int

const (
	EngineStateStopped EngineState = iota
	EngineStateStarting
	EngineStateLoading
	EngineStateCollecting
	EngineStateLivenessCheck
	EngineStateProving
	EngineStatePublishing
	EngineStateVoting
	EngineStateFinalizing
	EngineStateVerifying
	EngineStateStopping
)

func (s EngineState) String() string {
	switch s {
	case EngineStateStopped:
		return "stopped"
	case EngineStateStarting:
		return "starting"
	case EngineStateLoading:
		return "loading"
	case EngineStateCollecting:
		return "collecting"
	case EngineStateLivenessCheck:
		return "liveness_check"
	case EngineStateProving:
		return "proving"
	case EngineStatePublishing:
		return "publishing"
	case EngineStateVoting:
		return "voting"
	case EngineStateFinalizing:
		return "finalizing"
	case EngineStateVerifying:
		return "verifying"
	case EngineStateStopping:
		return "stopping"
	default:
		return "unknown"
	}
}

type AppConsensusEngine interface {
	Start(quit chan struct{}) <-chan error
	Stop(force bool) <-chan error
	RegisterExecutor(
		exec execution.ShardExecutionEngine,
		frame uint64,
	) <-chan error
	UnregisterExecutor(name string, frame uint64, force bool) <-chan error
	GetFrame() *protobufs.AppShardFrame
	GetDifficulty() uint32
	GetState() EngineState
	GetProvingKey(
		engineConfig *config.EngineConfig,
	) (crypto.Signer, crypto.KeyType, []byte, []byte)
	IsInProverTrie(key []byte) bool
	GetPeerInfo() *protobufs.PeerInfoResponse
	InitializeFromGlobalFrame(globalFrame *protobufs.GlobalFrameHeader) error
}

type GlobalConsensusEngine interface {
	Start(quit chan struct{}) <-chan error
	Stop(force bool) <-chan error
	RegisterExecutor(
		exec execution.ShardExecutionEngine,
		frame uint64,
	) <-chan error
	UnregisterExecutor(name string, frame uint64, force bool) <-chan error
	GetFrame() *protobufs.GlobalFrame
	GetDifficulty() uint32
	GetState() EngineState
	GetProvingKey(
		engineConfig *config.EngineConfig,
	) (crypto.Signer, crypto.KeyType, []byte, []byte)
	IsInProverTrie(key []byte) bool
	GetPeerInfo() *protobufs.PeerInfoResponse
}
