package global

import (
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
)

type GlobalTracer struct {
	logger *zap.Logger
}

func (t *GlobalTracer) Trace(message string) {
	t.logger.Debug(message)
}

func (t *GlobalTracer) Error(message string, err error) {
	t.logger.Error(message, zap.Error(err))
}

// GlobalTransitionListener handles state transitions
type GlobalTransitionListener struct {
	engine *GlobalConsensusEngine
	logger *zap.Logger
}

func (l *GlobalTransitionListener) OnTransition(
	from consensus.State,
	to consensus.State,
	event consensus.Event,
) {
	// Update metrics based on state
	switch to {
	case consensus.StateLoading:
		engineState.Set(2) // EngineStateLoading
	case consensus.StateCollecting:
		engineState.Set(3) // EngineStateCollecting
	case consensus.StateProving:
		engineState.Set(4) // EngineStateProving
	case consensus.StatePublishing:
		engineState.Set(5) // EngineStatePublishing
	case consensus.StateVerifying:
		engineState.Set(6) // EngineStateVerifying
	}
}
