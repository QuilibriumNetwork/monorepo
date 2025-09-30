package app

import (
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
)

type AppTracer struct {
	logger *zap.Logger
}

func (t *AppTracer) Trace(message string) {}

func (t *AppTracer) Error(message string, err error) {
	t.logger.Error(message, zap.Error(err))
}

// AppTransitionListener handles state transitions
type AppTransitionListener struct {
	engine *AppConsensusEngine
	logger *zap.Logger
}

func (l *AppTransitionListener) OnTransition(
	from consensus.State,
	to consensus.State,
	event consensus.Event,
) {
	var stateValue float64
	switch to {
	case consensus.StateStopped:
		stateValue = 0
	case consensus.StateStarting:
		stateValue = 1
	case consensus.StateLoading:
		stateValue = 2
	case consensus.StateCollecting:
		stateValue = 3
	case consensus.StateProving:
		stateValue = 4
	case consensus.StatePublishing:
		stateValue = 5
	case consensus.StateVerifying:
		stateValue = 6
	case consensus.StateStopping:
		stateValue = 7
	}

	engineState.WithLabelValues(l.engine.appAddressHex).Set(stateValue)
}
