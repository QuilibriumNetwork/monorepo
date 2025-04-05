package master

import (
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
)

func (e *MasterClockConsensusEngine) RegisterExecutor(
	exec execution.ExecutionEngine,
	frame uint64,
) <-chan error {
	logger := e.logger.With(zap.String("execution_engine_name", exec.GetName()))
	logger.Info("registering execution engine")
	errChan := make(chan error)

	go func() {
		masterFrame, err := e.masterTimeReel.Head()
		if err != nil {
			logger.Panic("could not get master time reel head", zap.Error(err))
		}

		logger.Info(
			"starting execution engine at frame",
			zap.Uint64("current_frame", masterFrame.FrameNumber),
		)
		err = <-exec.Start()
		if err != nil {
			logger.Error("could not start execution engine", zap.Error(err))
			errChan <- err
			return
		}

		for {
			masterFrame, err = e.masterTimeReel.Head()
			if err != nil {
				logger.Panic("could not get master time reel head", zap.Error(err))
			}

			logger.Info(
				"awaiting frame",
				zap.Uint64("current_frame", masterFrame.FrameNumber),
				zap.Uint64("target_frame", frame),
			)

			newFrame := masterFrame.FrameNumber
			if newFrame >= frame {
				logger.Info(
					"injecting execution engine at frame",
					zap.Uint64("current_frame", newFrame),
				)

				e.engineMx.Lock()
				e.executionEngines[exec.GetName()] = exec
				e.engineMx.Unlock()

				errChan <- nil
				break
			}
		}
	}()

	return errChan
}

func (e *MasterClockConsensusEngine) UnregisterExecutor(
	name string,
	frame uint64,
	force bool,
) <-chan error {
	logger := e.logger.With(zap.String("execution_engine_name", name))
	logger.Info("unregistering execution engine")
	errChan := make(chan error)

	exec, ok := e.executionEngines[name]
	if !ok {
		logger.Error(
			"could not unregister execution engine",
			zap.Error(errors.New("execution engine not registered")),
		)
		errChan <- errors.New("execution engine not registered")
		return errChan
	}

	go func() {
		for {
			masterFrame, err := e.masterTimeReel.Head()
			if err != nil {
				logger.Panic("could not get master time reel head", zap.Error(err))
			}

			logger.Info(
				"awaiting frame",
				zap.Uint64("current_frame", masterFrame.FrameNumber),
				zap.Uint64("target_frame", frame),
			)

			newFrame := masterFrame.FrameNumber
			if newFrame >= frame {
				logger.Info(
					"removing execution engine at frame",
					zap.Uint64("current_frame", newFrame),
				)
				e.engineMx.Lock()
				delete(e.executionEngines, name)
				e.engineMx.Unlock()

				logger.Info(
					"stopping execution engine at frame",
					zap.Uint64("current_frame", newFrame),
				)
				err := <-exec.Stop(force)
				if err != nil {
					logger.Error("could not stop execution engine", zap.Error(err))
				}

				errChan <- err
				break
			}
		}
	}()

	return errChan
}
