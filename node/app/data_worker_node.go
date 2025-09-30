package app

import (
	"fmt"

	"go.uber.org/zap"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/node/datarpc"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

type DataWorkerNode struct {
	logger         *zap.Logger
	dataProofStore store.DataProofStore
	clockStore     store.ClockStore
	coinStore      store.TokenStore
	keyManager     keys.KeyManager
	pebble         store.KVDB
	coreId         uint
	ipcServer      *datarpc.DataWorkerIPCServer
	frameProver    crypto.FrameProver
	globalTimeReel *consensustime.GlobalTimeReel
	parentProcess  int
	quit           chan struct{}
}

func newDataWorkerNode(
	logger *zap.Logger,
	dataProofStore store.DataProofStore,
	clockStore store.ClockStore,
	coinStore store.TokenStore,
	keyManager keys.KeyManager,
	pebble store.KVDB,
	frameProver crypto.FrameProver,
	ipcServer *datarpc.DataWorkerIPCServer,
	globalTimeReel *consensustime.GlobalTimeReel,
	coreId uint,
	parentProcess int,
) (*DataWorkerNode, error) {
	logger = logger.With(zap.String("process", fmt.Sprintf("worker %d", coreId)))
	return &DataWorkerNode{
		logger:         logger,
		dataProofStore: dataProofStore,
		clockStore:     clockStore,
		coinStore:      coinStore,
		keyManager:     keyManager,
		pebble:         pebble,
		coreId:         coreId,
		ipcServer:      ipcServer,
		frameProver:    frameProver,
		globalTimeReel: globalTimeReel,
		parentProcess:  parentProcess,
		quit:           make(chan struct{}),
	}, nil
}

func (n *DataWorkerNode) Start() error {
	go func() {
		err := n.ipcServer.Start()
		if err != nil {
			n.logger.Error(
				"error while starting ipc server for core",
				zap.Uint64("core", uint64(n.coreId)),
			)
			n.quit <- struct{}{}
		}
	}()

	n.logger.Info("data worker node started", zap.Uint("core_id", n.coreId))

	defer func() {
		err := n.pebble.Close()
		if err != nil {
			n.logger.Error(
				"database shut down with errors",
				zap.Error(err),
				zap.Uint("core_id", n.coreId),
			)
		} else {
			n.logger.Info(
				"database stopped cleanly",
				zap.Uint("core_id", n.coreId),
			)
		}
	}()

	<-n.quit

	return nil
}

func (n *DataWorkerNode) Stop() {
	n.logger.Info("stopping data worker node")

	// Signal quit
	if n.quit != nil {
		close(n.quit)
	}
}

// GetQuitChannel returns the quit channel for external signaling
func (n *DataWorkerNode) GetQuitChannel() chan struct{} {
	return n.quit
}

func (n *DataWorkerNode) GetLogger() *zap.Logger {
	return n.logger
}

func (n *DataWorkerNode) GetClockStore() store.ClockStore {
	return n.clockStore
}

func (n *DataWorkerNode) GetCoinStore() store.TokenStore {
	return n.coinStore
}

func (n *DataWorkerNode) GetDataProofStore() store.DataProofStore {
	return n.dataProofStore
}

func (n *DataWorkerNode) GetKeyManager() keys.KeyManager {
	return n.keyManager
}

func (n *DataWorkerNode) GetGlobalTimeReel() *consensustime.GlobalTimeReel {
	return n.globalTimeReel
}

func (n *DataWorkerNode) GetCoreId() uint {
	return n.coreId
}

func (n *DataWorkerNode) GetFrameProver() crypto.FrameProver {
	return n.frameProver
}

func (n *DataWorkerNode) GetIPCServer() *datarpc.DataWorkerIPCServer {
	return n.ipcServer
}
