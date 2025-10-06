package app

import (
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/global"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/manager"
	"source.quilibrium.com/quilibrium/monorepo/node/rpc"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/worker"
)

type DHTNode struct {
	pubSub p2p.PubSub
	quit   chan struct{}
}

type MasterNode struct {
	logger          *zap.Logger
	dataProofStore  store.DataProofStore
	clockStore      store.ClockStore
	coinStore       store.TokenStore
	keyManager      keys.KeyManager
	pubSub          p2p.PubSub
	globalConsensus *global.GlobalConsensusEngine
	globalTimeReel  *consensustime.GlobalTimeReel
	pebble          store.KVDB
	coreId          uint
	quit            chan struct{}
}

func newDHTNode(
	pubSub p2p.PubSub,
) (*DHTNode, error) {
	return &DHTNode{
		pubSub: pubSub,
		quit:   make(chan struct{}),
	}, nil
}

func newMasterNode(
	logger *zap.Logger,
	dataProofStore store.DataProofStore,
	clockStore store.ClockStore,
	coinStore store.TokenStore,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
	globalConsensus *global.GlobalConsensusEngine,
	globalTimeReel *consensustime.GlobalTimeReel,
	pebble store.KVDB,
	coreId uint,
) (*MasterNode, error) {
	logger = logger.With(zap.String("process", "master"))
	return &MasterNode{
		logger:          logger,
		dataProofStore:  dataProofStore,
		clockStore:      clockStore,
		coinStore:       coinStore,
		keyManager:      keyManager,
		pubSub:          pubSub,
		globalConsensus: globalConsensus,
		globalTimeReel:  globalTimeReel,
		pebble:          pebble,
		coreId:          coreId,
		quit:            make(chan struct{}),
	}, nil
}

func (d *DHTNode) Start() {
	<-d.quit
}

func (d *DHTNode) Stop() {
	go func() {
		d.quit <- struct{}{}
	}()
}

func (m *MasterNode) Start(quitCh chan struct{}) error {
	// Start the global consensus engine
	m.quit = quitCh
	errChan := m.globalConsensus.Start(quitCh)
	select {
	case err := <-errChan:
		if err != nil {
			return err
		}
	}

	m.logger.Info("master node started", zap.Uint("core_id", m.coreId))

	// Wait for shutdown signal
	<-m.quit
	return nil
}

func (m *MasterNode) Stop() {
	m.logger.Info("stopping master node")

	// Stop the global consensus engine
	if err := <-m.globalConsensus.Stop(false); err != nil {
		m.logger.Error("error stopping global consensus", zap.Error(err))
	}

	defer func() {
		// Close database
		if m.pebble != nil {
			err := m.pebble.Close()
			if err != nil {
				m.logger.Error("database shut down with errors", zap.Error(err))
			} else {
				m.logger.Info("database stopped cleanly")
			}
		}
	}()
}

func (m *MasterNode) GetLogger() *zap.Logger {
	return m.logger
}

func (m *MasterNode) GetClockStore() store.ClockStore {
	return m.clockStore
}

func (m *MasterNode) GetCoinStore() store.TokenStore {
	return m.coinStore
}

func (m *MasterNode) GetDataProofStore() store.DataProofStore {
	return m.dataProofStore
}

func (m *MasterNode) GetKeyManager() keys.KeyManager {
	return m.keyManager
}

func (m *MasterNode) GetPubSub() p2p.PubSub {
	return m.pubSub
}

func (m *MasterNode) GetGlobalConsensusEngine() *global.GlobalConsensusEngine {
	return m.globalConsensus
}

func (m *MasterNode) GetGlobalTimeReel() *consensustime.GlobalTimeReel {
	return m.globalTimeReel
}

func (m *MasterNode) GetCoreId() uint {
	return m.coreId
}

func (m *MasterNode) GetPeerInfoProvider() rpc.PeerInfoProvider {
	return m.globalConsensus
}

func (m *MasterNode) GetWorkerManager() worker.WorkerManager {
	return m.globalConsensus.GetWorkerManager()
}

func (m *MasterNode) GetProverRegistry() consensus.ProverRegistry {
	return m.globalConsensus.GetProverRegistry()
}

func (
	m *MasterNode,
) GetExecutionEngineManager() *manager.ExecutionEngineManager {
	return m.globalConsensus.GetExecutionEngineManager()
}
