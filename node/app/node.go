package app

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/master"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/rpc"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/utils"
)

type NodeMode string

const (
	NormalNodeMode     = NodeMode("normal")
	StrictSyncNodeMode = NodeMode("strict-sync")
)

type Node struct {
	mode           NodeMode
	logger         *zap.Logger
	dataProofStore store.DataProofStore
	clockStore     store.ClockStore
	coinStore      store.CoinStore
	keyManager     keys.KeyManager
	pubSub         p2p.PubSub
	execEngines    map[string]execution.ExecutionEngine
	engine         consensus.ConsensusEngine
	pebble         store.KVDB
	synchronizer   rpc.Synchronizer
}

type DHTNode struct {
	pubSub p2p.PubSub
	quit   chan struct{}
}

func newDHTNode(
	pubSub p2p.PubSub,
) (*DHTNode, error) {
	return &DHTNode{
		pubSub: pubSub,
		quit:   make(chan struct{}),
	}, nil
}

func newStrictSyncNode(
	logger *zap.Logger,
	dataProofStore store.DataProofStore,
	clockStore store.ClockStore,
	coinStore store.CoinStore,
	keyManager keys.KeyManager,
	pebble store.KVDB,
	synchronizer rpc.Synchronizer,
) (*Node, error) {
	return &Node{
		mode:           StrictSyncNodeMode,
		logger:         logger,
		dataProofStore: dataProofStore,
		clockStore:     clockStore,
		coinStore:      coinStore,
		keyManager:     keyManager,
		pebble:         pebble,
		synchronizer:   synchronizer,
	}, nil
}

func newNode(
	logger *zap.Logger,
	dataProofStore store.DataProofStore,
	clockStore store.ClockStore,
	coinStore store.CoinStore,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
	tokenExecutionEngine *token.TokenExecutionEngine,
	engine consensus.ConsensusEngine,
	pebble store.KVDB,
) (*Node, error) {
	if engine == nil {
		return nil, errors.New("engine must not be nil")
	}

	execEngines := make(map[string]execution.ExecutionEngine)
	if tokenExecutionEngine != nil {
		execEngines[tokenExecutionEngine.GetName()] = tokenExecutionEngine
	}

	return &Node{
		mode:           NormalNodeMode,
		logger:         logger,
		dataProofStore: dataProofStore,
		clockStore:     clockStore,
		coinStore:      coinStore,
		keyManager:     keyManager,
		pubSub:         pubSub,
		execEngines:    execEngines,
		engine:         engine,
		pebble:         pebble,
		synchronizer:   nil,
	}, nil
}

func GetOutputs(output []byte) (
	index uint32,
	indexProof []byte,
	kzgCommitment []byte,
	kzgProof []byte,
) {
	index = binary.BigEndian.Uint32(output[:4])
	indexProof = output[4:520]
	kzgCommitment = output[520:594]
	kzgProof = output[594:668]
	return index, indexProof, kzgCommitment, kzgProof
}

func nearestApplicablePowerOfTwo(number uint64) uint64 {
	power := uint64(128)
	if number > 2048 {
		power = 65536
	} else if number > 1024 {
		power = 2048
	} else if number > 128 {
		power = 1024
	}
	return power
}

func (n *Node) VerifyProofIntegrity() {
	logger := utils.GetLogger().With(zap.String("stage", "verify-proof-integrity"))
	i, _, _, e := n.dataProofStore.GetLatestDataTimeProof(n.pubSub.GetPeerID())
	if e != nil {
		logger.Panic("failed to get latest data time proof", zap.Error(e))
	}

	dataProver := crypto.NewKZGInclusionProver(n.logger)
	wesoProver := crypto.NewWesolowskiFrameProver(n.logger)

	for j := int(i); j >= 0; j-- {
		loggerWithIncrement := logger.With(zap.Int("increment", j))
		loggerWithIncrement.Info("verifying proof")
		_, parallelism, input, o, err := n.dataProofStore.GetDataTimeProof(n.pubSub.GetPeerID(), uint32(j))
		if err != nil {
			loggerWithIncrement.Panic("failed to get data time proof", zap.Error(err))
		}
		idx, idxProof, idxCommit, idxKP := GetOutputs(o)

		ip := sha3.Sum512(idxProof)

		v, err := dataProver.VerifyRaw(
			ip[:],
			idxCommit,
			int(idx),
			idxKP,
			nearestApplicablePowerOfTwo(uint64(parallelism)),
		)
		if err != nil {
			loggerWithIncrement.Panic("failed to verify kzg proof", zap.Error(err))
		}

		if !v {
			loggerWithIncrement.Panic("bad kzg proof")
		}
		wp := []byte{}
		wp = append(wp, n.pubSub.GetPeerID()...)
		wp = append(wp, input...)
		loggerWithIncrement.Info("build weso proof", zap.String("wp", fmt.Sprintf("%x", wp)))
		v = wesoProver.VerifyPreDuskChallengeProof(wp, uint32(j), idx, idxProof)
		if !v {
			loggerWithIncrement.Panic("bad weso proof")
		}
	}
}

func (d *DHTNode) Start() {
	<-d.quit
}

func (d *DHTNode) Stop() {
	go func() {
		d.quit <- struct{}{}
	}()
}

func (n *Node) Start() {
	logger := utils.GetLogger()
	switch n.mode {
	case NormalNodeMode:
		err := <-n.engine.Start()
		if err != nil {
			logger.Panic("failed to start engine", zap.Error(err))
		}

		// TODO: add config mapping to engine name/frame registration
		wg := sync.WaitGroup{}
		for _, e := range n.execEngines {
			wg.Add(1)
			go func(e execution.ExecutionEngine) {
				defer wg.Done()
				if err := <-n.engine.RegisterExecutor(e, 0); err != nil {
					logger.Panic("failed to register executor", zap.Error(err))
				}
			}(e)
		}
		wg.Wait()
	case StrictSyncNodeMode:
		go n.synchronizer.Start(n.logger, n.pebble)
	}
}

func (n *Node) Stop() {
	logger := utils.GetLogger()
	switch n.mode {
	case NormalNodeMode:
		err := <-n.engine.Stop(false)
		if err != nil {
			logger.Panic("failed to stop engine", zap.Error(err))
		}
	case StrictSyncNodeMode:
		n.synchronizer.Stop()
	}

	n.pebble.Close()
}

func (n *Node) GetLogger() *zap.Logger {
	return n.logger
}

func (n *Node) GetClockStore() store.ClockStore {
	return n.clockStore
}

func (n *Node) GetCoinStore() store.CoinStore {
	return n.coinStore
}

func (n *Node) GetDataProofStore() store.DataProofStore {
	return n.dataProofStore
}

func (n *Node) GetKeyManager() keys.KeyManager {
	return n.keyManager
}

func (n *Node) GetPubSub() p2p.PubSub {
	return n.pubSub
}

func (n *Node) GetMasterClock() *master.MasterClockConsensusEngine {
	return n.engine.(*master.MasterClockConsensusEngine)
}

func (n *Node) GetExecutionEngines() []execution.ExecutionEngine {
	list := []execution.ExecutionEngine{}
	for _, e := range n.execEngines {
		list = append(list, e)
	}
	return list
}
