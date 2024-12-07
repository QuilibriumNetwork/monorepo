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
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

type Node struct {
	logger         *zap.Logger
	dataProofStore store.DataProofStore
	clockStore     store.ClockStore
	coinStore      store.CoinStore
	keyManager     keys.KeyManager
	pubSub         p2p.PubSub
	execEngines    map[string]execution.ExecutionEngine
	engine         consensus.ConsensusEngine
	pebble         store.KVDB
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
		logger,
		dataProofStore,
		clockStore,
		coinStore,
		keyManager,
		pubSub,
		execEngines,
		engine,
		pebble,
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
	i, _, _, e := n.dataProofStore.GetLatestDataTimeProof(n.pubSub.GetPeerID())
	if e != nil {
		panic(e)
	}

	dataProver := crypto.NewKZGInclusionProver(n.logger)
	wesoProver := crypto.NewWesolowskiFrameProver(n.logger)

	for j := int(i); j >= 0; j-- {
		fmt.Println(j)
		_, parallelism, input, o, err := n.dataProofStore.GetDataTimeProof(n.pubSub.GetPeerID(), uint32(j))
		if err != nil {
			panic(err)
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
			panic(err)
		}

		if !v {
			panic(fmt.Sprintf("bad kzg proof at increment %d", j))
		}
		wp := []byte{}
		wp = append(wp, n.pubSub.GetPeerID()...)
		wp = append(wp, input...)
		fmt.Printf("%x\n", wp)
		v = wesoProver.VerifyPreDuskChallengeProof(wp, uint32(j), idx, idxProof)
		if !v {
			panic(fmt.Sprintf("bad weso proof at increment %d", j))
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
	err := <-n.engine.Start()
	if err != nil {
		panic(err)
	}

	// TODO: add config mapping to engine name/frame registration
	wg := sync.WaitGroup{}
	for _, e := range n.execEngines {
		wg.Add(1)
		go func(e execution.ExecutionEngine) {
			defer wg.Done()
			if err := <-n.engine.RegisterExecutor(e, 0); err != nil {
				panic(err)
			}
		}(e)
	}
	wg.Wait()
}

func (n *Node) Stop() {
	err := <-n.engine.Stop(false)
	if err != nil {
		panic(err)
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
