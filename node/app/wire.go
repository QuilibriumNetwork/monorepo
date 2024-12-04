//go:build wireinject
// +build wireinject

package app

import (
	"github.com/google/wire"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/master"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

func logger() *zap.Logger {
	log, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}

	return log
}

func debugLogger() *zap.Logger {
	log, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}

	return log
}

var loggerSet = wire.NewSet(
	logger,
)

var debugLoggerSet = wire.NewSet(
	debugLogger,
)

var keyManagerSet = wire.NewSet(
	wire.FieldsOf(new(*config.Config), "Key"),
	keys.NewFileKeyManager,
	wire.Bind(new(keys.KeyManager), new(*keys.FileKeyManager)),
)

var storeSet = wire.NewSet(
	wire.FieldsOf(new(*config.Config), "DB"),
	store.NewPebbleDB,
	wire.Bind(new(store.KVDB), new(*store.PebbleDB)),
	store.NewPebbleClockStore,
	store.NewPebbleCoinStore,
	store.NewPebbleKeyStore,
	store.NewPebbleDataProofStore,
	store.NewPeerstoreDatastore,
	wire.Bind(new(store.ClockStore), new(*store.PebbleClockStore)),
	wire.Bind(new(store.CoinStore), new(*store.PebbleCoinStore)),
	wire.Bind(new(store.KeyStore), new(*store.PebbleKeyStore)),
	wire.Bind(new(store.DataProofStore), new(*store.PebbleDataProofStore)),
	wire.Bind(new(store.Peerstore), new(*store.PeerstoreDatastore)),
)

var pubSubSet = wire.NewSet(
	wire.FieldsOf(new(*config.Config), "P2P"),
	p2p.NewInMemoryPeerInfoManager,
	p2p.NewBlossomSub,
	wire.Bind(new(p2p.PubSub), new(*p2p.BlossomSub)),
	wire.Bind(new(p2p.PeerInfoManager), new(*p2p.InMemoryPeerInfoManager)),
)

var engineSet = wire.NewSet(
	wire.FieldsOf(new(*config.Config), "Engine"),
	crypto.NewCachedWesolowskiFrameProver,
	crypto.NewKZGInclusionProver,
	wire.Bind(new(crypto.InclusionProver), new(*crypto.KZGInclusionProver)),
	time.NewMasterTimeReel,
	token.NewTokenExecutionEngine,
)

var consensusSet = wire.NewSet(
	master.NewMasterClockConsensusEngine,
	wire.Bind(
		new(consensus.ConsensusEngine),
		new(*master.MasterClockConsensusEngine),
	),
)

func NewDHTNode(*config.Config) (*DHTNode, error) {
	panic(wire.Build(
		debugLoggerSet,
		pubSubSet,
		newDHTNode,
	))
}

func NewDebugNode(*config.Config, *protobufs.SelfTestReport) (*Node, error) {
	panic(wire.Build(
		debugLoggerSet,
		keyManagerSet,
		storeSet,
		pubSubSet,
		engineSet,
		consensusSet,
		newNode,
	))
}

func NewNode(*config.Config, *protobufs.SelfTestReport) (*Node, error) {
	panic(wire.Build(
		loggerSet,
		keyManagerSet,
		storeSet,
		pubSubSet,
		engineSet,
		consensusSet,
		newNode,
	))
}

func NewDBConsole(*config.Config) (*DBConsole, error) {
	panic(wire.Build(newDBConsole))
}

func NewClockStore(*config.Config) (store.ClockStore, error) {
	panic(wire.Build(loggerSet, storeSet))
}
