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

func provideBaseDB(dbConfig *config.DBConfig) *store.MDBXDB {
	return store.NewMDBXDB(dbConfig)
}

func providePebbleClockStore(db *store.MDBXDB, logger *zap.Logger) *store.PebbleClockStore {
	return store.NewPebbleClockStore(db.OpenDB("clock_store"), logger)
}

func providePebbleCoinStore(db *store.MDBXDB, logger *zap.Logger) *store.PebbleCoinStore {
	return store.NewPebbleCoinStore(db.OpenDB("coin_store"), logger)
}

func providePebbleKeyStore(db *store.MDBXDB, logger *zap.Logger) *store.PebbleKeyStore {
	return store.NewPebbleKeyStore(db.OpenDB("key_store"), logger)
}

func providePebbleDataProofStore(db *store.MDBXDB, logger *zap.Logger) *store.PebbleDataProofStore {
	return store.NewPebbleDataProofStore(db.OpenDB("data_proof_store"), logger)
}

func providePebbleHypergraphStore(db *store.MDBXDB, logger *zap.Logger) *store.PebbleHypergraphStore {
	return store.NewPebbleHypergraphStore(db.OpenDB("hypergraph_store"), logger)
}

func providePeerstoreDatastore(db *store.MDBXDB, logger *zap.Logger) *store.PeerstoreDatastore {
	return store.NewPeerstoreDatastore(db.OpenDB("peerstore"))
}

var storeSet = wire.NewSet(
	wire.FieldsOf(new(*config.Config), "DB"),
	provideBaseDB,
	wire.Bind(new(store.KVDB), new(*store.MDBXDB)),
	providePebbleClockStore,
	providePebbleCoinStore,
	providePebbleKeyStore,
	providePebbleDataProofStore,
	providePebbleHypergraphStore,
	providePeerstoreDatastore,
	wire.Bind(new(store.ClockStore), new(*store.PebbleClockStore)),
	wire.Bind(new(store.CoinStore), new(*store.PebbleCoinStore)),
	wire.Bind(new(store.KeyStore), new(*store.PebbleKeyStore)),
	wire.Bind(new(store.DataProofStore), new(*store.PebbleDataProofStore)),
	wire.Bind(new(store.HypergraphStore), new(*store.PebbleHypergraphStore)),
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
