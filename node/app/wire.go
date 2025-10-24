//go:build wireinject
// +build wireinject

package app

import (
	"github.com/google/wire"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	"source.quilibrium.com/quilibrium/monorepo/channel"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/compiler"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/app"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/difficulty"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/fees"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/global"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/provers"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/registration"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/reward"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/validator"
	"source.quilibrium.com/quilibrium/monorepo/node/datarpc"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/rpc"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	tchannel "source.quilibrium.com/quilibrium/monorepo/types/channel"
	tcompiler "source.quilibrium.com/quilibrium/monorepo/types/compiler"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	thypergraph "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	tkeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
	tp2p "source.quilibrium.com/quilibrium/monorepo/types/p2p"
	tstore "source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/vdf"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

func provideBLSConstructor() *bls48581.Bls48581KeyConstructor {
	return &bls48581.Bls48581KeyConstructor{}
}

func provideDecafConstructor() *bulletproofs.Decaf448KeyConstructor {
	return &bulletproofs.Decaf448KeyConstructor{}
}

var keyManagerSet = wire.NewSet(
	wire.FieldsOf(new(*config.Config), "Key"),
	provideBLSConstructor,
	wire.Bind(new(crypto.BlsConstructor), new(*bls48581.Bls48581KeyConstructor)),
	provideDecafConstructor,
	wire.Bind(
		new(crypto.DecafConstructor),
		new(*bulletproofs.Decaf448KeyConstructor),
	),
	keys.NewFileKeyManager,
	wire.Bind(new(tkeys.KeyManager), new(*keys.FileKeyManager)),
)

func newVerifiableEncryptor() *verenc.MPCitHVerifiableEncryptor {
	return verenc.NewMPCitHVerifiableEncryptor(1)
}

var compilerSet = wire.NewSet(
	compiler.NewBedlamCompiler,
	wire.Bind(new(tcompiler.CircuitCompiler), new(*compiler.BedlamCompiler)),
)

var verencSet = wire.NewSet(
	newVerifiableEncryptor,
	wire.Bind(
		new(crypto.VerifiableEncryptor),
		new(*verenc.MPCitHVerifiableEncryptor),
	),
)

var storeSet = wire.NewSet(
	wire.FieldsOf(new(*config.Config), "DB"),
	store.NewPebbleDB,
	wire.Bind(new(tstore.KVDB), new(*store.PebbleDB)),
	store.NewPebbleClockStore,
	store.NewPebbleTokenStore,
	store.NewPebbleDataProofStore,
	store.NewPebbleHypergraphStore,
	store.NewPebbleInboxStore,
	store.NewPebbleKeyStore,
	store.NewPeerstoreDatastore,
	store.NewPebbleShardsStore,
	store.NewPebbleWorkerStore,
	wire.Bind(new(tstore.ClockStore), new(*store.PebbleClockStore)),
	wire.Bind(new(tstore.TokenStore), new(*store.PebbleTokenStore)),
	wire.Bind(new(tstore.DataProofStore), new(*store.PebbleDataProofStore)),
	wire.Bind(new(tstore.HypergraphStore), new(*store.PebbleHypergraphStore)),
	wire.Bind(new(tstore.InboxStore), new(*store.PebbleInboxStore)),
	wire.Bind(new(tstore.KeyStore), new(*store.PebbleKeyStore)),
	wire.Bind(new(tries.TreeBackingStore), new(*store.PebbleHypergraphStore)),
	wire.Bind(new(tstore.ShardsStore), new(*store.PebbleShardsStore)),
	wire.Bind(new(tstore.WorkerStore), new(*store.PebbleWorkerStore)),
)

var pubSubSet = wire.NewSet(
	wire.FieldsOf(new(*config.Config), "P2P"),
	wire.FieldsOf(new(*config.Config), "Engine"),
	p2p.NewInMemoryPeerInfoManager,
	p2p.NewBlossomSub,
	channel.NewDoubleRatchetEncryptedChannel,
	wire.Bind(new(tp2p.PubSub), new(*p2p.BlossomSub)),
	wire.Bind(new(tp2p.PeerInfoManager), new(*p2p.InMemoryPeerInfoManager)),
	wire.Bind(
		new(tchannel.EncryptedChannel),
		new(*channel.DoubleRatchetEncryptedChannel),
	),
)

var proxyPubSubSet = wire.NewSet(
	wire.FieldsOf(new(*config.Config), "P2P"),
	wire.FieldsOf(new(*config.Config), "Engine"),
	p2p.NewInMemoryPeerInfoManager,
	rpc.NewProxyBlossomSub,
	channel.NewDoubleRatchetEncryptedChannel,
	wire.Bind(new(tp2p.PubSub), new(*rpc.ProxyBlossomSub)),
	wire.Bind(new(tp2p.PeerInfoManager), new(*p2p.InMemoryPeerInfoManager)),
	wire.Bind(
		new(tchannel.EncryptedChannel),
		new(*channel.DoubleRatchetEncryptedChannel),
	),
)

var engineSet = wire.NewSet(
	vdf.NewCachedWesolowskiFrameProver,
	bls48581.NewKZGInclusionProver,
	wire.Bind(new(crypto.InclusionProver), new(*bls48581.KZGInclusionProver)),
	bulletproofs.NewBulletproofProver,
	wire.Bind(
		new(crypto.BulletproofProver),
		new(*bulletproofs.Decaf448BulletproofProver),
	),
)

func provideHypergraph(
	store *store.PebbleHypergraphStore,
) (thypergraph.Hypergraph, error) {
	return store.LoadHypergraph(&tests.Nopthenticator{})
}

var hypergraphSet = wire.NewSet(
	provideHypergraph,
)

var validatorSet = wire.NewSet(
	registration.NewCachedSignerRegistry,
	wire.Bind(
		new(consensus.SignerRegistry),
		new(*registration.CachedSignerRegistry),
	),
	provers.NewProverRegistry,
	fees.NewDynamicFeeManager,
	validator.NewBLSGlobalFrameValidator,
	wire.Bind(
		new(consensus.GlobalFrameValidator),
		new(*validator.BLSGlobalFrameValidator),
	),
	validator.NewBLSAppFrameValidator,
	wire.Bind(
		new(consensus.AppFrameValidator),
		new(*validator.BLSAppFrameValidator),
	),
	provideDifficultyAnchorFrameNumber,
	provideDifficultyAnchorParentTime,
	provideDifficultyAnchorDifficulty,
	difficulty.NewAsertDifficultyAdjuster,
	wire.Bind(
		new(consensus.DifficultyAdjuster),
		new(*difficulty.AsertDifficultyAdjuster),
	),
	reward.NewOptRewardIssuance,
	wire.Bind(
		new(consensus.RewardIssuance),
		new(*reward.OptimizedProofOfMeaningfulWorkRewardIssuance),
	),
)

var globalConsensusSet = wire.NewSet(
	global.NewConsensusEngineFactory,
)

var appConsensusSet = wire.NewSet(
	app.NewAppConsensusEngineFactory,
)

func NewDHTNode(*zap.Logger, *config.Config, uint) (*DHTNode, error) {
	panic(wire.Build(
		pubSubSet,
		newDHTNode,
	))
}

func NewDBConsole(*config.Config) (*DBConsole, error) {
	panic(wire.Build(newDBConsole))
}

func NewClockStore(
	*zap.Logger,
	*config.Config,
	uint,
) (tstore.ClockStore, error) {
	panic(wire.Build(storeSet))
}

func NewDataWorkerNodeWithProxyPubsub(
	logger *zap.Logger,
	config *config.Config,
	coreId uint,
	rpcMultiaddr string,
	parentProcess int,
) (*DataWorkerNode, error) {
	panic(wire.Build(
		verencSet,
		compilerSet,
		keyManagerSet,
		storeSet,
		proxyPubSubSet,
		engineSet,
		hypergraphSet,
		validatorSet,
		appConsensusSet,
		provideGlobalTimeReel,
		provideDataWorkerIPC,
		newDataWorkerNode,
	))
}

func NewDataWorkerNodeWithoutProxyPubsub(
	logger *zap.Logger,
	config *config.Config,
	coreId uint,
	rpcMultiaddr string,
	parentProcess int,
) (*DataWorkerNode, error) {
	panic(wire.Build(
		verencSet,
		compilerSet,
		keyManagerSet,
		storeSet,
		pubSubSet,
		engineSet,
		hypergraphSet,
		validatorSet,
		appConsensusSet,
		provideGlobalTimeReel,
		provideDataWorkerIPC,
		newDataWorkerNode,
	))
}

func NewDataWorkerNode(
	logger *zap.Logger,
	config *config.Config,
	coreId uint,
	rpcMultiaddr string,
	parentProcess int,
) (*DataWorkerNode, error) {
	if config.Engine.EnableMasterProxy {
		return NewDataWorkerNodeWithProxyPubsub(
			logger,
			config,
			coreId,
			rpcMultiaddr,
			parentProcess,
		)
	} else {
		return NewDataWorkerNodeWithoutProxyPubsub(
			logger,
			config,
			coreId,
			rpcMultiaddr,
			parentProcess,
		)
	}
}

func provideDataWorkerIPC(
	rpcMultiaddr string,
	config *config.Config,
	signerRegistry consensus.SignerRegistry,
	proverRegistry consensus.ProverRegistry,
	appConsensusEngineFactory *app.AppConsensusEngineFactory,
	peerInfoManager tp2p.PeerInfoManager,
	frameProver crypto.FrameProver,
	logger *zap.Logger,
	coreId uint,
	parentProcess int,
) *datarpc.DataWorkerIPCServer {
	svr, err := datarpc.NewDataWorkerIPCServer(
		rpcMultiaddr,
		config,
		signerRegistry,
		proverRegistry,
		peerInfoManager,
		frameProver,
		appConsensusEngineFactory,
		logger,
		uint32(coreId),
		parentProcess,
	)
	if err != nil {
		panic(err)
	}
	return svr
}

// GlobalConsensusComponents holds both the engine and time reel
type GlobalConsensusComponents struct {
	Engine   *global.GlobalConsensusEngine
	TimeReel *consensustime.GlobalTimeReel
}

func provideGlobalConsensusComponents(
	factory *global.ConsensusEngineFactory,
	config *config.Config,
) (*GlobalConsensusComponents, error) {
	engine, timeReel, err := factory.CreateGlobalConsensusEngine(10000)
	if err != nil {
		return nil, err
	}
	return &GlobalConsensusComponents{
		Engine:   engine,
		TimeReel: timeReel,
	}, nil
}

func provideGlobalConsensusEngine(
	components *GlobalConsensusComponents,
) *global.GlobalConsensusEngine {
	return components.Engine
}

func provideGlobalTimeReelFromComponents(
	components *GlobalConsensusComponents,
) *consensustime.GlobalTimeReel {
	return components.TimeReel
}

// Provider functions for difficulty adjuster parameters
func provideDifficultyAnchorFrameNumber(config *config.Config) uint64 {
	if config.P2P.Network == 0 {
		return 244200 // Genesis frame
	} else {
		return 0
	}
}

func provideDifficultyAnchorParentTime() int64 {
	return 1761217200000
}

func provideDifficultyAnchorDifficulty() uint32 {
	return 160000 // Initial difficulty
}

func provideGlobalTimeReel(
	factory *app.AppConsensusEngineFactory,
) (*consensustime.GlobalTimeReel, error) {
	return factory.CreateGlobalTimeReel()
}

func NewMasterNode(
	logger *zap.Logger,
	config *config.Config,
	coreId uint,
) (*MasterNode, error) {
	panic(wire.Build(
		verencSet,
		compilerSet,
		keyManagerSet,
		storeSet,
		pubSubSet,
		engineSet,
		hypergraphSet,
		validatorSet,
		globalConsensusSet,
		provideGlobalConsensusComponents,
		provideGlobalConsensusEngine,
		provideGlobalTimeReelFromComponents,
		newMasterNode,
	))
}
