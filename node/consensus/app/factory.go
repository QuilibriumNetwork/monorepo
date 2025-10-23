package app

import (
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/events"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	qp2p "source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/compiler"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

// AppConsensusEngineFactory provides a factory method for creating properly
// wired AppConsensusEngine instances with time reels and event distributors.
type AppConsensusEngineFactory struct {
	logger               *zap.Logger
	config               *config.Config
	pubsub               p2p.PubSub
	hypergraph           hypergraph.Hypergraph
	keyManager           keys.KeyManager
	keyStore             store.KeyStore
	clockStore           store.ClockStore
	inboxStore           store.InboxStore
	shardsStore          store.ShardsStore
	hypergraphStore      store.HypergraphStore
	frameProver          crypto.FrameProver
	inclusionProver      crypto.InclusionProver
	bulletproofProver    crypto.BulletproofProver
	verEnc               crypto.VerifiableEncryptor
	decafConstructor     crypto.DecafConstructor
	compiler             compiler.CircuitCompiler
	signerRegistry       consensus.SignerRegistry
	proverRegistry       consensus.ProverRegistry
	peerInfoManager      qp2p.PeerInfoManager
	dynamicFeeManager    consensus.DynamicFeeManager
	frameValidator       consensus.AppFrameValidator
	globalFrameValidator consensus.GlobalFrameValidator
	difficultyAdjuster   consensus.DifficultyAdjuster
	rewardIssuance       consensus.RewardIssuance
	blsConstructor       crypto.BlsConstructor
	encryptedChannel     channel.EncryptedChannel
}

// NewAppConsensusEngineFactory creates a new factory for consensus engines.
func NewAppConsensusEngineFactory(
	logger *zap.Logger,
	config *config.Config,
	pubsub p2p.PubSub,
	hypergraph hypergraph.Hypergraph,
	keyManager keys.KeyManager,
	keyStore store.KeyStore,
	clockStore store.ClockStore,
	inboxStore store.InboxStore,
	shardsStore store.ShardsStore,
	hypergraphStore store.HypergraphStore,
	frameProver crypto.FrameProver,
	inclusionProver crypto.InclusionProver,
	bulletproofProver crypto.BulletproofProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	compiler compiler.CircuitCompiler,
	signerRegistry consensus.SignerRegistry,
	proverRegistry consensus.ProverRegistry,
	peerInfoManager qp2p.PeerInfoManager,
	dynamicFeeManager consensus.DynamicFeeManager,
	frameValidator consensus.AppFrameValidator,
	globalFrameValidator consensus.GlobalFrameValidator,
	difficultyAdjuster consensus.DifficultyAdjuster,
	rewardIssuance consensus.RewardIssuance,
	blsConstructor crypto.BlsConstructor,
	encryptedChannel channel.EncryptedChannel,
) *AppConsensusEngineFactory {
	return &AppConsensusEngineFactory{
		logger:               logger,
		config:               config,
		pubsub:               pubsub,
		hypergraph:           hypergraph,
		keyManager:           keyManager,
		keyStore:             keyStore,
		clockStore:           clockStore,
		inboxStore:           inboxStore,
		shardsStore:          shardsStore,
		hypergraphStore:      hypergraphStore,
		frameProver:          frameProver,
		inclusionProver:      inclusionProver,
		bulletproofProver:    bulletproofProver,
		verEnc:               verEnc,
		decafConstructor:     decafConstructor,
		compiler:             compiler,
		signerRegistry:       signerRegistry,
		proverRegistry:       proverRegistry,
		dynamicFeeManager:    dynamicFeeManager,
		frameValidator:       frameValidator,
		globalFrameValidator: globalFrameValidator,
		difficultyAdjuster:   difficultyAdjuster,
		rewardIssuance:       rewardIssuance,
		blsConstructor:       blsConstructor,
		encryptedChannel:     encryptedChannel,
	}
}

// CreateAppConsensusEngine creates a new AppConsensusEngine
func (f *AppConsensusEngineFactory) CreateAppConsensusEngine(
	appAddress []byte,
	coreId uint,
	globalTimeReel *time.GlobalTimeReel,
	grpcServer *grpc.Server,
) (*AppConsensusEngine, error) {
	// Create the app time reel for this shard
	appTimeReel, err := time.NewAppTimeReel(
		f.logger,
		appAddress,
		f.proverRegistry,
		f.clockStore,
		f.config.Engine.ArchiveMode,
	)
	if err != nil {
		return nil, errors.Wrap(err, "create app time reel")
	}

	// Create the event distributor with channels from both time reels
	eventDistributor := events.NewAppEventDistributor(
		globalTimeReel.GetEventCh(),
		appTimeReel.GetEventCh(),
	)

	// Create the consensus engine with the wired event distributor and time reel
	engine, err := NewAppConsensusEngine(
		f.logger,
		f.config,
		coreId,
		appAddress,
		f.pubsub,
		f.hypergraph,
		f.keyManager,
		f.keyStore,
		f.clockStore,
		f.inboxStore,
		f.shardsStore,
		f.hypergraphStore,
		f.frameProver,
		f.inclusionProver,
		f.bulletproofProver,
		f.verEnc,
		f.decafConstructor,
		f.compiler,
		f.signerRegistry,
		f.proverRegistry,
		f.dynamicFeeManager,
		f.frameValidator,
		f.globalFrameValidator,
		f.difficultyAdjuster,
		f.rewardIssuance,
		eventDistributor,
		f.peerInfoManager,
		appTimeReel,
		globalTimeReel,
		f.blsConstructor,
		f.encryptedChannel,
		grpcServer,
	)
	if err != nil {
		return nil, errors.Wrap(err, "create app consensus engine")
	}

	return engine, nil
}

// CreateGlobalTimeReel creates a new global time reel
func (
	f *AppConsensusEngineFactory,
) CreateGlobalTimeReel() (*time.GlobalTimeReel, error) {
	return time.NewGlobalTimeReel(
		f.logger,
		f.proverRegistry,
		f.clockStore,
		f.config.P2P.Network,
		f.config.Engine.ArchiveMode,
	)
}
