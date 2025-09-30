package global

import (
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/events"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global/compat"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/compiler"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	tp2p "source.quilibrium.com/quilibrium/monorepo/types/p2p"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

// ConsensusEngineFactory provides a factory method for creating properly wired
// GlobalConsensusEngine instances with time reels and event distributors
type ConsensusEngineFactory struct {
	logger             *zap.Logger
	config             *config.Config
	pubsub             tp2p.PubSub
	hypergraph         hypergraph.Hypergraph
	keyManager         keys.KeyManager
	keyStore           store.KeyStore
	frameProver        crypto.FrameProver
	inclusionProver    crypto.InclusionProver
	signerRegistry     consensus.SignerRegistry
	proverRegistry     consensus.ProverRegistry
	dynamicFeeManager  consensus.DynamicFeeManager
	appFrameValidator  consensus.AppFrameValidator
	frameValidator     consensus.GlobalFrameValidator
	difficultyAdjuster consensus.DifficultyAdjuster
	rewardIssuance     consensus.RewardIssuance
	clockStore         store.ClockStore
	inboxStore         store.InboxStore
	hypergraphStore    store.HypergraphStore
	shardsStore        store.ShardsStore
	workerStore        store.WorkerStore
	encryptedChannel   channel.EncryptedChannel
	bulletproofProver  crypto.BulletproofProver
	verEnc             crypto.VerifiableEncryptor
	decafConstructor   crypto.DecafConstructor
	compiler           compiler.CircuitCompiler
	blsConstructor     crypto.BlsConstructor
	peerInfoManager    p2p.PeerInfoManager
}

// NewConsensusEngineFactory creates a new factory for consensus engines
func NewConsensusEngineFactory(
	logger *zap.Logger,
	config *config.Config,
	pubsub tp2p.PubSub,
	hypergraph hypergraph.Hypergraph,
	keyManager keys.KeyManager,
	keyStore store.KeyStore,
	frameProver crypto.FrameProver,
	inclusionProver crypto.InclusionProver,
	signerRegistry consensus.SignerRegistry,
	proverRegistry consensus.ProverRegistry,
	dynamicFeeManager consensus.DynamicFeeManager,
	appFrameValidator consensus.AppFrameValidator,
	frameValidator consensus.GlobalFrameValidator,
	difficultyAdjuster consensus.DifficultyAdjuster,
	rewardIssuance consensus.RewardIssuance,
	clockStore store.ClockStore,
	inboxStore store.InboxStore,
	hypergraphStore store.HypergraphStore,
	shardsStore store.ShardsStore,
	workerStore store.WorkerStore,
	encryptedChannel channel.EncryptedChannel,
	bulletproofProver crypto.BulletproofProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	compiler compiler.CircuitCompiler,
	blsConstructor crypto.BlsConstructor,
	peerInfoManager p2p.PeerInfoManager,
) *ConsensusEngineFactory {
	// Initialize peer seniority data
	compat.RebuildPeerSeniority(uint(config.P2P.Network))

	return &ConsensusEngineFactory{
		logger:             logger,
		config:             config,
		pubsub:             pubsub,
		hypergraph:         hypergraph,
		keyManager:         keyManager,
		keyStore:           keyStore,
		frameProver:        frameProver,
		inclusionProver:    inclusionProver,
		signerRegistry:     signerRegistry,
		proverRegistry:     proverRegistry,
		dynamicFeeManager:  dynamicFeeManager,
		appFrameValidator:  appFrameValidator,
		frameValidator:     frameValidator,
		difficultyAdjuster: difficultyAdjuster,
		rewardIssuance:     rewardIssuance,
		clockStore:         clockStore,
		inboxStore:         inboxStore,
		hypergraphStore:    hypergraphStore,
		shardsStore:        shardsStore,
		workerStore:        workerStore,
		encryptedChannel:   encryptedChannel,
		bulletproofProver:  bulletproofProver,
		verEnc:             verEnc,
		decafConstructor:   decafConstructor,
		compiler:           compiler,
		blsConstructor:     blsConstructor,
		peerInfoManager:    peerInfoManager,
	}
}

// CreateGlobalConsensusEngine creates a new GlobalConsensusEngine
func (f *ConsensusEngineFactory) CreateGlobalConsensusEngine(
	frameTimeMillis int64,
) (*GlobalConsensusEngine, *consensustime.GlobalTimeReel, error) {
	// Create the global time reel
	globalTimeReel, err := consensustime.NewGlobalTimeReel(
		f.logger,
		f.proverRegistry,
		f.clockStore,
		f.config.P2P.Network,
		f.config.Engine.ArchiveMode,
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "create global time reel")
	}

	// Create the event distributor with channel from the global time reel
	eventDistributor := events.NewGlobalEventDistributor(
		globalTimeReel.GetEventCh(),
	)

	// Create the consensus engine with the wired event distributor and time reel
	engine, err := NewGlobalConsensusEngine(
		f.logger,
		f.config,
		frameTimeMillis,
		f.pubsub,
		f.hypergraph,
		f.keyManager,
		f.keyStore,
		f.frameProver,
		f.inclusionProver,
		f.signerRegistry,
		f.proverRegistry,
		f.dynamicFeeManager,
		f.appFrameValidator,
		f.frameValidator,
		f.difficultyAdjuster,
		f.rewardIssuance,
		eventDistributor,
		globalTimeReel,
		f.clockStore,
		f.inboxStore,
		f.hypergraphStore,
		f.shardsStore,
		f.workerStore,
		f.encryptedChannel,
		f.bulletproofProver,
		f.verEnc,
		f.decafConstructor,
		f.compiler,
		f.blsConstructor,
		f.peerInfoManager,
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "create global consensus engine")
	}

	return engine, globalTimeReel, nil
}
