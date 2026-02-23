package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/forks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/notifications/pubsub"
	"source.quilibrium.com/quilibrium/monorepo/consensus/participant"
	"source.quilibrium.com/quilibrium/monorepo/consensus/validator"
	"source.quilibrium.com/quilibrium/monorepo/consensus/verification"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/aggregator"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/global"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/reward"
	qsync "source.quilibrium.com/quilibrium/monorepo/node/consensus/sync"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/tracing"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/voting"
	"source.quilibrium.com/quilibrium/monorepo/node/dispatch"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/manager"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	keyedaggregator "source.quilibrium.com/quilibrium/monorepo/node/keyedaggregator"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p/onion"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/compiler"
	typesconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	tkeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
	tp2p "source.quilibrium.com/quilibrium/monorepo/types/p2p"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

// AppConsensusEngine uses the generic state machine for consensus
type AppConsensusEngine struct {
	*lifecycle.ComponentManager
	protobufs.AppShardServiceServer

	logger               *zap.Logger
	config               *config.Config
	coreId               uint
	appAddress           []byte
	appFilter            []byte
	appAddressHex        string
	pubsub               tp2p.PubSub
	hypergraph           hypergraph.Hypergraph
	keyManager           tkeys.KeyManager
	keyStore             store.KeyStore
	clockStore           store.ClockStore
	inboxStore           store.InboxStore
	shardsStore          store.ShardsStore
	hypergraphStore      store.HypergraphStore
	consensusStore       consensus.ConsensusStore[*protobufs.ProposalVote]
	frameProver          crypto.FrameProver
	inclusionProver      crypto.InclusionProver
	signerRegistry       typesconsensus.SignerRegistry
	proverRegistry       typesconsensus.ProverRegistry
	dynamicFeeManager    typesconsensus.DynamicFeeManager
	frameValidator       typesconsensus.AppFrameValidator
	globalFrameValidator typesconsensus.GlobalFrameValidator
	difficultyAdjuster   typesconsensus.DifficultyAdjuster
	rewardIssuance       typesconsensus.RewardIssuance
	eventDistributor     typesconsensus.EventDistributor
	mixnet               typesconsensus.Mixnet
	appTimeReel          *consensustime.AppTimeReel
	globalTimeReel       *consensustime.GlobalTimeReel
	forks                consensus.Forks[*protobufs.AppShardFrame]
	notifier             consensus.Consumer[
		*protobufs.AppShardFrame,
		*protobufs.ProposalVote,
	]
	encryptedChannel              channel.EncryptedChannel
	dispatchService               *dispatch.DispatchService
	blsConstructor                crypto.BlsConstructor
	minimumProvers                func() uint64
	executors                     map[string]execution.ShardExecutionEngine
	executorsMu                   sync.RWMutex
	executionManager              *manager.ExecutionEngineManager
	peerInfoManager               tp2p.PeerInfoManager
	currentDifficulty             uint32
	currentDifficultyMu           sync.RWMutex
	messageCollectors             *keyedaggregator.SequencedCollectors[sequencedAppMessage]
	messageAggregator             *keyedaggregator.SequencedAggregator[sequencedAppMessage]
	appMessageSpillover           map[uint64][]*protobufs.Message
	appSpilloverMu                sync.Mutex
	lastProposalRank              uint64
	lastProposalRankMu            sync.RWMutex
	collectedMessages             []*protobufs.Message
	collectedMessagesMu           sync.RWMutex
	provingMessages               []*protobufs.Message
	provingMessagesMu             sync.RWMutex
	lastProvenFrameTime           time.Time
	lastProvenFrameTimeMu         sync.RWMutex
	frameStore                    map[string]*protobufs.AppShardFrame
	frameStoreMu                  sync.RWMutex
	proposalCache                 map[uint64]*protobufs.AppShardProposal
	proposalCacheMu               sync.RWMutex
	pendingCertifiedParents       map[uint64]*protobufs.AppShardProposal
	pendingCertifiedParentsMu     sync.RWMutex
	proofCache                    map[uint64][516]byte
	proofCacheMu                  sync.RWMutex
	ctx                           lifecycle.SignalerContext
	cancel                        context.CancelFunc
	quit                          chan struct{}
	frameChainChecker             *AppFrameChainChecker
	canRunStandalone              bool
	blacklistMap                  map[string]bool
	currentRank                   uint64
	alertPublicKey                []byte
	peerAuthCache                 map[string]time.Time
	peerAuthCacheMu               sync.RWMutex
	peerInfoDigestCache           map[string]struct{}
	peerInfoDigestCacheMu         sync.Mutex
	keyRegistryDigestCache        map[string]struct{}
	keyRegistryDigestCacheMu      sync.Mutex
	proverAddress                 []byte
	lowCoverageStreak             map[string]*coverageStreak
	coverageOnce                  sync.Once
	coverageMinProvers            uint64
	coverageHaltThreshold         uint64
	coverageHaltGrace             uint64
	globalProverRootVerifiedFrame atomic.Uint64
	globalProverRootSynced        atomic.Bool
	globalProverSyncInProgress    atomic.Bool

	// Genesis initialization
	genesisInitialized atomic.Bool
	genesisInitChan    chan *protobufs.GlobalFrame

	// Message queues
	consensusMessageQueue      chan *pb.Message
	proverMessageQueue         chan *pb.Message
	frameMessageQueue          chan *pb.Message
	globalFrameMessageQueue    chan *pb.Message
	globalAlertMessageQueue    chan *pb.Message
	globalPeerInfoMessageQueue chan *pb.Message
	dispatchMessageQueue       chan *pb.Message
	appShardProposalQueue      chan *protobufs.AppShardProposal

	// Emergency halt
	haltCtx context.Context
	halt    context.CancelFunc

	// Consensus participant instance
	consensusParticipant consensus.EventLoop[
		*protobufs.AppShardFrame,
		*protobufs.ProposalVote,
	]

	// Consensus plugins
	signatureAggregator         consensus.SignatureAggregator
	voteCollectorDistributor    *pubsub.VoteCollectorDistributor[*protobufs.ProposalVote]
	timeoutCollectorDistributor *pubsub.TimeoutCollectorDistributor[*protobufs.ProposalVote]
	voteAggregator              consensus.VoteAggregator[*protobufs.AppShardFrame, *protobufs.ProposalVote]
	timeoutAggregator           consensus.TimeoutAggregator[*protobufs.ProposalVote]

	// Provider implementations
	syncProvider     *qsync.SyncProvider[*protobufs.AppShardFrame, *protobufs.AppShardProposal]
	votingProvider   *AppVotingProvider
	leaderProvider   *AppLeaderProvider
	livenessProvider *AppLivenessProvider

	// Existing gRPC server instance
	grpcServer *grpc.Server

	// Synchronization service
	hyperSync protobufs.HypergraphComparisonServiceServer

	// Private routing
	onionRouter  *onion.OnionRouter
	onionService *onion.GRPCTransport

	// Communication with master process
	globalClient protobufs.GlobalServiceClient
}

// NewAppConsensusEngine creates a new app consensus engine using the generic
// state machine
func NewAppConsensusEngine(
	logger *zap.Logger,
	config *config.Config,
	coreId uint,
	appAddress []byte,
	ps tp2p.PubSub,
	hypergraph hypergraph.Hypergraph,
	keyManager tkeys.KeyManager,
	keyStore store.KeyStore,
	clockStore store.ClockStore,
	inboxStore store.InboxStore,
	shardsStore store.ShardsStore,
	hypergraphStore store.HypergraphStore,
	consensusStore consensus.ConsensusStore[*protobufs.ProposalVote],
	frameProver crypto.FrameProver,
	inclusionProver crypto.InclusionProver,
	bulletproofProver crypto.BulletproofProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	compiler compiler.CircuitCompiler,
	signerRegistry typesconsensus.SignerRegistry,
	proverRegistry typesconsensus.ProverRegistry,
	dynamicFeeManager typesconsensus.DynamicFeeManager,
	frameValidator typesconsensus.AppFrameValidator,
	globalFrameValidator typesconsensus.GlobalFrameValidator,
	difficultyAdjuster typesconsensus.DifficultyAdjuster,
	rewardIssuance typesconsensus.RewardIssuance,
	eventDistributor typesconsensus.EventDistributor,
	peerInfoManager tp2p.PeerInfoManager,
	appTimeReel *consensustime.AppTimeReel,
	globalTimeReel *consensustime.GlobalTimeReel,
	blsConstructor crypto.BlsConstructor,
	encryptedChannel channel.EncryptedChannel,
	grpcServer *grpc.Server,
) (*AppConsensusEngine, error) {
	appFilter := up2p.GetBloomFilter(appAddress, 256, 3)

	engine := &AppConsensusEngine{
		logger:                     logger,
		config:                     config,
		appAddress:                 appAddress, // buildutils:allow-slice-alias slice is static
		appFilter:                  appFilter,
		appAddressHex:              hex.EncodeToString(appAddress),
		pubsub:                     ps,
		hypergraph:                 hypergraph,
		keyManager:                 keyManager,
		keyStore:                   keyStore,
		clockStore:                 clockStore,
		inboxStore:                 inboxStore,
		shardsStore:                shardsStore,
		hypergraphStore:            hypergraphStore,
		consensusStore:             consensusStore,
		frameProver:                frameProver,
		inclusionProver:            inclusionProver,
		signerRegistry:             signerRegistry,
		proverRegistry:             proverRegistry,
		dynamicFeeManager:          dynamicFeeManager,
		frameValidator:             frameValidator,
		globalFrameValidator:       globalFrameValidator,
		difficultyAdjuster:         difficultyAdjuster,
		rewardIssuance:             rewardIssuance,
		eventDistributor:           eventDistributor,
		appTimeReel:                appTimeReel,
		globalTimeReel:             globalTimeReel,
		blsConstructor:             blsConstructor,
		encryptedChannel:           encryptedChannel,
		grpcServer:                 grpcServer,
		peerInfoManager:            peerInfoManager,
		executors:                  make(map[string]execution.ShardExecutionEngine),
		frameStore:                 make(map[string]*protobufs.AppShardFrame),
		proposalCache:              make(map[uint64]*protobufs.AppShardProposal),
		pendingCertifiedParents:    make(map[uint64]*protobufs.AppShardProposal),
		proofCache:                 make(map[uint64][516]byte),
		collectedMessages:          []*protobufs.Message{},
		provingMessages:            []*protobufs.Message{},
		appMessageSpillover:        make(map[uint64][]*protobufs.Message),
		consensusMessageQueue:      make(chan *pb.Message, 1000),
		proverMessageQueue:         make(chan *pb.Message, 1000),
		frameMessageQueue:          make(chan *pb.Message, 100),
		globalFrameMessageQueue:    make(chan *pb.Message, 100),
		globalAlertMessageQueue:    make(chan *pb.Message, 100),
		globalPeerInfoMessageQueue: make(chan *pb.Message, 1000),
		dispatchMessageQueue:       make(chan *pb.Message, 1000),
		appShardProposalQueue:      make(chan *protobufs.AppShardProposal, 1000),
		currentDifficulty:          config.Engine.Difficulty,
		blacklistMap:               make(map[string]bool),
		alertPublicKey:             []byte{},
		peerAuthCache:              make(map[string]time.Time),
		peerInfoDigestCache:        make(map[string]struct{}),
		keyRegistryDigestCache:     make(map[string]struct{}),
		genesisInitChan:            make(chan *protobufs.GlobalFrame, 1),
	}

	engine.frameChainChecker = NewAppFrameChainChecker(clockStore, logger, appAddress)

	keyId := "q-prover-key"

	key, err := keyManager.GetSigningKey(keyId)
	if err != nil {
		logger.Error("failed to get key for prover address", zap.Error(err))
		panic(err)
	}

	addressBI, err := poseidon.HashBytes(key.Public().([]byte))
	if err != nil {
		logger.Error("failed to calculate prover address", zap.Error(err))
		panic(err)
	}

	engine.proverAddress = addressBI.FillBytes(make([]byte, 32))

	engine.votingProvider = &AppVotingProvider{engine: engine}
	engine.leaderProvider = &AppLeaderProvider{engine: engine}
	engine.livenessProvider = &AppLivenessProvider{engine: engine}
	engine.signatureAggregator = aggregator.WrapSignatureAggregator(
		engine.blsConstructor,
		engine.proverRegistry,
		appAddress,
	)
	voteAggregationDistributor := voting.NewAppShardVoteAggregationDistributor()
	engine.voteCollectorDistributor =
		voteAggregationDistributor.VoteCollectorDistributor
	timeoutAggregationDistributor :=
		voting.NewAppShardTimeoutAggregationDistributor()
	engine.timeoutCollectorDistributor =
		timeoutAggregationDistributor.TimeoutCollectorDistributor

	if config.Engine.AlertKey != "" {
		alertPublicKey, err := hex.DecodeString(config.Engine.AlertKey)
		if err != nil {
			logger.Warn(
				"could not decode alert key",
				zap.Error(err),
			)
		} else if len(alertPublicKey) != 57 {
			logger.Warn(
				"invalid alert key",
				zap.String("alert_key", config.Engine.AlertKey),
			)
		} else {
			engine.alertPublicKey = alertPublicKey
		}
	}

	// Initialize blacklist map
	for _, blacklistedAddress := range config.Engine.Blacklist {
		normalizedAddress := strings.ToLower(
			strings.TrimPrefix(blacklistedAddress, "0x"),
		)

		addressBytes, err := hex.DecodeString(normalizedAddress)
		if err != nil {
			logger.Warn(
				"invalid blacklist address format",
				zap.String("address", blacklistedAddress),
			)
			continue
		}

		// Store full addresses and partial addresses (prefixes)
		if len(addressBytes) >= 32 && len(addressBytes) <= 64 {
			engine.blacklistMap[normalizedAddress] = true

			// Check if this consensus address matches or is a descendant of the
			// blacklisted address
			if bytes.Equal(appAddress, addressBytes) ||
				(len(addressBytes) < len(appAddress) &&
					strings.HasPrefix(string(appAddress), string(addressBytes))) {
				return nil, errors.Errorf(
					"consensus address %s is blacklisted or has blacklisted prefix %s",
					engine.appAddressHex,
					normalizedAddress,
				)
			}

			logger.Info(
				"added address to blacklist",
				zap.String("address", normalizedAddress),
			)
		} else {
			logger.Warn(
				"blacklist address has invalid length",
				zap.String("address", blacklistedAddress),
				zap.Int("length", len(addressBytes)),
			)
		}
	}

	// Establish alert halt context
	engine.haltCtx, engine.halt = context.WithCancel(context.Background())

	// Create execution engine manager
	executionManager, err := manager.NewExecutionEngineManager(
		logger,
		config,
		hypergraph,
		clockStore,
		nil,
		keyManager,
		inclusionProver,
		bulletproofProver,
		verEnc,
		decafConstructor,
		compiler,
		frameProver,
		nil,
		nil,
		nil,
		false, // includeGlobal
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create execution engine manager")
	}
	engine.executionManager = executionManager

	if err := engine.ensureGlobalGenesis(); err != nil {
		return nil, errors.Wrap(err, "new app consensus engine")
	}

	// Create dispatch service
	engine.dispatchService = dispatch.NewDispatchService(
		inboxStore,
		logger,
		keyManager,
		ps,
	)

	appTimeReel.SetMaterializeFunc(engine.materialize)
	appTimeReel.SetRevertFunc(engine.revert)

	// 99 (local devnet) is the special case where consensus is of one node
	if config.P2P.Network == 99 {
		logger.Debug("devnet detected, setting minimum provers to 1")
		engine.minimumProvers = func() uint64 { return 1 }
	} else {
		engine.minimumProvers = func() uint64 {
			currentSet, err := engine.proverRegistry.GetActiveProvers(
				engine.appAddress,
			)
			if err != nil {
				return 999
			}

			if len(currentSet) > 6 {
				return 6
			}

			return uint64(len(currentSet)) * 2 / 3
		}
	}

	// Establish hypersync service
	engine.hyperSync = hypergraph
	engine.onionService = onion.NewGRPCTransport(
		logger,
		ps.GetPeerID(),
		peerInfoManager,
		signerRegistry,
	)
	engine.onionRouter = onion.NewOnionRouter(
		logger,
		engine.peerInfoManager,
		engine.signerRegistry,
		engine.keyManager,
		onion.WithKeyConstructor(func() ([]byte, []byte, error) {
			k := keys.NewX448Key()
			return k.Public(), k.Private(), nil
		}),
		onion.WithSharedSecret(func(priv, pub []byte) ([]byte, error) {
			e, _ := keys.X448KeyFromBytes(priv)
			return e.AgreeWith(pub)
		}),
		onion.WithTransport(engine.onionService),
	)

	// Initialize metrics
	currentDifficulty.WithLabelValues(engine.appAddressHex).Set(
		float64(config.Engine.Difficulty),
	)
	engineState.WithLabelValues(engine.appAddressHex).Set(0)
	executorsRegistered.WithLabelValues(engine.appAddressHex).Set(0)
	pendingMessagesCount.WithLabelValues(engine.appAddressHex).Set(0)

	if err := engine.initAppMessageAggregator(); err != nil {
		return nil, errors.Wrap(err, "new app consensus engine")
	}

	componentBuilder := lifecycle.NewComponentManagerBuilder()
	// Add execution engines
	componentBuilder.AddWorker(engine.executionManager.Start)
	componentBuilder.AddWorker(engine.eventDistributor.Start)
	componentBuilder.AddWorker(engine.appTimeReel.Start)
	componentBuilder.AddWorker(engine.globalTimeReel.Start)
	componentBuilder.AddWorker(engine.startAppMessageAggregator)

	latest, err := engine.consensusStore.GetConsensusState(engine.appAddress)
	var state *models.CertifiedState[*protobufs.AppShardFrame]
	var pending []*models.SignedProposal[
		*protobufs.AppShardFrame,
		*protobufs.ProposalVote,
	]

	// Check if we need to await network data for genesis initialization
	needsNetworkGenesis := false
	initializeCertifiedGenesis := func(markInitialized bool) {
		frame, qc := engine.initializeGenesis()
		state = &models.CertifiedState[*protobufs.AppShardFrame]{
			State: &models.State[*protobufs.AppShardFrame]{
				Rank:       0,
				Identifier: frame.Identity(),
				State:      &frame,
			},
			CertifyingQuorumCertificate: qc,
		}
		pending = nil
		if markInitialized {
			engine.genesisInitialized.Store(true)
		}
	}

	initializeCertifiedGenesisFromNetwork := func(
		difficulty uint32,
		shardInfo []*protobufs.AppShardInfo,
	) {
		// Delete the temporary genesis frame first
		if err := engine.clockStore.DeleteShardClockFrameRange(
			engine.appAddress, 0, 1,
		); err != nil {
			logger.Debug(
				"could not delete temporary genesis frame",
				zap.Error(err),
			)
		}

		frame, qc := engine.initializeGenesisWithParams(difficulty, shardInfo)
		state = &models.CertifiedState[*protobufs.AppShardFrame]{
			State: &models.State[*protobufs.AppShardFrame]{
				Rank:       0,
				Identifier: frame.Identity(),
				State:      &frame,
			},
			CertifyingQuorumCertificate: qc,
		}
		pending = nil
		engine.genesisInitialized.Store(true)

		logger.Info(
			"initialized genesis with network data",
			zap.Uint32("difficulty", difficulty),
			zap.Int("shard_info_count", len(shardInfo)),
		)
	}

	if err != nil {
		// No consensus state exists - check if we have a genesis frame already
		_, _, genesisErr := engine.clockStore.GetShardClockFrame(
			engine.appAddress,
			0,
			false,
		)
		if genesisErr != nil && errors.Is(genesisErr, store.ErrNotFound) {
			// No genesis exists - we need to await network data
			needsNetworkGenesis = true
			logger.Warn(
				"app genesis missing - will await network data",
				zap.String("shard_address", hex.EncodeToString(appAddress)),
			)
			// Initialize with default values for now
			// This will be re-done after receiving network data
			// Pass false to NOT mark as initialized - we're waiting for network data
			initializeCertifiedGenesis(false)
		} else {
			initializeCertifiedGenesis(true)
		}
	} else {
		stateRestored := false
		qc, err := engine.clockStore.GetQuorumCertificate(
			engine.appAddress,
			latest.FinalizedRank,
		)
		if err == nil && qc.GetFrameNumber() != 0 {
			frame, _, frameErr := engine.clockStore.GetShardClockFrame(
				engine.appAddress,
				qc.GetFrameNumber(),
				false,
			)
			if frameErr != nil {
				// Frame data was deleted (e.g., non-archive mode cleanup) but
				// QC/consensus state still exists. Re-initialize genesis and
				// let sync recover the state.
				logger.Warn(
					"frame missing for finalized QC, re-initializing genesis",
					zap.Uint64("finalized_rank", latest.FinalizedRank),
					zap.Uint64("qc_frame_number", qc.GetFrameNumber()),
					zap.Error(frameErr),
				)
			} else {
				parentFrame, _, parentFrameErr := engine.clockStore.GetShardClockFrame(
					engine.appAddress,
					qc.GetFrameNumber()-1,
					false,
				)
				if parentFrameErr != nil {
					// Parent frame missing - same recovery path
					logger.Warn(
						"parent frame missing for finalized QC, re-initializing genesis",
						zap.Uint64("finalized_rank", latest.FinalizedRank),
						zap.Uint64("qc_frame_number", qc.GetFrameNumber()),
						zap.Error(parentFrameErr),
					)
				} else {
					parentQC, parentQCErr := engine.clockStore.GetQuorumCertificate(
						engine.appAddress,
						parentFrame.GetRank(),
					)
					if parentQCErr != nil {
						// Parent QC missing - same recovery path
						logger.Warn(
							"parent QC missing, re-initializing genesis",
							zap.Uint64("finalized_rank", latest.FinalizedRank),
							zap.Uint64("parent_rank", parentFrame.GetRank()),
							zap.Error(parentQCErr),
						)
					} else {
						state = &models.CertifiedState[*protobufs.AppShardFrame]{
							State: &models.State[*protobufs.AppShardFrame]{
								Rank:                    frame.GetRank(),
								Identifier:              frame.Identity(),
								ProposerID:              frame.Source(),
								ParentQuorumCertificate: parentQC,
								Timestamp:               frame.GetTimestamp(),
								State:                   &frame,
							},
							CertifyingQuorumCertificate: qc,
						}
						pending = engine.getPendingProposals(frame.Header.FrameNumber)
						stateRestored = true
					}
				}
			}
		}
		if !stateRestored {
			initializeCertifiedGenesis(true)
		}
	}

	engine.recordProposalRank(state.Rank())
	liveness, err := engine.consensusStore.GetLivenessState(appAddress)
	if err == nil {
		engine.currentRank = liveness.CurrentRank
	}

	engine.voteAggregator, err = voting.NewAppShardVoteAggregator[PeerID](
		tracing.NewZapTracer(logger),
		appAddress,
		engine,
		voteAggregationDistributor,
		engine.signatureAggregator,
		engine.votingProvider,
		func(qc models.QuorumCertificate) {
			engine.consensusParticipant.OnQuorumCertificateConstructedFromVotes(qc)
		},
		state.Rank()+1,
	)
	if err != nil {
		return nil, err
	}
	engine.timeoutAggregator, err = voting.NewAppShardTimeoutAggregator[PeerID](
		tracing.NewZapTracer(logger),
		appAddress,
		engine,
		engine,
		engine.signatureAggregator,
		timeoutAggregationDistributor,
		engine.votingProvider,
		state.Rank()+1,
	)

	notifier := pubsub.NewDistributor[
		*protobufs.AppShardFrame,
		*protobufs.ProposalVote,
	]()
	notifier.AddConsumer(engine)
	engine.notifier = notifier

	forks, err := forks.NewForks(state, engine, notifier)
	if err != nil {
		return nil, err
	}
	engine.forks = forks

	dbConfig := config.DB.WithDefaults()
	dbPath := dbConfig.Path
	if engine.coreId > 0 {
		if len(dbConfig.WorkerPaths) >= int(engine.coreId) {
			dbPath = dbConfig.WorkerPaths[engine.coreId-1]
		} else if dbConfig.WorkerPathPrefix != "" {
			dbPath = fmt.Sprintf(dbConfig.WorkerPathPrefix, engine.coreId)
		}
	}

	appSyncHooks := qsync.NewAppSyncHooks(
		appAddress,
		dbPath,
		config.P2P.Network,
	)

	engine.syncProvider = qsync.NewSyncProvider[
		*protobufs.AppShardFrame,
		*protobufs.AppShardProposal,
	](
		logger,
		forks,
		proverRegistry,
		signerRegistry,
		peerInfoManager,
		qsync.NewAppSyncClient(
			frameProver,
			proverRegistry,
			blsConstructor,
			engine,
			config,
			appAddress,
		),
		hypergraph,
		config,
		appAddress,
		engine.proverAddress,
		appSyncHooks,
	)

	// Add sync provider
	componentBuilder.AddWorker(engine.syncProvider.Start)

	// Add consensus
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		// If we need network genesis, await it before starting consensus
		if needsNetworkGenesis {
			engine.logger.Info(
				"awaiting network data for genesis initialization",
				zap.String("shard_address", engine.appAddressHex),
			)

			// Wait for a global frame from pubsub
			globalFrame, err := engine.awaitFirstGlobalFrame(ctx)
			if err != nil {
				engine.logger.Error(
					"failed to await global frame for genesis",
					zap.Error(err),
				)
				ctx.Throw(err)
				return
			}

			// Fetch shard info from bootstrap peers
			shardInfo, err := engine.fetchShardInfoFromBootstrap(ctx)
			if err != nil {
				engine.logger.Warn(
					"failed to fetch shard info from bootstrap peers",
					zap.Error(err),
				)
				// Continue anyway - we at least have the global frame
			}

			engine.logger.Info(
				"received network genesis data",
				zap.Uint64("global_frame_number", globalFrame.Header.FrameNumber),
				zap.Uint32("difficulty", globalFrame.Header.Difficulty),
				zap.Int("shard_info_count", len(shardInfo)),
			)

			// Re-initialize genesis with the correct network data
			initializeCertifiedGenesisFromNetwork(
				globalFrame.Header.Difficulty,
				shardInfo,
			)
		}

		if err := engine.waitForProverRegistration(ctx); err != nil {
			engine.logger.Error("prover unavailable", zap.Error(err))
			ctx.Throw(err)
			return
		}
		if err := engine.startConsensus(state, pending, ctx, ready); err != nil {
			ctx.Throw(err)
			return
		}

		<-ctx.Done()
		<-lifecycle.AllDone(engine.voteAggregator, engine.timeoutAggregator)
	})

	// Start app shard proposal queue processor
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.processAppShardProposalQueue(ctx)
	})

	err = engine.subscribeToConsensusMessages()
	if err != nil {
		return nil, err
	}

	err = engine.subscribeToProverMessages()
	if err != nil {
		return nil, err
	}

	err = engine.subscribeToFrameMessages()
	if err != nil {
		return nil, err
	}

	err = engine.subscribeToGlobalFrameMessages()
	if err != nil {
		return nil, err
	}

	err = engine.subscribeToGlobalProverMessages()
	if err != nil {
		return nil, err
	}

	err = engine.subscribeToGlobalAlertMessages()
	if err != nil {
		return nil, err
	}

	err = engine.subscribeToPeerInfoMessages()
	if err != nil {
		return nil, err
	}

	err = engine.subscribeToDispatchMessages()
	if err != nil {
		return nil, err
	}

	// Add sync provider
	componentBuilder.AddWorker(engine.syncProvider.Start)

	// Start message queue processors
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.processConsensusMessageQueue(ctx)
	})

	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.processProverMessageQueue(ctx)
	})

	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.processFrameMessageQueue(ctx)
	})

	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.processGlobalFrameMessageQueue(ctx)
	})

	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.processAlertMessageQueue(ctx)
	})

	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.processPeerInfoMessageQueue(ctx)
	})

	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.processDispatchMessageQueue(ctx)
	})

	// Start event distributor event loop
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.eventDistributorLoop(ctx)
	})

	// Start metrics update goroutine
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.updateMetricsLoop(ctx)
	})

	engine.ComponentManager = componentBuilder.Build()
	if hgWithShutdown, ok := engine.hyperSync.(interface {
		SetShutdownContext(context.Context)
	}); ok {
		hgWithShutdown.SetShutdownContext(
			contextFromShutdownSignal(engine.ShutdownSignal()),
		)
	}

	// Set self peer ID on hypergraph to allow unlimited self-sync sessions
	if hgWithSelfPeer, ok := engine.hyperSync.(interface {
		SetSelfPeerID(string)
	}); ok {
		hgWithSelfPeer.SetSelfPeerID(peer.ID(ps.GetPeerID()).String())
	}

	return engine, nil
}

func (e *AppConsensusEngine) Stop(force bool) <-chan error {
	errChan := make(chan error, 1)

	// First, cancel context to signal all goroutines to stop
	if e.cancel != nil {
		e.cancel()
	}

	// Unsubscribe from pubsub to stop new messages from arriving
	e.pubsub.Unsubscribe(e.getConsensusMessageBitmask(), false)
	e.pubsub.UnregisterValidator(e.getConsensusMessageBitmask())
	e.pubsub.Unsubscribe(e.getProverMessageBitmask(), false)
	e.pubsub.UnregisterValidator(e.getProverMessageBitmask())
	e.pubsub.Unsubscribe(e.getFrameMessageBitmask(), false)
	e.pubsub.UnregisterValidator(e.getFrameMessageBitmask())
	e.pubsub.Unsubscribe(e.getGlobalFrameMessageBitmask(), false)
	e.pubsub.UnregisterValidator(e.getGlobalFrameMessageBitmask())
	e.pubsub.Unsubscribe(e.getGlobalAlertMessageBitmask(), false)
	e.pubsub.UnregisterValidator(e.getGlobalAlertMessageBitmask())
	e.pubsub.Unsubscribe(e.getGlobalPeerInfoMessageBitmask(), false)
	e.pubsub.UnregisterValidator(e.getGlobalPeerInfoMessageBitmask())
	e.pubsub.Unsubscribe(e.getDispatchMessageBitmask(), false)
	e.pubsub.UnregisterValidator(e.getDispatchMessageBitmask())

	// Wait briefly for component workers to finish. If they don't exit in
	// time, close pubsub to cancel subscription goroutines that may be
	// keeping handlers alive and preventing clean shutdown.
	select {
	case <-e.Done():
	case <-time.After(5 * time.Second):
		e.pubsub.Close()
		select {
		case <-e.Done():
		case <-time.After(25 * time.Second):
			if !force {
				errChan <- errors.New("timeout waiting for app engine shutdown")
			}
		}
	}

	close(errChan)
	return errChan
}

func (e *AppConsensusEngine) handleGlobalProverRoot(
	frame *protobufs.GlobalFrame,
) {
	if frame == nil || frame.Header == nil {
		return
	}

	frameNumber := frame.Header.FrameNumber
	expectedProverRoot := frame.Header.ProverTreeCommitment

	if len(expectedProverRoot) == 0 {
		return
	}

	// Match the GlobalConsensusEngine's ordering: commit the tree first as a
	// standalone step, then extract and verify the prover root. The global
	// engine calls Commit(N) at the start of materialize(N) before checking
	// the root. We mirror this by committing first, then extracting.
	if _, err := e.hypergraph.Commit(frameNumber); err != nil {
		e.logger.Warn(
			"failed to commit hypergraph for global prover root check",
			zap.Uint64("frame_number", frameNumber),
			zap.Error(err),
		)
	}

	localRoot, err := e.computeLocalGlobalProverRoot(frameNumber)
	if err != nil {
		e.logger.Warn(
			"failed to compute local global prover root",
			zap.Uint64("frame_number", frameNumber),
			zap.Error(err),
		)
		e.globalProverRootSynced.Store(false)
		e.globalProverRootVerifiedFrame.Store(0)
		e.performBlockingGlobalHypersync(frame.Header.Prover, expectedProverRoot)
		return
	}

	if len(localRoot) == 0 {
		return
	}

	if !bytes.Equal(localRoot, expectedProverRoot) {
		e.logger.Warn(
			"global prover root mismatch",
			zap.Uint64("frame_number", frameNumber),
			zap.String("expected_root", hex.EncodeToString(expectedProverRoot)),
			zap.String("local_root", hex.EncodeToString(localRoot)),
		)
		e.globalProverRootSynced.Store(false)
		e.globalProverRootVerifiedFrame.Store(0)
		e.performBlockingGlobalHypersync(frame.Header.Prover, expectedProverRoot)

		// Re-compute local root after sync to verify convergence, matching
		// the global engine's post-sync verification pattern.
		newLocalRoot, newRootErr := e.computeLocalGlobalProverRoot(frameNumber)
		if newRootErr != nil {
			e.logger.Warn(
				"failed to compute local global prover root after sync",
				zap.Uint64("frame_number", frameNumber),
				zap.Error(newRootErr),
			)
		} else if bytes.Equal(newLocalRoot, expectedProverRoot) {
			e.logger.Info(
				"global prover root converged after sync",
				zap.Uint64("frame_number", frameNumber),
			)
			e.globalProverRootSynced.Store(true)
			e.globalProverRootVerifiedFrame.Store(frameNumber)
			if err := e.proverRegistry.Refresh(); err != nil {
				e.logger.Warn("failed to refresh prover registry", zap.Error(err))
			}
		} else {
			e.logger.Warn(
				"global prover root still mismatched after sync",
				zap.Uint64("frame_number", frameNumber),
				zap.String("expected_root", hex.EncodeToString(expectedProverRoot)),
				zap.String("post_sync_root", hex.EncodeToString(newLocalRoot)),
			)
		}
		return
	}

	prev := e.globalProverRootVerifiedFrame.Load()
	if prev >= frameNumber {
		return
	}

	e.globalProverRootSynced.Store(true)
	e.globalProverRootVerifiedFrame.Store(frameNumber)

	if err := e.proverRegistry.Refresh(); err != nil {
		e.logger.Warn("failed to refresh prover registry", zap.Error(err))
	}
}

func (e *AppConsensusEngine) computeLocalGlobalProverRoot(
	frameNumber uint64,
) ([]byte, error) {
	if e.hypergraph == nil {
		return nil, errors.New("hypergraph unavailable")
	}

	commitSet, err := e.hypergraph.Commit(frameNumber)
	if err != nil {
		return nil, errors.Wrap(err, "compute global prover root")
	}

	var zeroShardKey tries.ShardKey
	for shardKey, phaseCommits := range commitSet {
		if shardKey.L1 == zeroShardKey.L1 {
			if len(phaseCommits) == 0 || len(phaseCommits[0]) == 0 {
				return nil, errors.New("empty global prover root commitment")
			}
			return slices.Clone(phaseCommits[0]), nil
		}
	}

	return nil, errors.New("global prover root shard missing")
}

func (e *AppConsensusEngine) triggerGlobalHypersync(proposer []byte, expectedRoot []byte) {
	if e.syncProvider == nil {
		e.logger.Debug("no sync provider for hypersync")
		return
	}
	if bytes.Equal(proposer, e.proverAddress) {
		e.logger.Debug("proposer matches local prover, skipping hypersync")
		return
	}
	if !e.globalProverSyncInProgress.CompareAndSwap(false, true) {
		e.logger.Debug("global hypersync already running")
		return
	}

	// Sync from our own master node instead of the proposer to avoid
	// overburdening the proposer with sync requests from all workers.
	selfPeerID := peer.ID(e.pubsub.GetPeerID())

	go func() {
		defer e.globalProverSyncInProgress.Store(false)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		shardKey := tries.ShardKey{
			L1: [3]byte{0x00, 0x00, 0x00},
			L2: intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		}

		e.syncProvider.HyperSyncSelf(ctx, selfPeerID, shardKey, nil, expectedRoot)
		if err := e.proverRegistry.Refresh(); err != nil {
			e.logger.Warn(
				"failed to refresh prover registry after hypersync",
				zap.Error(err),
			)
		}
	}()
}

// performBlockingGlobalHypersync performs a synchronous hypersync that blocks
// until completion. This is used before materializing frames to ensure we sync
// before applying any transactions when there's a prover root mismatch.
func (e *AppConsensusEngine) performBlockingGlobalHypersync(proposer []byte, expectedRoot []byte) {
	if e.syncProvider == nil {
		e.logger.Debug("blocking hypersync: no sync provider")
		return
	}
	if bytes.Equal(proposer, e.proverAddress) {
		e.logger.Debug("blocking hypersync: we are the proposer")
		return
	}

	// Wait for any existing sync to complete first
	for e.globalProverSyncInProgress.Load() {
		e.logger.Debug("blocking hypersync: waiting for existing sync to complete")
		time.Sleep(100 * time.Millisecond)
	}

	// Mark sync as in progress
	if !e.globalProverSyncInProgress.CompareAndSwap(false, true) {
		// Another sync started, wait for it
		for e.globalProverSyncInProgress.Load() {
			time.Sleep(100 * time.Millisecond)
		}
		return
	}
	defer e.globalProverSyncInProgress.Store(false)

	e.logger.Info(
		"performing blocking global hypersync before processing frame",
		zap.String("proposer", hex.EncodeToString(proposer)),
		zap.String("expected_root", hex.EncodeToString(expectedRoot)),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up shutdown handler
	done := make(chan struct{})
	go func() {
		select {
		case <-e.ShutdownSignal():
			cancel()
		case <-done:
		}
	}()

	selfPeerID := peer.ID(e.pubsub.GetPeerID())
	shardKey := tries.ShardKey{
		L1: [3]byte{0x00, 0x00, 0x00},
		L2: intrinsics.GLOBAL_INTRINSIC_ADDRESS,
	}

	// Perform sync synchronously (blocking)
	e.syncProvider.HyperSyncSelf(ctx, selfPeerID, shardKey, nil, expectedRoot)
	close(done)

	if err := e.proverRegistry.Refresh(); err != nil {
		e.logger.Warn(
			"failed to refresh prover registry after blocking hypersync",
			zap.Error(err),
		)
	}

	// Don't unconditionally set synced=true. Commit(N-1) is cached with the
	// pre-sync root, so we can't re-verify here. The next frame's deferred
	// check will call Commit(N) fresh and verify convergence — matching the
	// global engine's pattern where convergence happens on the next materialize.
	e.logger.Info("blocking global hypersync completed, convergence will be verified on next frame")
}

func (e *AppConsensusEngine) GetFrame() *protobufs.AppShardFrame {
	frame, _, _ := e.clockStore.GetLatestShardClockFrame(e.appAddress)
	return frame
}

func (e *AppConsensusEngine) GetDifficulty() uint32 {
	e.currentDifficultyMu.RLock()
	defer e.currentDifficultyMu.RUnlock()
	return e.currentDifficulty
}

func (e *AppConsensusEngine) GetState() typesconsensus.EngineState {
	// Map the generic state machine state to engine state
	if e.consensusParticipant == nil {
		return typesconsensus.EngineStateStopped
	}

	select {
	case <-e.consensusParticipant.Ready():
		return typesconsensus.EngineStateProving
	case <-e.consensusParticipant.Done():
		return typesconsensus.EngineStateStopped
	default:
		return typesconsensus.EngineStateStarting
	}
}

func (e *AppConsensusEngine) GetProvingKey(
	engineConfig *config.EngineConfig,
) (crypto.Signer, crypto.KeyType, []byte, []byte) {
	keyId := "q-prover-key"

	signer, err := e.keyManager.GetSigningKey(keyId)
	if err != nil {
		e.logger.Error("failed to get signing key", zap.Error(err))
		proverKeyLookupTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return nil, 0, nil, nil
	}

	key, err := e.keyManager.GetRawKey(keyId)
	if err != nil {
		e.logger.Error("failed to get raw key", zap.Error(err))
		proverKeyLookupTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return nil, 0, nil, nil
	}

	if key.Type != crypto.KeyTypeBLS48581G1 {
		e.logger.Error(
			"wrong key type",
			zap.String("expected", "BLS48581G1"),
			zap.Int("actual", int(key.Type)),
		)
		proverKeyLookupTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return nil, 0, nil, nil
	}

	// Get the prover address
	proverAddress := e.getProverAddress()

	proverKeyLookupTotal.WithLabelValues(e.appAddressHex, "found").Inc()
	return signer, crypto.KeyTypeBLS48581G1, key.PublicKey, proverAddress
}

func (e *AppConsensusEngine) IsInProverTrie(key []byte) bool {
	// Check if the key is in the prover registry
	provers, err := e.proverRegistry.GetActiveProvers(e.appAddress)
	if err != nil {
		return false
	}

	// Check if key is in the list of provers
	for _, prover := range provers {
		if bytes.Equal(prover.Address, key) {
			return true
		}
	}
	return false
}

func (e *AppConsensusEngine) InitializeFromGlobalFrame(
	globalFrame *protobufs.GlobalFrameHeader,
) error {
	// This would trigger a re-sync through the state machine
	// The sync provider will handle the initialization
	return nil
}

// WithRunStandalone enables skipping the connected peer enforcement
func (e *AppConsensusEngine) WithRunStandalone() {
	e.canRunStandalone = true
}

// GetDynamicFeeManager returns the dynamic fee manager instance
func (
	e *AppConsensusEngine,
) GetDynamicFeeManager() typesconsensus.DynamicFeeManager {
	return e.dynamicFeeManager
}

func (e *AppConsensusEngine) revert(
	txn store.Transaction,
	frame *protobufs.AppShardFrame,
) error {
	bits := up2p.GetBloomFilterIndices(e.appAddress, 256, 3)
	l2 := make([]byte, 32)
	copy(l2, e.appAddress[:min(len(e.appAddress), 32)])

	shardKey := tries.ShardKey{
		L1: [3]byte(bits),
		L2: [32]byte(l2),
	}
	return errors.Wrap(
		e.hypergraph.RevertChanges(
			txn,
			frame.Header.FrameNumber,
			frame.Header.FrameNumber,
			shardKey,
		),
		"revert",
	)
}

func (e *AppConsensusEngine) materialize(
	txn store.Transaction,
	frame *protobufs.AppShardFrame,
) error {
	var state state.State
	state = hgstate.NewHypergraphState(e.hypergraph)

	eg := errgroup.Group{}
	eg.SetLimit(len(frame.Requests))

	for i, request := range frame.Requests {
		eg.Go(func() error {
			e.logger.Debug(
				"processing request",
				zap.Int("message_index", i),
			)

			requestBytes, err := request.ToCanonicalBytes()

			if err != nil {
				e.logger.Error(
					"error serializing request",
					zap.Int("message_index", i),
					zap.Error(err),
				)
				return errors.Wrap(err, "materialize")
			}

			if len(requestBytes) == 0 {
				e.logger.Error(
					"empty request bytes",
					zap.Int("message_index", i),
				)
				return errors.Wrap(errors.New("empty request"), "materialize")
			}

			costBasis, err := e.executionManager.GetCost(requestBytes)
			if err != nil {
				e.logger.Error(
					"invalid message",
					zap.Int("message_index", i),
					zap.Error(err),
				)
				return errors.Wrap(err, "materialize")
			}

			e.currentDifficultyMu.RLock()
			difficulty := uint64(e.currentDifficulty)
			e.currentDifficultyMu.RUnlock()
			var baseline *big.Int
			if costBasis.Cmp(big.NewInt(0)) == 0 {
				baseline = big.NewInt(0)
			} else {
				baseline = reward.GetBaselineFee(
					difficulty,
					e.hypergraph.GetSize(nil, nil).Uint64(),
					costBasis.Uint64(),
					8000000000,
				)
				baseline.Quo(baseline, costBasis)
			}

			_, err = e.executionManager.ProcessMessage(
				frame.Header.FrameNumber,
				new(big.Int).Mul(
					baseline,
					big.NewInt(int64(frame.Header.FeeMultiplierVote)),
				),
				e.appAddress[:32],
				requestBytes,
				state,
			)
			if err != nil {
				e.logger.Error(
					"error processing message",
					zap.Int("message_index", i),
					zap.Error(err),
				)
				return errors.Wrap(err, "materialize")
			}

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	e.logger.Debug(
		"processed transactions",
		zap.Any("current_changeset_count", len(state.Changeset())),
	)

	if err := state.Commit(); err != nil {
		return errors.Wrap(err, "materialize")
	}

	return nil
}

func contextFromShutdownSignal(sig <-chan struct{}) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if sig == nil {
			return
		}
		<-sig
		cancel()
	}()
	return ctx
}

func (e *AppConsensusEngine) getPeerID() PeerID {
	return PeerID{ID: e.getProverAddress()}
}

func (e *AppConsensusEngine) getProverAddress() []byte {
	return e.proverAddress
}

func (e *AppConsensusEngine) getAddressFromPublicKey(publicKey []byte) []byte {
	addressBI, _ := poseidon.HashBytes(publicKey)
	return addressBI.FillBytes(make([]byte, 32))
}

func (e *AppConsensusEngine) calculateFrameSelector(
	header *protobufs.FrameHeader,
) []byte {
	if header == nil || len(header.Output) < 32 {
		return make([]byte, 32)
	}

	selectorBI, _ := poseidon.HashBytes(header.Output)
	return selectorBI.FillBytes(make([]byte, 32))
}

func (e *AppConsensusEngine) calculateRequestsRoot(
	messages []*protobufs.Message,
	txMap map[string][][]byte,
) ([]byte, error) {
	if len(messages) == 0 {
		return make([]byte, 64), nil
	}

	tree := &tries.VectorCommitmentTree{}

	for _, msg := range messages {
		hash := sha3.Sum256(msg.Payload)

		if msg.Hash == nil || !bytes.Equal(msg.Hash, hash[:]) {
			return nil, errors.Wrap(
				errors.New("invalid hash"),
				"calculate requests root",
			)
		}

		err := tree.Insert(
			msg.Hash,
			slices.Concat(txMap[string(msg.Hash)]...),
			nil,
			big.NewInt(0),
		)
		if err != nil {
			return nil, errors.Wrap(err, "calculate requests root")
		}
	}

	commitment := tree.Commit(e.inclusionProver, false)

	if len(commitment) != 74 && len(commitment) != 64 {
		return nil, errors.Errorf("invalid commitment length %d", len(commitment))
	}

	commitHash := sha3.Sum256(commitment)

	set, err := tries.SerializeNonLazyTree(tree)
	if err != nil {
		return nil, errors.Wrap(err, "calculate requests root")
	}

	return slices.Concat(commitHash[:], set), nil
}

func (e *AppConsensusEngine) getConsensusMessageBitmask() []byte {
	return slices.Concat([]byte{0}, e.appFilter)
}

func (e *AppConsensusEngine) getGlobalProverMessageBitmask() []byte {
	return global.GLOBAL_PROVER_BITMASK
}

func (e *AppConsensusEngine) getFrameMessageBitmask() []byte {
	return e.appFilter
}

func (e *AppConsensusEngine) getProverMessageBitmask() []byte {
	return slices.Concat([]byte{0, 0, 0}, e.appFilter)
}

func (e *AppConsensusEngine) getGlobalFrameMessageBitmask() []byte {
	return global.GLOBAL_FRAME_BITMASK
}

func (e *AppConsensusEngine) getGlobalAlertMessageBitmask() []byte {
	return global.GLOBAL_ALERT_BITMASK
}

func (e *AppConsensusEngine) getGlobalPeerInfoMessageBitmask() []byte {
	return global.GLOBAL_PEER_INFO_BITMASK
}

func (e *AppConsensusEngine) getDispatchMessageBitmask() []byte {
	return slices.Concat([]byte{0, 0}, e.appFilter)
}

func (e *AppConsensusEngine) cleanupFrameStore() {
	e.frameStoreMu.Lock()
	defer e.frameStoreMu.Unlock()

	// Local frameStore map is always limited to 360 frames for fast retrieval
	maxFramesToKeep := 360

	if len(e.frameStore) <= maxFramesToKeep {
		return
	}

	// Find the maximum frame number in the local map
	var maxFrameNumber uint64 = 0
	framesByNumber := make(map[uint64][]string)

	for id, frame := range e.frameStore {
		if frame.Header.FrameNumber > maxFrameNumber {
			maxFrameNumber = frame.Header.FrameNumber
		}
		framesByNumber[frame.Header.FrameNumber] = append(
			framesByNumber[frame.Header.FrameNumber],
			id,
		)
	}

	if maxFrameNumber == 0 {
		return
	}

	// Calculate the cutoff point - keep frames newer than maxFrameNumber - 360
	cutoffFrameNumber := uint64(0)
	if maxFrameNumber > 360 {
		cutoffFrameNumber = maxFrameNumber - 360
	}

	// Delete frames older than cutoff from local map
	deletedCount := 0
	for frameNumber, ids := range framesByNumber {
		if frameNumber < cutoffFrameNumber {
			for _, id := range ids {
				delete(e.frameStore, id)
				deletedCount++
			}
		}
	}

	// If archive mode is disabled, also delete from ClockStore
	if !e.config.Engine.ArchiveMode && cutoffFrameNumber > 0 {
		if err := e.clockStore.DeleteShardClockFrameRange(
			e.appAddress,
			0,
			cutoffFrameNumber,
		); err != nil {
			e.logger.Error(
				"failed to delete frames from clock store",
				zap.Error(err),
				zap.Uint64("max_frame", cutoffFrameNumber-1),
			)
		} else {
			e.logger.Debug(
				"deleted frames from clock store",
				zap.Uint64("max_frame", cutoffFrameNumber-1),
			)
		}
	}

	e.logger.Debug(
		"cleaned up frame store",
		zap.Int("deleted_frames", deletedCount),
		zap.Int("remaining_frames", len(e.frameStore)),
		zap.Uint64("max_frame_number", maxFrameNumber),
		zap.Uint64("cutoff_frame_number", cutoffFrameNumber),
		zap.Bool("archive_mode", e.config.Engine.ArchiveMode),
	)
}

func (e *AppConsensusEngine) updateMetricsLoop(
	ctx lifecycle.SignalerContext,
) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error("fatal error encountered", zap.Any("panic", r))
			ctx.Throw(errors.Errorf("fatal unhandled error encountered: %v", r))
		}
	}()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.quit:
			return
		case <-ticker.C:
			// Update time since last proven frame
			e.lastProvenFrameTimeMu.RLock()
			if !e.lastProvenFrameTime.IsZero() {
				timeSince := time.Since(e.lastProvenFrameTime).Seconds()
				timeSinceLastProvenFrame.WithLabelValues(e.appAddressHex).Set(timeSince)
			}
			e.lastProvenFrameTimeMu.RUnlock()

			// Clean up old frames
			e.cleanupFrameStore()
		}
	}
}

func (e *AppConsensusEngine) initializeGenesis() (
	*protobufs.AppShardFrame,
	*protobufs.QuorumCertificate,
) {
	return e.initializeGenesisWithParams(e.config.Engine.Difficulty, nil)
}

func (e *AppConsensusEngine) initializeGenesisWithParams(
	difficulty uint32,
	shardInfo []*protobufs.AppShardInfo,
) (
	*protobufs.AppShardFrame,
	*protobufs.QuorumCertificate,
) {
	// Initialize state roots for hypergraph
	stateRoots := make([][]byte, 4)
	for i := range stateRoots {
		stateRoots[i] = make([]byte, 64)
	}

	// Use provided difficulty or fall back to config
	if difficulty == 0 {
		difficulty = e.config.Engine.Difficulty
	}

	genesisHeader, err := e.frameProver.ProveFrameHeaderGenesis(
		e.appAddress,
		difficulty,
		make([]byte, 516),
		100,
	)
	if err != nil {
		panic(err)
	}

	_, _, _, proverAddress := e.GetProvingKey(e.config.Engine)
	if proverAddress != nil {
		genesisHeader.Prover = proverAddress
	}

	genesisFrame := &protobufs.AppShardFrame{
		Header:   genesisHeader,
		Requests: []*protobufs.MessageBundle{},
	}

	frameIDBI, _ := poseidon.HashBytes(genesisHeader.Output)
	frameID := frameIDBI.FillBytes(make([]byte, 32))
	e.frameStoreMu.Lock()
	e.frameStore[string(frameID)] = genesisFrame
	e.frameStoreMu.Unlock()

	txn, err := e.clockStore.NewTransaction(false)
	if err != nil {
		panic(err)
	}
	if err := e.clockStore.StageShardClockFrame(
		[]byte(genesisFrame.Identity()),
		genesisFrame,
		txn,
	); err != nil {
		txn.Abort()
		e.logger.Error("could not add frame", zap.Error(err))
		return nil, nil
	}
	if err := e.clockStore.CommitShardClockFrame(
		e.appAddress,
		genesisHeader.FrameNumber,
		[]byte(genesisFrame.Identity()),
		nil,
		txn,
		false,
	); err != nil {
		txn.Abort()
		e.logger.Error("could not add frame", zap.Error(err))
		return nil, nil
	}
	genesisQC := &protobufs.QuorumCertificate{
		Rank:        0,
		Filter:      e.appAddress,
		FrameNumber: genesisFrame.Header.FrameNumber,
		Selector:    []byte(genesisFrame.Identity()),
		Timestamp:   0,
		AggregateSignature: &protobufs.BLS48581AggregateSignature{
			PublicKey: &protobufs.BLS48581G2PublicKey{
				KeyValue: make([]byte, 585),
			},
			Signature: make([]byte, 74),
			Bitmask:   bytes.Repeat([]byte{0xff}, 32),
		},
	}
	if err := e.clockStore.PutQuorumCertificate(genesisQC, txn); err != nil {
		txn.Abort()
		e.logger.Error("could not add quorum certificate", zap.Error(err))
		return nil, nil
	}
	if err := txn.Commit(); err != nil {
		txn.Abort()
		e.logger.Error("could not add frame", zap.Error(err))
		return nil, nil
	}
	if err = e.consensusStore.PutLivenessState(
		&models.LivenessState{
			Filter:                  e.appAddress,
			CurrentRank:             1,
			LatestQuorumCertificate: genesisQC,
		},
	); err != nil {
		e.logger.Error("could not add liveness state", zap.Error(err))
		return nil, nil
	}
	if err = e.consensusStore.PutConsensusState(
		&models.ConsensusState[*protobufs.ProposalVote]{
			Filter:                 e.appAddress,
			FinalizedRank:          0,
			LatestAcknowledgedRank: 0,
		},
	); err != nil {
		e.logger.Error("could not add consensus state", zap.Error(err))
		return nil, nil
	}

	e.logger.Info(
		"initialized genesis frame for app consensus",
		zap.String("shard_address", hex.EncodeToString(e.appAddress)),
	)

	return genesisFrame, genesisQC
}

func (e *AppConsensusEngine) ensureGlobalGenesis() error {
	genesisFrameNumber := global.ExpectedGenesisFrameNumber(e.config, e.logger)
	_, err := e.clockStore.GetGlobalClockFrame(genesisFrameNumber)
	if err == nil {
		return nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return errors.Wrap(err, "ensure global genesis")
	}

	e.logger.Info("global genesis missing, initializing")
	_, _, initErr := global.InitializeGenesisState(
		e.logger,
		e.config,
		e.clockStore,
		e.shardsStore,
		e.hypergraph,
		e.consensusStore,
		e.inclusionProver,
		e.keyManager,
		e.proverRegistry,
	)
	if initErr != nil {
		return errors.Wrap(initErr, "ensure global genesis")
	}
	return nil
}

func (e *AppConsensusEngine) ensureAppGenesis() error {
	_, _, err := e.clockStore.GetShardClockFrame(
		e.appAddress,
		0,
		false,
	)
	if err == nil {
		return nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return errors.Wrap(err, "ensure app genesis")
	}
	e.logger.Info(
		"app shard genesis missing, initializing",
		zap.String("shard_address", hex.EncodeToString(e.appAddress)),
	)
	_, _ = e.initializeGenesis()
	return nil
}

// fetchShardInfoFromBootstrap connects to bootstrap peers and fetches shard info
// for this app's address using the GetAppShards RPC.
func (e *AppConsensusEngine) fetchShardInfoFromBootstrap(
	ctx context.Context,
) ([]*protobufs.AppShardInfo, error) {
	bootstrapPeers := e.config.P2P.BootstrapPeers
	if len(bootstrapPeers) == 0 {
		return nil, errors.New("no bootstrap peers configured")
	}

	for _, peerAddr := range bootstrapPeers {
		shardInfo, err := e.tryFetchShardInfoFromPeer(ctx, peerAddr)
		if err != nil {
			e.logger.Debug(
				"failed to fetch shard info from peer",
				zap.String("peer", peerAddr),
				zap.Error(err),
			)
			continue
		}
		if len(shardInfo) > 0 {
			e.logger.Info(
				"fetched shard info from bootstrap peer",
				zap.String("peer", peerAddr),
				zap.Int("shard_count", len(shardInfo)),
			)
			return shardInfo, nil
		}
	}

	return nil, errors.New("failed to fetch shard info from any bootstrap peer")
}

func (e *AppConsensusEngine) tryFetchShardInfoFromPeer(
	ctx context.Context,
	peerAddr string,
) ([]*protobufs.AppShardInfo, error) {
	// Parse multiaddr to extract peer ID and address
	ma, err := multiaddr.StringCast(peerAddr)
	if err != nil {
		return nil, errors.Wrap(err, "parse multiaddr")
	}

	// Extract peer ID from the multiaddr
	peerIDStr, err := ma.ValueForProtocol(multiaddr.P_P2P)
	if err != nil {
		return nil, errors.Wrap(err, "extract peer id")
	}

	peerID, err := peer.Decode(peerIDStr)
	if err != nil {
		return nil, errors.Wrap(err, "decode peer id")
	}

	// Create gRPC connection to the peer
	mga, err := mn.ToNetAddr(ma)
	if err != nil {
		return nil, errors.Wrap(err, "convert multiaddr")
	}

	creds, err := p2p.NewPeerAuthenticator(
		e.logger,
		e.config.P2P,
		nil,
		nil,
		nil,
		nil,
		[][]byte{[]byte(peerID)},
		map[string]channel.AllowedPeerPolicyType{},
		map[string]channel.AllowedPeerPolicyType{},
	).CreateClientTLSCredentials([]byte(peerID))
	if err != nil {
		return nil, errors.Wrap(err, "create credentials")
	}

	conn, err := grpc.NewClient(
		mga.String(),
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		return nil, errors.Wrap(err, "dial peer")
	}
	defer conn.Close()

	client := protobufs.NewGlobalServiceClient(conn)

	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := client.GetAppShards(reqCtx, &protobufs.GetAppShardsRequest{
		ShardKey: e.appAddress,
		Prefix:   []uint32{},
	})
	if err != nil {
		return nil, errors.Wrap(err, "get app shards")
	}

	return resp.GetInfo(), nil
}

// awaitFirstGlobalFrame waits for a global frame to arrive via pubsub and
// returns it. This is used during genesis initialization to get the correct
// difficulty from the network.
func (e *AppConsensusEngine) awaitFirstGlobalFrame(
	ctx context.Context,
) (*protobufs.GlobalFrame, error) {
	e.logger.Info("awaiting first global frame from network for genesis initialization")

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case frame := <-e.genesisInitChan:
		e.logger.Info(
			"received global frame for genesis initialization",
			zap.Uint64("frame_number", frame.Header.FrameNumber),
			zap.Uint32("difficulty", frame.Header.Difficulty),
		)
		return frame, nil
	}
}

func (e *AppConsensusEngine) waitForProverRegistration(
	ctx lifecycle.SignalerContext,
) error {
	logger := e.logger.With(
		zap.String("shard_address", e.appAddressHex),
		zap.String("prover_address", hex.EncodeToString(e.proverAddress)),
	)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		provers, err := e.proverRegistry.GetActiveProvers(e.appAddress)
		if err != nil {
			logger.Warn("could not query prover registry", zap.Error(err))
		} else {
			for _, prover := range provers {
				if bytes.Equal(prover.Address, e.proverAddress) {
					logger.Info("prover present in registry, starting consensus")
					return nil
				}
			}
			proverAddrs := make([]string, 0, len(provers))
			for _, p := range provers {
				proverAddrs = append(proverAddrs, hex.EncodeToString(p.Address))
			}
			logger.Info(
				"waiting for prover registration",
				zap.Int("active_provers_for_filter", len(provers)),
				zap.String("filter", hex.EncodeToString(e.appAddress)),
				zap.Strings("registry_addresses", proverAddrs),
			)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// adjustFeeForTraffic calculates a traffic-adjusted fee multiplier based on
// frame timing
func (e *AppConsensusEngine) adjustFeeForTraffic(baseFee uint64) uint64 {
	// Only adjust fees if reward strategy is "reward-greedy"
	if e.config.Engine.RewardStrategy != "reward-greedy" {
		return baseFee
	}

	// Get the current frame
	currentFrame, _, err := e.clockStore.GetLatestShardClockFrame(e.appAddress)
	if err != nil || currentFrame == nil || currentFrame.Header == nil {
		e.logger.Debug("could not get latest frame for fee adjustment")
		return baseFee
	}

	// Get the previous frame
	if currentFrame.Header.FrameNumber <= 1 {
		// Not enough frames to calculate timing
		return baseFee
	}

	previousFrameNum := currentFrame.Header.FrameNumber - 1

	// Try to get the previous frame
	previousFrame, _, err := e.clockStore.GetShardClockFrame(
		e.appAddress,
		previousFrameNum,
		false,
	)
	if err != nil {
		e.logger.Debug(
			"could not get prior frame for fee adjustment",
			zap.Error(err),
		)
	}

	if previousFrame == nil || previousFrame.Header == nil {
		e.logger.Debug("could not get prior frame for fee adjustment")
		return baseFee
	}

	// Calculate time difference between frames (in milliseconds)
	timeDiff := currentFrame.Header.Timestamp - previousFrame.Header.Timestamp

	// Target is 10 seconds (10000 ms) between frames
	targetTime := int64(10000)

	// Calculate adjustment factor based on timing
	var adjustedFee uint64

	if timeDiff < targetTime {
		// Frames are too fast, decrease fee
		// Calculate percentage faster than target
		percentFaster := (targetTime - timeDiff) * 100 / targetTime

		// Cap adjustment at 10%
		if percentFaster > 10 {
			percentFaster = 10
		}

		// Increase fee
		adjustment := baseFee * uint64(percentFaster) / 100
		adjustedFee = baseFee - adjustment

		// Don't let fee go below 1
		if adjustedFee < 1 {
			adjustedFee = 1
		}

		e.logger.Debug(
			"decreasing fee multiplier due to fast frames",
			zap.Int64("time_diff_ms", timeDiff),
			zap.Uint64("base_fee", baseFee),
			zap.Uint64("adjusted_fee_multiplier", adjustedFee),
		)
	} else if timeDiff > targetTime {
		// Frames are too slow, increase fee
		// Calculate percentage slower than target
		percentSlower := (timeDiff - targetTime) * 100 / targetTime

		// Cap adjustment at 10%
		if percentSlower > 10 {
			percentSlower = 10
		}

		// Increase fee
		adjustment := baseFee * uint64(percentSlower) / 100
		adjustedFee = baseFee + adjustment

		e.logger.Debug(
			"increasing fee due to slow frames",
			zap.Int64("time_diff_ms", timeDiff),
			zap.Uint64("base_fee", baseFee),
			zap.Uint64("adjusted_fee", adjustedFee),
		)
	} else {
		// Timing is perfect, no adjustment needed
		adjustedFee = baseFee
	}

	return adjustedFee
}

func (e *AppConsensusEngine) internalProveFrame(
	rank uint64,
	messages []*protobufs.Message,
	previousFrame *protobufs.AppShardFrame,
) (*protobufs.AppShardFrame, error) {
	signer, _, publicKey, _ := e.GetProvingKey(e.config.Engine)
	if publicKey == nil {
		return nil, errors.New("no proving key available")
	}

	stateRoots, err := e.hypergraph.CommitShard(
		previousFrame.Header.FrameNumber+1,
		e.appAddress,
	)
	if err != nil {
		return nil, err
	}

	if len(stateRoots) == 0 {
		stateRoots = make([][]byte, 4)
		stateRoots[0] = make([]byte, 64)
		stateRoots[1] = make([]byte, 64)
		stateRoots[2] = make([]byte, 64)
		stateRoots[3] = make([]byte, 64)
	}

	// Publish the snapshot generation with the shard's vertex add root so clients
	// can sync against this specific state.
	if len(stateRoots[0]) > 0 {
		if hgCRDT, ok := e.hypergraph.(*hgcrdt.HypergraphCRDT); ok {
			hgCRDT.PublishSnapshot(stateRoots[0])
		}
	}

	txMap := map[string][][]byte{}
	for i, message := range messages {
		e.logger.Debug(
			"locking addresses for message",
			zap.Int("index", i),
			zap.String("tx_hash", hex.EncodeToString(message.Hash)),
		)
		lockedAddrs, err := e.executionManager.Lock(
			previousFrame.Header.FrameNumber+1,
			message.Address,
			message.Payload,
		)
		if err != nil {
			e.logger.Debug(
				"message failed lock",
				zap.Int("message_index", i),
				zap.Error(err),
			)

			err := e.executionManager.Unlock()
			if err != nil {
				e.logger.Error("could not unlock", zap.Error(err))
				return nil, err
			}
		}

		txMap[string(message.Hash)] = lockedAddrs
	}

	err = e.executionManager.Unlock()
	if err != nil {
		e.logger.Error("could not unlock", zap.Error(err))
		return nil, err
	}

	requestsRoot, err := e.calculateRequestsRoot(messages, txMap)
	if err != nil {
		return nil, err
	}

	timestamp := time.Now().UnixMilli()
	difficulty := e.difficultyAdjuster.GetNextDifficulty(
		previousFrame.GetFrameNumber()+1,
		timestamp,
	)

	e.currentDifficultyMu.Lock()
	e.logger.Debug(
		"next difficulty for frame",
		zap.Uint32("previous_difficulty", e.currentDifficulty),
		zap.Uint64("next_difficulty", difficulty),
	)
	e.currentDifficulty = uint32(difficulty)
	e.currentDifficultyMu.Unlock()

	baseFeeMultiplier, err := e.dynamicFeeManager.GetNextFeeMultiplier(
		e.appAddress,
	)
	if err != nil {
		e.logger.Error("could not get next fee multiplier", zap.Error(err))
		return nil, err
	}

	// Adjust fee based on traffic conditions (frame timing)
	currentFeeMultiplier := e.adjustFeeForTraffic(baseFeeMultiplier)

	provers, err := e.proverRegistry.GetActiveProvers(e.appAddress)
	if err != nil {
		return nil, err
	}

	proverIndex := uint8(0)
	for i, p := range provers {
		if bytes.Equal(p.Address, e.getProverAddress()) {
			proverIndex = uint8(i)
			break
		}
	}

	rootCommit := make([]byte, 64)
	if len(requestsRoot[32:]) > 0 {
		tree, err := tries.DeserializeNonLazyTree(requestsRoot[32:])
		if err != nil {
			return nil, err
		}
		rootCommit = tree.Commit(e.inclusionProver, false)
	}

	newHeader, err := e.frameProver.ProveFrameHeader(
		previousFrame.Header,
		e.appAddress,
		rootCommit,
		stateRoots,
		e.getProverAddress(),
		signer,
		timestamp,
		uint32(difficulty),
		currentFeeMultiplier,
		proverIndex,
	)
	if err != nil {
		return nil, err
	}
	newHeader.Rank = rank
	newHeader.PublicKeySignatureBls48581 = nil

	newFrame := &protobufs.AppShardFrame{
		Header:   newHeader,
		Requests: e.messagesToRequests(messages),
	}
	return newFrame, nil
}

func (e *AppConsensusEngine) messagesToRequests(
	messages []*protobufs.Message,
) []*protobufs.MessageBundle {
	requests := make([]*protobufs.MessageBundle, 0, len(messages))
	for _, msg := range messages {
		bundle := &protobufs.MessageBundle{}
		if err := bundle.FromCanonicalBytes(msg.Payload); err == nil {
			requests = append(requests, bundle)
		}
	}
	return requests
}

// SetGlobalClient sets the global client manually, used for tests
func (e *AppConsensusEngine) SetGlobalClient(
	client protobufs.GlobalServiceClient,
) {
	e.globalClient = client
}

func (e *AppConsensusEngine) ensureGlobalClient() error {
	if e.globalClient != nil {
		return nil
	}

	addr, err := multiaddr.StringCast(e.config.P2P.StreamListenMultiaddr)
	if err != nil {
		return errors.Wrap(err, "ensure global client")
	}

	mga, err := mn.ToNetAddr(addr)
	if err != nil {
		return errors.Wrap(err, "ensure global client")
	}

	creds, err := p2p.NewPeerAuthenticator(
		e.logger,
		e.config.P2P,
		nil,
		nil,
		nil,
		nil,
		[][]byte{[]byte(e.pubsub.GetPeerID())},
		map[string]channel.AllowedPeerPolicyType{
			"quilibrium.node.global.pb.GlobalService": channel.OnlySelfPeer,
		},
		map[string]channel.AllowedPeerPolicyType{},
	).CreateClientTLSCredentials([]byte(e.pubsub.GetPeerID()))
	if err != nil {
		return errors.Wrap(err, "ensure global client")
	}

	client, err := grpc.NewClient(
		mga.String(),
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		return errors.Wrap(err, "ensure global client")
	}

	e.globalClient = protobufs.NewGlobalServiceClient(client)
	return nil
}

func (e *AppConsensusEngine) startConsensus(
	trustedRoot *models.CertifiedState[*protobufs.AppShardFrame],
	pending []*models.SignedProposal[
		*protobufs.AppShardFrame,
		*protobufs.ProposalVote,
	],
	ctx lifecycle.SignalerContext,
	ready lifecycle.ReadyFunc,
) error {
	var err error
	e.consensusParticipant, err = participant.NewParticipant[
		*protobufs.AppShardFrame,
		*protobufs.ProposalVote,
		PeerID,
		CollectedCommitments,
	](
		tracing.NewZapTracer(e.logger), // logger
		e,                              // committee
		verification.NewSigner[
			*protobufs.AppShardFrame,
			*protobufs.ProposalVote,
			PeerID,
		](e.votingProvider), // signer
		e.leaderProvider,              // prover
		e.votingProvider,              // voter
		e.notifier,                    // notifier
		e.consensusStore,              // consensusStore
		e.signatureAggregator,         // signatureAggregator
		e,                             // consensusVerifier
		e.voteCollectorDistributor,    // voteCollectorDistributor
		e.timeoutCollectorDistributor, // timeoutCollectorDistributor
		e.forks,                       // forks
		validator.NewValidator[
			*protobufs.AppShardFrame,
			*protobufs.ProposalVote,
		](e, e), // validator
		e.voteAggregator,    // voteAggregator
		e.timeoutAggregator, // timeoutAggregator
		e,                   // finalizer
		e.appAddress,        // filter
		trustedRoot,
		pending,
	)
	if err != nil {
		return err
	}

	ready()
	e.voteAggregator.Start(ctx)
	e.timeoutAggregator.Start(ctx)
	<-lifecycle.AllReady(e.voteAggregator, e.timeoutAggregator)
	e.consensusParticipant.Start(ctx)
	return nil
}

// MakeFinal implements consensus.Finalizer.
func (e *AppConsensusEngine) MakeFinal(stateID models.Identity) error {
	// In a standard BFT-only approach, this would be how frames are finalized on
	// the time reel. But we're PoMW, so we don't rely on BFT for anything outside
	// of basic coordination. If the protocol were ever to move to something like
	// PoS, this would be one of the touch points to revisit.
	return nil
}

// OnCurrentRankDetails implements consensus.Consumer.
func (e *AppConsensusEngine) OnCurrentRankDetails(
	currentRank uint64,
	finalizedRank uint64,
	currentLeader models.Identity,
) {
	e.logger.Info(
		"entered new rank",
		zap.Uint64("current_rank", currentRank),
		zap.String("current_leader", hex.EncodeToString([]byte(currentLeader))),
	)
}

// OnDoubleProposeDetected implements consensus.Consumer.
func (e *AppConsensusEngine) OnDoubleProposeDetected(
	proposal1 *models.State[*protobufs.AppShardFrame],
	proposal2 *models.State[*protobufs.AppShardFrame],
) {
	select {
	case <-e.haltCtx.Done():
		return
	default:
	}
	e.eventDistributor.Publish(typesconsensus.ControlEvent{
		Type: typesconsensus.ControlEventAppEquivocation,
		Data: &consensustime.AppEvent{
			Type:    consensustime.TimeReelEventEquivocationDetected,
			Frame:   *proposal2.State,
			OldHead: *proposal1.State,
			Message: fmt.Sprintf(
				"equivocation at rank %d",
				proposal1.Rank,
			),
		},
	})
}

// OnEventProcessed implements consensus.Consumer.
func (e *AppConsensusEngine) OnEventProcessed() {}

// OnFinalizedState implements consensus.Consumer.
func (e *AppConsensusEngine) OnFinalizedState(
	state *models.State[*protobufs.AppShardFrame],
) {
}

// OnInvalidStateDetected implements consensus.Consumer.
func (e *AppConsensusEngine) OnInvalidStateDetected(
	err *models.InvalidProposalError[
		*protobufs.AppShardFrame,
		*protobufs.ProposalVote,
	],
) {
} // Presently a no-op, up for reconsideration

// OnLocalTimeout implements consensus.Consumer.
func (e *AppConsensusEngine) OnLocalTimeout(currentRank uint64) {}

// OnOwnProposal implements consensus.Consumer.
func (e *AppConsensusEngine) OnOwnProposal(
	proposal *models.SignedProposal[
		*protobufs.AppShardFrame,
		*protobufs.ProposalVote,
	],
	targetPublicationTime time.Time,
) {
	go func() {
		select {
		case <-time.After(time.Until(targetPublicationTime)):
		case <-e.ShutdownSignal():
			return
		}
		var priorTC *protobufs.TimeoutCertificate = nil
		if proposal.PreviousRankTimeoutCertificate != nil {
			priorTC =
				proposal.PreviousRankTimeoutCertificate.(*protobufs.TimeoutCertificate)
		}

		pbProposal := &protobufs.AppShardProposal{
			State:                       *proposal.State.State,
			ParentQuorumCertificate:     proposal.Proposal.State.ParentQuorumCertificate.(*protobufs.QuorumCertificate),
			PriorRankTimeoutCertificate: priorTC,
			Vote:                        *proposal.Vote,
		}
		data, err := pbProposal.ToCanonicalBytes()
		if err != nil {
			e.logger.Error("could not serialize proposal", zap.Error(err))
			return
		}

		txn, err := e.clockStore.NewTransaction(false)
		if err != nil {
			e.logger.Error("could not create transaction", zap.Error(err))
			return
		}

		if err := e.clockStore.PutProposalVote(txn, *proposal.Vote); err != nil {
			e.logger.Error("could not put vote", zap.Error(err))
			txn.Abort()
			return
		}

		err = e.clockStore.StageShardClockFrame(
			[]byte(proposal.State.Identifier),
			*proposal.State.State,
			txn,
		)
		if err != nil {
			e.logger.Error("could not put frame candidate", zap.Error(err))
			txn.Abort()
			return
		}

		if err := txn.Commit(); err != nil {
			e.logger.Error("could not commit transaction", zap.Error(err))
			txn.Abort()
			return
		}

		e.voteAggregator.AddState(proposal)
		e.consensusParticipant.SubmitProposal(proposal)

		if err := e.pubsub.PublishToBitmask(
			e.getConsensusMessageBitmask(),
			data,
		); err != nil {
			e.logger.Error("could not publish", zap.Error(err))
		}
	}()
}

// OnOwnTimeout implements consensus.Consumer.
func (e *AppConsensusEngine) OnOwnTimeout(
	timeout *models.TimeoutState[*protobufs.ProposalVote],
) {
	select {
	case <-e.haltCtx.Done():
		return
	default:
	}

	var priorTC *protobufs.TimeoutCertificate
	if timeout.PriorRankTimeoutCertificate != nil {
		priorTC =
			timeout.PriorRankTimeoutCertificate.(*protobufs.TimeoutCertificate)
	}

	pbTimeout := &protobufs.TimeoutState{
		LatestQuorumCertificate:     timeout.LatestQuorumCertificate.(*protobufs.QuorumCertificate),
		PriorRankTimeoutCertificate: priorTC,
		Vote:                        *timeout.Vote,
		TimeoutTick:                 timeout.TimeoutTick,
		Timestamp:                   uint64(time.Now().UnixMilli()),
	}
	data, err := pbTimeout.ToCanonicalBytes()
	if err != nil {
		e.logger.Error("could not serialize timeout", zap.Error(err))
		return
	}

	e.timeoutAggregator.AddTimeout(timeout)

	if err := e.pubsub.PublishToBitmask(
		e.getConsensusMessageBitmask(),
		data,
	); err != nil {
		e.logger.Error("could not publish", zap.Error(err))
	}
}

// OnOwnVote implements consensus.Consumer.
func (e *AppConsensusEngine) OnOwnVote(
	vote **protobufs.ProposalVote,
	recipientID models.Identity,
) {
	select {
	case <-e.haltCtx.Done():
		return
	default:
	}

	data, err := (*vote).ToCanonicalBytes()
	if err != nil {
		e.logger.Error("could not serialize timeout", zap.Error(err))
		return
	}

	e.voteAggregator.AddVote(vote)

	if err := e.pubsub.PublishToBitmask(
		e.getConsensusMessageBitmask(),
		data,
	); err != nil {
		e.logger.Error("could not publish", zap.Error(err))
	}
}

// OnPartialTimeoutCertificate implements consensus.Consumer.
func (e *AppConsensusEngine) OnPartialTimeoutCertificate(
	currentRank uint64,
	partialTimeoutCertificate *consensus.PartialTimeoutCertificateCreated,
) {
}

// OnQuorumCertificateTriggeredRankChange implements consensus.Consumer.
func (e *AppConsensusEngine) OnQuorumCertificateTriggeredRankChange(
	oldRank uint64,
	newRank uint64,
	qc models.QuorumCertificate,
) {
	e.logger.Debug("adding certified state", zap.Uint64("rank", newRank-1))

	parentQC, err := e.clockStore.GetLatestQuorumCertificate(e.appAddress)
	if err != nil {
		e.logger.Error("no latest quorum certificate", zap.Error(err))
		return
	}

	txn, err := e.clockStore.NewTransaction(false)
	if err != nil {
		e.logger.Error("could not create transaction", zap.Error(err))
		return
	}

	aggregateSig := &protobufs.BLS48581AggregateSignature{
		Signature: qc.GetAggregatedSignature().GetSignature(),
		PublicKey: &protobufs.BLS48581G2PublicKey{
			KeyValue: qc.GetAggregatedSignature().GetPubKey(),
		},
		Bitmask: qc.GetAggregatedSignature().GetBitmask(),
	}
	if err := e.clockStore.PutQuorumCertificate(
		&protobufs.QuorumCertificate{
			Filter:             qc.GetFilter(),
			Rank:               qc.GetRank(),
			FrameNumber:        qc.GetFrameNumber(),
			Selector:           []byte(qc.Identity()),
			AggregateSignature: aggregateSig,
		},
		txn,
	); err != nil {
		e.logger.Error("could not insert quorum certificate", zap.Error(err))
		txn.Abort()
		return
	}

	if err := txn.Commit(); err != nil {
		e.logger.Error("could not commit transaction", zap.Error(err))
		txn.Abort()
		return
	}

	e.frameStoreMu.RLock()
	frame, ok := e.frameStore[qc.Identity()]
	e.frameStoreMu.RUnlock()

	if !ok {
		frame, err = e.clockStore.GetStagedShardClockFrame(
			e.appAddress,
			qc.GetFrameNumber(),
			[]byte(qc.Identity()),
			false,
		)
		if err == nil {
			ok = true
		}
	}

	if !ok {
		e.logger.Error(
			"no frame for quorum certificate",
			zap.Uint64("rank", newRank-1),
			zap.Uint64("frame_number", qc.GetFrameNumber()),
		)
		current := (*e.forks.FinalizedState().State)
		peer, err := e.getRandomProverPeerId()
		if err != nil {
			e.logger.Error("could not get random peer", zap.Error(err))
			return
		}
		e.syncProvider.AddState(
			[]byte(peer),
			current.Header.FrameNumber,
			[]byte(current.Identity()),
		)
		return
	}

	if !bytes.Equal(frame.Header.ParentSelector, parentQC.Selector) {
		e.logger.Error(
			"quorum certificate does not match frame parent",
			zap.String(
				"frame_parent_selector",
				hex.EncodeToString(frame.Header.ParentSelector),
			),
			zap.String(
				"parent_qc_selector",
				hex.EncodeToString(parentQC.Selector),
			),
			zap.Uint64("parent_qc_rank", parentQC.Rank),
		)
		return
	}

	priorRankTC, err := e.clockStore.GetTimeoutCertificate(
		e.appAddress,
		qc.GetRank()-1,
	)
	if err != nil {
		e.logger.Debug("no prior rank TC to include", zap.Uint64("rank", newRank-1))
	}

	vote, err := e.clockStore.GetProposalVote(
		e.appAddress,
		frame.GetRank(),
		[]byte(frame.Source()),
	)
	if err != nil {
		e.logger.Error(
			"cannot find proposer's vote",
			zap.Uint64("rank", newRank-1),
			zap.String("proposer", hex.EncodeToString([]byte(frame.Source()))),
		)
		return
	}

	frame.Header.PublicKeySignatureBls48581 = aggregateSig

	latest, _, err := e.clockStore.GetLatestShardClockFrame(e.appAddress)
	if err != nil {
		e.logger.Error("could not obtain latest frame", zap.Error(err))
		return
	}
	if latest.Header.FrameNumber+1 != frame.Header.FrameNumber ||
		!bytes.Equal([]byte(latest.Identity()), frame.Header.ParentSelector) {
		e.logger.Debug(
			"not next frame, cannot advance",
			zap.Uint64("latest_frame_number", latest.Header.FrameNumber),
			zap.Uint64("new_frame_number", frame.Header.FrameNumber),
			zap.String(
				"latest_frame_selector",
				hex.EncodeToString([]byte(latest.Identity())),
			),
			zap.String(
				"new_frame_number",
				hex.EncodeToString(frame.Header.ParentSelector),
			),
		)
		return
	}

	txn, err = e.clockStore.NewTransaction(false)
	if err != nil {
		e.logger.Error("could not create transaction", zap.Error(err))
		return
	}

	if err := e.materialize(
		txn,
		frame,
	); err != nil {
		_ = txn.Abort()
		e.logger.Error("could not materialize frame requests", zap.Error(err))
		return
	}
	if err := e.clockStore.CommitShardClockFrame(
		e.appAddress,
		frame.GetFrameNumber(),
		[]byte(frame.Identity()),
		[]*tries.RollingFrecencyCritbitTrie{},
		txn,
		false,
	); err != nil {
		_ = txn.Abort()
		e.logger.Error("could not put global frame", zap.Error(err))
		return
	}

	if err := e.clockStore.PutCertifiedAppShardState(
		&protobufs.AppShardProposal{
			State:                       frame,
			ParentQuorumCertificate:     parentQC,
			PriorRankTimeoutCertificate: priorRankTC,
			Vote:                        vote,
		},
		txn,
	); err != nil {
		e.logger.Error("could not insert certified state", zap.Error(err))
		txn.Abort()
		return
	}

	if err := txn.Commit(); err != nil {
		e.logger.Error("could not commit transaction", zap.Error(err))
		txn.Abort()
		return
	}

	nextLeader, err := e.LeaderForRank(newRank)
	if err != nil {
		e.logger.Error("could not determine next prover", zap.Error(err))
		return
	}

	if nextLeader != e.Self() {
		go func() {
			info, err := e.proverRegistry.GetActiveProvers(frame.Header.Address)
			if err != nil {
				return
			}

			myIndex := -1
			ids := [][]byte{}
			for i := range info {
				if bytes.Equal(info[i].Address, e.getProverAddress()) {
					myIndex = i
				}
				if !bytes.Equal([]byte(nextLeader), info[i].Address) {
					ids = append(ids, info[i].Address)
				}
			}

			if myIndex == -1 {
				return
			}

			challenge := sha3.Sum256([]byte(frame.Identity()))
			proof := e.frameProver.CalculateMultiProof(
				challenge,
				frame.Header.Difficulty,
				ids,
				uint32(myIndex),
			)
			e.proofCacheMu.Lock()
			e.proofCache[newRank] = proof
			e.proofCacheMu.Unlock()
		}()
	}
}

// OnRankChange implements consensus.Consumer.
func (e *AppConsensusEngine) OnRankChange(oldRank uint64, newRank uint64) {
	if e.currentRank == newRank {
		return
	}
	e.currentRank = newRank
	err := e.ensureGlobalClient()
	if err != nil {
		e.logger.Error("cannot confirm cross-shard locks", zap.Error(err))
		return
	}

	frame, err := e.appTimeReel.GetHead()
	if err != nil {
		e.logger.Error("cannot obtain time reel head", zap.Error(err))
		return
	}

	res, err := e.globalClient.GetLockedAddresses(
		context.Background(),
		&protobufs.GetLockedAddressesRequest{
			ShardAddress: e.appAddress,
			FrameNumber:  frame.Header.FrameNumber,
		},
	)
	if err != nil {
		e.logger.Error("cannot confirm cross-shard locks", zap.Error(err))
		return
	}

	// Build a map of transaction hashes to their committed status
	txMap := map[string]bool{}
	txIncluded := map[string]bool{}
	txMessageMap := map[string]*protobufs.Message{}
	txHashesInOrder := []string{}
	txShardRefs := map[string]map[string]struct{}{}
	e.collectedMessagesMu.Lock()
	collected := make([]*protobufs.Message, len(e.collectedMessages))
	copy(collected, e.collectedMessages)
	e.collectedMessages = []*protobufs.Message{}
	e.collectedMessagesMu.Unlock()

	e.provingMessagesMu.Lock()
	e.provingMessages = []*protobufs.Message{}
	e.provingMessagesMu.Unlock()

	for _, req := range collected {
		tx, err := req.ToCanonicalBytes()
		if err != nil {
			e.logger.Error("cannot confirm cross-shard locks", zap.Error(err))
			return
		}

		txHash := sha3.Sum256(tx)
		e.logger.Debug(
			"adding transaction in frame to commit check",
			zap.String("tx_hash", hex.EncodeToString(txHash[:])),
		)
		hashStr := string(txHash[:])
		txMap[hashStr] = false
		txIncluded[hashStr] = true
		txMessageMap[hashStr] = req
		txHashesInOrder = append(txHashesInOrder, hashStr)
	}

	// Check that transactions are committed in our shard and collect shard
	// addresses
	shardAddressesSet := make(map[string]bool)
	for _, tx := range res.Transactions {
		e.logger.Debug(
			"checking transaction from global map",
			zap.String("tx_hash", hex.EncodeToString(tx.TransactionHash)),
		)
		hashStr := string(tx.TransactionHash)
		if _, ok := txMap[hashStr]; ok {
			txMap[hashStr] = tx.Committed

			// Extract shard addresses from each locked transaction's shard addresses
			for _, shardAddr := range tx.ShardAddresses {
				// Extract the applicable shard address (can be shorter than the full
				// address)
				extractedShards := e.extractShardAddresses(shardAddr)
				for _, extractedShard := range extractedShards {
					shardAddrStr := string(extractedShard)
					shardAddressesSet[shardAddrStr] = true
					if txShardRefs[hashStr] == nil {
						txShardRefs[hashStr] = make(map[string]struct{})
					}
					txShardRefs[hashStr][shardAddrStr] = struct{}{}
				}
			}
		}
	}

	// Check that all transactions are committed in our shard
	for _, committed := range txMap {
		if !committed {
			e.logger.Error("transaction not committed in local shard")
			return
		}
	}

	// Check cross-shard locks for each unique shard address
	for shardAddrStr := range shardAddressesSet {
		shardAddr := []byte(shardAddrStr)

		// Skip our own shard since we already checked it
		if bytes.Equal(shardAddr, e.appAddress) {
			continue
		}

		// Query the global client for locked addresses in this shard
		shardRes, err := e.globalClient.GetLockedAddresses(
			context.Background(),
			&protobufs.GetLockedAddressesRequest{
				ShardAddress: shardAddr,
				FrameNumber:  frame.Header.FrameNumber,
			},
		)
		if err != nil {
			e.logger.Error(
				"failed to get locked addresses for shard",
				zap.String("shard_addr", hex.EncodeToString(shardAddr)),
				zap.Error(err),
			)
			for hashStr, shards := range txShardRefs {
				if _, ok := shards[shardAddrStr]; ok {
					txIncluded[hashStr] = false
				}
			}
			continue
		}

		// Check that all our transactions are committed in this shard
		for txHashStr := range txMap {
			committedInShard := false
			for _, tx := range shardRes.Transactions {
				if string(tx.TransactionHash) == txHashStr {
					committedInShard = tx.Committed
					break
				}
			}

			if !committedInShard {
				e.logger.Error("cannot confirm cross-shard locks")
				txIncluded[txHashStr] = false
			}
		}
	}

	e.provingMessagesMu.Lock()
	e.provingMessages = e.provingMessages[:0]
	for _, hashStr := range txHashesInOrder {
		if txIncluded[hashStr] {
			e.provingMessages = append(e.provingMessages, txMessageMap[hashStr])
		}
	}
	e.provingMessagesMu.Unlock()

	commitments, err := e.livenessProvider.Collect(
		context.Background(),
		frame.Header.FrameNumber,
		newRank,
	)
	if err != nil {
		e.logger.Error("could not collect commitments", zap.Error(err))
		return
	}

	if err := e.broadcastLivenessCheck(newRank, commitments); err != nil {
		e.logger.Error("could not broadcast liveness check", zap.Error(err))
	}
}

func (e *AppConsensusEngine) broadcastLivenessCheck(
	newRank uint64,
	commitments CollectedCommitments,
) error {
	signer, _, publicKey, _ := e.GetProvingKey(e.config.Engine)
	if signer == nil || publicKey == nil {
		return errors.Wrap(
			errors.New("no proving key available"),
			"broadcast liveness check",
		)
	}

	check := &protobufs.ProverLivenessCheck{
		Filter:         slices.Clone(e.appAddress),
		Rank:           newRank,
		FrameNumber:    commitments.frameNumber,
		Timestamp:      time.Now().UnixMilli(),
		CommitmentHash: slices.Clone(commitments.commitmentHash),
	}

	payload, err := check.ConstructSignaturePayload()
	if err != nil {
		return errors.Wrap(err, "construct liveness payload")
	}

	sig, err := signer.SignWithDomain(payload, check.GetSignatureDomain())
	if err != nil {
		return errors.Wrap(err, "sign liveness check")
	}

	check.PublicKeySignatureBls48581 = &protobufs.BLS48581AddressedSignature{
		Address:   e.getAddressFromPublicKey(publicKey),
		Signature: sig,
	}

	bytes, err := check.ToCanonicalBytes()
	if err != nil {
		return errors.Wrap(err, "marshal liveness check")
	}

	if err := e.pubsub.PublishToBitmask(
		e.getConsensusMessageBitmask(),
		bytes,
	); err != nil {
		return errors.Wrap(err, "publish liveness check")
	}

	return nil
}

// OnReceiveProposal implements consensus.Consumer.
func (e *AppConsensusEngine) OnReceiveProposal(
	currentRank uint64,
	proposal *models.SignedProposal[
		*protobufs.AppShardFrame,
		*protobufs.ProposalVote,
	],
) {
}

// OnReceiveQuorumCertificate implements consensus.Consumer.
func (e *AppConsensusEngine) OnReceiveQuorumCertificate(
	currentRank uint64,
	qc models.QuorumCertificate,
) {
}

// OnReceiveTimeoutCertificate implements consensus.Consumer.
func (e *AppConsensusEngine) OnReceiveTimeoutCertificate(
	currentRank uint64,
	tc models.TimeoutCertificate,
) {
}

// OnStart implements consensus.Consumer.
func (e *AppConsensusEngine) OnStart(currentRank uint64) {}

// OnStartingTimeout implements consensus.Consumer.
func (e *AppConsensusEngine) OnStartingTimeout(
	startTime time.Time,
	endTime time.Time,
) {
}

// OnStateIncorporated implements consensus.Consumer.
func (e *AppConsensusEngine) OnStateIncorporated(
	state *models.State[*protobufs.AppShardFrame],
) {
	e.frameStoreMu.Lock()
	e.frameStore[state.Identifier] = *state.State
	e.frameStoreMu.Unlock()
}

// OnTimeoutCertificateTriggeredRankChange implements consensus.Consumer.
func (e *AppConsensusEngine) OnTimeoutCertificateTriggeredRankChange(
	oldRank uint64,
	newRank uint64,
	tc models.TimeoutCertificate,
) {
	e.logger.Debug(
		"inserting timeout certificate",
		zap.Uint64("rank", tc.GetRank()),
	)

	txn, err := e.clockStore.NewTransaction(false)
	if err != nil {
		e.logger.Error("could not create transaction", zap.Error(err))
		return
	}

	qc := tc.GetLatestQuorumCert()
	err = e.clockStore.PutTimeoutCertificate(&protobufs.TimeoutCertificate{
		Filter:      tc.GetFilter(),
		Rank:        tc.GetRank(),
		LatestRanks: tc.GetLatestRanks(),
		LatestQuorumCertificate: &protobufs.QuorumCertificate{
			Rank:        qc.GetRank(),
			FrameNumber: qc.GetFrameNumber(),
			Selector:    []byte(qc.Identity()),
			AggregateSignature: &protobufs.BLS48581AggregateSignature{
				Signature: qc.GetAggregatedSignature().GetSignature(),
				PublicKey: &protobufs.BLS48581G2PublicKey{
					KeyValue: qc.GetAggregatedSignature().GetPubKey(),
				},
				Bitmask: qc.GetAggregatedSignature().GetBitmask(),
			},
		},
		AggregateSignature: &protobufs.BLS48581AggregateSignature{
			Signature: tc.GetAggregatedSignature().GetSignature(),
			PublicKey: &protobufs.BLS48581G2PublicKey{
				KeyValue: tc.GetAggregatedSignature().GetPubKey(),
			},
			Bitmask: tc.GetAggregatedSignature().GetBitmask(),
		},
	}, txn)
	if err != nil {
		txn.Abort()
		e.logger.Error("could not insert timeout certificate")
		return
	}

	if err := txn.Commit(); err != nil {
		txn.Abort()
		e.logger.Error("could not commit transaction", zap.Error(err))
	}
}

// VerifyQuorumCertificate implements consensus.Verifier.
func (e *AppConsensusEngine) VerifyQuorumCertificate(
	quorumCertificate models.QuorumCertificate,
) error {
	qc, ok := quorumCertificate.(*protobufs.QuorumCertificate)
	if !ok {
		return errors.Wrap(
			errors.New("invalid quorum certificate"),
			"verify quorum certificate",
		)
	}

	if err := qc.Validate(); err != nil {
		return models.NewInvalidFormatError(
			errors.Wrap(err, "verify quorum certificate"),
		)
	}

	// genesis qc is special:
	if quorumCertificate.GetRank() == 0 {
		genqc, err := e.clockStore.GetQuorumCertificate(e.appAddress, 0)
		if err != nil {
			return errors.Wrap(err, "verify quorum certificate")
		}

		if genqc.Equals(quorumCertificate) {
			return nil
		}
	}

	provers, err := e.proverRegistry.GetActiveProvers(e.appAddress)
	if err != nil {
		return errors.Wrap(err, "verify quorum certificate")
	}

	pubkeys := [][]byte{}
	signatures := [][]byte{}
	if ((len(provers) + 7) / 8) > len(qc.AggregateSignature.Bitmask) {
		return models.ErrInvalidSignature
	}
	for i, prover := range provers {
		if qc.AggregateSignature.Bitmask[i/8]&(1<<(i%8)) == (1 << (i % 8)) {
			pubkeys = append(pubkeys, prover.PublicKey)
			signatures = append(signatures, qc.AggregateSignature.GetSignature())
		}
	}

	aggregationCheck, err := e.blsConstructor.Aggregate(pubkeys, signatures)
	if err != nil {
		return models.ErrInvalidSignature
	}

	if !bytes.Equal(
		qc.AggregateSignature.GetPubKey(),
		aggregationCheck.GetAggregatePublicKey(),
	) {
		return models.ErrInvalidSignature
	}

	if valid := e.blsConstructor.VerifySignatureRaw(
		qc.AggregateSignature.GetPubKey(),
		qc.AggregateSignature.GetSignature(),
		verification.MakeVoteMessage(e.appAddress, qc.Rank, qc.Identity()),
		slices.Concat([]byte("appshard"), e.appAddress),
	); !valid {
		return models.ErrInvalidSignature
	}

	return nil
}

// VerifyTimeoutCertificate implements consensus.Verifier.
func (e *AppConsensusEngine) VerifyTimeoutCertificate(
	timeoutCertificate models.TimeoutCertificate,
) error {
	tc, ok := timeoutCertificate.(*protobufs.TimeoutCertificate)
	if !ok {
		return errors.Wrap(
			errors.New("invalid timeout certificate"),
			"verify timeout certificate",
		)
	}

	if err := tc.Validate(); err != nil {
		return models.NewInvalidFormatError(
			errors.Wrap(err, "verify timeout certificate"),
		)
	}

	provers, err := e.proverRegistry.GetActiveProvers(e.appAddress)
	if err != nil {
		return errors.Wrap(err, "verify timeout certificate")
	}

	pubkeys := [][]byte{}
	messages := [][]byte{}
	signatures := [][]byte{}
	if ((len(provers) + 7) / 8) > len(tc.AggregateSignature.Bitmask) {
		return models.ErrInvalidSignature
	}

	idx := 0
	for i, prover := range provers {
		if tc.AggregateSignature.Bitmask[i/8]&(1<<(i%8)) == (1 << (i % 8)) {
			pubkeys = append(pubkeys, prover.PublicKey)
			signatures = append(signatures, tc.AggregateSignature.GetSignature())
			messages = append(messages, verification.MakeTimeoutMessage(
				e.appAddress,
				tc.Rank,
				tc.LatestRanks[idx],
			))
			idx++
		}
	}

	aggregationCheck, err := e.blsConstructor.Aggregate(pubkeys, signatures)
	if err != nil {
		return models.ErrInvalidSignature
	}

	if !bytes.Equal(
		tc.AggregateSignature.GetPubKey(),
		aggregationCheck.GetAggregatePublicKey(),
	) {
		return models.ErrInvalidSignature
	}

	if valid := e.blsConstructor.VerifyMultiMessageSignatureRaw(
		pubkeys,
		tc.AggregateSignature.GetSignature(),
		messages,
		slices.Concat([]byte("appshardtimeout"), e.appAddress),
	); !valid {
		return models.ErrInvalidSignature
	}

	return nil
}

// VerifyVote implements consensus.Verifier.
func (e *AppConsensusEngine) VerifyVote(
	vote **protobufs.ProposalVote,
) error {
	if vote == nil || *vote == nil {
		return errors.Wrap(errors.New("nil vote"), "verify vote")
	}

	if err := (*vote).Validate(); err != nil {
		return models.NewInvalidFormatError(
			errors.Wrap(err, "verify vote"),
		)
	}

	provers, err := e.proverRegistry.GetActiveProvers(e.appAddress)
	if err != nil {
		return errors.Wrap(err, "verify vote")
	}

	var pubkey []byte
	for _, p := range provers {
		if bytes.Equal(p.Address, (*vote).PublicKeySignatureBls48581.Address) {
			pubkey = p.PublicKey
			break
		}
	}

	if bytes.Equal(pubkey, []byte{}) {
		return models.ErrInvalidSignature
	}

	if valid := e.blsConstructor.VerifySignatureRaw(
		pubkey,
		(*vote).PublicKeySignatureBls48581.Signature[:74],
		verification.MakeVoteMessage(e.appAddress, (*vote).Rank, (*vote).Source()),
		slices.Concat([]byte("appshard"), e.appAddress),
	); !valid {
		return models.ErrInvalidSignature
	}

	return nil
}

func (e *AppConsensusEngine) getPendingProposals(
	frameNumber uint64,
) []*models.SignedProposal[
	*protobufs.AppShardFrame,
	*protobufs.ProposalVote,
] {
	root, _, err := e.clockStore.GetShardClockFrame(e.appAddress, frameNumber, false)
	if err != nil {
		panic(err)
	}

	result := []*models.SignedProposal[
		*protobufs.AppShardFrame,
		*protobufs.ProposalVote,
	]{}

	e.logger.Debug("getting pending proposals", zap.Uint64("start", frameNumber))

	startRank := root.Header.Rank
	latestQC, err := e.clockStore.GetLatestQuorumCertificate(e.appAddress)
	if err != nil {
		panic(err)
	}
	endRank := latestQC.Rank

	parent, err := e.clockStore.GetQuorumCertificate(e.appAddress, startRank)
	if err != nil {
		panic(err)
	}

	for rank := startRank + 1; rank <= endRank; rank++ {
		nextQC, err := e.clockStore.GetQuorumCertificate(e.appAddress, rank)
		if err != nil {
			e.logger.Debug("no qc for rank", zap.Error(err))
			break
		}

		value, err := e.clockStore.GetStagedShardClockFrame(
			e.appAddress,
			nextQC.FrameNumber,
			[]byte(nextQC.Identity()),
			false,
		)
		if err != nil {
			e.logger.Debug("no frame for qc", zap.Error(err))
			break
		}

		var priorTCModel models.TimeoutCertificate = nil
		if parent.Rank != rank-1 {
			priorTC, _ := e.clockStore.GetTimeoutCertificate(e.appAddress, rank-1)
			if priorTC != nil {
				priorTCModel = priorTC
			}
		}

		vote := &protobufs.ProposalVote{
			Filter:      e.appAddress,
			Rank:        value.GetRank(),
			FrameNumber: value.Header.FrameNumber,
			Selector:    []byte(value.Identity()),
			PublicKeySignatureBls48581: &protobufs.BLS48581AddressedSignature{
				Signature: value.Header.PublicKeySignatureBls48581.Signature,
				Address:   []byte(value.Source()),
			},
		}
		result = append(result, &models.SignedProposal[
			*protobufs.AppShardFrame,
			*protobufs.ProposalVote,
		]{
			Proposal: models.Proposal[*protobufs.AppShardFrame]{
				State: &models.State[*protobufs.AppShardFrame]{
					Rank:                    value.GetRank(),
					Identifier:              value.Identity(),
					ProposerID:              vote.Identity(),
					ParentQuorumCertificate: parent,
					State:                   &value,
				},
				PreviousRankTimeoutCertificate: priorTCModel,
			},
			Vote: &vote,
		})
		parent = nextQC
	}
	return result
}

func (e *AppConsensusEngine) getRandomProverPeerId() (peer.ID, error) {
	provers, err := e.proverRegistry.GetActiveProvers(e.appAddress)
	if err != nil {
		e.logger.Error(
			"could not get active provers for sync",
			zap.Error(err),
		)
	}
	if len(provers) == 0 {
		return "", err
	}
	index := rand.Intn(len(provers))
	registry, err := e.signerRegistry.GetKeyRegistryByProver(
		provers[index].Address,
	)
	if err != nil {
		e.logger.Debug(
			"could not get registry for prover",
			zap.Error(err),
		)
		return "", err
	}

	if registry == nil || registry.IdentityKey == nil {
		e.logger.Debug("registry for prover not found")
		return "", err
	}

	pk, err := pcrypto.UnmarshalEd448PublicKey(registry.IdentityKey.KeyValue)
	if err != nil {
		e.logger.Debug(
			"could not parse pub key",
			zap.Error(err),
		)
		return "", err
	}

	id, err := peer.IDFromPublicKey(pk)
	if err != nil {
		e.logger.Debug(
			"could not derive peer id",
			zap.Error(err),
		)
		return "", err
	}

	return id, nil
}

func (e *AppConsensusEngine) getPeerIDOfProver(
	prover []byte,
) (peer.ID, error) {
	registry, err := e.signerRegistry.GetKeyRegistryByProver(prover)
	if err != nil {
		e.logger.Debug(
			"could not get registry for prover",
			zap.Error(err),
		)
		return "", err
	}

	if registry == nil || registry.IdentityKey == nil {
		e.logger.Debug("registry for prover not found")
		return "", errors.New("registry not found for prover")
	}

	pk, err := pcrypto.UnmarshalEd448PublicKey(registry.IdentityKey.KeyValue)
	if err != nil {
		e.logger.Debug(
			"could not parse pub key",
			zap.Error(err),
		)
		return "", err
	}

	id, err := peer.IDFromPublicKey(pk)
	if err != nil {
		e.logger.Debug(
			"could not derive peer id",
			zap.Error(err),
		)
		return "", err
	}

	return id, nil
}

// extractShardAddresses extracts all possible shard addresses from a
// transaction address
func (e *AppConsensusEngine) extractShardAddresses(txAddress []byte) [][]byte {
	var shardAddresses [][]byte

	// Get the full path from the transaction address
	path := GetFullPath(txAddress)

	// The first 43 nibbles (258 bits) represent the base shard address
	// We need to extract all possible shard addresses by considering path
	// segments after the 43rd nibble
	if len(path) <= 43 {
		// If the path is too short, just return the original address truncated to
		// 32 bytes
		if len(txAddress) >= 32 {
			shardAddresses = append(shardAddresses, txAddress[:32])
		}
		return shardAddresses
	}

	// Convert the first 43 nibbles to bytes (base shard address)
	baseShardAddr := txAddress[:32]
	l1 := up2p.GetBloomFilterIndices(baseShardAddr, 256, 3)
	candidates := map[string]struct{}{}

	// Now generate all possible shard addresses by extending the path
	// Each additional nibble after the 43rd creates a new shard address
	for i := 43; i < len(path); i++ {
		// Create a new shard address by extending the base with this path segment
		extendedAddr := make([]byte, 32)
		copy(extendedAddr, baseShardAddr)

		// Add the path segment as a byte
		extendedAddr = append(extendedAddr, byte(path[i]))

		candidates[string(extendedAddr)] = struct{}{}
	}

	shards, err := e.shardsStore.GetAppShards(
		slices.Concat(l1, baseShardAddr),
		[]uint32{},
	)
	if err != nil {
		return [][]byte{}
	}

	for _, shard := range shards {
		if _, ok := candidates[string(
			slices.Concat(shard.L2, uint32ToBytes(shard.Path)),
		)]; ok {
			shardAddresses = append(shardAddresses, shard.L2)
		}
	}

	return shardAddresses
}

var _ consensus.DynamicCommittee = (*AppConsensusEngine)(nil)
