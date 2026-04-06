package global

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mr-tron/base58"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/pkg/errors"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/forks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/notifications/pubsub"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/aggregator"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/provers"
	qsync "source.quilibrium.com/quilibrium/monorepo/node/consensus/sync"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/tracing"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/voting"
	"source.quilibrium.com/quilibrium/monorepo/node/dispatch"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	tokenintrinsics "source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/manager"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	qgrpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	keyedaggregator "source.quilibrium.com/quilibrium/monorepo/node/keyedaggregator"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p/onion"
	"source.quilibrium.com/quilibrium/monorepo/node/rpc"
	mgr "source.quilibrium.com/quilibrium/monorepo/node/worker"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/rpm"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/compiler"
	typesconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	typesdispatch "source.quilibrium.com/quilibrium/monorepo/types/dispatch"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	typeskeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
	tp2p "source.quilibrium.com/quilibrium/monorepo/types/p2p"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/types/worker"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

var GLOBAL_CONSENSUS_BITMASK = []byte{0x00}
var GLOBAL_FRAME_BITMASK = []byte{0x00, 0x00}
var GLOBAL_PROVER_BITMASK = []byte{0x00, 0x00, 0x00}
var GLOBAL_PEER_INFO_BITMASK = []byte{0x00, 0x00, 0x00, 0x00}

var GLOBAL_ALERT_BITMASK = bytes.Repeat([]byte{0x00}, 16)

// ArchiveServiceCapabilityID is advertised in PeerInfo by archive nodes
// so non-archive nodes can discover them for frame retrieval.
const ArchiveServiceCapabilityID = uint32(0x00050001)

type coverageStreak struct {
	StartFrame uint64
	LastFrame  uint64
	Count      uint64
}

type LockedTransaction struct {
	TransactionHash []byte
	ShardAddresses  [][]byte
	Prover          []byte
	Committed       bool
	Filled          bool
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

func (e *GlobalConsensusEngine) addGlobalMessageSubscriber(
	ch chan *protobufs.StreamGlobalMessagesResponse,
) {
	e.globalMessageSubscribersMu.Lock()
	e.globalMessageSubscribers[ch] = struct{}{}
	e.globalMessageSubscribersMu.Unlock()
}

func (e *GlobalConsensusEngine) removeGlobalMessageSubscriber(
	ch chan *protobufs.StreamGlobalMessagesResponse,
) {
	e.globalMessageSubscribersMu.Lock()
	delete(e.globalMessageSubscribers, ch)
	e.globalMessageSubscribersMu.Unlock()
}

func (e *GlobalConsensusEngine) broadcastGlobalMessage(
	data []byte,
	bitmask []byte,
) {
	msg := &protobufs.StreamGlobalMessagesResponse{
		Data:    data,
		Bitmask: bitmask,
	}

	e.globalMessageSubscribersMu.RLock()
	defer e.globalMessageSubscribersMu.RUnlock()

	for ch := range e.globalMessageSubscribers {
		select {
		case ch <- msg:
		default:
		}
	}
}

// SetArchiveClient configures the engine to route frame retrieval and prover
// messages through the given archive client instead of pubsub.
func (e *GlobalConsensusEngine) SetArchiveClient(c *rpc.ArchiveClient) {
	e.archiveClient = c
}

// publishProverMessage sends data to the prover bitmask. When an archive
// client is configured (non-archive node), it routes through the archive's
// SubmitMessage RPC instead of local pubsub.
func (e *GlobalConsensusEngine) publishProverMessage(data []byte) error {
	if e.archiveClient != nil {
		return e.archiveClient.SubmitMessage(context.Background(), data)
	}
	return e.pubsub.PublishToBitmask(GLOBAL_PROVER_BITMASK, data)
}

// GlobalConsensusEngine  uses the generic state machine for consensus
//
// Mutex ordering (acquire in this order to prevent deadlocks):
//
//	materializer.commitBarrier > materializer.materializeMu > shardCommitmentMu
//	materializer.commitBarrier > frameStoreMu
//
// All other mutexes protect independent state and must not be held
// simultaneously with the above or each other.
type GlobalConsensusEngine struct {
	*lifecycle.ComponentManager
	protobufs.GlobalServiceServer

	logger             *zap.Logger
	config             *config.Config
	pubsub             tp2p.PubSub
	hypergraph         hypergraph.Hypergraph
	hypergraphStore    store.HypergraphStore
	keyManager         typeskeys.KeyManager
	keyStore           store.KeyStore
	clockStore         store.ClockStore
	shardsStore        store.ShardsStore
	consensusStore     consensus.ConsensusStore[*protobufs.ProposalVote]
	frameProver        crypto.FrameProver
	inclusionProver    crypto.InclusionProver
	signerRegistry     typesconsensus.SignerRegistry
	proverRegistry     typesconsensus.ProverRegistry
	dynamicFeeManager  typesconsensus.DynamicFeeManager
	appFrameValidator  typesconsensus.AppFrameValidator
	frameValidator     typesconsensus.GlobalFrameValidator
	difficultyAdjuster typesconsensus.DifficultyAdjuster
	rewardIssuance     typesconsensus.RewardIssuance
	eventDistributor   typesconsensus.EventDistributor
	dispatchService    typesdispatch.DispatchService
	globalTimeReel     *consensustime.GlobalTimeReel
	blsConstructor          crypto.BlsConstructor
	executionManager        *manager.ExecutionEngineManager
	mixnet                  typesconsensus.Mixnet
	peerInfoManager         tp2p.PeerInfoManager
	workerManager           worker.WorkerManager
	workerAllocator         *WorkerAllocator
	frameChainChecker       *FrameChainChecker
	alertPublicKey          []byte
	hasSentKeyBundle  bool
	lastObservedFrame atomic.Uint64
	lastRejectFrame   atomic.Uint64

	lastProposalFrameNumber     atomic.Uint64
	lastFrameMessageFrameNumber atomic.Uint64

	// Message routing
	messageRouter       *MessageRouter
	globalProposalQueue chan *protobufs.GlobalProposal

	// Emergency halt
	haltCtx context.Context
	halt    context.CancelFunc

	// Internal state
	proverAddress             []byte
	quit                      chan struct{}
	wg                        sync.WaitGroup
	minimumProvers            func() uint64
	coverageMonitor           *CoverageMonitor
	messageCollectors         *keyedaggregator.SequencedCollectors[sequencedGlobalMessage]
	messageAggregator         *keyedaggregator.SequencedAggregator[sequencedGlobalMessage]
	globalMessageSpillover    map[uint64][][]byte
	globalSpilloverMu         sync.Mutex
	currentDifficulty         uint32
	currentDifficultyMu       sync.RWMutex
	lastProvenFrameTime       time.Time
	lastProvenFrameTimeMu     sync.RWMutex
	frameStore                map[string]*protobufs.GlobalFrame
	frameStoreMu              sync.RWMutex
	appFrameStore             map[string]*protobufs.AppShardFrame
	appFrameStoreMu           sync.RWMutex
	proverOnlyMode            atomic.Bool
	shardFrameDedup           map[string]uint64
	shardFrameDedupMu         sync.Mutex
	peerInfoDigestCache       map[string]struct{}
	peerInfoDigestCacheMu     sync.Mutex
	keyRegistryDigestCache    map[string]struct{}
	keyRegistryDigestCacheMu  sync.Mutex
	peerAuthCache             map[string]time.Time
	peerAuthCacheMu           sync.RWMutex
	appShardCache             map[string]*appShardCacheEntry
	appShardCacheMu           sync.RWMutex
	appShardCacheRank         uint64
	globalFrameCache          *lru.Cache[uint64, *protobufs.GlobalFrame]

	// Transaction cross-shard lock tracking
	txLockMap map[uint64]map[string]map[string]*LockedTransaction
	txLockMu  sync.RWMutex

	// Consensus protocol: owns HotStuff BFT machinery, provider
	// implementations, cross-provider state, and sync provider.
	// Always non-nil (created for both archive and non-archive nodes).
	consensusProtocol *ConsensusProtocol

	// Frame materializer: owns commitBarrier, materializeMu,
	// lastMaterializedFrame, and prover root sync state.
	materializer *FrameMaterializer

	// Authentication provider
	authProvider channel.AuthenticationProvider

	// Synchronization service
	hyperSync protobufs.HypergraphComparisonServiceServer

	// Private routing
	onionRouter  *onion.OnionRouter
	onionService *onion.GRPCTransport

	// gRPC server for services
	grpcServer   *grpc.Server
	grpcListener net.Listener

	// Global message streaming to workers
	globalMessageSubscribersMu sync.RWMutex
	globalMessageSubscribers   map[chan *protobufs.StreamGlobalMessagesResponse]struct{}

	// Archive client for non-archive nodes (nil when using pubsub)
	archiveClient *rpc.ArchiveClient
}

// isConsensusParticipant returns true when this node runs full HotStuff
// consensus (archive nodes and devnet single-node mode).
func (e *GlobalConsensusEngine) isConsensusParticipant() bool {
	return e.config.P2P.Network == 99 || e.config.Engine.ArchiveMode
}

// NewGlobalConsensusEngine creates a new global consensus engine using the
// generic state machine
func NewGlobalConsensusEngine(
	logger *zap.Logger,
	config *config.Config,
	frameTimeMillis int64,
	ps tp2p.PubSub,
	hypergraph hypergraph.Hypergraph,
	keyManager typeskeys.KeyManager,
	keyStore store.KeyStore,
	frameProver crypto.FrameProver,
	inclusionProver crypto.InclusionProver,
	signerRegistry typesconsensus.SignerRegistry,
	proverRegistry typesconsensus.ProverRegistry,
	dynamicFeeManager typesconsensus.DynamicFeeManager,
	appFrameValidator typesconsensus.AppFrameValidator,
	frameValidator typesconsensus.GlobalFrameValidator,
	difficultyAdjuster typesconsensus.DifficultyAdjuster,
	rewardIssuance typesconsensus.RewardIssuance,
	eventDistributor typesconsensus.EventDistributor,
	globalTimeReel *consensustime.GlobalTimeReel,
	clockStore store.ClockStore,
	inboxStore store.InboxStore,
	hypergraphStore store.HypergraphStore,
	shardsStore store.ShardsStore,
	consensusStore consensus.ConsensusStore[*protobufs.ProposalVote],
	workerStore store.WorkerStore,
	encryptedChannel channel.EncryptedChannel,
	bulletproofProver crypto.BulletproofProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	compiler compiler.CircuitCompiler,
	blsConstructor crypto.BlsConstructor,
	peerInfoManager tp2p.PeerInfoManager,
) (*GlobalConsensusEngine, error) {
	engine := &GlobalConsensusEngine{
		logger:                      logger,
		config:                      config,
		pubsub:                      ps,
		hypergraph:                  hypergraph,
		hypergraphStore:             hypergraphStore,
		keyManager:                  keyManager,
		keyStore:                    keyStore,
		clockStore:                  clockStore,
		shardsStore:                 shardsStore,
		consensusStore:              consensusStore,
		frameProver:                 frameProver,
		inclusionProver:             inclusionProver,
		signerRegistry:              signerRegistry,
		proverRegistry:              proverRegistry,
		blsConstructor:              blsConstructor,
		dynamicFeeManager:           dynamicFeeManager,
		appFrameValidator:           appFrameValidator,
		frameValidator:              frameValidator,
		difficultyAdjuster:          difficultyAdjuster,
		rewardIssuance:              rewardIssuance,
		eventDistributor:            eventDistributor,
		globalTimeReel:              globalTimeReel,
		peerInfoManager:             peerInfoManager,
		frameStore:                  make(map[string]*protobufs.GlobalFrame),
		appFrameStore:               make(map[string]*protobufs.AppShardFrame),
		globalProposalQueue:         make(chan *protobufs.GlobalProposal, 1000),
		currentDifficulty:           config.Engine.Difficulty,
		lastProvenFrameTime:         time.Now(),
		shardFrameDedup:             make(map[string]uint64),
		peerInfoDigestCache:         make(map[string]struct{}),
		keyRegistryDigestCache:      make(map[string]struct{}),
		peerAuthCache:               make(map[string]time.Time),
		alertPublicKey:              []byte{},
		txLockMap:                   make(map[uint64]map[string]map[string]*LockedTransaction),
		appShardCache:               make(map[string]*appShardCacheEntry),
		globalMessageSpillover:      make(map[uint64][][]byte),
		globalMessageSubscribers:    make(map[chan *protobufs.StreamGlobalMessagesResponse]struct{}),
	}

	frameCache, err := lru.New[uint64, *protobufs.GlobalFrame](128)
	if err != nil {
		return nil, errors.Wrap(err, "create global frame cache")
	}
	engine.globalFrameCache = frameCache
	engine.frameChainChecker = NewFrameChainChecker(clockStore, logger)

	if err := engine.initGlobalMessageAggregator(); err != nil {
		return nil, err
	}

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

	engine.materializer = NewFrameMaterializer(engine)
	globalTimeReel.SetMaterializeFunc(engine.materializer.materialize)
	globalTimeReel.SetRevertFunc(engine.revert)

	// Set minimum provers
	if config.P2P.Network == 99 {
		logger.Debug("devnet detected, setting minimum provers to 1")
		engine.minimumProvers = func() uint64 { return 1 }
	} else {
		engine.minimumProvers = func() uint64 {
			currentSet, err := engine.proverRegistry.GetActiveProvers(nil)
			if err != nil {
				return 1
			}

			if len(currentSet) > 6 {
				return 6
			}

			return uint64(len(currentSet)) * 2 / 3
		}
	}

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

	// Create the consensus protocol sub-struct
	cp := &ConsensusProtocol{
		engine:                 engine,
		proposalCache:          make(map[uint64]*protobufs.GlobalProposal),
		pendingCertifiedParents: make(map[uint64]*protobufs.GlobalProposal),
		activeProveRanks:       make(map[uint64]struct{}),
		shardCommitmentTrees:   make([]*tries.VectorCommitmentTree, 256),
		shardCommitmentKeySets: make([]map[string]struct{}, 256),
	}
	engine.consensusProtocol = cp

	// Create provider implementations
	cp.votingProvider = &GlobalVotingProvider{engine: engine}
	cp.leaderProvider = &GlobalLeaderProvider{engine: engine}
	cp.livenessProvider = &GlobalLivenessProvider{engine: engine}
	cp.signatureAggregator = aggregator.WrapSignatureAggregator(
		engine.blsConstructor,
		engine.proverRegistry,
		nil,
	)
	voteAggregationDistributor := voting.NewGlobalVoteAggregationDistributor()
	cp.voteCollectorDistributor =
		voteAggregationDistributor.VoteCollectorDistributor
	timeoutAggregationDistributor :=
		voting.NewGlobalTimeoutAggregationDistributor()
	cp.timeoutCollectorDistributor =
		timeoutAggregationDistributor.TimeoutCollectorDistributor

	// Create the worker allocator (proposer set below after workerManager exists).
	engine.workerAllocator = NewWorkerAllocator(engine, nil)

	// Create the worker manager — callbacks forward to the allocator.
	engine.workerManager = mgr.NewWorkerManager(
		workerStore,
		logger,
		config,
		engine.workerAllocator.ProposeWorkerJoin,
		engine.workerAllocator.DecideWorkerJoins,
		engine.workerAllocator.ProposeWorkerLeave,
		engine.workerAllocator.DecideWorkerLeaves,
	)
	if !config.Engine.ArchiveMode {
		strategy := provers.RewardGreedy
		if config.Engine.RewardStrategy != "reward-greedy" {
			strategy = provers.DataGreedy
		}
		engine.workerAllocator.proposer = provers.NewManager(
			logger,
			workerStore,
			engine.workerManager,
			8000000000,
			strategy,
		)
	}

	// Create coverage monitor
	engine.coverageMonitor = NewCoverageMonitor(
		logger,
		config,
		proverRegistry,
		hypergraph,
		eventDistributor,
		keyManager,
		shardsStore,
	)
	engine.coverageMonitor.getProverAddress = engine.getProverAddress
	engine.coverageMonitor.getLastObservedFrame = func() uint64 {
		return engine.lastObservedFrame.Load()
	}
	engine.coverageMonitor.getProverOnlyMode = func() *atomic.Bool {
		return &engine.proverOnlyMode
	}
	engine.coverageMonitor.publishProverMessage = engine.publishProverMessage
	engine.coverageMonitor.minimumProvers = engine.minimumProvers

	// Initialize blacklist map on the coverage monitor
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
			engine.coverageMonitor.blacklistMap[string(addressBytes)] = true
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

	// Create the message router. ShutdownSignal is wired later (after
	// ComponentManager is built) via a closure that captures the engine.
	engine.messageRouter = NewMessageRouter(
		logger,
		ps,
		engine.haltCtx,
		nil, // shutdownSignal wired after ComponentManager.Build()
		engine.globalProposalQueue,
	)

	// Wire handler callbacks
	engine.messageRouter.isConsensusParticipant = engine.isConsensusParticipant
	engine.messageRouter.broadcastGlobalMessage = engine.broadcastGlobalMessage
	engine.messageRouter.initMixnet = func() {
		provingKey, _, _, _ := engine.GetProvingKey(engine.config.Engine)
		engine.mixnet = rpm.NewRPMMixnet(engine.logger, provingKey, engine.proverRegistry, nil)
	}
	engine.messageRouter.handleGlobalConsensusMessage = engine.handleGlobalConsensusMessage
	engine.messageRouter.handleAppFrameMessage = engine.handleAppFrameMessage
	engine.messageRouter.handleShardConsensusMessage = engine.handleShardConsensusMessage
	engine.messageRouter.handleProverMessage = engine.handleProverMessage
	engine.messageRouter.handleFrameMessage = engine.handleFrameMessage
	engine.messageRouter.handlePeerInfoMessage = engine.handlePeerInfoMessage
	engine.messageRouter.handleAlertMessage = engine.handleAlertMessage
	engine.messageRouter.handleGlobalProposal = engine.handleGlobalProposal
	engine.messageRouter.validateGlobalConsensusMessage = engine.validateGlobalConsensusMessage
	engine.messageRouter.validateAppFrameMessage = engine.validateAppFrameMessage
	engine.messageRouter.validateShardConsensusMessage = engine.validateShardConsensusMessage
	engine.messageRouter.validateFrameMessage = engine.validateFrameMessage
	engine.messageRouter.validateProverMessage = engine.validateProverMessage
	engine.messageRouter.validatePeerInfoMessage = engine.validatePeerInfoMessage
	engine.messageRouter.validateAlertMessage = engine.validateAlertMessage

	// Create dispatch service
	engine.dispatchService = dispatch.NewDispatchService(
		inboxStore,
		logger,
		keyManager,
		ps,
	)

	// Create execution engine manager
	executionManager, err := manager.NewExecutionEngineManager(
		logger,
		config,
		hypergraph,
		clockStore,
		shardsStore,
		keyManager,
		inclusionProver,
		bulletproofProver,
		verEnc,
		decafConstructor,
		compiler,
		frameProver,
		rewardIssuance,
		proverRegistry,
		blsConstructor,
		true, // includeGlobal
	)
	if err != nil {
		return nil, errors.Wrap(err, "new global consensus engine")
	}
	engine.executionManager = executionManager

	// Initialize metrics
	engineState.Set(0) // EngineStateStopped
	currentDifficulty.Set(float64(config.Engine.Difficulty))
	executorsRegistered.Set(0)
	shardCommitmentsCollected.Set(0)

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
		peerInfoManager,
		signerRegistry,
		keyManager,
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

	// Set up gRPC server with TLS credentials
	if err := engine.setupGRPCServer(); err != nil {
		return nil, errors.Wrap(err, "failed to setup gRPC server")
	}

	componentBuilder := lifecycle.NewComponentManagerBuilder()

	// Add worker manager background process (if applicable)
	if !engine.config.Engine.ArchiveMode {
		componentBuilder.AddWorker(func(
			ctx lifecycle.SignalerContext,
			ready lifecycle.ReadyFunc,
		) {
			if err := engine.workerManager.Start(ctx); err != nil {
				engine.logger.Error("could not start worker manager", zap.Error(err))
				ctx.Throw(err)
				return
			}
			ready()
			<-ctx.Done()
			if err := engine.workerManager.Stop(); err != nil {
				engine.logger.Warn("error stopping worker manager", zap.Error(err))
			}
		})
	}

	// Add execution engines
	componentBuilder.AddWorker(engine.executionManager.Start)
	componentBuilder.AddWorker(engine.globalTimeReel.Start)
	componentBuilder.AddWorker(engine.startGlobalMessageAggregator)

	engine.ensureGenesisProvers()

	if err := engine.initConsensusParticipation(
		componentBuilder,
		voteAggregationDistributor,
		timeoutAggregationDistributor,
	); err != nil {
		return nil, err
	}

	engine.registerWorkers(componentBuilder)

	engine.ComponentManager = componentBuilder.Build()

	// Wire up the shutdown signal callback now that ComponentManager exists.
	engine.coverageMonitor.shutdownSignal = engine.ShutdownSignal
	engine.messageRouter.shutdownSignal = engine.ShutdownSignal

	if hgWithShutdown, ok := engine.hyperSync.(interface {
		SetShutdownContext(context.Context)
	}); ok {
		hgWithShutdown.SetShutdownContext(
			contextFromShutdownSignal(engine.ShutdownSignal()),
		)
	}

	// Wire up pubsub shutdown to the component's shutdown signal
	engine.pubsub.SetShutdownContext(
		contextFromShutdownSignal(engine.ShutdownSignal()),
	)

	// Set self peer ID on hypergraph to allow unlimited self-sync sessions
	if hgWithSelfPeer, ok := engine.hyperSync.(interface {
		SetSelfPeerID(string)
	}); ok {
		hgWithSelfPeer.SetSelfPeerID(peer.ID(ps.GetPeerID()).String())
	}

	// Subscribe to pubsub bitmasks. These calls spawn handler goroutines
	// immediately, and the handlers reference ShutdownSignal() which
	// requires ComponentManager to be non-nil. That's why subscriptions
	// must happen after componentBuilder.Build() above.

	// Subscribe to global consensus if participating
	err = engine.messageRouter.subscribeToGlobalConsensus()
	if err != nil {
		return nil, err
	}

	// Subscribe to shard consensus messages to broker lock agreement
	err = engine.messageRouter.subscribeToShardConsensusMessages()
	if err != nil {
		return nil, errors.Wrap(err, "start")
	}

	// Subscribe to frames
	err = engine.messageRouter.subscribeToFrameMessages()
	if err != nil {
		return nil, errors.Wrap(err, "start")
	}

	// Subscribe to prover messages
	err = engine.messageRouter.subscribeToProverMessages()
	if err != nil {
		return nil, errors.Wrap(err, "start")
	}

	// Subscribe to peer info messages
	err = engine.messageRouter.subscribeToPeerInfoMessages()
	if err != nil {
		return nil, errors.Wrap(err, "start")
	}

	// Subscribe to alert messages
	err = engine.messageRouter.subscribeToAlertMessages()
	if err != nil {
		return nil, errors.Wrap(err, "start")
	}

	return engine, nil
}

// ensureGenesisProvers initializes the prover tree with genesis data if it has
// not been populated yet (first boot).
func (e *GlobalConsensusEngine) ensureGenesisProvers() {
	adds := e.hypergraph.(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(
		tries.ShardKey{
			L1: [3]byte{},
			L2: [32]byte(bytes.Repeat([]byte{0xff}, 32)),
		},
	)

	if lc, _ := adds.GetTree().GetMetadata(); lc == 0 {
		if e.config.P2P.Network == 0 {
			genesisData := e.getMainnetGenesisJSON()
			if genesisData == nil {
				panic("no genesis data")
			}

			state := hgstate.NewHypergraphState(e.hypergraph)

			err := e.establishMainnetGenesisProvers(state, genesisData)
			if err != nil {
				e.logger.Error("failed to establish provers", zap.Error(err))
				panic(err)
			}

			err = state.Commit()
			if err != nil {
				e.logger.Error("failed to commit", zap.Error(err))
				panic(err)
			}
		} else {
			e.establishTestnetGenesisProvers()
		}

		err := e.proverRegistry.Refresh()
		if err != nil {
			panic(err)
		}
	}
}

// initConsensusParticipation sets up the consensus state machine (vote/timeout
// aggregators, forks, sync provider) when this node is an active consensus
// participant, or just the sync provider when it is not.
func (e *GlobalConsensusEngine) initConsensusParticipation(
	componentBuilder lifecycle.ComponentManagerBuilder,
	voteAggregationDistributor *pubsub.VoteAggregationDistributor[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
	],
	timeoutAggregationDistributor *pubsub.TimeoutAggregationDistributor[
		*protobufs.ProposalVote,
	],
) error {
	if e.isConsensusParticipant() {
		latest, err := e.consensusStore.GetConsensusState(nil)
		var state *models.CertifiedState[*protobufs.GlobalFrame]
		var pending []*models.SignedProposal[
			*protobufs.GlobalFrame,
			*protobufs.ProposalVote,
		]
		establishGenesis := func() {
			frame, qc := e.initializeGenesis()
			state = &models.CertifiedState[*protobufs.GlobalFrame]{
				State: &models.State[*protobufs.GlobalFrame]{
					Rank:       0,
					Identifier: frame.Identity(),
					State:      &frame,
				},
				CertifyingQuorumCertificate: qc,
			}
			pending = []*models.SignedProposal[
				*protobufs.GlobalFrame,
				*protobufs.ProposalVote,
			]{}
			if _, rebuildErr := e.consensusProtocol.rebuildShardCommitments(
				frame.Header.FrameNumber+1,
				frame.Header.Rank+1,
			); rebuildErr != nil {
				panic(rebuildErr)
			}
		}
		if err != nil {
			establishGenesis()
		} else {
			if latest.LatestTimeout != nil {
				e.logger.Info(
					"obtained latest consensus state",
					zap.Uint64("finalized_rank", latest.FinalizedRank),
					zap.Uint64("latest_acknowledged_rank", latest.LatestAcknowledgedRank),
					zap.Uint64("latest_timeout_rank", latest.LatestTimeout.Rank),
					zap.Uint64("latest_timeout_tick", latest.LatestTimeout.TimeoutTick),
					zap.Uint64(
						"latest_timeout_qc_rank",
						latest.LatestTimeout.LatestQuorumCertificate.GetRank(),
					),
				)
			} else {
				e.logger.Info(
					"obtained latest consensus state",
					zap.Uint64("finalized_rank", latest.FinalizedRank),
					zap.Uint64("latest_acknowledged_rank", latest.LatestAcknowledgedRank),
				)
			}
			qc, err := e.clockStore.GetQuorumCertificate(
				nil,
				latest.FinalizedRank,
			)
			if err != nil {
				panic(err)
			} else {
				if qc.GetFrameNumber() == 0 {
					establishGenesis()
				} else {
					frame, err := e.clockStore.GetGlobalClockFrameCandidate(
						qc.GetFrameNumber(),
						qc.Selector,
					)
					if err != nil {
						panic(err)
					} else {
						if _, rebuildErr := e.consensusProtocol.rebuildShardCommitments(
							frame.Header.FrameNumber+1,
							frame.Header.Rank+1,
						); rebuildErr != nil {
							e.logger.Warn(
								"could not initialize shard commitments from latest frame",
								zap.Error(rebuildErr),
							)
						}
						parentFrame, err := e.clockStore.GetGlobalClockFrameCandidate(
							qc.GetFrameNumber()-1,
							frame.Header.ParentSelector,
						)
						if err != nil {
							panic(err)
						} else {
							parentQC, err := e.clockStore.GetQuorumCertificate(
								nil,
								parentFrame.GetRank(),
							)
							if err != nil {
								panic(err)
							} else {
								state = &models.CertifiedState[*protobufs.GlobalFrame]{
									State: &models.State[*protobufs.GlobalFrame]{
										Rank:                    frame.GetRank(),
										Identifier:              frame.Identity(),
										ProposerID:              frame.Source(),
										ParentQuorumCertificate: parentQC,
										Timestamp:               frame.GetTimestamp(),
										State:                   &frame,
									},
									CertifyingQuorumCertificate: qc,
								}
								pending = e.consensusProtocol.getPendingProposals(frame.Header.FrameNumber)
							}
						}
					}
				}
			}
			as, err := e.shardsStore.RangeAppShards()
			e.logger.Info("verifying app shard information")
			if err != nil || len(as) == 0 {
				e.initializeGenesis()
			}
		}
		cp := e.consensusProtocol
		liveness, err := e.consensusStore.GetLivenessState(nil)
		if err == nil {
			cp.currentRank = liveness.CurrentRank
		}
		cp.voteAggregator, err = voting.NewGlobalVoteAggregator[GlobalPeerID](
			tracing.NewZapTracer(e.logger),
			cp,
			voteAggregationDistributor,
			cp.signatureAggregator,
			cp.votingProvider,
			func(qc models.QuorumCertificate) {
				select {
				case <-e.haltCtx.Done():
					return
				default:
				}
				cp.consensusParticipant.OnQuorumCertificateConstructedFromVotes(qc)
			},
			state.Rank()+1,
		)
		if err != nil {
			return err
		}

		if latest == nil {
			if err := e.rebuildAppShardCache(0); err != nil {
				e.logger.Warn("could not prime app shard cache", zap.Error(err))
			}
		} else {
			if err := e.rebuildAppShardCache(latest.FinalizedRank); err != nil {
				e.logger.Warn("could not prime app shard cache", zap.Error(err))
			}
		}
		cp.timeoutAggregator, err = voting.NewGlobalTimeoutAggregator[GlobalPeerID](
			tracing.NewZapTracer(e.logger),
			cp,
			cp,
			cp.signatureAggregator,
			timeoutAggregationDistributor,
			cp.votingProvider,
			state.Rank()+1,
		)

		notifier := pubsub.NewDistributor[
			*protobufs.GlobalFrame,
			*protobufs.ProposalVote,
		]()
		notifier.AddConsumer(cp)
		cp.notifier = notifier

		cpForks, err := forks.NewForks(state, cp, notifier)
		if err != nil {
			return err
		}

		cp.forks = cpForks

		cp.syncProvider = qsync.NewSyncProvider[
			*protobufs.GlobalFrame,
			*protobufs.GlobalProposal,
		](
			e.logger,
			cpForks,
			e.proverRegistry,
			e.signerRegistry,
			e.peerInfoManager,
			qsync.NewGlobalSyncClient(
				e.frameProver,
				e.blsConstructor,
				e,
				e.config,
			),
			e.hypergraph,
			e.config,
			nil,
			e.proverAddress,
			nil,
		)

		// Add sync provider
		componentBuilder.AddWorker(cp.syncProvider.Start)

		// Add consensus
		componentBuilder.AddWorker(func(
			ctx lifecycle.SignalerContext,
			ready lifecycle.ReadyFunc,
		) {
			if err := cp.startConsensus(state, pending, ctx, ready); err != nil {
				e.logger.Error("could not start consensus", zap.Error(err))
				ctx.Throw(err)
				return
			}

			<-ctx.Done()
			<-lifecycle.AllDone(cp.voteAggregator, cp.timeoutAggregator)
		})
	} else {
		as, err := e.shardsStore.RangeAppShards()
		e.logger.Info("verifying app shard information")
		if err != nil || len(as) == 0 {
			e.initializeGenesis()
		}

		e.consensusProtocol.syncProvider = qsync.NewSyncProvider[
			*protobufs.GlobalFrame,
			*protobufs.GlobalProposal,
		](
			e.logger,
			nil,
			e.proverRegistry,
			e.signerRegistry,
			e.peerInfoManager,
			qsync.NewGlobalSyncClient(
				e.frameProver,
				e.blsConstructor,
				e,
				e.config,
			),
			e.hypergraph,
			e.config,
			nil,
			e.proverAddress,
			nil,
		)
	}

	return nil
}

// registerWorkers adds all background worker goroutines (queue processors,
// periodic tasks, gRPC server) to the component builder.
func (e *GlobalConsensusEngine) registerWorkers(
	componentBuilder lifecycle.ComponentManagerBuilder,
) {
	componentBuilder.AddWorker(e.peerInfoManager.Start)

	// NOTE: subscribe calls are deferred until after ComponentManager is built
	// (see the constructor). The handler closures reference e.ShutdownSignal()
	// which panics if ComponentManager is nil. Since Subscribe spawns goroutines
	// immediately, a message arriving before Build() would hit a nil receiver.

	addReadyWorker := func(fn func(lifecycle.SignalerContext)) {
		componentBuilder.AddWorker(func(
			ctx lifecycle.SignalerContext,
			ready lifecycle.ReadyFunc,
		) {
			ready()
			fn(ctx)
		})
	}

	addReadyWorker(e.messageRouter.processGlobalConsensusMessageQueue)
	addReadyWorker(e.messageRouter.processShardConsensusMessageQueue)
	addReadyWorker(e.messageRouter.processFrameMessageQueue)
	addReadyWorker(e.pollFramesFromArchive)
	addReadyWorker(e.messageRouter.processProverMessageQueue)
	addReadyWorker(e.messageRouter.processPeerInfoMessageQueue)
	addReadyWorker(e.messageRouter.processAlertMessageQueue)
	addReadyWorker(e.messageRouter.processGlobalProposalQueue)
	addReadyWorker(e.reportPeerInfoPeriodically)

	componentBuilder.AddWorker(e.eventDistributor.Start)
	addReadyWorker(e.eventDistributorLoop)
	addReadyWorker(e.updateMetrics)

	if !e.config.Engine.ArchiveMode {
		addReadyWorker(e.monitorNodeHealth)
	}

	addReadyWorker(e.pruneTxLocksPeriodically)

	if e.grpcServer != nil {
		// Register all services with the gRPC server
		e.RegisterServices(e.grpcServer)

		// Start serving the gRPC server
		componentBuilder.AddWorker(func(
			ctx lifecycle.SignalerContext,
			ready lifecycle.ReadyFunc,
		) {
			go func() {
				if err := e.grpcServer.Serve(e.grpcListener); err != nil {
					e.logger.Error("gRPC server error", zap.Error(err))
					ctx.Throw(err)
				}
			}()
			ready()
			e.logger.Info("started gRPC server",
				zap.String("address", e.grpcListener.Addr().String()))
			<-ctx.Done()
			e.logger.Info("stopping gRPC server")
			e.grpcServer.GracefulStop()
			if e.grpcListener != nil {
				e.grpcListener.Close()
			}
		})
	}
}

func (e *GlobalConsensusEngine) tryBeginProvingRank(rank uint64) bool {
	e.consensusProtocol.activeProveRanksMu.Lock()
	defer e.consensusProtocol.activeProveRanksMu.Unlock()

	if _, exists := e.consensusProtocol.activeProveRanks[rank]; exists {
		return false
	}

	e.consensusProtocol.activeProveRanks[rank] = struct{}{}
	return true
}

func (e *GlobalConsensusEngine) endProvingRank(rank uint64) {
	e.consensusProtocol.activeProveRanksMu.Lock()
	delete(e.consensusProtocol.activeProveRanks, rank)
	e.consensusProtocol.activeProveRanksMu.Unlock()
}

func (e *GlobalConsensusEngine) setupGRPCServer() error {
	// Parse the StreamListenMultiaddr to get the listen address
	listenAddr := "0.0.0.0:8340" // Default
	if e.config.P2P.StreamListenMultiaddr != "" {
		// Parse the multiaddr
		maddr, err := ma.NewMultiaddr(e.config.P2P.StreamListenMultiaddr)
		if err != nil {
			e.logger.Warn("failed to parse StreamListenMultiaddr, using default",
				zap.Error(err),
				zap.String("multiaddr", e.config.P2P.StreamListenMultiaddr))
			listenAddr = "0.0.0.0:8340"
		} else {
			// Extract host and port
			host, err := maddr.ValueForProtocol(ma.P_IP4)
			if err != nil {
				// Try IPv6
				host, err = maddr.ValueForProtocol(ma.P_IP6)
				if err != nil {
					host = "0.0.0.0" // fallback
				} else {
					host = fmt.Sprintf("[%s]", host) // IPv6 format
				}
			}

			port, err := maddr.ValueForProtocol(ma.P_TCP)
			if err != nil {
				port = "8340" // fallback
			}

			listenAddr = fmt.Sprintf("%s:%s", host, port)
		}
	}

	// Establish an auth provider
	e.authProvider = p2p.NewPeerAuthenticator(
		e.logger,
		e.config.P2P,
		e.peerInfoManager,
		e.proverRegistry,
		e.signerRegistry,
		nil,
		nil,
		map[string]channel.AllowedPeerPolicyType{
			"quilibrium.node.application.pb.HypergraphComparisonService": channel.AnyPeer,
			"quilibrium.node.global.pb.GlobalService":                    channel.AnyPeer,
			"quilibrium.node.global.pb.OnionService":                     channel.AnyPeer,
			"quilibrium.node.global.pb.KeyRegistryService":               channel.OnlySelfPeer,
			"quilibrium.node.proxy.pb.PubSubProxy":                       channel.OnlySelfPeer,
		},
		map[string]channel.AllowedPeerPolicyType{
			// Alternative nodes may not need to make this only self peer, but this
			// prevents a repeated lock DoS
			"/quilibrium.node.global.pb.GlobalService/GetLockedAddresses": channel.AnyProverPeer,
			"/quilibrium.node.global.pb.MixnetService/GetTag":             channel.AnyPeer,
			"/quilibrium.node.global.pb.MixnetService/PutTag":             channel.AnyPeer,
			"/quilibrium.node.global.pb.MixnetService/PutMessage":         channel.AnyPeer,
			"/quilibrium.node.global.pb.MixnetService/RoundStream":        channel.OnlyGlobalProverPeer,
			"/quilibrium.node.global.pb.DispatchService/PutInboxMessage":  channel.OnlySelfPeer,
			"/quilibrium.node.global.pb.DispatchService/GetInboxMessages": channel.OnlySelfPeer,
			"/quilibrium.node.global.pb.DispatchService/PutHub":           channel.OnlySelfPeer,
			"/quilibrium.node.global.pb.DispatchService/GetHub":           channel.OnlySelfPeer,
			"/quilibrium.node.global.pb.DispatchService/Sync":             channel.AnyProverPeer,
		},
	)

	tlsCreds, err := e.authProvider.CreateServerTLSCredentials()
	if err != nil {
		return errors.Wrap(err, "setup gRPC server")
	}

	// Create gRPC server with TLS
	e.grpcServer = qgrpc.NewServer(
		grpc.Creds(tlsCreds),
		grpc.ChainUnaryInterceptor(e.authProvider.UnaryInterceptor),
		grpc.ChainStreamInterceptor(e.authProvider.StreamInterceptor),
		grpc.MaxRecvMsgSize(e.config.Engine.SyncMessageLimits.MaxRecvMsgSize),
		grpc.MaxSendMsgSize(e.config.Engine.SyncMessageLimits.MaxSendMsgSize),
	)

	// Create TCP listener
	e.grpcListener, err = net.Listen("tcp", listenAddr)
	if err != nil {
		return errors.Wrap(err, "setup gRPC server")
	}

	e.logger.Info("gRPC server configured",
		zap.String("address", listenAddr))

	return nil
}

func (e *GlobalConsensusEngine) getAddressFromPublicKey(
	publicKey []byte,
) []byte {
	addressBI, _ := poseidon.HashBytes(publicKey)
	return addressBI.FillBytes(make([]byte, 32))
}

func (e *GlobalConsensusEngine) Stop(force bool) <-chan error {
	errChan := make(chan error, 1)

	// Unsubscribe from pubsub
	if e.isConsensusParticipant() {
		e.pubsub.Unsubscribe(GLOBAL_CONSENSUS_BITMASK, false)
		e.pubsub.UnregisterValidator(GLOBAL_CONSENSUS_BITMASK)
		e.pubsub.Unsubscribe(bytes.Repeat([]byte{0xff}, 32), false)
		e.pubsub.UnregisterValidator(bytes.Repeat([]byte{0xff}, 32))
	}

	e.pubsub.Unsubscribe(slices.Concat(
		[]byte{0},
		bytes.Repeat([]byte{0xff}, 32),
	), false)
	e.pubsub.UnregisterValidator(slices.Concat(
		[]byte{0},
		bytes.Repeat([]byte{0xff}, 32),
	))
	e.pubsub.Unsubscribe(GLOBAL_FRAME_BITMASK, false)
	e.pubsub.UnregisterValidator(GLOBAL_FRAME_BITMASK)
	e.pubsub.Unsubscribe(GLOBAL_PROVER_BITMASK, false)
	e.pubsub.UnregisterValidator(GLOBAL_PROVER_BITMASK)
	e.pubsub.Unsubscribe(GLOBAL_PEER_INFO_BITMASK, false)
	e.pubsub.UnregisterValidator(GLOBAL_PEER_INFO_BITMASK)
	e.pubsub.Unsubscribe(GLOBAL_ALERT_BITMASK, false)
	e.pubsub.UnregisterValidator(GLOBAL_ALERT_BITMASK)

	// Close pubsub to cancel all subscription goroutines
	if err := e.pubsub.Close(); err != nil {
		e.logger.Warn("error closing pubsub", zap.Error(err))
	}

	select {
	case <-e.Done():
		// Clean shutdown
	case <-time.After(30 * time.Second):
		if !force {
			errChan <- errors.New("timeout waiting for graceful shutdown")
		}
	}

	// Wait for any in-flight coverage check goroutine to finish before
	// returning, so callers can safely close the Pebble DB. This is safe
	// to wait on unboundedly because GetMetadataAtKey (the only hg.mu
	// caller in the coverage path) bails immediately once shutdownCtx
	// fires, so the goroutine will always complete after shutdown.
	e.coverageMonitor.coverageWg.Wait()

	// Synchronously close the snapshot manager so no Pebble snapshots remain
	// open when the database is closed. The async goroutine chain from
	// SetShutdownContext may not have completed yet.
	if closer, ok := e.hyperSync.(interface{ CloseSnapshots() }); ok {
		closer.CloseSnapshots()
	}

	close(errChan)
	return errChan
}

func (e *GlobalConsensusEngine) GetFrame() *protobufs.GlobalFrame {
	frame, _ := e.clockStore.GetLatestGlobalClockFrame()
	return frame
}

func (e *GlobalConsensusEngine) GetDifficulty() uint32 {
	e.currentDifficultyMu.RLock()
	defer e.currentDifficultyMu.RUnlock()
	return e.currentDifficulty
}

func (e *GlobalConsensusEngine) GetState() typesconsensus.EngineState {
	if !e.isConsensusParticipant() {
		return typesconsensus.EngineStateVerifying
	}

	// Map the generic state machine state to engine state
	select {
	case <-e.consensusProtocol.consensusParticipant.Ready():
		return typesconsensus.EngineStateProving
	case <-e.consensusProtocol.consensusParticipant.Done():
		return typesconsensus.EngineStateStopped
	default:
		return typesconsensus.EngineStateStarting
	}
}

func (e *GlobalConsensusEngine) GetProvingKey(
	engineConfig *config.EngineConfig,
) (crypto.Signer, crypto.KeyType, []byte, []byte) {
	keyId := "q-prover-key"

	signer, err := e.keyManager.GetSigningKey(keyId)
	if err != nil {
		e.logger.Error("failed to get signing key", zap.Error(err))
		proverKeyLookupTotal.WithLabelValues("error").Inc()
		return nil, 0, nil, nil
	}

	// Get the raw key for metadata
	key, err := e.keyManager.GetRawKey(keyId)
	if err != nil {
		e.logger.Error("failed to get raw key", zap.Error(err))
		proverKeyLookupTotal.WithLabelValues("error").Inc()
		return nil, 0, nil, nil
	}

	if key.Type != crypto.KeyTypeBLS48581G1 {
		e.logger.Error("wrong key type", zap.String("expected", "BLS48581G1"))
		proverKeyLookupTotal.WithLabelValues("error").Inc()
		return nil, 0, nil, nil
	}

	proverAddressBI, _ := poseidon.HashBytes(key.PublicKey)
	proverAddress := proverAddressBI.FillBytes(make([]byte, 32))
	proverKeyLookupTotal.WithLabelValues("found").Inc()

	return signer, crypto.KeyTypeBLS48581G1, key.PublicKey, proverAddress
}

func (e *GlobalConsensusEngine) IsInProverTrie(key []byte) bool {
	// Check if the key is in the prover registry
	provers, err := e.proverRegistry.GetActiveProvers(nil)
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

func (e *GlobalConsensusEngine) GetPeerInfo() *protobufs.PeerInfo {
	// Get all addresses from libp2p (includes both listen and observed addresses)
	// Observed addresses are what other peers have told us they see us as
	ownAddrs := e.pubsub.GetOwnMultiaddrs()

	archiveMode := e.config.Engine != nil && e.config.Engine.ArchiveMode

	var lastReceivedFrame uint64
	if archiveMode {
		lastReceivedFrame = e.lastProposalFrameNumber.Load()
	} else {
		lastReceivedFrame = e.lastFrameMessageFrameNumber.Load()
	}

	var lastGlobalHeadFrame uint64
	if archiveMode {
		if e.clockStore != nil {
			if frame, err := e.clockStore.GetLatestGlobalClockFrame(); err == nil &&
				frame != nil &&
				frame.Header != nil {
				lastGlobalHeadFrame = frame.Header.FrameNumber
			}
		}
	} else if e.globalTimeReel != nil {
		if frame, err := e.globalTimeReel.GetHead(); err == nil &&
			frame != nil &&
			frame.Header != nil {
			lastGlobalHeadFrame = frame.Header.FrameNumber
		}
	}

	// Get supported capabilities from execution manager
	capabilities := e.executionManager.GetSupportedCapabilities()

	// If this is an archive node, advertise the capability as a presence flag.
	// The stream multiaddr is already in Reachability[0].StreamMultiaddrs.
	if archiveMode {
		capabilities = append(capabilities, &protobufs.Capability{
			ProtocolIdentifier: ArchiveServiceCapabilityID,
		})
	}

	var reachability []*protobufs.Reachability

	// master node process:
	{
		var pubsubAddrs, streamAddrs []string
		if e.config.P2P.AnnounceListenMultiaddr != "" {
			if e.config.P2P.AnnounceStreamListenMultiaddr == "" {
				e.logger.Error(
					"p2p announce address is configured while stream announce " +
						"address is not, please fix",
				)
			}
			_, err := ma.StringCast(e.config.P2P.AnnounceListenMultiaddr)
			if err == nil {
				pubsubAddrs = append(pubsubAddrs, e.config.P2P.AnnounceListenMultiaddr)
			}
			if e.config.P2P.AnnounceStreamListenMultiaddr != "" {
				_, err = ma.StringCast(e.config.P2P.AnnounceStreamListenMultiaddr)
				if err == nil {
					streamAddrs = append(
						streamAddrs,
						e.config.P2P.AnnounceStreamListenMultiaddr,
					)
				}
			}
		} else {
			if e.config.Engine.EnableMasterProxy {
				pubsubAddrs = e.findObservedAddressesForProxy(
					ownAddrs,
					e.config.P2P.ListenMultiaddr,
					e.config.P2P.ListenMultiaddr,
				)
				if e.config.P2P.StreamListenMultiaddr != "" {
					streamAddrs = e.buildStreamAddressesFromPubsub(
						pubsubAddrs, e.config.P2P.StreamListenMultiaddr,
					)
				}
			} else {
				pubsubAddrs = e.findObservedAddressesForConfig(
					ownAddrs, e.config.P2P.ListenMultiaddr,
				)
				if e.config.P2P.StreamListenMultiaddr != "" {
					streamAddrs = e.buildStreamAddressesFromPubsub(
						pubsubAddrs, e.config.P2P.StreamListenMultiaddr,
					)
				}
			}
		}
		// If no stream addresses were derived from observed pubsub addresses
		// (common on local dev setups with no external-facing addresses), fall
		// back to the raw StreamListenMultiaddr so local workers can connect.
		if len(streamAddrs) == 0 && e.config.P2P.StreamListenMultiaddr != "" {
			streamAddrs = append(streamAddrs, e.config.P2P.StreamListenMultiaddr)
		}
		reachability = append(reachability, &protobufs.Reachability{
			Filter:           []byte{}, // master has empty filter
			PubsubMultiaddrs: pubsubAddrs,
			StreamMultiaddrs: streamAddrs,
		})
	}

	// worker processes
	{
		announceP2P, announceStream, ok := e.workerAnnounceAddrs()
		p2pPatterns, streamPatterns, filters := e.workerPatterns()
		for i := range p2pPatterns {
			if p2pPatterns[i] == "" {
				continue
			}

			var pubsubAddrs []string
			if ok && i < len(announceP2P) && announceP2P[i] != "" {
				pubsubAddrs = append(pubsubAddrs, announceP2P[i])
			} else {
				pubsubAddrs = e.findObservedAddressesForConfig(ownAddrs, p2pPatterns[i])
			}

			var streamAddrs []string
			if ok && i < len(announceStream) && announceStream[i] != "" {
				streamAddrs = append(streamAddrs, announceStream[i])
			} else if i < len(streamPatterns) && streamPatterns[i] != "" {
				streamAddrs = e.buildStreamAddressesFromPubsub(
					pubsubAddrs,
					streamPatterns[i],
				)
			} else if e.config.P2P.StreamListenMultiaddr != "" {
				streamAddrs = e.buildStreamAddressesFromPubsub(
					pubsubAddrs,
					e.config.P2P.StreamListenMultiaddr,
				)
			}

			var filter []byte
			if i < len(filters) {
				filter = filters[i]
			} else {
				var err error
				filter, err = e.workerManager.GetFilterByWorkerId(uint(i))
				if err != nil {
					continue
				}
			}

			if len(pubsubAddrs) > 0 && len(filter) != 0 {
				reachability = append(reachability, &protobufs.Reachability{
					Filter:           filter,
					PubsubMultiaddrs: pubsubAddrs,
					StreamMultiaddrs: streamAddrs,
				})
			}
		}
	}

	// Create our peer info
	ourInfo := &protobufs.PeerInfo{
		PeerId:              e.pubsub.GetPeerID(),
		Reachability:        reachability,
		Timestamp:           time.Now().UnixMilli(),
		Version:             config.GetVersion(),
		PatchNumber:         []byte{config.GetPatchNumber()},
		Capabilities:        capabilities,
		PublicKey:           e.pubsub.GetPublicKey(),
		LastReceivedFrame:   lastReceivedFrame,
		LastGlobalHeadFrame: lastGlobalHeadFrame,
	}

	// Sign the peer info
	signature, err := e.signPeerInfo(ourInfo)
	if err != nil {
		e.logger.Error("failed to sign peer info", zap.Error(err))
	} else {
		ourInfo.Signature = signature
	}

	return ourInfo
}

func (e *GlobalConsensusEngine) recordProposalFrameNumber(
	frameNumber uint64,
) {
	e.lastProposalFrameNumber.Store(frameNumber)
}

func (e *GlobalConsensusEngine) recordFrameMessageFrameNumber(
	frameNumber uint64,
) {
	for {
		current := e.lastFrameMessageFrameNumber.Load()
		if frameNumber <= current {
			return
		}
		if e.lastFrameMessageFrameNumber.CompareAndSwap(current, frameNumber) {
			return
		}
	}
}

func (e *GlobalConsensusEngine) GetWorkerManager() worker.WorkerManager {
	return e.workerManager
}

func (
	e *GlobalConsensusEngine,
) GetProverRegistry() typesconsensus.ProverRegistry {
	return e.proverRegistry
}

func (
	e *GlobalConsensusEngine,
) GetExecutionEngineManager() *manager.ExecutionEngineManager {
	return e.executionManager
}

// workerPatterns returns p2pPatterns, streamPatterns, filtersBytes
func (e *GlobalConsensusEngine) workerPatterns() (
	[]string,
	[]string,
	[][]byte,
) {
	ec := e.config.Engine
	if ec == nil {
		return nil, nil, nil
	}

	// Convert DataWorkerFilters (hex strings) -> [][]byte
	var filters [][]byte
	for _, hs := range ec.DataWorkerFilters {
		b, err := hex.DecodeString(strings.TrimPrefix(hs, "0x"))
		if err != nil {
			// keep empty on decode error
			b = []byte{}
			e.logger.Warn(
				"invalid DataWorkerFilters entry",
				zap.String("value", hs),
				zap.Error(err),
			)
		}
		filters = append(filters, b)
	}

	// If explicit worker multiaddrs are set, use those
	if len(ec.DataWorkerP2PMultiaddrs) > 0 ||
		len(ec.DataWorkerStreamMultiaddrs) > 0 {
		// truncate to min length
		n := len(ec.DataWorkerP2PMultiaddrs)
		if len(ec.DataWorkerStreamMultiaddrs) < n {
			n = len(ec.DataWorkerStreamMultiaddrs)
		}
		p2p := make([]string, n)
		stream := make([]string, n)
		for i := 0; i < n; i++ {
			if i < len(ec.DataWorkerP2PMultiaddrs) {
				p2p[i] = ec.DataWorkerP2PMultiaddrs[i]
			}
			if i < len(ec.DataWorkerStreamMultiaddrs) {
				stream[i] = ec.DataWorkerStreamMultiaddrs[i]
			}
		}
		return p2p, stream, filters
	}

	// Otherwise synthesize from base pattern + base ports
	base := ec.DataWorkerBaseListenMultiaddr
	if base == "" {
		base = "/ip4/0.0.0.0/tcp/%d"
	}

	n := ec.DataWorkerCount
	p2p := make([]string, n)
	stream := make([]string, n)
	for i := 0; i < n; i++ {
		p2p[i] = fmt.Sprintf(base, int(ec.DataWorkerBaseP2PPort)+i)
		stream[i] = fmt.Sprintf(base, int(ec.DataWorkerBaseStreamPort)+i)
	}
	return p2p, stream, filters
}

func (e *GlobalConsensusEngine) workerAnnounceAddrs() (
	[]string,
	[]string,
	bool,
) {
	ec := e.config.Engine
	if ec == nil {
		return nil, nil, false
	}

	count := ec.DataWorkerCount
	if count <= 0 {
		return nil, nil, false
	}

	if len(ec.DataWorkerAnnounceP2PMultiaddrs) == 0 &&
		len(ec.DataWorkerAnnounceStreamMultiaddrs) == 0 {
		return nil, nil, false
	}

	if len(ec.DataWorkerAnnounceP2PMultiaddrs) !=
		len(ec.DataWorkerAnnounceStreamMultiaddrs) ||
		len(ec.DataWorkerAnnounceP2PMultiaddrs) != count {
		e.logger.Error(
			"data worker announce multiaddr counts do not match",
			zap.Int("announce_p2p", len(ec.DataWorkerAnnounceP2PMultiaddrs)),
			zap.Int("announce_stream", len(ec.DataWorkerAnnounceStreamMultiaddrs)),
			zap.Int("worker_count", count),
		)
		return nil, nil, false
	}

	p2p := make([]string, count)
	stream := make([]string, count)
	valid := true
	for i := 0; i < count; i++ {
		p := ec.DataWorkerAnnounceP2PMultiaddrs[i]
		s := ec.DataWorkerAnnounceStreamMultiaddrs[i]
		if p == "" || s == "" {
			valid = false
			break
		}
		if _, err := ma.StringCast(p); err != nil {
			e.logger.Error(
				"invalid worker announce p2p multiaddr",
				zap.Int("index", i),
				zap.Error(err),
			)
			valid = false
			break
		}
		if _, err := ma.StringCast(s); err != nil {
			e.logger.Error(
				"invalid worker announce stream multiaddr",
				zap.Int("index", i),
				zap.Error(err),
			)
			valid = false
			break
		}
		p2p[i] = p
		stream[i] = s
	}

	if !valid {
		return nil, nil, false
	}

	return p2p, stream, true
}

// materialize, persistAltShardUpdates, computeLocalProverRoot,
// verifyProverRoot, triggerProverHypersync, performBlockingProverHypersync,
// and reconcileLocalWorkerAllocations are methods on FrameMaterializer in
// frame_materializer.go. Access via engine.materializer.

// joinProposalReady is kept here because it will move to WorkerAllocator in
// Phase 3.
// joinProposalReady, selectExcessPendingFilters, and rejectExcessPending
// have been moved to worker_allocator.go.

func (e *GlobalConsensusEngine) revert(
	txn store.Transaction,
	frameNumber uint64,
	requests []*protobufs.MessageBundle,
) error {
	bits := up2p.GetBloomFilterIndices(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		256,
		3,
	)
	l2 := make([]byte, 32)
	copy(l2, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])

	shardKey := tries.ShardKey{
		L1: [3]byte(bits),
		L2: [32]byte(l2),
	}

	err := e.hypergraph.RevertChanges(
		txn,
		frameNumber,
		frameNumber,
		shardKey,
	)
	if err != nil {
		return errors.Wrap(err, "revert")
	}

	err = e.proverRegistry.Refresh()
	if err != nil {
		return errors.Wrap(err, "revert")
	}

	return nil
}

func (e *GlobalConsensusEngine) getPeerID() GlobalPeerID {
	// Get our peer ID from the prover address
	return GlobalPeerID{ID: e.getProverAddress()}
}

func (e *GlobalConsensusEngine) getProverAddress() []byte {
	return e.proverAddress
}

func (e *GlobalConsensusEngine) updateMetrics(
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
			timeSince := time.Since(e.lastProvenFrameTime).Seconds()
			e.lastProvenFrameTimeMu.RUnlock()
			timeSinceLastProvenFrame.Set(timeSince)

			// Update current frame number
			if frame := e.GetFrame(); frame != nil && frame.Header != nil {
				currentFrameNumber.Set(float64(frame.Header.FrameNumber))
			}

			// Clean up old frames
			e.cleanupFrameStore()
		}
	}
}

func (e *GlobalConsensusEngine) cleanupFrameStore() {
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
		if frameNumber <= cutoffFrameNumber {
			for _, id := range ids {
				delete(e.frameStore, id)
				deletedCount++
			}
		}
	}

	// If archive mode is disabled, also delete from ClockStore
	if !e.config.Engine.ArchiveMode && cutoffFrameNumber > 0 {
		if err := e.clockStore.DeleteGlobalClockFrameRange(
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

		e.logger.Debug(
			"cleaned up frame store",
			zap.Int("deleted_frames", deletedCount),
			zap.Int("remaining_frames", len(e.frameStore)),
			zap.Uint64("max_frame_number", maxFrameNumber),
			zap.Uint64("cutoff_frame_number", cutoffFrameNumber),
			zap.Bool("archive_mode", e.config.Engine.ArchiveMode),
		)
	}
}

// buildStreamAddressesFromPubsub builds stream addresses using IPs from pubsub
// addresses but with the port and protocols from the stream config pattern
func (e *GlobalConsensusEngine) buildStreamAddressesFromPubsub(
	pubsubAddrs []string,
	streamPattern string,
) []string {
	if len(pubsubAddrs) == 0 {
		return []string{}
	}

	// Parse stream pattern to get port and protocol structure
	streamAddr, err := ma.NewMultiaddr(streamPattern)
	if err != nil {
		e.logger.Warn("failed to parse stream pattern", zap.Error(err))
		return []string{}
	}

	// Extract port from stream pattern
	streamPort, err := streamAddr.ValueForProtocol(ma.P_TCP)
	if err != nil {
		streamPort, err = streamAddr.ValueForProtocol(ma.P_UDP)
		if err != nil {
			e.logger.Warn(
				"failed to extract port from stream pattern",
				zap.Error(err),
			)
			return []string{}
		}
	}

	var result []string

	// For each pubsub address, create a corresponding stream address
	for _, pubsubAddrStr := range pubsubAddrs {
		pubsubAddr, err := ma.NewMultiaddr(pubsubAddrStr)
		if err != nil {
			continue
		}

		// Extract IP from pubsub address
		var ip string
		var ipProto int
		if ipVal, err := pubsubAddr.ValueForProtocol(ma.P_IP4); err == nil {
			ip = ipVal
			ipProto = ma.P_IP4
		} else if ipVal, err := pubsubAddr.ValueForProtocol(ma.P_IP6); err == nil {
			ip = ipVal
			ipProto = ma.P_IP6
		} else {
			continue
		}

		// Build stream address using pubsub IP and stream port/protocols
		// Copy protocol structure from stream pattern but use discovered IP
		protocols := streamAddr.Protocols()
		addrParts := []string{}

		for _, p := range protocols {
			if p.Code == ma.P_IP4 || p.Code == ma.P_IP6 {
				// Use IP from pubsub address
				if p.Code == ipProto {
					addrParts = append(addrParts, p.Name, ip)
				}
			} else if p.Code == ma.P_TCP || p.Code == ma.P_UDP {
				// Use port from stream pattern
				addrParts = append(addrParts, p.Name, streamPort)
			} else {
				// Copy other protocols as-is from stream pattern
				if val, err := streamAddr.ValueForProtocol(p.Code); err == nil {
					addrParts = append(addrParts, p.Name, val)
				} else {
					addrParts = append(addrParts, p.Name)
				}
			}
		}

		// Build the final address
		finalAddrStr := "/" + strings.Join(addrParts, "/")
		if finalAddr, err := ma.NewMultiaddr(finalAddrStr); err == nil {
			result = append(result, finalAddr.String())
		}
	}

	return result
}

// findObservedAddressesForProxy finds observed addresses but uses the master
// node's port instead of the worker's port when EnableMasterProxy is set
func (e *GlobalConsensusEngine) findObservedAddressesForProxy(
	addrs []ma.Multiaddr,
	workerPattern, masterPattern string,
) []string {
	masterAddr, err := ma.NewMultiaddr(masterPattern)
	if err != nil {
		e.logger.Warn("failed to parse master pattern", zap.Error(err))
		return []string{}
	}
	masterPort, err := masterAddr.ValueForProtocol(ma.P_TCP)
	if err != nil {
		masterPort, err = masterAddr.ValueForProtocol(ma.P_UDP)
		if err != nil {
			e.logger.Warn(
				"failed to extract port from master pattern",
				zap.Error(err),
			)
			return []string{}
		}
	}
	workerAddr, err := ma.NewMultiaddr(workerPattern)
	if err != nil {
		e.logger.Warn("failed to parse worker pattern", zap.Error(err))
		return []string{}
	}
	// pattern IP to skip “self”
	var workerIP string
	var workerProto int
	if ip, err := workerAddr.ValueForProtocol(ma.P_IP4); err == nil {
		workerIP, workerProto = ip, ma.P_IP4
	} else if ip, err := workerAddr.ValueForProtocol(ma.P_IP6); err == nil {
		workerIP, workerProto = ip, ma.P_IP6
	}

	public := []string{}
	localish := []string{}

	for _, addr := range addrs {
		if !e.matchesProtocol(addr.String(), workerPattern) {
			continue
		}

		// Rebuild with master's port
		protocols := addr.Protocols()
		values := []string{}
		for _, p := range protocols {
			val, err := addr.ValueForProtocol(p.Code)
			if err != nil {
				continue
			}
			if p.Code == ma.P_TCP || p.Code == ma.P_UDP {
				values = append(values, masterPort)
			} else {
				values = append(values, val)
			}
		}
		var b strings.Builder
		for i, p := range protocols {
			if i < len(values) {
				b.WriteString("/")
				b.WriteString(p.Name)
				b.WriteString("/")
				b.WriteString(values[i])
			} else {
				b.WriteString("/")
				b.WriteString(p.Name)
			}
		}
		newAddr, err := ma.NewMultiaddr(b.String())
		if err != nil {
			continue
		}

		// Skip the worker’s own listen IP if concrete (not wildcard)
		if workerIP != "" && workerIP != "0.0.0.0" && workerIP != "127.0.0.1" &&
			workerIP != "::" && workerIP != "::1" {
			if ipVal, err := newAddr.ValueForProtocol(workerProto); err == nil &&
				ipVal == workerIP {
				continue
			}
		}

		newStr := newAddr.String()
		if ipVal, err := newAddr.ValueForProtocol(ma.P_IP4); err == nil {
			if isLocalOrReservedIP(ipVal, ma.P_IP4) {
				localish = append(localish, newStr)
			} else {
				public = append(public, newStr)
			}
			continue
		}
		if ipVal, err := newAddr.ValueForProtocol(ma.P_IP6); err == nil {
			if isLocalOrReservedIP(ipVal, ma.P_IP6) {
				localish = append(localish, newStr)
			} else {
				public = append(public, newStr)
			}
			continue
		}
	}

	if len(public) > 0 {
		return public
	}

	return localish
}

// findObservedAddressesForConfig finds observed addresses that match the port
// and protocol from the config pattern, returning them in config declaration
// order
func (e *GlobalConsensusEngine) findObservedAddressesForConfig(
	addrs []ma.Multiaddr,
	configPattern string,
) []string {
	patternAddr, err := ma.NewMultiaddr(configPattern)
	if err != nil {
		e.logger.Warn("failed to parse config pattern", zap.Error(err))
		return []string{}
	}

	// Extract desired port and pattern IP (if any)
	configPort, err := patternAddr.ValueForProtocol(ma.P_TCP)
	if err != nil {
		configPort, err = patternAddr.ValueForProtocol(ma.P_UDP)
		if err != nil {
			e.logger.Warn(
				"failed to extract port from config pattern",
				zap.Error(err),
			)
			return []string{}
		}
	}
	var patternIP string
	var patternProto int
	if ip, err := patternAddr.ValueForProtocol(ma.P_IP4); err == nil {
		patternIP, patternProto = ip, ma.P_IP4
	} else if ip, err := patternAddr.ValueForProtocol(ma.P_IP6); err == nil {
		patternIP, patternProto = ip, ma.P_IP6
	}

	public := []string{}
	localish := []string{}

	for _, addr := range addrs {
		// Must match protocol prefix and port
		if !e.matchesProtocol(addr.String(), configPattern) {
			continue
		}
		if p, err := addr.ValueForProtocol(ma.P_TCP); err == nil &&
			p != configPort {
			continue
		} else if p, err := addr.ValueForProtocol(ma.P_UDP); err == nil &&
			p != configPort {
			continue
		}

		// Skip the actual listen addr itself (same IP as pattern, non-wildcard)
		if patternIP != "" && patternIP != "0.0.0.0" && patternIP != "127.0.0.1" &&
			patternIP != "::" && patternIP != "::1" {
			if ipVal, err := addr.ValueForProtocol(patternProto); err == nil &&
				ipVal == patternIP {
				// this is the listen addr, not an observed external
				continue
			}
		}

		addrStr := addr.String()

		// Classify IP
		if ipVal, err := addr.ValueForProtocol(ma.P_IP4); err == nil {
			if isLocalOrReservedIP(ipVal, ma.P_IP4) {
				localish = append(localish, addrStr)
			} else {
				public = append(public, addrStr)
			}
			continue
		}
		if ipVal, err := addr.ValueForProtocol(ma.P_IP6); err == nil {
			if isLocalOrReservedIP(ipVal, ma.P_IP6) {
				localish = append(localish, addrStr)
			} else {
				public = append(public, addrStr)
			}
			continue
		}
	}

	if len(public) > 0 {
		return public
	}
	return localish
}

func (e *GlobalConsensusEngine) matchesProtocol(addr, pattern string) bool {
	// Treat pattern as a protocol prefix that must appear in order in addr.
	// IP value is ignored when pattern uses 0.0.0.0/127.0.0.1 or ::/::1.
	a, err := ma.NewMultiaddr(addr)
	if err != nil {
		return false
	}
	p, err := ma.NewMultiaddr(pattern)
	if err != nil {
		return false
	}

	ap := a.Protocols()
	pp := p.Protocols()

	// Walk the pattern protocols and try to match them one-by-one in addr.
	ai := 0
	for pi := 0; pi < len(pp); pi++ {
		pProto := pp[pi]

		// advance ai until we find same protocol code in order
		for ai < len(ap) && ap[ai].Code != pProto.Code {
			ai++
		}
		if ai >= len(ap) {
			return false // required protocol not found in order
		}

		// compare values when meaningful
		switch pProto.Code {
		case ma.P_IP4, ma.P_IP6, ma.P_TCP, ma.P_UDP:
			// Skip
		default:
			// For other protocols, only compare value if the pattern actually has one
			if pVal, err := p.ValueForProtocol(pProto.Code); err == nil &&
				pVal != "" {
				if aVal, err := a.ValueForProtocol(pProto.Code); err != nil ||
					aVal != pVal {
					return false
				}
			}
		}

		ai++ // move past the matched protocol in addr
	}

	return true
}

// signPeerInfo signs the peer info message
func (e *GlobalConsensusEngine) signPeerInfo(
	info *protobufs.PeerInfo,
) ([]byte, error) {
	// Create a copy of the peer info without the signature for signing
	infoCopy := &protobufs.PeerInfo{
		PeerId:              info.PeerId,
		Reachability:        info.Reachability,
		Timestamp:           info.Timestamp,
		Version:             info.Version,
		PatchNumber:         info.PatchNumber,
		Capabilities:        info.Capabilities,
		PublicKey:           info.PublicKey,
		LastReceivedFrame:   info.LastReceivedFrame,
		LastGlobalHeadFrame: info.LastGlobalHeadFrame,
		// Exclude Signature field
	}

	// Use ToCanonicalBytes to get the complete message content
	msg, err := infoCopy.ToCanonicalBytes()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize peer info for signing")
	}

	return e.pubsub.SignMessage(msg)
}

// reportPeerInfoPeriodically sends peer info over the peer info bitmask every
// 5 minutes
func (e *GlobalConsensusEngine) reportPeerInfoPeriodically(
	ctx lifecycle.SignalerContext,
) {
	e.logger.Info("starting periodic peer info reporting")
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	// Publish immediately at startup so workers can sync before the first
	// ticker fires. Without this, workers wait 5 minutes before receiving
	// the master's PeerInfo and any HyperSyncSelf calls silently fail.
	e.publishPeerInfo()

	for {
		select {
		case <-ctx.Done():
			e.logger.Info("stopping periodic peer info reporting")
			return
		case <-ticker.C:
			e.publishPeerInfo()
			e.workerAllocator.publishKeyRegistry()
		}
	}
}

func (e *GlobalConsensusEngine) publishPeerInfo() {
	e.logger.Debug("publishing peer info")

	peerInfo := e.GetPeerInfo()

	peerInfoData, err := peerInfo.ToCanonicalBytes()
	if err != nil {
		e.logger.Error("failed to serialize peer info", zap.Error(err))
		return
	}

	// Publish to the peer info bitmask for network peers
	if err := e.pubsub.PublishToBitmask(
		GLOBAL_PEER_INFO_BITMASK,
		peerInfoData,
	); err != nil {
		e.logger.Error("failed to publish peer info", zap.Error(err))
	} else {
		e.logger.Debug("successfully published peer info",
			zap.String("peer_id", base58.Encode(peerInfo.PeerId)),
			zap.Int("capabilities_count", len(peerInfo.Capabilities)),
		)
	}

	// Also broadcast directly to local workers. Blossomsub does not echo
	// self-published messages back to the publisher, so the subscription
	// handler's broadcastGlobalMessage call never fires for our own
	// PeerInfo. Without this, workers' PeerInfoManagers never contain the
	// master's PeerInfo and HyperSyncSelf silently fails.
	e.broadcastGlobalMessage(peerInfoData, GLOBAL_PEER_INFO_BITMASK)
}

func (e *GlobalConsensusEngine) pruneTxLocksPeriodically(
	ctx lifecycle.SignalerContext,
) {
	if !e.isConsensusParticipant() {
		<-ctx.Done()
		return
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	e.pruneTxLocks()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.pruneTxLocks()
		}
	}
}

func (e *GlobalConsensusEngine) pruneTxLocks() {
	e.txLockMu.RLock()
	if len(e.txLockMap) == 0 {
		e.txLockMu.RUnlock()
		return
	}
	e.txLockMu.RUnlock()

	frame, err := e.clockStore.GetLatestGlobalClockFrame()
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			e.logger.Debug(
				"failed to load latest global frame for tx lock pruning",
				zap.Error(err),
			)
		}
		return
	}

	if frame == nil || frame.Header == nil {
		return
	}

	head := frame.Header.FrameNumber
	if head < 2 {
		return
	}

	cutoff := head - 2

	e.txLockMu.Lock()
	removed := 0
	for frameNumber := range e.txLockMap {
		if frameNumber < cutoff {
			delete(e.txLockMap, frameNumber)
			removed++
		}
	}
	e.txLockMu.Unlock()

	if removed > 0 {
		e.logger.Debug(
			"pruned stale tx locks",
			zap.Uint64("head_frame", head),
			zap.Uint64("cutoff_frame", cutoff),
			zap.Int("frames_removed", removed),
		)
	}
}

func (e *GlobalConsensusEngine) monitorNodeHealth(
	ctx lifecycle.SignalerContext,
) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	e.runNodeHealthCheck()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.runNodeHealthCheck()
		}
	}
}

func (e *GlobalConsensusEngine) runNodeHealthCheck() {
	if e.workerManager == nil {
		return
	}

	workers, err := e.workerManager.RangeWorkers()
	if err != nil {
		e.logger.Warn("node health check failed to load workers", zap.Error(err))
		return
	}

	allocated := 0
	for _, worker := range workers {
		if worker.Allocated {
			allocated++
		}
	}

	baseFields := []zap.Field{
		zap.Int("total_workers", len(workers)),
		zap.Int("allocated_workers", allocated),
	}

	unreachable, err := e.workerManager.CheckWorkersConnected()
	if err != nil {
		e.logger.Warn(
			"node health check could not verify worker connectivity",
			append(baseFields, zap.Error(err))...,
		)
		return
	}

	if len(unreachable) != 0 {
		unreachable64 := make([]uint64, len(unreachable))
		for i, id := range unreachable {
			unreachable64[i] = uint64(id)
		}
		e.logger.Warn(
			"workers unreachable",
			append(
				baseFields,
				zap.Uint64s("unreachable_workers", unreachable64),
			)...,
		)
		return
	}

	headFrame, err := e.globalTimeReel.GetHead()
	if err != nil {
		e.logger.Warn(
			"global head not yet available",
			append(baseFields, zap.Error(err))...,
		)
		return
	}
	if headFrame == nil || headFrame.Header == nil {
		e.logger.Warn("global head not yet available", baseFields...)
		return
	}

	headTime := time.UnixMilli(headFrame.Header.Timestamp)
	if time.Since(headTime) > time.Minute {
		e.logger.Warn(
			"latest frame is older than 60 seconds; node may still be synchronizing",
			append(
				baseFields,
				zap.Uint64(
					"latest_frame_received",
					e.lastFrameMessageFrameNumber.Load(),
				),
				zap.Uint64("head_frame_number", headFrame.Header.FrameNumber),
				zap.String("head_frame_time", headTime.String()),
			)...,
		)
		return
	}

	units, readable, err := e.getUnmintedRewardBalance()
	if err != nil {
		e.logger.Warn(
			"unable to read prover reward balance",
			append(baseFields, zap.Error(err))...,
		)
		return
	}

	e.logger.Info(
		"node health check passed",
		append(
			baseFields,
			zap.Uint64(
				"latest_frame_received",
				e.lastFrameMessageFrameNumber.Load(),
			),
			zap.Uint64("head_frame_number", headFrame.Header.FrameNumber),
			zap.String("head_frame_time", headTime.String()),
			zap.String("unminted_reward_quil", readable),
			zap.String("unminted_reward_raw_units", units.String()),
		)...,
	)
}

const rewardUnitsPerInterval int64 = 8_000_000_000

func (e *GlobalConsensusEngine) getUnmintedRewardBalance() (
	*big.Int,
	string,
	error,
) {
	rewardAddress, err := e.deriveRewardAddress()
	if err != nil {
		return nil, "", errors.Wrap(err, "derive reward address")
	}

	var vertexID [64]byte
	copy(vertexID[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(vertexID[32:], rewardAddress)

	tree, err := e.hypergraph.GetVertexData(vertexID)
	if err != nil {
		return big.NewInt(0), "0", nil
	}
	if tree == nil {
		return big.NewInt(0), "0", nil
	}

	rdf := schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, e.inclusionProver)
	balanceBytes, err := rdf.Get(
		global.GLOBAL_RDF_SCHEMA,
		"reward:ProverReward",
		"Balance",
		tree,
	)
	if err != nil {
		return nil, "", errors.Wrap(err, "read reward balance")
	}

	units := new(big.Int).SetBytes(balanceBytes)
	rewardReadable := decimal.NewFromBigInt(units, 0).Div(
		decimal.NewFromInt(rewardUnitsPerInterval),
	).String()

	return units, rewardReadable, nil
}

func (e *GlobalConsensusEngine) deriveRewardAddress() ([]byte, error) {
	proverAddr := e.getProverAddress()
	if len(proverAddr) == 0 {
		return nil, errors.New("missing prover address")
	}

	hash, err := poseidon.HashBytes(
		slices.Concat(tokenintrinsics.QUIL_TOKEN_ADDRESS[:], proverAddr),
	)
	if err != nil {
		return nil, err
	}

	return hash.FillBytes(make([]byte, 32)), nil
}

// validatePeerInfoSignature validates the signature of a peer info message
func (e *GlobalConsensusEngine) validatePeerInfoSignature(
	peerInfo *protobufs.PeerInfo,
) bool {
	if len(peerInfo.Signature) == 0 || len(peerInfo.PublicKey) == 0 {
		return false
	}

	// Create a copy of the peer info without the signature for validation
	infoCopy := &protobufs.PeerInfo{
		PeerId:              peerInfo.PeerId,
		Reachability:        peerInfo.Reachability,
		Timestamp:           peerInfo.Timestamp,
		Version:             peerInfo.Version,
		PatchNumber:         peerInfo.PatchNumber,
		Capabilities:        peerInfo.Capabilities,
		PublicKey:           peerInfo.PublicKey,
		LastReceivedFrame:   peerInfo.LastReceivedFrame,
		LastGlobalHeadFrame: peerInfo.LastGlobalHeadFrame,
		// Exclude Signature field
	}

	// Serialize the message for signature validation
	msg, err := infoCopy.ToCanonicalBytes()
	if err != nil {
		e.logger.Debug(
			"failed to serialize peer info for validation",
			zap.Error(err),
		)
		return false
	}

	// Validate the signature using pubsub's verification
	valid, err := e.keyManager.ValidateSignature(
		crypto.KeyTypeEd448,
		peerInfo.PublicKey,
		msg,
		peerInfo.Signature,
		[]byte{},
	)

	if err != nil {
		e.logger.Debug(
			"failed to validate signature",
			zap.Error(err),
		)
		return false
	}

	return valid
}

// isLocalOrReservedIP returns true for loopback, unspecified, link-local,
// RFC1918, RFC6598 (CGNAT), ULA, etc. It treats multicast and 240/4 as reserved
// too.
func isLocalOrReservedIP(ipStr string, proto int) bool {
	// Handle exact wildcard/localhost first
	if proto == ma.P_IP4 && (ipStr == "0.0.0.0" || ipStr == "127.0.0.1") {
		return true
	}
	if proto == ma.P_IP6 && (ipStr == "::" || ipStr == "::1") {
		return true
	}

	addr, ok := parseIP(ipStr)
	if !ok {
		// If it isn't a literal IP (e.g., DNS name), treat as non-local
		// unless it's localhost.
		return ipStr == "localhost"
	}

	// netip has nice predicates:
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() {
		return true
	}

	// Explicit ranges
	for _, p := range reservedPrefixes(proto) {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func parseIP(s string) (netip.Addr, bool) {
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr, true
	}

	// Fall back to net.ParseIP for odd inputs; convert if possible
	if ip := net.ParseIP(s); ip != nil {
		if addr, ok := netip.AddrFromSlice(ip.To16()); ok {
			return addr, true
		}
	}

	return netip.Addr{}, false
}

func mustPrefix(s string) netip.Prefix {
	p, _ := netip.ParsePrefix(s)
	return p
}

func reservedPrefixes(proto int) []netip.Prefix {
	if proto == ma.P_IP4 {
		return []netip.Prefix{
			mustPrefix("10.0.0.0/8"),     // RFC1918
			mustPrefix("172.16.0.0/12"),  // RFC1918
			mustPrefix("192.168.0.0/16"), // RFC1918
			mustPrefix("100.64.0.0/10"),  // RFC6598 CGNAT
			mustPrefix("169.254.0.0/16"), // Link-local
			mustPrefix("224.0.0.0/4"),    // Multicast
			mustPrefix("240.0.0.0/4"),    // Reserved
			mustPrefix("127.0.0.0/8"),    // Loopback
		}
	}
	// IPv6
	return []netip.Prefix{
		mustPrefix("fc00::/7"),      // ULA
		mustPrefix("fe80::/10"),     // Link-local
		mustPrefix("ff00::/8"),      // Multicast
		mustPrefix("::1/128"),       // Loopback
		mustPrefix("::/128"),        // Unspecified
		mustPrefix("2001:db8::/32"), // Documentation
		mustPrefix("64:ff9b::/96"),  // NAT64 well-known prefix
		mustPrefix("2002::/16"),     // 6to4
		mustPrefix("2001::/32"),     // Teredo
	}
}

// ProposeWorkerJoin, buildMergeHelpers, submitSeniorityMerge,
// DecideWorkerJoins, ProposeWorkerLeave, and DecideWorkerLeaves
// have been moved to worker_allocator.go.

// startConsensus, MakeFinal, On*, Verify*, rebuildShardCommitments, and
// getPendingProposals have been moved to consensus_protocol.go.
// DynamicCommittee methods are also in consensus_protocol.go.

func (e *GlobalConsensusEngine) getPeerIDOfProver(
	prover []byte,
) (peer.ID, error) {
	registry, err := e.signerRegistry.GetKeyRegistryByProver(
		prover,
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

func (e *GlobalConsensusEngine) getRandomProverPeerId() (peer.ID, error) {
	provers, err := e.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		e.logger.Error(
			"could not get active provers for sync",
			zap.Error(err),
		)
	}
	if len(provers) == 0 {
		return "", err
	}

	otherProvers := []*typesconsensus.ProverInfo{}
	for _, p := range provers {
		if bytes.Equal(p.Address, e.getProverAddress()) {
			continue
		}
		otherProvers = append(otherProvers, p)
	}

	index := rand.Intn(len(otherProvers))
	return e.getPeerIDOfProver(otherProvers[index].Address)
}
