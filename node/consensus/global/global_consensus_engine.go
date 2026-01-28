package global

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
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

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mr-tron/base58"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/pkg/errors"
	"github.com/shopspring/decimal"
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
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/aggregator"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/provers"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/reward"
	qsync "source.quilibrium.com/quilibrium/monorepo/node/consensus/sync"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/tracing"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/voting"
	"source.quilibrium.com/quilibrium/monorepo/node/dispatch"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global/compat"
	tokenintrinsics "source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/manager"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	qgrpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	keyedaggregator "source.quilibrium.com/quilibrium/monorepo/node/keyedaggregator"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p/onion"
	mgr "source.quilibrium.com/quilibrium/monorepo/node/worker"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/compiler"
	typesconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	typesdispatch "source.quilibrium.com/quilibrium/monorepo/types/dispatch"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
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

// GlobalConsensusEngine  uses the generic state machine for consensus
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
	forks              consensus.Forks[*protobufs.GlobalFrame]
	notifier           consensus.Consumer[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
	]
	blsConstructor          crypto.BlsConstructor
	executionManager        *manager.ExecutionEngineManager
	mixnet                  typesconsensus.Mixnet
	peerInfoManager         tp2p.PeerInfoManager
	workerManager           worker.WorkerManager
	proposer                *provers.Manager
	frameChainChecker       *FrameChainChecker
	currentRank             uint64
	alertPublicKey          []byte
	hasSentKeyBundle        bool
	proverSyncInProgress    atomic.Bool
	lastJoinAttemptFrame    atomic.Uint64
	lastObservedFrame       atomic.Uint64
	lastRejectFrame         atomic.Uint64
	proverRootVerifiedFrame atomic.Uint64
	proverRootSynced        atomic.Bool

	lastProposalFrameNumber     atomic.Uint64
	lastFrameMessageFrameNumber atomic.Uint64

	// Message queues
	globalConsensusMessageQueue chan *pb.Message
	globalFrameMessageQueue     chan *pb.Message
	globalProverMessageQueue    chan *pb.Message
	globalPeerInfoMessageQueue  chan *pb.Message
	globalAlertMessageQueue     chan *pb.Message
	appFramesMessageQueue       chan *pb.Message
	shardConsensusMessageQueue  chan *pb.Message
	globalProposalQueue         chan *protobufs.GlobalProposal

	// Emergency halt
	haltCtx context.Context
	halt    context.CancelFunc

	// Internal state
	proverAddress             []byte
	quit                      chan struct{}
	wg                        sync.WaitGroup
	minimumProvers            func() uint64
	blacklistMap              map[string]bool
	blacklistMu               sync.RWMutex
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
	proposalCache             map[uint64]*protobufs.GlobalProposal
	proposalCacheMu           sync.RWMutex
	pendingCertifiedParents   map[uint64]*protobufs.GlobalProposal
	pendingCertifiedParentsMu sync.RWMutex
	activeProveRanks          map[uint64]struct{}
	activeProveRanksMu        sync.Mutex
	appFrameStore             map[string]*protobufs.AppShardFrame
	appFrameStoreMu           sync.RWMutex
	lowCoverageStreak         map[string]*coverageStreak
	proverOnlyMode            atomic.Bool
	coverageCheckInProgress   atomic.Bool
	peerInfoDigestCache       map[string]struct{}
	peerInfoDigestCacheMu     sync.Mutex
	keyRegistryDigestCache    map[string]struct{}
	keyRegistryDigestCacheMu  sync.Mutex
	peerAuthCache             map[string]time.Time
	peerAuthCacheMu           sync.RWMutex
	appShardCache             map[string]*appShardCacheEntry
	appShardCacheMu           sync.RWMutex
	appShardCacheRank         uint64

	// Transaction cross-shard lock tracking
	txLockMap map[uint64]map[string]map[string]*LockedTransaction
	txLockMu  sync.RWMutex

	// Consensus participant instance
	consensusParticipant consensus.EventLoop[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
	]

	// Consensus plugins
	signatureAggregator         consensus.SignatureAggregator
	voteCollectorDistributor    *pubsub.VoteCollectorDistributor[*protobufs.ProposalVote]
	timeoutCollectorDistributor *pubsub.TimeoutCollectorDistributor[*protobufs.ProposalVote]
	voteAggregator              consensus.VoteAggregator[*protobufs.GlobalFrame, *protobufs.ProposalVote]
	timeoutAggregator           consensus.TimeoutAggregator[*protobufs.ProposalVote]

	// Provider implementations
	syncProvider     *qsync.SyncProvider[*protobufs.GlobalFrame, *protobufs.GlobalProposal]
	votingProvider   *GlobalVotingProvider
	leaderProvider   *GlobalLeaderProvider
	livenessProvider *GlobalLivenessProvider

	// Cross-provider state
	collectedMessages      [][]byte
	shardCommitments       [][]byte
	proverRoot             []byte
	commitmentHash         []byte
	shardCommitmentTrees   []*tries.VectorCommitmentTree
	shardCommitmentKeySets []map[string]struct{}
	shardCommitmentMu      sync.Mutex

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
		proposalCache:               make(map[uint64]*protobufs.GlobalProposal),
		pendingCertifiedParents:     make(map[uint64]*protobufs.GlobalProposal),
		activeProveRanks:            make(map[uint64]struct{}),
		shardCommitmentTrees:        make([]*tries.VectorCommitmentTree, 256),
		shardCommitmentKeySets:      make([]map[string]struct{}, 256),
		globalConsensusMessageQueue: make(chan *pb.Message, 1000),
		globalFrameMessageQueue:     make(chan *pb.Message, 100),
		globalProverMessageQueue:    make(chan *pb.Message, 1000),
		appFramesMessageQueue:       make(chan *pb.Message, 10000),
		globalPeerInfoMessageQueue:  make(chan *pb.Message, 1000),
		globalAlertMessageQueue:     make(chan *pb.Message, 100),
		shardConsensusMessageQueue:  make(chan *pb.Message, 10000),
		globalProposalQueue:         make(chan *protobufs.GlobalProposal, 1000),
		currentDifficulty:           config.Engine.Difficulty,
		lastProvenFrameTime:         time.Now(),
		blacklistMap:                make(map[string]bool),
		peerInfoDigestCache:         make(map[string]struct{}),
		keyRegistryDigestCache:      make(map[string]struct{}),
		peerAuthCache:               make(map[string]time.Time),
		alertPublicKey:              []byte{},
		txLockMap:                   make(map[uint64]map[string]map[string]*LockedTransaction),
		appShardCache:               make(map[string]*appShardCacheEntry),
		globalMessageSpillover:      make(map[uint64][][]byte),
	}
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

	globalTimeReel.SetMaterializeFunc(engine.materialize)
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

	// Create provider implementations
	engine.votingProvider = &GlobalVotingProvider{engine: engine}
	engine.leaderProvider = &GlobalLeaderProvider{engine: engine}
	engine.livenessProvider = &GlobalLivenessProvider{engine: engine}
	engine.signatureAggregator = aggregator.WrapSignatureAggregator(
		engine.blsConstructor,
		engine.proverRegistry,
		nil,
	)
	voteAggregationDistributor := voting.NewGlobalVoteAggregationDistributor()
	engine.voteCollectorDistributor =
		voteAggregationDistributor.VoteCollectorDistributor
	timeoutAggregationDistributor :=
		voting.NewGlobalTimeoutAggregationDistributor()
	engine.timeoutCollectorDistributor =
		timeoutAggregationDistributor.TimeoutCollectorDistributor

	// Create the worker manager
	engine.workerManager = mgr.NewWorkerManager(
		workerStore,
		logger,
		config,
		engine.ProposeWorkerJoin,
		engine.DecideWorkerJoins,
	)
	if !config.Engine.ArchiveMode {
		strategy := provers.RewardGreedy
		if config.Engine.RewardStrategy != "reward-greedy" {
			strategy = provers.DataGreedy
		}
		engine.proposer = provers.NewManager(
			logger,
			workerStore,
			engine.workerManager,
			8000000000,
			strategy,
		)
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
			engine.blacklistMap[string(addressBytes)] = true
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
		})
	}

	// Add execution engines
	componentBuilder.AddWorker(engine.executionManager.Start)
	componentBuilder.AddWorker(engine.globalTimeReel.Start)
	componentBuilder.AddWorker(engine.startGlobalMessageAggregator)

	adds := engine.hypergraph.(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(
		tries.ShardKey{
			L1: [3]byte{},
			L2: [32]byte(bytes.Repeat([]byte{0xff}, 32)),
		},
	)

	if lc, _ := adds.GetTree().GetMetadata(); lc == 0 {
		if config.P2P.Network == 0 {
			genesisData := engine.getMainnetGenesisJSON()
			if genesisData == nil {
				panic("no genesis data")
			}

			state := hgstate.NewHypergraphState(engine.hypergraph)

			err = engine.establishMainnetGenesisProvers(state, genesisData)
			if err != nil {
				engine.logger.Error("failed to establish provers", zap.Error(err))
				panic(err)
			}

			err = state.Commit()
			if err != nil {
				engine.logger.Error("failed to commit", zap.Error(err))
				panic(err)
			}
		} else {
			engine.establishTestnetGenesisProvers()
		}

		err := engine.proverRegistry.Refresh()
		if err != nil {
			panic(err)
		}
	}

	if engine.config.P2P.Network == 99 || engine.config.Engine.ArchiveMode {
		latest, err := engine.consensusStore.GetConsensusState(nil)
		var state *models.CertifiedState[*protobufs.GlobalFrame]
		var pending []*models.SignedProposal[
			*protobufs.GlobalFrame,
			*protobufs.ProposalVote,
		]
		establishGenesis := func() {
			frame, qc := engine.initializeGenesis()
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
			if _, rebuildErr := engine.rebuildShardCommitments(
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
				logger.Info(
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
				logger.Info(
					"obtained latest consensus state",
					zap.Uint64("finalized_rank", latest.FinalizedRank),
					zap.Uint64("latest_acknowledged_rank", latest.LatestAcknowledgedRank),
				)
			}
			qc, err := engine.clockStore.GetQuorumCertificate(
				nil,
				latest.FinalizedRank,
			)
			if err != nil {
				panic(err)
			} else {
				if qc.GetFrameNumber() == 0 {
					establishGenesis()
				} else {
					frame, err := engine.clockStore.GetGlobalClockFrameCandidate(
						qc.GetFrameNumber(),
						qc.Selector,
					)
					if err != nil {
						panic(err)
					} else {
						if _, rebuildErr := engine.rebuildShardCommitments(
							frame.Header.FrameNumber+1,
							frame.Header.Rank+1,
						); rebuildErr != nil {
							logger.Warn(
								"could not initialize shard commitments from latest frame",
								zap.Error(rebuildErr),
							)
						}
						parentFrame, err := engine.clockStore.GetGlobalClockFrameCandidate(
							qc.GetFrameNumber()-1,
							frame.Header.ParentSelector,
						)
						if err != nil {
							panic(err)
						} else {
							parentQC, err := engine.clockStore.GetQuorumCertificate(
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
								pending = engine.getPendingProposals(frame.Header.FrameNumber)
							}
						}
					}
				}
			}
			as, err := engine.shardsStore.RangeAppShards()
			engine.logger.Info("verifying app shard information")
			if err != nil || len(as) == 0 {
				engine.initializeGenesis()
			}
		}
		liveness, err := engine.consensusStore.GetLivenessState(nil)
		if err == nil {
			engine.currentRank = liveness.CurrentRank
		}
		engine.voteAggregator, err = voting.NewGlobalVoteAggregator[GlobalPeerID](
			tracing.NewZapTracer(logger),
			engine,
			voteAggregationDistributor,
			engine.signatureAggregator,
			engine.votingProvider,
			func(qc models.QuorumCertificate) {
				select {
				case <-engine.haltCtx.Done():
					return
				default:
				}
				engine.consensusParticipant.OnQuorumCertificateConstructedFromVotes(qc)
			},
			state.Rank()+1,
		)
		if err != nil {
			return nil, err
		}

		if latest == nil {
			if err := engine.rebuildAppShardCache(0); err != nil {
				logger.Warn("could not prime app shard cache", zap.Error(err))
			}
		} else {
			if err := engine.rebuildAppShardCache(latest.FinalizedRank); err != nil {
				logger.Warn("could not prime app shard cache", zap.Error(err))
			}
		}
		engine.timeoutAggregator, err = voting.NewGlobalTimeoutAggregator[GlobalPeerID](
			tracing.NewZapTracer(logger),
			engine,
			engine,
			engine.signatureAggregator,
			timeoutAggregationDistributor,
			engine.votingProvider,
			state.Rank()+1,
		)

		notifier := pubsub.NewDistributor[
			*protobufs.GlobalFrame,
			*protobufs.ProposalVote,
		]()
		notifier.AddConsumer(engine)
		engine.notifier = notifier

		forks, err := forks.NewForks(state, engine, notifier)
		if err != nil {
			return nil, err
		}

		engine.forks = forks

		engine.syncProvider = qsync.NewSyncProvider[
			*protobufs.GlobalFrame,
			*protobufs.GlobalProposal,
		](
			logger,
			forks,
			proverRegistry,
			signerRegistry,
			peerInfoManager,
			qsync.NewGlobalSyncClient(
				frameProver,
				blsConstructor,
				engine,
				config,
			),
			hypergraph,
			config,
			nil,
			engine.proverAddress,
			nil,
		)

		// Add sync provider
		componentBuilder.AddWorker(engine.syncProvider.Start)

		// Add consensus
		componentBuilder.AddWorker(func(
			ctx lifecycle.SignalerContext,
			ready lifecycle.ReadyFunc,
		) {
			if err := engine.startConsensus(state, pending, ctx, ready); err != nil {
				engine.logger.Error("could not start consensus", zap.Error(err))
				ctx.Throw(err)
				return
			}

			<-ctx.Done()
			<-lifecycle.AllDone(engine.voteAggregator, engine.timeoutAggregator)
		})
	} else {
		as, err := engine.shardsStore.RangeAppShards()
		engine.logger.Info("verifying app shard information")
		if err != nil || len(as) == 0 {
			engine.initializeGenesis()
		}

		engine.syncProvider = qsync.NewSyncProvider[
			*protobufs.GlobalFrame,
			*protobufs.GlobalProposal,
		](
			logger,
			nil,
			proverRegistry,
			signerRegistry,
			peerInfoManager,
			qsync.NewGlobalSyncClient(
				frameProver,
				blsConstructor,
				engine,
				config,
			),
			hypergraph,
			config,
			nil,
			engine.proverAddress,
			nil,
		)
	}

	componentBuilder.AddWorker(engine.peerInfoManager.Start)

	// Subscribe to global consensus if participating
	err = engine.subscribeToGlobalConsensus()
	if err != nil {
		return nil, err
	}

	// Subscribe to shard consensus messages to broker lock agreement
	err = engine.subscribeToShardConsensusMessages()
	if err != nil {
		return nil, errors.Wrap(err, "start")
	}

	// Subscribe to frames
	err = engine.subscribeToFrameMessages()
	if err != nil {
		return nil, errors.Wrap(err, "start")
	}

	// Subscribe to prover messages
	err = engine.subscribeToProverMessages()
	if err != nil {
		return nil, errors.Wrap(err, "start")
	}

	// Subscribe to peer info messages
	err = engine.subscribeToPeerInfoMessages()
	if err != nil {
		return nil, errors.Wrap(err, "start")
	}

	// Subscribe to alert messages
	err = engine.subscribeToAlertMessages()
	if err != nil {
		return nil, errors.Wrap(err, "start")
	}

	// Start consensus message queue processor
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.processGlobalConsensusMessageQueue(ctx)
	})

	// Start shard consensus message queue processor
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.processShardConsensusMessageQueue(ctx)
	})

	// Start frame message queue processor
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.processFrameMessageQueue(ctx)
	})

	// Start prover message queue processor
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.processProverMessageQueue(ctx)
	})

	// Start peer info message queue processor
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.processPeerInfoMessageQueue(ctx)
	})

	// Start alert message queue processor
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.processAlertMessageQueue(ctx)
	})

	// Start global proposal queue processor
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.processGlobalProposalQueue(ctx)
	})

	// Start periodic peer info reporting
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.reportPeerInfoPeriodically(ctx)
	})

	// Start event distributor event loop
	componentBuilder.AddWorker(engine.eventDistributor.Start)
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.eventDistributorLoop(ctx)
	})

	// Start periodic metrics update
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.updateMetrics(ctx)
	})

	if !engine.config.Engine.ArchiveMode {
		componentBuilder.AddWorker(func(
			ctx lifecycle.SignalerContext,
			ready lifecycle.ReadyFunc,
		) {
			ready()
			engine.monitorNodeHealth(ctx)
		})
	}

	// Start periodic tx lock pruning
	componentBuilder.AddWorker(func(
		ctx lifecycle.SignalerContext,
		ready lifecycle.ReadyFunc,
	) {
		ready()
		engine.pruneTxLocksPeriodically(ctx)
	})

	if engine.grpcServer != nil {
		// Register all services with the gRPC server
		engine.RegisterServices(engine.grpcServer)

		// Start serving the gRPC server
		componentBuilder.AddWorker(func(
			ctx lifecycle.SignalerContext,
			ready lifecycle.ReadyFunc,
		) {
			go func() {
				if err := engine.grpcServer.Serve(engine.grpcListener); err != nil {
					engine.logger.Error("gRPC server error", zap.Error(err))
					ctx.Throw(err)
				}
			}()
			ready()
			engine.logger.Info("started gRPC server",
				zap.String("address", engine.grpcListener.Addr().String()))
			<-ctx.Done()
			engine.logger.Info("stopping gRPC server")
			engine.grpcServer.GracefulStop()
			if engine.grpcListener != nil {
				engine.grpcListener.Close()
			}
		})
	}

	engine.ComponentManager = componentBuilder.Build()
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

	return engine, nil
}

func (e *GlobalConsensusEngine) tryBeginProvingRank(rank uint64) bool {
	e.activeProveRanksMu.Lock()
	defer e.activeProveRanksMu.Unlock()

	if _, exists := e.activeProveRanks[rank]; exists {
		return false
	}

	e.activeProveRanks[rank] = struct{}{}
	return true
}

func (e *GlobalConsensusEngine) endProvingRank(rank uint64) {
	e.activeProveRanksMu.Lock()
	delete(e.activeProveRanks, rank)
	e.activeProveRanksMu.Unlock()
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
			"/quilibrium.node.global.pb.GlobalService/GetLockedAddresses": channel.OnlySelfPeer,
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
		grpc.MaxRecvMsgSize(10*1024*1024),
		grpc.MaxSendMsgSize(10*1024*1024),
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
	if e.config.Engine.ArchiveMode || e.config.P2P.Network == 99 {
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
	if e.config.P2P.Network != 99 && !e.config.Engine.ArchiveMode {
		return typesconsensus.EngineStateVerifying
	}

	// Map the generic state machine state to engine state
	select {
	case <-e.consensusParticipant.Ready():
		return typesconsensus.EngineStateProving
	case <-e.consensusParticipant.Done():
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

func (e *GlobalConsensusEngine) materialize(
	txn store.Transaction,
	frame *protobufs.GlobalFrame,
) error {
	frameNumber := frame.Header.FrameNumber
	requests := frame.Requests
	expectedProverRoot := frame.Header.ProverTreeCommitment
	proposer := frame.Header.Prover
	start := time.Now()
	var appliedCount atomic.Int64
	var skippedCount atomic.Int64

	_, err := e.hypergraph.Commit(frameNumber)
	if err != nil {
		e.logger.Error("error committing hypergraph", zap.Error(err))
		return errors.Wrap(err, "materialize")
	}

	var expectedRootHex string
	localRootHex := ""

	// Check prover root BEFORE processing transactions. If there's a mismatch,
	// we need to sync first, otherwise we'll apply transactions on top of
	// divergent state and then sync will delete the newly added records.
	if len(expectedProverRoot) > 0 {
		localProverRoot, localRootErr := e.computeLocalProverRoot(frameNumber)
		if localRootErr != nil {
			e.logger.Warn(
				"failed to compute local prover root",
				zap.Uint64("frame_number", frameNumber),
				zap.Error(localRootErr),
			)
		}

		updatedProverRoot := localProverRoot
		if localRootErr == nil && len(localProverRoot) > 0 {
			if !bytes.Equal(localProverRoot, expectedProverRoot) {
				e.logger.Info(
					"prover root mismatch detected before processing frame, syncing first",
					zap.Uint64("frame_number", frameNumber),
					zap.String("expected_root", hex.EncodeToString(expectedProverRoot)),
					zap.String("local_root", hex.EncodeToString(localProverRoot)),
				)
				// Perform blocking hypersync before continuing
				_ = e.performBlockingProverHypersync(
					proposer,
					expectedProverRoot,
				)

				// Re-compute local prover root after sync to verify convergence
				newLocalRoot, newRootErr := e.computeLocalProverRoot(frameNumber)
				if newRootErr != nil {
					e.logger.Warn(
						"failed to compute local prover root after sync",
						zap.Uint64("frame_number", frameNumber),
						zap.Error(newRootErr),
					)
				} else {
					updatedProverRoot = newLocalRoot
					if !bytes.Equal(newLocalRoot, expectedProverRoot) {
						e.logger.Warn(
							"prover root still mismatched after sync - convergence failed",
							zap.Uint64("frame_number", frameNumber),
							zap.String("expected_root", hex.EncodeToString(expectedProverRoot)),
							zap.String("post_sync_local_root", hex.EncodeToString(newLocalRoot)),
						)
					} else {
						e.logger.Info(
							"prover root converged after sync",
							zap.Uint64("frame_number", frameNumber),
							zap.String("root", hex.EncodeToString(newLocalRoot)),
						)
					}
				}
			}
		}

		// Publish the snapshot generation with the new root so clients can sync
		// against this specific state.
		if len(updatedProverRoot) > 0 {
			if hgCRDT, ok := e.hypergraph.(*hgcrdt.HypergraphCRDT); ok {
				hgCRDT.PublishSnapshot(updatedProverRoot)
			}
		}

		if len(expectedProverRoot) > 0 {
			expectedRootHex = hex.EncodeToString(expectedProverRoot)
		}
		if len(localProverRoot) > 0 {
			localRootHex = hex.EncodeToString(localProverRoot)
		}

		if bytes.Equal(updatedProverRoot, expectedProverRoot) {
			e.proverRootSynced.Store(true)
			e.proverRootVerifiedFrame.Store(frameNumber)
		}
	}

	var state state.State
	state = hgstate.NewHypergraphState(e.hypergraph)

	e.logger.Debug(
		"materializing messages",
		zap.Int("message_count", len(requests)),
	)
	worldSize := e.hypergraph.GetSize(nil, nil).Uint64()
	e.currentDifficultyMu.RLock()
	difficulty := uint64(e.currentDifficulty)
	e.currentDifficultyMu.RUnlock()

	eg := errgroup.Group{}
	eg.SetLimit(len(requests))

	for i, request := range requests {
		idx := i
		req := request
		eg.Go(func() error {
			requestBytes, err := req.ToCanonicalBytes()

			if err != nil {
				e.logger.Error(
					"error serializing request",
					zap.Int("message_index", idx),
					zap.Error(err),
				)
				return errors.Wrap(err, "materialize")
			}

			if len(requestBytes) == 0 {
				e.logger.Error(
					"empty request bytes",
					zap.Int("message_index", idx),
				)
				return errors.Wrap(errors.New("empty request"), "materialize")
			}

			costBasis, err := e.executionManager.GetCost(requestBytes)
			if err != nil {
				e.logger.Error(
					"invalid message",
					zap.Int("message_index", idx),
					zap.Error(err),
				)
				skippedCount.Add(1)
				return nil
			}

			var baseline *big.Int
			if costBasis.Cmp(big.NewInt(0)) == 0 {
				baseline = big.NewInt(0)
			} else {
				baseline = reward.GetBaselineFee(
					difficulty,
					worldSize,
					costBasis.Uint64(),
					8000000000,
				)
				baseline.Quo(baseline, costBasis)
			}

			_, err = e.executionManager.ProcessMessage(
				frameNumber,
				baseline,
				bytes.Repeat([]byte{0xff}, 32),
				requestBytes,
				state,
			)
			if err != nil {
				e.logger.Error(
					"error processing message",
					zap.Int("message_index", idx),
					zap.Error(err),
				)
				skippedCount.Add(1)
				return nil
			}
			appliedCount.Add(1)

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	if err := state.Commit(); err != nil {
		return errors.Wrap(err, "materialize")
	}

	// Persist any alt shard updates from this frame
	if err := e.persistAltShardUpdates(frameNumber, requests); err != nil {
		e.logger.Error(
			"failed to persist alt shard updates",
			zap.Uint64("frame_number", frameNumber),
			zap.Error(err),
		)
	}

	err = e.proverRegistry.ProcessStateTransition(state, frameNumber)
	if err != nil {
		return errors.Wrap(err, "materialize")
	}

	err = e.proverRegistry.PruneOrphanJoins(frameNumber)
	if err != nil {
		return errors.Wrap(err, "materialize")
	}

	if len(localRootHex) > 0 {
		e.reconcileLocalWorkerAllocations()
	}

	e.logger.Info(
		"materialized global frame",
		zap.Uint64("frame_number", frameNumber),
		zap.Int("request_count", len(requests)),
		zap.Int("applied_requests", int(appliedCount.Load())),
		zap.Int("skipped_requests", int(skippedCount.Load())),
		zap.String("expected_root", expectedRootHex),
		zap.String("local_root", localRootHex),
		zap.String("proposer", hex.EncodeToString(proposer)),
		zap.Duration("duration", time.Since(start)),
	)

	return nil
}

// persistAltShardUpdates iterates through frame requests to find and persist
// any AltShardUpdate messages to the hypergraph store.
func (e *GlobalConsensusEngine) persistAltShardUpdates(
	frameNumber uint64,
	requests []*protobufs.MessageBundle,
) error {
	var altUpdates []*protobufs.AltShardUpdate

	// Collect all alt shard updates from the frame's requests
	for _, bundle := range requests {
		if bundle == nil {
			continue
		}
		for _, req := range bundle.Requests {
			if req == nil {
				continue
			}
			if altUpdate := req.GetAltShardUpdate(); altUpdate != nil {
				altUpdates = append(altUpdates, altUpdate)
			}
		}
	}

	if len(altUpdates) == 0 {
		return nil
	}

	// Create a transaction for the hypergraph store
	txn, err := e.hypergraphStore.NewTransaction(false)
	if err != nil {
		return errors.Wrap(err, "persist alt shard updates")
	}

	for _, update := range altUpdates {
		// Derive shard address from public key
		if len(update.PublicKey) == 0 {
			e.logger.Warn("alt shard update with empty public key, skipping")
			continue
		}

		addrBI, err := poseidon.HashBytes(update.PublicKey)
		if err != nil {
			e.logger.Warn(
				"failed to hash alt shard public key",
				zap.Error(err),
			)
			continue
		}
		shardAddress := addrBI.FillBytes(make([]byte, 32))

		// Persist the alt shard commit
		err = e.hypergraphStore.SetAltShardCommit(
			txn,
			frameNumber,
			shardAddress,
			update.VertexAddsRoot,
			update.VertexRemovesRoot,
			update.HyperedgeAddsRoot,
			update.HyperedgeRemovesRoot,
		)
		if err != nil {
			txn.Abort()
			return errors.Wrap(err, "persist alt shard updates")
		}

		e.logger.Debug(
			"persisted alt shard update",
			zap.Uint64("frame_number", frameNumber),
			zap.String("shard_address", hex.EncodeToString(shardAddress)),
		)
	}

	if err := txn.Commit(); err != nil {
		return errors.Wrap(err, "persist alt shard updates")
	}

	e.logger.Info(
		"persisted alt shard updates",
		zap.Uint64("frame_number", frameNumber),
		zap.Int("count", len(altUpdates)),
	)

	return nil
}

func (e *GlobalConsensusEngine) computeLocalProverRoot(
	frameNumber uint64,
) ([]byte, error) {
	if e.hypergraph == nil {
		return nil, errors.New("hypergraph unavailable")
	}

	commitSet, err := e.hypergraph.Commit(frameNumber)
	if err != nil {
		return nil, errors.Wrap(err, "compute local prover root")
	}

	var zeroShardKey tries.ShardKey
	for shardKey, phaseCommits := range commitSet {
		if shardKey.L1 == zeroShardKey.L1 {
			if len(phaseCommits) == 0 || len(phaseCommits[0]) == 0 {
				return nil, errors.New("empty prover root commitment")
			}
			return slices.Clone(phaseCommits[0]), nil
		}
	}

	return nil, errors.New("prover root shard missing")
}

func (e *GlobalConsensusEngine) verifyProverRoot(
	frameNumber uint64,
	expected []byte,
	localRoot []byte,
	proposer []byte,
) bool {
	if len(expected) == 0 || len(localRoot) == 0 {
		return true
	}

	if !bytes.Equal(localRoot, expected) {
		e.logger.Warn(
			"prover root mismatch",
			zap.Uint64("frame_number", frameNumber),
			zap.String("expected_root", hex.EncodeToString(expected)),
			zap.String("local_root", hex.EncodeToString(localRoot)),
			zap.String("proposer", hex.EncodeToString(proposer)),
		)
		e.proverRootSynced.Store(false)
		e.proverRootVerifiedFrame.Store(0)
		e.triggerProverHypersync(proposer, expected)
		return false
	}

	e.logger.Debug(
		"prover root verified",
		zap.Uint64("frame_number", frameNumber),
		zap.String("root", hex.EncodeToString(localRoot)),
		zap.String("proposer", hex.EncodeToString(proposer)),
	)

	e.proverRootSynced.Store(true)
	e.proverRootVerifiedFrame.Store(frameNumber)
	return true
}

func (e *GlobalConsensusEngine) triggerProverHypersync(proposer []byte, expectedRoot []byte) {
	if e.syncProvider == nil || len(proposer) == 0 {
		e.logger.Debug("no sync provider or proposer")
		return
	}
	if bytes.Equal(proposer, e.getProverAddress()) {
		e.logger.Debug("we are the proposer")
		return
	}
	if !e.proverSyncInProgress.CompareAndSwap(false, true) {
		e.logger.Debug("already syncing")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer e.proverSyncInProgress.Store(false)

		shardKey := tries.ShardKey{
			L1: [3]byte{0x00, 0x00, 0x00},
			L2: intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		}
		e.syncProvider.HyperSync(ctx, proposer, shardKey, nil, expectedRoot)
		if err := e.proverRegistry.Refresh(); err != nil {
			e.logger.Warn(
				"failed to refresh prover registry after hypersync",
				zap.Error(err),
			)
		}
		cancel()
	}()

	go func() {
		select {
		case <-e.ShutdownSignal():
			cancel()
		case <-ctx.Done():
		}
	}()
}

// performBlockingProverHypersync performs a synchronous hypersync that blocks
// until completion. This is used at the start of materialize to ensure we sync
// before applying any transactions when there's a prover root mismatch.
func (e *GlobalConsensusEngine) performBlockingProverHypersync(
	proposer []byte,
	expectedRoot []byte,
) []byte {
	if e.syncProvider == nil || len(proposer) == 0 {
		e.logger.Debug("blocking hypersync: no sync provider or proposer")
		return nil
	}
	if bytes.Equal(proposer, e.getProverAddress()) {
		e.logger.Debug("blocking hypersync: we are the proposer")
		return nil
	}

	// Wait for any existing sync to complete first
	for e.proverSyncInProgress.Load() {
		e.logger.Debug("blocking hypersync: waiting for existing sync to complete")
		time.Sleep(100 * time.Millisecond)
	}

	// Mark sync as in progress
	if !e.proverSyncInProgress.CompareAndSwap(false, true) {
		// Another sync started, wait for it
		for e.proverSyncInProgress.Load() {
			time.Sleep(100 * time.Millisecond)
		}
		return nil
	}
	defer e.proverSyncInProgress.Store(false)

	e.logger.Info(
		"performing blocking hypersync before processing frame",
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

	shardKey := tries.ShardKey{
		L1: [3]byte{0x00, 0x00, 0x00},
		L2: intrinsics.GLOBAL_INTRINSIC_ADDRESS,
	}

	// Perform sync synchronously (blocking)
	newRoots := e.syncProvider.HyperSync(ctx, proposer, shardKey, nil, expectedRoot)
	close(done)

	e.logger.Info("blocking hypersync completed")
	if len(newRoots) == 0 {
		return nil
	}

	return newRoots[0]
}

func (e *GlobalConsensusEngine) reconcileLocalWorkerAllocations() {
	if e.config.Engine.ArchiveMode {
		return
	}
	if e.workerManager == nil || e.proverRegistry == nil {
		return
	}
	workers, err := e.workerManager.RangeWorkers()
	if err != nil || len(workers) == 0 {
		if err != nil {
			e.logger.Warn(
				"failed to range workers for reconciliation",
				zap.Error(err),
			)
		}
		return
	}

	info, err := e.proverRegistry.GetProverInfo(e.getProverAddress())
	if err != nil || info == nil {
		if err != nil {
			e.logger.Warn(
				"failed to load prover info for reconciliation",
				zap.Error(err),
			)
		}
		return
	}

	statusByFilter := make(
		map[string]typesconsensus.ProverStatus,
		len(info.Allocations),
	)
	for _, alloc := range info.Allocations {
		if len(alloc.ConfirmationFilter) == 0 {
			continue
		}
		statusByFilter[hex.EncodeToString(alloc.ConfirmationFilter)] = alloc.Status
	}

	for _, worker := range workers {
		if len(worker.Filter) == 0 {
			continue
		}
		key := hex.EncodeToString(worker.Filter)
		status, ok := statusByFilter[key]
		if !ok {
			if worker.Allocated {
				if err := e.workerManager.DeallocateWorker(worker.CoreId); err != nil {
					e.logger.Warn(
						"failed to deallocate worker for missing allocation",
						zap.Uint("core_id", worker.CoreId),
						zap.Error(err),
					)
				}
			}
			continue
		}

		switch status {
		case typesconsensus.ProverStatusActive:
			if !worker.Allocated {
				if err := e.workerManager.AllocateWorker(
					worker.CoreId,
					worker.Filter,
				); err != nil {
					e.logger.Warn(
						"failed to allocate worker after confirmation",
						zap.Uint("core_id", worker.CoreId),
						zap.Error(err),
					)
				}
			}
		case typesconsensus.ProverStatusLeaving,
			typesconsensus.ProverStatusRejected,
			typesconsensus.ProverStatusKicked:
			if worker.Allocated {
				if err := e.workerManager.DeallocateWorker(worker.CoreId); err != nil {
					e.logger.Warn(
						"failed to deallocate worker after status change",
						zap.Uint("core_id", worker.CoreId),
						zap.Error(err),
					)
				}
			}
		}
	}
}

func (e *GlobalConsensusEngine) joinProposalReady(
	frameNumber uint64,
) (bool, string) {
	if e.lastObservedFrame.Load() == 0 {
		e.logger.Debug("join proposal blocked: no observed frame")
		return false, "awaiting initial frame"
	}

	if !e.proverRootSynced.Load() {
		e.logger.Debug("join proposal blocked: prover root not synced")
		return false, "awaiting prover root sync"
	}

	verified := e.proverRootVerifiedFrame.Load()
	if verified == 0 || verified < frameNumber {
		e.logger.Debug(
			"join proposal blocked: frame not verified",
			zap.Uint64("verified_frame", verified),
			zap.Uint64("current_frame", frameNumber),
		)
		return false, "latest frame not yet verified"
	}

	lastAttempt := e.lastJoinAttemptFrame.Load()
	if lastAttempt != 0 {
		if frameNumber <= lastAttempt {
			e.logger.Debug(
				"join proposal blocked: waiting for newer frame",
				zap.Uint64("last_attempt", lastAttempt),
				zap.Uint64("current_frame", frameNumber),
			)
			return false, "waiting for newer frame"
		}
		if frameNumber-lastAttempt < 4 {
			e.logger.Debug(
				"join proposal blocked: cooling down between attempts",
				zap.Uint64("last_attempt", lastAttempt),
				zap.Uint64("current_frame", frameNumber),
			)
			return false, "cooldown between join attempts"
		}
	}

	return true, ""
}

func (e *GlobalConsensusEngine) selectExcessPendingFilters(
	self *typesconsensus.ProverInfo,
) [][]byte {
	if self == nil || e.config == nil || e.config.Engine == nil {
		e.logger.Debug("excess pending evaluation skipped: missing config or prover info")
		return nil
	}

	capacity := e.config.Engine.DataWorkerCount
	if capacity <= 0 {
		return nil
	}

	active := 0
	pending := make([][]byte, 0, len(self.Allocations))

	for _, allocation := range self.Allocations {
		if len(allocation.ConfirmationFilter) == 0 {
			continue
		}

		switch allocation.Status {
		case typesconsensus.ProverStatusActive:
			active++
		case typesconsensus.ProverStatusJoining:
			filterCopy := make([]byte, len(allocation.ConfirmationFilter))
			copy(filterCopy, allocation.ConfirmationFilter)
			pending = append(pending, filterCopy)
		}
	}

	allowedPending := capacity - active
	if allowedPending < 0 {
		allowedPending = 0
	}

	if len(pending) <= allowedPending {
		e.logger.Debug(
			"pending joins within limit",
			zap.Int("active_allocations", active),
			zap.Int("pending_allocations", len(pending)),
			zap.Int("capacity", capacity),
		)
		return nil
	}

	excess := len(pending) - allowedPending
	e.logger.Debug(
		"pending joins exceed limit",
		zap.Int("active_allocations", active),
		zap.Int("pending_allocations", len(pending)),
		zap.Int("capacity", capacity),
		zap.Int("excess", excess),
	)
	rand.Shuffle(len(pending), func(i, j int) {
		pending[i], pending[j] = pending[j], pending[i]
	})

	return pending[:excess]
}

func (e *GlobalConsensusEngine) rejectExcessPending(
	filters [][]byte,
	frameNumber uint64,
) {
	if e.workerManager == nil || len(filters) == 0 {
		return
	}

	last := e.lastRejectFrame.Load()
	if last != 0 {
		if frameNumber <= last {
			e.logger.Debug(
				"forced rejection skipped: awaiting newer frame",
				zap.Uint64("last_reject_frame", last),
				zap.Uint64("current_frame", frameNumber),
			)
			return
		}
		if frameNumber-last < 4 {
			e.logger.Debug(
				"deferring forced join rejections",
				zap.Uint64("frame_number", frameNumber),
				zap.Uint64("last_reject_frame", last),
			)
			return
		}
	}

	limit := len(filters)
	if limit > 100 {
		limit = 100
	}

	rejects := make([][]byte, limit)
	for i := 0; i < limit; i++ {
		rejects[i] = filters[i]
	}

	if err := e.workerManager.DecideAllocations(rejects, nil); err != nil {
		e.logger.Warn("failed to reject excess joins", zap.Error(err))
		return
	}

	e.lastRejectFrame.Store(frameNumber)
	e.logger.Info(
		"submitted forced join rejections",
		zap.Int("rejections", len(rejects)),
		zap.Uint64("frame_number", frameNumber),
	)
}

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

// isAddressBlacklisted checks if a given address (full or partial) is in the
// blacklist
func (e *GlobalConsensusEngine) isAddressBlacklisted(address []byte) bool {
	e.blacklistMu.RLock()
	defer e.blacklistMu.RUnlock()

	// Check for exact match first
	if e.blacklistMap[string(address)] {
		return true
	}

	// Check for prefix matches (for partial blacklist entries)
	for blacklistedAddress := range e.blacklistMap {
		// If the blacklisted address is shorter than the full address,
		// it's a prefix and we check if the address starts with it
		if len(blacklistedAddress) < len(address) {
			if strings.HasPrefix(string(address), blacklistedAddress) {
				return true
			}
		}
	}

	return false
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

	for {
		select {
		case <-ctx.Done():
			e.logger.Info("stopping periodic peer info reporting")
			return
		case <-ticker.C:
			e.logger.Debug("publishing periodic peer info")

			peerInfo := e.GetPeerInfo()

			peerInfoData, err := peerInfo.ToCanonicalBytes()
			if err != nil {
				e.logger.Error("failed to serialize peer info", zap.Error(err))
				continue
			}

			// Publish to the peer info bitmask
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

			e.publishKeyRegistry()
		}
	}
}

func (e *GlobalConsensusEngine) pruneTxLocksPeriodically(
	ctx lifecycle.SignalerContext,
) {
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

// TODO(2.1.1+): This could use refactoring
func (e *GlobalConsensusEngine) ProposeWorkerJoin(
	coreIds []uint,
	filters [][]byte,
	serviceClients map[uint]*grpc.ClientConn,
) error {
	frame := e.GetFrame()
	if frame == nil {
		e.logger.Debug("cannot propose, no frame")
		return errors.New("not ready")
	}

	_, err := e.keyManager.GetSigningKey("q-prover-key")
	if err != nil {
		e.logger.Debug("cannot propose, no signer key")
		return errors.Wrap(err, "propose worker join")
	}

	info, err := e.proverRegistry.GetProverInfo(e.getProverAddress())
	proverExists := err == nil && info != nil

	// Build merge helpers and calculate potential merge seniority
	helpers, peerIds := e.buildMergeHelpers()
	mergeSeniorityBI := compat.GetAggregatedSeniority(peerIds)
	var mergeSeniority uint64 = 0
	if mergeSeniorityBI.IsUint64() {
		mergeSeniority = mergeSeniorityBI.Uint64()
	}

	// If prover already exists, check if we should submit a seniority merge
	if proverExists {
		if mergeSeniority > info.Seniority {
			e.logger.Info(
				"existing prover has lower seniority than merge would provide, submitting seniority merge",
				zap.Uint64("existing_seniority", info.Seniority),
				zap.Uint64("merge_seniority", mergeSeniority),
				zap.Strings("peer_ids", peerIds),
			)
			return e.submitSeniorityMerge(frame, helpers, mergeSeniority, peerIds)
		}
		e.logger.Debug(
			"prover already exists with sufficient seniority, skipping join",
			zap.Uint64("existing_seniority", info.Seniority),
			zap.Uint64("merge_seniority", mergeSeniority),
		)
		return nil
	}

	e.logger.Info(
		"proposing worker join with seniority",
		zap.Uint64("seniority", mergeSeniority),
		zap.Strings("peer_ids", peerIds),
	)

	var delegate []byte
	if e.config.Engine.DelegateAddress != "" {
		delegate, err = hex.DecodeString(e.config.Engine.DelegateAddress)
		if err != nil {
			e.logger.Error("could not construct join", zap.Error(err))
			return errors.Wrap(err, "propose worker join")
		}
	}

	challenge := sha3.Sum256(frame.Header.Output)

	joins := min(len(serviceClients), len(filters))
	results := make([][516]byte, joins)
	idx := uint32(0)
	ids := [][]byte{}
	e.logger.Debug("preparing join commitment")
	for range joins {
		ids = append(
			ids,
			slices.Concat(
				e.getProverAddress(),
				filters[idx],
				binary.BigEndian.AppendUint32(nil, idx),
			),
		)
		idx++
	}

	idx = 0

	wg := errgroup.Group{}
	wg.SetLimit(joins)

	e.logger.Debug(
		"attempting join proof",
		zap.String("challenge", hex.EncodeToString(challenge[:])),
		zap.Uint64("difficulty", uint64(frame.Header.Difficulty)),
		zap.Int("ids_count", len(ids)),
	)

	for _, core := range coreIds {
		svc := serviceClients[core]
		i := idx

		// limit to available joins
		if i == uint32(joins) {
			break
		}
		wg.Go(func() error {
			client := protobufs.NewDataIPCServiceClient(svc)
			resp, err := client.CreateJoinProof(
				context.TODO(),
				&protobufs.CreateJoinProofRequest{
					Challenge:   challenge[:],
					Difficulty:  frame.Header.Difficulty,
					Ids:         ids,
					ProverIndex: i,
				},
			)
			if err != nil {
				return err
			}

			results[i] = [516]byte(resp.Response)
			return nil
		})
		idx++
	}
	e.logger.Debug("waiting for join proof to complete")

	err = wg.Wait()
	if err != nil {
		e.logger.Debug("failed join proof", zap.Error(err))
		return errors.Wrap(err, "propose worker join")
	}

	join, err := global.NewProverJoin(
		filters,
		frame.Header.FrameNumber,
		helpers,
		delegate,
		e.keyManager,
		e.hypergraph,
		schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, e.inclusionProver),
		e.frameProver,
		e.clockStore,
	)
	if err != nil {
		e.logger.Error("could not construct join", zap.Error(err))
		return errors.Wrap(err, "propose worker join")
	}

	for _, res := range results {
		join.Proof = append(join.Proof, res[:]...)
	}

	err = join.Prove(frame.Header.FrameNumber)
	if err != nil {
		e.logger.Error("could not construct join", zap.Error(err))
		return errors.Wrap(err, "propose worker join")
	}

	bundle := &protobufs.MessageBundle{
		Requests: []*protobufs.MessageRequest{
			{
				Request: &protobufs.MessageRequest_Join{
					Join: join.ToProtobuf(),
				},
			},
		},
		Timestamp: time.Now().UnixMilli(),
	}

	msg, err := bundle.ToCanonicalBytes()
	if err != nil {
		e.logger.Error("could not construct join", zap.Error(err))
		return errors.Wrap(err, "propose worker join")
	}

	err = e.pubsub.PublishToBitmask(
		GLOBAL_PROVER_BITMASK,
		msg,
	)
	if err != nil {
		e.logger.Error("could not construct join", zap.Error(err))
		return errors.Wrap(err, "propose worker join")
	}

	e.logger.Info(
		"submitted join request",
		zap.Uint64("seniority", mergeSeniority),
		zap.Strings("peer_ids", peerIds),
	)

	return nil
}

// buildMergeHelpers constructs the seniority merge helpers from the current
// peer key and any configured multisig prover enrollment paths.
func (e *GlobalConsensusEngine) buildMergeHelpers() ([]*global.SeniorityMerge, []string) {
	helpers := []*global.SeniorityMerge{}
	peerIds := []string{}

	peerPrivKey, err := hex.DecodeString(e.config.P2P.PeerPrivKey)
	if err != nil {
		e.logger.Debug("cannot decode peer key for merge helpers", zap.Error(err))
		return helpers, peerIds
	}

	oldProver, err := keys.Ed448KeyFromBytes(
		peerPrivKey,
		e.pubsub.GetPublicKey(),
	)
	if err != nil {
		e.logger.Debug("cannot get peer key for merge helpers", zap.Error(err))
		return helpers, peerIds
	}

	helpers = append(helpers, global.NewSeniorityMerge(
		crypto.KeyTypeEd448,
		oldProver,
	))
	peerIds = append(peerIds, peer.ID(e.pubsub.GetPeerID()).String())

	if len(e.config.Engine.MultisigProverEnrollmentPaths) != 0 {
		e.logger.Debug("loading old configs for merge helpers")
		for _, conf := range e.config.Engine.MultisigProverEnrollmentPaths {
			extraConf, err := config.LoadConfig(conf, "", false)
			if err != nil {
				e.logger.Error("could not load config for merge helpers", zap.Error(err))
				continue
			}

			peerPrivKey, err := hex.DecodeString(extraConf.P2P.PeerPrivKey)
			if err != nil {
				e.logger.Error("could not decode peer key for merge helpers", zap.Error(err))
				continue
			}

			privKey, err := pcrypto.UnmarshalEd448PrivateKey(peerPrivKey)
			if err != nil {
				e.logger.Error("could not unmarshal peer key for merge helpers", zap.Error(err))
				continue
			}

			pub := privKey.GetPublic()
			pubBytes, err := pub.Raw()
			if err != nil {
				e.logger.Error("could not get public key for merge helpers", zap.Error(err))
				continue
			}

			id, err := peer.IDFromPublicKey(pub)
			if err != nil {
				e.logger.Error("could not get peer ID for merge helpers", zap.Error(err))
				continue
			}

			priv, err := privKey.Raw()
			if err != nil {
				e.logger.Error("could not get private key for merge helpers", zap.Error(err))
				continue
			}

			signer, err := keys.Ed448KeyFromBytes(priv, pubBytes)
			if err != nil {
				e.logger.Error("could not create signer for merge helpers", zap.Error(err))
				continue
			}

			peerIds = append(peerIds, id.String())
			helpers = append(helpers, global.NewSeniorityMerge(
				crypto.KeyTypeEd448,
				signer,
			))
		}
	}

	return helpers, peerIds
}

// submitSeniorityMerge submits a seniority merge request to claim additional
// seniority from old peer keys for an existing prover.
func (e *GlobalConsensusEngine) submitSeniorityMerge(
	frame *protobufs.GlobalFrame,
	helpers []*global.SeniorityMerge,
	seniority uint64,
	peerIds []string,
) error {
	if len(helpers) == 0 {
		return errors.New("no merge helpers available")
	}

	seniorityMerge, err := global.NewProverSeniorityMerge(
		frame.Header.FrameNumber,
		helpers,
		e.hypergraph,
		schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, e.inclusionProver),
		e.keyManager,
	)
	if err != nil {
		e.logger.Error("could not construct seniority merge", zap.Error(err))
		return errors.Wrap(err, "submit seniority merge")
	}

	err = seniorityMerge.Prove(frame.Header.FrameNumber)
	if err != nil {
		e.logger.Error("could not prove seniority merge", zap.Error(err))
		return errors.Wrap(err, "submit seniority merge")
	}

	bundle := &protobufs.MessageBundle{
		Requests: []*protobufs.MessageRequest{
			{
				Request: &protobufs.MessageRequest_SeniorityMerge{
					SeniorityMerge: seniorityMerge.ToProtobuf(),
				},
			},
		},
		Timestamp: time.Now().UnixMilli(),
	}

	msg, err := bundle.ToCanonicalBytes()
	if err != nil {
		e.logger.Error("could not encode seniority merge bundle", zap.Error(err))
		return errors.Wrap(err, "submit seniority merge")
	}

	err = e.pubsub.PublishToBitmask(
		GLOBAL_PROVER_BITMASK,
		msg,
	)
	if err != nil {
		e.logger.Error("could not publish seniority merge", zap.Error(err))
		return errors.Wrap(err, "submit seniority merge")
	}

	e.logger.Info(
		"submitted seniority merge request",
		zap.Uint64("seniority", seniority),
		zap.Strings("peer_ids", peerIds),
	)

	return nil
}

func (e *GlobalConsensusEngine) DecideWorkerJoins(
	reject [][]byte,
	confirm [][]byte,
) error {
	frame := e.GetFrame()
	if frame == nil {
		e.logger.Debug("cannot decide, no frame")
		return errors.New("not ready")
	}

	_, err := e.keyManager.GetSigningKey("q-prover-key")
	if err != nil {
		e.logger.Debug("cannot decide, no signer key")
		return errors.Wrap(err, "decide worker joins")
	}

	bundle := &protobufs.MessageBundle{
		Requests: []*protobufs.MessageRequest{},
	}

	if len(reject) != 0 {
		rejectMessage, err := global.NewProverReject(
			reject,
			frame.Header.FrameNumber,
			e.keyManager,
			e.hypergraph,
			schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, e.inclusionProver),
		)
		if err != nil {
			e.logger.Error("could not construct reject", zap.Error(err))
			return errors.Wrap(err, "decide worker joins")
		}

		err = rejectMessage.Prove(frame.Header.FrameNumber)
		if err != nil {
			e.logger.Error("could not construct reject", zap.Error(err))
			return errors.Wrap(err, "decide worker joins")
		}

		bundle.Requests = append(bundle.Requests, &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_Reject{
				Reject: rejectMessage.ToProtobuf(),
			},
		})
	} else if len(confirm) != 0 {
		confirmMessage, err := global.NewProverConfirm(
			confirm,
			frame.Header.FrameNumber,
			e.keyManager,
			e.hypergraph,
			schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, e.inclusionProver),
		)
		if err != nil {
			e.logger.Error("could not construct confirm", zap.Error(err))
			return errors.Wrap(err, "decide worker joins")
		}

		err = confirmMessage.Prove(frame.Header.FrameNumber)
		if err != nil {
			e.logger.Error("could not construct confirm", zap.Error(err))
			return errors.Wrap(err, "decide worker joins")
		}

		bundle.Requests = append(bundle.Requests, &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_Confirm{
				Confirm: confirmMessage.ToProtobuf(),
			},
		})
	}

	bundle.Timestamp = time.Now().UnixMilli()

	msg, err := bundle.ToCanonicalBytes()
	if err != nil {
		e.logger.Error("could not construct decision", zap.Error(err))
		return errors.Wrap(err, "decide worker joins")
	}

	err = e.pubsub.PublishToBitmask(
		GLOBAL_PROVER_BITMASK,
		msg,
	)
	if err != nil {
		e.logger.Error("could not construct join decisions", zap.Error(err))
		return errors.Wrap(err, "decide worker joins")
	}

	e.logger.Debug("submitted join decisions")

	return nil
}

func (e *GlobalConsensusEngine) startConsensus(
	trustedRoot *models.CertifiedState[*protobufs.GlobalFrame],
	pending []*models.SignedProposal[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
	],
	ctx lifecycle.SignalerContext,
	ready lifecycle.ReadyFunc,
) error {
	var err error
	e.consensusParticipant, err = participant.NewParticipant[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
		GlobalPeerID,
		GlobalCollectedCommitments,
	](
		tracing.NewZapTracer(e.logger), // logger
		e,                              // committee
		verification.NewSigner[
			*protobufs.GlobalFrame,
			*protobufs.ProposalVote,
			GlobalPeerID,
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
		validator.NewValidator[*protobufs.GlobalFrame](e, e), // validator
		e.voteAggregator,    // voteAggregator
		e.timeoutAggregator, // timeoutAggregator
		e,                   // finalizer
		nil,                 // filter
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
func (e *GlobalConsensusEngine) MakeFinal(stateID models.Identity) error {
	// In a standard BFT-only approach, this would be how frames are finalized on
	// the time reel. But we're PoMW, so we don't rely on BFT for anything outside
	// of basic coordination. If the protocol were ever to move to something like
	// PoS, this would be one of the touch points to revisit.
	return nil
}

// OnCurrentRankDetails implements consensus.Consumer.
func (e *GlobalConsensusEngine) OnCurrentRankDetails(
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
func (e *GlobalConsensusEngine) OnDoubleProposeDetected(
	proposal1 *models.State[*protobufs.GlobalFrame],
	proposal2 *models.State[*protobufs.GlobalFrame],
) {
	select {
	case <-e.haltCtx.Done():
		return
	default:
	}
	e.eventDistributor.Publish(typesconsensus.ControlEvent{
		Type: typesconsensus.ControlEventGlobalEquivocation,
		Data: &consensustime.GlobalEvent{
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
func (e *GlobalConsensusEngine) OnEventProcessed() {}

// OnFinalizedState implements consensus.Consumer.
func (e *GlobalConsensusEngine) OnFinalizedState(
	state *models.State[*protobufs.GlobalFrame],
) {
}

// OnInvalidStateDetected implements consensus.Consumer.
func (e *GlobalConsensusEngine) OnInvalidStateDetected(
	err *models.InvalidProposalError[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
	],
) {
} // Presently a no-op, up for reconsideration

// OnLocalTimeout implements consensus.Consumer.
func (e *GlobalConsensusEngine) OnLocalTimeout(currentRank uint64) {}

// OnOwnProposal implements consensus.Consumer.
func (e *GlobalConsensusEngine) OnOwnProposal(
	proposal *models.SignedProposal[
		*protobufs.GlobalFrame,
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

		// Manually override the signature as the vdf prover's signature is invalid
		(*proposal.State.State).Header.PublicKeySignatureBls48581.Signature =
			(*proposal.Vote).PublicKeySignatureBls48581.Signature

		pbProposal := &protobufs.GlobalProposal{
			State:                       *proposal.State.State,
			ParentQuorumCertificate:     proposal.Proposal.State.ParentQuorumCertificate.(*protobufs.QuorumCertificate),
			PriorRankTimeoutCertificate: priorTC,
			Vote:                        *proposal.Vote,
		}
		frame := pbProposal.State
		var proverRootHex string
		if frame.Header != nil {
			proverRootHex = hex.EncodeToString(frame.Header.ProverTreeCommitment)
		}
		e.logger.Info(
			"publishing own global proposal",
			zap.Uint64("rank", frame.GetRank()),
			zap.Uint64("frame_number", frame.GetFrameNumber()),
			zap.Int("request_count", len(frame.GetRequests())),
			zap.String("prover_root", proverRootHex),
			zap.String("proposer", hex.EncodeToString([]byte(frame.Source()))),
		)
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

		err = e.clockStore.PutGlobalClockFrameCandidate(*proposal.State.State, txn)
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
			GLOBAL_CONSENSUS_BITMASK,
			data,
		); err != nil {
			e.logger.Error("could not publish", zap.Error(err))
		}
	}()
}

// OnOwnTimeout implements consensus.Consumer.
func (e *GlobalConsensusEngine) OnOwnTimeout(
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

	txn, err := e.clockStore.NewTransaction(false)
	if err != nil {
		e.logger.Error("could not create transaction", zap.Error(err))
		return
	}

	if err := e.clockStore.PutTimeoutVote(txn, pbTimeout); err != nil {
		e.logger.Error("could not put vote", zap.Error(err))
		txn.Abort()
		return
	}

	if err := txn.Commit(); err != nil {
		e.logger.Error("could not commit transaction", zap.Error(err))
		txn.Abort()
		return
	}

	e.logger.Debug(
		"aggregating own timeout",
		zap.Uint64("timeout_rank", timeout.Rank),
		zap.Uint64("vote_rank", (*timeout.Vote).Rank),
	)
	e.timeoutAggregator.AddTimeout(timeout)

	if err := e.pubsub.PublishToBitmask(
		GLOBAL_CONSENSUS_BITMASK,
		data,
	); err != nil {
		e.logger.Error("could not publish", zap.Error(err))
	}
}

// OnOwnVote implements consensus.Consumer.
func (e *GlobalConsensusEngine) OnOwnVote(
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

	txn, err := e.clockStore.NewTransaction(false)
	if err != nil {
		e.logger.Error("could not create transaction", zap.Error(err))
		return
	}

	if err := e.clockStore.PutProposalVote(txn, *vote); err != nil {
		e.logger.Error("could not put vote", zap.Error(err))
		txn.Abort()
		return
	}

	if err := txn.Commit(); err != nil {
		e.logger.Error("could not commit transaction", zap.Error(err))
		txn.Abort()
		return
	}

	e.voteAggregator.AddVote(vote)

	if err := e.pubsub.PublishToBitmask(
		GLOBAL_CONSENSUS_BITMASK,
		data,
	); err != nil {
		e.logger.Error("could not publish", zap.Error(err))
	}
}

// OnPartialTimeoutCertificate implements consensus.Consumer.
func (e *GlobalConsensusEngine) OnPartialTimeoutCertificate(
	currentRank uint64,
	partialTimeoutCertificate *consensus.PartialTimeoutCertificateCreated,
) {
}

// OnQuorumCertificateTriggeredRankChange implements consensus.Consumer.
func (e *GlobalConsensusEngine) OnQuorumCertificateTriggeredRankChange(
	oldRank uint64,
	newRank uint64,
	qc models.QuorumCertificate,
) {
	e.logger.Debug("processing certified state", zap.Uint64("rank", newRank-1))

	parentQC, err := e.clockStore.GetLatestQuorumCertificate(nil)
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
		frame, err = e.clockStore.GetGlobalClockFrameCandidate(
			qc.GetFrameNumber(),
			[]byte(qc.Identity()),
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

	cloned := frame.Clone().(*protobufs.GlobalFrame)
	cloned.Header.PublicKeySignatureBls48581 =
		&protobufs.BLS48581AggregateSignature{
			Signature: qc.GetAggregatedSignature().GetSignature(),
			PublicKey: &protobufs.BLS48581G2PublicKey{
				KeyValue: qc.GetAggregatedSignature().GetPubKey(),
			},
			Bitmask: qc.GetAggregatedSignature().GetBitmask(),
		}
	frameBytes, err := cloned.ToCanonicalBytes()
	if err == nil {
		e.pubsub.PublishToBitmask(GLOBAL_FRAME_BITMASK, frameBytes)
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

	priorRankTC, err := e.clockStore.GetTimeoutCertificate(nil, qc.GetRank()-1)
	if err != nil {
		e.logger.Debug("no prior rank TC to include", zap.Uint64("rank", newRank-1))
	}

	vote, err := e.clockStore.GetProposalVote(
		nil,
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

	proposal := &protobufs.GlobalProposal{
		State:                       frame,
		ParentQuorumCertificate:     parentQC,
		PriorRankTimeoutCertificate: priorRankTC,
		Vote:                        vote,
	}

	e.globalProposalQueue <- proposal
}

// OnRankChange implements consensus.Consumer.
func (e *GlobalConsensusEngine) OnRankChange(oldRank uint64, newRank uint64) {
	if e.currentRank == newRank {
		return
	}

	e.currentRank = newRank

	qc, err := e.clockStore.GetLatestQuorumCertificate(nil)
	if err != nil {
		e.logger.Error("new rank, no latest QC")
		frameProvingTotal.WithLabelValues("error").Inc()
		return
	}
	_, err = e.clockStore.GetGlobalClockFrameCandidate(
		qc.FrameNumber,
		[]byte(qc.Identity()),
	)
	if err != nil {
		e.logger.Error("new rank, no global clock frame candidate")
		frameProvingTotal.WithLabelValues("error").Inc()
		return
	}
	// Note: Collect is called in ProveNextState after tryBeginProvingRank succeeds
	// to avoid race conditions where a subsequent OnRankChange overwrites
	// collectedMessages and shardCommitments while ProveNextState is still running
}

func (e *GlobalConsensusEngine) rebuildShardCommitments(
	frameNumber uint64,
	rank uint64,
) ([]byte, error) {
	commitSet, err := e.hypergraph.Commit(frameNumber)
	if err != nil {
		e.logger.Error("could not commit", zap.Error(err))
		return nil, errors.Wrap(err, "rebuild shard commitments")
	}

	if err := e.rebuildAppShardCache(rank); err != nil {
		e.logger.Warn(
			"could not rebuild app shard cache",
			zap.Uint64("rank", rank),
			zap.Error(err),
		)
	}

	e.shardCommitmentMu.Lock()
	defer e.shardCommitmentMu.Unlock()

	if e.shardCommitmentTrees == nil {
		e.shardCommitmentTrees = make([]*tries.VectorCommitmentTree, 256)
	}
	if e.shardCommitmentKeySets == nil {
		e.shardCommitmentKeySets = make([]map[string]struct{}, 256)
	}
	if e.shardCommitments == nil {
		e.shardCommitments = make([][]byte, 256)
	}

	currentKeySets := make([]map[string]struct{}, 256)
	changedTrees := make([]bool, 256)

	proverRoot := make([]byte, 64)
	collected := 0
	var zeroShardKeyL1 [3]byte

	for sk, phaseCommits := range commitSet {
		if sk.L1 == zeroShardKeyL1 {
			if len(phaseCommits) > 0 {
				proverRoot = slices.Clone(phaseCommits[0])
			}
			continue
		}

		collected++

		for phaseSet := 0; phaseSet < len(phaseCommits); phaseSet++ {
			commit := phaseCommits[phaseSet]
			foldedShardKey := make([]byte, 32)
			copy(foldedShardKey, sk.L2[:])

			foldedShardKey[0] |= byte(phaseSet << 6)
			keyStr := string(foldedShardKey)
			var valueCopy []byte

			for l1Idx := 0; l1Idx < len(sk.L1); l1Idx++ {
				index := int(sk.L1[l1Idx])
				if index >= len(e.shardCommitmentTrees) {
					e.logger.Warn(
						"shard commitment index out of range",
						zap.Int("index", index),
					)
					continue
				}

				if e.shardCommitmentTrees[index] == nil {
					e.shardCommitmentTrees[index] = &tries.VectorCommitmentTree{}
				}

				if currentKeySets[index] == nil {
					currentKeySets[index] = make(map[string]struct{})
				}
				currentKeySets[index][keyStr] = struct{}{}

				tree := e.shardCommitmentTrees[index]
				if existing, err := tree.Get(foldedShardKey); err == nil &&
					bytes.Equal(existing, commit) {
					continue
				}

				if valueCopy == nil {
					valueCopy = slices.Clone(commit)
				}

				if err := tree.Insert(
					foldedShardKey,
					valueCopy,
					nil,
					big.NewInt(int64(len(commit))),
				); err != nil {
					return nil, errors.Wrap(err, "rebuild shard commitments")
				}

				changedTrees[index] = true
			}
		}
	}

	for idx := 0; idx < len(e.shardCommitmentTrees); idx++ {
		prevKeys := e.shardCommitmentKeySets[idx]
		currKeys := currentKeySets[idx]

		if len(prevKeys) > 0 {
			for key := range prevKeys {
				if currKeys != nil {
					if _, ok := currKeys[key]; ok {
						continue
					}
				}

				tree := e.shardCommitmentTrees[idx]
				if tree == nil {
					continue
				}

				if err := tree.Delete([]byte(key)); err != nil {
					e.logger.Debug(
						"failed to delete shard commitment leaf",
						zap.Int("shard_index", idx),
						zap.Error(err),
					)
					continue
				}

				changedTrees[idx] = true
			}
		}

		e.shardCommitmentKeySets[idx] = currKeys
	}

	// Apply alt shard overrides - these have externally-managed roots
	if e.hypergraphStore != nil {
		altShardAddrs, err := e.hypergraphStore.RangeAltShardAddresses()
		if err != nil {
			e.logger.Warn("failed to get alt shard addresses", zap.Error(err))
		} else {
			for _, shardAddr := range altShardAddrs {
				vertexAdds, vertexRemoves, hyperedgeAdds, hyperedgeRemoves, err :=
					e.hypergraphStore.GetLatestAltShardCommit(shardAddr)
				if err != nil {
					e.logger.Debug(
						"failed to get alt shard commit",
						zap.Binary("shard_address", shardAddr),
						zap.Error(err),
					)
					continue
				}

				// Calculate L1 indices (bloom filter) for this shard address
				l1Indices := up2p.GetBloomFilterIndices(shardAddr, 256, 3)

				// Insert each phase's root into the commitment trees
				roots := [][]byte{vertexAdds, vertexRemoves, hyperedgeAdds, hyperedgeRemoves}
				for phaseSet, root := range roots {
					if len(root) == 0 {
						continue
					}

					foldedShardKey := make([]byte, 32)
					copy(foldedShardKey, shardAddr)
					foldedShardKey[0] |= byte(phaseSet << 6)
					keyStr := string(foldedShardKey)

					for _, l1Idx := range l1Indices {
						index := int(l1Idx)
						if index >= len(e.shardCommitmentTrees) {
							continue
						}

						if e.shardCommitmentTrees[index] == nil {
							e.shardCommitmentTrees[index] = &tries.VectorCommitmentTree{}
						}

						if currentKeySets[index] == nil {
							currentKeySets[index] = make(map[string]struct{})
						}
						currentKeySets[index][keyStr] = struct{}{}

						tree := e.shardCommitmentTrees[index]
						if existing, err := tree.Get(foldedShardKey); err == nil &&
							bytes.Equal(existing, root) {
							continue
						}

						if err := tree.Insert(
							foldedShardKey,
							slices.Clone(root),
							nil,
							big.NewInt(int64(len(root))),
						); err != nil {
							e.logger.Warn(
								"failed to insert alt shard root",
								zap.Binary("shard_address", shardAddr),
								zap.Int("phase", phaseSet),
								zap.Error(err),
							)
							continue
						}

						changedTrees[index] = true
					}
				}
			}
		}
	}

	for i := 0; i < len(e.shardCommitmentTrees); i++ {
		if e.shardCommitmentTrees[i] == nil {
			e.shardCommitmentTrees[i] = &tries.VectorCommitmentTree{}
		}

		if changedTrees[i] || e.shardCommitments[i] == nil {
			e.shardCommitments[i] = e.shardCommitmentTrees[i].Commit(
				e.inclusionProver,
				false,
			)
		}
	}

	preimage := slices.Concat(
		slices.Concat(e.shardCommitments...),
		proverRoot,
	)

	commitmentHash := sha3.Sum256(preimage)

	e.proverRoot = proverRoot
	e.commitmentHash = commitmentHash[:]

	shardCommitmentsCollected.Set(float64(collected))

	return commitmentHash[:], nil
}

// OnReceiveProposal implements consensus.Consumer.
func (e *GlobalConsensusEngine) OnReceiveProposal(
	currentRank uint64,
	proposal *models.SignedProposal[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
	],
) {
}

// OnReceiveQuorumCertificate implements consensus.Consumer.
func (e *GlobalConsensusEngine) OnReceiveQuorumCertificate(
	currentRank uint64,
	qc models.QuorumCertificate,
) {
}

// OnReceiveTimeoutCertificate implements consensus.Consumer.
func (e *GlobalConsensusEngine) OnReceiveTimeoutCertificate(
	currentRank uint64,
	tc models.TimeoutCertificate,
) {
}

// OnStart implements consensus.Consumer.
func (e *GlobalConsensusEngine) OnStart(currentRank uint64) {}

// OnStartingTimeout implements consensus.Consumer.
func (e *GlobalConsensusEngine) OnStartingTimeout(
	startTime time.Time,
	endTime time.Time,
) {
}

// OnStateIncorporated implements consensus.Consumer.
func (e *GlobalConsensusEngine) OnStateIncorporated(
	state *models.State[*protobufs.GlobalFrame],
) {
	e.frameStoreMu.Lock()
	e.frameStore[state.Identifier] = *state.State
	e.frameStoreMu.Unlock()
}

// OnTimeoutCertificateTriggeredRankChange implements consensus.Consumer.
func (e *GlobalConsensusEngine) OnTimeoutCertificateTriggeredRankChange(
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
func (e *GlobalConsensusEngine) VerifyQuorumCertificate(
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
		genqc, err := e.clockStore.GetQuorumCertificate(nil, 0)
		if err != nil {
			return errors.Wrap(err, "verify quorum certificate")
		}

		if genqc.Equals(quorumCertificate) {
			return nil
		}
	}

	provers, err := e.proverRegistry.GetActiveProvers(nil)
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
		verification.MakeVoteMessage(nil, qc.Rank, qc.Identity()),
		[]byte("global"),
	); !valid {
		return models.ErrInvalidSignature
	}

	return nil
}

// VerifyTimeoutCertificate implements consensus.Verifier.
func (e *GlobalConsensusEngine) VerifyTimeoutCertificate(
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

	provers, err := e.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return errors.Wrap(err, "verify timeout certificate")
	}

	pubkeys := [][]byte{}
	signatures := [][]byte{}
	messages := [][]byte{}
	if ((len(provers) + 7) / 8) > len(tc.AggregateSignature.Bitmask) {
		return models.ErrInvalidSignature
	}

	idx := 0
	for i, prover := range provers {
		if tc.AggregateSignature.Bitmask[i/8]&(1<<(i%8)) == (1 << (i % 8)) {
			pubkeys = append(pubkeys, prover.PublicKey)
			signatures = append(signatures, tc.AggregateSignature.GetSignature())
			messages = append(messages, verification.MakeTimeoutMessage(
				nil,
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
		[]byte("globaltimeout"),
	); !valid {
		return models.ErrInvalidSignature
	}

	return nil
}

// VerifyVote implements consensus.Verifier.
func (e *GlobalConsensusEngine) VerifyVote(
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

	provers, err := e.proverRegistry.GetActiveProvers(nil)
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
		(*vote).PublicKeySignatureBls48581.Signature,
		verification.MakeVoteMessage(nil, (*vote).Rank, (*vote).Source()),
		[]byte("global"),
	); !valid {
		return models.ErrInvalidSignature
	}

	return nil
}

func (e *GlobalConsensusEngine) getPendingProposals(
	frameNumber uint64,
) []*models.SignedProposal[
	*protobufs.GlobalFrame,
	*protobufs.ProposalVote,
] {
	rootIter, err := e.clockStore.RangeGlobalClockFrameCandidates(
		frameNumber,
		frameNumber,
	)
	if err != nil {
		panic(err)
	}

	rootIter.First()
	root, err := rootIter.Value()
	if err != nil {
		panic(err)
	}

	result := []*models.SignedProposal[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
	]{}

	e.logger.Debug("getting pending proposals", zap.Uint64("start", frameNumber))

	startRank := root.Header.Rank
	latestQC, err := e.clockStore.GetLatestQuorumCertificate(nil)
	if err != nil {
		panic(err)
	}
	endRank := latestQC.Rank

	parent, err := e.clockStore.GetQuorumCertificate(nil, startRank)
	if err != nil {
		return result
	}

	for rank := startRank + 1; rank <= endRank; rank++ {
		nextQC, err := e.clockStore.GetQuorumCertificate(nil, rank)
		if err != nil {
			e.logger.Debug("no qc for rank", zap.Error(err))
			break
		}

		value, err := e.clockStore.GetGlobalClockFrameCandidate(
			nextQC.FrameNumber,
			[]byte(nextQC.Identity()),
		)
		if err != nil {
			e.logger.Debug("no frame for qc", zap.Error(err))
			break
		}

		var priorTCModel models.TimeoutCertificate = nil
		if parent.Rank != rank-1 {
			priorTC, _ := e.clockStore.GetTimeoutCertificate(nil, rank-1)
			if priorTC != nil {
				priorTCModel = priorTC
			}
		}

		vote := &protobufs.ProposalVote{
			Rank:        value.GetRank(),
			FrameNumber: value.Header.FrameNumber,
			Selector:    []byte(value.Identity()),
			PublicKeySignatureBls48581: &protobufs.BLS48581AddressedSignature{
				Signature: value.Header.PublicKeySignatureBls48581.Signature,
				Address:   []byte(value.Source()),
			},
		}
		result = append(result, &models.SignedProposal[
			*protobufs.GlobalFrame,
			*protobufs.ProposalVote,
		]{
			Proposal: models.Proposal[*protobufs.GlobalFrame]{
				State: &models.State[*protobufs.GlobalFrame]{
					Rank:                    value.GetRank(),
					Identifier:              value.Identity(),
					ProposerID:              value.Source(),
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

var _ consensus.DynamicCommittee = (*GlobalConsensusEngine)(nil)
