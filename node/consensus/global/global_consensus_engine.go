package global

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mr-tron/base58"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	qhypergraph "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/provers"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/reward"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/node/dispatch"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global/compat"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/manager"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	qgrpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
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
	"source.quilibrium.com/quilibrium/monorepo/types/execution"
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

// GlobalConsensusEngine  uses the generic state machine for consensus
type GlobalConsensusEngine struct {
	protobufs.GlobalServiceServer

	logger             *zap.Logger
	config             *config.Config
	pubsub             tp2p.PubSub
	hypergraph         hypergraph.Hypergraph
	keyManager         typeskeys.KeyManager
	keyStore           store.KeyStore
	clockStore         store.ClockStore
	shardsStore        store.ShardsStore
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
	blsConstructor     crypto.BlsConstructor
	executors          map[string]execution.ShardExecutionEngine
	executorsMu        sync.RWMutex
	executionManager   *manager.ExecutionEngineManager
	mixnet             typesconsensus.Mixnet
	peerInfoManager    p2p.PeerInfoManager
	workerManager      worker.WorkerManager
	proposer           *provers.Manager
	alertPublicKey     []byte
	hasSentKeyBundle   bool

	// Message queues
	globalConsensusMessageQueue chan *pb.Message
	globalFrameMessageQueue     chan *pb.Message
	globalProverMessageQueue    chan *pb.Message
	globalPeerInfoMessageQueue  chan *pb.Message
	globalAlertMessageQueue     chan *pb.Message
	appFramesMessageQueue       chan *pb.Message
	shardConsensusMessageQueue  chan *pb.Message

	// Emergency halt
	haltCtx context.Context
	halt    context.CancelFunc

	// Internal state
	ctx                   context.Context
	cancel                context.CancelFunc
	quit                  chan struct{}
	wg                    sync.WaitGroup
	minimumProvers        func() uint64
	blacklistMap          map[string]bool
	blacklistMu           sync.RWMutex
	pendingMessages       [][]byte
	pendingMessagesMu     sync.RWMutex
	currentDifficulty     uint32
	currentDifficultyMu   sync.RWMutex
	lastProvenFrameTime   time.Time
	lastProvenFrameTimeMu sync.RWMutex
	frameStore            map[string]*protobufs.GlobalFrame
	frameStoreMu          sync.RWMutex
	appFrameStore         map[string]*protobufs.AppShardFrame
	appFrameStoreMu       sync.RWMutex
	lowCoverageStreak     map[string]*coverageStreak

	// Transaction cross-shard lock tracking
	txLockMap map[uint64]map[string]map[string]*LockedTransaction
	txLockMu  sync.RWMutex

	// Generic state machine
	stateMachine *consensus.StateMachine[
		*protobufs.GlobalFrame,
		*protobufs.FrameVote,
		GlobalPeerID,
		GlobalCollectedCommitments,
	]

	// Provider implementations
	syncProvider     *GlobalSyncProvider
	votingProvider   *GlobalVotingProvider
	leaderProvider   *GlobalLeaderProvider
	livenessProvider *GlobalLivenessProvider

	// Cross-provider state
	collectedMessages [][]byte
	shardCommitments  [][]byte
	proverRoot        []byte
	commitmentHash    []byte

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
	pubsub tp2p.PubSub,
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
	workerStore store.WorkerStore,
	encryptedChannel channel.EncryptedChannel,
	bulletproofProver crypto.BulletproofProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	compiler compiler.CircuitCompiler,
	blsConstructor crypto.BlsConstructor,
	peerInfoManager p2p.PeerInfoManager,
) (*GlobalConsensusEngine, error) {
	engine := &GlobalConsensusEngine{
		logger:                      logger,
		config:                      config,
		pubsub:                      pubsub,
		hypergraph:                  hypergraph,
		keyManager:                  keyManager,
		keyStore:                    keyStore,
		clockStore:                  clockStore,
		shardsStore:                 shardsStore,
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
		executors:                   make(map[string]execution.ShardExecutionEngine),
		frameStore:                  make(map[string]*protobufs.GlobalFrame),
		appFrameStore:               make(map[string]*protobufs.AppShardFrame),
		globalConsensusMessageQueue: make(chan *pb.Message, 1000),
		globalFrameMessageQueue:     make(chan *pb.Message, 100),
		globalProverMessageQueue:    make(chan *pb.Message, 1000),
		appFramesMessageQueue:       make(chan *pb.Message, 10000),
		globalPeerInfoMessageQueue:  make(chan *pb.Message, 1000),
		globalAlertMessageQueue:     make(chan *pb.Message, 100),
		shardConsensusMessageQueue:  make(chan *pb.Message, 10000),
		currentDifficulty:           config.Engine.Difficulty,
		lastProvenFrameTime:         time.Now(),
		blacklistMap:                make(map[string]bool),
		pendingMessages:             [][]byte{},
		alertPublicKey:              []byte{},
		txLockMap:                   make(map[uint64]map[string]map[string]*LockedTransaction),
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
			hypergraph,
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

	// Create provider implementations
	engine.syncProvider = &GlobalSyncProvider{engine: engine}
	engine.votingProvider = &GlobalVotingProvider{
		engine: engine,
		proposalVotes: make(
			map[consensus.Identity]map[consensus.Identity]**protobufs.FrameVote,
		),
	}
	engine.leaderProvider = &GlobalLeaderProvider{engine: engine}
	engine.livenessProvider = &GlobalLivenessProvider{engine: engine}

	// Create dispatch service
	engine.dispatchService = dispatch.NewDispatchService(
		inboxStore,
		logger,
		keyManager,
		pubsub,
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

	// Initialize execution engines
	if err := engine.executionManager.InitializeEngines(); err != nil {
		return nil, errors.Wrap(err, "new global consensus engine")
	}

	// Register all execution engines with the consensus engine
	err = engine.executionManager.RegisterAllEngines(engine.RegisterExecutor)
	if err != nil {
		return nil, errors.Wrap(err, "new global consensus engine")
	}

	// Initialize metrics
	engineState.Set(0) // EngineStateStopped
	currentDifficulty.Set(float64(config.Engine.Difficulty))
	executorsRegistered.Set(0)
	shardCommitmentsCollected.Set(0)

	// Establish hypersync service
	engine.hyperSync = hypergraph
	engine.onionService = onion.NewGRPCTransport(
		logger,
		pubsub.GetPeerID(),
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
		panic(errors.Wrap(err, "failed to setup gRPC server"))
	}

	return engine, nil
}

func (e *GlobalConsensusEngine) Start(quit chan struct{}) <-chan error {
	errChan := make(chan error, 1)

	e.quit = quit
	e.ctx, e.cancel = context.WithCancel(context.Background())

	// Start worker manager background process (if applicable)
	if !e.config.Engine.ArchiveMode {
		if err := e.workerManager.Start(e.ctx); err != nil {
			errChan <- errors.Wrap(err, "start")
			close(errChan)
			return errChan
		}
	}

	// Start execution engines
	if err := e.executionManager.StartAll(e.quit); err != nil {
		errChan <- errors.Wrap(err, "start")
		close(errChan)
		return errChan
	}

	// Start the event distributor
	if err := e.eventDistributor.Start(e.ctx); err != nil {
		errChan <- errors.Wrap(err, "start")
		close(errChan)
		return errChan
	}

	err := e.globalTimeReel.Start()
	if err != nil {
		errChan <- errors.Wrap(err, "start")
		close(errChan)
		return errChan
	}

	frame, err := e.clockStore.GetLatestGlobalClockFrame()
	if err != nil {
		e.logger.Warn(
			"invalid frame retrieved, will resync",
			zap.Error(err),
		)
	}

	var initialState **protobufs.GlobalFrame = nil
	if frame != nil {
		if frame.Header.FrameNumber == 244200 && e.config.P2P.Network == 0 {
			e.logger.Warn("purging previous genesis to start new")
			err = e.clockStore.DeleteGlobalClockFrameRange(0, 244201)
			if err != nil {
				panic(err)
			}
			set := e.hypergraph.(*qhypergraph.HypergraphCRDT).GetVertexAddsSet(
				tries.ShardKey{
					L1: [3]byte{},
					L2: [32]byte(bytes.Repeat([]byte{0xff}, 32)),
				},
			)
			leaves := tries.GetAllLeaves(
				set.GetTree().SetType,
				set.GetTree().PhaseType,
				set.GetTree().ShardKey,
				set.GetTree().Root,
			)
			txn, err := e.hypergraph.NewTransaction(false)
			if err != nil {
				panic(err)
			}
			for _, l := range leaves {
				err = set.GetTree().Delete(txn, l.Key)
				if err != nil {
					txn.Abort()
					panic(err)
				}
			}
			if err = txn.Commit(); err != nil {
				panic(err)
			}
			frame = nil
		} else {
			initialState = &frame
		}
	}

	if e.config.P2P.Network == 99 || e.config.Engine.ArchiveMode {
		// Create the generic state machine
		e.stateMachine = consensus.NewStateMachine(
			e.getPeerID(),
			initialState,
			true,
			e.minimumProvers,
			e.syncProvider,
			e.votingProvider,
			e.leaderProvider,
			e.livenessProvider,
			&GlobalTracer{
				logger: e.logger.Named("state_machine"),
			},
		)

		// Add transition listener
		e.stateMachine.AddListener(&GlobalTransitionListener{
			engine: e,
			logger: e.logger.Named("transitions"),
		})
	}

	// Confirm initial state
	if !e.config.Engine.ArchiveMode {
		latest, err := e.clockStore.GetLatestGlobalClockFrame()
		if err != nil || latest == nil {
			e.logger.Info("initializing genesis")
			e.initializeGenesis()
		}
	}

	// Subscribe to global consensus if participating
	err = e.subscribeToGlobalConsensus()
	if err != nil {
		errChan <- errors.Wrap(err, "start")
		close(errChan)
		return errChan
	}

	// Subscribe to shard consensus messages to broker lock agreement
	err = e.subscribeToShardConsensusMessages()
	if err != nil {
		errChan <- errors.Wrap(err, "start")
		close(errChan)
		return errChan
	}

	// Subscribe to frames
	err = e.subscribeToFrameMessages()
	if err != nil {
		errChan <- errors.Wrap(err, "start")
		close(errChan)
		return errChan
	}

	// Subscribe to prover messages
	err = e.subscribeToProverMessages()
	if err != nil {
		errChan <- errors.Wrap(err, "start")
		close(errChan)
		return errChan
	}

	// Subscribe to peer info messages
	err = e.subscribeToPeerInfoMessages()
	if err != nil {
		errChan <- errors.Wrap(err, "start")
		close(errChan)
		return errChan
	}

	// Subscribe to alert messages
	err = e.subscribeToAlertMessages()
	if err != nil {
		errChan <- errors.Wrap(err, "start")
		close(errChan)
		return errChan
	}

	// Start consensus message queue processor
	e.wg.Add(1)
	go e.processGlobalConsensusMessageQueue()

	// Start shard consensus message queue processor
	e.wg.Add(1)
	go e.processShardConsensusMessageQueue()

	// Start frame message queue processor
	e.wg.Add(1)
	go e.processFrameMessageQueue()

	// Start prover message queue processor
	e.wg.Add(1)
	go e.processProverMessageQueue()

	// Start peer info message queue processor
	e.wg.Add(1)
	go e.processPeerInfoMessageQueue()

	// Start alert message queue processor
	e.wg.Add(1)
	go e.processAlertMessageQueue()

	// Start periodic peer info reporting
	e.wg.Add(1)
	go e.reportPeerInfoPeriodically()

	// Start event distributor event loop
	e.wg.Add(1)
	go e.eventDistributorLoop()

	// Start periodic metrics update
	e.wg.Add(1)
	go e.updateMetrics()

	// Start periodic tx lock pruning
	e.wg.Add(1)
	go e.pruneTxLocksPeriodically()

	if e.config.P2P.Network == 99 || e.config.Engine.ArchiveMode {
		// Start the state machine
		if err := e.stateMachine.Start(); err != nil {
			errChan <- errors.Wrap(err, "start state machine")
			close(errChan)
			return errChan
		}
	}

	if e.grpcServer != nil {
		// Register all services with the gRPC server
		e.RegisterServices(e.grpcServer)

		// Start serving the gRPC server
		go func() {
			if err := e.grpcServer.Serve(e.grpcListener); err != nil {
				e.logger.Error("gRPC server error", zap.Error(err))
			}
		}()

		e.logger.Info("started gRPC server",
			zap.String("address", e.grpcListener.Addr().String()))
	}

	e.logger.Info("global consensus engine started")

	close(errChan)
	return errChan
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

	// Stop worker manager background process (if applicable)
	if !e.config.Engine.ArchiveMode {
		if err := e.workerManager.Stop(); err != nil {
			errChan <- errors.Wrap(err, "stop")
			close(errChan)
			return errChan
		}
	}

	if e.grpcServer != nil {
		e.logger.Info("stopping gRPC server")
		e.grpcServer.GracefulStop()
		if e.grpcListener != nil {
			e.grpcListener.Close()
		}
	}

	if e.config.P2P.Network == 99 || e.config.Engine.ArchiveMode {
		// Stop the state machine
		if err := e.stateMachine.Stop(); err != nil && !force {
			errChan <- errors.Wrap(err, "stop")
		}
	}

	// Stop execution engines
	if e.executionManager != nil {
		if err := e.executionManager.StopAll(force); err != nil && !force {
			errChan <- errors.Wrap(err, "stop")
		}
	}

	// Cancel context
	if e.cancel != nil {
		e.cancel()
	}

	// Stop event distributor
	if err := e.eventDistributor.Stop(); err != nil && !force {
		errChan <- errors.Wrap(err, "stop")
	}

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

	// Wait for goroutines to finish
	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Clean shutdown
	case <-time.After(30 * time.Second):
		if !force {
			errChan <- errors.New("timeout waiting for graceful shutdown")
		}
	}

	if e.config.P2P.Network == 99 || e.config.Engine.ArchiveMode {
		// Close the state machine
		e.stateMachine.Close()
	}

	close(errChan)
	return errChan
}

func (e *GlobalConsensusEngine) GetFrame() *protobufs.GlobalFrame {
	// Get the current frame from the time reel
	frame, _ := e.globalTimeReel.GetHead()

	if frame == nil {
		return nil
	}

	return frame.Clone().(*protobufs.GlobalFrame)
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
	if e.stateMachine == nil {
		return typesconsensus.EngineStateStopped
	}
	smState := e.stateMachine.GetState()
	switch smState {
	case consensus.StateStopped:
		return typesconsensus.EngineStateStopped
	case consensus.StateStarting:
		return typesconsensus.EngineStateStarting
	case consensus.StateLoading:
		return typesconsensus.EngineStateLoading
	case consensus.StateCollecting:
		return typesconsensus.EngineStateCollecting
	case consensus.StateLivenessCheck:
		return typesconsensus.EngineStateLivenessCheck
	case consensus.StateProving:
		return typesconsensus.EngineStateProving
	case consensus.StatePublishing:
		return typesconsensus.EngineStatePublishing
	case consensus.StateVoting:
		return typesconsensus.EngineStateVoting
	case consensus.StateFinalizing:
		return typesconsensus.EngineStateFinalizing
	default:
		return typesconsensus.EngineStateStopped
	}
}

func (e *GlobalConsensusEngine) RegisterExecutor(
	exec execution.ShardExecutionEngine,
	frame uint64,
) <-chan error {
	errChan := make(chan error, 1)

	e.executorsMu.Lock()
	defer e.executorsMu.Unlock()

	name := exec.GetName()
	if _, exists := e.executors[name]; exists {
		errChan <- errors.New("executor already registered")
		close(errChan)
		return errChan
	}

	e.executors[name] = exec

	// Update metrics
	executorRegistrationTotal.WithLabelValues("register").Inc()
	executorsRegistered.Set(float64(len(e.executors)))

	close(errChan)
	return errChan
}

func (e *GlobalConsensusEngine) UnregisterExecutor(
	name string,
	frame uint64,
	force bool,
) <-chan error {
	errChan := make(chan error, 1)

	e.executorsMu.Lock()
	defer e.executorsMu.Unlock()

	if _, exists := e.executors[name]; !exists {
		errChan <- errors.New("executor not registered")
		close(errChan)
		return errChan
	}

	// Stop the executor
	if exec, ok := e.executors[name]; ok {
		stopErrChan := exec.Stop(force)
		select {
		case err := <-stopErrChan:
			if err != nil && !force {
				errChan <- errors.Wrap(err, "stop executor")
				close(errChan)
				return errChan
			}
		case <-time.After(5 * time.Second):
			if !force {
				errChan <- errors.New("timeout stopping executor")
				close(errChan)
				return errChan
			}
		}
	}

	delete(e.executors, name)

	// Update metrics
	executorRegistrationTotal.WithLabelValues("unregister").Inc()
	executorsRegistered.Set(float64(len(e.executors)))

	close(errChan)
	return errChan
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

	// Get supported capabilities from execution manager
	capabilities := e.executionManager.GetSupportedCapabilities()

	var reachability []*protobufs.Reachability

	// master node process:
	{
		var pubsubAddrs, streamAddrs []string
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
		reachability = append(reachability, &protobufs.Reachability{
			Filter:           []byte{}, // master has empty filter
			PubsubMultiaddrs: pubsubAddrs,
			StreamMultiaddrs: streamAddrs,
		})
	}

	// worker processes
	{
		p2pPatterns, streamPatterns, filters := e.workerPatterns()
		for i := range p2pPatterns {
			if p2pPatterns[i] == "" {
				continue
			}

			// find observed P2P addrs for this worker
			// (prefer public > local/reserved)
			pubsubAddrs := e.findObservedAddressesForConfig(ownAddrs, p2pPatterns[i])

			// stream pattern: explicit for this worker or synthesized from P2P IPs
			var streamAddrs []string
			if i < len(streamPatterns) && streamPatterns[i] != "" {
				// Build using the declared worker stream pattern’s port/protocols.
				// Reuse the pubsub IPs so P2P/stream align on the same interface.
				streamAddrs = e.buildStreamAddressesFromPubsub(
					pubsubAddrs,
					streamPatterns[i],
				)
			} else {
				// No explicit worker stream pattern; if master stream is set, use its
				// structure
				if e.config.P2P.StreamListenMultiaddr != "" {
					streamAddrs = e.buildStreamAddressesFromPubsub(
						pubsubAddrs,
						e.config.P2P.StreamListenMultiaddr,
					)
				}
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

			// Only append a worker entry if we have at least one P2P addr and filter
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
		PeerId:       e.pubsub.GetPeerID(),
		Reachability: reachability,
		Timestamp:    time.Now().UnixMilli(),
		Version:      config.GetVersion(),
		PatchVersion: []byte{config.GetPatchNumber()},
		Capabilities: capabilities,
		PublicKey:    e.pubsub.GetPublicKey(),
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

func (e *GlobalConsensusEngine) materialize(
	txn store.Transaction,
	frameNumber uint64,
	requests []*protobufs.MessageBundle,
) error {
	var state state.State
	state = hgstate.NewHypergraphState(e.hypergraph)

	e.logger.Debug(
		"materializing messages",
		zap.Int("message_count", len(requests)),
	)
	for i, request := range requests {
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
			continue
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

		result, err := e.executionManager.ProcessMessage(
			frameNumber,
			baseline,
			bytes.Repeat([]byte{0xff}, 32),
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

		state = result.State
	}

	if err := state.Commit(); err != nil {
		return errors.Wrap(err, "materialize")
	}

	err := e.proverRegistry.ProcessStateTransition(state, frameNumber)
	if err != nil {
		return errors.Wrap(err, "materialize")
	}

	return nil
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
	keyId := "q-prover-key"

	key, err := e.keyManager.GetSigningKey(keyId)
	if err != nil {
		e.logger.Error("failed to get key for prover address", zap.Error(err))
		return []byte{}
	}

	addressBI, err := poseidon.HashBytes(key.Public().([]byte))
	if err != nil {
		e.logger.Error("failed to calculate prover address", zap.Error(err))
		return []byte{}
	}
	return addressBI.FillBytes(make([]byte, 32))
}

func (e *GlobalConsensusEngine) updateMetrics() {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error("fatal error encountered", zap.Any("panic", r))
			if e.cancel != nil {
				e.cancel()
			}
			e.quit <- struct{}{}
		}
	}()
	defer e.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-e.quit:
			return
		case <-ticker.C:
			// Update time since last proven frame
			e.lastProvenFrameTimeMu.RLock()
			timeSince := time.Since(e.lastProvenFrameTime).Seconds()
			e.lastProvenFrameTimeMu.RUnlock()
			timeSinceLastProvenFrame.Set(timeSince)

			// Update executor count
			e.executorsMu.RLock()
			execCount := len(e.executors)
			e.executorsMu.RUnlock()
			executorsRegistered.Set(float64(execCount))

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
		PeerId:       info.PeerId,
		Reachability: info.Reachability,
		Timestamp:    info.Timestamp,
		Version:      info.Version,
		PatchVersion: info.PatchVersion,
		Capabilities: info.Capabilities,
		PublicKey:    info.PublicKey,
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
func (e *GlobalConsensusEngine) reportPeerInfoPeriodically() {
	defer e.wg.Done()

	e.logger.Info("starting periodic peer info reporting")
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
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
		}
	}
}

func (e *GlobalConsensusEngine) pruneTxLocksPeriodically() {
	defer e.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	e.pruneTxLocks()

	for {
		select {
		case <-e.ctx.Done():
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

// validatePeerInfoSignature validates the signature of a peer info message
func (e *GlobalConsensusEngine) validatePeerInfoSignature(
	peerInfo *protobufs.PeerInfo,
) bool {
	if len(peerInfo.Signature) == 0 || len(peerInfo.PublicKey) == 0 {
		return false
	}

	// Create a copy of the peer info without the signature for validation
	infoCopy := &protobufs.PeerInfo{
		PeerId:       peerInfo.PeerId,
		Reachability: peerInfo.Reachability,
		Timestamp:    peerInfo.Timestamp,
		Version:      peerInfo.Version,
		PatchVersion: peerInfo.PatchVersion,
		Capabilities: peerInfo.Capabilities,
		PublicKey:    peerInfo.PublicKey,
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

	skipMerge := false
	info, err := e.proverRegistry.GetProverInfo(e.getProverAddress())
	if err == nil || info != nil {
		skipMerge = true
	}

	helpers := []*global.SeniorityMerge{}
	if !skipMerge {
		e.logger.Debug("attempting merge")
		peerIds := []string{}
		oldProver, err := keys.Ed448KeyFromBytes(
			[]byte(e.config.P2P.PeerPrivKey),
			e.pubsub.GetPublicKey(),
		)
		if err != nil {
			e.logger.Debug("cannot get peer key", zap.Error(err))
			return errors.Wrap(err, "propose worker join")
		}
		helpers = append(helpers, global.NewSeniorityMerge(
			crypto.KeyTypeEd448,
			oldProver,
		))
		peerIds = append(peerIds, peer.ID(e.pubsub.GetPeerID()).String())
		if len(e.config.Engine.MultisigProverEnrollmentPaths) != 0 {
			e.logger.Debug("loading old configs")
			for _, conf := range e.config.Engine.MultisigProverEnrollmentPaths {
				extraConf, err := config.LoadConfig(conf, "", false)
				if err != nil {
					e.logger.Error("could not construct join", zap.Error(err))
					return errors.Wrap(err, "propose worker join")
				}

				peerPrivKey, err := hex.DecodeString(extraConf.P2P.PeerPrivKey)
				if err != nil {
					e.logger.Error("could not construct join", zap.Error(err))
					return errors.Wrap(err, "propose worker join")
				}

				privKey, err := pcrypto.UnmarshalEd448PrivateKey(peerPrivKey)
				if err != nil {
					e.logger.Error("could not construct join", zap.Error(err))
					return errors.Wrap(err, "propose worker join")
				}

				pub := privKey.GetPublic()
				pubBytes, err := pub.Raw()
				if err != nil {
					e.logger.Error("could not construct join", zap.Error(err))
					return errors.Wrap(err, "propose worker join")
				}

				id, err := peer.IDFromPublicKey(pub)
				if err != nil {
					e.logger.Error("could not construct join", zap.Error(err))
					return errors.Wrap(err, "propose worker join")
				}

				priv, err := privKey.Raw()
				if err != nil {
					e.logger.Error("could not construct join", zap.Error(err))
					return errors.Wrap(err, "propose worker join")
				}

				signer, err := keys.Ed448KeyFromBytes(priv, pubBytes)
				if err != nil {
					e.logger.Error("could not construct join", zap.Error(err))
					return errors.Wrap(err, "propose worker join")
				}

				peerIds = append(peerIds, id.String())
				helpers = append(helpers, global.NewSeniorityMerge(
					crypto.KeyTypeEd448,
					signer,
				))
			}
		}
		seniorityBI := compat.GetAggregatedSeniority(peerIds)
		e.logger.Info(
			"existing seniority detected for proposed join",
			zap.String("seniority", seniorityBI.String()),
		)
	}

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
				e.ctx,
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

	e.logger.Debug("submitted join request")

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
		for _, r := range reject {
			rejectMessage, err := global.NewProverReject(
				r,
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
		}
	}

	if len(confirm) != 0 {
		for _, r := range confirm {
			confirmMessage, err := global.NewProverConfirm(
				r,
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
		e.logger.Error("could not construct join", zap.Error(err))
		return errors.Wrap(err, "decide worker joins")
	}

	e.logger.Debug("submitted join decisions")

	return nil
}
