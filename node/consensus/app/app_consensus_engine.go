package app

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/multiformats/go-multiaddr"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/global"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/reward"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/node/dispatch"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/manager"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p/onion"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/compiler"
	typesconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	tkeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
	tp2p "source.quilibrium.com/quilibrium/monorepo/types/p2p"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

// AppConsensusEngine uses the generic state machine for consensus
type AppConsensusEngine struct {
	protobufs.AppShardServiceServer

	logger                *zap.Logger
	config                *config.Config
	coreId                uint
	appAddress            []byte
	appFilter             []byte
	appAddressHex         string
	pubsub                tp2p.PubSub
	hypergraph            hypergraph.Hypergraph
	keyManager            tkeys.KeyManager
	keyStore              store.KeyStore
	clockStore            store.ClockStore
	inboxStore            store.InboxStore
	hypergraphStore       store.HypergraphStore
	frameProver           crypto.FrameProver
	inclusionProver       crypto.InclusionProver
	signerRegistry        typesconsensus.SignerRegistry
	proverRegistry        typesconsensus.ProverRegistry
	dynamicFeeManager     typesconsensus.DynamicFeeManager
	frameValidator        typesconsensus.AppFrameValidator
	globalFrameValidator  typesconsensus.GlobalFrameValidator
	difficultyAdjuster    typesconsensus.DifficultyAdjuster
	rewardIssuance        typesconsensus.RewardIssuance
	eventDistributor      typesconsensus.EventDistributor
	mixnet                typesconsensus.Mixnet
	appTimeReel           *consensustime.AppTimeReel
	globalTimeReel        *consensustime.GlobalTimeReel
	encryptedChannel      channel.EncryptedChannel
	dispatchService       *dispatch.DispatchService
	blsConstructor        crypto.BlsConstructor
	minimumProvers        func() uint64
	executors             map[string]execution.ShardExecutionEngine
	executorsMu           sync.RWMutex
	executionManager      *manager.ExecutionEngineManager
	peerInfoManager       p2p.PeerInfoManager
	currentDifficulty     uint32
	currentDifficultyMu   sync.RWMutex
	pendingMessages       []*protobufs.Message
	pendingMessagesMu     sync.RWMutex
	lastProvenFrameTime   time.Time
	lastProvenFrameTimeMu sync.RWMutex
	frameStore            map[string]*protobufs.AppShardFrame
	frameStoreMu          sync.RWMutex
	ctx                   context.Context
	cancel                context.CancelFunc
	quit                  chan struct{}
	wg                    sync.WaitGroup
	canRunStandalone      bool
	blacklistMap          map[string]bool
	alertPublicKey        []byte

	// Message queues
	consensusMessageQueue      chan *pb.Message
	proverMessageQueue         chan *pb.Message
	frameMessageQueue          chan *pb.Message
	globalFrameMessageQueue    chan *pb.Message
	globalAlertMessageQueue    chan *pb.Message
	globalPeerInfoMessageQueue chan *pb.Message
	dispatchMessageQueue       chan *pb.Message

	// Emergency halt
	haltCtx context.Context
	halt    context.CancelFunc

	// Generic state machine
	stateMachine *consensus.StateMachine[
		*protobufs.AppShardFrame,
		*protobufs.FrameVote,
		PeerID,
		CollectedCommitments,
	]

	// Provider implementations
	syncProvider     *AppSyncProvider
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
}

// NewAppConsensusEngine creates a new app consensus engine using the generic
// state machine
func NewAppConsensusEngine(
	logger *zap.Logger,
	config *config.Config,
	coreId uint,
	appAddress []byte,
	pubsub tp2p.PubSub,
	hypergraph hypergraph.Hypergraph,
	keyManager tkeys.KeyManager,
	keyStore store.KeyStore,
	clockStore store.ClockStore,
	inboxStore store.InboxStore,
	hypergraphStore store.HypergraphStore,
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
	peerInfoManager p2p.PeerInfoManager,
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
		appAddress:                 appAddress,
		appFilter:                  appFilter,
		appAddressHex:              hex.EncodeToString(appAddress),
		pubsub:                     pubsub,
		hypergraph:                 hypergraph,
		keyManager:                 keyManager,
		keyStore:                   keyStore,
		clockStore:                 clockStore,
		inboxStore:                 inboxStore,
		hypergraphStore:            hypergraphStore,
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
		consensusMessageQueue:      make(chan *pb.Message, 1000),
		frameMessageQueue:          make(chan *pb.Message, 100),
		globalFrameMessageQueue:    make(chan *pb.Message, 100),
		globalAlertMessageQueue:    make(chan *pb.Message, 100),
		globalPeerInfoMessageQueue: make(chan *pb.Message, 1000),
		dispatchMessageQueue:       make(chan *pb.Message, 1000),
		currentDifficulty:          config.Engine.Difficulty,
		blacklistMap:               make(map[string]bool),
		alertPublicKey:             []byte{},
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
		false, // includeGlobal
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create execution engine manager")
	}
	engine.executionManager = executionManager

	// Create dispatch service
	engine.dispatchService = dispatch.NewDispatchService(
		inboxStore,
		logger,
		keyManager,
		pubsub,
	)

	// Initialize execution engines
	if err := engine.executionManager.InitializeEngines(); err != nil {
		return nil, errors.Wrap(err, "failed to initialize execution engines")
	}

	// Register all execution engines with the consensus engine
	err = engine.executionManager.RegisterAllEngines(engine.RegisterExecutor)
	if err != nil {
		return nil, errors.Wrap(err, "failed to register execution engines")
	}

	engine.syncProvider = &AppSyncProvider{engine: engine}
	engine.votingProvider = &AppVotingProvider{
		engine: engine,
		proposalVotes: make(
			map[consensus.Identity]map[consensus.Identity]**protobufs.FrameVote,
		),
	}
	engine.leaderProvider = &AppLeaderProvider{engine: engine}
	engine.livenessProvider = &AppLivenessProvider{engine: engine}

	appTimeReel.SetMaterializeFunc(engine.materialize)
	appTimeReel.SetRevertFunc(engine.revert)

	// 99 (local devnet) is the special case where consensus is of one node
	minimumProvers := func() uint64 { return 6 }
	if config.P2P != nil && config.P2P.Network == 99 {
		minimumProvers = func() uint64 { return 1 }
	}

	engine.minimumProvers = minimumProvers

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

	return engine, nil
}

func (e *AppConsensusEngine) Start(quit chan struct{}) <-chan error {
	errChan := make(chan error, 1)

	e.quit = quit
	e.ctx, e.cancel = context.WithCancel(context.Background())

	// Start execution engines
	if err := e.executionManager.StartAll(e.quit); err != nil {
		errChan <- errors.Wrap(err, "start execution engines")
		close(errChan)
		return errChan
	}

	if err := e.eventDistributor.Start(e.ctx); err != nil {
		errChan <- errors.Wrap(err, "start event distributor")
		close(errChan)
		return errChan
	}

	err := e.appTimeReel.Start()
	if err != nil {
		errChan <- errors.Wrap(err, "start")
		close(errChan)
		return errChan
	}

	frame, _, err := e.clockStore.GetLatestShardClockFrame(e.appAddress)
	if err != nil {
		e.logger.Warn(
			"invalid frame retrieved, will resync",
			zap.Error(err),
		)
	}

	var initialState **protobufs.AppShardFrame = nil
	if frame != nil {
		initialState = &frame
	}

	e.stateMachine = consensus.NewStateMachine(
		e.getPeerID(),
		initialState, // Initial state will be set by sync provider
		true,         // shouldEmitReceiveEventsOnSends
		e.minimumProvers,
		e.syncProvider,
		e.votingProvider,
		e.leaderProvider,
		e.livenessProvider,
		&AppTracer{
			logger: e.logger.Named("state_machine"),
		},
	)

	e.stateMachine.AddListener(&AppTransitionListener{
		engine: e,
		logger: e.logger.Named("transitions"),
	})

	err = e.subscribeToConsensusMessages()
	if err != nil {
		errChan <- errors.Wrap(err, "start")
		close(errChan)
		return errChan
	}

	err = e.subscribeToProverMessages()
	if err != nil {
		errChan <- errors.Wrap(err, "start")
		close(errChan)
		return errChan
	}

	err = e.subscribeToFrameMessages()
	if err != nil {
		errChan <- errors.Wrap(err, "start")
		close(errChan)
		return errChan
	}

	err = e.subscribeToGlobalFrameMessages()
	if err != nil {
		errChan <- errors.Wrap(err, "start")
		close(errChan)
		return errChan
	}

	err = e.subscribeToGlobalProverMessages()
	if err != nil {
		errChan <- errors.Wrap(err, "start")
		close(errChan)
		return errChan
	}

	err = e.subscribeToGlobalAlertMessages()
	if err != nil {
		errChan <- errors.Wrap(err, "start")
		close(errChan)
		return errChan
	}

	err = e.subscribeToPeerInfoMessages()
	if err != nil {
		errChan <- errors.Wrap(err, "start")
		close(errChan)
		return errChan
	}

	err = e.subscribeToDispatchMessages()
	if err != nil {
		errChan <- errors.Wrap(err, "start")
		close(errChan)
		return errChan
	}

	// Start message queue processors
	e.wg.Add(1)
	go e.processConsensusMessageQueue()

	e.wg.Add(1)
	go e.processFrameMessageQueue()

	e.wg.Add(1)
	go e.processGlobalFrameMessageQueue()

	e.wg.Add(1)
	go e.processAlertMessageQueue()

	e.wg.Add(1)
	go e.processPeerInfoMessageQueue()

	e.wg.Add(1)
	go e.processDispatchMessageQueue()

	// Start event distributor event loop
	e.wg.Add(1)
	go e.eventDistributorLoop()

	// Start metrics update goroutine
	e.wg.Add(1)
	go e.updateMetricsLoop()

	// Start the state machine
	if err := e.stateMachine.Start(); err != nil {
		errChan <- errors.Wrap(err, "start state machine")
		close(errChan)
		return errChan
	}

	e.logger.Info(
		"app consensus engine started",
		zap.String("app_address", hex.EncodeToString(e.appAddress)),
	)

	if e.grpcServer != nil {
		e.RegisterServices(e.grpcServer)
	}

	close(errChan)
	return errChan
}

func (e *AppConsensusEngine) Stop(force bool) <-chan error {
	errChan := make(chan error, 1)

	// First, cancel context to signal all goroutines to stop
	if e.cancel != nil {
		e.cancel()
	}

	// Unsubscribe from pubsub to stop new messages from arriving
	if e.config.P2P.Network == 99 || e.config.Engine.ArchiveMode {
		e.pubsub.Unsubscribe(e.getConsensusMessageBitmask(), false)
		e.pubsub.UnregisterValidator(e.getConsensusMessageBitmask())
		e.pubsub.Unsubscribe(e.getProverMessageBitmask(), false)
		e.pubsub.UnregisterValidator(e.getProverMessageBitmask())
	}

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

	// Stop the state machine
	if e.stateMachine != nil {
		if err := e.stateMachine.Stop(); err != nil && !force {
			e.logger.Warn("error stopping state machine", zap.Error(err))
			errChan <- errors.Wrap(err, "stop state machine")
		}
	}

	// Stop event distributor
	if e.eventDistributor != nil {
		if err := e.eventDistributor.Stop(); err != nil && !force {
			e.logger.Warn("error stopping event distributor", zap.Error(err))
			errChan <- errors.Wrap(err, "stop event distributor")
		}
	}

	// Stop execution engines
	if e.executionManager != nil {
		if err := e.executionManager.StopAll(force); err != nil && !force {
			e.logger.Warn("error stopping execution engines", zap.Error(err))
			errChan <- errors.Wrap(err, "stop execution engines")
		}
	}

	// Wait for goroutines to finish with shorter timeout for tests
	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()

	// Use shorter timeout in test environments
	timeout := 30 * time.Second
	if e.config.P2P.Network == 99 {
		timeout = 5 * time.Second
	}

	select {
	case <-done:
		// Clean shutdown
		e.logger.Info("app consensus engine stopped cleanly")
	case <-time.After(timeout):
		if !force {
			e.logger.Error("timeout waiting for graceful shutdown")
			errChan <- errors.New("timeout waiting for graceful shutdown")
		} else {
			e.logger.Warn("forced shutdown after timeout")
		}
	}

	// Close the state machine
	if e.stateMachine != nil {
		e.stateMachine.Close()
	}

	close(errChan)
	return errChan
}

func (e *AppConsensusEngine) GetFrame() *protobufs.AppShardFrame {
	// Get the current state from the state machine
	frame, _ := e.appTimeReel.GetHead()

	if frame == nil {
		return nil
	}

	return frame.Clone().(*protobufs.AppShardFrame)
}

func (e *AppConsensusEngine) GetDifficulty() uint32 {
	e.currentDifficultyMu.RLock()
	defer e.currentDifficultyMu.RUnlock()
	return e.currentDifficulty
}

func (e *AppConsensusEngine) GetState() typesconsensus.EngineState {
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

func (e *AppConsensusEngine) RegisterExecutor(
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
	executorRegistrationTotal.WithLabelValues(e.appAddressHex, "register").Inc()
	executorsRegistered.WithLabelValues(e.appAddressHex).Set(float64(len(e.executors)))

	close(errChan)
	return errChan
}

func (e *AppConsensusEngine) UnregisterExecutor(
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
	executorRegistrationTotal.WithLabelValues(e.appAddressHex, "unregister").Inc()
	executorsRegistered.WithLabelValues(e.appAddressHex).Set(float64(len(e.executors)))

	close(errChan)
	return errChan
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

	shardKey := qcrypto.ShardKey{
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

	acceptedMessages := []*protobufs.MessageBundle{}

	for i, request := range frame.Requests {
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
		baseline := reward.GetBaselineFee(
			difficulty,
			e.hypergraph.GetSize(nil, nil).Uint64(),
			costBasis.Uint64(),
			8000000000,
		)
		baseline.Quo(baseline, costBasis)

		result, err := e.executionManager.ProcessMessage(
			frame.Header.FrameNumber,
			new(big.Int).Mul(
				baseline,
				big.NewInt(int64(frame.Header.FeeMultiplierVote)),
			),
			e.appAddress,
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
		acceptedMessages = append(acceptedMessages, request)
	}

	err := e.proverRegistry.ProcessStateTransition(state, frame.Header.FrameNumber)
	if err != nil {
		return errors.Wrap(err, "materialize")
	}

	if err := state.Commit(); err != nil {
		return errors.Wrap(err, "materialize")
	}

	return nil
}

func (e *AppConsensusEngine) getPeerID() PeerID {
	return PeerID{ID: e.getProverAddress()}
}

func (e *AppConsensusEngine) getProverAddress() []byte {
	keyId := "q-prover-key"

	key, err := e.keyManager.GetSigningKey(keyId)
	if err != nil {
		e.logger.Error("failed to get key for prover address", zap.Error(err))
		return []byte{}
	}

	addressBI, _ := poseidon.HashBytes(key.Public().([]byte))
	return addressBI.FillBytes(make([]byte, 32))
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
) ([]byte, error) {
	if len(messages) == 0 {
		return make([]byte, 64), nil
	}

	tree := &qcrypto.VectorCommitmentTree{}

	for i, msg := range messages {
		if msg.Hash != nil {
			err := tree.Insert(
				binary.BigEndian.AppendUint64(nil, uint64(i)),
				msg.Hash,
				nil,
				big.NewInt(0),
			)
			if err != nil {
				return nil, errors.Wrap(err, "calculate requests root")
			}
		}
	}

	commitment := tree.Commit(e.inclusionProver, false)

	if len(commitment) != 74 && len(commitment) != 64 {
		return nil, errors.Errorf("invalid commitment length %d", len(commitment))
	}

	return commitment, nil
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

func (e *AppConsensusEngine) updateMetricsLoop() {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error("fatal error encountered", zap.Any("panic", r))
			if e.cancel != nil {
				e.cancel()
			}
			// Avoid blocking on quit channel during panic recovery
			select {
			case e.quit <- struct{}{}:
			default:
			}
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

func (e *AppConsensusEngine) initializeGenesis() *protobufs.AppShardFrame {
	// Initialize state roots for hypergraph
	stateRoots := make([][]byte, 4)
	for i := range stateRoots {
		stateRoots[i] = make([]byte, 64)
	}

	genesisHeader, err := e.frameProver.ProveFrameHeaderGenesis(
		e.appAddress,
		80000,
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

	if err := e.appTimeReel.Insert(e.ctx, genesisFrame); err != nil {
		e.logger.Error("failed to add genesis frame to time reel", zap.Error(err))
		e.frameStoreMu.Lock()
		delete(e.frameStore, string(frameID))
		e.frameStoreMu.Unlock()
	}

	e.logger.Info(
		"initialized genesis frame for app consensus",
		zap.String("shard_address", hex.EncodeToString(e.appAddress)),
	)

	return genesisFrame
}

// adjustFeeForTraffic calculates a traffic-adjusted fee multiplier based on
// frame timing
func (e *AppConsensusEngine) adjustFeeForTraffic(baseFee uint64) uint64 {
	// Only adjust fees if reward strategy is "reward-greedy"
	if e.config.Engine.RewardStrategy != "reward-greedy" {
		return baseFee
	}

	// Get the current frame
	currentFrame, err := e.appTimeReel.GetHead()
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
	var previousFrame *protobufs.AppShardFrame

	// Try to get the previous frame
	frames, err := e.appTimeReel.GetFramesByNumber(previousFrameNum)
	if err != nil {
		e.logger.Debug(
			"could not get prior frame for fee adjustment",
			zap.Error(err),
		)
	}
	if len(frames) > 0 {
		previousFrame = frames[0]
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
	messages []*protobufs.Message,
	previousFrame *protobufs.AppShardFrame,
) (*protobufs.AppShardFrame, error) {
	signer, _, publicKey, _ := e.GetProvingKey(e.config.Engine)
	if publicKey == nil {
		return nil, errors.New("no proving key available")
	}

	bits := up2p.GetBloomFilterIndices(e.appAddress, 256, 3)
	l2 := make([]byte, 32)
	copy(l2, e.appAddress[:min(len(e.appAddress), 32)])

	shardKey := qcrypto.ShardKey{
		L1: [3]byte(bits),
		L2: [32]byte(l2),
	}

	root := e.hypergraph.Commit()
	stateRoots := root[shardKey]

	if len(stateRoots) == 0 {
		stateRoots = make([][]byte, 4)
		stateRoots[0] = make([]byte, 64)
		stateRoots[1] = make([]byte, 64)
		stateRoots[2] = make([]byte, 64)
		stateRoots[3] = make([]byte, 64)
	}

	requestsRoot, err := e.calculateRequestsRoot(messages)
	if err != nil {
		return nil, err
	}

	timestamp := time.Now().UnixMilli()
	difficulty := e.difficultyAdjuster.GetNextDifficulty(
		previousFrame.Rank(),
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

	newHeader, err := e.frameProver.ProveFrameHeader(
		previousFrame.Header,
		e.appAddress,
		requestsRoot,
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

// getWorkerIndexFromFilter determines the worker index based on the filter
func (e *AppConsensusEngine) getWorkerIndexFromFilter() int {
	// If no app address, assume worker 0
	if len(e.appAddress) == 0 {
		return 0
	}

	// Check configured worker filters
	for i, filter := range e.config.Engine.DataWorkerFilters {
		if filter == hex.EncodeToString(e.appAddress) {
			return i
		}
	}

	// Default to worker 0 if filter not found
	return 0
}

// getWorkerPubsubAddrs returns pubsub addresses for a specific worker
func (e *AppConsensusEngine) getWorkerPubsubAddrs(
	ownAddrs []multiaddr.Multiaddr,
	workerIndex int,
) []string {
	addrs := make([]string, 0)

	// Check specific worker multiaddrs first
	if workerIndex < len(e.config.Engine.DataWorkerP2PMultiaddrs) &&
		e.config.Engine.DataWorkerP2PMultiaddrs[workerIndex] != "" {
		// Use specific configured address
		specificAddr := e.config.Engine.DataWorkerP2PMultiaddrs[workerIndex]

		// Try to match against discovered addresses
		for _, addr := range ownAddrs {
			if e.matchesPattern(addr.String(), specificAddr) {
				addrs = append(addrs, addr.String())
			}
		}

		// If no match found, use the configured address as is
		if len(addrs) == 0 {
			addrs = append(addrs, specificAddr)
		}
	} else {
		// Build from base pattern
		port := e.config.Engine.DataWorkerBaseP2PPort + uint16(workerIndex)
		pattern := fmt.Sprintf(e.config.Engine.DataWorkerBaseListenMultiaddr, port)

		// Find matching discovered addresses
		for _, addr := range ownAddrs {
			if e.matchesPattern(addr.String(), pattern) {
				addrs = append(addrs, addr.String())
			}
		}

		// If no match found, construct from pattern
		if len(addrs) == 0 && pattern != "" {
			addrs = append(addrs, pattern)
		}
	}

	return addrs
}

// getWorkerStreamAddrs returns stream addresses for a specific worker
func (e *AppConsensusEngine) getWorkerStreamAddrs(
	ownAddrs []multiaddr.Multiaddr,
	workerIndex int,
) []string {
	addrs := make([]string, 0)

	// Check specific worker multiaddrs first
	if workerIndex < len(e.config.Engine.DataWorkerStreamMultiaddrs) &&
		e.config.Engine.DataWorkerStreamMultiaddrs[workerIndex] != "" {
		// Use specific configured address
		specificAddr := e.config.Engine.DataWorkerStreamMultiaddrs[workerIndex]

		// Try to match against discovered addresses
		for _, addr := range ownAddrs {
			if e.matchesPattern(addr.String(), specificAddr) {
				addrs = append(addrs, addr.String())
			}
		}

		// If no match found, use the configured address as-is
		if len(addrs) == 0 {
			addrs = append(addrs, specificAddr)
		}
	} else {
		// Build from base pattern
		port := e.config.Engine.DataWorkerBaseStreamPort + uint16(workerIndex)
		pattern := fmt.Sprintf(e.config.Engine.DataWorkerBaseListenMultiaddr, port)

		// Find matching discovered addresses
		for _, addr := range ownAddrs {
			if e.matchesPattern(addr.String(), pattern) {
				addrs = append(addrs, addr.String())
			}
		}

		// If no match found, construct from pattern
		if len(addrs) == 0 && pattern != "" {
			addrs = append(addrs, pattern)
		}
	}

	return addrs
}

// matchesProtocol checks if an address matches a configured protocol pattern
func (e *AppConsensusEngine) matchesProtocol(addr, pattern string) bool {
	// Extract protocol components and match
	// e.g., /ip4/1.2.3.4/tcp/8336/quic-v1 matches /ip4/0.0.0.0/tcp/8336/quic-v1
	patternParts := strings.Split(pattern, "/")
	addrParts := strings.Split(addr, "/")

	if len(patternParts) != len(addrParts) {
		return false
	}

	for i, part := range patternParts {
		// Skip IP comparison for wildcard/localhost in pattern
		if i > 0 && patternParts[i-1] == "ip4" &&
			(part == "0.0.0.0" || part == "127.0.0.1") {
			continue
		}
		if i > 0 && patternParts[i-1] == "ip6" &&
			(part == "::" || part == "::1") {
			continue
		}

		if part != addrParts[i] {
			return false
		}
	}

	return true
}

// matchesPattern is more flexible than matchesProtocol, allowing partial
// matches
func (e *AppConsensusEngine) matchesPattern(addr, pattern string) bool {
	// First try exact protocol match
	if e.matchesProtocol(addr, pattern) {
		return true
	}

	// Try matching with port substitution (for %d patterns)
	if strings.Contains(pattern, "%d") {
		// Extract the port from the address
		addrParts := strings.Split(addr, "/")
		patternParts := strings.Split(pattern, "/")

		if len(addrParts) == len(patternParts) {
			allMatch := true
			for i, part := range patternParts {
				if part == "%d" {
					// Skip port comparison
					continue
				}
				// Skip IP comparison for wildcard/localhost in pattern
				if i > 0 && patternParts[i-1] == "ip4" &&
					(part == "0.0.0.0" || part == "127.0.0.1") {
					continue
				}
				if i > 0 && patternParts[i-1] == "ip6" &&
					(part == "::" || part == "::1") {
					continue
				}

				if part != addrParts[i] {
					allMatch = false
					break
				}
			}
			return allMatch
		}
	}

	return false
}

// signPeerInfo signs the peer info message
func (e *AppConsensusEngine) signPeerInfo(
	info *protobufs.PeerInfo,
) ([]byte, error) {
	msg := append([]byte("peerinfo"), info.PeerId...)
	msg = binary.BigEndian.AppendUint64(msg, uint64(info.Timestamp))
	// for _, addr := range info.PubsubMultiaddrs {
	// 	msg = append(msg, addr...)
	// }
	// for _, addr := range info.StreamMultiaddrs {
	// 	msg = append(msg, addr...)
	// }
	// if info.Filter != nil {
	// 	msg = append(msg, hex.EncodeToString(info.Filter)...)
	// }

	return e.pubsub.SignMessage(msg)
}
