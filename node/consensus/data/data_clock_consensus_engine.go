package data

import (
	"context"
	"crypto"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/p2p/discovery/backoff"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	mt "github.com/txaty/go-merkletree"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	qtime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/cas"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/frametime"
	qgrpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

const PEER_INFO_TTL = 60 * 60 * 1000
const UNCOOPERATIVE_PEER_INFO_TTL = 60 * 1000

type SyncStatusType int

const (
	SyncStatusNotSyncing = iota
	SyncStatusAwaitingResponse
	SyncStatusSynchronizing
	SyncStatusFailed
)

type peerInfo struct {
	peerId        []byte
	multiaddr     string
	maxFrame      uint64
	timestamp     int64
	lastSeen      int64
	version       []byte
	totalDistance []byte
}

type ChannelServer = protobufs.DataService_GetPublicChannelServer

type DataClockConsensusEngine struct {
	protobufs.UnimplementedDataServiceServer

	ctx    context.Context
	cancel context.CancelFunc

	lastProven                  uint64
	difficulty                  uint32
	config                      *config.Config
	logger                      *zap.Logger
	state                       consensus.EngineState
	stateMx                     sync.RWMutex
	clockStore                  store.ClockStore
	coinStore                   store.CoinStore
	dataProofStore              store.DataProofStore
	keyStore                    store.KeyStore
	pubSub                      p2p.PubSub
	keyManager                  keys.KeyManager
	masterTimeReel              *qtime.MasterTimeReel
	dataTimeReel                *qtime.DataTimeReel
	peerInfoManager             p2p.PeerInfoManager
	provingKey                  crypto.Signer
	provingKeyBytes             []byte
	provingKeyType              keys.KeyType
	provingKeyAddress           []byte
	lastFrameReceivedAt         time.Time
	latestFrameReceived         uint64
	frameProverTries            []*tries.RollingFrecencyCritbitTrie
	preMidnightMintMx           sync.Mutex
	preMidnightMint             map[string]struct{}
	frameProverTriesMx          sync.RWMutex
	dependencyMap               map[string]*anypb.Any
	pendingCommits              chan *anypb.Any
	pendingCommitWorkers        int64
	inclusionProver             qcrypto.InclusionProver
	frameProver                 qcrypto.FrameProver
	minimumPeersRequired        int
	statsClient                 protobufs.NodeStatsClient
	currentReceivingSyncPeersMx sync.Mutex
	currentReceivingSyncPeers   int
	announcedJoin               int

	frameChan                      chan *protobufs.ClockFrame
	executionEngines               map[string]execution.ExecutionEngine
	filter                         []byte
	txFilter                       []byte
	infoFilter                     []byte
	frameFilter                    []byte
	input                          []byte
	parentSelector                 []byte
	syncingStatus                  SyncStatusType
	syncingTarget                  []byte
	previousHead                   *protobufs.ClockFrame
	engineMx                       sync.Mutex
	dependencyMapMx                sync.Mutex
	stagedTransactions             *protobufs.TokenRequests
	stagedTransactionsMx           sync.Mutex
	peerMapMx                      sync.RWMutex
	peerAnnounceMapMx              sync.Mutex
	lastKeyBundleAnnouncementFrame uint64
	peerMap                        map[string]*peerInfo
	uncooperativePeersMap          map[string]*peerInfo
	frameMessageProcessorCh        chan *pb.Message
	txMessageProcessorCh           chan *pb.Message
	infoMessageProcessorCh         chan *pb.Message
	report                         *protobufs.SelfTestReport
	clients                        []protobufs.DataIPCServiceClient
	grpcRateLimiter                *RateLimiter
	previousFrameProven            *protobufs.ClockFrame
	previousTree                   *mt.MerkleTree
	clientReconnectTest            int
	requestSyncCh                  chan *protobufs.ClockFrame
}

var _ consensus.DataConsensusEngine = (*DataClockConsensusEngine)(nil)

func NewDataClockConsensusEngine(
	cfg *config.Config,
	logger *zap.Logger,
	keyManager keys.KeyManager,
	clockStore store.ClockStore,
	coinStore store.CoinStore,
	dataProofStore store.DataProofStore,
	keyStore store.KeyStore,
	pubSub p2p.PubSub,
	frameProver qcrypto.FrameProver,
	inclusionProver qcrypto.InclusionProver,
	masterTimeReel *qtime.MasterTimeReel,
	dataTimeReel *qtime.DataTimeReel,
	peerInfoManager p2p.PeerInfoManager,
	report *protobufs.SelfTestReport,
	filter []byte,
	seed []byte,
) *DataClockConsensusEngine {
	if logger == nil {
		panic(errors.New("logger is nil"))
	}

	if cfg == nil {
		panic(errors.New("engine config is nil"))
	}

	if keyManager == nil {
		panic(errors.New("key manager is nil"))
	}

	if clockStore == nil {
		panic(errors.New("clock store is nil"))
	}

	if coinStore == nil {
		panic(errors.New("coin store is nil"))
	}

	if dataProofStore == nil {
		panic(errors.New("data proof store is nil"))
	}

	if keyStore == nil {
		panic(errors.New("key store is nil"))
	}

	if pubSub == nil {
		panic(errors.New("pubsub is nil"))
	}

	if frameProver == nil {
		panic(errors.New("frame prover is nil"))
	}

	if inclusionProver == nil {
		panic(errors.New("inclusion prover is nil"))
	}

	if masterTimeReel == nil {
		panic(errors.New("master time reel is nil"))
	}

	if dataTimeReel == nil {
		panic(errors.New("data time reel is nil"))
	}

	if peerInfoManager == nil {
		panic(errors.New("peer info manager is nil"))
	}

	minimumPeersRequired := cfg.Engine.MinimumPeersRequired
	if minimumPeersRequired == 0 {
		minimumPeersRequired = 3
	}

	difficulty := cfg.Engine.Difficulty
	if difficulty == 0 {
		difficulty = 160000
	}

	rateLimit := cfg.P2P.GrpcServerRateLimit
	if rateLimit == 0 {
		rateLimit = 10
	}

	ctx, cancel := context.WithCancel(context.Background())
	e := &DataClockConsensusEngine{
		ctx:              ctx,
		cancel:           cancel,
		difficulty:       difficulty,
		logger:           logger,
		state:            consensus.EngineStateStopped,
		clockStore:       clockStore,
		coinStore:        coinStore,
		dataProofStore:   dataProofStore,
		keyStore:         keyStore,
		keyManager:       keyManager,
		pubSub:           pubSub,
		frameChan:        make(chan *protobufs.ClockFrame),
		executionEngines: map[string]execution.ExecutionEngine{},
		dependencyMap:    make(map[string]*anypb.Any),
		parentSelector: []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		currentReceivingSyncPeers: 0,
		lastFrameReceivedAt:       time.Time{},
		frameProverTries:          []*tries.RollingFrecencyCritbitTrie{},
		inclusionProver:           inclusionProver,
		syncingStatus:             SyncStatusNotSyncing,
		peerMap:                   map[string]*peerInfo{},
		uncooperativePeersMap:     map[string]*peerInfo{},
		minimumPeersRequired:      minimumPeersRequired,
		report:                    report,
		frameProver:               frameProver,
		masterTimeReel:            masterTimeReel,
		dataTimeReel:              dataTimeReel,
		peerInfoManager:           peerInfoManager,
		frameMessageProcessorCh:   make(chan *pb.Message),
		txMessageProcessorCh:      make(chan *pb.Message),
		infoMessageProcessorCh:    make(chan *pb.Message),
		config:                    cfg,
		preMidnightMint:           map[string]struct{}{},
		grpcRateLimiter: NewRateLimiter(
			rateLimit,
			time.Minute,
		),
		requestSyncCh: make(chan *protobufs.ClockFrame, 1),
	}

	logger.Info("constructing consensus engine")

	signer, keyType, bytes, address := e.GetProvingKey(
		cfg.Engine,
	)

	e.filter = filter
	e.txFilter = append([]byte{0x00}, e.filter...)
	e.infoFilter = append([]byte{0x00, 0x00}, e.filter...)
	e.frameFilter = append([]byte{0x00, 0x00, 0x00}, e.filter...)
	e.input = seed
	e.provingKey = signer
	e.provingKeyType = keyType
	e.provingKeyBytes = bytes
	e.provingKeyAddress = address

	return e
}

func (e *DataClockConsensusEngine) Start() <-chan error {
	e.logger.Info("starting data consensus engine")
	e.stateMx.Lock()
	e.state = consensus.EngineStateStarting
	e.stateMx.Unlock()
	errChan := make(chan error)
	e.stateMx.Lock()
	e.state = consensus.EngineStateLoading
	e.stateMx.Unlock()

	e.logger.Info("loading last seen state")
	err := e.dataTimeReel.Start()
	if err != nil {
		panic(err)
	}

	e.frameProverTries = e.dataTimeReel.GetFrameProverTries()

	err = e.createCommunicationKeys()
	if err != nil {
		panic(err)
	}

	go e.runFrameMessageHandler()
	go e.runTxMessageHandler()
	go e.runInfoMessageHandler()

	e.logger.Info("subscribing to pubsub messages")
	e.pubSub.RegisterValidator(e.frameFilter, e.validateFrameMessage)
	e.pubSub.RegisterValidator(e.txFilter, e.validateTxMessage)
	e.pubSub.RegisterValidator(e.infoFilter, e.validateInfoMessage)
	e.pubSub.Subscribe(e.frameFilter, e.handleFrameMessage)
	e.pubSub.Subscribe(e.txFilter, e.handleTxMessage)
	e.pubSub.Subscribe(e.infoFilter, e.handleInfoMessage)
	go func() {
		server := qgrpc.NewServer(
			grpc.MaxSendMsgSize(20*1024*1024),
			grpc.MaxRecvMsgSize(20*1024*1024),
		)
		protobufs.RegisterDataServiceServer(server, e)
		if err := e.pubSub.StartDirectChannelListener(
			e.pubSub.GetPeerID(),
			"sync",
			server,
		); err != nil {
			panic(err)
		}
	}()

	go func() {
		if e.dataTimeReel.GetFrameProverTries()[0].Contains(e.provingKeyAddress) {
			server := qgrpc.NewServer(
				grpc.MaxSendMsgSize(1*1024*1024),
				grpc.MaxRecvMsgSize(1*1024*1024),
			)
			protobufs.RegisterDataServiceServer(server, e)

			if err := e.pubSub.StartDirectChannelListener(
				e.pubSub.GetPeerID(),
				"worker",
				server,
			); err != nil {
				panic(err)
			}
		}
	}()

	e.stateMx.Lock()
	e.state = consensus.EngineStateCollecting
	e.stateMx.Unlock()

	go func() {
		const baseDuration = 2 * time.Minute
		const maxBackoff = 3
		var currentBackoff = 0
		lastHead, err := e.dataTimeReel.Head()
		if err != nil {
			panic(err)
		}
		source := rand.New(rand.NewSource(rand.Int63()))
		for e.GetState() < consensus.EngineStateStopping {
			// Use exponential backoff with jitter in order to avoid hammering the bootstrappers.
			time.Sleep(
				backoff.FullJitter(
					baseDuration<<currentBackoff,
					baseDuration,
					baseDuration<<maxBackoff,
					source,
				),
			)
			currentHead, err := e.dataTimeReel.Head()
			if err != nil {
				panic(err)
			}
			if currentHead.FrameNumber == lastHead.FrameNumber {
				currentBackoff = min(maxBackoff, currentBackoff+1)
				_ = e.pubSub.DiscoverPeers()
			} else {
				currentBackoff = max(0, currentBackoff-1)
				lastHead = currentHead
			}
		}
	}()

	go func() {
		thresholdBeforeConfirming := 4
		frame, err := e.dataTimeReel.Head()
		if err != nil {
			panic(err)
		}
		for {
			nextFrame, err := e.dataTimeReel.Head()
			if err != nil {
				panic(err)
			}

			if frame.FrameNumber-100 >= nextFrame.FrameNumber ||
				nextFrame.FrameNumber == 0 {
				time.Sleep(120 * time.Second)
				continue
			}

			frame = nextFrame

			timestamp := time.Now().UnixMilli()
			list := &protobufs.DataPeerListAnnounce{
				Peer: &protobufs.DataPeer{
					PeerId:    nil,
					Multiaddr: "",
					MaxFrame:  frame.FrameNumber,
					Version:   config.GetVersion(),
					Timestamp: timestamp,
					TotalDistance: e.dataTimeReel.GetTotalDistance().FillBytes(
						make([]byte, 256),
					),
				},
			}

			cas.IfLessThanUint64(&e.latestFrameReceived, frame.FrameNumber)
			e.logger.Info(
				"preparing peer announce",
				zap.Uint64("frame_number", frame.FrameNumber),
				zap.Duration("frame_age", frametime.Since(frame)),
			)

			e.peerMapMx.Lock()
			e.peerMap[string(e.pubSub.GetPeerID())] = &peerInfo{
				peerId:    e.pubSub.GetPeerID(),
				multiaddr: "",
				maxFrame:  frame.FrameNumber,
				version:   config.GetVersion(),
				timestamp: timestamp,
				totalDistance: e.dataTimeReel.GetTotalDistance().FillBytes(
					make([]byte, 256),
				),
			}
			deletes := []*peerInfo{}
			for _, v := range e.peerMap {
				if v == nil {
					continue
				}
				if v.timestamp <= time.Now().UnixMilli()-PEER_INFO_TTL {
					deletes = append(deletes, v)
				}
			}
			for _, v := range deletes {
				delete(e.peerMap, string(v.peerId))
			}
			deletes = []*peerInfo{}
			for _, v := range e.uncooperativePeersMap {
				if v == nil {
					continue
				}
				if v.timestamp <= time.Now().UnixMilli()-UNCOOPERATIVE_PEER_INFO_TTL ||
					thresholdBeforeConfirming > 0 {
					deletes = append(deletes, v)
				}
			}
			for _, v := range deletes {
				delete(e.uncooperativePeersMap, string(v.peerId))
			}
			e.peerMapMx.Unlock()

			e.logger.Info(
				"broadcasting peer info",
				zap.Uint64("frame_number", frame.FrameNumber),
				zap.Duration("frame_age", frametime.Since(frame)),
			)

			if err := e.publishMessage(e.infoFilter, list); err != nil {
				e.logger.Debug("error publishing message", zap.Error(err))
			}

			if thresholdBeforeConfirming > 0 {
				thresholdBeforeConfirming--
			}

			time.Sleep(120 * time.Second)
		}
	}()

	go e.runLoop()
	go e.runSync()
	go func() {
		time.Sleep(30 * time.Second)
		e.logger.Info("checking for snapshots to play forward")
		if err := e.downloadSnapshot(e.config.DB.Path, e.config.P2P.Network); err != nil {
			e.logger.Debug("error downloading snapshot", zap.Error(err))
		} else if err := e.applySnapshot(e.config.DB.Path); err != nil {
			e.logger.Debug("error replaying snapshot", zap.Error(err))
		}
	}()

	go func() {
		errChan <- nil
	}()

	go e.runPreMidnightProofWorker()

	go func() {
		parallelism := e.report.Cores - 1

		if parallelism < 3 {
			panic("invalid system configuration, minimum system configuration must be four cores")
		}

		if len(e.config.Engine.DataWorkerMultiaddrs) != 0 {
			e.clients, err = e.createParallelDataClientsFromList()
			if err != nil {
				panic(err)
			}
		} else {
			e.clients, err = e.createParallelDataClientsFromBaseMultiaddr(
				int(parallelism),
			)
			if err != nil {
				panic(err)
			}
		}
	}()

	return errChan
}

func (e *DataClockConsensusEngine) PerformTimeProof(
	frame *protobufs.ClockFrame,
	difficulty uint32,
	ring int,
) []mt.DataBlock {
	type clientInfo struct {
		client protobufs.DataIPCServiceClient
		index  int
	}
	actives := []clientInfo{}
	for i, client := range e.clients {
		i := i
		client := client
		if client != nil {
			actives = append(actives, clientInfo{
				client: client,
				index:  i,
			})
		}
	}
	output := make([]mt.DataBlock, len(actives))
	e.logger.Info(
		"creating data shard ring proof",
		zap.Int("ring", ring),
		zap.Int("active_workers", len(actives)),
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.Duration("frame_age", frametime.Since(frame)),
	)

	wg := sync.WaitGroup{}
	wg.Add(len(actives))

	for i, client := range actives {
		i := i
		client := client
		go func() {
			resp, err :=
				client.client.CalculateChallengeProof(
					e.ctx,
					&protobufs.ChallengeProofRequest{
						PeerId:     e.pubSub.GetPeerID(),
						Core:       uint32(i),
						ClockFrame: frame,
					},
				)
			if err != nil {
				if status.Code(err) == codes.NotFound {
					wg.Done()
					return
				}
			}

			if resp != nil {
				output[i] = tries.NewProofLeaf(resp.Output)
			} else {
				e.clients[client.index] = nil
			}

			wg.Done()
		}()
	}
	wg.Wait()

	for _, out := range output {
		if out == nil {
			return nil
		}
	}

	return output
}

func (e *DataClockConsensusEngine) Stop(force bool) <-chan error {
	e.logger.Info("stopping ceremony consensus engine")
	e.cancel()
	e.stateMx.Lock()
	e.state = consensus.EngineStateStopping
	e.stateMx.Unlock()
	errChan := make(chan error)

	msg := []byte("pause")
	msg = binary.BigEndian.AppendUint64(msg, e.GetFrame().FrameNumber)
	msg = append(msg, e.filter...)
	sig, err := e.pubSub.SignMessage(msg)
	if err != nil {
		panic(err)
	}

	e.publishMessage(e.txFilter, &protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Pause{
			Pause: &protobufs.AnnounceProverPause{
				Filter:      e.filter,
				FrameNumber: e.GetFrame().FrameNumber,
				PublicKeySignatureEd448: &protobufs.Ed448Signature{
					PublicKey: &protobufs.Ed448PublicKey{
						KeyValue: e.pubSub.GetPublicKey(),
					},
					Signature: sig,
				},
			},
		},
		Timestamp: time.Now().UnixMilli(),
	})

	wg := sync.WaitGroup{}
	wg.Add(len(e.executionEngines))
	for name := range e.executionEngines {
		name := name
		go func(name string) {
			frame, err := e.dataTimeReel.Head()
			if err != nil {
				panic(err)
			}

			err = <-e.UnregisterExecutor(name, frame.FrameNumber, force)
			if err != nil {
				errChan <- err
			}
			wg.Done()
		}(name)
	}

	e.pubSub.Unsubscribe(e.frameFilter, false)
	e.pubSub.Unsubscribe(e.txFilter, false)
	e.pubSub.Unsubscribe(e.infoFilter, false)
	e.pubSub.UnregisterValidator(e.frameFilter)
	e.pubSub.UnregisterValidator(e.txFilter)
	e.pubSub.UnregisterValidator(e.infoFilter)

	e.logger.Info("waiting for execution engines to stop")
	wg.Wait()
	e.logger.Info("execution engines stopped")

	e.dataTimeReel.Stop()
	e.stateMx.Lock()
	e.state = consensus.EngineStateStopped
	e.stateMx.Unlock()

	e.engineMx.Lock()
	defer e.engineMx.Unlock()
	go func() {
		errChan <- nil
	}()
	return errChan
}

func (e *DataClockConsensusEngine) GetDifficulty() uint32 {
	return e.difficulty
}

func (e *DataClockConsensusEngine) GetFrame() *protobufs.ClockFrame {
	frame, err := e.dataTimeReel.Head()
	if err != nil {
		return nil
	}

	return frame
}

func (e *DataClockConsensusEngine) GetState() consensus.EngineState {
	e.stateMx.RLock()
	defer e.stateMx.RUnlock()
	return e.state
}

func (
	e *DataClockConsensusEngine,
) GetPeerInfo() *protobufs.PeerInfoResponse {
	resp := &protobufs.PeerInfoResponse{}
	e.peerMapMx.RLock()
	for _, v := range e.peerMap {
		resp.PeerInfo = append(resp.PeerInfo, &protobufs.PeerInfo{
			PeerId:        v.peerId,
			Multiaddrs:    []string{v.multiaddr},
			MaxFrame:      v.maxFrame,
			Timestamp:     v.timestamp,
			Version:       v.version,
			TotalDistance: v.totalDistance,
		})
	}
	for _, v := range e.uncooperativePeersMap {
		resp.UncooperativePeerInfo = append(
			resp.UncooperativePeerInfo,
			&protobufs.PeerInfo{
				PeerId:        v.peerId,
				Multiaddrs:    []string{v.multiaddr},
				MaxFrame:      v.maxFrame,
				Timestamp:     v.timestamp,
				Version:       v.version,
				TotalDistance: v.totalDistance,
			},
		)
	}
	e.peerMapMx.RUnlock()
	return resp
}

func (e *DataClockConsensusEngine) createCommunicationKeys() error {
	_, err := e.keyManager.GetAgreementKey("q-ratchet-idk")
	if err != nil {
		if errors.Is(err, keys.KeyNotFoundErr) {
			_, err = e.keyManager.CreateAgreementKey(
				"q-ratchet-idk",
				keys.KeyTypeX448,
			)
			if err != nil {
				return errors.Wrap(err, "announce key bundle")
			}
		} else {
			return errors.Wrap(err, "announce key bundle")
		}
	}

	_, err = e.keyManager.GetAgreementKey("q-ratchet-spk")
	if err != nil {
		if errors.Is(err, keys.KeyNotFoundErr) {
			_, err = e.keyManager.CreateAgreementKey(
				"q-ratchet-spk",
				keys.KeyTypeX448,
			)
			if err != nil {
				return errors.Wrap(err, "announce key bundle")
			}
		} else {
			return errors.Wrap(err, "announce key bundle")
		}
	}

	return nil
}

func (e *DataClockConsensusEngine) createParallelDataClientsFromListAndIndex(
	index uint32,
) (
	protobufs.DataIPCServiceClient,
	error,
) {
	ma, err := multiaddr.NewMultiaddr(e.config.Engine.DataWorkerMultiaddrs[index])
	if err != nil {
		return nil, errors.Wrap(err, "create parallel data client")
	}

	_, addr, err := mn.DialArgs(ma)
	if err != nil {
		return nil, errors.Wrap(err, "create parallel data client")
	}

	ctx, cancel := context.WithTimeout(e.ctx, 1*time.Second)
	defer cancel()
	conn, err := qgrpc.DialContext(
		ctx,
		addr,
		grpc.WithTransportCredentials(
			insecure.NewCredentials(),
		),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(10*1024*1024),
			grpc.MaxCallRecvMsgSize(10*1024*1024),
		),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, errors.Wrap(err, "create parallel data client")
	}

	client := protobufs.NewDataIPCServiceClient(conn)

	e.logger.Info(
		"connected to data worker process",
		zap.Uint32("client", index),
	)
	return client, nil
}

func (
	e *DataClockConsensusEngine,
) createParallelDataClientsFromBaseMultiaddrAndIndex(
	index uint32,
) (
	protobufs.DataIPCServiceClient,
	error,
) {
	e.logger.Info(
		"re-connecting to data worker process",
		zap.Uint32("client", index),
	)

	if e.config.Engine.DataWorkerBaseListenMultiaddr == "" {
		e.config.Engine.DataWorkerBaseListenMultiaddr = "/ip4/127.0.0.1/tcp/%d"
	}

	if e.config.Engine.DataWorkerBaseListenPort == 0 {
		e.config.Engine.DataWorkerBaseListenPort = 40000
	}

	ma, err := multiaddr.NewMultiaddr(
		fmt.Sprintf(
			e.config.Engine.DataWorkerBaseListenMultiaddr,
			int(e.config.Engine.DataWorkerBaseListenPort)+int(index),
		),
	)
	if err != nil {
		return nil, errors.Wrap(err, "create parallel data client")
	}

	_, addr, err := mn.DialArgs(ma)
	if err != nil {
		return nil, errors.Wrap(err, "create parallel data client")
	}

	ctx, cancel := context.WithTimeout(e.ctx, 1*time.Second)
	defer cancel()
	conn, err := qgrpc.DialContext(
		ctx,
		addr,
		grpc.WithTransportCredentials(
			insecure.NewCredentials(),
		),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(10*1024*1024),
			grpc.MaxCallRecvMsgSize(10*1024*1024),
		),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, errors.Wrap(err, "create parallel data client")
	}

	client := protobufs.NewDataIPCServiceClient(conn)

	e.logger.Info(
		"connected to data worker process",
		zap.Uint32("client", index),
	)
	return client, nil
}

func (e *DataClockConsensusEngine) createParallelDataClientsFromList() (
	[]protobufs.DataIPCServiceClient,
	error,
) {
	parallelism := len(e.config.Engine.DataWorkerMultiaddrs)

	e.logger.Info(
		"connecting to data worker processes",
		zap.Int("parallelism", parallelism),
	)

	clients := make([]protobufs.DataIPCServiceClient, parallelism)

	for i := 0; i < parallelism; i++ {
		ma, err := multiaddr.NewMultiaddr(e.config.Engine.DataWorkerMultiaddrs[i])
		if err != nil {
			panic(err)
		}

		_, addr, err := mn.DialArgs(ma)
		if err != nil {
			e.logger.Error("could not get dial args", zap.Error(err))
			continue
		}

		ctx, cancel := context.WithTimeout(e.ctx, 1*time.Second)
		defer cancel()
		conn, err := qgrpc.DialContext(
			ctx,
			addr,
			grpc.WithTransportCredentials(
				insecure.NewCredentials(),
			),
			grpc.WithDefaultCallOptions(
				grpc.MaxCallSendMsgSize(10*1024*1024),
				grpc.MaxCallRecvMsgSize(10*1024*1024),
			),
			grpc.WithBlock(),
		)
		if err != nil {
			e.logger.Error("could not dial", zap.Error(err))
			continue
		}

		clients[i] = protobufs.NewDataIPCServiceClient(conn)
	}

	e.logger.Info(
		"connected to data worker processes",
		zap.Int("parallelism", parallelism),
	)
	return clients, nil
}

func (e *DataClockConsensusEngine) createParallelDataClientsFromBaseMultiaddr(
	parallelism int,
) ([]protobufs.DataIPCServiceClient, error) {
	e.logger.Info(
		"connecting to data worker processes",
		zap.Int("parallelism", parallelism),
	)

	if e.config.Engine.DataWorkerBaseListenMultiaddr == "" {
		e.config.Engine.DataWorkerBaseListenMultiaddr = "/ip4/127.0.0.1/tcp/%d"
	}

	if e.config.Engine.DataWorkerBaseListenPort == 0 {
		e.config.Engine.DataWorkerBaseListenPort = 40000
	}

	clients := make([]protobufs.DataIPCServiceClient, parallelism)

	for i := 0; i < parallelism; i++ {
		ma, err := multiaddr.NewMultiaddr(
			fmt.Sprintf(
				e.config.Engine.DataWorkerBaseListenMultiaddr,
				int(e.config.Engine.DataWorkerBaseListenPort)+i,
			),
		)
		if err != nil {
			panic(err)
		}

		_, addr, err := mn.DialArgs(ma)
		if err != nil {
			e.logger.Error("could not get dial args", zap.Error(err))
			continue
		}
		ctx, cancel := context.WithTimeout(e.ctx, 1*time.Second)
		defer cancel()
		conn, err := qgrpc.DialContext(
			ctx,
			addr,
			grpc.WithTransportCredentials(
				insecure.NewCredentials(),
			),
			grpc.WithDefaultCallOptions(
				grpc.MaxCallSendMsgSize(10*1024*1024),
				grpc.MaxCallRecvMsgSize(10*1024*1024),
			),
			grpc.WithBlock(),
		)
		if err != nil {
			e.logger.Error("could not dial", zap.Error(err))
			continue
		}

		clients[i] = protobufs.NewDataIPCServiceClient(conn)
	}

	e.logger.Info(
		"connected to data worker processes",
		zap.Int("parallelism", parallelism),
	)
	return clients, nil
}
