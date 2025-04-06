package token

import (
	"bytes"
	"context"
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	gotime "time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/data"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	hypergraph "source.quilibrium.com/quilibrium/monorepo/node/hypergraph/application"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/frametime"
	qgrpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	qruntime "source.quilibrium.com/quilibrium/monorepo/node/internal/runtime"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/rpc"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

type PeerSeniorityItem struct {
	seniority uint64
	addr      string
}

func NewPeerSeniorityItem(seniority uint64, addr string) PeerSeniorityItem {
	return PeerSeniorityItem{
		seniority: seniority,
		addr:      addr,
	}
}

func (p PeerSeniorityItem) GetSeniority() uint64 {
	return p.seniority
}

func (p PeerSeniorityItem) GetAddr() string {
	return p.addr
}

type PeerSeniority map[string]PeerSeniorityItem

func NewFromMap(m map[string]uint64) *PeerSeniority {
	s := &PeerSeniority{}
	for k, v := range m {
		(*s)[k] = PeerSeniorityItem{
			seniority: v,
			addr:      k,
		}
	}
	return s
}

func ToSerializedMap(m *PeerSeniority) map[string]uint64 {
	s := map[string]uint64{}
	for k, v := range *m {
		s[k] = v.seniority
	}
	return s
}

func (p PeerSeniorityItem) Priority() uint64 {
	return p.seniority
}

type TokenExecutionEngine struct {
	ctx                        context.Context
	cancel                     context.CancelFunc
	wg                         sync.WaitGroup
	logger                     *zap.Logger
	clock                      *data.DataClockConsensusEngine
	clockStore                 store.ClockStore
	hypergraphStore            store.HypergraphStore
	coinStore                  store.CoinStore
	keyStore                   store.KeyStore
	keyManager                 keys.KeyManager
	engineConfig               *config.EngineConfig
	pubSub                     p2p.PubSub
	peerIdHash                 []byte
	provingKey                 crypto.Signer
	proverPublicKey            []byte
	provingKeyAddress          []byte
	inclusionProver            qcrypto.InclusionProver
	participantMx              sync.Mutex
	peerChannels               map[string]*p2p.PublicP2PChannel
	activeClockFrame           *protobufs.ClockFrame
	alreadyPublishedShare      bool
	intrinsicFilter            []byte
	frameProver                qcrypto.FrameProver
	peerSeniority              *PeerSeniority
	hypergraph                 *hypergraph.Hypergraph
	mpcithVerEnc               *qcrypto.MPCitHVerifiableEncryptor
	syncController             *rpc.SyncController
	grpcServers                []*grpc.Server
	metadataMessageProcessorCh chan *pb.Message
	syncTargetMap              map[string]syncInfo
	syncTargetMx               sync.Mutex
}

type syncInfo struct {
	peerId     []byte
	leaves     uint64
	commitment []byte
}

func NewTokenExecutionEngine(
	logger *zap.Logger,
	cfg *config.Config,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
	frameProver qcrypto.FrameProver,
	inclusionProver qcrypto.InclusionProver,
	clockStore store.ClockStore,
	dataProofStore store.DataProofStore,
	hypergraphStore store.HypergraphStore,
	coinStore store.CoinStore,
	masterTimeReel *time.MasterTimeReel,
	peerInfoManager p2p.PeerInfoManager,
	keyStore store.KeyStore,
	report *protobufs.SelfTestReport,
) *TokenExecutionEngine {
	if logger == nil {
		panic(errors.New("logger is nil"))
	}
	slogger := logger.With(zap.String("stage", "token-execution"))

	seed, err := hex.DecodeString(cfg.Engine.GenesisSeed)
	if err != nil {
		slogger.Panic("failed to decode genesis seed", zap.Error(err))
	}

	intrinsicFilter := p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3)

	_, _, err = clockStore.GetDataClockFrame(intrinsicFilter, 0, false)
	var origin []byte
	var inclusionProof *qcrypto.InclusionAggregateProof
	var proverKeys [][]byte
	var peerSeniority map[string]uint64
	hg := hypergraph.NewHypergraph(hypergraphStore)
	mpcithVerEnc := qcrypto.NewMPCitHVerifiableEncryptor(
		runtime.NumCPU(),
	)

	if err != nil && errors.Is(err, store.ErrNotFound) {
		origin, inclusionProof, proverKeys, peerSeniority = CreateGenesisState(
			logger,
			cfg.Engine,
			nil,
			inclusionProver,
			clockStore,
			coinStore,
			hypergraphStore,
			hg,
			mpcithVerEnc,
			uint(cfg.P2P.Network),
		)
		if err := coinStore.SetMigrationVersion(
			config.GetGenesis().GenesisSeedHex,
		); err != nil {
			slogger.Panic("failed to set migration version", zap.Error(err))
		}
	} else if err != nil {
		slogger.Panic("failed to get data clock frame", zap.Error(err))
	} else {
		if pubSub.GetNetwork() == 0 {
			err := coinStore.Migrate(
				intrinsicFilter,
				config.GetGenesis().GenesisSeedHex,
			)
			if err != nil {
				slogger.Panic("failed to migrate coins", zap.Error(err))
			}
			_, err = clockStore.GetEarliestDataClockFrame(intrinsicFilter)
			if err != nil && errors.Is(err, store.ErrNotFound) {
				origin, inclusionProof, proverKeys, peerSeniority = CreateGenesisState(
					logger,
					cfg.Engine,
					nil,
					inclusionProver,
					clockStore,
					coinStore,
					hypergraphStore,
					hg,
					mpcithVerEnc,
					uint(cfg.P2P.Network),
				)
			}
		}
	}

	if len(peerSeniority) == 0 {
		peerSeniority, err = clockStore.GetPeerSeniorityMap(intrinsicFilter)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			slogger.Panic("failed to get peer seniority map", zap.Error(err))
		}

		if len(peerSeniority) == 0 {
			peerSeniority, err = RebuildPeerSeniority(uint(cfg.P2P.Network))
			if err != nil {
				slogger.Panic("failed to rebuild peer seniority", zap.Error(err))
			}

			txn, err := clockStore.NewTransaction(false)
			if err != nil {
				slogger.Panic("failed to create transaction", zap.Error(err))
			}

			err = clockStore.PutPeerSeniorityMap(txn, intrinsicFilter, peerSeniority)
			if err != nil {
				txn.Abort()
				slogger.Panic("failed to put peer seniority map", zap.Error(err))
			}

			if err = txn.Commit(); err != nil {
				txn.Abort()
				slogger.Panic("failed to commit transaction", zap.Error(err))
			}
		}
	} else {
		LoadAggregatedSeniorityMap(uint(cfg.P2P.Network))
	}

	ctx, cancel := context.WithCancel(context.Background())
	e := &TokenExecutionEngine{
		ctx:                        ctx,
		cancel:                     cancel,
		logger:                     slogger,
		engineConfig:               cfg.Engine,
		keyManager:                 keyManager,
		clockStore:                 clockStore,
		coinStore:                  coinStore,
		hypergraphStore:            hypergraphStore,
		keyStore:                   keyStore,
		pubSub:                     pubSub,
		inclusionProver:            inclusionProver,
		frameProver:                frameProver,
		participantMx:              sync.Mutex{},
		peerChannels:               map[string]*p2p.PublicP2PChannel{},
		alreadyPublishedShare:      false,
		intrinsicFilter:            intrinsicFilter,
		peerSeniority:              NewFromMap(peerSeniority),
		mpcithVerEnc:               mpcithVerEnc,
		syncController:             rpc.NewSyncController(),
		metadataMessageProcessorCh: make(chan *pb.Message, 65536),
		syncTargetMap:              make(map[string]syncInfo),
	}

	alwaysSend := false
	if bytes.Equal(config.GetGenesis().Beacon, pubSub.GetPublicKey()) {
		alwaysSend = true
	}

	dataTimeReel := time.NewDataTimeReel(
		intrinsicFilter,
		logger,
		clockStore,
		cfg.Engine,
		frameProver,
		func(
			txn store.Transaction,
			frame *protobufs.ClockFrame,
			triesAtFrame []*tries.RollingFrecencyCritbitTrie,
		) (
			[]*tries.RollingFrecencyCritbitTrie,
			error,
		) {
			if e.engineConfig.FullProver {
				if err := e.VerifyExecution(frame, triesAtFrame); err != nil {
					return nil, err
				}
			}
			var tries []*tries.RollingFrecencyCritbitTrie
			if tries, err = e.ProcessFrame(txn, frame, triesAtFrame); err != nil {
				return nil, err
			}

			return tries, nil
		},
		origin,
		inclusionProof,
		proverKeys,
		alwaysSend,
	)

	e.clock = data.NewDataClockConsensusEngine(
		cfg,
		logger,
		keyManager,
		clockStore,
		coinStore,
		dataProofStore,
		keyStore,
		pubSub,
		frameProver,
		inclusionProver,
		masterTimeReel,
		dataTimeReel,
		peerInfoManager,
		report,
		intrinsicFilter,
		seed,
	)

	peerId := e.pubSub.GetPeerID()
	addr, err := poseidon.HashBytes(peerId)
	if err != nil {
		e.logger.Panic("could not hash peer id", zap.Error(err))
	}

	addrBytes := addr.FillBytes(make([]byte, 32))
	e.peerIdHash = addrBytes
	provingKey, _, publicKeyBytes, provingKeyAddress := e.clock.GetProvingKey(
		cfg.Engine,
	)
	e.provingKey = provingKey
	e.proverPublicKey = publicKeyBytes
	e.provingKeyAddress = provingKeyAddress

	// debug carveout for M5 testing
	iter, err := e.coinStore.RangeCoins(
		[]byte{0x00},
		[]byte{0xff},
	)
	if err != nil {
		e.logger.Panic("could not get range coins", zap.Error(err))
	}

	totalCoins := 0
	specificRange := 0
	if e.engineConfig.RebuildStart == "" {
		e.engineConfig.RebuildStart = "0000000000000000000000000000000000000000000000000000000000000000"
	}
	if e.engineConfig.RebuildEnd == "" {
		e.engineConfig.RebuildEnd = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	}
	start, err := hex.DecodeString(e.engineConfig.RebuildStart)
	if err != nil {
		e.logger.Panic("could not decode start", zap.Error(err))
	}
	end, err := hex.DecodeString(e.engineConfig.RebuildEnd)
	if err != nil {
		e.logger.Panic("could not decode end", zap.Error(err))
	}

	includeSet := [][]byte{}

	for iter.First(); iter.Valid(); iter.Next() {
		if bytes.Compare(iter.Key()[2:], start) >= 0 && bytes.Compare(iter.Key()[2:], end) < 0 {
			key := make([]byte, len(iter.Key())-2)
			copy(key, iter.Key()[2:])
			includeSet = append(includeSet, key)
			specificRange++
		}
		totalCoins++
	}
	iter.Close()
	// end debug carveout for M5 testing

	_, _, err = e.clockStore.GetLatestDataClockFrame(e.intrinsicFilter)
	if err != nil {
		e.rebuildHypergraph(specificRange)
	} else {
		e.hypergraph, err = e.hypergraphStore.LoadHypergraph()
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			e.logger.Error(
				"error encountered while fetching hypergraph, rebuilding",
				zap.Error(err),
			)
		}

		if e.hypergraph == nil || len(e.hypergraph.GetVertexAdds()) == 0 {
			e.rebuildHypergraph(specificRange)
		}

		if len(e.hypergraph.GetVertexAdds()) == 0 {
			e.logger.Panic("hypergraph does not contain id set for application")
		}

		var vertices *hypergraph.IdSet
		for _, set := range e.hypergraph.GetVertexAdds() {
			vertices = set
		}

		if vertices == nil {
			e.logger.Panic("hypergraph does not contain id set for application")
		}

		rebuildSet := [][]byte{}
		for _, inc := range includeSet {

			if !vertices.Has(
				[64]byte(slices.Concat(application.TOKEN_ADDRESS, inc)),
			) {
				rebuildSet = append(rebuildSet, inc)
			}
		}

		if len(rebuildSet) != 0 {
			e.rebuildMissingSetForHypergraph(rebuildSet)
		}
	}

	syncServer := qgrpc.NewServer(
		grpc.MaxRecvMsgSize(e.engineConfig.SyncMessageLimits.MaxRecvMsgSize),
		grpc.MaxSendMsgSize(e.engineConfig.SyncMessageLimits.MaxSendMsgSize),
	)
	e.grpcServers = append(e.grpcServers[:0:0], syncServer)
	hyperSync := rpc.NewHypergraphComparisonServer(
		e.logger,
		e.hypergraphStore,
		e.hypergraph,
		e.syncController,
		totalCoins,
		false,
	)

	hypersyncMetadataFilter := slices.Concat(
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00},
		intrinsicFilter,
	)
	e.pubSub.Subscribe(hypersyncMetadataFilter, e.handleMetadataMessage)
	e.wg.Add(1)
	go e.runMetadataMessageHandler()
	for _, h := range e.hypergraph.Commit() {
		e.logger.Info(
			"current hypergraph commit",
			zap.String("root_commitment", hex.EncodeToString(h)),
		)
	}

	protobufs.RegisterHypergraphComparisonServiceServer(syncServer, hyperSync)
	go func() {
		if err := e.pubSub.StartDirectChannelListener(
			e.pubSub.GetPeerID(),
			"hypersync",
			syncServer,
		); err != nil {
			e.logger.Error("error starting sync server", zap.Error(err))
		}
	}()

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			select {
			case <-gotime.After(5 * gotime.Second):
				e.hyperSync(totalCoins)
			case <-e.ctx.Done():
				return
			}
		}
	}()

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			select {
			case <-gotime.After(5 * gotime.Minute):
				e.publishSyncInfo()
			case <-e.ctx.Done():
				return
			}
		}
	}()

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		f, tries, err := e.clockStore.GetLatestDataClockFrame(e.intrinsicFilter)
		if err != nil {
			return
		}

		shouldResume := false
		for _, trie := range tries[1:] {
			altAddr, err := poseidon.HashBytes(e.pubSub.GetPeerID())
			if err != nil {
				break
			}

			if trie.Contains(altAddr.FillBytes(make([]byte, 32))) {
				shouldResume = true
				break
			}
		}

		if shouldResume {
			resume := &protobufs.AnnounceProverResume{
				Filter:      e.intrinsicFilter,
				FrameNumber: f.FrameNumber,
			}
			if err := resume.SignED448(e.pubSub.GetPublicKey(), e.pubSub.SignMessage); err != nil {
				e.logger.Panic("error signing resume message", zap.Error(err))
			}
			if err := resume.Validate(); err != nil {
				e.logger.Panic("error validating resume message", zap.Error(err))
			}

			// need to wait for peering
		waitPeers:
			for {
				select {
				case <-e.ctx.Done():
					return
				case <-gotime.After(30 * gotime.Second):
					peerMap := e.pubSub.GetBitmaskPeers()
					if peers, ok := peerMap[string(
						append([]byte{0x00}, e.intrinsicFilter...),
					)]; ok {
						if len(peers) >= 3 {
							break waitPeers
						}
					}
				}
			}
			if err := e.publishMessage(
				append([]byte{0x00}, e.intrinsicFilter...),
				resume.TokenRequest(),
			); err != nil {
				e.logger.Warn("error while publishing resume message", zap.Error(err))
			}
		}
	}()

	return e
}

var _ execution.ExecutionEngine = (*TokenExecutionEngine)(nil)

func (e *TokenExecutionEngine) handleMetadataMessage(
	message *pb.Message,
) error {
	select {
	case <-e.ctx.Done():
		return e.ctx.Err()
	case e.metadataMessageProcessorCh <- message:
	default:
		e.logger.Warn("dropping metadata message")
	}
	return nil
}

func (e *TokenExecutionEngine) runMetadataMessageHandler() {
	defer e.wg.Done()
	for {
		select {
		case <-e.ctx.Done():
			return
		case message := <-e.metadataMessageProcessorCh:
			e.logger.Debug("handling metadata message")
			msg := &protobufs.Message{}

			if err := proto.Unmarshal(message.Data, msg); err != nil {
				e.logger.Debug("could not unmarshal data", zap.Error(err))
				continue
			}

			a := &anypb.Any{}
			if err := proto.Unmarshal(msg.Payload, a); err != nil {
				e.logger.Debug("could not unmarshal payload", zap.Error(err))
				continue
			}

			switch a.TypeUrl {
			case protobufs.HypersyncMetadataType:
				if err := e.handleMetadata(
					message.From,
					msg.Address,
					a,
				); err != nil {
					e.logger.Debug("could not handle metadata", zap.Error(err))
				}
			}
		}
	}
}

func (e *TokenExecutionEngine) handleMetadata(
	peerID []byte,
	address []byte,
	a *anypb.Any,
) error {
	if bytes.Equal(peerID, e.pubSub.GetPeerID()) {
		return nil
	}

	metadata := &protobufs.HypersyncMetadata{}
	if err := a.UnmarshalTo(metadata); err != nil {
		return errors.Wrap(err, "handle metadata")
	}

	e.logger.Info(
		"received sync info from peer",
		zap.String("peer_id", peer.ID(peerID).String()),
		zap.Uint64("vertices", metadata.Leaves),
		zap.Binary("root_commitment", metadata.RootCommitment),
	)

	e.syncTargetMx.Lock()
	e.syncTargetMap[string(peerID)] = syncInfo{
		peerId:     peerID,
		leaves:     metadata.Leaves,
		commitment: metadata.RootCommitment,
	}
	e.syncTargetMx.Unlock()

	return nil
}

func (e *TokenExecutionEngine) addBatchToHypergraph(batchKey [][]byte, batchValue [][]byte) {
	var wg sync.WaitGroup
	throttle := make(chan struct{}, runtime.NumCPU())
	batchCompressed := make([]hypergraph.Vertex, len(batchKey))
	batchTrees := make([]*qcrypto.VectorCommitmentTree, len(batchKey))
	txn, err := e.hypergraphStore.NewTransaction(false)
	if err != nil {
		e.logger.Panic("could not create transaction", zap.Error(err))
	}

	for i, chunk := range batchValue {
		throttle <- struct{}{}
		wg.Add(1)
		go func(chunk []byte, i int) {
			defer func() { <-throttle }()
			defer wg.Done()
			id := append(
				append([]byte{}, application.TOKEN_ADDRESS...),
				batchKey[i]...,
			)

			vertTree, err := e.hypergraphStore.LoadVertexTree(
				id,
			)
			if err == nil {
				batchCompressed[i] = hypergraph.NewVertex(
					[32]byte(application.TOKEN_ADDRESS),
					[32]byte(batchKey[i]),
					vertTree.Commit(false),
					vertTree.GetSize(),
				)
				return
			}

			e.logger.Debug(
				"encrypting coin",
				zap.String("address", hex.EncodeToString(batchKey[i])),
			)
			data := e.mpcithVerEnc.EncryptAndCompress(
				chunk,
				config.GetGenesis().Beacon,
			)
			compressed := []hypergraph.Encrypted{}
			for _, d := range data {
				compressed = append(compressed, d)
			}
			e.logger.Debug(
				"encrypted coin",
				zap.String("address", hex.EncodeToString(batchKey[i])),
			)

			vertTree = hypergraph.EncryptedToVertexTree(compressed)
			batchTrees[i] = vertTree
			batchCompressed[i] = hypergraph.NewVertex(
				[32]byte(application.TOKEN_ADDRESS),
				[32]byte(batchKey[i]),
				vertTree.Commit(false),
				vertTree.GetSize(),
			)

		}(chunk, i)
	}
	wg.Wait()

	for i, vertTree := range batchTrees {
		if vertTree == nil {
			continue
		}

		id := append(
			append([]byte{}, application.TOKEN_ADDRESS...),
			batchKey[i]...,
		)

		err = e.hypergraphStore.SaveVertexTree(txn, id, vertTree)
		if err != nil {
			txn.Abort()
			e.logger.Panic("could not save vertex tree", zap.Error(err))
		}
	}

	for i := range batchKey {
		if err := e.hypergraph.AddVertex(
			txn,
			batchCompressed[i],
		); err != nil {
			e.logger.Panic("could not add vertex", zap.Error(err))
		}
	}

	if err := txn.Commit(); err != nil {
		txn.Abort()
		e.logger.Panic("could not commit transaction", zap.Error(err))
	}
}

func (e *TokenExecutionEngine) publishSyncInfo() {
	if !e.syncController.TryEstablishSyncSession() {
		return
	}
	defer e.syncController.EndSyncSession()
	for _, vertices := range e.hypergraph.GetVertexAdds() {
		leaves, _ := vertices.GetTree().GetMetadata()
		rootCommitment := vertices.GetTree().Commit(false)
		metadataFilter := slices.Concat(
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00},
			e.intrinsicFilter,
		)
		e.publishMessage(metadataFilter, &protobufs.HypersyncMetadata{
			Leaves:         uint64(leaves),
			RootCommitment: rootCommitment,
		})
		break
	}
}

func (e *TokenExecutionEngine) hyperSync(totalCoins int) {
	if !e.syncController.TryEstablishSyncSession() {
		return
	}
	defer e.syncController.EndSyncSession()

	peers := []syncInfo{}
	e.syncTargetMx.Lock()
	for peerId, target := range e.syncTargetMap {
		if !bytes.Equal([]byte(peerId), e.pubSub.GetPeerID()) {
			peers = append(peers, target)
		}
	}
	e.syncTargetMx.Unlock()

	sort.Slice(peers, func(i, j int) bool {
		return peers[i].leaves < peers[j].leaves
	})

	sets := e.hypergraph.GetVertexAdds()
	for key, set := range sets {
		var peerId []byte = nil
		for peerId == nil {
			if len(peers) == 0 {
				e.logger.Info("no available peers for sync")
				return
			}

			metadataInfo := peers[0]

			if bytes.Equal(metadataInfo.commitment, set.GetTree().Commit(false)) {
				peers = peers[1:]
				continue
			}

			peerId = metadataInfo.peerId

			info, ok := e.syncController.SyncStatus[peer.ID(peerId).String()]
			if ok {
				if info.Unreachable || gotime.Since(info.LastSynced) < 30*gotime.Minute {
					peers = peers[1:]
					peerId = nil
					continue
				}
			}
		}

		e.logger.Info(
			"syncing hypergraph with peer",
			zap.String("peer", peer.ID(peerId).String()),
		)
		syncTimeout := e.engineConfig.SyncTimeout
		dialCtx, cancelDial := context.WithTimeout(e.ctx, syncTimeout)
		defer cancelDial()
		cc, err := e.pubSub.GetDirectChannel(dialCtx, peerId, "hypersync")
		if err != nil {
			e.logger.Info(
				"could not establish direct channel",
				zap.Error(err),
			)
			e.syncController.SyncStatus[peer.ID(peerId).String()] = &rpc.SyncInfo{
				Unreachable: true,
				LastSynced:  gotime.Now(),
			}
			return
		}
		defer func() {
			if err := cc.Close(); err != nil {
				e.logger.Error("error while closing connection", zap.Error(err))
			}
		}()

		client := protobufs.NewHypergraphComparisonServiceClient(cc)

		stream, err := client.HyperStream(e.ctx)
		if err != nil {
			e.logger.Error("could not open stream", zap.Error(err))
			e.syncController.SyncStatus[peer.ID(peerId).String()] = &rpc.SyncInfo{
				Unreachable: true,
				LastSynced:  gotime.Now(),
			}
			return
		}

		err = rpc.SyncTreeBidirectionally(
			stream,
			e.logger,
			append(append([]byte{}, key.L1[:]...), key.L2[:]...),
			protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
			e.hypergraphStore,
			e.hypergraph,
			set,
			e.syncController,
			totalCoins,
			false,
		)

		metadataFilter := slices.Concat(
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00},
			e.intrinsicFilter,
		)
		rootCommitment := set.GetTree().Commit(false)
		leaves, _ := set.GetTree().GetMetadata()
		e.publishMessage(metadataFilter, &protobufs.HypersyncMetadata{
			Leaves:         uint64(leaves),
			RootCommitment: rootCommitment,
		})

		if err != nil {
			e.logger.Error("error while synchronizing", zap.Error(err))
			if !strings.Contains(err.Error(), "unavailable") {
				e.syncController.SyncStatus[peer.ID(peerId).String()] = &rpc.SyncInfo{
					Unreachable: false,
					LastSynced:  gotime.Now(),
				}
			}
		}
		break
	}

	roots := e.hypergraph.Commit()
	e.logger.Info(
		"hypergraph root commit",
		zap.String("root", hex.EncodeToString(roots[0])),
	)
}

func (e *TokenExecutionEngine) rebuildMissingSetForHypergraph(set [][]byte) {
	e.logger.Info("rebuilding missing set entries")
	var batchKey, batchValue [][]byte
	processed := 0
	totalRange := len(set)
	for _, address := range set {
		processed++
		key := slices.Clone(address)
		batchKey = append(batchKey, key)

		frameNumber, coin, err := e.coinStore.GetCoinByAddress(nil, address)
		if err != nil {
			e.logger.Panic("could not get coin by address", zap.Error(err))
		}

		value := []byte{}
		value = binary.BigEndian.AppendUint64(value, frameNumber)
		value = append(value, coin.Amount...)
		// implicit
		value = append(value, 0x00)
		value = append(value, coin.Owner.GetImplicitAccount().GetAddress()...)
		// domain len
		value = append(value, 0x00)
		value = append(value, coin.Intersection...)
		batchValue = append(batchValue, value)

		if len(batchKey) == runtime.NumCPU() {
			e.addBatchToHypergraph(batchKey, batchValue)
			e.logger.Info(
				"processed batch",
				zap.Float32("percentage", float32(processed)/float32(totalRange)),
			)
			batchKey = [][]byte{}
			batchValue = [][]byte{}
		}
	}

	if len(batchKey) != 0 {
		e.addBatchToHypergraph(batchKey, batchValue)
	}

	txn, err := e.clockStore.NewTransaction(false)
	if err != nil {
		e.logger.Panic("could not create transaction", zap.Error(err))
	}

	e.logger.Info("committing hypergraph")

	roots := e.hypergraph.Commit()

	e.logger.Info(
		"committed hypergraph state",
		zap.String("root", fmt.Sprintf("%x", roots[0])),
	)

	if err = txn.Commit(); err != nil {
		txn.Abort()
		e.logger.Panic("could not commit transaction", zap.Error(err))
	}
	e.hypergraphStore.MarkHypergraphAsComplete()
}

func (e *TokenExecutionEngine) rebuildHypergraph(totalRange int) {
	e.logger.Info("rebuilding hypergraph")
	e.hypergraph = hypergraph.NewHypergraph(e.hypergraphStore)
	if e.engineConfig.RebuildStart == "" {
		e.engineConfig.RebuildStart = "0000000000000000000000000000000000000000000000000000000000000000"
	}
	if e.engineConfig.RebuildEnd == "" {
		e.engineConfig.RebuildEnd = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	}
	start, err := hex.DecodeString(e.engineConfig.RebuildStart)
	if err != nil {
		e.logger.Panic("could not decode start", zap.Error(err))
	}
	end, err := hex.DecodeString(e.engineConfig.RebuildEnd)
	if err != nil {
		e.logger.Panic("could not decode end", zap.Error(err))
	}
	iter, err := e.coinStore.RangeCoins(
		start,
		end,
	)
	if err != nil {
		e.logger.Panic("could not get range coins", zap.Error(err))
	}
	var batchKey, batchValue [][]byte
	processed := 0
	for iter.First(); iter.Valid(); iter.Next() {
		processed++
		key := make([]byte, len(iter.Key()[2:]))
		copy(key, iter.Key()[2:])
		batchKey = append(batchKey, key)

		coin := &protobufs.Coin{}
		err := proto.Unmarshal(iter.Value()[8:], coin)
		if err != nil {
			e.logger.Panic("could not unmarshal coin", zap.Error(err))
		}

		value := []byte{}
		value = append(value, iter.Value()[:8]...)
		value = append(value, coin.Amount...)
		// implicit
		value = append(value, 0x00)
		value = append(value, coin.Owner.GetImplicitAccount().GetAddress()...)
		// domain len
		value = append(value, 0x00)
		value = append(value, coin.Intersection...)
		batchValue = append(batchValue, value)

		if len(batchKey) == runtime.NumCPU() {
			e.addBatchToHypergraph(batchKey, batchValue)
			e.logger.Info(
				"processed batch",
				zap.Float32("percentage", float32(processed)/float32(totalRange)),
			)
			batchKey = [][]byte{}
			batchValue = [][]byte{}
		}
	}
	iter.Close()

	if len(batchKey) != 0 {
		e.addBatchToHypergraph(batchKey, batchValue)
	}

	txn, err := e.clockStore.NewTransaction(false)
	if err != nil {
		e.logger.Panic("could not create transaction", zap.Error(err))
	}

	e.logger.Info("committing hypergraph")

	roots := e.hypergraph.Commit()

	e.logger.Info(
		"committed hypergraph state",
		zap.String("root", fmt.Sprintf("%x", roots[0])),
	)

	if err = txn.Commit(); err != nil {
		txn.Abort()
		e.logger.Panic("could not commit transaction", zap.Error(err))
	}
	e.hypergraphStore.MarkHypergraphAsComplete()
}

// GetName implements ExecutionEngine
func (*TokenExecutionEngine) GetName() string {
	return "Token"
}

// GetSupportedApplications implements ExecutionEngine
func (
	*TokenExecutionEngine,
) GetSupportedApplications() []*protobufs.Application {
	return []*protobufs.Application{
		{
			Address:          application.TOKEN_ADDRESS,
			ExecutionContext: protobufs.ExecutionContext_EXECUTION_CONTEXT_INTRINSIC,
		},
	}
}

// Start implements ExecutionEngine
func (e *TokenExecutionEngine) Start() <-chan error {
	errChan := make(chan error)

	go func() {
		err := <-e.clock.Start()
		if err != nil {
			e.logger.Panic("could not start clock", zap.Error(err))
		}

		err = <-e.clock.RegisterExecutor(e, 0)
		if err != nil {
			e.logger.Panic("could not register executor", zap.Error(err))
		}

		errChan <- nil
	}()

	return errChan
}

// Stop implements ExecutionEngine
func (e *TokenExecutionEngine) Stop(force bool) <-chan error {
	wg := sync.WaitGroup{}
	wg.Add(len(e.grpcServers))
	for _, server := range e.grpcServers {
		go func(server *grpc.Server) {
			defer wg.Done()
			server.GracefulStop()
		}(server)
	}
	wg.Wait()
	e.cancel()
	e.wg.Wait()

	errChan := make(chan error)

	go func() {
		errChan <- <-e.clock.Stop(force)
	}()

	return errChan
}

// ProcessMessage implements ExecutionEngine
func (e *TokenExecutionEngine) ProcessMessage(
	address []byte,
	message *protobufs.Message,
) ([]*protobufs.Message, error) {
	if bytes.Equal(address, e.GetSupportedApplications()[0].Address) {
		a := &anypb.Any{}
		if err := proto.Unmarshal(message.Payload, a); err != nil {
			return nil, errors.Wrap(err, "process message")
		}

		e.logger.Debug(
			"processing execution message",
			zap.String("type", a.TypeUrl),
		)

		switch a.TypeUrl {
		case protobufs.TokenRequestType:
			if e.clock.FrameProverTriesContains(e.provingKeyAddress) {
				payload, err := proto.Marshal(a)
				if err != nil {
					return nil, errors.Wrap(err, "process message")
				}

				h, err := poseidon.HashBytes(payload)
				if err != nil {
					return nil, errors.Wrap(err, "process message")
				}

				msg := &protobufs.Message{
					Hash:    h.Bytes(),
					Address: application.TOKEN_ADDRESS,
					Payload: payload,
				}
				return []*protobufs.Message{
					msg,
				}, nil
			}
		}
	}

	return nil, nil
}

func (e *TokenExecutionEngine) ProcessFrame(
	txn store.Transaction,
	frame *protobufs.ClockFrame,
	triesAtFrame []*tries.RollingFrecencyCritbitTrie,
) ([]*tries.RollingFrecencyCritbitTrie, error) {
	f, err := e.coinStore.GetLatestFrameProcessed()
	if err != nil || f == frame.FrameNumber {
		return nil, errors.Wrap(err, "process frame")
	}

	e.activeClockFrame = frame
	e.logger.Info(
		"evaluating next frame",
		zap.Uint64(
			"frame_number",
			frame.FrameNumber,
		),
		zap.Duration("frame_age", frametime.Since(frame)),
	)
	app, err := application.MaterializeApplicationFromFrame(
		e.provingKey,
		frame,
		triesAtFrame,
		e.coinStore,
		e.clockStore,
		e.pubSub,
		e.logger,
		e.frameProver,
	)
	if err != nil {
		e.logger.Error(
			"error while materializing application from frame",
			zap.Error(err),
		)
		return nil, errors.Wrap(err, "process frame")
	}

	e.logger.Debug(
		"app outputs",
		zap.Int("outputs", len(app.TokenOutputs.Outputs)),
	)

	proverTrieJoinRequests := [][]byte{}
	proverTrieLeaveRequests := [][]byte{}
	mapSnapshot := ToSerializedMap(e.peerSeniority)
	activeMap := NewFromMap(mapSnapshot)

	outputAddresses := make([][]byte, len(app.TokenOutputs.Outputs))
	outputAddressErrors := make([]error, len(app.TokenOutputs.Outputs))
	wg := sync.WaitGroup{}
	throttle := make(chan struct{}, qruntime.WorkerCount(0, false))
	for i, output := range app.TokenOutputs.Outputs {
		throttle <- struct{}{}
		wg.Add(1)
		go func(i int, output *protobufs.TokenOutput) {
			defer func() { <-throttle }()
			defer wg.Done()
			switch o := output.Output.(type) {
			case *protobufs.TokenOutput_Coin:
				outputAddresses[i], outputAddressErrors[i] = GetAddressOfCoin(o.Coin, frame.FrameNumber, uint64(i))
			case *protobufs.TokenOutput_Proof:
				outputAddresses[i], outputAddressErrors[i] = GetAddressOfPreCoinProof(o.Proof)
			case *protobufs.TokenOutput_DeletedProof:
				outputAddresses[i], outputAddressErrors[i] = GetAddressOfPreCoinProof(o.DeletedProof)
			}
		}(i, output)
	}
	wg.Wait()

	hg, err := e.hypergraphStore.LoadHypergraph()
	if err != nil {
		txn.Abort()
		e.logger.Panic("could not load hypergraph", zap.Error(err))
	}

	for i, output := range app.TokenOutputs.Outputs {
		switch o := output.Output.(type) {
		case *protobufs.TokenOutput_Coin:
			address, err := outputAddresses[i], outputAddressErrors[i]
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			err = e.coinStore.PutCoin(
				txn,
				frame.FrameNumber,
				address,
				o.Coin,
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}

			value := []byte{}
			value = append(value, make([]byte, 8)...)
			value = append(value, o.Coin.Amount...)
			// implicit
			value = append(value, 0x00)
			value = append(
				value,
				o.Coin.Owner.GetImplicitAccount().GetAddress()...,
			)
			// domain len
			value = append(value, 0x00)
			value = append(value, o.Coin.Intersection...)

			proofs := e.mpcithVerEnc.EncryptAndCompress(
				value,
				config.GetGenesis().Beacon,
			)
			compressed := []hypergraph.Encrypted{}
			for _, d := range proofs {
				compressed = append(compressed, d)
			}

			vertTree, commitment, err := e.hypergraphStore.CommitAndSaveVertexData(
				txn,
				append(append([]byte{}, application.TOKEN_ADDRESS...), address...),
				compressed,
			)
			if err != nil {
				txn.Abort()
				e.logger.Panic("could not commit and save vertex data", zap.Error(err))
			}

			if err := hg.AddVertex(
				txn,
				hypergraph.NewVertex(
					[32]byte(application.TOKEN_ADDRESS),
					[32]byte(address),
					commitment,
					vertTree.GetSize(),
				),
			); err != nil {
				txn.Abort()
				e.logger.Panic("could not add vertex", zap.Error(err))
			}
		case *protobufs.TokenOutput_DeletedCoin:
			_, coin, err := e.coinStore.GetCoinByAddress(nil, o.DeletedCoin.Address)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			err = e.coinStore.DeleteCoin(
				txn,
				o.DeletedCoin.Address,
				coin,
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}

			vertId := append(
				append([]byte{}, application.TOKEN_ADDRESS...),
				o.DeletedCoin.Address...,
			)
			vertTree, err := e.hypergraphStore.LoadVertexTree(vertId)
			if err != nil {
				value := []byte{}
				value = append(value, make([]byte, 8)...)
				value = append(value, coin.Amount...)
				// implicit
				value = append(value, 0x00)
				value = append(
					value,
					coin.Owner.GetImplicitAccount().GetAddress()...,
				)
				// domain len
				value = append(value, 0x00)
				value = append(value, coin.Intersection...)

				proofs := e.mpcithVerEnc.EncryptAndCompress(
					value,
					config.GetGenesis().Beacon,
				)
				compressed := []hypergraph.Encrypted{}
				for _, d := range proofs {
					compressed = append(compressed, d)
				}

				vertTree, _, err = e.hypergraphStore.CommitAndSaveVertexData(
					txn,
					vertId,
					compressed,
				)
				if err != nil {
					txn.Abort()
					e.logger.Panic("could not commit and save vertex data", zap.Error(err))
				}
			}

			if err := hg.RemoveVertex(
				txn,
				hypergraph.NewVertex(
					[32]byte(application.TOKEN_ADDRESS),
					[32]byte(o.DeletedCoin.Address),
					vertTree.Commit(false),
					vertTree.GetSize(),
				),
			); err != nil {
				txn.Abort()
				e.logger.Panic("could not remove vertex", zap.Error(err))
			}
		case *protobufs.TokenOutput_Proof:
			address, err := outputAddresses[i], outputAddressErrors[i]
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			err = e.coinStore.PutPreCoinProof(
				txn,
				frame.FrameNumber,
				address,
				o.Proof,
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}

			if len(o.Proof.Amount) == 32 &&
				!bytes.Equal(o.Proof.Amount, make([]byte, 32)) &&
				o.Proof.Commitment != nil {
				addr := string(o.Proof.Owner.GetImplicitAccount().Address)
				for _, t := range app.Tries {
					if t.Contains([]byte(addr)) {
						t.Add([]byte(addr), frame.FrameNumber)
						break
					}
				}
				if _, ok := (*activeMap)[addr]; !ok {
					(*activeMap)[addr] = PeerSeniorityItem{
						seniority: 10,
						addr:      addr,
					}
				} else {
					(*activeMap)[addr] = PeerSeniorityItem{
						seniority: (*activeMap)[addr].seniority + 10,
						addr:      addr,
					}
				}
			}
		case *protobufs.TokenOutput_DeletedProof:
			address, err := outputAddresses[i], outputAddressErrors[i]
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			err = e.coinStore.DeletePreCoinProof(
				txn,
				address,
				o.DeletedProof,
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
		case *protobufs.TokenOutput_Announce:
			peerIds := []string{}
			for _, sig := range o.Announce.PublicKeySignaturesEd448 {
				peerId, err := e.getPeerIdFromSignature(sig)
				if err != nil {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				peerIds = append(peerIds, peerId.String())
			}

			logger := e.logger.Debug
			if peerIds[0] == peer.ID(e.pubSub.GetPeerID()).String() {
				logger = e.logger.Info
			}
			mergeable := true
			for i, peerId := range peerIds {
				addr, err := e.getAddressFromSignature(
					o.Announce.PublicKeySignaturesEd448[i],
				)
				if err != nil {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				sen, ok := (*activeMap)[string(addr)]
				if !ok {
					logger(
						"peer announced with no seniority",
						zap.String("peer_id", peerId),
					)
					continue
				}

				peer := new(big.Int).SetUint64(sen.seniority)
				if peer.Cmp(GetAggregatedSeniority([]string{peerId})) != 0 {
					logger(
						"peer announced but has already been announced",
						zap.String("peer_id", peerId),
						zap.Uint64("seniority", sen.seniority),
					)
					mergeable = false
					break
				}
			}

			if mergeable {
				addr, err := e.getAddressFromSignature(
					o.Announce.PublicKeySignaturesEd448[0],
				)
				if err != nil {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				additional := uint64(0)
				_, prfs, err := e.coinStore.GetPreCoinProofsForOwner(addr)
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				aggregated := GetAggregatedSeniority(peerIds).Uint64()
				logger("peer has merge, aggregated seniority", zap.Uint64("seniority", aggregated))

				for _, pr := range prfs {
					if pr.IndexProof == nil && pr.Difficulty == 0 && pr.Commitment == nil {
						// approximate average per interval:
						add := new(big.Int).SetBytes(pr.Amount)
						add.Quo(add, big.NewInt(58800000))
						if add.Cmp(big.NewInt(4000000)) > 0 {
							add = big.NewInt(4000000)
						}
						additional = add.Uint64()
						logger("1.4.19-21 seniority", zap.Uint64("seniority", additional))
					}
				}

				total := aggregated + additional

				logger("combined aggregate and 1.4.19-21 seniority", zap.Uint64("seniority", total))

				(*activeMap)[string(addr)] = PeerSeniorityItem{
					seniority: aggregated + additional,
					addr:      string(addr),
				}

				for _, sig := range o.Announce.PublicKeySignaturesEd448[1:] {
					addr, err := e.getAddressFromSignature(
						sig,
					)
					if err != nil {
						txn.Abort()
						return nil, errors.Wrap(err, "process frame")
					}

					(*activeMap)[string(addr)] = PeerSeniorityItem{
						seniority: 0,
						addr:      string(addr),
					}
				}
			} else {
				addr, err := e.getAddressFromSignature(
					o.Announce.PublicKeySignaturesEd448[0],
				)
				if err != nil {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				sen, ok := (*activeMap)[string(addr)]
				if !ok {
					logger(
						"peer announced with no seniority",
						zap.String("peer_id", peerIds[0]),
					)
					continue
				}

				peer := new(big.Int).SetUint64(sen.seniority)
				if peer.Cmp(GetAggregatedSeniority([]string{peerIds[0]})) != 0 {
					logger(
						"peer announced but has already been announced",
						zap.String("peer_id", peerIds[0]),
						zap.Uint64("seniority", sen.seniority),
					)
					continue
				}

				additional := uint64(0)
				_, prfs, err := e.coinStore.GetPreCoinProofsForOwner(addr)
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				aggregated := GetAggregatedSeniority(peerIds).Uint64()
				logger("peer does not have merge, pre-1.4.19 seniority", zap.Uint64("seniority", aggregated))

				for _, pr := range prfs {
					if pr.IndexProof == nil && pr.Difficulty == 0 && pr.Commitment == nil {
						// approximate average per interval:
						add := new(big.Int).SetBytes(pr.Amount)
						add.Quo(add, big.NewInt(58800000))
						if add.Cmp(big.NewInt(4000000)) > 0 {
							add = big.NewInt(4000000)
						}
						additional = add.Uint64()
						logger("1.4.19-21 seniority", zap.Uint64("seniority", additional))
					}
				}
				total := GetAggregatedSeniority([]string{peerIds[0]}).Uint64() + additional
				logger("combined aggregate and 1.4.19-21 seniority", zap.Uint64("seniority", total))
				(*activeMap)[string(addr)] = PeerSeniorityItem{
					seniority: total,
					addr:      string(addr),
				}
			}
		case *protobufs.TokenOutput_Join:
			addr, err := e.getAddressFromSignature(o.Join.PublicKeySignatureEd448)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}

			if _, ok := (*activeMap)[string(addr)]; !ok {
				(*activeMap)[string(addr)] = PeerSeniorityItem{
					seniority: 20,
					addr:      string(addr),
				}
			} else {
				(*activeMap)[string(addr)] = PeerSeniorityItem{
					seniority: (*activeMap)[string(addr)].seniority + 20,
					addr:      string(addr),
				}
			}
			proverTrieJoinRequests = append(proverTrieJoinRequests, addr)
		case *protobufs.TokenOutput_Leave:
			addr, err := e.getAddressFromSignature(o.Leave.PublicKeySignatureEd448)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			proverTrieLeaveRequests = append(proverTrieLeaveRequests, addr)
		case *protobufs.TokenOutput_Pause:
			_, err := e.getAddressFromSignature(o.Pause.PublicKeySignatureEd448)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
		case *protobufs.TokenOutput_Resume:
			_, err := e.getAddressFromSignature(o.Resume.PublicKeySignatureEd448)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
		case *protobufs.TokenOutput_Penalty:
			addr := string(o.Penalty.Account.GetImplicitAccount().Address)
			if _, ok := (*activeMap)[addr]; !ok {
				(*activeMap)[addr] = PeerSeniorityItem{
					seniority: 0,
					addr:      addr,
				}
				proverTrieLeaveRequests = append(proverTrieLeaveRequests, []byte(addr))
			} else {
				if (*activeMap)[addr].seniority > o.Penalty.Quantity {
					for _, t := range app.Tries {
						if t.Contains([]byte(addr)) {
							v := t.Get([]byte(addr))
							latest := v.LatestFrame
							if frame.FrameNumber-latest > 100 {
								proverTrieLeaveRequests = append(proverTrieLeaveRequests, []byte(addr))
							}
							break
						}
					}
					(*activeMap)[addr] = PeerSeniorityItem{
						seniority: (*activeMap)[addr].seniority - o.Penalty.Quantity,
						addr:      addr,
					}
				} else {
					(*activeMap)[addr] = PeerSeniorityItem{
						seniority: 0,
						addr:      addr,
					}
					proverTrieLeaveRequests = append(proverTrieLeaveRequests, []byte(addr))
				}
			}
		}
	}

	joinAddrs := tries.NewMinHeap[PeerSeniorityItem]()
	leaveAddrs := tries.NewMinHeap[PeerSeniorityItem]()
	for _, addr := range proverTrieJoinRequests {
		if _, ok := (*activeMap)[string(addr)]; !ok {
			joinAddrs.Push(PeerSeniorityItem{
				addr:      string(addr),
				seniority: 0,
			})
		} else {
			joinAddrs.Push((*activeMap)[string(addr)])
		}
	}
	for _, addr := range proverTrieLeaveRequests {
		if _, ok := (*activeMap)[string(addr)]; !ok {
			leaveAddrs.Push(PeerSeniorityItem{
				addr:      string(addr),
				seniority: 0,
			})
		} else {
			leaveAddrs.Push((*activeMap)[string(addr)])
		}
	}

	joinReqs := make([]PeerSeniorityItem, len(joinAddrs.All()))
	copy(joinReqs, joinAddrs.All())
	slices.Reverse(joinReqs)
	leaveReqs := make([]PeerSeniorityItem, len(leaveAddrs.All()))
	copy(leaveReqs, leaveAddrs.All())
	slices.Reverse(leaveReqs)

	ProcessJoinsAndLeaves(joinReqs, leaveReqs, app, e.peerSeniority, frame)

	if frame.FrameNumber == application.PROOF_FRAME_SENIORITY_REPAIR {
		e.performSeniorityMapRepair(activeMap, frame)
	}

	err = e.clockStore.PutPeerSeniorityMap(
		txn,
		e.intrinsicFilter,
		ToSerializedMap(activeMap),
	)
	if err != nil {
		txn.Abort()
		return nil, errors.Wrap(err, "process frame")
	}

	err = e.coinStore.SetLatestFrameProcessed(txn, frame.FrameNumber)
	if err != nil {
		txn.Abort()
		return nil, errors.Wrap(err, "process frame")
	}

	e.peerSeniority = activeMap

	if frame.FrameNumber == application.PROOF_FRAME_RING_RESET ||
		frame.FrameNumber == application.PROOF_FRAME_RING_RESET_2 {
		e.logger.Info("performing ring reset")
		seniorityMap, err := RebuildPeerSeniority(e.pubSub.GetNetwork())
		if err != nil {
			return nil, errors.Wrap(err, "process frame")
		}
		e.peerSeniority = NewFromMap(seniorityMap)

		app.Tries = []*tries.RollingFrecencyCritbitTrie{
			app.Tries[0],
		}

		err = e.clockStore.PutPeerSeniorityMap(
			txn,
			e.intrinsicFilter,
			ToSerializedMap(e.peerSeniority),
		)
		if err != nil {
			txn.Abort()
			return nil, errors.Wrap(err, "process frame")
		}
	}

	e.logger.Info("committing hypergraph")

	roots := hg.Commit()

	e.logger.Info(
		"commited hypergraph",
		zap.String("root", fmt.Sprintf("%x", roots[0])),
	)

	e.hypergraph = hg

	return app.Tries, nil
}

func (e *TokenExecutionEngine) performSeniorityMapRepair(
	activeMap *PeerSeniority,
	frame *protobufs.ClockFrame,
) {
	if e.pubSub.GetNetwork() != 0 {
		return
	}

	e.logger.Info(
		"repairing seniority map from historic data, this may take a while",
	)

	RebuildPeerSeniority(0)
	for f := uint64(application.PROOF_FRAME_RING_RESET_2); f < frame.FrameNumber; f++ {
		frame, _, err := e.clockStore.GetDataClockFrame(e.intrinsicFilter, f, false)
		if err != nil {
			break
		}

		reqs, _, _ := application.GetOutputsFromClockFrame(frame)

		for _, req := range reqs.Requests {
			switch t := req.Request.(type) {
			case *protobufs.TokenRequest_Join:
				if t.Join.Announce != nil && len(
					t.Join.Announce.PublicKeySignaturesEd448,
				) > 0 {
					addr, err := e.getAddressFromSignature(
						t.Join.Announce.PublicKeySignaturesEd448[0],
					)
					if err != nil {
						continue
					}

					peerId, err := e.getPeerIdFromSignature(
						t.Join.Announce.PublicKeySignaturesEd448[0],
					)
					if err != nil {
						continue
					}

					additional := uint64(0)

					_, prfs, err := e.coinStore.GetPreCoinProofsForOwner(addr)
					for _, pr := range prfs {
						if pr.IndexProof == nil && pr.Difficulty == 0 && pr.Commitment == nil {
							// approximate average per interval:
							add := new(big.Int).SetBytes(pr.Amount)
							add.Quo(add, big.NewInt(58800000))
							if add.Cmp(big.NewInt(4000000)) > 0 {
								add = big.NewInt(4000000)
							}
							additional = add.Uint64()
						}
					}

					if err != nil && !errors.Is(err, store.ErrNotFound) {
						continue
					}
					peerIds := []string{peerId.String()}
					if len(t.Join.Announce.PublicKeySignaturesEd448) > 1 {
						for _, announce := range t.Join.Announce.PublicKeySignaturesEd448[1:] {
							peerId, err := e.getPeerIdFromSignature(
								announce,
							)
							if err != nil {
								continue
							}

							peerIds = append(peerIds, peerId.String())
						}
					}

					aggregated := GetAggregatedSeniority(peerIds).Uint64()
					total := aggregated + additional
					sen, ok := (*activeMap)[string(addr)]

					if !ok || sen.seniority < total {
						(*activeMap)[string(addr)] = PeerSeniorityItem{
							seniority: total,
							addr:      string(addr),
						}
					}
				}
			}
		}
	}
}

func ProcessJoinsAndLeaves(
	joinReqs []PeerSeniorityItem,
	leaveReqs []PeerSeniorityItem,
	app *application.TokenApplication,
	seniority *PeerSeniority,
	frame *protobufs.ClockFrame,
) {
	for _, addr := range joinReqs {
		rings := len(app.Tries)
		last := app.Tries[rings-1]
		set := last.FindNearestAndApproximateNeighbors(make([]byte, 32))
		if len(set) == 2048 || rings == 1 {
			app.Tries = append(
				app.Tries,
				&tries.RollingFrecencyCritbitTrie{},
			)
			last = app.Tries[rings]
		}
		if !last.Contains([]byte(addr.addr)) {
			last.Add([]byte(addr.addr), frame.FrameNumber)
		}
	}
	for _, addr := range leaveReqs {
		for _, t := range app.Tries[1:] {
			if t.Contains([]byte(addr.addr)) {
				t.Remove([]byte(addr.addr))
				break
			}
		}
	}

	if frame.FrameNumber > application.PROOF_FRAME_RING_RESET {
		if len(app.Tries) >= 2 {
			for _, t := range app.Tries[1:] {
				nodes := t.FindNearestAndApproximateNeighbors(make([]byte, 32))
				for _, n := range nodes {
					if frame.FrameNumber >= application.PROOF_FRAME_COMBINE_CUTOFF {
						if n.LatestFrame < frame.FrameNumber-100 {
							t.Remove(n.Key)
						}
					} else {
						if n.LatestFrame < frame.FrameNumber-1000 {
							t.Remove(n.Key)
						}
					}
				}
			}
		}
	}

	if len(app.Tries) > 2 {
		for i, t := range app.Tries[2:] {
			setSize := len(app.Tries[1+i].FindNearestAndApproximateNeighbors(make([]byte, 32)))
			if setSize < 2048 {
				nextSet := t.FindNearestAndApproximateNeighbors(make([]byte, 32))
				eligibilityOrder := tries.NewMinHeap[PeerSeniorityItem]()
				for _, n := range nextSet {
					eligibilityOrder.Push((*seniority)[string(n.Key)])
				}
				process := eligibilityOrder.All()
				slices.Reverse(process)
				for s := 0; s < len(process) && s+setSize < 2048; s++ {
					app.Tries[1+i].Add([]byte(process[s].addr), frame.FrameNumber)
					app.Tries[2+i].Remove([]byte(process[s].addr))
				}
			}
		}
	}
}

func (e *TokenExecutionEngine) publishMessage(
	filter []byte,
	message proto.Message,
) error {
	a := &anypb.Any{}
	if err := a.MarshalFrom(message); err != nil {
		return errors.Wrap(err, "publish message")
	}

	a.TypeUrl = strings.Replace(
		a.TypeUrl,
		"type.googleapis.com",
		"types.quilibrium.com",
		1,
	)

	payload, err := proto.Marshal(a)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	h, err := poseidon.HashBytes(payload)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	msg := &protobufs.Message{
		Hash:    h.Bytes(),
		Address: application.TOKEN_ADDRESS,
		Payload: payload,
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}
	return e.pubSub.PublishToBitmask(filter, data)
}

func (e *TokenExecutionEngine) VerifyExecution(
	frame *protobufs.ClockFrame,
	triesAtFrame []*tries.RollingFrecencyCritbitTrie,
) error {
	if len(frame.AggregateProofs) > 0 {
		for _, proofs := range frame.AggregateProofs {
			for _, inclusion := range proofs.InclusionCommitments {
				if inclusion.TypeUrl == protobufs.IntrinsicExecutionOutputType {
					transition, _, err := application.GetOutputsFromClockFrame(frame)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					parent, tries, err := e.clockStore.GetDataClockFrame(
						p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3),
						frame.FrameNumber-1,
						false,
					)
					if err != nil && !errors.Is(err, store.ErrNotFound) {
						return errors.Wrap(err, "verify execution")
					}

					if parent == nil && frame.FrameNumber != 0 {
						return errors.Wrap(
							errors.New("missing parent frame"),
							"verify execution",
						)
					}

					a, err := application.MaterializeApplicationFromFrame(
						e.provingKey,
						parent,
						tries,
						e.coinStore,
						e.clockStore,
						e.pubSub,
						e.logger,
						e.frameProver,
					)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					a, _, _, err = a.ApplyTransitions(
						frame.FrameNumber,
						transition,
						false,
					)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					a2, err := application.MaterializeApplicationFromFrame(
						e.provingKey,
						frame,
						triesAtFrame,
						e.coinStore,
						e.clockStore,
						e.pubSub,
						e.logger,
						e.frameProver,
					)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					if len(a.TokenOutputs.Outputs) != len(a2.TokenOutputs.Outputs) {
						return errors.Wrap(
							errors.New("mismatched outputs"),
							"verify execution",
						)
					}

					for i := range a.TokenOutputs.Outputs {
						o1 := a.TokenOutputs.Outputs[i]
						o2 := a2.TokenOutputs.Outputs[i]
						if !proto.Equal(o1, o2) {
							return errors.Wrap(
								errors.New("mismatched messages"),
								"verify execution",
							)
						}
					}

					return nil
				}
			}
		}
	}

	return nil
}

func (e *TokenExecutionEngine) GetPeerInfo() *protobufs.PeerInfoResponse {
	return e.clock.GetPeerInfo()
}

func (e *TokenExecutionEngine) GetFrame() *protobufs.ClockFrame {
	return e.clock.GetFrame()
}

func (e *TokenExecutionEngine) GetSeniority() *big.Int {
	altAddr, err := poseidon.HashBytes(e.pubSub.GetPeerID())
	if err != nil {
		return nil
	}

	sen, ok := (*e.peerSeniority)[string(
		altAddr.FillBytes(make([]byte, 32)),
	)]

	if !ok {
		return big.NewInt(0)
	}

	return new(big.Int).SetUint64(sen.Priority())
}

func GetAggregatedSeniority(peerIds []string) *big.Int {
	highestFirst := uint64(0)
	highestSecond := uint64(0)
	highestThird := uint64(0)
	highestFourth := uint64(0)

	for _, f := range firstRetro {
		found := false
		for _, p := range peerIds {
			if p != f.PeerId {
				continue
			}
			found = true
		}
		if !found {
			continue
		}
		// these don't have decimals so we can shortcut
		max := 157208
		actual, err := strconv.Atoi(f.Reward)
		if err != nil {
			panic(err)
		}

		s := uint64(10 * 6 * 60 * 24 * 92 / (max / actual))
		if s > uint64(highestFirst) {
			highestFirst = s
		}
	}

	for _, f := range secondRetro {
		found := false
		for _, p := range peerIds {
			if p != f.PeerId {
				continue
			}
			found = true
		}
		if !found {
			continue
		}

		amt := uint64(0)
		if f.JanPresence {
			amt += (10 * 6 * 60 * 24 * 31)
		}

		if f.FebPresence {
			amt += (10 * 6 * 60 * 24 * 29)
		}

		if f.MarPresence {
			amt += (10 * 6 * 60 * 24 * 31)
		}

		if f.AprPresence {
			amt += (10 * 6 * 60 * 24 * 30)
		}

		if f.MayPresence {
			amt += (10 * 6 * 60 * 24 * 31)
		}

		if amt > uint64(highestSecond) {
			highestSecond = amt
		}
	}

	for _, f := range thirdRetro {
		found := false
		for _, p := range peerIds {
			if p != f.PeerId {
				continue
			}
			found = true
		}
		if !found {
			continue
		}

		s := uint64(10 * 6 * 60 * 24 * 30)
		if s > uint64(highestThird) {
			highestThird = s
		}
	}

	for _, f := range fourthRetro {
		found := false
		for _, p := range peerIds {
			if p != f.PeerId {
				continue
			}
			found = true
		}
		if !found {
			continue
		}

		s := uint64(10 * 6 * 60 * 24 * 31)
		if s > uint64(highestFourth) {
			highestFourth = s
		}
	}
	return new(big.Int).SetUint64(
		highestFirst + highestSecond + highestThird + highestFourth,
	)
}

func (e *TokenExecutionEngine) AnnounceProverMerge() *protobufs.AnnounceProverRequest {
	currentHead := e.GetFrame()
	if currentHead == nil ||
		currentHead.FrameNumber < application.PROOF_FRAME_CUTOFF {
		return nil
	}

	var helpers []protobufs.ED448SignHelper = []protobufs.ED448SignHelper{
		{
			PublicKey: e.pubSub.GetPublicKey(),
			Sign:      e.pubSub.SignMessage,
		},
	}

	if len(e.engineConfig.MultisigProverEnrollmentPaths) != 0 &&
		e.GetSeniority().Cmp(GetAggregatedSeniority(
			[]string{peer.ID(e.pubSub.GetPeerID()).String()},
		)) == 0 {
		for _, conf := range e.engineConfig.MultisigProverEnrollmentPaths {
			extraConf, err := config.LoadConfig(conf, "", false)
			if err != nil {
				e.logger.Panic("error loading config", zap.Error(err))
			}

			peerPrivKey, err := hex.DecodeString(extraConf.P2P.PeerPrivKey)
			if err != nil {
				e.logger.Panic("error loading config", zap.Error(err))
			}

			privKey, err := pcrypto.UnmarshalEd448PrivateKey(peerPrivKey)
			if err != nil {
				e.logger.Panic("error unmarshaling peerkey", zap.Error(err))
			}

			pub := privKey.GetPublic()
			pubBytes, err := pub.Raw()
			if err != nil {
				e.logger.Panic("error unmarshaling peerkey", zap.Error(err))
			}

			helpers = append(helpers, protobufs.ED448SignHelper{
				PublicKey: pubBytes,
				Sign:      privKey.Sign,
			})
		}
	}

	announce := &protobufs.AnnounceProverRequest{}
	if err := announce.SignED448(helpers); err != nil {
		e.logger.Panic("error signing announce", zap.Error(err))
	}
	if err := announce.Validate(); err != nil {
		e.logger.Panic("error validating announce", zap.Error(err))
	}

	return announce
}

func (e *TokenExecutionEngine) AnnounceProverJoin() {
	head := e.GetFrame()
	if head == nil ||
		head.FrameNumber < application.PROOF_FRAME_CUTOFF {
		return
	}

	join := &protobufs.AnnounceProverJoin{
		Filter:      bytes.Repeat([]byte{0xff}, 32),
		FrameNumber: head.FrameNumber,
		Announce:    e.AnnounceProverMerge(),
	}
	if err := join.SignED448(e.pubSub.GetPublicKey(), e.pubSub.SignMessage); err != nil {
		e.logger.Panic("error signing join", zap.Error(err))
	}
	if err := join.Validate(); err != nil {
		e.logger.Panic("error validating join", zap.Error(err))
	}

	if err := e.publishMessage(
		append([]byte{0x00}, e.intrinsicFilter...),
		join.TokenRequest(),
	); err != nil {
		e.logger.Warn("error publishing join message", zap.Error(err))
	}
}

func (e *TokenExecutionEngine) GetRingPosition() int {
	altAddr, err := poseidon.HashBytes(e.pubSub.GetPeerID())
	if err != nil {
		return -1
	}

	tries := e.clock.GetFrameProverTries()
	if len(tries) <= 1 {
		return -1
	}

	for i, trie := range tries[1:] {
		if trie.Contains(altAddr.FillBytes(make([]byte, 32))) {
			return i
		}
	}

	return -1
}

func (e *TokenExecutionEngine) getPeerIdFromSignature(
	sig *protobufs.Ed448Signature,
) (peer.ID, error) {
	if sig.PublicKey == nil || sig.PublicKey.KeyValue == nil {
		return "", errors.New("invalid data")
	}

	pk, err := pcrypto.UnmarshalEd448PublicKey(
		sig.PublicKey.KeyValue,
	)
	if err != nil {
		return "", errors.Wrap(err, "get address from signature")
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return "", errors.Wrap(err, "get address from signature")
	}

	return peerId, nil
}

func (e *TokenExecutionEngine) getAddressFromSignature(
	sig *protobufs.Ed448Signature,
) ([]byte, error) {
	if sig.PublicKey == nil || sig.PublicKey.KeyValue == nil {
		return nil, errors.New("invalid data")
	}

	pk, err := pcrypto.UnmarshalEd448PublicKey(
		sig.PublicKey.KeyValue,
	)
	if err != nil {
		return nil, errors.Wrap(err, "get address from signature")
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return nil, errors.Wrap(err, "get address from signature")
	}

	altAddr, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		return nil, errors.Wrap(err, "get address from signature")
	}

	return altAddr.FillBytes(make([]byte, 32)), nil
}

func (e *TokenExecutionEngine) GetWorkerCount() uint32 {
	return e.clock.GetWorkerCount()
}
