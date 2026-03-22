package rpc

import (
	"bytes"
	"context"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/manager"
	qgrpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/worker"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

// RPCServer strictly implements NodeService.
type RPCServer struct {
	protobufs.NodeServiceServer

	// dependencies
	config           *config.Config
	logger           *zap.Logger
	keyManager       keys.KeyManager
	pubSub           p2p.PubSub
	peerInfoProvider p2p.PeerInfoManager
	workerManager    worker.WorkerManager
	proverRegistry   consensus.ProverRegistry
	executionManager *manager.ExecutionEngineManager
	shardInfoProvider consensus.ShardInfoProvider
	coinStore         store.TokenStore
	hypergraph        hypergraph.Hypergraph
	globalFrameService consensus.GlobalFrameService

	// server interfaces
	grpcServer *grpc.Server
	httpServer *http.Server
}

// GetTokensByAccount implements protobufs.NodeServiceServer.
func (r *RPCServer) GetTokensByAccount(
	ctx context.Context,
	req *protobufs.GetTokensByAccountRequest,
) (*protobufs.GetTokensByAccountResponse, error) {
	if r.coinStore == nil {
		return nil, errors.New(
			"get tokens by account: token store not available – " +
				"token shards may not yet be unlocked, or node synchronization " +
				"may still be in progress",
		)
	}

	// Handle legacy (pre-2.1) coins:
	if (len(req.Domain) == 0 ||
		bytes.Equal(req.Domain, token.QUIL_TOKEN_ADDRESS)) &&
		len(req.Address) == 32 {
		frameNumbers, addresses, coins, err := r.coinStore.GetCoinsForOwner(
			req.Address,
		)

		if err != nil {
			return nil, errors.Wrap(err, "get tokens by account")
		}

		legacyCoins := []*protobufs.LegacyCoin{}
		for i, coin := range coins {
			legacyCoins = append(legacyCoins, &protobufs.LegacyCoin{
				Coin:        coin,
				Address:     addresses[i],
				FrameNumber: frameNumbers[i],
			})
		}

		return &protobufs.GetTokensByAccountResponse{
			LegacyCoins: legacyCoins,
		}, nil
	}

	if len(req.Address) != 112 {
		return nil, errors.Wrap(
			errors.New("invalid address"),
			"get tokens by account",
		)
	}

	if len(req.Domain) != 32 && len(req.Domain) != 0 {
		return nil, errors.Wrap(
			errors.New("invalid domain"),
			"get tokens by account",
		)
	}

	if len(req.Domain) == 0 {
		req.Domain = token.QUIL_TOKEN_ADDRESS
	}

	transactions, err := r.coinStore.GetTransactionsForOwner(
		req.Domain,
		req.Address,
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"get tokens by account",
		)
	}

	pendingTransactions, err := r.coinStore.GetPendingTransactionsForOwner(
		req.Domain,
		req.Address,
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"get tokens by account",
		)
	}

	return &protobufs.GetTokensByAccountResponse{
		Transactions:        transactions,
		PendingTransactions: pendingTransactions,
	}, nil
}

func (r *RPCServer) GetPeerInfo(
	ctx context.Context,
	_ *protobufs.GetPeerInfoRequest,
) (*protobufs.PeerInfoResponse, error) {
	set := r.peerInfoProvider.GetPeerMap()
	if set == nil {
		return nil, errors.Wrap(errors.New("no peer info"), "get peer info")
	}

	out := []*protobufs.PeerInfo{}
	for _, pi := range set {
		re := []*protobufs.Reachability{}
		for _, e := range pi.Reachability {
			re = append(re, &protobufs.Reachability{
				Filter:           e.Filter,
				PubsubMultiaddrs: e.PubsubMultiaddrs,
				StreamMultiaddrs: e.StreamMultiaddrs,
			})
		}
		cs := []*protobufs.Capability{}
		for _, e := range pi.Capabilities {
			cs = append(cs, &protobufs.Capability{
				ProtocolIdentifier: e.ProtocolIdentifier,
				AdditionalMetadata: e.AdditionalMetadata,
			})
		}
		out = append(out, &protobufs.PeerInfo{
			PeerId:              pi.PeerId,
			Reachability:        re,
			Timestamp:           pi.LastSeen,
			Capabilities:        cs,
			Version:             pi.Version,
			PatchNumber:         pi.PatchNumber,
			LastReceivedFrame:   pi.LastReceivedFrame,
			LastGlobalHeadFrame: pi.LastGlobalHeadFrame,
		})
	}

	return &protobufs.PeerInfoResponse{
		PeerInfo: out,
	}, nil
}

func (r *RPCServer) GetNodeInfo(
	ctx context.Context,
	_ *protobufs.GetNodeInfoRequest,
) (*protobufs.NodeInfoResponse, error) {
	peerID := r.pubSub.GetPeerID()

	workers, err := r.workerManager.RangeWorkers()
	if err != nil {
		return nil, errors.Wrap(err, "get node info")
	}

	proverKey, err := r.keyManager.GetSigningKey("q-prover-key")
	if err != nil {
		return nil, errors.Wrap(err, "get node info")
	}

	proverAddress, err := poseidon.HashBytes(proverKey.Public().([]byte))
	if err != nil {
		return nil, errors.Wrap(err, "get node info")
	}

	proverInfo, err := r.proverRegistry.GetProverInfo(
		proverAddress.FillBytes(make([]byte, 32)),
	)
	seniority := big.NewInt(0)
	if err == nil && proverInfo != nil {
		seniority = seniority.SetUint64(proverInfo.Seniority)
	}

	allocated := uint32(0)
	for _, w := range workers {
		if w.Allocated {
			allocated++
		}
	}

	var shardAllocations []*protobufs.ShardAllocationInfo
	if proverInfo != nil {
		currentFrame := r.proverRegistry.CurrentFrame()
		for _, alloc := range proverInfo.Allocations {
			// Only include actively-relevant allocations: Joining, Active,
			// Paused, Leaving. Skip Unknown, Rejected, Kicked, and any
			// future terminal states.
			switch alloc.Status {
			case consensus.ProverStatusJoining,
				consensus.ProverStatusActive,
				consensus.ProverStatusPaused,
				consensus.ProverStatusLeaving:
			default:
				continue
			}
			// Omit expired joins and leaves, matching the proposer's logic
			// in event_distributor.go (pendingFilterGraceFrames = 720).
			if alloc.Status == consensus.ProverStatusJoining &&
				currentFrame > alloc.JoinFrameNumber+720 {
				continue
			}
			if alloc.Status == consensus.ProverStatusLeaving &&
				currentFrame > alloc.LeaveFrameNumber+720 {
				continue
			}
			shardAllocations = append(shardAllocations, &protobufs.ShardAllocationInfo{
				Filter:                 alloc.ConfirmationFilter,
				Status:                 uint32(alloc.Status),
				JoinFrameNumber:        alloc.JoinFrameNumber,
				JoinConfirmFrameNumber: alloc.JoinConfirmFrameNumber,
				LeaveFrameNumber:       alloc.LeaveFrameNumber,
				LastActiveFrameNumber:  alloc.LastActiveFrameNumber,
			})
		}
	}

	reachable := r.config.P2P.Network != 0
	if !reachable {
		if r := r.pubSub.Reachability(); r != nil {
			reachable = r.Value
		}
	}

	return &protobufs.NodeInfoResponse{
		PeerId:           peer.ID(peerID).String(),
		PeerScore:        uint64(r.pubSub.GetPeerScore(peerID)),
		Version:          append([]byte{}, config.GetVersion()...),
		PeerSeniority:    seniority.FillBytes(make([]byte, 8)),
		RunningWorkers:   uint32(len(workers)),
		AllocatedWorkers: allocated,
		PatchNumber:      append([]byte{}, config.GetPatchNumber()),
		Reachable:        reachable,
		ShardAllocations: shardAllocations,
	}, nil
}

func (r *RPCServer) GetWorkerInfo(
	ctx context.Context,
	_ *protobufs.GetWorkerInfoRequest,
) (*protobufs.WorkerInfoResponse, error) {
	workers, err := r.workerManager.RangeWorkers()
	if err != nil {
		return nil, errors.Wrap(err, "get worker info")
	}

	info := []*protobufs.WorkerInfo{}
	for _, worker := range workers {
		info = append(info, &protobufs.WorkerInfo{
			CoreId: uint32(worker.CoreId),
			Filter: worker.Filter,
			// TODO(2.1.1+): Expose available storage
			AvailableStorage:  uint64(worker.TotalStorage),
			TotalStorage:      uint64(worker.TotalStorage),
			ManuallyManaged:   worker.ManuallyManaged,
		})
	}

	return &protobufs.WorkerInfoResponse{
		WorkerInfo: info,
	}, nil
}

func (r *RPCServer) SetManuallyManaged(
	ctx context.Context,
	req *protobufs.SetManuallyManagedRequest,
) (*protobufs.SetManuallyManagedResponse, error) {
	if r.workerManager == nil {
		return nil, errors.New("worker manager not available")
	}
	err := r.workerManager.SetManuallyManaged(
		uint(req.CoreId), req.ManuallyManaged,
	)
	if err != nil {
		return nil, errors.Wrap(err, "set manually managed")
	}
	return &protobufs.SetManuallyManagedResponse{}, nil
}

func (r *RPCServer) GetMetrics(
	ctx context.Context,
	req *protobufs.GetMetricsRequest,
) (*protobufs.GetMetricsResponse, error) {
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		r.logger.Warn("partial metrics gather error", zap.Error(err))
	}

	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	filter := strings.ToLower(req.Filter)
	for _, fam := range families {
		if filter != "" && !strings.Contains(strings.ToLower(fam.GetName()), filter) {
			continue
		}
		if err := enc.Encode(fam); err != nil {
			return nil, errors.Wrap(err, "encode metrics")
		}
	}

	return &protobufs.GetMetricsResponse{Metrics: buf.Bytes()}, nil
}

// GetVertexData implements protobufs.NodeServiceServer.
func (r *RPCServer) GetVertexData(
	ctx context.Context,
	req *protobufs.GetVertexDataRequest,
) (*protobufs.GetVertexDataResponse, error) {
	if r.hypergraph == nil {
		return nil, errors.New("hypergraph not available")
	}

	if len(req.Address) != 64 {
		return nil, errors.Wrap(
			errors.New("invalid address length, expected 64 bytes"),
			"get vertex data",
		)
	}

	var id [64]byte
	copy(id[:], req.Address)
	tree, err := r.hypergraph.GetVertexData(id)
	if err != nil {
		return nil, errors.Wrap(err, "get vertex data")
	}

	// Derive shard key from the vertex's app address (first 32 bytes)
	shardL1 := up2p.GetBloomFilterIndices(id[:32], 256, 3)
	shardL2 := make([]byte, 32)
	copy(shardL2, id[:32])

	resp := &protobufs.GetVertexDataResponse{
		SetType:   "vertex",
		PhaseType: "adds",
		ShardL1:   shardL1,
		ShardL2:   shardL2,
	}

	if req.GetFullData() {
		serialized, err := tries.SerializeNonLazyTree(tree)
		if err != nil {
			return nil, errors.Wrap(err, "serialize vertex tree")
		}
		resp.RawData = serialized
	} else {
		entries := []*protobufs.VertexDataEntry{}
		knownIndices := [][]byte{
			{0}, {4}, {8}, {12}, {16}, {20}, {24}, {28}, {0xff},
		}
		for _, key := range knownIndices {
			val, err := tree.Get(key)
			if err != nil || val == nil {
				continue
			}
			entries = append(entries, &protobufs.VertexDataEntry{
				Key:   slices.Clone(key),
				Value: slices.Clone(val),
			})
		}
		resp.Entries = entries
	}

	return resp, nil
}

// GetHyperedgeData implements protobufs.NodeServiceServer.
func (r *RPCServer) GetHyperedgeData(
	ctx context.Context,
	req *protobufs.GetHyperedgeDataRequest,
) (*protobufs.GetHyperedgeDataResponse, error) {
	if r.hypergraph == nil {
		return nil, errors.New("hypergraph not available")
	}

	if len(req.Address) != 64 {
		return nil, errors.Wrap(
			errors.New("invalid address length, expected 64 bytes"),
			"get hyperedge data",
		)
	}

	var id [64]byte
	copy(id[:], req.Address)
	tree, err := r.hypergraph.GetHyperedgeExtrinsics(id)
	if err != nil {
		return nil, errors.Wrap(err, "get hyperedge data")
	}

	entries := []*protobufs.VertexDataEntry{}
	if tree != nil && tree.Root != nil {
		for _, leaf := range tries.GetAllPreloadedLeaves(tree.Root) {
			entries = append(entries, &protobufs.VertexDataEntry{
				Key:   slices.Clone(leaf.Key),
				Value: slices.Clone(leaf.Value),
			})
		}
	}

	shardL1 := up2p.GetBloomFilterIndices(id[:32], 256, 3)
	shardL2 := make([]byte, 32)
	copy(shardL2, id[:32])

	return &protobufs.GetHyperedgeDataResponse{
		Entries:   entries,
		SetType:   "hyperedge",
		PhaseType: "adds",
		ShardL1:   shardL1,
		ShardL2:   shardL2,
	}, nil
}

// CreateTraversalProof implements protobufs.NodeServiceServer.
func (r *RPCServer) CreateTraversalProof(
	ctx context.Context,
	req *protobufs.CreateTraversalProofRequest,
) (*protobufs.CreateTraversalProofResponse, error) {
	if r.hypergraph == nil {
		return nil, errors.New("hypergraph not available")
	}

	if len(req.Domain) != 32 {
		return nil, errors.Wrap(
			errors.New("invalid domain length, expected 32 bytes"),
			"create traversal proof",
		)
	}

	var domain [32]byte
	copy(domain[:], req.Domain)

	proof, err := r.hypergraph.CreateTraversalProof(
		domain,
		hypergraph.AtomType(req.AtomType),
		hypergraph.PhaseType(req.PhaseType),
		req.Keys,
	)
	if err != nil {
		return nil, errors.Wrap(err, "create traversal proof")
	}

	proofBytes, err := proof.ToBytes()
	if err != nil {
		return nil, errors.Wrap(err, "create traversal proof")
	}

	return &protobufs.CreateTraversalProofResponse{
		Proof: proofBytes,
	}, nil
}

// GetShardInfo implements protobufs.NodeServiceServer.
func (r *RPCServer) GetShardInfo(
	ctx context.Context,
	req *protobufs.GetShardInfoRequest,
) (*protobufs.GetShardInfoResponse, error) {
	if r.shardInfoProvider == nil {
		return nil, errors.New("shard info not available")
	}

	details, difficulty, basis, frameNumber, err := r.shardInfoProvider.GetShardInfo(
		req.IncludeAll,
	)
	if err != nil {
		return nil, errors.Wrap(err, "get shard info")
	}

	shards := make([]*protobufs.ShardRewardInfo, 0, len(details))
	worldBytes := big.NewInt(0)
	for _, d := range details {
		worldBytes.Add(worldBytes, d.ShardSize)
		shards = append(shards, &protobufs.ShardRewardInfo{
			Filter:          d.Filter,
			ActiveProvers:   uint32(d.ActiveProvers),
			Ring:            uint32(d.Ring),
			ShardSize:       d.ShardSize.Bytes(),
			EstimatedReward: d.EstimatedReward.Bytes(),
			IsAllocated:     d.IsAllocated,
		})
	}

	resp := &protobufs.GetShardInfoResponse{
		Shards:         shards,
		Difficulty:     difficulty,
		FrameNumber:    frameNumber,
		WorldStateBytes: worldBytes.Bytes(),
	}
	if basis != nil {
		resp.PomwBasis = basis.Bytes()
	}

	return resp, nil
}

// RequestJoin implements protobufs.NodeServiceServer.
func (r *RPCServer) RequestJoin(
	ctx context.Context,
	req *protobufs.RequestJoinRequest,
) (*protobufs.RequestJoinResponse, error) {
	if r.workerManager == nil {
		return nil, errors.New("worker manager not available")
	}

	if len(req.Filters) == 0 {
		return nil, errors.New("at least one filter is required")
	}

	if err := r.workerManager.RequestJoin(
		ctx, req.Filters, req.Delegate,
	); err != nil {
		return nil, errors.Wrap(err, "request join")
	}

	return &protobufs.RequestJoinResponse{}, nil
}

// Send implements protobufs.NodeServiceServer.
func (r *RPCServer) Send(
	ctx context.Context,
	req *protobufs.SendRequest,
) (*protobufs.SendResponse, error) {
	if req == nil || req.Request == nil || len(req.Authentication) == 0 {
		return nil, errors.New("send: missing request or authentication")
	}

	signer, err := r.keyManager.GetSigningKey("q-peer-key")
	if err != nil {
		r.logger.Error("no node auth key found")
		return nil, errors.Wrap(err, "send: get auth key")
	}

	var payload []byte
	var request []byte
	if req.Request != nil {
		payload, err = req.Request.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "send")
		}
		request = slices.Clone(payload)
	}

	if len(req.DeliveryData) != 0 {
		for _, d := range req.DeliveryData {
			p, err := proto.Marshal(d)
			if err != nil {
				return nil, errors.Wrap(err, "send")
			}
			payload = append(payload, p...)
		}
	}

	if len(payload) == 0 {
		return nil, errors.New("send: empty payload")
	}

	valid, err := r.keyManager.ValidateSignature(
		crypto.KeyTypeEd448,
		signer.Public().([]byte),
		payload,
		req.Authentication,
		slices.Concat([]byte("NODE_AUTHENTICATION"), req.Domain),
	)
	if err != nil || !valid {
		return nil, errors.New("send: authentication failed")
	}

	if len(request) != 0 {
		if bytes.Equal(req.Domain, bytes.Repeat([]byte{0xff}, 32)) {
			if r.globalFrameService != nil {
				if err := r.globalFrameService.InjectGlobalMessage(request); err != nil {
					return nil, err
				}
			} else {
				r.pubSub.Subscribe(
					[]byte{0x00, 0x00, 0x00},
					func(message *pb.Message) error { return nil },
				)
				err := r.pubSub.PublishToBitmask([]byte{0x00, 0x00, 0x00}, payload)
				if err != nil {
					return nil, err
				}
			}
		} else {
			bitmask := up2p.GetBloomFilter(req.Domain, 256, 3)
			r.pubSub.Subscribe(
				bitmask,
				func(message *pb.Message) error { return nil },
			)
			err := r.pubSub.PublishToBitmask(bitmask, payload)
			if err != nil {
				return nil, err
			}
		}
	}

	if len(req.DeliveryData) != 0 {
		for _, d := range req.DeliveryData {
			for _, i := range d.Messages {
				bitmask := slices.Concat(
					[]byte{0, 0},
					up2p.GetBloomFilter(i.Address, 256, 3),
				)
				r.pubSub.Subscribe(
					bitmask,
					func(message *pb.Message) error { return nil },
				)
				msg, err := i.ToCanonicalBytes()
				if err != nil {
					return nil, err
				}
				err = r.pubSub.PublishToBitmask(bitmask, msg)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	return &protobufs.SendResponse{}, nil
}

// GetLatestFrame implements protobufs.NodeServiceServer.
func (r *RPCServer) GetLatestFrame(
	ctx context.Context,
	req *protobufs.GetGlobalFrameRequest,
) (*protobufs.GlobalFrameResponse, error) {
	if r.globalFrameService == nil {
		return nil, status.Error(codes.Unavailable, "global frame service not available")
	}

	var frame *protobufs.GlobalFrame
	var err error
	if req.FrameNumber == 0 {
		frame, err = r.globalFrameService.LatestGlobalFrame()
	} else {
		frame, err = r.globalFrameService.GlobalFrameByNumber(req.FrameNumber)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get frame: %v", err)
	}

	return &protobufs.GlobalFrameResponse{
		Frame: frame,
	}, nil
}

// SubmitMessage implements protobufs.NodeServiceServer.
func (r *RPCServer) SubmitMessage(
	ctx context.Context,
	req *protobufs.SubmitMessageRequest,
) (*protobufs.SubmitMessageResponse, error) {
	if r.globalFrameService == nil {
		return nil, status.Error(codes.Unavailable, "message submission not available")
	}
	if len(req.Data) == 0 {
		return nil, status.Error(codes.InvalidArgument, "empty data")
	}
	if err := r.globalFrameService.InjectGlobalMessage(req.Data); err != nil {
		return nil, status.Errorf(codes.Internal, "inject message: %v", err)
	}
	return &protobufs.SubmitMessageResponse{}, nil
}

func NewRPCServer(
	config *config.Config,
	logger *zap.Logger,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
	peerInfoProvider p2p.PeerInfoManager,
	workerManager worker.WorkerManager,
	proverRegistry consensus.ProverRegistry,
	executionManager *manager.ExecutionEngineManager,
	shardInfoProvider consensus.ShardInfoProvider,
	coinStore store.TokenStore,
	globalFrameService consensus.GlobalFrameService,
) (*RPCServer, error) {
	mg, err := multiaddr.NewMultiaddr(config.ListenGRPCMultiaddr)
	if err != nil {
		return nil, errors.Wrap(err, "new rpc server: grpc multiaddr")
	}
	mga, err := mn.ToNetAddr(mg)
	if err != nil {
		return nil, errors.Wrap(err, "new rpc server: grpc netaddr")
	}

	// HTTP gateway mux (optional)
	mux := runtime.NewServeMux()
	opts := qgrpc.ClientOptions(
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(10*1024*1024),
			grpc.MaxCallSendMsgSize(10*1024*1024),
		),
	)
	if config.ListenRestMultiaddr != "" {
		if err := protobufs.RegisterNodeServiceHandlerFromEndpoint(
			context.Background(),
			mux,
			mga.String(),
			opts,
		); err != nil {
			return nil, errors.Wrap(err, "register node service handler")
		}
	}

	rpcServer := &RPCServer{
		config:             config,
		logger:             logger,
		keyManager:         keyManager,
		pubSub:             pubSub,
		peerInfoProvider:   peerInfoProvider,
		workerManager:      workerManager,
		proverRegistry:     proverRegistry,
		executionManager:   executionManager,
		shardInfoProvider:  shardInfoProvider,
		coinStore:          coinStore,
		globalFrameService: globalFrameService,
		grpcServer: qgrpc.NewServer(
			grpc.MaxRecvMsgSize(10*1024*1024),
			grpc.MaxSendMsgSize(10*1024*1024),
		),
		httpServer: &http.Server{Handler: mux},
	}

	protobufs.RegisterNodeServiceServer(rpcServer.grpcServer, rpcServer)
	return rpcServer, nil
}

func (r *RPCServer) Start() error {
	// Start GRPC
	mg, err := multiaddr.NewMultiaddr(r.config.ListenGRPCMultiaddr)
	if err != nil {
		return errors.Wrap(err, "start: grpc multiaddr")
	}
	lis, err := mn.Listen(mg)
	if err != nil {
		return errors.Wrap(err, "start: grpc listen")
	}
	go func() {
		if err := r.grpcServer.Serve(mn.NetListener(lis)); err != nil {
			r.logger.Error("grpc serve error", zap.Error(err))
		}
	}()

	// Start HTTP gateway if requested
	if r.config.ListenRestMultiaddr != "" {
		mh, err := multiaddr.NewMultiaddr(r.config.ListenRestMultiaddr)
		if err != nil {
			return errors.Wrap(err, "start: http multiaddr")
		}
		hl, err := mn.Listen(mh)
		if err != nil {
			return errors.Wrap(err, "start: http listen")
		}
		go func() {
			if err := r.httpServer.Serve(
				mn.NetListener(hl),
			); err != nil && !errors.Is(err, http.ErrServerClosed) {
				r.logger.Error("http serve error", zap.Error(err))
			}
		}()
	}

	return nil
}

func (r *RPCServer) Stop() {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r.grpcServer.GracefulStop()
	}()
	go func() {
		defer wg.Done()
		_ = r.httpServer.Shutdown(context.Background())
	}()
	wg.Wait()
}
