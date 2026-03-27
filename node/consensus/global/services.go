package global

import (
	"bytes"
	"context"
	"math/big"
	"slices"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"source.quilibrium.com/quilibrium/monorepo/hypergraph"
	qgrpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/rpc"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

// getCachedGlobalFrame returns a global frame by number, using an in-memory
// LRU cache to avoid repeated Pebble reads for recently-served frames.
func (e *GlobalConsensusEngine) getCachedGlobalFrame(
	frameNumber uint64,
) (*protobufs.GlobalFrame, error) {
	if frame, ok := e.globalFrameCache.Get(frameNumber); ok {
		return frame, nil
	}

	frame, err := e.clockStore.GetGlobalClockFrame(frameNumber)
	if err != nil {
		return nil, err
	}

	e.globalFrameCache.Add(frameNumber, frame)
	return frame, nil
}

func (e *GlobalConsensusEngine) GetGlobalFrame(
	ctx context.Context,
	request *protobufs.GetGlobalFrameRequest,
) (*protobufs.GlobalFrameResponse, error) {
	peerID, ok := qgrpc.PeerIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "remote peer ID not found")
	}

	e.logger.Debug(
		"received frame request",
		zap.Uint64("frame_number", request.FrameNumber),
		zap.String("peer_id", peerID.String()),
	)
	var frame *protobufs.GlobalFrame
	var err error
	if request.FrameNumber == 0 {
		frame = (*e.forks.FinalizedState().State)
		if frame.Header.FrameNumber == 0 {
			return nil, errors.Wrap(
				errors.New("not currently syncable"),
				"get global frame",
			)
		}
	} else {
		frame, err = e.getCachedGlobalFrame(request.FrameNumber)
	}

	if err != nil {
		e.logger.Debug(
			"received error while fetching time reel head",
			zap.String("peer_id", peerID.String()),
			zap.Uint64("frame_number", request.FrameNumber),
			zap.Error(err),
		)
		return nil, errors.Wrap(err, "get data frame")
	}

	return &protobufs.GlobalFrameResponse{
		Frame: frame,
	}, nil
}

func (e *GlobalConsensusEngine) GetGlobalProposal(
	ctx context.Context,
	request *protobufs.GetGlobalProposalRequest,
) (*protobufs.GlobalProposalResponse, error) {
	peerID, err := e.authenticateProverFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Genesis does not have a parent cert, treat special:
	if request.FrameNumber == 0 {
		frame, err := e.getCachedGlobalFrame(request.FrameNumber)
		if err != nil {
			e.logger.Debug(
				"received error while fetching global frame",
				zap.String("peer_id", peerID.String()),
				zap.Uint64("frame_number", request.FrameNumber),
				zap.Error(err),
			)
			return nil, errors.Wrap(err, "get global proposal")
		}
		return &protobufs.GlobalProposalResponse{
			Proposal: &protobufs.GlobalProposal{
				State: frame,
			},
		}, nil
	}

	e.logger.Debug(
		"received proposal request",
		zap.Uint64("frame_number", request.FrameNumber),
		zap.String("peer_id", peerID.String()),
	)
	frame, err := e.loadFrameMatchingSelector(
		request.FrameNumber,
		nil,
	)
	if err != nil {
		return &protobufs.GlobalProposalResponse{}, nil
	}

	vote, err := e.clockStore.GetProposalVote(
		nil,
		frame.GetRank(),
		[]byte(frame.Source()),
	)
	if err != nil {
		return &protobufs.GlobalProposalResponse{}, nil
	}

	parent, err := e.loadFrameMatchingSelector(
		request.FrameNumber-1,
		frame.Header.ParentSelector,
	)
	if err != nil {
		e.logger.Debug(
			"received error while fetching global frame parent",
			zap.String("peer_id", peerID.String()),
			zap.Uint64("frame_number", request.FrameNumber),
			zap.Error(err),
		)
		return nil, errors.Wrap(err, "get global proposal")
	}

	parentQC, err := e.clockStore.GetQuorumCertificate(nil, parent.GetRank())
	if err != nil {
		e.logger.Debug(
			"received error while fetching QC parent",
			zap.String("peer_id", peerID.String()),
			zap.Uint64("frame_number", request.FrameNumber),
			zap.Error(err),
		)
		return nil, errors.Wrap(err, "get global proposal")
	}

	// no tc is fine, pass the nil along
	priorRankTC, _ := e.clockStore.GetTimeoutCertificate(nil, frame.GetRank()-1)

	proposal := &protobufs.GlobalProposal{
		State:                       frame,
		ParentQuorumCertificate:     parentQC,
		PriorRankTimeoutCertificate: priorRankTC,
		Vote:                        vote,
	}

	return &protobufs.GlobalProposalResponse{
		Proposal: proposal,
	}, nil
}

func (e *GlobalConsensusEngine) loadFrameMatchingSelector(
	frameNumber uint64,
	expectedSelector []byte,
) (*protobufs.GlobalFrame, error) {
	matchesSelector := func(frame *protobufs.GlobalFrame) bool {
		if frame == nil || frame.Header == nil || len(expectedSelector) == 0 {
			return true
		}
		return bytes.Equal([]byte(frame.Identity()), expectedSelector)
	}

	frame, err := e.getCachedGlobalFrame(frameNumber)
	if err == nil && matchesSelector(frame) {
		return frame, nil
	}

	iter, iterErr := e.clockStore.RangeGlobalClockFrameCandidates(
		frameNumber,
		frameNumber,
	)
	if iterErr != nil {
		if err != nil {
			return nil, err
		}
		return nil, iterErr
	}
	defer iter.Close()

	for ok := iter.First(); ok && iter.Valid(); ok = iter.Next() {
		candidate, valErr := iter.Value()
		if valErr != nil {
			return nil, valErr
		}
		if matchesSelector(candidate) {
			return candidate, nil
		}
	}

	if err == nil && matchesSelector(frame) {
		return frame, nil
	}

	return nil, store.ErrNotFound
}

func (e *GlobalConsensusEngine) GetAppShards(
	ctx context.Context,
	req *protobufs.GetAppShardsRequest,
) (*protobufs.GetAppShardsResponse, error) {
	peerID, ok := qgrpc.PeerIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "remote peer ID not found")
	}

	if !bytes.Equal(e.pubsub.GetPeerID(), []byte(peerID)) {
		if len(req.ShardKey) != 35 {
			return nil, errors.Wrap(errors.New("invalid shard key"), "get app shards")
		}
	}

	var shards []store.ShardInfo
	var err error
	if len(req.ShardKey) != 35 {
		shards, err = e.shardsStore.RangeAppShards()
	} else {
		shards, err = e.shardsStore.GetAppShards(req.ShardKey, req.Prefix)
	}
	if err != nil {
		return nil, errors.Wrap(err, "get app shards")
	}

	response := &protobufs.GetAppShardsResponse{
		Info: []*protobufs.AppShardInfo{},
	}

	hg, ok := e.hypergraph.(*hypergraph.HypergraphCRDT)
	if !ok {
		return nil, errors.New("hypergraph does not support caching")
	}

	includeShardKey := len(req.ShardKey) != 35
	for _, shard := range shards {
		info := e.getAppShardInfoForShard(hg, shard, includeShardKey)
		response.Info = append(response.Info, info)
	}

	return response, nil
}

// selectPathSegmentForPrefix walks the returned path segments and prioritizes
// an exact match to the provided fullPrefix. If no exact match exists, it falls
// back to the first branch whose full prefix extends the requested prefix,
// otherwise it returns the first leaf encountered.
func selectPathSegmentForPrefix(
	pathSegments []*protobufs.TreePathSegments,
	fullPrefix []uint32,
) (*protobufs.TreePathBranch, *protobufs.TreePathLeaf) {
	var fallbackBranch *protobufs.TreePathBranch
	for _, ps := range pathSegments {
		for _, segment := range ps.Segments {
			switch node := segment.Segment.(type) {
			case *protobufs.TreePathSegment_Branch:
				if slices.Equal(node.Branch.FullPrefix, fullPrefix) {
					return node.Branch, nil
				}

				if len(node.Branch.FullPrefix) >= len(fullPrefix) &&
					len(fullPrefix) > 0 &&
					slices.Equal(
						node.Branch.FullPrefix[:len(fullPrefix)],
						fullPrefix,
					) &&
					fallbackBranch == nil {
					fallbackBranch = node.Branch
				}

				if len(fullPrefix) == 0 && fallbackBranch == nil {
					fallbackBranch = node.Branch
				}
			case *protobufs.TreePathSegment_Leaf:
				return nil, node.Leaf
			}
		}
	}

	if fallbackBranch != nil {
		return fallbackBranch, nil
	}

	return nil, nil
}

func (e *GlobalConsensusEngine) GetGlobalShards(
	ctx context.Context,
	req *protobufs.GetGlobalShardsRequest,
) (*protobufs.GetGlobalShardsResponse, error) {
	if len(req.L1) != 3 || len(req.L2) != 32 {
		return nil, errors.Wrap(
			errors.New("invalid shard key"),
			"get global shards",
		)
	}

	size := big.NewInt(0)
	commitment := [][]byte{}
	dataShards := uint64(0)
	for _, ps := range []protobufs.HypergraphPhaseSet{0, 1, 2, 3} {
		c, err := e.hypergraph.GetChildrenForPath(
			ctx,
			&protobufs.GetChildrenForPathRequest{
				ShardKey: slices.Concat(req.L1, req.L2),
				Path:     []uint32{},
				PhaseSet: protobufs.HypergraphPhaseSet(ps),
			},
		)
		if err != nil {
			commitment = append(commitment, make([]byte, 64))
			continue
		}

		if len(c.PathSegments) == 0 {
			commitment = append(commitment, make([]byte, 64))
			continue
		}

		s := c.PathSegments[0]
		if len(s.Segments) != 1 {
			commitment = append(commitment, make([]byte, 64))
			continue
		}

		switch t := s.Segments[0].Segment.(type) {
		case *protobufs.TreePathSegment_Branch:
			size = size.Add(size, new(big.Int).SetBytes(t.Branch.Size))
			commitment = append(commitment, t.Branch.Commitment)
			dataShards += t.Branch.LeafCount
		case *protobufs.TreePathSegment_Leaf:
			size = size.Add(size, new(big.Int).SetBytes(t.Leaf.Size))
			commitment = append(commitment, t.Leaf.Commitment)
			dataShards += 1
		}
	}

	return &protobufs.GetGlobalShardsResponse{
		Size:       size.Bytes(),
		Commitment: commitment,
	}, nil
}

func (e *GlobalConsensusEngine) GetLockedAddresses(
	ctx context.Context,
	req *protobufs.GetLockedAddressesRequest,
) (*protobufs.GetLockedAddressesResponse, error) {
	e.txLockMu.RLock()
	defer e.txLockMu.RUnlock()
	if _, ok := e.txLockMap[req.FrameNumber]; !ok {
		return &protobufs.GetLockedAddressesResponse{}, nil
	}

	locks := e.txLockMap[req.FrameNumber]
	if _, ok := locks[string(req.ShardAddress)]; !ok {
		return &protobufs.GetLockedAddressesResponse{}, nil
	}

	transactions := []*protobufs.LockedTransaction{}
	for _, tx := range locks[string(req.ShardAddress)] {
		transactions = append(transactions, &protobufs.LockedTransaction{
			TransactionHash: tx.TransactionHash,
			ShardAddresses:  tx.ShardAddresses,
			Committed:       tx.Committed,
			Filled:          tx.Filled,
		})
	}

	return &protobufs.GetLockedAddressesResponse{
		Transactions: transactions,
	}, nil
}

func (e *GlobalConsensusEngine) GetWorkerInfo(
	ctx context.Context,
	req *protobufs.GlobalGetWorkerInfoRequest,
) (*protobufs.GlobalGetWorkerInfoResponse, error) {
	peerID, ok := qgrpc.PeerIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "remote peer ID not found")
	}

	if !bytes.Equal(e.pubsub.GetPeerID(), []byte(peerID)) {
		return nil, status.Error(codes.Internal, "remote peer ID not found")
	}

	workers, err := e.workerManager.RangeWorkers()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	resp := &protobufs.GlobalGetWorkerInfoResponse{
		Workers: []*protobufs.GlobalGetWorkerInfoResponseItem{},
	}

	for _, w := range workers {
		resp.Workers = append(
			resp.Workers,
			&protobufs.GlobalGetWorkerInfoResponseItem{
				CoreId:                uint32(w.CoreId),
				ListenMultiaddr:       w.ListenMultiaddr,
				StreamListenMultiaddr: w.StreamListenMultiaddr,
				Filter:                w.Filter,
				TotalStorage:          uint64(w.TotalStorage),
				Allocated:             w.Allocated,
			},
		)
	}

	return resp, nil
}

func (e *GlobalConsensusEngine) StreamGlobalMessages(
	req *protobufs.StreamGlobalMessagesRequest,
	stream protobufs.GlobalService_StreamGlobalMessagesServer,
) error {
	peerID, ok := qgrpc.PeerIDFromContext(stream.Context())
	if !ok {
		return status.Error(codes.Internal, "remote peer ID not found")
	}

	if !bytes.Equal(e.pubsub.GetPeerID(), []byte(peerID)) {
		return status.Error(codes.PermissionDenied, "only local workers may stream global messages")
	}

	ch := make(chan *protobufs.StreamGlobalMessagesResponse, 256)
	e.addGlobalMessageSubscriber(ch)
	defer e.removeGlobalMessageSubscriber(ch)

	e.logger.Info("worker connected to global message stream",
		zap.String("peer_id", peerID.String()),
	)

	// Send current PeerInfo immediately so the worker can sync before the
	// next periodic publish (5-minute interval). The initial publish at
	// startup races with worker connections — workers typically miss it.
	peerInfo := e.GetPeerInfo()
	if peerInfoData, err := peerInfo.ToCanonicalBytes(); err == nil {
		if err := stream.Send(&protobufs.StreamGlobalMessagesResponse{
			Data:    peerInfoData,
			Bitmask: GLOBAL_PEER_INFO_BITMASK,
		}); err != nil {
			return err
		}
	}

	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg := <-ch:
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}
}

// LatestGlobalFrame implements consensus.GlobalFrameService.
func (e *GlobalConsensusEngine) LatestGlobalFrame() (*protobufs.GlobalFrame, error) {
	finalized := e.forks.FinalizedState()
	if finalized == nil || finalized.State == nil {
		return nil, errors.New("finalized state unavailable")
	}
	frame := *finalized.State
	if frame == nil || frame.Header == nil || frame.Header.FrameNumber == 0 {
		return nil, errors.New("not currently syncable")
	}
	return frame, nil
}

// GlobalFrameByNumber implements consensus.GlobalFrameService.
func (e *GlobalConsensusEngine) GlobalFrameByNumber(
	frameNumber uint64,
) (*protobufs.GlobalFrame, error) {
	return e.getCachedGlobalFrame(frameNumber)
}

// InjectGlobalMessage implements consensus.GlobalFrameService.
func (e *GlobalConsensusEngine) InjectGlobalMessage(data []byte) error {
	e.addGlobalMessage(data)
	return e.pubsub.PublishToBitmask(GLOBAL_PROVER_BITMASK, data)
}

func (e *GlobalConsensusEngine) SubmitGlobalMessage(
	ctx context.Context,
	req *protobufs.SubmitGlobalMessageRequest,
) (*protobufs.SubmitGlobalMessageResponse, error) {
	if _, ok := qgrpc.PeerIDFromContext(ctx); !ok {
		return nil, status.Error(codes.Internal, "remote peer ID not found")
	}

	if len(req.Data) == 0 {
		return nil, status.Error(codes.InvalidArgument, "empty data")
	}

	e.addGlobalMessage(req.Data)
	if err := e.publishProverMessage(req.Data); err != nil {
		return nil, status.Errorf(codes.Internal, "publish message: %v", err)
	}

	return &protobufs.SubmitGlobalMessageResponse{}, nil
}

func (e *GlobalConsensusEngine) RegisterServices(server *grpc.Server) {
	protobufs.RegisterGlobalServiceServer(server, e)
	protobufs.RegisterDispatchServiceServer(server, e.dispatchService)
	protobufs.RegisterHypergraphComparisonServiceServer(server, e.hyperSync)
	protobufs.RegisterOnionServiceServer(server, e.onionService)

	if e.config.Engine.EnableMasterProxy {
		proxyServer := rpc.NewPubSubProxyServer(e.pubsub, e.logger)
		protobufs.RegisterPubSubProxyServer(server, proxyServer)
	}
}

func (e *GlobalConsensusEngine) authenticateProverFromContext(
	ctx context.Context,
) (peer.ID, error) {
	peerID, ok := qgrpc.PeerIDFromContext(ctx)
	if !ok {
		return peerID, status.Error(codes.Internal, "remote peer ID not found")
	}

	if !bytes.Equal(e.pubsub.GetPeerID(), []byte(peerID)) {
		if e.peerAuthCacheAllows(peerID) {
			return peerID, nil
		}

		registry, err := e.keyStore.GetKeyRegistry(
			[]byte(peerID),
		)
		if err != nil {
			return peerID, status.Error(
				codes.PermissionDenied,
				"could not identify peer",
			)
		}

		if registry.ProverKey == nil || registry.ProverKey.KeyValue == nil {
			return peerID, status.Error(
				codes.PermissionDenied,
				"could not identify peer (no prover)",
			)
		}

		addrBI, err := poseidon.HashBytes(registry.ProverKey.KeyValue)
		if err != nil {
			return peerID, status.Error(
				codes.PermissionDenied,
				"could not identify peer (invalid address)",
			)
		}

		addr := addrBI.FillBytes(make([]byte, 32))
		info, err := e.proverRegistry.GetActiveProvers(nil)
		if err != nil {
			return peerID, status.Error(
				codes.PermissionDenied,
				"could not identify peer (no prover registry)",
			)
		}

		found := false
		for _, prover := range info {
			if bytes.Equal(prover.Address, addr) {
				found = true
				break
			}
		}

		if !found {
			return peerID, status.Error(
				codes.PermissionDenied,
				"invalid peer",
			)
		}

		e.markPeerAuthCache(peerID)
	}

	return peerID, nil
}

const peerAuthCacheTTL = 10 * time.Second

func (e *GlobalConsensusEngine) peerAuthCacheAllows(id peer.ID) bool {
	e.peerAuthCacheMu.RLock()
	expiry, ok := e.peerAuthCache[string(id)]
	e.peerAuthCacheMu.RUnlock()

	if !ok {
		return false
	}

	if time.Now().After(expiry) {
		e.peerAuthCacheMu.Lock()
		if current, exists := e.peerAuthCache[string(id)]; exists &&
			current == expiry {
			delete(e.peerAuthCache, string(id))
		}
		e.peerAuthCacheMu.Unlock()
		return false
	}

	return true
}

func (e *GlobalConsensusEngine) markPeerAuthCache(id peer.ID) {
	e.peerAuthCacheMu.Lock()
	e.peerAuthCache[string(id)] = time.Now().Add(peerAuthCacheTTL)
	e.peerAuthCacheMu.Unlock()
}
