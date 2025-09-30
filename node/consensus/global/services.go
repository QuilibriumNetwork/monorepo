package global

import (
	"bytes"
	"context"
	"math/big"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	qgrpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/rpc"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

func (e *GlobalConsensusEngine) GetGlobalFrame(
	ctx context.Context,
	request *protobufs.GetGlobalFrameRequest,
) (*protobufs.GlobalFrameResponse, error) {
	peerID, ok := qgrpc.PeerIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "remote peer ID not found")
	}

	registry, err := e.keyStore.GetKeyRegistry(
		[]byte(peerID),
	)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "could not identify peer")
	}

	if !bytes.Equal(e.pubsub.GetPeerID(), []byte(peerID)) {
		if registry.ProverKey == nil || registry.ProverKey.KeyValue == nil {
			return nil, status.Error(
				codes.PermissionDenied,
				"could not identify peer (no prover)",
			)
		}

		addrBI, err := poseidon.HashBytes(registry.ProverKey.KeyValue)
		if err != nil {
			return nil, status.Error(
				codes.PermissionDenied,
				"could not identify peer (invalid address)",
			)
		}

		addr := addrBI.FillBytes(make([]byte, 32))
		info, err := e.proverRegistry.GetActiveProvers(nil)
		if err != nil {
			return nil, status.Error(
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
			return nil, status.Error(
				codes.PermissionDenied,
				"invalid peer",
			)
		}
	}

	e.logger.Debug(
		"received frame request",
		zap.Uint64("frame_number", request.FrameNumber),
		zap.String("peer_id", peerID.String()),
	)
	var frame *protobufs.GlobalFrame
	if request.FrameNumber == 0 {
		frame, err = e.globalTimeReel.GetHead()
		if frame.Header.FrameNumber == 0 {
			return nil, errors.Wrap(
				errors.New("not currently syncable"),
				"get global frame",
			)
		}
	} else {
		frame, err = e.clockStore.GetGlobalClockFrame(request.FrameNumber)
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

func (e *GlobalConsensusEngine) GetAppShards(
	ctx context.Context,
	req *protobufs.GetAppShardsRequest,
) (*protobufs.GetAppShardsResponse, error) {
	if len(req.ShardKey) != 35 {
		return nil, errors.Wrap(errors.New("invalid shard key"), "get app shards")
	}

	shards, err := e.shardsStore.GetAppShards(req.ShardKey, req.Prefix)
	if err != nil {
		return nil, errors.Wrap(err, "get app shards")
	}

	response := &protobufs.GetAppShardsResponse{
		Info: []*protobufs.AppShardInfo{},
	}

	for _, shard := range shards {
		size := big.NewInt(0)
		commitment := [][]byte{}
		dataShards := uint64(0)
		for _, ps := range []protobufs.HypergraphPhaseSet{0, 1, 2, 3} {
			c, err := e.hypergraph.GetChildrenForPath(
				ctx,
				&protobufs.GetChildrenForPathRequest{
					ShardKey: req.ShardKey,
					Path:     shard.Path,
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

			s := c.PathSegments[len(c.PathSegments)-1]
			if len(s.Segments) > 1 {
				return nil, errors.Wrap(errors.New("no shard found"), "get app shards")
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

		response.Info = append(response.Info, &protobufs.AppShardInfo{
			Prefix:     shard.Path,
			Size:       size.Bytes(),
			Commitment: commitment,
			DataShards: dataShards,
		})
	}

	return response, nil
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
