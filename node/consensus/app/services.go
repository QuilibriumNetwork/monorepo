package app

import (
	"bytes"
	"context"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	qgrpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

func (e *AppConsensusEngine) GetAppShardFrame(
	ctx context.Context,
	request *protobufs.GetAppShardFrameRequest,
) (*protobufs.AppShardFrameResponse, error) {
	peerID, ok := qgrpc.PeerIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "remote peer ID not found")
	}

	if !bytes.Equal(request.Filter, e.appAddress) {
		return nil, status.Error(codes.InvalidArgument, "incorrect filter")
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
		info, err := e.proverRegistry.GetActiveProvers(request.Filter)
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
	var frame *protobufs.AppShardFrame
	if request.FrameNumber == 0 {
		frame, err = e.appTimeReel.GetHead()
		if frame.Header.FrameNumber == 0 {
			return nil, errors.Wrap(
				errors.New("not currently syncable"),
				"get app frame",
			)
		}
	} else {
		frame, _, err = e.clockStore.GetShardClockFrame(
			request.Filter,
			request.FrameNumber,
			false,
		)
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

	return &protobufs.AppShardFrameResponse{
		Frame: frame,
	}, nil
}

func (e *AppConsensusEngine) RegisterServices(server *grpc.Server) {
	protobufs.RegisterAppShardServiceServer(server, e)
	protobufs.RegisterDispatchServiceServer(server, e.dispatchService)
	protobufs.RegisterHypergraphComparisonServiceServer(server, e.hyperSync)
	protobufs.RegisterOnionServiceServer(server, e.onionService)
}
