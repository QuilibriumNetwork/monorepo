package app

import (
	"bytes"
	"context"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/peer"
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
	peerID, err := e.authenticateProverFromContext(ctx)
	if err != nil {
		return nil, err
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

func (e *AppConsensusEngine) GetAppShardProposal(
	ctx context.Context,
	request *protobufs.GetAppShardProposalRequest,
) (*protobufs.AppShardProposalResponse, error) {
	peerID, err := e.authenticateProverFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Genesis does not have a parent cert, treat special:
	if request.FrameNumber == 0 {
		frame, _, err := e.clockStore.GetShardClockFrame(
			request.Filter,
			request.FrameNumber,
			false,
		)
		if err != nil {
			e.logger.Debug(
				"received error while fetching shard frame",
				zap.String("peer_id", peerID.String()),
				zap.Uint64("frame_number", request.FrameNumber),
				zap.Error(err),
			)
			return nil, errors.Wrap(err, "get shard proposal")
		}
		return &protobufs.AppShardProposalResponse{
			Proposal: &protobufs.AppShardProposal{
				State: frame,
			},
		}, nil
	}

	e.logger.Debug(
		"received proposal request",
		zap.Uint64("frame_number", request.FrameNumber),
		zap.String("peer_id", peerID.String()),
	)
	frame, _, err := e.clockStore.GetShardClockFrame(
		request.Filter,
		request.FrameNumber,
		false,
	)
	if err != nil {
		return &protobufs.AppShardProposalResponse{}, nil
	}

	parent, _, err := e.clockStore.GetShardClockFrame(
		request.Filter,
		request.FrameNumber-1,
		false,
	)
	if err != nil {
		e.logger.Debug(
			"received error while fetching shard frame parent",
			zap.String("peer_id", peerID.String()),
			zap.Uint64("frame_number", request.FrameNumber),
			zap.Error(err),
		)
		return nil, errors.Wrap(err, "get shard proposal")
	}

	parentQC, err := e.clockStore.GetQuorumCertificate(
		request.Filter,
		parent.GetRank(),
	)
	if err != nil {
		e.logger.Debug(
			"received error while fetching QC parent",
			zap.String("peer_id", peerID.String()),
			zap.Uint64("frame_number", request.FrameNumber),
			zap.Error(err),
		)
		return nil, errors.Wrap(err, "get shard proposal")
	}
	// no tc is fine, pass the nil along
	priorRankTC, _ := e.clockStore.GetTimeoutCertificate(
		request.Filter,
		frame.GetRank()-1,
	)
	proposal := &protobufs.AppShardProposal{
		State:                       frame,
		ParentQuorumCertificate:     parentQC,
		PriorRankTimeoutCertificate: priorRankTC,
	}
	return &protobufs.AppShardProposalResponse{
		Proposal: proposal,
	}, nil
}

func (e *AppConsensusEngine) RegisterServices(server *grpc.Server) {
	protobufs.RegisterAppShardServiceServer(server, e)
	protobufs.RegisterDispatchServiceServer(server, e.dispatchService)
	protobufs.RegisterHypergraphComparisonServiceServer(server, e.hyperSync)
	protobufs.RegisterOnionServiceServer(server, e.onionService)
}

func (e *AppConsensusEngine) authenticateProverFromContext(
	ctx context.Context,
) (peer.ID, error) {
	peerID, ok := qgrpc.PeerIDFromContext(ctx)
	if !ok {
		return peerID, status.Error(codes.Internal, "remote peer ID not found")
	}

	if !bytes.Equal(e.pubsub.GetPeerID(), []byte(peerID)) {
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
		info, err := e.proverRegistry.GetActiveProvers(e.appAddress)
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
	}

	return peerID, nil
}
