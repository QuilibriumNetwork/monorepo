package sync

import (
	"bytes"
	"context"
	"encoding/hex"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/frametime"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	tconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

var ErrConnectivityFailed = errors.New("connectivity to peer failed")
var ErrInvalidResponse = errors.New("peer returned invalid response")

type SyncClient[StateT UniqueFrame, ProposalT any] interface {
	Sync(
		ctx context.Context,
		logger *zap.Logger,
		cc *grpc.ClientConn,
		frameNumber uint64,
		expectedIdentity []byte,
	) error
}

type GlobalSyncClient struct {
	frameProver       crypto.FrameProver
	blsConstructor    crypto.BlsConstructor
	proposalProcessor ProposalProcessor[*protobufs.GlobalProposal]
	config            *config.Config
	validateFrames    bool
}

func NewGlobalSyncClient(
	frameProver crypto.FrameProver,
	blsConstructor crypto.BlsConstructor,
	proposalProcessor ProposalProcessor[*protobufs.GlobalProposal],
	config *config.Config,
) *GlobalSyncClient {
	return &GlobalSyncClient{
		frameProver:       frameProver,
		config:            config,
		blsConstructor:    blsConstructor,
		proposalProcessor: proposalProcessor,
		validateFrames:    true,
	}
}

func (g *GlobalSyncClient) SetValidationEnabled(enabled bool) {
	g.validateFrames = enabled
}

func (g *GlobalSyncClient) Sync(
	ctx context.Context,
	logger *zap.Logger,
	cc *grpc.ClientConn,
	frameNumber uint64,
	expectedIdentity []byte,
) error {
	client := protobufs.NewGlobalServiceClient(cc)

	for {
		getCtx, cancelGet := context.WithTimeout(ctx, g.config.Engine.SyncTimeout)
		response, err := client.GetGlobalProposal(
			getCtx,
			&protobufs.GetGlobalProposalRequest{
				FrameNumber: frameNumber,
			},
			// The message size limits are swapped because the server is the one
			// sending the data.
			grpc.MaxCallRecvMsgSize(
				g.config.Engine.SyncMessageLimits.MaxSendMsgSize,
			),
			grpc.MaxCallSendMsgSize(
				g.config.Engine.SyncMessageLimits.MaxRecvMsgSize,
			),
		)
		cancelGet()
		if err != nil {
			logger.Debug(
				"could not get frame, trying next multiaddr",
				zap.Error(err),
			)
			return ErrConnectivityFailed
		}

		if response == nil {
			logger.Debug(
				"received no response from peer",
				zap.Error(err),
			)
			return ErrInvalidResponse
		}

		if response.Proposal == nil || response.Proposal.State == nil ||
			response.Proposal.State.Header == nil ||
			response.Proposal.State.Header.FrameNumber != frameNumber {
			logger.Debug("received empty response from peer")
			return ErrInvalidResponse
		}
		if g.validateFrames {
			if err := response.Proposal.Validate(); err != nil {
				logger.Debug(
					"received invalid response from peer",
					zap.Error(err),
				)
				return ErrInvalidResponse
			}
		}

		if len(expectedIdentity) != 0 {
			if !bytes.Equal(
				[]byte(response.Proposal.State.Identity()),
				expectedIdentity,
			) {
				logger.Warn(
					"aborting sync due to unexpected frame identity",
					zap.Uint64("frame_number", frameNumber),
					zap.String(
						"expected",
						hex.EncodeToString(expectedIdentity),
					),
					zap.String(
						"received",
						hex.EncodeToString(
							[]byte(response.Proposal.State.Identity()),
						),
					),
				)
				return errors.New("sync frame identity mismatch")
			}
			expectedIdentity = nil
		}

		logger.Info(
			"received new leading frame",
			zap.Uint64("frame_number", response.Proposal.State.Header.FrameNumber),
			zap.Duration(
				"frame_age",
				frametime.GlobalFrameSince(response.Proposal.State),
			),
		)

		if g.validateFrames {
			if _, err := g.frameProver.VerifyGlobalFrameHeader(
				response.Proposal.State.Header,
				g.blsConstructor,
			); err != nil {
				logger.Debug(
					"received invalid frame from peer",
					zap.Error(err),
				)
				return ErrInvalidResponse
			}
		}

		g.proposalProcessor.AddProposal(response.Proposal)
		frameNumber = frameNumber + 1
	}
}

type AppSyncClient struct {
	frameProver       crypto.FrameProver
	proverRegistry    tconsensus.ProverRegistry
	blsConstructor    crypto.BlsConstructor
	proposalProcessor ProposalProcessor[*protobufs.AppShardProposal]
	config            *config.Config
	filter            []byte
}

func NewAppSyncClient(
	frameProver crypto.FrameProver,
	proverRegistry tconsensus.ProverRegistry,
	blsConstructor crypto.BlsConstructor,
	proposalProcessor ProposalProcessor[*protobufs.AppShardProposal],
	config *config.Config,
	filter []byte,
) *AppSyncClient {
	return &AppSyncClient{
		frameProver:       frameProver,
		proverRegistry:    proverRegistry,
		config:            config,
		blsConstructor:    blsConstructor,
		proposalProcessor: proposalProcessor,
		filter:            filter,
	}
}

func (a *AppSyncClient) Sync(
	ctx context.Context,
	logger *zap.Logger,
	cc *grpc.ClientConn,
	frameNumber uint64,
	expectedIdentity []byte,
) error {
	client := protobufs.NewAppShardServiceClient(cc)

	for {
		getCtx, cancelGet := context.WithTimeout(ctx, a.config.Engine.SyncTimeout)
		response, err := client.GetAppShardProposal(
			getCtx,
			&protobufs.GetAppShardProposalRequest{
				Filter:      a.filter,
				FrameNumber: frameNumber,
			},
			// The message size limits are swapped because the server is the one
			// sending the data.
			grpc.MaxCallRecvMsgSize(
				a.config.Engine.SyncMessageLimits.MaxSendMsgSize,
			),
			grpc.MaxCallSendMsgSize(
				a.config.Engine.SyncMessageLimits.MaxRecvMsgSize,
			),
		)
		cancelGet()
		if err != nil {
			logger.Debug(
				"could not get frame, trying next multiaddr",
				zap.Error(err),
			)
			return ErrConnectivityFailed
		}

		if response == nil {
			logger.Debug(
				"received no response from peer",
				zap.Error(err),
			)
			return ErrInvalidResponse
		}

		if response.Proposal == nil || response.Proposal.State == nil ||
			response.Proposal.State.Header == nil ||
			response.Proposal.State.Header.FrameNumber != frameNumber {
			logger.Debug("received empty response from peer")
			return ErrInvalidResponse
		}
		if err := response.Proposal.Validate(); err != nil {
			logger.Debug(
				"received invalid response from peer",
				zap.Error(err),
			)
			return ErrInvalidResponse
		}

		if len(expectedIdentity) != 0 {
			if !bytes.Equal(
				[]byte(response.Proposal.State.Identity()),
				expectedIdentity,
			) {
				logger.Warn(
					"aborting sync due to unexpected frame identity",
					zap.Uint64("frame_number", frameNumber),
					zap.String(
						"expected",
						hex.EncodeToString(expectedIdentity),
					),
					zap.String(
						"received",
						hex.EncodeToString(
							[]byte(response.Proposal.State.Identity()),
						),
					),
				)
				return errors.New("sync frame identity mismatch")
			}
			expectedIdentity = nil
		}

		logger.Info(
			"received new leading frame",
			zap.Uint64("frame_number", response.Proposal.State.Header.FrameNumber),
			zap.Duration(
				"frame_age",
				frametime.AppFrameSince(response.Proposal.State),
			),
		)

		provers, err := a.proverRegistry.GetActiveProvers(a.filter)
		if err != nil {
			logger.Debug(
				"could not obtain active provers",
				zap.Error(err),
			)
			return ErrInvalidResponse
		}

		ids := [][]byte{}
		for _, p := range provers {
			ids = append(ids, p.Address)
		}

		if _, err := a.frameProver.VerifyFrameHeader(
			response.Proposal.State.Header,
			a.blsConstructor,
			ids,
		); err != nil {
			logger.Debug(
				"received invalid frame from peer",
				zap.Error(err),
			)
			return ErrInvalidResponse
		}

		a.proposalProcessor.AddProposal(response.Proposal)
		frameNumber = frameNumber + 1
	}
}
