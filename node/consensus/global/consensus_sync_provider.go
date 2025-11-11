package global

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/frametime"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

const defaultStateQueueCapacity = 10

type syncRequest struct {
	frameNumber uint64
	peerId      []byte
}

// GlobalSyncProvider implements SyncProvider
type GlobalSyncProvider struct {
	// TODO(2.1.1+): Refactor out direct use of engine
	engine       *GlobalConsensusEngine
	queuedStates chan syncRequest
}

func NewGlobalSyncProvider(
	engine *GlobalConsensusEngine,
) *GlobalSyncProvider {
	return &GlobalSyncProvider{
		engine:       engine,
		queuedStates: make(chan syncRequest, defaultStateQueueCapacity),
	}
}

func (p *GlobalSyncProvider) Start(
	ctx lifecycle.SignalerContext,
	ready lifecycle.ReadyFunc,
) {
	ready()
	for {
		select {
		case <-ctx.Done():
			return
		case request := <-p.queuedStates:
			finalized := p.engine.forks.FinalizedState()
			if request.frameNumber <=
				(*p.engine.forks.FinalizedState().State).Header.FrameNumber {
				continue
			}
			p.engine.logger.Info(
				"synchronizing with peer",
				zap.String("peer", peer.ID(request.peerId).String()),
				zap.Uint64("finalized_rank", finalized.Rank),
				zap.Uint64("peer_frame", request.frameNumber),
			)
			p.processState(
				ctx,
				request.frameNumber,
				request.peerId,
			)
		}
	}
}

func (p *GlobalSyncProvider) processState(
	ctx context.Context,
	frameNumber uint64,
	peerID []byte,
) {
	err := p.syncWithPeer(
		ctx,
		frameNumber,
		peerID,
	)
	if err != nil {
		p.engine.logger.Error("could not sync with peer", zap.Error(err))
	}
}

func (p *GlobalSyncProvider) Synchronize(
	existing **protobufs.GlobalFrame,
	ctx context.Context,
) (<-chan **protobufs.GlobalFrame, <-chan error) {
	dataCh := make(chan **protobufs.GlobalFrame, 1)
	errCh := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				if errCh != nil {
					errCh <- errors.New(fmt.Sprintf("fatal error encountered: %+v", r))
				}
			}
		}()
		defer close(dataCh)
		defer close(errCh)

		head, err := p.engine.globalTimeReel.GetHead()
		hasFrame := head != nil && err == nil

		peerCount := p.engine.pubsub.GetPeerstoreCount()

		if peerCount < p.engine.config.Engine.MinimumPeersRequired {
			p.engine.logger.Info(
				"waiting for minimum peers",
				zap.Int("current", peerCount),
				zap.Int("required", p.engine.config.Engine.MinimumPeersRequired),
			)

			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()

		loop:
			for {
				select {
				case <-ctx.Done():
					errCh <- errors.Wrap(
						ctx.Err(),
						"synchronize cancelled while waiting for peers",
					)
					return
				case <-ticker.C:
					peerCount = p.engine.pubsub.GetPeerstoreCount()
					if peerCount >= p.engine.config.Engine.MinimumPeersRequired {
						p.engine.logger.Info(
							"minimum peers reached",
							zap.Int("peers", peerCount),
						)
						break loop
					}
				}
				if peerCount >= p.engine.config.Engine.MinimumPeersRequired {
					break
				}
			}
		}

		if !hasFrame {
			errCh <- errors.New("no frame")
			return
		}

		err = p.syncWithMesh(ctx)
		if err != nil {
			dataCh <- existing
			errCh <- err
			return
		}

		if hasFrame {
			// Retrieve full frame from store
			frameID := p.engine.globalTimeReel.ComputeFrameID(head)
			p.engine.frameStoreMu.RLock()
			fullFrame, exists := p.engine.frameStore[frameID]
			p.engine.frameStoreMu.RUnlock()

			if exists {
				dataCh <- &fullFrame
			} else if existing != nil {
				dataCh <- existing
			}
		}

		syncStatusCheck.WithLabelValues("synced").Inc()
		errCh <- nil
	}()

	return dataCh, errCh
}

func (p *GlobalSyncProvider) syncWithMesh(ctx context.Context) error {
	p.engine.logger.Info("synchronizing with peers")

	latest, err := p.engine.globalTimeReel.GetHead()
	if err != nil {
		return errors.Wrap(err, "sync")
	}

	peers, err := p.engine.proverRegistry.GetActiveProvers(nil)
	if len(peers) <= 1 || err != nil {
		return nil
	}

	for _, candidate := range peers {
		if bytes.Equal(candidate.Address, p.engine.getProverAddress()) {
			continue
		}

		registry, err := p.engine.keyStore.GetKeyRegistryByProver(
			candidate.Address,
		)
		if err != nil {
			continue
		}

		if registry.IdentityKey == nil || registry.IdentityKey.KeyValue == nil {
			continue
		}

		pub, err := crypto.UnmarshalEd448PublicKey(registry.IdentityKey.KeyValue)
		if err != nil {
			p.engine.logger.Warn("error unmarshaling identity key", zap.Error(err))
			continue
		}

		peerID, err := peer.IDFromPublicKey(pub)
		if err != nil {
			p.engine.logger.Warn("error deriving peer id", zap.Error(err))
			continue
		}

		head, err := p.engine.globalTimeReel.GetHead()
		if err != nil {
			return errors.Wrap(err, "sync")
		}

		if latest.Header.FrameNumber < head.Header.FrameNumber {
			latest = head
		}

		err = p.syncWithPeer(ctx, latest.Header.FrameNumber, []byte(peerID))
		if err != nil {
			p.engine.logger.Debug("error syncing frame", zap.Error(err))
		}
	}

	p.engine.logger.Info(
		"returning leader frame",
		zap.Uint64("frame_number", latest.Header.FrameNumber),
		zap.Duration("frame_age", frametime.GlobalFrameSince(latest)),
	)

	return nil
}

func (p *GlobalSyncProvider) syncWithPeer(
	ctx context.Context,
	frameNumber uint64,
	peerId []byte,
) error {
	p.engine.logger.Info(
		"polling peer for new frames",
		zap.String("peer_id", peer.ID(peerId).String()),
		zap.Uint64("current_frame", frameNumber),
	)

	info := p.engine.peerInfoManager.GetPeerInfo(peerId)
	if info == nil {
		p.engine.logger.Info(
			"no peer info known yet, skipping sync",
			zap.String("peer", peer.ID(peerId).String()),
		)
		return nil
	}

	if len(info.Reachability) == 0 {
		p.engine.logger.Info(
			"no reachability info known yet, skipping sync",
			zap.String("peer", peer.ID(peerId).String()),
		)
		return nil
	}

	syncTimeout := p.engine.config.Engine.SyncTimeout
	for _, s := range info.Reachability[0].StreamMultiaddrs {
		creds, err := p2p.NewPeerAuthenticator(
			p.engine.logger,
			p.engine.config.P2P,
			nil,
			nil,
			nil,
			nil,
			[][]byte{[]byte(peerId)},
			map[string]channel.AllowedPeerPolicyType{},
			map[string]channel.AllowedPeerPolicyType{},
		).CreateClientTLSCredentials([]byte(peerId))
		if err != nil {
			return errors.Wrap(err, "sync")
		}

		ma, err := multiaddr.StringCast(s)
		if err != nil {
			return errors.Wrap(err, "sync")
		}

		mga, err := mn.ToNetAddr(ma)
		if err != nil {
			return errors.Wrap(err, "sync")
		}

		cc, err := grpc.NewClient(
			mga.String(),
			grpc.WithTransportCredentials(creds),
		)
		if err != nil {
			p.engine.logger.Debug(
				"could not establish direct channel, trying next multiaddr",
				zap.String("peer", peer.ID(peerId).String()),
				zap.String("multiaddr", ma.String()),
				zap.Error(err),
			)
			continue
		}
		defer func() {
			if err := cc.Close(); err != nil {
				p.engine.logger.Error("error while closing connection", zap.Error(err))
			}
		}()

		client := protobufs.NewGlobalServiceClient(cc)
	inner:
		for {
			getCtx, cancelGet := context.WithTimeout(ctx, syncTimeout)
			response, err := client.GetGlobalProposal(
				getCtx,
				&protobufs.GetGlobalProposalRequest{
					FrameNumber: frameNumber,
				},
				// The message size limits are swapped because the server is the one
				// sending the data.
				grpc.MaxCallRecvMsgSize(
					p.engine.config.Engine.SyncMessageLimits.MaxSendMsgSize,
				),
				grpc.MaxCallSendMsgSize(
					p.engine.config.Engine.SyncMessageLimits.MaxRecvMsgSize,
				),
			)
			cancelGet()
			if err != nil {
				p.engine.logger.Debug(
					"could not get frame, trying next multiaddr",
					zap.String("peer", peer.ID(peerId).String()),
					zap.String("multiaddr", ma.String()),
					zap.Error(err),
				)
				break inner
			}

			if response == nil {
				p.engine.logger.Debug(
					"received no response from peer",
					zap.String("peer", peer.ID(peerId).String()),
					zap.String("multiaddr", ma.String()),
					zap.Error(err),
				)
				break inner
			}

			if response.Proposal == nil || response.Proposal.State == nil ||
				response.Proposal.State.Header == nil ||
				response.Proposal.State.Header.FrameNumber != frameNumber {
				p.engine.logger.Debug("received empty response from peer")
				return nil
			}
			if err := response.Proposal.Validate(); err != nil {
				p.engine.logger.Debug(
					"received invalid response from peer",
					zap.Error(err),
				)
				return nil
			}

			p.engine.logger.Info(
				"received new leading frame",
				zap.Uint64("frame_number", response.Proposal.State.Header.FrameNumber),
				zap.Duration(
					"frame_age",
					frametime.GlobalFrameSince(response.Proposal.State),
				),
			)

			if _, err := p.engine.frameProver.VerifyGlobalFrameHeader(
				response.Proposal.State.Header,
				p.engine.blsConstructor,
			); err != nil {
				return errors.Wrap(err, "sync")
			}

			p.engine.globalProposalQueue <- response.Proposal
			frameNumber = frameNumber + 1
		}
	}

	p.engine.logger.Debug(
		"failed to complete sync for all known multiaddrs",
		zap.String("peer", peer.ID(peerId).String()),
	)
	return nil
}

func (p *GlobalSyncProvider) hyperSyncWithProver(
	ctx context.Context,
	prover []byte,
	shardKey tries.ShardKey,
) {
	registry, err := p.engine.signerRegistry.GetKeyRegistryByProver(prover)
	if err == nil && registry != nil && registry.IdentityKey != nil {
		peerKey := registry.IdentityKey
		pubKey, err := crypto.UnmarshalEd448PublicKey(peerKey.KeyValue)
		if err == nil {
			peerId, err := peer.IDFromPublicKey(pubKey)
			if err == nil {
				ch, err := p.engine.pubsub.GetDirectChannel(
					ctx,
					[]byte(peerId),
					"sync",
				)

				if err == nil {
					defer ch.Close()
					client := protobufs.NewHypergraphComparisonServiceClient(ch)
					str, err := client.HyperStream(ctx)
					if err != nil {
						p.engine.logger.Error("error from sync", zap.Error(err))
					} else {
						p.hyperSyncVertexAdds(str, shardKey)
						p.hyperSyncVertexRemoves(str, shardKey)
						p.hyperSyncHyperedgeAdds(str, shardKey)
						p.hyperSyncHyperedgeRemoves(str, shardKey)
					}
				}
			}
		}
	}
}

func (p *GlobalSyncProvider) hyperSyncVertexAdds(
	str protobufs.HypergraphComparisonService_HyperStreamClient,
	shardKey tries.ShardKey,
) {
	err := p.engine.hypergraph.Sync(
		str,
		shardKey,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
	)
	if err != nil {
		p.engine.logger.Error("error from sync", zap.Error(err))
	}
	str.CloseSend()
}

func (p *GlobalSyncProvider) hyperSyncVertexRemoves(
	str protobufs.HypergraphComparisonService_HyperStreamClient,
	shardKey tries.ShardKey,
) {
	err := p.engine.hypergraph.Sync(
		str,
		shardKey,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_REMOVES,
	)
	if err != nil {
		p.engine.logger.Error("error from sync", zap.Error(err))
	}
	str.CloseSend()
}

func (p *GlobalSyncProvider) hyperSyncHyperedgeAdds(
	str protobufs.HypergraphComparisonService_HyperStreamClient,
	shardKey tries.ShardKey,
) {
	err := p.engine.hypergraph.Sync(
		str,
		shardKey,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_ADDS,
	)
	if err != nil {
		p.engine.logger.Error("error from sync", zap.Error(err))
	}
	str.CloseSend()
}

func (p *GlobalSyncProvider) hyperSyncHyperedgeRemoves(
	str protobufs.HypergraphComparisonService_HyperStreamClient,
	shardKey tries.ShardKey,
) {
	err := p.engine.hypergraph.Sync(
		str,
		shardKey,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_REMOVES,
	)
	if err != nil {
		p.engine.logger.Error("error from sync", zap.Error(err))
	}
	str.CloseSend()
}

func (p *GlobalSyncProvider) AddState(
	sourcePeerID []byte,
	frameNumber uint64,
) {
	// Drop if we're within the threshold
	if frameNumber <=
		(*p.engine.forks.FinalizedState().State).Header.FrameNumber {
		p.engine.logger.Debug("dropping stale state for sync")
		return
	}

	// Enqueue if we can, otherwise drop it because we'll catch up
	select {
	case p.queuedStates <- syncRequest{
		frameNumber: frameNumber,
		peerId:      sourcePeerID,
	}:
		p.engine.logger.Debug(
			"enqueued sync request",
			zap.String("peer", peer.ID(sourcePeerID).String()),
			zap.Uint64("enqueued_frame_number", frameNumber),
		)
	default:
		p.engine.logger.Debug("no queue capacity, dropping state for sync")
	}
}
