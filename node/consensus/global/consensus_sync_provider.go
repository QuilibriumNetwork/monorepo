package global

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/frametime"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// GlobalSyncProvider implements SyncProvider
type GlobalSyncProvider struct {
	engine *GlobalConsensusEngine
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
			p.engine.logger.Info("initializing genesis")
			genesis := p.engine.initializeGenesis()
			dataCh <- &genesis
			errCh <- nil
			return
		}

		err = p.syncWithMesh()
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

func (p *GlobalSyncProvider) syncWithMesh() error {
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

		latest, err = p.syncWithPeer(latest, []byte(peerID))
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
	latest *protobufs.GlobalFrame,
	peerId []byte,
) (*protobufs.GlobalFrame, error) {
	p.engine.logger.Info(
		"polling peer for new frames",
		zap.String("peer_id", peer.ID(peerId).String()),
		zap.Uint64("current_frame", latest.Header.FrameNumber),
	)

	syncTimeout := p.engine.config.Engine.SyncTimeout
	dialCtx, cancelDial := context.WithTimeout(p.engine.ctx, syncTimeout)
	defer cancelDial()
	cc, err := p.engine.pubsub.GetDirectChannel(dialCtx, peerId, "sync")
	if err != nil {
		p.engine.logger.Debug(
			"could not establish direct channel",
			zap.Error(err),
		)
		return latest, errors.Wrap(err, "sync")
	}
	defer func() {
		if err := cc.Close(); err != nil {
			p.engine.logger.Error("error while closing connection", zap.Error(err))
		}
	}()

	client := protobufs.NewGlobalServiceClient(cc)
	for {
		getCtx, cancelGet := context.WithTimeout(p.engine.ctx, syncTimeout)
		response, err := client.GetGlobalFrame(
			getCtx,
			&protobufs.GetGlobalFrameRequest{
				FrameNumber: latest.Header.FrameNumber + 1,
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
				"could not get frame",
				zap.Error(err),
			)
			return latest, errors.Wrap(err, "sync")
		}

		if response == nil {
			p.engine.logger.Debug("received no response from peer")
			return latest, nil
		}

		if response.Frame == nil || response.Frame.Header == nil ||
			response.Frame.Header.FrameNumber != latest.Header.FrameNumber+1 ||
			response.Frame.Header.Timestamp < latest.Header.Timestamp {
			p.engine.logger.Debug("received invalid response from peer")
			return latest, nil
		}
		p.engine.logger.Info(
			"received new leading frame",
			zap.Uint64("frame_number", response.Frame.Header.FrameNumber),
			zap.Duration("frame_age", frametime.GlobalFrameSince(response.Frame)),
		)

		if _, err := p.engine.frameProver.VerifyGlobalFrameHeader(
			response.Frame.Header,
			p.engine.blsConstructor,
		); err != nil {
			return latest, errors.Wrap(err, "sync")
		}

		err = p.engine.globalTimeReel.Insert(p.engine.ctx, response.Frame)
		if err != nil {
			return latest, errors.Wrap(err, "sync")
		}

		latest = response.Frame
	}
}

func (p *GlobalSyncProvider) hyperSyncWithProver(
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
					p.engine.ctx,
					[]byte(peerId),
					"sync",
				)

				if err == nil {
					defer ch.Close()
					client := protobufs.NewHypergraphComparisonServiceClient(ch)
					str, err := client.HyperStream(p.engine.ctx)
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
