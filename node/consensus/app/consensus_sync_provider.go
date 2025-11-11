package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/frametime"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

const defaultStateQueueCapacity = 10

type syncRequest struct {
	frameNumber uint64
	peerId      []byte
}

// AppSyncProvider implements SyncProvider
type AppSyncProvider struct {
	// TODO(2.1.1+): Refactor out direct use of engine
	engine       *AppConsensusEngine
	queuedStates chan syncRequest
}

func NewAppSyncProvider(
	engine *AppConsensusEngine,
) *AppSyncProvider {
	return &AppSyncProvider{
		engine:       engine,
		queuedStates: make(chan syncRequest, defaultStateQueueCapacity),
	}
}

func (p *AppSyncProvider) Start(
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

func (p *AppSyncProvider) processState(
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

func (p *AppSyncProvider) Synchronize(
	existing **protobufs.AppShardFrame,
	ctx context.Context,
) (<-chan **protobufs.AppShardFrame, <-chan error) {
	dataCh := make(chan **protobufs.AppShardFrame, 1)
	errCh := make(chan error, 1)

	go func() {
		defer close(dataCh)
		defer close(errCh)
		defer func() {
			if r := recover(); r != nil {
				errCh <- errors.Wrap(
					errors.New(fmt.Sprintf("fatal error encountered: %+v", r)),
					"synchronize",
				)
			}
		}()

		// Check if we have a current frame
		p.engine.frameStoreMu.RLock()
		hasFrame := len(p.engine.frameStore) > 0
		p.engine.frameStoreMu.RUnlock()

		if !hasFrame {
			errCh <- errors.New("no frame")
			return
		}

		peerCount := p.engine.pubsub.GetPeerstoreCount()
		requiredPeers := p.engine.config.Engine.MinimumPeersRequired
		if peerCount < requiredPeers {
			p.engine.logger.Info(
				"waiting for minimum peers",
				zap.Int("current", peerCount),
				zap.Int("required", requiredPeers),
			)

			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()

		waitPeers:
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
					if peerCount >= requiredPeers {
						p.engine.logger.Info(
							"minimum peers reached",
							zap.Int("peers", peerCount),
						)
						break waitPeers
					}
				}
			}
		}

		if peerCount < int(p.engine.minimumProvers()) {
			errCh <- errors.Wrap(
				errors.New("minimum provers not reached"),
				"synchronize",
			)
			return
		}

		// We have frames, return the latest one
		p.engine.frameStoreMu.RLock()
		var latestFrame *protobufs.AppShardFrame
		var maxFrameNumber uint64
		for _, frame := range p.engine.frameStore {
			if frame.Header != nil && frame.Header.FrameNumber > maxFrameNumber {
				maxFrameNumber = frame.Header.FrameNumber
				latestFrame = frame
			}
		}
		p.engine.frameStoreMu.RUnlock()

		if latestFrame != nil {
			bits := up2p.GetBloomFilterIndices(p.engine.appAddress, 256, 3)
			l2 := make([]byte, 32)
			copy(l2, p.engine.appAddress[:min(len(p.engine.appAddress), 32)])

			shardKey := tries.ShardKey{
				L1: [3]byte(bits),
				L2: [32]byte(l2),
			}

			shouldHypersync := false
			comm, err := p.engine.hypergraph.GetShardCommits(
				latestFrame.Header.FrameNumber,
				p.engine.appAddress,
			)
			if err != nil {
				p.engine.logger.Error("could not get commits", zap.Error(err))
			} else {
				for i, c := range comm {
					if !bytes.Equal(c, latestFrame.Header.StateRoots[i]) {
						shouldHypersync = true
						break
					}
				}

				if shouldHypersync {
					p.hyperSyncWithProver(latestFrame.Header.Prover, shardKey)
				}
			}
		}

		// TODO(2.1.1): remove this
		if p.engine.config.P2P.Network == 0 &&
			bytes.Equal(p.engine.appAddress[:32], token.QUIL_TOKEN_ADDRESS[:]) {
			// Empty, candidate for snapshot reload
			if p.engine.hypergraph.GetSize(nil, nil).Cmp(big.NewInt(0)) == 0 {
				config := p.engine.config.DB
				cfgPath := config.Path
				coreId := p.engine.coreId
				if coreId > 0 && len(config.WorkerPaths) > int(coreId-1) {
					cfgPath = config.WorkerPaths[coreId-1]
				} else if coreId > 0 {
					cfgPath = fmt.Sprintf(config.WorkerPathPrefix, coreId)
				}
				err := p.downloadSnapshot(
					cfgPath,
					p.engine.config.P2P.Network,
					p.engine.appAddress,
				)
				if err != nil {
					p.engine.logger.Warn(
						"could not perform snapshot reload",
						zap.Error(err),
					)
				}
			}
		}

		err := p.syncWithMesh(ctx)
		if err != nil {
			if latestFrame != nil {
				dataCh <- &latestFrame
			} else if existing != nil {
				dataCh <- existing
			}
			errCh <- err
			return
		}

		if latestFrame != nil {
			p.engine.logger.Info("returning latest frame")
			dataCh <- &latestFrame
		} else if existing != nil {
			p.engine.logger.Info("returning existing frame")
			dataCh <- existing
		}

		syncStatusCheck.WithLabelValues(p.engine.appAddressHex, "synced").Inc()

		errCh <- nil
	}()

	return dataCh, errCh
}

func (p *AppSyncProvider) syncWithMesh(ctx context.Context) error {
	p.engine.logger.Info("synchronizing with peers")

	latest, err := p.engine.appTimeReel.GetHead()
	if err != nil {
		return errors.Wrap(err, "sync")
	}

	peers, err := p.engine.proverRegistry.GetActiveProvers(p.engine.appAddress)
	if len(peers) <= 1 || err != nil {
		p.engine.logger.Info("no peers to sync from")
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

		head, err := p.engine.appTimeReel.GetHead()
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
		zap.Duration("frame_age", frametime.AppFrameSince(latest)),
	)

	return nil
}

func (p *AppSyncProvider) syncWithPeer(
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
	for _, reachability := range info.Reachability {
		if !bytes.Equal(reachability.Filter, p.engine.appAddress) {
			continue
		}
		for _, s := range reachability.StreamMultiaddrs {
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
					p.engine.logger.Error(
						"error while closing connection",
						zap.Error(err),
					)
				}
			}()

			client := protobufs.NewAppShardServiceClient(cc)

		inner:
			for {
				getCtx, cancelGet := context.WithTimeout(ctx, syncTimeout)
				response, err := client.GetAppShardProposal(
					getCtx,
					&protobufs.GetAppShardProposalRequest{
						Filter:      p.engine.appAddress,
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
					p.engine.logger.Debug("received invalid response from peer")
					return nil
				}
				p.engine.logger.Info(
					"received new leading frame",
					zap.Uint64(
						"frame_number",
						response.Proposal.State.Header.FrameNumber,
					),
					zap.Duration(
						"frame_age",
						frametime.AppFrameSince(response.Proposal.State),
					),
				)
				if _, err := p.engine.frameProver.VerifyFrameHeader(
					response.Proposal.State.Header,
					p.engine.blsConstructor,
				); err != nil {
					return errors.Wrap(err, "sync")
				}

				p.engine.appShardProposalQueue <- response.Proposal
				frameNumber = frameNumber + 1
			}
		}
	}

	p.engine.logger.Debug(
		"failed to complete sync for all known multiaddrs",
		zap.String("peer", peer.ID(peerId).String()),
	)
	return nil
}

func (p *AppSyncProvider) AddState(
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

func (p *AppSyncProvider) downloadSnapshot(
	dbPath string,
	network uint8,
	lookupKey []byte,
) error {
	base := "https://frame-snapshots.quilibrium.com"
	keyHex := fmt.Sprintf("%x", lookupKey)

	manifestURL := fmt.Sprintf("%s/%d/%s/manifest", base, network, keyHex)
	resp, err := http.Get(manifestURL)
	if err != nil {
		return errors.Wrap(err, "download snapshot")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.Wrap(
			fmt.Errorf("manifest http status %d", resp.StatusCode),
			"download snapshot",
		)
	}

	type mfLine struct {
		Name string
		Hash string // lowercase hex
	}
	var lines []mfLine

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024) // handle large manifests
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		fields := strings.Fields(raw)
		if len(fields) != 2 {
			return errors.Wrap(
				fmt.Errorf("invalid manifest line: %q", raw),
				"download snapshot",
			)
		}
		name := fields[0]
		hash := strings.ToLower(fields[1])
		// quick sanity check hash looks hex
		if _, err := hex.DecodeString(hash); err != nil || len(hash) != 64 {
			return errors.Wrap(
				fmt.Errorf("invalid sha256 hex in manifest for %s: %q", name, hash),
				"download snapshot",
			)
		}
		lines = append(lines, mfLine{Name: name, Hash: hash})
	}
	if err := sc.Err(); err != nil {
		return errors.Wrap(err, "download snapshot")
	}
	if len(lines) == 0 {
		return errors.Wrap(errors.New("manifest is empty"), "download snapshot")
	}

	snapDir := path.Join(dbPath, "snapshot")
	// Start fresh
	_ = os.RemoveAll(snapDir)
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		return errors.Wrap(err, "download snapshot")
	}

	// Download each file with retries + hash verification
	for _, entry := range lines {
		srcURL := fmt.Sprintf("%s/%d/%s/%s", base, network, keyHex, entry.Name)
		dstPath := filepath.Join(snapDir, entry.Name)

		// ensure parent dir exists (manifest may list nested files like CURRENT,
		// MANIFEST-xxxx, OPTIONS, *.sst)
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
			return errors.Wrap(
				fmt.Errorf("mkdir for %s: %w", dstPath, err),
				"download snapshot",
			)
		}

		if err := downloadWithRetryAndHash(
			srcURL,
			dstPath,
			entry.Hash,
			5,
		); err != nil {
			return errors.Wrap(
				fmt.Errorf("downloading %s failed: %w", entry.Name, err),
				"download snapshot",
			)
		}
	}

	return nil
}

// downloadWithRetryAndHash fetches url, stores in dstPath, verifies
// sha256 == expectedHex, and retries up to retries times. Writes atomically via
// a temporary file.
func downloadWithRetryAndHash(
	url, dstPath, expectedHex string,
	retries int,
) error {
	var lastErr error
	for attempt := 1; attempt <= retries; attempt++ {
		if err := func() error {
			resp, err := http.Get(url)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("http status %d", resp.StatusCode)
			}

			tmp, err := os.CreateTemp(filepath.Dir(dstPath), ".part-*")
			if err != nil {
				return err
			}
			defer func() {
				tmp.Close()
				_ = os.Remove(tmp.Name())
			}()

			h := sha256.New()
			if _, err := io.Copy(io.MultiWriter(tmp, h), resp.Body); err != nil {
				return err
			}

			sumHex := hex.EncodeToString(h.Sum(nil))
			if !strings.EqualFold(sumHex, expectedHex) {
				return fmt.Errorf(
					"hash mismatch for %s: expected %s, got %s",
					url,
					expectedHex,
					sumHex,
				)
			}

			// fsync to be safe before rename
			if err := tmp.Sync(); err != nil {
				return err
			}

			// atomic replace
			if err := os.Rename(tmp.Name(), dstPath); err != nil {
				return err
			}
			return nil
		}(); err != nil {
			lastErr = err
			// simple backoff: 200ms * attempt
			time.Sleep(time.Duration(200*attempt) * time.Millisecond)
			continue
		}
		return nil
	}
	return lastErr
}

func (p *AppSyncProvider) hyperSyncWithProver(
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
					context.Background(),
					[]byte(peerId),
					"sync",
				)

				if err == nil {
					defer ch.Close()
					client := protobufs.NewHypergraphComparisonServiceClient(ch)
					str, err := client.HyperStream(context.Background())
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

func (p *AppSyncProvider) hyperSyncVertexAdds(
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

func (p *AppSyncProvider) hyperSyncVertexRemoves(
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

func (p *AppSyncProvider) hyperSyncHyperedgeAdds(
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

func (p *AppSyncProvider) hyperSyncHyperedgeRemoves(
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
