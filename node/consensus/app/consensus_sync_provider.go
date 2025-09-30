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
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/frametime"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

// AppSyncProvider implements SyncProvider
type AppSyncProvider struct {
	engine *AppConsensusEngine
}

func (p *AppSyncProvider) Synchronize(
	existing **protobufs.AppShardFrame,
	ctx context.Context,
) (<-chan **protobufs.AppShardFrame, <-chan error) {
	dataCh := make(chan **protobufs.AppShardFrame, 1)
	errCh := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				errCh <- errors.Wrap(
					errors.New(fmt.Sprintf("fatal error encountered: %+v", r)),
					"synchronize",
				)
			}
		}()
		defer close(dataCh)
		defer close(errCh)

		// Check if we have a current frame
		p.engine.frameStoreMu.RLock()
		hasFrame := len(p.engine.frameStore) > 0
		p.engine.frameStoreMu.RUnlock()

		if !hasFrame {
			// No peers and no frame - we're the first node, initialize genesis
			p.engine.logger.Info("no frame detected, initializing with genesis")
			syncStatusCheck.WithLabelValues(p.engine.appAddressHex, "synced").Inc()
			genesis := p.engine.initializeGenesis()
			dataCh <- &genesis
			errCh <- nil
			return
		}

		peerCount := p.engine.pubsub.GetPeerstoreCount()
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

			shardKey := qcrypto.ShardKey{
				L1: [3]byte(bits),
				L2: [32]byte(l2),
			}

			shouldHypersync := false
			comm := p.engine.hypergraph.Commit()
			for i, c := range comm[shardKey] {
				if !bytes.Equal(c, latestFrame.Header.StateRoots[i]) {
					shouldHypersync = true
					break
				}
			}

			if shouldHypersync {
				p.hyperSyncWithProver(latestFrame.Header.Prover, shardKey)
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

		err := p.syncWithMesh()
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
			dataCh <- &latestFrame
		} else if existing != nil {
			dataCh <- existing
		}

		syncStatusCheck.WithLabelValues(p.engine.appAddressHex, "synced").Inc()

		errCh <- nil
	}()

	return dataCh, errCh
}

func (p *AppSyncProvider) syncWithMesh() error {
	p.engine.logger.Info("synchronizing with peers")

	latest, err := p.engine.appTimeReel.GetHead()
	if err != nil {
		return errors.Wrap(err, "sync")
	}

	peers, err := p.engine.proverRegistry.GetActiveProvers(p.engine.appAddress)
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

		head, err := p.engine.appTimeReel.GetHead()
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
		zap.Duration("frame_age", frametime.AppFrameSince(latest)),
	)

	return nil
}

func (p *AppSyncProvider) syncWithPeer(
	latest *protobufs.AppShardFrame,
	peerId []byte,
) (*protobufs.AppShardFrame, error) {
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

	client := protobufs.NewAppShardServiceClient(cc)
	for {
		getCtx, cancelGet := context.WithTimeout(p.engine.ctx, syncTimeout)
		response, err := client.GetAppShardFrame(
			getCtx,
			&protobufs.GetAppShardFrameRequest{
				Filter:      p.engine.appAddress,
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
			zap.Duration("frame_age", frametime.AppFrameSince(response.Frame)),
		)

		if _, err := p.engine.frameProver.VerifyFrameHeader(
			response.Frame.Header,
			p.engine.blsConstructor,
		); err != nil {
			return latest, errors.Wrap(err, "sync")
		}

		err = p.engine.appTimeReel.Insert(p.engine.ctx, response.Frame)
		if err != nil {
			return latest, errors.Wrap(err, "sync")
		}

		latest = response.Frame
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
