package sync

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

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

type AppSyncHooks struct {
	shardAddress []byte
	shardKey     tries.ShardKey
	snapshotPath string
	network      uint8
	tokenShard   bool
}

func NewAppSyncHooks(
	shardAddress []byte,
	snapshotPath string,
	network uint8,
) *AppSyncHooks {
	var shardKey tries.ShardKey
	if len(shardAddress) > 0 {
		l1 := up2p.GetBloomFilterIndices(shardAddress, 256, 3)
		copy(shardKey.L1[:], l1)
		copy(shardKey.L2[:], shardAddress[:min(len(shardAddress), 32)])
	}

	tokenShard := len(shardAddress) >= 32 &&
		bytes.Equal(shardAddress[:32], token.QUIL_TOKEN_ADDRESS[:])

	return &AppSyncHooks{
		shardAddress: append([]byte(nil), shardAddress...),
		shardKey:     shardKey,
		snapshotPath: snapshotPath,
		network:      network,
		tokenShard:   tokenShard,
	}
}

func (h *AppSyncHooks) BeforeMeshSync(
	ctx context.Context,
	p *SyncProvider[*protobufs.AppShardFrame, *protobufs.AppShardProposal],
) {
	h.ensureHyperSync(ctx, p)
	h.ensureSnapshot(p)
}

func (h *AppSyncHooks) ensureHyperSync(
	ctx context.Context,
	p *SyncProvider[*protobufs.AppShardFrame, *protobufs.AppShardProposal],
) {
	if p.forks == nil || len(h.shardAddress) == 0 {
		return
	}

	head := p.forks.FinalizedState()
	if head == nil || head.State == nil {
		return
	}

	frame := *head.State
	if frame == nil || frame.Header == nil {
		return
	}

	stateRoots, err := p.hypergraph.CommitShard(
		frame.Header.FrameNumber,
		h.shardAddress,
	)
	if err != nil {
		p.logger.Debug(
			"could not compute shard commitments for hypersync check",
			zap.Error(err),
		)
		return
	}

	mismatch := len(stateRoots) != len(frame.Header.StateRoots)
	if !mismatch {
		for i := range frame.Header.StateRoots {
			if !bytes.Equal(stateRoots[i], frame.Header.StateRoots[i]) {
				mismatch = true
				break
			}
		}
	}

	if mismatch {
		p.logger.Info(
			"detected divergence between local hypergraph and frame roots, initiating hypersync",
			zap.Uint64("frame_number", frame.Header.FrameNumber),
		)
		p.HyperSync(ctx, frame.Header.Prover, h.shardKey, frame.Header.Address)
	}
}

func (h *AppSyncHooks) ensureSnapshot(
	p *SyncProvider[*protobufs.AppShardFrame, *protobufs.AppShardProposal],
) {
	if !h.shouldAttemptSnapshot(p) {
		return
	}

	if err := downloadSnapshot(h.snapshotPath, h.network, h.shardAddress); err != nil {
		p.logger.Warn("could not perform snapshot reload", zap.Error(err))
		return
	}

	p.logger.Info(
		"snapshot reload completed",
		zap.String("path", h.snapshotPath),
	)
}

func (h *AppSyncHooks) shouldAttemptSnapshot(
	p *SyncProvider[*protobufs.AppShardFrame, *protobufs.AppShardProposal],
) bool {
	if h.snapshotPath == "" || !h.tokenShard || h.network != 0 {
		return false
	}

	size := p.hypergraph.GetSize(nil, nil)
	return size != nil && size.Cmp(big.NewInt(0)) == 0
}

func downloadSnapshot(
	dbPath string,
	network uint8,
	lookupKey []byte,
) error {
	if dbPath == "" {
		return errors.New("snapshot path not configured")
	}

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
		Hash string
	}

	var lines []mfLine
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
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
	_ = os.RemoveAll(snapDir)
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		return errors.Wrap(err, "download snapshot")
	}

	for _, entry := range lines {
		srcURL := fmt.Sprintf("%s/%d/%s/%s", base, network, keyHex, entry.Name)
		dstPath := filepath.Join(snapDir, entry.Name)

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

			if err := tmp.Sync(); err != nil {
				return err
			}

			if err := os.Rename(tmp.Name(), dstPath); err != nil {
				return err
			}
			return nil
		}(); err != nil {
			lastErr = err
			time.Sleep(time.Duration(200*attempt) * time.Millisecond)
			continue
		}
		return nil
	}
	return lastErr
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
