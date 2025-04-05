package data

import (
	"bytes"
	"time"

	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/cas"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/frametime"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

func (
	e *DataClockConsensusEngine,
) GetFrameProverTries() []*tries.RollingFrecencyCritbitTrie {
	e.frameProverTriesMx.RLock()
	frameProverTries := make(
		[]*tries.RollingFrecencyCritbitTrie,
		len(e.frameProverTries),
	)

	for i, trie := range e.frameProverTries {
		newTrie := &tries.RollingFrecencyCritbitTrie{}
		b, err := trie.Serialize()
		if err != nil {
			e.logger.Panic("failed to serialize trie", zap.Error(err))
		}

		err = newTrie.Deserialize(b)
		if err != nil {
			e.logger.Panic("failed to deserialize trie", zap.Error(err))
		}
		frameProverTries[i] = newTrie
	}

	e.frameProverTriesMx.RUnlock()
	return frameProverTries
}

func (e *DataClockConsensusEngine) GetFrameProverTrie(i int) *tries.RollingFrecencyCritbitTrie {
	e.frameProverTriesMx.RLock()
	defer e.frameProverTriesMx.RUnlock()
	newTrie := &tries.RollingFrecencyCritbitTrie{}
	if i < 0 || i >= len(e.frameProverTries) {
		return newTrie
	}
	b, err := e.frameProverTries[i].Serialize()
	if err != nil {
		e.logger.Panic("failed to serialize trie", zap.Error(err))
	}
	if err := newTrie.Deserialize(b); err != nil {
		e.logger.Panic("failed to deserialize trie", zap.Error(err))
	}
	return newTrie
}

func (e *DataClockConsensusEngine) FrameProverTriesContains(
	key []byte,
) bool {
	e.frameProverTriesMx.RLock()
	defer e.frameProverTriesMx.RUnlock()
	for _, trie := range e.frameProverTries {
		if trie.Contains(key) {
			return true
		}
	}
	return false
}

func (e *DataClockConsensusEngine) FrameProverTrieContains(
	i int,
	key []byte,
) bool {
	e.frameProverTriesMx.RLock()
	defer e.frameProverTriesMx.RUnlock()
	if i < 0 || i >= len(e.frameProverTries) {
		return false
	}
	return e.frameProverTries[i].Contains(key)
}

func (e *DataClockConsensusEngine) runFramePruning() {
	defer e.wg.Done()
	// A full prover should _never_ do this
	if e.FrameProverTrieContains(0, e.provingKeyAddress) ||
		e.config.Engine.MaxFrames == -1 || e.config.Engine.FullProver {
		e.logger.Info("frame pruning not enabled")
		return
	}

	if e.config.Engine.MaxFrames < 1000 {
		e.logger.Warn(
			"max frames for pruning too low, pruning disabled",
			zap.Int64("max_frames", e.config.Engine.MaxFrames),
		)
		return
	}

	e.logger.Info("frame pruning enabled, waiting for delay timeout expiry")

	from := uint64(1)
	maxFrames := uint64(e.config.Engine.MaxFrames)
	batchSize := uint64(1000)
outer:
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-time.After(1 * time.Minute):
			head, err := e.dataTimeReel.Head()
			if err != nil {
				e.logger.Panic("failed to get head frame", zap.Error(err))
			}

			if head.FrameNumber <= maxFrames ||
				head.FrameNumber <= application.PROOF_FRAME_SENIORITY_REPAIR+1 {
				continue
			}

			if head.FrameNumber <= maxFrames {
				continue
			}

			to := head.FrameNumber - maxFrames
			for i := from; i < to; i += batchSize {
				start, stop := i, min(i+batchSize, to)
				if err := e.clockStore.DeleteDataClockFrameRange(e.filter, start, stop); err != nil {
					e.logger.Error(
						"failed to prune frames",
						zap.Error(err),
						zap.Uint64("from", start),
						zap.Uint64("to", stop),
					)
					continue outer
				}
				e.logger.Info(
					"pruned frames",
					zap.Uint64("from", start),
					zap.Uint64("to", stop),
				)
				select {
				case <-e.ctx.Done():
					return
				default:
				}
				from = stop
			}
		}
	}
}

func (e *DataClockConsensusEngine) runSync() {
	defer e.wg.Done()
	// small optimization, beacon should never collect for now:
	if e.FrameProverTrieContains(0, e.provingKeyAddress) {
		return
	}

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-e.requestSyncCh:
			if err := e.pubSub.Bootstrap(e.ctx); err != nil {
				e.logger.Error("could not bootstrap", zap.Error(err))
			}
			if err := e.syncWithMesh(); err != nil {
				e.logger.Error("could not sync", zap.Error(err))
			}
		}
	}
}

func (e *DataClockConsensusEngine) runLoop() {
	defer e.wg.Done()
	dataFrameCh := e.dataTimeReel.NewFrameCh()
	runOnce := true
	for {
		peerCount := e.pubSub.GetNetworkPeersCount()
		if peerCount < e.minimumPeersRequired {
			e.logger.Info(
				"waiting for minimum peers",
				zap.Int("peer_count", peerCount),
			)
			select {
			case <-e.ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
		} else {
			latestFrame, err := e.dataTimeReel.Head()
			if err != nil {
				e.logger.Panic("failed to get head frame", zap.Error(err))
			}

			if runOnce {
				if e.FrameProverTrieContains(0, e.provingKeyAddress) {
					dataFrame, err := e.dataTimeReel.Head()
					if err != nil {
						e.logger.Panic("failed to get head frame", zap.Error(err))
					}

					latestFrame = e.processFrame(latestFrame, dataFrame)
				}
				runOnce = false
			}

			select {
			case <-e.ctx.Done():
				return
			case dataFrame := <-dataFrameCh:
				e.validationFilterMx.Lock()
				e.validationFilter = make(map[string]struct{}, len(e.validationFilter))
				e.validationFilterMx.Unlock()
				if e.FrameProverTrieContains(0, e.provingKeyAddress) {
					if err := e.publishProof(dataFrame); err != nil {
						e.logger.Error("could not publish proof", zap.Error(err))
						e.stateMx.Lock()
						if e.state < consensus.EngineStateStopping {
							e.state = consensus.EngineStateCollecting
						}
						e.stateMx.Unlock()
					}
				}
				latestFrame = e.processFrame(latestFrame, dataFrame)
			}
		}
	}
}

func (e *DataClockConsensusEngine) processFrame(
	latestFrame *protobufs.ClockFrame,
	dataFrame *protobufs.ClockFrame,
) *protobufs.ClockFrame {

	e.logger.Info(
		"current frame head",
		zap.Uint64("frame_number", dataFrame.FrameNumber),
		zap.Duration("frame_age", frametime.Since(dataFrame)),
	)
	var err error
	if !e.FrameProverTrieContains(0, e.provingKeyAddress) {
		select {
		case e.requestSyncCh <- struct{}{}:
		default:
		}
	}

	if latestFrame != nil && dataFrame.FrameNumber > latestFrame.FrameNumber {
		latestFrame = dataFrame
	}

	cas.IfLessThanUint64(&e.latestFrameReceived, latestFrame.FrameNumber)
	e.frameProverTriesMx.Lock()
	e.frameProverTries = e.dataTimeReel.GetFrameProverTries()
	e.frameProverTriesMx.Unlock()

	trie := e.GetFrameProverTrie(0)
	selBI, _ := dataFrame.GetSelector()
	sel := make([]byte, 32)
	sel = selBI.FillBytes(sel)

	if bytes.Equal(
		trie.FindNearest(sel).Key,
		e.provingKeyAddress,
	) {
		var nextFrame *protobufs.ClockFrame
		if nextFrame, err = e.prove(dataFrame); err != nil {
			e.logger.Error("could not prove", zap.Error(err))
			e.stateMx.Lock()
			if e.state < consensus.EngineStateStopping {
				e.state = consensus.EngineStateCollecting
			}
			e.stateMx.Unlock()
			return dataFrame
		}

		if _, err := e.dataTimeReel.Insert(e.ctx, nextFrame); err != nil {
			e.logger.Debug("could not insert frame", zap.Error(err))
		}

		return nextFrame
	} else {
		return latestFrame
	}
}
