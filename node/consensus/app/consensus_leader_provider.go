package app

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// AppLeaderProvider implements LeaderProvider
type AppLeaderProvider struct {
	engine *AppConsensusEngine
}

func (p *AppLeaderProvider) GetNextLeaders(
	prior **protobufs.AppShardFrame,
	ctx context.Context,
) ([]PeerID, error) {
	// Get the parent selector for next prover calculation
	var parentSelector []byte
	if prior != nil && (*prior).Header != nil &&
		len((*prior).Header.Output) >= 32 {
		parentSelectorBI, _ := poseidon.HashBytes((*prior).Header.Output)
		parentSelector = parentSelectorBI.FillBytes(make([]byte, 32))
	} else {
		parentSelector = make([]byte, 32)
	}

	// Get ordered provers from registry
	provers, err := p.engine.proverRegistry.GetOrderedProvers(
		[32]byte(parentSelector),
		p.engine.appAddress,
	)
	if err != nil {
		return nil, errors.Wrap(err, "get ordered provers")
	}

	// Convert to PeerIDs
	leaders := make([]PeerID, len(provers))
	for i, prover := range provers {
		leaders[i] = PeerID{ID: prover}
	}

	if len(leaders) > 0 {
		p.engine.logger.Debug(
			"determined next leaders",
			zap.Int("count", len(leaders)),
			zap.String("first", hex.EncodeToString(leaders[0].ID)),
		)
	}

	return leaders, nil
}

func (p *AppLeaderProvider) ProveNextState(
	prior **protobufs.AppShardFrame,
	collected CollectedCommitments,
	ctx context.Context,
) (**protobufs.AppShardFrame, error) {
	timer := prometheus.NewTimer(frameProvingDuration.WithLabelValues(
		p.engine.appAddressHex,
	))
	defer timer.ObserveDuration()

	if prior == nil || *prior == nil {
		frameProvingTotal.WithLabelValues(p.engine.appAddressHex, "error").Inc()
		return nil, errors.Wrap(errors.New("nil prior frame"), "prove next state")
	}

	// Get pending messages to include in frame
	p.engine.pendingMessagesMu.RLock()
	messages := make([]*protobufs.Message, len(p.engine.pendingMessages))
	copy(messages, p.engine.pendingMessages)
	p.engine.pendingMessagesMu.RUnlock()

	// Clear pending messages after copying
	p.engine.pendingMessagesMu.Lock()
	p.engine.pendingMessages = p.engine.pendingMessages[:0]
	p.engine.pendingMessagesMu.Unlock()

	// Update pending messages metric
	pendingMessagesCount.WithLabelValues(p.engine.appAddressHex).Set(0)

	p.engine.logger.Info(
		"proving next state",
		zap.Int("message_count", len(messages)),
		zap.Uint64("frame_number", (*prior).Header.FrameNumber+1),
	)

	// Prove the frame
	newFrame, err := p.engine.internalProveFrame(messages, (*prior))
	if err != nil {
		frameProvingTotal.WithLabelValues(p.engine.appAddressHex, "error").Inc()
		return nil, errors.Wrap(err, "prove frame")
	}

	p.engine.frameStoreMu.Lock()
	p.engine.frameStore[string(
		p.engine.calculateFrameSelector(newFrame.Header),
	)] = newFrame.Clone().(*protobufs.AppShardFrame)
	p.engine.frameStoreMu.Unlock()

	// Update metrics
	frameProvingTotal.WithLabelValues(p.engine.appAddressHex, "success").Inc()
	p.engine.lastProvenFrameTimeMu.Lock()
	p.engine.lastProvenFrameTime = time.Now()
	p.engine.lastProvenFrameTimeMu.Unlock()
	currentFrameNumber.WithLabelValues(p.engine.appAddressHex).Set(
		float64(newFrame.Header.FrameNumber),
	)

	return &newFrame, nil
}
