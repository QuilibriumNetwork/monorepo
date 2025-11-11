package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// AppLeaderProvider implements LeaderProvider
type AppLeaderProvider struct {
	engine *AppConsensusEngine
}

func (p *AppLeaderProvider) GetNextLeaders(
	ctx context.Context,
	prior **protobufs.AppShardFrame,
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
	ctx context.Context,
	rank uint64,
	filter []byte,
	priorState models.Identity,
) (**protobufs.AppShardFrame, error) {
	timer := prometheus.NewTimer(frameProvingDuration.WithLabelValues(
		p.engine.appAddressHex,
	))
	defer timer.ObserveDuration()

	prior, _, err := p.engine.clockStore.GetLatestShardClockFrame(
		p.engine.appAddress,
	)
	if err != nil {
		frameProvingTotal.WithLabelValues("error").Inc()
		return nil, models.NewNoVoteErrorf("could not collect: %+w", err)
	}

	if prior == nil {
		frameProvingTotal.WithLabelValues("error").Inc()
		return nil, models.NewNoVoteErrorf("missing prior frame")
	}

	if prior.Identity() != priorState {
		frameProvingTotal.WithLabelValues("error").Inc()
		return nil, models.NewNoVoteErrorf(
			"building on fork or needs sync: frame %d, rank %d, parent_id: %x, asked: rank %d, id: %x",
			prior.Header.FrameNumber,
			prior.Header.Rank,
			prior.Header.ParentSelector,
			rank,
			priorState,
		)
	}

	// Get prover index
	provers, err := p.engine.proverRegistry.GetActiveProvers(p.engine.appAddress)
	if err != nil {
		frameProvingTotal.WithLabelValues("error").Inc()
		return nil, errors.Wrap(err, "prove next state")
	}

	found := false
	for _, prover := range provers {
		if bytes.Equal(prover.Address, p.engine.getProverAddress()) {
			found = true
			break
		}
	}

	if !found {
		frameProvingTotal.WithLabelValues("error").Inc()
		return nil, models.NewNoVoteErrorf("not a prover")
	}

	// Get collected messages to include in frame
	p.engine.provingMessagesMu.Lock()
	messages := make([]*protobufs.Message, len(p.engine.provingMessages))
	copy(messages, p.engine.provingMessages)
	p.engine.provingMessages = []*protobufs.Message{}
	p.engine.provingMessagesMu.Unlock()

	if len(messages) == 0 {
		p.engine.collectedMessagesMu.Lock()
		if len(p.engine.collectedMessages) > 0 {
			messages = make([]*protobufs.Message, len(p.engine.collectedMessages))
			copy(messages, p.engine.collectedMessages)
			p.engine.collectedMessages = []*protobufs.Message{}
		}
		p.engine.collectedMessagesMu.Unlock()
	}

	// Update pending messages metric
	pendingMessagesCount.WithLabelValues(p.engine.appAddressHex).Set(0)

	p.engine.logger.Info(
		"proving next state",
		zap.Int("message_count", len(messages)),
		zap.Uint64("frame_number", (*prior).Header.FrameNumber+1),
	)

	// Prove the frame
	newFrame, err := p.engine.internalProveFrame(rank, messages, prior)
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

var _ consensus.LeaderProvider[
	*protobufs.AppShardFrame,
	PeerID,
	CollectedCommitments,
] = (*AppLeaderProvider)(nil)
