package global

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// GlobalLeaderProvider implements LeaderProvider
type GlobalLeaderProvider struct {
	engine *GlobalConsensusEngine
}

func (p *GlobalLeaderProvider) GetNextLeaders(
	prior **protobufs.GlobalFrame,
	ctx context.Context,
) ([]GlobalPeerID, error) {
	// Get the parent selector for next prover calculation
	if prior == nil || *prior == nil || (*prior).Header == nil ||
		len((*prior).Header.Output) != 516 {
		return []GlobalPeerID{}, errors.Wrap(
			errors.New("no prior frame"),
			"get next leaders",
		)
	}

	var parentSelector [32]byte
	parentSelectorBI, _ := poseidon.HashBytes((*prior).Header.Output)
	parentSelectorBI.FillBytes(parentSelector[:])

	// Get ordered provers from registry - global filter is nil
	provers, err := p.engine.proverRegistry.GetOrderedProvers(parentSelector, nil)
	if err != nil {
		return []GlobalPeerID{}, errors.Wrap(err, "get next leaders")
	}

	// Convert to GlobalPeerIDs
	leaders := make([]GlobalPeerID, len(provers))
	for i, prover := range provers {
		leaders[i] = GlobalPeerID{ID: prover}
	}

	if len(leaders) > 0 {
		p.engine.logger.Debug(
			"determined next global leaders",
			zap.Int("count", len(leaders)),
			zap.String("first", hex.EncodeToString(leaders[0].ID)),
		)
	}

	return leaders, nil
}

func (p *GlobalLeaderProvider) ProveNextState(
	prior **protobufs.GlobalFrame,
	collected GlobalCollectedCommitments,
	ctx context.Context,
) (**protobufs.GlobalFrame, error) {
	timer := prometheus.NewTimer(frameProvingDuration)
	defer timer.ObserveDuration()

	if prior == nil || *prior == nil {
		frameProvingTotal.WithLabelValues("error").Inc()
		return nil, errors.Wrap(errors.New("nil prior frame"), "prove next state")
	}

	p.engine.logger.Info(
		"proving next global state",
		zap.Uint64("frame_number", (*prior).Header.FrameNumber+1),
	)

	// Get proving key
	signer, _, _, _ := p.engine.GetProvingKey(p.engine.config.Engine)
	if signer == nil {
		frameProvingTotal.WithLabelValues("error").Inc()
		return nil, errors.Wrap(
			errors.New("no proving key available"),
			"prove next state",
		)
	}

	// Get current timestamp and difficulty
	timestamp := time.Now().UnixMilli()
	difficulty := p.engine.difficultyAdjuster.GetNextDifficulty(
		(*prior).Rank()+1,
		timestamp,
	)

	p.engine.currentDifficultyMu.Lock()
	p.engine.logger.Debug(
		"next difficulty for frame",
		zap.Uint32("previous_difficulty", p.engine.currentDifficulty),
		zap.Uint64("next_difficulty", difficulty),
	)
	p.engine.currentDifficulty = uint32(difficulty)
	p.engine.currentDifficultyMu.Unlock()

	// Get prover index
	provers, err := p.engine.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		frameProvingTotal.WithLabelValues("error").Inc()
		return nil, errors.Wrap(err, "prove next state")
	}

	proverIndex := uint8(0)
	for i, prover := range provers {
		if bytes.Equal(prover.Address, p.engine.getProverAddress()) {
			proverIndex = uint8(i)
			break
		}
	}

	// Prove the global frame header
	newHeader, err := p.engine.frameProver.ProveGlobalFrameHeader(
		(*prior).Header,
		p.engine.shardCommitments,
		p.engine.proverRoot,
		signer,
		timestamp,
		uint32(difficulty),
		proverIndex,
	)
	if err != nil {
		frameProvingTotal.WithLabelValues("error").Inc()
		return nil, errors.Wrap(err, "prove next state")
	}

	// Convert collected messages to MessageBundles
	requests := make(
		[]*protobufs.MessageBundle,
		0,
		len(p.engine.collectedMessages),
	)
	p.engine.logger.Debug(
		"including messages",
		zap.Int("message_count", len(p.engine.collectedMessages)),
	)
	for _, msgData := range p.engine.collectedMessages {
		// Check if data is long enough to contain type prefix
		if len(msgData) < 4 {
			p.engine.logger.Warn(
				"collected message too short",
				zap.Int("length", len(msgData)),
			)
			continue
		}

		// Read type prefix from first 4 bytes
		typePrefix := binary.BigEndian.Uint32(msgData[:4])

		// Messages should be MessageBundle type
		if typePrefix != protobufs.MessageBundleType {
			p.engine.logger.Warn(
				"unexpected message type in collected messages",
				zap.Uint32("type", typePrefix),
			)
			continue
		}

		// Deserialize MessageBundle
		messageBundle := &protobufs.MessageBundle{}
		if err := messageBundle.FromCanonicalBytes(msgData); err != nil {
			p.engine.logger.Warn(
				"failed to unmarshal global request",
				zap.Error(err),
			)
			continue
		}

		// Set timestamp if not already set
		if messageBundle.Timestamp == 0 {
			messageBundle.Timestamp = time.Now().UnixMilli()
		}
		requests = append(requests, messageBundle)
	}

	// Create the new global frame with requests
	newFrame := &protobufs.GlobalFrame{
		Header:   newHeader,
		Requests: requests,
	}

	p.engine.logger.Info(
		"included requests in global frame",
		zap.Int("request_count", len(requests)),
	)

	// Update metrics
	frameProvingTotal.WithLabelValues("success").Inc()
	p.engine.lastProvenFrameTimeMu.Lock()
	p.engine.lastProvenFrameTime = time.Now()
	p.engine.lastProvenFrameTimeMu.Unlock()
	currentFrameNumber.Set(float64(newFrame.Header.FrameNumber))

	return &newFrame, nil
}
