package global

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// GlobalLeaderProvider implements LeaderProvider
type GlobalLeaderProvider struct {
	engine    *GlobalConsensusEngine
	collected GlobalCollectedCommitments
}

func (p *GlobalLeaderProvider) GetNextLeaders(
	ctx context.Context,
	prior **protobufs.GlobalFrame,
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
	ctx context.Context,
	rank uint64,
	filter []byte,
	priorState models.Identity,
) (**protobufs.GlobalFrame, error) {
	_, err := p.engine.livenessProvider.Collect(ctx)
	if err != nil {
		return nil, models.NewNoVoteErrorf("could not collect: %+w", err)
	}

	timer := prometheus.NewTimer(frameProvingDuration)
	defer timer.ObserveDuration()

	prior, err := p.engine.clockStore.GetLatestGlobalClockFrame()
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
	provers, err := p.engine.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		frameProvingTotal.WithLabelValues("error").Inc()
		return nil, errors.Wrap(err, "prove next state")
	}

	proverIndex := uint8(0)
	found := false
	for i, prover := range provers {
		if bytes.Equal(prover.Address, p.engine.getProverAddress()) {
			proverIndex = uint8(i)
			found = true
			break
		}
	}

	if !found {
		frameProvingTotal.WithLabelValues("error").Inc()
		return nil, models.NewNoVoteErrorf("not a prover")
	}

	p.engine.logger.Info(
		"proving next global state",
		zap.Uint64("frame_number", (*prior).Header.FrameNumber+1),
	)

	// Get proving key
	signer, _, _, _ := p.engine.GetProvingKey(p.engine.config.Engine)
	if signer == nil {
		frameProvingTotal.WithLabelValues("error").Inc()
		return nil, models.NewNoVoteErrorf("not a prover")
	}

	// Get current timestamp and difficulty
	timestamp := time.Now().UnixMilli()
	difficulty := p.engine.difficultyAdjuster.GetNextDifficulty(
		rank,
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
	requestTree := &tries.VectorCommitmentTree{}
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

		id := sha3.Sum256(msgData)
		err := requestTree.Insert(id[:], msgData, nil, big.NewInt(0))
		if err != nil {
			p.engine.logger.Warn(
				"failed to add global request",
				zap.Error(err),
			)
			continue
		}

		requests = append(requests, messageBundle)
	}

	requestRoot := requestTree.Commit(p.engine.inclusionProver, false)

	// Prove the global frame header
	newHeader, err := p.engine.frameProver.ProveGlobalFrameHeader(
		(*prior).Header,
		p.engine.shardCommitments,
		p.engine.proverRoot,
		requestRoot,
		signer,
		timestamp,
		uint32(difficulty),
		proverIndex,
	)
	if err != nil {
		frameProvingTotal.WithLabelValues("error").Inc()
		return nil, errors.Wrap(err, "prove next state")
	}
	newHeader.Prover = p.engine.getProverAddress()
	newHeader.Rank = rank

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

var _ consensus.LeaderProvider[*protobufs.GlobalFrame, GlobalPeerID, GlobalCollectedCommitments] = (*GlobalLeaderProvider)(nil)
