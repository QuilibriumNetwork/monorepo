package app

import (
	"context"
	"encoding/binary"
	"math/big"
	"slices"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/reward"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
)

// AppLivenessProvider implements LivenessProvider
type AppLivenessProvider struct {
	engine *AppConsensusEngine
}

func (p *AppLivenessProvider) Collect(
	ctx context.Context,
) (CollectedCommitments, error) {
	if p.engine.GetFrame() == nil {
		return CollectedCommitments{}, errors.Wrap(
			errors.New("no frame found"),
			"collect",
		)
	}

	// Prepare mixnet for collecting messages
	err := p.engine.mixnet.PrepareMixnet()
	if err != nil {
		p.engine.logger.Error(
			"error preparing mixnet",
			zap.Error(err),
		)
	}

	// Get messages from mixnet
	mixnetMessages := p.engine.mixnet.GetMessages()

	var state state.State
	state = hgstate.NewHypergraphState(p.engine.hypergraph)

	finalizedMessages := []*protobufs.Message{}

	// Get and clear pending messages
	p.engine.pendingMessagesMu.Lock()
	pendingMessages := p.engine.pendingMessages
	p.engine.pendingMessages = []*protobufs.Message{}
	p.engine.pendingMessagesMu.Unlock()

	for i, message := range slices.Concat(mixnetMessages, pendingMessages) {
		bundle := &protobufs.MessageBundle{}
		if err := bundle.FromCanonicalBytes(message.Payload); err != nil {
			p.engine.logger.Error(
				"invalid message bytes",
				zap.Int("message_index", i),
				zap.Error(err),
			)
			continue
		}

		if err := bundle.Validate(); err != nil {
			p.engine.logger.Error(
				"invalid message",
				zap.Int("message_index", i),
				zap.Error(err),
			)
			continue
		}

		costBasis, err := p.engine.executionManager.GetCost(message.Payload)
		if err != nil {
			p.engine.logger.Error(
				"invalid message",
				zap.Int("message_index", i),
				zap.Error(err),
			)
			continue
		}

		p.engine.currentDifficultyMu.RLock()
		difficulty := uint64(p.engine.currentDifficulty)
		p.engine.currentDifficultyMu.RUnlock()
		baseline := reward.GetBaselineFee(
			difficulty,
			p.engine.hypergraph.GetSize(nil, nil).Uint64(),
			costBasis.Uint64(),
			8000000000,
		)
		baseline.Quo(baseline, costBasis)

		result, err := p.engine.executionManager.ProcessMessage(
			uint64(p.engine.GetFrame().Header.FrameNumber),
			new(big.Int).Mul(
				baseline,
				big.NewInt(int64(p.engine.GetFrame().Header.FeeMultiplierVote)),
			),
			message.Address,
			message.Payload,
			state,
		)
		if err != nil {
			p.engine.logger.Error(
				"could not validate for execution",
				zap.Int("message_index", i),
				zap.Error(err),
			)
			continue
		}

		state = result.State
		finalizedMessages = append(finalizedMessages, message)
	}

	p.engine.logger.Info(
		"collected messages",
		zap.Int("total_message_count", len(mixnetMessages)+len(pendingMessages)),
		zap.Int("valid_message_count", len(finalizedMessages)),
		zap.Uint64(
			"current_frame",
			p.engine.GetFrame().Rank(),
		),
	)

	// Calculate commitment root
	commitment, err := p.engine.calculateRequestsRoot(finalizedMessages)
	if err != nil {
		return CollectedCommitments{}, errors.Wrap(err, "collect")
	}

	commitmentHash := sha3.Sum256(commitment)

	return CollectedCommitments{
		frameNumber:    uint64(p.engine.GetFrame().Header.FrameNumber),
		commitmentHash: commitmentHash[:],
		prover:         p.engine.getProverAddress(),
	}, nil
}

func (p *AppLivenessProvider) SendLiveness(
	prior **protobufs.AppShardFrame,
	collected CollectedCommitments,
	ctx context.Context,
) error {
	// Get prover key
	signer, _, publicKey, _ := p.engine.GetProvingKey(p.engine.config.Engine)
	if publicKey == nil {
		return errors.New("no proving key available for liveness check")
	}

	frameNumber := uint64(0)
	if prior != nil && (*prior).Header != nil {
		frameNumber = (*prior).Header.FrameNumber + 1
	}

	// Create liveness check message
	livenessCheck := &protobufs.ProverLivenessCheck{
		Filter:         p.engine.appAddress,
		FrameNumber:    frameNumber,
		Timestamp:      time.Now().UnixMilli(),
		CommitmentHash: collected.commitmentHash,
	}

	// Sign the message
	signatureData := append(
		p.engine.appAddress,
		binary.BigEndian.AppendUint64(nil, frameNumber)...,
	)
	signatureData = append(
		signatureData,
		binary.BigEndian.AppendUint64(nil, uint64(livenessCheck.Timestamp))...,
	)

	sig, err := signer.SignWithDomain(
		signatureData,
		slices.Concat([]byte("liveness"), p.engine.appAddress),
	)
	if err != nil {
		return errors.Wrap(err, "send liveness")
	}

	proverAddress := p.engine.getAddressFromPublicKey(publicKey)
	livenessCheck.PublicKeySignatureBls48581 = &protobufs.BLS48581AddressedSignature{
		Address:   proverAddress,
		Signature: sig,
	}

	// Serialize using canonical bytes
	data, err := livenessCheck.ToCanonicalBytes()
	if err != nil {
		return errors.Wrap(err, "serialize liveness check")
	}

	if err := p.engine.pubsub.PublishToBitmask(
		p.engine.getConsensusMessageBitmask(),
		data,
	); err != nil {
		return errors.Wrap(err, "send liveness")
	}

	p.engine.logger.Info(
		"sent liveness check",
		zap.Uint64("frame_number", frameNumber),
	)

	return nil
}
