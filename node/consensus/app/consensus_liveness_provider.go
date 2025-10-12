package app

import (
	"context"
	"slices"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
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

	mixnetMessages := []*protobufs.Message{}
	currentSet, _ := p.engine.proverRegistry.GetActiveProvers(nil)
	if len(currentSet) >= 9 {
		// Prepare mixnet for collecting messages
		err := p.engine.mixnet.PrepareMixnet()
		if err != nil {
			p.engine.logger.Error(
				"error preparing mixnet",
				zap.Error(err),
			)
		}

		// Get messages from mixnet
		mixnetMessages = p.engine.mixnet.GetMessages()
	}

	finalizedMessages := []*protobufs.Message{}

	// Get and clear pending messages
	p.engine.pendingMessagesMu.Lock()
	pendingMessages := p.engine.pendingMessages
	p.engine.pendingMessages = []*protobufs.Message{}
	p.engine.pendingMessagesMu.Unlock()

	frameNumber := uint64(p.engine.GetFrame().Header.FrameNumber) + 1

	txMap := map[string][][]byte{}
	for i, message := range slices.Concat(mixnetMessages, pendingMessages) {
		err := p.engine.executionManager.ValidateMessage(
			frameNumber,
			message.Address,
			message.Payload,
		)
		if err != nil {
			p.engine.logger.Debug(
				"invalid message",
				zap.Int("message_index", i),
				zap.Error(err),
			)
			continue
		}

		lockedAddrs, err := p.engine.executionManager.Lock(
			frameNumber,
			message.Address,
			message.Payload,
		)
		if err != nil {
			p.engine.logger.Debug(
				"message failed lock",
				zap.Int("message_index", i),
				zap.Error(err),
			)
			continue
		}

		txMap[string(message.Hash)] = lockedAddrs

		finalizedMessages = append(finalizedMessages, message)
	}

	err := p.engine.executionManager.Unlock()
	if err != nil {
		p.engine.logger.Error("could not unlock", zap.Error(err))
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
	commitment, err := p.engine.calculateRequestsRoot(finalizedMessages, txMap)
	if err != nil {
		return CollectedCommitments{}, errors.Wrap(err, "collect")
	}
	return CollectedCommitments{
		frameNumber:    frameNumber,
		commitmentHash: commitment,
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
	signatureData, err := livenessCheck.ConstructSignaturePayload()
	if err != nil {
		return errors.Wrap(err, "send liveness")
	}

	sig, err := signer.SignWithDomain(
		signatureData,
		livenessCheck.GetSignatureDomain(),
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
