package validator

import (
	"bytes"
	"encoding/hex"
	"slices"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

type BLSGlobalFrameValidator struct {
	proverRegistry consensus.ProverRegistry
	blsConstructor crypto.BlsConstructor
	frameProver    crypto.FrameProver
	logger         *zap.Logger
}

func NewBLSGlobalFrameValidator(
	proverRegistry consensus.ProverRegistry,
	blsConstructor crypto.BlsConstructor,
	frameProver crypto.FrameProver,
	logger *zap.Logger,
) *BLSGlobalFrameValidator {
	return &BLSGlobalFrameValidator{
		proverRegistry: proverRegistry,
		blsConstructor: blsConstructor,
		frameProver:    frameProver,
		logger:         logger,
	}
}

// Validate implements consensus.GlobalFrameValidator.
func (b *BLSGlobalFrameValidator) Validate(
	frame *protobufs.GlobalFrame,
) (bool, error) {
	if frame == nil || frame.Header == nil {
		return false, errors.New("frame or header is nil")
	}

	if len(frame.Header.Output) != 516 {
		return false, errors.Errorf(
			"invalid output length: %d",
			len(frame.Header.Output),
		)
	}

	if frame.Header.FrameNumber == 0 {
		b.logger.Debug("validating genesis frame - no signature required")
		return true, nil
	}

	if frame.Header.PublicKeySignatureBls48581 == nil {
		return false, errors.New("no bls signature")
	}

	sig := frame.Header.PublicKeySignatureBls48581
	if sig.Signature == nil || sig.PublicKey == nil {
		return false, errors.New("signature or public key is nil")
	}

	if sig.Bitmask == nil {
		return false, errors.New("bitmask is nil")
	}

	bits, err := b.frameProver.VerifyGlobalFrameHeader(
		frame.Header,
		b.blsConstructor,
	)
	isValid := err == nil

	if !isValid {
		b.logger.Debug(
			"frame verification failed",
			zap.Error(err),
			zap.Uint64("frame_number", frame.Header.FrameNumber),
			zap.String(
				"parent_selector",
				hex.EncodeToString(frame.Header.ParentSelector),
			),
		)
		return false, errors.Wrap(err, "global frame header verification")
	}

	provers, err := b.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		b.logger.Error("could not get active provers", zap.Error(err))
		return false, errors.Wrap(err, "validate")
	}

	activeProverSet := [][]byte{}
	throwawaySet := [][]byte{}
	for i, prover := range provers {
		if slices.Contains(bits, uint8(i)) {
			info := prover
			activeProverSet = append(activeProverSet, info.PublicKey)
			throwawaySet = append(
				throwawaySet,
				frame.Header.PublicKeySignatureBls48581.Signature,
			)
		}
	}

	aggregate, err := b.blsConstructor.Aggregate(activeProverSet, throwawaySet)
	if err != nil {
		b.logger.Error("could not aggregate keys", zap.Error(err))
		return false, errors.Wrap(err, "validate")
	}

	if !bytes.Equal(
		aggregate.GetAggregatePublicKey(),
		frame.Header.PublicKeySignatureBls48581.PublicKey.KeyValue,
	) {
		b.logger.Error(
			"could not verify aggregated keys",
			zap.String("expected_key", hex.EncodeToString(
				frame.Header.PublicKeySignatureBls48581.PublicKey.KeyValue,
			)),
			zap.String("actual_key", hex.EncodeToString(
				aggregate.GetAggregatePublicKey(),
			)),
			zap.Error(err),
		)
		return false, errors.Wrap(
			errors.New("could not verify aggregated keys"),
			"validate",
		)
	}

	b.logger.Debug(
		"frame verification result",
		zap.Bool("is_valid", isValid),
		zap.Error(err),
		zap.Uint64("frame_number", frame.Header.FrameNumber),
		zap.String(
			"parent_selector",
			hex.EncodeToString(frame.Header.ParentSelector),
		),
	)

	return isValid, err
}

var _ consensus.GlobalFrameValidator = (*BLSGlobalFrameValidator)(nil)
