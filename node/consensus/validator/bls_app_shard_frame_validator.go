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

type BLSAppFrameValidator struct {
	proverRegistry consensus.ProverRegistry
	blsConstructor crypto.BlsConstructor
	frameProver    crypto.FrameProver
	logger         *zap.Logger
}

func NewBLSAppFrameValidator(
	proverRegistry consensus.ProverRegistry,
	blsConstructor crypto.BlsConstructor,
	frameProver crypto.FrameProver,
	logger *zap.Logger,
) *BLSAppFrameValidator {
	return &BLSAppFrameValidator{
		proverRegistry: proverRegistry,
		blsConstructor: blsConstructor,
		frameProver:    frameProver,
		logger:         logger,
	}
}

// Validate implements consensus.AppFrameValidator.
func (b *BLSAppFrameValidator) Validate(
	frame *protobufs.AppShardFrame,
) (bool, error) {
	if frame == nil || frame.Header == nil {
		b.logger.Debug("frame or header is nil")
		return false, nil
	}

	if len(frame.Header.Address) == 0 {
		b.logger.Debug("address is empty")
		return false, nil
	}

	if frame.Header.StateRoots == nil || len(frame.Header.StateRoots) != 4 {
		b.logger.Debug(
			"invalid state roots",
			zap.Int("roots_len", len(frame.Header.StateRoots)),
		)
		return false, nil
	}

	for i, stateRoot := range frame.Header.StateRoots {
		if len(stateRoot) != 74 && len(stateRoot) != 64 {
			b.logger.Debug(
				"invalid state root",
				zap.Int("root_index", i),
				zap.Int("root_len", len(stateRoot)),
			)
			return false, nil
		}
	}

	bits, err := b.frameProver.VerifyFrameHeader(frame.Header, b.blsConstructor)
	isValid := err == nil

	if !isValid {
		b.logger.Debug(
			"frame verification result",
			zap.Bool("is_valid", isValid),
			zap.Error(err),
			zap.Uint64("frame_number", frame.Header.FrameNumber),
			zap.String("address", hex.EncodeToString(frame.Header.Address)),
			zap.String(
				"parent_selector",
				hex.EncodeToString(frame.Header.ParentSelector),
			),
		)
		return false, nil
	}

	if frame.Header.PublicKeySignatureBls48581 != nil {
		provers, err := b.proverRegistry.GetActiveProvers(frame.Header.Address)
		if err != nil {
			b.logger.Error("could not get active provers", zap.Error(err))
			return false, errors.Wrap(err, "validate")
		}

		throwaway, _, err := b.blsConstructor.New()
		if err != nil {
			b.logger.Error("could not generate key", zap.Error(err))
			return false, errors.Wrap(err, "validate")
		}

		activeProverSet := [][]byte{}
		throwawaySet := [][]byte{}
		for i, prover := range provers {
			if slices.Contains(bits, uint8(i)) {
				info := prover
				if err != nil {
					b.logger.Error("could not get prover info", zap.Error(err))
					return false, errors.Wrap(err, "validate")
				}
				activeProverSet = append(activeProverSet, info.PublicKey)
				throwawaySet = append(throwawaySet, throwaway.Public().([]byte))
				continue
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
				zap.String("bitmask", hex.EncodeToString(bits)),
				zap.Error(err),
			)
			return false, errors.Wrap(
				errors.New("could not verify aggregated keys"),
				"validate",
			)
		}
	}

	b.logger.Debug(
		"frame verification result",
		zap.Bool("is_valid", isValid),
		zap.Error(err),
		zap.Uint64("frame_number", frame.Header.FrameNumber),
		zap.String("address", hex.EncodeToString(frame.Header.Address)),
		zap.String(
			"parent_selector",
			hex.EncodeToString(frame.Header.ParentSelector),
		),
	)

	return isValid, err
}

var _ consensus.AppFrameValidator = (*BLSAppFrameValidator)(nil)
