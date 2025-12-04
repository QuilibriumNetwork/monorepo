package global

import (
	"bytes"
	"encoding/hex"
	"errors"

	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

// FrameChainReader captures the minimal subset of clock store functionality
// required for sequential frame verification.
type FrameChainReader interface {
	GetGlobalClockFrame(uint64) (*protobufs.GlobalFrame, error)
	GetGlobalClockFrameCandidate(uint64, []byte) (*protobufs.GlobalFrame, error)
}

// FrameChainChecker verifies whether a proposal's parent chain can be linked
// through stored frame candidates or sealed frames.
type FrameChainChecker struct {
	store  FrameChainReader
	logger *zap.Logger
}

// NewFrameChainChecker creates a new FrameChainChecker.
func NewFrameChainChecker(
	store FrameChainReader,
	logger *zap.Logger,
) *FrameChainChecker {
	if store == nil {
		return nil
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &FrameChainChecker{store: store, logger: logger}
}

// CanProcessSequentialChain returns true if the proposal's ancestors can be
// chained back to an existing sealed frame or the finalized state.
func (c *FrameChainChecker) CanProcessSequentialChain(
	finalized *models.State[*protobufs.GlobalFrame],
	proposal *protobufs.GlobalProposal,
) bool {
	if c == nil || c.store == nil || proposal == nil ||
		proposal.State == nil || proposal.State.Header == nil {
		return false
	}

	parentSelector := proposal.State.Header.ParentSelector
	if len(parentSelector) == 0 {
		return false
	}

	frameNumber := proposal.State.Header.FrameNumber
	if frameNumber == 0 {
		return false
	}

	for frameNumber > 0 && len(parentSelector) > 0 {
		frameNumber--

		if sealed, err := c.store.GetGlobalClockFrame(frameNumber); err == nil &&
			sealed != nil &&
			bytes.Equal([]byte(sealed.Identity()), parentSelector) {
			c.logger.Debug(
				"frame chain linked to sealed frame",
				zap.Uint64("sealed_frame_number", frameNumber),
			)
			return true
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			c.logger.Warn(
				"failed to read sealed frame during chain validation",
				zap.Uint64("frame_number", frameNumber),
				zap.Error(err),
			)
			return false
		}

		candidate, err := c.store.GetGlobalClockFrameCandidate(
			frameNumber,
			parentSelector,
		)
		if err == nil && candidate != nil {
			if candidate.Header == nil ||
				candidate.Header.FrameNumber != frameNumber {
				c.logger.Debug(
					"candidate frame had mismatched header",
					zap.Uint64("frame_number", frameNumber),
				)
				return false
			}
			c.logger.Debug(
				"frame chain matched candidate",
				zap.Uint64("candidate_frame_number", frameNumber),
			)
			parentSelector = candidate.Header.ParentSelector
			continue
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			c.logger.Warn(
				"failed to read candidate frame during chain validation",
				zap.Uint64("frame_number", frameNumber),
				zap.Error(err),
			)
			return false
		}

		if finalized != nil && finalized.State != nil &&
			(*finalized.State).Header != nil &&
			frameNumber == (*finalized.State).Header.FrameNumber &&
			bytes.Equal([]byte(finalized.Identifier), parentSelector) {
			c.logger.Debug(
				"frame chain linked to finalized frame",
				zap.Uint64("finalized_frame_number", frameNumber),
			)
			return true
		}

		c.logger.Debug(
			"missing ancestor frame while validating chain",
			zap.Uint64("missing_frame_number", frameNumber),
			zap.String(
				"expected_parent_selector",
				hex.EncodeToString(parentSelector),
			),
		)
		return false
	}

	return false
}
