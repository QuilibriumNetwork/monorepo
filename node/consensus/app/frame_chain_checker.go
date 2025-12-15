package app

import (
	"bytes"
	"encoding/hex"

	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

type AppFrameChainReader interface {
	GetShardClockFrame(
		filter []byte,
		frameNumber uint64,
		truncate bool,
	) (*protobufs.AppShardFrame, error)
	GetStagedShardClockFrame(
		filter []byte,
		frameNumber uint64,
		parentSelector []byte,
		truncate bool,
	) (*protobufs.AppShardFrame, error)
}

type AppFrameChainChecker struct {
	store  AppFrameChainReader
	filter []byte
	logger *zap.Logger
}

func NewAppFrameChainChecker(
	store store.ClockStore,
	logger *zap.Logger,
	filter []byte,
) *AppFrameChainChecker {
	if store == nil {
		return nil
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &AppFrameChainChecker{
		store:  appFrameChainStoreAdapter{store: store},
		filter: filter, // buildutils:allow-slice-alias slice is static
		logger: logger,
	}
}

func (c *AppFrameChainChecker) CanProcessSequentialChain(
	finalized *models.State[*protobufs.AppShardFrame],
	proposal *protobufs.AppShardProposal,
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
		sealed, err := c.store.GetShardClockFrame(c.filter, frameNumber, false)
		if err == nil && sealed != nil &&
			bytes.Equal([]byte(sealed.Identity()), parentSelector) {
			c.logger.Debug(
				"app frame chain linked to sealed frame",
				zap.Uint64("sealed_frame_number", frameNumber),
			)
			return true
		}

		candidate, err := c.store.GetStagedShardClockFrame(
			c.filter,
			frameNumber,
			parentSelector,
			false,
		)
		if err == nil && candidate != nil {
			parentSelector = candidate.Header.ParentSelector
			// keep walking
			continue
		}

		if finalized != nil && finalized.State != nil &&
			(*finalized.State).Header != nil &&
			frameNumber == (*finalized.State).Header.FrameNumber &&
			bytes.Equal([]byte(finalized.Identifier), parentSelector) {
			c.logger.Debug(
				"app frame chain linked to finalized frame",
				zap.Uint64("finalized_frame_number", frameNumber),
			)
			return true
		}

		c.logger.Debug(
			"missing app ancestor frame while validating chain",
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

type appFrameChainStoreAdapter struct {
	store store.ClockStore
}

func (a appFrameChainStoreAdapter) GetShardClockFrame(
	filter []byte,
	frameNumber uint64,
	truncate bool,
) (*protobufs.AppShardFrame, error) {
	frame, _, err := a.store.GetShardClockFrame(filter, frameNumber, truncate)
	return frame, err
}

func (a appFrameChainStoreAdapter) GetStagedShardClockFrame(
	filter []byte,
	frameNumber uint64,
	parentSelector []byte,
	truncate bool,
) (*protobufs.AppShardFrame, error) {
	return a.store.GetStagedShardClockFrame(
		filter,
		frameNumber,
		parentSelector,
		truncate,
	)
}
