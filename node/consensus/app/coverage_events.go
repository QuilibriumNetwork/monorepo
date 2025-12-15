package app

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	typesconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
)

type coverageStreak struct {
	StartFrame uint64
	LastFrame  uint64
	Count      uint64
}

type shardCoverage struct {
	ProverCount     int
	AttestedStorage uint64
	TreeMetadata    []typesconsensus.TreeMetadata
}

func (e *AppConsensusEngine) ensureCoverageThresholds() {
	e.coverageOnce.Do(func() {
		e.coverageMinProvers = e.minimumProvers()
		if e.config.P2P.Network == 0 {
			e.coverageHaltThreshold = 3
		} else {
			if e.coverageMinProvers > 1 {
				e.coverageHaltThreshold = 1
			} else {
				e.coverageHaltThreshold = 0
			}
		}
		e.coverageHaltGrace = 360
	})
}

func (e *AppConsensusEngine) checkShardCoverage(frameNumber uint64) error {
	e.ensureCoverageThresholds()

	coverage, ok := e.getShardCoverage()
	if !ok {
		e.clearCoverageStreak(string(e.appAddress))
		return nil
	}

	key := string(e.appAddress)
	size := big.NewInt(0)
	for _, metadata := range coverage.TreeMetadata {
		size = size.Add(size, new(big.Int).SetUint64(metadata.TotalSize))
	}

	if uint64(coverage.ProverCount) <= e.coverageHaltThreshold &&
		size.Cmp(big.NewInt(0)) > 0 {
		streak, err := e.bumpCoverageStreak(key, frameNumber)
		if err != nil {
			return errors.Wrap(err, "check shard coverage")
		}

		var remaining int64 = int64(e.coverageHaltGrace) - int64(streak.Count)
		if remaining < 0 {
			remaining = 0
		}

		if e.config.P2P.Network == 0 && remaining == 0 {
			e.emitCoverageEvent(
				typesconsensus.ControlEventCoverageHalt,
				&typesconsensus.CoverageEventData{
					ShardAddress:    e.appAddress,
					ProverCount:     coverage.ProverCount,
					RequiredProvers: int(e.coverageMinProvers),
					AttestedStorage: coverage.AttestedStorage,
					TreeMetadata:    coverage.TreeMetadata,
					Message: fmt.Sprintf(
						"Shard %s has only %d provers, halting operations",
						e.appAddressHex,
						coverage.ProverCount,
					),
				},
			)
			return nil
		}

		e.emitCoverageEvent(
			typesconsensus.ControlEventCoverageWarn,
			&typesconsensus.CoverageEventData{
				ShardAddress:    e.appAddress,
				ProverCount:     coverage.ProverCount,
				RequiredProvers: int(e.coverageMinProvers),
				AttestedStorage: coverage.AttestedStorage,
				TreeMetadata:    coverage.TreeMetadata,
				Message: fmt.Sprintf(
					"Critical coverage (<= %d provers). Grace period: %d/%d frames toward halt.",
					e.coverageHaltThreshold,
					streak.Count,
					e.coverageHaltGrace,
				),
			},
		)
		return nil
	}

	e.clearCoverageStreak(key)

	if uint64(coverage.ProverCount) < e.coverageMinProvers {
		e.emitCoverageEvent(
			typesconsensus.ControlEventCoverageWarn,
			&typesconsensus.CoverageEventData{
				ShardAddress:    e.appAddress,
				ProverCount:     coverage.ProverCount,
				RequiredProvers: int(e.coverageMinProvers),
				AttestedStorage: coverage.AttestedStorage,
				TreeMetadata:    coverage.TreeMetadata,
				Message: fmt.Sprintf(
					"Shard %s below minimum coverage: %d/%d provers.",
					e.appAddressHex,
					coverage.ProverCount,
					e.coverageMinProvers,
				),
			},
		)
	}

	return nil
}

func (e *AppConsensusEngine) getShardCoverage() (*shardCoverage, bool) {
	proverCount, err := e.proverRegistry.GetProverCount(e.appAddress)
	if err != nil {
		e.logger.Warn(
			"failed to get prover count for shard",
			zap.String("shard_address", e.appAddressHex),
			zap.Error(err),
		)
		return nil, false
	}
	if proverCount == 0 {
		return nil, false
	}

	activeProvers, err := e.proverRegistry.GetActiveProvers(e.appAddress)
	if err != nil {
		e.logger.Warn(
			"failed to get active provers for shard",
			zap.String("shard_address", e.appAddressHex),
			zap.Error(err),
		)
		return nil, false
	}

	attestedStorage := uint64(0)
	for _, prover := range activeProvers {
		attestedStorage += prover.AvailableStorage
	}

	var treeMetadata []typesconsensus.TreeMetadata
	metadata, err := e.hypergraph.GetMetadataAtKey(e.appAddress)
	if err != nil {
		e.logger.Error("could not obtain metadata for shard", zap.Error(err))
		return nil, false
	}
	for _, entry := range metadata {
		treeMetadata = append(
			treeMetadata,
			typesconsensus.TreeMetadata{
				CommitmentRoot: entry.Commitment,
				TotalSize:      entry.Size,
				TotalLeaves:    entry.LeafCount,
			},
		)
	}

	return &shardCoverage{
		ProverCount:     proverCount,
		AttestedStorage: attestedStorage,
		TreeMetadata:    treeMetadata,
	}, true
}

func (e *AppConsensusEngine) ensureCoverageStreakMap(frameNumber uint64) error {
	if e.lowCoverageStreak != nil {
		return nil
	}

	e.lowCoverageStreak = make(map[string]*coverageStreak)
	coverage, ok := e.getShardCoverage()
	if !ok {
		return nil
	}
	if uint64(coverage.ProverCount) <= e.coverageHaltThreshold {
		e.lowCoverageStreak[string(e.appAddress)] = &coverageStreak{
			StartFrame: frameNumber,
			LastFrame:  frameNumber,
			Count:      1,
		}
	}
	return nil
}

func (e *AppConsensusEngine) bumpCoverageStreak(
	key string,
	frame uint64,
) (*coverageStreak, error) {
	if err := e.ensureCoverageStreakMap(frame); err != nil {
		return nil, errors.Wrap(err, "bump coverage streak")
	}
	streak := e.lowCoverageStreak[key]
	if streak == nil {
		streak = &coverageStreak{
			StartFrame: frame,
			LastFrame:  frame,
			Count:      1,
		}
		e.lowCoverageStreak[key] = streak
		return streak, nil
	}
	if frame > streak.LastFrame {
		streak.Count += (frame - streak.LastFrame)
		streak.LastFrame = frame
	}
	return streak, nil
}

func (e *AppConsensusEngine) clearCoverageStreak(key string) {
	if e.lowCoverageStreak != nil {
		delete(e.lowCoverageStreak, key)
	}
}

func (e *AppConsensusEngine) emitCoverageEvent(
	eventType typesconsensus.ControlEventType,
	data *typesconsensus.CoverageEventData,
) {
	event := typesconsensus.ControlEvent{
		Type: eventType,
		Data: data,
	}

	go e.eventDistributor.Publish(event)

	e.logger.Info(
		"emitted coverage event",
		zap.String("type", fmt.Sprintf("%d", eventType)),
		zap.String("shard_address", hex.EncodeToString(data.ShardAddress)),
		zap.Int("prover_count", data.ProverCount),
		zap.String("message", data.Message),
	)
}
