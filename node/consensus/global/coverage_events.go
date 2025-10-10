package global

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	typesconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
)

// Define coverage thresholds
var (
	minProvers      = uint64(0)
	maxProvers      = uint64(0)
	haltThreshold   = uint64(0)
	haltGraceFrames = uint64(0)
)

func (e *GlobalConsensusEngine) ensureCoverageThresholds() {
	if minProvers != 0 {
		return
	}

	// Network halt if <= 3 provers for mainnet:
	haltThreshold = 3
	if e.config.P2P.Network != 0 {
		haltThreshold = 0
		if e.minimumProvers() > 1 {
			haltThreshold = 1
		}
	}

	// Minimum provers for safe operation
	minProvers = e.minimumProvers()

	// Maximum provers before split consideration
	maxProvers = 32

	// Require sustained critical state for 360 frames
	haltGraceFrames = 360
}

// checkShardCoverage verifies coverage levels for all active shards
func (e *GlobalConsensusEngine) checkShardCoverage(frameNumber uint64) error {
	e.ensureCoverageThresholds()

	// Get shard coverage information from prover registry
	shardCoverageMap := e.getShardCoverageMap()

	// Set up the streak map so we can quickly establish halt conditions on
	// restarts
	err := e.ensureStreakMap(frameNumber)
	if err != nil {
		return errors.Wrap(err, "check shard coverage")
	}

	// Update state summaries metric
	stateSummariesAggregated.Set(float64(len(shardCoverageMap)))

	for shardAddress, coverage := range shardCoverageMap {
		addressLen := len(shardAddress)

		// Validate address length (must be 32-64 bytes)
		if addressLen < 32 || addressLen > 64 {
			e.logger.Error(
				"invalid shard address length",
				zap.Int("length", addressLen),
				zap.String("shard_address", hex.EncodeToString([]byte(shardAddress))),
			)
			continue
		}

		proverCount := uint64(coverage.ProverCount)
		attestedStorage := coverage.AttestedStorage

		size := big.NewInt(0)
		for _, metadata := range coverage.TreeMetadata {
			size = size.Add(size, new(big.Int).SetUint64(metadata.TotalSize))
		}

		e.logger.Debug(
			"checking shard coverage",
			zap.String("shard_address", hex.EncodeToString([]byte(shardAddress))),
			zap.Uint64("prover_count", proverCount),
			zap.Uint64("attested_storage", attestedStorage),
			zap.Uint64("shard_size", size.Uint64()),
		)

		// Check for critical coverage (halt condition)
		if proverCount <= haltThreshold && size.Cmp(big.NewInt(0)) > 0 {
			// Check if this address is blacklisted
			if e.isAddressBlacklisted([]byte(shardAddress)) {
				e.logger.Warn(
					"Shard has insufficient coverage but is blacklisted - skipping halt",
					zap.String("shard_address", hex.EncodeToString([]byte(shardAddress))),
					zap.Uint64("prover_count", proverCount),
					zap.Uint64("halt_threshold", haltThreshold),
				)
				continue
			}

			// Bump the streak – only increments once per frame
			streak, err := e.bumpStreak(shardAddress, frameNumber)
			if err != nil {
				return errors.Wrap(err, "check shard coverage")
			}

			remaining := int(haltGraceFrames - streak.Count)
			if remaining <= 0 {
				e.logger.Error(
					"CRITICAL: Shard has insufficient coverage - triggering network halt",
					zap.String("shard_address", hex.EncodeToString([]byte(shardAddress))),
					zap.Uint64("prover_count", proverCount),
					zap.Uint64("halt_threshold", haltThreshold),
				)

				// Emit halt event
				e.emitCoverageEvent(
					typesconsensus.ControlEventCoverageHalt,
					&typesconsensus.CoverageEventData{
						ShardAddress:    []byte(shardAddress),
						ProverCount:     int(proverCount),
						RequiredProvers: int(minProvers),
						AttestedStorage: attestedStorage,
						TreeMetadata:    coverage.TreeMetadata,
						Message: fmt.Sprintf(
							"Shard has only %d provers, network halt required",
							proverCount,
						),
					},
				)
				continue
			}

			// During grace, warn and include progress toward halt
			e.logger.Warn(
				"Shard at critical coverage — grace window in effect",
				zap.String("shard_address", hex.EncodeToString([]byte(shardAddress))),
				zap.Uint64("prover_count", proverCount),
				zap.Uint64("halt_threshold", haltThreshold),
				zap.Uint64("streak_frames", streak.Count),
				zap.Int("frames_until_halt", remaining),
			)
			e.emitCoverageEvent(
				typesconsensus.ControlEventCoverageWarn,
				&typesconsensus.CoverageEventData{
					ShardAddress:    []byte(shardAddress),
					ProverCount:     int(proverCount),
					RequiredProvers: int(minProvers),
					AttestedStorage: attestedStorage,
					TreeMetadata:    coverage.TreeMetadata,
					Message: fmt.Sprintf(
						"Critical coverage (less than or equal to %d provers). Grace period: %d/%d frames toward halt.",
						haltThreshold, streak.Count, haltGraceFrames,
					),
				},
			)
			continue
		}

		// Not in critical state — clear any ongoing streak
		e.clearStreak(shardAddress)

		// Check for low coverage
		if proverCount < minProvers {
			e.handleLowCoverage([]byte(shardAddress), coverage, minProvers)
		}

		// Check for high coverage (potential split)
		if proverCount > maxProvers {
			e.handleHighCoverage([]byte(shardAddress), coverage, maxProvers)
		}
	}

	return nil
}

// ShardCoverage represents coverage information for a shard
type ShardCoverage struct {
	ProverCount     int
	AttestedStorage uint64
	TreeMetadata    []typesconsensus.TreeMetadata
}

// handleLowCoverage handles shards with insufficient provers
func (e *GlobalConsensusEngine) handleLowCoverage(
	shardAddress []byte,
	coverage *ShardCoverage,
	minProvers uint64,
) {
	addressLen := len(shardAddress)

	// Case 2.a: Full application address (32 bytes)
	if addressLen == 32 {
		e.logger.Warn(
			"shard has low coverage",
			zap.String("shard_address", hex.EncodeToString(shardAddress)),
			zap.Int("prover_count", coverage.ProverCount),
			zap.Uint64("min_provers", minProvers),
		)

		// Emit coverage warning event
		e.emitCoverageEvent(
			typesconsensus.ControlEventCoverageWarn,
			&typesconsensus.CoverageEventData{
				ShardAddress:    shardAddress,
				ProverCount:     coverage.ProverCount,
				RequiredProvers: int(minProvers),
				AttestedStorage: coverage.AttestedStorage,
				TreeMetadata:    coverage.TreeMetadata,
				Message:         "Application shard has low prover coverage",
			},
		)
		return
	}

	// Case 2.b: Longer than application address (> 32 bytes)
	// Check if merge is possible with sibling shards
	appPrefix := shardAddress[:32] // Application prefix
	siblingShards := e.findSiblingShards(appPrefix, shardAddress)

	if len(siblingShards) > 0 {
		// Calculate total storage across siblings
		totalStorage := coverage.AttestedStorage
		totalProvers := coverage.ProverCount
		allShards := append([][]byte{shardAddress}, siblingShards...)

		for _, sibling := range siblingShards {
			if sibCoverage, exists := e.getShardCoverage(sibling); exists {
				totalStorage += sibCoverage.AttestedStorage
				totalProvers += sibCoverage.ProverCount
			}
		}

		// Check if siblings have sufficient storage to handle merge
		requiredStorage := e.calculateRequiredStorage(allShards)

		if totalStorage >= requiredStorage {
			// Case 2.b.i: Merge is possible
			e.logger.Info(
				"shards eligible for merge",
				zap.String("shard_address", hex.EncodeToString(shardAddress)),
				zap.Int("sibling_count", len(siblingShards)),
				zap.Uint64("total_storage", totalStorage),
				zap.Uint64("required_storage", requiredStorage),
			)

			// Emit merge eligible event
			e.emitMergeEvent(
				&typesconsensus.ShardMergeEventData{
					ShardAddresses:  allShards,
					TotalProvers:    totalProvers,
					AttestedStorage: totalStorage,
					RequiredStorage: requiredStorage,
				},
			)
		} else {
			// Case 2.b.ii: Insufficient storage for merge
			e.logger.Warn(
				"shard has low coverage, merge not possible due to insufficient storage",
				zap.String("shard_address", hex.EncodeToString(shardAddress)),
				zap.Int("prover_count", coverage.ProverCount),
				zap.Uint64("total_storage", totalStorage),
				zap.Uint64("required_storage", requiredStorage),
			)

			// Emit coverage warning event
			e.emitCoverageEvent(
				typesconsensus.ControlEventCoverageWarn,
				&typesconsensus.CoverageEventData{
					ShardAddress:    shardAddress,
					ProverCount:     coverage.ProverCount,
					RequiredProvers: int(minProvers),
					AttestedStorage: coverage.AttestedStorage,
					TreeMetadata:    coverage.TreeMetadata,
					Message:         "shard has low coverage and cannot be merged due to insufficient storage",
				},
			)
		}
	} else {
		// No siblings found, emit warning
		e.emitCoverageEvent(
			typesconsensus.ControlEventCoverageWarn,
			&typesconsensus.CoverageEventData{
				ShardAddress:    shardAddress,
				ProverCount:     coverage.ProverCount,
				RequiredProvers: int(minProvers),
				AttestedStorage: coverage.AttestedStorage,
				TreeMetadata:    coverage.TreeMetadata,
				Message:         "Shard has low coverage and no siblings for merge",
			},
		)
	}
}

// handleHighCoverage handles shards with too many provers
func (e *GlobalConsensusEngine) handleHighCoverage(
	shardAddress []byte,
	coverage *ShardCoverage,
	maxProvers uint64,
) {
	addressLen := len(shardAddress)

	// Case 3.a: Not a full app+data address (< 64 bytes)
	if addressLen < 64 {
		// Check if there's space to split
		availableAddressSpace := e.calculateAvailableAddressSpace(shardAddress)

		if availableAddressSpace > 0 {
			// Case 3.a.i: Split is possible
			proposedShards := e.proposeShardSplit(shardAddress, coverage.ProverCount)

			e.logger.Info(
				"shard eligible for split",
				zap.String("shard_address", hex.EncodeToString(shardAddress)),
				zap.Int("prover_count", coverage.ProverCount),
				zap.Int("proposed_shard_count", len(proposedShards)),
			)

			// Emit split eligible event
			e.emitSplitEvent(&typesconsensus.ShardSplitEventData{
				ShardAddress:    shardAddress,
				ProverCount:     coverage.ProverCount,
				AttestedStorage: coverage.AttestedStorage,
				ProposedShards:  proposedShards,
			})
		} else {
			// Case 3.a.ii: No space to split, do nothing
			e.logger.Debug(
				"Shard has high prover count but cannot be split (no address space)",
				zap.String("shard_address", hex.EncodeToString(shardAddress)),
				zap.Int("prover_count", coverage.ProverCount),
			)
		}
	} else {
		// Already at maximum address length (64 bytes), cannot split further
		e.logger.Debug(
			"Shard has high prover count but cannot be split (max address length)",
			zap.String("shard_address", hex.EncodeToString(shardAddress)),
			zap.Int("prover_count", coverage.ProverCount),
		)
	}
}

func (e *GlobalConsensusEngine) getShardCoverageMap() map[string]*ShardCoverage {
	// Get all active app shard provers from the registry
	coverageMap := make(map[string]*ShardCoverage)

	// Get all app shard provers (provers with filters)
	allProvers, err := e.proverRegistry.GetAllActiveAppShardProvers()
	if err != nil {
		e.logger.Error("failed to get active app shard provers", zap.Error(err))
		return coverageMap
	}

	// Build a map of shards and their provers
	shardProvers := make(map[string][]*typesconsensus.ProverInfo)
	for _, prover := range allProvers {
		// Check which shards this prover is assigned to
		for _, allocation := range prover.Allocations {
			shardKey := string(allocation.ConfirmationFilter)
			shardProvers[shardKey] = append(shardProvers[shardKey], prover)
		}
	}

	// For each shard, build coverage information
	for shardAddress, provers := range shardProvers {
		proverCount := len(provers)

		// Calculate attested storage from prover data
		attestedStorage := uint64(0)
		for _, prover := range provers {
			attestedStorage += prover.AvailableStorage
		}

		// Get tree metadata from hypergraph
		var treeMetadata []typesconsensus.TreeMetadata
		metadata, err := e.hypergraph.GetMetadataAtKey([]byte(shardAddress))
		if err != nil {
			e.logger.Error("could not obtain metadata for path", zap.Error(err))
			return nil
		}
		for _, metadata := range metadata {
			treeMetadata = append(treeMetadata, typesconsensus.TreeMetadata{
				CommitmentRoot: metadata.Commitment,
				TotalSize:      metadata.Size,
				TotalLeaves:    metadata.LeafCount,
			})
		}

		coverageMap[shardAddress] = &ShardCoverage{
			ProverCount:     proverCount,
			AttestedStorage: attestedStorage,
			TreeMetadata:    treeMetadata,
		}
	}

	return coverageMap
}

func (e *GlobalConsensusEngine) getShardCoverage(shardAddress []byte) (
	*ShardCoverage,
	bool,
) {
	// Query prover registry for specific shard coverage
	proverCount, err := e.proverRegistry.GetProverCount(shardAddress)
	if err != nil {
		e.logger.Debug(
			"failed to get prover count for shard",
			zap.String("shard_address", hex.EncodeToString(shardAddress)),
			zap.Error(err),
		)
		return nil, false
	}

	// If no provers, shard doesn't exist
	if proverCount == 0 {
		return nil, false
	}

	// Get active provers for this shard to calculate storage
	activeProvers, err := e.proverRegistry.GetActiveProvers(shardAddress)
	if err != nil {
		e.logger.Warn(
			"failed to get active provers for shard",
			zap.String("shard_address", hex.EncodeToString(shardAddress)),
			zap.Error(err),
		)
		return nil, false
	}

	// Calculate attested storage from prover data
	attestedStorage := uint64(0)
	for _, prover := range activeProvers {
		attestedStorage += prover.AvailableStorage
	}

	// Get tree metadata from hypergraph
	var treeMetadata []typesconsensus.TreeMetadata

	metadata, err := e.hypergraph.GetMetadataAtKey(shardAddress)
	if err != nil {
		e.logger.Error("could not obtain metadata for path", zap.Error(err))
		return nil, false
	}
	for _, metadata := range metadata {
		treeMetadata = append(treeMetadata, typesconsensus.TreeMetadata{
			CommitmentRoot: metadata.Commitment,
			TotalSize:      metadata.Size,
			TotalLeaves:    metadata.LeafCount,
		})
	}

	coverage := &ShardCoverage{
		ProverCount:     proverCount,
		AttestedStorage: attestedStorage,
		TreeMetadata:    treeMetadata,
	}

	return coverage, true
}

func (e *GlobalConsensusEngine) findSiblingShards(
	appPrefix, shardAddress []byte,
) [][]byte {
	// Find shards with same app prefix but different suffixes
	var siblings [][]byte

	// Get all active shards from coverage map
	coverageMap := e.getShardCoverageMap()

	for shardKey := range coverageMap {
		shardBytes := []byte(shardKey)

		// Skip self
		if bytes.Equal(shardBytes, shardAddress) {
			continue
		}

		// Check if it has the same app prefix (first 32 bytes)
		if len(shardBytes) >= 32 && bytes.Equal(shardBytes[:32], appPrefix) {
			siblings = append(siblings, shardBytes)
		}
	}

	e.logger.Debug(
		"found sibling shards",
		zap.String("app_prefix", hex.EncodeToString(appPrefix)),
		zap.Int("sibling_count", len(siblings)),
	)

	return siblings
}

func (e *GlobalConsensusEngine) calculateRequiredStorage(
	shards [][]byte,
) uint64 {
	// Calculate total storage needed for these shards
	totalStorage := uint64(0)
	for _, shard := range shards {
		coverage, exists := e.getShardCoverage(shard)
		if exists && len(coverage.TreeMetadata) > 0 {
			totalStorage += coverage.TreeMetadata[0].TotalSize
		}
	}

	return totalStorage
}

func (e *GlobalConsensusEngine) calculateAvailableAddressSpace(
	shardAddress []byte,
) int {
	// Calculate how many more bytes can be added to address for splitting
	if len(shardAddress) >= 64 {
		return 0
	}
	return 64 - len(shardAddress)
}

func (e *GlobalConsensusEngine) proposeShardSplit(
	shardAddress []byte,
	proverCount int,
) [][]byte {
	// Propose how to split the shard address space
	availableSpace := e.calculateAvailableAddressSpace(shardAddress)
	if availableSpace == 0 {
		return nil
	}

	// Determine split factor based on prover count
	// For every 16 provers over 32, we can do another split
	splitFactor := 2
	if proverCount > 48 {
		splitFactor = 4
	}
	if proverCount > 64 && availableSpace >= 2 {
		splitFactor = 8
	}

	// Create proposed shards
	proposedShards := make([][]byte, 0, splitFactor)

	if splitFactor == 2 {
		// Binary split
		shard1 := append(append([]byte{}, shardAddress...), 0x00)
		shard2 := append(append([]byte{}, shardAddress...), 0x80)
		proposedShards = append(proposedShards, shard1, shard2)
	} else if splitFactor == 4 {
		// Quaternary split
		for i := 0; i < 4; i++ {
			shard := append(append([]byte{}, shardAddress...), byte(i*64))
			proposedShards = append(proposedShards, shard)
		}
	} else if splitFactor == 8 && availableSpace >= 2 {
		// Octal split with 2-byte suffix
		for i := 0; i < 8; i++ {
			shard := append(append([]byte{}, shardAddress...), byte(i*32), 0x00)
			proposedShards = append(proposedShards, shard)
		}
	}

	e.logger.Debug(
		"proposed shard split",
		zap.String("original_shard", hex.EncodeToString(shardAddress)),
		zap.Int("split_factor", splitFactor),
		zap.Int("proposed_count", len(proposedShards)),
	)

	return proposedShards
}

func (e *GlobalConsensusEngine) ensureStreakMap(frameNumber uint64) error {
	if e.lowCoverageStreak != nil {
		return nil
	}

	e.logger.Debug("ensuring streak map")
	e.lowCoverageStreak = make(map[string]*coverageStreak)

	info, err := e.proverRegistry.GetAllActiveAppShardProvers()
	if err != nil {
		e.logger.Error(
			"could not retrieve active app shard provers",
			zap.Error(err),
		)
		return errors.Wrap(err, "ensure streak map")
	}

	effectiveCoverage := map[string]int{}
	lastFrame := map[string]uint64{}

	for _, i := range info {
		for _, allocation := range i.Allocations {
			if _, ok := effectiveCoverage[string(allocation.ConfirmationFilter)]; !ok {
				effectiveCoverage[string(allocation.ConfirmationFilter)] = 0
				lastFrame[string(allocation.ConfirmationFilter)] =
					allocation.LastActiveFrameNumber
			}

			if allocation.Status == typesconsensus.ProverStatusActive {
				effectiveCoverage[string(allocation.ConfirmationFilter)]++
				lastFrame[string(allocation.ConfirmationFilter)] = max(
					lastFrame[string(allocation.ConfirmationFilter)],
					allocation.LastActiveFrameNumber,
				)
			}
		}
	}

	for shardKey, coverage := range effectiveCoverage {
		if coverage <= int(haltThreshold) {
			e.lowCoverageStreak[shardKey] = &coverageStreak{
				StartFrame: lastFrame[shardKey],
				LastFrame:  frameNumber,
				Count:      frameNumber - lastFrame[shardKey],
			}
		}
	}

	return nil
}

func (e *GlobalConsensusEngine) bumpStreak(
	shardKey string,
	frame uint64,
) (*coverageStreak, error) {
	err := e.ensureStreakMap(frame)
	if err != nil {
		return nil, errors.Wrap(err, "bump streak")
	}

	s := e.lowCoverageStreak[shardKey]
	if s == nil {
		s = &coverageStreak{StartFrame: frame, LastFrame: frame, Count: 1}
		e.lowCoverageStreak[shardKey] = s
		return s, nil
	}

	// Only increment if we advanced frames, prevents double counting within the
	// same frame due to single-slot fork choice
	if frame > s.LastFrame {
		s.Count += (frame - s.LastFrame)
		s.LastFrame = frame
	}
	return s, nil
}

func (e *GlobalConsensusEngine) clearStreak(shardKey string) {
	if e.lowCoverageStreak != nil {
		delete(e.lowCoverageStreak, shardKey)
	}
}
