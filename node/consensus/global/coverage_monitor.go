package global

// Coverage monitoring: shard coverage checks, halt detection, split/merge events, blacklist management, and event emission.

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	globalintrinsics "source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	typesconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	typeskeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

// CoverageMonitor encapsulates all shard coverage monitoring state and logic.
type CoverageMonitor struct {
	logger           *zap.Logger
	config           *config.Config
	proverRegistry   typesconsensus.ProverRegistry
	hypergraph       hypergraph.Hypergraph
	eventDistributor typesconsensus.EventDistributor
	keyManager       typeskeys.KeyManager
	shardsStore      store.ShardsStore

	// Owned state (moved from engine)
	coverageCheckInProgress atomic.Bool
	coverageWg              sync.WaitGroup
	lowCoverageStreak       map[string]*coverageStreak
	lowCoverageStreakMu     sync.Mutex
	lastShardActionFrame    map[string]uint64
	lastShardActionFrameMu  sync.Mutex
	blacklistMap            map[string]bool
	blacklistMu             sync.RWMutex

	// Coverage thresholds (were package-level vars)
	minProvers      uint64
	maxProvers      uint64
	haltThreshold   uint64
	haltGraceFrames uint64

	// Callbacks for engine operations the monitor needs
	getProverAddress     func() []byte
	getLastObservedFrame func() uint64
	getProverOnlyMode    func() *atomic.Bool
	publishProverMessage func([]byte) error
	shutdownSignal       func() <-chan struct{}
	minimumProvers       func() uint64
}

// NewCoverageMonitor creates a new CoverageMonitor.
func NewCoverageMonitor(
	logger *zap.Logger,
	cfg *config.Config,
	proverRegistry typesconsensus.ProverRegistry,
	hg hypergraph.Hypergraph,
	eventDistributor typesconsensus.EventDistributor,
	keyManager typeskeys.KeyManager,
	shardsStore store.ShardsStore,
) *CoverageMonitor {
	return &CoverageMonitor{
		logger:               logger,
		config:               cfg,
		proverRegistry:       proverRegistry,
		hypergraph:           hg,
		eventDistributor:     eventDistributor,
		keyManager:           keyManager,
		shardsStore:          shardsStore,
		lastShardActionFrame: make(map[string]uint64),
		blacklistMap:         make(map[string]bool),
		// lowCoverageStreak intentionally left nil so ensureStreakMap
		// populates it from prover data on first use.
	}
}

func (c *CoverageMonitor) ensureCoverageThresholds() {
	if c.minProvers != 0 {
		return
	}

	// Network halt if <= 3 provers for mainnet:
	c.haltThreshold = 3
	if c.config.P2P.Network != 0 {
		c.haltThreshold = 0
		if c.minimumProvers() > 1 {
			c.haltThreshold = 1
		}
	}

	// Minimum provers for safe operation
	c.minProvers = c.minimumProvers()

	// Maximum provers before split consideration
	c.maxProvers = 32

	// Require sustained critical state for 360 frames
	c.haltGraceFrames = 360
}

// triggerCoverageCheckAsync starts a coverage check in a goroutine if one is
// not already in progress. This prevents blocking the event processing loop.
// frameProver is the address of the prover who produced the triggering frame;
// only that prover will emit split/merge messages.
func (c *CoverageMonitor) triggerCoverageCheckAsync(
	frameNumber uint64,
	frameProver []byte,
) {
	// Skip if a coverage check is already in progress
	if !c.coverageCheckInProgress.CompareAndSwap(false, true) {
		c.logger.Debug(
			"skipping coverage check, one already in progress",
			zap.Uint64("frame_number", frameNumber),
		)
		return
	}

	c.coverageWg.Add(1)
	go func() {
		defer c.coverageWg.Done()
		defer c.coverageCheckInProgress.Store(false)

		// Bail immediately if shutdown is already in progress to avoid
		// blocking Stop() on hg.mu (which may be held by a sync or commit).
		select {
		case <-c.shutdownSignal():
			return
		default:
		}

		if err := c.checkShardCoverage(frameNumber, frameProver); err != nil {
			c.logger.Error("failed to check shard coverage", zap.Error(err))
		}
	}()
}

// checkShardCoverage verifies coverage levels for all active shards.
// frameProver is the address of the prover who produced the triggering frame.
func (c *CoverageMonitor) checkShardCoverage(
	frameNumber uint64,
	frameProver []byte,
) error {
	c.ensureCoverageThresholds()

	// Get shard coverage information from prover registry
	shardCoverageMap := c.getShardCoverageMap()

	// Set up the streak map so we can quickly establish halt conditions on
	// restarts
	c.lowCoverageStreakMu.Lock()
	err := c.ensureStreakMap(frameNumber)
	if err != nil {
		c.lowCoverageStreakMu.Unlock()
		return errors.Wrap(err, "check shard coverage")
	}
	c.lowCoverageStreakMu.Unlock()

	// Update state summaries metric
	stateSummariesAggregated.Set(float64(len(shardCoverageMap)))

	// Collect all merge-eligible shard groups to emit as a single bulk event
	var allMergeGroups []typesconsensus.ShardMergeEventData

	for shardAddress, coverage := range shardCoverageMap {
		addressLen := len(shardAddress)

		// Validate address length (must be 32-64 bytes)
		if addressLen < 32 || addressLen > 64 {
			c.logger.Error(
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

		c.logger.Debug(
			"checking shard coverage",
			zap.String("shard_address", hex.EncodeToString([]byte(shardAddress))),
			zap.Uint64("prover_count", proverCount),
			zap.Uint64("attested_storage", attestedStorage),
			zap.Uint64("shard_size", size.Uint64()),
		)

		// Check for critical coverage (halt condition)
		if proverCount <= c.haltThreshold && size.Cmp(big.NewInt(0)) > 0 {
			// Check if this address is blacklisted
			if c.isAddressBlacklisted([]byte(shardAddress)) {
				c.logger.Warn(
					"Shard has insufficient coverage but is blacklisted - skipping halt",
					zap.String("shard_address", hex.EncodeToString([]byte(shardAddress))),
					zap.Uint64("prover_count", proverCount),
					zap.Uint64("halt_threshold", c.haltThreshold),
				)
				continue
			}

			// Bump the streak – only increments once per frame
			streak, err := c.bumpStreak(shardAddress, frameNumber)
			if err != nil {
				return errors.Wrap(err, "check shard coverage")
			}

			var remaining int
			if frameNumber < token.FRAME_2_1_EXTENDED_ENROLL_CONFIRM_END+360 {
				remaining = int(c.haltGraceFrames + 720 - streak.Count)
			} else {
				remaining = int(c.haltGraceFrames - streak.Count)
			}
			if remaining <= 0 && c.config.P2P.Network == 0 {
				// Instead of halting, enter prover-only mode at the global level
				// This allows prover messages to continue while blocking other messages
				proverOnlyMode := c.getProverOnlyMode()
				if !proverOnlyMode.Load() {
					c.logger.Warn(
						"CRITICAL: Shard has insufficient coverage - entering prover-only mode (non-prover messages will be dropped)",
						zap.String("shard_address", hex.EncodeToString([]byte(shardAddress))),
						zap.Uint64("prover_count", proverCount),
						zap.Uint64("halt_threshold", c.haltThreshold),
					)
					proverOnlyMode.Store(true)
				}

				// Emit warning event (not halt) so monitoring knows we're in degraded state
				c.emitCoverageEvent(
					typesconsensus.ControlEventCoverageWarn,
					&typesconsensus.CoverageEventData{
						ShardAddress:    []byte(shardAddress),
						ProverCount:     int(proverCount),
						RequiredProvers: int(c.minProvers),
						AttestedStorage: attestedStorage,
						TreeMetadata:    coverage.TreeMetadata,
						Message: fmt.Sprintf(
							"Shard has only %d provers, prover-only mode active (non-prover messages dropped)",
							proverCount,
						),
					},
				)
				continue
			}

			// During grace, warn and include progress toward halt
			c.logger.Warn(
				"Shard at critical coverage — grace window in effect",
				zap.String("shard_address", hex.EncodeToString([]byte(shardAddress))),
				zap.Uint64("prover_count", proverCount),
				zap.Uint64("halt_threshold", c.haltThreshold),
				zap.Uint64("streak_frames", streak.Count),
				zap.Int("frames_until_halt", remaining),
			)
			c.emitCoverageEvent(
				typesconsensus.ControlEventCoverageWarn,
				&typesconsensus.CoverageEventData{
					ShardAddress:    []byte(shardAddress),
					ProverCount:     int(proverCount),
					RequiredProvers: int(c.minProvers),
					AttestedStorage: attestedStorage,
					TreeMetadata:    coverage.TreeMetadata,
					Message: fmt.Sprintf(
						"Critical coverage (less than or equal to %d provers). Grace period: %d/%d frames toward halt.",
						c.haltThreshold, streak.Count, c.haltGraceFrames,
					),
				},
			)
			continue
		}

		// Not in critical state — clear any ongoing streak
		c.clearStreak(shardAddress)

		// If we were in prover-only mode and coverage is restored, exit prover-only mode
		proverOnlyMode := c.getProverOnlyMode()
		if proverOnlyMode.Load() {
			c.logger.Info(
				"Coverage restored - exiting prover-only mode",
				zap.String("shard_address", hex.EncodeToString([]byte(shardAddress))),
				zap.Uint64("prover_count", proverCount),
			)
			proverOnlyMode.Store(false)
		}

		// Check for low coverage
		if proverCount < c.minProvers {
			if mergeData := c.handleLowCoverage([]byte(shardAddress), coverage, c.minProvers); mergeData != nil {
				allMergeGroups = append(allMergeGroups, *mergeData)
			}
		}

		// Check for high coverage (potential split)
		if proverCount > c.maxProvers {
			c.handleHighCoverage([]byte(shardAddress), coverage, c.maxProvers, frameProver)
		}
	}

	// Emit a single bulk merge event if there are any merge-eligible shards
	if len(allMergeGroups) > 0 {
		c.emitBulkMergeEvent(allMergeGroups, frameProver)
	}

	return nil
}

// ShardCoverage represents coverage information for a shard
type ShardCoverage struct {
	ProverCount     int
	AttestedStorage uint64
	TreeMetadata    []typesconsensus.TreeMetadata
}

// handleLowCoverage handles shards with insufficient provers.
// Returns merge event data if merge is possible, nil otherwise.
func (c *CoverageMonitor) handleLowCoverage(
	shardAddress []byte,
	coverage *ShardCoverage,
	minProvers uint64,
) *typesconsensus.ShardMergeEventData {
	addressLen := len(shardAddress)

	// Case 2.a: Full application address (32 bytes)
	if addressLen == 32 {
		c.logger.Warn(
			"shard has low coverage",
			zap.String("shard_address", hex.EncodeToString(shardAddress)),
			zap.Int("prover_count", coverage.ProverCount),
			zap.Uint64("min_provers", minProvers),
		)

		// Emit coverage warning event
		c.emitCoverageEvent(
			typesconsensus.ControlEventCoverageWarn,
			&typesconsensus.CoverageEventData{
				ShardAddress:    shardAddress, // buildutils:allow-slice-alias slice is static
				ProverCount:     coverage.ProverCount,
				RequiredProvers: int(minProvers),
				AttestedStorage: coverage.AttestedStorage,
				TreeMetadata:    coverage.TreeMetadata,
				Message:         "Application shard has low prover coverage",
			},
		)
		return nil
	}

	// Case 2.b: Longer than application address (> 32 bytes)
	// Check if merge is possible with sibling shards
	appPrefix := shardAddress[:32] // Application prefix
	siblingShards := c.findSiblingShards(appPrefix, shardAddress)

	if len(siblingShards) > 0 {
		// Calculate total storage across siblings
		totalStorage := coverage.AttestedStorage
		totalProvers := coverage.ProverCount
		allShards := append([][]byte{shardAddress}, siblingShards...)

		for _, sibling := range siblingShards {
			if sibCoverage, exists := c.getShardCoverage(sibling); exists {
				totalStorage += sibCoverage.AttestedStorage
				totalProvers += sibCoverage.ProverCount
			}
		}

		// Check if siblings have sufficient storage to handle merge
		requiredStorage := c.calculateRequiredStorage(allShards)

		if totalStorage >= requiredStorage {
			// Case 2.b.i: Merge is possible - return the data for bulk emission
			return &typesconsensus.ShardMergeEventData{
				ShardAddresses:  allShards,
				TotalProvers:    totalProvers,
				AttestedStorage: totalStorage,
				RequiredStorage: requiredStorage,
			}
		} else {
			// Case 2.b.ii: Insufficient storage for merge
			c.logger.Warn(
				"shard has low coverage, merge not possible due to insufficient storage",
				zap.String("shard_address", hex.EncodeToString(shardAddress)),
				zap.Int("prover_count", coverage.ProverCount),
				zap.Uint64("total_storage", totalStorage),
				zap.Uint64("required_storage", requiredStorage),
			)

			// Emit coverage warning event
			c.emitCoverageEvent(
				typesconsensus.ControlEventCoverageWarn,
				&typesconsensus.CoverageEventData{
					ShardAddress:    shardAddress, // buildutils:allow-slice-alias slice is static
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
		c.emitCoverageEvent(
			typesconsensus.ControlEventCoverageWarn,
			&typesconsensus.CoverageEventData{
				ShardAddress:    shardAddress, // buildutils:allow-slice-alias slice is static
				ProverCount:     coverage.ProverCount,
				RequiredProvers: int(minProvers),
				AttestedStorage: coverage.AttestedStorage,
				TreeMetadata:    coverage.TreeMetadata,
				Message:         "Shard has low coverage and no siblings for merge",
			},
		)
	}
	return nil
}

// handleHighCoverage handles shards with too many provers
func (c *CoverageMonitor) handleHighCoverage(
	shardAddress []byte,
	coverage *ShardCoverage,
	maxProvers uint64,
	frameProver []byte,
) {
	addressLen := len(shardAddress)

	// Case 3.a: Not a full app+data address (< 64 bytes)
	if addressLen < 64 {
		// Check if there's space to split
		availableAddressSpace := c.calculateAvailableAddressSpace(shardAddress)

		if availableAddressSpace > 0 {
			// Case 3.a.i: Split is possible
			proposedShards := c.proposeShardSplit(shardAddress, coverage.ProverCount)

			c.logger.Info(
				"shard eligible for split",
				zap.String("shard_address", hex.EncodeToString(shardAddress)),
				zap.Int("prover_count", coverage.ProverCount),
				zap.Int("proposed_shard_count", len(proposedShards)),
			)

			// Emit split eligible event
			c.emitSplitEvent(&typesconsensus.ShardSplitEventData{
				ShardAddress:    shardAddress, // buildutils:allow-slice-alias slice is static
				ProverCount:     coverage.ProverCount,
				AttestedStorage: coverage.AttestedStorage,
				ProposedShards:  proposedShards,
				FrameProver:     frameProver,
			})
		} else {
			// Case 3.a.ii: No space to split, do nothing
			c.logger.Debug(
				"Shard has high prover count but cannot be split (no address space)",
				zap.String("shard_address", hex.EncodeToString(shardAddress)),
				zap.Int("prover_count", coverage.ProverCount),
			)
		}
	} else {
		// Already at maximum address length (64 bytes), cannot split further
		c.logger.Debug(
			"Shard has high prover count but cannot be split (max address length)",
			zap.String("shard_address", hex.EncodeToString(shardAddress)),
			zap.Int("prover_count", coverage.ProverCount),
		)
	}
}

func (c *CoverageMonitor) getShardCoverageMap() map[string]*ShardCoverage {
	// Get all active app shard provers from the registry
	coverageMap := make(map[string]*ShardCoverage)

	// Get all app shard provers (provers with filters)
	allProvers, err := c.proverRegistry.GetAllActiveAppShardProvers()
	if err != nil {
		c.logger.Error("failed to get active app shard provers", zap.Error(err))
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
		metadata, err := c.hypergraph.GetMetadataAtKey([]byte(shardAddress))
		if err != nil {
			c.logger.Error("could not obtain metadata for path", zap.Error(err))
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

func (c *CoverageMonitor) getShardCoverage(shardAddress []byte) (
	*ShardCoverage,
	bool,
) {
	// Query prover registry for specific shard coverage
	proverCount, err := c.proverRegistry.GetProverCount(shardAddress)
	if err != nil {
		c.logger.Debug(
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
	activeProvers, err := c.proverRegistry.GetActiveProvers(shardAddress)
	if err != nil {
		c.logger.Warn(
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

	metadata, err := c.hypergraph.GetMetadataAtKey(shardAddress)
	if err != nil {
		c.logger.Error("could not obtain metadata for path", zap.Error(err))
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

func (c *CoverageMonitor) findSiblingShards(
	appPrefix, shardAddress []byte,
) [][]byte {
	// Find shards with same app prefix but different suffixes
	var siblings [][]byte

	// Get all active shards from coverage map
	coverageMap := c.getShardCoverageMap()

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

	c.logger.Debug(
		"found sibling shards",
		zap.String("app_prefix", hex.EncodeToString(appPrefix)),
		zap.Int("sibling_count", len(siblings)),
	)

	return siblings
}

func (c *CoverageMonitor) calculateRequiredStorage(
	shards [][]byte,
) uint64 {
	// Calculate total storage needed for these shards
	totalStorage := uint64(0)
	for _, shard := range shards {
		coverage, exists := c.getShardCoverage(shard)
		if exists && len(coverage.TreeMetadata) > 0 {
			totalStorage += coverage.TreeMetadata[0].TotalSize
		}
	}

	return totalStorage
}

func (c *CoverageMonitor) calculateAvailableAddressSpace(
	shardAddress []byte,
) int {
	// Calculate how many more bytes can be added to address for splitting
	if len(shardAddress) >= 64 {
		return 0
	}
	return 64 - len(shardAddress)
}

func (c *CoverageMonitor) proposeShardSplit(
	shardAddress []byte,
	proverCount int,
) [][]byte {
	// Propose how to split the shard address space
	availableSpace := c.calculateAvailableAddressSpace(shardAddress)
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

	c.logger.Debug(
		"proposed shard split",
		zap.String("original_shard", hex.EncodeToString(shardAddress)),
		zap.Int("split_factor", splitFactor),
		zap.Int("proposed_count", len(proposedShards)),
	)

	return proposedShards
}

func (c *CoverageMonitor) ensureStreakMap(frameNumber uint64) error {
	if c.lowCoverageStreak != nil {
		return nil
	}

	c.logger.Debug("ensuring streak map")
	c.lowCoverageStreak = make(map[string]*coverageStreak)

	info, err := c.proverRegistry.GetAllActiveAppShardProvers()
	if err != nil {
		c.logger.Error(
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
		staleness := uint64(0)
		if frameNumber > lastFrame[shardKey] {
			staleness = frameNumber - lastFrame[shardKey]
		}
		if coverage <= int(c.haltThreshold) {
			// Currently halted — record the full staleness as the streak
			c.lowCoverageStreak[shardKey] = &coverageStreak{
				StartFrame: lastFrame[shardKey],
				LastFrame:  frameNumber,
				Count:      staleness,
			}
		} else if staleness > 1 {
			// Shard has recovered but all provers are still stale from a
			// prior halt. Record the gap so eviction subtracts it. Without
			// this, a reboot after halt recovery would lose the in-memory
			// streak data and immediately evict everyone. The streak will
			// be cleared once provers submit and clearStreak runs.
			c.lowCoverageStreak[shardKey] = &coverageStreak{
				StartFrame: lastFrame[shardKey],
				LastFrame:  frameNumber,
				Count:      staleness,
			}
		}
	}

	return nil
}

func (c *CoverageMonitor) bumpStreak(
	shardKey string,
	frame uint64,
) (*coverageStreak, error) {
	c.lowCoverageStreakMu.Lock()
	defer c.lowCoverageStreakMu.Unlock()

	err := c.ensureStreakMap(frame)
	if err != nil {
		return nil, errors.Wrap(err, "bump streak")
	}

	s := c.lowCoverageStreak[shardKey]
	if s == nil {
		s = &coverageStreak{StartFrame: frame, LastFrame: frame, Count: 1}
		c.lowCoverageStreak[shardKey] = s
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

func (c *CoverageMonitor) clearStreak(shardKey string) {
	c.lowCoverageStreakMu.Lock()
	defer c.lowCoverageStreakMu.Unlock()

	if c.lowCoverageStreak != nil {
		delete(c.lowCoverageStreak, shardKey)
	}
}

// computeShardHaltDurations returns a map from shard filter to the number of
// frames the shard has been in a halt state. Shards currently at or below
// haltThreshold get math.MaxUint64 so eviction is fully suppressed. Shards
// that recently recovered but still have a coverage streak get the streak
// count so that the halt period is subtracted from the inactivity window.
func (c *CoverageMonitor) computeShardHaltDurations(
	frameNumber uint64,
) map[string]uint64 {
	c.ensureCoverageThresholds()

	durations := make(map[string]uint64)

	// Ensure the streak map is initialized (reconstructs halt data from
	// prover LastActiveFrameNumber on first call after a restart).
	// Return nil if initialization fails — caller skips eviction.
	c.lowCoverageStreakMu.Lock()
	if err := c.ensureStreakMap(frameNumber); err != nil {
		c.lowCoverageStreakMu.Unlock()
		c.logger.Error("failed to ensure streak map for eviction",
			zap.Error(err),
		)
		return nil
	}

	// Snapshot the streak counts.
	for shardKey, streak := range c.lowCoverageStreak {
		if streak != nil && streak.Count > 0 {
			durations[shardKey] = streak.Count
		}
	}
	c.lowCoverageStreakMu.Unlock()

	// Shards currently at or below haltThreshold are fully exempt even if
	// they don't have a streak entry yet (e.g. first frame of low coverage).
	summaries, err := c.proverRegistry.GetProverShardSummaries()
	if err != nil {
		c.logger.Error("failed to get shard summaries for eviction exemption",
			zap.Error(err),
		)
		return durations
	}
	for _, s := range summaries {
		activeCount := s.StatusCounts[typesconsensus.ProverStatusActive]
		if uint64(activeCount) <= c.haltThreshold {
			durations[string(s.Filter)] = math.MaxUint64
		}
	}

	return durations
}

func (c *CoverageMonitor) emitCoverageEvent(
	eventType typesconsensus.ControlEventType,
	data *typesconsensus.CoverageEventData,
) {
	event := typesconsensus.ControlEvent{
		Type: eventType,
		Data: data,
	}

	go c.eventDistributor.Publish(event)

	c.logger.Info(
		"emitted coverage event",
		zap.String("type", fmt.Sprintf("%d", eventType)),
		zap.String("shard_address", hex.EncodeToString(data.ShardAddress)),
		zap.Int("prover_count", data.ProverCount),
		zap.String("message", data.Message),
	)
}

func (c *CoverageMonitor) emitBulkMergeEvent(
	mergeGroups []typesconsensus.ShardMergeEventData,
	frameProver []byte,
) {
	if len(mergeGroups) == 0 {
		return
	}

	// Combine all merge groups into a single bulk event
	data := &typesconsensus.BulkShardMergeEventData{
		MergeGroups: mergeGroups,
		FrameProver: frameProver,
	}

	event := typesconsensus.ControlEvent{
		Type: typesconsensus.ControlEventShardMergeEligible,
		Data: data,
	}

	go c.eventDistributor.Publish(event)

	totalShards := 0
	totalProvers := 0
	for _, group := range mergeGroups {
		totalShards += len(group.ShardAddresses)
		totalProvers += group.TotalProvers
	}

	c.logger.Info(
		"emitted bulk merge eligible event",
		zap.Int("merge_groups", len(mergeGroups)),
		zap.Int("total_shards", totalShards),
		zap.Int("total_provers", totalProvers),
	)
}

func (c *CoverageMonitor) emitSplitEvent(
	data *typesconsensus.ShardSplitEventData,
) {
	event := typesconsensus.ControlEvent{
		Type: typesconsensus.ControlEventShardSplitEligible,
		Data: data,
	}

	go c.eventDistributor.Publish(event)

	c.logger.Info(
		"emitted split eligible event",
		zap.String("shard_address", hex.EncodeToString(data.ShardAddress)),
		zap.Int("proposed_shard_count", len(data.ProposedShards)),
		zap.Int("prover_count", data.ProverCount),
		zap.Uint64("attested_storage", data.AttestedStorage),
	)
}

func (c *CoverageMonitor) emitAlertEvent(alertMessage string) {
	event := typesconsensus.ControlEvent{
		Type: typesconsensus.ControlEventHalt,
		Data: &typesconsensus.ErrorEventData{
			Error: errors.New(alertMessage),
		},
	}

	go c.eventDistributor.Publish(event)

	c.logger.Info("emitted alert message")
}

const shardActionCooldownFrames = 360

func (c *CoverageMonitor) handleShardSplitEvent(
	data *typesconsensus.ShardSplitEventData,
) {
	// Only the prover who produced the triggering frame should emit
	if !bytes.Equal(data.FrameProver, c.getProverAddress()) {
		return
	}

	frameNumber := c.getLastObservedFrame()
	if frameNumber == 0 {
		return
	}

	addrKey := string(data.ShardAddress)
	c.lastShardActionFrameMu.Lock()
	if last, ok := c.lastShardActionFrame[addrKey]; ok &&
		frameNumber-last < shardActionCooldownFrames {
		c.lastShardActionFrameMu.Unlock()
		c.logger.Debug(
			"skipping shard split, cooldown active",
			zap.String("shard_address", hex.EncodeToString(data.ShardAddress)),
			zap.Uint64("last_action_frame", last),
			zap.Uint64("current_frame", frameNumber),
		)
		return
	}
	c.lastShardActionFrame[addrKey] = frameNumber
	c.lastShardActionFrameMu.Unlock()

	op := globalintrinsics.NewShardSplitOp(
		data.ShardAddress,
		data.ProposedShards,
		c.keyManager,
		c.shardsStore,
		c.proverRegistry,
	)

	if err := op.Prove(frameNumber); err != nil {
		c.logger.Error(
			"failed to prove shard split",
			zap.Error(err),
		)
		return
	}

	splitBytes, err := op.ToRequestBytes()
	if err != nil {
		c.logger.Error(
			"failed to serialize shard split",
			zap.Error(err),
		)
		return
	}

	if err := c.publishProverMessage(splitBytes); err != nil {
		c.logger.Error("failed to publish shard split", zap.Error(err))
	} else {
		c.logger.Info(
			"published shard split",
			zap.String("shard_address", hex.EncodeToString(data.ShardAddress)),
			zap.Int("proposed_shards", len(data.ProposedShards)),
			zap.Uint64("frame_number", frameNumber),
		)
	}
}

func (c *CoverageMonitor) handleShardMergeEvent(
	data *typesconsensus.BulkShardMergeEventData,
) {
	// Only the prover who produced the triggering frame should emit
	if !bytes.Equal(data.FrameProver, c.getProverAddress()) {
		return
	}

	frameNumber := c.getLastObservedFrame()
	if frameNumber == 0 {
		return
	}

	for _, group := range data.MergeGroups {
		if len(group.ShardAddresses) < 2 {
			continue
		}

		// Use first shard's first 32 bytes as parent address
		parentAddress := group.ShardAddresses[0][:32]

		// Check cooldown for the parent address
		parentKey := string(parentAddress)
		c.lastShardActionFrameMu.Lock()
		if last, ok := c.lastShardActionFrame[parentKey]; ok &&
			frameNumber-last < shardActionCooldownFrames {
			c.lastShardActionFrameMu.Unlock()
			c.logger.Debug(
				"skipping shard merge, cooldown active",
				zap.String("parent_address", hex.EncodeToString(parentAddress)),
				zap.Uint64("last_action_frame", last),
				zap.Uint64("current_frame", frameNumber),
			)
			continue
		}
		c.lastShardActionFrame[parentKey] = frameNumber
		c.lastShardActionFrameMu.Unlock()

		op := globalintrinsics.NewShardMergeOp(
			group.ShardAddresses,
			parentAddress,
			c.keyManager,
			c.shardsStore,
			c.proverRegistry,
		)

		if err := op.Prove(frameNumber); err != nil {
			c.logger.Error(
				"failed to prove shard merge",
				zap.Error(err),
			)
			continue
		}

		mergeBytes, err := op.ToRequestBytes()
		if err != nil {
			c.logger.Error(
				"failed to serialize shard merge",
				zap.Error(err),
			)
			continue
		}

		if err := c.publishProverMessage(mergeBytes); err != nil {
			c.logger.Error("failed to publish shard merge", zap.Error(err))
		} else {
			c.logger.Info(
				"published shard merge",
				zap.String("parent_address", hex.EncodeToString(parentAddress)),
				zap.Int("shard_count", len(group.ShardAddresses)),
				zap.Uint64("frame_number", frameNumber),
			)
		}
	}
}

// isAddressBlacklisted checks whether the given address is blacklisted.
func (c *CoverageMonitor) isAddressBlacklisted(address []byte) bool {
	c.blacklistMu.RLock()
	defer c.blacklistMu.RUnlock()

	// Check for exact match first
	if c.blacklistMap[string(address)] {
		return true
	}

	// Check for prefix matches (for partial blacklist entries)
	for blacklistedAddress := range c.blacklistMap {
		// If the blacklisted address is shorter than the full address,
		// it's a prefix and we check if the address starts with it
		if len(blacklistedAddress) < len(address) {
			if strings.HasPrefix(string(address), blacklistedAddress) {
				return true
			}
		}
	}

	return false
}
