package fees

import (
	"encoding/hex"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

const (
	// maxWindowSize is the maximum number of frames to keep in the sliding window
	maxWindowSize = 360
	// defaultFeeMultiplier is used when there are no votes yet
	defaultFeeMultiplier = 100
)

// feeVote represents a single fee multiplier vote from a frame
type feeVote struct {
	frameNumber       uint64
	feeMultiplierVote uint64
}

// filterFeeData tracks fee votes for a specific filter/shard
type filterFeeData struct {
	votes       []feeVote // Sliding window of votes (newest at end)
	sumVotes    uint64    // Running sum to avoid recalculation
	lastUpdated time.Time // For pruning inactive filters
}

// DynamicFeeManager implements the DynamicFeeManager interface
type DynamicFeeManager struct {
	logger *zap.Logger
	mu     sync.RWMutex

	// Map from filter (as hex string) to fee data
	filterData map[string]*filterFeeData

	inclusionProver crypto.InclusionProver
}

// NewDynamicFeeManager creates a new dynamic fee manager
func NewDynamicFeeManager(
	logger *zap.Logger,
	inclusionProver crypto.InclusionProver,
) consensus.DynamicFeeManager {
	return &DynamicFeeManager{
		logger:          logger,
		filterData:      make(map[string]*filterFeeData),
		inclusionProver: inclusionProver,
	}
}

// AddFrameFeeVote adds a fee multiplier vote from a frame to the sliding window
func (d *DynamicFeeManager) AddFrameFeeVote(
	filter []byte,
	frameNumber uint64,
	feeMultiplierVote uint64,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	filterKey := hex.EncodeToString(filter)

	// Get or create filter data
	data, exists := d.filterData[filterKey]
	if !exists {
		data = &filterFeeData{
			votes:       make([]feeVote, 0, maxWindowSize),
			sumVotes:    0,
			lastUpdated: time.Now(),
		}
		d.filterData[filterKey] = data
		filtersTracked.Set(float64(len(d.filterData)))
	}

	// Check if this is a duplicate or out-of-order frame
	if len(data.votes) > 0 {
		lastFrame := data.votes[len(data.votes)-1]
		if frameNumber <= lastFrame.frameNumber {
			return errors.Errorf(
				"frame %d is not newer than last frame %d",
				frameNumber,
				lastFrame.frameNumber,
			)
		}
	}

	// Add the new vote
	newVote := feeVote{
		frameNumber:       frameNumber,
		feeMultiplierVote: feeMultiplierVote,
	}
	data.votes = append(data.votes, newVote)
	data.sumVotes += feeMultiplierVote
	data.lastUpdated = time.Now()

	// Record metrics
	feeVotesAdded.WithLabelValues(filterKey).Inc()
	feeVoteDistribution.WithLabelValues(filterKey).Observe(
		float64(feeMultiplierVote),
	)

	// Maintain sliding window size
	if len(data.votes) > maxWindowSize {
		// Remove oldest vote
		oldVote := data.votes[0]
		data.votes = data.votes[1:]
		data.sumVotes -= oldVote.feeMultiplierVote
		feeVotesDropped.WithLabelValues(filterKey).Inc()
	}

	// Update metrics
	slidingWindowSize.WithLabelValues(filterKey).Set(float64(len(data.votes)))

	// Calculate and update current fee multiplier metric
	if len(data.votes) > 0 {
		avgFee := data.sumVotes / uint64(len(data.votes))
		currentFeeMultiplier.WithLabelValues(filterKey).Set(float64(avgFee))
	}

	d.logger.Debug(
		"added fee vote",
		zap.String("filter", filterKey),
		zap.Uint64("frame_number", frameNumber),
		zap.Uint64("fee_multiplier_vote", feeMultiplierVote),
		zap.Int("window_size", len(data.votes)),
	)

	return nil
}

// GetNextFeeMultiplier returns the calculated fee multiplier based on the
// average.
func (d *DynamicFeeManager) GetNextFeeMultiplier(
	filter []byte,
) (uint64, error) {
	timer := prometheus.NewTimer(
		feeCalculationDuration.WithLabelValues(hex.EncodeToString(filter)),
	)
	defer timer.ObserveDuration()

	d.mu.RLock()
	defer d.mu.RUnlock()

	filterKey := hex.EncodeToString(filter)
	data, exists := d.filterData[filterKey]
	if !exists || len(data.votes) == 0 {
		d.logger.Debug(
			"no fee votes for filter, using default",
			zap.String("filter", filterKey),
			zap.Uint64("default_fee", defaultFeeMultiplier),
		)
		return defaultFeeMultiplier, nil
	}

	// Calculate average using the maintained sum
	// This avoids floating point and minimizes rounding errors
	avgFee := data.sumVotes / uint64(len(data.votes))

	d.logger.Debug(
		"calculated fee multiplier",
		zap.String("filter", filterKey),
		zap.Uint64("average_fee", avgFee),
		zap.Int("votes_count", len(data.votes)),
		zap.Uint64("sum_votes", data.sumVotes),
	)

	return avgFee, nil
}

// GetVoteHistory returns the current sliding window of fee votes for a filter.
func (d *DynamicFeeManager) GetVoteHistory(
	filter []byte,
) ([]uint64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	filterKey := hex.EncodeToString(filter)
	data, exists := d.filterData[filterKey]
	if !exists {
		return []uint64{}, nil
	}

	history := make([]uint64, len(data.votes))
	for i, vote := range data.votes {
		history[i] = vote.feeMultiplierVote
	}

	return history, nil
}

// GetAverageWindowSize returns the current number of votes in the sliding
// window.
func (d *DynamicFeeManager) GetAverageWindowSize(
	filter []byte,
) (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	filterKey := hex.EncodeToString(filter)
	data, exists := d.filterData[filterKey]
	if !exists {
		return 0, nil
	}

	return len(data.votes), nil
}

// PruneOldData removes fee vote data for filters that haven't been updated
// recently.
func (d *DynamicFeeManager) PruneOldData(maxAge uint64) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoffTime := time.Now().Add(-time.Duration(maxAge) * time.Millisecond)
	prunedCount := 0

	for filterKey, data := range d.filterData {
		if data.lastUpdated.Before(cutoffTime) {
			delete(d.filterData, filterKey)
			prunedCount++

			// Clear metrics for this filter
			slidingWindowSize.DeleteLabelValues(filterKey)
			currentFeeMultiplier.DeleteLabelValues(filterKey)
		}
	}

	if prunedCount > 0 {
		filtersPruned.Add(float64(prunedCount))
		filtersTracked.Set(float64(len(d.filterData)))

		d.logger.Info(
			"pruned old filter data",
			zap.Int("pruned_count", prunedCount),
			zap.Int("remaining_filters", len(d.filterData)),
		)
	}

	return nil
}

// RewindToFrame removes all votes newer than the specified frame number.
func (d *DynamicFeeManager) RewindToFrame(
	filter []byte,
	frameNumber uint64,
) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	filterKey := hex.EncodeToString(filter)
	data, exists := d.filterData[filterKey]
	if !exists || len(data.votes) == 0 {
		return 0, nil
	}

	// Find the index of the first vote to remove
	// We want to keep all votes with frameNumber <= the specified frameNumber
	keepIndex := 0
	for i := 0; i < len(data.votes); i++ {
		if data.votes[i].frameNumber > frameNumber {
			keepIndex = i
			break
		}
	}
	// If all votes are <= frameNumber, keep all
	if keepIndex == 0 && len(data.votes) > 0 &&
		data.votes[len(data.votes)-1].frameNumber <= frameNumber {
		keepIndex = len(data.votes)
	}

	// If nothing to remove
	if keepIndex == len(data.votes) {
		return 0, nil
	}

	// Calculate how many votes we're removing
	removedCount := len(data.votes) - keepIndex

	// Update the sum by subtracting the removed votes
	for i := keepIndex; i < len(data.votes); i++ {
		data.sumVotes -= data.votes[i].feeMultiplierVote
		feeVotesDropped.WithLabelValues(filterKey).Inc()
	}

	// Truncate the votes slice
	data.votes = data.votes[:keepIndex]

	// Update metrics
	slidingWindowSize.WithLabelValues(filterKey).Set(float64(len(data.votes)))

	// Update current fee multiplier metric
	if len(data.votes) > 0 {
		avgFee := data.sumVotes / uint64(len(data.votes))
		currentFeeMultiplier.WithLabelValues(filterKey).Set(float64(avgFee))
	} else {
		currentFeeMultiplier.WithLabelValues(filterKey).Set(
			float64(defaultFeeMultiplier),
		)
	}

	d.logger.Debug(
		"rewound to frame",
		zap.String("filter", filterKey),
		zap.Uint64("frame_number", frameNumber),
		zap.Int("removed_count", removedCount),
		zap.Int("remaining_count", len(data.votes)),
	)

	return removedCount, nil
}
