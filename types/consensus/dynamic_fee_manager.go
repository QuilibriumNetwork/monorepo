package consensus

// DynamicFeeManager is an interface for tracking and calculating fee
// multipliers based on a sliding window of frame fee votes.
type DynamicFeeManager interface {
	// AddFrameFeeVote adds a fee multiplier vote from a frame to the sliding
	// window. The vote is associated with a specific filter/shard.
	AddFrameFeeVote(
		filter []byte,
		frameNumber uint64,
		feeMultiplierVote uint64,
	) error

	// GetNextFeeMultiplier returns the calculated fee multiplier based on the
	// average of votes in the sliding window for a specific filter/shard.
	// Returns the average fee multiplier from the last 360 frames.
	GetNextFeeMultiplier(filter []byte) (uint64, error)

	// GetVoteHistory returns the current sliding window of fee votes for a
	// filter. This is primarily for debugging and monitoring purposes.
	GetVoteHistory(filter []byte) ([]uint64, error)

	// GetAverageWindowSize returns the current number of votes in the sliding
	// window for a filter.
	GetAverageWindowSize(filter []byte) (int, error)

	// PruneOldData removes fee vote data for filters that haven't been updated
	// recently. This helps manage memory usage.
	PruneOldData(maxAge uint64) error

	// RewindToFrame removes all votes newer than the specified frame
	// number (excluding the frame itself). This is useful for reverting state
	// during reorganizations. Returns the number of votes removed.
	RewindToFrame(filter []byte, frameNumber uint64) (int, error)
}
