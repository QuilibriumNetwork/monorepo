package consensus

// DifficultyAdjuster is a simple interface that describes a value provider
// that sets the difficulty deterministically. If there is some form of EMA
// employed in the adjuster, it is highly recommended that implementations
// have an initializer that sets a sane anchor value – for global frame
// processing, we recommend the hard fork frame of 244,200 and a halved frame
// difficulty of 80,000. For app shard frames, we recommend the global frame's
// difficulty and frame number at the time it was initialized.
type DifficultyAdjuster interface {
	// Given the current frame number and current time, produces a new difficulty
	// value to be used for the VDF.
	GetNextDifficulty(currentFrameNumber uint64, currentTime int64) uint64
}
