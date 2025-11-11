package models

import "time"

// NextRank is the control flow event for when the next rank should be entered.
type NextRank struct {
	// Rank is the next rank value.
	Rank uint64
	// Start is the time the next rank was entered.
	Start time.Time
	// End is the time the next rank ends (i.e. times out).
	End time.Time
}

// TimerInfo is the control flow event for when the timeout controller
// initiates.
type TimerInfo struct {
	// Rank is the next rank value.
	Rank uint64
	// StartTime is the time the next timeout is started
	StartTime time.Time
	// Duration is the time span from the start.
	Duration time.Duration
}
