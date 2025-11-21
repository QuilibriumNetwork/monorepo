package keyedaggregator

import "errors"

var (
	// ErrSequenceBelowRetention indicates that a collector for the requested
	// sequence can no longer be accessed because it was pruned.
	ErrSequenceBelowRetention = errors.New("sequence below retention threshold")

	// ErrSequenceUnknown indicates that the requested sequence is not known to
	// the collaborating components and should be dropped.
	ErrSequenceUnknown = errors.New("unknown sequence")
)
