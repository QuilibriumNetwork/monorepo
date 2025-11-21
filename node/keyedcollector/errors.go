package keyedcollector

import (
	"errors"
	"fmt"
)

var (
	// ErrRepeatedRecord indicates that a record from the same identity with the
	// same content was added multiple times.
	ErrRepeatedRecord = errors.New("duplicated record")
	// ErrRecordForDifferentSequence indicates that a record belongs to a
	// different sequence than the collector handles.
	ErrRecordForDifferentSequence = errors.New("record for incompatible sequence")
)

// ConflictingRecordError is emitted when two records for the same sequence and
// identity contain different contents, signaling equivocation.
type ConflictingRecordError[RecordT any] struct {
	first  *RecordT
	second *RecordT
}

func NewConflictingRecordError[RecordT any](
	first *RecordT,
	second *RecordT,
) *ConflictingRecordError[RecordT] {
	return &ConflictingRecordError[RecordT]{first: first, second: second}
}

func (e *ConflictingRecordError[RecordT]) Error() string {
	return "conflicting records detected"
}

func (e *ConflictingRecordError[RecordT]) First() *RecordT  { return e.first }
func (e *ConflictingRecordError[RecordT]) Second() *RecordT { return e.second }

// InvalidRecordError indicates that a record failed validation. Processor
// implementations should wrap contextual information in this error type to
// signal recoverable invalid inputs to the collector.
type InvalidRecordError[RecordT any] struct {
	Record *RecordT
	Cause  error
}

func NewInvalidRecordError[RecordT any](
	record *RecordT,
	cause error,
) *InvalidRecordError[RecordT] {
	return &InvalidRecordError[RecordT]{Record: record, Cause: cause}
}

func (e *InvalidRecordError[RecordT]) Error() string {
	if e.Cause == nil {
		return "invalid record"
	}
	return fmt.Sprintf("invalid record: %v", e.Cause)
}

func (e *InvalidRecordError[RecordT]) Unwrap() error {
	return e.Cause
}

// AsInvalidRecordError performs a typed errors.As lookup for
// InvalidRecordError[RecordT].
func AsInvalidRecordError[RecordT any](
	err error,
) (*InvalidRecordError[RecordT], bool) {
	var invalid *InvalidRecordError[RecordT]
	if errors.As(err, &invalid) {
		return invalid, true
	}
	return nil, false
}
