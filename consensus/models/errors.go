package models

import (
	"errors"
	"fmt"
)

var (
	ErrUnverifiableState = errors.New("state proposal can't be verified")
	ErrInvalidSignature  = errors.New("invalid signature")
	ErrRankUnknown       = errors.New("rank is unknown")
)

type NoVoteError struct {
	Err error
}

func (e NoVoteError) Error() string {
	return fmt.Sprintf("not voting - %s", e.Err.Error())
}

func (e NoVoteError) Unwrap() error {
	return e.Err
}

// IsNoVoteError returns whether an error is NoVoteError
func IsNoVoteError(err error) bool {
	var e NoVoteError
	return errors.As(err, &e)
}

func NewNoVoteErrorf(msg string, args ...interface{}) error {
	return NoVoteError{Err: fmt.Errorf(msg, args...)}
}

type NoTimeoutError struct {
	Err error
}

func (e NoTimeoutError) Error() string {
	return fmt.Sprintf(
		"conditions not satisfied to generate valid TimeoutState: %s",
		e.Err.Error(),
	)
}

func (e NoTimeoutError) Unwrap() error {
	return e.Err
}

func IsNoTimeoutError(err error) bool {
	var e NoTimeoutError
	return errors.As(err, &e)
}

func NewNoTimeoutErrorf(msg string, args ...interface{}) error {
	return NoTimeoutError{Err: fmt.Errorf(msg, args...)}
}

type InvalidFormatError struct {
	err error
}

func NewInvalidFormatError(err error) error {
	return InvalidFormatError{err}
}

func NewInvalidFormatErrorf(msg string, args ...interface{}) error {
	return InvalidFormatError{fmt.Errorf(msg, args...)}
}

func (e InvalidFormatError) Error() string { return e.err.Error() }
func (e InvalidFormatError) Unwrap() error { return e.err }

func IsInvalidFormatError(err error) bool {
	var e InvalidFormatError
	return errors.As(err, &e)
}

type ConfigurationError struct {
	err error
}

func NewConfigurationError(err error) error {
	return ConfigurationError{err}
}

func NewConfigurationErrorf(msg string, args ...interface{}) error {
	return ConfigurationError{fmt.Errorf(msg, args...)}
}

func (e ConfigurationError) Error() string { return e.err.Error() }
func (e ConfigurationError) Unwrap() error { return e.err }

func IsConfigurationError(err error) bool {
	var e ConfigurationError
	return errors.As(err, &e)
}

type MissingStateError struct {
	Rank       uint64
	Identifier Identity
}

func (e MissingStateError) Error() string {
	return fmt.Sprintf(
		"missing state at rank %d with ID %x",
		e.Rank,
		e.Identifier,
	)
}

func IsMissingStateError(err error) bool {
	var e MissingStateError
	return errors.As(err, &e)
}

type InvalidQuorumCertificateError struct {
	Identifier Identity
	Rank       uint64
	Err        error
}

func (e InvalidQuorumCertificateError) Error() string {
	return fmt.Sprintf(
		"invalid QuorumCertificate for state %x at rank %d: %s",
		e.Identifier,
		e.Rank,
		e.Err.Error(),
	)
}

func IsInvalidQuorumCertificateError(err error) bool {
	var e InvalidQuorumCertificateError
	return errors.As(err, &e)
}

func (e InvalidQuorumCertificateError) Unwrap() error {
	return e.Err
}

type InvalidTimeoutCertificateError struct {
	Rank uint64
	Err  error
}

func (e InvalidTimeoutCertificateError) Error() string {
	return fmt.Sprintf(
		"invalid TimeoutCertificate at rank %d: %s",
		e.Rank,
		e.Err.Error(),
	)
}

func IsInvalidTimeoutCertificateError(err error) bool {
	var e InvalidTimeoutCertificateError
	return errors.As(err, &e)
}

func (e InvalidTimeoutCertificateError) Unwrap() error {
	return e.Err
}

type InvalidProposalError[StateT Unique, VoteT Unique] struct {
	InvalidProposal *SignedProposal[StateT, VoteT]
	Err             error
}

func NewInvalidProposalErrorf[StateT Unique, VoteT Unique](
	proposal *SignedProposal[StateT, VoteT],
	msg string,
	args ...interface{},
) error {
	return InvalidProposalError[StateT, VoteT]{
		InvalidProposal: proposal,
		Err:             fmt.Errorf(msg, args...),
	}
}

func (e InvalidProposalError[StateT, VoteT]) Error() string {
	return fmt.Sprintf(
		"invalid proposal %x at rank %d: %s",
		e.InvalidProposal.State.Identifier,
		e.InvalidProposal.State.Rank,
		e.Err.Error(),
	)
}

func (e InvalidProposalError[StateT, VoteT]) Unwrap() error {
	return e.Err
}

func IsInvalidProposalError[StateT Unique, VoteT Unique](err error) bool {
	var e InvalidProposalError[StateT, VoteT]
	return errors.As(err, &e)
}

func AsInvalidProposalError[StateT Unique, VoteT Unique](
	err error,
) (*InvalidProposalError[StateT, VoteT], bool) {
	var e InvalidProposalError[StateT, VoteT]
	ok := errors.As(err, &e)
	if ok {
		return &e, true
	}
	return nil, false
}

type InvalidStateError[StateT Unique] struct {
	InvalidState *State[StateT]
	Err          error
}

func NewInvalidStateErrorf[StateT Unique](
	state *State[StateT],
	msg string,
	args ...interface{},
) error {
	return InvalidStateError[StateT]{
		InvalidState: state,
		Err:          fmt.Errorf(msg, args...),
	}
}

func (e InvalidStateError[StateT]) Error() string {
	return fmt.Sprintf(
		"invalid state %x at rank %d: %s",
		e.InvalidState.Identifier,
		e.InvalidState.Rank,
		e.Err.Error(),
	)
}

func IsInvalidStateError[StateT Unique](err error) bool {
	var e InvalidStateError[StateT]
	return errors.As(err, &e)
}

func AsInvalidStateError[StateT Unique](err error) (
	*InvalidStateError[StateT],
	bool,
) {
	var e InvalidStateError[StateT]
	ok := errors.As(err, &e)
	if ok {
		return &e, true
	}
	return nil, false
}

func (e InvalidStateError[StateT]) Unwrap() error {
	return e.Err
}

type InvalidVoteError[VoteT Unique] struct {
	Vote *VoteT
	Err  error
}

func NewInvalidVoteErrorf[VoteT Unique](
	vote *VoteT,
	msg string,
	args ...interface{},
) error {
	return InvalidVoteError[VoteT]{
		Vote: vote,
		Err:  fmt.Errorf(msg, args...),
	}
}

func (e InvalidVoteError[VoteT]) Error() string {
	return fmt.Sprintf(
		"invalid vote at rank %d for state %x: %s",
		(*e.Vote).GetRank(),
		(*e.Vote).Identity(),
		e.Err.Error(),
	)
}

func IsInvalidVoteError[VoteT Unique](err error) bool {
	var e InvalidVoteError[VoteT]
	return errors.As(err, &e)
}

func AsInvalidVoteError[VoteT Unique](err error) (
	*InvalidVoteError[VoteT],
	bool,
) {
	var e InvalidVoteError[VoteT]
	ok := errors.As(err, &e)
	if ok {
		return &e, true
	}
	return nil, false
}

func (e InvalidVoteError[VoteT]) Unwrap() error {
	return e.Err
}

type ByzantineThresholdExceededError struct {
	Evidence string
}

func (e ByzantineThresholdExceededError) Error() string {
	return e.Evidence
}

func IsByzantineThresholdExceededError(err error) bool {
	var target ByzantineThresholdExceededError
	return errors.As(err, &target)
}

type DoubleVoteError[VoteT Unique] struct {
	FirstVote       *VoteT
	ConflictingVote *VoteT
	err             error
}

func (e DoubleVoteError[VoteT]) Error() string {
	return e.err.Error()
}

func IsDoubleVoteError[VoteT Unique](err error) bool {
	var e DoubleVoteError[VoteT]
	return errors.As(err, &e)
}

func AsDoubleVoteError[VoteT Unique](err error) (
	*DoubleVoteError[VoteT],
	bool,
) {
	var e DoubleVoteError[VoteT]
	ok := errors.As(err, &e)
	if ok {
		return &e, true
	}
	return nil, false
}

func (e DoubleVoteError[VoteT]) Unwrap() error {
	return e.err
}

func NewDoubleVoteErrorf[VoteT Unique](
	firstVote, conflictingVote *VoteT,
	msg string,
	args ...interface{},
) error {
	return DoubleVoteError[VoteT]{
		FirstVote:       firstVote,
		ConflictingVote: conflictingVote,
		err:             fmt.Errorf(msg, args...),
	}
}

type DuplicatedSignerError struct {
	err error
}

func NewDuplicatedSignerError(err error) error {
	return DuplicatedSignerError{err}
}

func NewDuplicatedSignerErrorf(msg string, args ...interface{}) error {
	return DuplicatedSignerError{err: fmt.Errorf(msg, args...)}
}

func (e DuplicatedSignerError) Error() string { return e.err.Error() }
func (e DuplicatedSignerError) Unwrap() error { return e.err }

func IsDuplicatedSignerError(err error) bool {
	var e DuplicatedSignerError
	return errors.As(err, &e)
}

type InvalidSignatureIncludedError struct {
	err error
}

func NewInvalidSignatureIncludedError(err error) error {
	return InvalidSignatureIncludedError{err}
}

func NewInvalidSignatureIncludedErrorf(msg string, args ...interface{}) error {
	return InvalidSignatureIncludedError{fmt.Errorf(msg, args...)}
}

func (e InvalidSignatureIncludedError) Error() string { return e.err.Error() }
func (e InvalidSignatureIncludedError) Unwrap() error { return e.err }

func IsInvalidSignatureIncludedError(err error) bool {
	var e InvalidSignatureIncludedError
	return errors.As(err, &e)
}

type InvalidAggregatedKeyError struct {
	error
}

func NewInvalidAggregatedKeyError(err error) error {
	return InvalidAggregatedKeyError{err}
}

func NewInvalidAggregatedKeyErrorf(msg string, args ...interface{}) error {
	return InvalidAggregatedKeyError{fmt.Errorf(msg, args...)}
}

func (e InvalidAggregatedKeyError) Unwrap() error { return e.error }

func IsInvalidAggregatedKeyError(err error) bool {
	var e InvalidAggregatedKeyError
	return errors.As(err, &e)
}

type InsufficientSignaturesError struct {
	err error
}

func NewInsufficientSignaturesError(err error) error {
	return InsufficientSignaturesError{err}
}

func NewInsufficientSignaturesErrorf(msg string, args ...interface{}) error {
	return InsufficientSignaturesError{fmt.Errorf(msg, args...)}
}

func (e InsufficientSignaturesError) Error() string { return e.err.Error() }
func (e InsufficientSignaturesError) Unwrap() error { return e.err }

func IsInsufficientSignaturesError(err error) bool {
	var e InsufficientSignaturesError
	return errors.As(err, &e)
}

type InvalidSignerError struct {
	err error
}

func NewInvalidSignerError(err error) error {
	return InvalidSignerError{err}
}

func NewInvalidSignerErrorf(msg string, args ...interface{}) error {
	return InvalidSignerError{fmt.Errorf(msg, args...)}
}

func (e InvalidSignerError) Error() string { return e.err.Error() }
func (e InvalidSignerError) Unwrap() error { return e.err }

func IsInvalidSignerError(err error) bool {
	var e InvalidSignerError
	return errors.As(err, &e)
}

type DoubleTimeoutError[VoteT Unique] struct {
	FirstTimeout       *TimeoutState[VoteT]
	ConflictingTimeout *TimeoutState[VoteT]
	err                error
}

func (e DoubleTimeoutError[VoteT]) Error() string {
	return e.err.Error()
}

func IsDoubleTimeoutError[VoteT Unique](err error) bool {
	var e DoubleTimeoutError[VoteT]
	return errors.As(err, &e)
}

func AsDoubleTimeoutError[VoteT Unique](err error) (
	*DoubleTimeoutError[VoteT],
	bool,
) {
	var e DoubleTimeoutError[VoteT]
	ok := errors.As(err, &e)
	if ok {
		return &e, true
	}
	return nil, false
}

func (e DoubleTimeoutError[VoteT]) Unwrap() error {
	return e.err
}

func NewDoubleTimeoutErrorf[VoteT Unique](
	firstTimeout, conflictingTimeout *TimeoutState[VoteT],
	msg string,
	args ...interface{},
) error {
	return DoubleTimeoutError[VoteT]{
		FirstTimeout:       firstTimeout,
		ConflictingTimeout: conflictingTimeout,
		err:                fmt.Errorf(msg, args...),
	}
}

type InvalidTimeoutError[VoteT Unique] struct {
	Timeout *TimeoutState[VoteT]
	Err     error
}

func NewInvalidTimeoutErrorf[VoteT Unique](
	timeout *TimeoutState[VoteT],
	msg string,
	args ...interface{},
) error {
	return InvalidTimeoutError[VoteT]{
		Timeout: timeout,
		Err:     fmt.Errorf(msg, args...),
	}
}

func (e InvalidTimeoutError[VoteT]) Error() string {
	return fmt.Sprintf("invalid timeout: %d: %s",
		e.Timeout.Rank,
		e.Err.Error(),
	)
}

func IsInvalidTimeoutError[VoteT Unique](err error) bool {
	var e InvalidTimeoutError[VoteT]
	return errors.As(err, &e)
}

func AsInvalidTimeoutError[VoteT Unique](err error) (
	*InvalidTimeoutError[VoteT],
	bool,
) {
	var e InvalidTimeoutError[VoteT]
	ok := errors.As(err, &e)
	if ok {
		return &e, true
	}
	return nil, false
}

func (e InvalidTimeoutError[VoteT]) Unwrap() error {
	return e.Err
}

// UnknownExecutionResultError indicates that the Execution Result is unknown
type UnknownExecutionResultError struct {
	err error
}

func NewUnknownExecutionResultErrorf(msg string, args ...interface{}) error {
	return UnknownExecutionResultError{
		err: fmt.Errorf(msg, args...),
	}
}

func (e UnknownExecutionResultError) Unwrap() error {
	return e.err
}

func (e UnknownExecutionResultError) Error() string {
	return e.err.Error()
}

func IsUnknownExecutionResultError(err error) bool {
	var unknownExecutionResultError UnknownExecutionResultError
	return errors.As(err, &unknownExecutionResultError)
}

type BelowPrunedThresholdError struct {
	err error
}

func NewBelowPrunedThresholdErrorf(msg string, args ...interface{}) error {
	return BelowPrunedThresholdError{
		err: fmt.Errorf(msg, args...),
	}
}

func (e BelowPrunedThresholdError) Unwrap() error {
	return e.err
}

func (e BelowPrunedThresholdError) Error() string {
	return e.err.Error()
}

func IsBelowPrunedThresholdError(err error) bool {
	var newIsBelowPrunedThresholdError BelowPrunedThresholdError
	return errors.As(err, &newIsBelowPrunedThresholdError)
}
