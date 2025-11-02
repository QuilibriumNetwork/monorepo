package unittest

import (
	"context"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
)

// MockSignalerContext is a SignalerContext that can be used in tests to assert
// that an error is thrown. It embeds a mock.Mock, so it can be used to assert
// that Throw is called with a specific error. Use
// NewMockSignalerContextExpectError to create a new MockSignalerContext that
// expects a specific error, otherwise NewMockSignalerContext.
type MockSignalerContext struct {
	context.Context
	*mock.Mock
}

var _ lifecycle.SignalerContext = &MockSignalerContext{}

func (m MockSignalerContext) Throw(err error) {
	m.Called(err)
}

func NewMockSignalerContext(
	t *testing.T,
	ctx context.Context,
) *MockSignalerContext {
	m := &MockSignalerContext{
		Context: ctx,
		Mock:    &mock.Mock{},
	}
	m.Mock.Test(t)
	t.Cleanup(func() { m.AssertExpectations(t) })
	return m
}

// NewMockSignalerContextWithCancel creates a new MockSignalerContext with a
// cancel function.
func NewMockSignalerContextWithCancel(
	t *testing.T,
	parent context.Context,
) (*MockSignalerContext, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	return NewMockSignalerContext(t, ctx), cancel
}

// NewMockSignalerContextExpectError creates a new MockSignalerContext which
// expects a specific error to be thrown.
func NewMockSignalerContextExpectError(
	t *testing.T,
	ctx context.Context,
	err error,
) *MockSignalerContext {
	require.NotNil(t, err)
	m := NewMockSignalerContext(t, ctx)

	// since we expect an error, we should expect a call to Throw
	m.On("Throw", err).Once().Return()

	return m
}

// AssertReturnsBefore asserts that the given function returns before the
// duration expires.
func AssertReturnsBefore(
	t *testing.T,
	f func(),
	duration time.Duration,
	msgAndArgs ...interface{},
) bool {
	done := make(chan struct{})

	go func() {
		f()
		close(done)
	}()

	select {
	case <-time.After(duration):
		t.Log("function did not return in time")
		assert.Fail(t, "function did not close in time", msgAndArgs...)
	case <-done:
		return true
	}
	return false
}

// ClosedChannel returns a closed channel.
func ClosedChannel() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// AssertClosesBefore asserts that the given channel closes before the
// duration expires.
func AssertClosesBefore(
	t assert.TestingT,
	done <-chan struct{},
	duration time.Duration,
	msgAndArgs ...interface{},
) {
	select {
	case <-time.After(duration):
		assert.Fail(t, "channel did not return in time", msgAndArgs...)
	case <-done:
		return
	}
}

func AssertFloatEqual(t *testing.T, expected, actual float64, message string) {
	tolerance := .00001
	if !(math.Abs(expected-actual) < tolerance) {
		assert.Equal(t, expected, actual, message)
	}
}

// AssertNotClosesBefore asserts that the given channel does not close before
// the duration expires.
func AssertNotClosesBefore(
	t assert.TestingT,
	done <-chan struct{},
	duration time.Duration,
	msgAndArgs ...interface{},
) {
	select {
	case <-time.After(duration):
		return
	case <-done:
		assert.Fail(t, "channel closed before timeout", msgAndArgs...)
	}
}

// RequireReturnsBefore requires that the given function returns before the
// duration expires.
func RequireReturnsBefore(
	t testing.TB,
	f func(),
	duration time.Duration,
	message string,
) {
	done := make(chan struct{})

	go func() {
		f()
		close(done)
	}()

	RequireCloseBefore(
		t,
		done,
		duration,
		message+": function did not return on time",
	)
}

// RequireComponentsDoneBefore invokes the done method of each of the input
// components concurrently, and fails the test if any components shutdown
// takes longer than the specified duration.
func RequireComponentsDoneBefore(
	t testing.TB,
	duration time.Duration,
	components ...lifecycle.Component,
) {
	done := lifecycle.AllDone(components...)
	RequireCloseBefore(
		t,
		done,
		duration,
		"failed to shutdown all components on time",
	)
}

// RequireComponentsReadyBefore invokes the ready method of each of the input
// components concurrently, and fails the test if any components startup takes
// longer than the specified duration.
func RequireComponentsReadyBefore(
	t testing.TB,
	duration time.Duration,
	components ...lifecycle.Component,
) {
	ready := lifecycle.AllReady(components...)
	RequireCloseBefore(
		t,
		ready,
		duration,
		"failed to start all components on time",
	)
}

// RequireCloseBefore requires that the given channel returns before the
// duration expires.
func RequireCloseBefore(
	t testing.TB,
	c <-chan struct{},
	duration time.Duration,
	message string,
) {
	select {
	case <-time.After(duration):
		require.Fail(t, "could not close done channel on time: "+message)
	case <-c:
		return
	}
}

// RequireClosed is a test helper function that fails the test if channel `ch`
// is not closed.
func RequireClosed(t *testing.T, ch <-chan struct{}, message string) {
	select {
	case <-ch:
	default:
		require.Fail(t, "channel is not closed: "+message)
	}
}

// RequireConcurrentCallsReturnBefore is a test helper that runs function `f`
// count-many times concurrently, and requires all invocations to return within
// duration.
func RequireConcurrentCallsReturnBefore(
	t *testing.T,
	f func(),
	count int,
	duration time.Duration,
	message string,
) {
	wg := &sync.WaitGroup{}
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			f()
			wg.Done()
		}()
	}

	RequireReturnsBefore(t, wg.Wait, duration, message)
}

// RequireNeverReturnBefore is a test helper that tries invoking function `f`
// and fails the test if either:
// - function `f` is not invoked within 1 second.
// - function `f` returns before specified `duration`.
//
// It also returns a channel that is closed once the function `f` returns and
// hence its openness can evaluate return status of function `f` for intervals
// longer than duration.
func RequireNeverReturnBefore(
	t *testing.T,
	f func(),
	duration time.Duration,
	message string,
) <-chan struct{} {
	ch := make(chan struct{})
	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		wg.Done()
		f()
		close(ch)
	}()

	// requires function invoked within next 1 second
	RequireReturnsBefore(
		t,
		wg.Wait,
		1*time.Second,
		"could not invoke the function: "+message,
	)

	// requires function never returns within duration
	RequireNeverClosedWithin(t, ch, duration, "unexpected return: "+message)

	return ch
}

// RequireNeverClosedWithin is a test helper function that fails the test if
// channel `ch` is closed before the determined duration.
func RequireNeverClosedWithin(
	t *testing.T,
	ch <-chan struct{},
	duration time.Duration,
	message string,
) {
	select {
	case <-time.After(duration):
	case <-ch:
		require.Fail(t, "channel closed before timeout: "+message)
	}
}

// RequireNotClosed is a test helper function that fails the test if channel
// `ch` is closed.
func RequireNotClosed(t *testing.T, ch <-chan struct{}, message string) {
	select {
	case <-ch:
		require.Fail(t, "channel is closed: "+message)
	default:
	}
}

// AssertErrSubstringMatch asserts that two errors match with substring
// checking on the Error method (`expected` must be a substring of `actual`, to
// account for the actual error being wrapped). Fails the test if either error
// is nil.
//
// NOTE: This should only be used in cases where `errors.Is` cannot be, like
// when errors are transmitted over the network without type information.
func AssertErrSubstringMatch(t testing.TB, expected, actual error) {
	require.NotNil(t, expected)
	require.NotNil(t, actual)
	assert.True(
		t,
		strings.Contains(actual.Error(), expected.Error()) ||
			strings.Contains(expected.Error(), actual.Error()),
		"expected error: '%s', got: '%s'", expected.Error(), actual.Error(),
	)
}

// Componentify sets up a generated mock to respond to Component lifecycle
// methods. Any mock type generated by mockery can be used.
func Componentify(mockable *mock.Mock) {
	rwch := make(chan struct{})
	var ch <-chan struct{} = rwch
	close(rwch)

	mockable.On("Ready").Return(ch).Maybe()
	mockable.On("Done").Return(ch).Maybe()
	mockable.On("Start").Return(nil).Maybe()
}
