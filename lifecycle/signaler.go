package lifecycle

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"

	"go.uber.org/atomic"
)

// Signaler sends the error out.
type Signaler struct {
	errChan   chan error
	errThrown *atomic.Bool
}

func NewSignaler() (*Signaler, <-chan error) {
	errChan := make(chan error, 1)
	return &Signaler{
		errChan:   errChan,
		errThrown: atomic.NewBool(false),
	}, errChan
}

// Throw is a narrow drop-in replacement for panic, log.Fatal, log.Panic, etc
// anywhere there's something connected to the error channel. It only sends
// the first error it is called with to the error channel, and logs subsequent
// errors as unhandled.
func (s *Signaler) Throw(err error) {
	defer runtime.Goexit()
	if s.errThrown.CompareAndSwap(false, true) {
		s.errChan <- err
		close(s.errChan)
	} else {
		// TODO: we simply log the unhandled fatal to stderr for now, but we should
		// probably allow the user to customize the logger / logging format used
		log.New(os.Stderr, "", log.LstdFlags).Println(
			fmt.Errorf("unhandled fatal: %w", err),
		)
	}
}

// SignalerContext is a constrained interface to provide a drop-in replacement
// for context.Context including in interfaces that compose it.
type SignalerContext interface {
	context.Context
	Throw(err error) // delegates to the signaler
}

// SignalerContextKey represents the key type for retrieving a SignalerContext
// from a value `context.Context`.
type SignalerContextKey struct{}

// private, to force context derivation / WithSignaler
type signalerCtx struct {
	context.Context
	*Signaler
}

// WithSignaler is the One True Way of getting a SignalerContext.
func WithSignaler(parent context.Context) (SignalerContext, <-chan error) {
	sig, errChan := NewSignaler()
	return &signalerCtx{parent, sig}, errChan
}

// WithSignalerContext wraps `SignalerContext` using `context.WithValue` so it
// can later be used with `Throw`.
func WithSignalerContext(
	parent context.Context,
	ctx SignalerContext,
) context.Context {
	return context.WithValue(parent, SignalerContextKey{}, ctx)
}

// Throw enables throwing a fatal error using any context.Context.
//
// If we have an SignalerContext, we can directly ctx.Throw.
// But a lot of library methods expect context.Context, & we want to pass the
// same w/o boilerplate. Moreover, we could have built with:
//
//	context.WithCancel(lifecycle.WithSignaler(ctx, sig)),
//
// "downcasting" to context.Context. Yet, we can still type-assert and recover.
//
// Throw can be a drop-in replacement anywhere we have a context.Context likely
// to support signals. IT WILL PANIC IF THE CONTEXT DOES NOT SUPPORT SIGNALS
func Throw(ctx context.Context, err error) {
	signalerAbleContext, ok := ctx.Value(SignalerContextKey{}).(SignalerContext)
	if ok {
		signalerAbleContext.Throw(err)
	} else {
		// Be spectacular on how this does not -but should- handle fatals:
		log.Fatalf(
			"fatal error: signaler not found for context, please implement! Unhandled fatal error: %v",
			err,
		)
	}
}

// WithSignallerAndCancel returns an fatal context, the cancel function for the
// context, and the error channel for the context.
func WithSignallerAndCancel(ctx context.Context) (
	SignalerContext,
	context.CancelFunc,
	<-chan error,
) {
	parent, cancel := context.WithCancel(ctx)
	fatalCtx, errCh := WithSignaler(parent)
	return fatalCtx, cancel, errCh
}
