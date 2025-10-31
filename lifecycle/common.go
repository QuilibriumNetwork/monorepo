package lifecycle

import (
	"context"
	"math"
	"reflect"
)

// AllReady calls Ready on all input components and returns a channel that is
// closed when all input components are ready.
func AllReady(components ...Component) <-chan struct{} {
	readyChans := make([]<-chan struct{}, len(components))

	for i, c := range components {
		readyChans[i] = c.Ready()
	}

	return AllClosed(readyChans...)
}

// AllDone calls Done on all input components and returns a channel that is
// closed when all input components are done.
func AllDone(components ...Component) <-chan struct{} {
	doneChans := make([]<-chan struct{}, len(components))

	for i, c := range components {
		doneChans[i] = c.Done()
	}

	return AllClosed(doneChans...)
}

// AllClosed returns a channel that is closed when all input channels are
// closed.
func AllClosed(channels ...<-chan struct{}) <-chan struct{} {
	done := make(chan struct{})
	if len(channels) == 0 {
		close(done)
		return done
	}

	go func() {
		for _, ch := range channels {
			<-ch
		}
		close(done)
	}()

	return done
}

// WaitClosed waits for either a signal/close on the channel or for the context
// to be cancelled. Returns nil if the channel was signalled/closed before
// returning, otherwise, it returns the context error.
//
// This handles the corner case where the context is cancelled at the same time
// that the channel is closed, and the Done case was selected. This is intended
// for situations where ignoring a signal can cause safety issues.
func WaitClosed(ctx context.Context, ch <-chan struct{}) error {
	select {
	case <-ctx.Done():
		select {
		case <-ch:
			return nil
		default:
		}
		return ctx.Err()
	case <-ch:
		return nil
	}
}

// CheckClosed checks if the provided channel has a signal or was closed.
// Returns true if the channel was signaled/closed, otherwise, returns false.
//
// This is intended to reduce boilerplate code when multiple channel checks are
// required because missed signals could cause safety issues.
func CheckClosed(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// MergeChannels merges a list of channels into a single channel
func MergeChannels(channels interface{}) interface{} {
	sliceType := reflect.TypeOf(channels)
	if sliceType.Kind() != reflect.Slice && sliceType.Kind() != reflect.Array {
		panic("argument must be an array or slice")
	}
	chanType := sliceType.Elem()
	if chanType.ChanDir() == reflect.SendDir {
		panic("channels cannot be send-only")
	}
	c := reflect.ValueOf(channels)
	var cases []reflect.SelectCase
	for i := 0; i < c.Len(); i++ {
		cases = append(cases, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: c.Index(i),
		})
	}
	elemType := chanType.Elem()
	out := reflect.MakeChan(reflect.ChanOf(reflect.BothDir, elemType), 0)
	go func() {
		for len(cases) > 0 {
			i, v, ok := reflect.Select(cases)
			if !ok {
				lastIndex := len(cases) - 1
				cases[i], cases[lastIndex] = cases[lastIndex], cases[i]
				cases = cases[:lastIndex]
				continue
			}
			out.Send(v)
		}
		out.Close()
	}()
	return out.Convert(reflect.ChanOf(reflect.RecvDir, elemType)).Interface()
}

// WaitError waits for either an error on the error channel or the done channel
// to close. Returns an error if one is received on the error channel, otherwise
// it returns nil.
//
// This handles a race condition where the done channel could have been closed
// as a result of a fatal error being thrown, so that when the scheduler yields
// control back to this goroutine, both channels are available to read from. If
// the done case happens to be chosen at random to proceed instead of the error
// case, then we would return without error which could result in unsafe
// continuation.
func WaitError(errChan <-chan error, done <-chan struct{}) error {
	select {
	case err := <-errChan:
		return err
	case <-done:
		select {
		case err := <-errChan:
			return err
		default:
		}
		return nil
	}
}

// componentMerger is a utility structure which implements lifecycle.Component
// and is used to merge []T into one T.
type componentMerger struct {
	components []Component
}

func (m componentMerger) Start(signalerContext SignalerContext) error {
	for _, component := range m.components {
		startable, ok := component.(Component)
		if ok {
			err := startable.Start(signalerContext)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (m componentMerger) Ready() <-chan struct{} {
	return AllReady(m.components...)
}

func (m componentMerger) Done() <-chan struct{} {
	return AllDone(m.components...)
}

var _ Component = (*componentMerger)(nil)

// MergeComponents merges []Component into one Component.
func MergeComponents(components ...Component) Component {
	return componentMerger{components: components}
}

// DetypeSlice converts a typed slice containing any kind of elements into an
// untyped []any type, in effect removing the element type information from the
// slice. It is useful for passing data into structpb.NewValue, which accepts
// []any but not []T for any specific type T.
func DetypeSlice[T any](typedSlice []T) []any {
	untypedSlice := make([]any, len(typedSlice))
	for i, t := range typedSlice {
		untypedSlice[i] = t
	}
	return untypedSlice
}

// SampleN computes a percentage of the given number 'n', and returns the result
// as an unsigned integer. If the calculated sample is greater than the provided
// 'max' value, it returns the ceil of 'max'. If 'n' is less than or equal to 0,
// it returns 0.
//
// Parameters:
// - n: The input number, used as the base to compute the percentage.
// - max: The maximum value that the computed sample should not exceed.
// - percentage: The percentage (in range 0.0 to 1.0) to be applied to 'n'.
//
// Returns:
//   - The computed sample as an unsigned integer, with consideration to the
//     given constraints.
func SampleN(n int, max, percentage float64) uint {
	if n <= 0 {
		return 0
	}
	sample := float64(n) * percentage
	if sample > max {
		sample = max
	}
	return uint(math.Ceil(sample))
}
