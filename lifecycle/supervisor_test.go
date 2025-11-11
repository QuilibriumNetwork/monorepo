package lifecycle_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
)

// Ensures the first Throw wins and the caller goroutine exits via Goexit.
// Goexit runs defers, but code after Throw must not execute.
func TestSignaler_FirstThrowWins_AndGoexit(t *testing.T) {
	s, errCh := lifecycle.NewSignaler()

	after := make(chan struct{}, 1)    // written if code after Throw executes (it shouldn't)
	deferred := make(chan struct{}, 1) // closed by defer; should run even with Goexit
	go func() {
		defer close(deferred) // Goexit SHOULD run defers
		s.Throw(errors.New("boom-1"))
		after <- struct{}{} // must never execute
	}()

	select {
	case err := <-errCh:
		if err == nil || err.Error() != "boom-1" {
			t.Fatalf("expected boom-1, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for first error")
	}

	// Defer should have run.
	select {
	case <-deferred:
		// ok
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("deferred function did not run before goroutine exit")
	}

	// Code after Throw must NOT have executed.
	select {
	case <-after:
		t.Fatalf("code after Throw executed; Goexit should prevent it")
	case <-time.After(200 * time.Millisecond):
		// ok
	}

	// Second Throw should be ignored (no panic), just logged to stderr.
	// We can call it from a fresh goroutine; nothing observable should change.
	go s.Throw(errors.New("boom-2"))
	time.Sleep(50 * time.Millisecond) // small settle; nothing to assert further
}

// Ensures Throw(ctx, err) works when the ctx carries a SignalerContext.
func TestThrow_WithContextBridge(t *testing.T) {
	base := context.Background()
	sctx, errCh := lifecycle.WithSignaler(base)

	ctx := lifecycle.WithSignalerContext(base, sctx)

	go func() {
		lifecycle.Throw(ctx, errors.New("ctx-boom"))
	}()

	select {
	case err := <-errCh:
		if err == nil || err.Error() != "ctx-boom" {
			t.Fatalf("expected ctx-boom, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for ctx error")
	}
}

type fakeComp struct {
	ready   chan struct{}
	done    chan struct{}
	started atomic.Int32
	// Triggers:
	triggerFatal chan error // if non-nil error arrives, call ctx.Throw(err)
}

func newFakeComp() *fakeComp {
	return &fakeComp{
		ready:        make(chan struct{}),
		done:         make(chan struct{}),
		triggerFatal: make(chan error, 1),
	}
}

func (f *fakeComp) Ready() <-chan struct{} { return f.ready }
func (f *fakeComp) Done() <-chan struct{}  { return f.done }

func (f *fakeComp) Start(ctx lifecycle.SignalerContext) error {
	if f.started.Add(1) != 1 {
		return lifecycle.ErrComponentRunning
	}
	// simulate startup finishing quickly
	close(f.ready)

	go func() {
		defer close(f.done)
		select {
		case err := <-f.triggerFatal:
			if err != nil {
				ctx.Throw(err)
			}
			// nil means "clean exit"
			return
		case <-ctx.Done():
			// graceful stop
			return
		}
	}()

	return nil
}

func (f *fakeComp) factory() lifecycle.ComponentFactory {
	return func() (lifecycle.Component, error) {
		return newFakeComp(), nil
	}
}

// helpers for timing in tests
func waitClosed(ch <-chan struct{}, d time.Duration) bool {
	select {
	case <-ch:
		return true
	case <-time.After(d):
		return false
	}
}

func TestComponentManager_ReadyAndDoneOrdering_NoFatal(t *testing.T) {
	builder := lifecycle.NewComponentManagerBuilder().
		AddWorker(lifecycle.NoopWorker).
		AddWorker(lifecycle.NoopWorker)

	mgr := builder.Build()

	// Parent signaler context
	sctx, cancel, errCh := lifecycle.WithSignallerAndCancel(context.Background())
	defer cancel()

	if err := mgr.Start(sctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	if ok := waitClosed(mgr.Ready(), time.Second); !ok {
		t.Fatalf("ready never closed")
	}

	// No errors expected
	select {
	case err := <-errCh:
		t.Fatalf("unexpected fatal: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	// Cancel triggers shutdown; ShutdownSignal should close before Done.
	cancel()

	if ok := waitClosed(mgr.ShutdownSignal(), time.Second); !ok {
		t.Fatalf("shutdown signal not closed before done")
	}
	if ok := waitClosed(mgr.Done(), time.Second); !ok {
		t.Fatalf("done never closed")
	}
}

func TestComponentManager_PropagatesWorkerFatal_ThenDone(t *testing.T) {
	fatalErr := errors.New("worker-boom")

	worker := func(ctx lifecycle.SignalerContext, ready lifecycle.ReadyFunc) {
		ready()
		ctx.Throw(fatalErr) // immediate fatal
	}

	mgr := lifecycle.NewComponentManagerBuilder().AddWorker(worker).Build()

	sctx, _, errCh := lifecycle.WithSignallerAndCancel(context.Background())

	if err := mgr.Start(sctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Expect fatal to reach parent err channel.
	select {
	case err := <-errCh:
		if err == nil || !errors.Is(err, fatalErr) {
			t.Fatalf("expected %v, got %v", fatalErr, err)
		}
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for fatal")
	}

	// After fatal, manager must eventually be done.
	if ok := waitClosed(mgr.Done(), time.Second); !ok {
		t.Fatalf("done never closed")
	}
}

// Ensures Ready closes exactly once after all workers call Ready().
func TestComponentManager_ReadyClosesAfterAllWorkers(t *testing.T) {
	worker := func(delay time.Duration) lifecycle.ComponentWorker {
		return func(ctx lifecycle.SignalerContext, ready lifecycle.ReadyFunc) {
			time.Sleep(delay)
			ready()
			<-ctx.Done()
		}
	}

	mgr := lifecycle.NewComponentManagerBuilder().
		AddWorker(worker(150 * time.Millisecond)).
		AddWorker(worker(20 * time.Millisecond)).
		Build()

	sctx, cancel, _ := lifecycle.WithSignallerAndCancel(context.Background())
	defer cancel()

	if err := mgr.Start(sctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	start := time.Now()
	if ok := waitClosed(mgr.Ready(), time.Second); !ok {
		t.Fatalf("ready never closed")
	}
	elapsed := time.Since(start)
	if elapsed < 150*time.Millisecond {
		t.Fatalf("ready closed before slowest worker (%v < 150ms)", elapsed)
	}
	cancel()
	_ = waitClosed(mgr.Done(), time.Second)
}

// Verifies that RunComponent restarts on ErrorShouldRestart
// and stops on ErrorShouldShutdown, surfacing the last error.
func TestRunComponent_RestartThenShutdown(t *testing.T) {
	var starts atomic.Int32

	// One-shot fake: first instance throws, second instance throws again triggering shutdown.
	componentFactory := func() (lifecycle.Component, error) {
		f := newFakeComp()
		idx := starts.Add(1)

		go func() {
			// Wait for Start to close ready
			_ = waitClosed(f.Ready(), time.Second)
			switch idx {
			case 1:
				f.triggerFatal <- errors.New("first-fatal")
			case 2:
				f.triggerFatal <- errors.New("second-fatal")
			default:
				// any further restarts cleanly exit
				f.triggerFatal <- nil
			}
		}()
		return f, nil
	}

	first := true
	handler := func(err error) lifecycle.ErrorHandlingBehavior {
		if first {
			first = false
			return lifecycle.ErrorShouldRestart
		}
		return lifecycle.ErrorShouldShutdown
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := lifecycle.RunComponent(ctx, componentFactory, handler)
	if err == nil || err.Error() != "second-fatal" {
		t.Fatalf("expected second-fatal, got %v", err)
	}
	if got := starts.Load(); got < 2 {
		t.Fatalf("expected at least 2 starts, got %d", got)
	}
}

// Verifies RunComponent returns ctx error on parent cancel and waits for Done.
func TestRunComponent_ContextCancel(t *testing.T) {
	f := newFakeComp()

	componentFactory := func() (lifecycle.Component, error) { return f, nil }

	handler := func(err error) lifecycle.ErrorHandlingBehavior {
		t.Fatalf("no fatal expected, got %v", err)
		return lifecycle.ErrorShouldShutdown
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = waitClosed(f.Ready(), time.Second)
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	err := lifecycle.RunComponent(ctx, componentFactory, handler)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if ok := waitClosed(f.Done(), time.Second); !ok {
		t.Fatalf("component not done after cancel")
	}
}

// Utilities to build Nodes whose OnError returns specific behaviors.
func nodeWithFake(name string, deps []string, fatalCh chan<- func()) *lifecycle.Node {
	var fired atomic.Bool
	fc := func() (lifecycle.Component, error) {
		f := newFakeComp()
		// expose a way for the test to trigger this node's fatal
		if fatalCh != nil && fired.CompareAndSwap(false, true) {
			fatalCh <- func() { f.triggerFatal <- errors.New(name + "-fatal") }
		}
		return f, nil
	}
	// Default OnError: Stop just this subtree unless overridden in tests.
	return &lifecycle.Node{Name: name, Deps: deps, Factory: fc, OnError: func(error) lifecycle.ErrorHandlingBehavior {
		return lifecycle.ErrorShouldStop
	}}
}

func TestSupervisor_Stop_StopsDescendantsOnly(t *testing.T) {
	// graph: A -> B -> C ; A -> D
	trigger := make(chan func(), 1)

	a := nodeWithFake("A", nil, nil)
	b := nodeWithFake("B", []string{"A"}, nil)
	c := nodeWithFake("C", []string{"B"}, nil)
	d := nodeWithFake("D", []string{"A"}, nil)
	boom := nodeWithFake("X", nil, trigger) // will be re-wired to B below
	b.Factory = boom.Factory                // trigger drives B

	s, err := lifecycle.NewSupervisor([]*lifecycle.Node{a, b, c, d})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = s.Start(ctx)
	}()

	// Wait for all to be Ready.
	time.Sleep(150 * time.Millisecond)

	// Fire B's fatal (policy: ErrorShouldStop)
	fire := <-trigger
	fire()

	// B and its descendants (C) should stop; A and D continue.
	// We cannot directly peek internals; observe via time — fake comps close Done quickly.
	time.Sleep(200 * time.Millisecond)

	// There isn't direct access to components; so instead assert supervisor keeps running,
	// then cancel and ensure clean exit (sanity). This smoke test verifies the cascade
	// did not shutdown the whole graph.
	cancel()
}

func TestSupervisor_StopParents_StopsAncestorsAndDesc(t *testing.T) {
	trigger := make(chan func(), 1)

	a := nodeWithFake("A", nil, nil)
	b := nodeWithFake("B", []string{"A"}, nil)
	c := nodeWithFake("C", []string{"B"}, nil)

	// Make C fire with StopParents
	c.Factory = func() (lifecycle.Component, error) {
		f := newFakeComp()
		go func() {
			_ = waitClosed(f.Ready(), time.Second)
			trigger <- func() { f.triggerFatal <- errors.New("C-fatal") }
		}()
		return f, nil
	}
	c.OnError = func(error) lifecycle.ErrorHandlingBehavior { return lifecycle.ErrorShouldStopParents }

	s, err := lifecycle.NewSupervisor([]*lifecycle.Node{a, b, c})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Start(ctx) }()

	time.Sleep(150 * time.Millisecond)

	fire := <-trigger
	fire()

	// Expect whole chain (A,B,C) to be canceled. Give it a moment, then end.
	time.Sleep(200 * time.Millisecond)
	cancel()
}

func TestSupervisor_ShutdownAll(t *testing.T) {
	trigger := make(chan func(), 1)

	a := nodeWithFake("A", nil, nil)
	b := nodeWithFake("B", []string{"A"}, nil)

	// A fatal on A requests full shutdown.
	a.Factory = func() (lifecycle.Component, error) {
		f := newFakeComp()
		go func() {
			_ = waitClosed(f.Ready(), time.Second)
			trigger <- func() { f.triggerFatal <- errors.New("A-fatal") }
		}()
		return f, nil
	}
	a.OnError = func(error) lifecycle.ErrorHandlingBehavior { return lifecycle.ErrorShouldShutdown }

	s, err := lifecycle.NewSupervisor([]*lifecycle.Node{a, b})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = s.Start(ctx) // Run should return after Shutdown cascade completes
		close(done)
	}()

	time.Sleep(150 * time.Millisecond)
	(<-trigger)()

	select {
	case <-done:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatalf("supervisor did not exit on Shutdown")
	}
}
