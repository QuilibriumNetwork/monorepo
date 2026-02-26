package p2p

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"go.uber.org/zap"
	blossomsub "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
)

// newTestBlossomSub creates a minimal BlossomSub wrapper suitable for testing
// Subscribe/Unsubscribe without the full DHT/discovery/bootstrap setup.
func newTestBlossomSub(t *testing.T) *BlossomSub {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	h, err := libp2p.New(
		libp2p.ResourceManager(&network.NullResourceManager{}),
	)
	if err != nil {
		t.Fatal(err)
	}

	ps, err := blossomsub.NewBlossomSub(ctx, h)
	if err != nil {
		h.Close()
		cancel()
		t.Fatal(err)
	}

	bs := &BlossomSub{
		ctx:                    ctx,
		cancel:                 cancel,
		logger:                 zap.NewNop(),
		ps:                     ps,
		h:                      h,
		bitmaskMap:             make(map[string]*blossomsub.Bitmask),
		subscriptionTracker:    make(map[string][][]byte),
		subscriptionsByBitmask: make(map[string][]*blossomsub.Subscription),
	}
	bs.p2pConfig.SubscriptionQueueSize = 128

	t.Cleanup(func() {
		cancel()
		h.Close()
	})

	return bs
}

func noopHandler(*pb.Message) error { return nil }

// TestUnsubscribeAllowsResubscribe is the critical regression test. It verifies
// that after Unsubscribe, the same bitmask can be subscribed to again. Before
// the fix, bm.Close() silently failed because subscriptions were still open,
// and the subsequent ps.Join() returned an error because the bitmask was still
// registered.
func TestUnsubscribeAllowsResubscribe(t *testing.T) {
	bs := newTestBlossomSub(t)
	bitmask := []byte{0x01}

	// First subscribe
	if err := bs.Subscribe(bitmask, noopHandler); err != nil {
		t.Fatalf("first Subscribe failed: %v", err)
	}

	// Unsubscribe – must cancel subs before Close so Close succeeds
	bs.Unsubscribe(bitmask, false)

	// Re-subscribe – this fails without the fix because the bitmask is still
	// registered in the pubsub (Close was a silent no-op).
	if err := bs.Subscribe(bitmask, noopHandler); err != nil {
		t.Fatalf("re-Subscribe after Unsubscribe failed: %v", err)
	}

	// Clean up
	bs.Unsubscribe(bitmask, false)
}

// TestUnsubscribeTracksPerBitmask verifies that subscribing to multiple
// bitmasks tracks them independently and unsubscribing one doesn't affect
// the other.
func TestUnsubscribeTracksPerBitmask(t *testing.T) {
	bs := newTestBlossomSub(t)
	bitmaskA := []byte{0x01}
	bitmaskB := []byte{0x02}

	// Subscribe to both
	if err := bs.Subscribe(bitmaskA, noopHandler); err != nil {
		t.Fatalf("Subscribe A failed: %v", err)
	}
	if err := bs.Subscribe(bitmaskB, noopHandler); err != nil {
		t.Fatalf("Subscribe B failed: %v", err)
	}

	// Both should be tracked
	bs.subscriptionMutex.RLock()
	if _, ok := bs.subscriptionsByBitmask[string(bitmaskA)]; !ok {
		t.Error("bitmask A not tracked in subscriptionsByBitmask")
	}
	if _, ok := bs.subscriptionsByBitmask[string(bitmaskB)]; !ok {
		t.Error("bitmask B not tracked in subscriptionsByBitmask")
	}
	bs.subscriptionMutex.RUnlock()

	// Unsubscribe A only
	bs.Unsubscribe(bitmaskA, false)

	bs.subscriptionMutex.RLock()
	if _, ok := bs.subscriptionsByBitmask[string(bitmaskA)]; ok {
		t.Error("bitmask A still tracked after Unsubscribe")
	}
	if _, ok := bs.subscriptionsByBitmask[string(bitmaskB)]; !ok {
		t.Error("bitmask B should still be tracked")
	}
	bs.subscriptionMutex.RUnlock()

	// A should be re-subscribable (Close succeeded)
	if err := bs.Subscribe(bitmaskA, noopHandler); err != nil {
		t.Fatalf("re-Subscribe A after Unsubscribe failed: %v", err)
	}

	// Unsubscribe both
	bs.Unsubscribe(bitmaskA, false)
	bs.Unsubscribe(bitmaskB, false)

	bs.subscriptionMutex.RLock()
	if len(bs.subscriptionsByBitmask) != 0 {
		t.Errorf("subscriptionsByBitmask should be empty, got %d entries",
			len(bs.subscriptionsByBitmask))
	}
	bs.subscriptionMutex.RUnlock()
}

// TestUnsubscribeHandlerExits verifies that after Unsubscribe, the handler
// goroutine actually stops. sub.Cancel() unblocks the sub.Next() call in the
// goroutine, causing it to return false and exit.
func TestUnsubscribeHandlerExits(t *testing.T) {
	bs := newTestBlossomSub(t)
	bitmask := []byte{0x01}

	var calls atomic.Int32
	handler := func(*pb.Message) error {
		calls.Add(1)
		return nil
	}

	if err := bs.Subscribe(bitmask, handler); err != nil {
		t.Fatalf("Subscribe failed: %v", err)
	}

	bs.Unsubscribe(bitmask, false)

	// Give the goroutine time to observe the cancellation and exit.
	time.Sleep(100 * time.Millisecond)
	snapshot := calls.Load()

	// Wait again and verify no further increments.
	time.Sleep(100 * time.Millisecond)
	if got := calls.Load(); got != snapshot {
		t.Errorf("handler still running after Unsubscribe: calls went from %d to %d",
			snapshot, got)
	}
}
