package blossomsub

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"math/rand"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	pb "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/record"
	"github.com/libp2p/go-msgio"
)

func assertPeerLists(t *testing.T, bitmask []byte, hosts []host.Host, ps *PubSub, has ...int) {
	peers := ps.ListPeers(bitmask)
	set := make(map[peer.ID]struct{})
	for _, p := range peers {
		set[p] = struct{}{}
	}

	for _, h := range has {
		if _, ok := set[hosts[h].ID()]; !ok {
			t.Fatal("expected to have connection to peer: ", h)
		}
	}
}

func checkMessageRouting(t *testing.T, ctx context.Context, bitmasks []*Bitmask, subs [][]*Subscription) {
	for _, p := range bitmasks {
		data := make([]byte, 16)
		crand.Read(data)
		err := p.Publish(ctx, p.bitmask, data)
		if err != nil {
			t.Fatal(err)
		}

		for _, s := range subs {
			assertReceive(t, s, data)
		}
	}
}

func getDefaultHosts(t *testing.T, n int) []host.Host {
	var out []host.Host

	for i := 0; i < n; i++ {
		h, err := libp2p.New(libp2p.ResourceManager(&network.NullResourceManager{}))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { h.Close() })
		out = append(out, h)
	}

	return out
}

func connect(t *testing.T, a, b host.Host) {
	pinfo := a.Peerstore().PeerInfo(a.ID())
	err := b.Connect(context.Background(), pinfo)
	if err != nil {
		t.Fatal(err)
	}
}

func sparseConnect(t *testing.T, hosts []host.Host) {
	connectSome(t, hosts, 3)
}

func denseConnect(t *testing.T, hosts []host.Host) {
	connectSome(t, hosts, 10)
}

func connectSome(t *testing.T, hosts []host.Host, d int) {
	for i, a := range hosts {
		for j := 0; j < d; j++ {
			n := rand.Intn(len(hosts))
			if n == i {
				j--
				continue
			}

			b := hosts[n]

			connect(t, a, b)
		}
	}
}

func connectAll(t *testing.T, hosts []host.Host) {
	for i, a := range hosts {
		for j, b := range hosts {
			if i == j {
				continue
			}

			connect(t, a, b)
		}
	}
}

func assertReceive(t *testing.T, ch []*Subscription, exp []byte) {
	received := false
	var wrong *Message
	wg := sync.WaitGroup{}
	done, cancel := context.WithCancel(context.TODO())
	wg.Add(len(ch))
	for _, c := range ch {
		c := c
		go func() {
			defer wg.Done()
			select {
			case msg := <-c.ch:
				if !bytes.Equal(msg.GetData(), exp) {
					wrong = msg
				} else {
					received = true
				}
				cancel()
			case <-done.Done():
			case <-time.After(time.Second * 5):
				t.Logf("%#v\n", ch)
			}
		}()
	}

	wg.Wait()
	if !received {
		t.Fatal("timed out waiting for message of: ", string(exp))
	}
	if wrong != nil {
		t.Fatalf("got wrong message, expected %s but got %s", string(exp), string(wrong.Data))
	}
}

func assertNeverReceives(t *testing.T, ch []*Subscription, timeout time.Duration) {
	for _, c := range ch {
		select {
		case msg := <-c.ch:
			t.Logf("%#v\n", ch)
			t.Fatal("got unexpected message: ", string(msg.GetData()))
		case <-time.After(timeout):
		}
	}
}

func getBlossomSub(ctx context.Context, h host.Host, opts ...Option) *PubSub {
	ps, err := NewBlossomSub(ctx, h, opts...)
	if err != nil {
		panic(err)
	}
	return ps
}

func getBlossomSubs(ctx context.Context, hs []host.Host, opts ...Option) []*PubSub {
	var psubs []*PubSub
	for _, h := range hs {
		psubs = append(psubs, getBlossomSub(ctx, h, opts...))
	}
	return psubs
}

func TestSparseBlossomSub(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 20)

	psubs := getBlossomSubs(ctx, hosts)

	var msgs []*Subscription
	var bitmasks []*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b...)

		subch, err := ps.Subscribe([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch...)
	}

	sparseConnect(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := rand.Intn(len(psubs))

		bitmasks[owner].Publish(ctx, []byte{0x00, 0x01}, msg)

		for _, sub := range msgs {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}
	}
}

func TestDenseBlossomSub(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 20)

	psubs := getBlossomSubs(ctx, hosts)

	var msgs []*Subscription
	var bitmasks []*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b...)
		subch, err := ps.Subscribe([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch...)
	}

	denseConnect(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := rand.Intn(len(psubs))

		bitmasks[owner].Publish(ctx, []byte{0x00, 0x01}, msg)

		for _, sub := range msgs {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}
	}
}

func TestBlossomSubFanout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 20)

	psubs := getBlossomSubs(ctx, hosts)

	var msgs []*Subscription
	var bitmasks []*Bitmask
	for _, ps := range psubs[1:] {
		b, err := ps.Join([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b...)
		subch, err := ps.Subscribe([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch...)
	}

	denseConnect(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	b, err := psubs[0].Join([]byte{0x00, 0x01})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood2 %d", i, i))

		b[0].Publish(ctx, []byte{0x00, 0x01}, msg)

		for _, sub := range msgs {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}
	}

	// subscribe the owner
	subch, err := psubs[0].Subscribe([]byte{0x00, 0x01})
	if err != nil {
		t.Fatal(err)
	}
	msgs = append(msgs, subch...)

	// wait for a heartbeat
	time.Sleep(time.Second * 1)

	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		b[0].Publish(ctx, []byte{0x00, 0x01}, msg)

		for _, sub := range msgs {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}
	}
}

func TestBlossomSubFanoutMaintenance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 20)

	psubs := getBlossomSubs(ctx, hosts)

	var msgs []*Subscription
	var bitmasks []*Bitmask
	for _, ps := range psubs[1:] {
		b, err := ps.Join([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b...)
		subch, err := ps.Subscribe([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch...)
	}

	denseConnect(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	b, err := psubs[0].Join([]byte{0x00, 0x01})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 20; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		b[0].Publish(ctx, []byte{0x00, 0x01}, msg)

		for _, sub := range msgs {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}
	}

	// unsubscribe all peers to exercise fanout maintenance
	for _, sub := range msgs {
		sub.Cancel()
	}
	msgs = nil

	// wait for heartbeats
	time.Sleep(time.Second * 2)

	// resubscribe and repeat
	for _, ps := range psubs[1:] {
		subch, err := ps.Subscribe([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch...)
	}

	time.Sleep(time.Second * 2)

	for i := 0; i < 20; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood2 %d", i, i))

		b[0].Publish(ctx, []byte{0x00, 0x01}, msg)

		for _, sub := range msgs {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}
	}
}

func TestBlossomSubFanoutExpiry(t *testing.T) {
	BlossomSubFanoutTTL = 1 * time.Second
	defer func() {
		BlossomSubFanoutTTL = 60 * time.Second
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 10)

	psubs := getBlossomSubs(ctx, hosts)

	var msgs []*Subscription
	var bitmasks []*Bitmask
	for _, ps := range psubs[1:] {
		b, err := ps.Join([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b...)
		subch, err := ps.Subscribe([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch...)
	}

	denseConnect(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	b, err := psubs[0].Join([]byte{0x00, 0x01})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		b[0].Publish(ctx, []byte{0x00, 0x01}, msg)

		for _, sub := range msgs {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}
	}

	psubs[0].eval <- func() {
		if len(psubs[0].rt.(*BlossomSubRouter).fanout) == 0 {
			t.Fatal("owner has no fanout")
		}
	}

	// wait for TTL to expire fanout peers in owner
	time.Sleep(time.Second * 2)

	psubs[0].eval <- func() {
		if len(psubs[0].rt.(*BlossomSubRouter).fanout) > 0 {
			t.Fatal("fanout hasn't expired")
		}
	}

	// wait for it to run in the event loop
	time.Sleep(10 * time.Millisecond)
}

func TestBlossomSubGossip(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 20)

	psubs := getBlossomSubs(ctx, hosts)

	var msgs [][]*Subscription
	var bitmasks [][]*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x00, 0x81})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b)
		subch, err := ps.Subscribe([]byte{0x00, 0x81})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch)
	}

	denseConnect(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := rand.Intn(len(psubs))

		bitmasks[owner][0].Publish(ctx, []byte{0x00, 0x81}, msg)

		for _, sub := range msgs {
			assertReceive(t, sub, msg)
		}

		// wait a bit to have some gossip interleaved
		time.Sleep(time.Millisecond * 100)
	}

	// and wait for some gossip flushing
	time.Sleep(time.Second * 2)
}

func TestBlossomSubGossipPropagation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 40)
	psubs := getBlossomSubs(ctx, hosts)

	hosts1 := hosts[:BlossomSubD+1]
	hosts2 := append(hosts[BlossomSubD+1:], hosts[0])

	denseConnect(t, hosts1)
	denseConnect(t, hosts2)

	var msgs1 []*Subscription
	var bitmasks []*Bitmask
	for _, ps := range psubs[1 : BlossomSubD+1] {
		b, err := ps.Join([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b...)
		subch, err := ps.Subscribe([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		msgs1 = append(msgs1, subch...)
	}

	b, err := psubs[0].Join([]byte{0x00, 0x01})
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Second * 1)

	for i := 0; i < 10; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		b[0].Publish(ctx, []byte{0x00, 0x01}, msg)

		for _, sub := range msgs1 {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}
	}

	time.Sleep(time.Millisecond * 100)

	var msgs2 []*Subscription
	for _, ps := range psubs[BlossomSubD+1:] {
		subch, err := ps.Subscribe([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		msgs2 = append(msgs2, subch...)
	}

	var collect [][]byte
	for i := 0; i < 10; i++ {
		for _, sub := range msgs2 {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			collect = append(collect, got.Data)
		}
	}

	for i := 0; i < 10; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))
		gotit := false
		for j := 0; j < len(collect); j++ {
			if bytes.Equal(msg, collect[j]) {
				gotit = true
				break
			}
		}
		if !gotit {
			t.Fatalf("Didn't get message %s", string(msg))
		}
	}
}

func TestBlossomSubPrune(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 20)

	psubs := getBlossomSubs(ctx, hosts)

	var msgs []*Subscription
	var bitmasks []*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b...)
		subch, err := ps.Subscribe([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch...)
	}

	denseConnect(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	// disconnect some peers from the mesh to get some PRUNEs
	for _, sub := range msgs[:5] {
		sub.Cancel()
	}

	// wait a bit to take effect
	time.Sleep(time.Millisecond * 100)

	for i := 0; i < 10; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := rand.Intn(len(psubs))

		bitmasks[owner].Publish(ctx, []byte{0x00, 0x01}, msg)

		for _, sub := range msgs[5:] {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}
	}
}

func TestBlossomSubPruneBackoffTime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 10)

	// App specific score that we'll change later.
	currentScoreForHost0 := int32(0)

	params := DefaultBlossomSubParams()
	params.HeartbeatInitialDelay = time.Millisecond * 10
	params.HeartbeatInterval = time.Millisecond * 100

	psubs := getBlossomSubs(ctx, hosts, WithBlossomSubParams(params), WithPeerScore(
		&PeerScoreParams{
			AppSpecificScore: func(p peer.ID) float64 {
				if p == hosts[0].ID() {
					return float64(atomic.LoadInt32(&currentScoreForHost0))
				} else {
					return 0
				}
			},
			AppSpecificWeight: 1,
			DecayInterval:     time.Second,
			DecayToZero:       0.01,
		},
		&PeerScoreThresholds{
			GossipThreshold:   -1,
			PublishThreshold:  -1,
			GraylistThreshold: -1,
		}))

	var msgs []*Subscription

	var bitmasks []*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b...)
		subch, err := ps.Subscribe([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch...)
	}

	connectAll(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second)

	pruneTime := time.Now()
	// Flip the score. Host 0 should be pruned from everyone
	atomic.StoreInt32(&currentScoreForHost0, -1000)

	// wait for heartbeats to run and prune
	time.Sleep(time.Second)

	wg := sync.WaitGroup{}
	var missingBackoffs uint32 = 0
	for i := 1; i < 10; i++ {
		wg.Add(1)
		// Copy i so this func keeps the correct value in the closure.
		var idx = i
		// Run this check in the eval thunk so that we don't step over the heartbeat goroutine and trigger a race.
		psubs[idx].rt.(*BlossomSubRouter).p.eval <- func() {
			defer wg.Done()
			backoff, ok := psubs[idx].rt.(*BlossomSubRouter).backoff[string([]byte{0x00, 0x01})][hosts[0].ID()]
			if !ok {
				atomic.AddUint32(&missingBackoffs, 1)
			}
			if ok && backoff.Sub(pruneTime)-params.PruneBackoff > time.Second {
				t.Errorf("backoff time should be equal to prune backoff (with some slack) was %v", backoff.Sub(pruneTime)-params.PruneBackoff)
			}
		}
	}
	wg.Wait()

	// Sometimes not all the peers will have updated their backoffs by this point. If the majority haven't we'll fail this test.
	if missingBackoffs >= 5 {
		t.Errorf("missing too many backoffs: %v", missingBackoffs)
	}

	for i := 0; i < 10; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		// Don't publish from host 0, since everyone should have pruned it.
		owner := rand.Intn(len(psubs)-1) + 1

		bitmasks[owner].Publish(ctx, []byte{0x00, 0x01}, msg)

		for _, sub := range msgs[1:] {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}
	}
}

func TestBlossomSubGraft(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 20)

	psubs := getBlossomSubs(ctx, hosts)

	sparseConnect(t, hosts)

	time.Sleep(time.Second * 1)

	var msgs []*Subscription
	var bitmasks []*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b...)
		subch, err := ps.Subscribe([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch...)

		// wait for announce to propagate
		time.Sleep(time.Millisecond * 100)
	}

	time.Sleep(time.Second * 1)

	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := rand.Intn(len(psubs))

		bitmasks[owner].Publish(ctx, []byte{0x00, 0x01}, msg)

		for _, sub := range msgs {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}
	}
}

func TestBlossomSubRemovePeer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 20)

	psubs := getBlossomSubs(ctx, hosts)

	var msgs []*Subscription
	var bitmasks []*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b...)
		subch, err := ps.Subscribe([]byte{0x00, 0x01})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch...)
	}

	denseConnect(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	// disconnect some peers to exercise RemovePeer paths
	for _, host := range hosts[:5] {
		host.Close()
	}

	// wait a heartbeat
	time.Sleep(time.Second * 1)

	for i := 0; i < 10; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := 5 + rand.Intn(len(psubs)-5)

		bitmasks[owner].Publish(ctx, []byte{0x00, 0x01}, msg)

		for _, sub := range msgs[5:] {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}
	}
}

func TestBlossomSubGraftPruneRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 10)
	psubs := getBlossomSubs(ctx, hosts)
	denseConnect(t, hosts)

	var msgs [][]*Subscription
	var bitmasks [][]*Bitmask
	for i := 0; i < 35; i++ {
		bitmask := bytes.Repeat([]byte{0x00}, i+1)
		var subs []*Subscription
		var masks []*Bitmask
		for _, ps := range psubs {
			b, err := ps.Join(bitmask)
			if err != nil {
				t.Fatal(err)
			}

			masks = append(masks, b...)
			subch, err := ps.Subscribe(bitmask)
			if err != nil {
				t.Fatal(err)
			}

			subs = append(subs, subch...)
		}
		bitmasks = append(bitmasks, masks)
		msgs = append(msgs, subs)
	}

	// wait for heartbeats to build meshes
	time.Sleep(time.Second * 5)

	for i, bitmask := range bitmasks {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := rand.Intn(len(psubs))

		bitmask[owner].Publish(ctx, bitmask[owner].bitmask, msg)

		for _, sub := range msgs[i] {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}
	}
}

func TestBlossomSubControlPiggyback(t *testing.T) {
	t.Skip("travis regularly fails on this test")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 10)
	psubs := getBlossomSubs(ctx, hosts)
	denseConnect(t, hosts)

	var bitmasks []*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x00, 0x00, 0x00, 0x08})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b...)
		subch, err := ps.Subscribe([]byte{0x00, 0x00, 0x00, 0x08})
		if err != nil {
			t.Fatal(err)
		}
		go func(sub *Subscription) {
			for {
				_, err := sub.Next(ctx)
				if err != nil {
					break
				}
			}
		}(subch[0])
	}

	time.Sleep(time.Second * 1)

	// create a background flood of messages that overloads the queues
	done := make(chan struct{})
	go func() {
		owner := rand.Intn(len(psubs))
		for i := 0; i < 10000; i++ {
			msg := []byte("background flooooood")
			bitmasks[owner].Publish(ctx, []byte{0x00, 0x01}, msg)
		}
		done <- struct{}{}
	}()

	time.Sleep(time.Millisecond * 20)

	// and subscribe to a bunch of bitmasks in the meantime -- this should
	// result in some dropped control messages, with subsequent piggybacking
	// in the background flood
	var otherBitmasks [][]*Bitmask
	var msgs [][]*Subscription
	for i := 0; i < 5; i++ {
		bitmask := make([]byte, i)
		var masks []*Bitmask
		var subs []*Subscription
		for _, ps := range psubs {
			b, err := ps.Join(bitmask)
			if err != nil {
				t.Fatal(err)
			}
			masks = append(masks, b...)

			subch, err := ps.Subscribe(bitmask)
			if err != nil {
				t.Fatal(err)
			}

			subs = append(subs, subch...)
		}

		otherBitmasks = append(otherBitmasks, masks)
		msgs = append(msgs, subs)
	}

	// wait for the flood to stop
	<-done

	// and test that we have functional overlays
	for i, bitmask := range otherBitmasks {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := rand.Intn(len(psubs))

		bitmask[owner].Publish(ctx, []byte{0x00, 0x01}, msg)

		for _, sub := range msgs[i] {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}
	}
}

func TestMixedBlossomSub(t *testing.T) {
	t.Skip("skip unless blossomsub regains some alternate messaging channel baked into the proto")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 30)

	bsubs := getBlossomSubs(ctx, hosts[:20])

	var msgs []*Subscription
	var bitmasks []*Bitmask
	for _, ps := range bsubs {
		b, err := ps.Join([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b...)
		subch, err := ps.Subscribe([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch...)
	}

	sparseConnect(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 4)

	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := rand.Intn(len(bsubs))

		bitmasks[owner].Publish(ctx, []byte{0x00, 0x00, 0x81, 0x00}, msg)

		for _, sub := range msgs {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}
	}
}

func TestBlossomSubMultihops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 6)

	psubs := getBlossomSubs(ctx, hosts)

	connect(t, hosts[0], hosts[1])
	connect(t, hosts[1], hosts[2])
	connect(t, hosts[2], hosts[3])
	connect(t, hosts[3], hosts[4])
	connect(t, hosts[4], hosts[5])

	var subs []*Subscription
	var bitmasks []*Bitmask
	for i := 1; i < 6; i++ {
		b, err := psubs[i].Join([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b...)
		ch, err := psubs[i].Subscribe([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, ch...)
	}

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	msg := []byte("i like cats")
	err := bitmasks[0].Publish(ctx, []byte{0x00, 0x00, 0x81, 0x00}, msg)
	if err != nil {
		t.Fatal(err)
	}

	// last node in the chain should get the message
	select {
	case out := <-subs[4].ch:
		if !bytes.Equal(out.GetData(), msg) {
			t.Fatal("got wrong data")
		}
	case <-time.After(time.Second * 5):
		t.Fatal("timed out waiting for message")
	}
}

func TestBlossomSubTreeTopology(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 10)
	psubs := getBlossomSubs(ctx, hosts)

	connect(t, hosts[0], hosts[1])
	connect(t, hosts[1], hosts[2])
	connect(t, hosts[1], hosts[4])
	connect(t, hosts[2], hosts[3])
	connect(t, hosts[0], hosts[5])
	connect(t, hosts[5], hosts[6])
	connect(t, hosts[5], hosts[8])
	connect(t, hosts[6], hosts[7])
	connect(t, hosts[8], hosts[9])

	/*
		[0] -> [1] -> [2] -> [3]
		 |      L->[4]
		 v
		[5] -> [6] -> [7]
		 |
		 v
		[8] -> [9]
	*/

	var chs [][]*Subscription
	var bitmasks [][]*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b)
		ch, err := ps.Subscribe([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}

		chs = append(chs, ch)
	}

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	assertPeerLists(t, []byte{0x00, 0x00, 0x81, 0x00}, hosts, psubs[0], 1, 5)
	assertPeerLists(t, []byte{0x00, 0x00, 0x81, 0x00}, hosts, psubs[1], 0, 2, 4)
	assertPeerLists(t, []byte{0x00, 0x00, 0x81, 0x00}, hosts, psubs[2], 1, 3)

	checkMessageRouting(t, ctx, []*Bitmask{bitmasks[9][0], bitmasks[3][0]}, chs)
}

// this tests overlay bootstrapping through px in BlossomSub v1.2
// we start with a star topology and rely on px through prune to build the mesh
func TestBlossomSubStarTopology(t *testing.T) {
	originalBlossomSubD := BlossomSubD
	BlossomSubD = 4
	originalBlossomSubDhi := BlossomSubDhi
	BlossomSubDhi = BlossomSubD + 1
	originalBlossomSubDlo := BlossomSubDlo
	BlossomSubDlo = BlossomSubD - 1
	originalBlossomSubDscore := BlossomSubDscore
	BlossomSubDscore = BlossomSubDlo
	defer func() {
		BlossomSubD = originalBlossomSubD
		BlossomSubDhi = originalBlossomSubDhi
		BlossomSubDlo = originalBlossomSubDlo
		BlossomSubDscore = originalBlossomSubDscore
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 20)
	psubs := getBlossomSubs(ctx, hosts, WithPeerExchange(true), WithFloodPublish(true))

	// configure the center of the star with a very low D
	psubs[0].eval <- func() {
		gs := psubs[0].rt.(*BlossomSubRouter)
		gs.params.D = 0
		gs.params.Dlo = 0
		gs.params.Dhi = 0
		gs.params.Dscore = 0
	}

	// add all peer addresses to the peerstores
	// this is necessary because we can't have signed address records witout identify
	// pushing them
	for i := range hosts {
		for j := range hosts {
			if i == j {
				continue
			}
			hosts[i].Peerstore().AddAddrs(hosts[j].ID(), hosts[j].Addrs(), peerstore.PermanentAddrTTL)
		}
	}

	// build the star
	for i := 1; i < 20; i++ {
		connect(t, hosts[0], hosts[i])
	}

	time.Sleep(time.Second)

	// build the mesh
	var subs [][]*Subscription
	var bitmasks []*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b...)
		sub, err := ps.Subscribe([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}

	// wait a bit for the mesh to build
	time.Sleep(2 * time.Second)

	// check that all peers have > 1 connection
	for i, h := range hosts {
		if len(h.Network().Conns()) == 1 {
			t.Errorf("peer %d has ony a single connection", i)
		}
	}

	// send a message from each peer and assert it was propagated
	for i := 0; i < 20; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		bitmasks[i].Publish(ctx, []byte{0x00, 0x00, 0x81, 0x00}, msg)

		for _, sub := range subs {
			assertReceive(t, sub, msg)
		}
	}
}

// this tests overlay bootstrapping through px in BlossomSub v1.2, with addresses
// exchanged in signed peer records.
// we start with a star topology and rely on px through prune to build the mesh
func TestBlossomSubStarTopologyWithSignedPeerRecords(t *testing.T) {
	originalBlossomSubD := BlossomSubD
	BlossomSubD = 4
	originalBlossomSubDhi := BlossomSubDhi
	BlossomSubDhi = BlossomSubD + 1
	originalBlossomSubDlo := BlossomSubDlo
	BlossomSubDlo = BlossomSubD - 1
	originalBlossomSubDscore := BlossomSubDscore
	BlossomSubDscore = BlossomSubDlo
	originalBlossomSubPruneBackoff := BlossomSubPruneBackoff
	BlossomSubPruneBackoff = 2 * time.Second
	defer func() {
		BlossomSubD = originalBlossomSubD
		BlossomSubDhi = originalBlossomSubDhi
		BlossomSubDlo = originalBlossomSubDlo
		BlossomSubDscore = originalBlossomSubDscore
		BlossomSubPruneBackoff = originalBlossomSubPruneBackoff
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 20)
	psubs := getBlossomSubs(ctx, hosts, WithPeerExchange(true), WithFloodPublish(true))

	// configure the center of the star with a very low D
	psubs[0].eval <- func() {
		gs := psubs[0].rt.(*BlossomSubRouter)
		gs.params.D = 0
		gs.params.Dlo = 0
		gs.params.Dhi = 0
		gs.params.Dscore = 0
	}

	// manually create signed peer records for each host and add them to the
	// peerstore of the center of the star, which is doing the bootstrapping
	for i := range hosts[1:] {
		privKey := hosts[i].Peerstore().PrivKey(hosts[i].ID())
		if privKey == nil {
			t.Fatalf("unable to get private key for host %s", hosts[i].ID().String())
		}
		ai := host.InfoFromHost(hosts[i])
		rec := peer.PeerRecordFromAddrInfo(*ai)
		signedRec, err := record.Seal(rec, privKey)
		if err != nil {
			t.Fatalf("error creating signed peer record: %s", err)
		}

		cab, ok := peerstore.GetCertifiedAddrBook(hosts[0].Peerstore())
		if !ok {
			t.Fatal("peerstore does not implement CertifiedAddrBook")
		}
		_, err = cab.ConsumePeerRecord(signedRec, peerstore.PermanentAddrTTL)
		if err != nil {
			t.Fatalf("error adding signed peer record: %s", err)
		}
	}

	// build the star
	for i := 1; i < 20; i++ {
		connect(t, hosts[0], hosts[i])
	}

	time.Sleep(time.Second)

	// build the mesh
	var subs [][]*Subscription
	var bitmasks [][]*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b)
		sub, err := ps.Subscribe([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}

	// wait a bit for the mesh to build
	time.Sleep(10 * time.Second)

	// check that all peers have > 1 connection
	for i, h := range hosts {
		if len(h.Network().Conns()) == 1 {
			t.Errorf("peer %d has only a single connection", i)
		}
	}

	// send a message from each peer and assert it was propagated
	for i := 0; i < 20; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		bitmasks[i][0].Publish(ctx, []byte{0x00, 0x00, 0x81, 0x00}, msg)

		for _, sub := range subs {
			assertReceive(t, sub, msg)
		}
	}
}

func TestBlossomSubDirectPeers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := getDefaultHosts(t, 3)
	psubs := []*PubSub{
		getBlossomSub(ctx, h[0], WithDirectConnectTicks(2)),
		getBlossomSub(ctx, h[1], WithDirectPeers([]peer.AddrInfo{{ID: h[2].ID(), Addrs: h[2].Addrs()}}), WithDirectConnectTicks(2)),
		getBlossomSub(ctx, h[2], WithDirectPeers([]peer.AddrInfo{{ID: h[1].ID(), Addrs: h[1].Addrs()}}), WithDirectConnectTicks(2)),
	}

	connect(t, h[0], h[1])
	connect(t, h[0], h[2])

	// verify that the direct peers connected
	time.Sleep(2 * time.Second)
	if len(h[1].Network().ConnsToPeer(h[2].ID())) == 0 {
		t.Fatal("expected a connection between direct peers")
	}

	// build the mesh
	var subs [][]*Subscription
	var bitmasks [][]*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b)
		sub, err := ps.Subscribe([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}

	time.Sleep(time.Second)

	// publish some messages
	for i := 0; i < 3; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		bitmasks[i][0].Publish(ctx, []byte{0x00, 0x00, 0x81, 0x00}, msg)

		for _, sub := range subs {
			assertReceive(t, sub, msg)
		}
	}

	// disconnect the direct peers to test reconnection
	for _, c := range h[1].Network().ConnsToPeer(h[2].ID()) {
		c.Close()
	}

	time.Sleep(5 * time.Second)

	if len(h[1].Network().ConnsToPeer(h[2].ID())) == 0 {
		t.Fatal("expected a connection between direct peers")
	}

	// publish some messages
	for i := 0; i < 3; i++ {
		msg := []byte(fmt.Sprintf("message %d", i+3))
		bitmasks[i][0].Publish(ctx, []byte{0x00, 0x00, 0x81, 0x00}, msg)

		for _, sub := range subs {
			assertReceive(t, sub, msg)
		}
	}
}

func TestBlossomSubPeerFilter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := getDefaultHosts(t, 3)
	psubs := []*PubSub{
		getBlossomSub(ctx, h[0], WithPeerFilter(func(pid peer.ID, bitmask []byte) bool {
			return pid == h[1].ID()
		})),
		getBlossomSub(ctx, h[1], WithPeerFilter(func(pid peer.ID, bitmask []byte) bool {
			return pid == h[0].ID()
		})),
		getBlossomSub(ctx, h[2]),
	}

	connect(t, h[0], h[1])
	connect(t, h[0], h[2])

	// Join all peers
	var subs [][]*Subscription
	var bitmasks [][]*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b)
		sub, err := ps.Subscribe([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}

	time.Sleep(time.Second)

	msg := []byte("message")

	bitmasks[0][0].Publish(ctx, []byte{0x00, 0x00, 0x81, 0x00}, msg)
	assertReceive(t, subs[0], msg)
	assertReceive(t, subs[1], msg)
	assertNeverReceives(t, subs[2], time.Second)

	msg = []byte("message2")

	bitmasks[1][0].Publish(ctx, []byte{0x00, 0x00, 0x81, 0x00}, msg)
	assertReceive(t, subs[0], msg)
	assertReceive(t, subs[1], msg)
	assertNeverReceives(t, subs[2], time.Second)
}

func TestBlossomSubDirectPeersFanout(t *testing.T) {
	// Temporarily skip, fanout is bugged
	t.SkipNow()
	// regression test for #371
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := getDefaultHosts(t, 3)
	psubs := []*PubSub{
		getBlossomSub(ctx, h[0]),
		getBlossomSub(ctx, h[1], WithDirectPeers([]peer.AddrInfo{{ID: h[2].ID(), Addrs: h[2].Addrs()}})),
		getBlossomSub(ctx, h[2], WithDirectPeers([]peer.AddrInfo{{ID: h[1].ID(), Addrs: h[1].Addrs()}})),
	}

	connect(t, h[0], h[1])
	connect(t, h[0], h[2])

	// Join all peers except h2
	var subs [][]*Subscription
	var bitmasks [][]*Bitmask
	for _, ps := range psubs[:2] {
		b, err := ps.Join([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b)
		sub, err := ps.Subscribe([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}

	time.Sleep(time.Second)

	// h2 publishes some messages to build a fanout
	for i := 0; i < 3; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		psubs[2].Publish(ctx, []byte{0x00, 0x00, 0x81, 0x00}, msg)

		for _, sub := range subs {
			assertReceive(t, sub, msg)
		}
	}

	// verify that h0 is in the fanout of h2, but not h1 who is a direct peer
	result := make(chan bool, 2)
	psubs[2].eval <- func() {
		rt := psubs[2].rt.(*BlossomSubRouter)
		fanout := rt.fanout[string([]byte{0x00, 0x00, 0x81, 0x00})]
		_, ok := fanout[h[0].ID()]
		result <- ok
		_, ok = fanout[h[1].ID()]
		result <- ok
	}

	inFanout := <-result
	if !inFanout {
		t.Fatal("expected peer 0 to be in fanout")
	}

	inFanout = <-result
	if inFanout {
		t.Fatal("expected peer 1 to not be in fanout")
	}

	// now subscribe h2 too and verify tht h0 is in the mesh but not h1
	_, err := psubs[2].Subscribe([]byte{0x00, 0x00, 0x81, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * time.Second)

	psubs[2].eval <- func() {
		rt := psubs[2].rt.(*BlossomSubRouter)
		mesh := rt.mesh[string([]byte{0x00, 0x00, 0x81, 0x00})]
		_, ok := mesh[h[0].ID()]
		result <- ok
		_, ok = mesh[h[1].ID()]
		result <- ok
	}

	inMesh := <-result
	if !inMesh {
		t.Fatal("expected peer 0 to be in mesh")
	}

	inMesh = <-result
	if inMesh {
		t.Fatal("expected peer 1 to not be in mesh")
	}
}

func TestBlossomSubFloodPublish(t *testing.T) {
	// uses a star topology without PX and publishes from the star to verify that all
	// messages get received
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 20)
	psubs := getBlossomSubs(ctx, hosts, WithFloodPublish(true))

	// build the star
	for i := 1; i < 20; i++ {
		connect(t, hosts[0], hosts[i])
	}

	// build the (partial, unstable) mesh
	var subs [][]*Subscription
	var bitmasks [][]*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b)
		sub, err := ps.Subscribe([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}

	time.Sleep(time.Second)

	// send a message from the star and assert it was received
	for i := 0; i < 20; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		bitmasks[0][0].Publish(ctx, []byte{0x00, 0x00, 0x81, 0x00}, msg)

		for _, sub := range subs {
			assertReceive(t, sub, msg)
		}
	}
}

func TestBlossomSubEnoughPeers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 20)
	psubs := getBlossomSubs(ctx, hosts)

	for _, ps := range psubs {
		_, err := ps.Subscribe([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}
	}

	// at this point we have no connections and no mesh, so EnoughPeers should return false
	// NOTE: EnoughPeers operates with bloom filters, so we need to check for individual filters.
	res := make(chan bool, 1)
	psubs[0].eval <- func() {
		res <- psubs[0].rt.EnoughPeers([]byte{0x00, 0x00, 0x80, 0x00}, 0)
	}
	enough := <-res
	if enough {
		t.Fatal("should not have enough peers")
	}

	// connect them densly to build up the mesh
	denseConnect(t, hosts)

	time.Sleep(5 * time.Second)

	psubs[0].eval <- func() {
		res <- psubs[0].rt.EnoughPeers([]byte{0x00, 0x00, 0x80, 0x00}, 0)
	}
	enough = <-res
	if !enough {
		t.Fatal("should have enough peers")
	}
}

func TestBlossomSubCustomParams(t *testing.T) {
	// in this test we score sinkhole a peer to exercise code paths relative to negative scores
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	params := DefaultBlossomSubParams()

	wantedFollowTime := 1 * time.Second
	params.IWantFollowupTime = wantedFollowTime

	wantedMaxPendingConns := 23
	params.MaxPendingConnections = wantedMaxPendingConns
	hosts := getDefaultHosts(t, 1)
	psubs := getBlossomSubs(ctx, hosts,
		WithBlossomSubParams(params))

	if len(psubs) != 1 {
		t.Fatalf("incorrect number of pusbub objects received: wanted %d but got %d", 1, len(psubs))
	}

	rt, ok := psubs[0].rt.(*BlossomSubRouter)
	if !ok {
		t.Fatal("Did not get gossip sub router from pub sub object")
	}

	if rt.params.IWantFollowupTime != wantedFollowTime {
		t.Errorf("Wanted %d of param BlossomSubIWantFollowupTime but got %d", wantedFollowTime, rt.params.IWantFollowupTime)
	}
	if rt.params.MaxPendingConnections != wantedMaxPendingConns {
		t.Errorf("Wanted %d of param BlossomSubMaxPendingConnections but got %d", wantedMaxPendingConns, rt.params.MaxPendingConnections)
	}
}

func TestBlossomSubNegativeScore(t *testing.T) {
	// in this test we score sinkhole a peer to exercise code paths relative to negative scores
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 20)
	psubs := getBlossomSubs(ctx, hosts,
		WithPeerScore(
			&PeerScoreParams{
				AppSpecificScore: func(p peer.ID) float64 {
					if p == hosts[0].ID() {
						return -100000
					} else {
						return 0
					}
				},
				AppSpecificWeight: 1,
				DecayInterval:     time.Second,
				DecayToZero:       0.01,
			},
			&PeerScoreThresholds{
				GossipThreshold:   -10,
				PublishThreshold:  -100,
				GraylistThreshold: -10000,
			}))

	denseConnect(t, hosts)

	var subs [][]*Subscription
	var bitmasks [][]*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b)
		sub, err := ps.Subscribe([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}

	time.Sleep(3 * time.Second)

	for i := 0; i < 20; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		bitmasks[i%20][0].Publish(ctx, []byte{0x00, 0x00, 0x81, 0x00}, msg)
		time.Sleep(20 * time.Millisecond)
	}

	// let the sinkholed peer try to emit gossip as well
	time.Sleep(2 * time.Second)

	// checks:
	// 1. peer 0 should only receive its own message
	// 2. peers 1-20 should not receive a message from peer 0, because it's not part of the mesh
	//    and its gossip is rejected
	collectAll := func(sub []*Subscription) []*Message {
		var res []*Message
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		for _, s := range sub {
			msg, err := s.Next(ctx)
			if err != nil {
				break
			}

			res = append(res, msg)
		}

		return res
	}

	count := len(collectAll(subs[0]))
	if count != 1 {
		t.Fatalf("expected 1 message but got %d instead", count)
	}

	for _, sub := range subs[1:] {
		all := collectAll(sub)
		for _, m := range all {
			if m.ReceivedFrom == hosts[0].ID() {
				t.Fatal("received message from sinkholed peer")
			}
		}
	}
}

func TestBlossomSubScoreValidatorEx(t *testing.T) {
	// this is a test that of the two message drop responses from a validator
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 3)
	psubs := getBlossomSubs(ctx, hosts,
		WithPeerScore(
			&PeerScoreParams{
				AppSpecificScore: func(p peer.ID) float64 { return 0 },
				DecayInterval:    time.Second,
				DecayToZero:      0.01,
				Bitmasks: map[string]*BitmaskScoreParams{
					string([]byte{0x00, 0x00, 0x81, 0x00}): {
						BitmaskWeight:                  1,
						TimeInMeshQuantum:              time.Second,
						InvalidMessageDeliveriesWeight: -1,
						InvalidMessageDeliveriesDecay:  0.9999,
					},
				},
			},
			&PeerScoreThresholds{
				GossipThreshold:   -10,
				PublishThreshold:  -100,
				GraylistThreshold: -10000,
			}))

	connectAll(t, hosts)

	err := psubs[0].RegisterBitmaskValidator([]byte{0x00, 0x00, 0x81, 0x00}, func(ctx context.Context, p peer.ID, msg *Message) ValidationResult {
		// we ignore host1 and reject host2
		if p == hosts[1].ID() {
			return ValidationIgnore
		}
		if p == hosts[2].ID() {
			return ValidationReject
		}

		return ValidationAccept
	})
	if err != nil {
		t.Fatal(err)
	}

	sub, err := psubs[0].Subscribe([]byte{0x00, 0x00, 0x81, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	b1, err := psubs[1].Join([]byte{0x00, 0x00, 0x81, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	b2, err := psubs[2].Join([]byte{0x00, 0x00, 0x81, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond)

	expectNoMessage := func(sub *Subscription) {
		ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()

		m, err := sub.Next(ctx)
		if err == nil {
			t.Fatal("expected no message, but got ", string(m.Data))
		}
	}

	b1[0].Publish(ctx, []byte{0x00, 0x00, 0x81, 0x00}, []byte("i am not a walrus"))
	b2[0].Publish(ctx, []byte{0x00, 0x00, 0x81, 0x00}, []byte("i am not a walrus either"))

	// assert no messages
	expectNoMessage(sub[0])

	// assert that peer1's score is still 0 (its message was ignored) while peer2 should have
	// a negative score (its message got rejected)
	res := make(chan float64, 1)
	psubs[0].eval <- func() {
		res <- psubs[0].rt.(*BlossomSubRouter).score.Score(hosts[1].ID())
	}
	score := <-res
	if score != 0 {
		t.Fatalf("expected 0 score for peer1, but got %f", score)
	}

	psubs[0].eval <- func() {
		res <- psubs[0].rt.(*BlossomSubRouter).score.Score(hosts[2].ID())
	}
	score = <-res
	if score >= 0 {
		t.Fatalf("expected negative score for peer2, but got %f", score)
	}
}

func TestBlossomSubPiggybackControl(t *testing.T) {
	// this is a direct test of the piggybackControl function as we can't reliably
	// trigger it on travis
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := getDefaultHosts(t, 1)[0]
	ps := getBlossomSub(ctx, h)

	blah := peer.ID("bogotr0n")

	res := make(chan *RPC, 1)
	ps.eval <- func() {
		gs := ps.rt.(*BlossomSubRouter)
		test1 := []byte{0x00, 0x81, 0x00, 0x00}
		test2 := []byte{0x00, 0x20, 0x00, 0x00}
		test3 := []byte{0x00, 0x00, 0x02, 0x00}
		gs.mesh[string(test1)] = make(map[peer.ID]struct{})
		gs.mesh[string(test2)] = make(map[peer.ID]struct{})
		gs.mesh[string(test1)][blah] = struct{}{}

		rpc := &RPC{RPC: &pb.RPC{}}
		gs.piggybackControl(blah, rpc, &pb.ControlMessage{
			Graft: []*pb.ControlGraft{{Bitmask: test1}, {Bitmask: test2}, {Bitmask: test3}},
			Prune: []*pb.ControlPrune{{Bitmask: test1}, {Bitmask: test2}, {Bitmask: test3}},
		})
		res <- rpc
	}

	rpc := <-res
	if rpc.Control == nil {
		t.Fatal("expected non-nil control message")
	}
	if len(rpc.Control.Graft) != 1 {
		t.Fatal("expected 1 GRAFT")
	}
	if !bytes.Equal(rpc.Control.Graft[0].GetBitmask(), []byte{0x00, 0x81, 0x00, 0x00}) {
		t.Fatal("expected test1 as graft bitmask ID")
	}
	if len(rpc.Control.Prune) != 2 {
		t.Fatal("expected 2 PRUNEs")
	}
	if !bytes.Equal(rpc.Control.Prune[0].GetBitmask(), []byte{0x00, 0x20, 0x00, 0x00}) {
		t.Fatal("expected test2 as prune bitmask ID")
	}
	if !bytes.Equal(rpc.Control.Prune[1].GetBitmask(), []byte{0x00, 0x00, 0x02, 0x00}) {
		t.Fatal("expected test3 as prune bitmask ID")
	}
}

func TestBlossomSubMultipleGraftBitmasks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 2)
	psubs := getBlossomSubs(ctx, hosts)
	sparseConnect(t, hosts)

	time.Sleep(time.Second * 1)

	firstBitmask := []byte{0x00, 0x81, 0x00, 0x00}
	secondBitmask := []byte{0x00, 0x20, 0x00, 0x00}
	thirdBitmask := []byte{0x00, 0x00, 0x02, 0x00}

	firstPeer := hosts[0].ID()
	secondPeer := hosts[1].ID()

	p2Sub := psubs[1]
	p1Router := psubs[0].rt.(*BlossomSubRouter)
	p2Router := psubs[1].rt.(*BlossomSubRouter)

	finChan := make(chan struct{})

	p2Sub.eval <- func() {
		// Add bitmasks to second peer
		p2Router.mesh[string(firstBitmask)] = map[peer.ID]struct{}{}
		p2Router.mesh[string(secondBitmask)] = map[peer.ID]struct{}{}
		p2Router.mesh[string(thirdBitmask)] = map[peer.ID]struct{}{}

		finChan <- struct{}{}
	}
	<-finChan

	// Send multiple GRAFT messages to second peer from
	// 1st peer
	p1Router.sendGraftPrune(map[peer.ID][][]byte{
		secondPeer: {firstBitmask, secondBitmask, thirdBitmask},
	}, map[peer.ID][][]byte{}, map[peer.ID]bool{})

	time.Sleep(time.Second * 1)

	p2Sub.eval <- func() {
		if _, ok := p2Router.mesh[string(firstBitmask)][firstPeer]; !ok {
			t.Errorf("First peer wasnt added to mesh of the second peer for the bitmask %s", firstBitmask)
		}
		if _, ok := p2Router.mesh[string(secondBitmask)][firstPeer]; !ok {
			t.Errorf("First peer wasnt added to mesh of the second peer for the bitmask %s", secondBitmask)
		}
		if _, ok := p2Router.mesh[string(thirdBitmask)][firstPeer]; !ok {
			t.Errorf("First peer wasnt added to mesh of the second peer for the bitmask %s", thirdBitmask)
		}
		finChan <- struct{}{}
	}
	<-finChan
}

func TestBlossomSubOpportunisticGrafting(t *testing.T) {
	originalBlossomSubPruneBackoff := BlossomSubPruneBackoff
	BlossomSubPruneBackoff = 500 * time.Millisecond
	originalBlossomSubGraftFloodThreshold := BlossomSubGraftFloodThreshold
	BlossomSubGraftFloodThreshold = 100 * time.Millisecond
	originalBlossomSubOpportunisticGraftTicks := BlossomSubOpportunisticGraftTicks
	BlossomSubOpportunisticGraftTicks = 2
	defer func() {
		BlossomSubPruneBackoff = originalBlossomSubPruneBackoff
		BlossomSubGraftFloodThreshold = originalBlossomSubGraftFloodThreshold
		BlossomSubOpportunisticGraftTicks = originalBlossomSubOpportunisticGraftTicks
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 50)
	// pubsubs for the first 10 hosts
	psubs := getBlossomSubs(ctx, hosts[:10],
		WithFloodPublish(true),
		WithPeerScore(
			&PeerScoreParams{
				AppSpecificScore:  func(peer.ID) float64 { return 0 },
				AppSpecificWeight: 0,
				DecayInterval:     time.Second,
				DecayToZero:       0.01,
				Bitmasks: map[string]*BitmaskScoreParams{
					string([]byte{0x00, 0x00, 0x81, 0x00}): {
						BitmaskWeight:                 1,
						TimeInMeshWeight:              0.0002777,
						TimeInMeshQuantum:             time.Second,
						TimeInMeshCap:                 3600,
						FirstMessageDeliveriesWeight:  1,
						FirstMessageDeliveriesDecay:   0.9997,
						FirstMessageDeliveriesCap:     100,
						InvalidMessageDeliveriesDecay: 0.99997,
					},
				},
			},
			&PeerScoreThresholds{
				GossipThreshold:             -10,
				PublishThreshold:            -100,
				GraylistThreshold:           -10000,
				OpportunisticGraftThreshold: 1,
			}))

	// connect the real hosts with degree 5
	connectSome(t, hosts[:10], 5)

	// sybil squatters for the remaining 40 hosts
	for _, h := range hosts[10:] {
		squatter := &sybilSquatter{h: h}
		h.SetStreamHandler(BlossomSubID_v2, squatter.handleStream)
	}

	// connect all squatters to every real host
	for _, squatter := range hosts[10:] {
		for _, real := range hosts[:10] {
			connect(t, squatter, real)
		}
	}

	// wait a bit for the connections to propagate events to the pubsubs
	time.Sleep(time.Second)

	// ask the real pubsus to join the bitmask
	var bitmasks []*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b...)
		sub, err := ps.Subscribe([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		// consume the messages
		go func(sub *Subscription) {
			for {
				_, err := sub.Next(ctx)
				if err != nil {
					return
				}
			}
		}(sub[0])
	}

	// publish a bunch of messages from the real hosts
	for i := 0; i < 1000; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		bitmasks[i%10].Publish(ctx, []byte{0x00, 0x00, 0x81, 0x00}, msg)
		time.Sleep(20 * time.Millisecond)
	}

	// now wait a few of oppgraft cycles
	time.Sleep(7 * time.Second)

	// check the honest peer meshes, they should have at least 3 honest peers each
	res := make(chan int, 1)
	for _, ps := range psubs {
		ps.eval <- func() {
			count := 0
			for _, h := range hosts[:10] {
				peers := ps.getPeersInBitmask([]byte{0x00, 0x00, 0x81, 0x00})
				for _, p := range peers {
					if p == h.ID() {
						count++
					}
				}
			}
			res <- count
		}

		count := <-res
		if count < 3 {
			t.Fatalf("expected at least 3 honest peers, got %d", count)
		}
	}
}

func TestBlossomSubLeaveBitmask(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := getDefaultHosts(t, 2)
	psubs := []*PubSub{
		getBlossomSub(ctx, h[0]),
		getBlossomSub(ctx, h[1]),
	}

	connect(t, h[0], h[1])

	// Join all peers
	var subs [][]*Subscription
	for _, ps := range psubs {
		sub, err := ps.Subscribe([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}

	time.Sleep(time.Second)

	leaveTime := time.Now()
	done := make(chan struct{})

	// NOTE: Leave operates with bloom filters, so we need to check for individual filters.
	psubs[0].rt.(*BlossomSubRouter).p.eval <- func() {
		defer close(done)
		psubs[0].rt.Leave([]byte{0x00, 0x00, 0x80, 0x00})
		time.Sleep(time.Second)
		peerMap := psubs[0].rt.(*BlossomSubRouter).backoff[string([]byte{0x00, 0x00, 0x80, 0x00})]
		if len(peerMap) != 1 {
			t.Fatalf("No peer is populated in the backoff map for peer 0")
		}
		_, ok := peerMap[h[1].ID()]
		if !ok {
			t.Errorf("Expected peer does not exist in the backoff map")
		}

		backoffTime := peerMap[h[1].ID()].Sub(leaveTime)
		// Check that the backoff time is roughly the unsubscribebackoff time (with a slack of 1s)
		if backoffTime-BlossomSubUnsubscribeBackoff > time.Second {
			t.Error("Backoff time should be set to BlossomSubUnsubscribeBackoff.")
		}
	}
	<-done

	done = make(chan struct{})
	// Ensure that remote peer 1 also applies the backoff appropriately
	// for peer 0.
	psubs[1].rt.(*BlossomSubRouter).p.eval <- func() {
		defer close(done)
		peerMap2 := psubs[1].rt.(*BlossomSubRouter).backoff[string([]byte{0x00, 0x00, 0x80, 0x00})]
		if len(peerMap2) != 1 {
			t.Fatalf("No peer is populated in the backoff map for peer 1")
		}
		_, ok := peerMap2[h[0].ID()]
		if !ok {
			t.Errorf("Expected peer does not exist in the backoff map")
		}

		backoffTime := peerMap2[h[0].ID()].Sub(leaveTime)
		// Check that the backoff time is roughly the unsubscribebackoff time (with a slack of 1s)
		if backoffTime-BlossomSubUnsubscribeBackoff > time.Second {
			t.Error("Backoff time should be set to BlossomSubUnsubscribeBackoff.")
		}
	}
	<-done
}

func TestBlossomSubJoinBitmask(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := getDefaultHosts(t, 3)
	psubs := []*PubSub{
		getBlossomSub(ctx, h[0]),
		getBlossomSub(ctx, h[1]),
		getBlossomSub(ctx, h[2]),
	}

	connect(t, h[0], h[1])
	connect(t, h[0], h[2])

	router0 := psubs[0].rt.(*BlossomSubRouter)

	// Add in backoff for peer.
	ran := make(chan struct{})
	router0.p.eval <- func() {
		defer close(ran)
		peerMap := make(map[peer.ID]time.Time)
		peerMap[h[1].ID()] = time.Now().Add(router0.params.UnsubscribeBackoff)
		router0.backoff[string([]byte{0x00, 0x00, 0x80, 0x00})] = peerMap
	}
	<-ran

	// Join all peers
	var subs [][]*Subscription
	for _, ps := range psubs {
		sub, err := ps.Subscribe([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}

	time.Sleep(time.Second)

	ran = make(chan struct{})
	var meshMap map[peer.ID]struct{}
	router0.p.eval <- func() {
		defer close(ran)
		meshMap = maps.Clone(router0.mesh[string([]byte{0x00, 0x00, 0x80, 0x00})])
	}
	<-ran

	if len(meshMap) != 1 {
		t.Fatalf("Unexpect peer included in the mesh")
	}
	_, ok := meshMap[h[1].ID()]
	if ok {
		t.Fatalf("Peer that was to be backed off is included in the mesh")
	}
}

type sybilSquatter struct {
	h host.Host
}

func (sq *sybilSquatter) handleStream(s network.Stream) {
	defer s.Close()

	os, err := sq.h.NewStream(context.Background(), s.Conn().RemotePeer(), BlossomSubID_v2)
	if err != nil {
		panic(err)
	}

	// send a subscription for test in the output stream to become candidate for GRAFT
	// and then just read and ignore the incoming RPCs
	r := msgio.NewVarintReaderSize(s, DefaultHardMaxMessageSize)
	w := msgio.NewVarintWriter(os)
	truth := true
	bitmask := []byte{0x00, 0x00, 0x81, 0x00}
	msg := &pb.RPC{Subscriptions: []*pb.RPC_SubOpts{{Subscribe: truth, Bitmask: bitmask}}}
	out, err := proto.Marshal(msg)
	if err != nil {
		panic(err)
	}

	err = w.WriteMsg(out)
	if err != nil {
		panic(err)
	}

	var rpc pb.RPC
	for {
		rpc.Reset()
		v, err := r.ReadMsg()
		if err != nil {
			break
		}

		err = proto.Unmarshal(v, &rpc)
		if err != nil {
			break
		}
	}
}

func TestBlossomSubPeerScoreInspect(t *testing.T) {
	t.SkipNow()
	// this test exercises the code paths of peer score inspection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 2)

	inspector := &mockPeerScoreInspector{}
	psub1 := getBlossomSub(ctx, hosts[0],
		WithPeerScore(
			&PeerScoreParams{
				Bitmasks: map[string]*BitmaskScoreParams{
					string([]byte{0x00, 0x00, 0x81, 0x00}): {
						BitmaskWeight:                  1,
						TimeInMeshQuantum:              time.Second,
						FirstMessageDeliveriesWeight:   1,
						FirstMessageDeliveriesDecay:    0.999,
						FirstMessageDeliveriesCap:      100,
						InvalidMessageDeliveriesWeight: -1,
						InvalidMessageDeliveriesDecay:  0.9999,
					},
				},
				AppSpecificScore: func(peer.ID) float64 { return 0 },
				DecayInterval:    time.Second,
				DecayToZero:      0.01,
			},
			&PeerScoreThresholds{
				GossipThreshold:   -1,
				PublishThreshold:  -10,
				GraylistThreshold: -1000,
			}),
		WithPeerScoreInspect(inspector.inspect, time.Second))
	psub2 := getBlossomSub(ctx, hosts[1])
	psubs := []*PubSub{psub1, psub2}

	connect(t, hosts[0], hosts[1])
	var bitmasks []*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b...)
		_, err = ps.Subscribe([]byte{0x00, 0x00, 0x81, 0x00})
		if err != nil {
			t.Fatal(err)
		}
	}

	time.Sleep(time.Second)

	for i := 0; i < 20; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		bitmasks[i%2].Publish(ctx, []byte{0x00, 0x00, 0x81, 0x00}, msg)
		time.Sleep(20 * time.Millisecond)
	}

	time.Sleep(time.Second + 200*time.Millisecond)

	score2 := inspector.score(hosts[1].ID())
	if score2 < 9 {
		t.Fatalf("expected score to be at least 9, instead got %f", score2)
	}
}

func TestBlossomSubPeerScoreResetBitmaskParams(t *testing.T) {
	// this test exercises the code path sof peer score inspection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 1)

	ps := getBlossomSub(ctx, hosts[0],
		WithPeerScore(
			&PeerScoreParams{
				Bitmasks: map[string]*BitmaskScoreParams{
					string([]byte{0x00, 0x00, 0x81, 0x00}): {
						BitmaskWeight:                  1,
						TimeInMeshQuantum:              time.Second,
						FirstMessageDeliveriesWeight:   1,
						FirstMessageDeliveriesDecay:    0.999,
						FirstMessageDeliveriesCap:      100,
						InvalidMessageDeliveriesWeight: -1,
						InvalidMessageDeliveriesDecay:  0.9999,
					},
				},
				AppSpecificScore: func(peer.ID) float64 { return 0 },
				DecayInterval:    time.Second,
				DecayToZero:      0.01,
			},
			&PeerScoreThresholds{
				GossipThreshold:   -1,
				PublishThreshold:  -10,
				GraylistThreshold: -1000,
			}))

	bitmask, err := ps.Join([]byte{0x00, 0x00, 0x81, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	err = bitmask[0].SetScoreParams(
		&BitmaskScoreParams{
			BitmaskWeight:                  1,
			TimeInMeshQuantum:              time.Second,
			FirstMessageDeliveriesWeight:   1,
			FirstMessageDeliveriesDecay:    0.999,
			FirstMessageDeliveriesCap:      200,
			InvalidMessageDeliveriesWeight: -1,
			InvalidMessageDeliveriesDecay:  0.9999,
		})
	if err != nil {
		t.Fatal(err)
	}
}

type mockPeerScoreInspector struct {
	mx     sync.Mutex
	scores map[peer.ID]float64
}

func (ps *mockPeerScoreInspector) inspect(scores map[peer.ID]float64) {
	ps.mx.Lock()
	defer ps.mx.Unlock()
	ps.scores = scores
}

func (ps *mockPeerScoreInspector) score(p peer.ID) float64 {
	ps.mx.Lock()
	defer ps.mx.Unlock()
	return ps.scores[p]
}

func TestBlossomSubRPCFragmentation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 2)
	ps := getBlossomSub(ctx, hosts[0])

	// make a fake peer that requests everything through IWANT gossip
	iwe := iwantEverything{h: hosts[1]}
	iwe.h.SetStreamHandler(BlossomSubID_v2, iwe.handleStream)

	connect(t, hosts[0], hosts[1])

	// have the real pubsub join the test bitmask
	b, err := ps.Join([]byte{0x00, 0x00, 0x81, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ps.Subscribe([]byte{0x00, 0x00, 0x81, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	// wait for the real pubsub to connect and try to graft to the faker
	time.Sleep(time.Second)

	// publish a bunch of fairly large messages from the real host
	nMessages := 1000
	msgSize := 20000
	for i := 0; i < nMessages; i++ {
		msg := make([]byte, msgSize)
		crand.Read(msg)
		b[0].Publish(ctx, []byte{0x00, 0x00, 0x81, 0x00}, msg)
		time.Sleep(20 * time.Millisecond)
	}

	// wait a bit for them to be received via gossip by the fake peer
	time.Sleep(5 * time.Second)
	iwe.lk.Lock()
	defer iwe.lk.Unlock()

	// we should have received all the messages
	if iwe.msgsReceived != nMessages {
		t.Fatalf("expected fake BlossomSub peer to receive all messages, got %d / %d", iwe.msgsReceived, nMessages)
	}

	// and we should have seen an IHAVE message for each of them
	if iwe.ihavesReceived != nMessages {
		t.Fatalf("expected to get IHAVEs for every message, got %d / %d", iwe.ihavesReceived, nMessages)
	}

	// If everything were fragmented with maximum efficiency, we would expect to get
	// (nMessages * msgSize) / ps.maxMessageSize total RPCs containing the messages we sent IWANTs for.
	// The actual number will probably be larger, since there's some overhead for the RPC itself, and
	// we probably aren't packing each RPC to it's maximum size
	minExpectedRPCS := (nMessages * msgSize) / ps.softMaxMessageSize
	if iwe.rpcsWithMessages < minExpectedRPCS {
		t.Fatalf("expected to receive at least %d RPCs containing messages, got %d", minExpectedRPCS, iwe.rpcsWithMessages)
	}
}

// iwantEverything is a simple BlossomSub client that never grafts onto a mesh,
// instead requesting everything through IWANT gossip messages. It is used to
// test that large responses to IWANT requests are fragmented into multiple RPCs.
type iwantEverything struct {
	h                host.Host
	lk               sync.Mutex
	rpcsWithMessages int
	msgsReceived     int
	ihavesReceived   int
}

func (iwe *iwantEverything) handleStream(s network.Stream) {
	defer s.Close()

	os, err := iwe.h.NewStream(context.Background(), s.Conn().RemotePeer(), BlossomSubID_v2)
	if err != nil {
		panic(err)
	}

	msgIdsReceived := make(map[string]struct{})
	gossipMsgIdsReceived := make(map[string]struct{})

	// send a subscription for test in the output stream to become candidate for gossip
	r := msgio.NewVarintReaderSize(s, DefaultHardMaxMessageSize)
	w := msgio.NewVarintWriter(os)
	truth := true
	bitmasks := [][]byte{{0x00, 0x00, 0x80, 0x00}, {0x00, 0x00, 0x01, 0x00}}
	msg := &pb.RPC{Subscriptions: []*pb.RPC_SubOpts{{Subscribe: truth, Bitmask: bitmasks[0]}, {Subscribe: truth, Bitmask: bitmasks[1]}}}
	out, err := proto.Marshal(msg)

	if err != nil {
		panic(err)
	}

	err = w.WriteMsg(out)
	if err != nil {
		panic(err)
	}

	var rpc pb.RPC
	for {
		rpc.Reset()
		v, err := r.ReadMsg()
		if err != nil {
			break
		}

		err = proto.Unmarshal(v, &rpc)
		if err != nil {
			break
		}

		iwe.lk.Lock()
		if len(rpc.Publish) != 0 {
			iwe.rpcsWithMessages++
		}
		// keep track of unique message ids received
		for _, msg := range rpc.Publish {
			id := string(msg.Seqno)
			if _, seen := msgIdsReceived[id]; !seen {
				iwe.msgsReceived++
			}
			msgIdsReceived[id] = struct{}{}
		}

		if rpc.Control != nil {
			// send a PRUNE for all grafts, so we don't get direct message deliveries
			var prunes []*pb.ControlPrune
			for _, graft := range rpc.Control.Graft {
				prunes = append(prunes, &pb.ControlPrune{Bitmask: graft.Bitmask})
			}

			var iwants []*pb.ControlIWant
			for _, ihave := range rpc.Control.Ihave {
				iwants = append(iwants, &pb.ControlIWant{MessageIDs: ihave.MessageIDs})
				for _, msgId := range ihave.MessageIDs {
					if _, seen := gossipMsgIdsReceived[string(msgId)]; !seen {
						iwe.ihavesReceived++
					}
					gossipMsgIdsReceived[string(msgId)] = struct{}{}
				}
			}

			msg := rpcWithControl(nil, nil, iwants, nil, prunes, nil)
			out, err := proto.Marshal(msg)

			if err != nil {
				panic(err)
			}

			err = w.WriteMsg(out)
			if err != nil {
				panic(err)
			}
		}
		iwe.lk.Unlock()
	}
}

func TestFragmentRPCFunction(t *testing.T) {
	p := peer.ID("some-peer")
	bitmask := []byte{0x00, 0x00, 0x81, 0x00}
	rpc := &RPC{RPC: new(pb.RPC), from: p}
	limit := 1024

	mkMsg := func(size int) *pb.Message {
		msg := &pb.Message{}
		msg.Data = make([]byte, size-4) // subtract the protobuf overhead, so msg.Size() returns requested size
		crand.Read(msg.Data)
		return msg
	}

	ensureBelowLimit := func(rpcs []*RPC) {
		for _, r := range rpcs {
			if r.Size() > limit {
				t.Fatalf("expected fragmented RPC to be below %d bytes, was %d", limit, r.Size())
			}
		}
	}

	// it should not fragment if everything fits in one RPC
	rpc.Publish = []*pb.Message{}
	rpc.Publish = []*pb.Message{mkMsg(10), mkMsg(10)}
	results := appendOrMergeRPC([]*RPC{}, limit, rpc)
	if len(results) != 1 {
		t.Fatalf("expected single RPC if input is < limit, got %d", len(results))
	}

	// if there's a message larger than the limit, we should fail
	rpc.Publish = []*pb.Message{mkMsg(10), mkMsg(limit * 2)}
	results = appendOrMergeRPC([]*RPC{}, limit, rpc)

	// if the individual messages are below the limit, but the RPC as a whole is larger, we should fragment
	nMessages := 100
	msgSize := 200
	truth := true
	rpc.Subscriptions = []*pb.RPC_SubOpts{
		{
			Subscribe: truth,
			Bitmask:   bitmask,
		},
	}
	rpc.Publish = make([]*pb.Message, nMessages)
	for i := 0; i < nMessages; i++ {
		rpc.Publish[i] = mkMsg(msgSize)
	}
	results = appendOrMergeRPC([]*RPC{}, limit, rpc)
	ensureBelowLimit(results)
	msgsPerRPC := limit / msgSize
	expectedRPCs := nMessages / msgsPerRPC
	if len(results) != expectedRPCs {
		t.Fatalf("expected %d RPC messages in output, got %d", expectedRPCs, len(results))
	}
	var nMessagesFragmented int
	var nSubscriptions int
	for _, r := range results {
		nMessagesFragmented += len(r.Publish)
		nSubscriptions += len(r.Subscriptions)
	}
	if nMessagesFragmented != nMessages {
		t.Fatalf("expected fragemented RPCs to contain same number of messages as input, got %d / %d", nMessagesFragmented, nMessages)
	}
	if nSubscriptions != 1 {
		t.Fatal("expected subscription to be present in one of the fragmented messages, but not found")
	}

	// if we're fragmenting, and the input RPC has control messages,
	// the control messages should be in a separate RPC at the end
	// reuse RPC from prev test, but add a control message
	rpc.Control = &pb.ControlMessage{
		Graft: []*pb.ControlGraft{{Bitmask: bitmask}},
		Prune: []*pb.ControlPrune{{Bitmask: bitmask}},
		Ihave: []*pb.ControlIHave{{MessageIDs: [][]byte{[]byte("foo")}}},
		Iwant: []*pb.ControlIWant{{MessageIDs: [][]byte{[]byte("bar")}}},
	}
	results = appendOrMergeRPC([]*RPC{}, limit, rpc)
	ensureBelowLimit(results)
	// we expect one more RPC than last time, with the final one containing the control messages
	expectedCtrl := 1
	expectedRPCs = (nMessages / msgsPerRPC) + expectedCtrl
	if len(results) != expectedRPCs {
		t.Fatalf("expected %d RPC messages in output, got %d", expectedRPCs, len(results))
	}
	ctl := results[len(results)-1].Control
	if ctl == nil {
		t.Fatal("expected final fragmented RPC to contain control messages, but .Control was nil")
	}
	// since it was not altered, the original control message should be identical to the output control message
	originalBytes, err := rpc.Control.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	receivedBytes, err := ctl.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalBytes, receivedBytes) {
		t.Fatal("expected control message to be unaltered if it fits within one RPC message")
	}

	// if the control message is too large to fit into a single RPC, it should be split into multiple RPCs
	nBitmasks := 5 // pretend we're subscribed to multiple bitmasks and sending IHAVE / IWANTs for each
	messageIdSize := 32
	msgsPerBitmask := 100 // enough that a single IHAVE or IWANT will exceed the limit
	rpc.Control.Ihave = make([]*pb.ControlIHave, nBitmasks)
	rpc.Control.Iwant = make([]*pb.ControlIWant, nBitmasks)
	for i := 0; i < nBitmasks; i++ {
		messageIds := make([][]byte, msgsPerBitmask)
		for m := 0; m < msgsPerBitmask; m++ {
			mid := make([]byte, messageIdSize)
			crand.Read(mid)
			messageIds[m] = mid
		}
		rpc.Control.Ihave[i] = &pb.ControlIHave{MessageIDs: messageIds}
		rpc.Control.Iwant[i] = &pb.ControlIWant{MessageIDs: messageIds}
	}
	results = appendOrMergeRPC([]*RPC{}, limit, rpc)
	ensureBelowLimit(results)
	minExpectedCtl := rpc.Control.Size() / limit
	minExpectedRPCs := (nMessages / msgsPerRPC) + minExpectedCtl
	if len(results) < minExpectedRPCs {
		t.Fatalf("expected at least %d total RPCs (at least %d with control messages), got %d total", expectedRPCs, expectedCtrl, len(results))
	}

	// Test the pathological case where a single gossip message ID exceeds the limit.
	rpc.Reset()
	giantIdBytes := make([]byte, limit*2)
	crand.Read(giantIdBytes)
	rpc.Control = &pb.ControlMessage{
		Iwant: []*pb.ControlIWant{
			{MessageIDs: [][]byte{[]byte("hello"), giantIdBytes}},
		},
	}
	results = appendOrMergeRPC([]*RPC{}, limit, rpc)
	if len(results) != 2 {
		t.Fatalf("expected 2 RPC, got %d", len(results))
	}
	if len(results[0].Control.Iwant) != 1 {
		t.Fatalf("expected 1 IWANT, got %d", len(results[0].Control.Iwant))
	}
	if len(results[1].Control.Iwant) != 1 {
		t.Fatalf("expected 1 IWANT, got %d", len(results[1].Control.Iwant))
	}
	if !bytes.Equal(results[0].Control.Iwant[0].MessageIDs[0], []byte("hello")) {
		t.Fatalf("expected small message ID to be included unaltered, got %s instead",
			results[0].Control.Iwant[0].MessageIDs[0])
	}
	if !bytes.Equal(results[1].Control.Iwant[0].MessageIDs[0], giantIdBytes) {
		t.Fatalf("expected giant message ID to be included unaltered, got %s instead",
			results[1].Control.Iwant[0].MessageIDs[0])
	}
}

func TestBlossomSubIdontwantSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 3)

	msgID := func(pmsg *pb.Message) []byte {
		mid := sha256.Sum256(pmsg.Data)
		return mid[:]
	}

	var validated atomic.Bool
	validate := func(context.Context, peer.ID, *Message) bool {
		time.Sleep(100 * time.Millisecond)
		validated.Store(true)
		return true
	}

	params := DefaultBlossomSubParams()
	params.IDontWantMessageThreshold = 16

	psubs := make([]*PubSub, 2)
	psubs[0] = getBlossomSub(ctx, hosts[0],
		WithBlossomSubParams(params),
		WithMessageIdFn(msgID))
	psubs[1] = getBlossomSub(ctx, hosts[1],
		WithBlossomSubParams(params),
		WithMessageIdFn(msgID),
		WithDefaultValidator(validate))

	bitmask := []byte{0x20, 0x00, 0x00}
	for _, ps := range psubs {
		_, err := ps.Subscribe(bitmask)
		if err != nil {
			t.Fatal(err)
		}
	}

	var expMids [][]byte
	var actMids [][]byte
	mx := sync.Mutex{}

	// Used to publish a message with random data
	publishMsg := func() {
		mx.Lock()
		defer mx.Unlock()
		data := make([]byte, 16)
		crand.Read(data)
		m := &pb.Message{Data: data}
		expMids = append(expMids, msgID(m))

		if err := psubs[0].Publish(ctx, bitmask, data); err != nil {
			t.Fatal(err)
		}
	}

	// Wait a bit after the last message before checking we got the right messages
	msgWaitMax := time.Second
	msgTimer := time.NewTimer(msgWaitMax)

	// Checks we received the right IDONTWANT messages
	checkMsgs := func() {
		mx.Lock()
		defer mx.Unlock()
		sort.Slice(actMids, func(i, j int) bool {
			return bytes.Compare(actMids[i], actMids[j]) < 0
		})
		sort.Slice(expMids, func(i, j int) bool {
			return bytes.Compare(expMids[i], expMids[j]) < 0
		})

		if len(actMids) != len(expMids) {
			t.Fatalf("Expected %d IDONTWANT messages, got %d", len(expMids), len(actMids))
		}
		for i, expMid := range expMids {
			actMid := actMids[i]
			if !bytes.Equal(expMid, actMid) {
				t.Fatalf("Expected the id of %x in the %d'th IDONTWANT messages, got %x", expMid, i+1, actMid)
			}
		}
	}

	// Wait for the timer to expire
	go func() {
		select {
		case <-msgTimer.C:
			checkMsgs()
			cancel()
			return
		case <-ctx.Done():
			checkMsgs()
		}
	}()

	newMockBS(ctx, t, hosts[2], func(writeMsg func(*pb.RPC), irpc *pb.RPC) {
		// When the middle peer connects it will send us its subscriptions
		for _, sub := range irpc.GetSubscriptions() {
			if sub.GetSubscribe() {
				// Reply by subcribing to the bitmask and grafting to the middle peer
				writeMsg(&pb.RPC{
					Subscriptions: []*pb.RPC_SubOpts{{Subscribe: sub.Subscribe, Bitmask: sub.Bitmask}},
					Control:       &pb.ControlMessage{Graft: []*pb.ControlGraft{{Bitmask: sub.Bitmask}}},
				})

				go func() {
					// Wait for a short interval to make sure the middle peer
					// received and processed the subscribe + graft
					time.Sleep(100 * time.Millisecond)

					// Publish messages from the first peer
					for i := 0; i < 10; i++ {
						publishMsg()
					}
				}()
			}
		}

		// Each time the middle peer sends an IDONTWANT message
		for _, idonthave := range irpc.GetControl().GetIdontwant() {
			// If true, it means that, when we get IDONTWANT, the middle peer has done validation
			// already, which should not be the case
			if validated.Load() {
				t.Fatalf("IDONTWANT should be sent before doing validation")
			}
			for _, mid := range idonthave.GetMessageIDs() {
				// Add the message to the list and reset the timer
				actMids = append(actMids, mid)
				msgTimer.Reset(msgWaitMax)
			}
		}
	})

	connect(t, hosts[0], hosts[1])
	connect(t, hosts[1], hosts[2])

	<-ctx.Done()
}

func TestBlossomSubIdontwantReceive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 3)

	msgID := func(pmsg *pb.Message) []byte {
		mid := sha256.Sum256(pmsg.Data)
		return mid[:]
	}

	psubs := make([]*PubSub, 2)
	psubs[0] = getBlossomSub(ctx, hosts[0], WithMessageIdFn(msgID))
	psubs[1] = getBlossomSub(ctx, hosts[1], WithMessageIdFn(msgID))

	bitmask := []byte{0x20, 0x00, 0x00}
	for _, ps := range psubs {
		_, err := ps.Subscribe(bitmask)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Wait a bit after the last message before checking the result
	msgWaitMax := time.Second
	msgTimer := time.NewTimer(msgWaitMax)

	// Checks we received no messages
	received := false
	checkMsgs := func() {
		if received {
			t.Fatalf("Expected no messages received after IDONWANT")
		}
	}

	// Wait for the timer to expire
	go func() {
		select {
		case <-msgTimer.C:
			checkMsgs()
			cancel()
			return
		case <-ctx.Done():
			checkMsgs()
		}
	}()

	newMockBS(ctx, t, hosts[2], func(writeMsg func(*pb.RPC), irpc *pb.RPC) {
		// Check if it receives any message
		if len(irpc.GetPublish()) > 0 {
			received = true
		}
		// When the middle peer connects it will send us its subscriptions
		for _, sub := range irpc.GetSubscriptions() {
			if sub.GetSubscribe() {
				// Reply by subcribing to the bitmask and grafting to the middle peer
				writeMsg(&pb.RPC{
					Subscriptions: []*pb.RPC_SubOpts{{Subscribe: sub.Subscribe, Bitmask: sub.Bitmask}},
					Control:       &pb.ControlMessage{Graft: []*pb.ControlGraft{{Bitmask: sub.Bitmask}}},
				})

				go func() {
					// Wait for a short interval to make sure the middle peer
					// received and processed the subscribe + graft
					time.Sleep(100 * time.Millisecond)

					// Generate a message and send IDONTWANT to the middle peer
					data := make([]byte, 16)
					crand.Read(data)
					mid := msgID(&pb.Message{Data: data})
					writeMsg(&pb.RPC{
						Control: &pb.ControlMessage{Idontwant: []*pb.ControlIDontWant{{MessageIDs: [][]byte{mid}}}},
					})

					// Wait for a short interval to make sure the middle peer
					// received and processed the IDONTWANTs
					time.Sleep(100 * time.Millisecond)

					// Publish the message from the first peer
					if err := psubs[0].Publish(ctx, bitmask, data); err != nil {
						t.Error(err)
						return // cannot call t.Fatal in a non-test goroutine
					}
				}()
			}
		}
	})

	connect(t, hosts[0], hosts[1])
	connect(t, hosts[1], hosts[2])

	<-ctx.Done()
}

// Test that non-mesh peers will not get IDONTWANT
func TestBlossomSubIdontwantNonMesh(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 3)

	params := DefaultBlossomSubParams()
	params.IDontWantMessageThreshold = 16
	psubs := getBlossomSubs(ctx, hosts[:2], WithBlossomSubParams(params))

	bitmask := []byte{0x20, 0x00, 0x00}
	for _, ps := range psubs {
		_, err := ps.Subscribe(bitmask)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Used to publish a message with random data
	publishMsg := func() {
		data := make([]byte, 16)
		crand.Read(data)

		if err := psubs[0].Publish(ctx, bitmask, data); err != nil {
			t.Fatal(err)
		}
	}

	// Wait a bit after the last message before checking we got the right messages
	msgWaitMax := time.Second
	msgTimer := time.NewTimer(msgWaitMax)
	received := false

	// Checks if we received any IDONTWANT
	checkMsgs := func() {
		if received {
			t.Fatalf("No IDONTWANT is expected")
		}
	}

	// Wait for the timer to expire
	go func() {
		select {
		case <-msgTimer.C:
			checkMsgs()
			cancel()
			return
		case <-ctx.Done():
			checkMsgs()
		}
	}()

	newMockBS(ctx, t, hosts[2], func(writeMsg func(*pb.RPC), irpc *pb.RPC) {
		// When the middle peer connects it will send us its subscriptions
		for _, sub := range irpc.GetSubscriptions() {
			if sub.GetSubscribe() {
				// Reply by subcribing to the bitmask and pruning to the middle peer to make sure
				// that it's not in the mesh
				writeMsg(&pb.RPC{
					Subscriptions: []*pb.RPC_SubOpts{{Subscribe: sub.Subscribe, Bitmask: sub.Bitmask}},
					Control:       &pb.ControlMessage{Prune: []*pb.ControlPrune{{Bitmask: sub.Bitmask}}},
				})

				go func() {
					// Wait for a short interval to make sure the middle peer
					// received and processed the subscribe
					time.Sleep(100 * time.Millisecond)

					// Publish messages from the first peer
					for i := 0; i < 10; i++ {
						publishMsg()
					}
				}()
			}
		}

		// Each time the middle peer sends an IDONTWANT message
		for range irpc.GetControl().GetIdontwant() {
			received = true
		}
	})

	connect(t, hosts[0], hosts[1])
	connect(t, hosts[1], hosts[2])

	<-ctx.Done()
}

// Test that peers with incompatible versions will not get IDONTWANT
func TestBlossomSubIdontwantIncompat(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 3)

	params := DefaultBlossomSubParams()
	params.IDontWantMessageThreshold = 16
	psubs := getBlossomSubs(ctx, hosts[:2], WithBlossomSubParams(params))

	bitmask := []byte{0x20, 0x00, 0x00}
	for _, ps := range psubs {
		_, err := ps.Subscribe(bitmask)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Used to publish a message with random data
	publishMsg := func() {
		data := make([]byte, 16)
		crand.Read(data)

		if err := psubs[0].Publish(ctx, bitmask, data); err != nil {
			t.Fatal(err)
		}
	}

	// Wait a bit after the last message before checking we got the right messages
	msgWaitMax := time.Second
	msgTimer := time.NewTimer(msgWaitMax)
	received := false

	// Checks if we received any IDONTWANT
	checkMsgs := func() {
		if received {
			t.Fatalf("No IDONTWANT is expected")
		}
	}

	// Wait for the timer to expire
	go func() {
		select {
		case <-msgTimer.C:
			checkMsgs()
			cancel()
			return
		case <-ctx.Done():
			checkMsgs()
		}
	}()

	// Use the old BlossomSub version
	newMockBSWithVersion(ctx, t, hosts[2], BlossomSubID_v2, func(writeMsg func(*pb.RPC), irpc *pb.RPC) {
		// When the middle peer connects it will send us its subscriptions
		for _, sub := range irpc.GetSubscriptions() {
			if sub.GetSubscribe() {
				// Reply by subcribing to the bitmask and grafting to the middle peer
				writeMsg(&pb.RPC{
					Subscriptions: []*pb.RPC_SubOpts{{Subscribe: sub.Subscribe, Bitmask: sub.Bitmask}},
					Control:       &pb.ControlMessage{Graft: []*pb.ControlGraft{{Bitmask: sub.Bitmask}}},
				})

				go func() {
					// Wait for a short interval to make sure the middle peer
					// received and processed the subscribe + graft
					time.Sleep(100 * time.Millisecond)

					// Publish messages from the first peer
					for i := 0; i < 10; i++ {
						publishMsg()
					}
				}()
			}
		}

		// Each time the middle peer sends an IDONTWANT message
		for range irpc.GetControl().GetIdontwant() {
			received = true
		}
	})

	connect(t, hosts[0], hosts[1])
	connect(t, hosts[1], hosts[2])

	<-ctx.Done()
}

// Test that IDONTWANT will not be sent for small messages
func TestBlossomSubIdontwantSmallMessage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 3)

	params := DefaultBlossomSubParams()
	params.IDontWantMessageThreshold = 16
	psubs := getBlossomSubs(ctx, hosts[:2], WithBlossomSubParams(params))

	bitmask := []byte{0x20, 0x00, 0x00}
	for _, ps := range psubs {
		_, err := ps.Subscribe(bitmask)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Used to publish a message with random data
	publishMsg := func() {
		data := make([]byte, 8)
		crand.Read(data)

		if err := psubs[0].Publish(ctx, bitmask, data); err != nil {
			t.Fatal(err)
		}
	}

	// Wait a bit after the last message before checking we got the right messages
	msgWaitMax := time.Second
	msgTimer := time.NewTimer(msgWaitMax)
	received := false

	// Checks if we received any IDONTWANT
	checkMsgs := func() {
		if received {
			t.Fatalf("No IDONTWANT is expected")
		}
	}

	// Wait for the timer to expire
	go func() {
		select {
		case <-msgTimer.C:
			checkMsgs()
			cancel()
			return
		case <-ctx.Done():
			checkMsgs()
		}
	}()

	newMockBS(ctx, t, hosts[2], func(writeMsg func(*pb.RPC), irpc *pb.RPC) {
		// When the middle peer connects it will send us its subscriptions
		for _, sub := range irpc.GetSubscriptions() {
			if sub.GetSubscribe() {
				// Reply by subcribing to the bitmask and pruning to the middle peer to make sure
				// that it's not in the mesh
				writeMsg(&pb.RPC{
					Subscriptions: []*pb.RPC_SubOpts{{Subscribe: sub.Subscribe, Bitmask: sub.Bitmask}},
					Control:       &pb.ControlMessage{Graft: []*pb.ControlGraft{{Bitmask: sub.Bitmask}}},
				})

				go func() {
					// Wait for a short interval to make sure the middle peer
					// received and processed the subscribe
					time.Sleep(100 * time.Millisecond)

					// Publish messages from the first peer
					for i := 0; i < 10; i++ {
						publishMsg()
					}
				}()
			}
		}

		// Each time the middle peer sends an IDONTWANT message
		for range irpc.GetControl().GetIdontwant() {
			received = true
		}
	})

	connect(t, hosts[0], hosts[1])
	connect(t, hosts[1], hosts[2])

	<-ctx.Done()
}

// Test that IDONTWANT will cleared when it's old enough
func TestBlossomSubIdontwantClear(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 3)

	msgID := func(pmsg *pb.Message) []byte {
		mid := sha256.Sum256(pmsg.Data)
		return mid[:]
	}

	params := DefaultBlossomSubParams()
	params.IDontWantMessageTTL = 3

	psubs := make([]*PubSub, 2)
	psubs[0] = getBlossomSub(ctx, hosts[0], WithMessageIdFn(msgID), WithBlossomSubParams(params))
	psubs[1] = getBlossomSub(ctx, hosts[1], WithMessageIdFn(msgID), WithBlossomSubParams(params))

	bitmask := []byte{0x20, 0x00, 0x00}
	for _, ps := range psubs {
		_, err := ps.Subscribe(bitmask)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Wait a bit after the last message before checking the result
	msgWaitMax := 5 * time.Second
	msgTimer := time.NewTimer(msgWaitMax)

	// Checks we received some message after the IDONTWANT is cleared
	var received atomic.Bool
	checkMsgs := func() {
		if !received.Load() {
			t.Fatalf("Expected some message after the IDONTWANT is cleared")
		}
	}

	// Wait for the timer to expire
	go func() {
		select {
		case <-msgTimer.C:
			checkMsgs()
			cancel()
			return
		case <-ctx.Done():
			checkMsgs()
		}
	}()

	newMockBS(ctx, t, hosts[2], func(writeMsg func(*pb.RPC), irpc *pb.RPC) {
		// Check if it receives any message
		if len(irpc.GetPublish()) > 0 {
			received.Store(true)
		}
		// When the middle peer connects it will send us its subscriptions
		for _, sub := range irpc.GetSubscriptions() {
			if sub.GetSubscribe() {
				// Reply by subcribing to the bitmask and grafting to the middle peer
				writeMsg(&pb.RPC{
					Subscriptions: []*pb.RPC_SubOpts{{Subscribe: sub.Subscribe, Bitmask: sub.Bitmask}},
					Control:       &pb.ControlMessage{Graft: []*pb.ControlGraft{{Bitmask: sub.Bitmask}}},
				})

				go func() {
					// Wait for a short interval to make sure the middle peer
					// received and processed the subscribe + graft
					time.Sleep(100 * time.Millisecond)

					// Generate a message and send IDONTWANT to the middle peer
					data := make([]byte, 16)
					crand.Read(data)
					mid := msgID(&pb.Message{Data: data})
					writeMsg(&pb.RPC{
						Control: &pb.ControlMessage{Idontwant: []*pb.ControlIDontWant{{MessageIDs: [][]byte{mid}}}},
					})

					// Wait for a short interval to make sure the middle peer
					// received and processed the IDONTWANTs
					time.Sleep(100 * time.Millisecond)

					// Wait for 4 heartbeats to make sure the IDONTWANT is cleared
					time.Sleep(4 * time.Second)

					// Publish the message from the first peer
					if err := psubs[0].Publish(ctx, bitmask, data); err != nil {
						t.Error(err)
						return // cannot call t.Fatal in a non-test goroutine
					}
				}()
			}
		}
	})

	connect(t, hosts[0], hosts[1])
	connect(t, hosts[1], hosts[2])

	<-ctx.Done()
}

func TestBloomRouting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 20)
	psubs := getBlossomSubs(ctx, hosts)

	var msgs [][]*Subscription
	var bitmasks [][]*Bitmask
	targetSets := [][]byte{
		{0x00, 0x01},
		{0x00, 0x10},
		{0x01, 0x00},
		{0x01, 0x01},
		{0x01, 0x11},
	}

	expectedGroups := [][]int{
		{0, 3, 4},
		{1, 4},
		{2, 3, 4},
		{3, 4},
		{4},
	}

	for i, ps := range psubs {
		b, err := ps.Join(targetSets[i%5])
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b)

		subch, err := ps.Subscribe(targetSets[i%5])
		if err != nil {
			t.Fatal(err)
		}

		msgs = append(msgs, subch)
	}

	connectAll(t, hosts)

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("%d it's not a floooooood %d", i, i))

		owner := rand.Intn(len(psubs))

		psubs[owner].Publish(ctx, targetSets[owner%5], msg)

		for i, sub := range msgs {
			if !slices.Contains(expectedGroups[owner%5], i%5) {
				continue
			}

			// Normally the expectation is that any subscription will do when using a bloom bitmask
			// But we need to verify one gets it.
			g := sync.WaitGroup{}
			g.Add(len(sub) + 1)
			errch := make(chan error)
			var errs []error
			for _, s := range sub {
				s := s
				go func() {
					defer g.Done()
					nctx, _ := context.WithDeadline(ctx, time.Now().Add(100*time.Millisecond))
					got, err := s.Next(nctx)
					if err != nil {
						errch <- err
						return
					}
					if !bytes.Equal(msg, got.Data) {
						errch <- errors.New("got wrong message!")
						return
					}
					errch <- nil
				}()
			}

			go func() {
				for _ = range sub {
					select {
					case err := <-errch:
						if err != nil {
							errs = append(errs, err)
						}
					}
				}
				g.Done()
			}()
			g.Wait()
			if len(errs) == len(sub) {
				t.Fatal(errors.Join(errs...))
			}
		}
	}
}

func TestBloomPropagationOverSubTreeTopology(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 10)
	psubs := getBlossomSubs(ctx, hosts)

	connect(t, hosts[0], hosts[1])
	connect(t, hosts[1], hosts[2])
	connect(t, hosts[1], hosts[4])
	connect(t, hosts[2], hosts[3])
	connect(t, hosts[0], hosts[5])
	connect(t, hosts[5], hosts[6])
	connect(t, hosts[5], hosts[8])
	connect(t, hosts[6], hosts[7])
	connect(t, hosts[8], hosts[9])

	/*
		[0] -> [1] -> [2] -> [3]
		 |      L->[4]
		 v
		[5] -> [6] -> [7]
		 |
		 v
		[8] -> [9]
	*/

	var chs [][]*Subscription
	var bitmasks [][]*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x10, 0x10, 0x10, 0x00})
		if err != nil {
			t.Fatal(err)
		}

		bitmasks = append(bitmasks, b)
		ch, err := ps.Subscribe([]byte{0x10, 0x10, 0x10, 0x00})
		if err != nil {
			t.Fatal(err)
		}

		chs = append(chs, ch)
	}

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	assertPeerLists(t, []byte{0x10, 0x10, 0x10, 0x00}, hosts, psubs[0], 1, 5)
	assertPeerLists(t, []byte{0x10, 0x10, 0x10, 0x00}, hosts, psubs[1], 0, 2, 4)
	assertPeerLists(t, []byte{0x10, 0x10, 0x10, 0x00}, hosts, psubs[2], 1, 3)

	for _, p := range bitmasks {
		data := make([]byte, 32)
		crand.Read(data)
		err := p[0].Publish(ctx, []byte{0x10, 0x10, 0x10, 0x00}, data)
		if err != nil {
			t.Fatal(err)
		}

		for _, subs := range chs {
			subs := subs
			g := sync.WaitGroup{}
			g.Add(len(subs))
			nctx, cancel := context.WithCancel(ctx)
			msgch := make(chan struct{})
			for _, s := range subs {
				s := s
				go func() {
					nctx, _ := context.WithDeadline(nctx, time.Now().Add(10*time.Millisecond))
					got, err := s.Next(nctx)
					if err != nil {
						g.Done()
						return
					}

					if !bytes.Equal(data, got.Data) {
						g.Done()
						return
					}
					msgch <- struct{}{}
					g.Done()
				}()
			}

			var msg *struct{} = nil
			go func() {
				for i := 0; i < len(subs); i++ {
					select {
					case m := <-msgch:
						msg = &m
						cancel()
					}
				}
			}()
			g.Wait()
			if msg == nil {
				t.Fatal("didn't get message")
			}
		}
	}
}

func TestBlossomSubBloomStarTopology(t *testing.T) {
	originalBlossomSubD := BlossomSubD
	BlossomSubD = 4
	originalBlossomSubDhi := BlossomSubDhi
	BlossomSubDhi = BlossomSubD + 1
	originalBlossomSubDlo := BlossomSubDlo
	BlossomSubDlo = BlossomSubD - 1
	originalBlossomSubDscore := BlossomSubDscore
	BlossomSubDscore = BlossomSubDlo
	defer func() {
		BlossomSubD = originalBlossomSubD
		BlossomSubDhi = originalBlossomSubDhi
		BlossomSubDlo = originalBlossomSubDlo
		BlossomSubDscore = originalBlossomSubDscore
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 200)
	psubs := []*PubSub{}
	// Core bootstrapper:
	psubs = append(psubs, getBlossomSubs(ctx, hosts[:1], WithPeerExchange(true), WithFloodPublish(true))...)
	// Everyone else:
	psubs = append(psubs, getBlossomSubs(ctx, hosts[1:])...)

	// configure the center of the star with a very low D
	psubs[0].eval <- func() {
		gs := psubs[0].rt.(*BlossomSubRouter)
		gs.params.D = 0
		gs.params.Dlo = 0
		gs.params.Dhi = 0
		gs.params.Dscore = 0
	}

	// add all peer addresses to the peerstores
	// this is necessary because we can't have signed address records witout identify
	// pushing them
	for i := range hosts {
		for j := range hosts {
			if i == j {
				continue
			}
			hosts[i].Peerstore().AddAddrs(hosts[j].ID(), hosts[j].Addrs(), peerstore.PermanentAddrTTL)
		}
	}

	// build the star
	for i := 1; i < 200; i++ {
		connect(t, hosts[0], hosts[i])
	}

	fullBitmask := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
	slices := [][]byte{}
	for i := 0; i < 63; i++ {
		if i%2 == 0 {
			slices = append(
				slices,
				append(
					append(
						bytes.Repeat([]byte{0x00}, i/2),
						0xff,
					),
					bytes.Repeat([]byte{0x00}, 31-i/2)...,
				),
			)
		} else {
			slices = append(
				slices,
				append(
					append(
						bytes.Repeat([]byte{0x00}, i/2),
						0x0f,
						0xf0,
					),
					bytes.Repeat([]byte{0x00}, 30-i/2)...,
				),
			)
		}
	}
	time.Sleep(time.Second)

	// build the mesh
	var subs [][]*Subscription
	var bitmasks [][]*Bitmask
	for i, ps := range psubs {
		if i == 0 {
			b, err := ps.Join(fullBitmask)
			if err != nil {
				t.Fatal(err)
			}

			bitmasks = append(bitmasks, b)
			sub, err := ps.Subscribe(fullBitmask)
			if err != nil {
				t.Fatal(err)
			}
			subs = append(subs, sub)
		} else {
			b, err := ps.Join(slices[i%len(slices)])
			if err != nil {
				t.Fatal(err)
			}

			bitmasks = append(bitmasks, b)
			sub, err := ps.Subscribe(slices[i%len(slices)])
			if err != nil {
				t.Fatal(err)
			}
			subs = append(subs, sub)
		}
	}

	// wait a bit for the mesh to build
	time.Sleep(5 * time.Second)

	// check that all peers have > 1 connection
	for i, h := range hosts {
		if len(h.Network().Conns()) == 1 {
			t.Errorf("peer %d has ony a single connection", i)
		}
	}

	// send a message from each peer and assert it was propagated
	for i := 0; i < 600; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		if i == 0 {
			for j := 0; j < 256; j++ {
				msg = []byte(fmt.Sprintf("message %d-sub-%d", i, j))
				bitmasks[i%200][j].Publish(ctx, bitmasks[i%200][j].bitmask, msg)

				subgroup := [][]*Subscription{}
				for _, group := range subs {
					group := group
					for _, s := range group {
						if containsBitmask(bitmasks[i%200][j].bitmask, s.bitmask) {
							subgroup = append(subgroup, group)
							break
						}
					}
				}
				assertReceivedBitmaskSubgroup(t, ctx, subgroup, msg)
			}
		} else {
			psubs[i%200].Publish(ctx, slices[(i%200)%len(slices)], msg)

			subgroup := [][]*Subscription{}
			for _, group := range subs[1:] {
				group := group
				in := true
				for _, s := range group {
					if !containsBitmask(slices[(i%200)%len(slices)], s.bitmask) {
						in = false
						break
					}
				}
				if in {
					subgroup = append(subgroup, group)
				}
			}
			assertReceivedBitmaskSubgroup(t, ctx, subgroup, msg)
		}
	}
}

func containsBitmask(bitmask []byte, slice []byte) bool {
	out := make([]byte, len(slice))
	for i, b := range bitmask {
		out[i] = b & slice[i]
	}

	return bytes.Equal(out, slice)
}

func assertReceivedBitmaskSubgroup(t *testing.T, ctx context.Context, subs [][]*Subscription, msg []byte) {
	for i, subs := range subs {
		subs := subs
		g := sync.WaitGroup{}
		g.Add(len(subs))
		nctx, cancel := context.WithCancel(ctx)
		msgch := make(chan struct{})
		for _, s := range subs {
			s := s
			go func() {
				nctx, _ := context.WithDeadline(nctx, time.Now().Add(100*time.Millisecond))
				got, err := s.Next(nctx)
				if err != nil {
					g.Done()
					return
				}

				if !bytes.Equal(msg, got.Data) {
					g.Done()
					return
				}
				msgch <- struct{}{}
				g.Done()
			}()
		}

		var msg *struct{} = nil
		go func() {
			for i := 0; i < len(subs); i++ {
				select {
				case m := <-msgch:
					msg = &m
					cancel()
				}
			}
		}()
		g.Wait()
		if msg == nil {
			t.Fatalf("%d didn't get message", i)
		}
	}
}
