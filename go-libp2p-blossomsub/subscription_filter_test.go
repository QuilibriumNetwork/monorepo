package blossomsub

import (
	"bytes"
	"context"
	"testing"
	"time"

	pb "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"

	"github.com/libp2p/go-libp2p/core/peer"
)

func mustSubscribe(t *testing.T, ps *PubSub, bitmask []byte) *Subscription {
	sub, err := ps.Subscribe(bitmask)
	if err != nil {
		t.Fatal(err)
	}

	if len(sub) != 1 {
		t.Fatal("must subscribe only allows single bit bitmasks")
	}

	return sub[0]
}

func TestBasicSubscriptionFilter(t *testing.T) {
	peerA := peer.ID("A")

	bitmask1 := []byte{0x00, 0x80, 0x00, 0x00}
	bitmask2 := []byte{0x00, 0x20, 0x00, 0x00}
	bitmask3 := []byte{0x00, 0x00, 0x02, 0x00}
	yes := true
	subs := []*pb.RPC_SubOpts{
		{
			Bitmask:   bitmask1,
			Subscribe: yes,
		},
		{
			Bitmask:   bitmask2,
			Subscribe: yes,
		},
		{
			Bitmask:   bitmask3,
			Subscribe: yes,
		},
	}

	filter := NewAllowlistSubscriptionFilter(bitmask1, bitmask2)
	canSubscribe := filter.CanSubscribe(bitmask1)
	if !canSubscribe {
		t.Fatal("expected allowed subscription")
	}
	canSubscribe = filter.CanSubscribe(bitmask2)
	if !canSubscribe {
		t.Fatal("expected allowed subscription")
	}
	canSubscribe = filter.CanSubscribe(bitmask3)
	if canSubscribe {
		t.Fatal("expected disallowed subscription")
	}
	allowedSubs, err := filter.FilterIncomingSubscriptions(peerA, subs)
	if err != nil {
		t.Fatal(err)
	}
	if len(allowedSubs) != 2 {
		t.Fatalf("expected 2 allowed subscriptions but got %d", len(allowedSubs))
	}
	for _, sub := range allowedSubs {
		if bytes.Equal(sub.GetBitmask(), bitmask3) {
			t.Fatal("unpexted subscription to test3")
		}
	}

	limitFilter := WrapLimitSubscriptionFilter(filter, 2)
	_, err = limitFilter.FilterIncomingSubscriptions(peerA, subs)
	if err != ErrTooManySubscriptions {
		t.Fatal("expected rejection because of too many subscriptions")
	}
}

func TestSubscriptionFilterDeduplication(t *testing.T) {
	peerA := peer.ID("A")

	bitmask1 := []byte{0x00, 0x80, 0x00, 0x00}
	bitmask2 := []byte{0x00, 0x20, 0x00, 0x00}
	bitmask3 := []byte{0x00, 0x00, 0x02, 0x00}
	yes := true
	no := false
	subs := []*pb.RPC_SubOpts{
		{
			Bitmask:   bitmask1,
			Subscribe: yes,
		},
		{
			Bitmask:   bitmask1,
			Subscribe: yes,
		},

		{
			Bitmask:   bitmask2,
			Subscribe: yes,
		},
		{
			Bitmask:   bitmask2,
			Subscribe: no,
		},
		{
			Bitmask:   bitmask3,
			Subscribe: yes,
		},
	}

	filter := NewAllowlistSubscriptionFilter(bitmask1, bitmask2)
	allowedSubs, err := filter.FilterIncomingSubscriptions(peerA, subs)
	if err != nil {
		t.Fatal(err)
	}
	if len(allowedSubs) != 1 {
		t.Fatalf("expected 2 allowed subscriptions but got %d", len(allowedSubs))
	}
	for _, sub := range allowedSubs {
		if bytes.Equal(sub.GetBitmask(), bitmask3) || bytes.Equal(sub.GetBitmask(), bitmask2) {
			t.Fatal("unexpected subscription")
		}
	}
}

func TestSubscriptionFilterRPC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 2)
	ps1 := getBlossomSub(ctx, hosts[0], WithSubscriptionFilter(NewAllowlistSubscriptionFilter([]byte{0x00, 0x80, 0x00, 0x00}, []byte{0x00, 0x20, 0x00, 0x00})))
	ps2 := getBlossomSub(ctx, hosts[1], WithSubscriptionFilter(NewAllowlistSubscriptionFilter([]byte{0x00, 0x20, 0x00, 0x00}, []byte{0x00, 0x00, 0x02, 0x00})))

	_ = mustSubscribe(t, ps1, []byte{0x00, 0x80, 0x00, 0x00})
	_ = mustSubscribe(t, ps1, []byte{0x00, 0x20, 0x00, 0x00})
	_ = mustSubscribe(t, ps2, []byte{0x00, 0x20, 0x00, 0x00})
	_ = mustSubscribe(t, ps2, []byte{0x00, 0x00, 0x02, 0x00})

	// check the rejection as well
	_, err := ps1.Join([]byte{0x00, 0x00, 0x02, 0x00})
	if err == nil {
		t.Fatal("expected subscription error")
	}

	connect(t, hosts[0], hosts[1])

	time.Sleep(time.Second)

	var sub1, sub2, sub3 bool
	ready := make(chan struct{})

	ps1.eval <- func() {
		_, sub1 = ps1.bitmasks[string([]byte{0x00, 0x80, 0x00, 0x00})][hosts[1].ID()]
		_, sub2 = ps1.bitmasks[string([]byte{0x00, 0x20, 0x00, 0x00})][hosts[1].ID()]
		_, sub3 = ps1.bitmasks[string([]byte{0x00, 0x00, 0x02, 0x00})][hosts[1].ID()]
		ready <- struct{}{}
	}
	<-ready

	if sub1 {
		t.Fatal("expected no subscription for test1")
	}
	if !sub2 {
		t.Fatal("expected subscription for test2")
	}
	if sub3 {
		t.Fatal("expected no subscription for test1")
	}

	ps2.eval <- func() {
		_, sub1 = ps2.bitmasks[string([]byte{0x00, 0x80, 0x00, 0x00})][hosts[0].ID()]
		_, sub2 = ps2.bitmasks[string([]byte{0x00, 0x20, 0x00, 0x00})][hosts[0].ID()]
		_, sub3 = ps2.bitmasks[string([]byte{0x00, 0x00, 0x02, 0x00})][hosts[0].ID()]
		ready <- struct{}{}
	}
	<-ready

	if sub1 {
		t.Fatal("expected no subscription for test1")
	}
	if !sub2 {
		t.Fatal("expected subscription for test1")
	}
	if sub3 {
		t.Fatal("expected no subscription for test1")
	}
}
