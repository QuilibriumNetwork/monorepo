package blossomsub

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
)

// See https://source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/issues/426
func TestPubSubRemovesBlacklistedPeer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	hosts := getDefaultHosts(t, 2)

	bl := NewMapBlacklist()

	psubs0 := getBlossomSub(ctx, hosts[0])
	psubs1 := getBlossomSub(ctx, hosts[1], WithBlacklist(bl))
	connect(t, hosts[0], hosts[1])

	// Bad peer is blacklisted after it has connected.
	// Calling p.BlacklistPeer directly does the right thing but we should also clean
	// up the peer if it has been added the the blacklist by another means.
	ran := make(chan struct{})
	psubs1.eval <- func() {
		defer close(ran)
		bl.Add(hosts[0].ID())
	}
	<-ran
	bitmasks, err := psubs0.Join([]byte{0x01, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	_, err = psubs0.Subscribe([]byte{0x01, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	sub1, err := psubs1.Subscribe([]byte{0x01, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Millisecond * 100)

	bitmasks[0].Publish(ctx, []byte{0x01, 0x00}, []byte("message"))

	wctx, cancel2 := context.WithTimeout(ctx, 1*time.Second)
	defer cancel2()

	_, _ = sub1[0].Next(wctx)

	// Explicitly cancel context so PubSub cleans up peer channels.
	// Issue 426 reports a panic due to a peer channel being closed twice.
	cancel()
	time.Sleep(time.Millisecond * 100)
}

func TestSliceBitmask(t *testing.T) {
	fullVector := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}

	partialVector := []byte{
		0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x04, 0x03, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	outputs := SliceBitmask(fullVector)
	if len(outputs) != 256 {
		t.Fatalf("output length mismatch: %d, expected %d", len(outputs), 256)
	}

	outputs = SliceBitmask(partialVector)
	if len(outputs) != 4 {
		t.Fatalf("output length mismatch: %d, expected %d", len(outputs), 4)
	}
}

func TestDefaultMsgIdFn(t *testing.T) {
	for i := 0; i < 10; i++ {
		data := make([]byte, 1024)
		rand.Read(data)
		// for v2, prepends 0x01
		out := DefaultMsgIdFn(&pb.Message{
			Data: data,
		})
		if len(out) != 33 {
			t.Fatalf("length mismatch for msg id fn: %d, expected %d\n", len(out), 33)
		}
		if out[0] != 0x01 {
			t.Fatalf("missing prefix byte for msg id fn: %x, expected %x\n", out[:1], []byte{0x01})
		}
	}
}
