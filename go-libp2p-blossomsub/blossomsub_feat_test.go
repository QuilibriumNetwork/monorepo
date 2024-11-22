package blossomsub

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/protocol"
)

func TestDefaultBlossomSubFeatures(t *testing.T) {
	if !BlossomSubDefaultFeatures(BlossomSubFeatureMesh, BlossomSubID_v2) {
		t.Fatal("BlossomSub-v2.0 should support Mesh")
	}
	if !BlossomSubDefaultFeatures(BlossomSubFeatureMesh, BlossomSubID_v21) {
		t.Fatal("BlossomSub-v2.1 should support Mesh")
	}

	if !BlossomSubDefaultFeatures(BlossomSubFeaturePX, BlossomSubID_v2) {
		t.Fatal("BlossomSub-v2.0 should support PX")
	}
	if !BlossomSubDefaultFeatures(BlossomSubFeaturePX, BlossomSubID_v21) {
		t.Fatal("BlossomSub-v2.0 should support PX")
	}

	if BlossomSubDefaultFeatures(BlossomSubFeatureIdontwant, BlossomSubID_v2) {
		t.Fatal("BlossomSub-v2.0 should not support IDONTWANT")
	}
	if !BlossomSubDefaultFeatures(BlossomSubFeatureIdontwant, BlossomSubID_v21) {
		t.Fatal("BlossomSub-v2.1 should support IDONTWANT")
	}
}

func TestBlossomSubCustomProtocols(t *testing.T) {
	customsub := protocol.ID("customsub/1.0.0")
	protos := []protocol.ID{customsub}
	features := func(feat BlossomSubFeature, proto protocol.ID) bool {
		return proto == customsub
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 3)

	bsubs := getBlossomSubs(ctx, hosts[:2], WithBlossomSubProtocols(protos, features))

	connectAll(t, hosts)

	bitmask := []byte{0x00, 0x80, 0x00, 0x00}
	var bitmasks []*Bitmask
	var subs []*Subscription
	for _, ps := range bsubs {
		b, err := ps.Join(bitmask)
		if err != nil {
			t.Fatal(err)
		}

		subch, err := ps.Subscribe(bitmask)
		if err != nil {
			t.Fatal(err)
		}

		subs = append(subs, subch...)
		bitmasks = append(bitmasks, b...)
	}

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	// check the meshes of the bsubs, the BlossomSub meshes should include each other but not the
	// floddsub peer
	bsubs[0].eval <- func() {
		bs := bsubs[0].rt.(*BlossomSubRouter)

		_, ok := bs.mesh[string(bitmask)][hosts[1].ID()]
		if !ok {
			t.Fatal("expected bs0 to have bs1 in its mesh")
		}

		_, ok = bs.mesh[string(bitmask)][hosts[2].ID()]
		if ok {
			t.Fatal("expected bs0 to not have fs in its mesh")
		}
	}

	bsubs[1].eval <- func() {
		bs := bsubs[1].rt.(*BlossomSubRouter)

		_, ok := bs.mesh[string(bitmask)][hosts[0].ID()]
		if !ok {
			t.Fatal("expected bs1 to have bs0 in its mesh")
		}

		_, ok = bs.mesh[string(bitmask)][hosts[2].ID()]
		if ok {
			t.Fatal("expected bs1 to not have fs in its mesh")
		}
	}

	// send some messages
	for i := 0; i < 10; i++ {
		msg := []byte(fmt.Sprintf("%d it's not quite a floooooood %d", i, i))

		owner := rand.Intn(len(bsubs))
		bitmasks[owner].Publish(ctx, bitmasks[owner].bitmask, msg)

		for _, sub := range subs {
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
