package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	blossomsub "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub"
)

func main() {
	h, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0/ws"),
		libp2p.EnableNATService(),
		libp2p.NATPortMap(),
	)
	if err != nil {
		panic(err)
	}
	defer h.Close()

	fmt.Printf("Host created with ID: %s\n", h.ID())
	fmt.Printf("Listening on addresses: %v\n", h.Addrs())

	targetAddr := "/ip4/127.0.0.1/tcp/8336/ws/p2p/QmPkz3K2DpTiXf4ttRSLkjN71a9YMmKhSNW8nZig1QEoHP"
	targetAddrInfo, err := peer.AddrInfoFromString(targetAddr)
	if err != nil {
		panic(err)
	}

	fmt.Println("Connecting to target node...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := h.Connect(ctx, *targetAddrInfo); err != nil {
		panic(fmt.Errorf("failed to connect to target: %v", err))
	}
	fmt.Println("Successfully connected to target node")

	ps, err := blossomsub.NewBlossomSub(ctx, h)
	if err != nil {
		panic(err)
	}

	bitmask, err := hex.DecodeString(
		"0000000000000000000000000000000000000000000000000000000000000000",
	)
	if err != nil {
		panic(err)
	}

	bm, err := ps.Join(bitmask)
	if err != nil {
		panic(err)
	}

	sub, err := bm[0].Subscribe()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Current peers in bitmask: %v\n", bm[0].ListPeers())

	go func() {
		for {
			msg, err := sub.Next(context.Background())
			if err != nil {
				fmt.Printf("Subscription error: %v\n", err)
				continue
			}
			fmt.Printf("Received message from %s: %s\n", msg.From, string(msg.Data))
		}
	}()

	time.Sleep(2 * time.Second)

	data := []byte("Hello, from test client!")
	fmt.Println("Publishing message...")
	if err := ps.Publish(context.Background(), bitmask, data); err != nil {
		panic(err)
	}

	fmt.Println("Message sent:", string(data))
	select {}
}
