package ferret_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/ferret"
)

const PROXY_SERVER_PORT = 9999

// TestFerretProxyAlice demonstrates Alice-side usage through gRPC proxy
func TestFerretProxyAlice(t *testing.T) {
	srv, ln, _ := ferret.StartProxyServer(fmt.Sprintf(":%d", PROXY_SERVER_PORT))
	defer srv.Stop()
	defer ln.Close()

	ctx := context.Background()
	alice, ap, err := ferret.StartAliceFerretWithProxy(ctx, "127.0.0.1:9999", 5555, 1, 1000000, nil, true)
	if err != nil {
		panic(err)
	}
	defer ap.Close()
	fmt.Println("alice sendcot")
	err = alice.SendCOT()
	if err != nil {
		panic(err)
	}
	fmt.Println("alice sendrot")
	err = alice.SendROT()
	if err != nil {
		panic(err)
	}

	for i := range uint64(100) {
		fmt.Printf("%x\n", alice.SenderGetBlockData(i%2 == 1, i))
	}

	fmt.Println("Alice proxy test completed")
	t.FailNow() // This mimics the original test behavior
}

// TestFerretProxyBob demonstrates Bob-side usage through gRPC proxy
func TestFerretProxyBob(t *testing.T) {
	time.Sleep(200 * time.Millisecond) // Wait for Alice to set up
	ctx := context.Background()
	bob, bp, err := ferret.StartBobFerretWithProxy(ctx, "127.0.0.1:9999", 1, 1_000_000, make([]bool, 1_000_000), true)
	if err != nil {
		panic(err)
	}
	defer bp.Close()
	fmt.Println("bob recvcot")
	err = bob.RecvCOT()
	if err != nil {
		panic(err)
	}
	fmt.Println("bob recvrot")
	err = bob.RecvROT()
	if err != nil {
		panic(err)
	}
	for i := range uint64(100) {
		fmt.Printf("%x\n", bob.ReceiverGetBlockData(i))
	}

	fmt.Println("Bob proxy test completed")
	t.FailNow() // This mimics the original test behavior
}
