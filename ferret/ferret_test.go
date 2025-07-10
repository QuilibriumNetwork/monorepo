package ferret_test

import (
	"fmt"
	"testing"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/ferret"
)

func TestFerretAlice(t *testing.T) {
	alice, err := ferret.NewFerretOT(1, "", 5555, 1, 100000000, make([]bool, 0), true)
	if err != nil {
		t.Errorf("Failed to create ALICE: %v", err)
		return
	}

	fmt.Println("alice sendcot")
	alice.SendCOT()
	fmt.Println("alice sendrot")
	alice.SendROT()
	for i := range uint64(100) {
		fmt.Printf("%x\n", alice.SenderGetBlockData(i%2 == 1, i))
	}
	t.FailNow()
}

func TestFerretBob(t *testing.T) {
	time.Sleep(100 * time.Millisecond)

	bob, err := ferret.NewFerretOT(2, "127.0.0.1", 5555, 1, 100000000, make([]bool, 100000000), true)
	if err != nil {
		t.Errorf("Failed to create BOB: %v", err)
		return
	}

	fmt.Println("bob recvcot")
	bob.RecvCOT()
	fmt.Println("bob recvrot")
	bob.RecvROT()
	for i := range uint64(100) {
		fmt.Printf("%x\n", bob.ReceiverGetBlockData(i))
	}
	t.FailNow()
}
