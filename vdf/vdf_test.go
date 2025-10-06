package vdf_test

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/vdf"
)

func getChallenge(seed string) [32]byte {
	return sha3.Sum256([]byte(seed))
}

func TestProveVerify(t *testing.T) {
	difficulty := uint32(160000)
	challenge := getChallenge("TestProveVerify")
	solution := vdf.WesolowskiSolve(challenge, difficulty)
	now := time.Now()
	isOk := vdf.WesolowskiVerify(challenge, difficulty, solution)
	fmt.Printf("%v\n", time.Since(now))
	if !isOk {
		t.Fatalf("Verification failed")
	}
}

func TestProveVerifyMulti_Succeeds(t *testing.T) {
	difficulty := uint32(160000)
	challenge := getChallenge("TestProveVerifyMulti_Succeeds")

	ids := [][]byte{
		[]byte("worker-A"),
		[]byte("worker-B"),
		[]byte("worker-C"),
	}

	blobs := make([][516]byte, len(ids))
	wg := sync.WaitGroup{}
	for i := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			blobs[i] = vdf.WesolowskiSolveMulti(challenge, difficulty, ids, uint32(i))
		}()
	}
	wg.Wait()

	now := time.Now()
	if ok := vdf.WesolowskiVerifyMulti(challenge, difficulty, ids, blobs); !ok {
		t.Fatalf("Multi verification failed")
	}
	fmt.Printf("%v\n", time.Since(now))
	wg = sync.WaitGroup{}

	ids = [][]byte{
		[]byte("worker-A"),
		[]byte("worker-B"),
		[]byte("worker-C"),
		[]byte("worker-D"),
		[]byte("worker-E"),
		[]byte("worker-F"),
		[]byte("worker-G"),
	}

	blobs = make([][516]byte, len(ids))
	for i := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			blobs[i] = vdf.WesolowskiSolveMulti(challenge, difficulty, ids, uint32(i))
		}()
	}

	wg.Wait()

	now = time.Now()
	if ok := vdf.WesolowskiVerifyMulti(challenge, difficulty, ids, blobs); !ok {
		t.Fatalf("Multi verification failed")
	}
	fmt.Printf("%v\n", time.Since(now))
}

func TestProveVerifyMulti_OrderInsensitive(t *testing.T) {
	difficulty := uint32(50000)
	challenge := getChallenge("TestProveVerifyMulti_OrderInsensitive")

	ids := [][]byte{
		[]byte("alice"),
		[]byte("bob"),
		[]byte("carol"),
		[]byte("dave"),
	}

	blobs := make([][516]byte, len(ids))
	for i := range ids {
		blobs[i] = vdf.WesolowskiSolveMulti(challenge, difficulty, ids, uint32(i))
	}

	permIdx := []int{2, 0, 3, 1}
	idsPerm := make([][]byte, len(ids))
	blobsPerm := make([][516]byte, len(ids))
	for i, j := range permIdx {
		idsPerm[i] = ids[j]
		blobsPerm[i] = blobs[j]
	}

	if ok := vdf.WesolowskiVerifyMulti(challenge, difficulty, idsPerm, blobsPerm); !ok {
		t.Fatalf("Multi verification failed under permutation")
	}
}

func TestProveVerifyMulti_TamperFails(t *testing.T) {
	difficulty := uint32(30000)
	challenge := getChallenge("TestProveVerifyMulti_TamperFails")

	ids := [][]byte{[]byte("w1"), []byte("w2")}
	blobs := make([][516]byte, len(ids))
	for i := range ids {
		blobs[i] = vdf.WesolowskiSolveMulti(challenge, difficulty, ids, uint32(i))
	}

	tampered := blobs
	tampered[1][100] ^= 0x01

	if ok := vdf.WesolowskiVerifyMulti(challenge, difficulty, ids, tampered); ok {
		t.Fatalf("Expected tampered multi verification to fail")
	}
}

func TestProveVerifyMulti_MissingOrWrongIDsFail(t *testing.T) {
	difficulty := uint32(30000)
	challenge := getChallenge("TestProveVerifyMulti_MissingOrWrongIDsFail")

	ids := [][]byte{[]byte("w1"), []byte("w2"), []byte("w3")}
	blobs := make([][516]byte, len(ids))
	for i := range ids {
		blobs[i] = vdf.WesolowskiSolveMulti(challenge, difficulty, ids, uint32(i))
	}

	idsSubset := ids[:2]
	blobsSubset := blobs[:2]
	if ok := vdf.WesolowskiVerifyMulti(challenge, difficulty, idsSubset, blobsSubset); ok {
		t.Fatalf("Expected subset verification to fail (b and S bound to full ID set)")
	}

	idsWrong := make([][]byte, len(ids))
	copy(idsWrong, ids)
	idsWrong[1] = []byte("w2-CHANGED")
	if ok := vdf.WesolowskiVerifyMulti(challenge, difficulty, idsWrong, blobs); ok {
		t.Fatalf("Expected verification to fail with mismatched IDs")
	}

	idsExtra := append(ids, []byte("w4"))
	if ok := vdf.WesolowskiVerifyMulti(challenge, difficulty, idsExtra, blobs); ok {
		t.Fatalf("Expected verification to fail on mismatched lengths")
	}

	idsShuffled := [][]byte{ids[2], ids[0], ids[1]}
	blobsWrongPairing := [][516]byte{blobs[0], blobs[1], blobs[2]}

	// Shuffled set should still succeed, because it gets reordered
	if ok := vdf.WesolowskiVerifyMulti(challenge, difficulty, idsShuffled, blobsWrongPairing); !ok {
		t.Fatalf("Expected verification to succeed with wrong ID/blob pairing")
	}

	if ok := vdf.WesolowskiVerifyMulti(challenge, difficulty, ids, blobs); !ok {
		t.Fatalf("Original multi verification should pass")
	}
}

func TestProveVerifyMulti_DifferentChallengesFail(t *testing.T) {
	difficulty := uint32(30000)
	challengeA := getChallenge("A")
	challengeB := getChallenge("B")

	ids := [][]byte{[]byte("wa"), []byte("wb")}
	blobs := make([][516]byte, len(ids))
	for i := range ids {
		blobs[i] = vdf.WesolowskiSolveMulti(challengeA, difficulty, ids, uint32(i))
	}

	// Verify against a different challenge — should fail.
	if ok := vdf.WesolowskiVerifyMulti(challengeB, difficulty, ids, blobs); ok {
		t.Fatalf("Expected verification to fail for different challenge")
	}
}

func TestProveVerifyMulti_Determinism(t *testing.T) {
	difficulty := uint32(20000)
	challenge := getChallenge("determinism-multi")
	ids := [][]byte{[]byte("x"), []byte("y")}

	b1 := vdf.WesolowskiSolveMulti(challenge, difficulty, ids, 0)
	b2 := vdf.WesolowskiSolveMulti(challenge, difficulty, ids, 0)
	if !bytes.Equal(b1[:], b2[:]) {
		t.Fatalf("Expected deterministic blob for same inputs")
	}
}
