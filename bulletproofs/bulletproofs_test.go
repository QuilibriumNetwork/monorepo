package bulletproofs

import (
	"crypto/rand"
	"math/big"
	"testing"
	"time"
)

func RandomBigInt(bitSize uint64) (*big.Int, error) {
	// Compute 2^(bitSize) which serves as the exclusive upper bound.
	upperBound := new(big.Int).Lsh(big.NewInt(1), uint(bitSize))
	// Generate a random number in [0, upperBound).
	n, err := rand.Int(rand.Reader, upperBound)
	if err != nil {
		return nil, err
	}
	return n, nil
}

func TestRangeProof(t *testing.T) {
	// Generate a proof
	n := uint64(32)
	b1, _ := RandomBigInt(n)
	b2, _ := RandomBigInt(n)
	now := time.Now()
	prover := &Decaf448BulletproofProver{}
	result, err := prover.GenerateRangeProofFromBig([]*big.Int{b1, b2}, []byte{}, n)
	if err != nil {
		t.Fatalf("failed to generate range proof: %v", err)
	}
	t.Logf("Proof generated in %v", time.Since(now))
	now = time.Now()
	// Now we can verify the proof against the commitment that was returned
	valid := prover.VerifyRangeProof(result.Proof, result.Commitment, n)
	if !valid {
		t.Fatalf("range proof verification failed")
	}
	t.Logf("Proof verified in %v", time.Since(now))
	result.Proof[0] ^= 0xFF
	valid = prover.VerifyRangeProof(result.Proof, result.Commitment, n)
	if valid {
		t.Fatalf("invalid range proof verified")
	}
	t.Logf("Range proof successfully verified")
	t.Logf("Proof size: %d bytes: %x", len(result.Proof), result.Proof)
	t.Logf("Commitment size: %d bytes: %x", len(result.Commitment), result.Commitment)
	t.Logf("Blinding factor size: %d bytes: %x", len(result.Blinding), result.Blinding)
	// t.FailNow()
	// uncomment to print
}

func TestSumCheck(t *testing.T) {
	prover := &Decaf448BulletproofProver{}
	n := uint64(32)
	b1, _ := RandomBigInt(n)
	b2, _ := RandomBigInt(n)
	now := time.Now()
	result, err := prover.GenerateRangeProofFromBig([]*big.Int{b1, b2}, []byte{}, n)
	if err != nil {
		t.Fatalf("failed to generate range proof: %v", err)
	}
	t.Logf("Proof generated in %v", time.Since(now))
	input := big.NewInt(0)
	input.Add(input, b1)
	input.Add(input, b2)
	input.Add(input, big.NewInt(1))

	inputCommit := prover.GenerateInputCommitmentsFromBig([]*big.Int{input}, result.Blinding)
	if !prover.SumCheck([][]byte{inputCommit}, []*big.Int{}, [][]byte{result.Commitment[:56], result.Commitment[56:]}, []*big.Int{big.NewInt(1)}) {
		t.Fatalf("failed sum check")
	}
	if prover.SumCheck([][]byte{inputCommit}, []*big.Int{}, [][]byte{result.Commitment[:56], result.Commitment[56:]}, []*big.Int{big.NewInt(0)}) {
		t.Fatalf("should have failed sum check")
	}
}

func TestSignSimple(t *testing.T) {
	prover := &Decaf448BulletproofProver{}
	c := &Decaf448KeyConstructor{}
	k, _ := c.New()
	out := prover.SimpleSign(k.Private(), []byte("testing"))
	if len(out) != 112 {
		t.Fatalf("invalid signature produced: len = %d", len(out))
	}
	if !prover.SimpleVerify([]byte("testing"), out, k.Public()) {
		t.Fatalf("invalid signature")
	}
}
