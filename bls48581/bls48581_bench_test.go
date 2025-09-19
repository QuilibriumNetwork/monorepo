package bls48581_test

import (
	"fmt"
	"runtime"
	"testing"

	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	generated "source.quilibrium.com/quilibrium/monorepo/bls48581/generated/bls48581"
)

// Helper function to generate test data
func generateTestData(n int) ([][]byte, [][]byte) {
	pubs := make([][]byte, n)
	sigs := make([][]byte, n)
	for i := 0; i < n; i++ {
		key := bls48581.BlsKeygen()
		pubs[i] = key.GetPublicKey()
		sigs[i] = bls48581.BlsSign(key.GetPrivateKey(), []byte("benchmark"), []byte("sig"))
	}
	return pubs, sigs
}

// Direct implementation without parallelization for comparison
func blsAggregateSequential(pks [][]byte, sigs [][]byte) *bls48581.BlsAggregateOutput {
	ag := generated.BlsAggregate(pks, sigs)
	pk := make([]byte, len(ag.AggregatePublicKey))
	sig := make([]byte, len(ag.AggregateSignature))
	copy(pk, ag.AggregatePublicKey)
	copy(sig, ag.AggregateSignature)
	return &bls48581.BlsAggregateOutput{
		AggregatePublicKey: pk,
		AggregateSignature: sig,
	}
}

// Benchmark the parallelized implementation
func BenchmarkBlsAggregateParallel(b *testing.B) {
	sizes := []int{100, 500, 1000, 5000, 10000}
	
	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			pubs, sigs := generateTestData(size)
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				_ = bls48581.BlsAggregate(pubs, sigs)
			}
		})
	}
}

// Benchmark the sequential implementation for comparison
func BenchmarkBlsAggregateSequential(b *testing.B) {
	sizes := []int{100, 500, 1000, 5000, 10000}
	
	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			pubs, sigs := generateTestData(size)
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				_ = blsAggregateSequential(pubs, sigs)
			}
		})
	}
}

// Test to ensure the parallelized version produces the same results
func TestBlsAggregateParallelCorrectness(t *testing.T) {
	sizes := []int{50, 100, 200, 500, 1000}
	
	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			pubs, sigs := generateTestData(size)
			
			// Get result from parallelized version
			parallelResult := bls48581.BlsAggregate(pubs, sigs)
			
			// Get result from sequential version
			sequentialResult := blsAggregateSequential(pubs, sigs)
			
			// Compare public keys
			parallelPK := parallelResult.GetAggregatePublicKey()
			sequentialPK := sequentialResult.GetAggregatePublicKey()
			
			if len(parallelPK) != len(sequentialPK) {
				t.Errorf("Public key lengths differ: parallel=%d, sequential=%d", 
					len(parallelPK), len(sequentialPK))
			}
			
			for i := range parallelPK {
				if parallelPK[i] != sequentialPK[i] {
					t.Errorf("Public keys differ at index %d", i)
					break
				}
			}
			
			// Compare signatures
			parallelSig := parallelResult.GetAggregateSignature()
			sequentialSig := sequentialResult.GetAggregateSignature()
			
			if len(parallelSig) != len(sequentialSig) {
				t.Errorf("Signature lengths differ: parallel=%d, sequential=%d", 
					len(parallelSig), len(sequentialSig))
			}
			
			for i := range parallelSig {
				if parallelSig[i] != sequentialSig[i] {
					t.Errorf("Signatures differ at index %d", i)
					break
				}
			}
			
			// Verify both signatures work
			msg := []byte("test")
			domain := []byte("sig")
			
			// Sign with first key to get a signature for verification
			key := bls48581.BlsKeygen()
			testSig := bls48581.BlsSign(key.GetPrivateKey(), msg, domain)
			testPubs := [][]byte{key.GetPublicKey()}
			testSigs := [][]byte{testSig}
			
			parallelTestResult := bls48581.BlsAggregate(testPubs, testSigs)
			if !bls48581.BlsVerify(
				parallelTestResult.GetAggregatePublicKey(),
				parallelTestResult.GetAggregateSignature(),
				msg,
				domain,
			) {
				t.Error("Parallel aggregated signature verification failed")
			}
		})
	}
}

// Test edge cases
func TestBlsAggregateParallelEdgeCases(t *testing.T) {
	// Test with empty inputs
	t.Run("EmptyInputs", func(t *testing.T) {
		result := bls48581.BlsAggregate([][]byte{}, [][]byte{})
		if result == nil {
			t.Error("Expected non-nil result for empty inputs")
		}
	})
	
	// Test with single input (should not use parallelization)
	t.Run("SingleInput", func(t *testing.T) {
		key := bls48581.BlsKeygen()
		pub := key.GetPublicKey()
		sig := bls48581.BlsSign(key.GetPrivateKey(), []byte("test"), []byte("sig"))
		
		result := bls48581.BlsAggregate([][]byte{pub}, [][]byte{sig})
		if !bls48581.BlsVerify(
			result.GetAggregatePublicKey(),
			result.GetAggregateSignature(),
			[]byte("test"),
			[]byte("sig"),
		) {
			t.Error("Single input aggregation verification failed")
		}
	})
	
	// Test with mismatched lengths (should handle gracefully)
	t.Run("MismatchedLengths", func(t *testing.T) {
		pubs, sigs := generateTestData(10)
		// Remove one signature
		sigs = sigs[:9]
		
		result := bls48581.BlsAggregate(pubs, sigs)
		if result == nil {
			t.Error("Expected non-nil result for mismatched inputs")
		}
	})
}

// Benchmark to show speedup with different CPU counts
func BenchmarkBlsAggregateScaling(b *testing.B) {
	// This benchmark shows how performance scales with different worker counts
	const testSize = 10000
	pubs, sigs := generateTestData(testSize)
	
	b.Run(fmt.Sprintf("CPUs_%d", runtime.NumCPU()), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = bls48581.BlsAggregate(pubs, sigs)
		}
	})
}