package crypto_test

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
)

type mockFrameProver struct {
	crypto.FrameProver
	verifyChallengeProof func(challenge []byte, difficulty uint32, proof []byte) bool
}

var _ crypto.FrameProver = (*mockFrameProver)(nil)

func (m *mockFrameProver) VerifyChallengeProof(challenge []byte, difficulty uint32, proof []byte) bool {
	return m.verifyChallengeProof(challenge, difficulty, proof)
}

func TestCachedFrameProver(t *testing.T) {
	t.Parallel()

	callCount := 0
	prover := &mockFrameProver{
		verifyChallengeProof: func(challenge []byte, difficulty uint32, proof []byte) bool {
			callCount++
			switch {
			case bytes.Equal(challenge, []byte{1, 2, 3}):
				assert.Equal(t, uint32(42), difficulty)
				assert.Equal(t, bytes.Repeat([]byte{0x42}, 516), proof)
				return true
			case bytes.Equal(challenge, []byte{1, 2, 4}):
				assert.Equal(t, uint32(43), difficulty)
				assert.Equal(t, bytes.Repeat([]byte{0x43}, 516), proof)
				return false
			default:
				t.Fatal("unexpected call")
				return false
			}
		},
	}

	cache := crypto.NewCachedFrameProverWithTTL(prover, 500*time.Millisecond)
	defer cache.(io.Closer).Close()

	// Check that the proof size is checked.
	result := cache.VerifyChallengeProof([]byte{1, 2, 3}, 42, []byte{4, 5, 6})
	assert.Equal(t, 0, callCount)
	assert.False(t, result)

	// Check that the result is cached.
	result = cache.VerifyChallengeProof([]byte{1, 2, 3}, 42, bytes.Repeat([]byte{0x42}, 516))
	assert.Equal(t, 1, callCount)
	assert.True(t, result)

	result = cache.VerifyChallengeProof([]byte{1, 2, 3}, 42, bytes.Repeat([]byte{0x42}, 516))
	assert.Equal(t, 1, callCount)
	assert.True(t, result)

	// Check that the result is cached in another key.
	result = cache.VerifyChallengeProof([]byte{1, 2, 4}, 43, bytes.Repeat([]byte{0x43}, 516))
	assert.Equal(t, 2, callCount)
	assert.False(t, result)

	result = cache.VerifyChallengeProof([]byte{1, 2, 4}, 43, bytes.Repeat([]byte{0x43}, 516))
	assert.Equal(t, 2, callCount)
	assert.False(t, result)

	// Wait for GC.
	time.Sleep(time.Second)

	// Check that the result is not cached anymore.
	result = cache.VerifyChallengeProof([]byte{1, 2, 3}, 42, bytes.Repeat([]byte{0x42}, 516))
	assert.Equal(t, 3, callCount)
	assert.True(t, result)

	// Check that the result is not cached anymore in another key.
	result = cache.VerifyChallengeProof([]byte{1, 2, 4}, 43, bytes.Repeat([]byte{0x43}, 516))
	assert.Equal(t, 4, callCount)
	assert.False(t, result)
}
