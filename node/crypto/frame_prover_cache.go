package crypto

import (
	"context"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
)

type frameProverCache struct {
	FrameProver

	ctx    context.Context
	cancel context.CancelFunc

	verifyChallengeProofCache sync.Map
}

var (
	_ FrameProver = (*frameProverCache)(nil)
	_ io.Closer   = (*frameProverCache)(nil)
)

func (c *frameProverCache) gc(ctx context.Context, ttl time.Duration) {
	ticker := time.NewTicker(ttl / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.verifyChallengeProofCache.Range(func(key, value interface{}) bool {
				if entry := value.(*frameProverVerifyChallengeProofCacheEntry); time.Since(entry.createdAt) > ttl {
					_ = c.verifyChallengeProofCache.CompareAndDelete(key, value)
				}
				return true
			})
		}
	}
}

func NewCachedFrameProverWithTTL(prover FrameProver, ttl time.Duration) FrameProver {
	ctx, cancel := context.WithCancel(context.Background())
	c := &frameProverCache{
		FrameProver: prover,

		ctx:    ctx,
		cancel: cancel,
	}
	go c.gc(ctx, ttl)
	return c
}

func NewCachedFrameProver(prover FrameProver) FrameProver {
	return NewCachedFrameProverWithTTL(prover, 5*time.Minute)
}

func NewCachedWesolowskiFrameProver(logger *zap.Logger) FrameProver {
	return NewCachedFrameProver(NewWesolowskiFrameProver(logger))
}

type frameProverVerifyChallengeProofCacheEntry struct {
	done      chan struct{}
	result    bool
	createdAt time.Time
}

func (c *frameProverCache) verifyChallengeProofKey(
	challenge []byte,
	difficulty uint32,
	proof [516]byte,
) [552]byte {
	h := sha3.Sum256(challenge)
	var key [32 + 4 + 516]byte
	copy(key[:32], h[:])
	binary.BigEndian.PutUint32(key[32:36], difficulty)
	copy(key[36:], proof[:])
	return key
}

func (c *frameProverCache) VerifyChallengeProof(
	challenge []byte,
	difficulty uint32,
	proof []byte,
) bool {
	if len(proof) != 516 {
		return false
	}
	key := c.verifyChallengeProofKey(challenge, difficulty, [516]byte(proof))
	entry := &frameProverVerifyChallengeProofCacheEntry{
		done:      make(chan struct{}),
		createdAt: time.Now(),
	}
	defer close(entry.done)
	if entry, loaded := c.verifyChallengeProofCache.LoadOrStore(key, entry); loaded {
		entry := entry.(*frameProverVerifyChallengeProofCacheEntry)
		<-entry.done
		return entry.result
	}
	entry.result = c.FrameProver.VerifyChallengeProof(challenge, difficulty, proof)
	return entry.result
}

func (c *frameProverCache) Close() error {
	c.cancel()
	return nil
}
