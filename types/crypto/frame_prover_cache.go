package crypto

import (
	"context"
	"io"
	"sync"
	"time"
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

func NewCachedFrameProverWithTTL(
	prover FrameProver,
	ttl time.Duration,
) FrameProver {
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

type frameProverVerifyChallengeProofCacheEntry struct {
	done      chan struct{}
	result    bool
	createdAt time.Time
}

func (c *frameProverCache) Close() error {
	c.cancel()
	return nil
}
