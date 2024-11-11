package data

import (
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type RateLimiter struct {
	mu            sync.RWMutex
	clients       map[peer.ID]*bucket
	maxTokens     int
	refillTokens  int
	refillTime    time.Duration
	maxCallers    int
	lastCleanup   time.Time
	cleanupPeriod time.Duration
}

type bucket struct {
	tokens   int
	lastSeen time.Time
}

func NewRateLimiter(
	maxTokens int,
	maxCallers int,
	refillTokens int,
	refillDuration time.Duration,
) *RateLimiter {
	return &RateLimiter{
		clients:       make(map[peer.ID]*bucket),
		maxTokens:     maxTokens,
		refillTokens:  refillTokens,
		refillTime:    refillDuration,
		maxCallers:    maxCallers,
		lastCleanup:   time.Now(),
		cleanupPeriod: time.Minute,
	}
}

func (rl *RateLimiter) Allow(peerId peer.ID) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	if now.Sub(rl.lastCleanup) >= rl.cleanupPeriod {
		rl.cleanup(now)
		rl.lastCleanup = now
	}

	b, exists := rl.clients[peerId]
	if !exists {
		if len(rl.clients) >= rl.maxCallers {
			return status.Errorf(codes.ResourceExhausted,
				"maximum number of unique callers (%d) reached", rl.maxCallers)
		}

		b = &bucket{
			tokens:   rl.maxTokens - 1,
			lastSeen: now,
		}
		rl.clients[peerId] = b
		return nil
	}

	elapsed := now.Sub(b.lastSeen)
	refillCycles := int(elapsed / rl.refillTime)
	b.tokens += refillCycles * rl.refillTokens
	if b.tokens > rl.maxTokens {
		b.tokens = rl.maxTokens
	}

	if b.tokens <= 0 {
		return status.Errorf(codes.ResourceExhausted,
			"rate limit exceeded, try again in %v",
			rl.refillTime-elapsed%rl.refillTime)
	}

	b.tokens--
	b.lastSeen = now
	return nil
}

func (rl *RateLimiter) cleanup(now time.Time) {
	threshold := now.Add(-rl.cleanupPeriod * 2)
	for clientID, bucket := range rl.clients {
		if bucket.lastSeen.Before(threshold) {
			delete(rl.clients, clientID)
		}
	}
}

func (rl *RateLimiter) GetActiveCallers() int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return len(rl.clients)
}
