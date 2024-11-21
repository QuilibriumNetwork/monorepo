package blossomsub

import (
	"context"
	"errors"
)

var ErrQueueFull = errors.New("queue full")

// rpcQueue is a queue of RPCs with two priority levels: fast and slow.
// Fast RPCs are processed before slow RPCs.
type rpcQueue struct {
	ctx       context.Context
	cancel    context.CancelFunc
	fastQueue chan *RPC
	slowQueue chan *RPC
}

// Close closes the queue.
func (q *rpcQueue) Close() error {
	q.cancel()
	return nil
}

// TryPush tries to push an RPC to the queue.
// Returns ErrQueueFull if the queue is full, or the context error if the context is done.
func (q *rpcQueue) TryPush(ctx context.Context, rpc *RPC, fast bool) error {
	ch := q.slowQueue
	if fast {
		ch = q.fastQueue
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-q.ctx.Done():
		return q.ctx.Err()
	case ch <- rpc:
		return nil
	default:
		return ErrQueueFull
	}
}

// Push pushes an RPC to the queue.
// Returns the context error if the context is done.
func (q *rpcQueue) Push(ctx context.Context, rpc *RPC, fast bool) error {
	ch := q.slowQueue
	if fast {
		ch = q.fastQueue
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-q.ctx.Done():
		return q.ctx.Err()
	case ch <- rpc:
		return nil
	}
}

// Pop pops an RPC from the queue.
// Returns the RPC or the context error.
func (q *rpcQueue) Pop(ctx context.Context) (*RPC, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-q.ctx.Done():
		return nil, q.ctx.Err()
	case rpc := <-q.fastQueue:
		return rpc, nil
	default:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-q.ctx.Done():
		return nil, q.ctx.Err()
	case rpc := <-q.fastQueue:
		return rpc, nil
	case rpc := <-q.slowQueue:
		return rpc, nil
	}
}

// newRPCQueue creates a new RPC queue.
func newRPCQueue(fastSize, slowSize int) *rpcQueue {
	ctx, cancel := context.WithCancel(context.Background())
	return &rpcQueue{
		ctx:       ctx,
		cancel:    cancel,
		fastQueue: make(chan *RPC, fastSize),
		slowQueue: make(chan *RPC, slowSize),
	}
}
