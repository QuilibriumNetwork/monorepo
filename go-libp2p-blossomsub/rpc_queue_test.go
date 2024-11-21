package blossomsub

import (
	"context"
	"errors"
	"testing"
)

func TestRPCQueue(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	q := newRPCQueue(32, 32)
	defer q.Close()

	rpcs := []*RPC{
		{from: "a"},
		{from: "b"},
		{from: "c"},
		{from: "d"},
	}

	for i, tc := range []struct {
		fast bool
		rpc  *RPC
	}{
		{true, rpcs[0]},
		{false, rpcs[1]},
		{true, rpcs[2]},
		{false, rpcs[3]},
	} {
		if err := q.TryPush(ctx, tc.rpc, tc.fast); err != nil {
			t.Fatal(i, "unexpected error:", err)
		}
	}
	for i, tc := range []struct {
		rpc *RPC
	}{
		{rpcs[0]},
		{rpcs[2]},
		{rpcs[1]},
		{rpcs[3]},
	} {
		rpc, err := q.Pop(ctx)
		if err != nil {
			t.Fatal(i, "unexpected error:", err)
		}
		if rpc != tc.rpc {
			t.Fatal(i, "expected rpc", string(tc.rpc.from), "got", string(rpc.from))
		}
	}

	q = newRPCQueue(0, 0)
	defer q.Close()

	type result struct {
		rpc *RPC
		err error
	}
	res := make(chan result, 1)
	go func() {
		rpc, err := q.Pop(ctx)
		res <- result{rpc, err}
	}()
	if err := q.Push(ctx, rpcs[0], false); err != nil {
		t.Fatal("unexpected error:", err)
	}
	r := <-res
	if r.err != nil {
		t.Fatal("unexpected error:", r.err)
	}
	if r.rpc != rpcs[0] {
		t.Fatal("expected rpc", string(rpcs[0].from), "got", string(r.rpc.from))
	}

	if err := q.TryPush(ctx, rpcs[0], false); !errors.Is(err, ErrQueueFull) {
		t.Fatal("expected ErrQueueFull, got", err)
	}
}
