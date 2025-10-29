package consensus

import (
	"context"
	"time"
)

type BackoffTimer struct {
	timeoutCh chan time.Time
	cancel    context.CancelFunc
	fail      uint64
}

func NewBackoffTimer() *BackoffTimer {
	t := make(chan time.Time)
	close(t)

	return &BackoffTimer{
		timeoutCh: t,
		cancel:    func() {},
		fail:      0,
	}
}

func (t *BackoffTimer) TimeoutCh() <-chan time.Time {
	return t.timeoutCh
}

func (t *BackoffTimer) Start(
	ctx context.Context,
) (start, end time.Time) {
	t.cancel()

	t.timeoutCh = make(chan time.Time)
	ctx, cancelFn := context.WithCancel(ctx)
	t.cancel = cancelFn

	go rebroadcastTimeout(ctx, t.timeoutCh)

	start = time.Now().UTC()
	end = start.Add(time.Duration(min(t.fail, 10)+10) * time.Second)
	return start, end
}

func (t *BackoffTimer) ReceiveTimeout() {
	if t.fail < 10 {
		t.fail++
	}
}

func (t *BackoffTimer) ReceiveSuccess() {
	if t.fail > 0 {
		t.fail--
	}
}

func rebroadcastTimeout(ctx context.Context, timeoutCh chan<- time.Time) {
	timeout := time.NewTimer(20 * time.Second)
	select {
	case t := <-timeout.C:
		timeoutCh <- t
	case <-ctx.Done():
		timeout.Stop()
		return
	}

	rebroadcast := time.NewTicker(1 * time.Second)
	for {
		select {
		case t := <-rebroadcast.C:
			timeoutCh <- t
		case <-ctx.Done():
			rebroadcast.Stop()
			return
		}
	}
}
