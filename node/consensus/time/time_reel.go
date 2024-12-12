package time

import (
	"context"

	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

type TimeReel interface {
	Start() error
	Stop()
	Insert(ctx context.Context, frame *protobufs.ClockFrame) (<-chan struct{}, error)
	Head() (*protobufs.ClockFrame, error)
	NewFrameCh() <-chan *protobufs.ClockFrame
	BadFrameCh() <-chan *protobufs.ClockFrame
}
