package frametime

import (
	"time"

	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

// Since returns the time elapsed since the given frame was created.
func Since(frame *protobufs.ClockFrame) time.Duration {
	return time.Since(time.UnixMilli(frame.Timestamp))
}
