package frametime

import (
	"time"

	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// AppFrameSince returns the time elapsed since the given frame was created.
func AppFrameSince(frame *protobufs.AppShardFrame) time.Duration {
	return time.Since(time.UnixMilli(frame.Header.Timestamp))
}

// GlobalFrameSince returns the time elapsed since the given frame was created.
func GlobalFrameSince(frame *protobufs.GlobalFrame) time.Duration {
	return time.Since(time.UnixMilli(frame.Header.Timestamp))
}
