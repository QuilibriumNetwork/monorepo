package consensus

import "source.quilibrium.com/quilibrium/monorepo/protobufs"

type AppFrameValidator interface {
	Validate(frame *protobufs.AppShardFrame) (bool, error)
}

type GlobalFrameValidator interface {
	Validate(frame *protobufs.GlobalFrame) (bool, error)
}
