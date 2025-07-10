package execution

import (
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

type ShardExecutionEngine interface {
	GetName() string
	Start(chan struct{}) <-chan error
	Stop(force bool) <-chan error
	ProcessMessage(
		address []byte,
		message *protobufs.Message,
	) ([]*protobufs.Message, error)
}
