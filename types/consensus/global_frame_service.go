package consensus

import "source.quilibrium.com/quilibrium/monorepo/protobufs"

// GlobalFrameService provides access to finalized global frames and message
// injection. It is implemented by the global consensus engine and exposed via
// the RPC server so that non-archive nodes can poll frames and submit prover
// messages through archive nodes.
type GlobalFrameService interface {
	LatestGlobalFrame() (*protobufs.GlobalFrame, error)
	GlobalFrameByNumber(frameNumber uint64) (*protobufs.GlobalFrame, error)
	InjectGlobalMessage(data []byte) error
}
