package rpc

import (
	"context"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// ArchiveClient connects to an archive node's streaming gRPC server
// (GlobalService) using mTLS peer authentication.
type ArchiveClient struct {
	client protobufs.GlobalServiceClient
	conn   *grpc.ClientConn
	logger *zap.Logger
}

// NewArchiveClient wraps an already-established GlobalServiceClient and its
// underlying connection. The caller is responsible for creating the mTLS
// connection; this constructor simply stores the references.
func NewArchiveClient(
	client protobufs.GlobalServiceClient,
	conn *grpc.ClientConn,
	logger *zap.Logger,
) *ArchiveClient {
	return &ArchiveClient{
		client: client,
		conn:   conn,
		logger: logger,
	}
}

// Close shuts down the underlying connection.
func (c *ArchiveClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// GetGlobalFrame fetches a global frame from the archive node.
// Pass frameNumber=0 for the latest finalized frame.
func (c *ArchiveClient) GetGlobalFrame(
	ctx context.Context,
	frameNumber uint64,
) (*protobufs.GlobalFrame, error) {
	resp, err := c.client.GetGlobalFrame(ctx, &protobufs.GetGlobalFrameRequest{
		FrameNumber: frameNumber,
	})
	if err != nil {
		return nil, err
	}
	return resp.Frame, nil
}

// SubmitMessage sends a prover message to the archive node for relay.
func (c *ArchiveClient) SubmitMessage(ctx context.Context, data []byte) error {
	_, err := c.client.SubmitGlobalMessage(ctx, &protobufs.SubmitGlobalMessageRequest{
		Data: data,
	})
	return err
}

// GetLockedAddresses fetches cross-shard transaction locks from the archive.
func (c *ArchiveClient) GetLockedAddresses(
	ctx context.Context,
	req *protobufs.GetLockedAddressesRequest,
) (*protobufs.GetLockedAddressesResponse, error) {
	return c.client.GetLockedAddresses(ctx, req)
}

// Conn returns the underlying gRPC connection. This allows callers to create
// additional service clients (e.g. HypergraphComparisonServiceClient) on the
// same mTLS connection.
func (c *ArchiveClient) Conn() *grpc.ClientConn {
	return c.conn
}
