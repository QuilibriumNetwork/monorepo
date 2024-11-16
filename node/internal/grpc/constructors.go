package grpc

import (
	"context"

	"google.golang.org/grpc"
)

// NewServer returns a new grpc.Server with the given options.
func NewServer(opts ...grpc.ServerOption) *grpc.Server {
	return grpc.NewServer(ServerOptions(opts...)...)
}

// DialContext returns a new grpc.ClientConn with the given target and options.
func DialContext(ctx context.Context, target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	return grpc.DialContext(ctx, target, ClientOptions(opts...)...)
}
