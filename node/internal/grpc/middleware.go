package grpc

import "google.golang.org/grpc"

// ServerOptions returns a list of grpc.ServerOptions which are commonly used.
func ServerOptions(opts ...grpc.ServerOption) []grpc.ServerOption {
	return append(opts,
		grpc.ChainUnaryInterceptor(
			serverMetrics.UnaryServerInterceptor(),
		),
		grpc.ChainStreamInterceptor(
			serverMetrics.StreamServerInterceptor(),
		),
	)
}

// ClientOptions returns a list of grpc.DialOptions which are commonly used.
func ClientOptions(opts ...grpc.DialOption) []grpc.DialOption {
	return append(opts,
		grpc.WithChainStreamInterceptor(
			clientMetrics.StreamClientInterceptor(),
		),
		grpc.WithChainUnaryInterceptor(
			clientMetrics.UnaryClientInterceptor(),
		),
	)
}
