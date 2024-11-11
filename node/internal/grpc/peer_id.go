package grpc

import (
	"context"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/gostream"
	grpc_peer "google.golang.org/grpc/peer"
)

type peerIDKeyType struct{}

var peerIDKey peerIDKeyType

// PeerIDFromContext returns the peer.ID of the remote peer from the given context.
// It assumes that the context is a gRPC request context, and the connection was established
// by gostream.Listen.
func PeerIDFromContext(ctx context.Context) (peer.ID, bool) {
	if peerID, ok := ctx.Value(peerIDKey).(peer.ID); ok {
		return peerID, true
	}
	remotePeer, ok := grpc_peer.FromContext(ctx)
	if !ok {
		return "", false
	}
	return gostream.PeerIDFromAddr(remotePeer.Addr)
}

// NewContextWithPeerID returns a new context with the given peer.ID.
// This method is meant to be used only in unit testing contexts.
func NewContextWithPeerID(ctx context.Context, peerID peer.ID) context.Context {
	return context.WithValue(ctx, peerIDKey, peerID)
}
