package grpc

import (
	"context"

	"github.com/libp2p/go-libp2p/core/peer"
)

type peerIDKeyType struct{}

var peerIDKey peerIDKeyType

// PeerIDFromContext returns the peer.ID of the remote peer from the given
// context.
func PeerIDFromContext(ctx context.Context) (peer.ID, bool) {
	if peerID, ok := ctx.Value(peerIDKey).(peer.ID); ok {
		return peerID, true
	}
	return "", false
}

// NewContextWithPeerID returns a new context with the given peer.ID.
// This method is meant to be used only in unit testing contexts.
func NewContextWithPeerID(ctx context.Context, peerID peer.ID) context.Context {
	return context.WithValue(ctx, peerIDKey, peerID)
}
