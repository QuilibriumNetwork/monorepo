package internal

import (
	"context"

	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
)

// PeerSource is a source of peers.
type PeerSource interface {
	// Peers returns a channel of peers.
	Peers(context.Context) (<-chan peer.AddrInfo, error)
}

type staticPeerSource struct {
	peers   []peer.AddrInfo
	permute bool
}

// Peers implements PeerSource.
func (s *staticPeerSource) Peers(context.Context) (
	<-chan peer.AddrInfo,
	error,
) {
	peers := s.peers
	if s.permute {
		peers = Permuted(s.peers)
	}
	ch := make(chan peer.AddrInfo, len(peers))
	for _, p := range peers {
		ch <- p
	}
	close(ch)
	return ch, nil
}

// NewStaticPeerSource creates a new static peer source.
func NewStaticPeerSource(peers []peer.AddrInfo, permute bool) PeerSource {
	return &staticPeerSource{peers: peers, permute: permute}
}

type routingDiscoveryPeerSource struct {
	discovery *routing.RoutingDiscovery
	namespace string
	limit     int
}

// Peers implements PeerSource.
func (d *routingDiscoveryPeerSource) Peers(ctx context.Context) (
	<-chan peer.AddrInfo,
	error,
) {
	return d.discovery.FindPeers(ctx, d.namespace, discovery.Limit(d.limit))
}

// NewRoutingDiscoveryPeerSource creates a new discovery peer source.
func NewRoutingDiscoveryPeerSource(
	discovery *routing.RoutingDiscovery,
	namespace string,
	limit int,
) PeerSource {
	return &routingDiscoveryPeerSource{
		discovery: discovery,
		namespace: namespace,
		limit:     limit,
	}
}
