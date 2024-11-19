package internal

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/peer"
)

type peerConnectorDiscovery struct {
	connector PeerConnector
}

var _ discovery.Discovery = (*peerConnectorDiscovery)(nil)

// Advertise implements discovery.Advertiser.
func (d *peerConnectorDiscovery) Advertise(ctx context.Context, ns string, opts ...discovery.Option) (time.Duration, error) {
	return time.Duration(1<<63 - 1), nil
}

// FindPeers implements discovery.Discoverer.
func (d *peerConnectorDiscovery) FindPeers(ctx context.Context, ns string, opts ...discovery.Option) (<-chan peer.AddrInfo, error) {
	if err := d.connector.Connect(ctx); err != nil {
		return nil, err
	}
	ch := make(chan peer.AddrInfo)
	close(ch)
	return ch, nil
}

// NewPeerConnectorDiscovery creates a new peer connector discovery.
// The discovery instance does not do any advertisements and just triggers
// the peer connector once FindPeers is called.
func NewPeerConnectorDiscovery(connector PeerConnector) discovery.Discovery {
	return &peerConnectorDiscovery{connector: connector}
}
