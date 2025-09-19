package onion

import "context"

// Transport is the hop-to-hop link. It must already provide integrity/
// confidentiality. We route onion cells on top of it.
type Transport interface {
	// Send a link-level cell to a peer.
	Send(ctx context.Context, peerID []byte, circID uint32, cell []byte) error

	// Register a callback for _incoming_ link-level cells from any peer.
	// P2P layers should invoke cb for every onion payload destined to this node.
	OnReceive(cb func(srcPeerID []byte, circID uint32, cell []byte))
}
