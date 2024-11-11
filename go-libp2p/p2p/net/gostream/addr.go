package gostream

import (
	"net"

	"github.com/libp2p/go-libp2p/core/peer"
)

// addr implements net.Addr and holds a libp2p peer ID.
type addr struct{ id peer.ID }

// Network returns the name of the network that this address belongs to
// (libp2p).
func (a *addr) Network() string { return Network }

// String returns the peer ID of this address in string form
// (B58-encoded).
func (a *addr) String() string { return a.id.String() }

// PeerIDFromAddr extracts a peer ID from a net.Addr.
func PeerIDFromAddr(a net.Addr) (peer.ID, bool) {
	addr, ok := a.(*addr)
	if !ok {
		return "", false
	}
	return addr.id, true
}
