package internal

import (
	"github.com/libp2p/go-libp2p/core/peer"
	blossomsub "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub"
)

// NewStaticPeerFilter creates a new static peer filter.
// The allowList is a list of peers that are allowed to mesh.
// The blockList is a list of peers that are blocked from meshing.
// The def is the default value for peers that are not in the allowList or blockList.
// The allowList has priority over the blockList.
func NewStaticPeerFilter(allowList, blockList []peer.ID, def bool) blossomsub.PeerFilter {
	allowed := make(map[peer.ID]struct{})
	for _, p := range allowList {
		allowed[p] = struct{}{}
	}
	blocked := make(map[peer.ID]struct{})
	for _, p := range blockList {
		blocked[p] = struct{}{}
	}
	return func(peerID peer.ID, _ []byte) bool {
		if _, ok := allowed[peerID]; ok {
			return true
		}
		if _, ok := blocked[peerID]; ok {
			return false
		}
		return def
	}
}
