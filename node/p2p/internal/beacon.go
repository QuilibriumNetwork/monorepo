package internal

import (
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"source.quilibrium.com/quilibrium/monorepo/config"
)

// BeaconPeerID returns the peer ID of the beacon node.
func BeaconPeerID(network uint) peer.ID {
	genesis, err := config.DownloadAndVerifyGenesis(network)
	if err != nil {
		panic(err)
	}
	pub, err := crypto.UnmarshalEd448PublicKey(genesis.Beacon)
	if err != nil {
		panic(err)
	}
	peerID, err := peer.IDFromPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return peerID
}
