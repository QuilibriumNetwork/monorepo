package p2p

import "source.quilibrium.com/quilibrium/monorepo/protobufs"

type PeerInfoManager interface {
	Start()
	Stop()
	AddPeerInfo(info *protobufs.PeerInfo)
	GetPeerInfo(peerId []byte) *PeerInfo
	GetPeerMap() map[string]*PeerInfo
	GetPeersBySpeed() [][]byte
}

type Reachability struct {
	Filter           []byte
	PubsubMultiaddrs []string
	StreamMultiaddrs []string
}

type Capability struct {
	ProtocolIdentifier uint32
	AdditionalMetadata []byte
}

type PeerInfo struct {
	PeerId       []byte
	Cores        uint32
	Capabilities []Capability
	Reachability []Reachability
	Bandwidth    uint64
	LastSeen     int64
}
