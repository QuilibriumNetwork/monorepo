package p2p

import (
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

type PeerInfoManager interface {
	Start(context lifecycle.SignalerContext, ready lifecycle.ReadyFunc)
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
	PeerId              []byte
	Cores               uint32
	Capabilities        []Capability
	Reachability        []Reachability
	LastSeen            int64
	Version             []byte
	PatchNumber         []byte
	LastReceivedFrame   uint64
	LastGlobalHeadFrame uint64
}
