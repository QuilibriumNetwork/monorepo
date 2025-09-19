package p2p

import (
	"bytes"
	"sync"
	"time"

	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

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

type InMemoryPeerInfoManager struct {
	logger     *zap.Logger
	peerInfoCh chan *protobufs.PeerInfo
	quitCh     chan struct{}
	peerInfoMx sync.RWMutex

	peerMap      map[string]*PeerInfo
	fastestPeers []*PeerInfo
}

var _ PeerInfoManager = (*InMemoryPeerInfoManager)(nil)

func NewInMemoryPeerInfoManager(logger *zap.Logger) *InMemoryPeerInfoManager {
	return &InMemoryPeerInfoManager{
		logger:       logger,
		peerInfoCh:   make(chan *protobufs.PeerInfo, 1000),
		fastestPeers: []*PeerInfo{},
		peerMap:      make(map[string]*PeerInfo),
	}
}

func (m *InMemoryPeerInfoManager) Start() {
	go func() {
		for {
			select {
			case info := <-m.peerInfoCh:
				m.peerInfoMx.Lock()
				reachability := []Reachability{}
				for _, r := range info.Reachability {
					reachability = append(reachability, Reachability{
						Filter:           r.Filter,
						PubsubMultiaddrs: r.PubsubMultiaddrs,
						StreamMultiaddrs: r.StreamMultiaddrs,
					})
				}
				capabilities := []Capability{}
				for _, c := range info.Capabilities {
					capabilities = append(capabilities, Capability{
						ProtocolIdentifier: c.ProtocolIdentifier,
						AdditionalMetadata: c.AdditionalMetadata,
					})
				}
				seen := time.Now().UnixMilli()
				m.peerMap[string(info.PeerId)] = &PeerInfo{
					PeerId:       info.PeerId,
					Bandwidth:    100,
					Capabilities: capabilities,
					Reachability: reachability,
					Cores:        uint32(len(reachability)),
					LastSeen:     seen,
				}
				m.searchAndInsertPeer(&PeerInfo{
					PeerId:       info.PeerId,
					Bandwidth:    100,
					Capabilities: capabilities,
					Reachability: reachability,
					Cores:        uint32(len(reachability)),
					LastSeen:     seen,
				})
				m.peerInfoMx.Unlock()
			case <-m.quitCh:
				return
			}
		}
	}()
}

func (m *InMemoryPeerInfoManager) Stop() {
	go func() {
		m.quitCh <- struct{}{}
	}()
}

func (m *InMemoryPeerInfoManager) AddPeerInfo(info *protobufs.PeerInfo) {
	go func() {
		m.peerInfoCh <- info
	}()
}

func (m *InMemoryPeerInfoManager) GetPeerInfo(peerId []byte) *PeerInfo {
	m.peerInfoMx.RLock()
	manifest, ok := m.peerMap[string(peerId)]
	m.peerInfoMx.RUnlock()
	if !ok {
		return nil
	}
	return manifest
}

func (m *InMemoryPeerInfoManager) GetPeerMap() map[string]*PeerInfo {
	data := make(map[string]*PeerInfo)
	m.peerInfoMx.RLock()
	for k, v := range m.peerMap {
		data[k] = v
	}
	m.peerInfoMx.RUnlock()

	return data
}

func (m *InMemoryPeerInfoManager) GetPeersBySpeed() [][]byte {
	result := [][]byte{}
	m.peerInfoMx.RLock()
	for _, info := range m.fastestPeers {
		result = append(result, info.PeerId)
	}
	m.peerInfoMx.RUnlock()
	return result
}

// blatantly lifted from slices.BinarySearchFunc, optimized for direct insertion
// and uint64 comparison without overflow
func (m *InMemoryPeerInfoManager) searchAndInsertPeer(info *PeerInfo) {
	n := len(m.fastestPeers)
	i, j := 0, n
	for i < j {
		h := int(uint(i+j) >> 1)
		if m.fastestPeers[h].Bandwidth > info.Bandwidth {
			i = h + 1
		} else {
			j = h
		}
	}

	if i < n && m.fastestPeers[i].Bandwidth == info.Bandwidth &&
		bytes.Equal(m.fastestPeers[i].PeerId, info.PeerId) {
		m.fastestPeers[i] = info
	} else {
		m.fastestPeers = append(m.fastestPeers, new(PeerInfo))
		copy(m.fastestPeers[i+1:], m.fastestPeers[i:])
		m.fastestPeers[i] = info
	}
}
