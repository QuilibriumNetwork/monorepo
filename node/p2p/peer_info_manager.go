package p2p

import (
	"bytes"
	"sync"
	"time"

	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
)

type InMemoryPeerInfoManager struct {
	logger     *zap.Logger
	peerInfoCh chan *protobufs.PeerInfo
	quitCh     chan struct{}
	peerInfoMx sync.RWMutex

	peerMap      map[string]*p2p.PeerInfo
	fastestPeers []*p2p.PeerInfo
}

var _ p2p.PeerInfoManager = (*InMemoryPeerInfoManager)(nil)

func NewInMemoryPeerInfoManager(logger *zap.Logger) *InMemoryPeerInfoManager {
	return &InMemoryPeerInfoManager{
		logger:       logger,
		peerInfoCh:   make(chan *protobufs.PeerInfo, 1000),
		fastestPeers: []*p2p.PeerInfo{},
		peerMap:      make(map[string]*p2p.PeerInfo),
	}
}

func (m *InMemoryPeerInfoManager) Start() {
	go func() {
		for {
			select {
			case info := <-m.peerInfoCh:
				m.peerInfoMx.Lock()
				reachability := []p2p.Reachability{}
				for _, r := range info.Reachability {
					reachability = append(reachability, p2p.Reachability{
						Filter:           r.Filter,
						PubsubMultiaddrs: r.PubsubMultiaddrs,
						StreamMultiaddrs: r.StreamMultiaddrs,
					})
				}
				capabilities := []p2p.Capability{}
				for _, c := range info.Capabilities {
					capabilities = append(capabilities, p2p.Capability{
						ProtocolIdentifier: c.ProtocolIdentifier,
						AdditionalMetadata: c.AdditionalMetadata,
					})
				}
				seen := time.Now().UnixMilli()
				m.peerMap[string(info.PeerId)] = &p2p.PeerInfo{
					PeerId:       info.PeerId,
					Bandwidth:    100,
					Capabilities: capabilities,
					Reachability: reachability,
					Cores:        uint32(len(reachability)),
					LastSeen:     seen,
				}
				m.searchAndInsertPeer(&p2p.PeerInfo{
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

func (m *InMemoryPeerInfoManager) GetPeerInfo(peerId []byte) *p2p.PeerInfo {
	m.peerInfoMx.RLock()
	manifest, ok := m.peerMap[string(peerId)]
	m.peerInfoMx.RUnlock()
	if !ok {
		return nil
	}
	return manifest
}

func (m *InMemoryPeerInfoManager) GetPeerMap() map[string]*p2p.PeerInfo {
	data := make(map[string]*p2p.PeerInfo)
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
func (m *InMemoryPeerInfoManager) searchAndInsertPeer(info *p2p.PeerInfo) {
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
		m.fastestPeers = append(m.fastestPeers, new(p2p.PeerInfo))
		copy(m.fastestPeers[i+1:], m.fastestPeers[i:])
		m.fastestPeers[i] = info
	}
}
