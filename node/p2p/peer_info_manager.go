package p2p

import (
	"sync"
	"time"

	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
)

type InMemoryPeerInfoManager struct {
	logger     *zap.Logger
	peerInfoCh chan *protobufs.PeerInfo
	peerInfoMx sync.RWMutex

	peerMap map[string]*p2p.PeerInfo
	ctx     lifecycle.SignalerContext
}

var _ p2p.PeerInfoManager = (*InMemoryPeerInfoManager)(nil)

func NewInMemoryPeerInfoManager(logger *zap.Logger) *InMemoryPeerInfoManager {
	return &InMemoryPeerInfoManager{
		logger:     logger,
		peerInfoCh: make(chan *protobufs.PeerInfo, 1000),
		peerMap:    make(map[string]*p2p.PeerInfo),
	}
}

func (m *InMemoryPeerInfoManager) Start(
	ctx lifecycle.SignalerContext,
	ready lifecycle.ReadyFunc,
) {
	m.ctx = ctx
	ready()
	for {
		select {
		case info := <-m.peerInfoCh:
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
			m.peerInfoMx.Lock()
			m.peerMap[string(info.PeerId)] = &p2p.PeerInfo{
				PeerId:              info.PeerId,
				Capabilities:        capabilities,
				Reachability:        reachability,
				Cores:               uint32(len(reachability)),
				LastSeen:            seen,
				Version:             info.Version,
				PatchNumber:         info.PatchNumber,
				LastReceivedFrame:   info.LastReceivedFrame,
				LastGlobalHeadFrame: info.LastGlobalHeadFrame,
			}
			m.peerInfoMx.Unlock()
		case <-ctx.Done():
			return
		}
	}
}

func (m *InMemoryPeerInfoManager) AddPeerInfo(info *protobufs.PeerInfo) {
	select {
	case <-m.ctx.Done():
	case m.peerInfoCh <- info:
	}
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
	for _, info := range m.peerMap {
		result = append(result, info.PeerId)
	}
	m.peerInfoMx.RUnlock()
	return result
}
