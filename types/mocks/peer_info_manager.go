package mocks

import (
	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
)

var _ p2p.PeerInfoManager = (*MockPeerInfoManager)(nil)

type MockPeerInfoManager struct {
	mock.Mock
}

// AddPeerInfo implements p2p.PeerInfoManager.
func (m *MockPeerInfoManager) AddPeerInfo(info *protobufs.PeerInfo) {
	m.Called(info)
}

// GetPeerInfo implements p2p.PeerInfoManager.
func (m *MockPeerInfoManager) GetPeerInfo(peerId []byte) *p2p.PeerInfo {
	args := m.Called(peerId)
	return args.Get(0).(*p2p.PeerInfo)
}

// GetPeerMap implements p2p.PeerInfoManager.
func (m *MockPeerInfoManager) GetPeerMap() map[string]*p2p.PeerInfo {
	args := m.Called()
	return args.Get(0).(map[string]*p2p.PeerInfo)
}

// GetPeersBySpeed implements p2p.PeerInfoManager.
func (m *MockPeerInfoManager) GetPeersBySpeed() [][]byte {
	args := m.Called()
	return args.Get(0).([][]byte)
}

// Start implements p2p.PeerInfoManager.
func (m *MockPeerInfoManager) Start() {
	m.Called()
}

// Stop implements p2p.PeerInfoManager.
func (m *MockPeerInfoManager) Stop() {
	m.Called()
}
