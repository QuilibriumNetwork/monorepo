package mocks

import (
	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
)

var _ consensus.Mixnet = (*MockMixnet)(nil)

// MockMixnet is a mock implementation of consensus.Mixnet
type MockMixnet struct {
	mock.Mock
}

// PrepareMixnet implements consensus.Mixnet.
func (m *MockMixnet) PrepareMixnet() error {
	args := m.Called()
	return args.Error(0)
}

// GetState implements consensus.Mixnet.
func (m *MockMixnet) GetState() consensus.MixnetState {
	args := m.Called()
	return args.Get(0).(consensus.MixnetState)
}

// GetMessages implements consensus.Mixnet.
func (m *MockMixnet) GetMessages() []*protobufs.Message {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).([]*protobufs.Message)
}
