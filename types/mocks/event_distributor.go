package mocks

import (
	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
)

type MockEventDistributor struct {
	mock.Mock
}

func (m *MockEventDistributor) Start(
	ctx lifecycle.SignalerContext,
	ready lifecycle.ReadyFunc,
) {
	m.Called(ctx, ready)
}

func (m *MockEventDistributor) Subscribe(
	id string,
) <-chan consensus.ControlEvent {
	args := m.Called(id)
	return args.Get(0).(<-chan consensus.ControlEvent)
}

func (m *MockEventDistributor) Publish(event consensus.ControlEvent) {
	m.Called(event)
}

func (m *MockEventDistributor) Unsubscribe(id string) {
	m.Called(id)
}

var _ consensus.EventDistributor = (*MockEventDistributor)(nil)
