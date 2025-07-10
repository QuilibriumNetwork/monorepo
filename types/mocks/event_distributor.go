package mocks

import (
	"context"

	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
)

type MockEventDistributor struct {
	mock.Mock
}

func (m *MockEventDistributor) Start(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockEventDistributor) Stop() error {
	args := m.Called()
	return args.Error(0)
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
