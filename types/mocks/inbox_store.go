package mocks

import (
	"github.com/stretchr/testify/mock"

	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

// MockInboxStore is a mock implementation of store.InboxStore
type MockInboxStore struct {
	mock.Mock
}

var _ store.InboxStore = (*MockInboxStore)(nil)

// GetAllHubAssociations implements store.InboxStore.
func (m *MockInboxStore) GetAllHubAssociations(filters [][3]byte) (
	[]*protobufs.HubResponse,
	error,
) {
	args := m.Called(filters)
	return args.Get(0).([]*protobufs.HubResponse), args.Error(1)
}

func (m *MockInboxStore) AddMessage(msg *protobufs.InboxMessage) error {
	args := m.Called(msg)
	return args.Error(0)
}

func (m *MockInboxStore) GetMessagesByFilter(filter [3]byte) (
	[]*protobufs.InboxMessage,
	error,
) {
	args := m.Called(filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*protobufs.InboxMessage), args.Error(1)
}

func (m *MockInboxStore) GetMessagesByAddress(
	filter [3]byte,
	address []byte,
) ([]*protobufs.InboxMessage, error) {
	args := m.Called(filter, address)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*protobufs.InboxMessage), args.Error(1)
}

func (m *MockInboxStore) GetMessagesByTimeRange(
	filter [3]byte,
	address []byte,
	fromTimestamp uint64,
	toTimestamp uint64,
) ([]*protobufs.InboxMessage, error) {
	args := m.Called(filter, address, fromTimestamp, toTimestamp)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*protobufs.InboxMessage), args.Error(1)
}

func (m *MockInboxStore) ReapMessages(
	filter [3]byte,
	cutoffTimestamp uint64,
) error {
	args := m.Called(filter, cutoffTimestamp)
	return args.Error(0)
}

func (m *MockInboxStore) AddHubInboxAssociation(
	add *protobufs.HubAddInboxMessage,
) error {
	args := m.Called(add)
	return args.Error(0)
}

func (m *MockInboxStore) DeleteHubInboxAssociation(
	del *protobufs.HubDeleteInboxMessage,
) error {
	args := m.Called(del)
	return args.Error(0)
}

func (m *MockInboxStore) GetHubAssociations(filter [3]byte, hubAddress []byte) (
	*protobufs.HubResponse,
	error,
) {
	args := m.Called(filter, hubAddress)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*protobufs.HubResponse), args.Error(1)
}

func (m *MockInboxStore) GetHubAddHistory(filter [3]byte, hubAddress []byte) (
	[]*protobufs.HubAddInboxMessage,
	error,
) {
	args := m.Called(filter, hubAddress)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*protobufs.HubAddInboxMessage), args.Error(1)
}

func (m *MockInboxStore) GetHubDeleteHistory(
	filter [3]byte,
	hubAddress []byte,
) ([]*protobufs.HubDeleteInboxMessage, error) {
	args := m.Called(filter, hubAddress)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*protobufs.HubDeleteInboxMessage), args.Error(1)
}

func (m *MockInboxStore) GetAllMessagesCRDT(filters [][3]byte) (
	[]*protobufs.InboxMessage,
	error,
) {
	args := m.Called(filters)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*protobufs.InboxMessage), args.Error(1)
}

func (m *MockInboxStore) GetAllHubsCRDT(filters [][3]byte) (
	[]*protobufs.HubResponse,
	error,
) {
	args := m.Called(filters)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*protobufs.HubResponse), args.Error(1)
}
