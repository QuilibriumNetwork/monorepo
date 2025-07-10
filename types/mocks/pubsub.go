package mocks

import (
	"context"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
)

// MockPubSub mocks the PubSub interface for testing
type MockPubSub struct {
	mock.Mock
}

// GetOwnMultiaddrs implements p2p.PubSub.
func (m *MockPubSub) GetOwnMultiaddrs() []multiaddr.Multiaddr {
	args := m.Called()
	return args.Get(0).([]multiaddr.Multiaddr)
}

func (m *MockPubSub) PublishToBitmask(bitmask []byte, data []byte) error {
	args := m.Called(bitmask, data)
	return args.Error(0)
}

func (m *MockPubSub) Publish(address []byte, data []byte) error {
	args := m.Called(address, data)
	return args.Error(0)
}

func (m *MockPubSub) Subscribe(
	bitmask []byte,
	handler func(message *pb.Message) error,
) error {
	args := m.Called(bitmask, handler)
	return args.Error(0)
}

func (m *MockPubSub) Unsubscribe(bitmask []byte, raw bool) {
	m.Called(bitmask, raw)
}

func (m *MockPubSub) RegisterValidator(
	bitmask []byte,
	validator func(peerID peer.ID, message *pb.Message) p2p.ValidationResult,
	sync bool,
) error {
	args := m.Called(bitmask, validator, sync)
	return args.Error(0)
}

func (m *MockPubSub) UnregisterValidator(bitmask []byte) error {
	args := m.Called(bitmask)
	return args.Error(0)
}

func (m *MockPubSub) GetPeerID() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

func (m *MockPubSub) GetPeerstoreCount() int {
	args := m.Called()
	return args.Int(0)
}

func (m *MockPubSub) GetNetworkPeersCount() int {
	args := m.Called()
	return args.Int(0)
}

func (m *MockPubSub) GetRandomPeer(bitmask []byte) ([]byte, error) {
	args := m.Called(bitmask)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockPubSub) GetMultiaddrOfPeerStream(
	ctx context.Context,
	peerId []byte,
) <-chan multiaddr.Multiaddr {
	args := m.Called(ctx, peerId)
	return args.Get(0).(<-chan multiaddr.Multiaddr)
}

func (m *MockPubSub) GetMultiaddrOfPeer(peerId []byte) string {
	args := m.Called(peerId)
	return args.String(0)
}

func (m *MockPubSub) StartDirectChannelListener(
	key []byte,
	purpose string,
	server *grpc.Server,
) error {
	args := m.Called(key, purpose, server)
	return args.Error(0)
}

func (m *MockPubSub) GetDirectChannel(
	ctx context.Context,
	peerId []byte,
	purpose string,
) (*grpc.ClientConn, error) {
	args := m.Called(ctx, peerId, purpose)
	return args.Get(0).(*grpc.ClientConn), args.Error(1)
}

func (m *MockPubSub) GetNetworkInfo() *protobufs.NetworkInfoResponse {
	args := m.Called()
	return args.Get(0).(*protobufs.NetworkInfoResponse)
}

func (m *MockPubSub) SignMessage(msg []byte) ([]byte, error) {
	args := m.Called(msg)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockPubSub) GetPublicKey() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

func (m *MockPubSub) GetPeerScore(peerId []byte) int64 {
	args := m.Called(peerId)
	return args.Get(0).(int64)
}

func (m *MockPubSub) SetPeerScore(peerId []byte, score int64) {
	m.Called(peerId, score)
}

func (m *MockPubSub) AddPeerScore(peerId []byte, scoreDelta int64) {
	m.Called(peerId, scoreDelta)
}

func (m *MockPubSub) Reconnect(peerId []byte) error {
	args := m.Called(peerId)
	return args.Error(0)
}

func (m *MockPubSub) Bootstrap(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockPubSub) DiscoverPeers(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockPubSub) GetNetwork() uint {
	args := m.Called()
	return args.Get(0).(uint)
}

func (m *MockPubSub) IsPeerConnected(peerId []byte) bool {
	args := m.Called(peerId)
	return args.Bool(0)
}

func (m *MockPubSub) Reachability() *wrapperspb.BoolValue {
	args := m.Called()
	return args.Get(0).(*wrapperspb.BoolValue)
}

var _ p2p.PubSub = (*MockPubSub)(nil)
