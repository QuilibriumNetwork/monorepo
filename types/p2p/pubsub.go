package p2p

import (
	"context"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

type ValidationResult int

const (
	ValidationResultAccept ValidationResult = iota
	ValidationResultReject
	ValidationResultIgnore
)

type PubSub interface {
	PublishToBitmask(bitmask []byte, data []byte) error
	Publish(address []byte, data []byte) error
	Subscribe(bitmask []byte, handler func(message *pb.Message) error) error
	Unsubscribe(bitmask []byte, raw bool)
	RegisterValidator(
		bitmask []byte,
		validator func(peerID peer.ID, message *pb.Message) ValidationResult,
		sync bool,
	) error
	UnregisterValidator(bitmask []byte) error
	GetPeerID() []byte
	GetPeerstoreCount() int
	GetNetworkPeersCount() int
	GetRandomPeer(bitmask []byte) ([]byte, error)
	GetMultiaddrOfPeerStream(
		ctx context.Context,
		peerId []byte,
	) <-chan multiaddr.Multiaddr
	GetMultiaddrOfPeer(peerId []byte) string
	GetOwnMultiaddrs() []multiaddr.Multiaddr
	StartDirectChannelListener(
		key []byte,
		purpose string,
		server *grpc.Server,
	) error
	GetDirectChannel(
		ctx context.Context,
		peerId []byte,
		purpose string,
	) (*grpc.ClientConn, error)
	GetNetworkInfo() *protobufs.NetworkInfoResponse
	SignMessage(msg []byte) ([]byte, error)
	GetPublicKey() []byte
	GetPeerScore(peerId []byte) int64
	SetPeerScore(peerId []byte, score int64)
	AddPeerScore(peerId []byte, scoreDelta int64)
	Reconnect(peerId []byte) error
	Bootstrap(ctx context.Context) error
	DiscoverPeers(ctx context.Context) error
	GetNetwork() uint
	IsPeerConnected(peerId []byte) bool
	Reachability() *wrapperspb.BoolValue
}
