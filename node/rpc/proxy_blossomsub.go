package rpc

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	multiaddr "github.com/multiformats/go-multiaddr"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	qp2p "source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
)

// ProxyBlossomSub implements p2p.PubSub interface by proxying calls to a master
// node
type ProxyBlossomSub struct {
	client *PubSubProxyClient
	conn   *grpc.ClientConn
	logger *zap.Logger
	coreId uint
}

// Ensure ProxyBlossomSub implements p2p.PubSub
var _ p2p.PubSub = (*ProxyBlossomSub)(nil)

// NewProxyBlossomSub creates a new proxy pubsub client that connects to the
// master node
func NewProxyBlossomSub(
	p2pConfig *config.P2PConfig,
	engineConfig *config.EngineConfig,
	logger *zap.Logger,
	coreId uint,
) (*ProxyBlossomSub, error) {
	if coreId == 0 {
		return nil, errors.Wrap(
			errors.New("proxy blossomsub should not be used for master node"),
			"new proxy blossom sub",
		)
	}

	// Check if proxy mode is enabled
	if engineConfig == nil || !engineConfig.EnableMasterProxy {
		return nil, errors.Wrap(
			errors.New("proxy mode is not enabled in engine config"),
			"new proxy blossom sub",
		)
	}

	logger = logger.With(
		zap.String("component", "proxy_blossomsub"),
		zap.Uint("core_id", coreId),
	)

	// Parse the StreamListenMultiaddr to get the master RPC address
	streamMultiaddr := p2pConfig.StreamListenMultiaddr
	var masterAddr string

	if streamMultiaddr == "" {
		masterAddr = "localhost:8340" // Default fallback
	} else {
		// Parse the multiaddr
		ma, err := multiaddr.NewMultiaddr(streamMultiaddr)
		if err != nil {
			return nil, errors.Wrap(err, "new proxy blossom sub")
		}

		// Extract host and port
		host, err := ma.ValueForProtocol(multiaddr.P_IP4)
		if err != nil {
			// Try IPv6
			host, err = ma.ValueForProtocol(multiaddr.P_IP6)
			if err != nil {
				host = "localhost" // fallback
			}
		}

		port, err := ma.ValueForProtocol(multiaddr.P_TCP)
		if err != nil {
			port = "8340" // fallback
		}

		// Use localhost if binding to 0.0.0.0
		if host == "0.0.0.0" {
			host = "localhost"
		}

		masterAddr = fmt.Sprintf("%s:%s", host, port)
	}

	logger.Info("connecting to master node RPC",
		zap.String("address", masterAddr),
		zap.String("stream_listen_multiaddr", streamMultiaddr))

	pubkeyBytes, err := hex.DecodeString(p2pConfig.PeerPrivKey)
	if err != nil {
		return nil, errors.Wrap(err, "new proxy blossom sub")
	}

	pubkey, err := crypto.UnmarshalEd448PublicKey(pubkeyBytes[57:])
	if err != nil {
		return nil, errors.Wrap(err, "new proxy blossom sub")
	}

	peerid, err := peer.IDFromPublicKey(pubkey)
	if err != nil {
		return nil, errors.Wrap(err, "new proxy blossom sub")
	}

	// Using kind of a hack to do this here, but we don't have the other two
	// dependencies at this point in the init loop
	tlsCreds, err := qp2p.NewPeerAuthenticator(
		logger,
		p2pConfig,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
	).CreateClientTLSCredentials([]byte(peerid))
	if err != nil {
		return nil, errors.Wrap(err, "new proxy blossom sub")
	}

	logger.Info("using TLS connection to master node")

	// Create gRPC connection with TLS
	conn, err := grpc.Dial(
		masterAddr,
		grpc.WithTransportCredentials(tlsCreds),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(100*1024*1024)),
	)
	if err != nil {
		return nil, errors.Wrap(err, "new proxy blossom sub")
	}

	// Create the proxy client
	client := NewPubSubProxyClient(conn, logger)

	return &ProxyBlossomSub{
		client: client,
		conn:   conn,
		logger: logger,
		coreId: coreId,
	}, nil
}

// Close closes the proxy connection
func (p *ProxyBlossomSub) Close() error {
	if p.conn != nil {
		return p.conn.Close()
	}
	return nil
}

// PublishToBitmask publishes data to a specific bitmask
func (p *ProxyBlossomSub) PublishToBitmask(bitmask []byte, data []byte) error {
	return p.client.PublishToBitmask(bitmask, data)
}

// Publish publishes data to an address (converted to bitmask)
func (p *ProxyBlossomSub) Publish(address []byte, data []byte) error {
	return p.client.Publish(address, data)
}

// Subscribe subscribes to messages on a bitmask
func (p *ProxyBlossomSub) Subscribe(
	bitmask []byte,
	handler func(message *pb.Message) error,
) error {
	return p.client.Subscribe(bitmask, handler)
}

// Unsubscribe unsubscribes from a bitmask
func (p *ProxyBlossomSub) Unsubscribe(bitmask []byte, raw bool) {
	p.client.Unsubscribe(bitmask, raw)
}

// RegisterValidator registers a message validator for a bitmask
func (p *ProxyBlossomSub) RegisterValidator(
	bitmask []byte,
	validator func(peerID peer.ID, message *pb.Message) p2p.ValidationResult,
	sync bool,
) error {
	return p.client.RegisterValidator(bitmask, validator, sync)
}

// UnregisterValidator unregisters a validator for a bitmask
func (p *ProxyBlossomSub) UnregisterValidator(bitmask []byte) error {
	return p.client.UnregisterValidator(bitmask)
}

// GetPeerID returns this node's peer ID
func (p *ProxyBlossomSub) GetPeerID() []byte {
	return p.client.GetPeerID()
}

// GetPeerstoreCount returns the number of peers in the peerstore
func (p *ProxyBlossomSub) GetPeerstoreCount() int {
	return p.client.GetPeerstoreCount()
}

// GetNetworkPeersCount returns the number of network peers
func (p *ProxyBlossomSub) GetNetworkPeersCount() int {
	return p.client.GetNetworkPeersCount()
}

// GetRandomPeer returns a random peer subscribed to the bitmask
func (p *ProxyBlossomSub) GetRandomPeer(bitmask []byte) ([]byte, error) {
	return p.client.GetRandomPeer(bitmask)
}

// GetMultiaddrOfPeerStream returns a stream of multiaddrs for a peer
func (p *ProxyBlossomSub) GetMultiaddrOfPeerStream(
	ctx context.Context,
	peerId []byte,
) <-chan multiaddr.Multiaddr {
	return p.client.GetMultiaddrOfPeerStream(ctx, peerId)
}

// GetMultiaddrOfPeer returns the multiaddr of a peer
func (p *ProxyBlossomSub) GetMultiaddrOfPeer(peerId []byte) string {
	return p.client.GetMultiaddrOfPeer(peerId)
}

// GetOwnMultiaddrs returns our own multiaddresses
func (p *ProxyBlossomSub) GetOwnMultiaddrs() []multiaddr.Multiaddr {
	return p.client.GetOwnMultiaddrs()
}

// StartDirectChannelListener starts a direct channel listener
func (p *ProxyBlossomSub) StartDirectChannelListener(
	key []byte,
	purpose string,
	server *grpc.Server,
) error {
	return p.client.StartDirectChannelListener(key, purpose, server)
}

// GetDirectChannel gets a direct channel to a peer
func (p *ProxyBlossomSub) GetDirectChannel(
	ctx context.Context,
	peerId []byte,
	purpose string,
) (*grpc.ClientConn, error) {
	return p.client.GetDirectChannel(ctx, peerId, purpose)
}

// GetNetworkInfo returns network information
func (p *ProxyBlossomSub) GetNetworkInfo() *protobufs.NetworkInfoResponse {
	return p.client.GetNetworkInfo()
}

// SignMessage signs a message with this node's private key
func (p *ProxyBlossomSub) SignMessage(msg []byte) ([]byte, error) {
	return p.client.SignMessage(msg)
}

// GetPublicKey returns this node's public key
func (p *ProxyBlossomSub) GetPublicKey() []byte {
	return p.client.GetPublicKey()
}

// GetPeerScore returns the score of a peer
func (p *ProxyBlossomSub) GetPeerScore(peerId []byte) int64 {
	return p.client.GetPeerScore(peerId)
}

// SetPeerScore sets the score of a peer
func (p *ProxyBlossomSub) SetPeerScore(peerId []byte, score int64) {
	p.client.SetPeerScore(peerId, score)
}

// AddPeerScore adds to the score of a peer
func (p *ProxyBlossomSub) AddPeerScore(peerId []byte, scoreDelta int64) {
	p.client.AddPeerScore(peerId, scoreDelta)
}

// Reconnect reconnects to a peer
func (p *ProxyBlossomSub) Reconnect(peerId []byte) error {
	return p.client.Reconnect(peerId)
}

// Bootstrap runs the bootstrap process
func (p *ProxyBlossomSub) Bootstrap(ctx context.Context) error {
	return p.client.Bootstrap(ctx)
}

// DiscoverPeers discovers new peers
func (p *ProxyBlossomSub) DiscoverPeers(ctx context.Context) error {
	return p.client.DiscoverPeers(ctx)
}

// GetNetwork returns the network ID
func (p *ProxyBlossomSub) GetNetwork() uint {
	return p.client.GetNetwork()
}

// IsPeerConnected checks if a peer is connected
func (p *ProxyBlossomSub) IsPeerConnected(peerId []byte) bool {
	return p.client.IsPeerConnected(peerId)
}

// Reachability returns the reachability status
func (p *ProxyBlossomSub) Reachability() *wrapperspb.BoolValue {
	return p.client.Reachability()
}
