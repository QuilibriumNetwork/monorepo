package p2p

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"slices"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	multiaddr "github.com/multiformats/go-multiaddr"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/rpc"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
)

// ProxyBlossomSub implements p2p.PubSub interface by proxying calls to a master
// node
type ProxyBlossomSub struct {
	client *rpc.PubSubProxyClient
	conn   *grpc.ClientConn
	logger *zap.Logger
	coreId uint
}

// Ensure ProxyBlossomSub implements p2p.PubSub
var _ p2p.PubSub = (*ProxyBlossomSub)(nil)

// CreateTLSCredentials creates TLS credentials using the peer private key
func CreateTLSCredentials(p2pConfig *config.P2PConfig, peerPubKey []byte) (
	credentials.TransportCredentials,
	error,
) {
	if p2pConfig.PeerPrivKey == "" {
		return nil, errors.Wrap(
			errors.New("peer private key is required for TLS"),
			"create tls credentials",
		)
	}

	// Decode the peer private key
	peerPrivKeyBytes, err := hex.DecodeString(p2pConfig.PeerPrivKey)
	if err != nil {
		return nil, errors.Wrap(err, "create tls credentials")
	}

	// Unmarshal the Ed448 private key
	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKeyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "create tls credentials")
	}

	// Extract the raw Ed448 key material
	privKeyRaw, err := privKey.Raw()
	if err != nil {
		return nil, errors.Wrap(err, "create tls credentials")
	}

	// Create Ed448 key pair from the raw key material
	if len(privKeyRaw) != ed448.PrivateKeySize {
		return nil, errors.Wrap(
			errors.New("invalid ed448 private key size"),
			"create tls credentials",
		)
	}

	// Since Go's x509 doesn't support Ed448, we'll derive an Ed25519 key for TLS
	// from the Ed448 key material to maintain deterministic behavior

	// Create deterministic Ed25519 key from Ed448 seed
	hasher := sha256.New()
	hasher.Write(privKeyRaw[:ed448.SeedSize])
	hasher.Write([]byte("tls-cert-derivation")) // Add context to avoid key reuse
	ed25519Seed := hasher.Sum(nil)[:ed25519.SeedSize]

	// Generate Ed25519 key pair for TLS certificate
	ed25519PrivKey := ed25519.NewKeyFromSeed(ed25519Seed)
	ed25519PubKey := ed25519PrivKey.Public().(ed25519.PublicKey)

	// Create a self-signed certificate using the Ed25519 key (for TLS
	// compatibility)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"QTLS"},
			Country:       []string{""},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}

	rawPub, err := privKey.GetPublic().Raw()
	if err != nil {
		return nil, errors.Wrap(err, "create tls credentials")
	}

	// Construct cross-signature of derived ed25519 key from ed448 key
	xsign, err := privKey.Sign(
		slices.Concat([]byte("tls-cert-derivation"), ed25519PubKey),
	)
	if err != nil {
		return nil, errors.Wrap(err, "create tls credentials")
	}

	// Add localhost and common names
	template.IPAddresses = []net.IP{}
	template.DNSNames = []string{hex.EncodeToString(
		slices.Concat(rawPub, xsign),
	)}

	// Create certificate with Ed25519 key
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		ed25519PubKey,
		ed25519PrivKey,
	)
	if err != nil {
		return nil, errors.Wrap(err, "create tls credentials")
	}

	// Create TLS certificate
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  ed25519PrivKey,
	}

	// Create TLS config with proper certificate verification
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   "localhost",
		ClientAuth:   tls.RequireAnyClientCert,
		// Custom verification to ensure peers use the same base key
		VerifyPeerCertificate: func(
			rawCerts [][]byte,
			verifiedChains [][]*x509.Certificate,
		) error {
			if len(rawCerts) == 0 {
				return errors.New("no peer certificate provided")
			}

			// Parse the peer certificate
			peerCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return errors.Wrap(err, "failed to parse peer certificate")
			}

			// For mutual authentication, verify the peer certificate was generated
			// from the same Ed448 seed by checking if the xsign matches
			peerEd25519PubKey, ok := peerCert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("peer certificate does not use Ed25519 key")
			}

			if len(peerCert.DNSNames) != 1 {
				return errors.New("peer certificate dns mismatch")
			}

			xsign, err := hex.DecodeString(peerCert.DNSNames[0])
			if err != nil {
				return errors.Wrap(err, "failed to parse xsign")
			}

			valid := ed448.Verify(
				ed448.PublicKey(peerPubKey),
				slices.Concat([]byte("tls-cert-derivation"), peerEd25519PubKey),
				xsign[57:],
				"",
			)
			if !valid {
				return errors.New("peer certificate invalid xsign")
			}

			// Compare public keys - they should match for same peer public key
			if !bytes.Equal(xsign[:57], peerPubKey) {
				return errors.New("peer certificate public key mismatch")
			}

			return nil
		},
		InsecureSkipVerify: true, // We handle verification in VerifyPeerCertificate
	}

	return credentials.NewTLS(tlsConfig), nil
}

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

	// Create TLS credentials using the peer private key
	privKey, err := hex.DecodeString(p2pConfig.PeerPrivKey)
	if err != nil {
		return nil, errors.Wrap(err, "new proxy blossom sub")
	}

	tlsCreds, err := CreateTLSCredentials(p2pConfig, privKey[57:])
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
	client := rpc.NewPubSubProxyClient(conn, logger)

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
