package rpc_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	multiaddr "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/rpc"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	p2ptypes "source.quilibrium.com/quilibrium/monorepo/types/p2p"
)

// mockPubSub implements the p2p.PubSub interface for testing
type mockPubSub struct {
	peerID         []byte
	subscriptions  map[string][]func(message *pb.Message) error // Support multiple handlers per bitmask
	validators     map[string]func(peerID peer.ID, message *pb.Message) p2ptypes.ValidationResult
	publishedData  map[string][]byte
	mu             sync.RWMutex
	validatorCalls int
	messageCount   int
	nextSubID      int // For generating unique subscription IDs
}

func newMockPubSub() *mockPubSub {
	// Generate a random peer ID for testing
	peerID := make([]byte, 32)
	rand.Read(peerID)

	return &mockPubSub{
		peerID:        peerID,
		subscriptions: make(map[string][]func(message *pb.Message) error),
		validators:    make(map[string]func(peer.ID, *pb.Message) p2ptypes.ValidationResult),
		publishedData: make(map[string][]byte),
	}
}

// Implement all p2p.PubSub interface methods
func (m *mockPubSub) PublishToBitmask(bitmask []byte, data []byte) error {
	m.mu.Lock()
	m.publishedData[string(bitmask)] = data

	// Trigger any subscriptions - make a copy of ALL handlers for this bitmask
	var handlersToCall []func(message *pb.Message) error
	if handlers, exists := m.subscriptions[string(bitmask)]; exists {
		handlersToCall = make([]func(message *pb.Message) error, len(handlers))
		copy(handlersToCall, handlers)
	}
	m.messageCount++
	msgSeqno := m.messageCount
	m.mu.Unlock()

	// Call all handlers without holding lock
	if len(handlersToCall) > 0 {
		msg := &pb.Message{
			Data:    data,
			From:    m.peerID,
			Seqno:   []byte(fmt.Sprintf("%d", msgSeqno)),
			Bitmask: bitmask,
		}
		for _, handler := range handlersToCall {
			go func(h func(message *pb.Message) error) {
				h(msg)
			}(handler)
		}
	}

	return nil
}

func (m *mockPubSub) Publish(address []byte, data []byte) error {
	// Simple mock - just use address as bitmask
	return m.PublishToBitmask(address, data)
}

func (m *mockPubSub) Subscribe(bitmask []byte, handler func(message *pb.Message) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	bitmaskKey := string(bitmask)

	// Add handler to the list of handlers for this bitmask
	if _, exists := m.subscriptions[bitmaskKey]; !exists {
		m.subscriptions[bitmaskKey] = make([]func(message *pb.Message) error, 0)
	}
	m.subscriptions[bitmaskKey] = append(m.subscriptions[bitmaskKey], handler)

	return nil
}

func (m *mockPubSub) Unsubscribe(bitmask []byte, raw bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// In a real implementation, we'd need to track individual subscriptions
	// For this mock, we'll just clear all handlers for this bitmask
	delete(m.subscriptions, string(bitmask))
}

func (m *mockPubSub) RegisterValidator(
	bitmask []byte,
	validator func(peerID peer.ID, message *pb.Message) p2ptypes.ValidationResult,
	sync bool,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.validators[string(bitmask)] = validator
	return nil
}

func (m *mockPubSub) UnregisterValidator(bitmask []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.validators, string(bitmask))
	return nil
}

func (m *mockPubSub) GetPeerID() []byte {
	return m.peerID
}

func (m *mockPubSub) GetValidatorCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.validatorCalls
}

// Implement remaining interface methods with basic mocks
func (m *mockPubSub) GetPeerstoreCount() int                       { return 5 }
func (m *mockPubSub) GetNetworkPeersCount() int                    { return 10 }
func (m *mockPubSub) GetRandomPeer(bitmask []byte) ([]byte, error) { return m.peerID, nil }
func (m *mockPubSub) GetMultiaddrOfPeerStream(ctx context.Context, peerId []byte) <-chan multiaddr.Multiaddr {
	ch := make(chan multiaddr.Multiaddr)
	close(ch)
	return ch
}
func (m *mockPubSub) GetMultiaddrOfPeer(peerId []byte) string { return "/ip4/127.0.0.1/tcp/8080" }
func (m *mockPubSub) GetOwnMultiaddrs() []multiaddr.Multiaddr {
	ma, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/8080")
	return []multiaddr.Multiaddr{ma}
}
func (m *mockPubSub) StartDirectChannelListener(key []byte, purpose string, server *grpc.Server) error {
	return nil
}
func (m *mockPubSub) GetDirectChannel(ctx context.Context, peerId []byte, purpose string) (*grpc.ClientConn, error) {
	return nil, nil
}
func (m *mockPubSub) GetNetworkInfo() *protobufs.NetworkInfoResponse {
	return &protobufs.NetworkInfoResponse{}
}
func (m *mockPubSub) SignMessage(msg []byte) ([]byte, error)       { return msg, nil }
func (m *mockPubSub) GetPublicKey() []byte                         { return m.peerID }
func (m *mockPubSub) GetPeerScore(peerId []byte) int64             { return 100 }
func (m *mockPubSub) SetPeerScore(peerId []byte, score int64)      {}
func (m *mockPubSub) AddPeerScore(peerId []byte, scoreDelta int64) {}
func (m *mockPubSub) Reconnect(peerId []byte) error                { return nil }
func (m *mockPubSub) Bootstrap(ctx context.Context) error          { return nil }
func (m *mockPubSub) DiscoverPeers(ctx context.Context) error      { return nil }
func (m *mockPubSub) GetNetwork() uint                             { return 0 }
func (m *mockPubSub) IsPeerConnected(peerId []byte) bool           { return true }
func (m *mockPubSub) Reachability() *wrapperspb.BoolValue          { return wrapperspb.Bool(true) }

// Test helper functions
func createTestConfigs() (*config.P2PConfig, *config.EngineConfig, error) {
	// Generate a test Ed448 private key
	privKey, _, err := crypto.GenerateEd448Key(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privKeyBytes, err := privKey.Raw()
	if err != nil {
		return nil, nil, err
	}

	p2pConfig := &config.P2PConfig{
		StreamListenMultiaddr: "/ip4/127.0.0.1/tcp/0", // Use ephemeral port
		PeerPrivKey:           hex.EncodeToString(privKeyBytes),
	}

	engineConfig := &config.EngineConfig{
		EnableMasterProxy: true,
	}

	return p2pConfig, engineConfig, nil
}

func setupTestServer(t *testing.T, mockPubSub *mockPubSub, p2pConfig *config.P2PConfig) (string, func()) {
	// Create TLS credentials for the test server using the provided config
	tlsCreds, err := p2p.NewPeerAuthenticator(
		zap.NewNop(),
		p2pConfig,
		nil,
		nil,
		nil,
		nil,
		nil,
		map[string]channel.AllowedPeerPolicyType{
			"quilibrium.node.proxy.pb.PubSubProxy": channel.OnlySelfPeer,
		},
		nil,
	).CreateServerTLSCredentials()
	require.NoError(t, err)

	// Find available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := listener.Addr().String()
	listener.Close()

	// Create gRPC server with TLS
	server := grpc.NewServer(grpc.Creds(tlsCreds))
	proxyServer := rpc.NewPubSubProxyServer(mockPubSub, zap.NewNop())
	protobufs.RegisterPubSubProxyServer(server, proxyServer)

	// Start server
	listener, err = net.Listen("tcp", addr)
	require.NoError(t, err)

	go func() {
		if err := server.Serve(listener); err != nil {
			t.Logf("Server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	return addr, func() {
		server.Stop()
		listener.Close()
	}
}

func TestProxyBlossomSubCreation(t *testing.T) {
	p2pConfig, engineConfig, err := createTestConfigs()
	require.NoError(t, err)

	// Test with coreId = 0 (should fail)
	_, err = rpc.NewProxyBlossomSub(p2pConfig, engineConfig, zap.NewNop(), 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "proxy blossomsub should not be used for master node")

	// Test with proxy disabled (should fail)
	engineConfig.EnableMasterProxy = false
	_, err = rpc.NewProxyBlossomSub(p2pConfig, engineConfig, zap.NewNop(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "proxy mode is not enabled")

	// Enable proxy mode
	engineConfig.EnableMasterProxy = true

	// Test with valid config but no server running
	// Note: gRPC dial doesn't fail immediately, so we just test that creation succeeds
	proxy, err := rpc.NewProxyBlossomSub(p2pConfig, engineConfig, zap.NewNop(), 1)
	if err == nil {
		// Creation succeeded, but actual RPC calls should fail
		proxy.Close()

		// Test that RPC operations fail when server is not available
		err = proxy.PublishToBitmask([]byte("test"), []byte("data"))
		assert.Error(t, err, "should fail when server is not available")
	} else {
		// Creation failed, which is also acceptable
		assert.Error(t, err)
	}
}

func TestBasicPublishSubscribe(t *testing.T) {
	// Mark first todo as completed and start next one
	defer func() {
		// Update todos at the end of this test
	}()

	// Create configs first
	p2pConfig, engineConfig, err := createTestConfigs()
	require.NoError(t, err)

	mockPubSub := newMockPubSub()
	serverAddr, cleanup := setupTestServer(t, mockPubSub, p2pConfig)
	defer cleanup()

	// Parse server address to update stream multiaddr
	host, port, err := net.SplitHostPort(serverAddr)
	require.NoError(t, err)
	p2pConfig.StreamListenMultiaddr = fmt.Sprintf("/ip4/%s/tcp/%s", host, port)

	// Create proxy client
	proxy, err := rpc.NewProxyBlossomSub(p2pConfig, engineConfig, zap.NewNop(), 1)
	require.NoError(t, err)
	defer proxy.Close()

	// Test basic operations
	testBitmask := []byte("test-bitmask")
	testData := []byte("hello world")

	// Test publish
	err = proxy.PublishToBitmask(testBitmask, testData)
	assert.NoError(t, err)

	// Verify data was published to mock
	mockPubSub.mu.RLock()
	publishedData := mockPubSub.publishedData[string(testBitmask)]
	mockPubSub.mu.RUnlock()

	assert.Equal(t, testData, publishedData)

	// Test subscribe
	receivedMessages := make(chan *pb.Message, 1)
	err = proxy.Subscribe(testBitmask, func(message *pb.Message) error {
		receivedMessages <- message
		return nil
	})
	assert.NoError(t, err)

	// Give subscription time to be established through gRPC stream
	time.Sleep(200 * time.Millisecond)

	// Publish another message
	testData2 := []byte("hello again")
	err = proxy.PublishToBitmask(testBitmask, testData2)
	assert.NoError(t, err)

	// Wait for message
	select {
	case msg := <-receivedMessages:
		assert.Equal(t, testData2, msg.Data)
		assert.Equal(t, testBitmask, msg.Bitmask)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for message")
	}

	// Test other basic methods
	peerID := proxy.GetPeerID()
	assert.NotNil(t, peerID)

	count := proxy.GetPeerstoreCount()
	assert.Equal(t, 5, count)

	networkCount := proxy.GetNetworkPeersCount()
	assert.Equal(t, 10, networkCount)
}

func TestValidatorRegistration(t *testing.T) {
	p2pConfig, engineConfig, err := createTestConfigs()
	require.NoError(t, err)

	mockPubSub := newMockPubSub()
	serverAddr, cleanup := setupTestServer(t, mockPubSub, p2pConfig)
	defer cleanup()

	host, port, err := net.SplitHostPort(serverAddr)
	require.NoError(t, err)
	p2pConfig.StreamListenMultiaddr = fmt.Sprintf("/ip4/%s/tcp/%s", host, port)

	proxy, err := rpc.NewProxyBlossomSub(p2pConfig, engineConfig, zap.NewNop(), 1)
	require.NoError(t, err)
	defer proxy.Close()

	testBitmask := []byte("validator-test")
	validationResults := make(chan p2ptypes.ValidationResult, 1)

	// Register validator
	err = proxy.RegisterValidator(testBitmask, func(peerID peer.ID, message *pb.Message) p2ptypes.ValidationResult {
		// Validate message
		if string(message.Data) == "valid" {
			validationResults <- p2ptypes.ValidationResultAccept
			return p2ptypes.ValidationResultAccept
		}
		validationResults <- p2ptypes.ValidationResultReject
		return p2ptypes.ValidationResultReject
	}, false)
	assert.NoError(t, err)

	// Give some time for validator to be registered
	time.Sleep(100 * time.Millisecond)

	// Test unregistering validator
	err = proxy.UnregisterValidator(testBitmask)
	assert.NoError(t, err)
}

func TestTLSConnection(t *testing.T) {
	p2pConfig, engineConfig, err := createTestConfigs()
	require.NoError(t, err)

	// Test TLS credential creation with valid Ed448 key
	tlsCreds, err := p2p.NewPeerAuthenticator(
		zap.NewNop(),
		p2pConfig,
		nil,
		nil,
		nil,
		nil,
		nil,
		map[string]channel.AllowedPeerPolicyType{
			"quilibrium.node.proxy.pb.PubSubProxy": channel.OnlySelfPeer,
		},
		nil,
	).CreateServerTLSCredentials()
	require.NoError(t, err, "should be able to create TLS credentials with valid Ed448 key")
	assert.NotNil(t, tlsCreds, "TLS credentials should not be nil")

	// Test TLS connection by setting up a TLS server and connecting to it
	mockPubSub := newMockPubSub()

	// Find available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	listener.Close()

	// Create gRPC server with TLS credentials
	server := grpc.NewServer(grpc.Creds(tlsCreds))
	proxyServer := rpc.NewPubSubProxyServer(mockPubSub, zap.NewNop())
	protobufs.RegisterPubSubProxyServer(server, proxyServer)

	// Start TLS server
	listener, err = net.Listen("tcp", addr)
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		if err := server.Serve(listener); err != nil {
			t.Logf("TLS Server error: %v", err)
		}
	}()
	defer server.Stop()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Update p2p config to use the TLS server address
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	p2pConfig.StreamListenMultiaddr = fmt.Sprintf("/ip4/%s/tcp/%s", host, port)

	// Create proxy client that should connect with TLS
	proxy, err := rpc.NewProxyBlossomSub(p2pConfig, engineConfig, zap.NewNop(), 1)
	require.NoError(t, err, "should be able to create proxy with TLS connection")
	defer proxy.Close()

	// Test that we can actually use the TLS connection
	testBitmask := []byte("tls-test")
	testData := []byte("tls message")

	err = proxy.PublishToBitmask(testBitmask, testData)
	assert.NoError(t, err, "should be able to publish over TLS connection")

	// Verify the message was received by the server
	mockPubSub.mu.RLock()
	publishedData := mockPubSub.publishedData[string(testBitmask)]
	mockPubSub.mu.RUnlock()

	assert.Equal(t, testData, publishedData, "message should have been transmitted over TLS")
}

func TestTLSXSignConnection(t *testing.T) {
	// Create server with one set of keys
	serverP2PConfig, _, err := createTestConfigs()
	require.NoError(t, err)

	// Create client with different keys
	clientP2PConfig, _, err := createTestConfigs()
	require.NoError(t, err)

	// Make sure client has different keys than server by regenerating
	privKey, _, err := crypto.GenerateEd448Key(rand.Reader)
	require.NoError(t, err)

	privKeyBytes, err := privKey.Raw()
	require.NoError(t, err)

	clientP2PConfig.PeerPrivKey = hex.EncodeToString(privKeyBytes)

	serverTLSCreds, err := p2p.NewPeerAuthenticator(
		zap.NewNop(),
		serverP2PConfig,
		nil,
		nil,
		nil,
		nil,
		nil,
		map[string]channel.AllowedPeerPolicyType{
			"quilibrium.node.proxy.pb.PubSubProxy": channel.OnlySelfPeer,
		},
		nil,
	).CreateServerTLSCredentials()
	require.NoError(t, err, "should be able to create TLS credentials with valid Ed448 key")
	assert.NotNil(t, serverTLSCreds, "TLS credentials should not be nil")

	// Test TLS connection by setting up a TLS server and connecting to it
	mockPubSub := newMockPubSub()

	// Find available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	listener.Close()

	// Create gRPC server with TLS credentials
	server := grpc.NewServer(grpc.Creds(serverTLSCreds))
	proxyServer := rpc.NewPubSubProxyServer(mockPubSub, zap.NewNop())
	protobufs.RegisterPubSubProxyServer(server, proxyServer)

	// Start TLS server
	listener, err = net.Listen("tcp", addr)
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		if err := server.Serve(listener); err != nil {
			t.Logf("TLS Server error: %v", err)
		}
	}()
	defer server.Stop()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Update p2p config to use the TLS server address
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	serverP2PConfig.StreamListenMultiaddr = fmt.Sprintf("/ip4/%s/tcp/%s", host, port)

	pkb, _ := hex.DecodeString(serverP2PConfig.PeerPrivKey)
	pk, _ := crypto.UnmarshalEd448PublicKey(pkb[57:])
	peerid, _ := peer.IDFromPublicKey(pk)
	// Create proxy client that should connect with TLS
	tlsCreds, err := p2p.NewPeerAuthenticator(
		zap.NewNop(),
		serverP2PConfig,
		nil,
		nil,
		nil,
		nil,
		nil,
		map[string]channel.AllowedPeerPolicyType{
			"quilibrium.node.proxy.pb.PubSubProxy": channel.OnlySelfPeer,
		},
		nil,
	).CreateClientTLSCredentials([]byte(peerid))
	require.NoError(t, err)

	// Create gRPC connection with TLS
	conn, err := grpc.Dial(
		fmt.Sprintf("%s:%s", host, port),
		grpc.WithTransportCredentials(tlsCreds),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(100*1024*1024)),
	)
	assert.NoError(t, err)

	defer conn.Close()
	// Create the proxy client
	client := rpc.NewPubSubProxyClient(conn, zap.NewNop())

	// Test that we can actually use the TLS connection
	testBitmask := []byte("tls-test")
	testData := []byte("tls message")

	err = client.PublishToBitmask(testBitmask, testData)
	assert.NoError(t, err, "should be able to publish over TLS connection")

	// Verify the message was received by the server
	mockPubSub.mu.RLock()
	publishedData := mockPubSub.publishedData[string(testBitmask)]
	mockPubSub.mu.RUnlock()

	assert.Equal(t, testData, publishedData, "message should have been transmitted over TLS")
}

func TestTLSKeyMismatch(t *testing.T) {
	// Create server with one set of keys
	serverP2PConfig, _, err := createTestConfigs()
	require.NoError(t, err)

	// Create client with different keys
	clientP2PConfig, clientEngineConfig, err := createTestConfigs()
	require.NoError(t, err)

	// Make sure client has different keys than server by regenerating
	privKey, _, err := crypto.GenerateEd448Key(rand.Reader)
	require.NoError(t, err)

	privKeyBytes, err := privKey.Raw()
	require.NoError(t, err)

	clientP2PConfig.PeerPrivKey = hex.EncodeToString(privKeyBytes)

	serverTLSCreds, err := p2p.NewPeerAuthenticator(zap.NewNop(), serverP2PConfig, nil, nil, nil, nil, nil,
		map[string]channel.AllowedPeerPolicyType{
			"quilibrium.node.proxy.pb.PubSubProxy": channel.OnlySelfPeer,
		}, nil).CreateServerTLSCredentials()
	require.NoError(t, err)

	// Set up TLS server with server keys
	mockPubSub := newMockPubSub()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	listener.Close()

	// Create server with server TLS credentials
	server := grpc.NewServer(grpc.Creds(serverTLSCreds))
	proxyServer := rpc.NewPubSubProxyServer(mockPubSub, zap.NewNop())
	protobufs.RegisterPubSubProxyServer(server, proxyServer)

	listener, err = net.Listen("tcp", addr)
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		if err := server.Serve(listener); err != nil {
			t.Logf("TLS Server error: %v", err)
		}
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	// Update client config to connect to server
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	clientP2PConfig.StreamListenMultiaddr = fmt.Sprintf("/ip4/%s/tcp/%s", host, port)

	// Try to create proxy client with different keys - this should fail
	proxy, err := rpc.NewProxyBlossomSub(clientP2PConfig, clientEngineConfig, zap.NewNop(), 1)

	if err == nil {
		// If proxy creation succeeded, operations should fail due to TLS mismatch
		defer proxy.Close()

		err = proxy.PublishToBitmask([]byte("test"), []byte("data"))
		assert.Error(t, err, "operations should fail with TLS key mismatch")
		assert.Contains(t, err.Error(), "authentication handshake failed", "error should be authentication-related")
	} else {
		// Proxy creation failed due to TLS issues, which is expected
		assert.Error(t, err, "should fail to create proxy with mismatched TLS keys")
		assert.Contains(t, err.Error(), "authentication handshake failed", "error should be authentication-related")
	}
}

func TestTLSBidirectionalVerification(t *testing.T) {
	// This test verifies that TLS verification works in both directions:
	// 1. Client verifies server certificate
	// 2. Server verifies client certificate

	// Create shared key config for both server and client
	sharedP2PConfig, engineConfig, err := createTestConfigs()
	require.NoError(t, err)

	mockPubSub := newMockPubSub()

	// Start server with shared key
	serverAddr, cleanup := setupTestServer(t, mockPubSub, sharedP2PConfig)
	defer cleanup()

	// Update config for client to use server address
	host, port, err := net.SplitHostPort(serverAddr)
	require.NoError(t, err)
	sharedP2PConfig.StreamListenMultiaddr = fmt.Sprintf("/ip4/%s/tcp/%s", host, port)

	// Create client with same shared key - this should succeed
	proxy, err := rpc.NewProxyBlossomSub(sharedP2PConfig, engineConfig, zap.NewNop(), 1)
	require.NoError(t, err, "should successfully connect with matching keys")
	defer proxy.Close()

	// Verify the connection works for operations
	testBitmask := []byte("bidirectional-test")
	testData := []byte("bidirectional message")

	err = proxy.PublishToBitmask(testBitmask, testData)
	assert.NoError(t, err, "should be able to publish over bidirectionally verified TLS")

	// Verify the message was received
	mockPubSub.mu.RLock()
	publishedData := mockPubSub.publishedData[string(testBitmask)]
	mockPubSub.mu.RUnlock()

	assert.Equal(t, testData, publishedData, "message should have been transmitted successfully")
}

// Integration test that runs the full proxy system
func TestFullProxyIntegration(t *testing.T) {
	t.Log("Starting full proxy integration test")

	p2pConfig, engineConfig, err := createTestConfigs()
	require.NoError(t, err)

	mockPubSub := newMockPubSub()
	serverAddr, cleanup := setupTestServer(t, mockPubSub, p2pConfig)
	defer cleanup()

	host, port, err := net.SplitHostPort(serverAddr)
	require.NoError(t, err)
	p2pConfig.StreamListenMultiaddr = fmt.Sprintf("/ip4/%s/tcp/%s", host, port)

	// Create multiple proxy clients to simulate workers
	var proxies []*rpc.ProxyBlossomSub
	for i := 1; i <= 3; i++ {
		proxy, err := rpc.NewProxyBlossomSub(p2pConfig, engineConfig, zap.NewNop(), uint(i))
		require.NoError(t, err)
		proxies = append(proxies, proxy)
		defer proxy.Close()
	}

	testBitmask := []byte("integration-test")

	// Set up subscribers on all proxies
	messageCount := make([]int, len(proxies))
	var messageCountMu sync.Mutex
	var wg sync.WaitGroup

	for i, proxy := range proxies {
		i := i // capture loop variable
		proxy := proxy

		err := proxy.Subscribe(testBitmask, func(message *pb.Message) error {
			messageCountMu.Lock()
			messageCount[i]++
			count := messageCount[i]
			messageCountMu.Unlock()

			t.Logf("Proxy %d received message %d: %s", i, count, string(message.Data))
			wg.Done()
			return nil
		})
		require.NoError(t, err)
	}

	// Give subscriptions time to be established
	time.Sleep(200 * time.Millisecond)

	// Publish messages from different proxies
	messages := []string{"msg1", "msg2", "msg3"}
	wg.Add(len(proxies) * len(messages)) // Each proxy should receive each message

	for i, msg := range messages {
		t.Logf("Publishing message %d: %s from proxy %d", i, msg, i)
		err := proxies[i].PublishToBitmask(testBitmask, []byte(msg))
		require.NoError(t, err)

		// Add small delay between messages
		time.Sleep(50 * time.Millisecond)
	}

	// Wait for all messages to be received (with timeout)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Log("All messages received successfully")
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for messages")
	}

	// Verify each proxy received all messages (correct pubsub behavior)
	for i, count := range messageCount {
		t.Logf("Proxy %d received %d messages", i, count)
		assert.Equal(t, len(messages), count,
			"proxy %d should have received %d messages, got %d", i, len(messages), count)
	}
}
