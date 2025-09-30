package onion

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
)

// GRPCTransport implements the Transport interface using gRPC bidirectional
// streams
type GRPCTransport struct {
	protobufs.UnimplementedOnionServiceServer

	logger  *zap.Logger
	peers   p2p.PeerInfoManager
	signers consensus.SignerRegistry
	peerID  []byte

	mu            sync.RWMutex
	serverStreams map[string]protobufs.OnionService_ConnectServer // peerID -> server stream
	clientStreams map[string]protobufs.OnionService_ConnectClient // peerID -> client stream
	clientConns   map[string]*grpc.ClientConn                     // peerID -> client connection
	onReceive     func(srcPeerID []byte, circID uint32, cell []byte)
}

// NewGRPCTransport creates a new gRPC-based transport implementation
func NewGRPCTransport(
	logger *zap.Logger,
	peerID []byte,
	peers p2p.PeerInfoManager,
	signers consensus.SignerRegistry,
) *GRPCTransport {
	return &GRPCTransport{
		logger:        logger,
		peerID:        peerID,
		peers:         peers,
		signers:       signers,
		serverStreams: make(map[string]protobufs.OnionService_ConnectServer),
		clientStreams: make(map[string]protobufs.OnionService_ConnectClient),
		clientConns:   make(map[string]*grpc.ClientConn),
	}
}

// Send implements Transport.Send by sending a message to the specified peer
func (g *GRPCTransport) Send(
	ctx context.Context,
	peerID []byte,
	circID uint32,
	cell []byte,
) error {
	if err := g.validatePeer(peerID); err != nil {
		return errors.Wrap(err, "send")
	}

	g.mu.RLock()
	serverStream, hasServer := g.serverStreams[string(peerID)]
	clientStream, hasClient := g.clientStreams[string(peerID)]
	g.mu.RUnlock()

	if !hasServer && !hasClient {
		return errors.Wrap(
			fmt.Errorf("no active stream to peer %x", peerID),
			"send",
		)
	}

	// Send via server stream (to connected client) or client stream (to remote server)
	if hasServer {
		msg := &protobufs.ReceiveMessage{
			SourcePeerId: peerID,
			CircId:       circID,
			Cell:         cell,
		}
		if err := serverStream.Send(msg); err != nil {
			g.logger.Warn(
				"failed to send message via server stream",
				zap.Binary("peer_id", peerID),
				zap.Uint32("circ_id", circID),
				zap.Error(err),
			)
			// Remove failed stream
			g.mu.Lock()
			delete(g.serverStreams, string(peerID))
			g.mu.Unlock()
			return errors.Wrap(err, "send")
		}
	} else if hasClient {
		msg := &protobufs.SendMessage{
			PeerId: peerID,
			CircId: circID,
			Cell:   cell,
		}
		if err := clientStream.Send(msg); err != nil {
			g.logger.Warn(
				"failed to send message via client stream",
				zap.Binary("peer_id", peerID),
				zap.Uint32("circ_id", circID),
				zap.Error(err),
			)
			// Remove failed stream
			g.mu.Lock()
			delete(g.clientStreams, string(peerID))
			g.mu.Unlock()
			return errors.Wrap(err, "send")
		}
	}

	return nil
}

// OnReceive implements Transport.OnReceive by registering a callback for
// incoming messages
func (g *GRPCTransport) OnReceive(cb func(
	srcPeerID []byte,
	circID uint32,
	cell []byte,
)) {
	g.mu.Lock()
	g.onReceive = cb
	g.mu.Unlock()
}

// Connect implements the gRPC OnionService.Connect method for bidirectional
// streaming
func (g *GRPCTransport) Connect(
	stream protobufs.OnionService_ConnectServer,
) error {
	ctx := stream.Context()

	// Handle incoming messages from the stream
	go g.handleIncomingMessages(ctx, stream)

	// Keep the connection alive until context is cancelled
	<-ctx.Done()
	return ctx.Err()
}

// handleIncomingMessages processes incoming messages from a gRPC stream
func (g *GRPCTransport) handleIncomingMessages(
	ctx context.Context,
	stream protobufs.OnionService_ConnectServer,
) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				g.logger.Debug("stream closed by peer")
				return
			}
			g.logger.Warn("error receiving message from stream", zap.Error(err))
			return
		}

		// Validate the message
		if err := g.validateMessage(msg); err != nil {
			g.logger.Warn(
				"invalid message received",
				zap.Binary("peer_id", msg.PeerId),
				zap.Error(err),
			)
			continue
		}

		// Register this server stream for the peer if not already registered
		peerKey := string(msg.PeerId)
		g.mu.Lock()
		if _, exists := g.serverStreams[peerKey]; !exists {
			g.serverStreams[peerKey] = stream
			g.logger.Debug(
				"registered new server stream",
				zap.Binary("peer_id", msg.PeerId),
			)
		}
		onReceive := g.onReceive
		g.mu.Unlock()

		// Forward the message to the callback if set
		if onReceive != nil {
			onReceive(msg.PeerId, msg.CircId, msg.Cell)
		}
	}
}

// validatePeer verifies that the peer is known and has routing capability
func (g *GRPCTransport) validatePeer(peerID []byte) error {
	if len(peerID) == 0 {
		return errors.New("empty peer ID")
	}

	peerInfo := g.peers.GetPeerInfo(peerID)
	if peerInfo == nil {
		return fmt.Errorf("unknown peer %x", peerID)
	}

	// Check if peer has routing capability
	hasRouting := false
	for _, cap := range peerInfo.Capabilities {
		if cap.ProtocolIdentifier == ProtocolRouting {
			hasRouting = true
			break
		}
	}

	if !hasRouting {
		return fmt.Errorf("peer %x lacks routing capability", peerID)
	}

	return nil
}

// validateMessage validates an incoming gRPC message
func (g *GRPCTransport) validateMessage(msg *protobufs.SendMessage) error {
	if msg == nil {
		return errors.New("nil message")
	}

	if len(msg.PeerId) == 0 {
		return errors.New("empty peer ID in message")
	}

	if len(msg.Cell) == 0 {
		return errors.New("empty cell in message")
	}

	// Validate that we know this peer
	return g.validatePeer(msg.PeerId)
}

// ConnectToPeer establishes a connection to a peer as a gRPC client if not
// already connected
func (g *GRPCTransport) ConnectToPeer(
	ctx context.Context,
	peerID []byte,
) error {
	if bytes.Equal(peerID, g.peerID) {
		return errors.Wrap(errors.New("invalid connection"), "connect to peer")
	}

	if err := g.validatePeer(peerID); err != nil {
		return errors.Wrap(err, "connect to peer")
	}

	peerKey := string(peerID)

	// Check if we already have a connection
	g.mu.RLock()
	_, hasServer := g.serverStreams[peerKey]
	_, hasClient := g.clientStreams[peerKey]
	g.mu.RUnlock()

	if hasServer || hasClient {
		return nil // Already connected
	}

	// Get peer info to find streaming multiaddr
	peerInfo := g.peers.GetPeerInfo(peerID)
	if peerInfo == nil {
		return fmt.Errorf("peer info not found for %x", peerID)
	}

	// Find a streaming multiaddr from reachability info
	var streamAddr string
	for _, reach := range peerInfo.Reachability {
		if len(reach.StreamMultiaddrs) > 0 {
			streamAddr = reach.StreamMultiaddrs[0]
			break
		}
	}
	if streamAddr == "" {
		return fmt.Errorf("no streaming multiaddr found for peer %x", peerID)
	}

	// Parse multiaddr to extract host:port
	ma, err := multiaddr.NewMultiaddr(streamAddr)
	if err != nil {
		return errors.Wrap(err, "parse multiaddr")
	}

	// Convert multiaddr to network address
	_, addr, err := manet.DialArgs(ma)
	if err != nil {
		return errors.Wrap(err, "convert multiaddr to dial args")
	}

	target := addr

	// Establish gRPC connection
	conn, err := grpc.DialContext(
		ctx,
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return errors.Wrap(err, "dial grpc")
	}

	// Create OnionService client
	client := protobufs.NewOnionServiceClient(conn)

	// Start bidirectional stream
	stream, err := client.Connect(ctx)
	if err != nil {
		conn.Close()
		return errors.Wrap(err, "create stream")
	}

	// Store the connection and stream
	g.mu.Lock()
	g.clientConns[peerKey] = conn
	g.clientStreams[peerKey] = stream
	g.mu.Unlock()

	// Start goroutine to handle incoming messages from this client stream
	go g.handleClientStream(ctx, peerID, stream)

	g.logger.Info(
		"connected to peer",
		zap.Binary("peer_id", peerID),
		zap.String("address", target),
	)

	return nil
}

// DisconnectPeer removes a peer's stream from the active connections
func (g *GRPCTransport) DisconnectPeer(peerID []byte) {
	peerKey := string(peerID)

	g.mu.Lock()
	defer g.mu.Unlock()

	// Close and remove server stream
	delete(g.serverStreams, peerKey)

	// Close and remove client stream and connection
	if stream, exists := g.clientStreams[peerKey]; exists {
		stream.CloseSend()
		delete(g.clientStreams, peerKey)
	}

	if conn, exists := g.clientConns[peerKey]; exists {
		conn.Close()
		delete(g.clientConns, peerKey)
	}

	g.logger.Debug(
		"disconnected peer",
		zap.Binary("peer_id", peerID),
	)
}

// GetActivePeers returns a list of peer IDs with active connections
func (g *GRPCTransport) GetActivePeers() [][]byte {
	g.mu.RLock()
	defer g.mu.RUnlock()

	peerMap := make(map[string]bool)

	// Add all peers with server streams
	for peerKey := range g.serverStreams {
		peerMap[peerKey] = true
	}

	// Add all peers with client streams
	for peerKey := range g.clientStreams {
		peerMap[peerKey] = true
	}

	peers := make([][]byte, 0, len(peerMap))
	for peerKey := range peerMap {
		peers = append(peers, []byte(peerKey))
	}

	return peers
}

// handleClientStream processes incoming messages from a client stream
func (g *GRPCTransport) handleClientStream(
	ctx context.Context,
	peerID []byte,
	stream protobufs.OnionService_ConnectClient,
) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				g.logger.Debug("client stream closed", zap.Binary("peer_id", peerID))
			} else {
				g.logger.Warn("error receiving from client stream",
					zap.Binary("peer_id", peerID),
					zap.Error(err))
			}

			// Clean up the stream
			g.mu.Lock()
			delete(g.clientStreams, string(peerID))
			g.mu.Unlock()
			return
		}

		// Forward the message to the callback if set
		g.mu.RLock()
		onReceive := g.onReceive
		g.mu.RUnlock()

		if onReceive != nil {
			onReceive(msg.SourcePeerId, msg.CircId, msg.Cell)
		}
	}
}
