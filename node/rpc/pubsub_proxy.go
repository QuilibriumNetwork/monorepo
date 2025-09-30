package rpc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	multiaddr "github.com/multiformats/go-multiaddr"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
)

// PubSubProxyServer implements the gRPC server for proxying PubSub calls
type PubSubProxyServer struct {
	protobufs.UnimplementedPubSubProxyServer
	pubsub p2p.PubSub
	logger *zap.Logger

	// Track subscriptions and validators
	subscriptions map[string]context.CancelFunc
	validators    map[string]validatorInfo
	mu            sync.RWMutex
}

type validatorInfo struct {
	bitmask   []byte
	validator func(peer.ID, *pb.Message) p2p.ValidationResult
	sync      bool
}

// NewPubSubProxyServer creates a new proxy server
func NewPubSubProxyServer(
	pubsub p2p.PubSub,
	logger *zap.Logger,
) *PubSubProxyServer {
	return &PubSubProxyServer{
		pubsub:        pubsub,
		logger:        logger,
		subscriptions: make(map[string]context.CancelFunc),
		validators:    make(map[string]validatorInfo),
	}
}

// Publishing methods

func (s *PubSubProxyServer) PublishToBitmask(
	ctx context.Context,
	req *protobufs.PublishToBitmaskRequest,
) (*emptypb.Empty, error) {
	if err := s.pubsub.PublishToBitmask(req.Bitmask, req.Data); err != nil {
		s.logger.Error("failed to publish to bitmask", zap.Error(err))
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *PubSubProxyServer) Publish(
	ctx context.Context,
	req *protobufs.PublishRequest,
) (*emptypb.Empty, error) {
	if err := s.pubsub.Publish(req.Address, req.Data); err != nil {
		s.logger.Error("failed to publish", zap.Error(err))
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

// Subscription methods

func (s *PubSubProxyServer) Subscribe(
	req *protobufs.SubscribeRequest,
	stream protobufs.PubSubProxy_SubscribeServer,
) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	s.mu.Lock()
	s.subscriptions[req.SubscriptionId] = cancel
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.subscriptions, req.SubscriptionId)
		s.mu.Unlock()
	}()

	// Channel to receive messages
	msgChan := make(chan *pb.Message, 100)

	// Subscribe with a handler that sends to channel
	err := s.pubsub.Subscribe(req.Bitmask, func(message *pb.Message) error {
		select {
		case msgChan <- message:
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Drop message if channel is full
			s.logger.Warn(
				"dropping message, channel full",
				zap.String("subscription_id", req.SubscriptionId),
			)
		}
		return nil
	})

	if err != nil {
		return err
	}

	// Clean up subscription when done
	defer s.pubsub.Unsubscribe(req.Bitmask, false)

	// Stream messages to client
	for {
		select {
		case msg := <-msgChan:
			event := &protobufs.MessageEvent{
				Data:      msg.Data,
				From:      msg.From,
				Seqno:     msg.Seqno,
				Bitmask:   msg.Bitmask,
				Signature: msg.Signature,
				Key:       msg.Key,
			}
			if err := stream.Send(event); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *PubSubProxyServer) Unsubscribe(
	ctx context.Context,
	req *protobufs.UnsubscribeRequest,
) (*emptypb.Empty, error) {
	s.pubsub.Unsubscribe(req.Bitmask, req.Raw)
	return &emptypb.Empty{}, nil
}

// Validator methods - bidirectional streaming

func (s *PubSubProxyServer) ValidatorStream(
	stream protobufs.PubSubProxy_ValidatorStreamServer,
) error {
	// Map to store validator callbacks that will send requests back to client
	validatorCallbacks := make(map[string]chan *protobufs.ValidationRequest)
	defer func() {
		// Clean up all validators on disconnect
		for _, ch := range validatorCallbacks {
			close(ch)
		}
	}()

	// Handle incoming messages from client
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				s.logger.Debug("validator stream recv error", zap.Error(err))
				return
			}

			switch m := msg.Message.(type) {
			case *protobufs.ValidationStreamMessage_Register:
				reg := m.Register
				s.logger.Debug("registering validator",
					zap.String("validator_id", reg.ValidatorId),
					zap.Binary("bitmask", reg.Bitmask))

				// Create a channel for this validator's requests
				reqChan := make(chan *protobufs.ValidationRequest, 100)
				validatorCallbacks[reg.ValidatorId] = reqChan

				// Register the actual validator with pubsub
				err := s.pubsub.RegisterValidator(reg.Bitmask,
					func(peerID peer.ID, message *pb.Message) p2p.ValidationResult {
						// Send validation request to client
						req := &protobufs.ValidationRequest{
							ValidatorId: reg.ValidatorId,
							PeerId:      []byte(peerID),
							Message: &protobufs.MessageEvent{
								Data:      message.Data,
								From:      message.From,
								Seqno:     message.Seqno,
								Bitmask:   message.Bitmask,
								Signature: message.Signature,
								Key:       message.Key,
							},
						}

						select {
						case reqChan <- req:
							// Wait for response with timeout
							timer := time.NewTimer(5 * time.Second)
							defer timer.Stop()

							for {
								innerMsg, err := stream.Recv()
								if err != nil {
									return p2p.ValidationResultIgnore
								}

								if resp, ok := innerMsg.Message.(*protobufs.ValidationStreamMessage_ValidationResponse); ok {
									if resp.ValidationResponse.ValidatorId == reg.ValidatorId {
										switch resp.ValidationResponse.Result {
										case protobufs.ValidationResponse_ACCEPT:
											return p2p.ValidationResultAccept
										case protobufs.ValidationResponse_REJECT:
											return p2p.ValidationResultReject
										default:
											return p2p.ValidationResultIgnore
										}
									}
								}

								select {
								case <-timer.C:
									return p2p.ValidationResultIgnore
								default:
									continue
								}
							}
						default:
							s.logger.Warn("validator request channel full, dropping")
							return p2p.ValidationResultIgnore
						}
					}, reg.Sync)

				if err != nil {
					s.logger.Error("failed to register validator", zap.Error(err))
					delete(validatorCallbacks, reg.ValidatorId)
					close(reqChan)
				}

			case *protobufs.ValidationStreamMessage_Unregister:
				unreg := m.Unregister
				s.logger.Debug("unregistering validator",
					zap.String("validator_id", unreg.ValidatorId))

				if err := s.pubsub.UnregisterValidator(unreg.Bitmask); err != nil {
					s.logger.Error("failed to unregister validator", zap.Error(err))
				}

				if ch, exists := validatorCallbacks[unreg.ValidatorId]; exists {
					close(ch)
					delete(validatorCallbacks, unreg.ValidatorId)
				}

			case *protobufs.ValidationStreamMessage_ValidationResponse:
				// Response handled in the validator callback above
				continue
			}
		}
	}()

	// Send validation requests to client
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		default:
			// Check all validator channels for pending requests
			for _, reqChan := range validatorCallbacks {
				select {
				case req := <-reqChan:
					msg := &protobufs.ValidationStreamMessage{
						Message: &protobufs.ValidationStreamMessage_ValidationRequest{
							ValidationRequest: req,
						},
					}
					if err := stream.Send(msg); err != nil {
						return err
					}
				default:
					continue
				}
			}
			time.Sleep(10 * time.Millisecond) // Small delay to prevent busy loop
		}
	}
}

// Peer information methods

func (s *PubSubProxyServer) GetPeerID(
	ctx context.Context,
	_ *emptypb.Empty,
) (*protobufs.GetPeerIDResponse, error) {
	return &protobufs.GetPeerIDResponse{
		PeerId: s.pubsub.GetPeerID(),
	}, nil
}

func (s *PubSubProxyServer) GetPeerstoreCount(
	ctx context.Context,
	_ *emptypb.Empty,
) (*protobufs.GetPeerstoreCountResponse, error) {
	return &protobufs.GetPeerstoreCountResponse{
		Count: int32(s.pubsub.GetPeerstoreCount()),
	}, nil
}

func (s *PubSubProxyServer) GetNetworkPeersCount(
	ctx context.Context,
	_ *emptypb.Empty,
) (*protobufs.GetNetworkPeersCountResponse, error) {
	return &protobufs.GetNetworkPeersCountResponse{
		Count: int32(s.pubsub.GetNetworkPeersCount()),
	}, nil
}

func (s *PubSubProxyServer) GetRandomPeer(
	ctx context.Context,
	req *protobufs.GetRandomPeerRequest,
) (*protobufs.GetRandomPeerResponse, error) {
	peerID, err := s.pubsub.GetRandomPeer(req.Bitmask)
	if err != nil {
		return nil, err
	}
	return &protobufs.GetRandomPeerResponse{
		PeerId: peerID,
	}, nil
}

func (s *PubSubProxyServer) GetMultiaddrOfPeer(
	ctx context.Context,
	req *protobufs.GetMultiaddrOfPeerRequest,
) (*protobufs.GetMultiaddrOfPeerResponse, error) {
	return &protobufs.GetMultiaddrOfPeerResponse{
		Multiaddr: s.pubsub.GetMultiaddrOfPeer(req.PeerId),
	}, nil
}

func (s *PubSubProxyServer) GetMultiaddrOfPeerStream(
	req *protobufs.GetMultiaddrOfPeerRequest,
	stream protobufs.PubSubProxy_GetMultiaddrOfPeerStreamServer,
) error {
	ctx := stream.Context()
	addrChan := s.pubsub.GetMultiaddrOfPeerStream(ctx, req.PeerId)

	for {
		select {
		case addr, ok := <-addrChan:
			if !ok {
				return nil // Channel closed
			}
			resp := &protobufs.GetMultiaddrOfPeerResponse{
				Multiaddr: addr.String(),
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *PubSubProxyServer) GetOwnMultiaddrs(
	ctx context.Context,
	_ *emptypb.Empty,
) (*protobufs.GetOwnMultiaddrsResponse, error) {
	addrs := s.pubsub.GetOwnMultiaddrs()
	multiaddrs := make([]string, len(addrs))
	for i, addr := range addrs {
		multiaddrs[i] = addr.String()
	}
	return &protobufs.GetOwnMultiaddrsResponse{
		Multiaddrs: multiaddrs,
	}, nil
}

func (s *PubSubProxyServer) GetNetworkInfo(
	ctx context.Context,
	_ *emptypb.Empty,
) (*protobufs.NetworkInfoResponse, error) {
	info := s.pubsub.GetNetworkInfo()

	// Convert from protobufs.NetworkInfoResponse to protobufs.NetworkInfoResponse
	result := &protobufs.NetworkInfoResponse{
		NetworkInfo: make([]*protobufs.NetworkInfo, len(info.NetworkInfo)),
	}

	for i, ni := range info.NetworkInfo {
		result.NetworkInfo[i] = &protobufs.NetworkInfo{
			PeerId:     ni.PeerId,
			Multiaddrs: ni.Multiaddrs,
			PeerScore:  ni.PeerScore,
		}
	}

	return result, nil
}

// Scoring methods

func (s *PubSubProxyServer) GetPeerScore(
	ctx context.Context,
	req *protobufs.GetPeerScoreRequest,
) (*protobufs.GetPeerScoreResponse, error) {
	return &protobufs.GetPeerScoreResponse{
		Score: s.pubsub.GetPeerScore(req.PeerId),
	}, nil
}

func (s *PubSubProxyServer) SetPeerScore(
	ctx context.Context,
	req *protobufs.SetPeerScoreRequest,
) (*emptypb.Empty, error) {
	s.pubsub.SetPeerScore(req.PeerId, req.Score)
	return &emptypb.Empty{}, nil
}

func (s *PubSubProxyServer) AddPeerScore(
	ctx context.Context,
	req *protobufs.AddPeerScoreRequest,
) (*emptypb.Empty, error) {
	s.pubsub.AddPeerScore(req.PeerId, req.ScoreDelta)
	return &emptypb.Empty{}, nil
}

// Connection management

func (s *PubSubProxyServer) Reconnect(
	ctx context.Context,
	req *protobufs.ReconnectRequest,
) (*emptypb.Empty, error) {
	if err := s.pubsub.Reconnect(req.PeerId); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *PubSubProxyServer) Bootstrap(
	ctx context.Context,
	_ *emptypb.Empty,
) (*emptypb.Empty, error) {
	if err := s.pubsub.Bootstrap(ctx); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *PubSubProxyServer) DiscoverPeers(
	ctx context.Context,
	_ *emptypb.Empty,
) (*emptypb.Empty, error) {
	if err := s.pubsub.DiscoverPeers(ctx); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *PubSubProxyServer) IsPeerConnected(
	ctx context.Context,
	req *protobufs.IsPeerConnectedRequest,
) (*protobufs.IsPeerConnectedResponse, error) {
	return &protobufs.IsPeerConnectedResponse{
		Connected: s.pubsub.IsPeerConnected(req.PeerId),
	}, nil
}

// Utility methods

func (s *PubSubProxyServer) GetNetwork(
	ctx context.Context,
	_ *emptypb.Empty,
) (*protobufs.GetNetworkResponse, error) {
	return &protobufs.GetNetworkResponse{
		Network: uint32(s.pubsub.GetNetwork()),
	}, nil
}

func (s *PubSubProxyServer) Reachability(
	ctx context.Context,
	_ *emptypb.Empty,
) (*wrapperspb.BoolValue, error) {
	val := s.pubsub.Reachability()
	if val == nil {
		return nil, nil
	}
	return val, nil
}

func (s *PubSubProxyServer) SignMessage(
	ctx context.Context,
	req *protobufs.SignMessageRequest,
) (*protobufs.SignMessageResponse, error) {
	sig, err := s.pubsub.SignMessage(req.Message)
	if err != nil {
		return nil, err
	}
	return &protobufs.SignMessageResponse{
		Signature: sig,
	}, nil
}

func (s *PubSubProxyServer) GetPublicKey(
	ctx context.Context,
	_ *emptypb.Empty,
) (*protobufs.GetPublicKeyResponse, error) {
	return &protobufs.GetPublicKeyResponse{
		PublicKey: s.pubsub.GetPublicKey(),
	}, nil
}

// PubSubProxyClient wraps a gRPC client to implement the p2p.PubSub interface
type PubSubProxyClient struct {
	client protobufs.PubSubProxyClient
	conn   *grpc.ClientConn
	logger *zap.Logger

	// Track active subscriptions and validators
	subscriptions     map[string]context.CancelFunc
	validators        map[string]func(peer.ID, *pb.Message) p2p.ValidationResult
	bitmaskValidators map[string]string // bitmask -> validatorID
	validatorStream   protobufs.PubSubProxy_ValidatorStreamClient
	validatorStreamMu sync.Mutex
	mu                sync.RWMutex
}

// NewPubSubProxyClient creates a new proxy client
func NewPubSubProxyClient(
	conn *grpc.ClientConn,
	logger *zap.Logger,
) *PubSubProxyClient {
	client := &PubSubProxyClient{
		client:        protobufs.NewPubSubProxyClient(conn),
		conn:          conn,
		logger:        logger,
		subscriptions: make(map[string]context.CancelFunc),
		validators: make(map[string]func(
			peer.ID,
			*pb.Message,
		) p2p.ValidationResult),
		bitmaskValidators: make(map[string]string),
	}

	// Initialize validator stream
	if err := client.initValidatorStream(); err != nil {
		logger.Error("failed to initialize validator stream", zap.Error(err))
	}

	return client
}

func (c *PubSubProxyClient) initValidatorStream() error {
	c.validatorStreamMu.Lock()
	defer c.validatorStreamMu.Unlock()

	stream, err := c.client.ValidatorStream(context.Background())
	if err != nil {
		return err
	}

	c.validatorStream = stream

	// Start goroutine to handle incoming validation requests
	go c.handleValidationRequests()

	return nil
}

func (c *PubSubProxyClient) handleValidationRequests() {
	for {
		msg, err := c.validatorStream.Recv()
		if err != nil {
			c.logger.Error("validator stream recv error", zap.Error(err))
			// Try to reconnect
			time.Sleep(1 * time.Second)
			if err := c.initValidatorStream(); err != nil {
				c.logger.Error(
					"failed to reinitialize validator stream",
					zap.Error(err),
				)
			}
			return
		}

		switch m := msg.Message.(type) {
		case *protobufs.ValidationStreamMessage_ValidationRequest:
			req := m.ValidationRequest

			// Look up the validator function
			c.mu.RLock()
			validator, exists := c.validators[req.ValidatorId]
			c.mu.RUnlock()

			if !exists {
				c.logger.Warn("received validation request for unknown validator",
					zap.String("validator_id", req.ValidatorId))
				continue
			}

			// Convert message and call validator
			pbMsg := &pb.Message{
				Data:      req.Message.Data,
				From:      req.Message.From,
				Seqno:     req.Message.Seqno,
				Bitmask:   req.Message.Bitmask,
				Signature: req.Message.Signature,
				Key:       req.Message.Key,
			}

			result := validator(peer.ID(req.PeerId), pbMsg)

			// Send response
			var protoResult protobufs.ValidationResponse_ValidationResult
			switch result {
			case p2p.ValidationResultAccept:
				protoResult = protobufs.ValidationResponse_ACCEPT
			case p2p.ValidationResultReject:
				protoResult = protobufs.ValidationResponse_REJECT
			default:
				protoResult = protobufs.ValidationResponse_IGNORE
			}

			resp := &protobufs.ValidationStreamMessage{
				Message: &protobufs.ValidationStreamMessage_ValidationResponse{
					ValidationResponse: &protobufs.ValidationResponse{
						ValidatorId: req.ValidatorId,
						Result:      protoResult,
					},
				},
			}

			c.validatorStreamMu.Lock()
			if err := c.validatorStream.Send(resp); err != nil {
				c.logger.Error("failed to send validation response", zap.Error(err))
			}
			c.validatorStreamMu.Unlock()
		}
	}
}

// Ensure PubSubProxyClient implements p2p.PubSub
var _ p2p.PubSub = (*PubSubProxyClient)(nil)

func (c *PubSubProxyClient) PublishToBitmask(bitmask []byte, data []byte) error {
	_, err := c.client.PublishToBitmask(
		context.Background(),
		&protobufs.PublishToBitmaskRequest{
			Bitmask: bitmask,
			Data:    data,
		},
	)
	return err
}

func (c *PubSubProxyClient) Publish(address []byte, data []byte) error {
	_, err := c.client.Publish(context.Background(), &protobufs.PublishRequest{
		Address: address,
		Data:    data,
	})
	return err
}

func (c *PubSubProxyClient) Subscribe(
	bitmask []byte,
	handler func(message *pb.Message) error,
) error {
	// Generate unique subscription ID
	subID := generateSubscriptionID()

	ctx, cancel := context.WithCancel(context.Background())

	c.mu.Lock()
	c.subscriptions[subID] = cancel
	c.mu.Unlock()

	stream, err := c.client.Subscribe(ctx, &protobufs.SubscribeRequest{
		Bitmask:        bitmask,
		SubscriptionId: subID,
	})
	if err != nil {
		cancel()
		c.mu.Lock()
		delete(c.subscriptions, subID)
		c.mu.Unlock()
		return err
	}

	// Start goroutine to handle incoming messages
	go func() {
		defer func() {
			cancel()
			c.mu.Lock()
			delete(c.subscriptions, subID)
			c.mu.Unlock()
		}()

		for {
			msg, err := stream.Recv()
			if err != nil {
				c.logger.Error("subscription stream error", zap.Error(err))
				return
			}

			// Convert to pb.Message
			pbMsg := &pb.Message{
				Data:      msg.Data,
				From:      msg.From,
				Seqno:     msg.Seqno,
				Bitmask:   msg.Bitmask,
				Signature: msg.Signature,
				Key:       msg.Key,
			}

			if err := handler(pbMsg); err != nil {
				c.logger.Debug("message handler error", zap.Error(err))
			}
		}
	}()

	return nil
}

func (c *PubSubProxyClient) Unsubscribe(bitmask []byte, raw bool) {
	_, err := c.client.Unsubscribe(
		context.Background(),
		&protobufs.UnsubscribeRequest{
			Bitmask: bitmask,
			Raw:     raw,
		},
	)
	if err != nil {
		c.logger.Error("unsubscribe error", zap.Error(err))
	}
}

func (c *PubSubProxyClient) RegisterValidator(
	bitmask []byte,
	validator func(peerID peer.ID, message *pb.Message) p2p.ValidationResult,
	sync bool,
) error {
	bitmaskKey := string(bitmask)

	// Check if there's already a validator for this bitmask
	c.mu.Lock()
	if existingID, exists := c.bitmaskValidators[bitmaskKey]; exists {
		// Unregister the existing validator first
		delete(c.validators, existingID)
		delete(c.bitmaskValidators, bitmaskKey)
		c.mu.Unlock()

		// Send unregister for the old validator
		unreg := &protobufs.ValidationStreamMessage{
			Message: &protobufs.ValidationStreamMessage_Unregister{
				Unregister: &protobufs.UnregisterValidatorRequest{
					Bitmask:     bitmask,
					ValidatorId: existingID,
				},
			},
		}
		c.validatorStreamMu.Lock()
		if c.validatorStream != nil {
			_ = c.validatorStream.Send(unreg) // Ignore error for cleanup
		}
		c.validatorStreamMu.Unlock()

		c.mu.Lock()
	}

	validatorID := generateSubscriptionID()

	// Store the validator function and mapping
	c.validators[validatorID] = validator
	c.bitmaskValidators[bitmaskKey] = validatorID
	c.mu.Unlock()

	// Send register request through the stream
	req := &protobufs.ValidationStreamMessage{
		Message: &protobufs.ValidationStreamMessage_Register{
			Register: &protobufs.RegisterValidatorRequest{
				Bitmask:     bitmask,
				ValidatorId: validatorID,
				Sync:        sync,
			},
		},
	}

	c.validatorStreamMu.Lock()
	defer c.validatorStreamMu.Unlock()

	if c.validatorStream == nil {
		// Try to initialize stream if not already done
		if err := c.initValidatorStream(); err != nil {
			c.mu.Lock()
			delete(c.validators, validatorID)
			delete(c.bitmaskValidators, bitmaskKey)
			c.mu.Unlock()
			return err
		}
	}

	if err := c.validatorStream.Send(req); err != nil {
		c.mu.Lock()
		delete(c.validators, validatorID)
		delete(c.bitmaskValidators, bitmaskKey)
		c.mu.Unlock()
		return err
	}

	return nil
}

func (c *PubSubProxyClient) UnregisterValidator(bitmask []byte) error {
	bitmaskKey := string(bitmask)

	// Find and remove the validator ID for this bitmask
	c.mu.Lock()
	validatorID, exists := c.bitmaskValidators[bitmaskKey]
	if !exists {
		c.mu.Unlock()
		return nil // No validator registered for this bitmask
	}

	// Clean up the mappings
	delete(c.validators, validatorID)
	delete(c.bitmaskValidators, bitmaskKey)
	c.mu.Unlock()

	// Send unregister request through the stream
	req := &protobufs.ValidationStreamMessage{
		Message: &protobufs.ValidationStreamMessage_Unregister{
			Unregister: &protobufs.UnregisterValidatorRequest{
				Bitmask:     bitmask,
				ValidatorId: validatorID,
			},
		},
	}

	c.validatorStreamMu.Lock()
	defer c.validatorStreamMu.Unlock()

	if c.validatorStream == nil {
		return nil // Stream not initialized, nothing to unregister on server
	}

	return c.validatorStream.Send(req)
}

func (c *PubSubProxyClient) GetPeerID() []byte {
	resp, err := c.client.GetPeerID(context.Background(), &emptypb.Empty{})
	if err != nil {
		c.logger.Error("GetPeerID error", zap.Error(err))
		return nil
	}
	return resp.PeerId
}

func (c *PubSubProxyClient) GetPeerstoreCount() int {
	resp, err := c.client.GetPeerstoreCount(context.Background(), &emptypb.Empty{})
	if err != nil {
		c.logger.Error("GetPeerstoreCount error", zap.Error(err))
		return 0
	}
	return int(resp.Count)
}

func (c *PubSubProxyClient) GetNetworkPeersCount() int {
	resp, err := c.client.GetNetworkPeersCount(
		context.Background(),
		&emptypb.Empty{},
	)
	if err != nil {
		c.logger.Error("GetNetworkPeersCount error", zap.Error(err))
		return 0
	}
	return int(resp.Count)
}

func (c *PubSubProxyClient) GetRandomPeer(bitmask []byte) ([]byte, error) {
	resp, err := c.client.GetRandomPeer(
		context.Background(),
		&protobufs.GetRandomPeerRequest{
			Bitmask: bitmask,
		},
	)
	if err != nil {
		return nil, err
	}
	return resp.PeerId, nil
}

func (c *PubSubProxyClient) GetMultiaddrOfPeerStream(
	ctx context.Context,
	peerId []byte,
) <-chan multiaddr.Multiaddr {
	ch := make(chan multiaddr.Multiaddr)

	go func() {
		defer close(ch)

		stream, err := c.client.GetMultiaddrOfPeerStream(
			ctx,
			&protobufs.GetMultiaddrOfPeerRequest{
				PeerId: peerId,
			},
		)
		if err != nil {
			c.logger.Error("failed to start multiaddr stream", zap.Error(err))
			return
		}

		for {
			resp, err := stream.Recv()
			if err != nil {
				if err.Error() != "EOF" {
					c.logger.Debug("multiaddr stream ended", zap.Error(err))
				}
				return
			}

			if resp.Multiaddr != "" {
				if ma, err := multiaddr.NewMultiaddr(resp.Multiaddr); err == nil {
					select {
					case ch <- ma:
					case <-ctx.Done():
						return
					}
				} else {
					c.logger.Warn("invalid multiaddr received",
						zap.String("addr", resp.Multiaddr),
						zap.Error(err))
				}
			}
		}
	}()

	return ch
}

func (c *PubSubProxyClient) GetMultiaddrOfPeer(peerId []byte) string {
	resp, err := c.client.GetMultiaddrOfPeer(
		context.Background(),
		&protobufs.GetMultiaddrOfPeerRequest{
			PeerId: peerId,
		},
	)
	if err != nil {
		c.logger.Error("GetMultiaddrOfPeer error", zap.Error(err))
		return ""
	}
	return resp.Multiaddr
}

func (c *PubSubProxyClient) GetOwnMultiaddrs() []multiaddr.Multiaddr {
	resp, err := c.client.GetOwnMultiaddrs(context.Background(), &emptypb.Empty{})
	if err != nil {
		c.logger.Error("GetOwnMultiaddrs error", zap.Error(err))
		return nil
	}

	addrs := make([]multiaddr.Multiaddr, 0, len(resp.Multiaddrs))
	for _, addrStr := range resp.Multiaddrs {
		if ma, err := multiaddr.NewMultiaddr(addrStr); err == nil {
			addrs = append(addrs, ma)
		}
	}
	return addrs
}

func (c *PubSubProxyClient) StartDirectChannelListener(
	key []byte,
	purpose string,
	server *grpc.Server,
) error {
	// This requires special handling as it involves starting a server
	// Not implemented in proxy mode
	return errors.Wrap(
		errors.New("not supported in proxy mode"),
		"start direct channel listener",
	)
}

func (c *PubSubProxyClient) GetDirectChannel(
	ctx context.Context,
	peerId []byte,
	purpose string,
) (*grpc.ClientConn, error) {
	// This requires special handling for direct connections
	// Not implemented in proxy mode
	return nil, errors.Wrap(
		errors.New("not supported in proxy mode"),
		"get direct channel",
	)
}

func (c *PubSubProxyClient) GetNetworkInfo() *protobufs.NetworkInfoResponse {
	resp, err := c.client.GetNetworkInfo(context.Background(), &emptypb.Empty{})
	if err != nil {
		c.logger.Error("GetNetworkInfo error", zap.Error(err))
		return nil
	}

	// Convert from protobufs to protobufs
	result := &protobufs.NetworkInfoResponse{
		NetworkInfo: make([]*protobufs.NetworkInfo, len(resp.NetworkInfo)),
	}

	for i, ni := range resp.NetworkInfo {
		result.NetworkInfo[i] = &protobufs.NetworkInfo{
			PeerId:     ni.PeerId,
			Multiaddrs: ni.Multiaddrs,
			PeerScore:  ni.PeerScore,
		}
	}

	return result
}

func (c *PubSubProxyClient) SignMessage(msg []byte) ([]byte, error) {
	resp, err := c.client.SignMessage(
		context.Background(),
		&protobufs.SignMessageRequest{
			Message: msg,
		},
	)
	if err != nil {
		return nil, err
	}
	return resp.Signature, nil
}

func (c *PubSubProxyClient) GetPublicKey() []byte {
	resp, err := c.client.GetPublicKey(context.Background(), &emptypb.Empty{})
	if err != nil {
		c.logger.Error("GetPublicKey error", zap.Error(err))
		return nil
	}
	return resp.PublicKey
}

func (c *PubSubProxyClient) GetPeerScore(peerId []byte) int64 {
	resp, err := c.client.GetPeerScore(context.Background(), &protobufs.GetPeerScoreRequest{
		PeerId: peerId,
	})
	if err != nil {
		c.logger.Error("GetPeerScore error", zap.Error(err))
		return 0
	}
	return resp.Score
}

func (c *PubSubProxyClient) SetPeerScore(peerId []byte, score int64) {
	_, err := c.client.SetPeerScore(
		context.Background(),
		&protobufs.SetPeerScoreRequest{
			PeerId: peerId,
			Score:  score,
		},
	)
	if err != nil {
		c.logger.Error("SetPeerScore error", zap.Error(err))
	}
}

func (c *PubSubProxyClient) AddPeerScore(peerId []byte, scoreDelta int64) {
	_, err := c.client.AddPeerScore(
		context.Background(),
		&protobufs.AddPeerScoreRequest{
			PeerId:     peerId,
			ScoreDelta: scoreDelta,
		},
	)
	if err != nil {
		c.logger.Error("AddPeerScore error", zap.Error(err))
	}
}

func (c *PubSubProxyClient) Reconnect(peerId []byte) error {
	_, err := c.client.Reconnect(
		context.Background(),
		&protobufs.ReconnectRequest{
			PeerId: peerId,
		},
	)
	return err
}

func (c *PubSubProxyClient) Bootstrap(ctx context.Context) error {
	_, err := c.client.Bootstrap(ctx, &emptypb.Empty{})
	return err
}

func (c *PubSubProxyClient) DiscoverPeers(ctx context.Context) error {
	_, err := c.client.DiscoverPeers(ctx, &emptypb.Empty{})
	return err
}

func (c *PubSubProxyClient) GetNetwork() uint {
	resp, err := c.client.GetNetwork(context.Background(), &emptypb.Empty{})
	if err != nil {
		c.logger.Error("GetNetwork error", zap.Error(err))
		return 0
	}
	return uint(resp.Network)
}

func (c *PubSubProxyClient) IsPeerConnected(peerId []byte) bool {
	resp, err := c.client.IsPeerConnected(
		context.Background(),
		&protobufs.IsPeerConnectedRequest{
			PeerId: peerId,
		},
	)
	if err != nil {
		c.logger.Error("IsPeerConnected error", zap.Error(err))
		return false
	}
	return resp.Connected
}

func (c *PubSubProxyClient) Reachability() *wrapperspb.BoolValue {
	resp, err := c.client.Reachability(context.Background(), &emptypb.Empty{})
	if err != nil {
		c.logger.Error("Reachability error", zap.Error(err))
		return nil
	}
	return resp
}

// Helper function to generate unique IDs
func generateSubscriptionID() string {
	return fmt.Sprintf("sub_%d", time.Now().UnixNano())
}
