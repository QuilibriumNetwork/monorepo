package global

// Message routing: queue processors, pubsub subscriptions, and archive client frame polling.

import (
	"bytes"
	"context"
	"slices"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	tp2p "source.quilibrium.com/quilibrium/monorepo/types/p2p"
)

// MessageRouter owns the pubsub subscription handlers and the message queue
// goroutines that dispatch incoming messages to engine callbacks.
type MessageRouter struct {
	logger *zap.Logger
	pubsub tp2p.PubSub

	// Owned queues
	consensusQueue chan *pb.Message
	frameQueue     chan *pb.Message
	proverQueue    chan *pb.Message
	peerInfoQueue  chan *pb.Message
	alertQueue     chan *pb.Message
	appFramesQueue chan *pb.Message
	shardQueue     chan *pb.Message

	// Handler callbacks (engine provides these)
	handleGlobalConsensusMessage func(*pb.Message)
	handleAppFrameMessage        func(*pb.Message)
	handleShardConsensusMessage  func(*pb.Message)
	handleProverMessage          func(*pb.Message)
	handleFrameMessage           func(context.Context, *pb.Message)
	handlePeerInfoMessage        func(*pb.Message)
	handleAlertMessage           func(*pb.Message)
	handleGlobalProposal         func(*protobufs.GlobalProposal)

	// Pubsub validation callbacks
	validateGlobalConsensusMessage func(peer.ID, *pb.Message) tp2p.ValidationResult
	validateAppFrameMessage        func(peer.ID, *pb.Message) tp2p.ValidationResult
	validateShardConsensusMessage  func(peer.ID, *pb.Message) tp2p.ValidationResult
	validateFrameMessage           func(peer.ID, *pb.Message) tp2p.ValidationResult
	validateProverMessage          func(peer.ID, *pb.Message) tp2p.ValidationResult
	validatePeerInfoMessage        func(peer.ID, *pb.Message) tp2p.ValidationResult
	validateAlertMessage           func(peer.ID, *pb.Message) tp2p.ValidationResult

	// Access to engine state needed by router
	isConsensusParticipant func() bool
	broadcastGlobalMessage func([]byte, []byte)
	initMixnet             func()
	haltCtx                context.Context
	shutdownSignal         func() <-chan struct{}

	// References to engine queues the router writes to but doesn't own
	globalProposalQueue chan *protobufs.GlobalProposal
}

// NewMessageRouter creates a MessageRouter with the given queue capacities and
// callback wiring. The caller is responsible for providing all callbacks before
// calling any subscribe or process methods.
func NewMessageRouter(
	logger *zap.Logger,
	pubsub tp2p.PubSub,
	haltCtx context.Context,
	shutdownSignal func() <-chan struct{},
	globalProposalQueue chan *protobufs.GlobalProposal,
) *MessageRouter {
	return &MessageRouter{
		logger:              logger,
		pubsub:              pubsub,
		haltCtx:             haltCtx,
		shutdownSignal:      shutdownSignal,
		globalProposalQueue: globalProposalQueue,

		consensusQueue: make(chan *pb.Message, 1000),
		frameQueue:     make(chan *pb.Message, 100),
		proverQueue:    make(chan *pb.Message, 1000),
		appFramesQueue: make(chan *pb.Message, 10000),
		peerInfoQueue:  make(chan *pb.Message, 1000),
		alertQueue:     make(chan *pb.Message, 100),
		shardQueue:     make(chan *pb.Message, 10000),
	}
}

// ---------------------------------------------------------------------------
// Pubsub subscriptions
// ---------------------------------------------------------------------------

func (r *MessageRouter) subscribeToGlobalConsensus() error {
	if !r.isConsensusParticipant() {
		return nil
	}

	r.initMixnet()

	if err := r.pubsub.Subscribe(
		GLOBAL_CONSENSUS_BITMASK,
		func(message *pb.Message) error {
			select {
			case <-r.haltCtx.Done():
				return nil
			case <-r.shutdownSignal():
				return errors.New("context cancelled")
			case r.consensusQueue <- message:
				return nil
			default:
				r.logger.Warn("global message queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		return errors.Wrap(err, "subscribe to global consensus")
	}

	// Register frame validator
	if err := r.pubsub.RegisterValidator(
		GLOBAL_CONSENSUS_BITMASK,
		func(peerID peer.ID, message *pb.Message) tp2p.ValidationResult {
			return r.validateGlobalConsensusMessage(peerID, message)
		},
		true,
	); err != nil {
		return errors.Wrap(err, "subscribe to global consensus")
	}

	// Initiate a bulk subscribe to entire bitmask
	if err := r.pubsub.Subscribe(
		bytes.Repeat([]byte{0xff}, 32),
		func(message *pb.Message) error {
			select {
			case <-r.haltCtx.Done():
				return nil
			case <-r.shutdownSignal():
				return errors.New("context cancelled")
			case r.appFramesQueue <- message:
				return nil
			default:
				r.logger.Warn("app frames message queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		r.logger.Error(
			"error while subscribing to app shard consensus channels",
			zap.Error(err),
		)
		return nil
	}

	// Register frame validator
	if err := r.pubsub.RegisterValidator(
		bytes.Repeat([]byte{0xff}, 32),
		func(peerID peer.ID, message *pb.Message) tp2p.ValidationResult {
			return r.validateAppFrameMessage(peerID, message)
		},
		true,
	); err != nil {
		return nil
	}

	return nil
}

func (r *MessageRouter) subscribeToShardConsensusMessages() error {
	if !r.isConsensusParticipant() {
		return nil
	}

	if err := r.pubsub.Subscribe(
		slices.Concat(
			[]byte{0},
			bytes.Repeat([]byte{0xff}, 32),
		),
		func(message *pb.Message) error {
			select {
			case <-r.haltCtx.Done():
				return nil
			case <-r.shutdownSignal():
				return errors.New("context cancelled")
			case r.shardQueue <- message:
				return nil
			default:
				r.logger.Warn("shard consensus queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		return errors.Wrap(err, "subscribe to shard consensus messages")
	}

	// Register frame validator
	if err := r.pubsub.RegisterValidator(
		slices.Concat(
			[]byte{0},
			bytes.Repeat([]byte{0xff}, 32),
		),
		func(peerID peer.ID, message *pb.Message) tp2p.ValidationResult {
			return r.validateShardConsensusMessage(peerID, message)
		},
		true,
	); err != nil {
		return errors.Wrap(err, "subscribe to shard consensus messages")
	}

	return nil
}

func (r *MessageRouter) subscribeToFrameMessages() error {
	// Non-archive nodes receive frames via the archive client (polled or
	// discovered), so they never subscribe to the frame bitmask.
	if !r.isConsensusParticipant() {
		return nil
	}

	if err := r.pubsub.Subscribe(
		GLOBAL_FRAME_BITMASK,
		func(message *pb.Message) error {
			r.broadcastGlobalMessage(message.Data, GLOBAL_FRAME_BITMASK)

			// Don't subscribe if running in consensus, the time reel shouldn't have
			// the frame ahead of time
			if r.isConsensusParticipant() {
				return nil
			}
			select {
			case <-r.haltCtx.Done():
				return nil
			case <-r.shutdownSignal():
				return errors.New("context cancelled")
			case r.frameQueue <- message:
				return nil
			default:
				r.logger.Warn("global frame queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		return errors.Wrap(err, "subscribe to frame messages")
	}

	// Register frame validator
	if err := r.pubsub.RegisterValidator(
		GLOBAL_FRAME_BITMASK,
		func(peerID peer.ID, message *pb.Message) tp2p.ValidationResult {
			return r.validateFrameMessage(peerID, message)
		},
		true,
	); err != nil {
		return errors.Wrap(err, "subscribe to frame messages")
	}

	return nil
}

func (r *MessageRouter) subscribeToProverMessages() error {
	// Non-archive nodes submit prover messages via the archive client, so
	// they never subscribe to the prover bitmask.
	if !r.isConsensusParticipant() {
		return nil
	}

	if err := r.pubsub.Subscribe(
		GLOBAL_PROVER_BITMASK,
		func(message *pb.Message) error {
			r.broadcastGlobalMessage(message.Data, GLOBAL_PROVER_BITMASK)

			if !r.isConsensusParticipant() {
				return nil
			}

			select {
			case <-r.haltCtx.Done():
				return nil
			case <-r.shutdownSignal():
				return errors.New("context cancelled")
			case r.proverQueue <- message:
				r.logger.Debug("received prover message")
				return nil
			default:
				r.logger.Warn("global prover message queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		return errors.Wrap(err, "subscribe to prover messages")
	}

	// Register frame validator
	if err := r.pubsub.RegisterValidator(
		GLOBAL_PROVER_BITMASK,
		func(peerID peer.ID, message *pb.Message) tp2p.ValidationResult {
			return r.validateProverMessage(peerID, message)
		},
		true,
	); err != nil {
		return errors.Wrap(err, "subscribe to prover messages")
	}

	return nil
}

func (r *MessageRouter) subscribeToPeerInfoMessages() error {
	if err := r.pubsub.Subscribe(
		GLOBAL_PEER_INFO_BITMASK,
		func(message *pb.Message) error {
			r.broadcastGlobalMessage(message.Data, GLOBAL_PEER_INFO_BITMASK)

			select {
			case <-r.haltCtx.Done():
				return nil
			case <-r.shutdownSignal():
				return errors.New("context cancelled")
			case r.peerInfoQueue <- message:
				return nil
			default:
				r.logger.Warn("peer info message queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		return errors.Wrap(err, "subscribe to peer info messages")
	}

	// Register frame validator
	if err := r.pubsub.RegisterValidator(
		GLOBAL_PEER_INFO_BITMASK,
		func(peerID peer.ID, message *pb.Message) tp2p.ValidationResult {
			return r.validatePeerInfoMessage(peerID, message)
		},
		true,
	); err != nil {
		return errors.Wrap(err, "subscribe to peer info messages")
	}

	return nil
}

func (r *MessageRouter) subscribeToAlertMessages() error {
	if err := r.pubsub.Subscribe(
		GLOBAL_ALERT_BITMASK,
		func(message *pb.Message) error {
			r.broadcastGlobalMessage(message.Data, GLOBAL_ALERT_BITMASK)

			select {
			case r.alertQueue <- message:
				return nil
			case <-r.shutdownSignal():
				return errors.New("context cancelled")
			default:
				r.logger.Warn("alert message queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		return errors.Wrap(err, "subscribe to alert messages")
	}

	// Register frame validator
	if err := r.pubsub.RegisterValidator(
		GLOBAL_ALERT_BITMASK,
		func(peerID peer.ID, message *pb.Message) tp2p.ValidationResult {
			return r.validateAlertMessage(peerID, message)
		},
		true,
	); err != nil {
		return errors.Wrap(err, "subscribe to alert messages")
	}

	return nil
}

// ---------------------------------------------------------------------------
// Queue processors
// ---------------------------------------------------------------------------

func (r *MessageRouter) processGlobalConsensusMessageQueue(
	ctx lifecycle.SignalerContext,
) {
	if !r.isConsensusParticipant() {
		<-ctx.Done()
		return
	}

	for {
		select {
		case <-r.haltCtx.Done():
			return
		case <-ctx.Done():
			return
		case message := <-r.consensusQueue:
			r.handleGlobalConsensusMessage(message)
		case appmsg := <-r.appFramesQueue:
			r.handleAppFrameMessage(appmsg)
		}
	}
}

func (r *MessageRouter) processShardConsensusMessageQueue(
	ctx lifecycle.SignalerContext,
) {
	if !r.isConsensusParticipant() {
		<-ctx.Done()
		return
	}

	for {
		select {
		case <-r.haltCtx.Done():
			return
		case <-ctx.Done():
			return
		case message := <-r.shardQueue:
			r.handleShardConsensusMessage(message)
		}
	}
}

func (r *MessageRouter) processProverMessageQueue(
	ctx lifecycle.SignalerContext,
) {
	if !r.isConsensusParticipant() {
		r.logger.Debug("prover message queue processor disabled (not archive mode)")
		return
	}

	r.logger.Info("prover message queue processor started")

	for {
		select {
		case <-r.haltCtx.Done():
			return
		case <-ctx.Done():
			return
		case message := <-r.proverQueue:
			r.handleProverMessage(message)
		}
	}
}

func (r *MessageRouter) processFrameMessageQueue(
	ctx lifecycle.SignalerContext,
) {
	for {
		select {
		case <-r.haltCtx.Done():
			return
		case <-ctx.Done():
			return
		case message := <-r.frameQueue:
			r.handleFrameMessage(ctx, message)
		}
	}
}

func (r *MessageRouter) processPeerInfoMessageQueue(
	ctx lifecycle.SignalerContext,
) {
	for {
		select {
		case <-r.haltCtx.Done():
			return
		case <-ctx.Done():
			return
		case message := <-r.peerInfoQueue:
			r.handlePeerInfoMessage(message)
		}
	}
}

func (r *MessageRouter) processAlertMessageQueue(
	ctx lifecycle.SignalerContext,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case message := <-r.alertQueue:
			r.handleAlertMessage(message)
		}
	}
}

func (r *MessageRouter) processGlobalProposalQueue(
	ctx lifecycle.SignalerContext,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case proposal := <-r.globalProposalQueue:
			r.handleGlobalProposal(proposal)
		}
	}
}
