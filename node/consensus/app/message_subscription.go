package app

import (
	"bytes"
	"context"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/global"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/rpm"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
)

func (e *AppConsensusEngine) subscribeToConsensusMessages() error {
	proverKey, _, _, _ := e.GetProvingKey(e.config.Engine)
	e.mixnet = rpm.NewRPMMixnet(
		e.logger,
		proverKey,
		e.proverRegistry,
		e.appAddress,
	)

	if err := e.pubsub.Subscribe(
		e.getConsensusMessageBitmask(),
		func(message *pb.Message) error {
			select {
			case <-e.haltCtx.Done():
				return nil
			case e.consensusMessageQueue <- message:
				return nil
			case <-e.ShutdownSignal():
				return errors.New("context cancelled")
			default:
				e.logger.Warn("consensus message queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		return errors.Wrap(err, "subscribe to consensus messages")
	}

	// Register consensus message validator
	if err := e.pubsub.RegisterValidator(
		e.getConsensusMessageBitmask(),
		func(peerID peer.ID, message *pb.Message) p2p.ValidationResult {
			return e.validateConsensusMessage(peerID, message)
		},
		true,
	); err != nil {
		return errors.Wrap(err, "subscribe to consensus messages")
	}

	return nil
}


func (e *AppConsensusEngine) subscribeToProverMessages() error {
	if err := e.pubsub.Subscribe(
		e.getProverMessageBitmask(),
		func(message *pb.Message) error {
			select {
			case <-e.haltCtx.Done():
				return nil
			case e.proverMessageQueue <- message:
				e.logger.Debug("got prover message")
				return nil
			case <-e.ShutdownSignal():
				return errors.New("context cancelled")
			default:
				e.logger.Warn("prover message queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		return errors.Wrap(err, "subscribe to prover messages")
	}

	// Register frame validator
	if err := e.pubsub.RegisterValidator(
		e.getProverMessageBitmask(),
		func(peerID peer.ID, message *pb.Message) p2p.ValidationResult {
			return e.validateProverMessage(peerID, message)
		},
		true,
	); err != nil {
		return errors.Wrap(err, "subscribe to prover messages")
	}

	return nil
}

func (e *AppConsensusEngine) subscribeToFrameMessages() error {
	if err := e.pubsub.Subscribe(
		e.getFrameMessageBitmask(),
		func(message *pb.Message) error {
			if e.IsInProverTrie(e.getProverAddress()) {
				return nil
			}

			select {
			case <-e.haltCtx.Done():
				return nil
			case e.frameMessageQueue <- message:
				return nil
			case <-e.ShutdownSignal():
				return errors.New("context cancelled")
			default:
				e.logger.Warn("app message queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		return errors.Wrap(err, "subscribe to frame messages")
	}

	// Register frame validator
	if err := e.pubsub.RegisterValidator(
		e.getFrameMessageBitmask(),
		func(peerID peer.ID, message *pb.Message) p2p.ValidationResult {
			return e.validateFrameMessage(peerID, message)
		},
		true,
	); err != nil {
		return errors.Wrap(err, "subscribe to frame messages")
	}

	return nil
}


func (e *AppConsensusEngine) subscribeToDispatchMessages() error {
	if err := e.pubsub.Subscribe(
		e.getDispatchMessageBitmask(),
		func(message *pb.Message) error {
			select {
			case e.dispatchMessageQueue <- message:
				return nil
			case <-e.ShutdownSignal():
				return errors.New("context cancelled")
			default:
				e.logger.Warn("dispatch queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		return errors.Wrap(err, "subscribe to dispatch messages")
	}

	// Register dispatch validator
	if err := e.pubsub.RegisterValidator(
		e.getDispatchMessageBitmask(),
		func(peerID peer.ID, message *pb.Message) p2p.ValidationResult {
			return e.validateDispatchMessage(peerID, message)
		},
		true,
	); err != nil {
		return errors.Wrap(err, "subscribe to dispatch messages")
	}

	return nil
}

func (e *AppConsensusEngine) streamGlobalMessagesFromMaster(
	ctx lifecycle.SignalerContext,
) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := e.ensureGlobalClient(); err != nil {
			e.logger.Warn("global message stream: failed to connect to master",
				zap.Error(err),
			)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		stream, err := e.globalClient.StreamGlobalMessages(
			ctx,
			&protobufs.StreamGlobalMessagesRequest{},
		)
		if err != nil {
			e.logger.Warn("global message stream: failed to open stream",
				zap.Error(err),
			)
			e.resetGlobalClient()
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		e.logger.Info("connected to master global message stream")
		e.receiveGlobalMessages(ctx, stream)

		e.logger.Warn("global message stream disconnected, reconnecting")
		e.resetGlobalClient()
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (e *AppConsensusEngine) receiveGlobalMessages(
	ctx lifecycle.SignalerContext,
	stream protobufs.GlobalService_StreamGlobalMessagesClient,
) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return
			}
			e.logger.Warn("global message stream: recv error",
				zap.Error(err),
			)
			return
		}

		pbMsg := &pb.Message{
			Data:    msg.Data,
			Bitmask: msg.Bitmask,
		}

		switch {
		case bytes.Equal(msg.Bitmask, global.GLOBAL_FRAME_BITMASK):
			select {
			case e.globalFrameMessageQueue <- pbMsg:
			default:
			}
		case bytes.Equal(msg.Bitmask, global.GLOBAL_ALERT_BITMASK):
			select {
			case e.globalAlertMessageQueue <- pbMsg:
			default:
			}
		case bytes.Equal(msg.Bitmask, global.GLOBAL_PEER_INFO_BITMASK):
			select {
			case e.globalPeerInfoMessageQueue <- pbMsg:
			default:
			}
		// GLOBAL_PROVER_BITMASK: intentionally not dispatched (workers discard)
		}
	}
}
