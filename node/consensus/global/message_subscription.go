package global

import (
	"bytes"
	"slices"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/rpm"
	tp2p "source.quilibrium.com/quilibrium/monorepo/types/p2p"
)

func (e *GlobalConsensusEngine) subscribeToGlobalConsensus() error {
	if e.config.P2P.Network != 99 && !e.config.Engine.ArchiveMode {
		return nil
	}

	provingKey, _, _, _ := e.GetProvingKey(e.config.Engine)
	e.mixnet = rpm.NewRPMMixnet(e.logger, provingKey, e.proverRegistry, nil)

	if err := e.pubsub.Subscribe(
		GLOBAL_CONSENSUS_BITMASK,
		func(message *pb.Message) error {
			select {
			case <-e.haltCtx.Done():
				return nil
			case e.globalConsensusMessageQueue <- message:
				return nil
			case <-e.ctx.Done():
				return errors.New("context cancelled")
			default:
				e.logger.Warn("global message queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		return errors.Wrap(err, "subscribe to global consensus")
	}

	// Register frame validator
	if err := e.pubsub.RegisterValidator(
		GLOBAL_CONSENSUS_BITMASK,
		func(peerID peer.ID, message *pb.Message) tp2p.ValidationResult {
			return e.validateGlobalConsensusMessage(peerID, message)
		},
		true,
	); err != nil {
		return errors.Wrap(err, "subscribe to global consensus")
	}

	// Initiate a bulk subscribe to entire bitmask
	if err := e.pubsub.Subscribe(
		bytes.Repeat([]byte{0xff}, 32),
		func(message *pb.Message) error {
			select {
			case <-e.haltCtx.Done():
				return nil
			case e.appFramesMessageQueue <- message:
				return nil
			case <-e.ctx.Done():
				return errors.New("context cancelled")
			default:
				e.logger.Warn("app frames message queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		e.logger.Error(
			"error while subscribing to app shard consensus channels",
			zap.Error(err),
		)
		return nil
	}

	// Register frame validator
	if err := e.pubsub.RegisterValidator(
		bytes.Repeat([]byte{0xff}, 32),
		func(peerID peer.ID, message *pb.Message) tp2p.ValidationResult {
			return e.validateAppFrameMessage(peerID, message)
		},
		true,
	); err != nil {
		return nil
	}

	return nil
}

func (e *GlobalConsensusEngine) subscribeToShardConsensusMessages() error {
	if err := e.pubsub.Subscribe(
		slices.Concat(
			[]byte{0},
			bytes.Repeat([]byte{0xff}, 32),
		),
		func(message *pb.Message) error {
			select {
			case <-e.haltCtx.Done():
				return nil
			case e.shardConsensusMessageQueue <- message:
				return nil
			case <-e.ctx.Done():
				return errors.New("context cancelled")
			default:
				e.logger.Warn("shard consensus queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		return errors.Wrap(err, "subscribe to shard consensus messages")
	}

	// Register frame validator
	if err := e.pubsub.RegisterValidator(
		slices.Concat(
			[]byte{0},
			bytes.Repeat([]byte{0xff}, 32),
		),
		func(peerID peer.ID, message *pb.Message) tp2p.ValidationResult {
			return e.validateShardConsensusMessage(peerID, message)
		},
		true,
	); err != nil {
		return errors.Wrap(err, "subscribe to shard consensus messages")
	}

	return nil
}

func (e *GlobalConsensusEngine) subscribeToFrameMessages() error {
	if err := e.pubsub.Subscribe(
		GLOBAL_FRAME_BITMASK,
		func(message *pb.Message) error {
			select {
			case <-e.haltCtx.Done():
				return nil
			case e.globalFrameMessageQueue <- message:
				return nil
			case <-e.ctx.Done():
				return errors.New("context cancelled")
			default:
				e.logger.Warn("global frame queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		return errors.Wrap(err, "subscribe to frame messages")
	}

	// Register frame validator
	if err := e.pubsub.RegisterValidator(
		GLOBAL_FRAME_BITMASK,
		func(peerID peer.ID, message *pb.Message) tp2p.ValidationResult {
			return e.validateFrameMessage(peerID, message)
		},
		true,
	); err != nil {
		return errors.Wrap(err, "subscribe to frame messages")
	}

	return nil
}

func (e *GlobalConsensusEngine) subscribeToProverMessages() error {
	if err := e.pubsub.Subscribe(
		GLOBAL_PROVER_BITMASK,
		func(message *pb.Message) error {
			if e.config.P2P.Network != 99 && !e.config.Engine.ArchiveMode {
				e.logger.Debug("dropping prover message, not in archive mode")
				return nil
			}

			select {
			case <-e.haltCtx.Done():
				return nil
			case e.globalProverMessageQueue <- message:
				e.logger.Debug("received prover message")
				return nil
			case <-e.ctx.Done():
				return errors.New("context cancelled")
			default:
				e.logger.Warn("global prover message queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		return errors.Wrap(err, "subscribe to prover messages")
	}

	// Register frame validator
	if err := e.pubsub.RegisterValidator(
		GLOBAL_PROVER_BITMASK,
		func(peerID peer.ID, message *pb.Message) tp2p.ValidationResult {
			return e.validateProverMessage(peerID, message)
		},
		true,
	); err != nil {
		return errors.Wrap(err, "subscribe to prover messages")
	}

	return nil
}

func (e *GlobalConsensusEngine) subscribeToPeerInfoMessages() error {
	if err := e.pubsub.Subscribe(
		GLOBAL_PEER_INFO_BITMASK,
		func(message *pb.Message) error {
			select {
			case <-e.haltCtx.Done():
				return nil
			case e.globalPeerInfoMessageQueue <- message:
				return nil
			case <-e.ctx.Done():
				return errors.New("context cancelled")
			default:
				e.logger.Warn("peer info message queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		return errors.Wrap(err, "subscribe to peer info messages")
	}

	// Register frame validator
	if err := e.pubsub.RegisterValidator(
		GLOBAL_PEER_INFO_BITMASK,
		func(peerID peer.ID, message *pb.Message) tp2p.ValidationResult {
			return e.validatePeerInfoMessage(peerID, message)
		},
		true,
	); err != nil {
		return errors.Wrap(err, "subscribe to peer info messages")
	}

	return nil
}

func (e *GlobalConsensusEngine) subscribeToAlertMessages() error {
	if err := e.pubsub.Subscribe(
		GLOBAL_ALERT_BITMASK,
		func(message *pb.Message) error {
			select {
			case e.globalAlertMessageQueue <- message:
				return nil
			case <-e.ctx.Done():
				return errors.New("context cancelled")
			default:
				e.logger.Warn("alert message queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		return errors.Wrap(err, "subscribe to alert messages")
	}

	// Register frame validator
	if err := e.pubsub.RegisterValidator(
		GLOBAL_ALERT_BITMASK,
		func(peerID peer.ID, message *pb.Message) tp2p.ValidationResult {
			return e.validateAlertMessage(peerID, message)
		},
		true,
	); err != nil {
		return errors.Wrap(err, "subscribe to alert messages")
	}

	return nil
}
