package app

import (
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
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
			case e.consensusMessageQueue <- message:
				return nil
			case <-e.ctx.Done():
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

func (e *AppConsensusEngine) subscribeToGlobalProverMessages() error {
	if err := e.pubsub.Subscribe(
		e.getGlobalProverMessageBitmask(),
		func(message *pb.Message) error {
			return nil
		},
	); err != nil {
		return errors.Wrap(err, "subscribe to consensus messages")
	}

	// Register consensus message validator
	if err := e.pubsub.RegisterValidator(
		e.getGlobalProverMessageBitmask(),
		func(peerID peer.ID, message *pb.Message) p2p.ValidationResult {
			return e.validateGlobalProverMessage(peerID, message)
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
			case <-e.ctx.Done():
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
			select {
			case e.frameMessageQueue <- message:
				return nil
			case <-e.ctx.Done():
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

func (e *AppConsensusEngine) subscribeToGlobalFrameMessages() error {
	if err := e.pubsub.Subscribe(
		e.getGlobalFrameMessageBitmask(),
		func(message *pb.Message) error {
			select {
			case e.globalFrameMessageQueue <- message:
				return nil
			case <-e.ctx.Done():
				return errors.New("context cancelled")
			default:
				e.logger.Warn("global message queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		return errors.Wrap(err, "subscribe to global frame messages")
	}

	// Register frame validator
	if err := e.pubsub.RegisterValidator(
		e.getGlobalFrameMessageBitmask(),
		func(peerID peer.ID, message *pb.Message) p2p.ValidationResult {
			return e.validateGlobalFrameMessage(peerID, message)
		},
		true,
	); err != nil {
		return errors.Wrap(err, "subscribe to global frame messages")
	}

	return nil
}

func (e *AppConsensusEngine) subscribeToGlobalAlertMessages() error {
	if err := e.pubsub.Subscribe(
		e.getGlobalAlertMessageBitmask(),
		func(message *pb.Message) error {
			select {
			case e.globalAlertMessageQueue <- message:
				return nil
			case <-e.ctx.Done():
				return errors.New("context cancelled")
			default:
				e.logger.Warn("global alert queue full, dropping message")
				return nil
			}
		},
	); err != nil {
		return errors.Wrap(err, "subscribe to global alert messages")
	}

	// Register alert validator
	if err := e.pubsub.RegisterValidator(
		e.getGlobalAlertMessageBitmask(),
		func(peerID peer.ID, message *pb.Message) p2p.ValidationResult {
			return e.validateAlertMessage(peerID, message)
		},
		true,
	); err != nil {
		return errors.Wrap(err, "subscribe to global alert messages")
	}

	return nil
}

func (e *AppConsensusEngine) subscribeToPeerInfoMessages() error {
	if err := e.pubsub.Subscribe(
		e.getGlobalPeerInfoMessageBitmask(),
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
		e.getGlobalPeerInfoMessageBitmask(),
		func(peerID peer.ID, message *pb.Message) p2p.ValidationResult {
			return e.validatePeerInfoMessage(peerID, message)
		},
		true,
	); err != nil {
		return errors.Wrap(err, "subscribe to peer info messages")
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
			case <-e.ctx.Done():
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
