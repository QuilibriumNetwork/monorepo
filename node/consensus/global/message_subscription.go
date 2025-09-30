package global

import (
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

	GenerateThreeBitSlices(func(bitmask []byte) bool {
		b := slices.Clone(bitmask)
		if err := e.pubsub.Subscribe(
			b,
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
			return false
		}

		// Register frame validator
		if err := e.pubsub.RegisterValidator(
			b,
			func(peerID peer.ID, message *pb.Message) tp2p.ValidationResult {
				return e.validateAppFrameMessage(peerID, message)
			},
			true,
		); err != nil {
			return false
		}

		return true
	})

	return nil
}

func GenerateThreeBitSlices(emit func(b []byte) bool) {
	var buf [32]byte

	set := func(pos int) { buf[pos>>3] |= 1 << uint(pos&7) }
	zero := func() {
		for i := range buf {
			buf[i] = 0
		}
	}

	for i := 0; i < 256; i++ {
		for j := i + 1; j < 256; j++ {
			for k := j + 1; k < 256; k++ {
				zero()
				set(i)
				set(j)
				set(k)
				if !emit(buf[:]) {
					return
				}
			}
		}
	}
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
				return nil
			}

			select {
			case <-e.haltCtx.Done():
				return nil
			case e.globalProverMessageQueue <- message:
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
