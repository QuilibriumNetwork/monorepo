package global

import (
	"encoding/binary"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/frametime"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	tp2p "source.quilibrium.com/quilibrium/monorepo/types/p2p"
)

func (e *GlobalConsensusEngine) validateGlobalConsensusMessage(
	peerID peer.ID,
	message *pb.Message,
) tp2p.ValidationResult {
	// Check if data is long enough to contain type prefix
	if len(message.Data) < 4 {
		e.logger.Error(
			"message too short",
			zap.Int("data_length", len(message.Data)),
		)
		return tp2p.ValidationResultReject
	}

	// Read type prefix from first 4 bytes
	typePrefix := binary.BigEndian.Uint32(message.Data[:4])

	switch typePrefix {
	case protobufs.GlobalFrameType:
		start := time.Now()
		defer func() {
			frameValidationDuration.Observe(time.Since(start).Seconds())
		}()

		frame := &protobufs.GlobalFrame{}
		if err := frame.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal frame", zap.Error(err))
			frameValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		if frame.Header.PublicKeySignatureBls48581 == nil ||
			frame.Header.PublicKeySignatureBls48581.PublicKey == nil ||
			frame.Header.PublicKeySignatureBls48581.PublicKey.KeyValue == nil {
			e.logger.Debug("global frame validation missing signature")
			frameValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		valid, err := e.frameValidator.Validate(frame)
		if err != nil {
			e.logger.Debug("global frame validation error", zap.Error(err))
			frameValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		if !valid {
			frameValidationTotal.WithLabelValues("reject").Inc()
			e.logger.Debug("invalid global frame")
			return tp2p.ValidationResultReject
		}

		frameValidationTotal.WithLabelValues("accept").Inc()

	case protobufs.ProverLivenessCheckType:
		livenessCheck := &protobufs.ProverLivenessCheck{}
		if err := livenessCheck.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal liveness check", zap.Error(err))
			return tp2p.ValidationResultReject
		}

		// Validate the liveness check
		if err := livenessCheck.Validate(); err != nil {
			e.logger.Debug("invalid liveness check", zap.Error(err))
			return tp2p.ValidationResultReject
		}

	case protobufs.FrameVoteType:
		vote := &protobufs.FrameVote{}
		if err := vote.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal vote", zap.Error(err))
			return tp2p.ValidationResultReject
		}

		// Validate the vote
		if err := vote.Validate(); err != nil {
			e.logger.Debug("invalid vote", zap.Error(err))
			return tp2p.ValidationResultReject
		}

	case protobufs.FrameConfirmationType:
		confirmation := &protobufs.FrameConfirmation{}
		if err := confirmation.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal confirmation", zap.Error(err))
			return tp2p.ValidationResultReject
		}

		// Validate the confirmation
		if err := confirmation.Validate(); err != nil {
			e.logger.Debug("invalid confirmation", zap.Error(err))
			return tp2p.ValidationResultReject
		}

	default:
		e.logger.Debug("received unknown type", zap.Uint32("type", typePrefix))
		return tp2p.ValidationResultIgnore
	}

	frameValidationTotal.WithLabelValues("accept").Inc()
	return tp2p.ValidationResultAccept
}

func (e *GlobalConsensusEngine) validateProverMessage(
	peerID peer.ID,
	message *pb.Message,
) tp2p.ValidationResult {
	// Check if data is long enough to contain type prefix
	if len(message.Data) < 4 {
		e.logger.Error(
			"message too short",
			zap.Int("data_length", len(message.Data)),
		)
		return tp2p.ValidationResultReject
	}

	// Read type prefix from first 4 bytes
	typePrefix := binary.BigEndian.Uint32(message.Data[:4])

	switch typePrefix {

	case protobufs.MessageBundleType:
		// Prover messages come wrapped in MessageBundle
		messageBundle := &protobufs.MessageBundle{}
		if err := messageBundle.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal message bundle", zap.Error(err))
			return tp2p.ValidationResultReject
		}

		if err := messageBundle.Validate(); err != nil {
			e.logger.Debug("invalid request", zap.Error(err))
			return tp2p.ValidationResultReject
		}

		now := time.Now().UnixMilli()
		if messageBundle.Timestamp > now+5000 || messageBundle.Timestamp < now-5000 {
			return tp2p.ValidationResultIgnore
		}

	default:
		e.logger.Debug("received unknown type", zap.Uint32("type", typePrefix))
		return tp2p.ValidationResultIgnore
	}

	return tp2p.ValidationResultAccept
}

func (e *GlobalConsensusEngine) validateAppFrameMessage(
	peerID peer.ID,
	message *pb.Message,
) tp2p.ValidationResult {
	// Check if data is long enough to contain type prefix
	if len(message.Data) < 4 {
		e.logger.Debug(
			"message too short",
			zap.Int("data_length", len(message.Data)),
		)
		return tp2p.ValidationResultReject
	}

	// Read type prefix from first 4 bytes
	typePrefix := binary.BigEndian.Uint32(message.Data[:4])

	switch typePrefix {
	case protobufs.AppShardFrameType:
		frame := &protobufs.AppShardFrame{}
		if err := frame.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal frame", zap.Error(err))
			return tp2p.ValidationResultReject
		}

		if frame.Header.PublicKeySignatureBls48581 == nil ||
			frame.Header.PublicKeySignatureBls48581.PublicKey == nil ||
			frame.Header.PublicKeySignatureBls48581.PublicKey.KeyValue == nil {
			e.logger.Debug("frame validation missing signature")
			return tp2p.ValidationResultReject
		}

		valid, err := e.appFrameValidator.Validate(frame)
		if err != nil {
			e.logger.Debug("frame validation error", zap.Error(err))
			return tp2p.ValidationResultReject
		}

		if !valid {
			e.logger.Debug("invalid frame")
			return tp2p.ValidationResultReject
		}

		if frametime.AppFrameSince(frame) > 20*time.Second {
			return tp2p.ValidationResultIgnore
		}

	default:
		return tp2p.ValidationResultReject
	}

	return tp2p.ValidationResultAccept
}

func (e *GlobalConsensusEngine) validateFrameMessage(
	peerID peer.ID,
	message *pb.Message,
) tp2p.ValidationResult {
	// Check if data is long enough to contain type prefix
	if len(message.Data) < 4 {
		e.logger.Error(
			"message too short",
			zap.Int("data_length", len(message.Data)),
		)
		return tp2p.ValidationResultReject
	}

	// Read type prefix from first 4 bytes
	typePrefix := binary.BigEndian.Uint32(message.Data[:4])

	switch typePrefix {
	case protobufs.GlobalFrameType:
		start := time.Now()
		defer func() {
			frameValidationDuration.Observe(time.Since(start).Seconds())
		}()

		frame := &protobufs.GlobalFrame{}
		if err := frame.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal frame", zap.Error(err))
			frameValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		if frame.Header.PublicKeySignatureBls48581 == nil ||
			frame.Header.PublicKeySignatureBls48581.PublicKey == nil ||
			frame.Header.PublicKeySignatureBls48581.PublicKey.KeyValue == nil {
			e.logger.Debug("global frame validation missing signature")
			frameValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		valid, err := e.frameValidator.Validate(frame)
		if err != nil {
			e.logger.Debug("global frame validation error", zap.Error(err))
			frameValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		if !valid {
			frameValidationTotal.WithLabelValues("reject").Inc()
			e.logger.Debug("invalid global frame")
			return tp2p.ValidationResultReject
		}

		if frametime.GlobalFrameSince(frame) > 20*time.Second {
			return tp2p.ValidationResultIgnore
		}

		frameValidationTotal.WithLabelValues("accept").Inc()
	default:
		e.logger.Debug("received unknown type", zap.Uint32("type", typePrefix))
		return tp2p.ValidationResultIgnore
	}

	return tp2p.ValidationResultAccept
}

func (e *GlobalConsensusEngine) validatePeerInfoMessage(
	peerID peer.ID,
	message *pb.Message,
) tp2p.ValidationResult {
	// Check if data is long enough to contain type prefix
	if len(message.Data) < 4 {
		e.logger.Error(
			"message too short",
			zap.Int("data_length", len(message.Data)),
		)
		return tp2p.ValidationResultReject
	}

	// Read type prefix from first 4 bytes
	typePrefix := binary.BigEndian.Uint32(message.Data[:4])

	switch typePrefix {
	case protobufs.PeerInfoType:
		peerInfo := &protobufs.PeerInfo{}
		if err := peerInfo.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal peer info", zap.Error(err))
			return tp2p.ValidationResultReject
		}

		err := peerInfo.Validate()
		if err != nil {
			e.logger.Debug("peer info validation error", zap.Error(err))
			return tp2p.ValidationResultReject
		}

		// Validate timestamp: reject if older than 1 minute or newer than 5 minutes
		// from now
		now := time.Now().UnixMilli()
		oneMinuteAgo := now - (1 * 60 * 1000)     // 1 minute ago
		fiveMinutesLater := now + (5 * 60 * 1000) // 5 minutes from now

		if peerInfo.Timestamp < oneMinuteAgo {
			e.logger.Debug("peer info timestamp too old",
				zap.Int64("peer_timestamp", peerInfo.Timestamp),
				zap.Int64("cutoff", oneMinuteAgo),
			)
			return tp2p.ValidationResultIgnore
		}

		if peerInfo.Timestamp > fiveMinutesLater {
			e.logger.Debug("peer info timestamp too far in future",
				zap.Int64("peer_timestamp", peerInfo.Timestamp),
				zap.Int64("cutoff", fiveMinutesLater),
			)
			return tp2p.ValidationResultIgnore
		}

	default:
		e.logger.Debug("received unknown type", zap.Uint32("type", typePrefix))
		return tp2p.ValidationResultIgnore
	}

	return tp2p.ValidationResultAccept
}

func (e *GlobalConsensusEngine) validateAlertMessage(
	peerID peer.ID,
	message *pb.Message,
) tp2p.ValidationResult {
	// Check if data is long enough to contain type prefix
	if len(message.Data) < 4 {
		e.logger.Error(
			"message too short",
			zap.Int("data_length", len(message.Data)),
		)
		return tp2p.ValidationResultReject
	}

	// Read type prefix from first 4 bytes
	typePrefix := binary.BigEndian.Uint32(message.Data[:4])

	switch typePrefix {
	case protobufs.GlobalAlertType:
		alert := &protobufs.GlobalAlert{}
		if err := alert.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal alert", zap.Error(err))
			return tp2p.ValidationResultReject
		}

		err := alert.Validate()
		if err != nil {
			e.logger.Debug("alert validation error", zap.Error(err))
			return tp2p.ValidationResultReject
		}

		valid, err := e.keyManager.ValidateSignature(
			crypto.KeyTypeEd448,
			e.alertPublicKey,
			[]byte(alert.Message),
			alert.Signature,
			[]byte("GLOBAL_ALERT"),
		)
		if !valid || err != nil {
			e.logger.Debug("alert signature invalid")
			return tp2p.ValidationResultReject
		}

	default:
		e.logger.Debug("received unknown type", zap.Uint32("type", typePrefix))
		return tp2p.ValidationResultIgnore
	}

	return tp2p.ValidationResultAccept
}
