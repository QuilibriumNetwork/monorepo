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
	_ peer.ID,
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
			proposalValidationDuration.Observe(time.Since(start).Seconds())
		}()

		frame := &protobufs.GlobalFrame{}
		if err := frame.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal frame", zap.Error(err))
			proposalValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		if frametime.GlobalFrameSince(frame) > 20*time.Second {
			proposalValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultIgnore
		}

		if frame.Header.PublicKeySignatureBls48581 == nil ||
			frame.Header.PublicKeySignatureBls48581.PublicKey == nil ||
			frame.Header.PublicKeySignatureBls48581.PublicKey.KeyValue == nil {
			e.logger.Debug("global frame validation missing signature")
			proposalValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		valid, err := e.frameValidator.Validate(frame)
		if err != nil {
			e.logger.Debug("global frame validation error", zap.Error(err))
			proposalValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		if !valid {
			e.logger.Debug("invalid global frame")
			proposalValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		proposalValidationTotal.WithLabelValues("accept").Inc()

	case protobufs.ProverLivenessCheckType:
		start := time.Now()
		defer func() {
			livenessCheckValidationDuration.Observe(time.Since(start).Seconds())
		}()

		livenessCheck := &protobufs.ProverLivenessCheck{}
		if err := livenessCheck.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal liveness check", zap.Error(err))
			livenessCheckValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		now := time.Now().UnixMilli()
		if livenessCheck.Timestamp > now+5000 ||
			livenessCheck.Timestamp < now-5000 {
			return tp2p.ValidationResultIgnore
		}

		// Validate the liveness check
		if err := livenessCheck.Validate(); err != nil {
			e.logger.Debug("invalid liveness check", zap.Error(err))
			livenessCheckValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		livenessCheckValidationTotal.WithLabelValues("accept").Inc()

	case protobufs.FrameVoteType:
		start := time.Now()
		defer func() {
			voteValidationDuration.Observe(time.Since(start).Seconds())
		}()

		vote := &protobufs.FrameVote{}
		if err := vote.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal vote", zap.Error(err))
			voteValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		now := time.Now().UnixMilli()
		if vote.Timestamp > now+5000 || vote.Timestamp < now-5000 {
			return tp2p.ValidationResultIgnore
		}

		// Validate the vote
		if err := vote.Validate(); err != nil {
			e.logger.Debug("invalid vote", zap.Error(err))
			voteValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		voteValidationTotal.WithLabelValues("accept").Inc()

	case protobufs.FrameConfirmationType:
		start := time.Now()
		defer func() {
			confirmationValidationDuration.Observe(time.Since(start).Seconds())
		}()

		confirmation := &protobufs.FrameConfirmation{}
		if err := confirmation.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal confirmation", zap.Error(err))
			confirmationValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		now := time.Now().UnixMilli()
		if confirmation.Timestamp > now+5000 ||
			confirmation.Timestamp < now-5000 {
			return tp2p.ValidationResultIgnore
		}

		// Validate the confirmation
		if err := confirmation.Validate(); err != nil {
			e.logger.Debug("invalid confirmation", zap.Error(err))
			confirmationValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		confirmationValidationTotal.WithLabelValues("accept").Inc()

	default:
		e.logger.Debug("received unknown type", zap.Uint32("type", typePrefix))
		return tp2p.ValidationResultIgnore
	}

	return tp2p.ValidationResultAccept
}

func (e *GlobalConsensusEngine) validateShardConsensusMessage(
	_ peer.ID,
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
		start := time.Now()
		defer func() {
			shardProposalValidationDuration.Observe(time.Since(start).Seconds())
		}()

		frame := &protobufs.AppShardFrame{}
		if err := frame.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal frame", zap.Error(err))
			shardProposalValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		if frame.Header == nil {
			e.logger.Debug("frame has no header")
			shardProposalValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		if frametime.AppFrameSince(frame) > 20*time.Second {
			shardProposalValidationTotal.WithLabelValues("ignore").Inc()
			return tp2p.ValidationResultIgnore
		}

		if frame.Header.PublicKeySignatureBls48581 != nil {
			e.logger.Debug("frame validation has signature")
			shardProposalValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		valid, err := e.appFrameValidator.Validate(frame)
		if err != nil {
			e.logger.Debug("frame validation error", zap.Error(err))
			shardProposalValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		if !valid {
			e.logger.Debug("invalid app frame")
			shardProposalValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		shardProposalValidationTotal.WithLabelValues("accept").Inc()

	case protobufs.ProverLivenessCheckType:
		start := time.Now()
		defer func() {
			shardLivenessCheckValidationDuration.Observe(time.Since(start).Seconds())
		}()

		livenessCheck := &protobufs.ProverLivenessCheck{}
		if err := livenessCheck.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal liveness check", zap.Error(err))
			shardLivenessCheckValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		now := time.Now().UnixMilli()
		if livenessCheck.Timestamp > now+500 ||
			livenessCheck.Timestamp < now-1000 {
			shardLivenessCheckValidationTotal.WithLabelValues("ignore").Inc()
			return tp2p.ValidationResultIgnore
		}

		if err := livenessCheck.Validate(); err != nil {
			e.logger.Debug("failed to validate liveness check", zap.Error(err))
			shardLivenessCheckValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		shardLivenessCheckValidationTotal.WithLabelValues("accept").Inc()

	case protobufs.FrameVoteType:
		start := time.Now()
		defer func() {
			shardVoteValidationDuration.Observe(time.Since(start).Seconds())
		}()

		vote := &protobufs.FrameVote{}
		if err := vote.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal vote", zap.Error(err))
			shardVoteValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		now := time.Now().UnixMilli()
		if vote.Timestamp > now+5000 || vote.Timestamp < now-5000 {
			shardVoteValidationTotal.WithLabelValues("ignore").Inc()
			return tp2p.ValidationResultIgnore
		}

		if err := vote.Validate(); err != nil {
			e.logger.Debug("failed to validate vote", zap.Error(err))
			shardVoteValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		shardVoteValidationTotal.WithLabelValues("accept").Inc()

	case protobufs.FrameConfirmationType:
		start := time.Now()
		defer func() {
			shardConfirmationValidationDuration.Observe(time.Since(start).Seconds())
		}()

		confirmation := &protobufs.FrameConfirmation{}
		if err := confirmation.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal confirmation", zap.Error(err))
			shardConfirmationValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		now := time.Now().UnixMilli()
		if confirmation.Timestamp > now+5000 || confirmation.Timestamp < now-5000 {
			shardConfirmationValidationTotal.WithLabelValues("ignore").Inc()
			return tp2p.ValidationResultIgnore
		}

		if err := confirmation.Validate(); err != nil {
			e.logger.Debug("failed to validate confirmation", zap.Error(err))
			shardConfirmationValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		shardConfirmationValidationTotal.WithLabelValues("accept").Inc()

	default:
		return tp2p.ValidationResultReject
	}

	return tp2p.ValidationResultAccept
}

func (e *GlobalConsensusEngine) validateProverMessage(
	peerID peer.ID,
	message *pb.Message,
) tp2p.ValidationResult {
	e.logger.Debug(
		"validating prover message from peer",
		zap.String("peer_id", peerID.String()),
	)
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
		e.logger.Debug(
			"validating message bundle from peer",
			zap.String("peer_id", peerID.String()),
		)
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
		if messageBundle.Timestamp > now+5000 ||
			messageBundle.Timestamp < now-5000 {
			e.logger.Debug("message too late or too early")
			return tp2p.ValidationResultIgnore
		}

	default:
		e.logger.Debug("received unknown type", zap.Uint32("type", typePrefix))
		return tp2p.ValidationResultIgnore
	}

	return tp2p.ValidationResultAccept
}

func (e *GlobalConsensusEngine) validateAppFrameMessage(
	_ peer.ID,
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
		start := time.Now()
		defer func() {
			shardFrameValidationDuration.Observe(time.Since(start).Seconds())
		}()

		frame := &protobufs.AppShardFrame{}
		if err := frame.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal frame", zap.Error(err))
			shardFrameValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		if frame.Header.PublicKeySignatureBls48581 == nil ||
			frame.Header.PublicKeySignatureBls48581.PublicKey == nil ||
			frame.Header.PublicKeySignatureBls48581.PublicKey.KeyValue == nil {
			e.logger.Debug("frame validation missing signature")
			shardFrameValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		valid, err := e.appFrameValidator.Validate(frame)
		if err != nil {
			e.logger.Debug("frame validation error", zap.Error(err))
			shardFrameValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		if !valid {
			e.logger.Debug("invalid frame")
			shardFrameValidationTotal.WithLabelValues("reject").Inc()
			return tp2p.ValidationResultReject
		}

		if frametime.AppFrameSince(frame) > 20*time.Second {
			shardFrameValidationTotal.WithLabelValues("ignore").Inc()
			return tp2p.ValidationResultIgnore
		}

		shardFrameValidationTotal.WithLabelValues("accept").Inc()

	default:
		return tp2p.ValidationResultReject
	}

	return tp2p.ValidationResultAccept
}

func (e *GlobalConsensusEngine) validateFrameMessage(
	_ peer.ID,
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
			frameValidationTotal.WithLabelValues("ignore").Inc()
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
	_ peer.ID,
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

		now := time.Now().UnixMilli()

		if peerInfo.Timestamp < now-1000 {
			e.logger.Debug("peer info timestamp too old",
				zap.Int64("peer_timestamp", peerInfo.Timestamp),
			)
			return tp2p.ValidationResultIgnore
		}

		if peerInfo.Timestamp > now+5000 {
			e.logger.Debug("peer info timestamp too far in future",
				zap.Int64("peer_timestamp", peerInfo.Timestamp),
			)
			return tp2p.ValidationResultIgnore
		}
	case protobufs.KeyRegistryType:
		keyRegistry := &protobufs.KeyRegistry{}
		if err := keyRegistry.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal key registry", zap.Error(err))
			return tp2p.ValidationResultReject
		}

		err := keyRegistry.Validate()
		if err != nil {
			e.logger.Debug("key registry validation error", zap.Error(err))
			return tp2p.ValidationResultReject
		}

		now := time.Now().UnixMilli()

		if int64(keyRegistry.LastUpdated) < now-1000 {
			e.logger.Debug("key registry timestamp too old")
			return tp2p.ValidationResultIgnore
		}

		if int64(keyRegistry.LastUpdated) > now+5000 {
			e.logger.Debug("key registry timestamp too far in future")
			return tp2p.ValidationResultIgnore
		}
	default:
		e.logger.Debug("received unknown type", zap.Uint32("type", typePrefix))
		return tp2p.ValidationResultIgnore
	}

	return tp2p.ValidationResultAccept
}

func (e *GlobalConsensusEngine) validateAlertMessage(
	_ peer.ID,
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
