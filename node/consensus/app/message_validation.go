package app

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/frametime"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
)

func (e *AppConsensusEngine) validateConsensusMessage(
	_ peer.ID,
	message *pb.Message,
) p2p.ValidationResult {
	// Check if data is long enough to contain type prefix
	if len(message.Data) < 4 {
		e.logger.Debug(
			"message too short",
			zap.Int("data_length", len(message.Data)),
		)
		frameValidationTotal.WithLabelValues(e.appAddressHex, "reject").Inc()
		return p2p.ValidationResultReject
	}

	// Read type prefix from first 4 bytes
	typePrefix := binary.BigEndian.Uint32(message.Data[:4])

	switch typePrefix {
	case protobufs.AppShardProposalType:
		timer := prometheus.NewTimer(
			proposalValidationDuration.WithLabelValues(e.appAddressHex),
		)
		defer timer.ObserveDuration()

		proposal := &protobufs.AppShardProposal{}
		if err := proposal.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal frame", zap.Error(err))
			proposalValidationTotal.WithLabelValues(e.appAddressHex, "reject").Inc()
			return p2p.ValidationResultReject
		}

		if err := proposal.Validate(); err != nil {
			e.logger.Error("invalid proposal", zap.Error(err))
			proposalValidationTotal.WithLabelValues(e.appAddressHex, "reject").Inc()
			return p2p.ValidationResultReject
		}

		if !bytes.Equal(proposal.State.Header.Address, e.appAddress) {
			proposalValidationTotal.WithLabelValues(e.appAddressHex, "ignore").Inc()
			return p2p.ValidationResultIgnore
		}

		if e.forks.FinalizedRank() > proposal.GetRank() {
			proposalValidationTotal.WithLabelValues(e.appAddressHex, "ignore").Inc()
			return p2p.ValidationResultIgnore
		}

		if proposal.State.Header.PublicKeySignatureBls48581 != nil {
			e.logger.Debug("frame validation has signature")
			proposalValidationTotal.WithLabelValues(e.appAddressHex, "reject").Inc()
			return p2p.ValidationResultReject
		}

		valid, err := e.frameValidator.Validate(proposal.State)
		if err != nil {
			e.logger.Debug("frame validation error", zap.Error(err))
			proposalValidationTotal.WithLabelValues(e.appAddressHex, "reject").Inc()
			return p2p.ValidationResultReject
		}

		if !valid {
			e.logger.Debug("invalid frame")
			proposalValidationTotal.WithLabelValues(e.appAddressHex, "reject").Inc()
			return p2p.ValidationResultReject
		}

		proposalValidationTotal.WithLabelValues(e.appAddressHex, "accept").Inc()

	case protobufs.ProposalVoteType:
		timer := prometheus.NewTimer(
			voteValidationDuration.WithLabelValues(e.appAddressHex),
		)
		defer timer.ObserveDuration()

		vote := &protobufs.ProposalVote{}
		if err := vote.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal vote", zap.Error(err))
			voteValidationTotal.WithLabelValues(e.appAddressHex, "reject").Inc()
			return p2p.ValidationResultReject
		}

		now := uint64(time.Now().UnixMilli())
		if vote.Timestamp > now+5000 || vote.Timestamp < now-5000 {
			voteValidationTotal.WithLabelValues(e.appAddressHex, "ignore").Inc()
			return p2p.ValidationResultIgnore
		}

		if err := vote.Validate(); err != nil {
			e.logger.Debug("failed to validate vote", zap.Error(err))
			voteValidationTotal.WithLabelValues(e.appAddressHex, "reject").Inc()
			return p2p.ValidationResultReject
		}

		voteValidationTotal.WithLabelValues(e.appAddressHex, "accept").Inc()

	case protobufs.TimeoutStateType:
		timer := prometheus.NewTimer(
			timeoutStateValidationDuration.WithLabelValues(e.appAddressHex),
		)
		defer timer.ObserveDuration()

		timeoutState := &protobufs.TimeoutState{}
		if err := timeoutState.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal timeout state", zap.Error(err))
			timeoutStateValidationTotal.WithLabelValues(
				e.appAddressHex,
				"reject",
			).Inc()
			return p2p.ValidationResultReject
		}

		now := uint64(time.Now().UnixMilli())
		if timeoutState.Timestamp > now+5000 || timeoutState.Timestamp < now-5000 {
			timeoutStateValidationTotal.WithLabelValues(
				e.appAddressHex,
				"ignore",
			).Inc()
			return p2p.ValidationResultIgnore
		}

		if err := timeoutState.Validate(); err != nil {
			e.logger.Debug("failed to validate timeout state", zap.Error(err))
			timeoutStateValidationTotal.WithLabelValues(
				e.appAddressHex,
				"reject",
			).Inc()
			return p2p.ValidationResultReject
		}

		timeoutStateValidationTotal.WithLabelValues(e.appAddressHex, "accept").Inc()

	case protobufs.ProverLivenessCheckType:
		check := &protobufs.ProverLivenessCheck{}
		if err := check.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal liveness check", zap.Error(err))
			return p2p.ValidationResultReject
		}

		if err := check.Validate(); err != nil {
			e.logger.Debug("invalid liveness check", zap.Error(err))
			return p2p.ValidationResultReject
		}

		if len(check.Filter) != 0 && !bytes.Equal(check.Filter, e.appAddress) {
			return p2p.ValidationResultIgnore
		}

	default:
		return p2p.ValidationResultReject
	}

	return p2p.ValidationResultAccept
}

func (e *AppConsensusEngine) validateProverMessage(
	_ peer.ID,
	message *pb.Message,
) p2p.ValidationResult {
	// Check if data is long enough to contain type prefix
	if len(message.Data) < 4 {
		e.logger.Error(
			"message too short",
			zap.Int("data_length", len(message.Data)),
		)
		return p2p.ValidationResultReject
	}

	// Read type prefix from first 4 bytes
	typePrefix := binary.BigEndian.Uint32(message.Data[:4])

	switch typePrefix {

	case protobufs.MessageBundleType:
		// Prover messages come wrapped in MessageBundle
		messageBundle := &protobufs.MessageBundle{}
		if err := messageBundle.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal message bundle", zap.Error(err))
			return p2p.ValidationResultReject
		}

		if err := messageBundle.Validate(); err != nil {
			e.logger.Debug("invalid request", zap.Error(err))
			return p2p.ValidationResultReject
		}

		now := time.Now().UnixMilli()
		if messageBundle.Timestamp > now+5000 || messageBundle.Timestamp < now-5000 {
			return p2p.ValidationResultIgnore
		}

	default:
		e.logger.Debug("received unknown type", zap.Uint32("type", typePrefix))
		return p2p.ValidationResultIgnore
	}

	return p2p.ValidationResultAccept
}

func (e *AppConsensusEngine) validateGlobalProverMessage(
	_ peer.ID,
	message *pb.Message,
) p2p.ValidationResult {
	// Check if data is long enough to contain type prefix
	if len(message.Data) < 4 {
		e.logger.Error(
			"message too short",
			zap.Int("data_length", len(message.Data)),
		)
		return p2p.ValidationResultReject
	}

	// Read type prefix from first 4 bytes
	typePrefix := binary.BigEndian.Uint32(message.Data[:4])

	switch typePrefix {

	case protobufs.MessageBundleType:
		// Prover messages come wrapped in MessageBundle
		messageBundle := &protobufs.MessageBundle{}
		if err := messageBundle.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal message bundle", zap.Error(err))
			return p2p.ValidationResultReject
		}

		if err := messageBundle.Validate(); err != nil {
			e.logger.Debug("invalid request", zap.Error(err))
			return p2p.ValidationResultReject
		}

		now := time.Now().UnixMilli()
		if messageBundle.Timestamp > now+5000 || messageBundle.Timestamp < now-5000 {
			return p2p.ValidationResultIgnore
		}

	default:
		e.logger.Debug("received unknown type", zap.Uint32("type", typePrefix))
		return p2p.ValidationResultIgnore
	}

	return p2p.ValidationResultAccept
}

func (e *AppConsensusEngine) validateFrameMessage(
	_ peer.ID,
	message *pb.Message,
) p2p.ValidationResult {
	timer := prometheus.NewTimer(
		frameValidationDuration.WithLabelValues(e.appAddressHex),
	)
	defer timer.ObserveDuration()

	// Check if data is long enough to contain type prefix
	if len(message.Data) < 4 {
		e.logger.Debug(
			"message too short",
			zap.Int("data_length", len(message.Data)),
		)
		frameValidationTotal.WithLabelValues(e.appAddressHex, "reject").Inc()
		return p2p.ValidationResultReject
	}

	// Read type prefix from first 4 bytes
	typePrefix := binary.BigEndian.Uint32(message.Data[:4])

	switch typePrefix {
	case protobufs.AppShardFrameType:
		frame := &protobufs.AppShardFrame{}
		if err := frame.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal frame", zap.Error(err))
			frameValidationTotal.WithLabelValues(e.appAddressHex, "reject").Inc()
			return p2p.ValidationResultReject
		}

		if !bytes.Equal(frame.Header.Address, e.appAddress) {
			e.logger.Debug("frame address incorrect")
			frameValidationTotal.WithLabelValues(e.appAddressHex, "ignore").Inc()
			// We ignore this rather than reject because it might be correctly routing
			// but something we should ignore
			return p2p.ValidationResultIgnore
		}

		if frame.Header.PublicKeySignatureBls48581 == nil ||
			frame.Header.PublicKeySignatureBls48581.PublicKey == nil ||
			frame.Header.PublicKeySignatureBls48581.PublicKey.KeyValue == nil {
			e.logger.Debug("frame validation missing signature")
			frameValidationTotal.WithLabelValues(e.appAddressHex, "reject").Inc()
			return p2p.ValidationResultReject
		}

		valid, err := e.frameValidator.Validate(frame)
		if err != nil {
			e.logger.Debug("frame validation error", zap.Error(err))
			frameValidationTotal.WithLabelValues(e.appAddressHex, "reject").Inc()
			return p2p.ValidationResultReject
		}

		if !valid {
			frameValidationTotal.WithLabelValues(e.appAddressHex, "reject").Inc()
			e.logger.Debug("invalid frame")
			return p2p.ValidationResultReject
		}

		if frametime.AppFrameSince(frame) > 20*time.Second {
			return p2p.ValidationResultIgnore
		}

		frameValidationTotal.WithLabelValues(e.appAddressHex, "accept").Inc()

	default:
		return p2p.ValidationResultReject
	}

	return p2p.ValidationResultAccept
}

func (e *AppConsensusEngine) validateGlobalFrameMessage(
	_ peer.ID,
	message *pb.Message,
) p2p.ValidationResult {
	timer := prometheus.NewTimer(globalFrameValidationDuration)
	defer timer.ObserveDuration()

	// Check if data is long enough to contain type prefix
	if len(message.Data) < 4 {
		e.logger.Debug("message too short", zap.Int("data_length", len(message.Data)))
		globalFrameValidationTotal.WithLabelValues(e.appAddressHex, "reject").Inc()
		return p2p.ValidationResultReject
	}

	// Read type prefix from first 4 bytes
	typePrefix := binary.BigEndian.Uint32(message.Data[:4])

	switch typePrefix {
	case protobufs.GlobalFrameType:
		frame := &protobufs.GlobalFrame{}
		if err := frame.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal frame", zap.Error(err))
			globalFrameValidationTotal.WithLabelValues(e.appAddressHex, "reject").Inc()
			return p2p.ValidationResultReject
		}

		if frame.Header.PublicKeySignatureBls48581 == nil ||
			frame.Header.PublicKeySignatureBls48581.PublicKey == nil ||
			frame.Header.PublicKeySignatureBls48581.PublicKey.KeyValue == nil {
			e.logger.Debug("frame validation missing signature")
			globalFrameValidationTotal.WithLabelValues(e.appAddressHex, "reject").Inc()
			return p2p.ValidationResultReject
		}

		valid, err := e.globalFrameValidator.Validate(frame)
		if err != nil {
			e.logger.Debug("frame validation error", zap.Error(err))
			globalFrameValidationTotal.WithLabelValues(e.appAddressHex, "reject").Inc()
			return p2p.ValidationResultReject
		}

		if !valid {
			e.logger.Debug("invalid frame")
			globalFrameValidationTotal.WithLabelValues(e.appAddressHex, "reject").Inc()
			return p2p.ValidationResultReject
		}

		if frametime.GlobalFrameSince(frame) > 20*time.Second {
			return p2p.ValidationResultIgnore
		}

		globalFrameValidationTotal.WithLabelValues(e.appAddressHex, "accept").Inc()

	default:
		return p2p.ValidationResultReject
	}

	return p2p.ValidationResultAccept
}

func (e *AppConsensusEngine) validateAlertMessage(
	_ peer.ID,
	message *pb.Message,
) p2p.ValidationResult {
	// Check if data is long enough to contain type prefix
	if len(message.Data) < 4 {
		e.logger.Error(
			"message too short",
			zap.Int("data_length", len(message.Data)),
		)
		return p2p.ValidationResultReject
	}

	// Read type prefix from first 4 bytes
	typePrefix := binary.BigEndian.Uint32(message.Data[:4])

	switch typePrefix {
	case protobufs.GlobalAlertType:
		alert := &protobufs.GlobalAlert{}
		if err := alert.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal alert", zap.Error(err))
			return p2p.ValidationResultReject
		}

		err := alert.Validate()
		if err != nil {
			e.logger.Debug("alert validation error", zap.Error(err))
			return p2p.ValidationResultReject
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
			return p2p.ValidationResultReject
		}

	default:
		e.logger.Debug("received unknown type", zap.Uint32("type", typePrefix))
		return p2p.ValidationResultIgnore
	}

	return p2p.ValidationResultAccept
}

func (e *AppConsensusEngine) validatePeerInfoMessage(
	_ peer.ID,
	message *pb.Message,
) p2p.ValidationResult {
	// Check if data is long enough to contain type prefix
	if len(message.Data) < 4 {
		e.logger.Error(
			"message too short",
			zap.Int("data_length", len(message.Data)),
		)
		return p2p.ValidationResultReject
	}

	// Read type prefix from first 4 bytes
	typePrefix := binary.BigEndian.Uint32(message.Data[:4])

	switch typePrefix {
	case protobufs.PeerInfoType:
		peerInfo := &protobufs.PeerInfo{}
		if err := peerInfo.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal peer info", zap.Error(err))
			return p2p.ValidationResultReject
		}

		err := peerInfo.Validate()
		if err != nil {
			e.logger.Debug("peer info validation error", zap.Error(err))
			return p2p.ValidationResultReject
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
			return p2p.ValidationResultIgnore
		}

		if peerInfo.Timestamp > fiveMinutesLater {
			e.logger.Debug("peer info timestamp too far in future",
				zap.Int64("peer_timestamp", peerInfo.Timestamp),
				zap.Int64("cutoff", fiveMinutesLater),
			)
			return p2p.ValidationResultIgnore
		}

	default:
		e.logger.Debug("received unknown type", zap.Uint32("type", typePrefix))
		return p2p.ValidationResultIgnore
	}

	return p2p.ValidationResultAccept
}

func (e *AppConsensusEngine) validateDispatchMessage(
	_ peer.ID,
	message *pb.Message,
) p2p.ValidationResult {
	// Check if data is long enough to contain type prefix
	if len(message.Data) < 4 {
		e.logger.Error(
			"message too short",
			zap.Int("data_length", len(message.Data)),
		)
		return p2p.ValidationResultReject
	}

	// Read type prefix from first 4 bytes
	typePrefix := binary.BigEndian.Uint32(message.Data[:4])

	switch typePrefix {
	case protobufs.InboxMessageType:
		envelope := &protobufs.InboxMessage{}
		if err := envelope.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal envelope", zap.Error(err))
			return p2p.ValidationResultReject
		}

		err := envelope.Validate()
		if err != nil {
			e.logger.Debug("envelope validation error", zap.Error(err))
			return p2p.ValidationResultReject
		}

		if envelope.Timestamp < uint64(time.Now().UnixMilli())-2000 ||
			envelope.Timestamp > uint64(time.Now().UnixMilli())+5000 {
			return p2p.ValidationResultIgnore
		}
	case protobufs.HubAddInboxType:
		envelope := &protobufs.HubAddInboxMessage{}
		if err := envelope.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal envelope", zap.Error(err))
			return p2p.ValidationResultReject
		}

		err := envelope.Validate()
		if err != nil {
			e.logger.Debug("envelope validation error", zap.Error(err))
			return p2p.ValidationResultReject
		}

	case protobufs.HubDeleteInboxType:
		envelope := &protobufs.HubDeleteInboxMessage{}
		if err := envelope.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal envelope", zap.Error(err))
			return p2p.ValidationResultReject
		}

		err := envelope.Validate()
		if err != nil {
			e.logger.Debug("envelope validation error", zap.Error(err))
			return p2p.ValidationResultReject
		}

	default:
		e.logger.Debug("received unknown type", zap.Uint32("type", typePrefix))
		return p2p.ValidationResultIgnore
	}

	return p2p.ValidationResultAccept
}
