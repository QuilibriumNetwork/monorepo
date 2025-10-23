package app

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

func (e *AppConsensusEngine) processConsensusMessageQueue() {
	defer e.wg.Done()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-e.quit:
			return
		case message := <-e.consensusMessageQueue:
			e.handleConsensusMessage(message)
		}
	}
}

func (e *AppConsensusEngine) processProverMessageQueue() {
	defer e.wg.Done()

	for {
		select {
		case <-e.haltCtx.Done():
			return
		case <-e.ctx.Done():
			return
		case message := <-e.proverMessageQueue:
			e.handleProverMessage(message)
		}
	}
}

func (e *AppConsensusEngine) processFrameMessageQueue() {
	defer e.wg.Done()

	for {
		select {
		case <-e.haltCtx.Done():
			return
		case <-e.ctx.Done():
			return
		case <-e.quit:
			return
		case message := <-e.frameMessageQueue:
			e.handleFrameMessage(message)
		}
	}
}

func (e *AppConsensusEngine) processGlobalFrameMessageQueue() {
	defer e.wg.Done()

	for {
		select {
		case <-e.haltCtx.Done():
			return
		case <-e.ctx.Done():
			return
		case <-e.quit:
			return
		case message := <-e.globalFrameMessageQueue:
			e.handleGlobalFrameMessage(message)
		}
	}
}

func (e *AppConsensusEngine) processAlertMessageQueue() {
	defer e.wg.Done()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-e.quit:
			return
		case message := <-e.globalAlertMessageQueue:
			e.handleAlertMessage(message)
		}
	}
}

func (e *AppConsensusEngine) processPeerInfoMessageQueue() {
	defer e.wg.Done()

	for {
		select {
		case <-e.haltCtx.Done():
			return
		case <-e.ctx.Done():
			return
		case <-e.quit:
			return
		case message := <-e.globalPeerInfoMessageQueue:
			e.handlePeerInfoMessage(message)
		}
	}
}

func (e *AppConsensusEngine) processDispatchMessageQueue() {
	defer e.wg.Done()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-e.quit:
			return
		case message := <-e.dispatchMessageQueue:
			e.handleDispatchMessage(message)
		}
	}
}

func (e *AppConsensusEngine) handleConsensusMessage(message *pb.Message) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error(
				"panic recovered from message",
				zap.Any("panic", r),
				zap.Stack("stacktrace"),
			)
		}
	}()

	typePrefix := e.peekMessageType(message)
	switch typePrefix {
	case protobufs.AppShardFrameType:
		e.handleProposal(message)

	case protobufs.ProverLivenessCheckType:
		e.handleLivenessCheck(message)

	case protobufs.FrameVoteType:
		e.handleVote(message)

	case protobufs.FrameConfirmationType:
		e.handleConfirmation(message)

	default:
		e.logger.Debug(
			"received unknown message type on app address",
			zap.Uint32("type", typePrefix),
		)
	}
}

func (e *AppConsensusEngine) handleFrameMessage(message *pb.Message) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error(
				"panic recovered from message",
				zap.Any("panic", r),
				zap.Stack("stacktrace"),
			)
		}
	}()

	// we're already getting this from consensus
	if e.IsInProverTrie(e.getProverAddress()) {
		return
	}

	typePrefix := e.peekMessageType(message)
	switch typePrefix {
	case protobufs.AppShardFrameType:
		timer := prometheus.NewTimer(
			frameProcessingDuration.WithLabelValues(e.appAddressHex),
		)
		defer timer.ObserveDuration()

		frame := &protobufs.AppShardFrame{}
		if err := frame.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal frame", zap.Error(err))
			framesProcessedTotal.WithLabelValues("error").Inc()
			return
		}

		frameIDBI, _ := poseidon.HashBytes(frame.Header.Output)
		frameID := frameIDBI.FillBytes(make([]byte, 32))
		e.frameStoreMu.Lock()
		e.frameStore[string(frameID)] = frame
		e.frameStoreMu.Unlock()

		if err := e.appTimeReel.Insert(e.ctx, frame); err != nil {
			// Success metric recorded at the end of processing
			framesProcessedTotal.WithLabelValues("error").Inc()
			return
		}

		// Success metric recorded at the end of processing
		framesProcessedTotal.WithLabelValues("success").Inc()
	default:
		e.logger.Debug(
			"unknown message type",
			zap.Uint32("type", typePrefix),
		)
	}
}

func (e *AppConsensusEngine) handleProverMessage(message *pb.Message) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error(
				"panic recovered from message",
				zap.Any("panic", r),
				zap.Stack("stacktrace"),
			)
		}
	}()

	typePrefix := e.peekMessageType(message)

	e.logger.Debug("handling prover message", zap.Uint32("type_prefix", typePrefix))
	switch typePrefix {
	case protobufs.MessageBundleType:
		// MessageBundle messages need to be collected for execution
		// Store them in pendingMessages to be processed during Collect
		hash := sha3.Sum256(message.Data)
		e.pendingMessagesMu.Lock()
		e.pendingMessages = append(e.pendingMessages, &protobufs.Message{
			Address: e.appAddress[:32],
			Hash:    hash[:],
			Payload: message.Data,
		})
		e.pendingMessagesMu.Unlock()

		e.logger.Debug(
			"collected app request for execution",
			zap.Uint32("type", typePrefix),
		)

	default:
		e.logger.Debug(
			"unknown message type",
			zap.Uint32("type", typePrefix),
		)
	}
}

func (e *AppConsensusEngine) handleGlobalFrameMessage(message *pb.Message) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error(
				"panic recovered from message",
				zap.Any("panic", r),
				zap.Stack("stacktrace"),
			)
		}
	}()

	typePrefix := e.peekMessageType(message)
	switch typePrefix {
	case protobufs.GlobalFrameType:
		timer := prometheus.NewTimer(globalFrameProcessingDuration)
		defer timer.ObserveDuration()

		frame := &protobufs.GlobalFrame{}
		if err := frame.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal frame", zap.Error(err))
			globalFramesProcessedTotal.WithLabelValues("error").Inc()
			return
		}

		if err := e.globalTimeReel.Insert(e.ctx, frame); err != nil {
			// Success metric recorded at the end of processing
			globalFramesProcessedTotal.WithLabelValues("error").Inc()
			return
		}

		// Success metric recorded at the end of processing
		globalFramesProcessedTotal.WithLabelValues("success").Inc()
	default:
		e.logger.Debug(
			"unknown message type",
			zap.Uint32("type", typePrefix),
		)
	}
}

func (e *AppConsensusEngine) handleAlertMessage(message *pb.Message) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error(
				"panic recovered from message",
				zap.Any("panic", r),
				zap.Stack("stacktrace"),
			)
		}
	}()

	typePrefix := e.peekMessageType(message)
	switch typePrefix {
	case protobufs.GlobalAlertType:
		alert := &protobufs.GlobalAlert{}
		if err := alert.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal peer info", zap.Error(err))
			return
		}

		e.emitAlertEvent(alert.Message)

	default:
		e.logger.Debug(
			"unknown message type",
			zap.Uint32("type", typePrefix),
		)
	}
}

func (e *AppConsensusEngine) handlePeerInfoMessage(message *pb.Message) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error(
				"panic recovered from message",
				zap.Any("panic", r),
				zap.Stack("stacktrace"),
			)
		}
	}()

	typePrefix := e.peekMessageType(message)

	switch typePrefix {
	case protobufs.PeerInfoType:
		peerInfo := &protobufs.PeerInfo{}
		if err := peerInfo.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal peer info", zap.Error(err))
			return
		}

		// Validate signature
		if !e.validatePeerInfoSignature(peerInfo) {
			e.logger.Debug("invalid peer info signature",
				zap.String("peer_id", peer.ID(peerInfo.PeerId).String()))
			return
		}

		// Also add to the existing peer info manager
		e.peerInfoManager.AddPeerInfo(peerInfo)

	default:
		e.logger.Debug(
			"unknown message type",
			zap.Uint32("type", typePrefix),
		)
	}
}

func (e *AppConsensusEngine) handleDispatchMessage(message *pb.Message) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error(
				"panic recovered from message",
				zap.Any("panic", r),
				zap.Stack("stacktrace"),
			)
		}
	}()

	typePrefix := e.peekMessageType(message)
	switch typePrefix {
	case protobufs.InboxMessageType:
		envelope := &protobufs.InboxMessage{}
		if err := envelope.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal envelope", zap.Error(err))
			return
		}

		if err := e.dispatchService.AddInboxMessage(
			e.ctx,
			envelope,
		); err != nil {
			e.logger.Debug("failed to add inbox message", zap.Error(err))
		}
	case protobufs.HubAddInboxType:
		envelope := &protobufs.HubAddInboxMessage{}
		if err := envelope.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal envelope", zap.Error(err))
			return
		}

		if err := e.dispatchService.AddHubInboxAssociation(
			e.ctx,
			envelope,
		); err != nil {
			e.logger.Debug("failed to add inbox message", zap.Error(err))
		}
	case protobufs.HubDeleteInboxType:
		envelope := &protobufs.HubDeleteInboxMessage{}
		if err := envelope.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal envelope", zap.Error(err))
			return
		}

		if err := e.dispatchService.DeleteHubInboxAssociation(
			e.ctx,
			envelope,
		); err != nil {
			e.logger.Debug("failed to add inbox message", zap.Error(err))
		}

	default:
		e.logger.Debug(
			"unknown message type",
			zap.Uint32("type", typePrefix),
		)
	}
}

func (e *AppConsensusEngine) handleProposal(message *pb.Message) {
	timer := prometheus.NewTimer(
		proposalProcessingDuration.WithLabelValues(e.appAddressHex),
	)
	defer timer.ObserveDuration()

	frame := &protobufs.AppShardFrame{}
	if err := frame.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal frame", zap.Error(err))
		proposalProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return
	}

	if frame.Header != nil && frame.Header.Prover != nil {
		valid, err := e.frameValidator.Validate(frame)
		if !valid || err != nil {
			e.logger.Error("received invalid frame", zap.Error(err))
			proposalProcessedTotal.WithLabelValues(
				e.appAddressHex,
				"invalid",
			).Inc()
			return
		}

		frameIDBI, _ := poseidon.HashBytes(frame.Header.Output)
		frameID := frameIDBI.FillBytes(make([]byte, 32))
		e.frameStoreMu.Lock()
		e.frameStore[string(frameID)] = frame.Clone().(*protobufs.AppShardFrame)
		e.frameStoreMu.Unlock()

		e.stateMachine.ReceiveProposal(
			PeerID{ID: frame.Header.Prover},
			&frame,
		)
		proposalProcessedTotal.WithLabelValues(e.appAddressHex, "success").Inc()
	}
}

func (e *AppConsensusEngine) handleLivenessCheck(message *pb.Message) {
	timer := prometheus.NewTimer(
		livenessCheckProcessingDuration.WithLabelValues(e.appAddressHex),
	)
	defer timer.ObserveDuration()

	livenessCheck := &protobufs.ProverLivenessCheck{}
	if err := livenessCheck.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal liveness check", zap.Error(err))
		livenessCheckProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return
	}

	if !bytes.Equal(livenessCheck.Filter, e.appAddress) {
		return
	}

	// Validate the liveness check structure
	if err := livenessCheck.Validate(); err != nil {
		e.logger.Debug("invalid liveness check", zap.Error(err))
		livenessCheckProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return
	}

	proverSet, err := e.proverRegistry.GetActiveProvers(e.appAddress)
	if err != nil {
		e.logger.Error("could not receive liveness check", zap.Error(err))
		livenessCheckProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return
	}

	lcBytes, err := livenessCheck.ConstructSignaturePayload()
	if err != nil {
		e.logger.Error(
			"could not construct signature message for liveness check",
			zap.Error(err),
		)
		livenessCheckProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return
	}

	var found []byte = nil
	for _, prover := range proverSet {
		if bytes.Equal(
			prover.Address,
			livenessCheck.PublicKeySignatureBls48581.Address,
		) {
			valid, err := e.keyManager.ValidateSignature(
				crypto.KeyTypeBLS48581G1,
				prover.PublicKey,
				lcBytes,
				livenessCheck.PublicKeySignatureBls48581.Signature,
				livenessCheck.GetSignatureDomain(),
			)
			if err != nil || !valid {
				e.logger.Error(
					"could not validate signature for liveness check",
					zap.Error(err),
				)
				break
			}
			found = prover.PublicKey

			break
		}
	}

	if found == nil {
		e.logger.Warn(
			"invalid liveness check",
			zap.String(
				"prover",
				hex.EncodeToString(
					livenessCheck.PublicKeySignatureBls48581.Address,
				),
			),
		)
		livenessCheckProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return
	}

	if livenessCheck.PublicKeySignatureBls48581 == nil {
		e.logger.Error("no signature on liveness check")
		livenessCheckProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
	}

	commitment := CollectedCommitments{
		commitmentHash: livenessCheck.CommitmentHash,
		frameNumber:    livenessCheck.FrameNumber,
		prover:         livenessCheck.PublicKeySignatureBls48581.Address,
	}
	if err := e.stateMachine.ReceiveLivenessCheck(
		PeerID{ID: livenessCheck.PublicKeySignatureBls48581.Address},
		commitment,
	); err != nil {
		e.logger.Error("could not receive liveness check", zap.Error(err))
		livenessCheckProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return
	}

	livenessCheckProcessedTotal.WithLabelValues(e.appAddressHex, "success").Inc()
}

func (e *AppConsensusEngine) handleVote(message *pb.Message) {
	timer := prometheus.NewTimer(
		voteProcessingDuration.WithLabelValues(e.appAddressHex),
	)
	defer timer.ObserveDuration()

	vote := &protobufs.FrameVote{}
	if err := vote.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal vote", zap.Error(err))
		voteProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return
	}

	if !bytes.Equal(vote.Filter, e.appAddress) {
		return
	}

	if vote.PublicKeySignatureBls48581 == nil {
		e.logger.Error("vote without signature")
		voteProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return
	}

	if err := e.stateMachine.ReceiveVote(
		PeerID{ID: vote.Proposer},
		PeerID{ID: vote.PublicKeySignatureBls48581.Address},
		&vote,
	); err != nil {
		e.logger.Error("could not receive vote", zap.Error(err))
		voteProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return
	}

	voteProcessedTotal.WithLabelValues(e.appAddressHex, "success").Inc()
}

func (e *AppConsensusEngine) handleConfirmation(message *pb.Message) {
	timer := prometheus.NewTimer(
		confirmationProcessingDuration.WithLabelValues(e.appAddressHex),
	)
	defer timer.ObserveDuration()

	confirmation := &protobufs.FrameConfirmation{}
	if err := confirmation.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal confirmation", zap.Error(err))
		confirmationProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return
	}

	if !bytes.Equal(confirmation.Filter, e.appAddress) {
		return
	}

	e.frameStoreMu.RLock()
	var matchingFrame *protobufs.AppShardFrame
	for _, frame := range e.frameStore {
		if frame.Header != nil &&
			frame.Header.FrameNumber == confirmation.FrameNumber {
			frameSelector := e.calculateFrameSelector(frame.Header)
			if bytes.Equal(frameSelector, confirmation.Selector) {
				matchingFrame = frame
				break
			}
		}
	}

	if matchingFrame == nil {
		e.frameStoreMu.RUnlock()
		return
	}

	e.frameStoreMu.RUnlock()
	e.frameStoreMu.Lock()
	defer e.frameStoreMu.Unlock()

	matchingFrame.Header.PublicKeySignatureBls48581 =
		confirmation.AggregateSignature
	valid, err := e.frameValidator.Validate(matchingFrame)
	if !valid || err != nil {
		e.logger.Error("received invalid confirmation", zap.Error(err))
		confirmationProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return
	}

	if matchingFrame.Header.Prover == nil {
		e.logger.Error("confirmation with no matched prover")
		confirmationProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return
	}

	if err := e.stateMachine.ReceiveConfirmation(
		PeerID{ID: matchingFrame.Header.Prover},
		&matchingFrame,
	); err != nil {
		e.logger.Error("could not receive confirmation", zap.Error(err))
		confirmationProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return
	}

	if err := e.appTimeReel.Insert(e.ctx, matchingFrame); err != nil {
		e.logger.Error(
			"could not insert into time reel",
			zap.Error(err),
		)
		confirmationProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return
	}

	confirmationProcessedTotal.WithLabelValues(e.appAddressHex, "success").Inc()
}

func (e *AppConsensusEngine) peekMessageType(message *pb.Message) uint32 {
	// Check if data is long enough to contain type prefix
	if len(message.Data) < 4 {
		e.logger.Debug(
			"message too short",
			zap.Int("data_length", len(message.Data)),
		)
		return 0
	}

	// Read type prefix from first 4 bytes
	return binary.BigEndian.Uint32(message.Data[:4])
}

// validatePeerInfoSignature validates the signature of a peer info message
func (e *AppConsensusEngine) validatePeerInfoSignature(
	peerInfo *protobufs.PeerInfo,
) bool {
	if len(peerInfo.Signature) == 0 || len(peerInfo.PublicKey) == 0 {
		return false
	}

	// Create a copy of the peer info without the signature for validation
	infoCopy := &protobufs.PeerInfo{
		PeerId:       peerInfo.PeerId,
		Reachability: peerInfo.Reachability,
		Timestamp:    peerInfo.Timestamp,
		Version:      peerInfo.Version,
		PatchVersion: peerInfo.PatchVersion,
		Capabilities: peerInfo.Capabilities,
		PublicKey:    peerInfo.PublicKey,
		// Exclude Signature field
	}

	// Serialize the message for signature validation
	msg, err := infoCopy.ToCanonicalBytes()
	if err != nil {
		e.logger.Debug(
			"failed to serialize peer info for validation",
			zap.Error(err),
		)
		return false
	}

	// Validate the signature using pubsub's verification
	valid, err := e.keyManager.ValidateSignature(
		crypto.KeyTypeEd448,
		peerInfo.PublicKey,
		msg,
		peerInfo.Signature,
		[]byte{},
	)

	if err != nil {
		e.logger.Debug(
			"failed to validate signature",
			zap.Error(err),
		)
		return false
	}

	return valid
}
