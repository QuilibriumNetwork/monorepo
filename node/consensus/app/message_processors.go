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
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

func (e *AppConsensusEngine) processConsensusMessageQueue(
	ctx lifecycle.SignalerContext,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.quit:
			return
		case message := <-e.consensusMessageQueue:
			e.handleConsensusMessage(message)
		}
	}
}

func (e *AppConsensusEngine) processProverMessageQueue(
	ctx lifecycle.SignalerContext,
) {
	for {
		select {
		case <-e.haltCtx.Done():
			return
		case <-ctx.Done():
			return
		case message := <-e.proverMessageQueue:
			e.handleProverMessage(message)
		}
	}
}

func (e *AppConsensusEngine) processFrameMessageQueue(
	ctx lifecycle.SignalerContext,
) {
	for {
		select {
		case <-e.haltCtx.Done():
			return
		case <-ctx.Done():
			return
		case <-e.quit:
			return
		case message := <-e.frameMessageQueue:
			e.handleFrameMessage(message)
		}
	}
}

func (e *AppConsensusEngine) processGlobalFrameMessageQueue(
	ctx lifecycle.SignalerContext,
) {
	for {
		select {
		case <-e.haltCtx.Done():
			return
		case <-ctx.Done():
			return
		case <-e.quit:
			return
		case message := <-e.globalFrameMessageQueue:
			e.handleGlobalFrameMessage(message)
		}
	}
}

func (e *AppConsensusEngine) processAlertMessageQueue(
	ctx lifecycle.SignalerContext,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.quit:
			return
		case message := <-e.globalAlertMessageQueue:
			e.handleAlertMessage(message)
		}
	}
}

func (e *AppConsensusEngine) processPeerInfoMessageQueue(
	ctx lifecycle.SignalerContext,
) {
	for {
		select {
		case <-e.haltCtx.Done():
			return
		case <-ctx.Done():
			return
		case <-e.quit:
			return
		case message := <-e.globalPeerInfoMessageQueue:
			e.handlePeerInfoMessage(message)
		}
	}
}

func (e *AppConsensusEngine) processDispatchMessageQueue(
	ctx lifecycle.SignalerContext,
) {
	for {
		select {
		case <-ctx.Done():
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
	case protobufs.AppShardProposalType:
		e.handleProposal(message)

	case protobufs.ProposalVoteType:
		e.handleVote(message)

	case protobufs.TimeoutStateType:
		e.handleTimeoutState(message)

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

		if err := e.appTimeReel.Insert(frame); err != nil {
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

		if err := e.globalTimeReel.Insert(frame); err != nil {
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

	proposal := &protobufs.AppShardProposal{}
	if err := proposal.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal proposal", zap.Error(err))
		proposalProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return
	}

	if proposal.State != nil && proposal.State.Header != nil &&
		proposal.State.Header.Prover != nil {
		valid, err := e.frameValidator.Validate(proposal.State)
		if !valid || err != nil {
			e.logger.Error("received invalid frame", zap.Error(err))
			proposalProcessedTotal.WithLabelValues(
				e.appAddressHex,
				"invalid",
			).Inc()
			return
		}

		frameIDBI, _ := poseidon.HashBytes(proposal.State.Header.Output)
		frameID := frameIDBI.FillBytes(make([]byte, 32))
		e.frameStoreMu.Lock()
		e.frameStore[string(frameID)] =
			proposal.State.Clone().(*protobufs.AppShardFrame)
		e.frameStoreMu.Unlock()

		// Small gotcha: the proposal structure uses interfaces, so we can't assign
		// directly, otherwise the nil values for the structs will fail the nil
		// check on the interfaces (and would incur costly reflection if we wanted
		// to check it directly)
		pqc := proposal.ParentQuorumCertificate
		prtc := proposal.PriorRankTimeoutCertificate
		signedProposal := &models.SignedProposal[*protobufs.AppShardFrame, *protobufs.ProposalVote]{
			Proposal: models.Proposal[*protobufs.AppShardFrame]{
				State: &models.State[*protobufs.AppShardFrame]{
					Rank:       proposal.State.GetRank(),
					Identifier: proposal.State.Identity(),
					ProposerID: proposal.Vote.Identity(),
					Timestamp:  proposal.State.GetTimestamp(),
					State:      &proposal.State,
				},
			},
			Vote: &proposal.Vote,
		}

		if pqc != nil {
			signedProposal.Proposal.State.ParentQuorumCertificate = pqc
		}

		if prtc != nil {
			signedProposal.PreviousRankTimeoutCertificate = prtc
		}

		e.consensusParticipant.SubmitProposal(signedProposal)
		proposalProcessedTotal.WithLabelValues(e.appAddressHex, "success").Inc()
	}
}

func (e *AppConsensusEngine) handleVote(message *pb.Message) {
	timer := prometheus.NewTimer(
		voteProcessingDuration.WithLabelValues(e.appAddressHex),
	)
	defer timer.ObserveDuration()

	vote := &protobufs.ProposalVote{}
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

	proverSet, err := e.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		e.logger.Error("could not get active provers", zap.Error(err))
		voteProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	// Find the voter's public key
	var voterPublicKey []byte = nil
	for _, prover := range proverSet {
		if bytes.Equal(
			prover.Address,
			vote.PublicKeySignatureBls48581.Address,
		) {
			voterPublicKey = prover.PublicKey
			break
		}
	}

	if voterPublicKey == nil {
		e.logger.Warn(
			"invalid vote - voter not found",
			zap.String(
				"voter",
				hex.EncodeToString(
					vote.PublicKeySignatureBls48581.Address,
				),
			),
		)
		voteProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	e.voteAggregator.AddVote(&vote)

	voteProcessedTotal.WithLabelValues(e.appAddressHex, "success").Inc()
}

func (e *AppConsensusEngine) handleTimeoutState(message *pb.Message) {
	timer := prometheus.NewTimer(
		timeoutStateProcessingDuration.WithLabelValues(e.appAddressHex),
	)
	defer timer.ObserveDuration()

	timeoutState := &protobufs.TimeoutState{}
	if err := timeoutState.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal timeoutState", zap.Error(err))
		timeoutStateProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
		return
	}

	if !bytes.Equal(timeoutState.Vote.Filter, e.appAddress) {
		return
	}

	// Small gotcha: the timeout structure uses interfaces, so we can't assign
	// directly, otherwise the nil values for the structs will fail the nil
	// check on the interfaces (and would incur costly reflection if we wanted
	// to check it directly)
	lqc := timeoutState.LatestQuorumCertificate
	prtc := timeoutState.PriorRankTimeoutCertificate
	timeout := &models.TimeoutState[*protobufs.ProposalVote]{
		Rank:        timeoutState.Vote.Rank,
		Vote:        &timeoutState.Vote,
		TimeoutTick: timeoutState.TimeoutTick,
	}
	if lqc != nil {
		timeout.LatestQuorumCertificate = lqc
	}
	if prtc != nil {
		timeout.PriorRankTimeoutCertificate = prtc
	}

	e.timeoutAggregator.AddTimeout(timeout)

	timeoutStateProcessedTotal.WithLabelValues(e.appAddressHex, "success").Inc()
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
