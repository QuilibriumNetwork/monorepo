package global

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/bits"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

func (e *GlobalConsensusEngine) processGlobalConsensusMessageQueue() {
	defer e.wg.Done()

	if e.config.P2P.Network != 99 && !e.config.Engine.ArchiveMode {
		return
	}

	for {
		select {
		case <-e.haltCtx.Done():
			return
		case <-e.ctx.Done():
			return
		case message := <-e.globalConsensusMessageQueue:
			e.handleGlobalConsensusMessage(message)
		case appmsg := <-e.appFramesMessageQueue:
			e.handleAppFrameMessage(appmsg)
		}
	}
}

func (e *GlobalConsensusEngine) processProverMessageQueue() {
	defer e.wg.Done()

	if e.config.P2P.Network != 99 && !e.config.Engine.ArchiveMode {
		return
	}

	for {
		select {
		case <-e.haltCtx.Done():
			return
		case <-e.ctx.Done():
			return
		case message := <-e.globalProverMessageQueue:
			e.handleProverMessage(message)
		}
	}
}

func (e *GlobalConsensusEngine) processFrameMessageQueue() {
	defer e.wg.Done()

	for {
		select {
		case <-e.haltCtx.Done():
			return
		case <-e.ctx.Done():
			return
		case message := <-e.globalFrameMessageQueue:
			e.handleFrameMessage(message)
		}
	}
}

func (e *GlobalConsensusEngine) processPeerInfoMessageQueue() {
	defer e.wg.Done()

	for {
		select {
		case <-e.haltCtx.Done():
			return
		case <-e.ctx.Done():
			return
		case message := <-e.globalPeerInfoMessageQueue:
			e.handlePeerInfoMessage(message)
		}
	}
}

func (e *GlobalConsensusEngine) processAlertMessageQueue() {
	defer e.wg.Done()

	for {
		select {
		case <-e.ctx.Done():
			return
		case message := <-e.globalAlertMessageQueue:
			e.handleAlertMessage(message)
		}
	}
}

func (e *GlobalConsensusEngine) handleGlobalConsensusMessage(
	message *pb.Message,
) {
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
		e.handleProposal(message)

	case protobufs.ProverLivenessCheckType:
		e.handleLivenessCheck(message)

	case protobufs.FrameVoteType:
		e.handleVote(message)

	case protobufs.FrameConfirmationType:
		e.handleConfirmation(message)

	case protobufs.MessageBundleType:
		e.handleMessageBundle(message)

	default:
		e.logger.Debug(
			"unknown message type",
			zap.Uint32("type", typePrefix),
		)
	}
}

func (e *GlobalConsensusEngine) handleProverMessage(message *pb.Message) {
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
	case protobufs.MessageBundleType:
		// MessageBundle messages need to be collected for execution
		// Store them in pendingMessages to be processed during Collect
		e.pendingMessagesMu.Lock()
		e.pendingMessages = append(e.pendingMessages, message.Data)
		e.pendingMessagesMu.Unlock()

		e.logger.Debug(
			"collected global request for execution",
			zap.Uint32("type", typePrefix),
		)

	default:
		e.logger.Debug(
			"unknown message type",
			zap.Uint32("type", typePrefix),
		)
	}
}

func (e *GlobalConsensusEngine) handleFrameMessage(message *pb.Message) {
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
		timer := prometheus.NewTimer(frameProcessingDuration)
		defer timer.ObserveDuration()

		frame := &protobufs.GlobalFrame{}
		if err := frame.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal frame", zap.Error(err))
			framesProcessedTotal.WithLabelValues("error").Inc()
			return
		}

		frameIDBI, _ := poseidon.HashBytes(frame.Header.Output)
		frameID := frameIDBI.FillBytes(make([]byte, 32))
		e.frameStoreMu.Lock()
		e.frameStore[string(frameID)] = frame
		clone := frame.Clone().(*protobufs.GlobalFrame)
		e.frameStoreMu.Unlock()

		if err := e.globalTimeReel.Insert(e.ctx, clone); err != nil {
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

func (e *GlobalConsensusEngine) handleAppFrameMessage(message *pb.Message) {
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
	if e.config.P2P.Network == 99 || e.config.Engine.ArchiveMode {
		return
	}

	typePrefix := e.peekMessageType(message)
	switch typePrefix {
	case protobufs.AppShardFrameType:
		frame := &protobufs.AppShardFrame{}
		if err := frame.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal frame", zap.Error(err))
			return
		}

		valid, err := e.appFrameValidator.Validate(frame)
		if !valid || err != nil {
			e.logger.Debug("failed to validate frame", zap.Error(err))
		}
		e.frameStoreMu.Lock()
		defer e.frameStoreMu.Unlock()
		if old, ok := e.appFrameStore[string(frame.Header.Address)]; ok {
			if old.Header.FrameNumber > frame.Header.FrameNumber || (old.Header.FrameNumber == frame.Header.FrameNumber &&
				compareBits(
					old.Header.PublicKeySignatureBls48581.Bitmask,
					frame.Header.PublicKeySignatureBls48581.Bitmask,
				) >= 0) {
				return
			}
		}
		e.appFrameStore[string(frame.Header.Address)] = frame
	default:
		e.logger.Debug(
			"unknown message type",
			zap.Uint32("type", typePrefix),
		)
	}
}

func (e *GlobalConsensusEngine) handlePeerInfoMessage(message *pb.Message) {
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

func (e *GlobalConsensusEngine) handleAlertMessage(message *pb.Message) {
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
			e.logger.Debug("failed to unmarshal alert", zap.Error(err))
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

func (e *GlobalConsensusEngine) handleProposal(message *pb.Message) {
	timer := prometheus.NewTimer(frameProcessingDuration)
	defer timer.ObserveDuration()

	frame := &protobufs.GlobalFrame{}
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

	// For proposals, we need to identify the proposer differently
	// The proposer's address should be determinable from the frame header
	proposerAddress := e.getAddressFromPublicKey(
		frame.Header.PublicKeySignatureBls48581.PublicKey.KeyValue,
	)
	if len(proposerAddress) > 0 {
		clonedFrame := frame.Clone().(*protobufs.GlobalFrame)
		if err := e.stateMachine.ReceiveProposal(
			GlobalPeerID{
				ID: proposerAddress,
			},
			&clonedFrame,
		); err != nil {
			e.logger.Error("could not receive proposal", zap.Error(err))
		}
	}

	// Success metric recorded at the end of processing
	framesProcessedTotal.WithLabelValues("success").Inc()
}

func (e *GlobalConsensusEngine) handleLivenessCheck(message *pb.Message) {
	livenessCheck := &protobufs.ProverLivenessCheck{}
	if err := livenessCheck.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal liveness check", zap.Error(err))
		return
	}

	// Validate the liveness check structure
	if err := livenessCheck.Validate(); err != nil {
		e.logger.Debug("invalid liveness check", zap.Error(err))
		return
	}

	proverSet, err := e.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		e.logger.Error("could not receive liveness check", zap.Error(err))
		return
	}

	var found []byte = nil
	for _, prover := range proverSet {
		if bytes.Equal(
			prover.Address,
			livenessCheck.PublicKeySignatureBls48581.Address,
		) {
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
		return
	}

	signatureData := slices.Concat(
		make([]byte, 32),
		binary.BigEndian.AppendUint64(nil, livenessCheck.FrameNumber),
		livenessCheck.CommitmentHash,
		binary.BigEndian.AppendUint64(nil, uint64(livenessCheck.Timestamp)),
	)

	valid, err := e.keyManager.ValidateSignature(
		crypto.KeyTypeBLS48581G1,
		found,
		signatureData,
		livenessCheck.PublicKeySignatureBls48581.Signature,
		[]byte("liveness"),
	)

	if err != nil || !valid {
		e.logger.Error("invalid liveness check signature", zap.Error(err))
		return
	}

	commitment := GlobalCollectedCommitments{
		frameNumber:    livenessCheck.FrameNumber,
		commitmentHash: livenessCheck.CommitmentHash,
		prover:         livenessCheck.PublicKeySignatureBls48581.Address,
	}
	if err := e.stateMachine.ReceiveLivenessCheck(
		GlobalPeerID{ID: livenessCheck.PublicKeySignatureBls48581.Address},
		commitment,
	); err != nil {
		e.logger.Error("could not receive liveness check", zap.Error(err))
	}
}

func (e *GlobalConsensusEngine) handleVote(message *pb.Message) {
	vote := &protobufs.FrameVote{}
	if err := vote.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal vote", zap.Error(err))
		return
	}

	// Validate the vote structure
	if err := vote.Validate(); err != nil {
		e.logger.Debug("invalid vote", zap.Error(err))
		return
	}

	if vote.PublicKeySignatureBls48581 != nil {
		// Validate the voter's signature
		proverSet, err := e.proverRegistry.GetActiveProvers(nil)
		if err != nil {
			e.logger.Error("could not get active provers", zap.Error(err))
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
			return
		}

		// Find the proposal frame for this vote
		e.frameStoreMu.RLock()
		var proposalFrame *protobufs.GlobalFrame = nil
		for _, frame := range e.frameStore {
			if frame.Header != nil &&
				frame.Header.FrameNumber == vote.FrameNumber &&
				bytes.Equal(
					e.getAddressFromPublicKey(
						frame.Header.PublicKeySignatureBls48581.PublicKey.KeyValue,
					),
					vote.Proposer,
				) {
				proposalFrame = frame
				break
			}
		}
		e.frameStoreMu.RUnlock()

		if proposalFrame == nil {
			e.logger.Warn(
				"vote for unknown proposal",
				zap.Uint64("frame_number", vote.FrameNumber),
				zap.String("proposer", hex.EncodeToString(vote.Proposer)),
			)
			return
		}

		// Get the signature payload for the proposal
		signatureData, err := e.frameProver.GetGlobalFrameSignaturePayload(
			proposalFrame.Header,
		)
		if err != nil {
			e.logger.Error("could not get signature payload", zap.Error(err))
			return
		}

		// Validate the vote signature
		valid, err := e.keyManager.ValidateSignature(
			crypto.KeyTypeBLS48581G1,
			voterPublicKey,
			signatureData,
			vote.PublicKeySignatureBls48581.Signature,
			[]byte("global"),
		)

		if err != nil || !valid {
			e.logger.Error("invalid vote signature", zap.Error(err))
			return
		}

		// Signature is valid, process the vote
		if err := e.stateMachine.ReceiveVote(
			GlobalPeerID{ID: vote.Proposer},
			GlobalPeerID{ID: vote.PublicKeySignatureBls48581.Address},
			&vote,
		); err != nil {
			e.logger.Error("could not receive vote", zap.Error(err))
		}
	}
}

func (e *GlobalConsensusEngine) handleMessageBundle(message *pb.Message) {
	// MessageBundle messages need to be collected for execution
	// Store them in pendingMessages to be processed during Collect
	e.pendingMessagesMu.Lock()
	e.pendingMessages = append(e.pendingMessages, message.Data)
	e.pendingMessagesMu.Unlock()

	e.logger.Debug("collected global request for execution")
}

func (e *GlobalConsensusEngine) handleConfirmation(message *pb.Message) {
	confirmation := &protobufs.FrameConfirmation{}
	if err := confirmation.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal confirmation", zap.Error(err))
		return
	}

	// Validate the confirmation structure
	if err := confirmation.Validate(); err != nil {
		e.logger.Debug("invalid confirmation", zap.Error(err))
		return
	}

	// Find the frame with matching selector
	e.frameStoreMu.RLock()
	var matchingFrame *protobufs.GlobalFrame
	for frameID, frame := range e.frameStore {
		if frame.Header != nil &&
			frame.Header.FrameNumber == confirmation.FrameNumber &&
			frameID == string(confirmation.Selector) {
			matchingFrame = frame
			break
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
		return
	}

	// Check if we already have a confirmation stowed
	exceeds := false
	set := 0
	for _, b := range matchingFrame.Header.PublicKeySignatureBls48581.Bitmask {
		set += bits.OnesCount8(b)
		if set > 1 {
			exceeds = true
			break
		}
	}
	if exceeds {
		// Skip the remaining operations
		return
	}

	// Extract proposer address from the original frame
	var proposerAddress []byte
	frameSignature := matchingFrame.Header.PublicKeySignatureBls48581
	if frameSignature != nil && frameSignature.PublicKey != nil &&
		len(frameSignature.PublicKey.KeyValue) > 0 {
		proposerAddress = e.getAddressFromPublicKey(
			frameSignature.PublicKey.KeyValue,
		)
	} else if frameSignature != nil &&
		frameSignature.Bitmask != nil {
		// Extract from bitmask if no public key
		provers, err := e.proverRegistry.GetActiveProvers(nil)
		if err == nil {
			for i := 0; i < len(provers); i++ {
				byteIndex := i / 8
				bitIndex := i % 8
				if byteIndex < len(frameSignature.Bitmask) &&
					(frameSignature.Bitmask[byteIndex]&(1<<bitIndex)) != 0 {
					proposerAddress = provers[i].Address
					break
				}
			}
		}
	}

	// We may receive multiple confirmations, should be idempotent
	if bytes.Equal(
		frameSignature.Signature,
		confirmation.AggregateSignature.Signature,
	) {
		e.logger.Debug("received duplicate confirmation, ignoring")
		return
	}

	// Apply confirmation to frame
	matchingFrame.Header.PublicKeySignatureBls48581 =
		confirmation.AggregateSignature

	// Send confirmation to state machine
	if len(proposerAddress) > 0 {
		if err := e.stateMachine.ReceiveConfirmation(
			GlobalPeerID{ID: proposerAddress},
			&matchingFrame,
		); err != nil {
			e.logger.Error("could not receive confirmation", zap.Error(err))
		}
	}
	err = e.globalTimeReel.Insert(e.ctx, matchingFrame)
	if err != nil {
		e.logger.Error(
			"could not insert into time reel",
			zap.Error(err),
		)
	}
}

func (e *GlobalConsensusEngine) peekMessageType(message *pb.Message) uint32 {
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

func compareBits(b1, b2 []byte) int {
	bitCount1 := 0
	bitCount2 := 0

	for i := 0; i < len(b1); i++ {
		for bit := 0; bit < 8; bit++ {
			if b1[i]&(1<<bit) != 0 {
				bitCount1++
			}
		}
	}
	for i := 0; i < len(b2); i++ {
		for bit := 0; bit < 8; bit++ {
			if b2[i]&(1<<bit) != 0 {
				bitCount2++
			}
		}
	}
	return bitCount1 - bitCount2
}
