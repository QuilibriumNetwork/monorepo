package global

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/verification"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

var keyRegistryDomain = []byte("KEY_REGISTRY")

func (e *GlobalConsensusEngine) processGlobalConsensusMessageQueue(
	ctx lifecycle.SignalerContext,
) {
	if e.config.P2P.Network != 99 && !e.config.Engine.ArchiveMode {
		<-ctx.Done()
		return
	}

	for {
		select {
		case <-e.haltCtx.Done():
			return
		case <-ctx.Done():
			return
		case message := <-e.globalConsensusMessageQueue:
			e.handleGlobalConsensusMessage(message)
		case appmsg := <-e.appFramesMessageQueue:
			e.handleAppFrameMessage(appmsg)
		}
	}
}

func (e *GlobalConsensusEngine) processShardConsensusMessageQueue(
	ctx lifecycle.SignalerContext,
) {
	for {
		select {
		case <-e.haltCtx.Done():
			return
		case <-ctx.Done():
			return
		case message := <-e.shardConsensusMessageQueue:
			e.handleShardConsensusMessage(message)
		}
	}
}

func (e *GlobalConsensusEngine) processProverMessageQueue(
	ctx lifecycle.SignalerContext,
) {
	if e.config.P2P.Network != 99 && !e.config.Engine.ArchiveMode {
		return
	}

	for {
		select {
		case <-e.haltCtx.Done():
			return
		case <-ctx.Done():
			return
		case message := <-e.globalProverMessageQueue:
			e.handleProverMessage(message)
		}
	}
}

func (e *GlobalConsensusEngine) processFrameMessageQueue(
	ctx lifecycle.SignalerContext,
) {
	for {
		select {
		case <-e.haltCtx.Done():
			return
		case <-ctx.Done():
			return
		case message := <-e.globalFrameMessageQueue:
			e.handleFrameMessage(ctx, message)
		}
	}
}

func (e *GlobalConsensusEngine) processPeerInfoMessageQueue(
	ctx lifecycle.SignalerContext,
) {
	for {
		select {
		case <-e.haltCtx.Done():
			return
		case <-ctx.Done():
			return
		case message := <-e.globalPeerInfoMessageQueue:
			e.handlePeerInfoMessage(message)
		}
	}
}

func (e *GlobalConsensusEngine) processAlertMessageQueue(
	ctx lifecycle.SignalerContext,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case message := <-e.globalAlertMessageQueue:
			e.handleAlertMessage(message)
		}
	}
}

func (e *GlobalConsensusEngine) processGlobalProposalQueue(
	ctx lifecycle.SignalerContext,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case proposal := <-e.globalProposalQueue:
			e.handleGlobalProposal(proposal)
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
	case protobufs.GlobalProposalType:
		e.handleProposal(message)

	case protobufs.ProposalVoteType:
		e.handleVote(message)

	case protobufs.TimeoutStateType:
		e.handleTimeoutState(message)

	case protobufs.MessageBundleType:
		e.handleMessageBundle(message)

	default:
		e.logger.Debug(
			"unknown message type",
			zap.Uint32("type", typePrefix),
		)
	}
}

func (e *GlobalConsensusEngine) handleShardConsensusMessage(
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
	case protobufs.AppShardFrameType:
		e.handleShardProposal(message)

	case protobufs.ProposalVoteType:
		e.handleShardVote(message)

	case protobufs.ProverLivenessCheckType:
		e.handleShardLivenessCheck(message)

	case protobufs.TimeoutStateType:
		// e.handleShardTimeout(message)
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

func (e *GlobalConsensusEngine) handleFrameMessage(
	ctx context.Context,
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

		if err := e.globalTimeReel.Insert(clone); err != nil {
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
		timer := prometheus.NewTimer(shardFrameProcessingDuration)
		defer timer.ObserveDuration()

		frame := &protobufs.AppShardFrame{}
		if err := frame.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal frame", zap.Error(err))
			shardFramesProcessedTotal.WithLabelValues("error").Inc()
			return
		}

		e.frameStoreMu.RLock()
		existing, ok := e.appFrameStore[string(frame.Header.Address)]
		if ok && existing != nil &&
			existing.Header.FrameNumber >= frame.Header.FrameNumber {
			e.frameStoreMu.RUnlock()
			return
		}
		e.frameStoreMu.RUnlock()

		valid, err := e.appFrameValidator.Validate(frame)
		if !valid || err != nil {
			e.logger.Debug("failed to validate frame", zap.Error(err))
			shardFramesProcessedTotal.WithLabelValues("error").Inc()
		}

		e.pendingMessagesMu.Lock()
		bundle := &protobufs.MessageBundle{
			Requests: []*protobufs.MessageRequest{
				&protobufs.MessageRequest{
					Request: &protobufs.MessageRequest_Shard{
						Shard: frame.Header,
					},
				},
			},
			Timestamp: frame.Header.Timestamp,
		}

		bundleBytes, err := bundle.ToCanonicalBytes()
		if err != nil {
			e.logger.Error("failed to add shard bundle", zap.Error(err))
			e.pendingMessagesMu.Unlock()
			return
		}

		e.pendingMessages = append(e.pendingMessages, bundleBytes)
		e.pendingMessagesMu.Unlock()
		e.frameStoreMu.Lock()
		defer e.frameStoreMu.Unlock()
		e.appFrameStore[string(frame.Header.Address)] = frame
		shardFramesProcessedTotal.WithLabelValues("success").Inc()
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
	case protobufs.KeyRegistryType:
		keyRegistry := &protobufs.KeyRegistry{}
		if err := keyRegistry.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal key registry", zap.Error(err))
			return
		}

		if err := keyRegistry.Validate(); err != nil {
			e.logger.Debug("invalid key registry", zap.Error(err))
			return
		}

		validation, err := e.validateKeyRegistry(keyRegistry)
		if err != nil {
			e.logger.Debug("invalid key registry signatures", zap.Error(err))
			return
		}

		txn, err := e.keyStore.NewTransaction()
		if err != nil {
			e.logger.Error("failed to create keystore txn", zap.Error(err))
			return
		}

		commit := false
		defer func() {
			if !commit {
				if abortErr := txn.Abort(); abortErr != nil {
					e.logger.Warn("failed to abort keystore txn", zap.Error(abortErr))
				}
			}
		}()

		var identityAddress []byte
		if keyRegistry.IdentityKey != nil &&
			len(keyRegistry.IdentityKey.KeyValue) != 0 {
			if err := e.keyStore.PutIdentityKey(
				txn,
				validation.identityPeerID,
				keyRegistry.IdentityKey,
			); err != nil {
				e.logger.Error("failed to store identity key", zap.Error(err))
				return
			}
			identityAddress = validation.identityPeerID
		}

		var proverAddress []byte
		if keyRegistry.ProverKey != nil &&
			len(keyRegistry.ProverKey.KeyValue) != 0 {
			if err := e.keyStore.PutProvingKey(
				txn,
				validation.proverAddress,
				&protobufs.BLS48581SignatureWithProofOfPossession{
					PublicKey: keyRegistry.ProverKey,
				},
			); err != nil {
				e.logger.Error("failed to store prover key", zap.Error(err))
				return
			}
			proverAddress = validation.proverAddress
		}

		if len(identityAddress) != 0 && len(proverAddress) == 32 &&
			keyRegistry.IdentityToProver != nil &&
			len(keyRegistry.IdentityToProver.Signature) != 0 &&
			keyRegistry.ProverToIdentity != nil &&
			len(keyRegistry.ProverToIdentity.Signature) != 0 {
			if err := e.keyStore.PutCrossSignature(
				txn,
				identityAddress,
				proverAddress,
				keyRegistry.IdentityToProver.Signature,
				keyRegistry.ProverToIdentity.Signature,
			); err != nil {
				e.logger.Error("failed to store cross signatures", zap.Error(err))
				return
			}
		}

		for _, collection := range keyRegistry.KeysByPurpose {
			for _, key := range collection.X448Keys {
				if key == nil || key.Key == nil ||
					len(key.Key.KeyValue) == 0 {
					continue
				}
				addrBI, err := poseidon.HashBytes(key.Key.KeyValue)
				if err != nil {
					e.logger.Error("failed to derive x448 key address", zap.Error(err))
					return
				}
				address := addrBI.FillBytes(make([]byte, 32))
				if err := e.keyStore.PutSignedX448Key(txn, address, key); err != nil {
					e.logger.Error("failed to store signed x448 key", zap.Error(err))
					return
				}
			}

			for _, key := range collection.Decaf448Keys {
				if key == nil || key.Key == nil ||
					len(key.Key.KeyValue) == 0 {
					continue
				}
				addrBI, err := poseidon.HashBytes(key.Key.KeyValue)
				if err != nil {
					e.logger.Error(
						"failed to derive decaf448 key address",
						zap.Error(err),
					)
					return
				}
				address := addrBI.FillBytes(make([]byte, 32))
				if err := e.keyStore.PutSignedDecaf448Key(
					txn,
					address,
					key,
				); err != nil {
					e.logger.Error("failed to store signed decaf448 key", zap.Error(err))
					return
				}
			}
		}

		if err := txn.Commit(); err != nil {
			e.logger.Error("failed to commit key registry txn", zap.Error(err))
			return
		}
		commit = true

	default:
		e.logger.Debug(
			"unknown message type",
			zap.Uint32("type", typePrefix),
		)
	}
}

type keyRegistryValidationResult struct {
	identityPeerID []byte
	proverAddress  []byte
}

func (e *GlobalConsensusEngine) validateKeyRegistry(
	keyRegistry *protobufs.KeyRegistry,
) (*keyRegistryValidationResult, error) {
	if keyRegistry.IdentityKey == nil ||
		len(keyRegistry.IdentityKey.KeyValue) == 0 {
		return nil, fmt.Errorf("key registry missing identity key")
	}
	if err := keyRegistry.IdentityKey.Validate(); err != nil {
		return nil, fmt.Errorf("invalid identity key: %w", err)
	}

	pubKey, err := pcrypto.UnmarshalEd448PublicKey(
		keyRegistry.IdentityKey.KeyValue,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal identity key: %w", err)
	}
	peerID, err := peer.IDFromPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive identity peer id: %w", err)
	}
	identityPeerID := []byte(peerID)

	if keyRegistry.ProverKey == nil ||
		len(keyRegistry.ProverKey.KeyValue) == 0 {
		return nil, fmt.Errorf("key registry missing prover key")
	}
	if err := keyRegistry.ProverKey.Validate(); err != nil {
		return nil, fmt.Errorf("invalid prover key: %w", err)
	}

	if keyRegistry.IdentityToProver == nil ||
		len(keyRegistry.IdentityToProver.Signature) == 0 {
		return nil, fmt.Errorf("missing identity-to-prover signature")
	}

	identityMsg := slices.Concat(
		keyRegistryDomain,
		keyRegistry.ProverKey.KeyValue,
	)
	valid, err := e.keyManager.ValidateSignature(
		crypto.KeyTypeEd448,
		keyRegistry.IdentityKey.KeyValue,
		identityMsg,
		keyRegistry.IdentityToProver.Signature,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"identity-to-prover signature validation failed: %w",
			err,
		)
	}
	if !valid {
		return nil, fmt.Errorf("identity-to-prover signature invalid")
	}

	if keyRegistry.ProverToIdentity == nil ||
		len(keyRegistry.ProverToIdentity.Signature) == 0 {
		return nil, fmt.Errorf("missing prover-to-identity signature")
	}

	valid, err = e.keyManager.ValidateSignature(
		crypto.KeyTypeBLS48581G1,
		keyRegistry.ProverKey.KeyValue,
		keyRegistry.IdentityKey.KeyValue,
		keyRegistry.ProverToIdentity.Signature,
		keyRegistryDomain,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"prover-to-identity signature validation failed: %w",
			err,
		)
	}
	if !valid {
		return nil, fmt.Errorf("prover-to-identity signature invalid")
	}

	addrBI, err := poseidon.HashBytes(keyRegistry.ProverKey.KeyValue)
	if err != nil {
		return nil, fmt.Errorf("failed to derive prover key address: %w", err)
	}
	proverAddress := addrBI.FillBytes(make([]byte, 32))

	for purpose, collection := range keyRegistry.KeysByPurpose {
		if collection == nil {
			continue
		}
		for _, key := range collection.X448Keys {
			if err := e.validateSignedX448Key(
				key,
				identityPeerID,
				proverAddress,
				keyRegistry,
			); err != nil {
				return nil, fmt.Errorf(
					"invalid x448 key (purpose %s): %w",
					purpose,
					err,
				)
			}
		}
		for _, key := range collection.Decaf448Keys {
			if err := e.validateSignedDecaf448Key(
				key,
				identityPeerID,
				proverAddress,
				keyRegistry,
			); err != nil {
				return nil, fmt.Errorf(
					"invalid decaf448 key (purpose %s): %w",
					purpose,
					err,
				)
			}
		}
	}

	return &keyRegistryValidationResult{
		identityPeerID: identityPeerID,
		proverAddress:  proverAddress,
	}, nil
}

func (e *GlobalConsensusEngine) validateSignedX448Key(
	key *protobufs.SignedX448Key,
	identityPeerID []byte,
	proverAddress []byte,
	keyRegistry *protobufs.KeyRegistry,
) error {
	if key == nil || key.Key == nil || len(key.Key.KeyValue) == 0 {
		return nil
	}

	msg := slices.Concat(keyRegistryDomain, key.Key.KeyValue)
	switch sig := key.Signature.(type) {
	case *protobufs.SignedX448Key_Ed448Signature:
		if sig.Ed448Signature == nil ||
			len(sig.Ed448Signature.Signature) == 0 {
			return fmt.Errorf("missing ed448 signature")
		}
		if !bytes.Equal(key.ParentKeyAddress, identityPeerID) {
			return fmt.Errorf("unexpected parent for ed448 signed x448 key")
		}
		valid, err := e.keyManager.ValidateSignature(
			crypto.KeyTypeEd448,
			keyRegistry.IdentityKey.KeyValue,
			msg,
			sig.Ed448Signature.Signature,
			nil,
		)
		if err != nil {
			return fmt.Errorf("failed to validate ed448 signature: %w", err)
		}
		if !valid {
			return fmt.Errorf("ed448 signature invalid")
		}
	case *protobufs.SignedX448Key_BlsSignature:
		if sig.BlsSignature == nil ||
			len(sig.BlsSignature.Signature) == 0 {
			return fmt.Errorf("missing bls signature")
		}
		if len(proverAddress) != 0 &&
			!bytes.Equal(key.ParentKeyAddress, proverAddress) {
			return fmt.Errorf("unexpected parent for bls signed x448 key")
		}
		valid, err := e.keyManager.ValidateSignature(
			crypto.KeyTypeBLS48581G1,
			keyRegistry.ProverKey.KeyValue,
			key.Key.KeyValue,
			sig.BlsSignature.Signature,
			keyRegistryDomain,
		)
		if err != nil {
			return fmt.Errorf("failed to validate bls signature: %w", err)
		}
		if !valid {
			return fmt.Errorf("bls signature invalid")
		}
	case *protobufs.SignedX448Key_DecafSignature:
		return fmt.Errorf("decaf signature not supported for x448 key")
	default:
		return fmt.Errorf("missing signature for x448 key")
	}

	return nil
}

func (e *GlobalConsensusEngine) validateSignedDecaf448Key(
	key *protobufs.SignedDecaf448Key,
	identityPeerID []byte,
	proverAddress []byte,
	keyRegistry *protobufs.KeyRegistry,
) error {
	if key == nil || key.Key == nil || len(key.Key.KeyValue) == 0 {
		return nil
	}

	msg := slices.Concat(keyRegistryDomain, key.Key.KeyValue)
	switch sig := key.Signature.(type) {
	case *protobufs.SignedDecaf448Key_Ed448Signature:
		if sig.Ed448Signature == nil ||
			len(sig.Ed448Signature.Signature) == 0 {
			return fmt.Errorf("missing ed448 signature")
		}
		if !bytes.Equal(key.ParentKeyAddress, identityPeerID) {
			return fmt.Errorf("unexpected parent for ed448 signed decaf key")
		}
		valid, err := e.keyManager.ValidateSignature(
			crypto.KeyTypeEd448,
			keyRegistry.IdentityKey.KeyValue,
			msg,
			sig.Ed448Signature.Signature,
			nil,
		)
		if err != nil {
			return fmt.Errorf("failed to validate ed448 signature: %w", err)
		}
		if !valid {
			return fmt.Errorf("ed448 signature invalid")
		}
	case *protobufs.SignedDecaf448Key_BlsSignature:
		if sig.BlsSignature == nil ||
			len(sig.BlsSignature.Signature) == 0 {
			return fmt.Errorf("missing bls signature")
		}
		if len(proverAddress) != 0 &&
			!bytes.Equal(key.ParentKeyAddress, proverAddress) {
			return fmt.Errorf("unexpected parent for bls signed decaf key")
		}
		valid, err := e.keyManager.ValidateSignature(
			crypto.KeyTypeBLS48581G1,
			keyRegistry.ProverKey.KeyValue,
			key.Key.KeyValue,
			sig.BlsSignature.Signature,
			keyRegistryDomain,
		)
		if err != nil {
			return fmt.Errorf("failed to validate bls signature: %w", err)
		}
		if !valid {
			return fmt.Errorf("bls signature invalid")
		}
	case *protobufs.SignedDecaf448Key_DecafSignature:
		return fmt.Errorf("decaf signature validation not supported")
	default:
		return fmt.Errorf("missing signature for decaf key")
	}

	return nil
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

func (e *GlobalConsensusEngine) handleGlobalProposal(
	proposal *protobufs.GlobalProposal,
) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error(
				"panic recovered from proposal",
				zap.Any("panic", r),
				zap.Stack("stacktrace"),
			)
		}
	}()

	e.logger.Debug(
		"handling global proposal",
		zap.String("id", hex.EncodeToString([]byte(proposal.State.Identity()))),
	)

	// Small gotcha: the proposal structure uses interfaces, so we can't assign
	// directly, otherwise the nil values for the structs will fail the nil
	// check on the interfaces (and would incur costly reflection if we wanted
	// to check it directly)
	pqc := proposal.ParentQuorumCertificate
	prtc := proposal.PriorRankTimeoutCertificate
	vote := proposal.Vote
	signedProposal := &models.SignedProposal[*protobufs.GlobalFrame, *protobufs.ProposalVote]{
		Proposal: models.Proposal[*protobufs.GlobalFrame]{
			State: &models.State[*protobufs.GlobalFrame]{
				Rank:       proposal.State.GetRank(),
				Identifier: proposal.State.Identity(),
				ProposerID: proposal.Vote.Identity(),
				Timestamp:  proposal.State.GetTimestamp(),
				State:      &proposal.State,
			},
		},
		Vote: &vote,
	}

	if pqc != nil {
		signedProposal.Proposal.State.ParentQuorumCertificate = pqc
	}

	if prtc != nil {
		signedProposal.PreviousRankTimeoutCertificate = prtc
	}

	finalized := e.forks.FinalizedState()
	finalizedRank := finalized.Rank
	finalizedFrameNumber := (*finalized.State).Header.FrameNumber
	frameNumber := proposal.State.Header.FrameNumber

	// drop proposals if we already processed them
	if frameNumber <= finalizedFrameNumber ||
		proposal.State.Header.Rank <= finalizedRank {
		e.logger.Debug("dropping stale proposal")
		return
	}

	existingFrame, err := e.clockStore.GetGlobalClockFrame(frameNumber)
	if err == nil && existingFrame != nil {
		qc, qcErr := e.clockStore.GetQuorumCertificate(
			nil,
			proposal.State.GetRank(),
		)
		if qcErr == nil && qc != nil &&
			qc.GetFrameNumber() == frameNumber &&
			qc.Identity() == proposal.State.Identity() {
			e.logger.Debug("dropping stale proposal")
			return
		}
	}

	// if we have a parent, cache and move on
	if proposal.State.Header.FrameNumber != 0 {
		// also check with persistence layer
		parent, err := e.clockStore.GetGlobalClockFrame(
			proposal.State.Header.FrameNumber - 1,
		)
		if err != nil || !bytes.Equal(
			[]byte(parent.Identity()),
			proposal.State.Header.ParentSelector,
		) {
			e.logger.Debug(
				"parent frame not stored, requesting sync",
				zap.Uint64("frame_number", proposal.State.Header.FrameNumber-1),
			)
			e.cacheProposal(proposal)

			peerID, err := e.getPeerIDOfProver(proposal.State.Header.Prover)
			if err != nil {
				peerID, err = e.getRandomProverPeerId()
				if err != nil {
					return
				}
			}

			head, err := e.globalTimeReel.GetHead()
			if err != nil {
				return
			}

			e.syncProvider.AddState(
				[]byte(peerID),
				head.Header.FrameNumber,
				[]byte(head.Identity()),
			)
			return
		}
	}

	expectedFrame, err := e.globalTimeReel.GetHead()
	if err != nil {
		e.logger.Error("could not obtain time reel head", zap.Error(err))
		return
	}

	expectedFrameNumber := expectedFrame.Header.FrameNumber + 1

	if frameNumber < expectedFrameNumber {
		e.logger.Debug(
			"dropping proposal behind expected frame",
			zap.Uint64("frame_number", frameNumber),
			zap.Uint64("expected_frame_number", expectedFrameNumber),
		)
		return
	}

	if frameNumber == expectedFrameNumber {
		e.deleteCachedProposal(frameNumber)
		if e.processProposal(proposal) {
			e.drainProposalCache(frameNumber + 1)
			return
		}

		e.logger.Debug("failed to process expected proposal, caching")
		e.cacheProposal(proposal)
		return
	}

	e.cacheProposal(proposal)
	e.drainProposalCache(expectedFrameNumber)
}

func (e *GlobalConsensusEngine) processProposal(
	proposal *protobufs.GlobalProposal,
) bool {
	e.logger.Debug(
		"processing proposal",
		zap.String("id", hex.EncodeToString([]byte(proposal.State.Identity()))),
	)

	err := e.VerifyQuorumCertificate(proposal.ParentQuorumCertificate)
	if err != nil {
		e.logger.Debug("proposal has invalid qc", zap.Error(err))
		return false
	}

	if proposal.PriorRankTimeoutCertificate != nil {
		err := e.VerifyTimeoutCertificate(proposal.PriorRankTimeoutCertificate)
		if err != nil {
			e.logger.Debug("proposal has invalid tc", zap.Error(err))
			return false
		}
	}

	err = e.VerifyVote(&proposal.Vote)
	if err != nil {
		e.logger.Debug("proposal has invalid vote", zap.Error(err))
		return false
	}

	err = proposal.State.Validate()
	if err != nil {
		e.logger.Debug("proposal is not valid", zap.Error(err))
		return false
	}

	valid, err := e.frameValidator.Validate(proposal.State)
	if !valid || err != nil {
		e.logger.Debug("invalid frame in proposal", zap.Error(err))
		return false
	}

	// Small gotcha: the proposal structure uses interfaces, so we can't assign
	// directly, otherwise the nil values for the structs will fail the nil
	// check on the interfaces (and would incur costly reflection if we wanted
	// to check it directly)
	pqc := proposal.ParentQuorumCertificate
	prtc := proposal.PriorRankTimeoutCertificate
	vote := proposal.Vote
	signedProposal := &models.SignedProposal[*protobufs.GlobalFrame, *protobufs.ProposalVote]{
		Proposal: models.Proposal[*protobufs.GlobalFrame]{
			State: &models.State[*protobufs.GlobalFrame]{
				Rank:       proposal.State.GetRank(),
				Identifier: proposal.State.Identity(),
				ProposerID: vote.Identity(),
				Timestamp:  proposal.State.GetTimestamp(),
				State:      &proposal.State,
			},
		},
		Vote: &vote,
	}

	if pqc != nil {
		signedProposal.Proposal.State.ParentQuorumCertificate = pqc
	}

	if prtc != nil {
		signedProposal.PreviousRankTimeoutCertificate = prtc
	}

	// IMPORTANT: we do not want to send old proposals to the vote aggregator or
	// we risk engine shutdown if the leader selection method changed – frame
	// validation ensures that the proposer is valid for the proposal per time
	// reel rules.
	if signedProposal.State.Rank >= e.currentRank {
		e.voteAggregator.AddState(signedProposal)
	}
	e.consensusParticipant.SubmitProposal(signedProposal)

	e.trySealParentWithChild(proposal)
	e.registerPendingCertifiedParent(proposal)

	return true
}

func (e *GlobalConsensusEngine) cacheProposal(
	proposal *protobufs.GlobalProposal,
) {
	frameNumber := proposal.State.Header.FrameNumber
	e.proposalCacheMu.Lock()
	e.proposalCache[frameNumber] = proposal
	e.proposalCacheMu.Unlock()

	e.logger.Debug(
		"cached out-of-order proposal",
		zap.Uint64("frame_number", frameNumber),
		zap.String("id", hex.EncodeToString([]byte(proposal.State.Identity()))),
	)
}

func (e *GlobalConsensusEngine) deleteCachedProposal(frameNumber uint64) {
	e.proposalCacheMu.Lock()
	delete(e.proposalCache, frameNumber)
	e.proposalCacheMu.Unlock()
}

func (e *GlobalConsensusEngine) popCachedProposal(
	frameNumber uint64,
) *protobufs.GlobalProposal {
	e.proposalCacheMu.Lock()
	defer e.proposalCacheMu.Unlock()

	proposal, ok := e.proposalCache[frameNumber]
	if ok {
		delete(e.proposalCache, frameNumber)
	}

	return proposal
}

func (e *GlobalConsensusEngine) drainProposalCache(startFrame uint64) {
	next := startFrame
	for {
		prop := e.popCachedProposal(next)
		if prop == nil {
			return
		}

		if !e.processProposal(prop) {
			e.logger.Debug(
				"cached proposal failed processing, retaining for retry",
				zap.Uint64("frame_number", next),
			)
			e.cacheProposal(prop)
			return
		}

		next++
	}
}

func (e *GlobalConsensusEngine) registerPendingCertifiedParent(
	proposal *protobufs.GlobalProposal,
) {
	if proposal == nil || proposal.State == nil || proposal.State.Header == nil {
		return
	}

	frameNumber := proposal.State.Header.FrameNumber
	e.pendingCertifiedParentsMu.Lock()
	e.pendingCertifiedParents[frameNumber] = proposal
	e.pendingCertifiedParentsMu.Unlock()
}

func (e *GlobalConsensusEngine) trySealParentWithChild(
	child *protobufs.GlobalProposal,
) {
	if child == nil || child.State == nil || child.State.Header == nil {
		return
	}

	header := child.State.Header
	if header.FrameNumber == 0 {
		return
	}

	parentFrame := header.FrameNumber - 1

	e.pendingCertifiedParentsMu.RLock()
	parent, ok := e.pendingCertifiedParents[parentFrame]
	e.pendingCertifiedParentsMu.RUnlock()
	if !ok || parent == nil || parent.State == nil || parent.State.Header == nil {
		return
	}

	if !bytes.Equal(
		header.ParentSelector,
		[]byte(parent.State.Identity()),
	) {
		e.logger.Debug(
			"pending parent selector mismatch, dropping entry",
			zap.Uint64("parent_frame", parent.State.Header.FrameNumber),
			zap.Uint64("child_frame", header.FrameNumber),
		)
		e.pendingCertifiedParentsMu.Lock()
		delete(e.pendingCertifiedParents, parentFrame)
		e.pendingCertifiedParentsMu.Unlock()
		return
	}

	e.logger.Debug(
		"sealing parent with descendant proposal",
		zap.Uint64("parent_frame", parent.State.Header.FrameNumber),
		zap.Uint64("child_frame", header.FrameNumber),
	)

	head, err := e.globalTimeReel.GetHead()
	if err != nil {
		e.logger.Error("error fetching time reel head", zap.Error(err))
		return
	}

	if head.Header.FrameNumber+1 == parent.State.Header.FrameNumber {
		e.addCertifiedState(parent, child)
	}

	e.pendingCertifiedParentsMu.Lock()
	delete(e.pendingCertifiedParents, parentFrame)
	e.pendingCertifiedParentsMu.Unlock()
}

func (e *GlobalConsensusEngine) addCertifiedState(
	parent, child *protobufs.GlobalProposal,
) {
	if parent == nil || parent.State == nil || parent.State.Header == nil ||
		child == nil || child.State == nil || child.State.Header == nil {
		e.logger.Error("cannot seal certified state: missing parent or child data")
		return
	}

	txn, err := e.clockStore.NewTransaction(false)
	if err != nil {
		e.logger.Error("could not create transaction", zap.Error(err))
		return
	}

	qc := child.ParentQuorumCertificate
	if qc == nil {
		e.logger.Error(
			"child missing parent quorum certificate",
			zap.Uint64("child_frame_number", child.State.Header.FrameNumber),
		)
		return
	}
	aggregateSig := &protobufs.BLS48581AggregateSignature{
		Signature: qc.GetAggregatedSignature().GetSignature(),
		PublicKey: &protobufs.BLS48581G2PublicKey{
			KeyValue: qc.GetAggregatedSignature().GetPubKey(),
		},
		Bitmask: qc.GetAggregatedSignature().GetBitmask(),
	}
	if err := e.clockStore.PutQuorumCertificate(
		&protobufs.QuorumCertificate{
			Rank:               qc.GetRank(),
			FrameNumber:        qc.GetFrameNumber(),
			Selector:           []byte(qc.Identity()),
			AggregateSignature: aggregateSig,
		},
		txn,
	); err != nil {
		e.logger.Error("could not insert quorum certificate", zap.Error(err))
		txn.Abort()
		return
	}

	if err := txn.Commit(); err != nil {
		e.logger.Error("could not commit transaction", zap.Error(err))
		txn.Abort()
		return
	}

	parent.State.Header.PublicKeySignatureBls48581 = aggregateSig

	err = e.globalTimeReel.Insert(parent.State)
	if err != nil {
		e.logger.Error("could not insert frame into time reel", zap.Error(err))
		return
	}

	current, err := e.globalTimeReel.GetHead()
	if err != nil {
		e.logger.Error("could not get time reel head", zap.Error(err))
		return
	}

	if !bytes.Equal(parent.State.Header.Output, current.Header.Output) {
		e.logger.Error(
			"frames not aligned",
			zap.Uint64("parent_frame_number", parent.State.Header.FrameNumber),
			zap.Uint64("new_frame_number", child.State.Header.FrameNumber),
			zap.Uint64("reel_frame_number", current.Header.FrameNumber),
			zap.Uint64("new_frame_rank", child.State.Header.Rank),
			zap.Uint64("reel_frame_rank", current.Header.Rank),
			zap.String(
				"new_frame_id",
				hex.EncodeToString([]byte(child.State.Identity())),
			),
			zap.String(
				"reel_frame_id",
				hex.EncodeToString([]byte(current.Identity())),
			),
		)
		return
	}

	txn, err = e.clockStore.NewTransaction(false)
	if err != nil {
		e.logger.Error("could not create transaction", zap.Error(err))
		return
	}

	if err := e.clockStore.PutCertifiedGlobalState(
		parent,
		txn,
	); err != nil {
		e.logger.Error("could not insert certified state", zap.Error(err))
		txn.Abort()
		return
	}

	if err := txn.Commit(); err != nil {
		e.logger.Error("could not commit transaction", zap.Error(err))
		txn.Abort()
		return
	}
}

func (e *GlobalConsensusEngine) handleProposal(message *pb.Message) {
	// Skip our own messages
	if bytes.Equal(message.From, e.pubsub.GetPeerID()) {
		return
	}

	timer := prometheus.NewTimer(proposalProcessingDuration)
	defer timer.ObserveDuration()

	proposal := &protobufs.GlobalProposal{}
	if err := proposal.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal proposal", zap.Error(err))
		proposalProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	frameIDBI, _ := poseidon.HashBytes(proposal.State.Header.Output)
	frameID := frameIDBI.FillBytes(make([]byte, 32))
	e.frameStoreMu.Lock()
	e.frameStore[string(frameID)] = proposal.State
	e.frameStoreMu.Unlock()

	txn, err := e.clockStore.NewTransaction(false)
	if err != nil {
		e.logger.Error("could not create transaction", zap.Error(err))
		return
	}

	if err := e.clockStore.PutProposalVote(txn, proposal.Vote); err != nil {
		e.logger.Error("could not put vote", zap.Error(err))
		txn.Abort()
		return
	}

	if err := e.clockStore.PutGlobalClockFrameCandidate(
		proposal.State,
		txn,
	); err != nil {
		e.logger.Error("could not put frame", zap.Error(err))
		txn.Abort()
		return
	}

	if err := txn.Commit(); err != nil {
		e.logger.Error("could not commit transaction", zap.Error(err))
		txn.Abort()
		return
	}

	e.globalProposalQueue <- proposal

	// Success metric recorded at the end of processing
	proposalProcessedTotal.WithLabelValues("success").Inc()
}

func (e *GlobalConsensusEngine) handleVote(message *pb.Message) {
	// Skip our own messages
	if bytes.Equal(message.From, e.pubsub.GetPeerID()) {
		return
	}

	timer := prometheus.NewTimer(voteProcessingDuration)
	defer timer.ObserveDuration()

	vote := &protobufs.ProposalVote{}
	if err := vote.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal vote", zap.Error(err))
		voteProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	// Validate the vote structure
	if err := vote.Validate(); err != nil {
		e.logger.Debug("invalid vote", zap.Error(err))
		voteProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	if vote.PublicKeySignatureBls48581 == nil {
		e.logger.Error("vote had no signature")
		voteProcessedTotal.WithLabelValues("error").Inc()
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

	txn, err := e.clockStore.NewTransaction(false)
	if err != nil {
		e.logger.Error("could not create transaction", zap.Error(err))
		return
	}

	if err := e.clockStore.PutProposalVote(txn, vote); err != nil {
		e.logger.Error("could not put vote", zap.Error(err))
		txn.Abort()
		return
	}

	if err := txn.Commit(); err != nil {
		e.logger.Error("could not commit transaction", zap.Error(err))
		txn.Abort()
		return
	}

	e.voteAggregator.AddVote(&vote)
	voteProcessedTotal.WithLabelValues("success").Inc()
}

func (e *GlobalConsensusEngine) handleTimeoutState(message *pb.Message) {
	// Skip our own messages
	if bytes.Equal(message.From, e.pubsub.GetPeerID()) {
		return
	}

	timer := prometheus.NewTimer(voteProcessingDuration)
	defer timer.ObserveDuration()

	timeoutState := &protobufs.TimeoutState{}
	if err := timeoutState.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal timeout", zap.Error(err))
		voteProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	// Validate the vote structure
	if err := timeoutState.Validate(); err != nil {
		e.logger.Debug("invalid timeout", zap.Error(err))
		voteProcessedTotal.WithLabelValues("error").Inc()
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

	txn, err := e.clockStore.NewTransaction(false)
	if err != nil {
		e.logger.Error("could not create transaction", zap.Error(err))
		return
	}

	if err := e.clockStore.PutTimeoutVote(txn, timeoutState); err != nil {
		e.logger.Error("could not put vote", zap.Error(err))
		txn.Abort()
		return
	}

	if err := txn.Commit(); err != nil {
		e.logger.Error("could not commit transaction", zap.Error(err))
		txn.Abort()
		return
	}

	e.timeoutAggregator.AddTimeout(timeout)

	voteProcessedTotal.WithLabelValues("success").Inc()
}

func (e *GlobalConsensusEngine) handleMessageBundle(message *pb.Message) {
	// MessageBundle messages need to be collected for execution
	// Store them in pendingMessages to be processed during Collect
	e.pendingMessagesMu.Lock()
	e.pendingMessages = append(e.pendingMessages, message.Data)
	e.pendingMessagesMu.Unlock()

	e.logger.Debug("collected global request for execution")
}

func (e *GlobalConsensusEngine) handleShardProposal(message *pb.Message) {
	timer := prometheus.NewTimer(shardProposalProcessingDuration)
	defer timer.ObserveDuration()

	frame := &protobufs.AppShardFrame{}
	if err := frame.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal frame", zap.Error(err))
		shardProposalProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	if valid, err := e.appFrameValidator.Validate(frame); err != nil || !valid {
		e.logger.Debug("invalid frame", zap.Error(err))
		shardProposalProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	clonedFrame := frame.Clone().(*protobufs.AppShardFrame)

	e.appFrameStoreMu.Lock()
	frameID := fmt.Sprintf("%x%d", frame.Header.Prover, frame.Header.FrameNumber)
	selectorBI, err := poseidon.HashBytes(frame.Header.Output)
	if err != nil {
		e.logger.Debug("invalid selector", zap.Error(err))
		shardProposalProcessedTotal.WithLabelValues("error").Inc()
		e.appFrameStoreMu.Unlock()
		return
	}
	e.appFrameStore[frameID] = clonedFrame
	e.appFrameStore[string(selectorBI.FillBytes(make([]byte, 32)))] = clonedFrame
	e.appFrameStoreMu.Unlock()

	e.txLockMu.Lock()
	if _, ok := e.txLockMap[frame.Header.FrameNumber]; !ok {
		e.txLockMap[frame.Header.FrameNumber] = make(
			map[string]map[string]*LockedTransaction,
		)
	}
	_, ok := e.txLockMap[frame.Header.FrameNumber][string(frame.Header.Address)]
	if !ok {
		e.txLockMap[frame.Header.FrameNumber][string(frame.Header.Address)] =
			make(map[string]*LockedTransaction)
	}
	set := e.txLockMap[frame.Header.FrameNumber][string(frame.Header.Address)]
	for _, l := range set {
		for _, p := range slices.Collect(slices.Chunk(l.Prover, 32)) {
			if bytes.Equal(p, frame.Header.Prover) {
				l.Committed = true
			}
		}
	}
	e.txLockMu.Unlock()

	// Success metric recorded at the end of processing
	shardProposalProcessedTotal.WithLabelValues("success").Inc()
}

func (e *GlobalConsensusEngine) handleShardLivenessCheck(message *pb.Message) {
	timer := prometheus.NewTimer(shardLivenessCheckProcessingDuration)
	defer timer.ObserveDuration()

	livenessCheck := &protobufs.ProverLivenessCheck{}
	if err := livenessCheck.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal liveness check", zap.Error(err))
		shardLivenessCheckProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	// Validate the liveness check structure
	if err := livenessCheck.Validate(); err != nil {
		e.logger.Debug("invalid liveness check", zap.Error(err))
		shardLivenessCheckProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	proverSet, err := e.proverRegistry.GetActiveProvers(livenessCheck.Filter)
	if err != nil {
		e.logger.Error("could not receive liveness check", zap.Error(err))
		shardLivenessCheckProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	var found []byte = nil
	for _, prover := range proverSet {
		if bytes.Equal(
			prover.Address,
			livenessCheck.PublicKeySignatureBls48581.Address,
		) {
			lcBytes, err := livenessCheck.ConstructSignaturePayload()
			if err != nil {
				e.logger.Error(
					"could not construct signature message for liveness check",
					zap.Error(err),
				)
				shardLivenessCheckProcessedTotal.WithLabelValues("error").Inc()
				break
			}
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
				shardLivenessCheckProcessedTotal.WithLabelValues("error").Inc()
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
		shardLivenessCheckProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	if len(livenessCheck.CommitmentHash) > 32 {
		e.txLockMu.Lock()
		if _, ok := e.txLockMap[livenessCheck.FrameNumber]; !ok {
			e.txLockMap[livenessCheck.FrameNumber] = make(
				map[string]map[string]*LockedTransaction,
			)
		}
		_, ok := e.txLockMap[livenessCheck.FrameNumber][string(livenessCheck.Filter)]
		if !ok {
			e.txLockMap[livenessCheck.FrameNumber][string(livenessCheck.Filter)] =
				make(map[string]*LockedTransaction)
		}

		filter := string(livenessCheck.Filter)

		commits, err := tries.DeserializeNonLazyTree(
			livenessCheck.CommitmentHash[32:],
		)
		if err != nil {
			e.txLockMu.Unlock()
			e.logger.Error("could not deserialize commitment trie", zap.Error(err))
			shardLivenessCheckProcessedTotal.WithLabelValues("error").Inc()
			return
		}

		leaves := tries.GetAllPreloadedLeaves(commits.Root)
		for _, leaf := range leaves {
			existing, ok := e.txLockMap[livenessCheck.FrameNumber][filter][string(leaf.Key)]
			prover := []byte{}
			if ok {
				prover = existing.Prover
			}

			prover = append(
				prover,
				livenessCheck.PublicKeySignatureBls48581.Address...,
			)

			e.txLockMap[livenessCheck.FrameNumber][filter][string(leaf.Key)] =
				&LockedTransaction{
					TransactionHash: leaf.Key,
					ShardAddresses:  slices.Collect(slices.Chunk(leaf.Value, 64)),
					Prover:          prover,
					Committed:       false,
					Filled:          false,
				}
		}
		e.txLockMu.Unlock()
	}

	shardLivenessCheckProcessedTotal.WithLabelValues("success").Inc()
}

func (e *GlobalConsensusEngine) handleShardVote(message *pb.Message) {
	timer := prometheus.NewTimer(shardVoteProcessingDuration)
	defer timer.ObserveDuration()

	vote := &protobufs.ProposalVote{}
	if err := vote.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal vote", zap.Error(err))
		shardVoteProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	// Validate the vote structure
	if err := vote.Validate(); err != nil {
		e.logger.Debug("invalid vote", zap.Error(err))
		shardVoteProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	if vote.PublicKeySignatureBls48581 == nil {
		e.logger.Error("vote without signature")
		shardVoteProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	// Validate the voter's signature
	proverSet, err := e.proverRegistry.GetActiveProvers(vote.Filter)
	if err != nil {
		e.logger.Error("could not get active provers", zap.Error(err))
		shardVoteProcessedTotal.WithLabelValues("error").Inc()
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
		shardVoteProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	e.appFrameStoreMu.Lock()
	frameID := fmt.Sprintf("%x%d", vote.Identity(), vote.FrameNumber)
	proposalFrame := e.appFrameStore[frameID]
	e.appFrameStoreMu.Unlock()

	if proposalFrame == nil {
		e.logger.Error("could not find proposed frame")
		shardVoteProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	// Get the signature payload for the proposal
	signatureData := verification.MakeVoteMessage(
		proposalFrame.Header.Address,
		proposalFrame.GetRank(),
		proposalFrame.Source(),
	)

	// Validate the vote signature
	valid, err := e.keyManager.ValidateSignature(
		crypto.KeyTypeBLS48581G1,
		voterPublicKey,
		signatureData,
		vote.PublicKeySignatureBls48581.Signature,
		slices.Concat([]byte("appshard"), vote.Filter),
	)

	if err != nil || !valid {
		e.logger.Error("invalid vote signature", zap.Error(err))
		shardVoteProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	shardVoteProcessedTotal.WithLabelValues("success").Inc()
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
