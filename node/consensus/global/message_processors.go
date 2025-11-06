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
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
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
	identityPeerID := []byte(peerID.String())

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

	// Small gotcha: the proposal structure uses interfaces, so we can't assign
	// directly, otherwise the nil values for the structs will fail the nil
	// check on the interfaces (and would incur costly reflection if we wanted
	// to check it directly)
	pqc := proposal.ParentQuorumCertificate
	prtc := proposal.PriorRankTimeoutCertificate
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
		Vote: &proposal.Vote,
	}

	if pqc != nil {
		signedProposal.Proposal.State.ParentQuorumCertificate = pqc
	}

	if prtc != nil {
		signedProposal.PreviousRankTimeoutCertificate = prtc
	}

	e.voteAggregator.AddState(signedProposal)
	e.consensusParticipant.SubmitProposal(signedProposal)

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
	signatureData, err := e.frameProver.GetFrameSignaturePayload(
		proposalFrame.Header,
	)
	if err != nil {
		e.logger.Error("could not get signature payload", zap.Error(err))
		shardVoteProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	// Validate the vote signature
	valid, err := e.keyManager.ValidateSignature(
		crypto.KeyTypeBLS48581G1,
		voterPublicKey,
		signatureData,
		vote.PublicKeySignatureBls48581.Signature,
		[]byte("appshard"),
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
