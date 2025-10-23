package global

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

var keyRegistryDomain = []byte("KEY_REGISTRY")

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

func (e *GlobalConsensusEngine) processShardConsensusMessageQueue() {
	defer e.wg.Done()

	for {
		select {
		case <-e.haltCtx.Done():
			return
		case <-e.ctx.Done():
			return
		case message := <-e.shardConsensusMessageQueue:
			e.handleShardConsensusMessage(message)
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
	case protobufs.GlobalFrameType:
		e.handleShardProposal(message)

	case protobufs.ProverLivenessCheckType:
		e.handleShardLivenessCheck(message)

	case protobufs.FrameVoteType:
		e.handleShardVote(message)

	case protobufs.FrameConfirmationType:
		e.handleShardConfirmation(message)
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
	timer := prometheus.NewTimer(proposalProcessingDuration)
	defer timer.ObserveDuration()

	frame := &protobufs.GlobalFrame{}
	if err := frame.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal frame", zap.Error(err))
		proposalProcessedTotal.WithLabelValues("error").Inc()
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
			proposalProcessedTotal.WithLabelValues("error").Inc()
			return
		}
	}

	// Success metric recorded at the end of processing
	proposalProcessedTotal.WithLabelValues("success").Inc()
}

func (e *GlobalConsensusEngine) handleLivenessCheck(message *pb.Message) {
	timer := prometheus.NewTimer(livenessCheckProcessingDuration)
	defer timer.ObserveDuration()

	livenessCheck := &protobufs.ProverLivenessCheck{}
	if err := livenessCheck.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal liveness check", zap.Error(err))
		livenessCheckProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	// Validate the liveness check structure
	if err := livenessCheck.Validate(); err != nil {
		e.logger.Debug("invalid liveness check", zap.Error(err))
		livenessCheckProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	proverSet, err := e.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		e.logger.Error("could not receive liveness check", zap.Error(err))
		livenessCheckProcessedTotal.WithLabelValues("error").Inc()
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
		livenessCheckProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	signatureData, err := livenessCheck.ConstructSignaturePayload()
	if err != nil {
		e.logger.Error("invalid signature payload", zap.Error(err))
		livenessCheckProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	valid, err := e.keyManager.ValidateSignature(
		crypto.KeyTypeBLS48581G1,
		found,
		signatureData,
		livenessCheck.PublicKeySignatureBls48581.Signature,
		livenessCheck.GetSignatureDomain(),
	)

	if err != nil || !valid {
		e.logger.Error("invalid liveness check signature", zap.Error(err))
		livenessCheckProcessedTotal.WithLabelValues("error").Inc()
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
		livenessCheckProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	livenessCheckProcessedTotal.WithLabelValues("success").Inc()
}

func (e *GlobalConsensusEngine) handleVote(message *pb.Message) {
	timer := prometheus.NewTimer(voteProcessingDuration)
	defer timer.ObserveDuration()

	vote := &protobufs.FrameVote{}
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

	// Validate the voter's signature
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
		voteProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	// Get the signature payload for the proposal
	signatureData, err := e.frameProver.GetGlobalFrameSignaturePayload(
		proposalFrame.Header,
	)
	if err != nil {
		e.logger.Error("could not get signature payload", zap.Error(err))
		voteProcessedTotal.WithLabelValues("error").Inc()
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
		voteProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	// Signature is valid, process the vote
	if err := e.stateMachine.ReceiveVote(
		GlobalPeerID{ID: vote.Proposer},
		GlobalPeerID{ID: vote.PublicKeySignatureBls48581.Address},
		&vote,
	); err != nil {
		e.logger.Error("could not receive vote", zap.Error(err))
		voteProcessedTotal.WithLabelValues("error").Inc()
		return
	}

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

func (e *GlobalConsensusEngine) handleConfirmation(message *pb.Message) {
	timer := prometheus.NewTimer(confirmationProcessingDuration)
	defer timer.ObserveDuration()

	confirmation := &protobufs.FrameConfirmation{}
	if err := confirmation.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal confirmation", zap.Error(err))
		confirmationProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	// Validate the confirmation structure
	if err := confirmation.Validate(); err != nil {
		e.logger.Debug("invalid confirmation", zap.Error(err))
		confirmationProcessedTotal.WithLabelValues("error").Inc()
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
		confirmationProcessedTotal.WithLabelValues("error").Inc()
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
			confirmationProcessedTotal.WithLabelValues("error").Inc()
			return
		}
	}
	err = e.globalTimeReel.Insert(e.ctx, matchingFrame)
	if err != nil {
		e.logger.Error(
			"could not insert into time reel",
			zap.Error(err),
		)
		confirmationProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	confirmationProcessedTotal.WithLabelValues("success").Inc()
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

	vote := &protobufs.FrameVote{}
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
	frameID := fmt.Sprintf("%x%d", vote.Proposer, vote.FrameNumber)
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
		[]byte("global"),
	)

	if err != nil || !valid {
		e.logger.Error("invalid vote signature", zap.Error(err))
		shardVoteProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	shardVoteProcessedTotal.WithLabelValues("success").Inc()
}

func (e *GlobalConsensusEngine) handleShardConfirmation(message *pb.Message) {
	timer := prometheus.NewTimer(shardConfirmationProcessingDuration)
	defer timer.ObserveDuration()

	confirmation := &protobufs.FrameConfirmation{}
	if err := confirmation.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal confirmation", zap.Error(err))
		shardConfirmationProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	// Validate the confirmation structure
	if err := confirmation.Validate(); err != nil {
		e.logger.Debug("invalid confirmation", zap.Error(err))
		shardConfirmationProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	e.appFrameStoreMu.Lock()
	matchingFrame := e.appFrameStore[string(confirmation.Selector)]
	e.appFrameStoreMu.Unlock()

	if matchingFrame == nil {
		e.logger.Error("could not find matching frame")
		shardConfirmationProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	matchingFrame.Header.PublicKeySignatureBls48581 =
		confirmation.AggregateSignature
	valid, err := e.appFrameValidator.Validate(matchingFrame)
	if !valid || err != nil {
		e.logger.Error("received invalid confirmation", zap.Error(err))
		shardConfirmationProcessedTotal.WithLabelValues("error").Inc()
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

	e.txLockMu.Lock()
	if _, ok := e.txLockMap[confirmation.FrameNumber]; !ok {
		e.txLockMap[confirmation.FrameNumber] = make(
			map[string]map[string]*LockedTransaction,
		)
	}
	_, ok := e.txLockMap[confirmation.FrameNumber][string(confirmation.Filter)]
	if !ok {
		e.txLockMap[confirmation.FrameNumber][string(confirmation.Filter)] =
			make(map[string]*LockedTransaction)
	}
	txSet := e.txLockMap[confirmation.FrameNumber][string(confirmation.Filter)]
	for _, l := range txSet {
		for _, p := range slices.Collect(slices.Chunk(l.Prover, 32)) {
			if bytes.Equal(p, matchingFrame.Header.Prover) {
				l.Committed = true
				l.Filled = true
			}
		}
	}
	e.txLockMu.Unlock()

	shardConfirmationProcessedTotal.WithLabelValues("success").Inc()
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
