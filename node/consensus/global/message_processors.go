package global

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/verification"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/rpc"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

var keyRegistryDomain = []byte("KEY_REGISTRY")

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
		if err := e.addGlobalMessage(message.Data); err != nil {
			e.logger.Warn(
				"prover message rejected by collector",
				zap.Error(err),
			)
		} else {
			e.logger.Debug(
				"collected global request for execution",
				zap.Uint32("type", typePrefix),
			)
		}

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

		e.processGlobalFrame(frame)
	default:
		e.logger.Debug(
			"unknown message type",
			zap.Uint32("type", typePrefix),
		)
	}
}

// processGlobalFrame is the core frame-processing pipeline shared by both
// the pubsub path (handleFrameMessage) and the archive polling path
// (pollFramesFromArchive).
func (e *GlobalConsensusEngine) processGlobalFrame(frame *protobufs.GlobalFrame) {
	valid, err := e.frameValidator.Validate(frame)
	if err != nil {
		e.logger.Debug("global frame validation error", zap.Error(err))
		framesProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	if !valid {
		framesProcessedTotal.WithLabelValues("error").Inc()
		e.logger.Debug("invalid global frame")
		return
	}

	if frame.Header != nil {
		e.recordFrameMessageFrameNumber(frame.Header.FrameNumber)
	}

	frameIDBI, _ := poseidon.HashBytes(frame.Header.Output)
	frameID := frameIDBI.FillBytes(make([]byte, 32))
	e.frameStoreMu.Lock()
	e.frameStore[string(frameID)] = frame
	clone := frame.Clone().(*protobufs.GlobalFrame)
	e.frameStoreMu.Unlock()

	if err := e.globalTimeReel.Insert(clone); err != nil {
		framesProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	// Broadcast to workers AFTER the time reel insert (which triggers
	// materialize). This ensures the master's snapshot reflects the correct
	// tree state before workers try to verify the prover root and sync.
	if frameBytes, err := frame.ToCanonicalBytes(); err == nil {
		e.broadcastGlobalMessage(frameBytes, GLOBAL_FRAME_BITMASK)
	}

	head, err := e.globalTimeReel.GetHead()
	if err == nil && head != nil {
		e.consensusProtocol.currentRank = head.GetRank()
	}

	framesProcessedTotal.WithLabelValues("success").Inc()
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
	if e.isConsensusParticipant() {
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

		e.appFrameStoreMu.RLock()
		existing, ok := e.appFrameStore[string(frame.Header.Address)]
		if ok && existing != nil &&
			existing.Header.FrameNumber >= frame.Header.FrameNumber {
			e.appFrameStoreMu.RUnlock()
			return
		}
		e.appFrameStoreMu.RUnlock()

		valid, err := e.appFrameValidator.Validate(frame)
		if !valid || err != nil {
			e.logger.Debug("failed to validate frame", zap.Error(err))
			shardFramesProcessedTotal.WithLabelValues("error").Inc()
		}

		bundle := &protobufs.MessageBundle{
			Requests: []*protobufs.MessageRequest{
				{
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
			return
		}

		if err := e.addGlobalMessage(bundleBytes); err != nil {
			e.logger.Warn("shard frame rejected by collector", zap.Error(err))
		}
		if err := e.publishProverMessage(bundleBytes); err != nil {
			e.logger.Warn(
				"failed to forward shard frame to archive",
				zap.Error(err),
			)
		}
		e.appFrameStoreMu.Lock()
		defer e.appFrameStoreMu.Unlock()
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

		if e.isDuplicatePeerInfo(peerInfo) {
			e.peerInfoManager.GetPeerInfo(peerInfo.PeerId).LastSeen =
				time.Now().UnixMilli()
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

		// Try to discover an archive endpoint from the peer's capabilities
		e.tryDiscoverArchiveEndpoint(peerInfo)
	case protobufs.KeyRegistryType:
		keyRegistry := &protobufs.KeyRegistry{}
		if err := keyRegistry.FromCanonicalBytes(message.Data); err != nil {
			e.logger.Debug("failed to unmarshal key registry", zap.Error(err))
			return
		}

		if e.isDuplicateKeyRegistry(keyRegistry) {
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

func (e *GlobalConsensusEngine) isDuplicatePeerInfo(
	peerInfo *protobufs.PeerInfo,
) bool {
	digest, err := hashPeerInfo(peerInfo)
	if err != nil {
		e.logger.Warn("failed to hash peer info", zap.Error(err))
		return false
	}

	e.peerInfoDigestCacheMu.Lock()
	defer e.peerInfoDigestCacheMu.Unlock()

	if _, ok := e.peerInfoDigestCache[digest]; ok {
		return true
	}

	e.peerInfoDigestCache[digest] = struct{}{}
	return false
}

func (e *GlobalConsensusEngine) isDuplicateKeyRegistry(
	keyRegistry *protobufs.KeyRegistry,
) bool {
	digest, err := hashKeyRegistry(keyRegistry)
	if err != nil {
		e.logger.Warn("failed to hash key registry", zap.Error(err))
		return false
	}

	e.keyRegistryDigestCacheMu.Lock()
	defer e.keyRegistryDigestCacheMu.Unlock()

	if _, ok := e.keyRegistryDigestCache[digest]; ok {
		return true
	}

	e.keyRegistryDigestCache[digest] = struct{}{}
	return false
}

func hashPeerInfo(peerInfo *protobufs.PeerInfo) (string, error) {
	cloned := proto.Clone(peerInfo).(*protobufs.PeerInfo)
	cloned.Timestamp = 0

	data, err := cloned.ToCanonicalBytes()
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func hashKeyRegistry(keyRegistry *protobufs.KeyRegistry) (string, error) {
	cloned := proto.Clone(keyRegistry).(*protobufs.KeyRegistry)
	cloned.LastUpdated = 0

	data, err := cloned.ToCanonicalBytes()
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
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

		e.coverageMonitor.emitAlertEvent(alert.Message)

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

	frame := proposal.State
	var proverRootHex string
	if frame.Header != nil {
		proverRootHex = hex.EncodeToString(frame.Header.ProverTreeCommitment)
	}
	proposerHex := ""
	if proposal.Vote != nil {
		proposerHex = hex.EncodeToString([]byte(proposal.Vote.Identity()))
	}
	e.logger.Debug(
		"handling global proposal",
		zap.Uint64("rank", proposal.GetRank()),
		zap.Uint64("frame_number", frame.GetFrameNumber()),
		zap.Int("request_count", len(frame.GetRequests())),
		zap.String("id", hex.EncodeToString([]byte(frame.Identity()))),
		zap.String("prover_root", proverRootHex),
		zap.String("proposer", proposerHex),
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

	finalized := e.consensusProtocol.forks.FinalizedState()
	finalizedRank := finalized.Rank
	finalizedFrameNumber := (*finalized.State).Header.FrameNumber
	frameNumber := proposal.State.Header.FrameNumber

	// drop proposals if we already processed them, unless we need to
	// rehydrate the finalized frame in persistence
	if frameNumber <= finalizedFrameNumber ||
		proposal.State.Header.Rank <= finalizedRank {
		if e.tryRecoverFinalizedFrame(proposal, finalized) {
			return
		}

		e.logger.Debug(
			"dropping stale (lower than finalized) proposal",
			zap.Uint64("finalized_rank", finalizedRank),
			zap.Uint64("finalized_frame_number", finalizedFrameNumber),
			zap.Uint64("rank", proposal.GetRank()),
			zap.Uint64("frame_number", proposal.State.GetFrameNumber()),
		)
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
			e.logger.Debug(
				"dropping stale (already committed) proposal",
				zap.Uint64("rank", proposal.GetRank()),
				zap.Uint64("frame_number", proposal.State.GetFrameNumber()),
			)
			return
		}
	}

	// if we have a parent, cache and move on
	if proposal.State.Header.FrameNumber != 0 {
		_, sErr := e.clockStore.GetGlobalClockFrame(
			proposal.State.Header.FrameNumber - 1,
		)
		// also check with persistence layer
		_, cErr := e.clockStore.GetGlobalClockFrameCandidate(
			proposal.State.Header.FrameNumber-1,
			proposal.State.Header.ParentSelector,
		)
		if sErr != nil && cErr != nil {
			e.logger.Debug(
				"parent frame not stored, requesting sync",
				zap.Uint64("rank", proposal.GetRank()),
				zap.Uint64("frame_number", proposal.State.GetFrameNumber()),
				zap.Uint64("parent_frame_number", proposal.State.Header.FrameNumber-1),
			)
			e.cacheProposal(proposal)

			peerID, err := e.getPeerIDOfProver(proposal.State.Header.Prover)
			if err != nil {
				peerID, err = e.getRandomProverPeerId()
				if err != nil {
					return
				}
			}

			head := e.consensusProtocol.forks.FinalizedState()

			e.consensusProtocol.syncProvider.AddState(
				[]byte(peerID),
				(*head.State).Header.FrameNumber,
				[]byte(head.Identifier),
			)
			return
		}
	}

	if e.frameChainChecker != nil &&
		e.frameChainChecker.CanProcessSequentialChain(finalized, proposal) {
		e.deleteCachedProposal(frameNumber)
		if e.processProposal(proposal) {
			e.drainProposalCache(frameNumber + 1)
			return
		}

		e.logger.Debug("failed to process sequential proposal, caching")
		e.cacheProposal(proposal)
		return
	}

	e.cacheProposal(proposal)
}

func (e *GlobalConsensusEngine) tryRecoverFinalizedFrame(
	proposal *protobufs.GlobalProposal,
	finalized *models.State[*protobufs.GlobalFrame],
) bool {
	if proposal == nil ||
		proposal.State == nil ||
		proposal.State.Header == nil ||
		finalized == nil ||
		finalized.State == nil ||
		(*finalized.State).Header == nil {
		return false
	}

	frameNumber := proposal.State.Header.FrameNumber
	finalizedFrameNumber := (*finalized.State).Header.FrameNumber
	if frameNumber != finalizedFrameNumber {
		return false
	}

	if !bytes.Equal(
		[]byte(finalized.Identifier),
		[]byte(proposal.State.Identity()),
	) {
		e.logger.Warn(
			"received conflicting finalized frame during sync",
			zap.Uint64("finalized_frame_number", finalizedFrameNumber),
			zap.String(
				"expected",
				hex.EncodeToString([]byte(finalized.Identifier)),
			),
			zap.String(
				"received",
				hex.EncodeToString([]byte(proposal.State.Identity())),
			),
		)
		return true
	}

	e.registerPendingCertifiedParent(proposal)

	e.logger.Debug(
		"cached finalized frame for descendant processing",
		zap.Uint64("frame_number", frameNumber),
	)

	return true
}

func (e *GlobalConsensusEngine) processProposal(
	proposal *protobufs.GlobalProposal,
) bool {
	return e.processProposalInternal(proposal, false)
}

func (e *GlobalConsensusEngine) processProposalInternal(
	proposal *protobufs.GlobalProposal,
	skipAncestors bool,
) bool {
	if proposal == nil || proposal.State == nil || proposal.State.Header == nil {
		return false
	}

	if !skipAncestors {
		if ok, err := e.ensureAncestorStates(proposal); err != nil {
			e.logger.Warn(
				"failed to recover ancestor states for proposal",
				zap.Uint64("frame_number", proposal.State.Header.FrameNumber),
				zap.Uint64("rank", proposal.State.Header.Rank),
				zap.Error(err),
			)
			e.requestAncestorSync(proposal)
			return false
		} else if !ok {
			return false
		}
	}

	frame := proposal.State
	var proverRootHex string
	if frame.Header != nil {
		proverRootHex = hex.EncodeToString(frame.Header.ProverTreeCommitment)
	}
	proposerHex := ""
	if proposal.Vote != nil {
		proposerHex = hex.EncodeToString([]byte(proposal.Vote.Identity()))
	}
	e.logger.Debug(
		"processing proposal",
		zap.Uint64("rank", proposal.GetRank()),
		zap.Uint64("frame_number", frame.GetFrameNumber()),
		zap.Int("request_count", len(frame.GetRequests())),
		zap.String("id", hex.EncodeToString([]byte(frame.Identity()))),
		zap.String("prover_root", proverRootHex),
		zap.String("proposer", proposerHex),
	)

	txn, err := e.clockStore.NewTransaction(false)
	if err != nil {
		return false
	}

	err = e.clockStore.PutGlobalClockFrameCandidate(proposal.State, txn)
	if err != nil {
		txn.Abort()
		return false
	}

	if err = txn.Commit(); err != nil {
		txn.Abort()
		return false
	}

	err = e.consensusProtocol.VerifyQuorumCertificate(proposal.ParentQuorumCertificate)
	if err != nil {
		e.logger.Debug(
			"proposal has invalid qc",
			zap.Uint64("rank", proposal.GetRank()),
			zap.Uint64("frame_number", proposal.State.GetFrameNumber()),
			zap.Error(err),
		)
		return false
	}

	if proposal.PriorRankTimeoutCertificate != nil {
		err := e.consensusProtocol.VerifyTimeoutCertificate(proposal.PriorRankTimeoutCertificate)
		if err != nil {
			e.logger.Debug(
				"proposal has invalid tc",
				zap.Uint64("rank", proposal.GetRank()),
				zap.Uint64("frame_number", proposal.State.GetFrameNumber()),
				zap.Error(err),
			)
			return false
		}
	}

	err = e.consensusProtocol.VerifyVote(&proposal.Vote)
	if err != nil {
		e.logger.Debug(
			"proposal has invalid vote",
			zap.Uint64("rank", proposal.GetRank()),
			zap.Uint64("frame_number", proposal.State.GetFrameNumber()),
			zap.Error(err),
		)
		return false
	}

	err = proposal.State.Validate()
	if err != nil {
		e.logger.Debug(
			"proposal is not valid",
			zap.Uint64("rank", proposal.GetRank()),
			zap.Uint64("frame_number", proposal.State.GetFrameNumber()),
			zap.Error(err),
		)
		return false
	}

	valid, err := e.frameValidator.Validate(proposal.State)
	if !valid || err != nil {
		e.logger.Debug(
			"invalid frame in proposal",
			zap.Uint64("rank", proposal.GetRank()),
			zap.Uint64("frame_number", proposal.State.GetFrameNumber()),
			zap.Error(err),
		)
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
	if signedProposal.State.Rank >= e.consensusProtocol.currentRank {
		e.consensusProtocol.voteAggregator.AddState(signedProposal)
	}
	e.consensusProtocol.consensusParticipant.SubmitProposal(signedProposal)

	e.trySealParentWithChild(proposal)
	e.registerPendingCertifiedParent(proposal)

	return true
}

type ancestorDescriptor struct {
	frameNumber uint64
	selector    []byte
}

func (e *GlobalConsensusEngine) ensureAncestorStates(
	proposal *protobufs.GlobalProposal,
) (bool, error) {
	ancestors, err := e.collectMissingAncestors(proposal)
	if err != nil {
		return false, err
	}

	if len(ancestors) == 0 {
		return true, nil
	}

	for i := len(ancestors) - 1; i >= 0; i-- {
		ancestor, err := e.buildStoredProposal(ancestors[i])
		if err != nil {
			return false, err
		}
		if !e.processProposalInternal(ancestor, true) {
			return false, fmt.Errorf(
				"unable to process ancestor frame %d",
				ancestors[i].frameNumber,
			)
		}
	}

	return true, nil
}

func (e *GlobalConsensusEngine) collectMissingAncestors(
	proposal *protobufs.GlobalProposal,
) ([]ancestorDescriptor, error) {
	header := proposal.State.Header
	if header == nil || header.FrameNumber == 0 {
		return nil, nil
	}

	finalized := e.consensusProtocol.forks.FinalizedState()
	if finalized == nil || finalized.State == nil || (*finalized.State).Header == nil {
		return nil, errors.New("finalized state unavailable")
	}
	finalizedFrame := (*finalized.State).Header.FrameNumber
	finalizedSelector := []byte(finalized.Identifier)

	parentFrame := header.FrameNumber - 1
	parentSelector := slices.Clone(header.ParentSelector)
	if len(parentSelector) == 0 {
		return nil, nil
	}

	var ancestors []ancestorDescriptor
	anchored := false
	for parentFrame > finalizedFrame && len(parentSelector) > 0 {
		if _, found := e.consensusProtocol.forks.GetState(
			models.Identity(string(parentSelector)),
		); found {
			anchored = true
			break
		}
		ancestors = append(ancestors, ancestorDescriptor{
			frameNumber: parentFrame,
			selector:    slices.Clone(parentSelector),
		})

		frame, err := e.clockStore.GetGlobalClockFrameCandidate(
			parentFrame,
			parentSelector,
		)
		if err != nil {
			return nil, err
		}
		if frame == nil || frame.Header == nil {
			return nil, errors.New("ancestor frame missing header")
		}

		parentFrame--
		parentSelector = slices.Clone(frame.Header.ParentSelector)
	}

	if !anchored {
		switch {
		case parentFrame == finalizedFrame:
			if !bytes.Equal(parentSelector, finalizedSelector) {
				return nil, fmt.Errorf(
					"ancestor chain not rooted at finalized frame %d",
					finalizedFrame,
				)
			}
			anchored = true
		case parentFrame < finalizedFrame:
			return nil, fmt.Errorf(
				"ancestor chain crossed finalized boundary (frame %d < %d)",
				parentFrame,
				finalizedFrame,
			)
		case len(parentSelector) == 0:
			return nil, errors.New(
				"ancestor selector missing before reaching finalized state",
			)
		}
	}

	if !anchored {
		return nil, errors.New("ancestor chain could not be anchored in forks")
	}

	return ancestors, nil
}

func (e *GlobalConsensusEngine) buildStoredProposal(
	desc ancestorDescriptor,
) (*protobufs.GlobalProposal, error) {
	frame, err := e.clockStore.GetGlobalClockFrameCandidate(
		desc.frameNumber,
		desc.selector,
	)
	if err != nil {
		return nil, err
	}
	if frame == nil || frame.Header == nil {
		return nil, errors.New("stored ancestor missing header")
	}

	var parentQC *protobufs.QuorumCertificate
	if frame.GetRank() > 0 {
		parentQC, err = e.clockStore.GetQuorumCertificate(
			nil,
			frame.GetRank()-1,
		)
		if err != nil {
			return nil, err
		}
		if parentQC == nil {
			return nil, fmt.Errorf(
				"missing parent qc for frame %d",
				frame.GetRank()-1,
			)
		}
	}

	var priorTC *protobufs.TimeoutCertificate
	if frame.GetRank() > 0 {
		priorTC, err = e.clockStore.GetTimeoutCertificate(
			nil,
			frame.GetRank()-1,
		)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		if errors.Is(err, store.ErrNotFound) {
			priorTC = nil
		}
	}

	vote, err := e.clockStore.GetProposalVote(
		nil,
		frame.GetRank(),
		[]byte(frame.Identity()),
	)
	if err != nil {
		return nil, err
	}

	return &protobufs.GlobalProposal{
		State:                       frame,
		ParentQuorumCertificate:     parentQC,
		PriorRankTimeoutCertificate: priorTC,
		Vote:                        vote,
	}, nil
}

func (e *GlobalConsensusEngine) requestAncestorSync(
	proposal *protobufs.GlobalProposal,
) {
	if proposal == nil || proposal.State == nil || proposal.State.Header == nil {
		return
	}
	if e.consensusProtocol.syncProvider == nil {
		return
	}

	peerID, err := e.getPeerIDOfProver(proposal.State.Header.Prover)
	if err != nil {
		peerID, err = e.getRandomProverPeerId()
		if err != nil {
			return
		}
	}

	head := e.consensusProtocol.forks.FinalizedState()
	if head == nil || head.State == nil {
		return
	}

	e.consensusProtocol.syncProvider.AddState(
		[]byte(peerID),
		(*head.State).Header.FrameNumber,
		[]byte(head.Identifier),
	)
}

func (e *GlobalConsensusEngine) cacheProposal(
	proposal *protobufs.GlobalProposal,
) {
	frameNumber := proposal.State.Header.FrameNumber
	e.consensusProtocol.proposalCacheMu.Lock()
	e.consensusProtocol.proposalCache[frameNumber] = proposal
	e.consensusProtocol.proposalCacheMu.Unlock()

	txn, err := e.clockStore.NewTransaction(false)
	if err != nil {
		e.logger.Error("could not create transaction", zap.Error(err))
		return
	}
	err = e.clockStore.PutGlobalClockFrameCandidate(proposal.State, txn)
	if err != nil {
		e.logger.Error("could not put global clock frame candidate", zap.Error(err))
		txn.Abort()
		return
	}
	if err = txn.Commit(); err != nil {
		e.logger.Error("could not commit transaction", zap.Error(err))
		txn.Abort()
		return
	}

	e.logger.Debug(
		"cached out-of-order proposal",
		zap.Uint64("rank", proposal.GetRank()),
		zap.Uint64("frame_number", frameNumber),
		zap.String("id", hex.EncodeToString([]byte(proposal.State.Identity()))),
	)
}

func (e *GlobalConsensusEngine) deleteCachedProposal(frameNumber uint64) {
	e.consensusProtocol.proposalCacheMu.Lock()
	delete(e.consensusProtocol.proposalCache, frameNumber)
	e.consensusProtocol.proposalCacheMu.Unlock()
}

func (e *GlobalConsensusEngine) popCachedProposal(
	frameNumber uint64,
) *protobufs.GlobalProposal {
	e.consensusProtocol.proposalCacheMu.Lock()
	defer e.consensusProtocol.proposalCacheMu.Unlock()

	proposal, ok := e.consensusProtocol.proposalCache[frameNumber]
	if ok {
		delete(e.consensusProtocol.proposalCache, frameNumber)
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
				zap.Uint64("rank", prop.GetRank()),
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
	e.consensusProtocol.pendingCertifiedParentsMu.Lock()
	e.consensusProtocol.pendingCertifiedParents[frameNumber] = proposal
	e.consensusProtocol.pendingCertifiedParentsMu.Unlock()
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

	e.consensusProtocol.pendingCertifiedParentsMu.RLock()
	parent, ok := e.consensusProtocol.pendingCertifiedParents[parentFrame]
	e.consensusProtocol.pendingCertifiedParentsMu.RUnlock()
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
		e.consensusProtocol.pendingCertifiedParentsMu.Lock()
		delete(e.consensusProtocol.pendingCertifiedParents, parentFrame)
		e.consensusProtocol.pendingCertifiedParentsMu.Unlock()
		return
	}

	finalized := e.consensusProtocol.forks.FinalizedState()
	if finalized != nil && finalized.State != nil &&
		parentFrame <= (*finalized.State).Header.FrameNumber {
		e.logger.Debug(
			"skipping sealing for already finalized parent",
			zap.Uint64("parent_frame", parentFrame),
		)
		e.consensusProtocol.pendingCertifiedParentsMu.Lock()
		delete(e.consensusProtocol.pendingCertifiedParents, parentFrame)
		e.consensusProtocol.pendingCertifiedParentsMu.Unlock()
		return
	}

	e.logger.Debug(
		"sealing parent with descendant proposal",
		zap.Uint64("parent_frame", parent.State.Header.FrameNumber),
		zap.Uint64("child_frame", header.FrameNumber),
	)

	e.addCertifiedState(parent, child)
	e.consensusProtocol.pendingCertifiedParentsMu.Lock()
	delete(e.consensusProtocol.pendingCertifiedParents, parentFrame)
	e.consensusProtocol.pendingCertifiedParentsMu.Unlock()
}

func (e *GlobalConsensusEngine) addCertifiedState(
	parent, child *protobufs.GlobalProposal,
) {
	if parent == nil || parent.State == nil || parent.State.Header == nil ||
		child == nil || child.State == nil || child.State.Header == nil {
		e.logger.Error("cannot seal certified state: missing parent or child data")
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

	parent.State.Header.PublicKeySignatureBls48581 = aggregateSig

	txn, err := e.clockStore.NewTransaction(false)
	if err != nil {
		e.logger.Error("could not create transaction", zap.Error(err))
		return
	}

	if err := e.materializer.materialize(txn, parent.State); err != nil {
		_ = txn.Abort()
		e.logger.Error("could not materialize frame requests", zap.Error(err))
		return
	}
	if err := e.clockStore.PutGlobalClockFrame(parent.State, txn); err != nil {
		_ = txn.Abort()
		e.logger.Error("could not put global frame", zap.Error(err))
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

	// Trigger coverage check asynchronously to avoid blocking message processing
	e.coverageMonitor.triggerCoverageCheckAsync(
		parent.State.GetFrameNumber(),
		parent.State.Header.Prover,
	)
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

	if proposal.State != nil && proposal.State.Header != nil {
		e.recordProposalFrameNumber(proposal.State.Header.FrameNumber)
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

func (e *GlobalConsensusEngine) AddProposal(
	proposal *protobufs.GlobalProposal,
) {
	e.globalProposalQueue <- proposal
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

	e.consensusProtocol.voteAggregator.AddVote(&vote)

	voteProcessedTotal.WithLabelValues("success").Inc()
}

func (e *GlobalConsensusEngine) handleTimeoutState(message *pb.Message) {
	e.logger.Debug("handling timeout state")
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

	e.consensusProtocol.timeoutAggregator.AddTimeout(timeout)

	voteProcessedTotal.WithLabelValues("success").Inc()
}

func (e *GlobalConsensusEngine) handleMessageBundle(message *pb.Message) {
	if err := e.addGlobalMessage(message.Data); err != nil {
		e.logger.Warn("message bundle rejected by collector", zap.Error(err))
	} else {
		e.logger.Debug("collected global request for execution")
	}
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
				e.logger.Debug(
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
				e.logger.Debug(
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
		e.logger.Debug(
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

// ---------------------------------------------------------------------------
// Archive frame polling
// ---------------------------------------------------------------------------

// pollFramesFromArchive periodically fetches new frames from the archive
// node and feeds them into processGlobalFrame. It replaces the pubsub
// frame subscription for non-archive nodes.
func (e *GlobalConsensusEngine) pollFramesFromArchive(
	ctx lifecycle.SignalerContext,
) {
	if e.archiveClient == nil {
		<-ctx.Done()
		return
	}

	e.logger.Info("starting archive frame poller")
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastFrameNumber uint64

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.haltCtx.Done():
			return
		case <-ticker.C:
			pollCtx, pollCancel := context.WithTimeout(
				context.Background(), 30*time.Second,
			)
			frame, err := e.archiveClient.GetGlobalFrame(pollCtx, 0)
			pollCancel()
			if err != nil {
				e.logger.Debug("archive poll error", zap.Error(err))
				continue
			}
			if frame == nil || frame.Header == nil {
				continue
			}

			newNumber := frame.Header.FrameNumber
			if newNumber <= lastFrameNumber {
				continue
			}

			// Catch up on any missed frames
			if lastFrameNumber > 0 && newNumber > lastFrameNumber+1 {
				for fn := lastFrameNumber + 1; fn < newNumber; fn++ {
					catchupCtx, catchupCancel := context.WithTimeout(
						context.Background(), 30*time.Second,
					)
					catchup, err := e.archiveClient.GetGlobalFrame(
						catchupCtx, fn,
					)
					catchupCancel()
					if err != nil {
						e.logger.Debug(
							"archive catchup error",
							zap.Uint64("frame_number", fn),
							zap.Error(err),
						)
						break
					}
					if catchup != nil {
						e.processGlobalFrame(catchup)
					}
				}
			}

			e.processGlobalFrame(frame)
			lastFrameNumber = newNumber
		}
	}
}

// ---------------------------------------------------------------------------
// Archive endpoint discovery
// ---------------------------------------------------------------------------

func (e *GlobalConsensusEngine) tryDiscoverArchiveEndpoint(
	peerInfo *protobufs.PeerInfo,
) {
	// Only relevant for non-archive nodes that don't already have an archive
	// client.
	if e.isConsensusParticipant() {
		return
	}
	if e.archiveClient != nil {
		return
	}

	// Scan capabilities for the archive service (presence flag only)
	found := false
	for _, cap := range peerInfo.Capabilities {
		if cap != nil && cap.ProtocolIdentifier == ArchiveServiceCapabilityID {
			found = true
			break
		}
	}
	if !found {
		return
	}

	// Extract the stream multiaddr from the peer's reachability info
	if len(peerInfo.Reachability) == 0 ||
		len(peerInfo.Reachability[0].StreamMultiaddrs) == 0 {
		e.logger.Debug(
			"archive peer has no stream multiaddrs",
			zap.String("peer_id", peer.ID(peerInfo.PeerId).String()),
		)
		return
	}

	s := peerInfo.Reachability[0].StreamMultiaddrs[0]

	// Create mTLS credentials for the archive peer
	emptyPolicies := map[string]channel.AllowedPeerPolicyType{}
	creds, err := p2p.NewPeerAuthenticator(
		e.logger,
		e.config.P2P,
		nil, nil, nil, nil,
		[][]byte{peerInfo.PeerId},
		emptyPolicies,
		emptyPolicies,
	).CreateClientTLSCredentials(peerInfo.PeerId)
	if err != nil {
		e.logger.Warn(
			"failed to create mTLS credentials for archive peer",
			zap.String("peer_id", peer.ID(peerInfo.PeerId).String()),
			zap.Error(err),
		)
		return
	}

	maddr, err := multiaddr.StringCast(s)
	if err != nil {
		e.logger.Debug(
			"failed to parse archive stream multiaddr",
			zap.String("multiaddr", s),
			zap.Error(err),
		)
		return
	}

	mga, err := mn.ToNetAddr(maddr)
	if err != nil {
		e.logger.Debug(
			"failed to convert archive stream multiaddr to net addr",
			zap.String("multiaddr", s),
			zap.Error(err),
		)
		return
	}

	conn, err := grpc.NewClient(
		mga.String(),
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		e.logger.Warn(
			"failed to dial archive peer",
			zap.String("addr", mga.String()),
			zap.String("peer_id", peer.ID(peerInfo.PeerId).String()),
			zap.Error(err),
		)
		return
	}

	client := protobufs.NewGlobalServiceClient(conn)
	archiveClient := rpc.NewArchiveClient(client, conn, e.logger)

	e.SetArchiveClient(archiveClient)
	e.logger.Info(
		"archive client configured from discovered peer",
		zap.String("addr", mga.String()),
		zap.String("peer_id", peer.ID(peerInfo.PeerId).String()),
	)
}
