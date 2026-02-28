package app

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
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

var keyRegistryDomain = []byte("KEY_REGISTRY")

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

func (e *AppConsensusEngine) processAppShardProposalQueue(
	ctx lifecycle.SignalerContext,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case proposal := <-e.appShardProposalQueue:
			e.handleAppShardProposal(proposal)
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

func (e *AppConsensusEngine) handleAppShardProposal(
	proposal *protobufs.AppShardProposal,
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
	signedProposal := &models.SignedProposal[*protobufs.AppShardFrame, *protobufs.ProposalVote]{
		Proposal: models.Proposal[*protobufs.AppShardFrame]{
			State: &models.State[*protobufs.AppShardFrame]{
				Rank:       proposal.State.GetRank(),
				Identifier: proposal.State.Identity(),
				ProposerID: proposal.State.Source(),
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
	existingFrame, _, err := e.clockStore.GetShardClockFrame(
		proposal.State.Header.Address,
		frameNumber,
		false,
	)
	if err == nil && existingFrame != nil {
		qc, qcErr := e.clockStore.GetQuorumCertificate(
			proposal.State.Header.Address,
			proposal.State.GetRank(),
		)
		if qcErr == nil && qc != nil &&
			qc.GetFrameNumber() == frameNumber &&
			qc.Identity() == proposal.State.Identity() {
			e.logger.Debug("dropping stale proposal")
			return
		}
	}

	if proposal.State.Header.FrameNumber != 0 {
		parent, _, err := e.clockStore.GetShardClockFrame(
			proposal.State.Header.Address,
			proposal.State.Header.FrameNumber-1,
			false,
		)
		if err != nil || parent == nil || !bytes.Equal(
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
					e.logger.Debug("could not get peer id for sync", zap.Error(err))
					return
				}
			}

			head, _, err := e.clockStore.GetLatestShardClockFrame(e.appAddress)
			if err != nil || head == nil || head.Header == nil {
				e.logger.Debug("could not get shard time reel head", zap.Error(err))
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

	expectedFrame, _, err := e.clockStore.GetLatestShardClockFrame(e.appAddress)
	if err != nil {
		e.logger.Error("could not obtain app time reel head", zap.Error(err))
		return
	}

	expectedFrameNumber := uint64(0)
	if expectedFrame != nil && expectedFrame.Header != nil {
		expectedFrameNumber = expectedFrame.Header.FrameNumber + 1
	}

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

func (e *AppConsensusEngine) processProposal(
	proposal *protobufs.AppShardProposal,
) bool {
	return e.processProposalInternal(proposal, false)
}

func (e *AppConsensusEngine) processProposalInternal(
	proposal *protobufs.AppShardProposal,
	skipAncestors bool,
) bool {
	if proposal == nil || proposal.State == nil || proposal.State.Header == nil {
		return false
	}

	if !skipAncestors {
		if ok, err := e.ensureShardAncestorStates(proposal); err != nil {
			e.logger.Warn(
				"failed to recover app shard ancestors",
				zap.String("address", e.appAddressHex),
				zap.Uint64("frame_number", proposal.State.Header.FrameNumber),
				zap.Error(err),
			)
			e.requestShardAncestorSync(proposal)
			return false
		} else if !ok {
			return false
		}
	}

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

	if proposal.Vote != nil {
		err := e.VerifyVote(&proposal.Vote)
		if err != nil {
			e.logger.Debug("proposal has invalid vote", zap.Error(err))
			return false
		}
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
	proposalProcessedTotal.WithLabelValues(e.appAddressHex, "success").Inc()

	e.trySealParentWithChild(proposal)
	e.registerPendingCertifiedParent(proposal)

	if proposal.State != nil {
		e.recordProposalRank(proposal.State.GetRank())
	}

	return true
}

type shardAncestorDescriptor struct {
	frameNumber uint64
	selector    []byte
}

func (e *AppConsensusEngine) ensureShardAncestorStates(
	proposal *protobufs.AppShardProposal,
) (bool, error) {
	ancestors, err := e.collectMissingShardAncestors(proposal)
	if err != nil {
		return false, err
	}

	if len(ancestors) == 0 {
		return true, nil
	}

	for i := len(ancestors) - 1; i >= 0; i-- {
		ancestor, err := e.buildStoredShardProposal(ancestors[i])
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

func (e *AppConsensusEngine) collectMissingShardAncestors(
	proposal *protobufs.AppShardProposal,
) ([]shardAncestorDescriptor, error) {
	header := proposal.State.Header
	if header == nil || header.FrameNumber == 0 {
		return nil, nil
	}

	finalized := e.forks.FinalizedState()
	if finalized == nil || finalized.State == nil ||
		(*finalized.State).Header == nil {
		return nil, errors.New("finalized state unavailable")
	}

	finalizedFrame := (*finalized.State).Header.FrameNumber
	finalizedSelector := []byte(finalized.Identifier)

	parentFrame := header.FrameNumber - 1
	parentSelector := slices.Clone(header.ParentSelector)
	if len(parentSelector) == 0 {
		return nil, nil
	}

	var ancestors []shardAncestorDescriptor
	anchored := false

	for parentFrame > finalizedFrame && len(parentSelector) > 0 {
		if _, found := e.forks.GetState(
			models.Identity(string(parentSelector)),
		); found {
			anchored = true
			break
		}

		ancestors = append(ancestors, shardAncestorDescriptor{
			frameNumber: parentFrame,
			selector:    slices.Clone(parentSelector),
		})

		frame, err := e.loadShardFrameFromStore(parentFrame, parentSelector)
		if err != nil {
			return nil, err
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

func (e *AppConsensusEngine) loadShardFrameFromStore(
	frameNumber uint64,
	selector []byte,
) (*protobufs.AppShardFrame, error) {
	frame, err := e.clockStore.GetStagedShardClockFrame(
		e.appAddress,
		frameNumber,
		selector,
		false,
	)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		frame, _, err = e.clockStore.GetShardClockFrame(
			e.appAddress,
			frameNumber,
			false,
		)
		if err != nil {
			return nil, err
		}
		if frame == nil || frame.Header == nil ||
			!bytes.Equal([]byte(frame.Identity()), selector) {
			return nil, fmt.Errorf(
				"sealed shard frame mismatch at %d",
				frameNumber,
			)
		}
	}

	if frame == nil || frame.Header == nil {
		return nil, errors.New("stored shard frame missing header")
	}

	return frame, nil
}

func (e *AppConsensusEngine) buildStoredShardProposal(
	desc shardAncestorDescriptor,
) (*protobufs.AppShardProposal, error) {
	frame, err := e.loadShardFrameFromStore(desc.frameNumber, desc.selector)
	if err != nil {
		return nil, err
	}

	var parentQC *protobufs.QuorumCertificate
	if frame.GetRank() > 0 {
		parentQC, err = e.clockStore.GetQuorumCertificate(
			e.appAddress,
			frame.GetRank()-1,
		)
		if err != nil {
			return nil, err
		}
	}

	var priorTC *protobufs.TimeoutCertificate
	if frame.GetRank() > 0 {
		priorTC, err = e.clockStore.GetTimeoutCertificate(
			e.appAddress,
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
		e.appAddress,
		frame.GetRank(),
		[]byte(frame.Identity()),
	)
	if err != nil {
		return nil, err
	}

	return &protobufs.AppShardProposal{
		State:                       frame,
		ParentQuorumCertificate:     parentQC,
		PriorRankTimeoutCertificate: priorTC,
		Vote:                        vote,
	}, nil
}

func (e *AppConsensusEngine) requestShardAncestorSync(
	proposal *protobufs.AppShardProposal,
) {
	if proposal == nil || proposal.State == nil || proposal.State.Header == nil {
		return
	}
	if e.syncProvider == nil {
		return
	}

	peerID, err := e.getPeerIDOfProver(proposal.State.Header.Prover)
	if err != nil {
		peerID, err = e.getRandomProverPeerId()
		if err != nil {
			return
		}
	}

	head, _, err := e.clockStore.GetLatestShardClockFrame(e.appAddress)
	if err != nil || head == nil || head.Header == nil {
		e.logger.Debug("could not obtain shard head for sync", zap.Error(err))
		return
	}

	e.syncProvider.AddState(
		[]byte(peerID),
		head.Header.FrameNumber,
		[]byte(head.Identity()),
	)
}

type keyRegistryValidationResult struct {
	identityPeerID []byte
	proverAddress  []byte
}

func (e *AppConsensusEngine) isDuplicatePeerInfo(
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

func (e *AppConsensusEngine) isDuplicateKeyRegistry(
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

func (e *AppConsensusEngine) validateKeyRegistry(
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

func (e *AppConsensusEngine) validateSignedX448Key(
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

func (e *AppConsensusEngine) validateSignedDecaf448Key(
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

func (e *AppConsensusEngine) cacheProposal(
	proposal *protobufs.AppShardProposal,
) {
	if proposal == nil || proposal.State == nil || proposal.State.Header == nil {
		return
	}

	frameNumber := proposal.State.Header.FrameNumber
	e.proposalCacheMu.Lock()
	e.proposalCache[frameNumber] = proposal
	e.proposalCacheMu.Unlock()

	e.logger.Debug(
		"cached out-of-order proposal",
		zap.String("address", e.appAddressHex),
		zap.Uint64("frame_number", frameNumber),
	)
}

func (e *AppConsensusEngine) deleteCachedProposal(frameNumber uint64) {
	e.proposalCacheMu.Lock()
	delete(e.proposalCache, frameNumber)
	e.proposalCacheMu.Unlock()
}

func (e *AppConsensusEngine) popCachedProposal(
	frameNumber uint64,
) *protobufs.AppShardProposal {
	e.proposalCacheMu.Lock()
	defer e.proposalCacheMu.Unlock()

	proposal, ok := e.proposalCache[frameNumber]
	if ok {
		delete(e.proposalCache, frameNumber)
	}

	return proposal
}

func (e *AppConsensusEngine) drainProposalCache(startFrame uint64) {
	next := startFrame
	for {
		prop := e.popCachedProposal(next)
		if prop == nil {
			return
		}

		if !e.processProposal(prop) {
			e.logger.Debug(
				"cached proposal failed processing, retaining for retry",
				zap.String("address", e.appAddressHex),
				zap.Uint64("frame_number", next),
			)
			e.cacheProposal(prop)
			return
		}

		next++
	}
}

func (e *AppConsensusEngine) registerPendingCertifiedParent(
	proposal *protobufs.AppShardProposal,
) {
	if proposal == nil || proposal.State == nil || proposal.State.Header == nil {
		return
	}

	frameNumber := proposal.State.Header.FrameNumber
	e.pendingCertifiedParentsMu.Lock()
	e.pendingCertifiedParents[frameNumber] = proposal
	e.pendingCertifiedParentsMu.Unlock()
}

func (e *AppConsensusEngine) trySealParentWithChild(
	child *protobufs.AppShardProposal,
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
			zap.String("address", e.appAddressHex),
			zap.Uint64("parent_frame", parent.State.Header.FrameNumber),
			zap.Uint64("child_frame", header.FrameNumber),
		)
		e.pendingCertifiedParentsMu.Lock()
		delete(e.pendingCertifiedParents, parentFrame)
		e.pendingCertifiedParentsMu.Unlock()
		return
	}

	head, _, err := e.clockStore.GetLatestShardClockFrame(e.appAddress)
	if err != nil {
		e.logger.Error("error fetching app time reel head", zap.Error(err))
		return
	}

	if head != nil && head.Header != nil &&
		head.Header.FrameNumber+1 == parent.State.Header.FrameNumber {
		e.logger.Debug(
			"sealing parent with descendant proposal",
			zap.String("address", e.appAddressHex),
			zap.Uint64("parent_frame", parent.State.Header.FrameNumber),
			zap.Uint64("child_frame", header.FrameNumber),
		)
		e.addCertifiedState(parent, child)
	}

	e.pendingCertifiedParentsMu.Lock()
	delete(e.pendingCertifiedParents, parentFrame)
	e.pendingCertifiedParentsMu.Unlock()
}

func (e *AppConsensusEngine) addCertifiedState(
	parent, child *protobufs.AppShardProposal,
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

	if err := e.materialize(
		txn,
		parent.State,
	); err != nil {
		_ = txn.Abort()
		e.logger.Error("could not materialize frame requests", zap.Error(err))
		return
	}
	if err := e.clockStore.CommitShardClockFrame(
		e.appAddress,
		parent.State.GetFrameNumber(),
		[]byte(parent.State.Identity()),
		[]*tries.RollingFrecencyCritbitTrie{},
		txn,
		false,
	); err != nil {
		_ = txn.Abort()
		e.logger.Error("could not put global frame", zap.Error(err))
		return
	}

	if err := e.clockStore.PutCertifiedAppShardState(
		parent,
		txn,
	); err != nil {
		e.logger.Error("could not insert certified state", zap.Error(err))
		txn.Abort()
		return
	}

	if err := e.clockStore.PutQuorumCertificate(
		&protobufs.QuorumCertificate{
			Filter:             e.appAddress,
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

	if err := e.checkShardCoverage(parent.State.Header.FrameNumber); err != nil {
		e.logger.Error("could not check shard coverage", zap.Error(err))
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

	case protobufs.ProverLivenessCheckType:
		// Liveness checks are processed globally; nothing to do here.

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

	e.logger.Debug(
		"handling prover message",
		zap.Uint32("type_prefix", typePrefix),
	)
	switch typePrefix {
	case protobufs.MessageBundleType:
		hash := sha3.Sum256(message.Data)
		e.addAppMessage(&protobufs.Message{
			Address: e.appAddress[:32],
			Hash:    hash[:],
			Payload: slices.Clone(message.Data),
		})
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

		// If genesis hasn't been initialized yet, send this frame to the
		// genesis init channel (non-blocking)
		if !e.genesisInitialized.Load() {
			select {
			case e.genesisInitChan <- frame:
				e.logger.Debug(
					"sent global frame to genesis init channel",
					zap.Uint64("frame_number", frame.Header.FrameNumber),
				)
			default:
				// Channel already has a frame, skip
			}
		}

		if err := e.globalTimeReel.Insert(frame); err != nil {
			// Success metric recorded at the end of processing
			globalFramesProcessedTotal.WithLabelValues("error").Inc()
			return
		}

		e.handleGlobalProverRoot(frame)

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

		if e.peerInfoManager == nil {
			e.logger.Warn(
				"peer info manager unavailable; dropping peer info",
				zap.ByteString("peer_id", peerInfo.PeerId),
			)
			return
		}

		if e.isDuplicatePeerInfo(peerInfo) {
			if existing := e.peerInfoManager.GetPeerInfo(
				peerInfo.PeerId,
			); existing != nil {
				existing.LastSeen = time.Now().UnixMilli()
				return
			}
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

		if e.isDuplicateKeyRegistry(keyRegistry) {
			_, err := e.keyStore.GetKeyRegistry(validation.identityPeerID)
			if err == nil {
				return
			}
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
			context.Background(),
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
			context.Background(),
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
			context.Background(),
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
	// Skip our own messages
	if bytes.Equal(message.From, e.pubsub.GetPeerID()) {
		return
	}

	timer := prometheus.NewTimer(
		proposalProcessingDuration.WithLabelValues(e.appAddressHex),
	)
	defer timer.ObserveDuration()

	proposal := &protobufs.AppShardProposal{}
	if err := proposal.FromCanonicalBytes(message.Data); err != nil {
		e.logger.Debug("failed to unmarshal proposal", zap.Error(err))
		proposalProcessedTotal.WithLabelValues("error").Inc()
		return
	}

	if !bytes.Equal(proposal.State.Header.Address, e.appAddress) {
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

	if err := e.clockStore.StageShardClockFrame(
		[]byte(proposal.State.Identity()),
		proposal.State,
		txn,
	); err != nil {
		e.logger.Error("could not stage clock frame", zap.Error(err))
		txn.Abort()
		return
	}

	if err := txn.Commit(); err != nil {
		e.logger.Error("could not commit transaction", zap.Error(err))
		txn.Abort()
		return
	}

	e.appShardProposalQueue <- proposal

	proposalProcessedTotal.WithLabelValues(e.appAddressHex, "success").Inc()
}

func (e *AppConsensusEngine) AddProposal(proposal *protobufs.AppShardProposal) {
	e.appShardProposalQueue <- proposal
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

	proverSet, err := e.proverRegistry.GetActiveProvers(e.appAddress)
	if err != nil {
		e.logger.Error("could not get active provers", zap.Error(err))
		voteProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
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
		voteProcessedTotal.WithLabelValues(e.appAddressHex, "error").Inc()
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
		PeerId:              peerInfo.PeerId,
		Reachability:        peerInfo.Reachability,
		Timestamp:           peerInfo.Timestamp,
		Version:             peerInfo.Version,
		PatchNumber:         peerInfo.PatchNumber,
		Capabilities:        peerInfo.Capabilities,
		PublicKey:           peerInfo.PublicKey,
		LastReceivedFrame:   peerInfo.LastReceivedFrame,
		LastGlobalHeadFrame: peerInfo.LastGlobalHeadFrame,
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
