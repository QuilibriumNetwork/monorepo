package app

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"slices"

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
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
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

	txn, err := e.clockStore.NewTransaction(false)
	if err != nil {
		e.logger.Error("could not create transaction", zap.Error(err))
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

	parent.State.Header.PublicKeySignatureBls48581 = aggregateSig

	txn, err = e.clockStore.NewTransaction(false)
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

	if err := txn.Commit(); err != nil {
		e.logger.Error("could not commit transaction", zap.Error(err))
		txn.Abort()
		return
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
