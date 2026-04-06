package global

// Consensus protocol: HotStuff/BFT interface implementations (Consumer,
// Finalizer, Verifier, DynamicCommittee). The ConsensusProtocol struct owns
// all HotStuff consensus machinery and cross-provider state that is only
// meaningful for archive/devnet nodes running as consensus participants.
// Non-archive nodes still get a ConsensusProtocol with currentRank and
// syncProvider populated; the remaining fields are nil.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"sync"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/notifications/pubsub"
	"source.quilibrium.com/quilibrium/monorepo/consensus/participant"
	"source.quilibrium.com/quilibrium/monorepo/consensus/validator"
	"source.quilibrium.com/quilibrium/monorepo/consensus/verification"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	qsync "source.quilibrium.com/quilibrium/monorepo/node/consensus/sync"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/tracing"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	tconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

// ConsensusProtocol owns the HotStuff BFT consensus machinery and the
// cross-provider state used during frame proving. For non-archive nodes only
// currentRank and syncProvider are populated.
type ConsensusProtocol struct {
	engine *GlobalConsensusEngine // back-reference

	// Consensus participant instance
	consensusParticipant consensus.EventLoop[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
	]

	// Consensus plugins
	signatureAggregator         consensus.SignatureAggregator
	voteCollectorDistributor    *pubsub.VoteCollectorDistributor[*protobufs.ProposalVote]
	timeoutCollectorDistributor *pubsub.TimeoutCollectorDistributor[*protobufs.ProposalVote]
	voteAggregator              consensus.VoteAggregator[*protobufs.GlobalFrame, *protobufs.ProposalVote]
	timeoutAggregator           consensus.TimeoutAggregator[*protobufs.ProposalVote]

	// Synchronization service
	syncProvider *qsync.SyncProvider[*protobufs.GlobalFrame, *protobufs.GlobalProposal]

	// Consensus state
	forks    consensus.Forks[*protobufs.GlobalFrame]
	notifier consensus.Consumer[*protobufs.GlobalFrame, *protobufs.ProposalVote]

	// Provider implementations
	votingProvider   *GlobalVotingProvider
	leaderProvider   *GlobalLeaderProvider
	livenessProvider *GlobalLivenessProvider

	// Cross-provider state
	collectedMessages      [][]byte
	shardCommitments       [][]byte
	proverRoot             []byte
	commitmentHash         []byte
	shardCommitmentTrees   []*tries.VectorCommitmentTree
	shardCommitmentKeySets []map[string]struct{}
	shardCommitmentMu      sync.Mutex

	// Proposal/certified parent caches
	proposalCache             map[uint64]*protobufs.GlobalProposal
	proposalCacheMu           sync.RWMutex
	pendingCertifiedParents   map[uint64]*protobufs.GlobalProposal
	pendingCertifiedParentsMu sync.RWMutex

	// Active proving ranks
	activeProveRanks   map[uint64]struct{}
	activeProveRanksMu sync.Mutex

	// Current consensus rank (plain uint64, NOT atomic)
	currentRank uint64
}

// ---------------------------------------------------------------------------
// DynamicCommittee
// ---------------------------------------------------------------------------

type ConsensusWeightedIdentity struct {
	prover *tconsensus.ProverInfo
}

// Identity implements models.WeightedIdentity.
func (c *ConsensusWeightedIdentity) Identity() models.Identity {
	return models.Identity(c.prover.Address)
}

// PublicKey implements models.WeightedIdentity.
func (c *ConsensusWeightedIdentity) PublicKey() []byte {
	return c.prover.PublicKey
}

// Weight implements models.WeightedIdentity.
func (c *ConsensusWeightedIdentity) Weight() uint64 {
	return c.prover.Seniority
}

// IdentitiesByRank implements consensus.DynamicCommittee.
func (cp *ConsensusProtocol) IdentitiesByRank(
	rank uint64,
) ([]models.WeightedIdentity, error) {
	proverInfo, err := cp.engine.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return nil, errors.Wrap(err, "identities by rank")
	}

	return internalProversToWeightedIdentity(proverInfo), nil
}

// IdentitiesByState implements consensus.DynamicCommittee.
func (cp *ConsensusProtocol) IdentitiesByState(
	stateID models.Identity,
) ([]models.WeightedIdentity, error) {
	proverInfo, err := cp.engine.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return nil, errors.Wrap(err, "identities by state")
	}

	return internalProversToWeightedIdentity(proverInfo), nil
}

// IdentityByRank implements consensus.DynamicCommittee.
func (cp *ConsensusProtocol) IdentityByRank(
	rank uint64,
	participantID models.Identity,
) (models.WeightedIdentity, error) {
	proverInfo, err := cp.engine.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return nil, errors.Wrap(err, "identity by rank")
	}

	var found *tconsensus.ProverInfo
	for _, p := range proverInfo {
		if bytes.Equal(p.Address, []byte(participantID)) {
			found = p
			break
		}
	}

	if found == nil {
		return nil, errors.Wrap(errors.New("prover not found"), "identity by rank")
	}

	return internalProverToWeightedIdentity(found), nil
}

// IdentityByState implements consensus.DynamicCommittee.
func (cp *ConsensusProtocol) IdentityByState(
	stateID models.Identity,
	participantID models.Identity,
) (models.WeightedIdentity, error) {
	proverInfo, err := cp.engine.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return nil, errors.Wrap(err, "identity by state")
	}

	var found *tconsensus.ProverInfo
	for _, p := range proverInfo {
		if bytes.Equal(p.Address, []byte(participantID)) {
			found = p
			break
		}
	}

	if found == nil {
		return nil, errors.Wrap(errors.New("prover not found"), "identity by state")
	}

	return internalProverToWeightedIdentity(found), nil
}

// LeaderForRank implements consensus.DynamicCommittee.
func (cp *ConsensusProtocol) LeaderForRank(
	rank uint64,
) (models.Identity, error) {
	// TODO(2.2): revisit this
	inputBI, err := poseidon.HashBytes(slices.Concat(
		binary.BigEndian.AppendUint64(nil, rank),
	))
	if err != nil {
		return "", errors.Wrap(err, "leader for rank")
	}

	proverSet, err := cp.engine.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return "", errors.Wrap(err, "leader for rank")
	}

	inputBI.Mod(inputBI, big.NewInt(int64(len(proverSet))))
	index := inputBI.Int64()
	return models.Identity(proverSet[int(index)].Address), nil
}

// QuorumThresholdForRank implements consensus.DynamicCommittee.
func (cp *ConsensusProtocol) QuorumThresholdForRank(
	rank uint64,
) (uint64, error) {
	proverInfo, err := cp.engine.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return 0, errors.Wrap(err, "quorum threshold for rank")
	}

	total := uint64(0)
	for _, p := range proverInfo {
		total += p.Seniority
	}

	return (total * 4) / 6, nil
}

// Self implements consensus.DynamicCommittee.
func (cp *ConsensusProtocol) Self() models.Identity {
	return cp.engine.getPeerID().Identity()
}

// TimeoutThresholdForRank implements consensus.DynamicCommittee.
func (cp *ConsensusProtocol) TimeoutThresholdForRank(
	rank uint64,
) (uint64, error) {
	proverInfo, err := cp.engine.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return 0, errors.Wrap(err, "quorum threshold for rank")
	}

	total := uint64(0)
	for _, p := range proverInfo {
		total += p.Seniority
	}

	return (total * 4) / 6, nil
}

func internalProversToWeightedIdentity(
	provers []*tconsensus.ProverInfo,
) []models.WeightedIdentity {
	wis := []models.WeightedIdentity{}
	for _, p := range provers {
		wis = append(wis, internalProverToWeightedIdentity(p))
	}

	return wis
}

func internalProverToWeightedIdentity(
	prover *tconsensus.ProverInfo,
) models.WeightedIdentity {
	return &ConsensusWeightedIdentity{prover}
}

var _ consensus.DynamicCommittee = (*ConsensusProtocol)(nil)

// ---------------------------------------------------------------------------
// Consumer, Finalizer, Verifier
// ---------------------------------------------------------------------------

func (cp *ConsensusProtocol) startConsensus(
	trustedRoot *models.CertifiedState[*protobufs.GlobalFrame],
	pending []*models.SignedProposal[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
	],
	ctx lifecycle.SignalerContext,
	ready lifecycle.ReadyFunc,
) error {
	var err error
	cp.consensusParticipant, err = participant.NewParticipant[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
		GlobalPeerID,
		GlobalCollectedCommitments,
	](
		tracing.NewZapTracer(cp.engine.logger), // logger
		cp,                                     // committee
		verification.NewSigner[
			*protobufs.GlobalFrame,
			*protobufs.ProposalVote,
			GlobalPeerID,
		](cp.votingProvider), // signer
		cp.leaderProvider,              // prover
		cp.votingProvider,              // voter
		cp.notifier,                    // notifier
		cp.engine.consensusStore,       // consensusStore
		cp.signatureAggregator,         // signatureAggregator
		cp,                             // consensusVerifier
		cp.voteCollectorDistributor,    // voteCollectorDistributor
		cp.timeoutCollectorDistributor, // timeoutCollectorDistributor
		cp.forks,                       // forks
		validator.NewValidator[*protobufs.GlobalFrame](cp, cp), // validator
		cp.voteAggregator,    // voteAggregator
		cp.timeoutAggregator, // timeoutAggregator
		cp,                   // finalizer
		nil,                  // filter
		trustedRoot,
		pending,
	)
	if err != nil {
		return err
	}

	ready()
	cp.voteAggregator.Start(ctx)
	cp.timeoutAggregator.Start(ctx)
	<-lifecycle.AllReady(cp.voteAggregator, cp.timeoutAggregator)
	cp.consensusParticipant.Start(ctx)
	return nil
}

// MakeFinal implements consensus.Finalizer.
func (cp *ConsensusProtocol) MakeFinal(stateID models.Identity) error {
	// In a standard BFT-only approach, this would be how frames are finalized on
	// the time reel. But we're PoMW, so we don't rely on BFT for anything outside
	// of basic coordination. If the protocol were ever to move to something like
	// PoS, this would be one of the touch points to revisit.
	return nil
}

// OnCurrentRankDetails implements consensus.Consumer.
func (cp *ConsensusProtocol) OnCurrentRankDetails(
	currentRank uint64,
	finalizedRank uint64,
	currentLeader models.Identity,
) {
	cp.engine.logger.Info(
		"entered new rank",
		zap.Uint64("current_rank", currentRank),
		zap.String("current_leader", hex.EncodeToString([]byte(currentLeader))),
	)
}

// OnDoubleProposeDetected implements consensus.Consumer.
func (cp *ConsensusProtocol) OnDoubleProposeDetected(
	proposal1 *models.State[*protobufs.GlobalFrame],
	proposal2 *models.State[*protobufs.GlobalFrame],
) {
	select {
	case <-cp.engine.haltCtx.Done():
		return
	default:
	}
	cp.engine.eventDistributor.Publish(tconsensus.ControlEvent{
		Type: tconsensus.ControlEventGlobalEquivocation,
		Data: &consensustime.GlobalEvent{
			Type:    consensustime.TimeReelEventEquivocationDetected,
			Frame:   *proposal2.State,
			OldHead: *proposal1.State,
			Message: fmt.Sprintf(
				"equivocation at rank %d",
				proposal1.Rank,
			),
		},
	})
}

// OnEventProcessed implements consensus.Consumer.
func (cp *ConsensusProtocol) OnEventProcessed() {}

// OnFinalizedState implements consensus.Consumer.
func (cp *ConsensusProtocol) OnFinalizedState(
	state *models.State[*protobufs.GlobalFrame],
) {
}

// OnInvalidStateDetected implements consensus.Consumer.
func (cp *ConsensusProtocol) OnInvalidStateDetected(
	err *models.InvalidProposalError[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
	],
) {
} // Presently a no-op, up for reconsideration

// OnLocalTimeout implements consensus.Consumer.
func (cp *ConsensusProtocol) OnLocalTimeout(currentRank uint64) {}

// OnOwnProposal implements consensus.Consumer.
func (cp *ConsensusProtocol) OnOwnProposal(
	proposal *models.SignedProposal[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
	],
	targetPublicationTime time.Time,
) {
	go func() {
		select {
		case <-time.After(time.Until(targetPublicationTime)):
		case <-cp.engine.ShutdownSignal():
			return
		}
		var priorTC *protobufs.TimeoutCertificate = nil
		if proposal.PreviousRankTimeoutCertificate != nil {
			priorTC =
				proposal.PreviousRankTimeoutCertificate.(*protobufs.TimeoutCertificate)
		}

		// Manually override the signature as the vdf prover's signature is invalid
		(*proposal.State.State).Header.PublicKeySignatureBls48581.Signature =
			(*proposal.Vote).PublicKeySignatureBls48581.Signature

		pbProposal := &protobufs.GlobalProposal{
			State:                       *proposal.State.State,
			ParentQuorumCertificate:     proposal.Proposal.State.ParentQuorumCertificate.(*protobufs.QuorumCertificate),
			PriorRankTimeoutCertificate: priorTC,
			Vote:                        *proposal.Vote,
		}
		frame := pbProposal.State
		var proverRootHex string
		if frame.Header != nil {
			proverRootHex = hex.EncodeToString(frame.Header.ProverTreeCommitment)
		}
		cp.engine.logger.Info(
			"publishing own global proposal",
			zap.Uint64("rank", frame.GetRank()),
			zap.Uint64("frame_number", frame.GetFrameNumber()),
			zap.Int("request_count", len(frame.GetRequests())),
			zap.String("prover_root", proverRootHex),
			zap.String("proposer", hex.EncodeToString([]byte(frame.Source()))),
		)
		data, err := pbProposal.ToCanonicalBytes()
		if err != nil {
			cp.engine.logger.Error("could not serialize proposal", zap.Error(err))
			return
		}

		txn, err := cp.engine.clockStore.NewTransaction(false)
		if err != nil {
			cp.engine.logger.Error("could not create transaction", zap.Error(err))
			return
		}

		if err := cp.engine.clockStore.PutProposalVote(txn, *proposal.Vote); err != nil {
			cp.engine.logger.Error("could not put vote", zap.Error(err))
			txn.Abort()
			return
		}

		err = cp.engine.clockStore.PutGlobalClockFrameCandidate(*proposal.State.State, txn)
		if err != nil {
			cp.engine.logger.Error("could not put frame candidate", zap.Error(err))
			txn.Abort()
			return
		}

		if err := txn.Commit(); err != nil {
			cp.engine.logger.Error("could not commit transaction", zap.Error(err))
			txn.Abort()
			return
		}

		cp.voteAggregator.AddState(proposal)
		cp.consensusParticipant.SubmitProposal(proposal)

		if err := cp.engine.pubsub.PublishToBitmask(
			GLOBAL_CONSENSUS_BITMASK,
			data,
		); err != nil {
			cp.engine.logger.Error("could not publish", zap.Error(err))
		}
	}()
}

// OnOwnTimeout implements consensus.Consumer.
func (cp *ConsensusProtocol) OnOwnTimeout(
	timeout *models.TimeoutState[*protobufs.ProposalVote],
) {
	select {
	case <-cp.engine.haltCtx.Done():
		return
	default:
	}

	var priorTC *protobufs.TimeoutCertificate
	if timeout.PriorRankTimeoutCertificate != nil {
		priorTC =
			timeout.PriorRankTimeoutCertificate.(*protobufs.TimeoutCertificate)
	}

	pbTimeout := &protobufs.TimeoutState{
		LatestQuorumCertificate:     timeout.LatestQuorumCertificate.(*protobufs.QuorumCertificate),
		PriorRankTimeoutCertificate: priorTC,
		Vote:                        *timeout.Vote,
		TimeoutTick:                 timeout.TimeoutTick,
		Timestamp:                   uint64(time.Now().UnixMilli()),
	}
	data, err := pbTimeout.ToCanonicalBytes()
	if err != nil {
		cp.engine.logger.Error("could not serialize timeout", zap.Error(err))
		return
	}

	txn, err := cp.engine.clockStore.NewTransaction(false)
	if err != nil {
		cp.engine.logger.Error("could not create transaction", zap.Error(err))
		return
	}

	if err := cp.engine.clockStore.PutTimeoutVote(txn, pbTimeout); err != nil {
		cp.engine.logger.Error("could not put vote", zap.Error(err))
		txn.Abort()
		return
	}

	if err := txn.Commit(); err != nil {
		cp.engine.logger.Error("could not commit transaction", zap.Error(err))
		txn.Abort()
		return
	}

	cp.engine.logger.Debug(
		"aggregating own timeout",
		zap.Uint64("timeout_rank", timeout.Rank),
		zap.Uint64("vote_rank", (*timeout.Vote).Rank),
	)
	cp.timeoutAggregator.AddTimeout(timeout)

	if err := cp.engine.pubsub.PublishToBitmask(
		GLOBAL_CONSENSUS_BITMASK,
		data,
	); err != nil {
		cp.engine.logger.Error("could not publish", zap.Error(err))
	}
}

// OnOwnVote implements consensus.Consumer.
func (cp *ConsensusProtocol) OnOwnVote(
	vote **protobufs.ProposalVote,
	recipientID models.Identity,
) {
	select {
	case <-cp.engine.haltCtx.Done():
		return
	default:
	}

	data, err := (*vote).ToCanonicalBytes()
	if err != nil {
		cp.engine.logger.Error("could not serialize timeout", zap.Error(err))
		return
	}

	txn, err := cp.engine.clockStore.NewTransaction(false)
	if err != nil {
		cp.engine.logger.Error("could not create transaction", zap.Error(err))
		return
	}

	if err := cp.engine.clockStore.PutProposalVote(txn, *vote); err != nil {
		cp.engine.logger.Error("could not put vote", zap.Error(err))
		txn.Abort()
		return
	}

	if err := txn.Commit(); err != nil {
		cp.engine.logger.Error("could not commit transaction", zap.Error(err))
		txn.Abort()
		return
	}

	cp.voteAggregator.AddVote(vote)

	if err := cp.engine.pubsub.PublishToBitmask(
		GLOBAL_CONSENSUS_BITMASK,
		data,
	); err != nil {
		cp.engine.logger.Error("could not publish", zap.Error(err))
	}
}

// OnPartialTimeoutCertificate implements consensus.Consumer.
func (cp *ConsensusProtocol) OnPartialTimeoutCertificate(
	currentRank uint64,
	partialTimeoutCertificate *consensus.PartialTimeoutCertificateCreated,
) {
}

// OnQuorumCertificateTriggeredRankChange implements consensus.Consumer.
func (cp *ConsensusProtocol) OnQuorumCertificateTriggeredRankChange(
	oldRank uint64,
	newRank uint64,
	qc models.QuorumCertificate,
) {
	cp.engine.logger.Debug("processing certified state", zap.Uint64("rank", newRank-1))

	parentQC, err := cp.engine.clockStore.GetLatestQuorumCertificate(nil)
	if err != nil {
		cp.engine.logger.Error("no latest quorum certificate", zap.Error(err))
		return
	}

	txn, err := cp.engine.clockStore.NewTransaction(false)
	if err != nil {
		cp.engine.logger.Error("could not create transaction", zap.Error(err))
		return
	}

	aggregateSig := &protobufs.BLS48581AggregateSignature{
		Signature: qc.GetAggregatedSignature().GetSignature(),
		PublicKey: &protobufs.BLS48581G2PublicKey{
			KeyValue: qc.GetAggregatedSignature().GetPubKey(),
		},
		Bitmask: qc.GetAggregatedSignature().GetBitmask(),
	}
	if err := cp.engine.clockStore.PutQuorumCertificate(
		&protobufs.QuorumCertificate{
			Rank:               qc.GetRank(),
			FrameNumber:        qc.GetFrameNumber(),
			Selector:           []byte(qc.Identity()),
			AggregateSignature: aggregateSig,
		},
		txn,
	); err != nil {
		cp.engine.logger.Error("could not insert quorum certificate", zap.Error(err))
		txn.Abort()
		return
	}

	if err := txn.Commit(); err != nil {
		cp.engine.logger.Error("could not commit transaction", zap.Error(err))
		txn.Abort()
		return
	}

	cp.engine.frameStoreMu.RLock()
	frame, ok := cp.engine.frameStore[qc.Identity()]
	cp.engine.frameStoreMu.RUnlock()

	if !ok {
		frame, err = cp.engine.clockStore.GetGlobalClockFrameCandidate(
			qc.GetFrameNumber(),
			[]byte(qc.Identity()),
		)
		if err == nil {
			ok = true
		}
	}

	if !ok {
		cp.engine.logger.Error(
			"no frame for quorum certificate",
			zap.Uint64("rank", newRank-1),
			zap.Uint64("frame_number", qc.GetFrameNumber()),
		)
		current := (*cp.forks.FinalizedState().State)
		peer, err := cp.engine.getRandomProverPeerId()
		if err != nil {
			cp.engine.logger.Error("could not get random peer", zap.Error(err))
			return
		}
		cp.syncProvider.AddState(
			[]byte(peer),
			current.Header.FrameNumber,
			[]byte(current.Identity()),
		)
		return
	}

	cloned := frame.Clone().(*protobufs.GlobalFrame)
	cloned.Header.PublicKeySignatureBls48581 =
		&protobufs.BLS48581AggregateSignature{
			Signature: qc.GetAggregatedSignature().GetSignature(),
			PublicKey: &protobufs.BLS48581G2PublicKey{
				KeyValue: qc.GetAggregatedSignature().GetPubKey(),
			},
			Bitmask: qc.GetAggregatedSignature().GetBitmask(),
		}
	frameBytes, err := cloned.ToCanonicalBytes()
	if err == nil {
		cp.engine.pubsub.PublishToBitmask(GLOBAL_FRAME_BITMASK, frameBytes)
	}

	if !bytes.Equal(frame.Header.ParentSelector, parentQC.Selector) {
		cp.engine.logger.Error(
			"quorum certificate does not match frame parent",
			zap.String(
				"frame_parent_selector",
				hex.EncodeToString(frame.Header.ParentSelector),
			),
			zap.String(
				"parent_qc_selector",
				hex.EncodeToString(parentQC.Selector),
			),
			zap.Uint64("parent_qc_rank", parentQC.Rank),
		)
		return
	}

	priorRankTC, err := cp.engine.clockStore.GetTimeoutCertificate(nil, qc.GetRank()-1)
	if err != nil {
		cp.engine.logger.Debug("no prior rank TC to include", zap.Uint64("rank", newRank-1))
	}

	vote, err := cp.engine.clockStore.GetProposalVote(
		nil,
		frame.GetRank(),
		[]byte(frame.Source()),
	)
	if err != nil {
		cp.engine.logger.Error(
			"cannot find proposer's vote",
			zap.Uint64("rank", newRank-1),
			zap.String("proposer", hex.EncodeToString([]byte(frame.Source()))),
		)
		return
	}

	frame.Header.PublicKeySignatureBls48581 = aggregateSig

	proposal := &protobufs.GlobalProposal{
		State:                       frame,
		ParentQuorumCertificate:     parentQC,
		PriorRankTimeoutCertificate: priorRankTC,
		Vote:                        vote,
	}

	cp.engine.globalProposalQueue <- proposal
}

// OnRankChange implements consensus.Consumer.
func (cp *ConsensusProtocol) OnRankChange(oldRank uint64, newRank uint64) {
	if cp.currentRank == newRank {
		return
	}

	cp.currentRank = newRank

	qc, err := cp.engine.clockStore.GetLatestQuorumCertificate(nil)
	if err != nil {
		cp.engine.logger.Error("new rank, no latest QC")
		frameProvingTotal.WithLabelValues("error").Inc()
		return
	}
	_, err = cp.engine.clockStore.GetGlobalClockFrameCandidate(
		qc.FrameNumber,
		[]byte(qc.Identity()),
	)
	if err != nil {
		cp.engine.logger.Error("new rank, no global clock frame candidate")
		frameProvingTotal.WithLabelValues("error").Inc()
		return
	}
	// Note: Collect is called in ProveNextState after tryBeginProvingRank succeeds
	// to avoid race conditions where a subsequent OnRankChange overwrites
	// collectedMessages and shardCommitments while ProveNextState is still running
}

func (cp *ConsensusProtocol) rebuildShardCommitments(
	frameNumber uint64,
	rank uint64,
) ([]byte, error) {
	cp.engine.materializer.commitBarrier.Lock()
	commitSet, err := cp.engine.hypergraph.Commit(frameNumber)
	if err != nil {
		cp.engine.materializer.commitBarrier.Unlock()
		cp.engine.logger.Error("could not commit", zap.Error(err))
		return nil, errors.Wrap(err, "rebuild shard commitments")
	}

	// Publish the snapshot with proverRoot BEFORE releasing commitBarrier.
	// This prevents a race where materialize(N) modifies the tree between
	// Commit(N+1) and PublishSnapshot, causing the snapshot to capture
	// post-materialize data (root 020897...) while being tagged with the
	// pre-materialize proverRoot (030270...). Workers would then find the
	// snapshot's actual data matches their stale state, resulting in
	// tree_changed=false despite a root mismatch.
	var zeroShardKeyL1 [3]byte
	for sk, phaseCommits := range commitSet {
		if sk.L1 == zeroShardKeyL1 && len(phaseCommits) > 0 && len(phaseCommits[0]) > 0 {
			if hgCRDT, ok := cp.engine.hypergraph.(*hgcrdt.HypergraphCRDT); ok {
				hgCRDT.PublishSnapshot(slices.Clone(phaseCommits[0]))
			}
			break
		}
	}
	cp.engine.materializer.commitBarrier.Unlock()

	if err := cp.engine.rebuildAppShardCache(rank); err != nil {
		cp.engine.logger.Warn(
			"could not rebuild app shard cache",
			zap.Uint64("rank", rank),
			zap.Error(err),
		)
	}

	cp.shardCommitmentMu.Lock()
	defer cp.shardCommitmentMu.Unlock()

	if cp.shardCommitmentTrees == nil {
		cp.shardCommitmentTrees = make([]*tries.VectorCommitmentTree, 256)
	}
	if cp.shardCommitmentKeySets == nil {
		cp.shardCommitmentKeySets = make([]map[string]struct{}, 256)
	}
	if cp.shardCommitments == nil {
		cp.shardCommitments = make([][]byte, 256)
	}

	currentKeySets := make([]map[string]struct{}, 256)
	changedTrees := make([]bool, 256)

	proverRoot := make([]byte, 64)
	collected := 0

	for sk, phaseCommits := range commitSet {
		if sk.L1 == zeroShardKeyL1 {
			if len(phaseCommits) > 0 {
				proverRoot = slices.Clone(phaseCommits[0])
			}
			continue
		}

		collected++

		for phaseSet := 0; phaseSet < len(phaseCommits); phaseSet++ {
			commit := phaseCommits[phaseSet]
			foldedShardKey := make([]byte, 32)
			copy(foldedShardKey, sk.L2[:])

			foldedShardKey[0] |= byte(phaseSet << 6)
			keyStr := string(foldedShardKey)
			var valueCopy []byte

			for l1Idx := 0; l1Idx < len(sk.L1); l1Idx++ {
				index := int(sk.L1[l1Idx])
				if index >= len(cp.shardCommitmentTrees) {
					cp.engine.logger.Warn(
						"shard commitment index out of range",
						zap.Int("index", index),
					)
					continue
				}

				if cp.shardCommitmentTrees[index] == nil {
					cp.shardCommitmentTrees[index] = &tries.VectorCommitmentTree{}
				}

				if currentKeySets[index] == nil {
					currentKeySets[index] = make(map[string]struct{})
				}
				currentKeySets[index][keyStr] = struct{}{}

				tree := cp.shardCommitmentTrees[index]
				if existing, err := tree.Get(foldedShardKey); err == nil &&
					bytes.Equal(existing, commit) {
					continue
				}

				if valueCopy == nil {
					valueCopy = slices.Clone(commit)
				}

				if err := tree.Insert(
					foldedShardKey,
					valueCopy,
					nil,
					big.NewInt(int64(len(commit))),
				); err != nil {
					return nil, errors.Wrap(err, "rebuild shard commitments")
				}

				changedTrees[index] = true
			}
		}
	}

	for idx := 0; idx < len(cp.shardCommitmentTrees); idx++ {
		prevKeys := cp.shardCommitmentKeySets[idx]
		currKeys := currentKeySets[idx]

		if len(prevKeys) > 0 {
			for key := range prevKeys {
				if currKeys != nil {
					if _, ok := currKeys[key]; ok {
						continue
					}
				}

				tree := cp.shardCommitmentTrees[idx]
				if tree == nil {
					continue
				}

				if err := tree.Delete([]byte(key)); err != nil {
					cp.engine.logger.Debug(
						"failed to delete shard commitment leaf",
						zap.Int("shard_index", idx),
						zap.Error(err),
					)
					continue
				}

				changedTrees[idx] = true
			}
		}

		cp.shardCommitmentKeySets[idx] = currKeys
	}

	// Apply alt shard overrides - these have externally-managed roots
	if cp.engine.hypergraphStore != nil {
		altShardAddrs, err := cp.engine.hypergraphStore.RangeAltShardAddresses()
		if err != nil {
			cp.engine.logger.Warn("failed to get alt shard addresses", zap.Error(err))
		} else {
			for _, shardAddr := range altShardAddrs {
				vertexAdds, vertexRemoves, hyperedgeAdds, hyperedgeRemoves, err :=
					cp.engine.hypergraphStore.GetLatestAltShardCommit(shardAddr)
				if err != nil {
					cp.engine.logger.Debug(
						"failed to get alt shard commit",
						zap.Binary("shard_address", shardAddr),
						zap.Error(err),
					)
					continue
				}

				// Calculate L1 indices (bloom filter) for this shard address
				l1Indices := up2p.GetBloomFilterIndices(shardAddr, 256, 3)

				// Insert each phase's root into the commitment trees
				roots := [][]byte{vertexAdds, vertexRemoves, hyperedgeAdds, hyperedgeRemoves}
				for phaseSet, root := range roots {
					if len(root) == 0 {
						continue
					}

					foldedShardKey := make([]byte, 32)
					copy(foldedShardKey, shardAddr)
					foldedShardKey[0] |= byte(phaseSet << 6)
					keyStr := string(foldedShardKey)

					for _, l1Idx := range l1Indices {
						index := int(l1Idx)
						if index >= len(cp.shardCommitmentTrees) {
							continue
						}

						if cp.shardCommitmentTrees[index] == nil {
							cp.shardCommitmentTrees[index] = &tries.VectorCommitmentTree{}
						}

						if currentKeySets[index] == nil {
							currentKeySets[index] = make(map[string]struct{})
						}
						currentKeySets[index][keyStr] = struct{}{}

						tree := cp.shardCommitmentTrees[index]
						if existing, err := tree.Get(foldedShardKey); err == nil &&
							bytes.Equal(existing, root) {
							continue
						}

						if err := tree.Insert(
							foldedShardKey,
							slices.Clone(root),
							nil,
							big.NewInt(int64(len(root))),
						); err != nil {
							cp.engine.logger.Warn(
								"failed to insert alt shard root",
								zap.Binary("shard_address", shardAddr),
								zap.Int("phase", phaseSet),
								zap.Error(err),
							)
							continue
						}

						changedTrees[index] = true
					}
				}
			}
		}
	}

	for i := 0; i < len(cp.shardCommitmentTrees); i++ {
		if cp.shardCommitmentTrees[i] == nil {
			cp.shardCommitmentTrees[i] = &tries.VectorCommitmentTree{}
		}

		if changedTrees[i] || cp.shardCommitments[i] == nil {
			cp.shardCommitments[i] = cp.shardCommitmentTrees[i].Commit(
				cp.engine.inclusionProver,
				false,
			)
		}
	}

	preimage := slices.Concat(
		slices.Concat(cp.shardCommitments...),
		proverRoot,
	)

	commitmentHash := sha3.Sum256(preimage)

	cp.proverRoot = proverRoot
	cp.commitmentHash = commitmentHash[:]

	// Note: PublishSnapshot(proverRoot) is now called earlier, inside the
	// materializer.commitBarrier lock, immediately after hg.Commit(). This
	// prevents materialize(N) from racing and corrupting the snapshot data.

	shardCommitmentsCollected.Set(float64(collected))

	return commitmentHash[:], nil
}

// OnReceiveProposal implements consensus.Consumer.
func (cp *ConsensusProtocol) OnReceiveProposal(
	currentRank uint64,
	proposal *models.SignedProposal[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
	],
) {
}

// OnReceiveQuorumCertificate implements consensus.Consumer.
func (cp *ConsensusProtocol) OnReceiveQuorumCertificate(
	currentRank uint64,
	qc models.QuorumCertificate,
) {
}

// OnReceiveTimeoutCertificate implements consensus.Consumer.
func (cp *ConsensusProtocol) OnReceiveTimeoutCertificate(
	currentRank uint64,
	tc models.TimeoutCertificate,
) {
}

// OnStart implements consensus.Consumer.
func (cp *ConsensusProtocol) OnStart(currentRank uint64) {}

// OnStartingTimeout implements consensus.Consumer.
func (cp *ConsensusProtocol) OnStartingTimeout(
	startTime time.Time,
	endTime time.Time,
) {
}

// OnStateIncorporated implements consensus.Consumer.
func (cp *ConsensusProtocol) OnStateIncorporated(
	state *models.State[*protobufs.GlobalFrame],
) {
	cp.engine.frameStoreMu.Lock()
	cp.engine.frameStore[state.Identifier] = *state.State
	cp.engine.frameStoreMu.Unlock()
}

// OnTimeoutCertificateTriggeredRankChange implements consensus.Consumer.
func (cp *ConsensusProtocol) OnTimeoutCertificateTriggeredRankChange(
	oldRank uint64,
	newRank uint64,
	tc models.TimeoutCertificate,
) {
	cp.engine.logger.Debug(
		"inserting timeout certificate",
		zap.Uint64("rank", tc.GetRank()),
	)

	txn, err := cp.engine.clockStore.NewTransaction(false)
	if err != nil {
		cp.engine.logger.Error("could not create transaction", zap.Error(err))
		return
	}

	qc := tc.GetLatestQuorumCert()
	err = cp.engine.clockStore.PutTimeoutCertificate(&protobufs.TimeoutCertificate{
		Rank:        tc.GetRank(),
		LatestRanks: tc.GetLatestRanks(),
		LatestQuorumCertificate: &protobufs.QuorumCertificate{
			Rank:        qc.GetRank(),
			FrameNumber: qc.GetFrameNumber(),
			Selector:    []byte(qc.Identity()),
			AggregateSignature: &protobufs.BLS48581AggregateSignature{
				Signature: qc.GetAggregatedSignature().GetSignature(),
				PublicKey: &protobufs.BLS48581G2PublicKey{
					KeyValue: qc.GetAggregatedSignature().GetPubKey(),
				},
				Bitmask: qc.GetAggregatedSignature().GetBitmask(),
			},
		},
		AggregateSignature: &protobufs.BLS48581AggregateSignature{
			Signature: tc.GetAggregatedSignature().GetSignature(),
			PublicKey: &protobufs.BLS48581G2PublicKey{
				KeyValue: tc.GetAggregatedSignature().GetPubKey(),
			},
			Bitmask: tc.GetAggregatedSignature().GetBitmask(),
		},
	}, txn)
	if err != nil {
		txn.Abort()
		cp.engine.logger.Error("could not insert timeout certificate")
		return
	}

	if err := txn.Commit(); err != nil {
		txn.Abort()
		cp.engine.logger.Error("could not commit transaction", zap.Error(err))
	}
}

// VerifyQuorumCertificate implements consensus.Verifier.
func (cp *ConsensusProtocol) VerifyQuorumCertificate(
	quorumCertificate models.QuorumCertificate,
) error {
	qc, ok := quorumCertificate.(*protobufs.QuorumCertificate)
	if !ok {
		return errors.Wrap(
			errors.New("invalid quorum certificate"),
			"verify quorum certificate",
		)
	}

	if err := qc.Validate(); err != nil {
		return models.NewInvalidFormatError(
			errors.Wrap(err, "verify quorum certificate"),
		)
	}

	// genesis qc is special:
	if quorumCertificate.GetRank() == 0 {
		genqc, err := cp.engine.clockStore.GetQuorumCertificate(nil, 0)
		if err != nil {
			return errors.Wrap(err, "verify quorum certificate")
		}

		if genqc.Equals(quorumCertificate) {
			return nil
		}
	}

	provers, err := cp.engine.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return errors.Wrap(err, "verify quorum certificate")
	}

	pubkeys := [][]byte{}
	signatures := [][]byte{}
	if ((len(provers) + 7) / 8) > len(qc.AggregateSignature.Bitmask) {
		return models.ErrInvalidSignature
	}
	for i, prover := range provers {
		if qc.AggregateSignature.Bitmask[i/8]&(1<<(i%8)) == (1 << (i % 8)) {
			pubkeys = append(pubkeys, prover.PublicKey)
			signatures = append(signatures, qc.AggregateSignature.GetSignature())
		}
	}

	aggregationCheck, err := cp.engine.blsConstructor.Aggregate(pubkeys, signatures)
	if err != nil {
		return models.ErrInvalidSignature
	}

	if !bytes.Equal(
		qc.AggregateSignature.GetPubKey(),
		aggregationCheck.GetAggregatePublicKey(),
	) {
		return models.ErrInvalidSignature
	}

	if valid := cp.engine.blsConstructor.VerifySignatureRaw(
		qc.AggregateSignature.GetPubKey(),
		qc.AggregateSignature.GetSignature(),
		verification.MakeVoteMessage(nil, qc.Rank, qc.Identity()),
		[]byte("global"),
	); !valid {
		return models.ErrInvalidSignature
	}

	return nil
}

// VerifyTimeoutCertificate implements consensus.Verifier.
func (cp *ConsensusProtocol) VerifyTimeoutCertificate(
	timeoutCertificate models.TimeoutCertificate,
) error {
	tc, ok := timeoutCertificate.(*protobufs.TimeoutCertificate)
	if !ok {
		return errors.Wrap(
			errors.New("invalid timeout certificate"),
			"verify timeout certificate",
		)
	}

	if err := tc.Validate(); err != nil {
		return models.NewInvalidFormatError(
			errors.Wrap(err, "verify timeout certificate"),
		)
	}

	provers, err := cp.engine.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return errors.Wrap(err, "verify timeout certificate")
	}

	pubkeys := [][]byte{}
	signatures := [][]byte{}
	messages := [][]byte{}
	if ((len(provers) + 7) / 8) > len(tc.AggregateSignature.Bitmask) {
		return models.ErrInvalidSignature
	}

	idx := 0
	for i, prover := range provers {
		if tc.AggregateSignature.Bitmask[i/8]&(1<<(i%8)) == (1 << (i % 8)) {
			pubkeys = append(pubkeys, prover.PublicKey)
			signatures = append(signatures, tc.AggregateSignature.GetSignature())
			messages = append(messages, verification.MakeTimeoutMessage(
				nil,
				tc.Rank,
				tc.LatestRanks[idx],
			))
			idx++
		}
	}

	aggregationCheck, err := cp.engine.blsConstructor.Aggregate(pubkeys, signatures)
	if err != nil {
		return models.ErrInvalidSignature
	}

	if !bytes.Equal(
		tc.AggregateSignature.GetPubKey(),
		aggregationCheck.GetAggregatePublicKey(),
	) {
		return models.ErrInvalidSignature
	}

	if valid := cp.engine.blsConstructor.VerifyMultiMessageSignatureRaw(
		pubkeys,
		tc.AggregateSignature.GetSignature(),
		messages,
		[]byte("globaltimeout"),
	); !valid {
		return models.ErrInvalidSignature
	}

	return nil
}

// VerifyVote implements consensus.Verifier.
func (cp *ConsensusProtocol) VerifyVote(
	vote **protobufs.ProposalVote,
) error {
	if vote == nil || *vote == nil {
		return errors.Wrap(errors.New("nil vote"), "verify vote")
	}

	if err := (*vote).Validate(); err != nil {
		return models.NewInvalidFormatError(
			errors.Wrap(err, "verify vote"),
		)
	}

	provers, err := cp.engine.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return errors.Wrap(err, "verify vote")
	}

	var pubkey []byte
	for _, p := range provers {
		if bytes.Equal(p.Address, (*vote).PublicKeySignatureBls48581.Address) {
			pubkey = p.PublicKey
			break
		}
	}

	if bytes.Equal(pubkey, []byte{}) {
		return models.ErrInvalidSignature
	}

	if valid := cp.engine.blsConstructor.VerifySignatureRaw(
		pubkey,
		(*vote).PublicKeySignatureBls48581.Signature,
		verification.MakeVoteMessage(nil, (*vote).Rank, (*vote).Source()),
		[]byte("global"),
	); !valid {
		return models.ErrInvalidSignature
	}

	return nil
}

func (cp *ConsensusProtocol) getPendingProposals(
	frameNumber uint64,
) []*models.SignedProposal[
	*protobufs.GlobalFrame,
	*protobufs.ProposalVote,
] {
	rootIter, err := cp.engine.clockStore.RangeGlobalClockFrameCandidates(
		frameNumber,
		frameNumber,
	)
	if err != nil {
		panic(err)
	}

	rootIter.First()
	root, err := rootIter.Value()
	if err != nil {
		panic(err)
	}

	result := []*models.SignedProposal[
		*protobufs.GlobalFrame,
		*protobufs.ProposalVote,
	]{}

	cp.engine.logger.Debug("getting pending proposals", zap.Uint64("start", frameNumber))

	startRank := root.Header.Rank
	latestQC, err := cp.engine.clockStore.GetLatestQuorumCertificate(nil)
	if err != nil {
		panic(err)
	}
	endRank := latestQC.Rank

	parent, err := cp.engine.clockStore.GetQuorumCertificate(nil, startRank)
	if err != nil {
		return result
	}

	for rank := startRank + 1; rank <= endRank; rank++ {
		nextQC, err := cp.engine.clockStore.GetQuorumCertificate(nil, rank)
		if err != nil {
			cp.engine.logger.Debug("no qc for rank", zap.Error(err))
			break
		}

		value, err := cp.engine.clockStore.GetGlobalClockFrameCandidate(
			nextQC.FrameNumber,
			[]byte(nextQC.Identity()),
		)
		if err != nil {
			cp.engine.logger.Debug("no frame for qc", zap.Error(err))
			break
		}

		var priorTCModel models.TimeoutCertificate = nil
		if parent.Rank != rank-1 {
			priorTC, _ := cp.engine.clockStore.GetTimeoutCertificate(nil, rank-1)
			if priorTC != nil {
				priorTCModel = priorTC
			}
		}

		vote := &protobufs.ProposalVote{
			Rank:        value.GetRank(),
			FrameNumber: value.Header.FrameNumber,
			Selector:    []byte(value.Identity()),
			PublicKeySignatureBls48581: &protobufs.BLS48581AddressedSignature{
				Signature: value.Header.PublicKeySignatureBls48581.Signature,
				Address:   []byte(value.Source()),
			},
		}
		result = append(result, &models.SignedProposal[
			*protobufs.GlobalFrame,
			*protobufs.ProposalVote,
		]{
			Proposal: models.Proposal[*protobufs.GlobalFrame]{
				State: &models.State[*protobufs.GlobalFrame]{
					Rank:                    value.GetRank(),
					Identifier:              value.Identity(),
					ProposerID:              value.Source(),
					ParentQuorumCertificate: parent,
					State:                   &value,
				},
				PreviousRankTimeoutCertificate: priorTCModel,
			},
			Vote: &vote,
		})
		parent = nextQC
	}
	return result
}
