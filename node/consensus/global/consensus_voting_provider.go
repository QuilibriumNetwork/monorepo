package global

import (
	"bytes"
	"context"
	"encoding/hex"
	"sync"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// GlobalVotingProvider implements VotingProvider
type GlobalVotingProvider struct {
	engine        *GlobalConsensusEngine
	proposalVotes map[consensus.Identity]map[consensus.Identity]**protobufs.FrameVote
	mu            sync.RWMutex
}

func (p *GlobalVotingProvider) SendProposal(
	proposal **protobufs.GlobalFrame,
	ctx context.Context,
) error {
	timer := prometheus.NewTimer(framePublishingDuration)
	defer timer.ObserveDuration()

	if proposal == nil || (*proposal).Header == nil {
		framePublishingTotal.WithLabelValues("error").Inc()
		return errors.Wrap(
			errors.New("invalid proposal"),
			"send proposal",
		)
	}

	// Store the frame
	frameID := p.engine.globalTimeReel.ComputeFrameID(*proposal)
	p.engine.frameStoreMu.Lock()
	p.engine.frameStore[frameID] = (*proposal)
	p.engine.frameStoreMu.Unlock()

	p.engine.logger.Info(
		"sending global proposal",
		zap.Uint64("frame_number", (*proposal).Header.FrameNumber),
	)

	// Serialize the frame using canonical bytes
	frameData, err := (*proposal).ToCanonicalBytes()
	if err != nil {
		p.engine.logger.Error("could not serialize frame", zap.Error(err))
		framePublishingTotal.WithLabelValues("error").Inc()
		return errors.Wrap(err, "serialize global frame")
	}

	// Publish to the global consensus bitmask
	if err := p.engine.pubsub.PublishToBitmask(
		GLOBAL_CONSENSUS_BITMASK,
		frameData,
	); err != nil {
		p.engine.logger.Error("could not publish frame", zap.Error(err))
		framePublishingTotal.WithLabelValues("error").Inc()
		return errors.Wrap(err, "send proposal")
	}

	framePublishingTotal.WithLabelValues("success").Inc()
	return nil
}

func (p *GlobalVotingProvider) DecideAndSendVote(
	proposals map[consensus.Identity]**protobufs.GlobalFrame,
	ctx context.Context,
) (GlobalPeerID, **protobufs.FrameVote, error) {
	var chosenProposal *protobufs.GlobalFrame
	var chosenID consensus.Identity
	parentFrame := p.engine.GetFrame()

	// Get parent selector for validating continuity
	var parentSelector []byte
	if parentFrame != nil && parentFrame.Header != nil {
		parentSelectorBI, _ := poseidon.HashBytes(parentFrame.Header.Output)
		parentSelector = parentSelectorBI.FillBytes(make([]byte, 32))
	}

	// Get ordered provers to prioritize proposals
	provers, err := p.engine.proverRegistry.GetOrderedProvers(
		[32]byte(parentSelector),
		nil, // global consensus uses nil filter
	)
	if err != nil {
		p.engine.logger.Error("could not get prover list", zap.Error(err))
		return GlobalPeerID{}, nil, errors.Wrap(err, "decide and send vote")
	}

	// Check proposals in prover order
	for _, proverID := range provers {
		prop := proposals[GlobalPeerID{ID: proverID}.Identity()]
		if prop == nil {
			continue
		}

		// Validate the proposal
		valid, err := p.engine.frameValidator.Validate((*prop))
		if err != nil {
			p.engine.logger.Debug("proposal validation error", zap.Error(err))
			continue
		}

		// Check parent continuity
		if parentFrame != nil && parentFrame.Header != nil {
			if !bytes.Equal((*prop).Header.ParentSelector, parentSelector) {
				p.engine.logger.Debug(
					"proposed frame out of sequence",
					zap.String(
						"proposed_parent_selector",
						hex.EncodeToString((*prop).Header.ParentSelector),
					),
					zap.String(
						"target_parent_selector",
						hex.EncodeToString(parentSelector),
					),
					zap.Uint64("proposed_frame_number", (*prop).Header.FrameNumber),
					zap.Uint64("target_frame_number", parentFrame.Header.FrameNumber+1),
				)
				continue
			}
		}

		if valid {
			chosenProposal = (*prop)
			chosenID = GlobalPeerID{ID: proverID}.Identity()
			break
		}
	}

	if chosenProposal == nil {
		p.engine.logger.Error("proposal is nil")
		return GlobalPeerID{}, nil, errors.Wrap(
			errors.New("no valid proposals to vote on"),
			"decide and send vote",
		)
	}

	// Get signing key
	signer, _, publicKey, _ := p.engine.GetProvingKey(p.engine.config.Engine)
	if publicKey == nil {
		p.engine.logger.Error("no proving key available")
		return GlobalPeerID{}, nil, errors.Wrap(
			errors.New("no proving key available for voting"),
			"decide and send vote",
		)
	}

	// Create vote (signature)
	signatureData, err := p.engine.frameProver.GetGlobalFrameSignaturePayload(
		chosenProposal.Header,
	)
	if err != nil {
		p.engine.logger.Error("could not get signature payload", zap.Error(err))
		return GlobalPeerID{}, nil, errors.Wrap(err, "decide and send vote")
	}

	sig, err := signer.SignWithDomain(signatureData, []byte("global"))
	if err != nil {
		p.engine.logger.Error("could not sign vote", zap.Error(err))
		return GlobalPeerID{}, nil, errors.Wrap(err, "decide and send vote")
	}

	voterAddress := p.engine.getAddressFromPublicKey(publicKey)

	// Extract proposer ID from the chosen proposal
	var proposerID []byte
	for _, proverID := range provers {
		if (GlobalPeerID{ID: proverID}).Identity() == chosenID {
			proposerID = proverID
			break
		}
	}

	// Create vote message
	vote := &protobufs.FrameVote{
		FrameNumber: chosenProposal.Header.FrameNumber,
		Proposer:    proposerID,
		Approve:     true,
		Timestamp:   time.Now().UnixMilli(),
		PublicKeySignatureBls48581: &protobufs.BLS48581AddressedSignature{
			Address:   voterAddress,
			Signature: sig,
		},
	}

	data, err := vote.ToCanonicalBytes()
	if err != nil {
		return GlobalPeerID{}, nil, errors.Wrap(err, "serialize vote")
	}

	if err := p.engine.pubsub.PublishToBitmask(
		GLOBAL_CONSENSUS_BITMASK,
		data,
	); err != nil {
		p.engine.logger.Error("failed to publish vote", zap.Error(err))
	}

	// Store our vote
	p.mu.Lock()
	if _, ok := p.proposalVotes[chosenID]; !ok {
		p.proposalVotes[chosenID] = map[consensus.Identity]**protobufs.FrameVote{}
	}
	p.proposalVotes[chosenID][p.engine.getPeerID().Identity()] = &vote
	p.mu.Unlock()

	p.engine.logger.Info(
		"decided and sent vote",
		zap.Uint64("frame_number", chosenProposal.Header.FrameNumber),
		zap.String("for_proposal", chosenID),
	)

	return GlobalPeerID{ID: proposerID}, &vote, nil
}

func (p *GlobalVotingProvider) SendVote(
	vote **protobufs.FrameVote,
	ctx context.Context,
) (GlobalPeerID, error) {
	if vote == nil || *vote == nil {
		return GlobalPeerID{}, errors.Wrap(
			errors.New("no vote provided"),
			"send vote",
		)
	}

	bumpVote := &protobufs.FrameVote{
		FrameNumber:                (*vote).FrameNumber,
		Proposer:                   (*vote).Proposer,
		Approve:                    true,
		Timestamp:                  time.Now().UnixMilli(),
		PublicKeySignatureBls48581: (*vote).PublicKeySignatureBls48581,
	}

	data, err := (*bumpVote).ToCanonicalBytes()
	if err != nil {
		return GlobalPeerID{}, errors.Wrap(err, "serialize vote")
	}

	if err := p.engine.pubsub.PublishToBitmask(
		GLOBAL_CONSENSUS_BITMASK,
		data,
	); err != nil {
		p.engine.logger.Error("failed to publish vote", zap.Error(err))
	}

	return GlobalPeerID{ID: (*vote).Proposer}, nil
}

func (p *GlobalVotingProvider) IsQuorum(
	proposalVotes map[consensus.Identity]**protobufs.FrameVote,
	ctx context.Context,
) (bool, error) {
	// Get active prover count for quorum calculation
	activeProvers, err := p.engine.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return false, errors.Wrap(err, "is quorum")
	}

	minVotes := len(activeProvers) * 2 / 3 // 2/3 majority
	if minVotes < int(p.engine.minimumProvers()) {
		minVotes = int(p.engine.minimumProvers())
	}

	totalVotes := len(proposalVotes)

	if totalVotes >= minVotes {
		return true, nil
	}

	return false, nil
}

func (p *GlobalVotingProvider) FinalizeVotes(
	proposals map[consensus.Identity]**protobufs.GlobalFrame,
	proposalVotes map[consensus.Identity]**protobufs.FrameVote,
	ctx context.Context,
) (**protobufs.GlobalFrame, GlobalPeerID, error) {
	// Count approvals and collect signatures
	var signatures [][]byte
	var publicKeys [][]byte
	var chosenProposal **protobufs.GlobalFrame
	var chosenProposerID GlobalPeerID
	winnerCount := 0
	parentFrame := p.engine.GetFrame()
	voteCount := map[string]int{}
	for _, vote := range proposalVotes {
		count, ok := voteCount[string((*vote).Proposer)]
		if !ok {
			voteCount[string((*vote).Proposer)] = 1
		} else {
			voteCount[string((*vote).Proposer)] = count + 1
		}
	}
	for _, proposal := range proposals {
		if proposal == nil {
			continue
		}

		proposer := p.engine.getAddressFromPublicKey(
			(*proposal).Header.PublicKeySignatureBls48581.PublicKey.KeyValue,
		)
		count := voteCount[string(proposer)]
		if count > winnerCount {
			winnerCount = count
			chosenProposal = proposal
			chosenProposerID = GlobalPeerID{ID: proposer}
		}
	}

	if chosenProposal == nil && len(proposals) > 0 {
		// No specific votes, just pick first proposal
		for _, proposal := range proposals {
			if proposal == nil {
				continue
			}

			chosenProposal = proposal
		}
	}

	if chosenProposal == nil {
		return &parentFrame, GlobalPeerID{}, errors.Wrap(
			errors.New("no proposals to finalize"),
			"finalize votes",
		)
	}

	proverSet, err := p.engine.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return &parentFrame, GlobalPeerID{}, errors.Wrap(err, "finalize votes")
	}

	proverMap := map[string][]byte{}
	for _, prover := range proverSet {
		proverMap[string(prover.Address)] = prover.PublicKey
	}

	voterMap := map[string]**protobufs.FrameVote{}

	// Collect all signatures for aggregation
	for _, vote := range proposalVotes {
		if vote == nil {
			continue
		}

		if (*vote).FrameNumber != (*chosenProposal).Header.FrameNumber ||
			!bytes.Equal((*vote).Proposer, chosenProposerID.ID) {
			continue
		}

		if (*vote).PublicKeySignatureBls48581.Signature != nil &&
			(*vote).PublicKeySignatureBls48581.Address != nil {
			signatures = append(
				signatures,
				(*vote).PublicKeySignatureBls48581.Signature,
			)

			pub := proverMap[string((*vote).PublicKeySignatureBls48581.Address)]
			publicKeys = append(publicKeys, pub)
			voterMap[string((*vote).PublicKeySignatureBls48581.Address)] = vote
		}
	}

	if len(signatures) == 0 {
		return &parentFrame, GlobalPeerID{}, errors.Wrap(
			errors.New("no signatures to aggregate"),
			"finalize votes",
		)
	}

	// Aggregate signatures
	aggregateOutput, err := p.engine.keyManager.Aggregate(publicKeys, signatures)
	if err != nil {
		return &parentFrame, GlobalPeerID{}, errors.Wrap(err, "finalize votes")
	}
	aggregatedSignature := aggregateOutput.GetAggregateSignature()

	// Create participant bitmap
	provers, err := p.engine.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return &parentFrame, GlobalPeerID{}, errors.Wrap(err, "finalize votes")
	}

	bitmask := make([]byte, (len(provers)+7)/8)

	for i := 0; i < len(provers); i++ {
		activeProver := provers[i]

		// Check if this prover voted in our voterMap
		if _, ok := voterMap[string(activeProver.Address)]; ok {
			byteIndex := i / 8
			bitIndex := i % 8
			bitmask[byteIndex] |= (1 << bitIndex)
		}
	}

	// Update the frame with aggregated signature
	finalizedFrame := &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:          (*chosenProposal).Header.FrameNumber,
			ParentSelector:       (*chosenProposal).Header.ParentSelector,
			Timestamp:            (*chosenProposal).Header.Timestamp,
			Difficulty:           (*chosenProposal).Header.Difficulty,
			GlobalCommitments:    (*chosenProposal).Header.GlobalCommitments,
			ProverTreeCommitment: (*chosenProposal).Header.ProverTreeCommitment,
			Output:               (*chosenProposal).Header.Output,
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Signature: aggregatedSignature,
				PublicKey: &protobufs.BLS48581G2PublicKey{
					KeyValue: aggregateOutput.GetAggregatePublicKey(),
				},
				Bitmask: bitmask,
			},
		},
		Requests: (*chosenProposal).Requests,
	}

	p.engine.logger.Info(
		"finalized votes",
		zap.Uint64("frame_number", finalizedFrame.Header.FrameNumber),
		zap.Int("signatures", len(signatures)),
	)

	return &finalizedFrame, chosenProposerID, nil
}

func (p *GlobalVotingProvider) SendConfirmation(
	finalized **protobufs.GlobalFrame,
	ctx context.Context,
) error {
	if finalized == nil || (*finalized).Header == nil {
		return errors.Wrap(
			errors.New("invalid finalized frame"),
			"send confirmation",
		)
	}

	copiedFinalized := proto.Clone(*finalized).(*protobufs.GlobalFrame)

	selectorBI, err := poseidon.HashBytes(copiedFinalized.Header.Output)

	if err != nil {
		return errors.Wrap(err, "send confirmation")
	}
	// Create frame confirmation
	confirmation := &protobufs.FrameConfirmation{
		FrameNumber:        copiedFinalized.Header.FrameNumber,
		Selector:           selectorBI.FillBytes(make([]byte, 32)),
		Timestamp:          time.Now().UnixMilli(),
		AggregateSignature: copiedFinalized.Header.PublicKeySignatureBls48581,
	}

	// Serialize and send confirmation
	data, err := confirmation.ToCanonicalBytes()
	if err != nil {
		return errors.Wrap(err, "send confirmation")
	}

	if err := p.engine.pubsub.PublishToBitmask(
		GLOBAL_CONSENSUS_BITMASK,
		data,
	); err != nil {
		return errors.Wrap(err, "send confirmation")
	}

	// Serialize and send finalized frame over the global frame bitmask
	frameData, err := copiedFinalized.ToCanonicalBytes()
	if err != nil {
		return errors.Wrap(err, "send confirmation")
	}
	if err := p.engine.pubsub.PublishToBitmask(
		GLOBAL_FRAME_BITMASK,
		frameData,
	); err != nil {
		return errors.Wrap(err, "send confirmation")
	}

	// Insert into time reel
	if err := p.engine.globalTimeReel.Insert(
		p.engine.ctx,
		copiedFinalized,
	); err != nil {
		p.engine.logger.Error("failed to add frame to time reel", zap.Error(err))
		// Clean up on error
		frameIDBI, _ := poseidon.HashBytes(copiedFinalized.Header.Output)
		frameID := frameIDBI.FillBytes(make([]byte, 32))
		p.engine.frameStoreMu.Lock()
		delete(p.engine.frameStore, string(frameID))
		p.engine.frameStoreMu.Unlock()
		return errors.Wrap(err, "send confirmation")
	}

	p.engine.logger.Info(
		"sent confirmation",
		zap.Uint64("frame_number", copiedFinalized.Header.FrameNumber),
	)

	return nil
}
