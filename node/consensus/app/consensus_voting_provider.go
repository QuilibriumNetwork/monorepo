package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"slices"
	"sync"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

// AppVotingProvider implements VotingProvider
type AppVotingProvider struct {
	engine        *AppConsensusEngine
	proposalVotes map[consensus.Identity]map[consensus.Identity]**protobufs.FrameVote
	mu            sync.Mutex
}

func (p *AppVotingProvider) SendProposal(
	proposal **protobufs.AppShardFrame,
	ctx context.Context,
) error {
	timer := prometheus.NewTimer(framePublishingDuration.WithLabelValues(
		p.engine.appAddressHex,
	))
	defer timer.ObserveDuration()

	if proposal == nil || (*proposal).Header == nil {
		framePublishingTotal.WithLabelValues(p.engine.appAddressHex, "error").Inc()
		return errors.Wrap(
			errors.New("invalid proposal"),
			"send proposal",
		)
	}

	p.engine.logger.Info(
		"sending proposal",
		zap.Uint64("frame_number", (*proposal).Header.FrameNumber),
		zap.String("prover", hex.EncodeToString((*proposal).Header.Prover)),
	)

	// Serialize the frame using canonical bytes
	frameData, err := (*proposal).ToCanonicalBytes()
	if err != nil {
		framePublishingTotal.WithLabelValues(p.engine.appAddressHex, "error").Inc()
		return errors.Wrap(err, "serialize proposal")
	}

	// Publish to the network
	if err := p.engine.pubsub.PublishToBitmask(
		p.engine.getConsensusMessageBitmask(),
		frameData,
	); err != nil {
		framePublishingTotal.WithLabelValues(p.engine.appAddressHex, "error").Inc()
		return errors.Wrap(err, "send proposal")
	}

	// Store the frame
	frameIDBI, _ := poseidon.HashBytes((*proposal).Header.Output)
	frameID := frameIDBI.FillBytes(make([]byte, 32))
	p.engine.frameStoreMu.Lock()
	p.engine.frameStore[string(frameID)] =
		(*proposal).Clone().(*protobufs.AppShardFrame)
	p.engine.frameStoreMu.Unlock()

	framePublishingTotal.WithLabelValues(p.engine.appAddressHex, "success").Inc()
	return nil
}

func (p *AppVotingProvider) DecideAndSendVote(
	proposals map[consensus.Identity]**protobufs.AppShardFrame,
	ctx context.Context,
) (PeerID, **protobufs.FrameVote, error) {
	var chosenProposal *protobufs.AppShardFrame
	var chosenID consensus.Identity
	parentFrame := p.engine.GetFrame()
	if parentFrame == nil {
		return PeerID{}, nil, errors.Wrap(
			errors.New("no frame: no valid proposals to vote on"),
			"decide and send vote",
		)
	}

	parentSelector := p.engine.calculateFrameSelector(parentFrame.Header)
	provers, err := p.engine.proverRegistry.GetOrderedProvers(
		[32]byte(parentSelector),
		p.engine.appAddress,
	)
	if err != nil {
		return PeerID{}, nil, errors.Wrap(err, "decide and send vote")
	}

	for _, id := range provers {
		prop := proposals[PeerID{ID: id}.Identity()]
		if prop == nil {
			p.engine.logger.Debug(
				"proposer not found for prover",
				zap.String("prover", PeerID{ID: id}.Identity()),
			)
			continue
		}
		// Validate the proposal
		valid, err := p.engine.frameValidator.Validate((*prop))
		if err != nil {
			p.engine.logger.Debug("proposal validation error", zap.Error(err))
			continue
		}

		p.engine.frameStoreMu.RLock()
		_, hasParent := p.engine.frameStore[string(
			(*prop).Header.ParentSelector,
		)]
		p.engine.frameStoreMu.RUnlock()
		// Do we have continuity?
		if !hasParent {
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
		} else {
			p.engine.logger.Debug(
				"proposed frame in sequence",
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
		}

		if valid {
			// Validate fee multiplier is within acceptable bounds (+/-10% of base)
			baseFeeMultiplier, err := p.engine.dynamicFeeManager.GetNextFeeMultiplier(
				p.engine.appAddress,
			)
			if err != nil {
				p.engine.logger.Debug(
					"could not get base fee multiplier for validation",
					zap.Error(err),
				)
				continue
			}

			// Calculate the maximum allowed deviation (10%)
			maxIncrease := baseFeeMultiplier + (baseFeeMultiplier / 10)
			minDecrease := baseFeeMultiplier - (baseFeeMultiplier / 10)
			if minDecrease < 1 {
				minDecrease = 1
			}

			proposedFee := (*prop).Header.FeeMultiplierVote

			// Reject if fee is outside acceptable bounds
			if proposedFee > maxIncrease || proposedFee < minDecrease {
				p.engine.logger.Debug(
					"rejecting proposal with excessive fee change",
					zap.Uint64("base_fee", baseFeeMultiplier),
					zap.Uint64("proposed_fee", proposedFee),
					zap.Uint64("max_allowed", maxIncrease),
					zap.Uint64("min_allowed", minDecrease),
				)
				continue
			}

			chosenProposal = (*prop)
			chosenID = PeerID{ID: id}.Identity()
			break
		}
	}

	if chosenProposal == nil {
		return PeerID{}, nil, errors.Wrap(
			errors.New("no valid proposals to vote on"),
			"decide and send vote",
		)
	}

	// Get signing key
	signer, _, publicKey, _ := p.engine.GetProvingKey(p.engine.config.Engine)
	if publicKey == nil {
		return PeerID{}, nil, errors.Wrap(
			errors.New("no proving key available for voting"),
			"decide and send vote",
		)
	}

	// Create vote (signature)
	signatureData, err := p.engine.frameProver.GetFrameSignaturePayload(
		chosenProposal.Header,
	)
	if err != nil {
		return PeerID{}, nil, errors.Wrap(err, "decide and send vote")
	}

	sig, err := signer.SignWithDomain(
		signatureData,
		append([]byte("shard"), p.engine.appAddress...),
	)
	if err != nil {
		return PeerID{}, nil, errors.Wrap(err, "decide and send vote")
	}

	// Get our voter address
	voterAddress := p.engine.getAddressFromPublicKey(publicKey)

	// Create vote message
	vote := &protobufs.FrameVote{
		Filter:      p.engine.appAddress,
		FrameNumber: chosenProposal.Header.FrameNumber,
		Proposer:    chosenProposal.Header.Prover,
		Approve:     true,
		Timestamp:   time.Now().UnixMilli(),
		PublicKeySignatureBls48581: &protobufs.BLS48581AddressedSignature{
			Address:   voterAddress,
			Signature: sig,
		},
	}

	// Serialize and publish vote
	data, err := vote.ToCanonicalBytes()
	if err != nil {
		return PeerID{}, nil, errors.Wrap(err, "serialize vote")
	}

	if err := p.engine.pubsub.PublishToBitmask(
		p.engine.getConsensusMessageBitmask(),
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

	// Return the peer ID from the chosen proposal's prover
	return PeerID{ID: chosenProposal.Header.Prover}, &vote, nil
}

func (p *AppVotingProvider) IsQuorum(
	proposalVotes map[consensus.Identity]**protobufs.FrameVote,
	ctx context.Context,
) (bool, error) {
	// Get active prover count for quorum calculation
	activeProvers, err := p.engine.proverRegistry.GetActiveProvers(
		p.engine.appAddress,
	)
	if err != nil {
		return false, errors.Wrap(err, "is quorum")
	}

	minVotes := len(activeProvers) * 2 / 3
	if minVotes < int(p.engine.minimumProvers()) {
		minVotes = int(p.engine.minimumProvers())
	}

	totalVotes := len(proposalVotes)

	if totalVotes >= minVotes {
		return true, nil
	}

	return false, nil
}

func (p *AppVotingProvider) FinalizeVotes(
	proposals map[consensus.Identity]**protobufs.AppShardFrame,
	proposalVotes map[consensus.Identity]**protobufs.FrameVote,
	ctx context.Context,
) (**protobufs.AppShardFrame, PeerID, error) {
	// Count approvals and collect signatures
	var signatures [][]byte
	var publicKeys [][]byte
	var chosenProposal **protobufs.AppShardFrame
	var chosenProposerID PeerID
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

		p.engine.frameStoreMu.RLock()
		_, hasParent := p.engine.frameStore[string(
			(*proposal).Header.ParentSelector,
		)]
		p.engine.frameStoreMu.RUnlock()

		count := 0
		if hasParent {
			count = voteCount[string((*proposal).Header.Prover)]
		}
		if count > winnerCount {
			winnerCount = count
			chosenProposal = proposal
			chosenProposerID = PeerID{ID: (*proposal).Header.Prover}
		}
	}

	if chosenProposal == nil && len(proposals) > 0 {
		// No specific votes, just pick first proposal
		for _, proposal := range proposals {
			if proposal == nil {
				continue
			}
			p.engine.frameStoreMu.RLock()
			parent, hasParent := p.engine.frameStore[string(
				(*proposal).Header.ParentSelector,
			)]
			p.engine.frameStoreMu.RUnlock()
			if hasParent && (parentFrame == nil ||
				parent.Header.FrameNumber == parentFrame.Header.FrameNumber) {
				chosenProposal = proposal
				chosenProposerID = PeerID{ID: (*proposal).Header.Prover}
				break
			}
		}
	}

	if chosenProposal == nil {
		return &parentFrame, PeerID{}, errors.Wrap(
			errors.New("no proposals to finalize"),
			"finalize votes",
		)
	}

	err := p.engine.ensureGlobalClient()
	if err != nil {
		return &parentFrame, PeerID{}, errors.Wrap(
			errors.New("cannot confirm cross-shard locks"),
			"finalize votes",
		)
	}

	res, err := p.engine.globalClient.GetLockedAddresses(
		ctx,
		&protobufs.GetLockedAddressesRequest{
			ShardAddress: p.engine.appAddress,
			FrameNumber:  (*chosenProposal).Header.FrameNumber,
		},
	)
	if err != nil {
		p.engine.globalClient = nil
		return &parentFrame, PeerID{}, errors.Wrap(
			errors.New("cannot confirm cross-shard locks"),
			"finalize votes",
		)
	}

	// Build a map of transaction hashes to their committed status
	txMap := map[string]bool{}
	for _, req := range (*chosenProposal).Requests {
		tx, err := req.ToCanonicalBytes()
		if err != nil {
			return &parentFrame, PeerID{}, errors.Wrap(
				err,
				"finalize votes",
			)
		}

		txHash := sha3.Sum256(tx)
		p.engine.logger.Debug(
			"adding transaction in frame to commit check",
			zap.String("tx_hash", hex.EncodeToString(txHash[:])),
		)
		txMap[string(txHash[:])] = false
	}

	// Check that transactions are committed in our shard and collect shard
	// addresses
	shardAddressesSet := make(map[string]bool)
	for _, tx := range res.Transactions {
		p.engine.logger.Debug(
			"checking transaction from global map",
			zap.String("tx_hash", hex.EncodeToString(tx.TransactionHash)),
		)
		if _, ok := txMap[string(tx.TransactionHash)]; ok {
			txMap[string(tx.TransactionHash)] = tx.Committed

			// Extract shard addresses from each locked transaction's shard addresses
			for _, shardAddr := range tx.ShardAddresses {
				// Extract the applicable shard address (can be shorter than the full
				// address)
				extractedShards := p.extractShardAddresses(shardAddr)
				for _, extractedShard := range extractedShards {
					shardAddrStr := string(extractedShard)
					shardAddressesSet[shardAddrStr] = true
				}
			}
		}
	}

	// Check that all transactions are committed in our shard
	for _, committed := range txMap {
		if !committed {
			return &parentFrame, PeerID{}, errors.Wrap(
				errors.New("tx not committed in our shard"),
				"finalize votes",
			)
		}
	}

	// Check cross-shard locks for each unique shard address
	for shardAddrStr := range shardAddressesSet {
		shardAddr := []byte(shardAddrStr)

		// Skip our own shard since we already checked it
		if bytes.Equal(shardAddr, p.engine.appAddress) {
			continue
		}

		// Query the global client for locked addresses in this shard
		shardRes, err := p.engine.globalClient.GetLockedAddresses(
			ctx,
			&protobufs.GetLockedAddressesRequest{
				ShardAddress: shardAddr,
				FrameNumber:  (*chosenProposal).Header.FrameNumber,
			},
		)
		if err != nil {
			p.engine.logger.Debug(
				"failed to get locked addresses for shard",
				zap.String("shard_addr", hex.EncodeToString(shardAddr)),
				zap.Error(err),
			)
			continue
		}

		// Check that all our transactions are committed in this shard
		for txHashStr := range txMap {
			committedInShard := false
			for _, tx := range shardRes.Transactions {
				if string(tx.TransactionHash) == txHashStr {
					committedInShard = tx.Committed
					break
				}
			}

			if !committedInShard {
				return &parentFrame, PeerID{}, errors.Wrap(
					errors.New("tx cross-shard lock unconfirmed"),
					"finalize votes",
				)
			}
		}
	}

	proverSet, err := p.engine.proverRegistry.GetActiveProvers(
		p.engine.appAddress,
	)
	if err != nil {
		return &parentFrame, PeerID{}, errors.Wrap(err, "finalize votes")
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
			!bytes.Equal((*vote).Proposer, (*chosenProposal).Header.Prover) {
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
		return &parentFrame, PeerID{}, errors.Wrap(
			errors.New("no signatures to aggregate"),
			"finalize votes",
		)
	}

	// Aggregate signatures
	aggregateOutput, err := p.engine.keyManager.Aggregate(publicKeys, signatures)
	if err != nil {
		return &parentFrame, PeerID{}, errors.Wrap(err, "finalize votes")
	}
	aggregatedSignature := aggregateOutput.GetAggregateSignature()

	// Create participant bitmap
	provers, err := p.engine.proverRegistry.GetActiveProvers(p.engine.appAddress)
	if err != nil {
		return &parentFrame, PeerID{}, errors.Wrap(err, "finalize votes")
	}

	bitmask := make([]byte, (len(provers)+7)/8)

	for i := 0; i < len(provers); i++ {
		activeProver := provers[i]
		if _, ok := voterMap[string(activeProver.Address)]; !ok {
			continue
		}
		if !bytes.Equal(
			(*voterMap[string(activeProver.Address)]).Proposer,
			chosenProposerID.ID,
		) {
			continue
		}

		byteIndex := i / 8
		bitIndex := i % 8
		bitmask[byteIndex] |= (1 << bitIndex)
	}

	// Update the frame with aggregated signature
	finalizedFrame := &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:           (*chosenProposal).Header.Address,
			FrameNumber:       (*chosenProposal).Header.FrameNumber,
			ParentSelector:    (*chosenProposal).Header.ParentSelector,
			Timestamp:         (*chosenProposal).Header.Timestamp,
			Difficulty:        (*chosenProposal).Header.Difficulty,
			RequestsRoot:      (*chosenProposal).Header.RequestsRoot,
			StateRoots:        (*chosenProposal).Header.StateRoots,
			Output:            (*chosenProposal).Header.Output,
			Prover:            (*chosenProposal).Header.Prover,
			FeeMultiplierVote: (*chosenProposal).Header.FeeMultiplierVote,
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

func (p *AppVotingProvider) SendConfirmation(
	finalized **protobufs.AppShardFrame,
	ctx context.Context,
) error {
	if finalized == nil || (*finalized).Header == nil {
		return errors.New("invalid finalized frame")
	}

	copiedFinalized := proto.Clone(*finalized).(*protobufs.AppShardFrame)

	// Create frame confirmation
	confirmation := &protobufs.FrameConfirmation{
		Filter:             p.engine.appAddress,
		FrameNumber:        copiedFinalized.Header.FrameNumber,
		Selector:           p.engine.calculateFrameSelector((*finalized).Header),
		Timestamp:          time.Now().UnixMilli(),
		AggregateSignature: copiedFinalized.Header.PublicKeySignatureBls48581,
	}

	// Serialize using canonical bytes
	data, err := confirmation.ToCanonicalBytes()
	if err != nil {
		return errors.Wrap(err, "serialize confirmation")
	}

	if err := p.engine.pubsub.PublishToBitmask(
		p.engine.getConsensusMessageBitmask(),
		data,
	); err != nil {
		return errors.Wrap(err, "publish confirmation")
	}

	// Insert into time reel
	if err := p.engine.appTimeReel.Insert(
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
	}

	p.engine.logger.Info(
		"sent confirmation",
		zap.Uint64("frame_number", copiedFinalized.Header.FrameNumber),
	)

	return nil
}

// GetFullPath converts a key to its path representation using 6-bit nibbles
func GetFullPath(key []byte) []int32 {
	var nibbles []int32
	depth := 0
	for {
		n1 := getNextNibble(key, depth)
		if n1 == -1 {
			break
		}
		nibbles = append(nibbles, n1)
		depth += tries.BranchBits
	}

	return nibbles
}

// getNextNibble returns the next BranchBits bits from the key starting at pos
func getNextNibble(key []byte, pos int) int32 {
	startByte := pos / 8
	if startByte >= len(key) {
		return -1
	}

	// Calculate how many bits we need from the current byte
	startBit := pos % 8
	bitsFromCurrentByte := 8 - startBit

	result := int(key[startByte] & ((1 << bitsFromCurrentByte) - 1))

	if bitsFromCurrentByte >= tries.BranchBits {
		// We have enough bits in the current byte
		return int32((result >> (bitsFromCurrentByte - tries.BranchBits)) &
			tries.BranchMask)
	}

	// We need bits from the next byte
	result = result << (tries.BranchBits - bitsFromCurrentByte)
	if startByte+1 < len(key) {
		remainingBits := tries.BranchBits - bitsFromCurrentByte
		nextByte := int(key[startByte+1])
		result |= (nextByte >> (8 - remainingBits))
	}

	return int32(result & tries.BranchMask)
}

// extractShardAddresses extracts all possible shard addresses from a transaction address
func (p *AppVotingProvider) extractShardAddresses(txAddress []byte) [][]byte {
	var shardAddresses [][]byte

	// Get the full path from the transaction address
	path := GetFullPath(txAddress)

	// The first 43 nibbles (258 bits) represent the base shard address
	// We need to extract all possible shard addresses by considering path segments after the 43rd nibble
	if len(path) <= 43 {
		// If the path is too short, just return the original address truncated to 32 bytes
		if len(txAddress) >= 32 {
			shardAddresses = append(shardAddresses, txAddress[:32])
		}
		return shardAddresses
	}

	// Convert the first 43 nibbles to bytes (base shard address)
	baseShardAddr := txAddress[:32]
	l1 := up2p.GetBloomFilterIndices(baseShardAddr, 256, 3)
	candidates := map[string]struct{}{}

	// Now generate all possible shard addresses by extending the path
	// Each additional nibble after the 43rd creates a new shard address
	for i := 43; i < len(path); i++ {
		// Create a new shard address by extending the base with this path segment
		extendedAddr := make([]byte, 32)
		copy(extendedAddr, baseShardAddr)

		// Add the path segment as a byte
		extendedAddr = append(extendedAddr, byte(path[i]))

		candidates[string(extendedAddr)] = struct{}{}
	}

	shards, err := p.engine.shardsStore.GetAppShards(
		slices.Concat(l1, baseShardAddr),
		[]uint32{},
	)
	if err != nil {
		return [][]byte{}
	}

	for _, shard := range shards {
		if _, ok := candidates[string(
			slices.Concat(shard.L2, uint32ToBytes(shard.Path)),
		)]; ok {
			shardAddresses = append(shardAddresses, shard.L2)
		}
	}

	return shardAddresses
}

func uint32ToBytes(path []uint32) []byte {
	bytes := []byte{}
	for _, p := range path {
		bytes = append(bytes, byte(p))
	}
	return bytes
}
