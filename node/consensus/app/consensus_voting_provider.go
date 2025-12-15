package app

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/verification"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

// AppVotingProvider implements VotingProvider
type AppVotingProvider struct {
	engine *AppConsensusEngine
}

// FinalizeQuorumCertificate implements consensus.VotingProvider.
func (p *AppVotingProvider) FinalizeQuorumCertificate(
	ctx context.Context,
	state *models.State[*protobufs.AppShardFrame],
	aggregatedSignature models.AggregatedSignature,
) (models.QuorumCertificate, error) {
	cloned := (*state.State).Clone().(*protobufs.AppShardFrame)
	cloned.Header.PublicKeySignatureBls48581 =
		&protobufs.BLS48581AggregateSignature{
			Signature: aggregatedSignature.GetSignature(),
			PublicKey: &protobufs.BLS48581G2PublicKey{
				KeyValue: aggregatedSignature.GetPubKey(),
			},
			Bitmask: aggregatedSignature.GetBitmask(),
		}
	frameBytes, err := cloned.ToCanonicalBytes()
	if err != nil {
		return nil, errors.Wrap(err, "finalize quorum certificate")
	}

	p.engine.pubsub.PublishToBitmask(
		p.engine.getFrameMessageBitmask(),
		frameBytes,
	)

	return &protobufs.QuorumCertificate{
		Filter:      (*state.State).Header.Address,
		Rank:        (*state.State).GetRank(),
		FrameNumber: (*state.State).Header.FrameNumber,
		Selector:    []byte((*state.State).Identity()),
		Timestamp:   uint64(time.Now().UnixMilli()),
		AggregateSignature: &protobufs.BLS48581AggregateSignature{
			Signature: aggregatedSignature.GetSignature(),
			PublicKey: &protobufs.BLS48581G2PublicKey{
				KeyValue: aggregatedSignature.GetPubKey(),
			},
			Bitmask: aggregatedSignature.GetBitmask(),
		},
	}, nil
}

// FinalizeTimeout implements consensus.VotingProvider.
func (p *AppVotingProvider) FinalizeTimeout(
	ctx context.Context,
	rank uint64,
	latestQuorumCertificate models.QuorumCertificate,
	latestQuorumCertificateRanks []consensus.TimeoutSignerInfo,
	aggregatedSignature models.AggregatedSignature,
) (models.TimeoutCertificate, error) {
	ranksInProverOrder := slices.Clone(latestQuorumCertificateRanks)
	provers, err := p.engine.proverRegistry.GetActiveProvers(p.engine.appAddress)
	if err != nil {
		return nil, err
	}

	proverIndexes := map[models.Identity]int{}
	for i, p := range provers {
		proverIndexes[models.Identity(p.Address)] = i
	}

	sort.Slice(ranksInProverOrder, func(i, j int) bool {
		return proverIndexes[ranksInProverOrder[i].Signer]-
			proverIndexes[ranksInProverOrder[j].Signer] < 0
	})

	ranks := []uint64{}
	for _, r := range ranksInProverOrder {
		ranks = append(ranks, r.NewestQCRank)
	}

	return &protobufs.TimeoutCertificate{
		Filter:                  p.engine.appAddress,
		Rank:                    rank,
		LatestRanks:             ranks,
		LatestQuorumCertificate: latestQuorumCertificate.(*protobufs.QuorumCertificate),
		Timestamp:               uint64(time.Now().UnixMilli()),
		AggregateSignature: &protobufs.BLS48581AggregateSignature{
			Signature: aggregatedSignature.GetSignature(),
			PublicKey: &protobufs.BLS48581G2PublicKey{
				KeyValue: aggregatedSignature.GetPubKey(),
			},
			Bitmask: aggregatedSignature.GetBitmask(),
		},
	}, nil
}

// SignTimeoutVote implements consensus.VotingProvider.
func (p *AppVotingProvider) SignTimeoutVote(
	ctx context.Context,
	filter []byte,
	currentRank uint64,
	newestQuorumCertificateRank uint64,
) (**protobufs.ProposalVote, error) {
	// Get signing key
	signer, _, publicKey, _ := p.engine.GetProvingKey(p.engine.config.Engine)
	if publicKey == nil {
		p.engine.logger.Error("no proving key available")
		return nil, errors.Wrap(
			errors.New("no proving key available for voting"),
			"sign vote",
		)
	}

	// Create vote (signature)
	signatureData := verification.MakeTimeoutMessage(
		filter,
		currentRank,
		newestQuorumCertificateRank,
	)

	sig, err := signer.SignWithDomain(
		signatureData,
		slices.Concat([]byte("appshardtimeout"), p.engine.appAddress),
	)
	if err != nil {
		p.engine.logger.Error("could not sign vote", zap.Error(err))
		return nil, errors.Wrap(err, "sign vote")
	}

	voterAddress := p.engine.getAddressFromPublicKey(publicKey)

	// Create vote message
	vote := &protobufs.ProposalVote{
		Filter:      filter, // buildutils:allow-slice-alias slice is static
		FrameNumber: 0,
		Rank:        currentRank,
		Selector:    nil,
		Timestamp:   uint64(time.Now().UnixMilli()),
		PublicKeySignatureBls48581: &protobufs.BLS48581AddressedSignature{
			Address:   voterAddress,
			Signature: sig,
		},
	}

	return &vote, nil
}

// SignVote implements consensus.VotingProvider.
func (p *AppVotingProvider) SignVote(
	ctx context.Context,
	state *models.State[*protobufs.AppShardFrame],
) (**protobufs.ProposalVote, error) {
	// Get signing key
	signer, _, publicKey, _ := p.engine.GetProvingKey(p.engine.config.Engine)
	if publicKey == nil {
		p.engine.logger.Error("no proving key available")
		return nil, errors.Wrap(
			errors.New("no proving key available for voting"),
			"sign vote",
		)
	}

	nextLeader, err := p.engine.LeaderForRank(state.Rank)
	if err != nil {
		p.engine.logger.Error("could not determine next prover", zap.Error(err))
		return nil, errors.Wrap(
			errors.New("could not determine next prover"),
			"sign vote",
		)
	}

	var extProof []byte
	if nextLeader != p.engine.Self() {
		p.engine.proofCacheMu.RLock()
		proof, ok := p.engine.proofCache[state.Rank]
		p.engine.proofCacheMu.RUnlock()

		if !ok {
			return nil, errors.Wrap(
				errors.New("no proof ready for vote"),
				"sign vote",
			)
		}
		extProof = proof[:]
	}

	// Create vote (signature)
	signatureData := verification.MakeVoteMessage(
		(*state.State).Header.Address,
		state.Rank,
		state.Identifier,
	)
	sig, err := signer.SignWithDomain(
		signatureData,
		slices.Concat([]byte("appshard"), p.engine.appAddress),
	)
	if err != nil {
		p.engine.logger.Error("could not sign vote", zap.Error(err))
		return nil, errors.Wrap(err, "sign vote")
	}

	voterAddress := p.engine.getAddressFromPublicKey(publicKey)

	// Create vote message
	vote := &protobufs.ProposalVote{
		Filter:      (*state.State).Header.Address,
		FrameNumber: (*state.State).Header.FrameNumber,
		Rank:        (*state.State).Header.Rank,
		Selector:    []byte((*state.State).Identity()),
		Timestamp:   uint64(time.Now().UnixMilli()),
		PublicKeySignatureBls48581: &protobufs.BLS48581AddressedSignature{
			Address:   voterAddress,
			Signature: slices.Concat(sig, extProof),
		},
	}

	return &vote, nil
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

var _ consensus.VotingProvider[*protobufs.AppShardFrame, *protobufs.ProposalVote, PeerID] = (*AppVotingProvider)(nil)
