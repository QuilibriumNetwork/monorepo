package global

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
)

// GlobalVotingProvider implements VotingProvider
type GlobalVotingProvider struct {
	engine *GlobalConsensusEngine
}

// FinalizeQuorumCertificate implements consensus.VotingProvider.
func (p *GlobalVotingProvider) FinalizeQuorumCertificate(
	ctx context.Context,
	state *models.State[*protobufs.GlobalFrame],
	aggregatedSignature models.AggregatedSignature,
) (models.QuorumCertificate, error) {
	return &protobufs.QuorumCertificate{
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
func (p *GlobalVotingProvider) FinalizeTimeout(
	ctx context.Context,
	rank uint64,
	latestQuorumCertificate models.QuorumCertificate,
	latestQuorumCertificateRanks []consensus.TimeoutSignerInfo,
	aggregatedSignature models.AggregatedSignature,
) (models.TimeoutCertificate, error) {
	ranksInProverOrder := slices.Clone(latestQuorumCertificateRanks)
	provers, err := p.engine.proverRegistry.GetActiveProvers(nil)
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
func (p *GlobalVotingProvider) SignTimeoutVote(
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
		nil,
		currentRank,
		newestQuorumCertificateRank,
	)

	sig, err := signer.SignWithDomain(signatureData, []byte("globaltimeout"))
	if err != nil {
		p.engine.logger.Error("could not sign vote", zap.Error(err))
		return nil, errors.Wrap(err, "sign vote")
	}

	voterAddress := p.engine.getAddressFromPublicKey(publicKey)

	// Create vote message
	vote := &protobufs.ProposalVote{
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
func (p *GlobalVotingProvider) SignVote(
	ctx context.Context,
	state *models.State[*protobufs.GlobalFrame],
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
	signatureData := verification.MakeVoteMessage(
		nil,
		state.Rank,
		state.Identifier,
	)
	sig, err := signer.SignWithDomain(signatureData, []byte("global"))
	if err != nil {
		p.engine.logger.Error("could not sign vote", zap.Error(err))
		return nil, errors.Wrap(err, "sign vote")
	}

	voterAddress := p.engine.getAddressFromPublicKey(publicKey)

	// Create vote message
	vote := &protobufs.ProposalVote{
		FrameNumber: (*state.State).Header.FrameNumber,
		Rank:        (*state.State).Header.Rank,
		Selector:    []byte((*state.State).Identity()),
		Timestamp:   uint64(time.Now().UnixMilli()),
		PublicKeySignatureBls48581: &protobufs.BLS48581AddressedSignature{
			Address:   voterAddress,
			Signature: sig,
		},
	}

	return &vote, nil
}

var _ consensus.VotingProvider[*protobufs.GlobalFrame, *protobufs.ProposalVote, GlobalPeerID] = (*GlobalVotingProvider)(nil)
