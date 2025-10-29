package helper

import (
	crand "crypto/rand"
	"math/rand"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

func MakeIdentity() models.Identity {
	s := make([]byte, 32)
	crand.Read(s)
	return models.Identity(s)
}

func MakeState[StateT models.Unique](options ...func(*models.State[StateT])) *models.State[StateT] {
	rank := rand.Uint64()

	state := models.State[StateT]{
		Rank:                    rank,
		Identifier:              MakeIdentity(),
		ProposerID:              MakeIdentity(),
		Timestamp:               uint64(time.Now().UnixMilli()),
		ParentQuorumCertificate: MakeQC(WithQCRank(rank - 1)),
	}
	for _, option := range options {
		option(&state)
	}
	return &state
}

func WithStateRank[StateT models.Unique](rank uint64) func(*models.State[StateT]) {
	return func(state *models.State[StateT]) {
		state.Rank = rank
	}
}

func WithStateProposer[StateT models.Unique](proposerID models.Identity) func(*models.State[StateT]) {
	return func(state *models.State[StateT]) {
		state.ProposerID = proposerID
	}
}

func WithParentState[StateT models.Unique](parent *models.State[StateT]) func(*models.State[StateT]) {
	return func(state *models.State[StateT]) {
		state.ParentQuorumCertificate.(*TestQuorumCertificate).Selector = parent.Identifier
		state.ParentQuorumCertificate.(*TestQuorumCertificate).Rank = parent.Rank
	}
}

func WithParentSigners[StateT models.Unique](signerIndices []byte) func(*models.State[StateT]) {
	return func(state *models.State[StateT]) {
		state.ParentQuorumCertificate.(*TestQuorumCertificate).AggregatedSignature.(*TestAggregatedSignature).Bitmask = signerIndices
	}
}

func WithStateQC[StateT models.Unique](qc models.QuorumCertificate) func(*models.State[StateT]) {
	return func(state *models.State[StateT]) {
		state.ParentQuorumCertificate = qc
	}
}

func MakeVote[VoteT models.Unique]() *VoteT {
	return new(VoteT)
}

func MakeSignedProposal[StateT models.Unique, VoteT models.Unique](options ...func(*models.SignedProposal[StateT, VoteT])) *models.SignedProposal[StateT, VoteT] {
	proposal := &models.SignedProposal[StateT, VoteT]{
		Proposal: *MakeProposal[StateT](),
		Vote:     MakeVote[VoteT](),
	}
	for _, option := range options {
		option(proposal)
	}
	return proposal
}

func MakeProposal[StateT models.Unique](options ...func(*models.Proposal[StateT])) *models.Proposal[StateT] {
	proposal := &models.Proposal[StateT]{
		State:                          MakeState[StateT](),
		PreviousRankTimeoutCertificate: nil,
	}
	for _, option := range options {
		option(proposal)
	}
	return proposal
}

func WithProposal[StateT models.Unique, VoteT models.Unique](proposal *models.Proposal[StateT]) func(*models.SignedProposal[StateT, VoteT]) {
	return func(signedProposal *models.SignedProposal[StateT, VoteT]) {
		signedProposal.Proposal = *proposal
	}
}

func WithState[StateT models.Unique](state *models.State[StateT]) func(*models.Proposal[StateT]) {
	return func(proposal *models.Proposal[StateT]) {
		proposal.State = state
	}
}

func WithVote[StateT models.Unique, VoteT models.Unique](vote *VoteT) func(*models.SignedProposal[StateT, VoteT]) {
	return func(proposal *models.SignedProposal[StateT, VoteT]) {
		proposal.Vote = vote
	}
}

func WithPreviousRankTimeoutCertificate[StateT models.Unique](previousRankTimeoutCert models.TimeoutCertificate) func(*models.Proposal[StateT]) {
	return func(proposal *models.Proposal[StateT]) {
		proposal.PreviousRankTimeoutCertificate = previousRankTimeoutCert
	}
}
