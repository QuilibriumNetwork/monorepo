package models

import (
	"errors"
)

type Proposal[StateT Unique] struct {
	State                          *State[StateT]
	PreviousRankTimeoutCertificate TimeoutCertificate
}

func ProposalFrom[StateT Unique](
	state *State[StateT],
	prevTC TimeoutCertificate,
) *Proposal[StateT] {
	return &Proposal[StateT]{
		State:                          state,
		PreviousRankTimeoutCertificate: prevTC,
	}
}

type SignedProposal[StateT Unique, VoteT Unique] struct {
	Proposal[StateT]
	Vote *VoteT
}

func (p *SignedProposal[StateT, VoteT]) ProposerVote() (*VoteT, error) {
	if p.Vote == nil {
		return nil, errors.New("missing vote")
	}
	return p.Vote, nil
}

func SignedProposalFromState[StateT Unique, VoteT Unique](
	p *Proposal[StateT],
	v *VoteT,
) *SignedProposal[StateT, VoteT] {
	return &SignedProposal[StateT, VoteT]{
		Proposal: Proposal[StateT]{
			State:                          p.State,
			PreviousRankTimeoutCertificate: p.PreviousRankTimeoutCertificate,
		},
		Vote: v,
	}
}
