package models

import (
	"fmt"
)

// State is the HotStuff algorithm's concept of a state, which - in the bigger
// picture - corresponds to the state header.
type State[StateT Unique] struct {
	Rank                    uint64
	Identifier              Identity
	ProposerID              Identity
	ParentQuorumCertificate QuorumCertificate
	Timestamp               uint64 // Unix milliseconds
	State                   *StateT
}

// StateFrom combines external state with source parent quorum certificate.
func StateFrom[StateT Unique](
	t *StateT,
	parentCert QuorumCertificate,
) *State[StateT] {
	state := State[StateT]{
		Identifier:              (*t).Identity(),
		Rank:                    (*t).GetRank(),
		ParentQuorumCertificate: parentCert,
		ProposerID:              (*t).Source(),
		Timestamp:               (*t).GetTimestamp(),
		State:                   t,
	}

	return &state
}

// GenesisStateFrom returns a generic consensus model of genesis state.
func GenesisStateFrom[StateT Unique](internal *StateT) *State[StateT] {
	genesis := &State[StateT]{
		Identifier:              (*internal).Identity(),
		Rank:                    (*internal).GetRank(),
		ProposerID:              (*internal).Source(),
		ParentQuorumCertificate: nil,
		Timestamp:               (*internal).GetTimestamp(),
		State:                   internal,
	}
	return genesis
}

// CertifiedState holds a certified state, which is a state and a
// QuorumCertificate that is pointing to the state. A QuorumCertificate is the
// aggregated form of votes from a supermajority of HotStuff and
// therefore proves validity of the state. A certified state satisfies:
// State.Rank == QuorumCertificate.Rank and
// State.Identifier == QuorumCertificate.Identifier
type CertifiedState[StateT Unique] struct {
	State                       *State[StateT]
	CertifyingQuorumCertificate QuorumCertificate
}

// NewCertifiedState constructs a new certified state. It checks the consistency
// requirements and returns an exception otherwise:
//
// State.Rank == QuorumCertificate.Rank and State.Identifier ==
//
//	QuorumCertificate.Identifier
func NewCertifiedState[StateT Unique](
	state *State[StateT],
	quorumCertificate QuorumCertificate,
) (*CertifiedState[StateT], error) {
	if state.Rank != quorumCertificate.GetRank() {
		return &CertifiedState[StateT]{},
			fmt.Errorf(
				"state's rank (%d) should equal the qc's rank (%d)",
				state.Rank,
				quorumCertificate.GetRank(),
			)
	}
	if state.Identifier != quorumCertificate.Identity() {
		return &CertifiedState[StateT]{},
			fmt.Errorf(
				"state's ID (%x) should equal the state referenced by the qc (%x)",
				state.Identifier,
				quorumCertificate.Identity(),
			)
	}
	return &CertifiedState[StateT]{
		State:                       state,
		CertifyingQuorumCertificate: quorumCertificate,
	}, nil
}

// Identifier returns a unique identifier for the state (the ID signed to
// produce a state vote). To avoid repeated computation, we use value from the
// QuorumCertificate.
func (b *CertifiedState[StateT]) Identifier() Identity {
	return b.CertifyingQuorumCertificate.Identity()
}

// Rank returns rank where the state was proposed.
func (b *CertifiedState[StateT]) Rank() uint64 {
	return b.State.Rank
}
