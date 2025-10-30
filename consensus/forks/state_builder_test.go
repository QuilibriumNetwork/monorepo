package forks

import (
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// StateRank specifies the data to create a state
type StateRank struct {
	// Rank is the rank of the state to be created
	Rank uint64
	// StateVersion is the version of the state for that rank.
	// Useful for creating conflicting states at the same rank.
	StateVersion int
	// QCRank is the rank of the QC embedded in this state (also: the rank of the state's parent)
	QCRank uint64
	// QCVersion is the version of the QC for that rank.
	QCVersion int
}

// QCIndex returns a unique identifier for the state's QC.
func (bv *StateRank) QCIndex() string {
	return fmt.Sprintf("%v-%v", bv.QCRank, bv.QCVersion)
}

// StateIndex returns a unique identifier for the state.
func (bv *StateRank) StateIndex() string {
	return fmt.Sprintf("%v-%v", bv.Rank, bv.StateVersion)
}

// StateBuilder is a test utility for creating state structure fixtures.
type StateBuilder struct {
	stateRanks []*StateRank
}

func NewStateBuilder() *StateBuilder {
	return &StateBuilder{
		stateRanks: make([]*StateRank, 0),
	}
}

// Add adds a state with the given qcRank and stateRank. Returns self-reference for chaining.
func (bb *StateBuilder) Add(qcRank uint64, stateRank uint64) *StateBuilder {
	bb.stateRanks = append(bb.stateRanks, &StateRank{
		Rank:   stateRank,
		QCRank: qcRank,
	})
	return bb
}

// GenesisState returns the genesis state, which is always finalized.
func (bb *StateBuilder) GenesisState() *models.CertifiedState[*helper.TestState] {
	return makeGenesis()
}

// AddVersioned adds a state with the given qcRank and stateRank.
// In addition, the version identifier of the QC embedded within the state
// is specified by `qcVersion`. The version identifier for the state itself
// (primarily for emulating different state ID) is specified by `stateVersion`.
// [(◄3) 4] denotes a state of rank 4, with a qc for rank 3
// [(◄3) 4'] denotes a state of rank 4 that is different than [(◄3) 4], with a qc for rank 3
// [(◄3) 4'] can be created by AddVersioned(3, 4, 0, 1)
// [(◄3') 4] can be created by AddVersioned(3, 4, 1, 0)
// Returns self-reference for chaining.
func (bb *StateBuilder) AddVersioned(qcRank uint64, stateRank uint64, qcVersion int, stateVersion int) *StateBuilder {
	bb.stateRanks = append(bb.stateRanks, &StateRank{
		Rank:         stateRank,
		QCRank:       qcRank,
		StateVersion: stateVersion,
		QCVersion:    qcVersion,
	})
	return bb
}

// Proposals returns a list of all proposals added to the StateBuilder.
// Returns an error if the states do not form a connected tree rooted at genesis.
func (bb *StateBuilder) Proposals() ([]*models.Proposal[*helper.TestState], error) {
	states := make([]*models.Proposal[*helper.TestState], 0, len(bb.stateRanks))

	genesisState := makeGenesis()
	genesisBV := &StateRank{
		Rank:   genesisState.State.Rank,
		QCRank: genesisState.CertifyingQuorumCertificate.GetRank(),
	}

	qcs := make(map[string]models.QuorumCertificate)
	qcs[genesisBV.QCIndex()] = genesisState.CertifyingQuorumCertificate

	for _, bv := range bb.stateRanks {
		qc, ok := qcs[bv.QCIndex()]
		if !ok {
			return nil, fmt.Errorf("test fail: no qc found for qc index: %v", bv.QCIndex())
		}
		var previousRankTimeoutCert models.TimeoutCertificate
		if qc.GetRank()+1 != bv.Rank {
			previousRankTimeoutCert = helper.MakeTC(helper.WithTCRank(bv.Rank - 1))
		}
		proposal := &models.Proposal[*helper.TestState]{
			State: &models.State[*helper.TestState]{
				Rank:                    bv.Rank,
				ParentQuorumCertificate: qc,
			},
			PreviousRankTimeoutCertificate: previousRankTimeoutCert,
		}
		proposal.State.Identifier = makeIdentifier(proposal.State, bv.StateVersion)

		states = append(states, proposal)

		// generate QC for the new proposal
		qcs[bv.StateIndex()] = &helper.TestQuorumCertificate{
			Rank:                proposal.State.Rank,
			Selector:            proposal.State.Identifier,
			AggregatedSignature: nil,
		}
	}

	return states, nil
}

// States returns a list of all states added to the StateBuilder.
// Returns an error if the states do not form a connected tree rooted at genesis.
func (bb *StateBuilder) States() ([]*models.State[*helper.TestState], error) {
	proposals, err := bb.Proposals()
	if err != nil {
		return nil, fmt.Errorf("StateBuilder failed to generate proposals: %w", err)
	}
	return toStates(proposals), nil
}

// makeIdentifier creates a state identifier based on the state's rank, QC, and state version.
// This is used to identify states uniquely, in this specific test setup.
// ATTENTION: this should not be confused with the state ID used in production code which is a collision-resistant hash
// of the full state content.
func makeIdentifier(state *models.State[*helper.TestState], stateVersion int) models.Identity {
	return fmt.Sprintf("%d-%s-%d", state.Rank, state.Identifier, stateVersion)
}

// constructs the genesis state (identical for all calls)
func makeGenesis() *models.CertifiedState[*helper.TestState] {
	genesis := &models.State[*helper.TestState]{
		Rank: 1,
	}
	genesis.Identifier = makeIdentifier(genesis, 0)

	genesisQC := &helper.TestQuorumCertificate{
		Rank:     1,
		Selector: genesis.Identifier,
	}
	certifiedGenesisState, err := models.NewCertifiedState(genesis, genesisQC)
	if err != nil {
		panic(fmt.Sprintf("combining genesis state and genensis QC to certified state failed: %s", err.Error()))
	}
	return certifiedGenesisState
}

// toStates converts the given proposals to slice of states
func toStates(proposals []*models.Proposal[*helper.TestState]) []*models.State[*helper.TestState] {
	states := make([]*models.State[*helper.TestState], 0, len(proposals))
	for _, b := range proposals {
		states = append(states, b.State)
	}
	return states
}
