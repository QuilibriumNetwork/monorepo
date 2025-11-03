package integration

import (
	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

func FinalizedStates(in *Instance) []*models.State[*helper.TestState] {
	finalized := make([]*models.State[*helper.TestState], 0)

	lastFinalID := in.forks.FinalizedState().Identifier
	in.updatingStates.RLock()
	finalizedState, found := in.headers[lastFinalID]
	defer in.updatingStates.RUnlock()
	if !found {
		return finalized
	}

	for {
		finalized = append(finalized, finalizedState)
		if finalizedState.ParentQuorumCertificate == nil {
			break
		}
		finalizedState, found =
			in.headers[finalizedState.ParentQuorumCertificate.Identity()]
		if !found {
			break
		}
	}
	return finalized
}

func FinalizedRanks(in *Instance) []uint64 {
	finalizedStates := FinalizedStates(in)
	ranks := make([]uint64, 0, len(finalizedStates))
	for _, b := range finalizedStates {
		ranks = append(ranks, b.Rank)
	}
	return ranks
}
