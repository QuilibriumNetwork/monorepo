package consensus

import "math/big"

type ProverAllocation struct {
	Ring      uint8
	Shards    uint64
	StateSize uint64
}

// RewardIssuance describes a reward issuer algorithm.
type RewardIssuance interface {
	// Calculate calculates the reward issuance for the total set of provers,
	// returns in matching order to prover list.
	Calculate(
		difficulty uint64,
		worldStateBytes uint64,
		units uint64,
		provers []map[string]*ProverAllocation,
	) ([]*big.Int, error)
}
