package mocks

import (
	"math/big"

	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
)

type MockRewardIssuance struct {
	mock.Mock
}

func (m *MockRewardIssuance) Calculate(
	difficulty uint64,
	worldStateBytes uint64,
	units uint64,
	provers []map[string]*consensus.ProverAllocation,
) ([]*big.Int, error) {
	args := m.Called(difficulty, worldStateBytes, units, provers)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*big.Int), args.Error(1)
}
