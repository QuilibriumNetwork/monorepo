package votecollector

import (
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	mockconsensus "source.quilibrium.com/quilibrium/monorepo/consensus/mocks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

type VoteProcessorTestSuiteBase struct {
	suite.Suite

	sigWeight          uint64
	provingTotalWeight uint64
	onQCCreatedState   mock.Mock

	provingAggregator *mockconsensus.WeightedSignatureAggregator
	minRequiredWeight uint64
	proposal          *models.SignedProposal[*helper.TestState, *helper.TestVote]
}

func (s *VoteProcessorTestSuiteBase) SetupTest() {
	s.provingAggregator = &mockconsensus.WeightedSignatureAggregator{}
	s.proposal = helper.MakeSignedProposal[*helper.TestState, *helper.TestVote]()

	// let's assume we have 19 nodes each with weight 100
	s.sigWeight = 100
	s.minRequiredWeight = 1300 // we require at least 13 sigs to collect min weight
	s.provingTotalWeight = 0

	// setup proving signature aggregator
	s.provingAggregator.On("TrustedAdd", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		s.provingTotalWeight += s.sigWeight
	}).Return(func(signerID models.Identity, sig []byte) uint64 {
		return s.provingTotalWeight
	}, func(signerID models.Identity, sig []byte) error {
		return nil
	}).Maybe()
	s.provingAggregator.On("TotalWeight").Return(func() uint64 {
		return s.provingTotalWeight
	}).Maybe()
}

// onQCCreated is a special function that registers call in mocked state.
// ATTENTION: don't change name of this function since the same name is used in:
// s.onQCCreatedState.On("onQCCreated") statements
func (s *VoteProcessorTestSuiteBase) onQCCreated(qc models.QuorumCertificate) {
	s.onQCCreatedState.Called(qc)
}
