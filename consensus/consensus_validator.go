package consensus

import (
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// Validator provides functions to validate QuorumCertificate, proposals and
// votes.
type Validator[StateT models.Unique, VoteT models.Unique] interface {

	// ValidateQuorumCertificate checks the validity of a QuorumCertificate.
	// During normal operations, the following error returns are expected:
	//  * models.InvalidQuorumCertificateError if the QuorumCertificate is invalid
	ValidateQuorumCertificate(qc models.QuorumCertificate) error

	// ValidateTimeoutCertificate checks the validity of a TimeoutCertificate.
	// During normal operations, the following error returns are expected:
	//  * models.InvalidTimeoutCertificateError if the TimeoutCertificate is
	//    invalid
	ValidateTimeoutCertificate(tc models.TimeoutCertificate) error

	// ValidateProposal checks the validity of a proposal.
	// During normal operations, the following error returns are expected:
	//  * models.InvalidProposalError if the state is invalid
	ValidateProposal(proposal *models.SignedProposal[StateT, VoteT]) error

	// ValidateVote checks the validity of a vote.
	// Returns the full entity for the voter. During normal operations,
	// the following errors are expected:
	//  * models.InvalidVoteError for invalid votes
	ValidateVote(vote *VoteT) (*models.WeightedIdentity, error)
}
