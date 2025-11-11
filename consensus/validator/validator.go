package validator

import (
	"errors"
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// Validator is responsible for validating QC, State and Vote
type Validator[StateT models.Unique, VoteT models.Unique] struct {
	committee consensus.Replicas
	verifier  consensus.Verifier[VoteT]
}

var _ consensus.Validator[*nilUnique, *nilUnique] = (*Validator[*nilUnique, *nilUnique])(nil)

// New creates a new Validator instance
func NewValidator[StateT models.Unique, VoteT models.Unique](
	committee consensus.Replicas,
	verifier consensus.Verifier[VoteT],
) *Validator[StateT, VoteT] {
	return &Validator[StateT, VoteT]{
		committee: committee,
		verifier:  verifier,
	}
}

// ValidateTimeoutCertificate validates the TimeoutCertificate `TC`.
// During normal operations, the following error returns are expected:
//   - models.InvalidTCError if the TC is invalid
//   - models.ErrRankUnknown if the TC refers unknown rank
//
// Any other error should be treated as exception
func (v *Validator[StateT, VoteT]) ValidateTimeoutCertificate(
	tc models.TimeoutCertificate,
) error {
	newestQC := tc.GetLatestQuorumCert()
	if newestQC == nil {
		return newInvalidTimeoutCertificateError(
			tc,
			fmt.Errorf("TC must include a QC but found nil"),
		)
	}

	// The TC's rank cannot be smaller than the rank of the QC it contains.
	// Note: we specifically allow for the TC to have the same rank as the highest
	// QC. This is useful as a fallback, because it allows replicas other than the
	// designated leader to also collect votes and generate a QC.
	if tc.GetRank() < newestQC.GetRank() {
		return newInvalidTimeoutCertificateError(
			tc,
			fmt.Errorf("TC's QC cannot be newer than the TC's rank"),
		)
	}

	// 1. Check if there is super-majority of votes
	allParticipants, err := v.committee.IdentitiesByRank(tc.GetRank())
	if err != nil {
		return fmt.Errorf(
			"could not get consensus participants at rank %d: %w",
			tc.GetRank(),
			err,
		)
	}

	signerIDs := []models.WeightedIdentity{}
	sigIndices := tc.GetAggregatedSignature().GetBitmask()
	totalWeight := uint64(0)
	if len(sigIndices) < (len(allParticipants)+7)/8 {
		return models.NewInsufficientSignaturesErrorf("insufficient signatures")
	}
	for i, member := range allParticipants {
		if sigIndices[i/8]&(1<<(i%8)) == (1 << (i % 8)) {
			signerIDs = append(signerIDs, member)
			totalWeight += member.Weight()
		}
	}

	// determine whether signers reach minimally required weight threshold for
	// consensus
	threshold, err := v.committee.QuorumThresholdForRank(tc.GetRank())
	if err != nil {
		return newInvalidTimeoutCertificateError(
			tc,
			fmt.Errorf(
				"could not get weight threshold for rank %d: %w",
				tc.GetRank(),
				err,
			),
		)
	}

	if totalWeight < threshold {
		return newInvalidTimeoutCertificateError(tc, fmt.Errorf(
			"tc signers have insufficient weight of %d (required=%d)",
			totalWeight,
			threshold,
		))
	}

	// Verify multi-message BLS sig of TC, by far the most expensive check
	err = v.verifier.VerifyTimeoutCertificate(tc)
	if err != nil {
		// Considerations about other errors that `VerifyTC` could return:
		// * models.InsufficientSignaturesError: we previously checked the total
		//   weight of all signers meets the supermajority threshold, which is a
		//   _positive_ number. Hence, there must be at least one signer. Hence,
		//   receiving this error would be a symptom of a fatal internal bug.
		switch {
		case models.IsInvalidFormatError(err):
			return newInvalidTimeoutCertificateError(
				tc,
				fmt.Errorf("TC's signature data has an invalid structure: %w", err),
			)
		case errors.Is(err, models.ErrInvalidSignature):
			return newInvalidTimeoutCertificateError(
				tc,
				fmt.Errorf("TC contains invalid signature(s): %w", err),
			)
		default:
			return fmt.Errorf(
				"cannot verify tc's aggregated signature (tc.Rank: %d): %w",
				tc.GetRank(),
				err,
			)
		}
	}

	// verifying that tc.NewestQC is the QC with the highest rank.
	// Note: A byzantine TC could include `nil` for tc.NewestQCRanks, in which
	// case `tc.NewestQCRanks[0]` would panic. Though, per API specification
	// `verifier.VerifyTC(…)` should return a `models.InvalidFormatError` if
	// `signers` and `tc.NewestQCRanks` have different length. Hence, the
	// following code is safe only if it is executed
	//  1. _after_ checking the quorum threshold (thereby we guarantee that
	//     `signers` is not empty); and
	//  2. _after_ `verifier.VerifyTC(…)`, which enforces that `signers` and
	//     `tc.NewestQCRanks` have identical length.
	// Only then we can be sure that `tc.NewestQCRanks` cannot be nil.
	newestQCRank := tc.GetLatestRanks()[0]
	for _, rank := range tc.GetLatestRanks() {
		if newestQCRank < rank {
			newestQCRank = rank
		}
	}
	if newestQCRank > tc.GetLatestQuorumCert().GetRank() {
		return newInvalidTimeoutCertificateError(
			tc,
			fmt.Errorf(
				"included QC (rank=%d) should be equal or higher to highest contributed rank: %d",
				tc.GetLatestQuorumCert().GetRank(),
				newestQCRank,
			),
		)
	}

	// Validate QC
	err = v.ValidateQuorumCertificate(newestQC)
	if err != nil {
		if models.IsInvalidQuorumCertificateError(err) {
			return newInvalidTimeoutCertificateError(tc, fmt.Errorf(
				"invalid QC included in TC: %w",
				err,
			))
		}
		if errors.Is(err, models.ErrRankUnknown) {
			// We require each replica to be bootstrapped with a QC pointing to a
			// finalized state. Consensus safety rules guarantee that a QC at least as
			// new as the root QC must be contained in any TC. This is because the TC
			// must include signatures from a supermajority of replicas, including at
			// least one honest replica, which attest to their locally highest known
			// QC. Hence, any QC included in a TC must be the root QC or newer.
			// Therefore, we should know the rank for any QC we encounter. Receiving
			// a `models.ErrRankUnknown` is conceptually impossible, i.e. a symptom of
			// an internal bug or invalid bootstrapping information.
			return fmt.Errorf(
				"no rank information availalbe for QC that was included in TC; symptom of internal bug or invalid bootstrapping information: %s",
				err.Error(),
			)
		}
		return fmt.Errorf(
			"unexpected internal error while verifying the QC included in the TC: %w",
			err,
		)
	}

	return nil
}

// ValidateQuorumCertificate validates the Quorum Certificate `qc`.
// During normal operations, the following error returns are expected:
//   - models.InvalidQCError if the QC is invalid
//   - models.ErrRankUnknown if the QC refers unknown rank
//
// Any other error should be treated as exception
func (v *Validator[StateT, VoteT]) ValidateQuorumCertificate(
	qc models.QuorumCertificate,
) error {
	// Retrieve the initial identities of consensus participants for this rank,
	// and those that signed the QC. IdentitiesByRank contains all nodes that were
	// authorized to sign during this rank. Ejection and dynamic weight
	// adjustments are not taken into account here. By using an rank-static set
	// of authorized signers, we can check QC validity without needing all
	// ancestor states.
	allParticipants, err := v.committee.IdentitiesByRank(qc.GetRank())
	if err != nil {
		return fmt.Errorf(
			"could not get consensus participants at rank %d: %w",
			qc.GetRank(),
			err,
		)
	}

	signerIDs := []models.WeightedIdentity{}
	sigIndices := qc.GetAggregatedSignature().GetBitmask()
	totalWeight := uint64(0)
	if len(sigIndices) < (len(allParticipants)+7)/8 {
		return newInvalidQuorumCertificateError(
			qc,
			models.NewInsufficientSignaturesErrorf("insufficient signatures"),
		)
	}
	for i, member := range allParticipants {
		if sigIndices[i/8]&(1<<(i%8)) == (1 << (i % 8)) {
			signerIDs = append(signerIDs, member)
			totalWeight += member.Weight()
		}
	}

	// determine whether signers reach minimally required weight threshold for
	// consensus
	threshold, err := v.committee.QuorumThresholdForRank(qc.GetRank())
	if err != nil {
		return newInvalidQuorumCertificateError(
			qc,
			fmt.Errorf(
				"could not get weight threshold for rank %d: %w",
				qc.GetRank(),
				err,
			),
		)
	}

	if totalWeight < threshold {
		return newInvalidQuorumCertificateError(
			qc,
			fmt.Errorf(
				"QC signers have insufficient weight of %d (required=%d)",
				totalWeight,
				threshold,
			),
		)
	}

	// verify whether the signature bytes are valid for the QC
	err = v.verifier.VerifyQuorumCertificate(qc)
	if err != nil {
		// Considerations about other errors that `VerifyQC` could return:
		// * models.InvalidSignerError
		// * models.InsufficientSignaturesError: we previously checked the total
		//   weight of all signers meets the supermajority threshold, which is a
		//   _positive_ number. Hence, there must be at least one signer. Hence,
		//   receiving this error would be a symptom of a fatal internal bug.
		switch {
		case models.IsInvalidFormatError(err):
			return newInvalidQuorumCertificateError(
				qc,
				fmt.Errorf("QC's signature data has an invalid structure: %w", err),
			)
		case errors.Is(err, models.ErrInvalidSignature):
			return newInvalidQuorumCertificateError(
				qc,
				fmt.Errorf("QC contains invalid signature(s): %w", err),
			)
		case errors.Is(err, models.ErrRankUnknown):
			// We have earlier queried the Identities for the QC's rank, which must
			// have returned proper values, otherwise, we wouldn't reach this code.
			// Therefore, it should be impossible for `verifier.VerifyQC` to return
			// ErrRankUnknown. To avoid confusion with expected sentinel errors, we
			// only preserve the error messages here, but not the error types.
			return fmt.Errorf(
				"internal error, as querying identities for rank %d succeeded earlier but now the rank supposedly belongs to an unknown rank: %s",
				qc.GetRank(),
				err.Error(),
			)
		default:
			return fmt.Errorf(
				"cannot verify qc's aggregated signature (qc.Identifier: %x): %w",
				qc.Identity(),
				err,
			)
		}
	}

	return nil
}

// ValidateProposal validates the state proposal
// A state is considered as valid if it's a valid extension of existing forks.
// Note it doesn't check if it's conflicting with finalized state
// During normal operations, the following error returns are expected:
//   - models.InvalidProposalError if the state is invalid
//   - models.ErrRankUnknown if the proposal refers unknown rank
//
// Any other error should be treated as exception
func (v *Validator[StateT, VoteT]) ValidateProposal(
	proposal *models.SignedProposal[StateT, VoteT],
) error {
	qc := proposal.State.ParentQuorumCertificate
	state := proposal.State

	// validate the proposer's vote and get their identity
	vote, err := proposal.ProposerVote()
	if err != nil {
		return fmt.Errorf("could not get vote from proposer vote: %w", err)
	}
	_, err = v.ValidateVote(vote)
	if models.IsInvalidVoteError[VoteT](err) {
		return models.NewInvalidProposalErrorf(
			proposal,
			"invalid proposer signature: %w",
			err,
		)
	}
	if err != nil {
		return fmt.Errorf(
			"error verifying leader signature for state %x: %w",
			state.Identifier,
			err,
		)
	}

	// check the proposer is the leader for the proposed state's rank
	leader, err := v.committee.LeaderForRank(state.Rank)
	if err != nil {
		return fmt.Errorf(
			"error determining leader for state %x: %w",
			state.Identifier,
			err,
		)
	}
	if leader != state.ProposerID {
		return models.NewInvalidProposalErrorf(
			proposal,
			"proposer %s is not leader (%s) for rank %d",
			state.ProposerID,
			leader,
			state.Rank,
		)
	}

	// The State must contain a proof that the primary legitimately entered the
	// respective rank. Transitioning to proposal.State.Rank is possible either by
	// observing a QC or a TC for the previous round. If and only if the QC is
	// _not_ for the previous round we require a TC for the previous rank to be
	// present.
	lastRankSuccessful := proposal.State.Rank ==
		proposal.State.ParentQuorumCertificate.GetRank()+1
	if !lastRankSuccessful {
		// check if proposal is correctly structured
		if proposal.PreviousRankTimeoutCertificate == nil {
			return models.NewInvalidProposalErrorf(
				proposal,
				"QC in state is not for previous rank, so expecting a TC but none is included in state",
			)
		}

		// check if included TC is for previous rank
		if proposal.State.Rank !=
			proposal.PreviousRankTimeoutCertificate.GetRank()+1 {
			return models.NewInvalidProposalErrorf(
				proposal,
				"QC in state is not for previous rank, so expecting a TC for rank %d but got TC for rank %d",
				proposal.State.Rank-1,
				proposal.PreviousRankTimeoutCertificate.GetRank(),
			)
		}

		// Check if proposal extends either the newest QC specified in the TC, or a
		// newer QC in edge cases a leader may construct a TC and QC concurrently
		// such that TC contains an older QC - in these case we still want to build
		// on the newest QC, so this case is allowed.
		if proposal.State.ParentQuorumCertificate.GetRank() <
			proposal.PreviousRankTimeoutCertificate.GetLatestQuorumCert().GetRank() {
			return models.NewInvalidProposalErrorf(
				proposal,
				"TC in state contains a newer QC than the state itself, which is a protocol violation",
			)
		}
	} else if proposal.PreviousRankTimeoutCertificate != nil {
		// last rank ended with QC, including TC is a protocol violation
		return models.NewInvalidProposalErrorf(
			proposal,
			"last rank has ended with QC but proposal includes PreviousRankTimeoutCertificate",
		)
	}

	// Check signatures, keep the most expensive the last to check

	// check if included QC is valid
	err = v.ValidateQuorumCertificate(qc)
	if err != nil {
		if models.IsInvalidQuorumCertificateError(err) {
			return models.NewInvalidProposalErrorf(proposal, "invalid qc included: %w", err)
		}
		if errors.Is(err, models.ErrRankUnknown) {
			// We require each replica to be bootstrapped with a QC pointing to a
			// finalized state. Therefore, receiving a `models.ErrRankUnknown` is
			// conceptually impossible, i.e. a symptom of an internal bug or invalid
			// bootstrapping information.
			return fmt.Errorf(
				"no rank information availalbe for QC that was included in proposal; symptom of internal bug or invalid bootstrapping information: %s",
				err.Error(),
			)
		}
		return fmt.Errorf("unexpected error verifying qc: %w", err)
	}

	if !lastRankSuccessful {
		// check if included TC is valid
		err = v.ValidateTimeoutCertificate(proposal.PreviousRankTimeoutCertificate)
		if err != nil {
			if models.IsInvalidTimeoutCertificateError(err) {
				return models.NewInvalidProposalErrorf(
					proposal,
					"proposals TC's is not valid: %w",
					err,
				)
			}
			if errors.Is(err, models.ErrRankUnknown) {
				// We require each replica to be bootstrapped with a QC pointing to a
				// finalized state. Therefore, we should know the rank for any QC.Rank
				// and TC.Rank we encounter. Receiving a `models.ErrRankUnknown` is
				// conceptually impossible, i.e. a symptom of an internal bug or invalid
				// bootstrapping information.
				return fmt.Errorf(
					"no rank information availalbe for QC that was included in TC; symptom of internal bug or invalid bootstrapping information: %s",
					err.Error(),
				)
			}
			return fmt.Errorf(
				"unexpected internal error while verifying the TC included in state: %w",
				err,
			)
		}
	}

	return nil
}

// ValidateVote validates the vote and returns the identity of the voter who
// signed the vote - the vote to be validated
// During normal operations, the following error returns are expected:
//   - models.InvalidVoteError for invalid votes
//   - models.ErrRankUnknown if the vote refers unknown rank
//
// Any other error should be treated as exception
func (v *Validator[StateT, VoteT]) ValidateVote(vote *VoteT) (
	*models.WeightedIdentity,
	error,
) {
	voter, err := v.committee.IdentityByRank(
		(*vote).GetRank(),
		(*vote).Identity(),
	)
	if models.IsInvalidSignerError(err) {
		return nil, newInvalidVoteError(vote, err)
	}
	if err != nil {
		return nil, fmt.Errorf(
			"error retrieving voter Identity at rank %d: %w",
			(*vote).GetRank(),
			err,
		)
	}

	// check whether the signature data is valid for the vote in the hotstuff
	// context
	err = v.verifier.VerifyVote(vote)
	if err != nil {
		// Theoretically, `VerifyVote` could also return a
		// `models.InvalidSignerError`.
		if models.IsInvalidFormatError(err) ||
			errors.Is(err, models.ErrInvalidSignature) {
			return nil, newInvalidVoteError(vote, err)
		}
		if errors.Is(err, models.ErrRankUnknown) {
			return nil, fmt.Errorf(
				"no rank information available for vote; symptom of internal bug or invalid bootstrapping information: %s",
				err.Error(),
			)
		}
		return nil, fmt.Errorf(
			"cannot verify signature for vote (%x): %w",
			(*vote).Identity(),
			err,
		)
	}

	return &voter, nil
}

func newInvalidQuorumCertificateError(
	qc models.QuorumCertificate,
	err error,
) error {
	return models.InvalidQuorumCertificateError{
		Identifier: qc.Identity(),
		Rank:       qc.GetRank(),
		Err:        err,
	}
}

func newInvalidTimeoutCertificateError(
	tc models.TimeoutCertificate,
	err error,
) error {
	return models.InvalidTimeoutCertificateError{
		Rank: tc.GetRank(),
		Err:  err,
	}
}

func newInvalidVoteError[VoteT models.Unique](vote *VoteT, err error) error {
	return models.InvalidVoteError[VoteT]{
		Vote: vote,
		Err:  err,
	}
}

// Type used to satisfy generic arguments in compiler time type assertion check
type nilUnique struct{}

// GetSignature implements models.Unique.
func (n *nilUnique) GetSignature() []byte {
	panic("unimplemented")
}

// GetTimestamp implements models.Unique.
func (n *nilUnique) GetTimestamp() uint64 {
	panic("unimplemented")
}

// Source implements models.Unique.
func (n *nilUnique) Source() models.Identity {
	panic("unimplemented")
}

// Clone implements models.Unique.
func (n *nilUnique) Clone() models.Unique {
	panic("unimplemented")
}

// GetRank implements models.Unique.
func (n *nilUnique) GetRank() uint64 {
	panic("unimplemented")
}

// Identity implements models.Unique.
func (n *nilUnique) Identity() models.Identity {
	panic("unimplemented")
}

var _ models.Unique = (*nilUnique)(nil)
