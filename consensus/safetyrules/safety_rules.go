package safetyrules

import (
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// SafetyRules is a dedicated module that enforces consensus safety. This
// component has the sole authority to generate votes and timeouts. It follows
// voting and timeout rules for creating votes and timeouts respectively.
// Caller can be sure that created vote or timeout doesn't break safety and can
// be used in consensus process. SafetyRules relies on consensus.ConsensusStore
// to store latest state of consensus.SafetyData.
//
// The voting rules implemented by SafetyRules are:
//  1. Replicas vote in strictly increasing ranks. At most one vote can be
//     signed per rank. Caution: The leader's state signature is formally a vote
//     for their own proposal.
//  2. Each state has to include a TC or a QC from the previous rank.
//     a. [Happy path] If the previous rank resulted in a QC then the proposer
//     should include it in their state.
//     b. [Recovery path] If the previous round did *not* result in a QC, the
//     leader of the subsequent round *must* include a valid TC for the
//     previous rank in its state.
//
// Condition 1 guarantees a foundational security theorem for HotStuff (incl.
// the DiemBFT / Jolteon variant):
//
//	THEOREM: For each rank, there can be at most 1 certified state.
//
// NOT safe for concurrent use.
type SafetyRules[StateT models.Unique, VoteT models.Unique] struct {
	signer         consensus.Signer[StateT, VoteT]
	store          consensus.ConsensusStore[VoteT]
	committee      consensus.DynamicCommittee // only produce votes when we are valid committee members
	consensusState *models.ConsensusState[VoteT]
}

var _ consensus.SafetyRules[*nilUnique, *nilUnique] = (*SafetyRules[*nilUnique, *nilUnique])(nil)

// NewSafetyRules creates a new SafetyRules instance
func NewSafetyRules[StateT models.Unique, VoteT models.Unique](
	filter []byte,
	signer consensus.Signer[StateT, VoteT],
	store consensus.ConsensusStore[VoteT],
	committee consensus.DynamicCommittee,
) (*SafetyRules[StateT, VoteT], error) {
	// get the last stored safety data
	consensusState, err := store.GetConsensusState(filter)
	if err != nil {
		return nil, fmt.Errorf("could not load safety data: %w", err)
	}
	return &SafetyRules[StateT, VoteT]{
		signer:         signer,
		store:          store,
		committee:      committee,
		consensusState: consensusState,
	}, nil
}

// ProduceVote will make a decision on whether it will vote for the given
// proposal, the returned error indicates whether to vote or not.  To ensure
// that only safe proposals are being voted on, we check that the proposer is a
// valid committee member and that the proposal complies with voting rules.
// We expect that only well-formed proposals with valid signatures are submitted
// for voting. The curRank is taken as input to ensure SafetyRules will only
// vote for proposals at current rank and prevent double voting.
// Returns:
//   - (vote, nil): On the _first_ state for the current rank that is safe to
//     vote for. Subsequently, voter does _not_ vote for any other state with
//     the same (or lower) rank.
//   - (nil, models.NoVoteError): If the voter decides that it does not want to
//     vote for the given state. This is a sentinel error and _expected_ during
//     normal operation.
//
// All other errors are unexpected and potential symptoms of uncovered edge
// cases or corrupted internal state (fatal).
func (r *SafetyRules[StateT, VoteT]) ProduceVote(
	signedProposal *models.SignedProposal[StateT, VoteT],
	curRank uint64,
) (*VoteT, error) {
	return r.produceVote(&signedProposal.Proposal, curRank)
}

// produceVote implements the core Safety Rules to validate whether it is safe
// to vote. This method is to be used to vote for other leaders' states as well
// as this node's own proposals under construction. We explicitly codify the
// important aspect that a proposer's signature for their own state is
// conceptually also just a vote (we explicitly use that property when
// aggregating votes and including the proposer's own vote into a QC). In order
// to express this conceptual equivalence in code, the voting logic in Safety
// Rules must also operate on an unsigned Proposal.
//
// The curRank is taken as input to ensure SafetyRules will only vote for
// proposals at current rank and prevent double voting.
// Returns:
//   - (vote, nil): On the _first_ state for the current rank that is safe to
//     vote for. Subsequently, voter does _not_ vote for any other state with
//     the same (or lower) rank.
//   - (nil, models.NoVoteError): If the voter decides that it does not want to
//     vote for the given state. This is a sentinel error and _expected_ during
//     normal operation.
//
// All other errors are unexpected and potential symptoms of uncovered edge
// cases or corrupted internal state (fatal).
func (r *SafetyRules[StateT, VoteT]) produceVote(
	proposal *models.Proposal[StateT],
	curRank uint64,
) (*VoteT, error) {
	state := proposal.State
	// sanity checks:
	if curRank != state.Rank {
		return nil, fmt.Errorf(
			"expecting state for current rank %d, but state's rank is %d",
			curRank,
			state.Rank,
		)
	}

	err := r.isSafeToVote(proposal)
	if err != nil {
		return nil, fmt.Errorf(
			"not safe to vote for proposal %x: %w",
			proposal.State.Identifier,
			err,
		)
	}

	currentLeader, err := r.committee.LeaderForRank(state.Rank)
	if err != nil {
		return nil, fmt.Errorf(
			"expect to have a valid leader for rank %d: %w",
			curRank,
			err,
		)
	}
	// This sanity check confirms that the proposal is from the correct leader of
	// this rank. In case this sanity check fails, we return an exception, because
	// the compliance layer should have verified this already. However, proposals
	// from this node might not go through the compliance engine, and must be
	// signed before anyway. Therefore, we still include this sanity check, but
	// return an exception because signing a proposal should be only for ranks
	// where this node is actually the leader.
	if state.ProposerID != currentLeader {
		return nil, fmt.Errorf(
			"incorrect proposal, as proposer %x is different from the leader %x for rank %d",
			state.ProposerID,
			currentLeader,
			curRank,
		)
	}

	// In case this node is the leader, we can skip the following checks.
	// • If this node is ejected (check (ii) would fail), voting for any states or
	//   signing own proposals is of no harm. This is because all other honest
	//   nodes should have terminated their connection to us, so we are not
	//   risking to use up the networking bandwidth of honest nodes. This is
	//   relevant in case of self-ejection: a node operator suspecting their
	//   node's keys to be compromised can request for their node to be ejected to
	//   prevent malicious actors impersonating their node, launching an attack on
	//   the network, and the seniority being slashed. The self-ejection mechanism
	//   corresponds to key-revocation and reduces attack surface for the network
	//   and the node operator's seniority. In case of self-ejection, a node is no
	//   longer part of the network, hence it cannot harm the network and is no
	//   longer subject to slashing for actions during the respective ranks.
	//   Therefore, voting or continuing to signing state proposals is of no
	//   concern.
	// • In case this node is the leader, `state.ProposerID` and
	//   `r.committee.Self()` are identical. In other words, check (i) also
	//   verifies that this node itself is not ejected -- the same as check (ii).
	//   Hence, also check (i) can be skipped with the same reasoning.
	if currentLeader != r.committee.Self() {
		// (i): we need to make sure that proposer is not ejected to vote
		_, err = r.committee.IdentityByState(state.Identifier, state.ProposerID)
		if models.IsInvalidSignerError(err) {
			// the proposer must be ejected since the proposal has already been
			// validated, which ensures that the proposer was a valid committee member
			// at the start of the rank
			return nil, models.NewNoVoteErrorf("proposer ejected: %w", err)
		}
		if err != nil {
			return nil, fmt.Errorf(
				"internal error retrieving Identity of proposer %x at state %x: %w",
				state.ProposerID,
				state.Identifier,
				err,
			)
		}

		// (ii) Do not produce a vote for states where we are not an active
		// committee member. The HotStuff state machine may request to vote during
		// grace periods outside the ranks, where the node is authorized to
		// actively participate. If we voted during those grace periods, we would
		// needlessly waste network bandwidth, as such votes can't be used to
		// produce valid QCs.
		_, err = r.committee.IdentityByState(state.Identifier, r.committee.Self())
		if models.IsInvalidSignerError(err) {
			return nil, models.NewNoVoteErrorf(
				"I am not authorized to vote for state %x: %w",
				state.Identifier,
				err,
			)
		}
		if err != nil {
			return nil, fmt.Errorf("could not get self identity: %w", err)
		}
	}

	vote, err := r.signer.CreateVote(state)
	if err != nil {
		return nil, fmt.Errorf("could not vote for state: %w", err)
	}

	// vote for the current rank has been produced, update safetyData
	r.consensusState.LatestAcknowledgedRank = curRank
	if r.consensusState.FinalizedRank < state.ParentQuorumCertificate.GetRank() {
		r.consensusState.FinalizedRank = state.ParentQuorumCertificate.GetRank()
	}

	err = r.store.PutConsensusState(r.consensusState)
	if err != nil {
		return nil, fmt.Errorf("could not persist safety data: %w", err)
	}

	return vote, nil
}

// ProduceTimeout takes current rank, highest locally known QC and TC (optional,
// must be nil if and only if QC is for previous rank) and decides whether to
// produce timeout for current rank.
// Returns:
//   - (timeout, nil): It is safe to timeout for current rank using newestQC and
//     previousRankTimeoutCert.
//   - (nil, models.NoTimeoutError): If replica is not part of the authorized
//     consensus committee (anymore) and therefore is not authorized to produce
//     a valid timeout state. This sentinel error is _expected_ during normal
//     operation, e.g. during the grace-period after Rank switchover or after
//     the replica self-ejected.
//
// All other errors are unexpected and potential symptoms of uncovered edge
// cases or corrupted internal state (fatal).
func (r *SafetyRules[StateT, VoteT]) ProduceTimeout(
	curRank uint64,
	newestQC models.QuorumCertificate,
	previousRankTimeoutCert models.TimeoutCertificate,
) (*models.TimeoutState[VoteT], error) {
	lastTimeout := r.consensusState.LatestTimeout
	if lastTimeout != nil && lastTimeout.Rank == curRank {
		updatedTimeout := &models.TimeoutState[VoteT]{
			Rank:                        lastTimeout.Rank,
			LatestQuorumCertificate:     lastTimeout.LatestQuorumCertificate,
			PriorRankTimeoutCertificate: lastTimeout.PriorRankTimeoutCertificate,
			TimeoutTick:                 lastTimeout.TimeoutTick + 1,
			Vote:                        lastTimeout.Vote,
		}

		// persist updated TimeoutState in `safetyData` and return it
		r.consensusState.LatestTimeout = updatedTimeout
		err := r.store.PutConsensusState(r.consensusState)
		if err != nil {
			return nil, fmt.Errorf("could not persist safety data: %w", err)
		}
		return r.consensusState.LatestTimeout, nil
	}

	err := r.IsSafeToTimeout(curRank, newestQC, previousRankTimeoutCert)
	if err != nil {
		return nil, fmt.Errorf("local, trusted inputs failed safety rules: %w", err)
	}

	// Do not produce a timeout for rank where we are not a valid committee
	// member.
	_, err = r.committee.IdentityByRank(curRank, r.committee.Self())
	if err != nil {
		if models.IsInvalidSignerError(err) {
			return nil, models.NewNoTimeoutErrorf(
				"I am not authorized to timeout for rank %d: %w",
				curRank,
				err,
			)
		}
		return nil, fmt.Errorf("could not get self identity: %w", err)
	}

	timeout, err := r.signer.CreateTimeout(
		curRank,
		newestQC,
		previousRankTimeoutCert,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"could not create timeout at rank %d: %w",
			curRank,
			err,
		)
	}

	r.consensusState.LatestAcknowledgedRank = curRank
	r.consensusState.LatestTimeout = timeout

	err = r.store.PutConsensusState(r.consensusState)
	if err != nil {
		return nil, fmt.Errorf("could not persist safety data: %w", err)
	}

	return timeout, nil
}

// SignOwnProposal takes an unsigned state proposal and produces a vote for it.
// Vote is a cryptographic commitment to the proposal. By adding the vote to an
// unsigned proposal, the caller constructs a signed state proposal. This method
// has to be used only by the leader, which must be the proposer of the state
// (or an exception is returned). Implementors must guarantee that:
// - vote on the proposal satisfies safety rules
// - maximum one proposal is signed per rank
// Returns:
//   - (vote, nil): the passed unsigned proposal is a valid one, and it's safe
//     to make a proposal. Subsequently, leader does _not_ produce any _other_
//     proposal with the same (or lower) rank.
//   - (nil, models.NoVoteError): according to HotStuff's Safety Rules, it is
//     not safe to sign the given proposal. This could happen because we have
//     already proposed or timed out for the given rank. This is a sentinel
//     error and _expected_ during normal operation.
//
// All other errors are unexpected and potential symptoms of uncovered edge
// cases or corrupted internal state (fatal).
func (r *SafetyRules[StateT, VoteT]) SignOwnProposal(
	unsignedProposal *models.Proposal[StateT],
) (*VoteT, error) {
	// check that the state is created by us
	if unsignedProposal.State.ProposerID != r.committee.Self() {
		return nil, fmt.Errorf(
			"can't sign proposal for someone else's state, proposer: %x, self: %x",
			unsignedProposal.State.ProposerID,
			r.committee.Self(),
		)
	}

	return r.produceVote(unsignedProposal, unsignedProposal.State.Rank)
}

// isSafeToVote checks if this proposal is valid in terms of voting rules, if
// voting for this proposal won't break safety rules. Expected errors during
// normal operations:
//   - NoVoteError if replica already acted during this rank (either voted o
//     generated timeout)
func (r *SafetyRules[StateT, VoteT]) isSafeToVote(
	proposal *models.Proposal[StateT],
) error {
	stateRank := proposal.State.Rank

	err := r.validateEvidenceForEnteringRank(
		stateRank,
		proposal.State.ParentQuorumCertificate,
		proposal.PreviousRankTimeoutCertificate,
	)
	if err != nil {
		// As we are expecting the states to be pre-validated, any failure here is a
		// symptom of an internal bug.
		return fmt.Errorf("proposal failed consensus validity check: %w", err)
	}

	// This check satisfies voting rule 1
	// 1. Replicas vote strictly in increasing rounds,
	// state's rank must be greater than the rank that we have voted for
	acRank := r.consensusState.LatestAcknowledgedRank
	if stateRank == acRank {
		return models.NewNoVoteErrorf(
			"already voted or generated timeout in rank %d",
			stateRank,
		)
	}
	if stateRank < acRank {
		return fmt.Errorf(
			"already acted during rank %d but got proposal for lower rank %d",
			acRank,
			stateRank,
		)
	}

	return nil
}

// IsSafeToTimeout checks if it's safe to timeout with proposed data, i.e.
// timing out won't break safety. newestQC is the valid QC with the greatest
// rank that we have observed. previousRankTimeoutCert is the TC for the
// previous rank (might be nil).
//
// When generating a timeout, the inputs are provided by node-internal
// components. Failure to comply with the protocol is a symptom of an internal
// bug. We don't expect any errors during normal operations.
func (r *SafetyRules[StateT, VoteT]) IsSafeToTimeout(
	curRank uint64,
	newestQC models.QuorumCertificate,
	previousRankTimeoutCert models.TimeoutCertificate,
) error {
	err := r.validateEvidenceForEnteringRank(
		curRank,
		newestQC,
		previousRankTimeoutCert,
	)
	if err != nil {
		return fmt.Errorf("not safe to timeout: %w", err)
	}

	if newestQC.GetRank() < r.consensusState.FinalizedRank {
		return fmt.Errorf(
			"have already seen QC for rank %d, but newest QC is reported to be for rank %d",
			r.consensusState.FinalizedRank,
			newestQC.GetRank(),
		)
	}
	if curRank+1 <= r.consensusState.LatestAcknowledgedRank {
		return fmt.Errorf("cannot generate timeout for past rank %d", curRank)
	}
	// the logic for rejecting inputs with `curRank <= newestQC.Rank` is already
	// contained in `validateEvidenceForEnteringRank(..)`, because it only passes
	// if
	// * either `curRank == newestQC.Rank + 1` (condition 2)
	// * or `curRank > newestQC.Rank` (condition 4)

	return nil
}

// validateEvidenceForEnteringRank performs the following check that is
// fundamental for consensus safety: Whenever a replica acts within a rank, it
// must prove that is has sufficient evidence to enter this rank
// Specifically:
//  1. The replica must always provide a QC and optionally a TC.
//  2. [Happy Path] If the previous round (i.e. `rank -1`) resulted in a QC, the
//     replica is allowed to transition to `rank`. The QC from the previous
//     round provides sufficient evidence. Furthermore, to prevent
//     resource-exhaustion attacks, we require that no TC is included as part of
//     the proof.
//  3. Following the Happy Path has priority over following the Recovery Path
//     (specified below).
//  4. [Recovery Path] If the previous round (i.e. `rank -1`) did *not* result
//     in a QC, a TC from the previous round is required to transition to
//     `rank`. The following additional consistency requirements have to be
//     satisfied:
//     (a) newestQC.Rank + 1 < rank
//     Otherwise, the replica has violated condition 3 (in case
//     newestQC.Rank + 1 = rank); or the replica failed to apply condition 2 (in
//     case newestQC.Rank + 1 > rank).
//     (b) newestQC.Rank ≥ previousRankTimeoutCert.NewestQC.Rank
//     Otherwise, the replica has violated condition 3.
//
// SafetyRules has the sole signing authority and enforces adherence to these
// conditions. In order to generate valid consensus signatures, the replica must
// provide the respective evidence (required QC + optional TC) to its internal
// SafetyRules component for each consensus action that the replica wants to
// take:
//   - primary signing its own proposal
//   - replica voting for a state
//   - replica generating a timeout message
//
// During normal operations, no errors are expected:
//   - As we are expecting the states to be pre-validated, any failure here is a
//     symptom of an internal bug.
//   - When generating a timeout, the inputs are provided by node-internal
//     components. Failure to comply with the protocol is a symptom of an
//     internal bug.
func (r *SafetyRules[StateT, VoteT]) validateEvidenceForEnteringRank(
	rank uint64,
	newestQC models.QuorumCertificate,
	previousRankTimeoutCert models.TimeoutCertificate,
) error {
	// Condition 1:
	if newestQC == nil {
		return fmt.Errorf("missing the mandatory QC")
	}

	// Condition 2:
	if newestQC.GetRank()+1 == rank {
		if previousRankTimeoutCert != nil {
			return fmt.Errorf(
				"when QC is for prior round (%d), no TC should be provided (%d)",
				newestQC.GetRank(),
				previousRankTimeoutCert.GetRank(),
			)
		}
		return nil
	}
	// Condition 3: if we reach the following lines, the happy path is not
	// satisfied.

	// Condition 4:
	if previousRankTimeoutCert == nil {
		return fmt.Errorf(
			"expecting TC because QC (%d) is not for prior rank (%d - 1); but didn't get any TC",
			newestQC.GetRank(),
			rank,
		)
	}
	if previousRankTimeoutCert.GetRank()+1 != rank {
		return fmt.Errorf(
			"neither QC (rank %d) nor TC (rank %d) allows to transition to rank %d",
			newestQC.GetRank(),
			previousRankTimeoutCert.GetRank(),
			rank,
		)
	}
	if newestQC.GetRank() >= rank {
		// Note: we need to enforce here that `newestQC.Rank + 1 < rank`, i.e. we
		// error for `newestQC.Rank+1 >= rank` However, `newestQC.Rank+1 == rank` is
		// impossible, because otherwise we would have walked into condition 2.
		// Hence, it suffices to error if `newestQC.Rank+1 > rank`, which is
		// identical to `newestQC.Rank >= rank`
		return fmt.Errorf(
			"still at rank %d, despite knowing a QC for rank %d",
			rank,
			newestQC.GetRank(),
		)
	}
	if newestQC.GetRank() < previousRankTimeoutCert.GetLatestQuorumCert().GetRank() {
		return fmt.Errorf(
			"failed to update newest QC (still at rank %d) despite a newer QC (rank %d) being included in TC",
			newestQC.GetRank(),
			previousRankTimeoutCert.GetLatestQuorumCert().GetRank(),
		)
	}

	return nil
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
