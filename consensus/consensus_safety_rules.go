package consensus

import "source.quilibrium.com/quilibrium/monorepo/consensus/models"

// SafetyRules enforces all consensus rules that guarantee safety. It produces
// votes for the given states or TimeoutState for the given ranks, only if all
// safety rules are satisfied. In particular, SafetyRules guarantees a
// foundational security theorem for HotStuff, which we utilize also outside of
// consensus (e.g. queuing pending states for execution, verification, sealing
// etc):
//
//	THEOREM: For each rank, there can be at most 1 certified state.
//
// Implementations are generally *not* concurrency safe.
type SafetyRules[StateT models.Unique, VoteT models.Unique] interface {
	// ProduceVote takes a state proposal and current rank, and decides whether to
	// vote for the state. Voting is deterministic, i.e. voting for same proposal
	// will always result in the same vote.
	// Returns:
	//  * (vote, nil): On the _first_ state for the current rank that is safe to
	//    vote for. Subsequently, voter does _not_ vote for any _other_ state with
	//    the same (or lower) rank. SafetyRules internally caches and persists its
	//    latest vote. As long as the SafetyRules' internal state remains
	//    unchanged, ProduceVote will return its cached for identical inputs.
	//  * (nil, model.NoVoteError): If the safety module decides that it is not
	//    safe to vote for the given state. This is a sentinel error and
	//    _expected_ during normal operation.
	// All other errors are unexpected and potential symptoms of uncovered edge
	// cases or corrupted internal state (fatal).
	ProduceVote(
		proposal *models.SignedProposal[StateT, VoteT],
		curRank uint64,
	) (*VoteT, error)

	// ProduceTimeout takes current rank, highest locally known QC and TC
	// (optional, must be nil if and only if QC is for previous rank) and decides
	// whether to produce timeout for current rank.
	// Returns:
	//  * (timeout, nil): It is safe to timeout for current rank using newestQC
	//    and lastRankTC.
	//  * (nil, model.NoTimeoutError): If replica is not part of the authorized
	//    consensus committee (anymore) and therefore is not authorized to produce
	//    a valid timeout state. This sentinel error is _expected_ during normal
	//    operation, e.g. during the grace-period after Rank switchover or after
	//    the replica self-ejected.
	// All other errors are unexpected and potential symptoms of uncovered edge
	// cases or corrupted internal state (fatal).
	ProduceTimeout(
		curRank uint64,
		newestQC models.QuorumCertificate,
		lastRankTC models.TimeoutCertificate,
	) (*models.TimeoutState[VoteT], error)

	// SignOwnProposal takes an unsigned state proposal and produces a vote for
	// it. Vote is a cryptographic commitment to the proposal. By adding the vote
	// to an unsigned proposal, the caller constructs a signed state proposal.
	// This method has to be used only by the leader, which must be the proposer
	// of the state (or an exception is returned).
	// Implementors must guarantee that:
	// - vote on the proposal satisfies safety rules
	// - maximum one proposal is signed per rank
	// Returns:
	//  * (vote, nil): the passed unsigned proposal is a valid one, and it's safe
	//    to make a proposal. Subsequently, leader does _not_ produce any _other_
	//    proposal with the same (or lower) rank.
	//  * (nil, model.NoVoteError): according to HotStuff's Safety Rules, it is
	//    not safe to sign the given proposal. This could happen because we have
	//    already proposed or timed out for the given rank. This is a sentinel
	//    error and _expected_ during normal operation.
	// All other errors are unexpected and potential symptoms of uncovered edge
	// cases or corrupted internal state (fatal).
	SignOwnProposal(unsignedProposal *models.Proposal[StateT]) (*VoteT, error)
}
