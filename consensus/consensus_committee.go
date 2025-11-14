package consensus

import "source.quilibrium.com/quilibrium/monorepo/consensus/models"

// A committee provides a subset of the protocol.State, which is restricted to
// exactly those nodes that participate in the current HotStuff instance: the
// state of all legitimate HotStuff participants for the specified rank.
// Legitimate HotStuff participants have NON-ZERO WEIGHT.
//
// For the purposes of validating votes, timeouts, quorum certificates, and
// timeout certificates we consider a committee which is static over the course
// of an rank. Although committee members may be ejected, or have their weight
// change during an rank, we ignore these changes. For these purposes we use
// the Replicas and *ByRank methods.
//
// When validating proposals, we take into account changes to the committee
// during the course of an rank. In particular, if a node is ejected, we will
// immediately reject all future proposals from that node. For these purposes we
// use the DynamicCommittee and *ByState methods.

// Replicas defines the consensus committee for the purposes of validating
// votes, timeouts, quorum certificates, and timeout certificates. Any consensus
// committee member who was authorized to contribute to consensus AT THE
// BEGINNING of the rank may produce valid votes and timeouts for the entire
// rank, even if they are later ejected. So for validating votes/timeouts we
// use *ByRank methods.
//
// Since the voter committee is considered static over an rank:
//   - we can query identities by rank
//   - we don't need the full state ancestry prior to validating messages
type Replicas interface {

	// LeaderForRank returns the identity of the leader for a given rank.
	// CAUTION: per liveness requirement of HotStuff, the leader must be
	//          fork-independent. Therefore, a node retains its proposer rank
	//          slots even if it is slashed. Its proposal is simply considered
	//          invalid, as it is not from a legitimate participant.
	// Returns the following expected errors for invalid inputs:
	//   - model.ErrRankUnknown if no rank containing the given rank is
	//     known
	LeaderForRank(rank uint64) (models.Identity, error)

	// QuorumThresholdForRank returns the minimum total weight for a supermajority
	// at the given rank. This weight threshold is computed using the total weight
	// of the initial committee and is static over the course of an rank.
	// Returns the following expected errors for invalid inputs:
	//   - model.ErrRankUnknown if no rank containing the given rank is
	//     known
	QuorumThresholdForRank(rank uint64) (uint64, error)

	// TimeoutThresholdForRank returns the minimum total weight of observed
	// timeout states required to safely timeout for the given rank. This weight
	// threshold is computed using the total weight of the initial committee and
	// is static over the course of an rank.
	// Returns the following expected errors for invalid inputs:
	//   - model.ErrRankUnknown if no rank containing the given rank is
	//     known
	TimeoutThresholdForRank(rank uint64) (uint64, error)

	// Self returns our own node identifier.
	// TODO: ultimately, the own identity of the node is necessary for signing.
	//       Ideally, we would move the method for checking whether an Identifier
	//       refers to this node to the signer. This would require some
	//       refactoring of EventHandler (postponed to later)
	Self() models.Identity

	// IdentitiesByRank returns a list of the legitimate HotStuff participants
	// for the rank given by the input rank.
	// The returned list of HotStuff participants:
	//   - contains nodes that are allowed to submit votes or timeouts within the
	//     given rank (un-ejected, non-zero weight at the beginning of the rank)
	//   - is ordered in the canonical order
	//   - contains no duplicates.
	//
	// CAUTION: DO NOT use this method for validating state proposals.
	//
	// Returns the following expected errors for invalid inputs:
	//   - model.ErrRankUnknown if no rank containing the given rank is
	//     known
	//
	IdentitiesByRank(
		rank uint64,
	) ([]models.WeightedIdentity, error)

	// IdentityByRank returns the full Identity for specified HotStuff
	// participant. The node must be a legitimate HotStuff participant with
	// NON-ZERO WEIGHT at the specified state.
	//
	// ERROR conditions:
	//  - model.InvalidSignerError if participantID does NOT correspond to an
	//    authorized HotStuff participant at the specified state.
	//
	// Returns the following expected errors for invalid inputs:
	//   - model.ErrRankUnknown if no rank containing the given rank is
	//     known
	//
	IdentityByRank(
		rank uint64,
		participantID models.Identity,
	) (models.WeightedIdentity, error)
}

// DynamicCommittee extends Replicas to provide the consensus committee for the
// purposes of validating proposals. The proposer committee reflects
// state-to-state changes in the identity table to support immediately rejecting
// proposals from nodes after they are ejected. For validating proposals, we use
// *ByState methods.
//
// Since the proposer committee can change at any state:
//   - we query by state ID
//   - we must have incorporated the full state ancestry prior to validating
//     messages
type DynamicCommittee interface {
	Replicas

	// IdentitiesByState returns a list of the legitimate HotStuff participants
	// for the given state. The returned list of HotStuff participants:
	//   - contains nodes that are allowed to submit proposals, votes, and
	//     timeouts (un-ejected, non-zero weight at current state)
	//   - is ordered in the canonical order
	//   - contains no duplicates.
	//
	// ERROR conditions:
	//  - state.ErrUnknownSnapshotReference if the stateID is for an unknown state
	IdentitiesByState(stateID models.Identity) ([]models.WeightedIdentity, error)

	// IdentityByState returns the full Identity for specified HotStuff
	// participant. The node must be a legitimate HotStuff participant with
	// NON-ZERO WEIGHT at the specified state.
	// ERROR conditions:
	//  - model.InvalidSignerError if participantID does NOT correspond to an
	//    authorized HotStuff participant at the specified state.
	//  - state.ErrUnknownSnapshotReference if the stateID is for an unknown state
	IdentityByState(
		stateID models.Identity,
		participantID models.Identity,
	) (models.WeightedIdentity, error)
}

// StateSignerDecoder defines how to convert the ParentSignerIndices field
// within a particular state header to the identifiers of the nodes which signed
// the state.
type StateSignerDecoder[StateT models.Unique] interface {
	// DecodeSignerIDs decodes the signer indices from the given state header into
	// full node IDs.
	// Note: A state header contains a quorum certificate for its parent, which
	// proves that the consensus committee has reached agreement on validity of
	// parent state. Consequently, the returned IdentifierList contains the
	// consensus participants that signed the parent state.
	// Expected Error returns during normal operations:
	//  - consensus.InvalidSignerIndicesError if signer indices included in the
	//    header do not encode a valid subset of the consensus committee
	DecodeSignerIDs(
		state *models.State[StateT],
	) ([]models.WeightedIdentity, error)
}
