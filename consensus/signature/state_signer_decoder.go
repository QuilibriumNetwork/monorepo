package signature

import (
	"errors"
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// StateSignerDecoder is a wrapper around the `consensus.DynamicCommittee`,
// which implements the auxiliary logic for de-coding signer indices of a state
// (header) to full node IDs
type StateSignerDecoder[StateT models.Unique] struct {
	consensus.DynamicCommittee
}

func NewStateSignerDecoder[StateT models.Unique](
	committee consensus.DynamicCommittee,
) *StateSignerDecoder[StateT] {
	return &StateSignerDecoder[StateT]{committee}
}

var _ consensus.StateSignerDecoder[*nilUnique] = (*StateSignerDecoder[*nilUnique])(nil)

// DecodeSignerIDs decodes the signer indices from the given state into
// full node IDs. Note: A state header contains a quorum certificate for its
// parent, which proves that the consensus committee has reached agreement on
// validity of parent state. Consequently, the returned IdentifierList contains
// the consensus participants that signed the parent state. Expected Error
// returns during normal operations:
//   - consensus.InvalidSignerIndicesError if signer indices included in the
//     state do not encode a valid subset of the consensus committee
//   - state.ErrUnknownSnapshotReference if the input state is not a known
//     incorporated state.
func (b *StateSignerDecoder[StateT]) DecodeSignerIDs(
	state *models.State[StateT],
) (
	[]models.WeightedIdentity,
	error,
) {
	// root state does not have signer indices
	if state.ParentQuorumCertificate == nil {
		return []models.WeightedIdentity{}, nil
	}

	// we will use IdentitiesByRank since it's a faster call and avoids DB lookup
	members, err := b.IdentitiesByRank(state.ParentQuorumCertificate.GetRank())
	if err != nil {
		if errors.Is(err, models.ErrRankUnknown) {
			// possibly, we request rank which is far behind in the past, in this
			// case we won't have it in cache. try asking by parent ID
			byStateMembers, err := b.IdentitiesByState(
				state.ParentQuorumCertificate.Identity(),
			)
			if err != nil {
				return nil, fmt.Errorf(
					"could not retrieve identities for state %x with QC rank %d for parent %x: %w",
					state.Identifier,
					state.ParentQuorumCertificate.GetRank(),
					state.ParentQuorumCertificate.Identity(),
					err,
				) // state.ErrUnknownSnapshotReference or exception
			}
			members = byStateMembers
		} else {
			return nil, fmt.Errorf(
				"unexpected error retrieving identities for state %x: %w",
				state.Identifier,
				err,
			)
		}
	}

	signerIDs := []models.WeightedIdentity{}
	sigIndices := state.ParentQuorumCertificate.GetAggregatedSignature().GetBitmask()
	for i, member := range members {
		if sigIndices[i/8]>>i%8&1 == 1 {
			signerIDs = append(signerIDs, member)
		}
	}

	return signerIDs, nil
}

// NoopStateSignerDecoder does not decode any signer indices and consistently
// returns nil for the signing node IDs (auxiliary data)
type NoopStateSignerDecoder[StateT models.Unique] struct{}

func NewNoopStateSignerDecoder[
	StateT models.Unique,
]() *NoopStateSignerDecoder[StateT] {
	return &NoopStateSignerDecoder[StateT]{}
}

func (b *NoopStateSignerDecoder[StateT]) DecodeSignerIDs(
	_ *models.State[StateT],
) ([]models.WeightedIdentity, error) {
	return nil, nil
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
