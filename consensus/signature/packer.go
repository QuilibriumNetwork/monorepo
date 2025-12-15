package signature

import (
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// ConsensusSigDataPacker implements the consensus.Packer interface.
type ConsensusSigDataPacker struct {
	committees consensus.Replicas
}

var _ consensus.Packer = &ConsensusSigDataPacker{}

// NewConsensusSigDataPacker creates a new ConsensusSigDataPacker instance
func NewConsensusSigDataPacker(
	committees consensus.Replicas,
) *ConsensusSigDataPacker {
	return &ConsensusSigDataPacker{
		committees: committees,
	}
}

// Pack serializes the state signature data into raw bytes, suitable to create a
// QC. To pack the state signature data, we first build a compact data type, and
// then encode it into bytes. Expected error returns during normal operations:
//   - none; all errors are symptoms of inconsistent input data or corrupted
//     internal state.
func (p *ConsensusSigDataPacker) Pack(
	rank uint64,
	sig *consensus.StateSignatureData,
) ([]byte, []byte, error) {
	// retrieve all authorized consensus participants at the given state
	fullMembers, err := p.committees.IdentitiesByRank(rank)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"could not find consensus committee for rank %d: %w",
			rank,
			err,
		)
	}

	sigSet := map[models.Identity]struct{}{}
	for _, s := range sig.Signers {
		sigSet[s.Identity()] = struct{}{}
	}

	signerIndices := make([]byte, (len(fullMembers)+7)/8)
	for i, member := range fullMembers {
		if _, ok := sigSet[member.Identity()]; ok {
			signerIndices[i/8] |= 1 << (i % 8)
		}
	}

	return signerIndices, sig.Signature, nil
}

// Unpack de-serializes the provided signature data.
// rank is the rank of the state that the aggregated sig is signed for
// sig is the aggregated signature data
// It returns:
//   - (sigData, nil) if successfully unpacked the signature data
//   - (nil, models.InvalidFormatError) if failed to unpack the signature data
func (p *ConsensusSigDataPacker) Unpack(
	signerIdentities []models.WeightedIdentity,
	sigData []byte,
) (*consensus.StateSignatureData, error) {
	return &consensus.StateSignatureData{
		Signers:   signerIdentities, // buildutils:allow-slice-alias
		Signature: sigData,          // buildutils:allow-slice-alias
	}, nil
}
