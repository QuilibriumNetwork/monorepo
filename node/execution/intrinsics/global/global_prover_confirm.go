package global

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type BLS48581AddressedSignature struct {
	// The derived address of the signer
	Address []byte
	// The BLS48-581 signature
	Signature []byte
}

type ProverConfirm struct {
	// The filter representing the confirm request
	Filter []byte
	// The frame number when this request is made
	FrameNumber uint64
	// The BLS48581 addressed signature
	PublicKeySignatureBLS48581 BLS48581AddressedSignature

	// Private fields
	keyManager     keys.KeyManager
	hypergraph     hypergraph.Hypergraph
	rdfMultiprover *schema.RDFMultiprover
}

func NewProverConfirm(
	filter []byte,
	frameNumber uint64,
	keyManager keys.KeyManager,
	hypergraph hypergraph.Hypergraph,
	rdfMultiprover *schema.RDFMultiprover,
) (*ProverConfirm, error) {
	return &ProverConfirm{
		Filter:         filter,
		FrameNumber:    frameNumber,
		keyManager:     keyManager,
		hypergraph:     hypergraph,
		rdfMultiprover: rdfMultiprover,
	}, nil
}

// GetCost implements intrinsics.IntrinsicOperation.
// Note: if staking were ever added to the protocol, costs here could be the
// stake entry point.
func (p *ProverConfirm) GetCost() (*big.Int, error) {
	return big.NewInt(0), nil
}

// Materialize implements intrinsics.IntrinsicOperation.
func (p *ProverConfirm) Materialize(
	frameNumber uint64,
	state state.State,
) (state.State, error) {
	hg := state.(*hgstate.HypergraphState)

	proverAddress := p.PublicKeySignatureBLS48581.Address
	proverFullAddress := [64]byte{}
	copy(proverFullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(proverFullAddress[32:], proverAddress)

	// Get the existing prover vertex
	vertex, err := hg.Get(
		proverFullAddress[:32],
		proverFullAddress[32:],
		hgstate.VertexAddsDiscriminator,
	)
	if err != nil || vertex == nil {
		return nil, errors.Wrap(
			errors.New("prover not found"),
			"materialize",
		)
	}

	var proverTree *tries.VectorCommitmentTree
	var ok bool
	proverTree, ok = vertex.(*tries.VectorCommitmentTree)
	if !ok || proverTree == nil {
		return nil, errors.Wrap(
			errors.New("invalid object returned for vertex"),
			"materialize",
		)
	}

	// Get prover public key for allocation lookup
	publicKey, err := p.rdfMultiprover.Get(
		GLOBAL_RDF_SCHEMA,
		"prover:Prover",
		"PublicKey",
		proverTree,
	)
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	// Calculate allocation address:
	allocationAddressBI, err := poseidon.HashBytes(
		slices.Concat([]byte("PROVER_ALLOCATION"), publicKey, p.Filter),
	)
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}
	allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))
	allocationFullAddress := [64]byte{}
	copy(allocationFullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(allocationFullAddress[32:], allocationAddress)

	// Get allocation vertex
	allocationVertex, err := hg.Get(
		allocationFullAddress[:32],
		allocationFullAddress[32:],
		hgstate.VertexAddsDiscriminator,
	)
	if err != nil || allocationVertex == nil {
		return nil, errors.Wrap(
			errors.New("allocation not found"),
			"materialize",
		)
	}

	var allocationTree *tries.VectorCommitmentTree
	allocationTree, ok = allocationVertex.(*tries.VectorCommitmentTree)
	if !ok || allocationTree == nil {
		return nil, errors.Wrap(
			errors.New("invalid object returned for vertex"),
			"materialize",
		)
	}

	// Check current allocation status
	statusBytes, err := p.rdfMultiprover.Get(
		GLOBAL_RDF_SCHEMA,
		"allocation:ProverAllocation",
		"Status",
		allocationTree,
	)
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	status := uint8(0)
	if len(statusBytes) > 0 {
		status = statusBytes[0]
	}

	// Determine what we're confirming based on current status
	if status == 0 {
		// Confirming join - update allocation status to active (1)
		err = p.rdfMultiprover.Set(
			GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"allocation:ProverAllocation",
			"Status",
			[]byte{1},
			allocationTree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Store join confirmation frame number
		frameNumberBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(frameNumberBytes, p.FrameNumber)
		err = p.rdfMultiprover.Set(
			GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"allocation:ProverAllocation",
			"JoinConfirmFrameNumber",
			frameNumberBytes,
			allocationTree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}
	} else if status == 3 {
		// Confirming leave - update allocation status to left (4)
		err = p.rdfMultiprover.Set(
			GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"allocation:ProverAllocation",
			"Status",
			[]byte{4},
			allocationTree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Store leave confirmation frame number
		frameNumberBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(frameNumberBytes, p.FrameNumber)
		err = p.rdfMultiprover.Set(
			GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"allocation:ProverAllocation",
			"LeaveConfirmFrameNumber",
			frameNumberBytes,
			allocationTree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}
	}

	// Get a copy of the original allocation tree for change tracking
	var prior *tries.VectorCommitmentTree
	originalAllocationVertex, err := hg.Get(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		allocationAddress,
		hgstate.VertexAddsDiscriminator,
	)
	if err == nil && originalAllocationVertex != nil {
		prior = originalAllocationVertex.(*tries.VectorCommitmentTree)
	}

	// Create allocation vertex
	allocationVertexState := hg.NewVertexAddMaterializedState(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		[32]byte(allocationAddress),
		frameNumber,
		prior,
		allocationTree,
	)

	err = hg.Set(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		allocationAddress,
		hgstate.VertexAddsDiscriminator,
		frameNumber,
		allocationVertexState,
	)
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	// Update the prover status to reflect the aggregate allocation status
	err = UpdateAggregateProverStatus(
		hg,
		proverAddress,
		frameNumber,
		proverTree,
		p.rdfMultiprover,
	)
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	return state, nil
}

// Prove implements intrinsics.IntrinsicOperation.
func (p *ProverConfirm) Prove(frameNumber uint64) error {
	// Get the q-prover-key
	prover, err := p.keyManager.GetSigningKey("q-prover-key")
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// Get the public key
	pubKey := prover.Public().([]byte)

	// Compute the address from the public key using Poseidon hash
	addressBI, err := poseidon.HashBytes(pubKey)
	if err != nil {
		return errors.Wrap(err, "prove")
	}
	address := addressBI.FillBytes(make([]byte, 32))

	// Create confirm message contents
	confirmMessage := bytes.Buffer{}

	// Add filter
	confirmMessage.Write(p.Filter)

	// Add frame number
	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, p.FrameNumber)
	confirmMessage.Write(frameNumberBytes)

	// Create the domain for the signature
	confirmDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("PROVER_CONFIRM"),
	)
	confirmDomain, err := poseidon.HashBytes(confirmDomainPreimage)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// Create signature over the confirm message with the confirm domain
	signature, err := prover.SignWithDomain(
		confirmMessage.Bytes(),
		confirmDomain.Bytes(),
	)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// Create the BLS48581AddressedSignature
	p.PublicKeySignatureBLS48581 = BLS48581AddressedSignature{
		Signature: signature,
		Address:   address,
	}

	return nil
}

// Verify implements intrinsics.IntrinsicOperation.
func (p *ProverConfirm) Verify(frameNumber uint64) (bool, error) {
	// Create confirm message contents
	confirmMessage := bytes.Buffer{}

	// Add filter
	confirmMessage.Write(p.Filter)

	// Add frame number
	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, p.FrameNumber)
	confirmMessage.Write(frameNumberBytes)

	// Create the domain for the signature
	confirmDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("PROVER_CONFIRM"),
	)
	confirmDomain, err := poseidon.HashBytes(confirmDomainPreimage)
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	_, err = p.hypergraph.GetVertex([64]byte(slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		p.PublicKeySignatureBLS48581.Address,
	)))
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	tree, err := p.hypergraph.GetVertexData([64]byte(slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		p.PublicKeySignatureBLS48581.Address,
	)))
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	pubkey, err := p.rdfMultiprover.Get(
		GLOBAL_RDF_SCHEMA,
		"prover:Prover",
		"PublicKey",
		tree,
	)
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	// Calculate allocation address to verify it exists
	allocationAddressBI, err := poseidon.HashBytes(
		slices.Concat([]byte("PROVER_ALLOCATION"), pubkey, p.Filter),
	)
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}
	allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))
	allocationFullAddress := [64]byte{}
	copy(allocationFullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(allocationFullAddress[32:], allocationAddress)

	// Get allocation vertex
	allocationTree, err := p.hypergraph.GetVertexData(allocationFullAddress)
	if err != nil || allocationTree == nil {
		return false, errors.Wrap(
			errors.New("allocation not found"),
			"verify",
		)
	}

	// Check current allocation status
	statusBytes, err := p.rdfMultiprover.Get(
		GLOBAL_RDF_SCHEMA,
		"allocation:ProverAllocation",
		"Status",
		allocationTree,
	)
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	status := uint8(0)
	if len(statusBytes) > 0 {
		status = statusBytes[0]
	}

	// Can only confirm if allocation is in joining (0) or leaving (3) state
	if status != 0 && status != 3 {
		return false, errors.Wrap(
			errors.New("invalid allocation state for confirmation"),
			"verify",
		)
	}

	if status == 0 {
		// Confirming join
		// Get join frame number
		joinFrameBytes, err := p.rdfMultiprover.Get(
			GLOBAL_RDF_SCHEMA,
			"allocation:ProverAllocation",
			"JoinFrameNumber",
			allocationTree,
		)
		if err != nil || len(joinFrameBytes) != 8 {
			return false, errors.Wrap(errors.New("missing join frame"), "verify")
		}
		joinFrame := binary.BigEndian.Uint64(joinFrameBytes)

		// Check timing constraints
		if joinFrame < 252840 {
			if frameNumber < 252840 {
				// If joined before frame 252840, cannot confirm until frame 252840
				return false, errors.Wrap(
					errors.New("cannot confirm before frame 252840"),
					"verify",
				)
			}

			// Set this to either 252840 - 360 or the raw join frame if higher than it
			// so the provers before can immeidately join after the wait, those after
			// still have the full 360.
			if joinFrame < 252480 {
				joinFrame = 252480
			}
		}

		// For joins before 252840, once we reach frame 252840, they can confirm
		// immediately, for joins after 252840, normal 360 frame wait applies
		if joinFrame >= 252480 {
			framesSinceJoin := frameNumber - joinFrame
			if framesSinceJoin < 360 {
				return false, errors.Wrap(
					fmt.Errorf(
						"must wait 360 frames after join to confirm (%d)",
						framesSinceJoin,
					),
					"verify",
				)
			}
			if framesSinceJoin > 720 {
				return false, errors.Wrap(
					errors.New("confirmation window expired (720 frames)"),
					"verify",
				)
			}
		}
	} else if status == 3 {
		// Confirming leave
		// Get leave frame number
		leaveFrameBytes, err := p.rdfMultiprover.Get(
			GLOBAL_RDF_SCHEMA,
			"allocation:ProverAllocation",
			"LeaveFrameNumber",
			allocationTree,
		)
		if err != nil || len(leaveFrameBytes) != 8 {
			return false, errors.Wrap(errors.New("missing leave frame"), "verify")
		}
		leaveFrame := binary.BigEndian.Uint64(leaveFrameBytes)

		framesSinceLeave := frameNumber - leaveFrame
		if framesSinceLeave < 360 {
			return false, errors.Wrap(
				errors.New("must wait 360 frames after leave to confirm"),
				"verify",
			)
		}
		if framesSinceLeave > 720 {
			return false, errors.Wrap(
				errors.New("leave confirmation window expired (720 frames)"),
				"verify",
			)
		}
	}

	// Verify the signature
	valid, err := p.keyManager.ValidateSignature(
		crypto.KeyTypeBLS48581G1,
		pubkey,
		confirmMessage.Bytes(),
		p.PublicKeySignatureBLS48581.Signature,
		confirmDomain.Bytes(),
	)
	if err != nil || !valid {
		return false, errors.Wrap(errors.New("invalid signature"), "verify")
	}

	return true, nil
}

var _ intrinsics.IntrinsicOperation = (*ProverConfirm)(nil)
