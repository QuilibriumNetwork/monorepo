package global

import (
	"bytes"
	"encoding/binary"
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

type ProverLeave struct {
	// The filters representing the leave request (can be multiple)
	Filters [][]byte
	// The frame number when this request is made
	FrameNumber uint64
	// The BLS48581 addressed signature
	PublicKeySignatureBLS48581 BLS48581AddressedSignature

	// Private fields
	keyManager     keys.KeyManager
	hypergraph     hypergraph.Hypergraph
	rdfMultiprover *schema.RDFMultiprover
}

func NewProverLeave(
	filters [][]byte,
	frameNumber uint64,
	keyManager keys.KeyManager,
	hypergraph hypergraph.Hypergraph,
	rdfMultiprover *schema.RDFMultiprover,
) (*ProverLeave, error) {
	return &ProverLeave{
		Filters:        filters,
		FrameNumber:    frameNumber,
		keyManager:     keyManager,
		hypergraph:     hypergraph,
		rdfMultiprover: rdfMultiprover,
	}, nil
}

// GetCost implements intrinsics.IntrinsicOperation.
func (p *ProverLeave) GetCost() (*big.Int, error) {
	return big.NewInt(0), nil
}

// Materialize implements intrinsics.IntrinsicOperation.
func (p *ProverLeave) Materialize(
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

	// Get prover public key for allocation lookups
	publicKey, err := p.rdfMultiprover.Get(
		GLOBAL_RDF_SCHEMA,
		"prover:Prover",
		"PublicKey",
		proverTree,
	)
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	// Update allocations for each filter
	for _, filter := range p.Filters {
		// Calculate allocation address:
		allocationAddressBI, err := poseidon.HashBytes(
			slices.Concat([]byte("PROVER_ALLOCATION"), publicKey, filter),
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
			// Skip if allocation doesn't exist
			continue
		}

		var allocationTree *tries.VectorCommitmentTree
		allocationTree, ok = allocationVertex.(*tries.VectorCommitmentTree)
		if !ok || allocationTree == nil {
			// Skip if invalid type
			continue
		}

		// Update allocation status to leaving (3)
		err = p.rdfMultiprover.Set(
			GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"allocation:ProverAllocation",
			"Status",
			[]byte{3},
			allocationTree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Store leave frame number
		frameNumberBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(frameNumberBytes, p.FrameNumber)
		err = p.rdfMultiprover.Set(
			GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"allocation:ProverAllocation",
			"LeaveFrameNumber",
			frameNumberBytes,
			allocationTree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Get a copy of the original allocation tree for change tracking
		var prior *tries.VectorCommitmentTree
		originalAllocationVertex, err := hg.Get(
			allocationFullAddress[:32],
			allocationFullAddress[32:],
			hgstate.VertexAddsDiscriminator,
		)
		if err == nil && originalAllocationVertex != nil {
			prior = originalAllocationVertex.(*tries.VectorCommitmentTree)
		}

		// Update allocation vertex
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
func (p *ProverLeave) Prove(frameNumber uint64) error {
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

	// Create leave message contents
	leaveMessage := bytes.Buffer{}

	// Add number of filters
	numFiltersBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(numFiltersBytes, uint32(len(p.Filters)))
	leaveMessage.Write(numFiltersBytes)

	// Add each filter
	for _, filter := range p.Filters {
		filterLenBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(filterLenBytes, uint32(len(filter)))
		leaveMessage.Write(filterLenBytes)
		leaveMessage.Write(filter)
	}

	// Add frame number
	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, p.FrameNumber)
	leaveMessage.Write(frameNumberBytes)

	// Create the domain for the signature
	// Poseidon hash of GLOBAL_INTRINSIC_ADDRESS concatenated with "PROVER_LEAVE"
	leaveDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("PROVER_LEAVE"),
	)
	leaveDomain, err := poseidon.HashBytes(leaveDomainPreimage)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// Create signature over the leave message with the leave domain
	signature, err := prover.SignWithDomain(
		leaveMessage.Bytes(),
		leaveDomain.Bytes(),
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
func (p *ProverLeave) Verify(frameNumber uint64) (bool, error) {
	// Create leave message contents
	leaveMessage := bytes.Buffer{}

	// Add number of filters
	numFiltersBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(numFiltersBytes, uint32(len(p.Filters)))
	leaveMessage.Write(numFiltersBytes)

	// Add each filter
	for _, filter := range p.Filters {
		filterLenBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(filterLenBytes, uint32(len(filter)))
		leaveMessage.Write(filterLenBytes)
		leaveMessage.Write(filter)
	}

	// Add frame number
	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, p.FrameNumber)
	leaveMessage.Write(frameNumberBytes)

	// Create the domain for the signature
	// Poseidon hash of GLOBAL_INTRINSIC_ADDRESS concatenated with "PROVER_LEAVE"
	leaveDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("PROVER_LEAVE"),
	)
	leaveDomain, err := poseidon.HashBytes(leaveDomainPreimage)
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

	// Check that at least one allocation exists and is active
	hasActiveAllocation := false
	for _, filter := range p.Filters {
		// Calculate allocation address
		allocationAddressBI, err := poseidon.HashBytes(
			slices.Concat([]byte("PROVER_ALLOCATION"), pubkey, filter),
		)
		if err != nil {
			continue
		}

		allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))

		allocationFullAddress := [64]byte{}
		copy(allocationFullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(allocationFullAddress[32:], allocationAddress)

		// Try to get allocation
		allocationTree, err := p.hypergraph.GetVertexData(allocationFullAddress)
		if err != nil || allocationTree == nil {
			continue
		}

		// Check allocation status
		statusBytes, err := p.rdfMultiprover.Get(
			GLOBAL_RDF_SCHEMA,
			"allocation:ProverAllocation",
			"Status",
			allocationTree,
		)
		if err == nil && len(statusBytes) > 0 && statusBytes[0] == 1 {
			hasActiveAllocation = true
			break
		}
	}

	if !hasActiveAllocation {
		return false, errors.Wrap(
			errors.New("no active allocations found for specified filters"),
			"verify",
		)
	}

	// Verify the signature
	valid, err := p.keyManager.ValidateSignature(
		crypto.KeyTypeBLS48581G1,
		pubkey,
		leaveMessage.Bytes(),
		p.PublicKeySignatureBLS48581.Signature,
		leaveDomain.Bytes(),
	)
	if err != nil || !valid {
		return false, errors.Wrap(errors.New("invalid signature"), "verify")
	}

	return true, nil
}

var _ intrinsics.IntrinsicOperation = (*ProverLeave)(nil)
