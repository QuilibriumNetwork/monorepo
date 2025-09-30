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

type ProverPause struct {
	// The filter representing the pause request
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

func NewProverPause(
	filter []byte,
	frameNumber uint64,
	keyManager keys.KeyManager,
	hypergraph hypergraph.Hypergraph,
	rdfMultiprover *schema.RDFMultiprover,
) (*ProverPause, error) {
	return &ProverPause{
		Filter:         filter,
		FrameNumber:    frameNumber,
		keyManager:     keyManager,
		hypergraph:     hypergraph,
		rdfMultiprover: rdfMultiprover,
	}, nil
}

// GetCost implements intrinsics.IntrinsicOperation.
func (p *ProverPause) GetCost() (*big.Int, error) {
	return big.NewInt(0), nil
}

// Materialize implements intrinsics.IntrinsicOperation.
func (p *ProverPause) Materialize(
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

	// Update allocation status to paused (2)
	err = p.rdfMultiprover.Set(
		GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"Status",
		[]byte{2},
		allocationTree,
	)
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	// Store pause frame number
	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, p.FrameNumber)
	err = p.rdfMultiprover.Set(
		GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"PauseFrameNumber",
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
	updatedAllocation := hg.NewVertexAddMaterializedState(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		[32]byte(allocationFullAddress[32:]),
		frameNumber,
		prior,
		allocationTree,
	)

	err = hg.Set(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		allocationAddress,
		hgstate.VertexAddsDiscriminator,
		frameNumber,
		updatedAllocation,
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
func (p *ProverPause) Prove(frameNumber uint64) error {
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

	// Create pause message contents
	pauseMessage := bytes.Buffer{}

	// Add filter
	pauseMessage.Write(p.Filter)

	// Add frame number
	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, p.FrameNumber)
	pauseMessage.Write(frameNumberBytes)

	// Create the domain for the signature
	// Poseidon hash of GLOBAL_INTRINSIC_ADDRESS concatenated with "PROVER_PAUSE"
	pauseDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("PROVER_PAUSE"),
	)
	pauseDomain, err := poseidon.HashBytes(pauseDomainPreimage)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// Create signature over the pause message with the pause domain
	signature, err := prover.SignWithDomain(
		pauseMessage.Bytes(),
		pauseDomain.Bytes(),
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
func (p *ProverPause) Verify(frameNumber uint64) (bool, error) {
	// Create pause message contents
	pauseMessage := bytes.Buffer{}

	// Add filter
	pauseMessage.Write(p.Filter)

	// Add frame number
	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, p.FrameNumber)
	pauseMessage.Write(frameNumberBytes)

	// Create the domain for the signature
	// Poseidon hash of GLOBAL_INTRINSIC_ADDRESS concatenated with "PROVER_PAUSE"
	pauseDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("PROVER_PAUSE"),
	)
	pauseDomain, err := poseidon.HashBytes(pauseDomainPreimage)
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

	// Calculate allocation address to verify it exists and is active
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

	// Can only pause if allocation is in active (1) state
	if status != 1 {
		return false, errors.Wrap(
			errors.New("can only pause when allocation is active"),
			"verify",
		)
	}

	// Verify the signature
	valid, err := p.keyManager.ValidateSignature(
		crypto.KeyTypeBLS48581G1,
		pubkey,
		pauseMessage.Bytes(),
		p.PublicKeySignatureBLS48581.Signature,
		pauseDomain.Bytes(),
	)
	if err != nil || !valid {
		return false, errors.Wrap(errors.New("invalid signature"), "verify")
	}

	return true, nil
}

var _ intrinsics.IntrinsicOperation = (*ProverPause)(nil)
