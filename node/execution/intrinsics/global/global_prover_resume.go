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

type ProverResume struct {
	// The filter representing the resume request
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

func NewProverResume(
	filter []byte,
	frameNumber uint64,
	keyManager keys.KeyManager,
	hypergraph hypergraph.Hypergraph,
	rdfMultiprover *schema.RDFMultiprover,
) (*ProverResume, error) {
	return &ProverResume{
		Filter:         filter,
		FrameNumber:    frameNumber,
		keyManager:     keyManager,
		hypergraph:     hypergraph,
		rdfMultiprover: rdfMultiprover,
	}, nil
}

// GetCost implements intrinsics.IntrinsicOperation.
func (p *ProverResume) GetCost() (*big.Int, error) {
	return big.NewInt(0), nil
}

// Materialize implements intrinsics.IntrinsicOperation.
func (p *ProverResume) Materialize(
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

	// Update allocation status back to active (1)
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

	// Store resume frame number
	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, p.FrameNumber)
	err = p.rdfMultiprover.Set(
		GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"ResumeFrameNumber",
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
func (p *ProverResume) Prove(frameNumber uint64) error {
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

	// Create resume message contents
	resumeMessage := bytes.Buffer{}

	// Add filter
	resumeMessage.Write(p.Filter)

	// Add frame number
	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, p.FrameNumber)
	resumeMessage.Write(frameNumberBytes)

	// Create the domain for the signature
	resumeDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("PROVER_RESUME"),
	)
	resumeDomain, err := poseidon.HashBytes(resumeDomainPreimage)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// Create signature over the resume message with the resume domain
	signature, err := prover.SignWithDomain(
		resumeMessage.Bytes(),
		resumeDomain.Bytes(),
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

func (p *ProverResume) GetReadAddresses(frameNumber uint64) ([][]byte, error) {
	return nil, nil
}

func (p *ProverResume) GetWriteAddresses(frameNumber uint64) ([][]byte, error) {
	proverAddress := p.PublicKeySignatureBLS48581.Address
	proverFullAddress := [64]byte{}
	copy(proverFullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(proverFullAddress[32:], proverAddress)

	// Get the existing prover vertex
	proverTree, err := p.hypergraph.GetVertexData(proverFullAddress)
	if err != nil || proverTree == nil {
		return nil, errors.Wrap(
			errors.New("prover not found"),
			"get write addresses",
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
		return nil, errors.Wrap(err, "get write addresses")
	}

	// Calculate allocation address:
	allocationAddressBI, err := poseidon.HashBytes(
		slices.Concat([]byte("PROVER_ALLOCATION"), publicKey, p.Filter),
	)
	if err != nil {
		return nil, errors.Wrap(err, "get write addresses")
	}

	allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))
	allocationFullAddress := [64]byte{}
	copy(allocationFullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(allocationFullAddress[32:], allocationAddress)

	addresses := map[string]struct{}{}
	addresses[string(proverFullAddress[:])] = struct{}{}
	addresses[string(allocationFullAddress[:])] = struct{}{}

	result := [][]byte{}
	for key := range addresses {
		result = append(result, []byte(key))
	}

	return result, nil
}

// Verify implements intrinsics.IntrinsicOperation.
func (p *ProverResume) Verify(frameNumber uint64) (bool, error) {
	// Create resume message contents
	resumeMessage := bytes.Buffer{}

	// Add filter
	resumeMessage.Write(p.Filter)

	// Add frame number
	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, p.FrameNumber)
	resumeMessage.Write(frameNumberBytes)

	// Create the domain for the signature
	// Poseidon hash of GLOBAL_INTRINSIC_ADDRESS concatenated with "PROVER_RESUME"
	resumeDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("PROVER_RESUME"),
	)
	resumeDomain, err := poseidon.HashBytes(resumeDomainPreimage)
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

	// Calculate allocation address to verify it exists and is paused
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

	// Can only resume if allocation is in paused (2) state
	if status != 2 {
		return false, errors.Wrap(
			errors.New("can only resume when allocation is paused"),
			"verify",
		)
	}

	// Get pause frame number
	pauseFrameBytes, err := p.rdfMultiprover.Get(
		GLOBAL_RDF_SCHEMA,
		"allocation:ProverAllocation",
		"PauseFrameNumber",
		allocationTree,
	)
	if err != nil || len(pauseFrameBytes) != 8 {
		return false, errors.Wrap(errors.New("missing pause frame"), "verify")
	}
	pauseFrame := binary.BigEndian.Uint64(pauseFrameBytes)

	// Check if pause has timed out (360 frames)
	framesSincePause := frameNumber - pauseFrame
	if framesSincePause > 360 {
		return false, errors.Wrap(
			errors.New("pause timeout exceeded, allocation has implicitly left"),
			"verify",
		)
	}

	// Verify the signature
	valid, err := p.keyManager.ValidateSignature(
		crypto.KeyTypeBLS48581G1,
		pubkey,
		resumeMessage.Bytes(),
		p.PublicKeySignatureBLS48581.Signature,
		resumeDomain.Bytes(),
	)
	if err != nil || !valid {
		return false, errors.Wrap(errors.New("invalid signature"), "verify")
	}

	return true, nil
}

var _ intrinsics.IntrinsicOperation = (*ProverResume)(nil)
