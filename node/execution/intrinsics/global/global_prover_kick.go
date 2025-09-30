package global

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type ProverKick struct {
	// The frame number when this request is made
	FrameNumber uint64
	// The public key of the prover being kicked
	KickedProverPublicKey []byte
	// The first conflicting frame header (raw bytes)
	ConflictingFrame1 []byte
	// The second conflicting frame header (raw bytes)
	ConflictingFrame2 []byte
	// The commitment of the proof
	Commitment []byte
	// The multiprover proof for PublicKey and Status fields
	Proof []byte
	// The traversal proof of the hypergraph for the prover state
	TraversalProof *tries.TraversalProof

	// Private fields
	blsConstructor crypto.BlsConstructor
	frameProver    crypto.FrameProver
	hypergraph     hypergraph.Hypergraph
	rdfMultiprover *schema.RDFMultiprover
	proverRegistry consensus.ProverRegistry
}

func NewProverKick(
	frameNumber uint64,
	kickedProverPublicKey []byte,
	conflictingFrame1 []byte,
	conflictingFrame2 []byte,
	blsConstructor crypto.BlsConstructor,
	frameProver crypto.FrameProver,
	hypergraph hypergraph.Hypergraph,
	rdfMultiprover *schema.RDFMultiprover,
	proverRegistry consensus.ProverRegistry,
) (*ProverKick, error) {
	return &ProverKick{
		FrameNumber:           frameNumber,
		KickedProverPublicKey: kickedProverPublicKey,
		ConflictingFrame1:     conflictingFrame1,
		ConflictingFrame2:     conflictingFrame2,
		blsConstructor:        blsConstructor,
		frameProver:           frameProver,
		hypergraph:            hypergraph,
		rdfMultiprover:        rdfMultiprover,
		proverRegistry:        proverRegistry,
	}, nil
}

// GetCost implements intrinsics.IntrinsicOperation.
func (p *ProverKick) GetCost() (*big.Int, error) {
	return big.NewInt(0), nil
}

// Materialize implements intrinsics.IntrinsicOperation.
func (p *ProverKick) Materialize(
	frameNumber uint64,
	state state.State,
) (state.State, error) {
	hg := state.(*hgstate.HypergraphState)

	// Compute the kicked prover's address from their public key
	kickedAddressBI, err := poseidon.HashBytes(p.KickedProverPublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}
	kickedAddress := kickedAddressBI.FillBytes(make([]byte, 32))

	fullAddress := [64]byte{}
	copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(fullAddress[32:], kickedAddress)

	// Get the existing prover vertex
	vertex, err := hg.Get(
		fullAddress[:32],
		fullAddress[32:],
		hgstate.VertexAddsDiscriminator,
	)
	if err != nil || vertex == nil {
		return nil, errors.Wrap(
			errors.New("prover not found"),
			"materialize",
		)
	}

	var tree *tries.VectorCommitmentTree
	var ok bool
	tree, ok = vertex.(*tries.VectorCommitmentTree)
	if !ok || tree == nil {
		return nil, errors.Wrap(
			errors.New("invalid object returned for vertex"),
			"materialize",
		)
	}

	// Update status to left (4) - kicked provers are immediately removed
	err = p.rdfMultiprover.Set(
		GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover",
		"Status",
		[]byte{4},
		tree,
	)
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	// Store kick frame number
	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, p.FrameNumber)
	err = p.rdfMultiprover.Set(
		GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover",
		"KickFrameNumber",
		frameNumberBytes,
		tree,
	)
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	// Get an unmodified copy of the original prover vertex
	var prior *tries.VectorCommitmentTree
	original, err := hg.Get(
		fullAddress[:32],
		fullAddress[32:],
		hgstate.VertexAddsDiscriminator,
	)
	if err == nil && original != nil {
		prior = original.(*tries.VectorCommitmentTree)
	}

	// Update prover vertex
	proverVertex := hg.NewVertexAddMaterializedState(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		[32]byte(kickedAddress),
		frameNumber,
		prior,
		tree,
	)

	err = hg.Set(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		kickedAddress,
		hgstate.VertexAddsDiscriminator,
		frameNumber,
		proverVertex,
	)
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	// Now we need to update ALL prover allocations to kicked status
	// Get the hyperedge that connects the prover to its allocations
	hyperedgeAddress := [64]byte{}
	copy(hyperedgeAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(hyperedgeAddress[32:], kickedAddress)

	hyperedge, err := hg.Get(
		hyperedgeAddress[:32],
		hyperedgeAddress[32:],
		hgstate.HyperedgeAddsDiscriminator,
	)
	if err == nil && hyperedge != nil {
		// Get all vertices from the hyperedge
		he, ok := hyperedge.(hypergraph.Hyperedge)
		if !ok {
			return nil, errors.Wrap(
				errors.New("invalid object returned for hyperedge"),
				"materialize",
			)
		}
		vertices := tries.GetAllPreloadedLeaves(he.GetExtrinsicTree().Root)
		if err == nil && len(vertices) > 0 {
			for _, vertex := range vertices {
				allocationFullAddress := vertex.Key

				if !bytes.Equal(
					allocationFullAddress[:32],
					intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
				) {
					return nil, errors.Wrap(
						errors.New("hyperedge includes non prover allocation vertex"),
						"materialize",
					)
				}

				// Get allocation vertex
				allocationTree, err := hg.Get(
					allocationFullAddress[:32],
					allocationFullAddress[32:],
					hgstate.VertexAddsDiscriminator,
				)
				if err != nil || allocationTree == nil {
					continue
				}

				var allocTree *tries.VectorCommitmentTree
				var ok bool
				allocTree, ok = allocationTree.(*tries.VectorCommitmentTree)
				if !ok || allocTree == nil {
					return nil, errors.Wrap(
						errors.New("invalid object returned for vertex"),
						"materialize",
					)
				}

				// Update allocation status to left (4)
				err = p.rdfMultiprover.Set(
					GLOBAL_RDF_SCHEMA,
					intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
					"allocation:ProverAllocation",
					"Status",
					[]byte{4},
					allocTree,
				)
				if err != nil {
					return nil, errors.Wrap(err, "materialize")
				}

				// Store kick frame number in allocation
				err = p.rdfMultiprover.Set(
					GLOBAL_RDF_SCHEMA,
					intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
					"allocation:ProverAllocation",
					"KickFrameNumber",
					frameNumberBytes,
					allocTree,
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
				allocationVertex := hg.NewVertexAddMaterializedState(
					intrinsics.GLOBAL_INTRINSIC_ADDRESS,
					[32]byte(allocationFullAddress[32:]),
					frameNumber,
					prior,
					allocTree,
				)

				err = hg.Set(
					intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
					allocationFullAddress[32:],
					hgstate.VertexAddsDiscriminator,
					frameNumber,
					allocationVertex,
				)
				if err != nil {
					return nil, errors.Wrap(err, "materialize")
				}
			}
		}
	}

	return state, nil
}

// Prove implements intrinsics.IntrinsicOperation.
func (p *ProverKick) Prove(frameNumber uint64) error {
	address, err := poseidon.HashBytes(p.KickedProverPublicKey)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	tree, err := p.hypergraph.GetVertexData([64]byte(slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		address.FillBytes(make([]byte, 32)),
	)))
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// Obtain commitment
	p.Commitment = tree.Commit(p.hypergraph.GetProver(), false)

	p.TraversalProof, err = p.hypergraph.CreateTraversalProof(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		hypergraph.VertexAtomType,
		hypergraph.AddsPhaseType,
		[][]byte{address.FillBytes(make([]byte, 32))},
	)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// Create multiproof for PublicKey and Status fields
	fields := []string{"prover:Prover.PublicKey", "prover:Prover.Status"}
	multiproof, err := p.rdfMultiprover.ProveWithType(
		GLOBAL_RDF_SCHEMA,
		fields,
		tree,
		nil, // No type index needed for global intrinsic
	)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	multiproofBytes, err := multiproof.ToBytes()
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	p.Proof = multiproofBytes
	return nil
}

// Verify implements intrinsics.IntrinsicOperation.
func (p *ProverKick) Verify(frameNumber uint64) (bool, error) {
	// First verify the conflicting frames prove equivocation
	if !p.verifyEquivocation(p.KickedProverPublicKey) {
		return false, errors.Wrap(
			errors.New("no equivocation detected"),
			"verify",
		)
	}

	validTraversal, err := p.hypergraph.VerifyTraversalProof(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		hypergraph.VertexAtomType,
		hypergraph.AddsPhaseType,
		p.TraversalProof,
	)
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	if !validTraversal || len(p.Proof) == 0 {
		return false, errors.Wrap(errors.New("invalid multiproof"), "verify")
	}

	// Parse the multiproof
	multiproof := p.hypergraph.GetProver().NewMultiproof()
	if err := multiproof.FromBytes(p.Proof); err != nil {
		return false, errors.Wrap(err, "verify")
	}

	// Verify the proof against the tree
	fields := []string{"prover:Prover.PublicKey", "prover:Prover.Status"}
	valid, err := p.rdfMultiprover.VerifyWithType(
		GLOBAL_RDF_SCHEMA,
		fields,
		nil,
		p.Commitment,
		p.Proof,
		[][]byte{p.KickedProverPublicKey, {1}},
		nil,
		nil, // No type index needed for global intrinsic
	)
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}
	if !valid {
		return false, errors.Wrap(errors.New("invalid multiproof"), "verify")
	}

	return true, nil
}

// verifyEquivocation verifies that the two frames constitute an equivocation
func (p *ProverKick) verifyEquivocation(kickedPublicKey []byte) bool {
	if len(p.ConflictingFrame1) < 4 || len(p.ConflictingFrame2) < 4 {
		return false
	}

	// Verify types are aligned
	frame1Type := binary.BigEndian.Uint32(p.ConflictingFrame1[:4])
	frame2Type := binary.BigEndian.Uint32(p.ConflictingFrame2[:4])

	if frame1Type != frame2Type {
		return false
	}

	// Frames must be different
	if bytes.Equal(p.ConflictingFrame1, p.ConflictingFrame2) {
		return false
	}

	// Parse frame headers and extract relevant details
	var frameNumber1, frameNumber2 uint64
	var filter1, filter2 []byte
	var output1, output2 []byte
	var signature1, signature2 *protobufs.BLS48581AggregateSignature

	switch frame1Type {
	case protobufs.FrameHeaderType:
		frame1 := &protobufs.FrameHeader{}
		frame2 := &protobufs.FrameHeader{}
		if err := frame1.FromCanonicalBytes(p.ConflictingFrame1); err != nil {
			return false
		}
		if err := frame2.FromCanonicalBytes(p.ConflictingFrame2); err != nil {
			return false
		}

		frameNumber1 = frame1.FrameNumber
		frameNumber2 = frame2.FrameNumber
		output1 = frame1.Output
		output2 = frame2.Output
		filter1 = frame1.Address
		filter2 = frame2.Address

		// Both frames must have BLS signatures
		if frame1.PublicKeySignatureBls48581 == nil ||
			frame2.PublicKeySignatureBls48581 == nil {
			return false
		}

		valid, err := p.frameProver.VerifyFrameHeaderSignature(
			frame1,
			p.blsConstructor,
		)
		if !valid || err != nil {
			return false
		}

		valid, err = p.frameProver.VerifyFrameHeaderSignature(
			frame2,
			p.blsConstructor,
		)
		if !valid || err != nil {
			return false
		}

		signature1 = frame1.PublicKeySignatureBls48581
		signature2 = frame2.PublicKeySignatureBls48581
	case protobufs.GlobalFrameHeaderType:
		frame1 := &protobufs.GlobalFrameHeader{}
		frame2 := &protobufs.GlobalFrameHeader{}
		if err := frame1.FromCanonicalBytes(p.ConflictingFrame1); err != nil {
			return false
		}
		if err := frame2.FromCanonicalBytes(p.ConflictingFrame2); err != nil {
			return false
		}

		if frame1 == nil || frame2 == nil {
			return false
		}

		frameNumber1 = frame1.FrameNumber
		frameNumber2 = frame2.FrameNumber
		output1 = frame1.Output
		output2 = frame2.Output
		filter1 = []byte{}
		filter2 = []byte{}

		// Both frames must have BLS signatures
		if frame1.PublicKeySignatureBls48581 == nil ||
			frame2.PublicKeySignatureBls48581 == nil {
			return false
		}

		valid, err := p.frameProver.VerifyGlobalHeaderSignature(
			frame1,
			p.blsConstructor,
		)
		if !valid || err != nil {
			return false
		}

		valid, err = p.frameProver.VerifyGlobalHeaderSignature(
			frame2,
			p.blsConstructor,
		)
		if !valid || err != nil {
			return false
		}

		signature1 = frame1.PublicKeySignatureBls48581
		signature2 = frame2.PublicKeySignatureBls48581
	}

	// Verify the frame number matches
	if frameNumber1 != frameNumber2 {
		return false
	}

	// Verify the address matches
	if !bytes.Equal(filter1, filter2) {
		return false
	}

	// Verify the output doesn't match
	if bytes.Equal(output1, output2) {
		return false
	}

	// Check for overlapping signatures in the bitmasks
	bitmask1 := signature1.Bitmask
	bitmask2 := signature2.Bitmask

	maxLen := len(bitmask1)
	if len(bitmask2) > maxLen {
		maxLen = len(bitmask2)
	}

	proverAddrBI, _ := poseidon.HashBytes(kickedPublicKey)
	proverAddr := proverAddrBI.FillBytes(make([]byte, 32))

	info, err := p.proverRegistry.GetActiveProvers(filter1)
	if err != nil {
		return false
	}

	index := -1
	for i, inf := range info {
		if bytes.Equal(inf.Address, proverAddr) {
			index = i
			break
		}
	}

	if index == -1 {
		return false
	}

	hasOverlap := false
	byteIndex := index / 8
	bitIndex := index % 8
	var b1, b2 byte
	if byteIndex < len(bitmask1) {
		b1 = bitmask1[byteIndex]
	}
	if byteIndex < len(bitmask2) {
		b2 = bitmask2[byteIndex]
	}
	b := byte(1 << bitIndex)
	if b&b1 != 0 && b&b2 != 0 {
		hasOverlap = true
	}

	// For an equivocation, there must be overlapping signers
	return hasOverlap
}

var _ intrinsics.IntrinsicOperation = (*ProverKick)(nil)
