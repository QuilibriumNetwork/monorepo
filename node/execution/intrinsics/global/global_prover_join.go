package global

import (
	"encoding/binary"
	"math/big"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global/compat"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type BLS48581SignatureWithProofOfPossession struct {
	// The BLS48-581 public key of the signer
	PublicKey []byte
	// The BLS48-581 signature
	Signature []byte
	// The Proof of Possession of public key signature
	PopSignature []byte
}

type SeniorityMerge struct {
	// The key type, used to distinguish old Ed448 keys vs BLS48-581 keys
	KeyType crypto.KeyType
	// The public key of the merge source
	PublicKey []byte
	// The signature of the public key
	Signature []byte

	// Private fields
	signer crypto.Signer
}

func NewSeniorityMerge(
	keyType crypto.KeyType,
	signer crypto.Signer,
) *SeniorityMerge {
	return &SeniorityMerge{
		KeyType:   keyType,
		PublicKey: signer.Public().([]byte),
		signer:    signer,
	}
}

type ProverJoin struct {
	// The filters representing the join request (can be multiple)
	Filters [][]byte
	// The frame number when this request is made
	FrameNumber uint64
	// The public key signature with proof of possession for BLS48581
	PublicKeySignatureBLS48581 BLS48581SignatureWithProofOfPossession
	// Any optional merge targets for seniority
	MergeTargets []*SeniorityMerge
	// The optional delegated address for rewards to accrue, when omitted, uses
	// the prover address
	DelegateAddress []byte

	// Private fields
	keyManager     keys.KeyManager
	hypergraph     hypergraph.Hypergraph
	rdfMultiprover *schema.RDFMultiprover
}

func NewProverJoin(
	filters [][]byte,
	frameNumber uint64,
	mergeTargets []*SeniorityMerge,
	delegateAddress []byte,
	keyManager keys.KeyManager,
	hypergraph hypergraph.Hypergraph,
	rdfMultiprover *schema.RDFMultiprover,
) (*ProverJoin, error) {
	return &ProverJoin{
		Filters:         filters,
		FrameNumber:     frameNumber,
		MergeTargets:    mergeTargets,
		DelegateAddress: delegateAddress,
		keyManager:      keyManager,
		hypergraph:      hypergraph,
		rdfMultiprover:  rdfMultiprover,
	}, nil
}

// GetCost implements intrinsics.IntrinsicOperation.
func (p *ProverJoin) GetCost() (*big.Int, error) {
	return big.NewInt(0), nil
}

// Materialize implements intrinsics.IntrinsicOperation.
func (p *ProverJoin) Materialize(
	frameNumber uint64,
	state state.State,
) (state.State, error) {
	hg := state.(*hgstate.HypergraphState)

	publicKey := p.PublicKeySignatureBLS48581.PublicKey
	proverAddressBI, err := poseidon.HashBytes(publicKey)
	if err != nil || proverAddressBI == nil {
		return nil, errors.Wrap(errors.New("invalid address"), "materialize")
	}
	proverAddress := proverAddressBI.FillBytes(make([]byte, 32))

	// Full address for the prover entry
	proverFullAddress := [64]byte{}
	copy(proverFullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(proverFullAddress[32:], proverAddress)

	// Check if prover already exists
	vertex, err := hg.Get(
		proverFullAddress[:32],
		proverFullAddress[32:],
		hgstate.VertexAddsDiscriminator,
	)
	proverExists := err == nil

	var proverTree *tries.VectorCommitmentTree
	if proverExists {
		var ok bool
		proverTree, ok = vertex.(*tries.VectorCommitmentTree)
		if !ok || proverTree == nil {
			return nil, errors.Wrap(
				errors.New("invalid object returned for vertex"),
				"materialize",
			)
		}
	}

	if !proverExists {
		// Create new prover entry
		proverTree = &qcrypto.VectorCommitmentTree{}

		// Store the public key
		err = p.rdfMultiprover.Set(
			GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"prover:Prover",
			"PublicKey",
			publicKey,
			proverTree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Store status (0 = joining since we have allocations joining)
		err = p.rdfMultiprover.Set(
			GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"prover:Prover",
			"Status",
			[]byte{0},
			proverTree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Store available storage (initially 0)
		availableStorageBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(availableStorageBytes, 0)
		err = p.rdfMultiprover.Set(
			GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"prover:Prover",
			"AvailableStorage",
			availableStorageBytes,
			proverTree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Calculate seniority from MergeTargets
		var seniority uint64 = 0
		if len(p.MergeTargets) > 0 {
			// Convert Ed448 public keys to peer IDs
			var peerIds []string
			for _, target := range p.MergeTargets {
				if target.KeyType == crypto.KeyTypeEd448 {
					pk, err := pcrypto.UnmarshalEd448PublicKey(target.PublicKey)
					if err != nil {
						return nil, errors.Wrap(err, "materialize")
					}

					peerId, err := peer.IDFromPublicKey(pk)
					if err != nil {
						return nil, errors.Wrap(err, "materialize")
					}

					peerIds = append(peerIds, peerId.String())
				}
			}

			// Get aggregated seniority
			if len(peerIds) > 0 {
				seniorityBig := compat.GetAggregatedSeniority(peerIds)
				if seniorityBig.IsUint64() {
					seniority = seniorityBig.Uint64()
				}
			}
		}

		// Store seniority
		seniorityBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(seniorityBytes, seniority)
		err = p.rdfMultiprover.Set(
			GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"prover:Prover",
			"Seniority",
			seniorityBytes,
			proverTree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Create prover vertex
		proverVertex := hg.NewVertexAddMaterializedState(
			intrinsics.GLOBAL_INTRINSIC_ADDRESS,
			[32]byte(proverAddress),
			frameNumber,
			nil,
			proverTree,
		)

		err = hg.Set(
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			proverAddress,
			hgstate.VertexAddsDiscriminator,
			frameNumber,
			proverVertex,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Create ProverReward entry in QUIL token address with zero balance
		rewardTree := &qcrypto.VectorCommitmentTree{}
		delegateAddress := proverAddress
		if len(p.DelegateAddress) == 32 {
			delegateAddress = p.DelegateAddress
		}

		err = p.rdfMultiprover.Set(
			GLOBAL_RDF_SCHEMA,
			token.QUIL_TOKEN_ADDRESS,
			"reward:ProverReward",
			"DelegateAddress",
			delegateAddress,
			rewardTree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Set zero balance
		zeroBalance := make([]byte, 32)
		err = p.rdfMultiprover.Set(
			GLOBAL_RDF_SCHEMA,
			token.QUIL_TOKEN_ADDRESS,
			"reward:ProverReward",
			"Balance",
			zeroBalance,
			rewardTree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Create reward vertex in QUIL token address
		rewardVertex := hg.NewVertexAddMaterializedState(
			[32]byte(token.QUIL_TOKEN_ADDRESS),
			[32]byte(proverAddress),
			frameNumber,
			nil,
			rewardTree,
		)

		err = hg.Set(
			token.QUIL_TOKEN_ADDRESS,
			proverAddress,
			hgstate.VertexAddsDiscriminator,
			frameNumber,
			rewardVertex,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}
	}

	// Create hyperedge for this prover
	hyperedgeAddress := [32]byte(proverAddress)
	hyperedge := hgcrdt.NewHyperedge(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		hyperedgeAddress,
	)

	// Get existing hyperedge if it exists
	existingHyperedge, err := hg.Get(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		hyperedgeAddress[:],
		hgstate.HyperedgeAddsDiscriminator,
	)
	if err == nil && existingHyperedge != nil {
		// Use existing hyperedge
		var ok bool
		hyperedge, ok = existingHyperedge.(hypergraph.Hyperedge)
		if !ok {
			return nil, errors.Wrap(
				errors.New("invalid object returned for hyperedge"),
				"materialize",
			)
		}
	}

	// Create ProverAllocation entries for each filter
	for _, filter := range p.Filters {
		// Calculate allocation address: poseidon.Hash(publicKey || filter)
		allocationAddressBI, err := poseidon.HashBytes(
			slices.Concat([]byte("PROVER_ALLOCATION"), publicKey, filter),
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}
		allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))

		// Create allocation tree
		allocationTree := &qcrypto.VectorCommitmentTree{}

		// Store prover reference
		err = p.rdfMultiprover.Set(
			GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"allocation:ProverAllocation",
			"Prover",
			slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], proverAddress),
			allocationTree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Store allocation status (0 = joining)
		err = p.rdfMultiprover.Set(
			GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"allocation:ProverAllocation",
			"Status",
			[]byte{0},
			allocationTree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Store confirmation filter
		err = p.rdfMultiprover.Set(
			GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"allocation:ProverAllocation",
			"ConfirmationFilter",
			filter,
			allocationTree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Store join frame number
		frameNumberBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(frameNumberBytes, p.FrameNumber)
		err = p.rdfMultiprover.Set(
			GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"allocation:ProverAllocation",
			"JoinFrameNumber",
			frameNumberBytes,
			allocationTree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
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
		allocationVertex := hg.NewVertexAddMaterializedState(
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
			allocationVertex,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Add allocation vertex to hyperedge
		hyperedge.AddExtrinsic(allocationVertex.GetVertex())
	}

	var priorHyperedge *tries.VectorCommitmentTree
	previousHyperedge, err := hg.Get(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		hyperedgeAddress[:],
		hgstate.HyperedgeAddsDiscriminator,
	)
	if err == nil && previousHyperedge != nil {
		// Use existing hyperedge
		var ok bool
		prior, ok := previousHyperedge.(hypergraph.Hyperedge)
		if !ok {
			return nil, errors.Wrap(
				errors.New("invalid object returned for hyperedge"),
				"materialize",
			)
		}
		priorHyperedge = prior.GetExtrinsicTree()
	}

	// Update hyperedge
	hyperedgeState := hg.NewHyperedgeAddMaterializedState(
		frameNumber,
		priorHyperedge,
		hyperedge,
	)
	err = hg.Set(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		hyperedgeAddress[:],
		hgstate.HyperedgeAddsDiscriminator,
		frameNumber,
		hyperedgeState,
	)
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	return state, nil
}

// Prove implements intrinsics.IntrinsicOperation.
func (p *ProverJoin) Prove(frameNumber uint64) error {
	// Get the q-prover-key
	prover, err := p.keyManager.GetSigningKey("q-prover-key")
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	for _, mt := range p.MergeTargets {
		if mt.signer != nil {
			mt.Signature, err = mt.signer.SignWithDomain(
				p.PublicKeySignatureBLS48581.PublicKey,
				[]byte("PROVER_JOIN_MERGE"),
			)
			if err != nil {
				return errors.Wrap(err, "prove")
			}
		}
	}

	joinClone := p.ToProtobuf()
	joinClone.PublicKeySignatureBls48581 = nil
	joinMessage, err := joinClone.ToCanonicalBytes()
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// Create the domain for the first signature
	// Poseidon hash of GLOBAL_INTRINSIC_ADDRESS concatenated with "PROVER_JOIN"
	joinDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("PROVER_JOIN"),
	)
	joinDomain, err := poseidon.HashBytes(joinDomainPreimage)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// Create first signature over the join message with the join domain
	signature, err := prover.SignWithDomain(
		joinMessage,
		joinDomain.FillBytes(make([]byte, 32)),
	)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// Create the domain for the proof of possession
	popDomain := []byte("BLS48_POP_SK")

	// Create the proof of possession signature over the public key with the POP
	// domain
	popSignature, err := prover.SignWithDomain(
		prover.Public().([]byte),
		popDomain,
	)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// Create the BLS48581SignatureWithProofOfPossession
	p.PublicKeySignatureBLS48581 = BLS48581SignatureWithProofOfPossession{
		Signature:    signature,
		PublicKey:    prover.Public().([]byte),
		PopSignature: popSignature,
	}

	return nil
}

// Verify implements intrinsics.IntrinsicOperation.
func (p *ProverJoin) Verify(frameNumber uint64) (bool, error) {
	// First check if prover can join (not in tree or in left state)
	addressBI, err := poseidon.HashBytes(p.PublicKeySignatureBLS48581.PublicKey)
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}
	address := addressBI.FillBytes(make([]byte, 32))

	for _, filter := range p.Filters {
		if len(filter) < 32 {
			return false, errors.Wrap(errors.New("invalid filter size"), "verify")
		}
	}

	// Create composite address: GLOBAL_INTRINSIC_ADDRESS + prover address
	fullAddress := [64]byte{}
	copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(fullAddress[32:], address)

	// Get the existing prover vertex data
	vertexData, err := p.hypergraph.GetVertexData(fullAddress)
	if err == nil && vertexData != nil {
		// Prover exists, check if they're in left state (4)
		tree := vertexData

		// Check if prover is in left state (4)
		statusData, err := p.rdfMultiprover.Get(
			GLOBAL_RDF_SCHEMA,
			"prover:Prover",
			"Status",
			tree,
		)
		if err == nil && len(statusData) > 0 {
			status := statusData[0]
			if status != 4 {
				// Prover is in some other state - cannot join
				return false, errors.Wrap(
					errors.New("prover already exists in non-left state"),
					"verify",
				)
			}
		}
	}

	// If we get here, either prover doesn't exist or is in left state - both are
	// valid

	joinClone := p.ToProtobuf()
	joinClone.PublicKeySignatureBls48581 = nil
	joinMessage, err := joinClone.ToCanonicalBytes()
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	// Create the domain for the first signature
	// Poseidon hash of GLOBAL_INTRINSIC_ADDRESS concatenated with "PROVER_JOIN"
	joinDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("PROVER_JOIN"),
	)
	joinDomain, err := poseidon.HashBytes(joinDomainPreimage)
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	// Create the domain for the proof of possession
	popDomain := []byte("BLS48_POP_SK")

	// Verify the signature
	valid, err := p.keyManager.ValidateSignature(
		crypto.KeyTypeBLS48581G1,
		p.PublicKeySignatureBLS48581.PublicKey,
		joinMessage,
		p.PublicKeySignatureBLS48581.Signature,
		joinDomain.Bytes(),
	)
	if err != nil || !valid {
		return false, errors.Wrap(errors.New("invalid signature"), "verify")
	}

	// Verify the proof of possession
	valid, err = p.keyManager.ValidateSignature(
		crypto.KeyTypeBLS48581G1,
		p.PublicKeySignatureBLS48581.PublicKey,
		p.PublicKeySignatureBLS48581.PublicKey,
		p.PublicKeySignatureBLS48581.PopSignature,
		popDomain,
	)
	if err != nil || !valid {
		return false, errors.Wrap(errors.New("invalid pop signature"), "verify")
	}

	// Verify any merge signatures
	for _, mt := range p.MergeTargets {
		valid, err := p.keyManager.ValidateSignature(
			mt.KeyType,
			mt.PublicKey,
			p.PublicKeySignatureBLS48581.PublicKey,
			mt.Signature,
			[]byte("PROVER_JOIN_MERGE"),
		)
		if err != nil || !valid {
			return false, errors.Wrap(errors.New("invalid merge signature"), "verify")
		}
	}

	return true, nil
}

var _ intrinsics.IntrinsicOperation = (*ProverJoin)(nil)
