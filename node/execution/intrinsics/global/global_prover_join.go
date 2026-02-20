package global

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
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
	"source.quilibrium.com/quilibrium/monorepo/types/store"
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
	// The proof element assuring availability and commitment of the workers
	Proof []byte

	// Private fields
	keyManager     keys.KeyManager
	hypergraph     hypergraph.Hypergraph
	rdfMultiprover *schema.RDFMultiprover
	frameProver    crypto.FrameProver
	frameStore     store.ClockStore
}

func NewProverJoin(
	filters [][]byte,
	frameNumber uint64,
	mergeTargets []*SeniorityMerge,
	delegateAddress []byte,
	keyManager keys.KeyManager,
	hypergraph hypergraph.Hypergraph,
	rdfMultiprover *schema.RDFMultiprover,
	frameProver crypto.FrameProver,
	frameStore store.ClockStore,
) (*ProverJoin, error) {
	return &ProverJoin{
		Filters:         filters, // buildutils:allow-slice-alias slice is static
		FrameNumber:     frameNumber,
		MergeTargets:    mergeTargets,    // buildutils:allow-slice-alias slice is static
		DelegateAddress: delegateAddress, // buildutils:allow-slice-alias slice is static
		keyManager:      keyManager,
		hypergraph:      hypergraph,
		rdfMultiprover:  rdfMultiprover,
		frameProver:     frameProver,
		frameStore:      frameStore,
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

	// Compute seniority from merge targets before the prover-exists check,
	// so it can be applied to both new and existing provers.
	var computedSeniority uint64 = 0
	if len(p.MergeTargets) > 0 {
		var mergePeerIds []string
		for _, target := range p.MergeTargets {
			// Check if this merge target was already consumed
			spentBI, err := poseidon.HashBytes(slices.Concat(
				[]byte("PROVER_JOIN_MERGE"),
				target.PublicKey,
			))
			if err != nil {
				return nil, errors.Wrap(err, "materialize")
			}
			v, vErr := hg.Get(
				intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
				spentBI.FillBytes(make([]byte, 32)),
				hgstate.VertexAddsDiscriminator,
			)
			if vErr == nil && v != nil {
				// Spent marker exists — check who consumed it
				spentTree, ok := v.(*tries.VectorCommitmentTree)
				if ok && spentTree != nil {
					storedAddr, getErr := p.rdfMultiprover.Get(
						GLOBAL_RDF_SCHEMA,
						"merge:SpentMerge",
						"ProverAddress",
						spentTree,
					)
					if getErr == nil && len(storedAddr) == 32 &&
						!bytes.Equal(storedAddr, proverAddress) {
						continue // consumed by a different prover
					}
				}
				// Same prover or legacy empty marker — count seniority
			}

			if target.KeyType == crypto.KeyTypeEd448 {
				pk, err := pcrypto.UnmarshalEd448PublicKey(target.PublicKey)
				if err != nil {
					return nil, errors.Wrap(err, "materialize")
				}

				peerId, err := peer.IDFromPublicKey(pk)
				if err != nil {
					return nil, errors.Wrap(err, "materialize")
				}

				mergePeerIds = append(mergePeerIds, peerId.String())
			}
		}

		if len(mergePeerIds) > 0 {
			seniorityBig := compat.GetAggregatedSeniority(mergePeerIds)
			if seniorityBig.IsUint64() {
				computedSeniority = seniorityBig.Uint64()
			}
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

		// Store seniority (computed above from merge targets)
		seniorityBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(seniorityBytes, computedSeniority)
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

		derivedRewardAddress, err := poseidon.HashBytes(
			slices.Concat(token.QUIL_TOKEN_ADDRESS[:], proverAddress),
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		err = p.rdfMultiprover.Set(
			GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
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
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
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
			[32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:]),
			[32]byte(derivedRewardAddress.FillBytes(make([]byte, 32))),
			frameNumber,
			nil,
			rewardTree,
		)

		err = hg.Set(
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			derivedRewardAddress.FillBytes(make([]byte, 32)),
			hgstate.VertexAddsDiscriminator,
			frameNumber,
			rewardVertex,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}
	} else if computedSeniority > 0 {
		// For existing provers, update seniority if merge targets provide a
		// higher value than what's currently stored.
		existingSeniorityData, err := p.rdfMultiprover.Get(
			GLOBAL_RDF_SCHEMA,
			"prover:Prover",
			"Seniority",
			proverTree,
		)
		var existingSeniority uint64 = 0
		if err == nil && len(existingSeniorityData) == 8 {
			existingSeniority = binary.BigEndian.Uint64(existingSeniorityData)
		}

		if computedSeniority > existingSeniority {
			seniorityBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(seniorityBytes, computedSeniority)
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

			updatedVertex := hg.NewVertexAddMaterializedState(
				intrinsics.GLOBAL_INTRINSIC_ADDRESS,
				[32]byte(proverAddress),
				frameNumber,
				proverTree,
				proverTree,
			)

			err = hg.Set(
				intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
				proverAddress,
				hgstate.VertexAddsDiscriminator,
				frameNumber,
				updatedVertex,
			)
			if err != nil {
				return nil, errors.Wrap(err, "materialize")
			}
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
			proverAddress,
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

	for _, mt := range p.MergeTargets {
		spentMergeBI, err := poseidon.HashBytes(slices.Concat(
			[]byte("PROVER_JOIN_MERGE"),
			mt.PublicKey,
		))
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		spentMergeAddr := spentMergeBI.FillBytes(make([]byte, 32))

		// Check existing spent marker
		var prior *tries.VectorCommitmentTree
		existing, existErr := hg.Get(
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			spentMergeAddr,
			hgstate.VertexAddsDiscriminator,
		)
		if existErr == nil && existing != nil {
			existingTree, ok := existing.(*tries.VectorCommitmentTree)
			if ok && existingTree != nil {
				storedAddr, getErr := p.rdfMultiprover.Get(
					GLOBAL_RDF_SCHEMA,
					"merge:SpentMerge",
					"ProverAddress",
					existingTree,
				)
				if getErr == nil && len(storedAddr) == 32 {
					// New format marker — already has a prover address.
					// Skip regardless of whether it's ours or another's.
					continue
				}
				// Legacy empty marker — overwrite with prover address
				prior = existingTree
			}
		}

		// Write spent marker with prover address
		spentTree := &tries.VectorCommitmentTree{}
		err = p.rdfMultiprover.Set(
			GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"merge:SpentMerge",
			"ProverAddress",
			proverAddress,
			spentTree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		spentMergeVertex := hg.NewVertexAddMaterializedState(
			intrinsics.GLOBAL_INTRINSIC_ADDRESS,
			[32]byte(spentMergeAddr),
			frameNumber,
			prior,
			spentTree,
		)

		err = hg.Set(
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			spentMergeAddr,
			hgstate.VertexAddsDiscriminator,
			frameNumber,
			spentMergeVertex,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}
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

	// Set the public key before signing merge targets, since merge target
	// signatures are over the BLS public key and Verify() checks against it.
	blsPublicKey := prover.Public().([]byte)

	for _, mt := range p.MergeTargets {
		if mt.signer != nil {
			mt.Signature, err = mt.signer.SignWithDomain(
				blsPublicKey,
				[]byte("PROVER_JOIN_MERGE"),
			)
			if err != nil {
				return errors.Wrap(err, "prove")
			}

			// Self-verify: catch key material issues before publishing
			valid, verifyErr := p.keyManager.ValidateSignature(
				mt.KeyType,
				mt.PublicKey,
				blsPublicKey,
				mt.Signature,
				[]byte("PROVER_JOIN_MERGE"),
			)
			if verifyErr != nil || !valid {
				return fmt.Errorf(
					"prove: merge target self-verify failed "+
						"(key_type=%d, pub_key_len=%d, sig_len=%d, bls_pub_len=%d, err=%v)",
					mt.KeyType, len(mt.PublicKey), len(mt.Signature),
					len(blsPublicKey), verifyErr,
				)
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
		blsPublicKey,
		popDomain,
	)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// Create the BLS48581SignatureWithProofOfPossession
	p.PublicKeySignatureBLS48581 = BLS48581SignatureWithProofOfPossession{
		Signature:    signature,
		PublicKey:    blsPublicKey,
		PopSignature: popSignature,
	}

	return nil
}

func (p *ProverJoin) GetReadAddresses(frameNumber uint64) ([][]byte, error) {
	return nil, nil
}

func (p *ProverJoin) GetWriteAddresses(frameNumber uint64) ([][]byte, error) {
	publicKey := p.PublicKeySignatureBLS48581.PublicKey
	proverAddressBI, err := poseidon.HashBytes(publicKey)
	if err != nil || proverAddressBI == nil {
		return nil, errors.Wrap(
			errors.New("invalid address"),
			"get write addresses",
		)
	}
	proverAddress := proverAddressBI.FillBytes(make([]byte, 32))

	proverFullAddress := [64]byte{}
	copy(proverFullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(proverFullAddress[32:], proverAddress)

	addresses := map[string]struct{}{}
	addresses[string(proverFullAddress[:])] = struct{}{}

	derivedRewardAddress, err := poseidon.HashBytes(
		slices.Concat(token.QUIL_TOKEN_ADDRESS[:], proverAddress),
	)
	if err != nil {
		return nil, errors.Wrap(err, "get write addresses")
	}

	addresses[string(slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		derivedRewardAddress.FillBytes(make([]byte, 32)),
	))] = struct{}{}

	for _, filter := range p.Filters {
		allocationAddressBI, err := poseidon.HashBytes(
			slices.Concat([]byte("PROVER_ALLOCATION"), publicKey, filter),
		)
		if err != nil {
			return nil, errors.Wrap(err, "get write addresses")
		}
		allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))

		addresses[string(slices.Concat(
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			allocationAddress,
		))] = struct{}{}
	}

	for _, mt := range p.MergeTargets {
		spentMergeBI, err := poseidon.HashBytes(slices.Concat(
			[]byte("PROVER_JOIN_MERGE"),
			mt.PublicKey,
		))
		if err != nil {
			return nil, errors.Wrap(err, "get write addresses")
		}

		spentAddr := spentMergeBI.FillBytes(make([]byte, 32))

		// Skip merge targets whose spent markers already contain a prover
		// address (new format). These won't be written to — either they
		// belong to this prover (already recorded) or a different one.
		// Legacy empty markers and new markers need a write lock since
		// Materialize will write them.
		if p.hypergraph != nil {
			spentFullAddr := [64]byte{}
			copy(spentFullAddr[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
			copy(spentFullAddr[32:], spentAddr)
			spentData, dataErr := p.hypergraph.GetVertexData(spentFullAddr)
			if dataErr == nil && spentData != nil {
				storedAddr, getErr := p.rdfMultiprover.Get(
					GLOBAL_RDF_SCHEMA,
					"merge:SpentMerge",
					"ProverAddress",
					spentData,
				)
				if getErr == nil && len(storedAddr) == 32 {
					// New format — won't be written to
					continue
				}
				// Legacy empty — will be overwritten, need write lock
			}
		}

		addresses[string(slices.Concat(
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			spentAddr,
		))] = struct{}{}
	}

	result := [][]byte{}
	for key := range addresses {
		result = append(result, []byte(key))
	}

	return result, nil
}

// Verify implements intrinsics.IntrinsicOperation.
func (p *ProverJoin) Verify(frameNumber uint64) (valid bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			valid = false
			err = fmt.Errorf("panic from: %v", r)
		}
	}()
	// First check if prover can join (not in tree or in left state)
	addressBI, err := poseidon.HashBytes(p.PublicKeySignatureBLS48581.PublicKey)
	if err != nil {
		return false, errors.Wrap(err, "verify: invalid prover join")
	}
	address := addressBI.FillBytes(make([]byte, 32))

	for _, filter := range p.Filters {
		if len(filter) < 32 {
			return false, errors.Wrap(errors.New("invalid filter size"), "verify: invalid prover join")
		}
	}

	if len(p.Proof)%516 != 0 || len(p.Proof)/516 != len(p.Filters) {
		return false, errors.Wrap(errors.New("proof size mismatch"), "verify: invalid prover join")
	}

	// Disallow too old of a request
	if p.FrameNumber+10 < frameNumber {
		return false, errors.Wrap(errors.New("outdated request"), "verify: invalid prover join")
	}

	frame, err := p.frameStore.GetGlobalClockFrame(p.FrameNumber)
	if err != nil {
		frames, err := p.frameStore.RangeGlobalClockFrameCandidates(
			p.FrameNumber,
			p.FrameNumber,
		)
		if err != nil {
			return false, errors.Wrap(errors.Wrap(
				err,
				fmt.Sprintf("frame number: %d", p.FrameNumber),
			), "verify: invalid prover join")
		}
		if !frames.First() || !frames.Valid() {
			return false, errors.Wrap(errors.Wrap(
				errors.New("not found"),
				fmt.Sprintf("frame number: %d", p.FrameNumber),
			), "verify: invalid prover join")
		}
		frame, err = frames.Value()
		frames.Close()
		if err != nil {
			return false, errors.Wrap(errors.Wrap(
				err,
				fmt.Sprintf("frame number: %d", p.FrameNumber),
			), "verify: invalid prover join")
		}
	}

	// Prepare challenge for verification
	challenge := sha3.Sum256(frame.Header.Output)
	ids := [][]byte{}
	for idx, filter := range p.Filters {
		ids = append(ids, slices.Concat(
			address,
			filter,
			binary.BigEndian.AppendUint32(nil, uint32(idx)),
		))
	}

	solutions := [][516]byte{}
	for i := range p.Filters {
		solutions = append(solutions, [516]byte(p.Proof[i*516:(i+1)*516]))
	}
	valid, err = p.frameProver.VerifyMultiProof(
		challenge,
		frame.Header.Difficulty,
		ids,
		solutions,
	)
	if err != nil || !valid {
		return false, errors.Wrap(errors.New("invalid multi proof"), "verify: invalid prover join")
	}

	for _, mt := range p.MergeTargets {
		spentMergeBI, err := poseidon.HashBytes(slices.Concat(
			[]byte("PROVER_JOIN_MERGE"),
			mt.PublicKey,
		))
		if err != nil {
			return false, errors.Wrap(err, "verify: invalid prover join")
		}

		spentFullAddr := [64]byte{}
		copy(spentFullAddr[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(spentFullAddr[32:], spentMergeBI.FillBytes(make([]byte, 32)))

		v, err := p.hypergraph.GetVertex(spentFullAddr)
		if err == nil && v != nil {
			// Spent marker exists — check if consumed by a different prover
			spentData, dataErr := p.hypergraph.GetVertexData(spentFullAddr)
			if dataErr == nil && spentData != nil {
				storedAddr, getErr := p.rdfMultiprover.Get(
					GLOBAL_RDF_SCHEMA,
					"merge:SpentMerge",
					"ProverAddress",
					spentData,
				)
				if getErr == nil && len(storedAddr) == 32 &&
					!bytes.Equal(storedAddr, address) {
					// Consumed by a different prover — skip
					continue
				}
			}
			// Same prover or legacy empty — validate signature below
		}

		valid, err := p.keyManager.ValidateSignature(
			mt.KeyType,
			mt.PublicKey,
			p.PublicKeySignatureBLS48581.PublicKey,
			mt.Signature,
			[]byte("PROVER_JOIN_MERGE"),
		)
		if err != nil || !valid {
			return false, errors.Wrap(
				fmt.Errorf(
					"invalid merge target signature (key_type=%d, pub_key_len=%d, sig_len=%d, bls_pub_len=%d)",
					mt.KeyType, len(mt.PublicKey), len(mt.Signature),
					len(p.PublicKeySignatureBLS48581.PublicKey),
				),
				"verify: invalid prover join",
			)
		}
	}

	// Get the existing prover vertex data
	proverAddress := [64]byte{}
	copy(proverAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(proverAddress[32:], address)
	proverVertexData, err := p.hypergraph.GetVertexData(proverAddress)
	if err == nil && proverVertexData != nil {
		tree := proverVertexData
		kickedFrame, err := p.rdfMultiprover.Get(
			GLOBAL_RDF_SCHEMA,
			"allocation:ProverAllocation",
			"KickFrameNumber",
			tree,
		)
		if err == nil && len(kickedFrame) == 8 {
			kickedFrame := binary.BigEndian.Uint64(kickedFrame)
			if kickedFrame != 0 {
				// Prover has been kicked for malicious behavior
				return false, errors.Wrap(
					errors.New("prover has been previously kicked"),
					"verify: invalid prover join",
				)
			}
		}
	}

	for _, f := range p.Filters {
		allocationAddressBI, err := poseidon.HashBytes(
			slices.Concat(
				[]byte("PROVER_ALLOCATION"),
				p.PublicKeySignatureBLS48581.PublicKey,
				f,
			),
		)
		if err != nil {
			return false, errors.Wrap(err, "verify: invalid prover join")
		}
		allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))
		// Create composite address: GLOBAL_INTRINSIC_ADDRESS + prover address
		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], allocationAddress)

		// Get the existing prover allocation vertex data
		vertexData, err := p.hypergraph.GetVertexData(fullAddress)
		if err == nil && vertexData != nil {
			// Prover exists, check if they're in left state (4)
			tree := vertexData

			// Check if prover is in left state (4)
			statusData, err := p.rdfMultiprover.Get(
				GLOBAL_RDF_SCHEMA,
				"allocation:ProverAllocation",
				"Status",
				tree,
			)
			if err == nil && len(statusData) > 0 {
				status := statusData[0]
				if status != 4 {
					// Check if the previous join/leave has implicitly expired
					// (720 frames), making the prover effectively "left"
					expired := false
					if status == 0 {
						// Joining: check if join expired
						joinFrameBytes, jErr := p.rdfMultiprover.Get(
							GLOBAL_RDF_SCHEMA,
							"allocation:ProverAllocation",
							"JoinFrameNumber",
							tree,
						)
						if jErr == nil && len(joinFrameBytes) == 8 {
							joinFrame := binary.BigEndian.Uint64(joinFrameBytes)
							if joinFrame >= token.FRAME_2_1_EXTENDED_ENROLL_END &&
								frameNumber > joinFrame+720 {
								expired = true
							}
						}
					} else if status == 3 {
						// Leaving: check if leave expired
						leaveFrameBytes, lErr := p.rdfMultiprover.Get(
							GLOBAL_RDF_SCHEMA,
							"allocation:ProverAllocation",
							"LeaveFrameNumber",
							tree,
						)
						if lErr == nil && len(leaveFrameBytes) == 8 {
							leaveFrame := binary.BigEndian.Uint64(leaveFrameBytes)
							if frameNumber > leaveFrame+720 {
								expired = true
							}
						}
					}

					if !expired {
						return false, errors.Wrap(
							fmt.Errorf(
								"prover already exists in non-left state (status=%d, frame=%d)",
								status, frameNumber,
							),
							"verify: invalid prover join",
						)
					}
				}
			}
		}
	}

	// If we get here, either prover doesn't exist or is in left state - both are
	// valid

	joinClone := p.ToProtobuf()
	joinClone.PublicKeySignatureBls48581 = nil
	joinMessage, err := joinClone.ToCanonicalBytes()
	if err != nil {
		return false, errors.Wrap(err, "verify: invalid prover join")
	}

	// Create the domain for the first signature
	// Poseidon hash of GLOBAL_INTRINSIC_ADDRESS concatenated with "PROVER_JOIN"
	joinDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("PROVER_JOIN"),
	)
	joinDomain, err := poseidon.HashBytes(joinDomainPreimage)
	if err != nil {
		return false, errors.Wrap(err, "verify: invalid prover join")
	}

	// Create the domain for the proof of possession
	popDomain := []byte("BLS48_POP_SK")

	// Verify the signature
	valid, err = p.keyManager.ValidateSignature(
		crypto.KeyTypeBLS48581G1,
		p.PublicKeySignatureBLS48581.PublicKey,
		joinMessage,
		p.PublicKeySignatureBLS48581.Signature,
		joinDomain.FillBytes(make([]byte, 32)),
	)
	if err != nil || !valid {
		return false, errors.Wrap(errors.New("invalid signature"), "verify: invalid prover join")
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
		return false, errors.Wrap(errors.New("invalid pop signature"), "verify: invalid prover join")
	}

	// Verify any merge signatures (skip already-consumed targets)
	for _, mt := range p.MergeTargets {
		spentBI, err := poseidon.HashBytes(slices.Concat(
			[]byte("PROVER_JOIN_MERGE"),
			mt.PublicKey,
		))
		if err != nil {
			return false, errors.Wrap(err, "verify: invalid prover join")
		}
		spentAddr := [64]byte{}
		copy(spentAddr[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(spentAddr[32:], spentBI.FillBytes(make([]byte, 32)))
		v, vErr := p.hypergraph.GetVertex(spentAddr)
		if vErr == nil && v != nil {
			continue
		}

		valid, err := p.keyManager.ValidateSignature(
			mt.KeyType,
			mt.PublicKey,
			p.PublicKeySignatureBLS48581.PublicKey,
			mt.Signature,
			[]byte("PROVER_JOIN_MERGE"),
		)
		if err != nil || !valid {
			return false, errors.Wrap(errors.New("invalid merge signature"), "verify: invalid prover join")
		}
	}

	return true, nil
}

var _ intrinsics.IntrinsicOperation = (*ProverJoin)(nil)
