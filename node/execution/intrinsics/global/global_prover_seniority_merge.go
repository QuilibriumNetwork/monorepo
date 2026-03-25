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
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global/compat"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// ProverSeniorityMerge allows existing provers to claim seniority from their
// old peer keys. This is used as a repair mechanism for provers who joined
// before the seniority merge bug was fixed.
type ProverSeniorityMerge struct {
	// The frame number when this request is made
	FrameNumber uint64
	// The BLS48581 addressed signature
	PublicKeySignatureBLS48581 BLS48581AddressedSignature
	// Any merge targets for seniority
	MergeTargets []*SeniorityMerge

	// Runtime dependencies (injected after deserialization)
	hypergraph     hypergraph.Hypergraph
	keyManager     keys.KeyManager
	rdfMultiprover *schema.RDFMultiprover
}

// NewProverSeniorityMerge creates a new ProverSeniorityMerge instance
func NewProverSeniorityMerge(
	frameNumber uint64,
	mergeTargets []*SeniorityMerge,
	hypergraph hypergraph.Hypergraph,
	rdfMultiprover *schema.RDFMultiprover,
	keyManager keys.KeyManager,
) (*ProverSeniorityMerge, error) {
	return &ProverSeniorityMerge{
		FrameNumber:    frameNumber,
		MergeTargets:   mergeTargets,   // buildutils:allow-slice-alias slice is static
		hypergraph:     hypergraph,
		rdfMultiprover: rdfMultiprover,
		keyManager:     keyManager,
	}, nil
}

// GetCost implements intrinsics.IntrinsicOperation.
func (p *ProverSeniorityMerge) GetCost() (*big.Int, error) {
	return big.NewInt(0), nil
}

// Materialize implements intrinsics.IntrinsicOperation.
func (p *ProverSeniorityMerge) Materialize(
	frameNumber uint64,
	s state.State,
) (state.State, error) {
	if p.hypergraph == nil || p.rdfMultiprover == nil {
		return nil, errors.Wrap(errors.New("missing deps"), "materialize")
	}
	if len(p.MergeTargets) == 0 {
		return nil, errors.Wrap(errors.New("no merge targets"), "materialize")
	}

	hg := s.(*hgstate.HypergraphState)

	// The prover address is the addressed signature's Address (poseidon(pubkey))
	proverAddress := p.PublicKeySignatureBLS48581.Address
	if len(proverAddress) != 32 {
		return nil, errors.Wrap(
			errors.New("invalid prover address length"),
			"materialize",
		)
	}

	// Ensure the prover exists
	proverFullAddr := [64]byte{}
	copy(proverFullAddr[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(proverFullAddr[32:], proverAddress)

	proverVertex, err := hg.Get(
		proverFullAddr[:32],
		proverFullAddr[32:],
		hgstate.VertexAddsDiscriminator,
	)
	if err != nil || proverVertex == nil {
		return nil, errors.Wrap(errors.New("prover not found"), "materialize")
	}

	proverTree, ok := proverVertex.(*tries.VectorCommitmentTree)
	if !ok || proverTree == nil {
		return nil, errors.Wrap(errors.New("invalid prover vertex"), "materialize")
	}

	// Get existing seniority
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

	// Convert Ed448 public keys to peer IDs and calculate seniority
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

	// Get aggregated seniority from merge targets
	var mergeSeniority uint64 = 0
	if len(peerIds) > 0 {
		seniorityBig := compat.GetAggregatedSeniority(peerIds)
		if seniorityBig.IsUint64() {
			mergeSeniority = seniorityBig.Uint64()
		}
	}

	// Add merge seniority to existing seniority
	newSeniority := existingSeniority + mergeSeniority

	// Store updated seniority
	seniorityBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seniorityBytes, newSeniority)
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

	// Get the prior tree for change tracking
	priorVertex, err := hg.Get(
		proverFullAddr[:32],
		proverFullAddr[32:],
		hgstate.VertexAddsDiscriminator,
	)
	var priorTree *tries.VectorCommitmentTree
	if err == nil && priorVertex != nil {
		priorTree, _ = priorVertex.(*tries.VectorCommitmentTree)
	}

	// Update prover vertex with new seniority
	proverVertexUpdate := hg.NewVertexAddMaterializedState(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		[32]byte(proverAddress),
		frameNumber,
		priorTree,
		proverTree,
	)

	err = hg.Set(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		proverAddress,
		hgstate.VertexAddsDiscriminator,
		frameNumber,
		proverVertexUpdate,
	)
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	// Mark merge targets as spent with prover address so the same prover
	// can re-use them (matching the ProverJoin spent marker format).
	for _, mt := range p.MergeTargets {
		spentMergeBI, err := poseidon.HashBytes(slices.Concat(
			[]byte("PROVER_SENIORITY_MERGE"),
			mt.PublicKey,
		))
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		spentMergeAddr := spentMergeBI.FillBytes(make([]byte, 32))

		// Check for existing spent marker to use as prior tree
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
					// Already has a prover address — skip
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

	return s, nil
}

// Prove implements intrinsics.IntrinsicOperation.
func (p *ProverSeniorityMerge) Prove(frameNumber uint64) error {
	if p.keyManager == nil {
		return errors.New("key manager not initialized")
	}

	// Get the signing key
	signingKey, err := p.keyManager.GetSigningKey("q-prover-key")
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// Sign merge target signatures
	blsPublicKey := signingKey.Public().([]byte)
	for _, mt := range p.MergeTargets {
		if mt.signer != nil {
			mt.Signature, err = mt.signer.SignWithDomain(
				blsPublicKey,
				[]byte("PROVER_SENIORITY_MERGE"),
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
				[]byte("PROVER_SENIORITY_MERGE"),
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

	// Compute address from public key
	addressBI, err := poseidon.HashBytes(blsPublicKey)
	if err != nil {
		return errors.Wrap(err, "prove")
	}
	address := addressBI.FillBytes(make([]byte, 32))

	// Create domain for seniority merge signature
	mergeDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("PROVER_SENIORITY_MERGE"),
	)
	mergeDomain, err := poseidon.HashBytes(mergeDomainPreimage)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// Create message to sign: frame number + all merge target public keys
	message := binary.BigEndian.AppendUint64(nil, p.FrameNumber)
	for _, mt := range p.MergeTargets {
		message = append(message, mt.PublicKey...)
	}

	// Sign the message
	signature, err := signingKey.SignWithDomain(
		message,
		mergeDomain.Bytes(),
	)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// Create the addressed signature
	p.PublicKeySignatureBLS48581 = BLS48581AddressedSignature{
		Signature: signature,
		Address:   address,
	}

	return nil
}

func (p *ProverSeniorityMerge) GetReadAddresses(frameNumber uint64) ([][]byte, error) {
	return nil, nil
}

func (p *ProverSeniorityMerge) GetWriteAddresses(frameNumber uint64) ([][]byte, error) {
	proverAddress := p.PublicKeySignatureBLS48581.Address
	proverFullAddress := [64]byte{}
	copy(proverFullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(proverFullAddress[32:], proverAddress)

	addresses := map[string]struct{}{}
	addresses[string(proverFullAddress[:])] = struct{}{}

	// Add spent merge addresses
	for _, mt := range p.MergeTargets {
		spentMergeBI, err := poseidon.HashBytes(slices.Concat(
			[]byte("PROVER_SENIORITY_MERGE"),
			mt.PublicKey,
		))
		if err != nil {
			return nil, errors.Wrap(err, "get write addresses")
		}

		addresses[string(slices.Concat(
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			spentMergeBI.FillBytes(make([]byte, 32)),
		))] = struct{}{}
	}

	result := [][]byte{}
	for key := range addresses {
		result = append(result, []byte(key))
	}

	return result, nil
}

// Verify implements intrinsics.IntrinsicOperation.
func (p *ProverSeniorityMerge) Verify(frameNumber uint64) (bool, error) {
	if p.hypergraph == nil {
		return false, errors.Wrap(
			errors.New("hypergraph not initialized"),
			"verify: invalid prover seniority merge",
		)
	}
	if p.keyManager == nil {
		return false, errors.Wrap(
			errors.New("key manager not initialized"),
			"verify: invalid prover seniority merge",
		)
	}
	if p.rdfMultiprover == nil {
		return false, errors.Wrap(
			errors.New("rdf multiprover not initialized"),
			"verify: invalid prover seniority merge",
		)
	}
	if len(p.MergeTargets) == 0 {
		return false, errors.Wrap(errors.New("no merge targets"), "verify: invalid prover seniority merge")
	}
	if len(p.PublicKeySignatureBLS48581.Address) != 32 {
		return false, errors.Wrap(
			errors.New("invalid addressed prover address"),
			"verify: invalid prover seniority merge",
		)
	}

	// Disallow too old of a request
	if p.FrameNumber+10 < frameNumber {
		return false, errors.Wrap(errors.New("outdated request"), "verify: invalid prover seniority merge")
	}

	// Resolve the prover vertex
	proverFullAddr := [64]byte{}
	copy(proverFullAddr[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(proverFullAddr[32:], p.PublicKeySignatureBLS48581.Address)

	vertexData, err := p.hypergraph.GetVertexData(proverFullAddr)
	if err != nil || vertexData == nil {
		return false, errors.Wrap(errors.New("prover not found"), "verify: invalid prover seniority merge")
	}

	// Fetch the registered PublicKey
	pubKeyBytes, err := p.rdfMultiprover.Get(
		GLOBAL_RDF_SCHEMA,
		"prover:Prover",
		"PublicKey",
		vertexData,
	)
	if err != nil || len(pubKeyBytes) == 0 {
		return false, errors.Wrap(errors.New("prover public key missing"), "verify: invalid prover seniority merge")
	}

	// Check poseidon(pubKey) == addressed.Address
	addrBI, err := poseidon.HashBytes(pubKeyBytes)
	if err != nil {
		return false, errors.Wrap(err, "verify: invalid prover seniority merge")
	}
	addrCheck := addrBI.FillBytes(make([]byte, 32))
	if !slices.Equal(addrCheck, p.PublicKeySignatureBLS48581.Address) {
		return false, errors.Wrap(
			errors.New("address does not match registered pubkey"),
			"verify: invalid prover seniority merge",
		)
	}

	// Verify merge target signatures and track peer IDs for seniority lookup
	var peerIds []string
	for _, mt := range p.MergeTargets {
		valid, err := p.keyManager.ValidateSignature(
			mt.KeyType,
			mt.PublicKey,
			pubKeyBytes,
			mt.Signature,
			[]byte("PROVER_SENIORITY_MERGE"),
		)
		if err != nil || !valid {
			return false, errors.Wrap(
				errors.New("invalid merge target signature"),
				"verify: invalid prover seniority merge",
			)
		}

		// Confirm this merge target has not already been used by a
		// different prover. If the same prover consumed it (via a prior
		// join or merge), allow re-use so seniority can be restored.
		spentMergeBI, err := poseidon.HashBytes(slices.Concat(
			[]byte("PROVER_SENIORITY_MERGE"),
			mt.PublicKey,
		))
		if err != nil {
			return false, errors.Wrap(err, "verify: invalid prover seniority merge")
		}

		spentAddress := [64]byte{}
		copy(spentAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(spentAddress[32:], spentMergeBI.FillBytes(make([]byte, 32)))

		v, err := p.hypergraph.GetVertex(spentAddress)
		if err == nil && v != nil {
			spentData, dataErr := p.hypergraph.GetVertexData(spentAddress)
			if dataErr == nil && spentData != nil {
				storedAddr, getErr := p.rdfMultiprover.Get(
					GLOBAL_RDF_SCHEMA,
					"merge:SpentMerge",
					"ProverAddress",
					spentData,
				)
				if getErr == nil && len(storedAddr) == 32 &&
					!bytes.Equal(storedAddr, p.PublicKeySignatureBLS48581.Address) {
					return false, errors.Wrap(
						errors.New("merge target already used"),
						"verify: invalid prover seniority merge",
					)
				}
			}
		}

		// Also check against the ProverJoin spent marker
		joinSpentMergeBI, err := poseidon.HashBytes(slices.Concat(
			[]byte("PROVER_JOIN_MERGE"),
			mt.PublicKey,
		))
		if err != nil {
			return false, errors.Wrap(err, "verify: invalid prover seniority merge")
		}

		joinSpentAddress := [64]byte{}
		copy(joinSpentAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(joinSpentAddress[32:], joinSpentMergeBI.FillBytes(make([]byte, 32)))

		v, err = p.hypergraph.GetVertex(joinSpentAddress)
		if err == nil && v != nil {
			spentData, dataErr := p.hypergraph.GetVertexData(joinSpentAddress)
			if dataErr == nil && spentData != nil {
				storedAddr, getErr := p.rdfMultiprover.Get(
					GLOBAL_RDF_SCHEMA,
					"merge:SpentMerge",
					"ProverAddress",
					spentData,
				)
				if getErr == nil && len(storedAddr) == 32 &&
					!bytes.Equal(storedAddr, p.PublicKeySignatureBLS48581.Address) {
					return false, errors.Wrap(
						errors.New("merge target already used in join"),
						"verify: invalid prover seniority merge",
					)
				}
			}
		}

		// Track peer ID for seniority lookup
		if mt.KeyType == crypto.KeyTypeEd448 {
			pk, err := pcrypto.UnmarshalEd448PublicKey(mt.PublicKey)
			if err != nil {
				return false, errors.Wrap(err, "verify: invalid prover seniority merge")
			}

			peerId, err := peer.IDFromPublicKey(pk)
			if err != nil {
				return false, errors.Wrap(err, "verify: invalid prover seniority merge")
			}

			peerIds = append(peerIds, peerId.String())
		}
	}

	// Get existing seniority
	existingSeniorityData, err := p.rdfMultiprover.Get(
		GLOBAL_RDF_SCHEMA,
		"prover:Prover",
		"Seniority",
		vertexData,
	)
	var existingSeniority uint64 = 0
	if err == nil && len(existingSeniorityData) == 8 {
		existingSeniority = binary.BigEndian.Uint64(existingSeniorityData)
	}

	// Calculate seniority from merge targets
	var mergeSeniority uint64 = 0
	if len(peerIds) > 0 {
		seniorityBig := compat.GetAggregatedSeniority(peerIds)
		if seniorityBig.IsUint64() {
			mergeSeniority = seniorityBig.Uint64()
		}
	}

	// Merge is only allowed if the resulting seniority would be higher
	if mergeSeniority <= existingSeniority {
		return false, errors.Wrap(
			errors.New("merge would not increase seniority"),
			"verify: invalid prover seniority merge",
		)
	}

	// Domain for seniority merge
	mergeDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("PROVER_SENIORITY_MERGE"),
	)
	mergeDomain, err := poseidon.HashBytes(mergeDomainPreimage)
	if err != nil {
		return false, errors.Wrap(err, "verify: invalid prover seniority merge")
	}

	// Recreate the message that was signed
	message := binary.BigEndian.AppendUint64(nil, p.FrameNumber)
	for _, mt := range p.MergeTargets {
		message = append(message, mt.PublicKey...)
	}

	// Validate signature
	ok, err := p.keyManager.ValidateSignature(
		crypto.KeyTypeBLS48581G1,
		pubKeyBytes,
		message,
		p.PublicKeySignatureBLS48581.Signature,
		mergeDomain.Bytes(),
	)
	if err != nil || !ok {
		return false, errors.Wrap(errors.New("invalid seniority merge signature"), "verify: invalid prover seniority merge")
	}

	return true, nil
}

var _ intrinsics.IntrinsicOperation = (*ProverSeniorityMerge)(nil)
