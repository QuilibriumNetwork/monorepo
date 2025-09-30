package global

import (
	"math/big"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
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

// ProverUpdate represents a prover update operation
type ProverUpdate struct {
	// The delegate address to update to (32 bytes)
	DelegateAddress []byte
	// The BLS48581 addressed signature
	PublicKeySignatureBLS48581 *BLS48581AddressedSignature

	// Runtime dependencies (injected after deserialization)
	hypergraph     hypergraph.Hypergraph
	signer         crypto.Signer
	keyManager     keys.KeyManager
	rdfMultiprover *schema.RDFMultiprover
}

// NewProverUpdate creates a new ProverUpdate instance
func NewProverUpdate(
	delegateAddress []byte,
	publicKeySignatureBLS48581 *BLS48581AddressedSignature,
	hypergraph hypergraph.Hypergraph,
	signer crypto.Signer,
	rdfMultiprover *schema.RDFMultiprover,
	keyManager keys.KeyManager,
) *ProverUpdate {
	return &ProverUpdate{
		DelegateAddress:            delegateAddress,
		PublicKeySignatureBLS48581: publicKeySignatureBLS48581,
		hypergraph:                 hypergraph,
		signer:                     signer,
		rdfMultiprover:             rdfMultiprover,
		keyManager:                 keyManager,
	}
}

// GetCost implements intrinsics.IntrinsicOperation.
func (p *ProverUpdate) GetCost() (*big.Int, error) {
	return big.NewInt(0), nil
}

// Materialize implements intrinsics.IntrinsicOperation.
func (p *ProverUpdate) Materialize(
	frameNumber uint64,
	s state.State,
) (state.State, error) {
	if p.hypergraph == nil || p.rdfMultiprover == nil {
		return nil, errors.Wrap(errors.New("missing deps"), "materialize")
	}
	if p.PublicKeySignatureBLS48581 == nil {
		return nil, errors.Wrap(
			errors.New("missing addressed signature"),
			"materialize",
		)
	}
	if len(p.DelegateAddress) == 0 {
		return nil, errors.Wrap(
			errors.New("missing delegate address"),
			"materialize",
		)
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

	// Ensure the prover exists (under GLOBAL_INTRINSIC_ADDRESS + proverAddress)
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

	// Read existing PublicKey to double-check correctness (defense-in-depth)
	proverTree, ok := proverVertex.(*tries.VectorCommitmentTree)
	if !ok || proverTree == nil {
		return nil, errors.Wrap(errors.New("invalid prover vertex"), "materialize")
	}
	pubKeyBytes, err := p.rdfMultiprover.Get(
		GLOBAL_RDF_SCHEMA,
		"prover:Prover",
		"PublicKey",
		proverTree,
	)
	if err != nil || len(pubKeyBytes) == 0 {
		return nil, errors.Wrap(
			errors.New("prover public key missing"),
			"materialize",
		)
	}

	addrBI, err := poseidon.HashBytes(pubKeyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}
	addrCheck := addrBI.FillBytes(make([]byte, 32))
	if !slices.Equal(addrCheck, proverAddress) {
		return nil, errors.Wrap(
			errors.New("address mismatch with registered pubkey"),
			"materialize",
		)
	}

	// Now update only the reward entry under the QUIL token namespace:
	// key = (token.QUIL_TOKEN_ADDRESS , proverAddress) in VertexAddsDiscriminator
	// We will preserve the existing Balance and only set DelegateAddress.
	rewardPriorVertex, err := hg.Get(
		token.QUIL_TOKEN_ADDRESS,
		proverAddress,
		hgstate.VertexAddsDiscriminator,
	)
	if err != nil {
		return nil, errors.Wrap(errors.New("prover not found"), "materialize")
	}
	var rewardPriorTree *tries.VectorCommitmentTree
	if rewardPriorVertex != nil {
		var ok bool
		rewardPriorTree, ok = rewardPriorVertex.(*tries.VectorCommitmentTree)
		if !ok {
			return nil, errors.Wrap(
				errors.New("invalid reward vertex prior"),
				"materialize",
			)
		}
	}

	if rewardPriorTree == nil {
		rewardPriorTree = &qcrypto.VectorCommitmentTree{}
	}

	// Set new DelegateAddress
	if err := p.rdfMultiprover.Set(
		GLOBAL_RDF_SCHEMA,
		token.QUIL_TOKEN_ADDRESS,
		"reward:ProverReward",
		"DelegateAddress",
		p.DelegateAddress,
		rewardPriorTree,
	); err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	unmodifiedPrior, err := hg.Get(
		token.QUIL_TOKEN_ADDRESS,
		proverAddress,
		hgstate.VertexAddsDiscriminator,
	)
	var unmodifiedTree *tries.VectorCommitmentTree
	if err == nil && unmodifiedPrior != nil {
		var ok bool
		unmodifiedTree, ok = unmodifiedPrior.(*tries.VectorCommitmentTree)
		if !ok {
			return nil, errors.Wrap(
				errors.New("invalid reward vertex prior"),
				"materialize",
			)
		}
	}

	// Build the updated reward vertex
	rewardVertex := hg.NewVertexAddMaterializedState(
		[32]byte(token.QUIL_TOKEN_ADDRESS),
		[32]byte(slices.Clone(proverAddress)),
		frameNumber,
		unmodifiedTree,
		rewardPriorTree,
	)

	if err := hg.Set(
		token.QUIL_TOKEN_ADDRESS,
		proverAddress,
		hgstate.VertexAddsDiscriminator,
		frameNumber,
		rewardVertex,
	); err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	return s, nil
}

// Prove implements intrinsics.IntrinsicOperation.
func (p *ProverUpdate) Prove(frameNumber uint64) error {
	if p.keyManager == nil {
		return errors.New("key manager not initialized")
	}

	// Get the signing key
	signingKey, err := p.keyManager.GetSigningKey("q-prover-key")
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// Get the public key
	pubKey := signingKey.Public()

	// Compute address from public key
	addressBI, err := poseidon.HashBytes(pubKey.([]byte))
	if err != nil {
		return errors.Wrap(err, "prove")
	}
	address := addressBI.FillBytes(make([]byte, 32))

	// Create domain for update signature
	updateDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("PROVER_UPDATE"),
	)
	updateDomain, err := poseidon.HashBytes(updateDomainPreimage)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// Sign the delegate address
	signature, err := signingKey.SignWithDomain(
		p.DelegateAddress,
		updateDomain.Bytes(),
	)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// Create the addressed signature
	p.PublicKeySignatureBLS48581 = &BLS48581AddressedSignature{
		Signature: signature,
		Address:   address,
	}

	return nil
}

// Verify implements intrinsics.IntrinsicOperation.
func (p *ProverUpdate) Verify(frameNumber uint64) (bool, error) {
	if p.hypergraph == nil {
		return false, errors.Wrap(
			errors.New("hypergraph not initialized"),
			"verify",
		)
	}
	if p.keyManager == nil {
		return false, errors.Wrap(
			errors.New("key manager not initialized"),
			"verify",
		)
	}
	if p.rdfMultiprover == nil {
		return false, errors.Wrap(
			errors.New("rdf multiprover not initialized"),
			"verify",
		)
	}
	if p.PublicKeySignatureBLS48581 == nil {
		return false, errors.Wrap(errors.New("missing signature"), "verify")
	}
	if len(p.DelegateAddress) != 32 {
		return false, errors.Wrap(
			errors.New("missing delegate address"),
			"verify",
		)
	}
	if len(p.PublicKeySignatureBLS48581.Address) != 32 {
		return false, errors.Wrap(
			errors.New("invalid addressed prover address"),
			"verify",
		)
	}

	// Resolve the prover vertex
	proverFullAddr := [64]byte{}
	copy(proverFullAddr[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(proverFullAddr[32:], p.PublicKeySignatureBLS48581.Address)

	vertexData, err := p.hypergraph.GetVertexData(proverFullAddr)
	if err != nil || vertexData == nil {
		return false, errors.Wrap(errors.New("prover not found"), "verify")
	}

	// Fetch the registered PublicKey to verify the address binding and the
	// signature
	pubKeyBytes, err := p.rdfMultiprover.Get(
		GLOBAL_RDF_SCHEMA,
		"prover:Prover",
		"PublicKey",
		vertexData,
	)
	if err != nil || len(pubKeyBytes) == 0 {
		return false, errors.Wrap(errors.New("prover public key missing"), "verify")
	}
	pubKey := pubKeyBytes

	// Check poseidon(pubKey) == addressed.Address
	addrBI, err := poseidon.HashBytes(pubKey)
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}
	addrCheck := addrBI.FillBytes(make([]byte, 32))
	if !slices.Equal(addrCheck, p.PublicKeySignatureBLS48581.Address) {
		return false, errors.Wrap(
			errors.New("address does not match registered pubkey"),
			"verify",
		)
	}

	// Domain for update
	updateDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("PROVER_UPDATE"),
	)
	updateDomain, err := poseidon.HashBytes(updateDomainPreimage)
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	// Validate signature over the new DelegateAddress
	ok := false
	ok, err = p.keyManager.ValidateSignature(
		crypto.KeyTypeBLS48581G1,
		pubKey,
		p.DelegateAddress,
		p.PublicKeySignatureBLS48581.Signature,
		updateDomain.Bytes(),
	)
	if err != nil || !ok {
		return false, errors.Wrap(errors.New("invalid update signature"), "verify")
	}

	if len(p.DelegateAddress) != 32 {
		return false, errors.Wrap(
			errors.New("delegate address must be 32 bytes"),
			"verify",
		)
	}

	return true, nil
}

var _ intrinsics.IntrinsicOperation = (*ProverUpdate)(nil)
