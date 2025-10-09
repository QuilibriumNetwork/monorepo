package hypergraph

import (
	"bytes"
	"math/big"
	"slices"

	"github.com/pkg/errors"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type HyperedgeAdd struct {
	Domain          [32]byte
	Value           hypergraph.Hyperedge
	Signature       []byte // Ed448 signature for write authorization
	inclusionProver qcrypto.InclusionProver
	keyManager      keys.KeyManager
	signer          qcrypto.Signer
	config          *HypergraphIntrinsicConfiguration
}

func NewHyperedgeAdd(
	domain [32]byte,
	value hypergraph.Hyperedge,
	inclusionProver qcrypto.InclusionProver,
	signer qcrypto.Signer,
) *HyperedgeAdd {
	return &HyperedgeAdd{
		Domain:          domain,
		Value:           value,
		inclusionProver: inclusionProver,
		signer:          signer,
	}
}

// GetCost implements intrinsics.IntrinsicOperation.
func (h *HyperedgeAdd) GetCost() (*big.Int, error) {
	return h.Value.GetSize(), nil
}

// Materialize implements intrinsics.IntrinsicOperation.
func (h *HyperedgeAdd) Materialize(
	frameNumber uint64,
	state state.State,
) (state.State, error) {
	hg, ok := state.(*hgstate.HypergraphState)
	if !ok {
		return nil, errors.Wrap(errors.New("invalid state"), "materialize")
	}

	// Get the hyperedge ID to use as the address
	hyperedgeID := h.Value.GetID()

	var prior *tries.VectorCommitmentTree
	he, err := hg.Get(
		h.Domain[:],
		hyperedgeID[32:],
		hgstate.HyperedgeAddsDiscriminator,
	)
	if err == nil && he != nil {
		prior = he.(hypergraph.Hyperedge).GetExtrinsicTree()
	}
	value := hg.NewHyperedgeAddMaterializedState(
		frameNumber,
		prior,
		h.Value,
	)

	// Set the state
	err = hg.Set(
		h.Domain[:],
		hyperedgeID[32:],
		hgstate.HyperedgeAddsDiscriminator,
		frameNumber,
		value,
	)

	return hg, errors.Wrap(err, "materialize")
}

// Prove implements intrinsics.IntrinsicOperation.
func (h *HyperedgeAdd) Prove(frameNumber uint64) error {
	if h.Value == nil {
		return errors.Wrap(errors.New("missing hyperedge value"), "prove")
	}

	conns := h.Value.GetSize()
	if conns.Cmp(big.NewInt(0)) == 0 {
		return errors.Wrap(
			errors.New("hyperedge must connect at least one atom"),
			"prove",
		)
	}

	hyperedgeID := h.Value.GetID()

	commit := h.Value.Commit(h.inclusionProver)
	if len(commit) == 0 {
		return errors.Wrap(
			errors.New("invalid commitment for hyperedge"),
			"prove",
		)
	}

	message := make([]byte, 0, 64+74)
	message = append(message, hyperedgeID[:]...)
	message = append(message, commit...)

	sig, err := h.signer.SignWithDomain(
		message,
		slices.Concat(h.Domain[:], []byte("HYPEREDGE_ADD")),
	)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	h.Signature = sig

	return nil
}

func (h *HyperedgeAdd) GetReadAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	return nil, nil
}

func (h *HyperedgeAdd) GetWriteAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	hyperedgeID := h.Value.GetID()

	return [][]byte{
		slices.Concat(
			h.Domain[:],
			hyperedgeID[32:],
		),
	}, nil
}

// Verify implements intrinsics.IntrinsicOperation.
func (h *HyperedgeAdd) Verify(frameNumber uint64) (bool, error) {
	if h.Value == nil {
		return false, errors.Wrap(errors.New("missing hyperedge value"), "verify")
	}

	conns := h.Value.GetSize()
	if conns.Cmp(big.NewInt(0)) == 0 {
		return false, errors.Wrap(
			errors.New("hyperedge must connect at least one atom"),
			"verify",
		)
	}

	hyperedgeID := h.Value.GetID()
	if !bytes.Equal(hyperedgeID[:32], h.Domain[:]) {
		return false, errors.Wrap(errors.New("hyperedge domain mismatch"), "verify")
	}

	commit := h.Value.Commit(h.inclusionProver)
	if len(commit) == 0 {
		return false, errors.Wrap(
			errors.New("invalid commitment for hyperedge"),
			"verify",
		)
	}

	message := make([]byte, 0, 64+74)
	message = append(message, hyperedgeID[:]...)
	message = append(message, commit...)

	valid, err := h.keyManager.ValidateSignature(
		qcrypto.KeyTypeEd448,
		h.config.WritePublicKey,
		message,
		h.Signature,
		slices.Concat(h.Domain[:], []byte("HYPEREDGE_ADD")),
	)
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	if !valid {
		return false, errors.Wrap(errors.New("invalid signature"), "verify")
	}

	return true, nil
}

var _ intrinsics.IntrinsicOperation = (*HyperedgeAdd)(nil)
