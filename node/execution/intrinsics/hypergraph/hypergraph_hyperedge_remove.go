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
)

type HyperedgeRemove struct {
	Domain     [32]byte
	Value      hypergraph.Hyperedge
	Signature  []byte // Ed448 signature for write authorization
	keyManager keys.KeyManager
	signer     qcrypto.Signer
	config     *HypergraphIntrinsicConfiguration
}

func NewHyperedgeRemove(
	domain [32]byte,
	value hypergraph.Hyperedge,
	signer qcrypto.Signer,
) *HyperedgeRemove {
	return &HyperedgeRemove{
		Domain: domain,
		Value:  value,
		signer: signer,
	}
}

// GetCost implements intrinsics.IntrinsicOperation.
func (h *HyperedgeRemove) GetCost() (*big.Int, error) {
	return big.NewInt(64), nil
}

// Materialize implements intrinsics.IntrinsicOperation.
func (h *HyperedgeRemove) Materialize(
	frameNumber uint64,
	state state.State,
) (state.State, error) {
	hypergraph, ok := state.(*hgstate.HypergraphState)
	if !ok {
		return nil, errors.Wrap(errors.New("invalid state"), "materialize")
	}

	// Get the hyperedge ID to use as the address
	hyperedgeID := h.Value.GetID()

	// Set the state
	err := hypergraph.Delete(
		h.Domain[:],
		hyperedgeID[32:],
		hgstate.HyperedgeRemovesDiscriminator,
		frameNumber,
	)

	return hypergraph, errors.Wrap(err, "materialize")
}

// Prove implements intrinsics.IntrinsicOperation.
func (h *HyperedgeRemove) Prove(frameNumber uint64) error {
	// For hyperedge removal, ensure the hyperedge value is valid
	if h.Value == nil {
		return errors.Wrap(errors.New("missing hyperedge value"), "prove")
	}

	hyperedgeID := h.Value.GetID()
	if len(hyperedgeID) != 64 {
		return errors.Wrap(errors.New("invalid hyperedge id length"), "prove")
	}

	message := make([]byte, 0, 64)
	message = append(message, hyperedgeID[:]...)

	sig, err := h.signer.SignWithDomain(
		message,
		slices.Concat(h.Domain[:], []byte("HYPEREDGE_REMOVE")),
	)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	h.Signature = sig

	return nil
}

func (h *HyperedgeRemove) GetReadAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	return nil, nil
}

func (h *HyperedgeRemove) GetWriteAddresses(
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
func (h *HyperedgeRemove) Verify(frameNumber uint64) (bool, error) {
	// Verify that the hyperedge is valid
	if h.Value == nil {
		return false, errors.Wrap(errors.New("missing hyperedge value"), "verify")
	}

	hyperedgeID := h.Value.GetID()
	if len(hyperedgeID) != 64 {
		return false, errors.Wrap(
			errors.New("invalid hyperedge id length"),
			"verify",
		)
	}

	if !bytes.Equal(hyperedgeID[:32], h.Domain[:]) {
		return false, errors.Wrap(
			errors.New("hyperedge domain mismatch"),
			"verify",
		)
	}

	message := make([]byte, 0, 64)
	message = append(message, hyperedgeID[:]...)

	valid, err := h.keyManager.ValidateSignature(
		qcrypto.KeyTypeEd448,
		h.config.WritePublicKey,
		message,
		h.Signature,
		slices.Concat(h.Domain[:], []byte("HYPEREDGE_REMOVE")),
	)
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	if !valid {
		return false, errors.Wrap(errors.New("invalid signature"), "verify")
	}

	return true, nil
}

var _ intrinsics.IntrinsicOperation = (*HyperedgeRemove)(nil)
