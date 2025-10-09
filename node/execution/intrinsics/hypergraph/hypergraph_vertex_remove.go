package hypergraph

import (
	"math/big"
	"slices"

	"github.com/pkg/errors"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
)

type VertexRemove struct {
	Domain      [32]byte
	DataAddress [32]byte
	Signature   []byte
	keyManager  keys.KeyManager
	signer      qcrypto.Signer
	config      *HypergraphIntrinsicConfiguration
}

// NewVertexRemove constructs a new vertex removal.
func NewVertexRemove(
	domain [32]byte,
	dataAddress [32]byte,
	signer qcrypto.Signer,
) *VertexRemove {
	return &VertexRemove{
		Domain:      domain,
		DataAddress: dataAddress,
		signer:      signer,
	}
}

// GetCost implements intrinsics.IntrinsicOperation.
func (h *VertexRemove) GetCost() (*big.Int, error) {
	return big.NewInt(64), nil
}

// Materialize implements intrinsics.IntrinsicOperation.
func (h *VertexRemove) Materialize(
	frameNumber uint64,
	state state.State,
) (state.State, error) {
	hypergraph, ok := state.(*hgstate.HypergraphState)
	if !ok {
		return nil, errors.Wrap(errors.New("invalid state"), "materialize")
	}

	err := hypergraph.Delete(
		h.Domain[:],
		h.DataAddress[:],
		hgstate.VertexRemovesDiscriminator,
		frameNumber,
	)

	return hypergraph, errors.Wrap(err, "materialize")
}

// Prove implements intrinsics.IntrinsicOperation.
func (h *VertexRemove) Prove(frameNumber uint64) error {
	message := make([]byte, 0, 64)
	message = append(message, h.Domain[:]...)
	message = append(message, h.DataAddress[:]...)

	sig, err := h.signer.SignWithDomain(
		message,
		slices.Concat(h.Domain[:], []byte("VERTEX_REMOVE")),
	)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	h.Signature = sig
	return nil
}

func (h *VertexRemove) GetReadAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	return nil, nil
}

func (h *VertexRemove) GetWriteAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	return [][]byte{
		slices.Concat(
			h.Domain[:],
			h.DataAddress[:],
		),
	}, nil
}

// Verify implements intrinsics.IntrinsicOperation.
func (h *VertexRemove) Verify(frameNumber uint64) (bool, error) {
	message := make([]byte, 0, 64)
	message = append(message, h.Domain[:]...)
	message = append(message, h.DataAddress[:]...)

	valid, err := h.keyManager.ValidateSignature(
		crypto.KeyTypeEd448,
		h.config.WritePublicKey,
		message,
		h.Signature,
		slices.Concat(h.Domain[:], []byte("VERTEX_REMOVE")),
	)
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	if !valid {
		return false, errors.Wrap(errors.New("invalid signature"), "verify")
	}

	return true, nil
}

var _ intrinsics.IntrinsicOperation = (*VertexRemove)(nil)
