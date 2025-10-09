package hypergraph

import (
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

type VertexAdd struct {
	Domain          [32]byte
	DataAddress     [32]byte
	Data            []qcrypto.VerEncProof
	Signature       []byte // Ed448 signature for write authorization
	inclusionProver qcrypto.InclusionProver
	keyManager      keys.KeyManager
	signer          qcrypto.Signer
	config          *HypergraphIntrinsicConfiguration
	verenc          qcrypto.VerifiableEncryptor
	rawData         []byte
	encryptionKey   []byte
}

// NewVertexAdd constructs a new vertex addition.
func NewVertexAdd(
	domain [32]byte,
	dataAddress [32]byte,
	rawData []byte,
	encryptionKey []byte,
	inclusionProver qcrypto.InclusionProver,
	signer qcrypto.Signer,
	config *HypergraphIntrinsicConfiguration,
	verenc qcrypto.VerifiableEncryptor,
	keyManager keys.KeyManager,
) *VertexAdd {
	return &VertexAdd{
		Domain:          domain,
		DataAddress:     dataAddress,
		inclusionProver: inclusionProver,
		signer:          signer,
		config:          config,
		verenc:          verenc,
		rawData:         rawData,
		encryptionKey:   encryptionKey,
		keyManager:      keyManager,
	}
}

// GetCost implements intrinsics.IntrinsicOperation.
func (h *VertexAdd) GetCost() (*big.Int, error) {
	// Cost is proportional to the size of the data
	if h.Data == nil {
		if h.rawData == nil {
			return big.NewInt(0), errors.Wrap(
				errors.New("missing data for vertex"),
				"get cost",
			)
		}

		return big.NewInt((int64(len(h.rawData)+54) / 55) * 55), nil
	}

	return big.NewInt(int64(len(h.Data)) * 55), nil
}

// Materialize implements intrinsics.IntrinsicOperation.
func (h *VertexAdd) Materialize(
	frameNumber uint64,
	state state.State,
) (state.State, error) {
	hgs, ok := state.(*hgstate.HypergraphState)
	if !ok {
		return nil, errors.Wrap(errors.New("invalid state"), "materialize")
	}

	// Obtain prior entry (if exists)
	var prior *tries.VectorCommitmentTree
	data, err := hgs.Get(
		h.Domain[:],
		h.DataAddress[:],
		hgstate.VertexAddsDiscriminator,
	)
	if err == nil {
		prior = data.(*tries.VectorCommitmentTree)
	}

	// Compress the entries for vertex tree format
	out := []hypergraph.Encrypted{}
	for _, d := range h.Data {
		out = append(out, d.Compress())
	}

	tree := hypergraph.EncryptedToVertexTree(h.inclusionProver, out)

	// Create the materialized state
	value := hgs.NewVertexAddMaterializedState(
		h.Domain,
		h.DataAddress,
		frameNumber,
		prior,
		tree,
	)

	// Set the state
	err = hgs.Set(
		h.Domain[:],
		h.DataAddress[:],
		hgstate.VertexAddsDiscriminator,
		frameNumber,
		value,
	)

	return hgs, errors.Wrap(err, "materialize")
}

// Prove implements intrinsics.IntrinsicOperation.
func (h *VertexAdd) Prove(frameNumber uint64) error {
	if len(h.rawData) == 0 {
		return errors.Wrap(errors.New("missing data for vertex"), "prove")
	}

	h.Data = h.verenc.Encrypt(h.rawData, h.encryptionKey)
	if len(h.Data) == 0 {
		return errors.Wrap(errors.New("could not encrypt data"), "prove")
	}

	message := []byte{}
	message = append(message, h.Domain[:]...)
	message = append(message, h.DataAddress[:]...)
	diskSize := 0
	for _, d := range h.Data {
		data := d.ToBytes()
		message = append(message, data...)
		diskSize += len(data)
	}

	if diskSize > 1024*1024*5 {
		return errors.Wrap(errors.New("data too large"), "prove")
	}

	sig, err := h.signer.SignWithDomain(
		message,
		slices.Concat(h.Domain[:], []byte("VERTEX_ADD")),
	)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	h.Signature = sig

	return nil
}

func (h *VertexAdd) GetReadAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	return nil, nil
}

func (h *VertexAdd) GetWriteAddresses(
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
func (h *VertexAdd) Verify(frameNumber uint64) (bool, error) {
	// Check if data is valid and can be committed
	if len(h.Data) == 0 {
		return false, errors.Wrap(errors.New("missing data for vertex"), "verify")
	}

	for _, d := range h.Data {
		if !d.Verify() {
			return false, errors.Wrap(
				errors.New("invalid proof for data"),
				"verify",
			)
		}
	}

	message := []byte{}
	message = append(message, h.Domain[:]...)
	message = append(message, h.DataAddress[:]...)
	diskSize := 0
	for _, d := range h.Data {
		data := d.ToBytes()
		message = append(message, data...)
		diskSize += len(data)
	}

	if diskSize > 1024*1024*5 {
		return false, errors.Wrap(errors.New("data too large"), "verify")
	}

	valid, err := h.keyManager.ValidateSignature(
		qcrypto.KeyTypeEd448,
		h.config.WritePublicKey,
		message,
		h.Signature,
		slices.Concat(h.Domain[:], []byte("VERTEX_ADD")),
	)
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	if !valid {
		return false, errors.Wrap(errors.New("invalid signature"), "verify")
	}

	return true, nil
}

var _ intrinsics.IntrinsicOperation = (*VertexAdd)(nil)
