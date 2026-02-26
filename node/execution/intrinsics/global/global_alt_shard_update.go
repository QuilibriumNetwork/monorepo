package global

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
)

// AltShardUpdate represents an update to an alternative shard's roots.
// The shard address is derived from the poseidon hash of the BLS48-581 public key.
// This allows external entities to maintain their own state trees with provable
// ownership through signature verification.
type AltShardUpdate struct {
	// The BLS48-581 public key that owns this shard
	// The shard address is poseidon(PublicKey)
	PublicKey []byte

	// The frame number when this update was signed
	// Must be within 2 frames of the verification frame number
	FrameNumber uint64

	// The root hash for vertex adds tree
	VertexAddsRoot []byte

	// The root hash for vertex removes tree
	VertexRemovesRoot []byte

	// The root hash for hyperedge adds tree
	HyperedgeAddsRoot []byte

	// The root hash for hyperedge removes tree
	HyperedgeRemovesRoot []byte

	// The BLS48-581 signature over (FrameNumber || VertexAddsRoot ||
	// VertexRemovesRoot || HyperedgeAddsRoot || HyperedgeRemovesRoot)
	Signature []byte

	// Private dependencies
	hypergraph hypergraph.Hypergraph
	keyManager keys.KeyManager
	signer     crypto.Signer
}

// NewAltShardUpdate creates a new AltShardUpdate instance
func NewAltShardUpdate(
	frameNumber uint64,
	vertexAddsRoot []byte,
	vertexRemovesRoot []byte,
	hyperedgeAddsRoot []byte,
	hyperedgeRemovesRoot []byte,
	hypergraph hypergraph.Hypergraph,
	keyManager keys.KeyManager,
	signer crypto.Signer,
) (*AltShardUpdate, error) {
	return &AltShardUpdate{
		FrameNumber:          frameNumber,
		VertexAddsRoot:       vertexAddsRoot,
		VertexRemovesRoot:    vertexRemovesRoot,
		HyperedgeAddsRoot:    hyperedgeAddsRoot,
		HyperedgeRemovesRoot: hyperedgeRemovesRoot,
		hypergraph:           hypergraph,
		keyManager:           keyManager,
		signer:               signer,
	}, nil
}

// GetCost returns the cost of this operation (zero for shard updates)
func (a *AltShardUpdate) GetCost() (*big.Int, error) {
	return big.NewInt(0), nil
}

// getSignedMessage constructs the message that is signed
func (a *AltShardUpdate) getSignedMessage() []byte {
	frameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameBytes, a.FrameNumber)

	return slices.Concat(
		frameBytes,
		a.VertexAddsRoot,
		a.VertexRemovesRoot,
		a.HyperedgeAddsRoot,
		a.HyperedgeRemovesRoot,
	)
}

// getShardAddress derives the shard address from the public key
func (a *AltShardUpdate) getShardAddress() ([]byte, error) {
	if len(a.PublicKey) == 0 {
		return nil, errors.New("public key is empty")
	}

	addrBI, err := poseidon.HashBytes(a.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "hash public key")
	}

	return addrBI.FillBytes(make([]byte, 32)), nil
}

// Prove signs the update with the signer's BLS48-581 key
func (a *AltShardUpdate) Prove(frameNumber uint64) error {
	if a.signer == nil {
		return errors.New("signer is nil")
	}

	a.PublicKey = a.signer.Public().([]byte)

	// Create domain for signature
	domainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("ALT_SHARD_UPDATE"),
	)
	domain, err := poseidon.HashBytes(domainPreimage)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	message := a.getSignedMessage()
	signature, err := a.signer.SignWithDomain(
		message,
		domain.FillBytes(make([]byte, 32)),
	)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	a.Signature = signature
	return nil
}

// Verify validates the signature and frame number constraints
func (a *AltShardUpdate) Verify(frameNumber uint64) (bool, error) {
	if a.keyManager == nil {
		return false, errors.New("key manager is nil")
	}

	// Validate public key length (BLS48-581 public key is 585 bytes)
	if len(a.PublicKey) != 585 {
		return false, errors.Errorf(
			"invalid public key length: expected 585, got %d",
			len(a.PublicKey),
		)
	}

	// Validate signature length (BLS48-581 signature is 74 bytes)
	if len(a.Signature) != 74 {
		return false, errors.Errorf(
			"invalid signature length: expected 74, got %d",
			len(a.Signature),
		)
	}

	// Validate root lengths (must be 64 or 74 bytes)
	isValidRootLen := func(length int) bool {
		return length == 64 || length == 74
	}
	if !isValidRootLen(len(a.VertexAddsRoot)) {
		return false, errors.Errorf(
			"vertex adds root must be 64 or 74 bytes, got %d",
			len(a.VertexAddsRoot),
		)
	}
	if !isValidRootLen(len(a.VertexRemovesRoot)) {
		return false, errors.Errorf(
			"vertex removes root must be 64 or 74 bytes, got %d",
			len(a.VertexRemovesRoot),
		)
	}
	if !isValidRootLen(len(a.HyperedgeAddsRoot)) {
		return false, errors.Errorf(
			"hyperedge adds root must be 64 or 74 bytes, got %d",
			len(a.HyperedgeAddsRoot),
		)
	}
	if !isValidRootLen(len(a.HyperedgeRemovesRoot)) {
		return false, errors.Errorf(
			"hyperedge removes root must be 64 or 74 bytes, got %d",
			len(a.HyperedgeRemovesRoot),
		)
	}

	// Frame number must be within 2 frames of the verification frame
	// and not in the future
	if a.FrameNumber > frameNumber {
		return false, errors.New("frame number is in the future")
	}
	if frameNumber-a.FrameNumber > 2 {
		return false, errors.New("frame number is too old (more than 2 frames)")
	}

	// Create domain for signature verification
	domainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("ALT_SHARD_UPDATE"),
	)
	domain, err := poseidon.HashBytes(domainPreimage)
	if err != nil {
		return false, errors.Wrap(err, "verify: invalid alt shard update")
	}

	message := a.getSignedMessage()
	valid, err := a.keyManager.ValidateSignature(
		crypto.KeyTypeBLS48581G1,
		a.PublicKey,
		message,
		a.Signature,
		domain.FillBytes(make([]byte, 32)),
	)
	if err != nil {
		return false, errors.Wrap(err, "verify: invalid alt shard update")
	}
	if !valid {
		return false, errors.New("invalid signature")
	}

	return true, nil
}

// GetReadAddresses returns the addresses this operation reads from
func (a *AltShardUpdate) GetReadAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	return nil, nil
}

// GetWriteAddresses returns the addresses this operation writes to
func (a *AltShardUpdate) GetWriteAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	shardAddress, err := a.getShardAddress()
	if err != nil {
		return nil, errors.Wrap(err, "get write addresses")
	}

	// We write to four trees under this shard address, all at the zero key
	// The full address is shardAddress (app) + 00...00 (data)
	zeroKey := bytes.Repeat([]byte{0x00}, 32)
	fullAddress := slices.Concat(shardAddress, zeroKey)

	return [][]byte{fullAddress}, nil
}

// Materialize applies the shard update to the state
func (a *AltShardUpdate) Materialize(
	frameNumber uint64,
	state state.State,
) (state.State, error) {
	return state, nil
}

var _ intrinsics.IntrinsicOperation = (*AltShardUpdate)(nil)
