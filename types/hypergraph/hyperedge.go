package hypergraph

import (
	"math/big"

	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// Hyperedge represents a connection between multiple vertices or other
// hyperedges in the hypergraph. Unlike traditional edges, hyperedges can
// connect any number of atoms.
type Hyperedge interface {
	// GetID returns the 64-byte unique identifier for this hyperedge.
	// The ID is composed of [32-byte AppAddress][32-byte DataAddress].
	GetID() [64]byte

	// GetAtomType returns HyperedgeAtomType for hyperedges.
	GetAtomType() AtomType

	// GetAppAddress returns the 32-byte application address.
	GetAppAddress() [32]byte

	// GetDataAddress returns the 32-byte data address.
	GetDataAddress() [32]byte

	// ToBytes serializes the hyperedge to bytes for storage.
	ToBytes() []byte

	// AddExtrinsic adds an atom to this hyperedge's extrinsic set.
	AddExtrinsic(a Atom)

	// RemoveExtrinsic removes an atom from this hyperedge's extrinsic set.
	RemoveExtrinsic(a Atom)

	// GetSize returns the number of atoms in this hyperedge.
	GetSize() *big.Int

	// Commit generates a cryptographic commitment of the hyperedge data.
	Commit(prover crypto.InclusionProver) []byte

	// GetExtrinsicTree returns the tree containing all connected atoms.
	GetExtrinsicTree() *tries.VectorCommitmentTree
}
