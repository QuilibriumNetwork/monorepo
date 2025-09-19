package hypergraph

import (
	"math/big"

	tcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

// Atom is the base interface for both vertices and hyperedges.
// It represents any element that can exist in the hypergraph.
type Atom interface {
	// GetID returns the 64-byte unique identifier for this atom.
	// The ID is composed of [32-byte AppAddress][32-byte DataAddress].
	GetID() [64]byte

	// GetAtomType returns the type of this atom (vertex or hyperedge).
	GetAtomType() AtomType

	// GetAppAddress returns the 32-byte application address.
	GetAppAddress() [32]byte

	// GetDataAddress returns the 32-byte data address.
	GetDataAddress() [32]byte

	// GetSize returns the size of this atom for size accounting.
	GetSize() *big.Int

	// ToBytes serializes the atom to bytes for storage.
	ToBytes() []byte

	// Commit generates a cryptographic commitment of the atom data.
	Commit(prover tcrypto.InclusionProver) []byte
}
