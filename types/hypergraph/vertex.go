package hypergraph

import (
	"math/big"

	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

// Vertex represents a node in the hypergraph. Each vertex has a unique ID
// composed of an app address and data address.
type Vertex interface {
	// GetID returns the 64-byte unique identifier for this vertex.
	// The ID is composed of [32-byte AppAddress][32-byte DataAddress].
	GetID() [64]byte

	// GetAtomType returns VertexAtomType for vertices.
	GetAtomType() AtomType

	// GetAppAddress returns the 32-byte application address.
	GetAppAddress() [32]byte

	// GetDataAddress returns the 32-byte data address.
	GetDataAddress() [32]byte

	// ToBytes serializes the vertex to bytes for storage.
	ToBytes() []byte

	// GetSize returns the size of this vertex for size accounting.
	GetSize() *big.Int

	// Commit generates a KZG commitment of the vertex data.
	Commit(prover crypto.InclusionProver) []byte
}
