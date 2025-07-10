package hypergraph

import (
	"math/big"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type AtomType string
type PhaseType string

const (
	VertexAtomType    AtomType  = "vertex"
	HyperedgeAtomType AtomType  = "hyperedge"
	AddsPhaseType     PhaseType = "adds"
	RemovesPhaseType  PhaseType = "removes"
)

type Extrinsic struct {
	Ref [64]byte
}

type Location [64]byte // 32 bytes for AppAddress + 32 bytes for DataAddress

var ErrInvalidAtomType = errors.New("invalid atom type for set")
var ErrInvalidLocation = errors.New("invalid location")
var ErrRemoved = errors.New("removed")

// Hypergraph defines the interface for hypergraph operations. A hypergraph is a
// higher-dimensional generalization of a graph where edges (hyperedges) can
// connect any number of vertices or hyperedges themselves.
type Hypergraph interface {
	// GetSize returns the current total size of the hypergraph. The size is
	// calculated as the sum of all added atoms' sizes minus removed atoms.
	GetSize() *big.Int

	// Commit calculates the hierarchical vector commitments for each shard's
	// add/remove sets and returns the roots.
	Commit() [][]byte

	// Vertex operations

	// GetVertex retrieves a vertex by its ID. Returns ErrRemoved if the vertex
	// has been removed, or an error if the vertex doesn't exist.
	GetVertex(id [64]byte) (Vertex, error)

	// AddVertex adds a new vertex to the hypergraph within the given transaction.
	// The vertex will be added to the appropriate shard based on its address.
	AddVertex(txn tries.TreeBackingStoreTransaction, v Vertex) error

	// RemoveVertex marks a vertex as removed.
	RemoveVertex(txn tries.TreeBackingStoreTransaction, v Vertex) error

	// RevertAddVertex undoes a previous AddVertex operation. This is useful for
	// rolling back series of operations in the event of a frame rewind.
	RevertAddVertex(
		txn tries.TreeBackingStoreTransaction,
		v Vertex,
	) error

	// RevertRemoveVertex undoes a previous RemoveVertex operation.
	RevertRemoveVertex(
		txn tries.TreeBackingStoreTransaction,
		v Vertex,
	) error

	// LookupVertex checks if a vertex exists and hasn't been removed. Returns
	// true if the vertex is present and active.
	LookupVertex(v Vertex) bool

	// Hyperedge operations

	// GetHyperedge retrieves a hyperedge by its ID. Returns ErrRemoved if the
	// hyperedge has been removed, or an error if it doesn't exist.
	GetHyperedge(id [64]byte) (Hyperedge, error)

	// AddHyperedge adds a new hyperedge to the hypergraph. The hyperedge will be
	// added to the appropriate shard based on its address.
	AddHyperedge(
		txn tries.TreeBackingStoreTransaction,
		h Hyperedge,
	) error

	// RemoveHyperedge marks a hyperedge as removed.
	RemoveHyperedge(
		txn tries.TreeBackingStoreTransaction,
		h Hyperedge,
	) error

	// RevertAddHyperedge undoes a previous AddHyperedge operation.
	RevertAddHyperedge(
		txn tries.TreeBackingStoreTransaction,
		h Hyperedge,
	) error

	// RevertRemoveHyperedge undoes a previous RemoveHyperedge operation.
	RevertRemoveHyperedge(
		txn tries.TreeBackingStoreTransaction,
		h Hyperedge,
	) error

	// LookupHyperedge checks if a hyperedge exists and hasn't been removed.
	// Returns true if the hyperedge is present and active.
	LookupHyperedge(h Hyperedge) bool

	// Atom operations

	// LookupAtom checks if any atom (vertex or hyperedge) exists and hasn't been
	// removed.
	LookupAtom(a Atom) bool

	// LookupAtomSet checks if all atoms in the set exist and haven't been
	// removed. Returns true only if all atoms are present and active.
	LookupAtomSet(atomSet []Atom) bool

	// Within checks if atom 'a' is within hyperedge 'h'. This includes direct
	// containment and recursive containment through nested hyperedges.
	Within(a, h Atom) bool

	// Access to sets

	GetVertexDataIterator(domain [32]byte) tries.VertexDataIterator

	// GetVertexAdds returns the map of vertex add sets by shard key.
	GetVertexAdds() map[tries.ShardKey]*IdSet

	// GetVertexRemoves returns the map of vertex remove sets by shard key.
	GetVertexRemoves() map[tries.ShardKey]*IdSet

	// GetHyperedgeAdds returns the map of hyperedge add sets by shard key.
	GetHyperedgeAdds() map[tries.ShardKey]*IdSet

	// GetHyperedgeRemoves returns the map of hyperedge remove sets by shard key.
	GetHyperedgeRemoves() map[tries.ShardKey]*IdSet

	// Import operations

	// ImportTree imports a pre-existing tree into the hypergraph. This is invoked
	// by the persistence layer to load tree roots for each set into the
	// hypergraph instance.
	ImportTree(
		atomType AtomType,
		phaseType PhaseType,
		shardKey tries.ShardKey,
		root tries.LazyVectorCommitmentNode,
		store tries.TreeBackingStore,
		prover crypto.InclusionProver,
	) error

	// Vertex data operations

	// GetVertexData retrieves the data tree associated with a vertex.
	GetVertexData(id [64]byte) (*tries.VectorCommitmentTree, error)

	// SetVertexData associates a data tree with a vertex.
	SetVertexData(
		txn tries.TreeBackingStoreTransaction,
		id [64]byte,
		data *tries.VectorCommitmentTree,
	) error

	// MarkVertexDataForDeletion schedules vertex data for deletion at the
	// specified time. The data won't be immediately deleted to allow for frame
	// rewind events to avoid needing resynchronization.
	MarkVertexDataForDeletion(
		txn tries.TreeBackingStoreTransaction,
		deleteAt int64,
		id [64]byte,
	) error

	// UnmarkVertexDataForDeletion cancels a scheduled deletion of vertex data.
	UnmarkVertexDataForDeletion(
		txn tries.TreeBackingStoreTransaction,
		deleteAt int64,
		id [64]byte,
	) error

	// RunVertexDataPruning executes the deletion of vertex data that has been
	// marked for deletion and whose deletion time has passed.
	RunVertexDataPruning(txn tries.TreeBackingStoreTransaction) error

	// Hyperedge data operations

	// GetHyperedgeExtrinsics retrieves the extrinsic tree of a hyperedge, which
	// contains all atoms connected by the hyperedge. When the atom is a vertex,
	// GetVertexData will still need to be called to retrieve the underlying data.
	GetHyperedgeExtrinsics(id [64]byte) (*tries.VectorCommitmentTree, error)

	// Proof operations

	// CreateTraversalProof generates a verkle multiproof for the specified keys
	// within the given domain's atom set, contains traversal elements required to
	// verify the proof.
	CreateTraversalProof(
		domain [32]byte,
		atomType AtomType,
		phaseType PhaseType,
		keys [][]byte,
	) (*tries.TraversalProof, error)

	// VerifyTraversalProof validates a set of verkle multiproofs against the
	// current state of the hypergraph.
	VerifyTraversalProof(
		domain [32]byte,
		atomType AtomType,
		phaseType PhaseType,
		traversalProof *tries.TraversalProof,
	) (bool, error)

	// Transaction and utility operations

	// NewTransaction creates a new transaction for batch operations.
	NewTransaction(indexed bool) (
		tries.TreeBackingStoreTransaction,
		error,
	)

	// GetProver returns the inclusion prover used for triesgraphic operations.
	GetProver() crypto.InclusionProver
}

// Encrypted represents an encrypted data element that can be verified.
type Encrypted interface {
	// ToBytes serializes the encrypted data to bytes.
	ToBytes() []byte

	// GetStatement returns the statement being encrypted.
	GetStatement() []byte

	// Verify validates the proof for this encrypted data.
	Verify(proof []byte) bool
}
