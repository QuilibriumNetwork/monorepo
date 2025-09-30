package hypergraph

import (
	"math/big"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
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

// HyperStream defines the synchronization stream interface shared by a syncing
// client and server instance.
type HyperStream interface {
	Send(*protobufs.HypergraphComparison) error
	Recv() (*protobufs.HypergraphComparison, error)
}

// Hypergraph defines the interface for hypergraph operations. A hypergraph is a
// higher-dimensional generalization of a graph where edges (hyperedges) can
// connect any number of vertices or hyperedges themselves.
type Hypergraph interface {
	// GetSize returns the current total size of the hypergraph or at a key. The
	// size is calculated as the sum of all added atoms' sizes minus removed
	// atoms.
	GetSize(shardKey *tries.ShardKey, path []int) *big.Int

	// Commit calculates the hierarchical vector commitments for each shard's
	// add/remove sets and returns the roots.
	Commit() map[tries.ShardKey][][]byte

	// SetCoveredPrefix sets a prefix where inserted values are retained. Values
	// outside of this will be rejected – synchronization will only set neighbor
	// and ascendant branches.
	SetCoveredPrefix(prefix []int) error

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

	// GetVertexDataIterator exposes an iterator to enumerate all data objects
	// stored under the given domain
	GetVertexDataIterator(domain [32]byte) tries.VertexDataIterator

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

	// RunDataPruning executes the deletion of changesets prior to the given
	// frame number. This should be called periodically to save room.
	RunDataPruning(
		txn tries.TreeBackingStoreTransaction,
		frameNumber uint64,
	) error

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

	// Reversion-oriented methods

	// TrackChange tracks a previous state for data for reversion purposes.
	TrackChange(
		txn tries.TreeBackingStoreTransaction,
		key []byte,
		oldValue *tries.VectorCommitmentTree,
		frameNumber uint64,
		phaseType string,
		setType string,
		shardKey tries.ShardKey,
	) error

	// GetChanges returns the set of previous states in reverse chronological
	// order.
	GetChanges(
		frameStart uint64,
		frameEnd uint64,
		phaseType string,
		setType string,
		shardKey tries.ShardKey,
	) ([]*tries.ChangeRecord, error)

	// RevertChanges reverts the set of changes in reverse chronological order.
	RevertChanges(
		txn tries.TreeBackingStoreTransaction,
		frameStart uint64,
		frameEnd uint64,
		shardKey tries.ShardKey,
	) error

	// Synchronization operations

	// Embeds the comparison service
	protobufs.HypergraphComparisonServiceServer

	// Sync is the client-side initiator for synchronization.
	Sync(
		stream protobufs.HypergraphComparisonService_HyperStreamClient,
		shardKey tries.ShardKey,
		phaseSet protobufs.HypergraphPhaseSet,
	) error

	// Transaction and utility operations

	// NewTransaction creates a new transaction for batch operations.
	NewTransaction(indexed bool) (
		tries.TreeBackingStoreTransaction,
		error,
	)

	// GetProver returns the inclusion prover used for cryptographic operations.
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
