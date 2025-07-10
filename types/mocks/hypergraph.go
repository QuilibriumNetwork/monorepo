package mocks

import (
	"math/big"

	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	hg "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// MockHyperedge mocks the Vertex implementation for testing
type MockVertex struct {
	mock.Mock
}

// Commit implements hypergraph.Vertex.
func (m *MockVertex) Commit(prover crypto.InclusionProver) []byte {
	args := m.Called(prover)
	return args.Get(0).([]byte)
}

// GetAppAddress implements hypergraph.Vertex.
func (m *MockVertex) GetAppAddress() [32]byte {
	args := m.Called()
	return args.Get(0).([32]byte)
}

// GetAtomType implements hypergraph.Vertex.
func (m *MockVertex) GetAtomType() hg.AtomType {
	return hg.VertexAtomType
}

// GetDataAddress implements hypergraph.Vertex.
func (m *MockVertex) GetDataAddress() [32]byte {
	args := m.Called()
	return args.Get(0).([32]byte)
}

// GetID implements hypergraph.Vertex.
func (m *MockVertex) GetID() [64]byte {
	args := m.Called()
	return args.Get(0).([64]byte)
}

// GetSize implements hypergraph.Vertex.
func (m *MockVertex) GetSize() *big.Int {
	args := m.Called()
	return args.Get(0).(*big.Int)
}

// ToBytes implements hypergraph.Vertex.
func (m *MockVertex) ToBytes() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

// MockHyperedge mocks the Hyperedge implementation for testing
type MockHyperedge struct {
	mock.Mock
}

// GetExtrinsicTree implements hypergraph.Hyperedge.
func (m *MockHyperedge) GetExtrinsicTree() *tries.VectorCommitmentTree {
	args := m.Called()
	return args.Get(0).(*tries.VectorCommitmentTree)
}

// AddExtrinsic implements hypergraph.Hyperedge.
func (m *MockHyperedge) AddExtrinsic(a hg.Atom) {
	m.Called(a)
}

// Commit implements hypergraph.Hyperedge.
func (m *MockHyperedge) Commit(prover crypto.InclusionProver) []byte {
	args := m.Called(prover)
	return args.Get(0).([]byte)
}

// GetAppAddress implements hypergraph.Hyperedge.
func (m *MockHyperedge) GetAppAddress() [32]byte {
	args := m.Called()
	return args.Get(0).([32]byte)
}

// GetAtomType implements hypergraph.Hyperedge.
func (m *MockHyperedge) GetAtomType() hg.AtomType {
	return hg.HyperedgeAtomType
}

// GetDataAddress implements hypergraph.Hyperedge.
func (m *MockHyperedge) GetDataAddress() [32]byte {
	args := m.Called()
	return args.Get(0).([32]byte)
}

// GetID implements hypergraph.Hyperedge.
func (m *MockHyperedge) GetID() [64]byte {
	args := m.Called()
	return args.Get(0).([64]byte)
}

// GetSize implements hypergraph.Hyperedge.
func (m *MockHyperedge) GetSize() *big.Int {
	args := m.Called()
	return args.Get(0).(*big.Int)
}

// RemoveExtrinsic implements hypergraph.Hyperedge.
func (m *MockHyperedge) RemoveExtrinsic(a hg.Atom) {
	m.Called(a)
}

// ToBytes implements hypergraph.Hyperedge.
func (m *MockHyperedge) ToBytes() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

// MockHypergraph mocks the Hypergraph implementation for testing
type MockHypergraph struct {
	mock.Mock
}

// GetVertexDataIterator implements hypergraph.Hypergraph.
func (h *MockHypergraph) GetVertexDataIterator(
	domain [32]byte,
) tries.VertexDataIterator {
	args := h.Called(domain)
	return args.Get(0).(tries.VertexDataIterator)
}

// GetHyperedgeExtrinsics implements hypergraph.Hypergraph.
func (h *MockHypergraph) GetHyperedgeExtrinsics(id [64]byte) (
	*tries.VectorCommitmentTree,
	error,
) {
	args := h.Called(id)
	return args.Get(0).(*tries.VectorCommitmentTree), args.Error(0)
}

// CreateTraversalProofs implements hypergraph.Hypergraph.
func (h *MockHypergraph) CreateTraversalProof(
	domain [32]byte,
	atomType hg.AtomType,
	phaseType hg.PhaseType,
	keys [][]byte,
) (*tries.TraversalProof, error) {
	args := h.Called(domain, atomType, phaseType, keys)
	return args.Get(0).(*tries.TraversalProof), args.Error(1)
}

// VerifyTraversalProofs implements hypergraph.Hypergraph.
func (h *MockHypergraph) VerifyTraversalProof(
	domain [32]byte,
	atomType hg.AtomType,
	phaseType hg.PhaseType,
	traversalProof *tries.TraversalProof,
) (bool, error) {
	args := h.Called(domain, atomType, phaseType, traversalProof)
	return args.Bool(0), args.Error(1)
}

// GetProver implements hypergraph.Hypergraph.
func (h *MockHypergraph) GetProver() crypto.InclusionProver {
	args := h.Called()
	return args.Get(0).(crypto.InclusionProver)
}

// MarkVertexDataForDeletion implements hypergraph.Hypergraph.
func (h *MockHypergraph) MarkVertexDataForDeletion(
	txn tries.TreeBackingStoreTransaction,
	deleteAt int64,
	id [64]byte,
) error {
	args := h.Called(txn, deleteAt, id)
	return args.Error(0)
}

// NewTransaction implements hypergraph.Hypergraph.
func (h *MockHypergraph) NewTransaction(indexed bool) (
	tries.TreeBackingStoreTransaction,
	error,
) {
	args := h.Called(indexed)
	return args.Get(0).(tries.TreeBackingStoreTransaction), args.Error(1)
}

// RunVertexDataPruning implements hypergraph.Hypergraph.
func (h *MockHypergraph) RunVertexDataPruning(
	txn tries.TreeBackingStoreTransaction,
) error {
	args := h.Called(txn)
	return args.Error(0)
}

// SetVertexData implements hypergraph.Hypergraph.
func (h *MockHypergraph) SetVertexData(
	txn tries.TreeBackingStoreTransaction,
	id [64]byte,
	data *tries.VectorCommitmentTree,
) error {
	args := h.Called(txn, id, data)
	return args.Error(0)
}

// UnmarkVertexDataForDeletion implements hypergraph.Hypergraph.
func (h *MockHypergraph) UnmarkVertexDataForDeletion(
	txn tries.TreeBackingStoreTransaction,
	deleteAt int64,
	id [64]byte,
) error {
	args := h.Called(txn, deleteAt, id)
	return args.Error(0)
}

// GetSize implements the interface
func (h *MockHypergraph) GetSize() *big.Int {
	args := h.Called()
	return args.Get(0).(*big.Int)
}

// Commit implements the interface
func (h *MockHypergraph) Commit() [][]byte {
	args := h.Called()
	return args.Get(0).([][]byte)
}

// GetVertex implements the interface
func (h *MockHypergraph) GetVertex(id [64]byte) (hg.Vertex, error) {
	args := h.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(hg.Vertex), args.Error(1)
}

// GetVertexData implements the interface
func (h *MockHypergraph) GetVertexData(id [64]byte) (
	*tries.VectorCommitmentTree,
	error,
) {
	args := h.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*tries.VectorCommitmentTree), args.Error(1)
}

// AddVertex implements the interface
func (h *MockHypergraph) AddVertex(
	txn tries.TreeBackingStoreTransaction,
	v hg.Vertex,
) error {
	args := h.Called(txn, v)
	return args.Error(0)
}

// RemoveVertex implements the interface
func (h *MockHypergraph) RemoveVertex(
	txn tries.TreeBackingStoreTransaction,
	v hg.Vertex,
) error {
	args := h.Called(txn, v)
	return args.Error(0)
}

// RevertAddVertex implements the interface
func (h *MockHypergraph) RevertAddVertex(
	txn tries.TreeBackingStoreTransaction,
	v hg.Vertex,
) error {
	args := h.Called(txn, v)
	return args.Error(0)
}

// RevertRemoveVertex implements the interface
func (h *MockHypergraph) RevertRemoveVertex(
	txn tries.TreeBackingStoreTransaction,
	v hg.Vertex,
) error {
	args := h.Called(txn, v)
	return args.Error(0)
}

// LookupVertex implements the interface
func (h *MockHypergraph) LookupVertex(v hg.Vertex) bool {
	args := h.Called(v)
	return args.Bool(0)
}

// GetHyperedge implements the interface
func (h *MockHypergraph) GetHyperedge(id [64]byte) (hg.Hyperedge, error) {
	args := h.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(hg.Hyperedge), args.Error(1)
}

// AddHyperedge implements the interface
func (h *MockHypergraph) AddHyperedge(
	txn tries.TreeBackingStoreTransaction,
	he hg.Hyperedge,
) error {
	args := h.Called(txn, he)
	return args.Error(0)
}

// RemoveHyperedge implements the interface
func (h *MockHypergraph) RemoveHyperedge(
	txn tries.TreeBackingStoreTransaction,
	he hg.Hyperedge,
) error {
	args := h.Called(txn, he)
	return args.Error(0)
}

// RevertAddHyperedge implements the interface
func (h *MockHypergraph) RevertAddHyperedge(
	txn tries.TreeBackingStoreTransaction,
	he hg.Hyperedge,
) error {
	args := h.Called(txn, he)
	return args.Error(0)
}

// RevertRemoveHyperedge implements the interface
func (h *MockHypergraph) RevertRemoveHyperedge(
	txn tries.TreeBackingStoreTransaction,
	he hg.Hyperedge,
) error {
	args := h.Called(txn, he)
	return args.Error(0)
}

// LookupHyperedge implements the interface
func (h *MockHypergraph) LookupHyperedge(he hg.Hyperedge) bool {
	args := h.Called(he)
	return args.Bool(0)
}

// LookupAtom implements the interface
func (h *MockHypergraph) LookupAtom(a hg.Atom) bool {
	args := h.Called(a)
	return args.Bool(0)
}

// LookupAtomSet implements the interface
func (h *MockHypergraph) LookupAtomSet(atomSet []hg.Atom) bool {
	args := h.Called(atomSet)
	return args.Bool(0)
}

// Within implements the interface
func (h *MockHypergraph) Within(a, he hg.Atom) bool {
	args := h.Called(a, he)
	return args.Bool(0)
}

// GetVertexAdds implements the interface
func (h *MockHypergraph) GetVertexAdds() map[tries.ShardKey]*hg.IdSet {
	args := h.Called()
	return args.Get(0).(map[tries.ShardKey]*hg.IdSet)
}

// GetVertexRemoves implements the interface
func (h *MockHypergraph) GetVertexRemoves() map[tries.ShardKey]*hg.IdSet {
	args := h.Called()
	return args.Get(0).(map[tries.ShardKey]*hg.IdSet)
}

// GetHyperedgeAdds implements the interface
func (h *MockHypergraph) GetHyperedgeAdds() map[tries.ShardKey]*hg.IdSet {
	args := h.Called()
	return args.Get(0).(map[tries.ShardKey]*hg.IdSet)
}

// GetHyperedgeRemoves implements the interface
func (h *MockHypergraph) GetHyperedgeRemoves() map[tries.ShardKey]*hg.IdSet {
	args := h.Called()
	return args.Get(0).(map[tries.ShardKey]*hg.IdSet)
}

// ImportTree implements the interface
func (h *MockHypergraph) ImportTree(
	atomType hg.AtomType,
	phaseType hg.PhaseType,
	shardKey tries.ShardKey,
	root tries.LazyVectorCommitmentNode,
	store tries.TreeBackingStore,
	prover crypto.InclusionProver,
) error {
	args := h.Called(atomType, phaseType, shardKey, root, store, prover)
	return args.Error(0)
}

// Ensure MockHypergraph implements Hypergraph
var _ hg.Hypergraph = (*MockHypergraph)(nil)

// Ensure MockHyperedge implements Hyperedge
var _ hg.Hyperedge = (*MockHyperedge)(nil)

// Ensure MockVertex implements Vertex
var _ hg.Vertex = (*MockVertex)(nil)
