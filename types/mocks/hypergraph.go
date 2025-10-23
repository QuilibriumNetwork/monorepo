package mocks

import (
	"context"
	"io"
	"math/big"

	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	hg "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type MockTransaction struct {
	mock.Mock
}

// Abort implements store.Transaction.
func (m *MockTransaction) Abort() error {
	args := m.Called()
	return args.Error(0)
}

// Commit implements store.Transaction.
func (m *MockTransaction) Commit() error {
	args := m.Called()
	return args.Error(0)
}

// Delete implements store.Transaction.
func (m *MockTransaction) Delete(key []byte) error {
	args := m.Called(key)
	return args.Error(0)
}

// DeleteRange implements store.Transaction.
func (m *MockTransaction) DeleteRange(
	lowerBound []byte,
	upperBound []byte,
) error {
	args := m.Called(lowerBound, upperBound)
	return args.Error(0)
}

// Get implements store.Transaction.
func (m *MockTransaction) Get(key []byte) ([]byte, io.Closer, error) {
	args := m.Called(key)
	return args.Get(0).([]byte), args.Get(1).(io.Closer), args.Error(2)
}

// NewIter implements store.Transaction.
func (m *MockTransaction) NewIter(
	lowerBound []byte,
	upperBound []byte,
) (store.Iterator, error) {
	args := m.Called(lowerBound, upperBound)
	return args.Get(0).(store.Iterator), args.Error(1)
}

// Set implements store.Transaction.
func (m *MockTransaction) Set(key []byte, value []byte) error {
	args := m.Called(key, value)
	return args.Error(0)
}

var _ store.Transaction = (*MockTransaction)(nil)

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
	protobufs.HypergraphComparisonServiceServer
	mock.Mock
}

// GetChildrenForPath implements hypergraph.Hypergraph.
func (h *MockHypergraph) GetChildrenForPath(
	context context.Context,
	req *protobufs.GetChildrenForPathRequest,
) (*protobufs.GetChildrenForPathResponse, error) {
	args := h.Called(context, req)
	return args.Get(0).(*protobufs.GetChildrenForPathResponse), args.Error(1)
}

// GetMetadataAtKey implements hypergraph.Hypergraph.
func (h *MockHypergraph) GetMetadataAtKey(pathKey []byte) (
	[]hg.ShardMetadata,
	error,
) {
	args := h.Called(pathKey)
	return args.Get(0).([]hg.ShardMetadata), args.Error(1)
}

// HyperStream implements hypergraph.Hypergraph.
func (h *MockHypergraph) HyperStream(
	server protobufs.HypergraphComparisonService_HyperStreamServer,
) error {
	args := h.Called(server)
	return args.Error(0)
}

// Sync implements hypergraph.Hypergraph.
func (h *MockHypergraph) Sync(
	stream protobufs.HypergraphComparisonService_HyperStreamClient,
	shardKey tries.ShardKey,
	phaseSet protobufs.HypergraphPhaseSet,
) error {
	args := h.Called(stream, shardKey, phaseSet)
	return args.Error(0)
}

// RunDataPruning implements hypergraph.Hypergraph.
func (h *MockHypergraph) RunDataPruning(
	txn tries.TreeBackingStoreTransaction,
	frameNumber uint64,
) error {
	args := h.Called(txn, frameNumber)
	return args.Error(0)
}

// GetCoveredPrefix implements hypergraph.Hypergraph.
func (h *MockHypergraph) GetCoveredPrefix() ([]int, error) {
	args := h.Called()
	return args.Get(0).([]int), args.Error(1)
}

// SetCoveredPrefix implements hypergraph.Hypergraph.
func (h *MockHypergraph) SetCoveredPrefix(prefix []int) error {
	args := h.Called(prefix)
	return args.Error(0)
}

// RevertChanges implements hypergraph.Hypergraph.
func (h *MockHypergraph) RevertChanges(
	txn tries.TreeBackingStoreTransaction,
	frameStart uint64,
	frameEnd uint64,
	shardKey tries.ShardKey,
) error {
	args := h.Called(txn, frameStart, frameEnd, shardKey)
	return args.Error(0)
}

// GetChanges implements hypergraph.Hypergraph.
func (h *MockHypergraph) GetChanges(
	frameStart uint64,
	frameEnd uint64,
	phaseType string,
	setType string,
	shardKey tries.ShardKey,
) ([]*tries.ChangeRecord, error) {
	args := h.Called(frameStart, frameEnd, phaseType, setType, shardKey)
	return args.Get(0).([]*tries.ChangeRecord), args.Error(1)
}

// TrackChange implements hypergraph.Hypergraph.
func (h *MockHypergraph) TrackChange(
	txn tries.TreeBackingStoreTransaction,
	key []byte,
	oldValue *tries.VectorCommitmentTree,
	frameNumber uint64,
	phaseType string,
	setType string,
	shardKey tries.ShardKey,
) error {
	args := h.Called(
		txn,
		key,
		oldValue,
		frameNumber,
		phaseType,
		setType,
		shardKey,
	)
	return args.Error(0)
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
	root []byte,
	traversalProof *tries.TraversalProof,
) (bool, error) {
	args := h.Called(domain, atomType, phaseType, root, traversalProof)
	return args.Bool(0), args.Error(1)
}

// GetProver implements hypergraph.Hypergraph.
func (h *MockHypergraph) GetProver() crypto.InclusionProver {
	args := h.Called()
	return args.Get(0).(crypto.InclusionProver)
}

// NewTransaction implements hypergraph.Hypergraph.
func (h *MockHypergraph) NewTransaction(indexed bool) (
	tries.TreeBackingStoreTransaction,
	error,
) {
	args := h.Called(indexed)
	return args.Get(0).(tries.TreeBackingStoreTransaction), args.Error(1)
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

// GetSize implements hypergraph.Hypergraph.
func (h *MockHypergraph) GetSize(key *tries.ShardKey, path []int) *big.Int {
	args := h.Called(key, path)
	return args.Get(0).(*big.Int)
}

// Commit implements hypergraph.Hypergraph.
func (h *MockHypergraph) Commit(
	frameNumber uint64,
) (map[tries.ShardKey][][]byte, error) {
	args := h.Called(frameNumber)
	return args.Get(0).(map[tries.ShardKey][][]byte), args.Error(1)
}

// CommitShard implements hypergraph.Hypergraph.
func (h *MockHypergraph) CommitShard(
	frameNumber uint64,
	shardAddress []byte,
) ([][]byte, error) {
	args := h.Called(frameNumber)
	return args.Get(0).([][]byte), args.Error(1)
}

// GetShardCommits implements hypergraph.Hypergraph.
func (h *MockHypergraph) GetShardCommits(
	frameNumber uint64,
	shardAddress []byte,
) ([][]byte, error) {
	args := h.Called(frameNumber, shardAddress)
	return args.Get(0).([][]byte), args.Error(1)
}

// GetVertex implements hypergraph.Hypergraph.
func (h *MockHypergraph) GetVertex(id [64]byte) (hg.Vertex, error) {
	args := h.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(hg.Vertex), args.Error(1)
}

// GetVertexData implements hypergraph.Hypergraph.
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

// AddVertex implements hypergraph.Hypergraph.
func (h *MockHypergraph) AddVertex(
	txn tries.TreeBackingStoreTransaction,
	v hg.Vertex,
) error {
	args := h.Called(txn, v)
	return args.Error(0)
}

// RemoveVertex implements hypergraph.Hypergraph.
func (h *MockHypergraph) RemoveVertex(
	txn tries.TreeBackingStoreTransaction,
	v hg.Vertex,
) error {
	args := h.Called(txn, v)
	return args.Error(0)
}

// RevertAddVertex implements hypergraph.Hypergraph.
func (h *MockHypergraph) RevertAddVertex(
	txn tries.TreeBackingStoreTransaction,
	v hg.Vertex,
) error {
	args := h.Called(txn, v)
	return args.Error(0)
}

// RevertRemoveVertex implements hypergraph.Hypergraph.
func (h *MockHypergraph) RevertRemoveVertex(
	txn tries.TreeBackingStoreTransaction,
	v hg.Vertex,
) error {
	args := h.Called(txn, v)
	return args.Error(0)
}

// LookupVertex implements hypergraph.Hypergraph.
func (h *MockHypergraph) LookupVertex(v hg.Vertex) bool {
	args := h.Called(v)
	return args.Bool(0)
}

// GetHyperedge implements hypergraph.Hypergraph.
func (h *MockHypergraph) GetHyperedge(id [64]byte) (hg.Hyperedge, error) {
	args := h.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(hg.Hyperedge), args.Error(1)
}

// AddHyperedge implements hypergraph.Hypergraph.
func (h *MockHypergraph) AddHyperedge(
	txn tries.TreeBackingStoreTransaction,
	he hg.Hyperedge,
) error {
	args := h.Called(txn, he)
	return args.Error(0)
}

// RemoveHyperedge implements hypergraph.Hypergraph.
func (h *MockHypergraph) RemoveHyperedge(
	txn tries.TreeBackingStoreTransaction,
	he hg.Hyperedge,
) error {
	args := h.Called(txn, he)
	return args.Error(0)
}

// RevertAddHyperedge implements hypergraph.Hypergraph.
func (h *MockHypergraph) RevertAddHyperedge(
	txn tries.TreeBackingStoreTransaction,
	he hg.Hyperedge,
) error {
	args := h.Called(txn, he)
	return args.Error(0)
}

// RevertRemoveHyperedge implements hypergraph.Hypergraph.
func (h *MockHypergraph) RevertRemoveHyperedge(
	txn tries.TreeBackingStoreTransaction,
	he hg.Hyperedge,
) error {
	args := h.Called(txn, he)
	return args.Error(0)
}

// LookupHyperedge implements hypergraph.Hypergraph.
func (h *MockHypergraph) LookupHyperedge(he hg.Hyperedge) bool {
	args := h.Called(he)
	return args.Bool(0)
}

// LookupAtom implements hypergraph.Hypergraph.
func (h *MockHypergraph) LookupAtom(a hg.Atom) bool {
	args := h.Called(a)
	return args.Bool(0)
}

// LookupAtomSet implements hypergraph.Hypergraph.
func (h *MockHypergraph) LookupAtomSet(atomSet []hg.Atom) bool {
	args := h.Called(atomSet)
	return args.Bool(0)
}

// Within implements hypergraph.Hypergraph.
func (h *MockHypergraph) Within(a, he hg.Atom) bool {
	args := h.Called(a, he)
	return args.Bool(0)
}

// GetVertexAddsSet implements hypergraph.Hypergraph.
func (h *MockHypergraph) GetVertexAddsSet(shardKey tries.ShardKey) hg.IdSet {
	args := h.Called(shardKey)
	return args.Get(0).(hg.IdSet)
}

// GetVertexRemovesSet implements hypergraph.Hypergraph.
func (h *MockHypergraph) GetVertexRemovesSet(
	shardKey tries.ShardKey,
) hg.IdSet {
	args := h.Called(shardKey)
	return args.Get(0).(hg.IdSet)
}

// GetHyperedgeAddsSet implements hypergraph.Hypergraph.
func (h *MockHypergraph) GetHyperedgeAddsSet(
	shardKey tries.ShardKey,
) hg.IdSet {
	args := h.Called(shardKey)
	return args.Get(0).(hg.IdSet)
}

// GetHyperedgeRemovesSet implements hypergraph.Hypergraph.
func (h *MockHypergraph) GetHyperedgeRemovesSet(
	shardKey tries.ShardKey,
) hg.IdSet {
	args := h.Called(shardKey)
	return args.Get(0).(hg.IdSet)
}

// ImportTree implements hypergraph.Hypergraph.
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
