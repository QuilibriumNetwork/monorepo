package tries

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

// MemoryTreeBackingStore implements TreeBackingStore with in-memory maps.
// This is used by qclient for client-side tree reconstruction from RPC data.
type MemoryTreeBackingStore struct {
	mu    sync.RWMutex
	nodes map[string]LazyVectorCommitmentNode // key: composite key
	roots map[string]LazyVectorCommitmentNode // key: setType+phaseType+shardKey
}

func NewMemoryTreeBackingStore() *MemoryTreeBackingStore {
	return &MemoryTreeBackingStore{
		nodes: make(map[string]LazyVectorCommitmentNode),
		roots: make(map[string]LazyVectorCommitmentNode),
	}
}

func memoryNodeKey(setType, phaseType string, shardKey ShardKey, key []byte) string {
	return fmt.Sprintf("%s:%s:%x:%x:%x", setType, phaseType, shardKey.L1, shardKey.L2, key)
}

func memoryPathKey(setType, phaseType string, shardKey ShardKey, path []int) string {
	h := sha3.Sum256(encodePathForKey(path))
	return fmt.Sprintf("%s:%s:%x:%x:path:%x", setType, phaseType, shardKey.L1, shardKey.L2, h[:])
}

func memoryRootKey(setType, phaseType string, shardKey ShardKey) string {
	return fmt.Sprintf("%s:%s:%x:%x", setType, phaseType, shardKey.L1, shardKey.L2)
}

func encodePathForKey(path []int) []byte {
	buf := make([]byte, len(path)*4)
	for i, p := range path {
		binary.BigEndian.PutUint32(buf[i*4:], uint32(p))
	}
	return buf
}

// MemoryTransaction implements TreeBackingStoreTransaction.
type MemoryTransaction struct {
	store   *MemoryTreeBackingStore
	pending map[string][]byte
	deletes map[string]bool
}

func (t *MemoryTransaction) Get(key []byte) ([]byte, io.Closer, error) {
	k := string(key)
	if t.deletes[k] {
		return nil, io.NopCloser(nil), errors.New("item not found")
	}
	if v, ok := t.pending[k]; ok {
		return v, io.NopCloser(nil), nil
	}
	return nil, io.NopCloser(nil), errors.New("item not found")
}

func (t *MemoryTransaction) Set(key []byte, value []byte) error {
	t.pending[string(key)] = append([]byte{}, value...)
	delete(t.deletes, string(key))
	return nil
}

func (t *MemoryTransaction) Delete(key []byte) error {
	t.deletes[string(key)] = true
	delete(t.pending, string(key))
	return nil
}

func (t *MemoryTransaction) DeleteRange(lowerBound []byte, upperBound []byte) error {
	return nil
}

func (t *MemoryTransaction) Commit() error {
	return nil
}

func (t *MemoryTransaction) Abort() error {
	t.pending = nil
	t.deletes = nil
	return nil
}

// TreeBackingStore interface implementation

func (m *MemoryTreeBackingStore) NewTransaction(indexed bool) (TreeBackingStoreTransaction, error) {
	return &MemoryTransaction{
		store:   m,
		pending: make(map[string][]byte),
		deletes: make(map[string]bool),
	}, nil
}

func (m *MemoryTreeBackingStore) GetNodeByKey(
	setType string,
	phaseType string,
	shardKey ShardKey,
	key []byte,
) (LazyVectorCommitmentNode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	k := memoryNodeKey(setType, phaseType, shardKey, key)
	if node, ok := m.nodes[k]; ok {
		return node, nil
	}
	return nil, errors.New("item not found")
}

func (m *MemoryTreeBackingStore) GetNodeByPath(
	setType string,
	phaseType string,
	shardKey ShardKey,
	path []int,
) (LazyVectorCommitmentNode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	k := memoryPathKey(setType, phaseType, shardKey, path)
	if node, ok := m.nodes[k]; ok {
		return node, nil
	}
	return nil, errors.New("item not found")
}

func (m *MemoryTreeBackingStore) InsertNode(
	txn TreeBackingStoreTransaction,
	setType string,
	phaseType string,
	shardKey ShardKey,
	key []byte,
	path []int,
	node LazyVectorCommitmentNode,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := memoryNodeKey(setType, phaseType, shardKey, key)
	m.nodes[k] = node

	pk := memoryPathKey(setType, phaseType, shardKey, path)
	m.nodes[pk] = node
	return nil
}

func (m *MemoryTreeBackingStore) SaveRoot(
	txn TreeBackingStoreTransaction,
	setType string,
	phaseType string,
	shardKey ShardKey,
	node LazyVectorCommitmentNode,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := memoryRootKey(setType, phaseType, shardKey)
	m.roots[k] = node
	return nil
}

func (m *MemoryTreeBackingStore) DeleteNode(
	txn TreeBackingStoreTransaction,
	setType string,
	phaseType string,
	shardKey ShardKey,
	key []byte,
	path []int,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := memoryNodeKey(setType, phaseType, shardKey, key)
	delete(m.nodes, k)

	pk := memoryPathKey(setType, phaseType, shardKey, path)
	delete(m.nodes, pk)
	return nil
}

func (m *MemoryTreeBackingStore) LoadVertexTree(id []byte) (
	*VectorCommitmentTree,
	error,
) {
	return nil, errors.New("not supported in memory store")
}

func (m *MemoryTreeBackingStore) SaveVertexTree(
	txn TreeBackingStoreTransaction,
	id []byte,
	vertTree *VectorCommitmentTree,
) error {
	return nil
}

func (m *MemoryTreeBackingStore) DeleteVertexTree(
	txn TreeBackingStoreTransaction,
	id []byte,
) error {
	return nil
}

func (m *MemoryTreeBackingStore) GetVertexDataIterator(
	prefix ShardKey,
) (VertexDataIterator, error) {
	return nil, errors.New("not supported in memory store")
}

func (m *MemoryTreeBackingStore) DeleteUncoveredPrefix(
	setType string,
	phaseType string,
	shardKey ShardKey,
	prefix []int,
) error {
	return nil
}

func (m *MemoryTreeBackingStore) ReapOldChangesets(
	txn TreeBackingStoreTransaction,
	frameNumber uint64,
) error {
	return nil
}

func (m *MemoryTreeBackingStore) TrackChange(
	txn TreeBackingStoreTransaction,
	key []byte,
	oldValue *VectorCommitmentTree,
	frameNumber uint64,
	phaseType string,
	setType string,
	shardKey ShardKey,
) error {
	return nil
}

func (m *MemoryTreeBackingStore) GetChanges(
	frameStart uint64,
	frameEnd uint64,
	phaseType string,
	setType string,
	shardKey ShardKey,
) ([]*ChangeRecord, error) {
	return nil, nil
}

func (m *MemoryTreeBackingStore) UntrackChange(
	txn TreeBackingStoreTransaction,
	key []byte,
	frameNumber uint64,
	phaseType string,
	setType string,
	shardKey ShardKey,
) error {
	return nil
}

func (m *MemoryTreeBackingStore) SetCoveredPrefix(path []int) error {
	return nil
}

func (m *MemoryTreeBackingStore) SetShardCommit(
	txn TreeBackingStoreTransaction,
	frameNumber uint64,
	phaseType string,
	setType string,
	shardAddress []byte,
	commitment []byte,
) error {
	return nil
}

func (m *MemoryTreeBackingStore) GetShardCommit(
	frameNumber uint64,
	phaseType string,
	setType string,
	shardAddress []byte,
) ([]byte, error) {
	return nil, errors.New("not supported in memory store")
}

func (m *MemoryTreeBackingStore) GetRootCommits(
	frameNumber uint64,
) (map[ShardKey][][]byte, error) {
	return nil, errors.New("not supported in memory store")
}

func (m *MemoryTreeBackingStore) NewShardSnapshot(
	shardKey ShardKey,
) (TreeBackingStore, func(), error) {
	return m, func() {}, nil
}

func (m *MemoryTreeBackingStore) NewDBSnapshot() (DBSnapshot, error) {
	return &memoryDBSnapshot{}, nil
}

func (m *MemoryTreeBackingStore) NewShardSnapshotFromDBSnapshot(
	shardKey ShardKey,
	dbSnapshot DBSnapshot,
) (TreeBackingStore, func(), error) {
	return m, func() {}, nil
}

func (m *MemoryTreeBackingStore) IterateRawLeaves(
	setType string,
	phaseType string,
	shardKey ShardKey,
) (RawLeafIterator, error) {
	return nil, errors.New("not supported in memory store")
}

func (m *MemoryTreeBackingStore) InsertRawLeaf(
	txn TreeBackingStoreTransaction,
	setType string,
	phaseType string,
	shardKey ShardKey,
	leaf *RawLeafData,
) error {
	return nil
}

type memoryDBSnapshot struct{}

func (s *memoryDBSnapshot) Close() error { return nil }
