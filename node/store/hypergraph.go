package store

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"path"
	"slices"

	"github.com/cockroachdb/pebble/v2"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

var _ store.HypergraphStore = (*PebbleHypergraphStore)(nil)

type PebbleHypergraphStore struct {
	config *config.DBConfig
	db     store.KVDB
	logger *zap.Logger
	verenc crypto.VerifiableEncryptor
	prover crypto.InclusionProver
	pebble *pebble.DB
}

func NewPebbleHypergraphStore(
	config *config.DBConfig,
	db store.KVDB,
	logger *zap.Logger,
	verenc crypto.VerifiableEncryptor,
	prover crypto.InclusionProver,
) *PebbleHypergraphStore {
	var pebbleHandle *pebble.DB
	if pdb, ok := db.(*PebbleDB); ok {
		pebbleHandle = pdb.DB()
	}

	return &PebbleHypergraphStore{
		config,
		db,
		logger,
		verenc,
		prover,
		pebbleHandle,
	}
}

func (p *PebbleHypergraphStore) NewShardSnapshot(
	shardKey tries.ShardKey,
) (
	tries.TreeBackingStore,
	func(),
	error,
) {
	memDBConfig := *p.config
	memDBConfig.InMemoryDONOTUSE = true
	memDBConfig.Path = fmt.Sprintf(
		"memory-shard-%x",
		shardKey.L2[:4],
	)
	// Wrap DBConfig in a minimal Config for NewPebbleDB
	memConfig := &config.Config{
		DB: &memDBConfig,
	}

	memDB := NewPebbleDB(p.logger, memConfig, 0)
	managedDB := newManagedKVDB(memDB)
	snapshotStore := NewPebbleHypergraphStore(
		&memDBConfig,
		managedDB,
		p.logger,
		p.verenc,
		p.prover,
	)
	snapshotStore.pebble = nil

	if err := p.copyShardData(managedDB, shardKey); err != nil {
		_ = managedDB.Close()
		return nil, nil, errors.Wrap(err, "copy shard snapshot")
	}

	release := func() {
		if err := managedDB.Close(); err != nil {
			p.logger.Warn("failed to close shard snapshot", zap.Error(err))
		}
	}

	return snapshotStore, release, nil
}

// pebbleDBSnapshot wraps a pebble.Snapshot to implement tries.DBSnapshot.
type pebbleDBSnapshot struct {
	snap *pebble.Snapshot
}

func (s *pebbleDBSnapshot) Close() error {
	if s.snap == nil {
		return nil
	}
	return s.snap.Close()
}

// NewDBSnapshot creates a point-in-time snapshot of the database.
// This is used to ensure consistency when creating shard snapshots.
func (p *PebbleHypergraphStore) NewDBSnapshot() (tries.DBSnapshot, error) {
	if p.pebble == nil {
		return nil, errors.New("pebble handle not available for snapshot")
	}
	snap := p.pebble.NewSnapshot()
	return &pebbleDBSnapshot{snap: snap}, nil
}

// NewShardSnapshotFromDBSnapshot creates a shard snapshot using data from
// an existing database snapshot. This ensures the shard snapshot reflects
// the exact state at the time the DB snapshot was taken.
func (p *PebbleHypergraphStore) NewShardSnapshotFromDBSnapshot(
	shardKey tries.ShardKey,
	dbSnapshot tries.DBSnapshot,
) (
	tries.TreeBackingStore,
	func(),
	error,
) {
	pebbleSnap, ok := dbSnapshot.(*pebbleDBSnapshot)
	if !ok || pebbleSnap.snap == nil {
		return nil, nil, errors.New("invalid database snapshot")
	}

	memDBConfig := *p.config
	memDBConfig.InMemoryDONOTUSE = true
	memDBConfig.Path = fmt.Sprintf(
		"memory-shard-%x",
		shardKey.L2[:4],
	)
	// Wrap DBConfig in a minimal Config for NewPebbleDB
	memConfig := &config.Config{
		DB: &memDBConfig,
	}

	memDB := NewPebbleDB(p.logger, memConfig, 0)
	managedDB := newManagedKVDB(memDB)
	snapshotStore := NewPebbleHypergraphStore(
		&memDBConfig,
		managedDB,
		p.logger,
		p.verenc,
		p.prover,
	)
	snapshotStore.pebble = nil

	// Copy data from the pebble snapshot instead of the live DB
	if err := p.copyShardDataFromSnapshot(managedDB, shardKey, pebbleSnap.snap); err != nil {
		_ = managedDB.Close()
		return nil, nil, errors.Wrap(err, "copy shard snapshot from db snapshot")
	}

	release := func() {
		if err := managedDB.Close(); err != nil {
			p.logger.Warn("failed to close shard snapshot", zap.Error(err))
		}
	}

	return snapshotStore, release, nil
}

// copyShardDataFromSnapshot copies shard data from a pebble snapshot to the
// destination DB. This is similar to copyShardData but reads from a snapshot
// instead of the live database.
func (p *PebbleHypergraphStore) copyShardDataFromSnapshot(
	dst store.KVDB,
	shardKey tries.ShardKey,
	snap *pebble.Snapshot,
) error {
	prefixes := []byte{
		VERTEX_ADDS_TREE_NODE,
		VERTEX_REMOVES_TREE_NODE,
		HYPEREDGE_ADDS_TREE_NODE,
		HYPEREDGE_REMOVES_TREE_NODE,
		VERTEX_ADDS_TREE_NODE_BY_PATH,
		VERTEX_REMOVES_TREE_NODE_BY_PATH,
		HYPEREDGE_ADDS_TREE_NODE_BY_PATH,
		HYPEREDGE_REMOVES_TREE_NODE_BY_PATH,
		VERTEX_ADDS_TREE_ROOT,
		VERTEX_REMOVES_TREE_ROOT,
		HYPEREDGE_ADDS_TREE_ROOT,
		HYPEREDGE_REMOVES_TREE_ROOT,
		VERTEX_ADDS_CHANGE_RECORD,
		VERTEX_REMOVES_CHANGE_RECORD,
		HYPEREDGE_ADDS_CHANGE_RECORD,
		HYPEREDGE_REMOVES_CHANGE_RECORD,
		HYPERGRAPH_VERTEX_ADDS_SHARD_COMMIT,
		HYPERGRAPH_VERTEX_REMOVES_SHARD_COMMIT,
		HYPERGRAPH_HYPEREDGE_ADDS_SHARD_COMMIT,
		HYPERGRAPH_HYPEREDGE_REMOVES_SHARD_COMMIT,
	}

	for _, prefix := range prefixes {
		if err := p.copyPrefixedRangeFromSnapshot(dst, prefix, shardKey, snap); err != nil {
			return err
		}
	}

	if err := p.copyVertexDataForShardFromSnapshot(dst, shardKey, snap); err != nil {
		return err
	}

	if err := p.copyCoveredPrefixFromSnapshot(dst, snap); err != nil {
		return err
	}

	return nil
}

func (p *PebbleHypergraphStore) copyPrefixedRangeFromSnapshot(
	dst store.KVDB,
	prefix byte,
	shardKey tries.ShardKey,
	snap *pebble.Snapshot,
) error {
	start, end := shardRangeBounds(prefix, shardKey)
	iter, err := snap.NewIter(&pebble.IterOptions{
		LowerBound: start,
		UpperBound: end,
	})
	if err != nil {
		return errors.Wrap(err, "snapshot: iter range from snapshot")
	}
	defer iter.Close()

	for valid := iter.First(); valid; valid = iter.Next() {
		key := append([]byte(nil), iter.Key()...)
		val := append([]byte(nil), iter.Value()...)
		if err := dst.Set(key, val); err != nil {
			return errors.Wrap(err, "snapshot: set range value")
		}
	}

	return nil
}

func (p *PebbleHypergraphStore) copyVertexDataForShardFromSnapshot(
	dst store.KVDB,
	shardKey tries.ShardKey,
	snap *pebble.Snapshot,
) error {
	sets := []struct {
		setType   string
		phaseType string
	}{
		{string(hypergraph.VertexAtomType), string(hypergraph.AddsPhaseType)},
		{string(hypergraph.VertexAtomType), string(hypergraph.RemovesPhaseType)},
	}

	vertexKeys := make(map[string]struct{})
	for _, cfg := range sets {
		// Use snapshot-based iteration
		iter, err := p.iterateRawLeavesFromSnapshot(cfg.setType, cfg.phaseType, shardKey, snap)
		if err != nil {
			return errors.Wrap(err, "snapshot: iterate raw leaves from snapshot")
		}
		for valid := iter.First(); valid; valid = iter.Next() {
			leaf, err := iter.Leaf()
			if err != nil || leaf == nil {
				continue
			}
			if len(leaf.UnderlyingData) == 0 {
				continue
			}
			keyStr := string(leaf.Key)
			if _, ok := vertexKeys[keyStr]; ok {
				continue
			}
			vertexKeys[keyStr] = struct{}{}
			buf := append([]byte(nil), leaf.UnderlyingData...)
			if err := dst.Set(hypergraphVertexDataKey(leaf.Key), buf); err != nil {
				iter.Close()
				return errors.Wrap(err, "snapshot: copy vertex data")
			}
		}
		iter.Close()
	}

	return nil
}

func (p *PebbleHypergraphStore) copyCoveredPrefixFromSnapshot(
	dst store.KVDB,
	snap *pebble.Snapshot,
) error {
	val, closer, err := snap.Get([]byte{HYPERGRAPH_COVERED_PREFIX})
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil
		}
		return errors.Wrap(err, "snapshot: get covered prefix")
	}
	defer closer.Close()
	buf := append([]byte(nil), val...)
	return dst.Set([]byte{HYPERGRAPH_COVERED_PREFIX}, buf)
}

// pebbleSnapshotRawLeafIterator iterates over raw leaves from a pebble snapshot.
type pebbleSnapshotRawLeafIterator struct {
	iter     *pebble.Iterator
	shardKey tries.ShardKey
	snap     *pebble.Snapshot
	setType  string
	db       *PebbleHypergraphStore
}

func (p *PebbleHypergraphStore) iterateRawLeavesFromSnapshot(
	setType string,
	phaseType string,
	shardKey tries.ShardKey,
	snap *pebble.Snapshot,
) (*pebbleSnapshotRawLeafIterator, error) {
	// Determine the key prefix based on set and phase type
	var keyPrefix byte
	switch hypergraph.AtomType(setType) {
	case hypergraph.VertexAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			keyPrefix = VERTEX_ADDS_TREE_NODE
		case hypergraph.RemovesPhaseType:
			keyPrefix = VERTEX_REMOVES_TREE_NODE
		default:
			return nil, errors.New("unknown phase type")
		}
	case hypergraph.HyperedgeAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			keyPrefix = HYPEREDGE_ADDS_TREE_NODE
		case hypergraph.RemovesPhaseType:
			keyPrefix = HYPEREDGE_REMOVES_TREE_NODE
		default:
			return nil, errors.New("unknown phase type")
		}
	default:
		return nil, errors.New("unknown set type")
	}

	start, end := shardRangeBounds(keyPrefix, shardKey)
	iter, err := snap.NewIter(&pebble.IterOptions{
		LowerBound: start,
		UpperBound: end,
	})
	if err != nil {
		return nil, errors.Wrap(err, "iterate raw leaves from snapshot")
	}

	return &pebbleSnapshotRawLeafIterator{
		iter:     iter,
		shardKey: shardKey,
		snap:     snap,
		setType:  setType,
		db:       p,
	}, nil
}

func (i *pebbleSnapshotRawLeafIterator) First() bool {
	return i.iter.First()
}

func (i *pebbleSnapshotRawLeafIterator) Next() bool {
	return i.iter.Next()
}

func (i *pebbleSnapshotRawLeafIterator) Close() {
	i.iter.Close()
}

func (i *pebbleSnapshotRawLeafIterator) Leaf() (*tries.RawLeafData, error) {
	if !i.iter.Valid() {
		return nil, nil
	}

	nodeData := i.iter.Value()
	if len(nodeData) == 0 {
		return nil, nil
	}

	// Only process leaf nodes (type byte == TypeLeaf)
	if nodeData[0] != tries.TypeLeaf {
		return nil, nil
	}

	leaf, err := tries.DeserializeLeafNode(i.db, bytes.NewReader(nodeData[1:]))
	if err != nil {
		return nil, err
	}

	result := &tries.RawLeafData{
		Key:        slices.Clone(leaf.Key),
		Value:      slices.Clone(leaf.Value),
		HashTarget: slices.Clone(leaf.HashTarget),
		Commitment: slices.Clone(leaf.Commitment),
	}

	if leaf.Size != nil {
		result.Size = leaf.Size.FillBytes(make([]byte, 32))
	}

	// Load vertex data from snapshot if this is a vertex set
	if i.setType == string(hypergraph.VertexAtomType) {
		dataVal, closer, err := i.snap.Get(hypergraphVertexDataKey(leaf.Key))
		if err == nil {
			result.UnderlyingData = append([]byte(nil), dataVal...)
			closer.Close()
		}
	}

	return result, nil
}

type PebbleVertexDataIterator struct {
	i        store.Iterator
	db       *PebbleHypergraphStore
	prover   crypto.InclusionProver
	shardKey tries.ShardKey
}

// Key returns the current key (vertex ID) without the prefix
func (p *PebbleVertexDataIterator) Key() []byte {
	if !p.i.Valid() {
		return nil
	}

	key := p.i.Key()
	return key[2:]
}

// First moves the iterator to the first key/value pair
func (p *PebbleVertexDataIterator) First() bool {
	return p.i.First()
}

// Next moves the iterator to the next key/value pair
func (p *PebbleVertexDataIterator) Next() bool {
	return p.i.Next()
}

// Prev moves the iterator to the previous key/value pair
func (p *PebbleVertexDataIterator) Prev() bool {
	return p.i.Prev()
}

// Valid returns true if the iterator is positioned at a valid key/value pair
func (p *PebbleVertexDataIterator) Valid() bool {
	return p.i.Valid()
}

// Value returns the current value as a VectorCommitmentTree
func (p *PebbleVertexDataIterator) Value() *tries.VectorCommitmentTree {
	if !p.i.Valid() {
		return nil
	}

	value := p.i.Value()
	if len(value) == 0 {
		return nil
	}

	_, closer, err := p.db.db.Get(
		hypergraphVertexRemovesTreeNodeKey(p.shardKey, p.i.Key()),
	)
	if err == nil {
		closer.Close()

		// Vertex is removed, represent as nil (will be reaped)
		return nil
	}

	tree, err := tries.DeserializeNonLazyTree(slices.Clone(value))
	if err != nil {
		return nil
	}

	return tree
}

// Close releases the iterator resources
func (p *PebbleVertexDataIterator) Close() error {
	return errors.Wrap(p.i.Close(), "close")
}

// Last moves the iterator to the last key/value pair
func (p *PebbleVertexDataIterator) Last() bool {
	return p.i.Last()
}

var _ tries.VertexDataIterator = (*PebbleVertexDataIterator)(nil)

func hypergraphVertexDataKey(id []byte) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_DATA}
	key = append(key, id...)
	return key
}

func hypergraphVertexAddsTreeNodeKey(
	shardKey tries.ShardKey,
	nodeKey []byte,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_ADDS_TREE_NODE}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	key = append(key, nodeKey...)
	return key
}

func hypergraphVertexRemovesTreeNodeKey(
	shardKey tries.ShardKey,
	nodeKey []byte,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_REMOVES_TREE_NODE}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	key = append(key, nodeKey...)
	return key
}

func hypergraphHyperedgeAddsTreeNodeKey(
	shardKey tries.ShardKey,
	nodeKey []byte,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS_TREE_NODE}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	key = append(key, nodeKey...)
	return key
}

func hypergraphHyperedgeRemovesTreeNodeKey(
	shardKey tries.ShardKey,
	nodeKey []byte,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES_TREE_NODE}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	key = append(key, nodeKey...)
	return key
}

func hypergraphVertexAddsTreeNodeByPathKey(
	shardKey tries.ShardKey,
	path []int,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_ADDS_TREE_NODE_BY_PATH}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	for _, p := range path {
		key = binary.BigEndian.AppendUint64(key, uint64(p))
	}
	return key
}

func hypergraphVertexRemovesTreeNodeByPathKey(
	shardKey tries.ShardKey,
	path []int,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_REMOVES_TREE_NODE_BY_PATH}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	for _, p := range path {
		key = binary.BigEndian.AppendUint64(key, uint64(p))
	}
	return key
}

func hypergraphHyperedgeAddsTreeNodeByPathKey(
	shardKey tries.ShardKey,
	path []int,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS_TREE_NODE_BY_PATH}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	for _, p := range path {
		key = binary.BigEndian.AppendUint64(key, uint64(p))
	}
	return key
}

func hypergraphHyperedgeRemovesTreeNodeByPathKey(
	shardKey tries.ShardKey,
	path []int,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES_TREE_NODE_BY_PATH}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	for _, p := range path {
		key = binary.BigEndian.AppendUint64(key, uint64(p))
	}
	return key
}

func hypergraphChangeRecordKey(
	setType string,
	phaseType string,
	shardKey tries.ShardKey,
	frameNumber uint64,
	key []byte,
) []byte {
	var changeType byte
	switch hypergraph.AtomType(setType) {
	case hypergraph.VertexAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			changeType = VERTEX_ADDS_CHANGE_RECORD
		case hypergraph.RemovesPhaseType:
			changeType = VERTEX_REMOVES_CHANGE_RECORD
		}
	case hypergraph.HyperedgeAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			changeType = HYPEREDGE_ADDS_CHANGE_RECORD
		case hypergraph.RemovesPhaseType:
			changeType = HYPEREDGE_REMOVES_CHANGE_RECORD
		}
	}
	result := []byte{HYPERGRAPH_SHARD, changeType}
	result = append(result, shardKey.L1[:]...)
	result = append(result, shardKey.L2[:]...)
	result = binary.BigEndian.AppendUint64(result, frameNumber)
	result = append(result, key...)
	return result
}

func hypergraphVertexAddsTreeRootKey(
	shardKey tries.ShardKey,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_ADDS_TREE_ROOT}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func hypergraphVertexRemovesTreeRootKey(
	shardKey tries.ShardKey,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_REMOVES_TREE_ROOT}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func hypergraphHyperedgeAddsTreeRootKey(
	shardKey tries.ShardKey,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS_TREE_ROOT}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func hypergraphHyperedgeRemovesTreeRootKey(
	shardKey tries.ShardKey,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES_TREE_ROOT}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

// shard commits have a slightly different structure, because fast scanning
// of the range in a given frame number is preferable
func hypergraphVertexAddsShardCommitKey(
	frameNumber uint64,
	shardAddress []byte,
) []byte {
	key := []byte{HYPERGRAPH_SHARD}
	// The first byte is technically reserved – but in practicality won't be
	// non-zero (SHARD_COMMMIT)
	key = binary.BigEndian.AppendUint64(key, frameNumber)
	key = append(key, HYPERGRAPH_VERTEX_ADDS_SHARD_COMMIT)
	key = append(key, shardAddress...)
	return key
}

func hypergraphVertexRemovesShardCommitKey(
	frameNumber uint64,
	shardAddress []byte,
) []byte {
	key := []byte{HYPERGRAPH_SHARD}
	// The first byte is technically reserved – but in practicality won't be
	// non-zero (SHARD_COMMMIT)
	key = binary.BigEndian.AppendUint64(key, frameNumber)
	key = append(key, HYPERGRAPH_VERTEX_REMOVES_SHARD_COMMIT)
	key = append(key, shardAddress...)
	return key
}

func hypergraphHyperedgeAddsShardCommitKey(
	frameNumber uint64,
	shardAddress []byte,
) []byte {
	key := []byte{HYPERGRAPH_SHARD}
	// The first byte is technically reserved – but in practicality won't be
	// non-zero (SHARD_COMMMIT)
	key = binary.BigEndian.AppendUint64(key, frameNumber)
	key = append(key, HYPERGRAPH_HYPEREDGE_ADDS_SHARD_COMMIT)
	key = append(key, shardAddress...)
	return key
}

func hypergraphHyperedgeRemovesShardCommitKey(
	frameNumber uint64,
	shardAddress []byte,
) []byte {
	key := []byte{HYPERGRAPH_SHARD}
	// The first byte is technically reserved – but in practicality won't be
	// non-zero (SHARD_COMMMIT)
	key = binary.BigEndian.AppendUint64(key, frameNumber)
	key = append(key, HYPERGRAPH_HYPEREDGE_REMOVES_SHARD_COMMIT)
	key = append(key, shardAddress...)
	return key
}

func hypergraphCoveredPrefixKey() []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPERGRAPH_COVERED_PREFIX}
	return key
}

// hypergraphAltShardCommitKey returns the key for storing alt shard roots at a
// specific frame number. The value stored at this key contains all four roots
// concatenated (32 bytes each = 128 bytes total).
func hypergraphAltShardCommitKey(
	frameNumber uint64,
	shardAddress []byte,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPERGRAPH_ALT_SHARD_COMMIT}
	key = binary.BigEndian.AppendUint64(key, frameNumber)
	key = append(key, shardAddress...)
	return key
}

// hypergraphAltShardCommitLatestKey returns the key for storing the latest
// frame number for an alt shard. The value is an 8-byte big-endian frame number.
func hypergraphAltShardCommitLatestKey(shardAddress []byte) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPERGRAPH_ALT_SHARD_COMMIT_LATEST}
	key = append(key, shardAddress...)
	return key
}

// hypergraphAltShardAddressIndexKey returns the key for marking that an alt
// shard address exists. Used for iterating all alt shard addresses.
func hypergraphAltShardAddressIndexKey(shardAddress []byte) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPERGRAPH_ALT_SHARD_ADDRESS_INDEX}
	key = append(key, shardAddress...)
	return key
}

func (p *PebbleHypergraphStore) copyShardData(
	dst store.KVDB,
	shardKey tries.ShardKey,
) error {
	prefixes := []byte{
		VERTEX_ADDS_TREE_NODE,
		VERTEX_REMOVES_TREE_NODE,
		HYPEREDGE_ADDS_TREE_NODE,
		HYPEREDGE_REMOVES_TREE_NODE,
		VERTEX_ADDS_TREE_NODE_BY_PATH,
		VERTEX_REMOVES_TREE_NODE_BY_PATH,
		HYPEREDGE_ADDS_TREE_NODE_BY_PATH,
		HYPEREDGE_REMOVES_TREE_NODE_BY_PATH,
		VERTEX_ADDS_TREE_ROOT,
		VERTEX_REMOVES_TREE_ROOT,
		HYPEREDGE_ADDS_TREE_ROOT,
		HYPEREDGE_REMOVES_TREE_ROOT,
		VERTEX_ADDS_CHANGE_RECORD,
		VERTEX_REMOVES_CHANGE_RECORD,
		HYPEREDGE_ADDS_CHANGE_RECORD,
		HYPEREDGE_REMOVES_CHANGE_RECORD,
		HYPERGRAPH_VERTEX_ADDS_SHARD_COMMIT,
		HYPERGRAPH_VERTEX_REMOVES_SHARD_COMMIT,
		HYPERGRAPH_HYPEREDGE_ADDS_SHARD_COMMIT,
		HYPERGRAPH_HYPEREDGE_REMOVES_SHARD_COMMIT,
	}

	for _, prefix := range prefixes {
		if err := p.copyPrefixedRange(dst, prefix, shardKey); err != nil {
			return err
		}
	}

	if err := p.copyVertexDataForShard(dst, shardKey); err != nil {
		return err
	}

	if err := p.copyCoveredPrefix(dst); err != nil {
		return err
	}

	return nil
}

func (p *PebbleHypergraphStore) copyPrefixedRange(
	dst store.KVDB,
	prefix byte,
	shardKey tries.ShardKey,
) error {
	start, end := shardRangeBounds(prefix, shardKey)
	iter, err := p.db.NewIter(start, end)
	if err != nil {
		return errors.Wrap(err, "snapshot: iter range")
	}
	defer iter.Close()

	for valid := iter.First(); valid; valid = iter.Next() {
		key := append([]byte(nil), iter.Key()...)
		val := append([]byte(nil), iter.Value()...)
		if err := dst.Set(key, val); err != nil {
			return errors.Wrap(err, "snapshot: set range value")
		}
	}

	return nil
}

func (p *PebbleHypergraphStore) copyVertexDataForShard(
	dst store.KVDB,
	shardKey tries.ShardKey,
) error {
	sets := []struct {
		setType   string
		phaseType string
	}{
		{string(hypergraph.VertexAtomType), string(hypergraph.AddsPhaseType)},
		{string(hypergraph.VertexAtomType), string(hypergraph.RemovesPhaseType)},
	}

	vertexKeys := make(map[string]struct{})
	for _, cfg := range sets {
		iter, err := p.IterateRawLeaves(cfg.setType, cfg.phaseType, shardKey)
		if err != nil {
			return errors.Wrap(err, "snapshot: iterate raw leaves")
		}
		for valid := iter.First(); valid; valid = iter.Next() {
			leaf, err := iter.Leaf()
			if err != nil || leaf == nil {
				continue
			}
			if len(leaf.UnderlyingData) == 0 {
				continue
			}
			keyStr := string(leaf.Key)
			if _, ok := vertexKeys[keyStr]; ok {
				continue
			}
			vertexKeys[keyStr] = struct{}{}
			buf := append([]byte(nil), leaf.UnderlyingData...)
			if err := dst.Set(hypergraphVertexDataKey(leaf.Key), buf); err != nil {
				iter.Close()
				return errors.Wrap(err, "snapshot: copy vertex data")
			}
		}
		if err := iter.Close(); err != nil {
			return errors.Wrap(err, "snapshot: close vertex iterator")
		}
	}

	return nil
}

func (p *PebbleHypergraphStore) copyCoveredPrefix(dst store.KVDB) error {
	value, closer, err := p.db.Get(hypergraphCoveredPrefixKey())
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil
		}
		return errors.Wrap(err, "snapshot: get covered prefix")
	}
	defer closer.Close()
	buf := append([]byte(nil), value...)
	return errors.Wrap(
		dst.Set(hypergraphCoveredPrefixKey(), buf),
		"snapshot: set covered prefix",
	)
}

func shardRangeBounds(
	prefix byte,
	shardKey tries.ShardKey,
) ([]byte, []byte) {
	shardBytes := shardKeyBytes(shardKey)
	start := append([]byte{HYPERGRAPH_SHARD, prefix}, shardBytes...)
	nextShardBytes, ok := incrementShardBytes(shardBytes)
	if ok {
		end := append([]byte{HYPERGRAPH_SHARD, prefix}, nextShardBytes...)
		return start, end
	}
	if prefix < 0xFF {
		return start, []byte{HYPERGRAPH_SHARD, prefix + 1}
	}
	return start, []byte{HYPERGRAPH_SHARD + 1}
}

func shardKeyBytes(shardKey tries.ShardKey) []byte {
	key := make([]byte, 0, len(shardKey.L1)+len(shardKey.L2))
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func incrementShardBytes(data []byte) ([]byte, bool) {
	out := append([]byte(nil), data...)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			return out, true
		}
	}
	return nil, false
}

func shardKeyFromKey(key []byte) tries.ShardKey {
	return tries.ShardKey{
		L1: [3]byte(key[2:5]),
		L2: [32]byte(key[5:]),
	}
}

func (p *PebbleHypergraphStore) NewTransaction(indexed bool) (
	tries.TreeBackingStoreTransaction,
	error,
) {
	return p.db.NewBatch(indexed), nil
}

func (p *PebbleHypergraphStore) LoadVertexTreeRaw(id []byte) ([]byte, error) {
	vertexData, closer, err := p.db.Get(hypergraphVertexDataKey(id))
	if err != nil {
		return nil, errors.Wrap(err, "load vertex data")
	}
	defer closer.Close()

	data := make([]byte, len(vertexData))
	copy(data, vertexData)
	return data, nil
}

func (p *PebbleHypergraphStore) LoadVertexTree(id []byte) (
	*tries.VectorCommitmentTree,
	error,
) {
	vertexData, err := p.LoadVertexTreeRaw(id)
	if err != nil {
		return nil, err
	}

	tree, err := tries.DeserializeNonLazyTree(vertexData)
	if err != nil {
		return nil, errors.Wrap(err, "load vertex data")
	}

	return tree, nil
}

func (p *PebbleHypergraphStore) SaveVertexTree(
	txn tries.TreeBackingStoreTransaction,
	id []byte,
	vertTree *tries.VectorCommitmentTree,
) error {
	if txn == nil {
		return errors.Wrap(
			errors.New("requires transaction"),
			"save vertex tree",
		)
	}

	b, err := tries.SerializeNonLazyTree(vertTree)
	if err != nil {
		return errors.Wrap(err, "save vertex tree")
	}

	return errors.Wrap(
		txn.Set(hypergraphVertexDataKey(id), b),
		"save vertex tree",
	)
}

func (p *PebbleHypergraphStore) SaveVertexTreeRaw(
	txn tries.TreeBackingStoreTransaction,
	id []byte,
	data []byte,
) error {
	if txn == nil {
		return errors.Wrap(
			errors.New("requires transaction"),
			"save vertex tree raw",
		)
	}

	buf := make([]byte, len(data))
	copy(buf, data)

	return errors.Wrap(
		txn.Set(hypergraphVertexDataKey(id), buf),
		"save vertex tree raw",
	)
}

func (p *PebbleHypergraphStore) DeleteVertexTree(
	txn tries.TreeBackingStoreTransaction,
	id []byte,
) error {
	if txn == nil {
		return errors.Wrap(
			errors.New("requires transaction"),
			"delete vertex tree",
		)
	}

	return errors.Wrap(
		txn.Delete(hypergraphVertexDataKey(id)),
		"delete vertex tree",
	)
}

func (p *PebbleHypergraphStore) SetCoveredPrefix(coveredPrefix []int) error {
	buf := bytes.NewBuffer(nil)
	prefix := []int64{}
	for _, p := range coveredPrefix {
		prefix = append(prefix, int64(p))
	}

	err := binary.Write(buf, binary.BigEndian, prefix)
	if err != nil {
		return errors.Wrap(err, "set covered prefix")
	}
	return errors.Wrap(
		p.db.Set(hypergraphCoveredPrefixKey(), buf.Bytes()),
		"set covered prefix",
	)
}

func (p *PebbleHypergraphStore) LoadHypergraph(
	authenticationProvider channel.AuthenticationProvider,
	maxSyncSessions int,
) (
	hypergraph.Hypergraph,
	error,
) {
	coveredPrefix := []int{}
	coveredPrefixBytes, closer, err := p.db.Get(hypergraphCoveredPrefixKey())
	if err == nil && len(coveredPrefixBytes) != 0 {
		prefix := make([]int64, len(coveredPrefixBytes)/8)
		buf := bytes.NewBuffer(coveredPrefixBytes)
		err = binary.Read(buf, binary.BigEndian, &prefix)
		closer.Close()
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}

		coveredPrefix = make([]int, len(prefix))
		for i, p := range prefix {
			coveredPrefix[i] = int(p)
		}
	}
	hg := hgcrdt.NewHypergraph(
		p.logger,
		p,
		p.prover,
		coveredPrefix,
		authenticationProvider,
		maxSyncSessions,
	)

	vertexAddsIter, err := p.db.NewIter(
		[]byte{HYPERGRAPH_SHARD, VERTEX_ADDS_TREE_ROOT},
		[]byte{HYPERGRAPH_SHARD, VERTEX_REMOVES_TREE_ROOT},
	)
	if err != nil {
		return nil, errors.Wrap(err, "load hypergraph")
	}
	defer vertexAddsIter.Close()

	for vertexAddsIter.First(); vertexAddsIter.Valid(); vertexAddsIter.Next() {
		shardKey := shardKeyFromKey(vertexAddsIter.Key())
		data := vertexAddsIter.Value()

		var node tries.LazyVectorCommitmentNode
		switch data[0] {
		case tries.TypeLeaf:
			node, err = tries.DeserializeLeafNode(p, bytes.NewReader(data[1:]))
		case tries.TypeBranch:
			pathLength := binary.BigEndian.Uint32(data[1:5])

			node, err = tries.DeserializeBranchNode(
				p,
				bytes.NewReader(data[5+(pathLength*4):]),
				false,
			)
			if err != nil {
				return nil, errors.Wrap(err, "load hypergraph")
			}

			fullPrefix := []int{}
			for i := range pathLength {
				fullPrefix = append(
					fullPrefix,
					int(binary.BigEndian.Uint32(data[5+(i*4):5+((i+1)*4)])),
				)
			}
			branch := node.(*tries.LazyVectorCommitmentBranchNode)
			branch.FullPrefix = fullPrefix
		default:
			err = store.ErrInvalidData
		}

		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}

		err = hg.ImportTree(
			hypergraph.VertexAtomType,
			hypergraph.AddsPhaseType,
			shardKey,
			node,
			p,
			p.prover,
		)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}
	}

	vertexRemovesIter, err := p.db.NewIter(
		[]byte{HYPERGRAPH_SHARD, VERTEX_REMOVES_TREE_ROOT},
		[]byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS_TREE_ROOT},
	)
	if err != nil {
		return nil, errors.Wrap(err, "load hypergraph")
	}
	defer vertexRemovesIter.Close()

	for vertexRemovesIter.First(); vertexRemovesIter.Valid(); vertexRemovesIter.Next() {
		shardKey := shardKeyFromKey(vertexRemovesIter.Key())
		data := vertexRemovesIter.Value()

		var node tries.LazyVectorCommitmentNode
		switch data[0] {
		case tries.TypeLeaf:
			node, err = tries.DeserializeLeafNode(p, bytes.NewReader(data[1:]))
		case tries.TypeBranch:
			pathLength := binary.BigEndian.Uint32(data[1:5])

			node, err = tries.DeserializeBranchNode(
				p,
				bytes.NewReader(data[5+(pathLength*4):]),
				false,
			)
			if err != nil {
				return nil, errors.Wrap(err, "load hypergraph")
			}

			fullPrefix := []int{}
			for i := range pathLength {
				fullPrefix = append(
					fullPrefix,
					int(binary.BigEndian.Uint32(data[5+(i*4):5+((i+1)*4)])),
				)
			}
			branch := node.(*tries.LazyVectorCommitmentBranchNode)
			branch.FullPrefix = fullPrefix
		default:
			err = store.ErrInvalidData
		}

		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}

		err = hg.ImportTree(
			hypergraph.VertexAtomType,
			hypergraph.RemovesPhaseType,
			shardKey,
			node,
			p,
			p.prover,
		)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}
	}

	hyperedgeAddsIter, err := p.db.NewIter(
		[]byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS_TREE_ROOT},
		[]byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES_TREE_ROOT},
	)
	if err != nil {
		return nil, errors.Wrap(err, "load hypergraph")
	}
	defer hyperedgeAddsIter.Close()

	for hyperedgeAddsIter.First(); hyperedgeAddsIter.Valid(); hyperedgeAddsIter.Next() {
		shardKey := shardKeyFromKey(hyperedgeAddsIter.Key())
		data := hyperedgeAddsIter.Value()

		var node tries.LazyVectorCommitmentNode
		switch data[0] {
		case tries.TypeLeaf:
			node, err = tries.DeserializeLeafNode(
				p,
				bytes.NewReader(data[1:]),
			)
		case tries.TypeBranch:
			pathLength := binary.BigEndian.Uint32(data[1:5])
			node, err = tries.DeserializeBranchNode(
				p,
				bytes.NewReader(data[5+(pathLength*4):]),
				false,
			)
			if err != nil {
				return nil, errors.Wrap(err, "load hypergraph")
			}

			fullPrefix := []int{}
			for i := range pathLength {
				fullPrefix = append(
					fullPrefix,
					int(binary.BigEndian.Uint32(data[5+(i*4):5+((i+1)*4)])),
				)
			}

			branch := node.(*tries.LazyVectorCommitmentBranchNode)
			branch.FullPrefix = fullPrefix
		default:
			err = store.ErrInvalidData
		}

		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}

		err = hg.ImportTree(
			hypergraph.HyperedgeAtomType,
			hypergraph.AddsPhaseType,
			shardKey,
			node,
			p,
			p.prover,
		)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}
	}

	hyperedgeRemovesIter, err := p.db.NewIter(
		[]byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES_TREE_ROOT},
		[]byte{(HYPERGRAPH_SHARD + 1), 0x00},
	)
	if err != nil {
		return nil, errors.Wrap(err, "load hypergraph")
	}
	defer hyperedgeRemovesIter.Close()

	for hyperedgeRemovesIter.First(); hyperedgeRemovesIter.Valid(); hyperedgeRemovesIter.Next() {
		shardKey := shardKeyFromKey(hyperedgeRemovesIter.Key())
		data := hyperedgeRemovesIter.Value()
		var node tries.LazyVectorCommitmentNode
		switch data[0] {
		case tries.TypeLeaf:
			node, err = tries.DeserializeLeafNode(p, bytes.NewReader(data[1:]))
		case tries.TypeBranch:
			pathLength := binary.BigEndian.Uint32(data[1:5])

			node, err = tries.DeserializeBranchNode(
				p,
				bytes.NewReader(data[5+(pathLength*4):]),
				false,
			)
			if err != nil {
				return nil, errors.Wrap(err, "load hypergraph")
			}

			fullPrefix := []int{}
			for i := range pathLength {
				fullPrefix = append(
					fullPrefix,
					int(binary.BigEndian.Uint32(data[5+(i*4):5+((i+1)*4)])),
				)
			}
			branch := node.(*tries.LazyVectorCommitmentBranchNode)
			branch.FullPrefix = fullPrefix
		default:
			err = store.ErrInvalidData
		}

		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}

		err = hg.ImportTree(
			hypergraph.HyperedgeAtomType,
			hypergraph.RemovesPhaseType,
			shardKey,
			node,
			p,
			p.prover,
		)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}
	}

	return hg, nil
}

func (p *PebbleHypergraphStore) MarkHypergraphAsComplete() {
	err := p.db.Set([]byte{HYPERGRAPH_SHARD, HYPERGRAPH_COMPLETE}, []byte{0x02})
	if err != nil {
		panic(err)
	}
}

func (p *PebbleHypergraphStore) GetNodeByKey(
	setType string,
	phaseType string,
	shardKey tries.ShardKey,
	key []byte,
) (tries.LazyVectorCommitmentNode, error) {
	keyFn := hypergraphVertexAddsTreeNodeKey
	switch hypergraph.AtomType(setType) {
	case hypergraph.VertexAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			keyFn = hypergraphVertexAddsTreeNodeKey
		case hypergraph.RemovesPhaseType:
			keyFn = hypergraphVertexRemovesTreeNodeKey
		}
	case hypergraph.HyperedgeAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			keyFn = hypergraphHyperedgeAddsTreeNodeKey
		case hypergraph.RemovesPhaseType:
			keyFn = hypergraphHyperedgeRemovesTreeNodeKey
		}
	}
	data, closer, err := p.db.Get(keyFn(shardKey, key))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			err = store.ErrNotFound
			return nil, err
		}
	}
	defer closer.Close()

	var node tries.LazyVectorCommitmentNode

	switch data[0] {
	case tries.TypeLeaf:
		node, err = tries.DeserializeLeafNode(p, bytes.NewReader(data[1:]))
	case tries.TypeBranch:
		pathLength := binary.BigEndian.Uint32(data[1:5])

		node, err = tries.DeserializeBranchNode(
			p,
			bytes.NewReader(data[5+(pathLength*4):]),
			false,
		)

		fullPrefix := []int{}
		for i := range pathLength {
			fullPrefix = append(
				fullPrefix,
				int(binary.BigEndian.Uint32(data[5+(i*4):5+((i+1)*4)])),
			)
		}
		branch := node.(*tries.LazyVectorCommitmentBranchNode)
		branch.FullPrefix = fullPrefix
	default:
		err = store.ErrInvalidData
	}

	return node, errors.Wrap(err, "get node by key")
}

func (p *PebbleHypergraphStore) GetNodeByPath(
	setType string,
	phaseType string,
	shardKey tries.ShardKey,
	path []int,
) (tries.LazyVectorCommitmentNode, error) {
	keyFn := hypergraphVertexAddsTreeNodeByPathKey
	switch hypergraph.AtomType(setType) {
	case hypergraph.VertexAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			keyFn = hypergraphVertexAddsTreeNodeByPathKey
		case hypergraph.RemovesPhaseType:
			keyFn = hypergraphVertexRemovesTreeNodeByPathKey
		}
	case hypergraph.HyperedgeAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			keyFn = hypergraphHyperedgeAddsTreeNodeByPathKey
		case hypergraph.RemovesPhaseType:
			keyFn = hypergraphHyperedgeRemovesTreeNodeByPathKey
		}
	}

	requestedPathKey := keyFn(shardKey, path)
	basePathKey := keyFn(shardKey, []int{})

	iter, err := p.db.NewIter(
		basePathKey,
		// The trick here is this will be a path longer than any possible, and so
		// we can extend the search if needed
		slices.Concat(requestedPathKey, bytes.Repeat([]byte{0, 0, 0, 63}, 86)),
	)
	if err != nil {
		return nil, errors.Wrap(err, "get node by path: failed to create iterator")
	}
	defer iter.Close()

	var found []byte
	iter.SeekGE(requestedPathKey)
	if iter.Valid() {
		found = iter.Value()
	}

	if found == nil {
		return nil, store.ErrNotFound
	}

	nodeData, nodeCloser, err := p.db.Get(found)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, errors.Wrap(err, "get node by path: failed to get node data")
	}
	defer nodeCloser.Close()

	var node tries.LazyVectorCommitmentNode

	// Deserialize the node
	switch nodeData[0] {
	case tries.TypeLeaf:
		node, err = tries.DeserializeLeafNode(
			p,
			bytes.NewReader(nodeData[1:]),
		)
	case tries.TypeBranch:
		pathLength := binary.BigEndian.Uint32(nodeData[1:5])

		node, err = tries.DeserializeBranchNode(
			p,
			bytes.NewReader(nodeData[5+(pathLength*4):]),
			false,
		)

		fullPrefix := []int{}
		for i := range pathLength {
			fullPrefix = append(
				fullPrefix,
				int(binary.BigEndian.Uint32(nodeData[5+(i*4):5+((i+1)*4)])),
			)
		}
		branch := node.(*tries.LazyVectorCommitmentBranchNode)
		branch.FullPrefix = fullPrefix

		// Verify the node's path is compatible with our requested path
		if len(path) > len(fullPrefix) {
			// If our requested path is longer, check if the node's path is a prefix
			for i, p := range fullPrefix {
				if i < len(path) && p != path[i] {
					return nil, store.ErrNotFound
				}
			}
		} else {
			// If the node's path is longer or equal, check if our path is a prefix
			for i, p := range path {
				if i < len(fullPrefix) && p != fullPrefix[i] {
					return nil, store.ErrNotFound
				}
			}
		}
	default:
		return nil, store.ErrInvalidData
	}

	if err != nil {
		return nil, errors.Wrap(err, "get node by path: failed to deserialize node")
	}

	return node, nil
}

func (p *PebbleHypergraphStore) InsertNode(
	txn tries.TreeBackingStoreTransaction,
	setType string,
	phaseType string,
	shardKey tries.ShardKey,
	key []byte,
	path []int,
	node tries.LazyVectorCommitmentNode,
) error {
	setter := p.db.Set
	if txn != nil {
		setter = txn.Set
	}

	keyFn := hypergraphVertexAddsTreeNodeKey
	pathFn := hypergraphVertexAddsTreeNodeByPathKey
	switch hypergraph.AtomType(setType) {
	case hypergraph.VertexAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			keyFn = hypergraphVertexAddsTreeNodeKey
			pathFn = hypergraphVertexAddsTreeNodeByPathKey
		case hypergraph.RemovesPhaseType:
			keyFn = hypergraphVertexRemovesTreeNodeKey
			pathFn = hypergraphVertexRemovesTreeNodeByPathKey
		}
	case hypergraph.HyperedgeAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			keyFn = hypergraphHyperedgeAddsTreeNodeKey
			pathFn = hypergraphHyperedgeAddsTreeNodeByPathKey
		case hypergraph.RemovesPhaseType:
			keyFn = hypergraphHyperedgeRemovesTreeNodeKey
			pathFn = hypergraphHyperedgeRemovesTreeNodeByPathKey
		}
	}

	var b bytes.Buffer
	nodeKey := keyFn(shardKey, key)
	switch n := node.(type) {
	case *tries.LazyVectorCommitmentBranchNode:
		length := uint32(len(n.FullPrefix))
		pathBytes := []byte{}
		pathBytes = binary.BigEndian.AppendUint32(pathBytes, length)
		for i := range int(length) {
			pathBytes = binary.BigEndian.AppendUint32(
				pathBytes,
				uint32(n.FullPrefix[i]),
			)
		}
		err := tries.SerializeBranchNode(&b, n, false)
		if err != nil {
			return errors.Wrap(err, "insert node")
		}
		data := append([]byte{tries.TypeBranch}, pathBytes...)
		data = append(data, b.Bytes()...)
		err = setter(nodeKey, data)
		if err != nil {
			return errors.Wrap(err, "insert node")
		}
		pathKey := pathFn(shardKey, n.FullPrefix)
		err = setter(pathKey, nodeKey)
		if err != nil {
			return errors.Wrap(err, "insert node")
		}
		return nil
	case *tries.LazyVectorCommitmentLeafNode:
		err := tries.SerializeLeafNode(&b, n)
		if err != nil {
			return errors.Wrap(err, "insert node")
		}
		data := append([]byte{tries.TypeLeaf}, b.Bytes()...)
		pathKey := pathFn(shardKey, path)
		err = setter(nodeKey, data)
		if err != nil {
			return errors.Wrap(err, "insert node")
		}
		return errors.Wrap(setter(pathKey, nodeKey), "insert node")
	}

	return nil
}

func (p *PebbleHypergraphStore) SaveRoot(
	setType string,
	phaseType string,
	shardKey tries.ShardKey,
	node tries.LazyVectorCommitmentNode,
) error {
	keyFn := hypergraphVertexAddsTreeRootKey
	switch hypergraph.AtomType(setType) {
	case hypergraph.VertexAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			keyFn = hypergraphVertexAddsTreeRootKey
		case hypergraph.RemovesPhaseType:
			keyFn = hypergraphVertexRemovesTreeRootKey
		}
	case hypergraph.HyperedgeAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			keyFn = hypergraphHyperedgeAddsTreeRootKey
		case hypergraph.RemovesPhaseType:
			keyFn = hypergraphHyperedgeRemovesTreeRootKey
		}
	}

	var b bytes.Buffer
	nodeKey := keyFn(shardKey)
	switch n := node.(type) {
	case *tries.LazyVectorCommitmentBranchNode:
		length := uint32(len(n.FullPrefix))
		pathBytes := []byte{}
		pathBytes = binary.BigEndian.AppendUint32(pathBytes, length)
		for i := range int(length) {
			pathBytes = binary.BigEndian.AppendUint32(
				pathBytes,
				uint32(n.FullPrefix[i]),
			)
		}
		err := tries.SerializeBranchNode(&b, n, false)
		if err != nil {
			return errors.Wrap(err, "insert node")
		}
		data := append([]byte{tries.TypeBranch}, pathBytes...)
		data = append(data, b.Bytes()...)
		err = p.db.Set(nodeKey, data)
		return errors.Wrap(err, "insert node")
	case *tries.LazyVectorCommitmentLeafNode:
		err := tries.SerializeLeafNode(&b, n)
		if err != nil {
			return errors.Wrap(err, "insert node")
		}
		data := append([]byte{tries.TypeLeaf}, b.Bytes()...)
		err = p.db.Set(nodeKey, data)
		return errors.Wrap(err, "insert node")
	}

	return nil
}

func (p *PebbleHypergraphStore) DeleteNode(
	txn tries.TreeBackingStoreTransaction,
	setType string,
	phaseType string,
	shardKey tries.ShardKey,
	key []byte,
	path []int,
) error {
	deleter := p.db.Delete
	if txn != nil {
		deleter = txn.Delete
	}

	keyFn := hypergraphVertexAddsTreeNodeKey
	pathFn := hypergraphVertexAddsTreeNodeByPathKey
	switch hypergraph.AtomType(setType) {
	case hypergraph.VertexAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			keyFn = hypergraphVertexAddsTreeNodeKey
			pathFn = hypergraphVertexAddsTreeNodeByPathKey
		case hypergraph.RemovesPhaseType:
			keyFn = hypergraphVertexRemovesTreeNodeKey
			pathFn = hypergraphVertexRemovesTreeNodeByPathKey
		}
	case hypergraph.HyperedgeAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			keyFn = hypergraphHyperedgeAddsTreeNodeKey
			pathFn = hypergraphHyperedgeAddsTreeNodeByPathKey
		case hypergraph.RemovesPhaseType:
			keyFn = hypergraphHyperedgeRemovesTreeNodeKey
			pathFn = hypergraphHyperedgeRemovesTreeNodeByPathKey
		}
	}
	pathKey := pathFn(shardKey, path)
	if err := deleter(pathKey); err != nil {
		return errors.Wrap(err, "delete path")
	}
	keyKey := keyFn(shardKey, key)
	err := deleter(keyKey)
	return errors.Wrap(err, "delete path")
}

func (p *PebbleHypergraphStore) GetVertexDataIterator(
	shardKey tries.ShardKey,
) (tries.VertexDataIterator, error) {
	keyPrefix := hypergraphVertexDataKey(shardKey.L2[:])

	end := new(big.Int).SetBytes(keyPrefix)
	end.Add(end, big.NewInt(1))

	keyEnd := end.FillBytes(make([]byte, len(keyPrefix)))

	// Create iterator with the prefix
	iter, err := p.db.NewIter(keyPrefix, keyEnd)
	if err != nil {
		return nil, errors.Wrap(err, "get vertex data iterator")
	}

	return &PebbleVertexDataIterator{
		i:        iter,
		db:       p,
		prover:   p.prover,
		shardKey: shardKey,
	}, nil
}

func (p *PebbleHypergraphStore) TrackChange(
	txn tries.TreeBackingStoreTransaction,
	key []byte,
	oldValue *tries.VectorCommitmentTree,
	frameNumber uint64,
	phaseType string,
	setType string,
	shardKey tries.ShardKey,
) error {
	setter := p.db.Set
	if txn != nil {
		setter = txn.Set
	}

	changeKey := hypergraphChangeRecordKey(
		setType,
		phaseType,
		shardKey,
		frameNumber,
		key,
	)

	var value []byte
	if oldValue == nil {
		value = []byte{}
	} else {
		var err error
		value, err = tries.SerializeNonLazyTree(oldValue)
		if err != nil {
			return errors.Wrap(err, "track change")
		}
	}

	return errors.Wrap(setter(changeKey, value), "track change")
}

// DeleteUncoveredPrefix implements store.HypergraphStore.
func (p *PebbleHypergraphStore) DeleteUncoveredPrefix(
	setType string,
	phaseType string,
	shardKey tries.ShardKey,
	prefix []int,
) error {
	keyFn := hypergraphVertexAddsTreeNodeByPathKey
	switch hypergraph.AtomType(setType) {
	case hypergraph.VertexAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			keyFn = hypergraphVertexAddsTreeNodeByPathKey
		case hypergraph.RemovesPhaseType:
			keyFn = hypergraphVertexRemovesTreeNodeByPathKey
		}
	case hypergraph.HyperedgeAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			keyFn = hypergraphHyperedgeAddsTreeNodeByPathKey
		case hypergraph.RemovesPhaseType:
			keyFn = hypergraphHyperedgeRemovesTreeNodeByPathKey
		}
	}

	requestedPathKey := keyFn(shardKey, prefix)
	basePathKey := keyFn(shardKey, []int{})

	// This is a bit of a trick, but it takes advantage of the fact that no key
	// like this can exist, meaning lexicographically everything above it by the
	// iterator will be outside of the covered prefix
	aboveRequestedPath := slices.Concat(requestedPathKey, []byte{0xff})
	endPathKey := keyFn(shardKey, []int{0xffffffff})

	iter, err := p.db.NewIter(basePathKey, requestedPathKey)
	if err != nil {
		return errors.Wrap(err, "delete uncovered prefix")
	}

	txn := p.db.NewBatch(false)

	for iter.First(); iter.Valid(); iter.Next() {
		err = txn.Delete(iter.Value())
		if err != nil {
			iter.Close()
			txn.Abort()
			return errors.Wrap(err, "delete uncovered prefix")
		}
	}
	iter.Close()

	iter, err = p.db.NewIter(aboveRequestedPath, endPathKey)
	if err != nil {
		txn.Abort()
		return errors.Wrap(err, "delete uncovered prefix")
	}

	for iter.First(); iter.Valid(); iter.Next() {
		err = txn.Delete(iter.Value())
		if err != nil {
			iter.Close()
			txn.Abort()
			return errors.Wrap(err, "delete uncovered prefix")
		}
	}
	iter.Close()

	if err = txn.DeleteRange(basePathKey, requestedPathKey); err != nil {
		txn.Abort()
		return errors.Wrap(err, "delete uncovered prefix")
	}

	if err = txn.DeleteRange(aboveRequestedPath, endPathKey); err != nil {
		txn.Abort()
		return errors.Wrap(err, "delete uncovered prefix")
	}

	return errors.Wrap(txn.Commit(), "delete uncovered prefix")
}

func (p *PebbleHypergraphStore) ReapOldChangesets(
	txn tries.TreeBackingStoreTransaction,
	frameNumber uint64,
) error {
	if txn == nil {
		return errors.Wrap(
			errors.New("requires transaction"),
			"reap old changesets",
		)
	}

	if frameNumber == 0 {
		return nil
	}

	rootsIter, err := p.db.NewIter(
		[]byte{HYPERGRAPH_SHARD, VERTEX_ADDS_TREE_ROOT},
		[]byte{(HYPERGRAPH_SHARD + 1), 0x00},
	)
	if err != nil {
		return errors.Wrap(err, "reap old changesets")
	}

	shardKeys := map[string]struct{}{}
	for rootsIter.First(); rootsIter.Valid(); rootsIter.Next() {
		shardKeys[string(rootsIter.Key()[2:])] = struct{}{}
	}

	rootsIter.Close()

	changeTypes := []byte{
		VERTEX_ADDS_CHANGE_RECORD,
		VERTEX_REMOVES_CHANGE_RECORD,
		HYPEREDGE_ADDS_CHANGE_RECORD,
		HYPEREDGE_REMOVES_CHANGE_RECORD,
	}

	for _, changeType := range changeTypes {
		for shardKey := range shardKeys {
			startKey := []byte{HYPERGRAPH_SHARD, changeType}
			startKey = append(startKey, []byte(shardKey)...)
			startKey = binary.BigEndian.AppendUint64(startKey, 0)
			endKey := []byte{HYPERGRAPH_SHARD, changeType}
			endKey = append(endKey, []byte(shardKey)...)
			endKey = binary.BigEndian.AppendUint64(endKey, frameNumber)

			err = txn.DeleteRange(startKey, endKey)
			if err != nil {
				return errors.Wrap(err, "reap old changesets")
			}
		}
	}

	return nil
}

func (p *PebbleHypergraphStore) GetChanges(
	frameStart uint64,
	frameEnd uint64,
	phaseType string,
	setType string,
	shardKey tries.ShardKey,
) ([]*tries.ChangeRecord, error) {
	var changeType byte
	switch hypergraph.AtomType(setType) {
	case hypergraph.VertexAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			changeType = VERTEX_ADDS_CHANGE_RECORD
		case hypergraph.RemovesPhaseType:
			changeType = VERTEX_REMOVES_CHANGE_RECORD
		}
	case hypergraph.HyperedgeAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			changeType = HYPEREDGE_ADDS_CHANGE_RECORD
		case hypergraph.RemovesPhaseType:
			changeType = HYPEREDGE_REMOVES_CHANGE_RECORD
		}
	}

	// Build the start and end keys for the range scan
	startKey := []byte{HYPERGRAPH_SHARD, changeType}
	startKey = append(startKey, shardKey.L1[:]...)
	startKey = append(startKey, shardKey.L2[:]...)
	startKey = binary.BigEndian.AppendUint64(startKey, frameStart)

	endKey := []byte{HYPERGRAPH_SHARD, changeType}
	endKey = append(endKey, shardKey.L1[:]...)
	endKey = append(endKey, shardKey.L2[:]...)
	endKey = binary.BigEndian.AppendUint64(endKey, frameEnd+1) // inclusive range

	iter, err := p.db.NewIter(startKey, endKey)
	if err != nil {
		return nil, errors.Wrap(err, "get changes")
	}
	defer iter.Close()

	var changes []*tries.ChangeRecord
	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()
		value := iter.Value()

		// Extract the frame number and original key from the storage key
		offset := 2 + 3 + 32 // Skip prefix, changeType, L1, and L2
		frameNumber := binary.BigEndian.Uint64(key[offset : offset+8])
		originalKey := make([]byte, len(key[offset+8:]))
		// Subtle bug without copy – the iterator overwrites this key value.
		copy(originalKey, key[offset+8:])

		// Retrieve the tree contents (if applicable)
		var tree *tries.VectorCommitmentTree
		if len(value) != 0 {
			tree, err = tries.DeserializeNonLazyTree(value)
			if err != nil {
				return nil, errors.Wrap(err, "get changes")
			}
		}

		changes = append(changes, &tries.ChangeRecord{
			Key:      originalKey,
			OldValue: tree,
			Frame:    frameNumber,
		})
	}

	// Return changes in reverse order for rollback
	slices.Reverse(changes)
	return changes, nil
}

func (p *PebbleHypergraphStore) UntrackChange(
	txn tries.TreeBackingStoreTransaction,
	key []byte,
	frameNumber uint64,
	phaseType string,
	setType string,
	shardKey tries.ShardKey,
) error {
	deleter := p.db.Delete
	if txn != nil {
		deleter = txn.Delete
	}

	changeKey := hypergraphChangeRecordKey(
		setType,
		phaseType,
		shardKey,
		frameNumber,
		key,
	)

	return errors.Wrap(deleter(changeKey), "untrack change")
}

// SetShardCommit sets the shard-level commit value at a given address for a
// given frame number.
func (p *PebbleHypergraphStore) SetShardCommit(
	txn tries.TreeBackingStoreTransaction,
	frameNumber uint64,
	phaseType string,
	setType string,
	shardAddress []byte,
	commitment []byte,
) error {
	keyFn := hypergraphVertexAddsShardCommitKey
	switch phaseType {
	case "adds":
		switch setType {
		case "vertex":
			keyFn = hypergraphVertexAddsShardCommitKey
		case "hyperedge":
			keyFn = hypergraphHyperedgeAddsShardCommitKey
		}
	case "removes":
		switch setType {
		case "vertex":
			keyFn = hypergraphVertexRemovesShardCommitKey
		case "hyperedge":
			keyFn = hypergraphHyperedgeRemovesShardCommitKey
		}
	}

	err := txn.Set(keyFn(frameNumber, shardAddress), commitment)
	return errors.Wrap(err, "set shard commit")
}

// GetShardCommit retrieves the shard-level commit value at a given address for
// a given frame number.
func (p *PebbleHypergraphStore) GetShardCommit(
	frameNumber uint64,
	phaseType string,
	setType string,
	shardAddress []byte,
) ([]byte, error) {
	keyFn := hypergraphVertexAddsShardCommitKey
	switch phaseType {
	case "adds":
		switch setType {
		case "vertex":
			keyFn = hypergraphVertexAddsShardCommitKey
		case "hyperedge":
			keyFn = hypergraphHyperedgeAddsShardCommitKey
		}
	case "removes":
		switch setType {
		case "vertex":
			keyFn = hypergraphVertexRemovesShardCommitKey
		case "hyperedge":
			keyFn = hypergraphHyperedgeRemovesShardCommitKey
		}
	}

	value, closer, err := p.db.Get(keyFn(frameNumber, shardAddress))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, errors.Wrap(store.ErrNotFound, "get shard commit")
		}

		return nil, errors.Wrap(err, "get shard commit")
	}

	defer closer.Close()
	commitment := make([]byte, len(value))
	copy(commitment, value)

	return commitment, nil
}

// GetRootCommits retrieves the entire set of root commitments for all shards,
// including global-level, for a given frame number.
func (p *PebbleHypergraphStore) GetRootCommits(
	frameNumber uint64,
) (map[tries.ShardKey][][]byte, error) {
	iter, err := p.db.NewIter(
		hypergraphVertexAddsShardCommitKey(frameNumber, nil),
		hypergraphHyperedgeRemovesShardCommitKey(
			frameNumber,
			bytes.Repeat([]byte{0xff}, 65),
		),
	)
	if err != nil {
		return nil, errors.Wrap(err, "get root commits")
	}

	result := make(map[tries.ShardKey][][]byte)
	for iter.First(); iter.Valid(); iter.Next() {
		// root shard keys have a constant size of key type (2) + frame number (8) +
		// root address (32)
		if len(iter.Key()) != 2+8+32 {
			continue
		}

		l1 := up2p.GetBloomFilterIndices(iter.Key()[10:], 256, 3)
		l2 := slices.Clone(iter.Key()[10:])
		_, ok := result[tries.ShardKey{
			L1: [3]byte(l1),
			L2: [32]byte(l2),
		}]
		if !ok {
			result[tries.ShardKey{
				L1: [3]byte(l1),
				L2: [32]byte(l2),
			}] = make([][]byte, 4)
		}

		commitIdx := iter.Key()[9] - HYPERGRAPH_VERTEX_ADDS_SHARD_COMMIT
		result[tries.ShardKey{
			L1: [3]byte(l1),
			L2: [32]byte(l2),
		}][commitIdx] = slices.Clone(iter.Value())
	}
	iter.Close()

	return result, nil
}

// ApplySnapshot opens the downloaded Pebble DB at <dbPath>/snapshot and
// bulk-imports *all* data into the active store via. After import, it deletes
// the temporary snapshot directory.
func (p *PebbleHypergraphStore) ApplySnapshot(
	dbPath string,
) error {
	snapDir := path.Join(dbPath, "snapshot")

	// If snapshot dir doesn't exist, nothing to apply; still clean up anything
	// stale.
	if fi, err := os.Stat(snapDir); err != nil || !fi.IsDir() {
		_ = os.RemoveAll(snapDir)
		return nil
	}
	// Always remove when done (success or fail).
	defer os.RemoveAll(snapDir)

	// Open the downloaded Pebble snapshot DB (read-only is fine).
	src, err := pebble.Open(snapDir, &pebble.Options{
		// Read-only avoids accidental compactions/writes; set to true if your
		// Pebble version supports it.
		ReadOnly: true,
	})
	if err != nil {
		return errors.Wrap(err, "apply snapshot")
	}
	defer src.Close()

	dst := p.db
	if dst == nil {
		return errors.Wrap(fmt.Errorf("destination DB is nil"), "apply snapshot")
	}

	iter, err := src.NewIter(&pebble.IterOptions{
		LowerBound: []byte{0x00},
		UpperBound: []byte{0xff},
	})
	if err != nil {
		return errors.Wrap(err, "apply snapshot")
	}
	defer iter.Close()

	const chunk = 100
	batch := dst.NewBatch(false)

	count := 0
	for valid := iter.First(); valid; valid = iter.Next() {
		// Clone key & value since iterator buffers are reused.
		k := append([]byte(nil), iter.Key()...)
		v, err := iter.ValueAndErr()
		if err != nil {
			_ = batch.Abort()
			return errors.Wrap(err, "apply snapshot")
		}
		v = append([]byte(nil), v...)

		if err := batch.Set(k, v); err != nil {
			_ = batch.Abort()
			return errors.Wrap(err, "apply snapshot")
		}

		count++
		if count%chunk == 0 {
			if err := batch.Commit(); err != nil {
				_ = batch.Abort()
				return errors.Wrap(err, "apply snapshot")
			}
			batch = dst.NewBatch(false)
		}
	}

	// Final commit for the remainder.
	if err := batch.Commit(); err != nil {
		return errors.Wrap(err, "apply snapshot")
	}

	p.logger.Info(
		"imported snapshot via raw key/value copy",
		zap.Int("keys", count),
	)
	return nil
}

// PebbleRawLeafIterator implements tries.RawLeafIterator for direct DB iteration.
type PebbleRawLeafIterator struct {
	iter     store.Iterator
	db       *PebbleHypergraphStore
	shardKey tries.ShardKey
	setType  string
}

var _ tries.RawLeafIterator = (*PebbleRawLeafIterator)(nil)

func (p *PebbleRawLeafIterator) First() bool {
	return p.iter.First()
}

func (p *PebbleRawLeafIterator) Next() bool {
	return p.iter.Next()
}

func (p *PebbleRawLeafIterator) Valid() bool {
	return p.iter.Valid()
}

func (p *PebbleRawLeafIterator) Close() error {
	return p.iter.Close()
}

func (p *PebbleRawLeafIterator) Leaf() (*tries.RawLeafData, error) {
	if !p.iter.Valid() {
		return nil, errors.New("iterator not valid")
	}

	nodeData := p.iter.Value()
	if len(nodeData) == 0 {
		return nil, errors.New("empty node data")
	}

	// Only process leaf nodes (type byte == TypeLeaf)
	if nodeData[0] != tries.TypeLeaf {
		return nil, errors.New("not a leaf node")
	}

	leaf, err := tries.DeserializeLeafNode(p.db, bytes.NewReader(nodeData[1:]))
	if err != nil {
		return nil, errors.Wrap(err, "deserialize leaf")
	}

	result := &tries.RawLeafData{
		Key:        slices.Clone(leaf.Key),
		Value:      slices.Clone(leaf.Value),
		HashTarget: slices.Clone(leaf.HashTarget),
		Commitment: slices.Clone(leaf.Commitment),
	}

	if leaf.Size != nil {
		result.Size = leaf.Size.FillBytes(make([]byte, 32))
	}

	// Load underlying vertex tree data if this is a vertex adds set
	if p.setType == string(hypergraph.VertexAtomType) {
		data, err := p.db.LoadVertexTreeRaw(leaf.Key)
		if err == nil && len(data) > 0 {
			result.UnderlyingData = data
		}
	}

	return result, nil
}

// IterateRawLeaves returns an iterator over all leaf nodes for a given shard.
// This iterates directly over the database tree node storage, bypassing any
// in-memory tree caching.
func (p *PebbleHypergraphStore) IterateRawLeaves(
	setType string,
	phaseType string,
	shardKey tries.ShardKey,
) (tries.RawLeafIterator, error) {
	// Determine the key function based on set and phase type
	var keyPrefix byte
	switch hypergraph.AtomType(setType) {
	case hypergraph.VertexAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			keyPrefix = VERTEX_ADDS_TREE_NODE
		case hypergraph.RemovesPhaseType:
			keyPrefix = VERTEX_REMOVES_TREE_NODE
		default:
			return nil, errors.New("unknown phase type")
		}
	case hypergraph.HyperedgeAtomType:
		switch hypergraph.PhaseType(phaseType) {
		case hypergraph.AddsPhaseType:
			keyPrefix = HYPEREDGE_ADDS_TREE_NODE
		case hypergraph.RemovesPhaseType:
			keyPrefix = HYPEREDGE_REMOVES_TREE_NODE
		default:
			return nil, errors.New("unknown phase type")
		}
	default:
		return nil, errors.New("unknown set type")
	}

	// Build the key range for this shard's tree nodes
	startKey := []byte{HYPERGRAPH_SHARD, keyPrefix}
	startKey = append(startKey, shardKey.L1[:]...)
	startKey = append(startKey, shardKey.L2[:]...)

	// End key is the next shard (increment L2 by 1 for upper bound)
	endKey := []byte{HYPERGRAPH_SHARD, keyPrefix}
	endKey = append(endKey, shardKey.L1[:]...)
	// Use L2 + 1 as upper bound, handling overflow
	l2End := new(big.Int).SetBytes(shardKey.L2[:])
	l2End.Add(l2End, big.NewInt(1))

	// Check if L2 overflowed (would need more than 32 bytes)
	if l2End.BitLen() > 256 {
		// L2 overflow: increment L1 and set L2 to zero
		l1End := [3]byte{shardKey.L1[0], shardKey.L1[1], shardKey.L1[2]}
		carry := byte(1)
		for i := 2; i >= 0; i-- {
			sum := uint16(l1End[i]) + uint16(carry)
			l1End[i] = byte(sum)
			carry = byte(sum >> 8)
		}
		// If L1 also overflowed (carry is still 1), use max key
		if carry == 1 {
			// Both L1 and L2 at max - use prefix+1 as end key (next key prefix)
			endKey = []byte{HYPERGRAPH_SHARD, keyPrefix + 1}
		} else {
			endKey = append(endKey[:2], l1End[:]...)
			endKey = append(endKey, make([]byte, 32)...) // L2 = all zeros
		}
	} else {
		l2EndBytes := l2End.FillBytes(make([]byte, 32))
		endKey = append(endKey, l2EndBytes...)
	}

	iter, err := p.db.NewIter(startKey, endKey)
	if err != nil {
		return nil, errors.Wrap(err, "create raw leaf iterator")
	}

	return &PebbleRawLeafIterator{
		iter:     iter,
		db:       p,
		shardKey: shardKey,
		setType:  setType,
	}, nil
}

// InsertRawLeaf inserts a leaf node directly into the database without tree
// traversal. This is used during raw sync to efficiently insert many leaves
// without the overhead of maintaining tree structure.
func (p *PebbleHypergraphStore) InsertRawLeaf(
	txn tries.TreeBackingStoreTransaction,
	setType string,
	phaseType string,
	shardKey tries.ShardKey,
	leaf *tries.RawLeafData,
) error {
	if leaf == nil || len(leaf.Key) == 0 {
		return errors.New("invalid leaf data")
	}

	// Reconstruct the leaf node
	leafNode := &tries.LazyVectorCommitmentLeafNode{
		Key:        leaf.Key,
		Value:      leaf.Value,
		HashTarget: leaf.HashTarget,
		Commitment: leaf.Commitment,
		Store:      p,
	}

	if len(leaf.Size) > 0 {
		leafNode.Size = new(big.Int).SetBytes(leaf.Size)
	} else {
		leafNode.Size = big.NewInt(0)
	}

	// Get the full path for this leaf key
	path := tries.GetFullPath(leaf.Key)

	// Insert the node directly
	if err := p.InsertNode(
		txn,
		setType,
		phaseType,
		shardKey,
		leaf.Key,
		path,
		leafNode,
	); err != nil {
		return errors.Wrap(err, "insert raw leaf")
	}

	// If there's underlying vertex tree data, save it too
	if len(leaf.UnderlyingData) > 0 {
		if err := p.SaveVertexTreeRaw(txn, leaf.Key, leaf.UnderlyingData); err != nil {
			return errors.Wrap(err, "insert raw leaf: save vertex tree")
		}
	}

	return nil
}

// SetAltShardCommit stores the four roots for an alt shard at a given frame
// number and updates the latest index if this is the newest frame.
func (p *PebbleHypergraphStore) SetAltShardCommit(
	txn tries.TreeBackingStoreTransaction,
	frameNumber uint64,
	shardAddress []byte,
	vertexAddsRoot []byte,
	vertexRemovesRoot []byte,
	hyperedgeAddsRoot []byte,
	hyperedgeRemovesRoot []byte,
) error {
	if txn == nil {
		return errors.Wrap(
			errors.New("requires transaction"),
			"set alt shard commit",
		)
	}

	// Validate roots are valid sizes (64 or 74 bytes)
	for _, root := range [][]byte{
		vertexAddsRoot, vertexRemovesRoot, hyperedgeAddsRoot, hyperedgeRemovesRoot,
	} {
		if len(root) != 64 && len(root) != 74 {
			return errors.Wrap(
				errors.New("roots must be 64 or 74 bytes"),
				"set alt shard commit",
			)
		}
	}

	// Store as length-prefixed values: 1 byte length + data for each root
	value := make([]byte, 0, 4+len(vertexAddsRoot)+len(vertexRemovesRoot)+
		len(hyperedgeAddsRoot)+len(hyperedgeRemovesRoot))
	value = append(value, byte(len(vertexAddsRoot)))
	value = append(value, vertexAddsRoot...)
	value = append(value, byte(len(vertexRemovesRoot)))
	value = append(value, vertexRemovesRoot...)
	value = append(value, byte(len(hyperedgeAddsRoot)))
	value = append(value, hyperedgeAddsRoot...)
	value = append(value, byte(len(hyperedgeRemovesRoot)))
	value = append(value, hyperedgeRemovesRoot...)

	// Store the commit at the frame-specific key
	commitKey := hypergraphAltShardCommitKey(frameNumber, shardAddress)
	if err := txn.Set(commitKey, value); err != nil {
		return errors.Wrap(err, "set alt shard commit")
	}

	// Update the latest index if this frame is newer
	latestKey := hypergraphAltShardCommitLatestKey(shardAddress)
	existing, closer, err := p.db.Get(latestKey)
	if err != nil && !errors.Is(err, pebble.ErrNotFound) {
		return errors.Wrap(err, "set alt shard commit: get latest")
	}

	shouldUpdate := true
	if err == nil {
		defer closer.Close()
		if len(existing) == 8 {
			existingFrame := binary.BigEndian.Uint64(existing)
			if existingFrame >= frameNumber {
				shouldUpdate = false
			}
		}
	}

	if shouldUpdate {
		frameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(frameBytes, frameNumber)
		if err := txn.Set(latestKey, frameBytes); err != nil {
			return errors.Wrap(err, "set alt shard commit: update latest")
		}
	}

	// Ensure the address is in the index for RangeAltShardAddresses
	indexKey := hypergraphAltShardAddressIndexKey(shardAddress)
	if err := txn.Set(indexKey, []byte{0x01}); err != nil {
		return errors.Wrap(err, "set alt shard commit: update index")
	}

	return nil
}

// GetLatestAltShardCommit retrieves the most recent roots for an alt shard.
func (p *PebbleHypergraphStore) GetLatestAltShardCommit(
	shardAddress []byte,
) (
	vertexAddsRoot []byte,
	vertexRemovesRoot []byte,
	hyperedgeAddsRoot []byte,
	hyperedgeRemovesRoot []byte,
	err error,
) {
	// Get the latest frame number for this shard
	latestKey := hypergraphAltShardCommitLatestKey(shardAddress)
	frameBytes, closer, err := p.db.Get(latestKey)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, nil, nil, nil, errors.Wrap(
				store.ErrNotFound,
				"get latest alt shard commit",
			)
		}
		return nil, nil, nil, nil, errors.Wrap(err, "get latest alt shard commit")
	}
	defer closer.Close()

	if len(frameBytes) != 8 {
		return nil, nil, nil, nil, errors.Wrap(
			store.ErrInvalidData,
			"get latest alt shard commit: invalid frame number",
		)
	}

	frameNumber := binary.BigEndian.Uint64(frameBytes)

	// Get the commit at that frame
	commitKey := hypergraphAltShardCommitKey(frameNumber, shardAddress)
	value, commitCloser, err := p.db.Get(commitKey)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, nil, nil, nil, errors.Wrap(
				store.ErrNotFound,
				"get latest alt shard commit: commit not found",
			)
		}
		return nil, nil, nil, nil, errors.Wrap(err, "get latest alt shard commit")
	}
	defer commitCloser.Close()

	// Parse length-prefixed format
	offset := 0
	parseRoot := func() ([]byte, error) {
		if offset >= len(value) {
			return nil, errors.New("unexpected end of data")
		}
		length := int(value[offset])
		offset++
		if offset+length > len(value) {
			return nil, errors.New("root length exceeds data")
		}
		root := make([]byte, length)
		copy(root, value[offset:offset+length])
		offset += length
		return root, nil
	}

	var parseErr error
	vertexAddsRoot, parseErr = parseRoot()
	if parseErr != nil {
		return nil, nil, nil, nil, errors.Wrap(parseErr, "get latest alt shard commit")
	}
	vertexRemovesRoot, parseErr = parseRoot()
	if parseErr != nil {
		return nil, nil, nil, nil, errors.Wrap(parseErr, "get latest alt shard commit")
	}
	hyperedgeAddsRoot, parseErr = parseRoot()
	if parseErr != nil {
		return nil, nil, nil, nil, errors.Wrap(parseErr, "get latest alt shard commit")
	}
	hyperedgeRemovesRoot, parseErr = parseRoot()
	if parseErr != nil {
		return nil, nil, nil, nil, errors.Wrap(parseErr, "get latest alt shard commit")
	}

	return vertexAddsRoot, vertexRemovesRoot, hyperedgeAddsRoot, hyperedgeRemovesRoot, nil
}

// RangeAltShardAddresses returns all alt shard addresses that have stored
// commits.
func (p *PebbleHypergraphStore) RangeAltShardAddresses() ([][]byte, error) {
	startKey := []byte{HYPERGRAPH_SHARD, HYPERGRAPH_ALT_SHARD_ADDRESS_INDEX}
	endKey := []byte{HYPERGRAPH_SHARD, HYPERGRAPH_ALT_SHARD_ADDRESS_INDEX + 1}

	iter, err := p.db.NewIter(startKey, endKey)
	if err != nil {
		return nil, errors.Wrap(err, "range alt shard addresses")
	}
	defer iter.Close()

	var addresses [][]byte
	prefixLen := len(startKey)

	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()
		if len(key) > prefixLen {
			addr := make([]byte, len(key)-prefixLen)
			copy(addr, key[prefixLen:])
			addresses = append(addresses, addr)
		}
	}

	return addresses, nil
}
