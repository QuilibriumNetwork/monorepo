package store

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"path"
	"slices"

	"github.com/cockroachdb/pebble"
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
}

func NewPebbleHypergraphStore(
	config *config.DBConfig,
	db store.KVDB,
	logger *zap.Logger,
	verenc crypto.VerifiableEncryptor,
	prover crypto.InclusionProver,
) *PebbleHypergraphStore {
	return &PebbleHypergraphStore{
		config,
		db,
		logger,
		verenc,
		prover,
	}
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

	tree, err := tries.DeserializeNonLazyTree(value)
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

func (p *PebbleHypergraphStore) LoadVertexTree(id []byte) (
	*tries.VectorCommitmentTree,
	error,
) {
	vertexData, closer, err := p.db.Get(hypergraphVertexDataKey(id))
	if err != nil {
		return nil, errors.Wrap(err, "load vertex data")
	}
	defer closer.Close()

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
		hypergraphHyperedgeAddsShardCommitKey(
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
