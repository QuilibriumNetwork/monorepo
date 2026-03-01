package tries

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/big"
	"slices"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/utils/runtime"
)

type ShardKey struct {
	L1 [3]byte
	L2 [32]byte
}

// DBSnapshot represents a point-in-time snapshot of the database.
// This is used to ensure consistency when creating shard snapshots.
type DBSnapshot interface {
	io.Closer
}

type ChangeRecord struct {
	Key      []byte
	OldValue *VectorCommitmentTree
	Frame    uint64
}

type LazyVectorCommitmentNode interface {
	Commit(
		inclusionProver crypto.InclusionProver,
		txn TreeBackingStoreTransaction,
		setType string,
		phaseType string,
		shardKey ShardKey,
		path []int,
		recalculate bool,
	) []byte
	GetSize() *big.Int
}

type LazyVectorCommitmentLeafNode struct {
	Key        []byte
	Value      []byte
	HashTarget []byte
	Commitment []byte
	Size       *big.Int
	Store      TreeBackingStore
}

type LazyVectorCommitmentBranchNode struct {
	Prefix        []int
	Children      [BranchNodes]LazyVectorCommitmentNode
	Commitment    []byte
	Size          *big.Int
	LeafCount     int
	LongestBranch int
	FullPrefix    []int
	Store         TreeBackingStore
	FullyLoaded   bool
}

func (n *LazyVectorCommitmentLeafNode) Commit(
	inclusionProver crypto.InclusionProver,
	txn TreeBackingStoreTransaction,
	setType string,
	phaseType string,
	shardKey ShardKey,
	path []int,
	recalculate bool,
) []byte {
	if len(n.Commitment) == 0 || recalculate {
		h := sha512.New()
		h.Write([]byte{0})
		h.Write(n.Key)
		if len(n.HashTarget) != 0 {
			h.Write(n.HashTarget)
		} else {
			h.Write(n.Value)
		}
		n.Commitment = h.Sum(nil)
		if err := n.Store.InsertNode(
			txn,
			setType,
			phaseType,
			shardKey,
			n.Key,
			path,
			n,
		); err != nil {
			log.Panic("failed to insert node", zap.Error(err))
		}
	}
	return n.Commitment
}

func (n *LazyVectorCommitmentLeafNode) GetSize() *big.Int {
	return n.Size
}

func (n *LazyVectorCommitmentBranchNode) Commit(
	inclusionProver crypto.InclusionProver,
	txn TreeBackingStoreTransaction,
	setType string,
	phaseType string,
	shardKey ShardKey,
	path []int,
	recalculate bool,
) []byte {
	if len(n.Commitment) != 0 && !recalculate {
		return n.Commitment
	}

	workers := runtime.WorkerCount(0, false, false)
	var throttle chan struct{}
	if workers > 1 {
		throttle = make(chan struct{}, workers)
	}

	commitment, err := commitNode(
		inclusionProver,
		n,
		txn,
		setType,
		phaseType,
		shardKey,
		n.FullPrefix,
		recalculate,
		throttle,
	)
	if err != nil {
		log.Panic("failed to commit node", zap.Error(err))
	}
	return commitment
}

func commitNode(
	inclusionProver crypto.InclusionProver,
	n LazyVectorCommitmentNode,
	txn TreeBackingStoreTransaction,
	setType string,
	phaseType string,
	shardKey ShardKey,
	path []int,
	recalculate bool,
	throttle chan struct{},
) ([]byte, error) {
	switch node := n.(type) {
	case *LazyVectorCommitmentBranchNode:
		if len(node.Commitment) != 0 && !recalculate {
			return node.Commitment, nil
		}

		vector := make([][]byte, len(node.Children))

		if throttle == nil {
			// Sequential path: no goroutines, no sync primitives
			for i, child := range node.Children {
				childPath := slices.Concat(node.FullPrefix, []int{i})
				if child == nil {
					var err error
					child, err = node.Store.GetNodeByPath(
						setType,
						phaseType,
						shardKey,
						childPath,
					)
					if err != nil && !strings.Contains(err.Error(), "item not found") {
						return nil, errors.Wrap(err, "failed to get node by path")
					}
				}
				if child != nil {
					commit, err := commitNode(
						inclusionProver,
						child,
						txn,
						setType,
						phaseType,
						shardKey,
						childPath,
						recalculate,
						throttle,
					)
					if err != nil {
						return nil, err
					}
					if branchChild, ok := child.(*LazyVectorCommitmentBranchNode); ok {
						h := sha512.New()
						h.Write([]byte{1})
						for _, p := range branchChild.Prefix {
							h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
						}
						h.Write(commit)
						commit = h.Sum(nil)
					}
					vector[i] = commit
				} else {
					vector[i] = make([]byte, 64)
				}
			}
		} else {
			// Parallel path: use goroutines with throttle channel
			var wg sync.WaitGroup
			var mu sync.Mutex
			var firstErr error

			for i, child := range node.Children {
				childPath := slices.Concat(node.FullPrefix, []int{i})
				wg.Add(1)

				select {
				case throttle <- struct{}{}:
					go func(i int, child LazyVectorCommitmentNode, childPath []int) {
						defer wg.Done()
						defer func() { <-throttle }()

						if child == nil {
							var err error
							child, err = node.Store.GetNodeByPath(
								setType,
								phaseType,
								shardKey,
								childPath,
							)
							if err != nil && !strings.Contains(err.Error(), "item not found") {
								mu.Lock()
								if firstErr == nil {
									firstErr = errors.Wrap(err, "failed to get node by path")
								}
								mu.Unlock()
								return
							}
						}
						if child != nil {
							commit, err := commitNode(
								inclusionProver,
								child,
								txn,
								setType,
								phaseType,
								shardKey,
								childPath,
								recalculate,
								throttle,
							)
							if err != nil {
								mu.Lock()
								if firstErr == nil {
									firstErr = err
								}
								mu.Unlock()
								return
							}
							if branchChild, ok := child.(*LazyVectorCommitmentBranchNode); ok {
								h := sha512.New()
								h.Write([]byte{1})
								for _, p := range branchChild.Prefix {
									h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
								}
								h.Write(commit)
								commit = h.Sum(nil)
							}
							vector[i] = commit
						} else {
							vector[i] = make([]byte, 64)
						}
					}(i, child, childPath)
				default:
					if child == nil {
						var err error
						child, err = node.Store.GetNodeByPath(
							setType,
							phaseType,
							shardKey,
							childPath,
						)
						if err != nil && !strings.Contains(err.Error(), "item not found") {
							return nil, errors.Wrap(err, "failed to get node by path")
						}
					}
					if child != nil {
						commit, err := commitNode(
							inclusionProver,
							child,
							txn,
							setType,
							phaseType,
							shardKey,
							childPath,
							recalculate,
							throttle,
						)
						if err != nil {
							return nil, err
						}
						if branchChild, ok := child.(*LazyVectorCommitmentBranchNode); ok {
							h := sha512.New()
							h.Write([]byte{1})
							for _, p := range branchChild.Prefix {
								h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
							}
							h.Write(commit)
							commit = h.Sum(nil)
						}
						vector[i] = commit
					} else {
						vector[i] = make([]byte, 64)
					}
					wg.Done()
				}
			}
			wg.Wait()

			if firstErr != nil {
				return nil, firstErr
			}
		}

		data := []byte{}
		for _, vec := range vector {
			data = append(data, vec...)
		}
		node.Commitment, _ = inclusionProver.CommitRaw(data, 64)

		if err := node.Store.InsertNode(
			txn,
			setType,
			phaseType,
			shardKey,
			generateKeyFromPath(node.FullPrefix),
			node.FullPrefix,
			node,
		); err != nil {
			return nil, errors.Wrap(err, "failed to insert node")
		}
		return node.Commitment, nil
	case *LazyVectorCommitmentLeafNode:
		return node.Commit(
			inclusionProver,
			txn,
			setType,
			phaseType,
			shardKey,
			GetFullPath(node.Key),
			recalculate,
		), nil
	default:
		return nil, nil
	}
}

func (n *LazyVectorCommitmentBranchNode) Verify(
	inclusionProver crypto.InclusionProver,
	setType string,
	phaseType string,
	shardKey ShardKey,
	index int,
	proof []byte,
) bool {
	data := []byte{}
	if len(n.Commitment) == 0 {
		n.Commit(inclusionProver, nil, setType, phaseType, shardKey, []int{}, false)
	}

	child := n.Children[index]
	if child == nil {
		var err error
		child, err = n.Store.GetNodeByPath(
			setType,
			phaseType,
			shardKey,
			slices.Concat(n.FullPrefix, []int{index}),
		)
		if err != nil && !strings.Contains(err.Error(), "item not found") {
			log.Panic("failed to get node by path", zap.Error(err))
		}
	}
	if child != nil {
		var out []byte
		switch c := child.(type) {
		case *LazyVectorCommitmentBranchNode:
			out = c.Commitment
			h := sha512.New()
			h.Write([]byte{1})
			for _, p := range c.Prefix {
				h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
			}
			h.Write(out)
			out = h.Sum(nil)
		case *LazyVectorCommitmentLeafNode:
			out = c.Commitment
		}
		data = append(data, out...)
	} else {
		data = append(data, make([]byte, 64)...)
	}

	ok, _ := inclusionProver.VerifyRaw(
		data,
		n.Commitment,
		uint64(index),
		proof,
		64,
	)
	return ok
}

func (n *LazyVectorCommitmentBranchNode) GetSize() *big.Int {
	return n.Size
}

func (n *LazyVectorCommitmentBranchNode) GetPolynomial(
	setType string,
	phaseType string,
	shardKey ShardKey,
) []byte {
	data := []byte{}
	for i, child := range n.Children {
		if child == nil {
			var err error
			child, err = n.Store.GetNodeByPath(
				setType,
				phaseType,
				shardKey,
				slices.Concat(n.FullPrefix, []int{i}),
			)
			if err != nil && !strings.Contains(err.Error(), "item not found") {
				log.Panic("failed to get node by path", zap.Error(err))
			}
		}
		if child != nil {
			var out []byte
			switch c := child.(type) {
			case *LazyVectorCommitmentBranchNode:
				out = c.Commitment
				h := sha512.New()
				h.Write([]byte{1})
				for _, p := range c.Prefix {
					h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
				}
				h.Write(out)
				out = h.Sum(nil)
			case *LazyVectorCommitmentLeafNode:
				out = c.Commitment
			}
			data = append(data, out...)
		} else {
			data = append(data, make([]byte, 64)...)
		}
	}

	return data
}

type TreeBackingStoreTransaction interface {
	Get(key []byte) ([]byte, io.Closer, error)
	Set(key []byte, value []byte) error
	Commit() error
	Delete(key []byte) error
	Abort() error
	DeleteRange(lowerBound []byte, upperBound []byte) error
}

// SyncTransaction wraps a TreeBackingStoreTransaction with a mutex for
// thread-safe access from commitNode's parallel goroutines.
type SyncTransaction struct {
	mu  sync.Mutex
	Txn TreeBackingStoreTransaction
}

func (s *SyncTransaction) Get(key []byte) ([]byte, io.Closer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Txn.Get(key)
}

func (s *SyncTransaction) Set(key []byte, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Txn.Set(key, value)
}

func (s *SyncTransaction) Commit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Txn.Commit()
}

func (s *SyncTransaction) Delete(key []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Txn.Delete(key)
}

func (s *SyncTransaction) Abort() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Txn.Abort()
}

func (s *SyncTransaction) DeleteRange(
	lowerBound []byte,
	upperBound []byte,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Txn.DeleteRange(lowerBound, upperBound)
}

// VertexDataIterator defines an iterator for accessing ranges of data for a
// given app shard.
type VertexDataIterator interface {
	Key() []byte
	First() bool
	Next() bool
	Prev() bool
	Valid() bool
	Value() *VectorCommitmentTree
	Close() error
	Last() bool
}

// RawLeafData contains serialized leaf node data for raw sync operations.
type RawLeafData struct {
	Key            []byte // The leaf key (atom ID)
	Value          []byte // The atom bytes
	HashTarget     []byte // Hash target for commitment
	Commitment     []byte // Pre-computed commitment
	Size           []byte // Size as big-endian bytes
	UnderlyingData []byte // Serialized vertex tree data (if applicable)
}

// RawLeafIterator provides direct database iteration over leaf nodes,
// bypassing in-memory tree structures for efficient raw sync.
type RawLeafIterator interface {
	First() bool
	Next() bool
	Valid() bool
	// Leaf returns the current leaf data. The returned data is only valid
	// until the next call to Next() or Close().
	Leaf() (*RawLeafData, error)
	Close() error
}

type TreeBackingStore interface {
	NewTransaction(indexed bool) (TreeBackingStoreTransaction, error)
	GetNodeByKey(
		setType string,
		phaseType string,
		shardKey ShardKey,
		key []byte,
	) (LazyVectorCommitmentNode, error)
	GetNodeByPath(
		setType string,
		phaseType string,
		shardKey ShardKey,
		path []int,
	) (LazyVectorCommitmentNode, error)
	InsertNode(
		txn TreeBackingStoreTransaction,
		setType string,
		phaseType string,
		shardKey ShardKey,
		key []byte,
		path []int,
		node LazyVectorCommitmentNode,
	) error
	SaveRoot(
		txn TreeBackingStoreTransaction,
		setType string,
		phaseType string,
		shardKey ShardKey,
		node LazyVectorCommitmentNode,
	) error
	DeleteNode(
		txn TreeBackingStoreTransaction,
		setType string,
		phaseType string,
		shardKey ShardKey,
		key []byte,
		path []int,
	) error
	LoadVertexTree(id []byte) (
		*VectorCommitmentTree,
		error,
	)
	SaveVertexTree(
		txn TreeBackingStoreTransaction,
		id []byte,
		vertTree *VectorCommitmentTree,
	) error
	GetVertexDataIterator(
		prefix ShardKey,
	) (VertexDataIterator, error)
	DeleteUncoveredPrefix(
		setType string,
		phaseType string,
		shardKey ShardKey,
		prefix []int,
	) error

	ReapOldChangesets(
		txn TreeBackingStoreTransaction,
		frameNumber uint64,
	) error
	TrackChange(
		txn TreeBackingStoreTransaction,
		key []byte,
		oldValue *VectorCommitmentTree,
		frameNumber uint64,
		phaseType string,
		setType string,
		shardKey ShardKey,
	) error
	GetChanges(
		frameStart uint64,
		frameEnd uint64,
		phaseType string,
		setType string,
		shardKey ShardKey,
	) ([]*ChangeRecord, error)
	UntrackChange(
		txn TreeBackingStoreTransaction,
		key []byte,
		frameNumber uint64,
		phaseType string,
		setType string,
		shardKey ShardKey,
	) error
	SetCoveredPrefix(
		path []int,
	) error
	SetShardCommit(
		txn TreeBackingStoreTransaction,
		frameNumber uint64,
		phaseType string,
		setType string,
		shardAddress []byte,
		commitment []byte,
	) error
	GetShardCommit(
		frameNumber uint64,
		phaseType string,
		setType string,
		shardAddress []byte,
	) ([]byte, error)
	GetRootCommits(frameNumber uint64) (map[ShardKey][][]byte, error)
	NewShardSnapshot(shardKey ShardKey) (TreeBackingStore, func(), error)
	// NewDBSnapshot creates a point-in-time snapshot of the entire database.
	// This is used to ensure consistency when creating shard snapshots - the
	// returned DBSnapshot should be passed to NewShardSnapshotFromDBSnapshot.
	// The caller must call Close() on the returned DBSnapshot when done.
	NewDBSnapshot() (DBSnapshot, error)
	// NewShardSnapshotFromDBSnapshot creates a shard snapshot from an existing
	// database snapshot. This ensures the shard snapshot reflects the exact state
	// at the time the DB snapshot was taken, avoiding race conditions.
	NewShardSnapshotFromDBSnapshot(
		shardKey ShardKey,
		dbSnapshot DBSnapshot,
	) (TreeBackingStore, func(), error)
	// IterateRawLeaves returns an iterator over all leaf nodes for a given
	// shard and phase set. This bypasses in-memory tree caching and reads
	// directly from the database for raw sync operations.
	IterateRawLeaves(
		setType string,
		phaseType string,
		shardKey ShardKey,
	) (RawLeafIterator, error)
	// InsertRawLeaf inserts a leaf node directly into the database without
	// tree traversal. This is used for raw sync operations where the tree
	// structure will be rebuilt later or managed externally.
	InsertRawLeaf(
		txn TreeBackingStoreTransaction,
		setType string,
		phaseType string,
		shardKey ShardKey,
		leaf *RawLeafData,
	) error
	DeleteVertexTree(
		txn TreeBackingStoreTransaction,
		id []byte,
	) error
}

// LazyVectorCommitmentTree is a lazy-loaded (from a TreeBackingStore based
// implementation) version of the VectorCommitmentTree. Stored branches and
// leaves are both retrievable in a path-based and key-based pattern. For
// branches, the key is derived from the path as a sha3-256 hash (to prevent
// collision potential against leaf keys, which are derived from poseidon).
type LazyVectorCommitmentTree struct {
	Root            LazyVectorCommitmentNode
	SetType         string
	PhaseType       string
	ShardKey        ShardKey
	Store           TreeBackingStore
	CoveredPrefix   []int
	InclusionProver crypto.InclusionProver
	treeMx          sync.RWMutex
}

func (t *LazyVectorCommitmentTree) PruneUncoveredBranches() error {
	t.treeMx.Lock()
	defer t.treeMx.Unlock()

	if len(t.CoveredPrefix) == 0 {
		return errors.New("full tree cannot prune")
	}

	t.Root = nil

	return t.Store.DeleteUncoveredPrefix(
		t.SetType,
		t.PhaseType,
		t.ShardKey,
		t.CoveredPrefix,
	)
}

func (t *LazyVectorCommitmentTree) CloneWithStore(
	store TreeBackingStore,
) *LazyVectorCommitmentTree {
	if t == nil {
		return nil
	}

	t.treeMx.RLock()
	defer t.treeMx.RUnlock()

	clone := *t
	clone.Store = store
	clone.Root = cloneLazyNode(t.Root, store)
	return &clone
}

func cloneLazyNode(
	node LazyVectorCommitmentNode,
	store TreeBackingStore,
) LazyVectorCommitmentNode {
	if node == nil {
		return nil
	}

	switch n := node.(type) {
	case *LazyVectorCommitmentLeafNode:
		leaf := *n
		if n.Key != nil {
			leaf.Key = slices.Clone(n.Key)
		}
		if n.Value != nil {
			leaf.Value = slices.Clone(n.Value)
		}
		if n.HashTarget != nil {
			leaf.HashTarget = slices.Clone(n.HashTarget)
		}
		if n.Commitment != nil {
			leaf.Commitment = slices.Clone(n.Commitment)
		}
		if n.Size != nil {
			leaf.Size = new(big.Int).Set(n.Size)
		}
		leaf.Store = store
		return &leaf
	case *LazyVectorCommitmentBranchNode:
		branch := *n
		if n.Prefix != nil {
			branch.Prefix = slices.Clone(n.Prefix)
		}
		if n.FullPrefix != nil {
			branch.FullPrefix = slices.Clone(n.FullPrefix)
		}
		if n.Commitment != nil {
			branch.Commitment = slices.Clone(n.Commitment)
		}
		if n.Size != nil {
			branch.Size = new(big.Int).Set(n.Size)
		}
		for i := range branch.Children {
			branch.Children[i] = cloneLazyNode(n.Children[i], store)
		}
		branch.Store = store
		return &branch
	default:
		return nil
	}
}

// InsertBranchSkeleton writes a branch node at fullPrefix with the given
// metadata. prefix is the compressed prefix stored in the node, commitment
// should be the source tree’s commitment for this branch node. size, leafCount,
// longestBranch mirror source metadata. Never call this for a tree that has
// not undergone shard-out.
func (t *LazyVectorCommitmentTree) InsertBranchSkeleton(
	txn TreeBackingStoreTransaction,
	branch *LazyVectorCommitmentBranchNode,
	isRoot bool,
) error {
	t.treeMx.Lock()
	defer t.treeMx.Unlock()

	if len(t.CoveredPrefix) == 0 {
		return errors.New("skeleton data cannot be used with full tree")
	}

	if err := t.Store.InsertNode(
		txn,
		t.SetType,
		t.PhaseType,
		t.ShardKey,
		generateKeyFromPath(branch.FullPrefix),
		branch.FullPrefix,
		branch,
	); err != nil {
		return errors.Wrap(err, "insert branch skeleton")
	}

	// If this is the root skeleton, set Root in-memory so Commit() has a top.
	if isRoot {
		t.Root = branch
		return errors.Wrap(
			t.Store.SaveRoot(txn, t.SetType, t.PhaseType, t.ShardKey, branch),
			"insert branch skeleton",
		)
	}

	return nil
}

// InsertLeafSkeleton writes a leaf node with the given metadata. prefix is the
// compressed prefix stored in the node, commitment should be the source tree’s
// commitment for this node. Never call this for a tree that has not undergone
// shard-out.
func (t *LazyVectorCommitmentTree) InsertLeafSkeleton(
	txn TreeBackingStoreTransaction,
	leaf *LazyVectorCommitmentLeafNode,
	isRoot bool,
) error {
	t.treeMx.Lock()
	defer t.treeMx.Unlock()

	if len(t.CoveredPrefix) == 0 {
		return errors.New("skeleton data cannot be used with full tree")
	}

	if err := t.Store.InsertNode(
		txn,
		t.SetType,
		t.PhaseType,
		t.ShardKey,
		leaf.Key,
		GetFullPath(leaf.Key),
		leaf,
	); err != nil {
		return err
	}

	// If this is the root skeleton, set Root in-memory so Commit() has a top.
	if isRoot {
		t.Root = leaf
		return errors.Wrap(
			t.Store.SaveRoot(txn, t.SetType, t.PhaseType, t.ShardKey, leaf),
			"insert leaf skeleton",
		)
	}

	return nil
}

// Insert adds or updates a key-value pair in the tree
func (t *LazyVectorCommitmentTree) Insert(
	txn TreeBackingStoreTransaction,
	key, value, hashTarget []byte,
	size *big.Int,
) error {
	t.treeMx.Lock()
	defer t.treeMx.Unlock()
	if len(key) == 0 {
		return errors.New("empty key not allowed")
	}

	// Get the size value, and check if it's a branch (i.e. someone is trying
	// to use key derivation conflicts and the upstream caller doesn't check)
	maybeLeaf, err := t.Store.GetNodeByKey(
		t.SetType,
		t.PhaseType,
		t.ShardKey,
		key,
	)
	sizeDelta := size
	if err == nil {
		if _, ok := maybeLeaf.(*LazyVectorCommitmentBranchNode); ok {
			return errors.New("value is branch")
		}
		if leaf, ok := maybeLeaf.(*LazyVectorCommitmentLeafNode); ok {
			sizeDelta = new(big.Int).Sub(size, leaf.Size)
		}
	}

	// Check if key is within the covered prefix (if one is defined)
	if len(t.CoveredPrefix) > 0 {
		keyPath := GetFullPath(key)
		if !t.isPathWithinCoveredPrefix(keyPath) {
			return errors.New("key is outside covered prefix range")
		}
	}

	var insert func(
		node LazyVectorCommitmentNode,
		depth int,
		path []int,
	) (int, LazyVectorCommitmentNode)
	insert = func(
		node LazyVectorCommitmentNode,
		depth int,
		path []int,
	) (int, LazyVectorCommitmentNode) {
		if node == nil {
			var err error
			node, err = t.Store.GetNodeByPath(
				t.SetType,
				t.PhaseType,
				t.ShardKey,
				path,
			)
			if err != nil && !strings.Contains(err.Error(), "item not found") {
				// TODO[2.1.1]: no panic
				log.Panic("failed to get node by path", zap.Error(err))
			}
		}
		if node == nil {
			newNode := &LazyVectorCommitmentLeafNode{
				Key:        slices.Clone(key),
				Value:      slices.Clone(value),
				HashTarget: slices.Clone(hashTarget),
				Size:       size,
				Store:      t.Store,
			}

			err := t.Store.InsertNode(
				txn,
				t.SetType,
				t.PhaseType,
				t.ShardKey,
				key,
				GetFullPath(key),
				newNode,
			)
			if err != nil {
				// TODO[2.1.1]: no panic
				log.Panic("failed to insert node", zap.Error(err))
			}
			return 1, newNode
		} else {
			branch, ok := node.(*LazyVectorCommitmentBranchNode)
			if ok && !branch.FullyLoaded {
				for i := 0; i < BranchNodes; i++ {
					var err error
					branch.Children[i], err = t.Store.GetNodeByPath(
						t.SetType,
						t.PhaseType,
						t.ShardKey,
						slices.Concat(branch.FullPrefix, []int{i}),
					)
					if err != nil && !strings.Contains(err.Error(), "item not found") {
						log.Panic("failed to get node by path", zap.Error(err))
					}
				}
				branch.FullyLoaded = true
			}
		}

		switch n := node.(type) {
		case *LazyVectorCommitmentLeafNode:
			if bytes.Equal(n.Key, key) {
				n.Value = slices.Clone(value)
				n.HashTarget = slices.Clone(hashTarget)
				n.Commitment = nil
				n.Size = size

				err := t.Store.InsertNode(
					txn,
					t.SetType,
					t.PhaseType,
					t.ShardKey,
					key,
					GetFullPath(key),
					n,
				)
				if err != nil {
					// TODO[2.1.1]: no panic
					log.Panic("failed to insert node", zap.Error(err))
				}
				return 0, n
			}

			// Get common prefix nibbles and divergence point
			sharedNibbles, divergeDepth := getNibblesUntilDiverge(n.Key, key, depth)

			// Create single branch node with shared prefix
			branch := &LazyVectorCommitmentBranchNode{
				Prefix:        sharedNibbles,
				LeafCount:     2,
				LongestBranch: 1,
				Size:          new(big.Int).Add(n.Size, sizeDelta),
				FullPrefix:    slices.Concat(path, sharedNibbles),
				Store:         t.Store,
				FullyLoaded:   true,
			}

			// Add both leaves at their final positions
			finalOldNibble := getNextNibble(n.Key, divergeDepth)
			finalNewNibble := getNextNibble(key, divergeDepth)
			branch.Children[finalOldNibble] = n
			branch.Children[finalNewNibble] = &LazyVectorCommitmentLeafNode{
				Key:        slices.Clone(key),
				Value:      slices.Clone(value),
				HashTarget: slices.Clone(hashTarget),
				Size:       size,
				Store:      t.Store,
			}

			err := t.Store.InsertNode(
				txn,
				t.SetType,
				t.PhaseType,
				t.ShardKey,
				key,
				GetFullPath(key),
				branch.Children[finalNewNibble],
			)
			if err != nil {
				// TODO[2.1.1]: no panic
				log.Panic("failed to insert node", zap.Error(err))
			}

			err = t.Store.InsertNode(
				txn,
				t.SetType,
				t.PhaseType,
				t.ShardKey,
				generateKeyFromPath(branch.FullPrefix),
				branch.FullPrefix,
				branch,
			)
			if err != nil {
				// TODO[2.1.1]: no panic
				log.Panic("failed to insert node", zap.Error(err))
			}

			return 1, branch

		case *LazyVectorCommitmentBranchNode:
			if len(n.Prefix) > 0 {
				// Check if the new key matches the prefix
				for i, expectedNibble := range n.Prefix {
					actualNibble := getNextNibble(key, depth+i*BranchBits)

					if actualNibble != expectedNibble {
						// Create new branch with shared prefix subset
						newBranch := &LazyVectorCommitmentBranchNode{
							Prefix:        n.Prefix[:i],
							LeafCount:     n.LeafCount + 1,
							LongestBranch: n.LongestBranch + 1,
							Size:          new(big.Int).Add(n.Size, sizeDelta),
							Store:         t.Store,
							FullPrefix:    slices.Concat(path, n.Prefix[:i]),
							FullyLoaded:   true,
						}

						err := t.Store.DeleteNode(
							txn,
							t.SetType,
							t.PhaseType,
							t.ShardKey,
							generateKeyFromPath(n.FullPrefix),
							n.FullPrefix,
						)
						if err != nil {
							// TODO[2.1.1]: no panic
							log.Panic("failed to insert node", zap.Error(err))
						}

						// Position old branch and new leaf
						newBranch.Children[expectedNibble] = n
						n.Prefix = n.Prefix[i+1:] // remove shared prefix from old branch
						newBranch.Children[actualNibble] = &LazyVectorCommitmentLeafNode{
							Key:        slices.Clone(key),
							Value:      slices.Clone(value),
							HashTarget: slices.Clone(hashTarget),
							Size:       size,
							Store:      t.Store,
						}

						err = t.Store.InsertNode(
							txn,
							t.SetType,
							t.PhaseType,
							t.ShardKey,
							key,
							slices.Concat(path, newBranch.Prefix, []int{actualNibble}),
							newBranch.Children[actualNibble],
						)
						if err != nil {
							// TODO[2.1.1]: no panic
							log.Panic("failed to insert node", zap.Error(err))
						}

						n.FullPrefix = slices.Concat(
							path,
							newBranch.Prefix,
							[]int{expectedNibble},
							n.Prefix,
						)
						// Note: Relocation not needed in Insert's branch split case because
						// the branch keeps its absolute position. Children are at paths
						// relative to n.FullPrefix which doesn't change (only the Prefix gets split).

						err = t.Store.InsertNode(
							txn,
							t.SetType,
							t.PhaseType,
							t.ShardKey,
							generateKeyFromPath(n.FullPrefix),
							n.FullPrefix,
							newBranch.Children[expectedNibble],
						)
						if err != nil {
							// TODO[2.1.1]: no panic
							log.Panic("failed to insert node", zap.Error(err))
						}

						err = t.Store.InsertNode(
							txn,
							t.SetType,
							t.PhaseType,
							t.ShardKey,
							generateKeyFromPath(newBranch.FullPrefix),
							newBranch.FullPrefix,
							newBranch,
						)
						if err != nil {
							// TODO[2.1.1]: no panic
							log.Panic("failed to insert node", zap.Error(err))
						}

						return 1, newBranch
					}
				}

				// Key matches prefix, continue with final nibble
				finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)
				newPath := slices.Concat(n.FullPrefix, []int{finalNibble})

				delta, inserted := insert(
					n.Children[finalNibble],
					depth+len(n.Prefix)*BranchBits+BranchBits,
					newPath,
				)
				n.Children[finalNibble] = inserted
				n.Commitment = nil
				n.LeafCount += delta
				switch i := inserted.(type) {
				case *LazyVectorCommitmentBranchNode:
					if n.LongestBranch <= i.LongestBranch {
						n.LongestBranch = i.LongestBranch + 1
					}
				case *LazyVectorCommitmentLeafNode:
					n.LongestBranch = 1
				}

				n.Size = n.Size.Add(n.Size, sizeDelta)
				err := t.Store.InsertNode(
					txn,
					t.SetType,
					t.PhaseType,
					t.ShardKey,
					generateKeyFromPath(n.FullPrefix),
					n.FullPrefix,
					n,
				)
				if err != nil {
					// TODO[2.1.1]: no panic
					log.Panic("failed to insert node", zap.Error(err))
				}

				return delta, n
			} else {
				// Simple branch without prefix
				nibble := getNextNibble(key, depth)
				newPath := slices.Concat(n.FullPrefix, []int{nibble})
				delta, inserted := insert(n.Children[nibble], depth+BranchBits, newPath)
				n.Children[nibble] = inserted
				n.Commitment = nil
				n.LeafCount += delta
				switch i := inserted.(type) {
				case *LazyVectorCommitmentBranchNode:
					if n.LongestBranch <= i.LongestBranch {
						n.LongestBranch = i.LongestBranch + 1
					}
				case *LazyVectorCommitmentLeafNode:
					n.LongestBranch = 1
				}

				n.Size = n.Size.Add(n.Size, sizeDelta)

				err := t.Store.InsertNode(
					txn,
					t.SetType,
					t.PhaseType,
					t.ShardKey,
					generateKeyFromPath(n.FullPrefix),
					n.FullPrefix,
					n,
				)
				if err != nil {
					// TODO[2.1.1]: no panic
					log.Panic("failed to insert node", zap.Error(err))
				}

				return delta, n
			}
		}

		return 0, nil
	}

	_, t.Root = insert(t.Root, 0, []int{})
	return errors.Wrap(t.Store.SaveRoot(
		txn,
		t.SetType,
		t.PhaseType,
		t.ShardKey,
		t.Root,
	), "insert")
}

func generateKeyFromPath(path []int) []byte {
	b := []byte{}
	for _, p := range path {
		b = append(b, byte(p))
	}
	hash := sha3.Sum256(b)
	return hash[:]
}

// isPrefixOf checks if prefix is a prefix of fullPath
func isPrefixOf(fullPath, prefix []int) bool {
	if len(prefix) > len(fullPath) {
		return false
	}

	for i, val := range prefix {
		if fullPath[i] != val {
			return false
		}
	}

	return true
}

// isPathWithinCoveredPrefix checks if a path falls within the covered prefix
func (t *LazyVectorCommitmentTree) isPathWithinCoveredPrefix(path []int) bool {
	// If no covered prefix is specified, any path is allowed
	if len(t.CoveredPrefix) == 0 {
		return true
	}

	// Check if the covered prefix is a prefix of the path
	return isPrefixOf(path, t.CoveredPrefix)
}

func (t *LazyVectorCommitmentTree) Verify(
	root []byte,
	proof *TraversalProof,
) (bool, error) {
	t.treeMx.RLock()
	defer t.treeMx.RUnlock()

	if len(proof.Multiproof.GetMulticommitment()) == 0 ||
		len(proof.Multiproof.GetProof()) == 0 {
		return false, errors.Wrap(
			errors.New("invalid multiproof sizes"),
			"verify",
		)
	}

	for _, subProof := range proof.SubProofs {
		if len(subProof.Commits) == 0 ||
			len(subProof.Paths) != len(subProof.Commits)-1 ||
			len(subProof.Ys) != len(subProof.Commits) {
			return false, errors.Wrap(
				errors.New("invalid subproof lengths"),
				"verify",
			)
		}
	}

	var rootCommit []byte
	if len(root) == 0 {
		rootCommit = t.Root.Commit(
			t.InclusionProver,
			nil,
			t.SetType,
			t.PhaseType,
			t.ShardKey,
			[]int{},
			false,
		)
	} else {
		rootCommit = slices.Clone(root)
	}

	for _, subProof := range proof.SubProofs {
		if !bytes.Equal(rootCommit, subProof.Commits[0]) {
			return false, errors.Wrap(
				errors.New("invalid subproof commit root"),
				"verify",
			)
		}
	}

	var verify func(
		commits [][]byte,
		indices [][]uint64,
		ys [][]byte,
	) (bool, error)
	verify = func(
		commits [][]byte,
		indices [][]uint64,
		ys [][]byte,
	) (bool, error) {
		if len(commits) <= 1 {
			return true, nil
		}

		var out []byte
		if len(commits) > 2 {
			out = commits[1]
			h := sha512.New()
			h.Write([]byte{1})
			for _, p := range indices[1][:len(indices[1])-1] {
				h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
			}
			h.Write(out)
			out = h.Sum(nil)
		} else if len(commits) > 1 {
			out = commits[1]
		}

		if !bytes.Equal(out, ys[0]) {
			return false, errors.Wrap(
				errors.New("invalid eval"),
				"verify",
			)
		}

		return verify(
			commits[1:],
			indices[1:],
			ys[1:],
		)
	}

	indices := []uint64{}
	commits := [][]byte{}
	ys := [][]byte{}
	for _, subProof := range proof.SubProofs {
		if len(subProof.Commits) <= 1 {
			continue
		}

		for _, p := range subProof.Paths {
			indices = append(indices, p[len(p)-1])
		}

		commits = append(commits, subProof.Commits[:len(subProof.Commits)-1]...)
		ys = append(ys, subProof.Ys[:len(subProof.Ys)-1]...)

		valid, err := verify(subProof.Commits, subProof.Paths, subProof.Ys)
		if !valid {
			return false, err
		}
	}

	if len(commits) > 1 && !t.InclusionProver.VerifyMultiple(
		commits,
		ys,
		indices,
		64,
		proof.Multiproof.GetMulticommitment(),
		proof.Multiproof.GetProof(),
	) {
		return false, errors.Wrap(
			errors.New("invalid multiproof"),
			"verify",
		)
	}

	return true, nil
}

type TraversalSubProof struct {
	Commits [][]byte
	Ys      [][]byte
	Paths   [][]uint64
}

type TraversalProof struct {
	Multiproof crypto.Multiproof
	SubProofs  []TraversalSubProof
}

func (t *TraversalProof) ToBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write Multiproof
	multiproofBytes, err := t.Multiproof.ToBytes()
	if err != nil {
		return nil, errors.Wrap(err, "to bytes")
	}
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(multiproofBytes)),
	); err != nil {
		return nil, errors.Wrap(err, "to bytes")
	}
	if _, err := buf.Write(multiproofBytes); err != nil {
		return nil, errors.Wrap(err, "to bytes")
	}

	// Write SubProofs count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.SubProofs)),
	); err != nil {
		return nil, errors.Wrap(err, "to bytes")
	}

	// Write each SubProof
	for _, subProof := range t.SubProofs {
		// Write Commits count
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(subProof.Commits)),
		); err != nil {
			return nil, errors.Wrap(err, "to bytes")
		}

		// Write each Commit
		for _, commit := range subProof.Commits {
			if err := binary.Write(
				buf,
				binary.BigEndian,
				uint32(len(commit)),
			); err != nil {
				return nil, errors.Wrap(err, "to bytes")
			}
			if _, err := buf.Write(commit); err != nil {
				return nil, errors.Wrap(err, "to bytes")
			}
		}

		// Write Ys count
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(subProof.Ys)),
		); err != nil {
			return nil, errors.Wrap(err, "to bytes")
		}

		// Write each Y
		for _, y := range subProof.Ys {
			if err := binary.Write(
				buf,
				binary.BigEndian,
				uint32(len(y)),
			); err != nil {
				return nil, errors.Wrap(err, "to bytes")
			}
			if _, err := buf.Write(y); err != nil {
				return nil, errors.Wrap(err, "to bytes")
			}
		}

		// Write Paths count
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(subProof.Paths)),
		); err != nil {
			return nil, errors.Wrap(err, "to bytes")
		}

		// Write each Path
		for _, path := range subProof.Paths {
			if err := binary.Write(
				buf,
				binary.BigEndian,
				uint32(len(path)),
			); err != nil {
				return nil, errors.Wrap(err, "to bytes")
			}
			for _, p := range path {
				if err := binary.Write(buf, binary.BigEndian, p); err != nil {
					return nil, errors.Wrap(err, "to bytes")
				}
			}
		}
	}

	return buf.Bytes(), nil
}

func (t *TraversalProof) FromBytes(
	proofBytes []byte,
	inclusionProver crypto.InclusionProver,
) error {
	buf := bytes.NewBuffer(proofBytes)

	// Read Multiproof
	var multiproofLen uint32
	if err := binary.Read(buf, binary.BigEndian, &multiproofLen); err != nil {
		return errors.Wrap(err, "from bytes")
	}
	multiproofBytes := make([]byte, multiproofLen)
	if _, err := buf.Read(multiproofBytes); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Create a new Multiproof and deserialize it
	t.Multiproof = inclusionProver.NewMultiproof()
	if err := t.Multiproof.FromBytes(multiproofBytes); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Read SubProofs count
	var subProofsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &subProofsCount); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Read each SubProof
	t.SubProofs = make([]TraversalSubProof, subProofsCount)
	for i := uint32(0); i < subProofsCount; i++ {
		// Read Commits count
		var commitsCount uint32
		if err := binary.Read(buf, binary.BigEndian, &commitsCount); err != nil {
			return errors.Wrap(err, "from bytes")
		}

		// Read each Commit
		t.SubProofs[i].Commits = make([][]byte, commitsCount)
		for j := uint32(0); j < commitsCount; j++ {
			var commitLen uint32
			if err := binary.Read(buf, binary.BigEndian, &commitLen); err != nil {
				return errors.Wrap(err, "from bytes")
			}

			t.SubProofs[i].Commits[j] = make([]byte, commitLen)
			if _, err := buf.Read(t.SubProofs[i].Commits[j]); err != nil {
				return errors.Wrap(err, "from bytes")
			}
		}

		// Read Ys count
		var ysCount uint32
		if err := binary.Read(buf, binary.BigEndian, &ysCount); err != nil {
			return errors.Wrap(err, "from bytes")
		}

		// Read each Y
		t.SubProofs[i].Ys = make([][]byte, ysCount)
		for j := uint32(0); j < ysCount; j++ {
			var yLen uint32
			if err := binary.Read(buf, binary.BigEndian, &yLen); err != nil {
				return errors.Wrap(err, "from bytes")
			}

			t.SubProofs[i].Ys[j] = make([]byte, yLen)
			if _, err := buf.Read(t.SubProofs[i].Ys[j]); err != nil {
				return errors.Wrap(err, "from bytes")
			}
		}

		// Read Paths count
		var pathsCount uint32
		if err := binary.Read(buf, binary.BigEndian, &pathsCount); err != nil {
			return errors.Wrap(err, "from bytes")
		}

		// Read each Path
		t.SubProofs[i].Paths = make([][]uint64, pathsCount)
		for j := uint32(0); j < pathsCount; j++ {
			var pathLen uint32
			if err := binary.Read(buf, binary.BigEndian, &pathLen); err != nil {
				return errors.Wrap(err, "from bytes")
			}

			t.SubProofs[i].Paths[j] = make([]uint64, pathLen)
			for k := uint32(0); k < pathLen; k++ {
				if err := binary.Read(
					buf,
					binary.BigEndian,
					&t.SubProofs[i].Paths[j][k],
				); err != nil {
					return errors.Wrap(err, "from bytes")
				}
			}
		}
	}

	// Validate that we have at least one subproof with data
	if len(t.SubProofs) == 0 {
		return errors.Wrap(errors.New("no subproofs found"), "from bytes")
	}

	hasData := false
	for _, sp := range t.SubProofs {
		if len(sp.Ys) > 0 {
			hasData = true
			break
		}
	}
	if !hasData {
		return errors.Wrap(
			errors.New("invalid payload: no ys data in any subproof"),
			"from bytes",
		)
	}

	return nil
}

func (t *LazyVectorCommitmentTree) Prove(key []byte) *TraversalProof {
	t.treeMx.RLock()
	defer t.treeMx.RUnlock()

	if len(key) == 0 {
		return nil
	}

	var prove func(
		node LazyVectorCommitmentNode,
		depth int,
	) ([][]byte, [][]byte, [][]byte, [][]int)
	prove = func(
		node LazyVectorCommitmentNode,
		depth int,
	) ([][]byte, [][]byte, [][]byte, [][]int) {
		if node == nil {
			return nil, nil, nil, nil
		}

		switch n := node.(type) {
		case *LazyVectorCommitmentLeafNode:
			commitment := n.Commit(
				t.InclusionProver,
				nil,
				t.SetType,
				t.PhaseType,
				t.ShardKey,
				GetFullPath(n.Key),
				false,
			)
			if bytes.Equal(n.Key, key) {
				if len(n.HashTarget) != 0 {
					return [][]byte{},
						[][]byte{commitment},
						[][]byte{n.HashTarget},
						[][]int{}
				} else {
					return [][]byte{},
						[][]byte{commitment},
						[][]byte{n.Value},
						[][]int{}
				}
			}
			return nil, nil, nil, nil

		case *LazyVectorCommitmentBranchNode:
			// Check prefix match
			for i, expectedNibble := range n.Prefix {
				if getNextNibble(key, depth+i*BranchBits) != expectedNibble {
					return nil, nil, nil, nil
				}
			}

			// Get final nibble after prefix
			finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)

			commits := [][]byte{n.Commit(
				t.InclusionProver,
				nil,
				t.SetType,
				t.PhaseType,
				t.ShardKey,
				n.FullPrefix,
				false,
			)}
			poly := n.GetPolynomial(
				t.SetType,
				t.PhaseType,
				t.ShardKey,
			)
			polynomials := [][]byte{poly}
			ys := [][]byte{poly[finalNibble*64 : (finalNibble+1)*64]}

			pl, co, y, pa := prove(
				n.Children[finalNibble],
				depth+len(n.Prefix)*BranchBits+BranchBits,
			)

			paths := [][]int{
				slices.Concat(n.Prefix, []int{finalNibble}),
			}
			return append(
					polynomials,
					pl...,
				), append(
					commits,
					co...,
				), append(
					ys,
					y...,
				), append(
					paths,
					pa...,
				)
		}

		return nil, nil, nil, nil
	}

	polynomials, commits, ys, paths := prove(t.Root, 0)
	pathIndices := [][]uint64{}
	indices := []uint64{}
	for _, p := range paths {
		index := []uint64{}
		for _, i := range p {
			index = append(index, uint64(i))
		}
		pathIndices = append(pathIndices, index)
		indices = append(indices, uint64(p[len(p)-1]))
	}

	if len(commits) == 0 {
		return nil
	}

	multiproof := t.InclusionProver.ProveMultiple(
		commits[:len(commits)-1],
		polynomials,
		indices,
		64,
	)

	return &TraversalProof{
		Multiproof: multiproof,
		SubProofs: []TraversalSubProof{{
			Ys:      ys,
			Commits: commits,
			Paths:   pathIndices,
		}},
	}
}

func (t *LazyVectorCommitmentTree) ProveMultiple(
	prover crypto.InclusionProver,
	keys [][]byte,
) *TraversalProof {
	if len(keys) == 0 {
		return nil
	}

	for _, k := range keys {
		if len(k) == 0 {
			return nil
		}
	}

	var prove func(
		node LazyVectorCommitmentNode,
		key []byte,
		depth int,
	) ([][]byte, [][]byte, [][]byte, [][]int)
	prove = func(
		node LazyVectorCommitmentNode,
		key []byte,
		depth int,
	) ([][]byte, [][]byte, [][]byte, [][]int) {
		if node == nil {
			return nil, nil, nil, nil
		}

		switch n := node.(type) {
		case *LazyVectorCommitmentLeafNode:
			commitment := n.Commit(
				t.InclusionProver,
				nil,
				t.SetType,
				t.PhaseType,
				t.ShardKey,
				GetFullPath(n.Key),
				false,
			)
			if bytes.Equal(n.Key, key) {
				if len(n.HashTarget) != 0 {
					return [][]byte{},
						[][]byte{commitment},
						[][]byte{n.HashTarget},
						[][]int{}
				} else {
					return [][]byte{},
						[][]byte{commitment},
						[][]byte{n.Value},
						[][]int{}
				}
			}
			return nil, nil, nil, nil

		case *LazyVectorCommitmentBranchNode:
			// Check prefix match
			for i, expectedNibble := range n.Prefix {
				if getNextNibble(key, depth+i*BranchBits) != expectedNibble {
					return nil, nil, nil, nil
				}
			}

			// Get final nibble after prefix
			finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)

			commits := [][]byte{n.Commit(
				t.InclusionProver,
				nil,
				t.SetType,
				t.PhaseType,
				t.ShardKey,
				n.FullPrefix,
				false,
			)}
			poly := n.GetPolynomial(t.SetType, t.PhaseType, t.ShardKey)
			polynomials := [][]byte{poly}
			ys := [][]byte{poly[finalNibble*64 : (finalNibble+1)*64]}

			pl, co, y, pa := prove(
				n.Children[finalNibble],
				key,
				depth+len(n.Prefix)*BranchBits+BranchBits,
			)

			paths := [][]int{
				slices.Concat(n.Prefix, []int{finalNibble}),
			}
			return append(
					polynomials,
					pl...,
				), append(
					commits,
					co...,
				), append(
					ys,
					y...,
				), append(
					paths,
					pa...,
				)
		}

		return nil, nil, nil, nil
	}

	polynomials := [][]byte{}
	commitments := [][]byte{}
	indices := []uint64{}
	subProofs := []TraversalSubProof{}

	for _, key := range keys {
		pathIndices := [][]uint64{}
		polys, commits, ys, ps := prove(t.Root, key, 0)
		if len(commits) == 0 {
			return nil
		}

		for _, p := range ps {
			index := []uint64{}
			for _, i := range p {
				index = append(index, uint64(i))
			}
			pathIndices = append(pathIndices, index)
			indices = append(indices, uint64(p[len(p)-1]))
		}

		polynomials = append(polynomials, polys...)
		commitments = append(commitments, commits[:len(commits)-1]...)
		subProofs = append(subProofs, TraversalSubProof{
			Commits: commits,
			Ys:      ys,
			Paths:   pathIndices,
		})
	}

	multiproof := prover.ProveMultiple(
		commitments,
		polynomials,
		indices,
		64,
	)

	return &TraversalProof{
		Multiproof: multiproof,
		SubProofs:  subProofs,
	}
}

// Get retrieves a value from the tree by key
func (t *LazyVectorCommitmentTree) Get(key []byte) ([]byte, error) {
	t.treeMx.RLock()
	defer t.treeMx.RUnlock()

	if len(key) == 0 {
		return nil, errors.Wrap(errors.New("empty key not allowed"), "get")
	}

	node, err := t.Store.GetNodeByKey(t.SetType, t.PhaseType, t.ShardKey, key)
	if err != nil {
		return nil, errors.Wrap(err, "get")
	}

	leaf, ok := node.(*LazyVectorCommitmentLeafNode)
	if !ok {
		return nil, errors.Wrap(errors.New("invalid node"), "get")
	}

	return leaf.Value, nil
}

// Get retrieves a value from the tree by path
func (t *LazyVectorCommitmentTree) GetByPath(path []int) (
	LazyVectorCommitmentNode,
	error,
) {
	t.treeMx.RLock()
	defer t.treeMx.RUnlock()

	node, err := t.Store.GetNodeByPath(t.SetType, t.PhaseType, t.ShardKey, path)
	if err != nil {
		return nil, errors.Wrap(err, "get by path")
	}

	return node, nil
}

func (t *LazyVectorCommitmentTree) GetMetadata() (
	leafCount int,
	longestBranch int,
) {
	t.treeMx.RLock()
	defer t.treeMx.RUnlock()

	switch root := t.Root.(type) {
	case nil:
		return 0, 0
	case *LazyVectorCommitmentLeafNode:
		return 1, 0
	case *LazyVectorCommitmentBranchNode:
		return root.LeafCount, root.LongestBranch
	}
	return 0, 0
}

// Commit returns the root of the tree. If txn is non-nil, all node writes
// are performed through the transaction for atomicity.
func (t *LazyVectorCommitmentTree) Commit(
	txn TreeBackingStoreTransaction,
	recalculate bool,
) []byte {
	t.treeMx.Lock()
	defer t.treeMx.Unlock()

	if t.Root == nil {
		return make([]byte, 64)
	}

	// Wrap txn for thread safety when commitNode uses parallel goroutines.
	// With GOMAXPROCS=1, commitNode runs sequentially so no wrapper needed.
	var wrappedTxn TreeBackingStoreTransaction
	if txn != nil {
		if runtime.WorkerCount(0, false, false) > 1 {
			wrappedTxn = &SyncTransaction{Txn: txn}
		} else {
			wrappedTxn = txn
		}
	}

	commitment := t.Root.Commit(
		t.InclusionProver,
		wrappedTxn,
		t.SetType,
		t.PhaseType,
		t.ShardKey,
		[]int{},
		recalculate,
	)

	err := t.Store.SaveRoot(wrappedTxn, t.SetType, t.PhaseType, t.ShardKey, t.Root)
	if err != nil {
		log.Panic("failed to save root", zap.Error(err))
	}

	return commitment
}

func (t *LazyVectorCommitmentTree) GetSize() *big.Int {
	t.treeMx.RLock()
	defer t.treeMx.RUnlock()
	if t.Root == nil {
		return big.NewInt(0)
	}
	return t.Root.GetSize()
}

// Delete removes a key-value pair from the tree.
// This is the inverse of Insert - when a branch is left with only one child,
// we merge it back (the reverse of Insert's branch split operation).
func (t *LazyVectorCommitmentTree) Delete(
	txn TreeBackingStoreTransaction,
	key []byte,
) error {
	t.treeMx.Lock()
	defer t.treeMx.Unlock()
	if len(key) == 0 {
		return errors.New("empty key not allowed")
	}

	// remove returns (sizeRemoved, newNode)
	// newNode is nil if the node was deleted, otherwise the updated node
	var remove func(
		node LazyVectorCommitmentNode,
		depth int,
		path []int,
	) (*big.Int, LazyVectorCommitmentNode)

	remove = func(
		node LazyVectorCommitmentNode,
		depth int,
		path []int,
	) (*big.Int, LazyVectorCommitmentNode) {
		// Lazy load if needed
		if node == nil {
			var err error
			node, err = t.Store.GetNodeByPath(
				t.SetType,
				t.PhaseType,
				t.ShardKey,
				path,
			)
			if err != nil && !strings.Contains(err.Error(), "item not found") {
				log.Panic("failed to get node by path", zap.Error(err))
			}
		}
		if node == nil {
			return big.NewInt(0), nil
		}

		switch n := node.(type) {
		case *LazyVectorCommitmentLeafNode:
			// Base case: found the leaf to delete
			if bytes.Equal(n.Key, key) {
				err := t.Store.DeleteNode(
					txn,
					t.SetType,
					t.PhaseType,
					t.ShardKey,
					key,
					GetFullPath(key),
				)
				if err != nil {
					log.Panic("failed to delete leaf", zap.Error(err))
				}
				return n.Size, nil
			}
			// Key doesn't match - nothing to delete
			return big.NewInt(0), n

		case *LazyVectorCommitmentBranchNode:
			// Ensure branch is fully loaded
			if !n.FullyLoaded {
				for i := 0; i < BranchNodes; i++ {
					var err error
					n.Children[i], err = t.Store.GetNodeByPath(
						t.SetType,
						t.PhaseType,
						t.ShardKey,
						slices.Concat(n.FullPrefix, []int{i}),
					)
					if err != nil && !strings.Contains(err.Error(), "item not found") {
						log.Panic("failed to get node by path", zap.Error(err))
					}
				}
				n.FullyLoaded = true
			}

			// Check if key matches the prefix
			for i, expectedNibble := range n.Prefix {
				actualNibble := getNextNibble(key, depth+i*BranchBits)
				if actualNibble != expectedNibble {
					// Key doesn't match prefix - nothing to delete here
					return big.NewInt(0), n
				}
			}

			// Key matches prefix, find the child nibble
			childNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)
			childPath := slices.Concat(n.FullPrefix, []int{childNibble})

			// Recursively delete from child
			sizeRemoved, newChild := remove(
				n.Children[childNibble],
				depth+len(n.Prefix)*BranchBits+BranchBits,
				childPath,
			)

			if sizeRemoved.Cmp(big.NewInt(0)) == 0 {
				// Nothing was deleted
				return big.NewInt(0), n
			}

			// Update the child
			n.Children[childNibble] = newChild
			n.Commitment = nil

			// Count remaining children and gather metadata
			childCount := 0
			var lastChild LazyVectorCommitmentNode
			var lastChildIndex int
			longestBranch := 0
			leafCount := 0
			totalSize := big.NewInt(0)

			for i, child := range n.Children {
				if child != nil {
					childCount++
					lastChild = child
					lastChildIndex = i
					switch c := child.(type) {
					case *LazyVectorCommitmentBranchNode:
						leafCount += c.LeafCount
						if c.LongestBranch+1 > longestBranch {
							longestBranch = c.LongestBranch + 1
						}
						totalSize = totalSize.Add(totalSize, c.Size)
					case *LazyVectorCommitmentLeafNode:
						leafCount++
						if longestBranch < 1 {
							longestBranch = 1
						}
						totalSize = totalSize.Add(totalSize, c.Size)
					}
				}
			}

			switch childCount {
			case 0:
				// No children left - delete this branch entirely
				err := t.Store.DeleteNode(
					txn,
					t.SetType,
					t.PhaseType,
					t.ShardKey,
					generateKeyFromPath(n.FullPrefix),
					n.FullPrefix,
				)
				if err != nil {
					log.Panic("failed to delete empty branch", zap.Error(err))
				}
				return sizeRemoved, nil

			case 1:
				// Only one child left - merge this branch with the child
				// This is the REVERSE of Insert's branch split operation
				return t.mergeBranchWithChild(txn, n, lastChild, lastChildIndex, path, sizeRemoved)

			default:
				// Multiple children remain - just update metadata
				n.LeafCount = leafCount
				n.LongestBranch = longestBranch
				n.Size = totalSize

				err := t.Store.InsertNode(
					txn,
					t.SetType,
					t.PhaseType,
					t.ShardKey,
					generateKeyFromPath(n.FullPrefix),
					n.FullPrefix,
					n,
				)
				if err != nil {
					log.Panic("failed to update branch", zap.Error(err))
				}
				return sizeRemoved, n
			}

		default:
			return big.NewInt(0), node
		}
	}

	_, t.Root = remove(t.Root, 0, []int{})
	return errors.Wrap(t.Store.SaveRoot(
		txn,
		t.SetType,
		t.PhaseType,
		t.ShardKey,
		t.Root,
	), "delete")
}

// mergeBranchWithChild merges a branch node with its only remaining child.
// This is the reverse of Insert's branch split operation.
//
// When Insert splits a branch/leaf, it creates:
//   - A new branch at path with prefix[:splitPoint]
//   - The old node as a child with remaining prefix
//
// When Delete leaves only one child, we reverse this:
//   - If child is a leaf: just return the leaf (branch disappears)
//   - If child is a branch: merge prefixes and the child takes this branch's place
func (t *LazyVectorCommitmentTree) mergeBranchWithChild(
	txn TreeBackingStoreTransaction,
	branch *LazyVectorCommitmentBranchNode,
	child LazyVectorCommitmentNode,
	childIndex int,
	parentPath []int, // path to the branch (not including branch.Prefix)
	sizeRemoved *big.Int,
) (*big.Int, LazyVectorCommitmentNode) {
	switch c := child.(type) {
	case *LazyVectorCommitmentLeafNode:
		// Child is a leaf - the branch simply disappears
		// The leaf stays at its current location (keyed by c.Key)
		// We just need to delete the branch node
		err := t.Store.DeleteNode(
			txn,
			t.SetType,
			t.PhaseType,
			t.ShardKey,
			generateKeyFromPath(branch.FullPrefix),
			branch.FullPrefix,
		)
		if err != nil {
			log.Panic("failed to delete branch during leaf merge", zap.Error(err))
		}
		return sizeRemoved, c

	case *LazyVectorCommitmentBranchNode:
		// Child is a branch - merge prefixes
		// New prefix = branch.Prefix + childIndex + child.Prefix
		mergedPrefix := make([]int, 0, len(branch.Prefix)+1+len(c.Prefix))
		mergedPrefix = append(mergedPrefix, branch.Prefix...)
		mergedPrefix = append(mergedPrefix, childIndex)
		mergedPrefix = append(mergedPrefix, c.Prefix...)

		// The merged branch will be at parentPath with the merged prefix
		// So its FullPrefix = parentPath + mergedPrefix
		newFullPrefix := slices.Concat(parentPath, mergedPrefix)

		// The child's children are currently stored relative to c.FullPrefix
		// They need to stay at the same absolute positions, but we need to
		// update the child branch's metadata
		oldFullPrefix := c.FullPrefix

		// Delete the old branch node
		err := t.Store.DeleteNode(
			txn,
			t.SetType,
			t.PhaseType,
			t.ShardKey,
			generateKeyFromPath(branch.FullPrefix),
			branch.FullPrefix,
		)
		if err != nil {
			log.Panic("failed to delete parent branch during merge", zap.Error(err))
		}

		// Delete the child from its old location
		err = t.Store.DeleteNode(
			txn,
			t.SetType,
			t.PhaseType,
			t.ShardKey,
			generateKeyFromPath(oldFullPrefix),
			oldFullPrefix,
		)
		if err != nil {
			log.Panic("failed to delete child branch during merge", zap.Error(err))
		}

		// Update the child branch's prefix and FullPrefix
		c.Prefix = mergedPrefix
		c.FullPrefix = newFullPrefix
		c.Commitment = nil

		// Insert the merged child at the parent's location
		err = t.Store.InsertNode(
			txn,
			t.SetType,
			t.PhaseType,
			t.ShardKey,
			generateKeyFromPath(newFullPrefix),
			newFullPrefix,
			c,
		)
		if err != nil {
			log.Panic("failed to insert merged branch", zap.Error(err))
		}

		return sizeRemoved, c

	default:
		return sizeRemoved, child
	}
}

func SerializeTree(tree *LazyVectorCommitmentTree) ([]byte, error) {
	tree.treeMx.Lock()
	defer tree.treeMx.Unlock()
	var buf bytes.Buffer
	if err := serializeNode(&buf, tree.Root); err != nil {
		return nil, fmt.Errorf("failed to serialize tree: %w", err)
	}
	return buf.Bytes(), nil
}

func DeserializeTree(
	atomType string,
	phaseType string,
	shardKey ShardKey,
	store TreeBackingStore,
	data []byte,
	coveredPrefix []int,
) (*LazyVectorCommitmentTree, error) {
	buf := bytes.NewReader(data)
	node, err := deserializeNode(store, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize tree: %w", err)
	}
	return &LazyVectorCommitmentTree{
		Root:          node,
		SetType:       atomType,
		PhaseType:     phaseType,
		ShardKey:      shardKey,
		Store:         store,
		CoveredPrefix: slices.Clone(coveredPrefix), // Empty by default, must be set explicitly
	}, nil
}

func serializeNode(w io.Writer, node LazyVectorCommitmentNode) error {
	if node == nil {
		if err := binary.Write(w, binary.BigEndian, TypeNil); err != nil {
			return err
		}
		return nil
	}

	switch n := node.(type) {
	case *LazyVectorCommitmentLeafNode:
		if err := binary.Write(w, binary.BigEndian, TypeLeaf); err != nil {
			return err
		}
		return SerializeLeafNode(w, n)
	case *LazyVectorCommitmentBranchNode:
		if err := binary.Write(w, binary.BigEndian, TypeBranch); err != nil {
			return err
		}
		return SerializeBranchNode(w, n, true)
	default:
		return fmt.Errorf("unknown node type: %T", node)
	}
}

func SerializeLeafNode(w io.Writer, node *LazyVectorCommitmentLeafNode) error {
	if err := serializeBytes(w, node.Key); err != nil {
		return err
	}

	if err := serializeBytes(w, node.Value); err != nil {
		return err
	}

	if err := serializeBytes(w, node.HashTarget); err != nil {
		return err
	}

	if err := serializeBytes(w, node.Commitment); err != nil {
		return err
	}

	return serializeBigInt(w, node.Size)
}

func SerializeBranchNode(
	w io.Writer,
	node *LazyVectorCommitmentBranchNode,
	descend bool,
) error {
	if err := serializeIntSlice(w, node.Prefix); err != nil {
		return err
	}

	if descend {
		for i := 0; i < BranchNodes; i++ {
			child := node.Children[i]
			if err := serializeNode(w, child); err != nil {
				return err
			}
		}
	}

	if err := serializeBytes(w, node.Commitment); err != nil {
		return err
	}

	if err := serializeBigInt(w, node.Size); err != nil {
		return err
	}

	if err := binary.Write(
		w,
		binary.BigEndian,
		int64(node.LeafCount),
	); err != nil {
		return err
	}

	return binary.Write(w, binary.BigEndian, int32(node.LongestBranch))
}

func deserializeNode(
	store TreeBackingStore,
	r io.Reader,
) (LazyVectorCommitmentNode, error) {
	var nodeType byte
	if err := binary.Read(r, binary.BigEndian, &nodeType); err != nil {
		return nil, err
	}

	switch nodeType {
	case TypeNil:
		return nil, nil
	case TypeLeaf:
		return DeserializeLeafNode(store, r)
	case TypeBranch:
		return DeserializeBranchNode(store, r, true)
	default:
		return nil, fmt.Errorf("unknown node type marker: %d", nodeType)
	}
}

func DeserializeLeafNode(
	store TreeBackingStore,
	r io.Reader,
) (*LazyVectorCommitmentLeafNode, error) {
	node := &LazyVectorCommitmentLeafNode{}

	key, err := deserializeBytes(r)
	if err != nil {
		return nil, err
	}
	node.Key = key

	value, err := deserializeBytes(r)
	if err != nil {
		return nil, err
	}
	node.Value = value

	hashTarget, err := deserializeBytes(r)
	if err != nil {
		return nil, err
	}
	node.HashTarget = hashTarget
	node.Store = store

	commitment, err := deserializeBytes(r)
	if err != nil {
		return nil, err
	}
	node.Commitment = commitment

	size, err := deserializeBigInt(r)
	if err != nil {
		return nil, err
	}
	node.Size = size

	return node, nil
}

func DeserializeBranchNode(
	store TreeBackingStore,
	r io.Reader,
	descend bool,
) (*LazyVectorCommitmentBranchNode, error) {
	node := &LazyVectorCommitmentBranchNode{}

	prefix, err := deserializeIntSlice(r)
	if err != nil {
		return nil, err
	}
	node.Prefix = prefix
	node.Store = store

	node.Children = [BranchNodes]LazyVectorCommitmentNode{}
	if descend {
		for i := 0; i < BranchNodes; i++ {
			child, err := deserializeNode(store, r)
			if err != nil {
				return nil, err
			}
			node.Children[i] = child
		}
	}

	commitment, err := deserializeBytes(r)
	if err != nil {
		return nil, err
	}
	node.Commitment = commitment

	size, err := deserializeBigInt(r)
	if err != nil {
		return nil, err
	}
	node.Size = size

	var leafCount int64
	if err := binary.Read(r, binary.BigEndian, &leafCount); err != nil {
		return nil, err
	}
	node.LeafCount = int(leafCount)

	var longestBranch int32
	if err := binary.Read(r, binary.BigEndian, &longestBranch); err != nil {
		return nil, err
	}
	node.LongestBranch = int(longestBranch)

	return node, nil
}

func serializeBytes(w io.Writer, data []byte) error {
	length := uint64(len(data))
	if err := binary.Write(w, binary.BigEndian, length); err != nil {
		return err
	}

	if length > 0 {
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	return nil
}

func deserializeBytes(r io.Reader) ([]byte, error) {
	var length uint64
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	if length > 0 {
		// 1GB hard cap
		if length > 1*1024*1024*1024 {
			return nil, errors.New("invalid array length")
		}

		data := make([]byte, length)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, err
		}
		return data, nil
	}
	return []byte{}, nil
}

func serializeIntSlice(w io.Writer, ints []int) error {
	length := uint32(len(ints))
	if err := binary.Write(w, binary.BigEndian, length); err != nil {
		return err
	}

	for _, v := range ints {
		if err := binary.Write(w, binary.BigEndian, int32(v)); err != nil {
			return err
		}
	}
	return nil
}

func deserializeIntSlice(r io.Reader) ([]int, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	ints := make([]int, length)
	for i := range ints {
		var v int32
		if err := binary.Read(r, binary.BigEndian, &v); err != nil {
			return nil, err
		}
		ints[i] = int(v)
	}
	return ints, nil
}

func serializeBigInt(w io.Writer, n *big.Int) error {
	if n == nil {
		return binary.Write(w, binary.BigEndian, uint32(0))
	}

	bytes := n.Bytes()

	return serializeBytes(w, bytes)
}

func deserializeBigInt(r io.Reader) (*big.Int, error) {
	bytes, err := deserializeBytes(r)
	if err != nil {
		return nil, err
	}

	if len(bytes) == 0 {
		return new(big.Int), nil
	}

	n := new(big.Int).SetBytes(bytes)
	return n, nil
}
