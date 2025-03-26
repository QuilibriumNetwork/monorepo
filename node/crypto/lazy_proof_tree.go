package crypto

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
	rbls48581 "source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/runtime"
)

type ShardKey struct {
	L1 [3]byte
	L2 [32]byte
}

type LazyVectorCommitmentNode interface {
	Commit(
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
	txn TreeBackingStoreTransaction,
	setType string,
	phaseType string,
	shardKey ShardKey,
	path []int,
	recalculate bool,
) []byte {
	if n.Commitment == nil || recalculate {
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
			panic(err)
		}
	}
	return n.Commitment
}

func (n *LazyVectorCommitmentLeafNode) GetSize() *big.Int {
	return n.Size
}

func (n *LazyVectorCommitmentBranchNode) Commit(
	txn TreeBackingStoreTransaction,
	setType string,
	phaseType string,
	shardKey ShardKey,
	path []int,
	recalculate bool,
) []byte {
	if n.Commitment == nil || recalculate {
		vector := make([][]byte, len(n.Children))
		wg := sync.WaitGroup{}
		workers := 1
		if n.LongestBranch == 2 {
			workers = runtime.WorkerCount(0, false)
		}
		throttle := make(chan struct{}, workers)
		for i, child := range n.Children {
			throttle <- struct{}{}
			wg.Add(1)
			go func(i int, child LazyVectorCommitmentNode) {
				defer func() { <-throttle }()
				defer wg.Done()

				if child == nil {
					var err error
					child, err = n.Store.GetNodeByPath(
						setType,
						phaseType,
						shardKey,
						slices.Concat(n.FullPrefix, []int{i}),
					)
					if err != nil && !strings.Contains(err.Error(), "item not found") {
						panic(err)
					}
				}
				if child != nil {
					out := child.Commit(
						txn,
						setType,
						phaseType,
						shardKey,
						slices.Concat(n.FullPrefix, []int{i}),
						recalculate,
					)
					switch c := child.(type) {
					case *LazyVectorCommitmentBranchNode:
						h := sha512.New()
						h.Write([]byte{1})
						for _, p := range c.Prefix {
							h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
						}
						h.Write(out)
						out = h.Sum(nil)
					case *LazyVectorCommitmentLeafNode:
						// do nothing
					}
					vector[i] = out
				} else {
					vector[i] = make([]byte, 64)
				}
			}(i, child)
		}
		wg.Wait()
		data := []byte{}
		for _, vec := range vector {
			data = append(data, vec...)
		}
		n.Commitment = rbls48581.CommitRaw(data, 64)
		if err := n.Store.InsertNode(
			txn,
			setType,
			phaseType,
			shardKey,
			generateKeyFromPath(n.FullPrefix),
			path,
			n,
		); err != nil {
			panic(err)
		}
	}

	return n.Commitment
}

func (n *LazyVectorCommitmentBranchNode) Verify(index int, proof []byte) bool {
	data := []byte{}
	if n.Commitment == nil {
		panic("verify cannot be run on nil commitments")
	} else {
		child := n.Children[index]
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

	return rbls48581.VerifyRaw(data, n.Commitment, uint64(index), proof, 64)
}

func (n *LazyVectorCommitmentBranchNode) GetSize() *big.Int {
	return n.Size
}

func (n *LazyVectorCommitmentBranchNode) Prove(index int) []byte {
	data := []byte{}
	for _, child := range n.Children {
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

	return rbls48581.ProveRaw(data, uint64(index), 64)
}

type TreeBackingStoreTransaction interface {
	Get(key []byte) ([]byte, io.Closer, error)
	Set(key []byte, value []byte) error
	Commit() error
	Delete(key []byte) error
	Abort() error
	DeleteRange(lowerBound []byte, upperBound []byte) error
}

type TreeBackingStore interface {
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
		setType string,
		phaseType string,
		shardKey ShardKey,
		node LazyVectorCommitmentNode,
	) error
	DeletePath(
		setType string,
		phaseType string,
		shardKey ShardKey,
		path []int,
	) error
}

type LazyVectorCommitmentTree struct {
	Root      LazyVectorCommitmentNode
	SetType   string
	PhaseType string
	ShardKey  ShardKey
	Store     TreeBackingStore
}

// Insert adds or updates a key-value pair in the tree
func (t *LazyVectorCommitmentTree) Insert(
	txn TreeBackingStoreTransaction,
	key, value, hashTarget []byte,
	size *big.Int,
) error {
	if len(key) == 0 {
		return errors.New("empty key not allowed")
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
				panic(err)
			}
		}
		if node == nil {
			newNode := &LazyVectorCommitmentLeafNode{
				Key:        key,
				Value:      value,
				HashTarget: hashTarget,
				Size:       size,
				Store:      t.Store,
			}

			err := t.Store.InsertNode(
				txn,
				t.SetType,
				t.PhaseType,
				t.ShardKey,
				key,
				path,
				newNode,
			)
			if err != nil {
				// todo: no panic
				panic(err)
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
						slices.Concat(path, []int{i}),
					)
					if err != nil && !strings.Contains(err.Error(), "item not found") {
						panic(err)
					}
				}
				branch.FullyLoaded = true
			}
		}

		switch n := node.(type) {
		case *LazyVectorCommitmentLeafNode:
			if bytes.Equal(n.Key, key) {
				n.Value = value
				n.HashTarget = hashTarget
				n.Commitment = nil
				n.Size = size

				err := t.Store.InsertNode(
					txn,
					t.SetType,
					t.PhaseType,
					t.ShardKey,
					key,
					path,
					n,
				)
				if err != nil {
					// todo: no panic
					panic(err)
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
				Size:          new(big.Int).Add(n.Size, size),
				FullPrefix:    slices.Concat(path, sharedNibbles),
				Store:         t.Store,
				FullyLoaded:   true,
			}

			// Add both leaves at their final positions
			finalOldNibble := getNextNibble(n.Key, divergeDepth)
			finalNewNibble := getNextNibble(key, divergeDepth)
			branch.Children[finalOldNibble] = n
			branch.Children[finalNewNibble] = &LazyVectorCommitmentLeafNode{
				Key:        key,
				Value:      value,
				HashTarget: hashTarget,
				Size:       size,
				Store:      t.Store,
			}

			err := t.Store.InsertNode(
				txn,
				t.SetType,
				t.PhaseType,
				t.ShardKey,
				n.Key,
				slices.Concat(path, sharedNibbles, []int{finalOldNibble}),
				n,
			)
			if err != nil {
				// todo: no panic
				panic(err)
			}

			err = t.Store.InsertNode(
				txn,
				t.SetType,
				t.PhaseType,
				t.ShardKey,
				key,
				slices.Concat(path, sharedNibbles, []int{finalNewNibble}),
				branch.Children[finalNewNibble],
			)
			if err != nil {
				// todo: no panic
				panic(err)
			}

			err = t.Store.InsertNode(
				txn,
				t.SetType,
				t.PhaseType,
				t.ShardKey,
				generateKeyFromPath(slices.Concat(path, sharedNibbles)),
				path,
				branch,
			)
			if err != nil {
				// todo: no panic
				panic(err)
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
							Size:          new(big.Int).Add(n.Size, size),
							Store:         t.Store,
							FullPrefix:    slices.Concat(path, n.Prefix[:i]),
							FullyLoaded:   true,
						}
						// Position old branch and new leaf
						newBranch.Children[expectedNibble] = n
						n.Prefix = n.Prefix[i+1:] // remove shared prefix from old branch
						newBranch.Children[actualNibble] = &LazyVectorCommitmentLeafNode{
							Key:        key,
							Value:      value,
							HashTarget: hashTarget,
							Size:       size,
							Store:      t.Store,
						}

						err := t.Store.InsertNode(
							txn,
							t.SetType,
							t.PhaseType,
							t.ShardKey,
							key,
							slices.Concat(path, newBranch.Prefix, []int{actualNibble}),
							newBranch.Children[actualNibble],
						)
						if err != nil {
							// todo: no panic
							panic(err)
						}

						n.FullPrefix = slices.Concat(
							path,
							newBranch.Prefix,
							[]int{expectedNibble},
							n.Prefix,
						)

						err = t.Store.InsertNode(
							txn,
							t.SetType,
							t.PhaseType,
							t.ShardKey,
							generateKeyFromPath(slices.Concat(path, newBranch.Prefix, []int{expectedNibble}, n.Prefix)),
							slices.Concat(path, newBranch.Prefix, []int{expectedNibble}),
							newBranch.Children[expectedNibble],
						)
						if err != nil {
							// todo: no panic
							panic(err)
						}

						err = t.Store.InsertNode(
							txn,
							t.SetType,
							t.PhaseType,
							t.ShardKey,
							generateKeyFromPath(slices.Concat(path, newBranch.Prefix)),
							path,
							newBranch,
						)
						if err != nil {
							// todo: no panic
							panic(err)
						}

						return 1, newBranch
					}
				}

				// Key matches prefix, continue with final nibble
				finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)
				newPath := slices.Concat(path, n.Prefix, []int{finalNibble})

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
				if delta != 0 {
					n.Size = n.Size.Add(n.Size, size)
				}

				err := t.Store.InsertNode(
					txn,
					t.SetType,
					t.PhaseType,
					t.ShardKey,
					generateKeyFromPath(path),
					path,
					n,
				)
				if err != nil {
					// todo: no panic
					panic(err)
				}

				return delta, n
			} else {
				// Simple branch without prefix
				nibble := getNextNibble(key, depth)
				newPath := slices.Concat(path, n.Prefix, []int{nibble})

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
				if delta != 0 {
					n.Size = n.Size.Add(n.Size, size)
				}

				err := t.Store.InsertNode(
					txn,
					t.SetType,
					t.PhaseType,
					t.ShardKey,
					generateKeyFromPath(path),
					path,
					n,
				)
				if err != nil {
					// todo: no panic
					panic(err)
				}

				return delta, n
			}
		}

		return 0, nil
	}

	_, t.Root = insert(t.Root, 0, []int{})
	return errors.Wrap(t.Store.SaveRoot(
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

func (t *LazyVectorCommitmentTree) Verify(key []byte, proofs [][]byte) bool {
	if len(key) == 0 {
		return false
	}

	var verify func(node LazyVectorCommitmentNode, proofs [][]byte, depth int) bool
	verify = func(node LazyVectorCommitmentNode, proofs [][]byte, depth int) bool {
		if node == nil {
			return false
		}

		if len(proofs) == 0 {
			return false
		}

		switch n := node.(type) {
		case *LazyVectorCommitmentLeafNode:
			if bytes.Equal(n.Key, key) {
				return bytes.Equal(n.Value, proofs[0])
			}
			return false

		case *LazyVectorCommitmentBranchNode:
			// Check prefix match
			for i, expectedNibble := range n.Prefix {
				if getNextNibble(key, depth+i*BranchBits) != expectedNibble {
					return false
				}
			}

			// Get final nibble after prefix
			finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)

			if !n.Verify(finalNibble, proofs[0]) {
				return false
			}

			return verify(
				n.Children[finalNibble],
				proofs[1:],
				depth+len(n.Prefix)*BranchBits+BranchBits,
			)
		}

		return false
	}

	return verify(t.Root, proofs, 0)
}

func (t *LazyVectorCommitmentTree) Prove(key []byte) [][]byte {
	if len(key) == 0 {
		return nil
	}

	var prove func(node LazyVectorCommitmentNode, depth int) [][]byte
	prove = func(node LazyVectorCommitmentNode, depth int) [][]byte {
		if node == nil {
			return nil
		}

		switch n := node.(type) {
		case *LazyVectorCommitmentLeafNode:
			if bytes.Equal(n.Key, key) {
				return [][]byte{n.Value}
			}
			return nil

		case *LazyVectorCommitmentBranchNode:
			// Check prefix match
			for i, expectedNibble := range n.Prefix {
				if getNextNibble(key, depth+i*BranchBits) != expectedNibble {
					return nil
				}
			}

			// Get final nibble after prefix
			finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)

			proofs := [][]byte{n.Prove(finalNibble)}

			return append(
				proofs,
				prove(
					n.Children[finalNibble],
					depth+len(n.Prefix)*BranchBits+BranchBits,
				)...,
			)
		}

		return nil
	}

	return prove(t.Root, 0)
}

// Get retrieves a value from the tree by key
func (t *LazyVectorCommitmentTree) Get(key []byte) ([]byte, error) {
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

func (t *LazyVectorCommitmentTree) GetMetadata() (
	leafCount int,
	longestBranch int,
) {
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

// Commit returns the root of the tree
func (t *LazyVectorCommitmentTree) Commit(recalculate bool) []byte {
	if t.Root == nil {
		return make([]byte, 64)
	}

	commitment := t.Root.Commit(
		nil,
		t.SetType,
		t.PhaseType,
		t.ShardKey,
		[]int{},
		recalculate,
	)

	err := t.Store.SaveRoot(t.SetType, t.PhaseType, t.ShardKey, t.Root)
	if err != nil {
		panic(err)
	}

	return commitment
}

func (t *LazyVectorCommitmentTree) GetSize() *big.Int {
	return t.Root.GetSize()
}

func SerializeTree(tree *LazyVectorCommitmentTree) ([]byte, error) {
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
) (*LazyVectorCommitmentTree, error) {
	buf := bytes.NewReader(data)
	node, err := deserializeNode(store, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize tree: %w", err)
	}
	return &LazyVectorCommitmentTree{
		Root:      node,
		SetType:   atomType,
		PhaseType: phaseType,
		ShardKey:  shardKey,
		Store:     store,
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
