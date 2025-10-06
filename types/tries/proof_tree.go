package tries

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strings"
	"sync"

	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/utils/runtime"
)

const (
	BranchNodes      = 64
	BranchBits       = 6 // log2(64)
	BranchMask       = BranchNodes - 1
	TypeNil     byte = 0
	TypeLeaf    byte = 1
	TypeBranch  byte = 2
)

type VectorCommitmentNode interface {
	Commit(prover crypto.InclusionProver, recalculate bool) []byte
	GetSize() *big.Int
}

type VectorCommitmentLeafNode struct {
	Key        []byte
	Value      []byte
	HashTarget []byte
	Commitment []byte
	Size       *big.Int
}

type VectorCommitmentBranchNode struct {
	Prefix        []int
	Children      [BranchNodes]VectorCommitmentNode
	Commitment    []byte
	Size          *big.Int
	LeafCount     int
	LongestBranch int
}

func (n *VectorCommitmentLeafNode) Commit(
	prover crypto.InclusionProver,
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

	}
	return n.Commitment
}

func (n *VectorCommitmentLeafNode) GetSize() *big.Int {
	return n.Size
}

func (n *VectorCommitmentBranchNode) Commit(
	prover crypto.InclusionProver,
	recalculate bool,
) []byte {
	if len(n.Commitment) == 0 || recalculate {
		vector := make([][]byte, len(n.Children))
		wg := sync.WaitGroup{}
		throttle := make(chan struct{}, runtime.WorkerCount(0, false, false))
		for i, child := range n.Children {
			throttle <- struct{}{}
			wg.Add(1)
			go func(i int, child VectorCommitmentNode) {
				defer func() { <-throttle }()
				defer wg.Done()
				if child != nil {
					out := child.Commit(prover, recalculate)
					switch c := child.(type) {
					case *VectorCommitmentBranchNode:
						h := sha512.New()
						h.Write([]byte{1})
						for _, p := range c.Prefix {
							h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
						}
						h.Write(out)
						out = h.Sum(nil)
					case *VectorCommitmentLeafNode:
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
		n.Commitment, _ = prover.CommitRaw(data, 64)
	}

	return n.Commitment
}

func (n *VectorCommitmentBranchNode) Verify(
	prover crypto.InclusionProver,
	index int,
	proof []byte,
) bool {
	data := []byte{}
	if len(n.Commitment) == 0 {
		for _, child := range n.Children {
			if child != nil {
				out := child.Commit(prover, false)
				switch c := child.(type) {
				case *VectorCommitmentBranchNode:
					h := sha512.New()
					h.Write([]byte{1})
					for _, p := range c.Prefix {
						h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
					}
					h.Write(out)
					out = h.Sum(nil)
				case *VectorCommitmentLeafNode:
					// do nothing
				}
				data = append(data, out...)
			} else {
				data = append(data, make([]byte, 64)...)
			}
		}

		n.Commitment, _ = prover.CommitRaw(data, 64)
		data = data[64*index : 64*(index+1)]
	} else {
		child := n.Children[index]
		if child != nil {
			out := child.Commit(prover, false)
			switch c := child.(type) {
			case *VectorCommitmentBranchNode:
				h := sha512.New()
				h.Write([]byte{1})
				for _, p := range c.Prefix {
					h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
				}
				h.Write(out)
				out = h.Sum(nil)
			case *VectorCommitmentLeafNode:
				// do nothing
			}
			data = append(data, out...)
		} else {
			data = append(data, make([]byte, 64)...)
		}
	}

	valid, _ := prover.VerifyRaw(data, n.Commitment, uint64(index), proof, 64)
	return valid
}

func (n *VectorCommitmentBranchNode) GetSize() *big.Int {
	return n.Size
}

func (n *VectorCommitmentBranchNode) Prove(
	prover crypto.InclusionProver,
	index int,
) []byte {
	data := []byte{}
	for _, child := range n.Children {
		if child != nil {
			out := child.Commit(prover, false)
			switch c := child.(type) {
			case *VectorCommitmentBranchNode:
				h := sha512.New()
				h.Write([]byte{1})
				for _, p := range c.Prefix {
					h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
				}
				h.Write(out)
				out = h.Sum(nil)
			case *VectorCommitmentLeafNode:
				// do nothing
			}
			data = append(data, out...)
		} else {
			data = append(data, make([]byte, 64)...)
		}
	}
	proof, _ := prover.ProveRaw(data, index, 64)
	return proof
}

type VectorCommitmentTree struct {
	Root VectorCommitmentNode
}

// getNextNibble returns the next BranchBits bits from the key starting at pos
func getNextNibble(key []byte, pos int) int {
	startByte := pos / 8
	if startByte >= len(key) {
		return -1
	}

	// Calculate how many bits we need from the current byte
	startBit := pos % 8
	bitsFromCurrentByte := 8 - startBit

	result := int(key[startByte] & ((1 << bitsFromCurrentByte) - 1))

	if bitsFromCurrentByte >= BranchBits {
		// We have enough bits in the current byte
		return (result >> (bitsFromCurrentByte - BranchBits)) & BranchMask
	}

	// We need bits from the next byte
	result = result << (BranchBits - bitsFromCurrentByte)
	if startByte+1 < len(key) {
		remainingBits := BranchBits - bitsFromCurrentByte
		nextByte := int(key[startByte+1])
		result |= (nextByte >> (8 - remainingBits))
	}

	return result & BranchMask
}

func GetFullPath(key []byte) []int {
	var nibbles []int
	depth := 0
	for {
		n1 := getNextNibble(key, depth)
		if n1 == -1 {
			break
		}
		nibbles = append(nibbles, n1)
		depth += BranchBits
	}

	return nibbles
}

func getNibblesUntilDiverge(key1, key2 []byte, startDepth int) ([]int, int) {
	var nibbles []int
	depth := startDepth

	for {
		n1 := getNextNibble(key1, depth)
		n2 := getNextNibble(key2, depth)
		if n1 != n2 {
			return nibbles, depth
		}
		nibbles = append(nibbles, n1)
		depth += BranchBits
	}
}

// Insert adds or updates a key-value pair in the tree
func (t *VectorCommitmentTree) Insert(
	key, value, hashTarget []byte,
	size *big.Int,
) error {
	if len(key) == 0 {
		return errors.New("empty key not allowed")
	}
	var insert func(node VectorCommitmentNode, depth int) (
		int,
		VectorCommitmentNode,
	)
	insert = func(node VectorCommitmentNode, depth int) (
		int,
		VectorCommitmentNode,
	) {
		if node == nil {
			return 1, &VectorCommitmentLeafNode{
				Key:        key,
				Value:      value,
				HashTarget: hashTarget,
				Size:       size,
			}
		}

		switch n := node.(type) {
		case *VectorCommitmentLeafNode:
			if bytes.Equal(n.Key, key) {
				n.Value = value
				n.HashTarget = hashTarget
				n.Commitment = nil
				n.Size = size
				return 0, n
			}

			// Get common prefix nibbles and divergence point
			sharedNibbles, divergeDepth := getNibblesUntilDiverge(n.Key, key, depth)

			// Create single branch node with shared prefix
			branch := &VectorCommitmentBranchNode{
				Prefix:        sharedNibbles,
				LeafCount:     2,
				LongestBranch: 1,
				Size:          new(big.Int).Add(n.Size, size),
			}

			// Add both leaves at their final positions
			finalOldNibble := getNextNibble(n.Key, divergeDepth)
			finalNewNibble := getNextNibble(key, divergeDepth)
			branch.Children[finalOldNibble] = n
			branch.Children[finalNewNibble] = &VectorCommitmentLeafNode{
				Key:        key,
				Value:      value,
				HashTarget: hashTarget,
				Size:       size,
			}

			return 1, branch

		case *VectorCommitmentBranchNode:
			if len(n.Prefix) > 0 {
				// Check if the new key matches the prefix
				for i, expectedNibble := range n.Prefix {
					actualNibble := getNextNibble(key, depth+i*BranchBits)
					if actualNibble != expectedNibble {
						// Create new branch with shared prefix subset
						newBranch := &VectorCommitmentBranchNode{
							Prefix:        n.Prefix[:i],
							LeafCount:     n.LeafCount + 1,
							LongestBranch: n.LongestBranch + 1,
							Size:          new(big.Int).Add(n.Size, size),
						}
						// Position old branch and new leaf
						newBranch.Children[expectedNibble] = n
						n.Prefix = n.Prefix[i+1:] // remove shared prefix from old branch
						newBranch.Children[actualNibble] = &VectorCommitmentLeafNode{
							Key:        key,
							Value:      value,
							HashTarget: hashTarget,
							Size:       size,
						}
						return 1, newBranch
					}
				}

				// Key matches prefix, continue with final nibble
				finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)
				delta, inserted := insert(
					n.Children[finalNibble],
					depth+len(n.Prefix)*BranchBits+BranchBits,
				)
				n.Children[finalNibble] = inserted
				n.Commitment = nil
				n.LeafCount += delta
				switch i := inserted.(type) {
				case *VectorCommitmentBranchNode:
					if n.LongestBranch <= i.LongestBranch {
						n.LongestBranch = i.LongestBranch + 1
					}
				case *VectorCommitmentLeafNode:
					n.LongestBranch = 1
				}
				if delta != 0 {
					n.Size = n.Size.Add(n.Size, size)
				}
				return delta, n
			} else {
				// Simple branch without prefix
				nibble := getNextNibble(key, depth)
				delta, inserted := insert(n.Children[nibble], depth+BranchBits)
				n.Children[nibble] = inserted
				n.Commitment = nil
				n.LeafCount += delta
				switch i := inserted.(type) {
				case *VectorCommitmentBranchNode:
					if n.LongestBranch <= i.LongestBranch {
						n.LongestBranch = i.LongestBranch + 1
					}
				case *VectorCommitmentLeafNode:
					n.LongestBranch = 1
				}
				if delta != 0 {
					n.Size = n.Size.Add(n.Size, size)
				}
				return delta, n
			}
		}

		return 0, nil
	}

	_, t.Root = insert(t.Root, 0)
	return nil
}

func VerifyTreeTraversalProof(
	prover crypto.InclusionProver,
	rootCommit []byte,
	proof *TraversalProof,
) bool {
	if len(proof.Multiproof.GetMulticommitment()) == 0 ||
		len(proof.Multiproof.GetProof()) == 0 {
		return false
	}

	for _, subProof := range proof.SubProofs {
		if len(subProof.Commits) == 0 ||
			len(subProof.Paths) != len(subProof.Commits)-1 ||
			len(subProof.Ys) != len(subProof.Commits) {
			return false
		}
	}

	for _, subProof := range proof.SubProofs {
		if !bytes.Equal(rootCommit, subProof.Commits[0]) {
			return false
		}
	}

	var verify func(commits [][]byte, indices [][]uint64, ys [][]byte) bool
	verify = func(commits [][]byte, indices [][]uint64, ys [][]byte) bool {
		if len(commits) <= 1 {
			return true
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
			return false
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

		if !verify(subProof.Commits, subProof.Paths, subProof.Ys) {
			return false
		}
	}

	if len(commits) > 1 && !prover.VerifyMultiple(
		commits,
		ys,
		indices,
		64,
		proof.Multiproof.GetMulticommitment(),
		proof.Multiproof.GetProof(),
	) {
		return false
	}

	return true
}

func (n *VectorCommitmentBranchNode) GetPolynomial() []byte {
	data := []byte{}
	for _, child := range n.Children {
		if child != nil {
			var out []byte
			switch c := child.(type) {
			case *VectorCommitmentBranchNode:
				out = c.Commitment
				h := sha512.New()
				h.Write([]byte{1})
				for _, p := range c.Prefix {
					h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
				}
				h.Write(out)
				out = h.Sum(nil)
			case *VectorCommitmentLeafNode:
				out = c.Commitment
			}
			data = append(data, out...)
		} else {
			data = append(data, make([]byte, 64)...)
		}
	}

	return data
}

func (t *VectorCommitmentTree) Prove(
	prover crypto.InclusionProver,
	key []byte,
) *TraversalProof {
	if len(key) == 0 {
		return nil
	}

	var prove func(
		node VectorCommitmentNode,
		depth int,
	) ([][]byte, [][]byte, [][]byte, [][]int)
	prove = func(
		node VectorCommitmentNode,
		depth int,
	) ([][]byte, [][]byte, [][]byte, [][]int) {
		if node == nil {
			return nil, nil, nil, nil
		}

		switch n := node.(type) {
		case *VectorCommitmentLeafNode:
			commitment := n.Commit(
				prover,
				false,
			)
			if bytes.Equal(n.Key, key) {
				if len(n.HashTarget) != 0 {
					return [][]byte{}, [][]byte{commitment}, [][]byte{n.HashTarget}, [][]int{}
				} else {
					return [][]byte{}, [][]byte{commitment}, [][]byte{n.Value}, [][]int{}
				}
			}
			return nil, nil, nil, nil

		case *VectorCommitmentBranchNode:
			// Check prefix match
			for i, expectedNibble := range n.Prefix {
				if getNextNibble(key, depth+i*BranchBits) != expectedNibble {
					return nil, nil, nil, nil
				}
			}

			// Get final nibble after prefix
			finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)

			commits := [][]byte{n.Commit(
				prover,
				false,
			)}
			poly := n.GetPolynomial()
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

	multiproof := prover.ProveMultiple(
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

func (t *VectorCommitmentTree) ProveMultiple(
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
		node VectorCommitmentNode,
		key []byte,
		depth int,
	) ([][]byte, [][]byte, [][]byte, [][]int)
	prove = func(
		node VectorCommitmentNode,
		key []byte,
		depth int,
	) ([][]byte, [][]byte, [][]byte, [][]int) {
		if node == nil {
			return nil, nil, nil, nil
		}

		switch n := node.(type) {
		case *VectorCommitmentLeafNode:
			commitment := n.Commit(
				prover,
				false,
			)
			if bytes.Equal(n.Key, key) {
				if len(n.HashTarget) != 0 {
					return [][]byte{}, [][]byte{commitment}, [][]byte{n.HashTarget}, [][]int{}
				} else {
					return [][]byte{}, [][]byte{commitment}, [][]byte{n.Value}, [][]int{}
				}
			}
			return nil, nil, nil, nil

		case *VectorCommitmentBranchNode:
			// Check prefix match
			for i, expectedNibble := range n.Prefix {
				if getNextNibble(key, depth+i*BranchBits) != expectedNibble {
					return nil, nil, nil, nil
				}
			}

			// Get final nibble after prefix
			finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)

			commits := [][]byte{n.Commit(
				prover,
				false,
			)}
			poly := n.GetPolynomial()
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
func (t *VectorCommitmentTree) Get(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("empty key not allowed")
	}

	var get func(node VectorCommitmentNode, depth int) []byte
	get = func(node VectorCommitmentNode, depth int) []byte {
		if node == nil {
			return nil
		}

		switch n := node.(type) {
		case *VectorCommitmentLeafNode:
			if bytes.Equal(n.Key, key) {
				return n.Value
			}
			return nil

		case *VectorCommitmentBranchNode:
			// Check prefix match
			for i, expectedNibble := range n.Prefix {
				if getNextNibble(key, depth+i*BranchBits) != expectedNibble {
					return nil
				}
			}
			// Get final nibble after prefix
			finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)
			return get(n.Children[finalNibble], depth+len(n.Prefix)*BranchBits+BranchBits)
		}

		return nil
	}

	value := get(t.Root, 0)
	if value == nil {
		return nil, errors.New(fmt.Sprintf("key not found: 0x%x", key))
	}
	return value, nil
}

// Delete removes a key-value pair from the tree
func (t *VectorCommitmentTree) Delete(key []byte) error {
	if len(key) == 0 {
		return errors.New("empty key not allowed")
	}

	var remove func(
		node VectorCommitmentNode,
		depth int,
	) (*big.Int, VectorCommitmentNode)
	remove = func(
		node VectorCommitmentNode,
		depth int,
	) (*big.Int, VectorCommitmentNode) {
		if node == nil {
			return big.NewInt(0), nil
		}

		switch n := node.(type) {

		case *VectorCommitmentLeafNode:
			if bytes.Equal(n.Key, key) {
				return n.Size, nil
			}
			return big.NewInt(0), n

		case *VectorCommitmentBranchNode:
			for i, expectedNibble := range n.Prefix {
				currentNibble := getNextNibble(key, depth+i*BranchBits)
				if currentNibble != expectedNibble {
					return big.NewInt(0), n
				}
			}

			finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)
			var size *big.Int
			size, n.Children[finalNibble] =
				remove(
					n.Children[finalNibble],
					depth+len(n.Prefix)*BranchBits+BranchBits,
				)

			n.Commitment = nil

			childCount := 0
			var lastChild VectorCommitmentNode
			var lastChildIndex int
			longestBranch := 1
			leaves := 0
			for i, child := range n.Children {
				if child != nil {
					childCount++
					lastChild = child
					lastChildIndex = i
					switch c := child.(type) {
					case *VectorCommitmentBranchNode:
						leaves += c.LeafCount
						if longestBranch < c.LongestBranch+1 {
							longestBranch = c.LongestBranch + 1
						}
					case *VectorCommitmentLeafNode:
						leaves += 1
					}
				}
			}

			var retNode VectorCommitmentNode
			switch childCount {
			case 0:
				retNode = nil
			case 1:
				if childBranch, ok := lastChild.(*VectorCommitmentBranchNode); ok {
					// Merge:
					//   n.Prefix + [lastChildIndex] + childBranch.Prefix
					mergedPrefix := make(
						[]int,
						0,
						len(n.Prefix)+1+len(childBranch.Prefix),
					)
					mergedPrefix = append(mergedPrefix, n.Prefix...)
					mergedPrefix = append(mergedPrefix, lastChildIndex)
					mergedPrefix = append(mergedPrefix, childBranch.Prefix...)

					childBranch.Prefix = mergedPrefix
					childBranch.Commitment = nil
					retNode = childBranch
				} else {
					retNode = lastChild
				}
			default:
				n.LongestBranch = longestBranch
				n.LeafCount = leaves
				n.Size = n.Size.Sub(n.Size, size)
				retNode = n
			}

			return size, retNode
		default:
			return big.NewInt(0), node
		}
	}

	_, t.Root = remove(t.Root, 0)
	return nil
}

func (t *VectorCommitmentTree) GetMetadata() (
	leafCount int,
	longestBranch int,
) {
	switch root := t.Root.(type) {
	case nil:
		return 0, 0
	case *VectorCommitmentLeafNode:
		return 1, 0
	case *VectorCommitmentBranchNode:
		return root.LeafCount, root.LongestBranch
	}
	return 0, 0
}

// Commit returns the root of the tree
func (t *VectorCommitmentTree) Commit(
	prover crypto.InclusionProver,
	recalculate bool,
) []byte {
	if t.Root == nil {
		return make([]byte, 64)
	}
	return t.Root.Commit(prover, recalculate)
}

func (t *VectorCommitmentTree) GetSize() *big.Int {
	if t.Root == nil {
		return big.NewInt(0)
	}

	return t.Root.GetSize()
}

func SerializeNonLazyTree(tree *VectorCommitmentTree) ([]byte, error) {
	var buf bytes.Buffer
	if err := serializeNonLazyNode(&buf, tree.Root); err != nil {
		return nil, fmt.Errorf("failed to serialize tree: %w", err)
	}
	return buf.Bytes(), nil
}

func DeserializeNonLazyTree(
	data []byte,
) (*VectorCommitmentTree, error) {
	buf := bytes.NewReader(data)
	node, err := deserializeNonLazyNode(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize tree: %w", err)
	}
	return &VectorCommitmentTree{
		Root: node,
	}, nil
}

func serializeNonLazyNode(w io.Writer, node VectorCommitmentNode) error {
	if node == nil {
		if err := binary.Write(w, binary.BigEndian, TypeNil); err != nil {
			return err
		}
		return nil
	}

	switch n := node.(type) {
	case *VectorCommitmentLeafNode:
		if err := binary.Write(w, binary.BigEndian, TypeLeaf); err != nil {
			return err
		}
		return SerializeNonLazyLeafNode(w, n)
	case *VectorCommitmentBranchNode:
		if err := binary.Write(w, binary.BigEndian, TypeBranch); err != nil {
			return err
		}
		return SerializeNonLazyBranchNode(w, n)
	default:
		return fmt.Errorf("unknown node type: %T", node)
	}
}

func SerializeNonLazyLeafNode(
	w io.Writer,
	node *VectorCommitmentLeafNode,
) error {
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

func SerializeNonLazyBranchNode(
	w io.Writer,
	node *VectorCommitmentBranchNode,
) error {
	if err := serializeIntSlice(w, node.Prefix); err != nil {
		return err
	}

	for i := 0; i < BranchNodes; i++ {
		child := node.Children[i]
		if err := serializeNonLazyNode(w, child); err != nil {
			return err
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

func deserializeNonLazyNode(
	r io.Reader,
) (VectorCommitmentNode, error) {
	var nodeType byte
	if err := binary.Read(r, binary.BigEndian, &nodeType); err != nil {
		return nil, err
	}

	switch nodeType {
	case TypeNil:
		return nil, nil
	case TypeLeaf:
		return DeserializeNonLazyLeafNode(r)
	case TypeBranch:
		return DeserializeNonLazyBranchNode(r)
	default:
		return nil, fmt.Errorf("unknown node type marker: %d", nodeType)
	}
}

func DeserializeNonLazyLeafNode(
	r io.Reader,
) (*VectorCommitmentLeafNode, error) {
	node := &VectorCommitmentLeafNode{}

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

func DeserializeNonLazyBranchNode(
	r io.Reader,
) (*VectorCommitmentBranchNode, error) {
	node := &VectorCommitmentBranchNode{}

	prefix, err := deserializeIntSlice(r)
	if err != nil {
		return nil, err
	}
	node.Prefix = prefix

	node.Children = [BranchNodes]VectorCommitmentNode{}
	for i := 0; i < BranchNodes; i++ {
		child, err := deserializeNonLazyNode(r)
		if err != nil {
			return nil, err
		}
		node.Children[i] = child
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

func DebugNonLazyNode(node VectorCommitmentNode, depth int, prefix string) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *VectorCommitmentLeafNode:
		fmt.Printf("%sLeaf: key=%x value=%x\n", prefix, n.Key, n.Value)
	case *VectorCommitmentBranchNode:
		fmt.Printf("%sBranch %v:\n", prefix, n.Prefix)
		for i, child := range n.Children {
			if child != nil {
				fmt.Printf("%s  [%d]:\n", prefix, i)
				DebugNonLazyNode(child, depth+1, prefix+"    ")
			}
		}
	}
}

func DebugNode(
	setType, phaseType string,
	shardKey ShardKey,
	node LazyVectorCommitmentNode,
	depth int,
	prefix string,
) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *LazyVectorCommitmentLeafNode:
		fmt.Printf("%sLeaf: key=%x value=%x\n", prefix, n.Key, n.Value)
	case *LazyVectorCommitmentBranchNode:
		fmt.Printf("%sBranch %v:\n", prefix, n.Prefix)
		for i, child := range n.Children {
			// if child == nil {
			var err error
			child, err = n.Store.GetNodeByPath(
				setType,
				phaseType,
				shardKey,
				slices.Concat(n.FullPrefix, []int{i}),
			)
			if err != nil && !strings.Contains(err.Error(), "not found") {
				panic(err)
			}
			// }
			if child != nil {
				fmt.Printf("%s  [%d]:\n", prefix, i)
				DebugNode(setType, phaseType, shardKey, child, depth+1, prefix+"    ")
			}
		}
	}
}
