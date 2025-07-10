package tries

import (
	"bytes"
	"log"
	"slices"
	"strings"

	"go.uber.org/zap"
)

// CompareTreesAtHeight compares two vector commitment trees at each level
func CompareTreesAtHeight(
	tree1, tree2 *LazyVectorCommitmentTree,
) [][]ComparisonResult {
	if tree1 == nil || tree2 == nil {
		return nil
	}

	var results [][]ComparisonResult
	maxHeight := getMaxHeight(tree1.Root, tree2.Root)

	// Compare level by level
	for height := 0; height <= maxHeight; height++ {
		levelResults := compareLevelCommits(tree1.Root, tree2.Root, height, 0)
		results = append(results, levelResults)
	}

	return results
}

type ComparisonResult struct {
	Path    []int  // Path taken to reach this node (nibble values)
	Height  int    // Current height in the tree
	Commit1 []byte // Commitment from first tree
	Commit2 []byte // Commitment from second tree
	Matches bool   // Whether the commitments match
}

func getMaxHeight(node1, node2 LazyVectorCommitmentNode) int {
	height1 := getHeight(node1)
	height2 := getHeight(node2)
	if height1 > height2 {
		return height1
	}
	return height2
}

func getHeight(node LazyVectorCommitmentNode) int {
	if node == nil {
		return 0
	}

	switch n := node.(type) {
	case *LazyVectorCommitmentLeafNode:
		return 0
	case *LazyVectorCommitmentBranchNode:
		maxChildHeight := 0
		for _, child := range n.Children {
			childHeight := getHeight(child)
			if childHeight > maxChildHeight {
				maxChildHeight = childHeight
			}
		}
		return maxChildHeight + 1 + len(n.Prefix)
	}
	return 0
}

func compareLevelCommits(
	node1, node2 LazyVectorCommitmentNode,
	targetHeight, currentHeight int,
) []ComparisonResult {
	if node1 == nil && node2 == nil {
		return nil
	}

	// If we've reached the target height, compare the commits
	if currentHeight == targetHeight {
		var commit1, commit2 []byte
		if node1 != nil {
			leaf1, lok := node1.(*LazyVectorCommitmentLeafNode)
			branch1, bok := node1.(*LazyVectorCommitmentBranchNode)
			if lok {
				commit1 = leaf1.Commitment
			} else if bok {
				commit1 = branch1.Commitment
			} else {
				log.Panic("invalid node type")
			}
		}
		if node2 != nil {
			leaf2, lok := node1.(*LazyVectorCommitmentLeafNode)
			branch2, bok := node1.(*LazyVectorCommitmentBranchNode)
			if lok {
				commit2 = leaf2.Commitment
			} else if bok {
				commit2 = branch2.Commitment
			} else {
				log.Panic("invalid node type")
			}
		}

		return []ComparisonResult{{
			Height:  targetHeight,
			Commit1: commit1,
			Commit2: commit2,
			Matches: bytes.Equal(commit1, commit2),
		}}
	}

	// If we haven't reached the target height, traverse deeper
	var results []ComparisonResult

	// Handle branch nodes
	switch n1 := node1.(type) {
	case *LazyVectorCommitmentBranchNode:
		n2, ok := node2.(*LazyVectorCommitmentBranchNode)
		if !ok {
			// Trees have different structure at this point
			return results
		}

		// Account for prefix lengths
		nextHeight := currentHeight
		if len(n1.Prefix) > 0 {
			nextHeight += len(n1.Prefix)
		}

		// If we're still below target height after prefix, traverse children
		if nextHeight < targetHeight {
			for i := 0; i < BranchNodes; i++ {
				childResults := compareLevelCommits(
					n1.Children[i],
					n2.Children[i],
					targetHeight,
					nextHeight+1,
				)
				results = append(results, childResults...)
			}
		}
	}

	return results
}

// TraverseAndCompare provides a channel-based iterator for comparing trees
func TraverseAndCompare(
	tree1, tree2 *LazyVectorCommitmentTree,
) chan ComparisonResult {
	resultChan := make(chan ComparisonResult)

	go func() {
		defer close(resultChan)

		if tree1 == nil || tree2 == nil {
			return
		}

		maxHeight := getMaxHeight(tree1.Root, tree2.Root)

		// Traverse each height
		for height := 0; height <= maxHeight; height++ {
			results := compareLevelCommits(tree1.Root, tree2.Root, height, 0)
			for _, result := range results {
				resultChan <- result
			}
		}
	}()

	return resultChan
}

// Example usage:
// LeafDifference contains information about leaves that differ between trees
type LeafDifference struct {
	Key         []byte // The key of the leaf
	OnlyInTree1 bool   // True if the leaf only exists in tree1
	OnlyInTree2 bool   // True if the leaf only exists in tree2
	Value1      []byte // Value from tree1 (if present)
	Value2      []byte // Value from tree2 (if present)
}

// CompareLeaves returns all leaves that differ between the two trees
func CompareLeaves(tree1, tree2 *LazyVectorCommitmentTree) []LeafDifference {
	// Get all leaves from both trees
	leaves1 := GetAllLeaves(
		tree1.SetType,
		tree1.PhaseType,
		tree1.ShardKey,
		tree1.Root,
	)
	leaves2 := GetAllLeaves(
		tree2.SetType,
		tree2.PhaseType,
		tree2.ShardKey,
		tree2.Root,
	)

	differences := make([]LeafDifference, 0)

	// Use maps for efficient lookup
	leafMap1 := make(map[string]*LazyVectorCommitmentLeafNode)
	leafMap2 := make(map[string]*LazyVectorCommitmentLeafNode)

	// Build maps
	for _, leaf := range leaves1 {
		leafMap1[string(leaf.Key)] = leaf
	}
	for _, leaf := range leaves2 {
		leafMap2[string(leaf.Key)] = leaf
	}

	// Find leaves only in tree1 or with different values
	for _, leaf1 := range leaves1 {
		key := string(leaf1.Key)
		if leaf2, exists := leafMap2[key]; exists {
			// Leaf exists in both trees, check if values match
			if !bytes.Equal(leaf1.Value, leaf2.Value) {
				differences = append(differences, LeafDifference{
					Key:    leaf1.Key,
					Value1: leaf1.Value,
					Value2: leaf2.Value,
				})
			}
		} else {
			// Leaf only exists in tree1
			differences = append(differences, LeafDifference{
				Key:         leaf1.Key,
				OnlyInTree1: true,
				Value1:      leaf1.Value,
			})
		}
	}

	// Find leaves only in tree2
	for _, leaf2 := range leaves2 {
		key := string(leaf2.Key)
		if _, exists := leafMap1[key]; !exists {
			differences = append(differences, LeafDifference{
				Key:         leaf2.Key,
				OnlyInTree2: true,
				Value2:      leaf2.Value,
			})
		}
	}

	return differences
}

// GetNPreloadedLeaves returns up to N leaf nodes in the tree
func GetNPreloadedLeaves(
	node VectorCommitmentNode,
	limit int,
) []*VectorCommitmentLeafNode {
	if node == nil {
		return nil
	}

	var leaves []*VectorCommitmentLeafNode

	switch n := node.(type) {
	case *VectorCommitmentLeafNode:
		leaves = append(leaves, n)
	case *VectorCommitmentBranchNode:
	outer:
		for _, child := range n.Children {
			if child != nil {
				childLeaves := GetNPreloadedLeaves(
					child,
					limit,
				)
				for _, leaf := range childLeaves {
					leaves = append(leaves, leaf)
					limit--
					if limit == 0 {
						break outer
					}
				}
			}
		}
	}

	return leaves
}

// GetAllPreloadedLeaves returns all leaf nodes in the tree
func GetAllPreloadedLeaves(
	node VectorCommitmentNode,
) []*VectorCommitmentLeafNode {
	if node == nil {
		return nil
	}

	var leaves []*VectorCommitmentLeafNode

	switch n := node.(type) {
	case *VectorCommitmentLeafNode:
		leaves = append(leaves, n)
	case *VectorCommitmentBranchNode:
		for _, child := range n.Children {
			if child != nil {
				childLeaves := GetAllPreloadedLeaves(
					child,
				)
				leaves = append(leaves, childLeaves...)
			}
		}
	}

	return leaves
}

// GetAllLeaves returns all leaf nodes in the tree
func GetAllLeaves(
	setType string,
	phaseType string,
	shardKey ShardKey,
	node LazyVectorCommitmentNode,
) []*LazyVectorCommitmentLeafNode {
	if node == nil {
		return nil
	}

	var leaves []*LazyVectorCommitmentLeafNode

	switch n := node.(type) {
	case *LazyVectorCommitmentLeafNode:
		leaves = append(leaves, n)
	case *LazyVectorCommitmentBranchNode:
		for i, child := range n.Children {
			child := child
			i := i
			var err error
			if child == nil {
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
				childLeaves := GetAllLeaves(
					setType,
					phaseType,
					shardKey,
					child,
				)
				leaves = append(leaves, childLeaves...)
			}
		}
	}

	return leaves
}
