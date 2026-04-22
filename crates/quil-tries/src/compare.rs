use crate::node::VectorCommitmentNode;

/// Result of comparing two nodes at the same position.
#[derive(Debug, Clone)]
pub struct ComparisonResult {
    pub path: Vec<i32>,
    pub left_commitment: Vec<u8>,
    pub right_commitment: Vec<u8>,
    pub differs: bool,
}

/// Compare two trees at each level, returning differences.
pub fn compare_trees_at_height(
    tree1_root: Option<&VectorCommitmentNode>,
    tree2_root: Option<&VectorCommitmentNode>,
) -> Vec<Vec<ComparisonResult>> {
    let mut levels: Vec<Vec<ComparisonResult>> = Vec::new();

    match (tree1_root, tree2_root) {
        (None, None) => {}
        (Some(_), None) | (None, Some(_)) => {
            levels.push(vec![ComparisonResult {
                path: vec![],
                left_commitment: tree1_root
                    .map(|n| n.commitment().to_vec())
                    .unwrap_or_default(),
                right_commitment: tree2_root
                    .map(|n| n.commitment().to_vec())
                    .unwrap_or_default(),
                differs: true,
            }]);
        }
        (Some(n1), Some(n2)) => {
            let root_differs = n1.commitment() != n2.commitment();
            levels.push(vec![ComparisonResult {
                path: vec![],
                left_commitment: n1.commitment().to_vec(),
                right_commitment: n2.commitment().to_vec(),
                differs: root_differs,
            }]);

            // TODO: recursive comparison at each level for branch nodes
        }
    }

    levels
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{BranchNode, LeafNode};
    use num_bigint::BigInt;

    fn leaf_with_commitment(commitment: Vec<u8>) -> VectorCommitmentNode {
        VectorCommitmentNode::Leaf(LeafNode {
            key: vec![],
            value: vec![],
            hash_target: vec![],
            commitment,
            size: BigInt::from(0),
        })
    }

    fn branch_with_commitment(commitment: Vec<u8>) -> VectorCommitmentNode {
        let mut branch = BranchNode::new(vec![]);
        branch.commitment = commitment;
        VectorCommitmentNode::Branch(branch)
    }

    // =================================================================
    // Both trees None
    // =================================================================

    #[test]
    fn compare_both_none_returns_empty() {
        let levels = compare_trees_at_height(None, None);
        assert!(levels.is_empty());
    }

    // =================================================================
    // One side None
    // =================================================================

    #[test]
    fn compare_left_none_right_some_differs() {
        let right = leaf_with_commitment(vec![0xAA; 64]);
        let levels = compare_trees_at_height(None, Some(&right));
        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0].len(), 1);
        let result = &levels[0][0];
        assert!(result.differs);
        assert!(result.left_commitment.is_empty());
        assert_eq!(result.right_commitment, vec![0xAA; 64]);
    }

    #[test]
    fn compare_left_some_right_none_differs() {
        let left = leaf_with_commitment(vec![0xBB; 64]);
        let levels = compare_trees_at_height(Some(&left), None);
        assert_eq!(levels.len(), 1);
        let result = &levels[0][0];
        assert!(result.differs);
        assert_eq!(result.left_commitment, vec![0xBB; 64]);
        assert!(result.right_commitment.is_empty());
    }

    // =================================================================
    // Both present — identical commitments
    // =================================================================

    #[test]
    fn compare_both_identical_leaves_does_not_differ() {
        let commitment = vec![0xAB; 64];
        let left = leaf_with_commitment(commitment.clone());
        let right = leaf_with_commitment(commitment.clone());
        let levels = compare_trees_at_height(Some(&left), Some(&right));
        assert_eq!(levels.len(), 1);
        let result = &levels[0][0];
        assert!(!result.differs);
        assert_eq!(result.left_commitment, commitment);
        assert_eq!(result.right_commitment, commitment);
        assert_eq!(result.path, Vec::<i32>::new());
    }

    #[test]
    fn compare_both_identical_branches_does_not_differ() {
        let commitment = vec![0xCD; 64];
        let left = branch_with_commitment(commitment.clone());
        let right = branch_with_commitment(commitment);
        let levels = compare_trees_at_height(Some(&left), Some(&right));
        assert_eq!(levels.len(), 1);
        assert!(!levels[0][0].differs);
    }

    // =================================================================
    // Both present — different commitments
    // =================================================================

    #[test]
    fn compare_different_leaf_commitments_differ() {
        let left = leaf_with_commitment(vec![0xAA; 64]);
        let right = leaf_with_commitment(vec![0xBB; 64]);
        let levels = compare_trees_at_height(Some(&left), Some(&right));
        let result = &levels[0][0];
        assert!(result.differs);
        assert_eq!(result.left_commitment, vec![0xAA; 64]);
        assert_eq!(result.right_commitment, vec![0xBB; 64]);
    }

    #[test]
    fn compare_leaf_vs_branch_with_same_commitment_does_not_differ() {
        // Root-level comparison only checks commitment bytes; the
        // node type is not considered. This documents current
        // (TODO-limited) behavior.
        let commitment = vec![0x77; 64];
        let leaf = leaf_with_commitment(commitment.clone());
        let branch = branch_with_commitment(commitment);
        let levels = compare_trees_at_height(Some(&leaf), Some(&branch));
        assert!(!levels[0][0].differs);
    }

    #[test]
    fn compare_empty_commitments_do_not_differ() {
        let left = leaf_with_commitment(vec![]);
        let right = leaf_with_commitment(vec![]);
        let levels = compare_trees_at_height(Some(&left), Some(&right));
        assert!(!levels[0][0].differs);
    }

    #[test]
    fn comparison_result_path_is_empty_at_root() {
        // Every root-level comparison emits a result with an empty
        // path (the path represents nibbles from root).
        let left = leaf_with_commitment(vec![1; 64]);
        let right = leaf_with_commitment(vec![2; 64]);
        let levels = compare_trees_at_height(Some(&left), Some(&right));
        assert_eq!(levels[0][0].path, Vec::<i32>::new());
    }
}
