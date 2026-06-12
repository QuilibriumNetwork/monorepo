use crate::node::VectorCommitmentNode;

/// Result of comparing two nodes at the same position. `path` is the
/// sequence of branch indices walked from the root to reach this
/// node — empty at the root.
#[derive(Debug, Clone)]
pub struct ComparisonResult {
    pub path: Vec<i32>,
    pub left_commitment: Vec<u8>,
    pub right_commitment: Vec<u8>,
    pub differs: bool,
}

/// Compare two trees level by level, returning one row per depth with
/// the differences observed at that depth.
///
/// Walks each pair of branch nodes whose commitments differ, descending
/// into matching child indices on both sides. Stops at any node that's
/// equal (no further divergence to surface) or at any leaf (no
/// children to walk). Asymmetric children — present on one side but
/// not the other — are emitted as differing entries.
pub fn compare_trees_at_height(
    tree1_root: Option<&VectorCommitmentNode>,
    tree2_root: Option<&VectorCommitmentNode>,
) -> Vec<Vec<ComparisonResult>> {
    let mut levels: Vec<Vec<ComparisonResult>> = Vec::new();

    match (tree1_root, tree2_root) {
        (None, None) => return levels,
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
            return levels;
        }
        (Some(n1), Some(n2)) => {
            let root_differs = n1.commitment() != n2.commitment();
            levels.push(vec![ComparisonResult {
                path: vec![],
                left_commitment: n1.commitment().to_vec(),
                right_commitment: n2.commitment().to_vec(),
                differs: root_differs,
            }]);
            if root_differs {
                walk_children(n1, n2, &[], &mut levels);
            }
        }
    }

    levels
}

/// Recurse into matching child slots when both sides are branch nodes
/// and at least one differs. Each call may push onto an existing
/// `levels` row (if the depth row is already there) or create a new
/// one. We keep "agreement" entries out of the per-level rows so
/// callers can treat any row entry as a known divergence point.
fn walk_children(
    left: &VectorCommitmentNode,
    right: &VectorCommitmentNode,
    parent_path: &[i32],
    levels: &mut Vec<Vec<ComparisonResult>>,
) {
    let (lb, rb) = match (left, right) {
        (VectorCommitmentNode::Branch(l), VectorCommitmentNode::Branch(r)) => (l, r),
        _ => return, // one side leaf → no further refinement
    };

    let depth = parent_path.len() + 1;

    // Iterate the 64 child slots. We emit an entry whenever the two
    // sides disagree at this slot — same commitment is implicit
    // agreement and gets skipped.
    for i in 0..lb.children.len() {
        let lc = lb.children[i].as_deref();
        let rc = rb.children[i].as_deref();
        if lc.is_none() && rc.is_none() {
            continue;
        }
        let l_commit = lc.map(|n| n.commitment().to_vec()).unwrap_or_default();
        let r_commit = rc.map(|n| n.commitment().to_vec()).unwrap_or_default();
        let differs = l_commit != r_commit;
        if !differs {
            continue;
        }

        let mut path = parent_path.to_vec();
        path.push(i as i32);

        ensure_level(levels, depth).push(ComparisonResult {
            path: path.clone(),
            left_commitment: l_commit,
            right_commitment: r_commit,
            differs: true,
        });

        // Both sides are branch → recurse to surface the next layer.
        if let (Some(lcn), Some(rcn)) = (lc, rc) {
            // Apply each branch's compressed prefix as additional path
            // hops, so consumers see the full nibble path.
            let extended = with_prefix(&path, lcn, rcn);
            walk_children(lcn, rcn, &extended, levels);
        }
    }
}

fn with_prefix(
    base: &[i32],
    left: &VectorCommitmentNode,
    right: &VectorCommitmentNode,
) -> Vec<i32> {
    let mut out = base.to_vec();
    if let (VectorCommitmentNode::Branch(l), VectorCommitmentNode::Branch(r)) = (left, right) {
        // Both sides should share their compressed prefix when in the
        // same logical position; if they diverge the extra nibbles are
        // logged through whichever side is longer.
        let prefix = if l.prefix == r.prefix {
            &l.prefix
        } else if l.prefix.len() >= r.prefix.len() {
            &l.prefix
        } else {
            &r.prefix
        };
        out.extend_from_slice(prefix);
    }
    out
}

fn ensure_level<'a>(
    levels: &'a mut Vec<Vec<ComparisonResult>>,
    depth: usize,
) -> &'a mut Vec<ComparisonResult> {
    while levels.len() <= depth {
        levels.push(Vec::new());
    }
    &mut levels[depth]
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

    fn branch_with_children(
        commitment: Vec<u8>,
        children: Vec<(usize, VectorCommitmentNode)>,
    ) -> VectorCommitmentNode {
        let mut branch = BranchNode::new(vec![]);
        branch.commitment = commitment;
        for (idx, child) in children {
            branch.children[idx] = Some(Box::new(child));
        }
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
        // Root-level comparison only checks commitment bytes; structural
        // type (leaf vs branch) is not considered here. With matching
        // commitments we treat them as equal and don't recurse.
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
        let left = leaf_with_commitment(vec![1; 64]);
        let right = leaf_with_commitment(vec![2; 64]);
        let levels = compare_trees_at_height(Some(&left), Some(&right));
        assert_eq!(levels[0][0].path, Vec::<i32>::new());
    }

    // =================================================================
    // Recursive: divergent branches surface child differences
    // =================================================================

    #[test]
    fn compare_branches_recurses_into_differing_children() {
        // Two root branches differ in commitment; child 5 differs,
        // children 0..4 and 6.. are absent on both sides.
        let left = branch_with_children(
            vec![0xAA; 64],
            vec![(5, leaf_with_commitment(vec![0x11; 64]))],
        );
        let right = branch_with_children(
            vec![0xBB; 64],
            vec![(5, leaf_with_commitment(vec![0x22; 64]))],
        );
        let levels = compare_trees_at_height(Some(&left), Some(&right));
        assert!(levels.len() >= 2, "expected at least 2 levels (root + child)");
        // Root row records the root divergence.
        assert!(levels[0][0].differs);
        // Depth 1 row records the child-5 divergence with path [5].
        assert!(levels[1].iter().any(|r| r.path == vec![5] && r.differs));
    }

    #[test]
    fn compare_branches_skips_matching_children() {
        // Child 3 matches on both sides; child 7 differs. Only child 7
        // should appear in the depth-1 row.
        let common_leaf = leaf_with_commitment(vec![0x33; 64]);
        let left = branch_with_children(
            vec![0xAA; 64],
            vec![
                (3, common_leaf.clone()),
                (7, leaf_with_commitment(vec![0x44; 64])),
            ],
        );
        let right = branch_with_children(
            vec![0xBB; 64],
            vec![
                (3, common_leaf),
                (7, leaf_with_commitment(vec![0x55; 64])),
            ],
        );
        let levels = compare_trees_at_height(Some(&left), Some(&right));
        let depth_one = &levels[1];
        assert_eq!(depth_one.len(), 1);
        assert_eq!(depth_one[0].path, vec![7]);
    }

    #[test]
    fn compare_branches_records_asymmetric_children() {
        // Child 9 only present on the left side.
        let left = branch_with_children(
            vec![0xAA; 64],
            vec![(9, leaf_with_commitment(vec![0x66; 64]))],
        );
        let right = branch_with_commitment(vec![0xBB; 64]);
        let levels = compare_trees_at_height(Some(&left), Some(&right));
        assert!(levels[1].iter().any(|r| r.path == vec![9]
            && r.left_commitment == vec![0x66; 64]
            && r.right_commitment.is_empty()));
    }
}
