//! Consensus safety check: verify a collection of frames forms a single,
//! non-empty linear chain — exactly one root, every frame at most one child,
//! and all frames connected without gaps or cycles.

use std::collections::{HashMap, HashSet};

/// Accessor for the 32-byte identity and parent selector of a frame.
pub trait FrameFields {
    fn identity(&self) -> anyhow::Result<[u8; 32]>;
    fn parent_selector(&self) -> anyhow::Result<[u8; 32]>;
}

#[derive(Debug, thiserror::Error)]
pub enum SafetyError {
    #[error("cycle detected in frame chain: {0}")]
    Cycle(String),
    #[error("duplicate frame detected with different parents: {0}")]
    DuplicateFrame(String),
    #[error("empty frame sequence")]
    EmptyFrameSequence,
    #[error("fork detected: {0}")]
    Fork(String),
    #[error("failed to read frame fields: {0}")]
    Frame(#[from] anyhow::Error),
}

/// Verifies that `frames` form a single non-empty linear chain.
pub fn check_safety<F: FrameFields>(frames: &[F]) -> Result<(), SafetyError> {
    if frames.is_empty() {
        return Err(SafetyError::EmptyFrameSequence);
    }
    if frames.len() == 1 {
        return Ok(());
    }

    let child_to_parent = build_frame_parents(frames)?;
    let parent_to_children = build_parent_to_children(&child_to_parent);

    // Find leaves and detect forks (a parent with >1 child) at the same time.
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    for (parent_id, children) in &parent_to_children {
        if children.len() > 1 {
            return Err(SafetyError::Fork(format!(
                "parent {} has {} children",
                hex::encode(parent_id),
                children.len()
            )));
        }
        if children.is_empty() {
            leaves.push(*parent_id);
        }
    }

    if leaves.is_empty() {
        return Err(SafetyError::Cycle("no leaf frames detected".to_string()));
    }
    if leaves.len() > 1 {
        let hex_leaves: Vec<String> = leaves.iter().map(hex::encode).collect();
        return Err(SafetyError::Fork(format!(
            "multiple leaves detected: {hex_leaves:?}"
        )));
    }

    // Traverse from the single leaf to the root, detecting cycles.
    let mut visited: HashSet<[u8; 32]> = HashSet::new();
    let mut current = leaves[0];
    loop {
        if !visited.insert(current) {
            return Err(SafetyError::Cycle(format!(
                "cycle detected at frame {}",
                hex::encode(current)
            )));
        }
        match child_to_parent.get(&current) {
            Some(parent) => current = *parent,
            None => break, // reached a root frame
        }
    }

    // parent_to_children has an entry for every frame, so a smaller visited set
    // means there are disjoint frames.
    if visited.len() != parent_to_children.len() {
        return Err(SafetyError::Fork(format!(
            "only {} out of {} frames are connected",
            visited.len(),
            parent_to_children.len()
        )));
    }

    Ok(())
}

/// Maps each frame identity to its parent selector. Errors if the same identity
/// appears with different parents.
fn build_frame_parents<F: FrameFields>(
    frames: &[F],
) -> Result<HashMap<[u8; 32], [u8; 32]>, SafetyError> {
    let mut parents: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
    for frame in frames {
        let identity = frame.identity()?;
        let parent_selector = frame.parent_selector()?;
        if let Some(existing) = parents.get(&identity) {
            if *existing != parent_selector {
                return Err(SafetyError::DuplicateFrame(format!(
                    "frame {}",
                    hex::encode(identity)
                )));
            }
        }
        parents.insert(identity, parent_selector);
    }
    Ok(parents)
}

/// Reverse map from parent to its children. Every frame (parent or child) gets
/// an entry, so childless frames map to an empty list.
fn build_parent_to_children(
    parents: &HashMap<[u8; 32], [u8; 32]>,
) -> HashMap<[u8; 32], Vec<[u8; 32]>> {
    let mut children: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();
    for (child_id, parent_id) in parents {
        children.entry(*parent_id).or_default();
        children.entry(*child_id).or_default();
        children.get_mut(parent_id).unwrap().push(*child_id);
    }
    children
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockFrame {
        identity: [u8; 32],
        parent: [u8; 32],
    }
    impl FrameFields for MockFrame {
        fn identity(&self) -> anyhow::Result<[u8; 32]> {
            Ok(self.identity)
        }
        fn parent_selector(&self) -> anyhow::Result<[u8; 32]> {
            Ok(self.parent)
        }
    }

    /// 32-byte array from a single leading byte value (matches Go's byteArray).
    fn b(v: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = v;
        a
    }
    fn frame(identity: u8, parent: u8) -> MockFrame {
        MockFrame {
            identity: b(identity),
            parent: b(parent),
        }
    }

    #[test]
    fn empty_sequence() {
        let frames: Vec<MockFrame> = vec![];
        assert!(matches!(
            check_safety(&frames),
            Err(SafetyError::EmptyFrameSequence)
        ));
    }

    #[test]
    fn single_frame() {
        assert!(check_safety(&[frame(1, 0)]).is_ok());
    }

    #[test]
    fn valid_linear_chain() {
        let frames = vec![frame(1, 0), frame(2, 1), frame(3, 2), frame(4, 3)];
        assert!(check_safety(&frames).is_ok());
    }

    #[test]
    fn valid_linear_chain_out_of_order() {
        let frames = vec![frame(3, 2), frame(1, 0), frame(4, 3), frame(2, 1)];
        assert!(check_safety(&frames).is_ok());
    }

    #[test]
    fn valid_linear_chain_duplicate_frames() {
        let frames = vec![
            frame(3, 2),
            frame(1, 0),
            frame(4, 3),
            frame(2, 1),
            frame(1, 0),
        ];
        assert!(check_safety(&frames).is_ok());
    }

    #[test]
    fn tree_structure_is_fork() {
        let frames = vec![frame(1, 0), frame(2, 1), frame(3, 1)];
        assert!(matches!(check_safety(&frames), Err(SafetyError::Fork(_))));
    }

    #[test]
    fn disjointed_chains_is_fork() {
        let frames = vec![frame(1, 0), frame(2, 1), frame(4, 3), frame(5, 4)];
        assert!(matches!(check_safety(&frames), Err(SafetyError::Fork(_))));
    }

    #[test]
    fn gap_in_chain_is_fork() {
        let frames = vec![frame(1, 0), frame(3, 2)];
        assert!(matches!(check_safety(&frames), Err(SafetyError::Fork(_))));
    }

    #[test]
    fn cycle_detected() {
        // 1->3, 2->1, 3->2  (cycle)
        let frames = vec![frame(1, 3), frame(2, 1), frame(3, 2)];
        assert!(matches!(check_safety(&frames), Err(SafetyError::Cycle(_))));
    }

    #[test]
    fn long_valid_chain() {
        let mut frames = vec![frame(1, 0)];
        for i in 1..10u8 {
            frames.push(frame(i + 1, i));
        }
        assert!(check_safety(&frames).is_ok());
    }

    #[test]
    fn complex_tree_is_fork() {
        let frames = vec![
            frame(1, 0),
            frame(2, 1),
            frame(3, 1),
            frame(4, 3),
            frame(5, 3),
        ];
        assert!(matches!(check_safety(&frames), Err(SafetyError::Fork(_))));
    }

    #[test]
    fn duplicate_frame_ids_with_different_parents() {
        // frame 2 appears with parent 1 and parent 3 → some error (DuplicateFrame).
        let frames = vec![frame(1, 0), frame(2, 1), frame(2, 3), frame(3, 1)];
        assert!(check_safety(&frames).is_err());
    }

    #[test]
    fn disjoint_with_circular_sequence() {
        // chain 1->2 (leaf 2); isolated cycle 3->5->4->3 (no leaf)
        let frames = vec![
            frame(1, 0),
            frame(2, 1),
            frame(3, 5),
            frame(4, 3),
            frame(5, 4),
        ];
        let err = check_safety(&frames);
        assert!(matches!(
            err,
            Err(SafetyError::Fork(_)) | Err(SafetyError::Cycle(_))
        ));
    }
}
