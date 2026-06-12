use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use num_bigint::BigInt;
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::fork_choice::{self, Branch, Frame, Params, SCALE};

const MAX_TREE_DEPTH: u64 = 10;
const PENDING_FRAME_MAX_AGE_MS: i64 = 90 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeReelEventType {
    NewHead,
    ForkDetected,
    EquivocationDetected,
}

#[derive(Debug, Clone)]
pub struct GlobalEvent {
    pub event_type: TimeReelEventType,
    pub frame: Arc<quil_types::proto::global::GlobalFrame>,
    pub old_head: Option<Arc<quil_types::proto::global::GlobalFrame>>,
    pub message: String,
}

struct FrameNode {
    frame: Arc<quil_types::proto::global::GlobalFrame>,
    parent: Option<NodeId>,
    children: HashSet<NodeId>,
    depth: u64,
}

type NodeId = String;

struct PendingFrame {
    frame: Arc<quil_types::proto::global::GlobalFrame>,
    timestamp: i64,
}

struct Inner {
    root: Option<NodeId>,
    head: Option<NodeId>,
    nodes: HashMap<NodeId, FrameNode>,
    frames_by_number: HashMap<u64, Vec<NodeId>>,
    pending_frames: HashMap<String, Vec<PendingFrame>>,
    equivocators: HashMap<u64, HashSet<usize>>,
    fork_choice_params: Params,
    genesis_frame_number: u64,
}

pub struct GlobalTimeReel {
    inner: RwLock<Inner>,
    event_tx: mpsc::UnboundedSender<GlobalEvent>,
    event_rx: RwLock<Option<mpsc::UnboundedReceiver<GlobalEvent>>>,
}

impl GlobalTimeReel {
    pub fn new(network: u8) -> Self {
        let genesis_frame_number = if network == 0 { 244_200 } else { 0 };
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        Self {
            inner: RwLock::new(Inner {
                root: None,
                head: None,
                nodes: HashMap::new(),
                frames_by_number: HashMap::new(),
                pending_frames: HashMap::new(),
                equivocators: HashMap::new(),
                fork_choice_params: Params::default_params(),
                genesis_frame_number,
            }),
            event_tx,
            event_rx: RwLock::new(Some(event_rx)),
        }
    }

    pub fn take_event_rx(&self) -> Option<mpsc::UnboundedReceiver<GlobalEvent>> {
        self.event_rx.write().unwrap().take()
    }

    pub fn get_head(&self) -> Option<Arc<quil_types::proto::global::GlobalFrame>> {
        let inner = self.inner.read().unwrap();
        inner.head.as_ref().and_then(|id| inner.nodes.get(id).map(|n| n.frame.clone()))
    }

    pub fn get_head_frame_number(&self) -> u64 {
        let inner = self.inner.read().unwrap();
        inner.head.as_ref()
            .and_then(|id| inner.nodes.get(id))
            .and_then(|n| n.frame.header.as_ref())
            .map(|h| h.frame_number)
            .unwrap_or(0)
    }

    /// Structural sizes for memory diagnostics. Returned tuple:
    /// `(nodes, pending_frames_total, equivocator_frame_buckets)`.
    /// `pending_frames_total` sums across all parent-selector
    /// buckets so it reflects total cached orphan frames, not
    /// distinct selectors.
    pub fn sizes(&self) -> (usize, usize, usize) {
        let inner = self.inner.read().unwrap();
        let pending_total: usize = inner.pending_frames.values().map(|v| v.len()).sum();
        (inner.nodes.len(), pending_total, inner.equivocators.len())
    }

    pub fn insert(
        &self,
        frame: Arc<quil_types::proto::global::GlobalFrame>,
    ) -> Result<(), String> {
        let mut inner = self.inner.write().unwrap();
        self.insert_inner(&mut inner, frame)
    }

    fn insert_inner(
        &self,
        inner: &mut Inner,
        frame: Arc<quil_types::proto::global::GlobalFrame>,
    ) -> Result<(), String> {
        let (frame_id, frame_number, frame_timestamp, parent_selector_owned) = {
            let header = frame.header.as_ref().ok_or("frame has no header")?;
            (
                compute_frame_id(header),
                header.frame_number,
                header.timestamp,
                header.parent_selector.clone(),
            )
        };

        if inner.nodes.contains_key(&frame_id) {
            return Ok(());
        }

        // Equivocation detection
        if let Some(nodes_at_height) = inner.frames_by_number.get(&frame_number) {
            for existing_id in nodes_at_height.clone() {
                if let Some(existing) = inner.nodes.get(&existing_id) {
                    let existing_header = existing.frame.header.as_ref();
                    if let Some(eh) = existing_header {
                        if !is_equal_frame(eh, frame.header.as_ref().unwrap())
                            && has_overlapping_bits(&existing.frame, &frame)
                        {
                            let equivocators = inner.equivocators
                                .entry(frame_number)
                                .or_default();
                            extract_overlapping_bits(
                                &existing.frame,
                                &frame,
                                equivocators,
                            );
                            let _ = self.event_tx.send(GlobalEvent {
                                event_type: TimeReelEventType::EquivocationDetected,
                                frame: frame.clone(),
                                old_head: None,
                                message: format!(
                                    "equivocation at frame {}",
                                    frame_number,
                                ),
                            });
                        }
                    }
                }
            }
        }

        // Genesis handling
        if frame_number == inner.genesis_frame_number {
            return self.insert_genesis(inner, frame, &frame_id);
        }

        // Non-archive pseudo-root: accept first frame if tree is empty
        if inner.root.is_none() && inner.nodes.is_empty() {
            info!(
                frame = frame_number,
                "accepting first frame as pseudo-root"
            );
            return self.insert_genesis(inner, frame, &frame_id);
        }

        // Find parent
        let parent_id = find_node_by_selector(inner, &parent_selector_owned);

        if let Some(pid) = parent_id {
            // Verify parent selector matches
            if let Some(parent_node) = inner.nodes.get(&pid) {
                let expected = compute_poseidon_selector(
                    &parent_node.frame.header.as_ref().unwrap().output,
                );
                if expected != parent_selector_owned {
                    return Err("parent selector mismatch".into());
                }
                let parent_depth = parent_node.depth;

                let new_node = FrameNode {
                    frame: frame.clone(),
                    parent: Some(pid.clone()),
                    children: HashSet::new(),
                    depth: parent_depth + 1,
                };

                inner.nodes.insert(frame_id.clone(), new_node);
                inner.frames_by_number
                    .entry(frame_number)
                    .or_default()
                    .push(frame_id.clone());
                if let Some(p) = inner.nodes.get_mut(&pid) {
                    p.children.insert(frame_id.clone());
                }
            }

            self.process_pending(inner, &frame_id);
            self.evaluate_fork_choice(inner, &frame_id);
            self.prune_old_frames(inner);
            self.prune_old_pending(inner);
            return Ok(());
        }

        // Parent not found — check if frame is ahead of head (non-archive orphan)
        let head_frame_num = inner.head.as_ref()
            .and_then(|id| inner.nodes.get(id))
            .and_then(|n| n.frame.header.as_ref())
            .map(|h| h.frame_number)
            .unwrap_or(0);

        if inner.head.is_some() && frame_number > head_frame_num {
            let selector_key = hex::encode(&parent_selector_owned);
            inner.pending_frames
                .entry(selector_key)
                .or_default()
                .push(PendingFrame {
                    frame: frame.clone(),
                    timestamp: frame_timestamp,
                });

            let new_node = FrameNode {
                frame: frame.clone(),
                parent: None,
                children: HashSet::new(),
                depth: 1,
            };
            inner.nodes.insert(frame_id.clone(), new_node);
            inner.frames_by_number
                .entry(frame_number)
                .or_default()
                .push(frame_id.clone());

            self.evaluate_fork_choice(inner, &frame_id);
            return Ok(());
        }

        // Parent not found and not ahead — buffer as pending
        let selector_key = hex::encode(&parent_selector_owned);
        inner.pending_frames
            .entry(selector_key)
            .or_default()
            .push(PendingFrame {
                frame,
                timestamp: frame_timestamp,
            });

        Ok(())
    }

    fn insert_genesis(
        &self,
        inner: &mut Inner,
        frame: Arc<quil_types::proto::global::GlobalFrame>,
        frame_id: &str,
    ) -> Result<(), String> {
        if inner.root.is_some() {
            return Err("genesis/root already exists".into());
        }

        let node = FrameNode {
            frame: frame.clone(),
            parent: None,
            children: HashSet::new(),
            depth: 0,
        };
        let frame_number = frame.header.as_ref().map(|h| h.frame_number).unwrap_or(0);

        inner.nodes.insert(frame_id.to_string(), node);
        inner.frames_by_number
            .entry(frame_number)
            .or_default()
            .push(frame_id.to_string());
        inner.root = Some(frame_id.to_string());
        inner.head = Some(frame_id.to_string());

        let _ = self.event_tx.send(GlobalEvent {
            event_type: TimeReelEventType::NewHead,
            frame: frame.clone(),
            old_head: None,
            message: String::new(),
        });

        self.process_pending(inner, frame_id);
        self.prune_old_frames(inner);

        Ok(())
    }

    fn process_pending(&self, inner: &mut Inner, parent_frame_id: &str) {
        let parent_output = match inner.nodes.get(parent_frame_id) {
            Some(n) => n.frame.header.as_ref().map(|h| h.output.clone()),
            None => return,
        };
        let output = match parent_output {
            Some(o) => o,
            None => return,
        };

        let selector = compute_poseidon_selector(&output);
        let selector_key = hex::encode(&selector);

        let pending_list = match inner.pending_frames.remove(&selector_key) {
            Some(list) => list,
            None => return,
        };

        let parent_depth = inner.nodes.get(parent_frame_id)
            .map(|n| n.depth)
            .unwrap_or(0);

        for pending in pending_list {
            let pending_header = match pending.frame.header.as_ref() {
                Some(h) => h,
                None => continue,
            };
            let pending_id = compute_frame_id(pending_header);

            if let Some(existing) = inner.nodes.get_mut(&pending_id) {
                // Re-parent orphan
                if existing.parent.is_none() {
                    existing.parent = Some(parent_frame_id.to_string());
                    existing.depth = parent_depth + 1;
                    if let Some(parent) = inner.nodes.get_mut(parent_frame_id) {
                        parent.children.insert(pending_id.clone());
                    }
                    self.process_pending(inner, &pending_id);
                    self.evaluate_fork_choice(inner, &pending_id);
                }
                continue;
            }

            let new_node = FrameNode {
                frame: pending.frame.clone(),
                parent: Some(parent_frame_id.to_string()),
                children: HashSet::new(),
                depth: parent_depth + 1,
            };

            let frame_number = pending_header.frame_number;
            inner.nodes.insert(pending_id.clone(), new_node);
            inner.frames_by_number
                .entry(frame_number)
                .or_default()
                .push(pending_id.clone());
            if let Some(parent) = inner.nodes.get_mut(parent_frame_id) {
                parent.children.insert(pending_id.clone());
            }

            self.process_pending(inner, &pending_id);
            self.evaluate_fork_choice(inner, &pending_id);
        }
    }

    fn evaluate_fork_choice(&self, inner: &mut Inner, new_node_id: &str) {
        let new_depth = inner.nodes.get(new_node_id).map(|n| n.depth).unwrap_or(0);
        let new_frame_num = inner.nodes.get(new_node_id)
            .and_then(|n| n.frame.header.as_ref())
            .map(|h| h.frame_number)
            .unwrap_or(0);

        // Jump-ahead: no head, or new node far ahead
        if inner.head.is_none() {
            inner.head = Some(new_node_id.to_string());
            let frame = inner.nodes.get(new_node_id).unwrap().frame.clone();
            let _ = self.event_tx.send(GlobalEvent {
                event_type: TimeReelEventType::NewHead,
                frame,
                old_head: None,
                message: String::new(),
            });
            return;
        }

        let head_id = inner.head.as_ref().unwrap().clone();
        let head_frame_num = inner.nodes.get(&head_id)
            .and_then(|n| n.frame.header.as_ref())
            .map(|h| h.frame_number)
            .unwrap_or(0);
        let head_depth = inner.nodes.get(&head_id).map(|n| n.depth).unwrap_or(0);

        if new_frame_num > head_frame_num
            && new_frame_num - head_frame_num > MAX_TREE_DEPTH
        {
            let old_head_frame = inner.nodes.get(&head_id).map(|n| n.frame.clone());
            inner.head = Some(new_node_id.to_string());
            let frame = inner.nodes.get(new_node_id).unwrap().frame.clone();
            self.send_head_event(inner, new_node_id, old_head_frame);
            return;
        }

        // Find leaf nodes in same component as head
        let leaves = find_leaf_nodes(inner);

        if leaves.len() <= 1 {
            if new_depth > head_depth {
                let old_head_frame = inner.nodes.get(&head_id).map(|n| n.frame.clone());
                inner.head = Some(new_node_id.to_string());
                self.send_head_event(inner, new_node_id, old_head_frame);
            }
            return;
        }

        // Find max depth among leaves
        let max_depth = leaves.iter()
            .filter_map(|id| inner.nodes.get(id).map(|n| n.depth))
            .max()
            .unwrap_or(0);

        let competing: Vec<String> = leaves.into_iter()
            .filter(|id| inner.nodes.get(id).map(|n| n.depth).unwrap_or(0) == max_depth)
            .collect();

        if competing.len() == 1 {
            let chosen_id = &competing[0];
            if *chosen_id != head_id {
                let old_head_frame = inner.nodes.get(&head_id).map(|n| n.frame.clone());
                inner.head = Some(chosen_id.clone());
                self.send_head_event(inner, chosen_id, old_head_frame);
            }
            return;
        }

        // Build branches for fork choice
        let branches: Vec<Branch> = competing.iter()
            .map(|id| node_to_branch(inner, id))
            .collect();

        let prev_choice = competing.iter()
            .position(|id| *id == head_id)
            .unwrap_or(0);

        let chosen_index = fork_choice::fork_choice(
            &branches,
            &inner.fork_choice_params,
            prev_choice,
        );
        let chosen_id = competing[chosen_index].clone();

        if chosen_id != head_id {
            let old_head_frame = inner.nodes.get(&head_id).map(|n| n.frame.clone());
            inner.head = Some(chosen_id.clone());
            self.send_head_event(inner, &chosen_id, old_head_frame);
        }
    }

    fn send_head_event(
        &self,
        inner: &Inner,
        new_head_id: &str,
        old_head_frame: Option<Arc<quil_types::proto::global::GlobalFrame>>,
    ) {
        let frame = match inner.nodes.get(new_head_id) {
            Some(n) => n.frame.clone(),
            None => return,
        };

        let is_fork = if let Some(ref old_frame) = old_head_frame {
            let old_id = old_frame.header.as_ref()
                .map(|h| compute_frame_id(h))
                .unwrap_or_default();
            !is_ancestor(inner, &old_id, new_head_id)
        } else {
            false
        };

        let event_type = if is_fork {
            info!(
                old = old_head_frame.as_ref().and_then(|f| f.header.as_ref()).map(|h| h.frame_number).unwrap_or(0),
                new = frame.header.as_ref().map(|h| h.frame_number).unwrap_or(0),
                "reorganization detected"
            );
            TimeReelEventType::ForkDetected
        } else {
            TimeReelEventType::NewHead
        };

        let _ = self.event_tx.send(GlobalEvent {
            event_type,
            frame,
            old_head: old_head_frame,
            message: String::new(),
        });
    }

    fn prune_old_frames(&self, inner: &mut Inner) {
        let head_depth = match inner.head.as_ref().and_then(|id| inner.nodes.get(id)) {
            Some(n) => n.depth,
            None => return,
        };

        if head_depth < MAX_TREE_DEPTH {
            return;
        }

        let min_depth_to_keep = head_depth - MAX_TREE_DEPTH + 1;

        let to_remove: Vec<String> = inner.nodes.iter()
            .filter(|(_, n)| n.depth < min_depth_to_keep)
            .map(|(id, _)| id.clone())
            .collect();

        if to_remove.is_empty() {
            return;
        }

        for id in &to_remove {
            if let Some(node) = inner.nodes.remove(id) {
                let frame_num = node.frame.header.as_ref()
                    .map(|h| h.frame_number)
                    .unwrap_or(0);
                if let Some(list) = inner.frames_by_number.get_mut(&frame_num) {
                    list.retain(|nid| nid != id);
                    if list.is_empty() {
                        inner.frames_by_number.remove(&frame_num);
                    }
                }
                // Clear parent refs from surviving children
                for child_id in &node.children {
                    if let Some(child) = inner.nodes.get_mut(child_id) {
                        child.parent = None;
                    }
                }
                inner.equivocators.remove(&frame_num);
            }
        }

        // Update root to a surviving node at min_depth_to_keep
        let new_root = inner.nodes.iter()
            .filter(|(_, n)| n.depth == min_depth_to_keep)
            .min_by_key(|(_, n)| {
                n.frame.header.as_ref().map(|h| h.frame_number).unwrap_or(u64::MAX)
            })
            .map(|(id, _)| id.clone());
        if let Some(nr) = new_root {
            inner.root = Some(nr);
        }

        debug!(pruned = to_remove.len(), "pruned old frame nodes");
    }

    fn prune_old_pending(&self, inner: &mut Inner) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let cutoff = now_ms - PENDING_FRAME_MAX_AGE_MS;

        inner.pending_frames.retain(|_, list| {
            list.retain(|p| p.timestamp >= cutoff);
            !list.is_empty()
        });
    }
}

fn compute_frame_id(header: &quil_types::proto::global::GlobalFrameHeader) -> String {
    let data = format!(
        "{}:{}:{}:{}",
        header.frame_number,
        header.timestamp,
        hex::encode(&header.output),
        hex::encode(&header.parent_selector),
    );
    let hash = quil_crypto::poseidon::hash_bytes_to_32(data.as_bytes())
        .unwrap_or([0u8; 32]);
    hex::encode(hash)
}

fn compute_poseidon_selector(output: &[u8]) -> Vec<u8> {
    quil_crypto::poseidon::hash_bytes_to_32(output)
        .map(|h| h.to_vec())
        .unwrap_or_else(|_| vec![0u8; 32])
}

fn find_node_by_selector(inner: &Inner, selector: &[u8]) -> Option<NodeId> {
    for (id, node) in &inner.nodes {
        if let Some(h) = node.frame.header.as_ref() {
            let expected = compute_poseidon_selector(&h.output);
            if expected == selector {
                return Some(id.clone());
            }
        }
    }
    None
}

fn is_equal_frame(
    a: &quil_types::proto::global::GlobalFrameHeader,
    b: &quil_types::proto::global::GlobalFrameHeader,
) -> bool {
    a.frame_number == b.frame_number
        && a.timestamp == b.timestamp
        && a.difficulty == b.difficulty
        && a.output == b.output
        && a.parent_selector == b.parent_selector
}

fn has_overlapping_bits(
    a: &quil_types::proto::global::GlobalFrame,
    b: &quil_types::proto::global::GlobalFrame,
) -> bool {
    let a_mask = a.header.as_ref()
        .and_then(|h| h.public_key_signature_bls48581.as_ref())
        .map(|sig| sig.bitmask.as_slice())
        .unwrap_or(&[]);
    let b_mask = b.header.as_ref()
        .and_then(|h| h.public_key_signature_bls48581.as_ref())
        .map(|sig| sig.bitmask.as_slice())
        .unwrap_or(&[]);

    let max_len = a_mask.len().max(b_mask.len());
    for i in 0..max_len {
        let ab = if i < a_mask.len() { a_mask[i] } else { 0 };
        let bb = if i < b_mask.len() { b_mask[i] } else { 0 };
        if ab & bb != 0 {
            return true;
        }
    }
    false
}

fn extract_overlapping_bits(
    a: &quil_types::proto::global::GlobalFrame,
    b: &quil_types::proto::global::GlobalFrame,
    equivocators: &mut HashSet<usize>,
) {
    let a_mask = a.header.as_ref()
        .and_then(|h| h.public_key_signature_bls48581.as_ref())
        .map(|sig| sig.bitmask.as_slice())
        .unwrap_or(&[]);
    let b_mask = b.header.as_ref()
        .and_then(|h| h.public_key_signature_bls48581.as_ref())
        .map(|sig| sig.bitmask.as_slice())
        .unwrap_or(&[]);

    let max_len = a_mask.len().max(b_mask.len());
    for i in 0..max_len {
        let ab = if i < a_mask.len() { a_mask[i] } else { 0 };
        let bb = if i < b_mask.len() { b_mask[i] } else { 0 };
        let overlapping = ab & bb;
        for bit in 0..8 {
            if overlapping & (1 << bit) != 0 {
                equivocators.insert(i * 8 + bit);
            }
        }
    }
}

fn find_leaf_nodes(inner: &Inner) -> Vec<NodeId> {
    let head_id = match &inner.head {
        Some(id) => id.clone(),
        None => {
            return inner.nodes.iter()
                .filter(|(_, n)| n.children.is_empty())
                .map(|(id, _)| id.clone())
                .collect();
        }
    };

    let head_root = find_root(inner, &head_id);

    inner.nodes.iter()
        .filter(|(_, n)| n.children.is_empty())
        .filter(|(id, _)| find_root(inner, id) == head_root)
        .map(|(id, _)| id.clone())
        .collect()
}

fn find_root(inner: &Inner, id: &str) -> Option<NodeId> {
    let mut cur = id.to_string();
    loop {
        match inner.nodes.get(&cur) {
            Some(n) => match &n.parent {
                Some(pid) => cur = pid.clone(),
                None => return Some(cur),
            },
            None => return None,
        }
    }
}

fn is_ancestor(inner: &Inner, ancestor_id: &str, descendant_id: &str) -> bool {
    let mut cur = descendant_id.to_string();
    loop {
        if cur == ancestor_id {
            return true;
        }
        match inner.nodes.get(&cur) {
            Some(n) => match &n.parent {
                Some(pid) => cur = pid.clone(),
                None => return false,
            },
            None => return false,
        }
    }
}

fn node_to_branch(inner: &Inner, leaf_id: &str) -> Branch {
    let mut lineage = Vec::new();
    let mut cur = leaf_id.to_string();
    let mut depth = 0;

    while depth < MAX_TREE_DEPTH as usize {
        match inner.nodes.get(&cur) {
            Some(n) => {
                lineage.push(cur.clone());
                match &n.parent {
                    Some(pid) => cur = pid.clone(),
                    None => break,
                }
                depth += 1;
            }
            None => break,
        }
    }

    lineage.reverse();

    let frames: Vec<Frame> = lineage.iter()
        .filter_map(|id| inner.nodes.get(id))
        .map(|n| {
            let header = n.frame.header.as_ref();
            let mut prover_addr = header
                .map(|h| h.output.clone())
                .unwrap_or_default();
            prover_addr.truncate(32);

            let seniority = compute_frame_seniority(inner, &n.frame);

            Frame {
                distance: BigInt::from(0),
                seniority,
                prover_address: prover_addr,
            }
        })
        .collect();

    Branch { frames }
}

fn compute_frame_seniority(
    inner: &Inner,
    frame: &quil_types::proto::global::GlobalFrame,
) -> u64 {
    let header = match frame.header.as_ref() {
        Some(h) => h,
        None => return SCALE / 64,
    };

    let bitmask = match header.public_key_signature_bls48581.as_ref() {
        Some(sig) => &sig.bitmask,
        None => return SCALE / 64,
    };

    let equivocators_at_height = inner.equivocators.get(&header.frame_number);

    let mut bit_count = 0u64;
    for (i, &byte) in bitmask.iter().enumerate() {
        for bit in 0..8 {
            if byte & (1 << bit) != 0 {
                let bit_pos = i * 8 + bit;
                let is_equivocator = equivocators_at_height
                    .map(|eq| eq.contains(&bit_pos))
                    .unwrap_or(false);
                if !is_equivocator {
                    bit_count += 1;
                }
            }
        }
    }

    if bit_count == 0 {
        return 0;
    }

    let max_signers = 64u64;
    (SCALE / max_signers) * bit_count
}

impl Default for GlobalTimeReel {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader};

    fn make_frame(
        frame_number: u64,
        timestamp: i64,
        output: &[u8],
        parent_selector: &[u8],
    ) -> Arc<GlobalFrame> {
        Arc::new(GlobalFrame {
            header: Some(GlobalFrameHeader {
                frame_number,
                timestamp,
                output: output.to_vec(),
                parent_selector: parent_selector.to_vec(),
                difficulty: 80_000,
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    fn genesis_frame() -> Arc<GlobalFrame> {
        make_frame(0, 1000, &[0xAA; 32], &[0x00; 32])
    }

    fn child_of(parent: &GlobalFrame, frame_number: u64) -> Arc<GlobalFrame> {
        let parent_output = &parent.header.as_ref().unwrap().output;
        let selector = compute_poseidon_selector(parent_output);
        let mut output = vec![0u8; 32];
        output[0] = (frame_number & 0xFF) as u8;
        output[1] = ((frame_number >> 8) & 0xFF) as u8;
        make_frame(frame_number, 1000 + frame_number as i64 * 10_000, &output, &selector)
    }

    #[test]
    fn insert_genesis_sets_head() {
        let reel = GlobalTimeReel::new(1);
        let g = genesis_frame();
        reel.insert(g.clone()).unwrap();
        assert_eq!(reel.get_head_frame_number(), 0);
    }

    #[test]
    fn insert_chain_advances_head() {
        let reel = GlobalTimeReel::new(1);
        let g = genesis_frame();
        reel.insert(g.clone()).unwrap();

        let f1 = child_of(&g, 1);
        reel.insert(f1.clone()).unwrap();
        assert_eq!(reel.get_head_frame_number(), 1);

        let f2 = child_of(&f1, 2);
        reel.insert(f2.clone()).unwrap();
        assert_eq!(reel.get_head_frame_number(), 2);
    }

    #[test]
    fn duplicate_insert_is_idempotent() {
        let reel = GlobalTimeReel::new(1);
        let g = genesis_frame();
        reel.insert(g.clone()).unwrap();
        reel.insert(g.clone()).unwrap();
        assert_eq!(reel.get_head_frame_number(), 0);
    }

    #[test]
    fn pending_frame_connects_when_parent_arrives() {
        let reel = GlobalTimeReel::new(1);
        let g = genesis_frame();
        let f1 = child_of(&g, 1);

        // Insert child before parent — goes to pending
        reel.insert(f1.clone()).unwrap();
        // Head should be the orphan (accepted as pseudo-root since tree was empty)
        // Actually the first frame becomes pseudo-root, so head = f1
        // Let's test with genesis first
        let reel2 = GlobalTimeReel::new(1);
        let g2 = genesis_frame();
        reel2.insert(g2.clone()).unwrap();

        let f1_2 = child_of(&g2, 1);
        let f2_2 = child_of(&f1_2, 2);

        // Insert f2 before f1 — f2 goes to pending
        reel2.insert(f2_2.clone()).unwrap();
        assert_eq!(reel2.get_head_frame_number(), 2); // orphan accepted ahead of head

        // Now insert f1 — should connect f2
        reel2.insert(f1_2.clone()).unwrap();
        // Head should still be 2 (f2 is deeper)
        assert_eq!(reel2.get_head_frame_number(), 2);
    }

    #[test]
    fn events_emitted_on_head_change() {
        let reel = GlobalTimeReel::new(1);
        let mut rx = reel.take_event_rx().unwrap();

        let g = genesis_frame();
        reel.insert(g.clone()).unwrap();

        let event = rx.try_recv().unwrap();
        assert_eq!(event.event_type, TimeReelEventType::NewHead);
        assert_eq!(
            event.frame.header.as_ref().unwrap().frame_number,
            0,
        );
    }

    #[test]
    fn mainnet_genesis_frame_number() {
        let reel = GlobalTimeReel::new(0);
        let inner = reel.inner.read().unwrap();
        assert_eq!(inner.genesis_frame_number, 244_200);
    }
}
