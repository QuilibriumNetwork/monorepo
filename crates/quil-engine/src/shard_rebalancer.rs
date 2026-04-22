//! Shard split / merge proposal emitter.
//!
//! Ports the Go `coverage_monitor.go` → `proposeShardSplit` /
//! `emitBulkMergeEvent` flow. Every new global frame triggers a
//! coverage sweep; shards above the split threshold produce a
//! `ShardSplit` message, shards below the merge threshold produce a
//! `ShardMerge`. Only the prover who produced the triggering frame
//! emits (leader election = frame production).
//!
//! Per-shard cooldown of 360 frames between proposals matches
//! `shardActionCooldownFrames` at `coverage_monitor.go:950`.

use std::collections::HashMap;
use std::sync::Mutex;

use quil_execution::global_intrinsic::addressed_signature::AddressedSignature;
use quil_execution::global_intrinsic::prover_ops::{ShardMerge, ShardSplit};
use quil_types::crypto::Signer;
use quil_types::error::{QuilError, Result};

use crate::coverage::ShardAction;

/// Cooldown between split/merge proposals for the same shard —
/// matches `shardActionCooldownFrames` in Go.
pub const SHARD_ACTION_COOLDOWN_FRAMES: u64 = 360;

/// Threshold breakpoints (hardcoded in Go's coverage_monitor.go).
pub const SPLIT_FACTOR_2: u64 = 32;
pub const SPLIT_FACTOR_4: u64 = 48;
pub const SPLIT_FACTOR_8: u64 = 64;

/// Emitted proposal ready to publish on `GLOBAL_PROVER` bitmask.
#[derive(Debug, Clone)]
pub struct ProposalBytes {
    pub kind: ProposalKind,
    pub shard_filter: Vec<u8>,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalKind {
    Split,
    Merge,
}

/// Tracks the last-proposal frame per-shard so we don't spam proposals.
pub struct ShardRebalancer {
    last_action_frame: Mutex<HashMap<Vec<u8>, u64>>,
    local_prover_address: Vec<u8>,
}

impl ShardRebalancer {
    pub fn new(local_prover_address: Vec<u8>) -> Self {
        Self {
            last_action_frame: Mutex::new(HashMap::new()),
            local_prover_address,
        }
    }

    /// Evaluate `actions` against cooldown + leader gate and produce
    /// a set of canonical-bytes proposals. `frame_prover` is the
    /// producer of the triggering frame — only that node emits.
    ///
    /// `merge_candidates` pairs shard filters with their sibling
    /// shard addresses; merges need both halves. The caller supplies
    /// the pairing from the coverage monitor (it already computes
    /// siblings via `compute_sibling_filter`).
    pub fn propose(
        &self,
        frame_number: u64,
        frame_prover: &[u8],
        actions: &[ShardAction],
        signer: &dyn Signer,
    ) -> Result<Vec<ProposalBytes>> {
        // Leader gate — only the frame producer emits.
        if frame_prover != self.local_prover_address.as_slice() {
            return Ok(Vec::new());
        }

        let mut out = Vec::new();
        let mut last = self.last_action_frame.lock().unwrap();

        for action in actions {
            match action {
                ShardAction::Split {
                    filter,
                    active_count,
                    ..
                } => {
                    if !cooldown_ok(&*last, filter, frame_number) {
                        continue;
                    }
                    let factor = split_factor(*active_count);
                    let proposed = compute_proposed_shards(filter, factor);
                    let mut msg = ShardSplit {
                        shard_address: filter.clone(),
                        proposed_shards: proposed,
                        frame_number,
                        public_key_signature_bls48581: None,
                    };
                    // Sign over the unsigned canonical bytes — matches
                    // the intrinsic's `Prove` method (global intrinsic
                    // signatures are BLS48581 over the full message).
                    let bytes_to_sign = msg.to_canonical_bytes()?;
                    let signature = signer.sign(&bytes_to_sign).map_err(|e| {
                        QuilError::Internal(format!("ShardSplit sign failed: {}", e))
                    })?;
                    msg.public_key_signature_bls48581 = Some(AddressedSignature {
                        signature,
                        address: self.local_prover_address.clone(),
                    });
                    let final_bytes = msg.to_canonical_bytes()?;
                    last.insert(filter.clone(), frame_number);
                    out.push(ProposalBytes {
                        kind: ProposalKind::Split,
                        shard_filter: filter.clone(),
                        bytes: final_bytes,
                    });
                }
                ShardAction::MergeCandidate { filter, .. } => {
                    if !cooldown_ok(&*last, filter, frame_number) {
                        continue;
                    }
                    let Some(sibling) = crate::coverage::compute_sibling_filter(filter) else {
                        continue;
                    };
                    // Parent address: strip the common byte that
                    // differs between filter and sibling. Rule here
                    // mirrors Go's `ParentAddress = first 32 bytes of
                    // first child shard` (i.e. the app address prefix
                    // without its suffix byte).
                    let parent_address = if filter.len() > 32 {
                        filter[..32].to_vec()
                    } else {
                        filter.clone()
                    };
                    let mut merge = ShardMerge {
                        shard_addresses: vec![filter.clone(), sibling.clone()],
                        parent_address,
                        frame_number,
                        public_key_signature_bls48581: None,
                    };
                    let bytes_to_sign = merge.to_canonical_bytes()?;
                    let signature = signer.sign(&bytes_to_sign).map_err(|e| {
                        QuilError::Internal(format!("ShardMerge sign failed: {}", e))
                    })?;
                    merge.public_key_signature_bls48581 = Some(AddressedSignature {
                        signature,
                        address: self.local_prover_address.clone(),
                    });
                    let final_bytes = merge.to_canonical_bytes()?;
                    // Record both filter and sibling as recently
                    // acted-on so we don't also emit from the other
                    // half.
                    last.insert(filter.clone(), frame_number);
                    last.insert(sibling, frame_number);
                    out.push(ProposalBytes {
                        kind: ProposalKind::Merge,
                        shard_filter: filter.clone(),
                        bytes: final_bytes,
                    });
                }
            }
        }
        Ok(out)
    }

    /// Test-only: clear cooldown state.
    #[cfg(test)]
    pub fn reset(&self) {
        self.last_action_frame.lock().unwrap().clear();
    }
}

fn cooldown_ok(last: &HashMap<Vec<u8>, u64>, filter: &[u8], frame: u64) -> bool {
    match last.get(filter) {
        None => true,
        Some(&prev) => frame >= prev.saturating_add(SHARD_ACTION_COOLDOWN_FRAMES),
    }
}

/// Go's `proposeShardSplit` splits into 2 / 4 / 8 shards based on
/// population, appending a discriminator byte to the existing
/// filter. We preserve that exact prefix/suffix layout so receivers
/// can route against either child shard correctly.
pub fn split_factor(active_count: u64) -> u8 {
    if active_count > SPLIT_FACTOR_8 {
        8
    } else if active_count > SPLIT_FACTOR_4 {
        4
    } else {
        2
    }
}

pub fn compute_proposed_shards(filter: &[u8], factor: u8) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(factor as usize);
    match factor {
        2 => {
            for suffix in [0x00u8, 0x80u8] {
                let mut s = filter.to_vec();
                s.push(suffix);
                out.push(s);
            }
        }
        4 => {
            for suffix in [0x00u8, 0x40, 0x80, 0xC0] {
                let mut s = filter.to_vec();
                s.push(suffix);
                out.push(s);
            }
        }
        8 => {
            // 2-byte suffix encoding octal bucket (Go uses
            // big-endian 2-byte markers 0x0000, 0x2000, ..., 0xE000).
            for hi in [0x00u8, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0] {
                let mut s = filter.to_vec();
                s.push(hi);
                s.push(0x00);
                out.push(s);
            }
        }
        _ => {
            // Fallback to binary split.
            for suffix in [0x00u8, 0x80u8] {
                let mut s = filter.to_vec();
                s.push(suffix);
                out.push(s);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sig_bytes() -> Vec<u8> {
        vec![0xAA; 74]
    }

    static DUMMY_PUB: [u8; 585] = [0xBB; 585];
    static DUMMY_PRIV: [u8; 1] = [0u8];
    struct DummySigner;
    impl Signer for DummySigner {
        fn key_type(&self) -> quil_types::crypto::KeyType {
            quil_types::crypto::KeyType::Bls48581G1
        }
        fn public_key(&self) -> &[u8] {
            &DUMMY_PUB
        }
        fn private_key(&self) -> &[u8] {
            &DUMMY_PRIV
        }
        fn sign(&self, _msg: &[u8]) -> quil_types::error::Result<Vec<u8>> {
            Ok(make_sig_bytes())
        }
        fn sign_with_domain(&self, _msg: &[u8], _domain: &[u8]) -> quil_types::error::Result<Vec<u8>> {
            Ok(make_sig_bytes())
        }
    }

    #[test]
    fn leader_gate_filters_out_non_producers() {
        let reb = ShardRebalancer::new(vec![0x11; 32]);
        let actions = vec![ShardAction::Split {
            filter: vec![0x22; 32],
            active_count: 40,
            frame_number: 100,
        }];
        let signer = DummySigner;
        let out = reb
            .propose(100, &[0x99; 32], &actions, &signer)
            .unwrap();
        assert!(out.is_empty(), "non-leader must not emit");
    }

    #[test]
    fn leader_emits_split_once_then_honors_cooldown() {
        let reb = ShardRebalancer::new(vec![0x11; 32]);
        let actions = vec![ShardAction::Split {
            filter: vec![0x22; 32],
            active_count: 40,
            frame_number: 100,
        }];
        let signer = DummySigner;
        let out = reb
            .propose(100, &[0x11; 32], &actions, &signer)
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, ProposalKind::Split);

        // Second call within cooldown: nothing emitted.
        let out2 = reb
            .propose(200, &[0x11; 32], &actions, &signer)
            .unwrap();
        assert!(out2.is_empty(), "cooldown must suppress");

        // After cooldown passes, emit again.
        let out3 = reb
            .propose(100 + SHARD_ACTION_COOLDOWN_FRAMES, &[0x11; 32], &actions, &signer)
            .unwrap();
        assert_eq!(out3.len(), 1, "cooldown expired");
    }

    #[test]
    fn split_factor_thresholds() {
        assert_eq!(split_factor(33), 2);
        assert_eq!(split_factor(48), 2);
        assert_eq!(split_factor(49), 4);
        assert_eq!(split_factor(64), 4);
        assert_eq!(split_factor(65), 8);
    }

    #[test]
    fn proposed_shards_shape() {
        let two = compute_proposed_shards(&[0x11; 32], 2);
        assert_eq!(two.len(), 2);
        assert_eq!(two[0].len(), 33);
        assert_eq!(two[0][32], 0x00);
        assert_eq!(two[1][32], 0x80);

        let four = compute_proposed_shards(&[0x11; 32], 4);
        assert_eq!(four.len(), 4);

        let eight = compute_proposed_shards(&[0x11; 32], 8);
        assert_eq!(eight.len(), 8);
        assert_eq!(eight[0].len(), 34);
    }
}
