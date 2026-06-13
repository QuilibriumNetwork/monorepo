//! Archive-side ingest of full app-shard frames.
//!
//! Archives don't run an `AppConsensusEngine`, but they bulk-subscribe to
//! all shard traffic (`[0xFF;32]`) and must materialize every shard's
//! state so they can serve it via HyperSync. This receives the full
//! `AppShardFrame`s published on `shard_frame_bitmask`, verifies them, and
//! materializes them — in strict frame order per shard — into the
//! archive's (global) hypergraph CRDT via its existing
//! `ExecutionEngineManager`.
//!
//! Verification (no consensus participation required):
//!   1. The header's quorum aggregate BLS cert is checked against the
//!      shard committee (active provers under the frame's address) via
//!      `BlsAppFrameValidator` — same check the consensus path uses. This
//!      proves the header (and its `requests_root`) was finalized by the
//!      shard's quorum.
//!   2. The carried `requests` are recomputed to a `requests_root` and
//!      required to equal the signed one — defends against a relay
//!      swapping requests under an otherwise-valid header.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, warn};

use quil_types::consensus::{AppFrameValidator, ProverRegistry as ProverRegistryTrait};
use quil_types::crypto::{BlsConstructor, FrameProver, InclusionProver};
use quil_types::proto::global::AppShardFrame;

use crate::app_engine::{compute_requests_root, materialize_app_shard_requests};
use crate::frame_validator::BlsAppFrameValidator;

pub struct ArchiveAppShardIngest {
    validator: BlsAppFrameValidator,
    execution_manager: Arc<quil_execution::ExecutionEngineManager>,
    inclusion_prover: Arc<dyn InclusionProver>,
    hypergraph: Arc<quil_hypergraph::HypergraphCrdt>,
    /// Per-shard (address) → highest frame number materialized.
    /// Lazily seeded from the durable cursor (`kv_db`) on first access so
    /// it survives restart instead of resetting to 0 and re-materializing
    /// (or skipping frames the CRDT already advanced past).
    last_materialized: HashMap<Vec<u8>, u64>,
    /// Out-of-order verified frames, buffered until the gap fills:
    /// address → (frame_number → frame).
    buffered: HashMap<Vec<u8>, HashMap<u64, AppShardFrame>>,
    /// Durable backing store for the per-address materialized cursor.
    /// Keyed by app address (Poseidon of the filter) under
    /// `consensus_materialized_cursor_key`.
    kv_db: Option<Arc<dyn quil_types::store::KvDb>>,
}

impl ArchiveAppShardIngest {
    pub fn new(
        prover_registry: Arc<dyn ProverRegistryTrait>,
        bls_constructor: Arc<dyn BlsConstructor>,
        frame_prover: Arc<dyn FrameProver>,
        execution_manager: Arc<quil_execution::ExecutionEngineManager>,
        inclusion_prover: Arc<dyn InclusionProver>,
        hypergraph: Arc<quil_hypergraph::HypergraphCrdt>,
        kv_db: Option<Arc<dyn quil_types::store::KvDb>>,
    ) -> Self {
        Self {
            validator: BlsAppFrameValidator::new(prover_registry, bls_constructor, frame_prover),
            execution_manager,
            inclusion_prover,
            hypergraph,
            last_materialized: HashMap::new(),
            buffered: HashMap::new(),
            kv_db,
        }
    }

    /// Highest materialized frame for `address`, seeded from the durable
    /// cursor on first access.
    fn materialized_height(&mut self, address: &[u8]) -> u64 {
        if let Some(&h) = self.last_materialized.get(address) {
            return h;
        }
        let h = self
            .kv_db
            .as_ref()
            .and_then(|kv| {
                kv.get(&quil_store::encoding::consensus_materialized_cursor_key(address))
                    .ok()
                    .flatten()
            })
            .filter(|v| v.len() == 8)
            .map(|v| {
                let mut b = [0u8; 8];
                b.copy_from_slice(&v[..8]);
                u64::from_be_bytes(b)
            })
            .unwrap_or(0);
        self.last_materialized.insert(address.to_vec(), h);
        h
    }

    /// Record + persist the materialized height for `address`. Called only
    /// AFTER `commit_frame` succeeded so the durable cursor never outruns
    /// the CRDT.
    fn set_materialized_height(&mut self, address: &[u8], frame: u64) {
        self.last_materialized.insert(address.to_vec(), frame);
        if let Some(kv) = self.kv_db.as_ref() {
            if let Err(e) = kv.set(
                &quil_store::encoding::consensus_materialized_cursor_key(address),
                &frame.to_be_bytes(),
            ) {
                warn!(frame, error = %e, "archive: failed to persist materialized cursor");
            }
        }
    }

    /// Ingest a gossiped full `AppShardFrame` (prost bytes).
    pub fn ingest(&mut self, data: &[u8]) {
        let frame = match <AppShardFrame as prost::Message>::decode(data) {
            Ok(f) => f,
            Err(_) => return,
        };
        let (address, frame_number, requests_root) = match frame.header.as_ref() {
            Some(h) if !h.address.is_empty() => {
                (h.address.clone(), h.frame_number, h.requests_root.clone())
            }
            _ => return,
        };

        // Already materialized (or older) — ignore.
        if frame_number <= self.materialized_height(&address) {
            return;
        }

        // 1. Quorum BLS cert + VDF against the shard committee.
        match self.validator.validate(&frame) {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => {
                debug!(frame = frame_number, error = %e, "archive ingest: frame validation failed");
                return;
            }
        }

        // 2. Verify the carried requests recompute to the signed root.
        let canonical: Vec<Vec<u8>> = frame
            .requests
            .iter()
            .filter_map(|b| crate::consensus_wire::proto_message_bundle_to_canonical_bytes(b).ok())
            .collect();
        if canonical.len() != frame.requests.len() {
            return;
        }
        let recomputed = match compute_requests_root(
            &canonical,
            &address,
            frame_number,
            Some(self.execution_manager.as_ref()),
            Some(self.inclusion_prover.as_ref()),
        ) {
            Ok(r) => r,
            Err(_) => return,
        };
        if recomputed != requests_root {
            warn!(frame = frame_number, "archive ingest: requests_root mismatch — rejecting");
            return;
        }

        // 3. Buffer + materialize in strict order per shard.
        self.buffered
            .entry(address.clone())
            .or_default()
            .insert(frame_number, frame);
        self.try_materialize(&address);
    }

    fn try_materialize(&mut self, address: &[u8]) {
        loop {
            let last = self.materialized_height(address);
            let next = last + 1;
            let frame = match self.buffered.get(address).and_then(|m| m.get(&next)) {
                Some(f) => f.clone(),
                None => break, // gap — wait for the missing frame (or sync)
            };
            let fee_multiplier_vote = frame
                .header
                .as_ref()
                .map(|h| h.fee_multiplier_vote)
                .unwrap_or(0);
            let world_size = {
                use num_traits::ToPrimitive;
                self.hypergraph.total_size().to_u64().unwrap_or(0)
            };
            // Difficulty/fee don't affect materialized state (the fee
            // param is unused by the app engines), so 0 is fine here.
            match materialize_app_shard_requests(
                self.execution_manager.as_ref(),
                &frame.requests,
                next,
                0,
                world_size,
                fee_multiplier_vote,
                address,
            ) {
                Ok((processed, skipped)) => {
                    self.set_materialized_height(address, next);
                    if let Some(m) = self.buffered.get_mut(address) {
                        m.remove(&next);
                    }
                    debug!(frame = next, processed, skipped, "archive materialized shard frame");
                }
                Err(e) => {
                    warn!(frame = next, error = %e, "archive materialize failed");
                    break;
                }
            }
        }
        // Gap detection: frames buffered ahead of the next-needed one,
        // with the next-needed one missing, means the archive is behind
        // and needs a shard sync (step 4). Surface it; the actual
        // shard-keyed HyperSync fetch is the remaining integration.
        let last = *self.last_materialized.get(address).unwrap_or(&0);
        let next_needed = last + 1;
        if let Some(m) = self.buffered.get(address) {
            let ahead = m.keys().filter(|&&f| f > next_needed).count();
            if ahead > 0 && !m.contains_key(&next_needed) {
                warn!(
                    address = %hex::encode(&address[..address.len().min(8)]),
                    missing_from = next_needed,
                    buffered_ahead = ahead,
                    "archive app-shard frame gap — behind; shard sync needed (step 4)"
                );
            }
        }
        // Bound the buffer to frames still ahead of us.
        if let Some(m) = self.buffered.get_mut(address) {
            m.retain(|&f, _| f > last);
        }
    }
}
