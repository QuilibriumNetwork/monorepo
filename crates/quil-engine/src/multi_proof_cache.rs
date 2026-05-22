//! Async precompute + cache of per-voter VDF multi-proof contributions
//! for app shard consensus. Keyed by `(rank, parent_selector)` so TC
//! rank changes and re-orgs pick the right entry. `sign_vote` reads
//! synchronously and falls back to empty on a miss.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use sha3::{Digest, Sha3_256};

use quil_consensus::models::State;
use quil_types::consensus::ProverRegistry;
use quil_types::crypto::FrameProver;

use crate::app_types::AppShardState;

type CacheKey = (u64, Vec<u8>);

/// Per-shard async multi-proof precomputer + cache. Entries below
/// `min_active_rank` are pruned by `advance_min_active_rank`.
pub struct ShardMultiProofPrecomputer {
    cache: RwLock<HashMap<CacheKey, Vec<u8>>>,
    in_flight: RwLock<HashSet<CacheKey>>,
    frame_prover: Arc<dyn FrameProver>,
    prover_registry: Arc<dyn ProverRegistry>,
    local_prover_address: Vec<u8>,
    filter: Vec<u8>,
}

impl ShardMultiProofPrecomputer {
    pub fn new(
        frame_prover: Arc<dyn FrameProver>,
        prover_registry: Arc<dyn ProverRegistry>,
        local_prover_address: Vec<u8>,
        filter: Vec<u8>,
    ) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            in_flight: RwLock::new(HashSet::new()),
            frame_prover,
            prover_registry,
            local_prover_address,
            filter,
        }
    }

    /// Fire-and-forget multi-proof precompute, called from the
    /// rank-change hook. Idempotent on `(rank, parent_selector)`.
    pub fn precompute_for_rank_change(
        self: &Arc<Self>,
        new_rank: u64,
        parent_selector: Vec<u8>,
        difficulty: u32,
    ) {
        // Single-prover shards use the 74-byte aggregate path and
        // don't need multi-proofs.
        let active = match self.prover_registry.get_active_provers(&self.filter) {
            Ok(v) => v,
            Err(_) => return,
        };
        if active.len() <= 1 {
            return;
        }
        let my_index = match active
            .iter()
            .position(|p| p.address == self.local_prover_address)
        {
            Some(i) => i,
            None => return,
        };

        let key: CacheKey = (new_rank, parent_selector.clone());
        // Skip if already cached or compute already in flight.
        if self.cache.read().unwrap().contains_key(&key) {
            return;
        }
        {
            let mut inflight = self.in_flight.write().unwrap();
            if !inflight.insert(key.clone()) {
                return;
            }
        }

        let this = Arc::clone(self);
        let active_addrs: Vec<Vec<u8>> =
            active.iter().map(|p| p.address.clone()).collect();
        tokio::task::spawn_blocking(move || {
            let challenge: [u8; 32] =
                Sha3_256::digest(&parent_selector).into();
            let id_refs: Vec<&[u8]> =
                active_addrs.iter().map(|v| v.as_slice()).collect();
            let result = this.frame_prover.calculate_multi_proof(
                &challenge,
                difficulty,
                &id_refs,
                my_index as u32,
            );
            match result {
                Ok(bytes) => {
                    let mut cache = this.cache.write().unwrap();
                    cache.insert(key.clone(), bytes);
                }
                Err(e) => {
                    tracing::warn!(
                        filter = hex::encode(&this.filter),
                        rank = new_rank,
                        error = %e,
                        "multi-proof precompute failed"
                    );
                }
            }
            let mut inflight = this.in_flight.write().unwrap();
            inflight.remove(&key);
        });
    }

    /// Cache lookup keyed by `(rank, parent_selector)`. Empty on miss.
    pub fn get_for_state(&self, state: &State<AppShardState>) -> Vec<u8> {
        let key: CacheKey = (state.rank, state.state.parent_selector.clone());
        self.cache
            .read()
            .unwrap()
            .get(&key)
            .cloned()
            .unwrap_or_default()
    }

    /// Prune cache entries strictly below `min_rank`.
    pub fn advance_min_active_rank(&self, min_rank: u64) {
        let mut cache = self.cache.write().unwrap();
        cache.retain(|(r, _), _| *r >= min_rank);
        let mut inflight = self.in_flight.write().unwrap();
        inflight.retain(|(r, _)| *r >= min_rank);
    }
}
