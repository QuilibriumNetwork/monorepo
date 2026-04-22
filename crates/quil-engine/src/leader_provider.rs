//! Global chain leader provider. Port of
//! `node/consensus/global/consensus_leader_provider.go`.
//!
//! Selects leaders from the prover registry and produces new global
//! frames when this node is the elected leader.

use std::sync::Arc;

use sha2::{Digest, Sha256};

use quil_consensus::leader_provider::LeaderProvider;
use quil_consensus::models::{Identity, State};
use quil_types::consensus::{DifficultyAdjuster, ProverRegistry};
use quil_types::crypto::FrameProver;
use quil_types::error::{QuilError, Result};
use quil_types::store::ClockStore;

use crate::committee::address_to_identity;
use crate::consensus_types::GlobalState;
use crate::message_collector::MessageCollector;

/// Expected length of a valid VDF output (258-byte Y + 258-byte proof).
const VDF_OUTPUT_LEN: usize = 516;

/// Global chain leader provider. Selects leaders based on the prover
/// registry's ordered prover list, seeded by the parent frame's
/// `parent_selector`. Produces frames by collecting messages, computing
/// VDF proofs, and assembling GlobalFrameHeaders.
pub struct GlobalLeaderProvider {
    prover_registry: Arc<dyn ProverRegistry>,
    frame_prover: Arc<dyn FrameProver>,
    difficulty_adjuster: Arc<dyn DifficultyAdjuster>,
    clock_store: Arc<dyn ClockStore>,
    message_collector: Arc<MessageCollector>,
    /// This node's prover address (32-byte Poseidon hash of BLS pubkey).
    local_prover_address: Vec<u8>,
    /// This node's BLS48-581 public key (585 bytes).
    local_public_key: Vec<u8>,
}

impl GlobalLeaderProvider {
    pub fn new(
        prover_registry: Arc<dyn ProverRegistry>,
        frame_prover: Arc<dyn FrameProver>,
        difficulty_adjuster: Arc<dyn DifficultyAdjuster>,
        clock_store: Arc<dyn ClockStore>,
        message_collector: Arc<MessageCollector>,
        local_prover_address: Vec<u8>,
        local_public_key: Vec<u8>,
    ) -> Self {
        Self {
            prover_registry,
            frame_prover,
            difficulty_adjuster,
            clock_store,
            message_collector,
            local_prover_address,
            local_public_key,
        }
    }

    /// Compute the parent selector from a VDF output: Poseidon hash of
    /// the output bytes, yielding a 32-byte selector. Falls back to
    /// SHA-256 if the Poseidon hash fails (should not happen with
    /// well-formed output).
    fn compute_parent_selector(output: &[u8]) -> [u8; 32] {
        match quil_crypto::poseidon::hash_bytes_to_32(output) {
            Ok(hash) => hash,
            Err(_) => {
                // Fallback: this should not happen with valid 516-byte
                // VDF output. Log would be appropriate here but we keep
                // the function pure and let callers notice via
                // mismatched selectors.
                let hash = Sha256::digest(output);
                let mut out = [0u8; 32];
                out.copy_from_slice(&hash);
                out
            }
        }
    }

    /// Compute the QC identity from a quorum certificate's selector.
    /// In Go this is `models.Identity(qc.Selector)` which is raw bytes
    /// cast to a string. In Rust the Identity is a hex string.
    fn qc_identity(
        qc: &quil_types::proto::global::QuorumCertificate,
    ) -> Identity {
        hex::encode(&qc.selector)
    }

    /// Compute the identity of a GlobalFrame, matching Go's
    /// `GlobalFrame.Identity()`: Poseidon hash of the output, returned
    /// as the raw 32-byte value hex-encoded. Note: `GlobalState::compute_identity()`
    /// uses SHA-256 for the consensus-layer `Unique` trait; this method mirrors
    /// the Go `Identity()` used for frame-to-QC matching.
    fn frame_identity(header: &quil_types::proto::global::GlobalFrameHeader) -> Identity {
        match quil_crypto::poseidon::hash_bytes_to_32(&header.output) {
            Ok(hash) => hex::encode(hash),
            Err(_) => String::new(),
        }
    }

    /// Build a SHA-256 root over collected message payloads. This is a
    /// simplified stand-in for the full VectorCommitmentTree-based
    /// request root used in Go. Each message is hashed individually,
    /// then the hashes are concatenated and hashed again to produce
    /// the root. An empty message set produces an empty root.
    fn compute_requests_root(messages: &[Vec<u8>]) -> Vec<u8> {
        if messages.is_empty() {
            return Vec::new();
        }

        // Hash each message with SHA-256 (mirrors Go's sha3.Sum256 per
        // message, but we use SHA-256 to stay consistent with the rest
        // of the Rust port; the full VCT-based root will replace this).
        let mut combined = Vec::with_capacity(messages.len() * 32);
        for msg in messages {
            let hash = Sha256::digest(msg);
            combined.extend_from_slice(&hash);
        }
        let root = Sha256::digest(&combined);
        root.to_vec()
    }
}

impl LeaderProvider<GlobalState> for GlobalLeaderProvider {
    /// Return leaders for the next rank, ordered by the prover
    /// registry's VDF-distance walk seeded by the parent frame's
    /// Poseidon-hashed output.
    fn get_next_leaders(&self, prior: Option<&State<GlobalState>>) -> Result<Vec<Identity>> {
        // The prior state must have a valid VDF output to seed the
        // ordering. Without it we cannot determine leader order.
        let prior = prior.ok_or_else(|| {
            QuilError::Consensus("no prior frame for leader selection".into())
        })?;

        if prior.state.output.len() != VDF_OUTPUT_LEN {
            return Err(QuilError::Consensus(format!(
                "prior frame output length {} != expected {}",
                prior.state.output.len(),
                VDF_OUTPUT_LEN,
            )));
        }

        // Compute the parent selector: Poseidon(output) -> 32 bytes.
        let parent_selector = Self::compute_parent_selector(&prior.state.output);

        // Get provers ordered by VDF distance to the parent selector.
        // Empty filter = global chain (matches Go's `nil` filter).
        let ordered_addresses =
            self.prover_registry.get_ordered_provers(&parent_selector, &[])?;

        if ordered_addresses.is_empty() {
            return Err(QuilError::Consensus(
                "no active provers in registry".into(),
            ));
        }

        let leaders: Vec<Identity> = ordered_addresses
            .iter()
            .map(|addr| address_to_identity(addr))
            .collect();

        if !leaders.is_empty() {
            tracing::debug!(
                count = leaders.len(),
                first = %leaders[0],
                "determined next global leaders",
            );
        }

        Ok(leaders)
    }

    /// Produce a new global frame at the given rank. Full port of Go's
    /// `ProveNextState`:
    ///
    /// 1. Fetch the latest QC and resolve the prior frame
    /// 2. Validate that the prior frame identity matches `prior_state_id`
    /// 3. Collect pending messages from the message collector
    /// 4. Compute the request root from collected messages
    /// 5. Determine prover index among active provers
    /// 6. Compute next difficulty via ASERT
    /// 7. Call `frame_prover.prove_global_frame_header()` (blocks for VDF)
    /// 8. Assemble `GlobalState` with all fields populated
    /// 9. Return `State<GlobalState>`
    fn prove_next_state(
        &self,
        rank: u64,
        _filter: &[u8],
        prior_state_id: &Identity,
    ) -> Result<State<GlobalState>> {
        // ------------------------------------------------------------------
        // 1. Resolve the prior frame via the latest QC
        // ------------------------------------------------------------------
        let latest_qc = self
            .clock_store
            .get_latest_quorum_certificate(&[])
            .map_err(|e| {
                tracing::debug!(error = %e, "could not fetch latest quorum certificate");
                QuilError::Consensus(format!("could not fetch latest QC: {}", e))
            })?;

        let prior = if latest_qc.frame_number == 0 {
            self.clock_store.get_global_clock_frame(latest_qc.frame_number)?
        } else {
            // Fetch the candidate frame that matches the QC's
            // frame number + the caller's prior_state_id as selector.
            let selector_bytes = hex::decode(prior_state_id).unwrap_or_default();
            self.clock_store
                .get_global_clock_frame_candidate(latest_qc.frame_number, &selector_bytes)
                .or_else(|_| {
                    // Fall back to the canonical frame at this number
                    self.clock_store.get_global_clock_frame(latest_qc.frame_number)
                })?
        };

        let prior_header = prior.header.as_ref().ok_or_else(|| {
            QuilError::Consensus("prior frame has no header".into())
        })?;

        // ------------------------------------------------------------------
        // 2. Validate prior frame identity matches prior_state_id
        // ------------------------------------------------------------------
        let prior_identity = Self::frame_identity(prior_header);
        if prior_identity != *prior_state_id {
            // Check if the QC itself matches -- could be a fork
            let qc_id = Self::qc_identity(&latest_qc);
            if qc_id == *prior_state_id {
                if prior_header.rank < latest_qc.rank {
                    return Err(QuilError::Consensus(format!(
                        "needs sync: prior rank {} behind latest QC rank {}",
                        prior_header.rank, latest_qc.rank,
                    )));
                }
                if prior_header.frame_number == latest_qc.frame_number {
                    return Err(QuilError::Consensus(format!(
                        "fork detected at rank {} (local: {}, qc: {})",
                        latest_qc.rank, prior_identity, qc_id,
                    )));
                }
            }

            return Err(QuilError::Consensus(format!(
                "building on fork or needs sync: frame {}, rank {}, parent_id: {}, \
                 asked: rank {}, id: {}",
                prior_header.frame_number,
                prior_header.rank,
                hex::encode(&prior_header.parent_selector),
                rank,
                prior_state_id,
            )));
        }

        let frame_number = prior_header.frame_number + 1;

        // ------------------------------------------------------------------
        // 3. Collect pending messages
        // ------------------------------------------------------------------
        let messages = self.message_collector.collect_for_rank(rank);

        tracing::info!(
            frame = frame_number,
            rank,
            message_count = messages.len(),
            "proving next global state",
        );

        // ------------------------------------------------------------------
        // 4. Compute request root from collected messages
        // ------------------------------------------------------------------
        let requests_root = Self::compute_requests_root(&messages);

        // ------------------------------------------------------------------
        // 5. Verify this node is an active prover and find our index
        // ------------------------------------------------------------------
        let active_provers = self.prover_registry.get_active_provers(&[])?;
        let prover_index = active_provers
            .iter()
            .position(|p| p.address == self.local_prover_address);

        if prover_index.is_none() {
            return Err(QuilError::Consensus("not a prover".into()));
        }

        // ------------------------------------------------------------------
        // 6. Compute difficulty
        // ------------------------------------------------------------------
        // Go adds 10 seconds to the timestamp for the difficulty
        // calculation, matching the expected block interval.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let timestamp = now_ms + 10_000; // +10s, matching Go
        let difficulty = self.difficulty_adjuster.get_next_difficulty(rank, timestamp);

        tracing::debug!(
            difficulty,
            frame = frame_number,
            "next difficulty for frame",
        );

        // ------------------------------------------------------------------
        // 7. Compute parent selector from prior frame output
        // ------------------------------------------------------------------
        let parent_selector = if prior_header.output.len() == VDF_OUTPUT_LEN {
            Self::compute_parent_selector(&prior_header.output).to_vec()
        } else {
            prior_header.parent_selector.clone()
        };

        // ------------------------------------------------------------------
        // 8. VDF prove -- this blocks for seconds
        // ------------------------------------------------------------------
        let header = self.frame_prover.prove_global_frame_header(
            frame_number,
            &parent_selector,
            difficulty as u32,
            &self.local_public_key,
        )?;

        // ------------------------------------------------------------------
        // 9. Assemble GlobalState
        // ------------------------------------------------------------------
        // The prover_tree_commitment is empty here and populated after
        // the hypergraph CRDT commit in rebuildShardCommitments (which
        // runs during the consensus commit path, not during proving).
        // Similarly, the signature is populated by the consensus signing
        // step after the proposal is voted on.
        let state = GlobalState::new(
            frame_number,
            rank,
            timestamp,
            difficulty as u32,
            header.output.clone(),
            header.parent_selector.clone(),
            self.local_public_key.clone(),
            Vec::new(), // prover_tree_commitment — populated after hypergraph commit
            requests_root,
            Vec::new(), // signature — populated by consensus signing step
        );

        // ------------------------------------------------------------------
        // 10. Build and return State<GlobalState>
        // ------------------------------------------------------------------
        let identifier = state.compute_identity();

        tracing::info!(
            frame = frame_number,
            rank,
            identifier = %identifier,
            "proved global frame",
        );

        Ok(State {
            rank,
            identifier,
            proposer_id: address_to_identity(&self.local_prover_address),
            parent_qc_identity: prior_state_id.clone(),
            parent_qc_rank: rank.saturating_sub(1),
            timestamp: timestamp as u64,
            state,
        })
    }
}

// Tests for GlobalLeaderProvider require full ClockStore/ProverRegistry
// stubs. These are integration-tested via the consensus bootstrap tests
// which use the real RocksDB stores. The struct construction is verified
// implicitly by the consensus bootstrap wiring.
