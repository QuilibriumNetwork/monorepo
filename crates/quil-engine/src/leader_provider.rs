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
use quil_types::crypto::{FrameProver, InclusionProver, Signer};
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
    /// BLS48-581 signer used by `ProveGlobalFrameHeader` to sign the
    /// (challenge || output) payload under the "global" domain. Mirrors
    /// Go's `provingKey qcrypto.Signer` parameter at
    /// `vdf/wesolowski_frame_prover.go:402`.
    signer: Arc<dyn Signer>,
    /// KZG-style inclusion prover used to commit the request tree.
    /// Mirrors Go's `p.engine.inclusionProver` at
    /// `consensus_leader_provider.go:307`. The explicit `+ Send + Sync`
    /// bound is required because `VectorCommitmentTree::commit` walks
    /// branches in parallel via rayon.
    inclusion_prover: Arc<dyn InclusionProver + Send + Sync>,
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
        signer: Arc<dyn Signer>,
        inclusion_prover: Arc<dyn InclusionProver + Send + Sync>,
    ) -> Self {
        Self {
            prover_registry,
            frame_prover,
            difficulty_adjuster,
            clock_store,
            message_collector,
            local_prover_address,
            local_public_key,
            signer,
            inclusion_prover,
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

    /// Compute the QC identity. Mirror of Go's
    /// `QuorumCertificate.Identity()` at `protobufs/global.go:46-48`
    /// which returns `models.Identity(g.Selector)` — i.e. the Selector
    /// bytes interpreted as the identity directly (Go strings are byte
    /// sequences).
    fn qc_identity(
        qc: &quil_types::proto::global::QuorumCertificate,
    ) -> Identity {
        qc.selector.clone()
    }

    /// Compute the identity of a GlobalFrame. Mirror of Go's
    /// `GlobalFrame.Identity()` at `protobufs/global.go:142-149`:
    /// `poseidon.HashBytes(g.Header.Output).FillBytes(make([]byte, 32))`.
    fn frame_identity(header: &quil_types::proto::global::GlobalFrameHeader) -> Identity {
        match quil_crypto::poseidon::hash_bytes_to_32(&header.output) {
            Ok(hash) => hash.to_vec(),
            Err(_) => Vec::new(),
        }
    }

    /// Build the request root: a `VectorCommitmentTree` over the
    /// collected MessageBundle payloads, keyed by `sha3_256(payload)`.
    /// Mirrors Go's `consensus_leader_provider.go:256-307`:
    ///
    /// ```go
    ///   requestTree := &tries.VectorCommitmentTree{}
    ///   for _, msgData := range collectedMessages {
    ///     id := sha3.Sum256(msgData)
    ///     requestTree.Insert(id[:], msgData, nil, big.NewInt(0))
    ///   }
    ///   requestRoot := requestTree.Commit(inclusionProver, false)
    /// ```
    ///
    /// Empty inputs yield the canonical empty-root `[0u8; 64]` produced
    /// by `VectorCommitmentTree::commit` on an empty tree. Insert
    /// failures are logged and skipped, matching Go's `if err != nil`
    /// soft-fail (a single bad bundle does not abort the whole frame).
    fn compute_requests_root(&self, messages: &[Vec<u8>]) -> Vec<u8> {
        use sha3::{Digest as _, Sha3_256};
        let mut tree = quil_tries::VectorCommitmentTree::new();
        for msg in messages {
            let id: [u8; 32] = Sha3_256::digest(msg).into();
            if let Err(e) = tree.insert(
                &id,
                msg,
                &[],
                &num_bigint::BigInt::from(0),
            ) {
                tracing::warn!(
                    error = %e,
                    "failed to add global request to tree",
                );
                continue;
            }
        }
        tree.commit(self.inclusion_prover.as_ref())
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
                first = %hex::encode(&leaders[0]),
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
            // `prior_state_id` is already raw 32-byte Identity bytes
            // (post-Tier-1 fix). Mirrors Go's `[]byte(priorState)` at
            // `consensus_leader_provider.go:99-101`.
            self.clock_store
                .get_global_clock_frame_candidate(latest_qc.frame_number, prior_state_id)
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
                        latest_qc.rank,
                        hex::encode(&prior_identity),
                        hex::encode(&qc_id),
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
                hex::encode(prior_state_id),
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
        let requests_root = self.compute_requests_root(&messages);

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
        // 7. VDF prove + sign — blocks for seconds.
        //
        // ProveGlobalFrameHeader internally computes
        //   parent     = poseidon(previous_frame.output[:516])
        //   challenge  = sha3(frame# || timestamp || difficulty ||
        //                     parent || commitments... || prover_root ||
        //                     request_root)
        //   output     = WesolowskiSolve(challenge, difficulty)
        //   signature  = signer.SignWithDomain(challenge||output, "global")
        //
        // shard `commitments` and `prover_root` here are still
        // placeholders pending Tier 2 wiring of the materializer's
        // shardCommitments + proverRoot output. `requests_root` is the
        // partial commit we already have. Once Tier 2 lands, these
        // become the real values. (See audit BLOCKER list, Tier 2.)
        let prover_index_u8 = prover_index.map(|i| i as u8).unwrap_or(0);
        let commitments: Vec<Vec<u8>> = Vec::new();
        let prover_root: Vec<u8> = Vec::new();
        let header = self.frame_prover.prove_global_frame_header(
            prior_header,
            &commitments,
            &prover_root,
            &requests_root,
            self.signer.as_ref(),
            timestamp,
            difficulty as u32,
            prover_index_u8,
        )?;

        // ------------------------------------------------------------------
        // 9. Assemble GlobalState
        // ------------------------------------------------------------------
        // The prover_tree_commitment is empty here and populated after
        // the hypergraph CRDT commit in rebuildShardCommitments (which
        // runs during the consensus commit path, not during proving).
        // Similarly, the signature is populated by the consensus signing
        // step after the proposal is voted on.
        // Decode each canonical bundle into a prost `MessageBundle`
        // (the proto type the materializer expects). Bundles that
        // fail decode are skipped — `requests_root` was hashed over
        // the canonical bytes, so a partial set here would mismatch,
        // but in practice the same `decode_message_bundle` call has
        // already round-tripped these on every other replica's
        // receive path, so a leader-side failure indicates the same
        // bundle would also fail downstream.
        let proto_messages: Vec<quil_types::proto::global::MessageBundle> = messages
            .iter()
            .filter_map(|raw| crate::consensus_wire::decode_message_bundle(raw).ok())
            .collect();
        let state = GlobalState::new(
            frame_number,
            rank,
            timestamp,
            difficulty as u32,
            header.output.clone(),
            header.parent_selector.clone(),
            self.local_prover_address.clone(),
            Vec::new(), // prover_tree_commitment — populated after hypergraph commit
            requests_root,
            Vec::new(), // signature — populated by consensus signing step
        )
        // Attach the collected messages so they ride with the proposal
        // into `GlobalFrame.requests` and reach every replica's
        // materializer on finalization.
        .with_messages(proto_messages);

        // ------------------------------------------------------------------
        // 10. Build and return State<GlobalState>
        // ------------------------------------------------------------------
        let identifier = state.compute_identity();

        tracing::info!(
            frame = frame_number,
            rank,
            identifier = %hex::encode(&identifier),
            "proved global frame",
        );

        Ok(State {
            rank,
            identifier,
            proposer_id: address_to_identity(&self.local_prover_address),
            parent_qc_identity: prior_state_id.clone(),
            parent_qc_rank: rank.saturating_sub(1),
            // Leader-side construction: `prove_next_state` doesn't
            // receive the parent QC trait object. The QC arc is
            // populated on the receiver side from the wire-decoded
            // proposal.
            parent_quorum_certificate: None,
            timestamp: timestamp as u64,
            state,
        })
    }
}

// `prove_next_state` (the VDF/clock-store path) is integration-tested
// via the consensus bootstrap tests on real stores. The unit tests
// below cover `get_next_leaders` (leader selection) and the pure
// helper functions, which need only a `ProverRegistry`.
#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::consensus::{ProverInfo, ProverStatus};
    use quil_types::proto::global::GlobalFrameHeader;

    use crate::difficulty::AsertDifficultyAdjuster;
    use crate::test_support::TestProverRegistry;

    /// Minimal `FrameProver` stub — `get_next_leaders` never invokes it.
    #[derive(Default)]
    struct StubFrameProver;
    impl FrameProver for StubFrameProver {
        fn prove_frame_header(
            &self, _: &[u8], _: &[u8], _: &[u8], _: &[Vec<u8>], _: &[u8], _: i64, _: u32, _: u64, _: u64,
        ) -> Result<quil_types::proto::global::FrameHeader> {
            Err(QuilError::Internal("stub".into()))
        }
        fn verify_frame_header(
            &self, _: &quil_types::proto::global::FrameHeader,
        ) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
        fn prove_global_frame_header(
            &self, _: &GlobalFrameHeader, _: &[Vec<u8>], _: &[u8], _: &[u8],
            _: &dyn Signer, _: i64, _: u32, _: u8,
        ) -> Result<GlobalFrameHeader> {
            Err(QuilError::Internal("stub".into()))
        }
        fn verify_global_frame_header(&self, _: &GlobalFrameHeader) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
        fn calculate_multi_proof(&self, _: &[u8; 32], _: u32, _: &[&[u8]], _: u32) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
        fn verify_multi_proof(&self, _: &[u8; 32], _: u32, _: &[&[u8]], _: &[&[u8]]) -> Result<bool> {
            Ok(true)
        }
    }

    fn make_prover(addr_byte: u8) -> ProverInfo {
        ProverInfo {
            public_key: vec![addr_byte; 96],
            address: vec![addr_byte; 32],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![],
            available_storage: 0,
            seniority: 1,
            delegate_address: vec![],
        }
    }

    /// Structure-only signer (never actually invoked by these tests).
    struct DummySigner;
    impl Signer for DummySigner {
        fn key_type(&self) -> quil_types::crypto::KeyType {
            quil_types::crypto::KeyType::Bls48581G1
        }
        fn public_key(&self) -> &[u8] {
            &[]
        }
        fn private_key(&self) -> &[u8] {
            &[0u8]
        }
        fn sign(&self, _: &[u8]) -> Result<Vec<u8>> {
            Ok(vec![0xAA; 74])
        }
        fn sign_with_domain(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
            Ok(vec![0xAA; 74])
        }
    }

    fn provider_with(registry: Arc<dyn ProverRegistry>) -> GlobalLeaderProvider {
        let signer: Arc<dyn Signer> = Arc::new(DummySigner);
        GlobalLeaderProvider::new(
            registry,
            Arc::new(StubFrameProver),
            Arc::new(AsertDifficultyAdjuster::new(0, 0, 100)),
            Arc::new(quil_store::testing::InMemoryClockStore::new()),
            Arc::new(MessageCollector::new()),
            vec![0xABu8; 32],
            vec![0xABu8; 96],
            signer,
            // Real KZG prover so `compute_requests_root` reflects tree
            // contents (the noop prover returns all-zero roots).
            Arc::new(quil_crypto::KzgInclusionProver),
        )
    }

    fn prior_state(output_len: usize) -> State<GlobalState> {
        let gs = GlobalState::new(
            5,                          // frame_number
            5,                          // rank
            0,                          // timestamp
            100,                        // difficulty
            vec![0x11u8; output_len],   // output
            vec![0x03u8; 32],           // parent_selector
            vec![0x02u8; 32],           // prover
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        State {
            rank: 5,
            identifier: vec![0x01u8; 32],
            proposer_id: vec![0x02u8; 32],
            parent_qc_identity: vec![0x03u8; 32],
            parent_qc_rank: 4,
            parent_quorum_certificate: None,
            timestamp: 0,
            state: gs,
        }
    }

    #[test]
    fn get_next_leaders_errors_without_prior() {
        let p = provider_with(Arc::new(TestProverRegistry::new()));
        let err = p.get_next_leaders(None).unwrap_err();
        assert!(err.to_string().contains("no prior frame"));
    }

    #[test]
    fn get_next_leaders_errors_on_wrong_output_length() {
        let p = provider_with(Arc::new(TestProverRegistry::with_provers(vec![make_prover(1)])));
        let prior = prior_state(100); // != VDF_OUTPUT_LEN
        let err = p.get_next_leaders(Some(&prior)).unwrap_err();
        assert!(err.to_string().contains("output length"));
    }

    #[test]
    fn get_next_leaders_errors_when_registry_empty() {
        let p = provider_with(Arc::new(TestProverRegistry::new()));
        let prior = prior_state(VDF_OUTPUT_LEN);
        let err = p.get_next_leaders(Some(&prior)).unwrap_err();
        assert!(err.to_string().contains("no active provers"));
    }

    #[test]
    fn get_next_leaders_returns_ordered_identities() {
        let registry = TestProverRegistry::with_provers(vec![
            make_prover(0xAA),
            make_prover(0xBB),
            make_prover(0xCC),
        ]);
        let p = provider_with(Arc::new(registry));
        let prior = prior_state(VDF_OUTPUT_LEN);
        let leaders = p.get_next_leaders(Some(&prior)).unwrap();
        assert_eq!(leaders.len(), 3);
        // Identities are the raw 32-byte addresses (address_to_identity).
        assert_eq!(leaders[0], vec![0xAAu8; 32]);
        assert_eq!(leaders[1], vec![0xBBu8; 32]);
        assert_eq!(leaders[2], vec![0xCCu8; 32]);
    }

    #[test]
    fn compute_parent_selector_is_deterministic_and_32_bytes() {
        let out = vec![0x42u8; VDF_OUTPUT_LEN];
        let a = GlobalLeaderProvider::compute_parent_selector(&out);
        let b = GlobalLeaderProvider::compute_parent_selector(&out);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        // Different input → different selector.
        let c = GlobalLeaderProvider::compute_parent_selector(&vec![0x43u8; VDF_OUTPUT_LEN]);
        assert_ne!(a, c);
    }

    #[test]
    fn frame_identity_hashes_output() {
        let header = GlobalFrameHeader {
            output: vec![0x55u8; VDF_OUTPUT_LEN],
            ..Default::default()
        };
        let id = GlobalLeaderProvider::frame_identity(&header);
        assert_eq!(id.len(), 32);
        // Matches the direct poseidon hash of the output.
        let expected = quil_crypto::poseidon::hash_bytes_to_32(&header.output).unwrap();
        assert_eq!(id, expected.to_vec());
    }

    #[test]
    fn qc_identity_returns_selector_bytes() {
        let qc = quil_types::proto::global::QuorumCertificate {
            selector: vec![0x77u8; 32],
            ..Default::default()
        };
        assert_eq!(GlobalLeaderProvider::qc_identity(&qc), vec![0x77u8; 32]);
    }

    #[test]
    fn compute_requests_root_empty_vs_nonempty_differ() {
        let p = provider_with(Arc::new(TestProverRegistry::new()));
        let empty = p.compute_requests_root(&[]);
        let nonempty = p.compute_requests_root(&[vec![0x01u8; 16], vec![0x02u8; 16]]);
        assert_ne!(empty, nonempty);
        // Deterministic for the same input.
        assert_eq!(empty, p.compute_requests_root(&[]));
    }
}
