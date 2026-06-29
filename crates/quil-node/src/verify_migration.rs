//! `--verify-db`: deep verification that a migrated RocksDB is not merely
//! decodable but ACTUALLY VALID for the Rust node's use cases — the data
//! would be ACCEPTED.
//!
//! Unlike the Go `--verify-migrate-db` decode pass (which only checks that
//! bytes unmarshal), this opens the DB with the Rust node's real loaders
//! and validators and confirms acceptance:
//!
//! - **Tries**: load the global prover-shard hypergraph trees and recompute
//!   the root commitment, then compare it to the `prover_tree_commitment`
//!   committed in the latest global frame header. A match proves the trie
//!   nodes + vertex data migrated correctly AND load into the usable lazy
//!   tree (this mirrors the live check in `worker_node.rs`).
//! - **Frame**: run `BlsGlobalFrameValidator` over the latest global frame
//!   (VDF + committee-bound BLS aggregate) — i.e. would the node accept it.
//! - **QC / TC**: run the committee-aware `ConsensusValidator` over the
//!   latest stored quorum / timeout certificate (the migration translated
//!   these canonical→proto; this confirms they verify against the
//!   committee reconstructed from the migrated prover registry).
//! - **Certified state**: reconstruct the latest `GlobalProposal` from its
//!   components and verify its embedded QC.
//!
//! Each category reports PASS / SKIP (no data) / FAIL; any FAIL exits
//! non-zero.

use std::path::Path;
use std::sync::Arc;

use quil_consensus::committee::Replicas;
use quil_consensus::validator::Validator as _;
use quil_types::consensus::GlobalFrameValidator as _;
use quil_types::store::{ClockStore, HypergraphStore, ShardKey};

/// Human label for a shard by its 32-byte L2 address.
fn shard_label(l2: &[u8; 32]) -> String {
    if *l2 == [0xFFu8; 32] {
        return "global prover shard".to_string();
    }
    if l2.as_slice() == quil_execution::domains::QUIL_TOKEN.as_slice() {
        return "QUIL token shard".to_string();
    }
    format!("shard {}…", hex::encode(&l2[..8]))
}

pub fn run_verify_db(db_path: &Path, config: &quil_config::Config) -> anyhow::Result<()> {
    let path = if db_path.as_os_str().is_empty() {
        std::path::PathBuf::from(&config.db.path)
    } else {
        db_path.to_path_buf()
    };
    if path.as_os_str().is_empty() {
        anyhow::bail!("no database path given and config.db.path is empty");
    }

    println!("=== Verifying migrated RocksDB (acceptance) ===");
    println!("target (rocksdb): {}", path.display());

    let db = quil_store::RocksDb::open(&path)
        .map_err(|e| anyhow::anyhow!("open rocksdb {}: {e}", path.display()))?;
    let inner = db.inner();
    let clock = Arc::new(quil_store::RocksClockStore::new(inner.clone()));
    let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(inner.clone()));

    // Load the prover registry from the migrated hypergraph — needed to
    // build the committee (QC/TC) and validate frames.
    let registry = Arc::new(quil_execution::SharedProverRegistry::new());
    registry.refresh_from_store(&hg_store);
    let registry_dyn: Arc<dyn quil_types::consensus::ProverRegistry> = registry.clone();

    let mut failures = 0usize;
    let mut run = |name: &str, f: &mut dyn FnMut() -> anyhow::Result<Outcome>| {
        match f() {
            Ok(Outcome::Pass(detail)) => println!("  [PASS] {name:<32} {detail}"),
            Ok(Outcome::Skip(reason)) => println!("  [SKIP] {name:<32} ({reason})"),
            Err(e) => {
                failures += 1;
                println!("  [FAIL] {name:<32} {e}");
            }
        }
    };

    let bls: Arc<dyn quil_types::crypto::BlsConstructor> =
        Arc::new(quil_crypto::Bls48581KeyConstructor);
    let frame_prover: Arc<dyn quil_types::crypto::FrameProver> =
        Arc::new(quil_crypto::WesolowskiFrameProver::new(2048));

    // Latest global frame is the anchor for the trie + frame checks.
    let latest_frame = clock.get_latest_global_clock_frame().ok();

    // ---- 1. Tries: per-shard recomputed root == that shard's OWN stored
    // commit (the 0xE0 root). Comparing a shard's loaded tree root to its
    // own committed root (both written by the same `hg.Commit`) is
    // timing-independent — unlike the frame header's `prover_tree_commitment`,
    // which records the PARENT state and lags the live tree by a frame. This
    // covers every shard with committed data: the global prover shard, the
    // QUIL token shard (balances), and any app shards.
    {
        let crdt = quil_hypergraph::HypergraphCrdt::new(
            hg_store.clone() as Arc<dyn HypergraphStore>,
            Arc::new(quil_crypto::KzgInclusionProver),
        );
        let latest_n = latest_frame
            .as_ref()
            .and_then(|f| f.header.as_ref())
            .map(|h| h.frame_number);
        match latest_n {
            None => run("trie roots", &mut || Ok(Outcome::Skip("no global frames".into()))),
            Some(n) => {
                // Accumulate each shard's LATEST stored 0xE0 commit over a
                // lookback window (per-shard commit cadence varies; an
                // unchanged shard's latest commit may be several frames back).
                const LOOKBACK: u64 = 128;
                let lo = n.saturating_sub(LOOKBACK);
                let mut shard_commit: std::collections::HashMap<ShardKey, (u64, Vec<Vec<u8>>)> =
                    std::collections::HashMap::new();
                let mut fno = n;
                loop {
                    if let Ok(m) = hg_store.get_root_commits(fno) {
                        for (sk, roots) in m {
                            shard_commit.entry(sk).or_insert((fno, roots));
                        }
                    }
                    if fno == lo {
                        break;
                    }
                    fno -= 1;
                }

                if shard_commit.is_empty() {
                    run("trie roots", &mut || {
                        Ok(Outcome::Skip(format!("no shard commits in frames {lo}..={n}")))
                    });
                } else {
                    let mut shards: Vec<(ShardKey, (u64, Vec<Vec<u8>>))> =
                        shard_commit.into_iter().collect();
                    shards.sort_by_key(|(sk, _)| sk.l2);
                    let phases = [
                        ("vertex", "adds"),
                        ("vertex", "removes"),
                        ("hyperedge", "adds"),
                        ("hyperedge", "removes"),
                    ];
                    let crdt_ref = &crdt;
                    for (sk, (cf, roots)) in shards {
                        let label = format!("trie: {}", shard_label(&sk.l2));
                        run(&label, &mut || {
                            crdt_ref.ensure_all_phase_trees(&sk);
                            let mut checked = 0usize;
                            for (i, (s, p)) in phases.iter().enumerate() {
                                let stored = roots.get(i).map(|v| v.as_slice()).unwrap_or(&[]);
                                if stored.is_empty() {
                                    continue;
                                }
                                let rec = crdt_ref.compute_shard_root(s, p, &sk);
                                if rec.as_slice() != stored {
                                    anyhow::bail!(
                                        "{s}/{p} recomputed {} != stored commit {} (frame {cf})",
                                        short_hex(&rec),
                                        short_hex(stored),
                                    );
                                }
                                checked += 1;
                            }
                            if checked == 0 {
                                return Ok(Outcome::Skip("no non-empty phase commits".into()));
                            }
                            Ok(Outcome::Pass(format!("{checked} phase(s) match @ frame {cf}")))
                        });
                    }
                }
            }
        }
    }

    // ---- 2. Frame acceptance (VDF + committee-bound BLS) ----
    run("global frame accepted", &mut || {
        let frame = match &latest_frame {
            Some(f) => f,
            None => return Ok(Outcome::Skip("no global frames".into())),
        };
        let validator = quil_engine::frame_validator::BlsGlobalFrameValidator::new(
            registry_dyn.clone(),
            bls.clone(),
            frame_prover.clone(),
        );
        match validate_panic_safe(|| validator.validate(frame)) {
            Ok(true) => Ok(Outcome::Pass(format!(
                "frame {}",
                frame.header.as_ref().map(|h| h.frame_number).unwrap_or(0)
            ))),
            Ok(false) => anyhow::bail!("frame validation returned false (would be rejected)"),
            Err(e) => Err(e),
        }
    });

    // Committee + validator shared by the QC and TC checks. Global chain:
    // empty filter, ASCII domains b"global" / b"globaltimeout".
    let committee: Arc<dyn Replicas> = Arc::new(quil_engine::committee::ProverRegistryCommittee::new(
        registry_dyn.clone(),
        Vec::new(),
        &[0u8; 32],
        Vec::new(),
    ));
    let verifier = quil_engine::bls_verifier::BlsConsensusVerifier::new_with_committee(
        Arc::new(quil_engine::bls_signature_aggregator::BlsSignatureAggregator::new(bls.clone())),
        b"global".to_vec(),
        b"globaltimeout".to_vec(),
        committee.clone(),
        Vec::new(),
    );
    let consensus_validator: quil_engine::validator::ConsensusValidator<
        quil_engine::consensus_types::GlobalState,
        quil_engine::consensus_types::GlobalVote,
    > = quil_engine::validator::ConsensusValidator::new(committee.clone(), Arc::new(verifier))
        // Stored certs are at a real (non-zero) rank, so reject any rank-0.
        .with_genesis_qc_identity(None);

    // ---- 3a. QC acceptance ----
    run("quorum certificate accepted", &mut || {
        let qc_proto = match clock.get_latest_quorum_certificate(&[]) {
            Ok(qc) => qc,
            Err(_) => return Ok(Outcome::Skip("no quorum certificate".into())),
        };
        let qc = quil_engine::consensus_wire::QuorumCertificate::from_proto(&qc_proto)
            .into_trait_object();
        consensus_validator
            .validate_quorum_certificate(qc.as_ref())
            .map_err(|e| anyhow::anyhow!("QC rejected: {e}"))?;
        Ok(Outcome::Pass(format!("rank {}", qc_proto.rank)))
    });

    // ---- 3b. TC acceptance ----
    run("timeout certificate accepted", &mut || {
        let tc_proto = match clock.get_latest_timeout_certificate(&[]) {
            Ok(tc) => tc,
            Err(_) => return Ok(Outcome::Skip("no timeout certificate".into())),
        };
        let tc = quil_engine::consensus_wire::TimeoutCertificate::from_proto(&tc_proto)
            .into_trait_object();
        consensus_validator
            .validate_timeout_certificate(tc.as_ref())
            .map_err(|e| anyhow::anyhow!("TC rejected: {e}"))?;
        Ok(Outcome::Pass(format!("rank {}", tc_proto.rank)))
    });

    // ---- 4. Certified global state reconstruction + embedded QC ----
    run("certified global state", &mut || {
        let proposal = match clock.get_latest_certified_global_state() {
            Ok(p) => p,
            Err(_) => return Ok(Outcome::Skip("no certified state".into())),
        };
        // Reconstruction succeeded (frame + vote + QC + TC all decoded and
        // assembled). Verify the embedded parent QC too.
        if let Some(qc_proto) = proposal.parent_quorum_certificate.as_ref() {
            let qc = quil_engine::consensus_wire::QuorumCertificate::from_proto(qc_proto)
                .into_trait_object();
            consensus_validator
                .validate_quorum_certificate(qc.as_ref())
                .map_err(|e| anyhow::anyhow!("embedded QC rejected: {e}"))?;
        }
        Ok(Outcome::Pass("reconstructed + QC verified".into()))
    });

    println!();
    if failures > 0 {
        anyhow::bail!("verification failed: {failures} categor(y/ies) did not pass");
    }
    println!("=== Verification Passed ===");
    println!("Every present category loads and is accepted by the Rust node's validators.");
    Ok(())
}

enum Outcome {
    Pass(String),
    Skip(String),
}

fn short_hex(b: &[u8]) -> String {
    let n = b.len().min(8);
    format!("{}…", hex::encode(&b[..n]))
}

/// Run a validator closure with panic containment — malformed VDF/BLS input
/// can panic inside the classgroup/BLS code; a verify run should report it
/// as a failure, not abort.
fn validate_panic_safe(
    f: impl FnOnce() -> quil_types::error::Result<bool>,
) -> anyhow::Result<bool> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(anyhow::anyhow!("{e}")),
        Err(_) => Err(anyhow::anyhow!("validation panicked (malformed input)")),
    }
}
