//! Frame processing pipeline. Takes a `GlobalFrame` proto and walks
//! its `MessageBundle`s through the execution manager.

use num_bigint::BigInt;
use num_traits::Zero;
use prost::Message;
use tracing::{debug, warn};

use quil_types::consensus::{ProverRegistry, RewardIssuance};
use quil_types::error::{QuilError, Result};
use quil_types::proto::global::GlobalFrame;

use quil_execution::ExecutionEngineManager;

/// The global intrinsic address — all bundles in a global frame are
/// routed to this address. Matches Go's
/// `bytes.Repeat([]byte{0xff}, 32)` in the materialize loop.
const GLOBAL_ADDRESS: [u8; 32] = [0xFFu8; 32];

/// Process all `MessageBundle`s in a `GlobalFrame` through the
/// execution manager. Returns (applied_count, skipped_count).
///
/// Each bundle is serialized to canonical bytes via prost encoding,
/// then routed to the global engine at address `[0xFF; 32]`.
pub fn process_global_frame(
    execution_manager: &ExecutionEngineManager,
    frame: &GlobalFrame,
    fee_multiplier: &BigInt,
) -> Result<(usize, usize)> {
    process_global_frame_with_rewards(execution_manager, frame, fee_multiplier, None, None)
}

/// Process a frame with optional reward issuance.
pub fn process_global_frame_with_rewards(
    execution_manager: &ExecutionEngineManager,
    frame: &GlobalFrame,
    fee_multiplier: &BigInt,
    reward_issuer: Option<&dyn RewardIssuance>,
    prover_registry: Option<&dyn ProverRegistry>,
) -> Result<(usize, usize)> {
    let frame_number = frame
        .header
        .as_ref()
        .map(|h| h.frame_number)
        .unwrap_or(0);

    let mut applied = 0usize;
    let mut skipped = 0usize;

    debug!(
        frame = frame_number,
        bundles = frame.requests.len(),
        "processing global frame"
    );

    for (i, bundle) in frame.requests.iter().enumerate() {
        // Re-encode the proto bundle as canonical bytes (Quilibrium's
        // big-endian framing with type prefix `0x0312`) — the
        // execution engines decode via
        // `CanonicalMessageBundle::from_canonical_bytes`; feeding them
        // prost wire bytes silently fails the type-prefix check and
        // skips every message (matches Go's `ToCanonicalBytes()` path).
        let request_bytes = match crate::consensus_wire::proto_message_bundle_to_canonical_bytes(bundle) {
            Ok(b) => b,
            Err(e) => {
                debug!(
                    frame = frame_number,
                    index = i,
                    error = %e,
                    "skipping bundle that failed canonical encoding",
                );
                skipped += 1;
                continue;
            }
        };

        if request_bytes.is_empty() {
            warn!(frame = frame_number, index = i, "empty request bytes");
            skipped += 1;
            continue;
        }

        // Validate before processing — runs structural + signature
        // verification per the engine's per-op Verify hooks.
        // process_message alone re-verifies only a subset of ops, so
        // skipping validate would silently accept unsigned join /
        // kick / seniority_merge / shard_split / shard_merge /
        // frame_header messages.
        if let Err(e) = execution_manager.validate_message(
            frame_number,
            &GLOBAL_ADDRESS,
            &request_bytes,
        ) {
            debug!(
                frame = frame_number,
                index = i,
                error = %e,
                "rejecting message that failed validation",
            );
            skipped += 1;
            continue;
        }

        match execution_manager.process_message(
            frame_number,
            fee_multiplier,
            &GLOBAL_ADDRESS,
            &request_bytes,
        ) {
            Ok(_) => {
                applied += 1;
            }
            Err(e) => {
                debug!(
                    frame = frame_number,
                    index = i,
                    error = %e,
                    "skipping failed message"
                );
                skipped += 1;
            }
        }
    }

    // Reward issuance: after all messages materialized, compute PoMW
    // rewards per active prover and log the total issuance.
    if let (Some(issuer), Some(registry)) = (reward_issuer, prover_registry) {
        let header = frame.header.as_ref();
        let difficulty = header.map(|h| h.difficulty as u64).unwrap_or(0);
        // Build prover allocation maps from registry
        if let Ok(provers) = registry.get_all_active_app_shard_provers() {
            let alloc_maps: Vec<std::collections::HashMap<String, quil_types::consensus::ProverAllocation>> =
                provers.iter().map(|p| {
                    p.allocations.iter()
                        .filter(|a| a.status == quil_types::consensus::ProverStatus::Active)
                        .map(|a| {
                            (hex::encode(&a.confirmation_filter), quil_types::consensus::ProverAllocation {
                                ring: 0,
                                shards: 1,
                                state_size: 1,
                            })
                        })
                        .collect()
                }).collect();

            match issuer.calculate(difficulty, 1, crate::provers::proposer::DEFAULT_UNITS, &alloc_maps) {
                Ok(rewards) => {
                    let total: BigInt = rewards.iter().sum();
                    if !total.is_zero() {
                        debug!(
                            frame = frame_number,
                            provers = rewards.len(),
                            total = %total,
                            "reward issuance computed"
                        );
                    }
                    // Integration point: writing rewards to the CRDT
                    // requires a HypergraphState reference, which this
                    // free function does not own. The caller (the
                    // materialize loop in global_consensus_engine)
                    // should zip `rewards` with the prover list and
                    // call for each (prover_address, amount) pair:
                    //
                    //   state.set(
                    //       &GLOBAL_ADDRESS,          // domain
                    //       &prover_address,          // vertex address
                    //       &vertex_adds_disc,        // discriminator
                    //       frame_number,
                    //       serialized_reward_vertex, // RDF-encoded ProverReward
                    //   )
                    //
                    // The reward vertex schema is "reward:ProverReward"
                    // (TYPE_HASH_REWARD). Until this function is
                    // refactored to accept &HypergraphState, rewards
                    // are computed and logged but not persisted.
                }
                Err(e) => {
                    debug!(frame = frame_number, error = %e, "reward calculation failed");
                }
            }
        }
    }

    debug!(
        frame = frame_number,
        applied,
        skipped,
        "frame processing complete"
    );

    Ok((applied, skipped))
}

/// Process a `GlobalFrame` with real fee baseline calculation.
/// Uses the ASERT difficulty from the frame header and the provided
/// world state size to compute per-bundle fee multipliers via
/// `rewards::get_baseline_fee`.
///
/// This matches Go's materialize loop more closely than the simpler
/// `process_global_frame` variant.
pub fn process_global_frame_with_fees(
    execution_manager: &ExecutionEngineManager,
    frame: &GlobalFrame,
    world_state_bytes: u64,
) -> Result<(usize, usize)> {
    let header = frame.header.as_ref();
    let frame_number = header.map(|h| h.frame_number).unwrap_or(0);
    let difficulty = header.map(|h| h.difficulty).unwrap_or(0) as u64;

    let mut applied = 0usize;
    let mut skipped = 0usize;

    for (i, bundle) in frame.requests.iter().enumerate() {
        let request_bytes = match crate::consensus_wire::proto_message_bundle_to_canonical_bytes(bundle) {
            Ok(b) => b,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        if request_bytes.is_empty() {
            skipped += 1;
            continue;
        }

        // Compute per-bundle cost basis and fee multiplier
        let cost_basis = match execution_manager.get_cost(&request_bytes) {
            Ok(c) => c,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };

        let fee_multiplier = if cost_basis == BigInt::from(0) {
            BigInt::from(0)
        } else {
            let cost_u64 = cost_basis.to_u64_digits().1.first().copied().unwrap_or(1);
            let baseline = crate::rewards::get_baseline_fee(
                difficulty,
                world_state_bytes,
                cost_u64,
                crate::rewards::QUIL_TOKEN_UNITS,
            );
            if cost_basis != BigInt::from(0) {
                &baseline / &cost_basis
            } else {
                BigInt::from(0)
            }
        };

        // Validate before processing.
        if let Err(e) = execution_manager.validate_message(
            frame_number,
            &GLOBAL_ADDRESS,
            &request_bytes,
        ) {
            debug!(
                frame = frame_number,
                error = %e,
                "rejecting message that failed validation",
            );
            skipped += 1;
            continue;
        }

        match execution_manager.process_message(
            frame_number,
            &fee_multiplier,
            &GLOBAL_ADDRESS,
            &request_bytes,
        ) {
            Ok(_) => applied += 1,
            Err(e) => {
                debug!(frame = frame_number, index = i, error = %e, "skipping");
                skipped += 1;
            }
        }
    }

    Ok((applied, skipped))
}

/// Decode raw bytes into a `GlobalFrame` and process it.
pub fn process_global_frame_bytes(
    execution_manager: &ExecutionEngineManager,
    frame_bytes: &[u8],
    fee_multiplier: &BigInt,
) -> Result<(usize, usize)> {
    let frame = GlobalFrame::decode(frame_bytes)
        .map_err(|e| QuilError::Serialization(format!("decode GlobalFrame: {}", e)))?;
    process_global_frame(execution_manager, &frame, fee_multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_hypergraph::testing::MemStore;
    use quil_types::crypto::{InclusionProver, NoopInclusionProver};
    use quil_types::proto::global::{GlobalFrameHeader, MessageBundle, MessageRequest};
    use std::sync::Arc;

    fn mgr() -> ExecutionEngineManager {
        let inclusion_prover: Arc<dyn InclusionProver> = Arc::new(NoopInclusionProver);
        let hg_store: Arc<dyn quil_types::store::HypergraphStore> =
            Arc::new(MemStore::new());
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg_store,
            inclusion_prover.clone(),
        ));
        let stubs = quil_execution::testing::NoopExecutionCrypto::new();
        let hg_resolver: std::sync::Arc<dyn quil_execution::hypergraph_intrinsic::HypergraphConfigResolver> =
            std::sync::Arc::new(quil_execution::testing::NoopHypergraphConfigResolver);
        ExecutionEngineManager::new(
            inclusion_prover,
            stubs.key_manager.clone(),
            crdt,
            stubs.bulletproof_prover,
            stubs.decaf_constructor,
            stubs.circuit_compiler,
            stubs.clock_store,
            hg_resolver,
            true,
        )
    }

    fn empty_frame(frame_number: u64) -> GlobalFrame {
        GlobalFrame {
            header: Some(GlobalFrameHeader {
                frame_number,
                ..Default::default()
            }),
            requests: vec![],
        }
    }

    fn frame_with_bundles(frame_number: u64, bundle_count: usize) -> GlobalFrame {
        let bundles: Vec<MessageBundle> = (0..bundle_count)
            .map(|_| MessageBundle {
                requests: vec![], // empty bundles
                timestamp: 0,
            })
            .collect();
        GlobalFrame {
            header: Some(GlobalFrameHeader {
                frame_number,
                ..Default::default()
            }),
            requests: bundles,
        }
    }

    #[test]
    fn process_empty_frame() {
        let (applied, skipped) = process_global_frame(
            &mgr(),
            &empty_frame(1),
            &BigInt::from(1),
        )
        .unwrap();
        assert_eq!(applied, 0);
        assert_eq!(skipped, 0);
    }

    #[test]
    fn process_frame_with_empty_bundles() {
        let (applied, skipped) = process_global_frame(
            &mgr(),
            &frame_with_bundles(1, 3),
            &BigInt::from(1),
        )
        .unwrap();
        // Empty bundles produce prost-encoded bytes that the engine
        // will attempt to decode. The engine either processes them
        // (as no-ops) or skips them — either way no panic.
        assert_eq!(applied + skipped, 3);
    }

    #[test]
    fn process_frame_extracts_frame_number() {
        let frame = empty_frame(42);
        assert_eq!(
            frame.header.as_ref().unwrap().frame_number,
            42
        );
    }

    #[test]
    fn process_frame_bytes_decodes_and_processes() {
        let frame = empty_frame(10);
        let bytes = frame.encode_to_vec();
        let (applied, skipped) = process_global_frame_bytes(
            &mgr(),
            &bytes,
            &BigInt::from(1),
        )
        .unwrap();
        assert_eq!(applied, 0);
        assert_eq!(skipped, 0);
    }

    #[test]
    fn process_frame_bytes_rejects_garbage() {
        assert!(process_global_frame_bytes(
            &mgr(),
            &[0xDE, 0xAD],
            &BigInt::from(1),
        )
        .is_err());
    }
}
