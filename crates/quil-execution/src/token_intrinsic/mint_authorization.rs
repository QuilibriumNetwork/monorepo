//! Global mint authorization record for later app-side consumption.
//! Record construction alone confers no authority: only a membership proof
//! against a consensus-authenticated global root can authorize app outputs.
use quil_lattice_ct::confidential::{
    transfer::{parameter_context, Output},
    MAX_PRIVATE_COINS,
};
use quil_types::error::{QuilError, Result};
#[cfg(test)]
use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
use sha3::{Digest, Sha3_256, Sha3_384};

/// Stable identity shared by global execution and the claiming wallet.
/// Signatures and proof bytes are excluded from this identity.
pub fn receipt_address(s: &quil_lattice_ct::confidential::mint::MintStatement) -> Result<[u8; 32]> {
    let context = s.context_bytes().map_err(|_| invalid())?;
    let mut bytes = Vec::from(b"quil/mint/authorization/v4\0".as_slice());
    bytes.extend_from_slice(&parameter_context(&s.network, &s.application));
    bytes.extend_from_slice(&Sha3_256::digest(context));
    quil_crypto::poseidon::hash_bytes_to_32(&bytes)
}

/// Build a claim only after checking the receipt's exact authorization fields.
/// The returned root is node-supplied; consensus admission resolves it again.
pub fn claim_from_witness(
    s: &quil_lattice_ct::confidential::mint::MintStatement,
    witness: quil_types::store::MintAuthorizationWitnessData,
) -> Result<quil_lattice_ct::confidential::mint_claim::MintClaim> {
    if s.application != crate::domains::QUIL_TOKEN { return Err(invalid()); }
    if !witness.found {
        // Not yet visible at a global root this node retains; retry later.
        return Err(QuilError::ExecutionUnavailable(
            "mint authorization not yet finalized at a retained global root".into(),
        ));
    }
    let root = witness.global_root.as_slice().try_into().map_err(|_| invalid())?;
    let receipt = receipt_address(s)?;
    verify_membership(&s.network, &s.application, &receipt, &s.outputs, s.fee, &root, &witness.forest_proof)?;
    Ok(quil_lattice_ct::confidential::mint_claim::MintClaim {
        network: s.network, application: s.application, cited_global_frame: witness.cited_frame,
        global_root: root, receipt, fee: s.fee, outputs: s.outputs.clone(), forest_proof: witness.forest_proof,
    })
}

fn invalid() -> QuilError {
    QuilError::InvalidArgument("invalid mint authorization".into())
}

pub(crate) fn fields(
    network: &[u8; 32],
    application: &[u8; 32],
    outputs: &[Output],
    fee: u128,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    if outputs.is_empty() || outputs.len() > MAX_PRIVATE_COINS {
        return Err(invalid());
    }
    let context = parameter_context(network, application);
    let mut hash = Sha3_384::new();
    hash.update(b"quil/mint/authorized-outputs/v4\0");
    hash.update(context);
    hash.update((outputs.len() as u16).to_le_bytes());
    for output in outputs {
        hash.update(output.commitment.to_bytes());
        hash.update(output.owner);
        hash.update(output.memo);
    }
    let mut tag = b"quil/mint/authorization-record/v4\0".to_vec();
    tag.extend_from_slice(&context);
    let kind = quil_crypto::poseidon::hash_bytes_to_32(&tag)?;
    Ok(vec![
        (vec![0xff; 32], kind.to_vec()),
        (vec![0], context.to_vec()),
        (vec![4], hash.finalize().to_vec()),
        (vec![8], fee.to_be_bytes().to_vec()),
    ])
}

// Production mint admission needs this only with native proofs; tests also
// construct authorization records to exercise membership verification.
#[cfg(any(feature = "native-proof", test))]
pub(crate) fn create_record(
    network: &[u8; 32],
    application: &[u8; 32],
    outputs: &[Output],
    fee: u128,
) -> Result<Vec<u8>> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    for (key, value) in fields(network, application, outputs, fee)? {
        tree.insert(&key, &value, &[], &num_bigint::BigInt::from(value.len()))?;
    }
    quil_tries::serialize_go_tree(tree.root.as_ref())
        .map_err(|_| QuilError::ExecutionUnavailable("cannot encode mint authorization".into()))
}

/// Authenticate the exact authorized outputs, without consuming the receipt.
/// App execution must separately enforce its global-frame bound and one-time
/// consumption. This helper neither creates coins nor debits rewards.
pub fn verify_membership(
    network: &[u8; 32],
    application: &[u8; 32],
    receipt: &[u8; 32],
    outputs: &[Output],
    fee: u128,
    root: &[u8; 32],
    proof: &[u8],
) -> Result<()> {
    if proof.len() > super::reward_witness::MAX_REWARD_PROOF_BYTES
        || proof.get(..4) != Some([1u8, 0, 0, 0].as_slice())
    {
        return Err(invalid());
    }
    let membership = quil_forest::MembershipProof::from_bytes(proof).map_err(|_| invalid())?;
    let mut address = crate::domains::GLOBAL.to_vec();
    address.extend_from_slice(receipt);
    if membership.inputs.len() != 1 || membership.inputs[0].vertex_address != address {
        return Err(invalid());
    }
    quil_forest::verify_vertex_membership(
        root,
        &membership.inputs[0],
        &fields(network, application, outputs, fee)?,
    )
    .map_err(|_| invalid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_lattice_ct::confidential::{transfer::MEMO_BYTES, AmountOpening, CommitmentKey};

    #[test]
    fn mint_authorization_binds_destination_outputs_fee_and_receipt() {
        let network = [1; 32];
        let app = crate::domains::QUIL_TOKEN;
        let context = parameter_context(&network, &app);
        let key = CommitmentKey::derive(&context);
        let opening = AmountOpening::from_seed(&context, &[2; 32]);
        let outputs = vec![
            Output {
                commitment: key.commit(7, &opening),
                owner: [3; IDENTITY_BYTES],
                memo: [4; MEMO_BYTES],
            },
            Output {
                commitment: key.commit(9, &opening),
                owner: [5; IDENTITY_BYTES],
                memo: [6; MEMO_BYTES],
            },
        ];
        // Structural statement only: native validity is covered by the full mint test.
        let statement = quil_lattice_ct::confidential::mint::MintStatement {
            network, application: app, cited_frame: 1, reward_root: [8; 32], fee: 2,
            claims: vec![quil_lattice_ct::confidential::mint::RewardClaim {
                owner: [8; 32], value: 18, public_key: [0; 897], forest_proof: vec![1],
            }], outputs: outputs.clone(),
        };
        let receipt = receipt_address(&statement).unwrap();
        let blob = create_record(&network, &app, &outputs, 2).unwrap();
        let forest = quil_forest::Forest::in_memory();
        let root = forest
            .commit_shard_phase_raw(
                b"authorization-test",
                quil_forest::Phase::VertexAdds,
                0,
                [(
                    receipt.to_vec(),
                    quil_tries::vertex_leaf_value(&blob).unwrap(),
                )],
            )
            .unwrap();
        let mut address = crate::domains::GLOBAL.to_vec();
        address.extend_from_slice(&receipt);
        let membership = forest
            .build_vertex_membership_proof(
                b"authorization-test",
                quil_forest::Phase::VertexAdds,
                0,
                &address,
                &blob,
            )
            .unwrap();
        let proof = quil_forest::MembershipProof {
            inputs: vec![membership],
        }
        .to_bytes();
        let witness = quil_types::store::MintAuthorizationWitnessData {
            found: true, cited_frame: 9, global_root: root.to_vec(), forest_proof: proof.clone(),
        };
        let from_witness = claim_from_witness(&statement, witness.clone()).unwrap();
        assert_eq!(from_witness.outputs, outputs);
        assert_eq!(from_witness.receipt, receipt);
        let mut bad = witness.clone();
        bad.found = false;
        assert!(claim_from_witness(&statement, bad).is_err());
        let mut bad = witness.clone();
        bad.global_root.pop();
        assert!(claim_from_witness(&statement, bad).is_err());
        let mut bad = witness.clone();
        bad.forest_proof.resize(32 * 1024 + 1, 0);
        assert!(claim_from_witness(&statement, bad).is_err());
        let mut other = statement.clone();
        other.outputs[0].memo[0] ^= 1;
        assert!(claim_from_witness(&other, witness.clone()).is_err());
        other = statement.clone();
        other.claims[0].value += 1;
        assert!(claim_from_witness(&other, witness).is_err());
        let claim = quil_lattice_ct::confidential::mint_claim::MintClaim {
            network,
            application: app,
            cited_global_frame: 9,
            global_root: root,
            receipt,
            fee: 2,
            outputs: outputs.clone(),
            forest_proof: proof.clone(),
        };
        let claim_bytes = claim.encode().unwrap();
        let decoded = quil_lattice_ct::confidential::mint_claim::MintClaim::decode(
            &claim_bytes,
            &network,
            &app,
        )
        .unwrap();
        verify_membership(
            &decoded.network,
            &decoded.application,
            &decoded.receipt,
            &decoded.outputs,
            decoded.fee,
            &root,
            &decoded.forest_proof,
        )
        .unwrap();
        assert_eq!(
            claim_bytes.len(),
            170 + 2 * (10368 + IDENTITY_BYTES + MEMO_BYTES) + proof.len()
        );
        assert!(proof.len() < super::super::reward_witness::MAX_REWARD_PROOF_BYTES);
        #[cfg(feature = "native-proof")]
        {
            use super::super::{
                mint_claim::verify_from_clock, state::SnapshotLimits,
            };
            use quil_types::{
                execution::FrameExecutionContext,
                proto::global::{GlobalFrame, GlobalFrameHeader},
            };
            use std::sync::Arc;
            let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
            let context = FrameExecutionContext {
                frame_number: 2,
                finalized_global_frame: Some(9), venue: None, shard: quil_types::execution::ShardPath::WHOLE
            };
            let verify =
                |context| verify_from_clock(clock.as_ref(), context, &network, &app, &claim_bytes, 2);
            assert!(matches!(
                verify(context),
                Err(QuilError::ExecutionUnavailable(_))
            ));
            clock.seed_frame(GlobalFrame {
                header: Some(GlobalFrameHeader {
                    frame_number: 9,
                    prover_tree_commitment: root.to_vec(),
                    ..Default::default()
                }),
                ..Default::default()
            });
            assert!(matches!(
                verify(FrameExecutionContext {
                    finalized_global_frame: None,
                    ..context
                }),
                Err(QuilError::ExecutionUnavailable(_))
            ));
            assert!(matches!(
                verify(FrameExecutionContext {
                    finalized_global_frame: Some(8),
                    ..context
                }),
                Err(QuilError::InvalidArgument(_))
            ));
            let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
                Arc::new(quil_hypergraph::testing::MemStore::new()),
                Arc::new(quil_types::crypto::NoopInclusionProver),
            ));
            let state = crate::hypergraph_state::HypergraphState::new(crdt.clone());
            let limits = SnapshotLimits {
                max_coins: 8,
                max_depth: 32,
                max_nodes: 128,
            };
            // A real typed authorization membership proof can be consumed
            // through either venue. This fixture does not run native mint
            // proving; the global root above is seeded explicitly.
            use quil_types::execution::ShardExecutionEngine;
            use crate::engines::{ExecutionMode, TokenExecutionEngine};
            for mode in [ExecutionMode::Global, ExecutionMode::Application] {
                let local = Arc::new(quil_hypergraph::HypergraphCrdt::new(
                    Arc::new(quil_hypergraph::testing::MemStore::new()),
                    Arc::new(quil_types::crypto::NoopInclusionProver),
                ));
                let view = crate::hypergraph_state::HypergraphState::new(local.clone());
                let stubs = crate::testing::NoopExecutionCrypto::new();
                let engine = TokenExecutionEngine::new_with_state(mode,
                    Arc::new(quil_types::crypto::NoopInclusionProver), local,
                    stubs.key_manager, clock.clone(),
                ).with_token_proofs(super::super::dispatch::TokenPolicy {
                    network,
                    limits: quil_lattice_ct::confidential::transfer::CompileLimits {
                        max_inputs: 2, max_outputs: 2, max_depth: 32,
                    },
                    snapshots: limits,
                    native_budget: quil_lattice_ct::confidential::relation::backend::native::NativeBudget {
                        max_native_bytes: 0,
                    },
                }).unwrap();
                let message = crate::message_envelope::CanonicalMessageRequest::wrap(claim_bytes.clone())
                    .unwrap().to_canonical_bytes().unwrap();
                engine.validate_message(10, &app, &message).unwrap();
                // A shard holding only part of the application runs it too: it
                // verifies and relays, and the global frame decides. Nothing is
                // written there, whatever part of the application it holds.
                for partial in [
                    quil_types::execution::ShardPath::from_bits(&[false]),
                    quil_types::execution::ShardPath::from_bits(&[true, false, true, true, false, true]),
                ] {
                    engine.process_message_with_context(FrameExecutionContext {
                        frame_number: 10,
                        finalized_global_frame: Some(9),
                        venue: Some(quil_types::execution::Venue::Application), shard: partial,
                    }, &0.into(), &app, &message).unwrap();
                    assert!(super::super::roots::read_current(&view, &network, &app).unwrap().is_none());
                }
                // An app-shard frame names its venue: replayed by a node whose
                // engine is the global venue (an archive), it only verifies —
                // it never commits inline outside a global frame.
                engine.process_message_with_context(FrameExecutionContext {
                    frame_number: 10, finalized_global_frame: Some(9), shard: quil_types::execution::ShardPath::WHOLE,
                    venue: Some(quil_types::execution::Venue::Application),
                }, &0.into(), &app, &message).unwrap();
                assert!(super::super::roots::read_current(&view, &network, &app).unwrap().is_none());
                if mode == ExecutionMode::Global {
                    // An explicit anchor is authoritative in either venue and
                    // bounds the citation: anchor 8 cannot admit frame 9's root.
                    engine.process_message_with_context(FrameExecutionContext {
                        frame_number: 100, finalized_global_frame: Some(8), venue: None, shard: quil_types::execution::ShardPath::WHOLE
                    }, &0.into(), &app, &message).unwrap_err();
                    assert!(super::super::roots::read_current(&view, &network, &app).unwrap().is_none());
                }
                engine.process_message_with_context(FrameExecutionContext {
                    frame_number: 10,
                    finalized_global_frame: if mode == ExecutionMode::Global { None } else { Some(9) }, venue: None, shard: quil_types::execution::ShardPath::WHOLE
                }, &0.into(), &app, &message).unwrap();
                let accepted = super::super::roots::read_current(&view, &network, &app).unwrap();
                let replay = engine.process_message_with_context(FrameExecutionContext {
                    frame_number: 11, finalized_global_frame: Some(9), venue: None, shard: quil_types::execution::ShardPath::WHOLE
                }, &0.into(), &app, &message);
                if mode == ExecutionMode::Global {
                    // The global venue commits inline: outputs placed, and the
                    // receipt consumed once.
                    assert!(accepted.is_some());
                    replay.unwrap_err();
                } else {
                    // An app shard only verifies and relays; the global commit
                    // decides the receipt's consumption, so a replay verifies
                    // too and nothing is written locally.
                    assert!(accepted.is_none());
                    replay.unwrap();
                }
                assert_eq!(super::super::roots::read_current(&view, &network, &app).unwrap(), accepted);
            }
            // The claim commits like every other confidential operation; the
            // last app-path group contains two data bits in a full vertex ID.
            let tp = crate::token_engine::TYPE_LATTICE_MINT_CLAIM;
            let commit = |frame| crate::token_intrinsic::commit_apply::commit_and_place(
                &state, frame, &network, &app, tp, &claim_bytes, limits);
            crdt.set_covered_prefix(&quil_tries::get_full_path(&app)).unwrap();
            assert!(matches!(commit(2), Err(QuilError::ExecutionUnavailable(_))));
            assert_eq!(state.changeset_len(), 0);
            crdt.set_covered_prefix(&[]).unwrap();
            // Verification alone decides nothing: it passes as often as it is
            // asked, and the commit is what consumes the receipt.
            verify(context).unwrap();
            assert_eq!(commit(2).unwrap().len(), 2);
            let pending = state.changeset_len();
            let replay = commit(3).unwrap_err();
            assert!(replay.to_string().contains("already decided"), "{replay}");
            state.rollback_to(pending);
            assert_eq!(state.changeset_len(), pending);
            state.commit().unwrap();
            state.abort();
            let replay = commit(4).unwrap_err();
            assert!(replay.to_string().contains("already decided"), "{replay}");
            state.rollback_to(0);
            assert_eq!(state.changeset_len(), 0);
        }
        verify_membership(&network, &app, &receipt, &outputs, 2, &root, &proof).unwrap();
        for (n, a, r, fee) in [
            ([9; 32], app, receipt, 2),
            (network, [9; 32], receipt, 2),
            (network, app, [9; 32], 2),
            (network, app, receipt, 3),
        ] {
            assert!(verify_membership(&n, &a, &r, &outputs, fee, &root, &proof).is_err());
        }
        let mut changed = outputs.clone();
        changed[0].memo[0] ^= 1;
        assert!(verify_membership(&network, &app, &receipt, &changed, 2, &root, &proof).is_err());
        let mut changed = outputs.clone();
        changed.reverse();
        assert!(verify_membership(&network, &app, &receipt, &changed, 2, &root, &proof).is_err());
        let mut changed = outputs.clone();
        changed[0].owner[0] ^= 1;
        assert!(verify_membership(&network, &app, &receipt, &changed, 2, &root, &proof).is_err());
        assert!(
            verify_membership(&network, &app, &receipt, &outputs, 2, &[9; 32], &proof).is_err()
        );
        assert!(verify_membership(
            &network,
            &app,
            &receipt,
            &outputs,
            2,
            &root,
            &proof[..proof.len() - 1]
        )
        .is_err());
        assert!(fields(&network, &app, &[], 2).is_err());
        eprintln!(
            "mint_authorization_record bytes={} proof_bytes={} claim_bytes={}",
            blob.len(),
            proof.len(),
            claim_bytes.len()
        );
    }
}

/// The canonical GLOBAL prover-shard root committed by global frame
/// `cited_frame`, which must not follow the executing frame's finalized global
/// anchor. Missing local history is an execution failure (the frame is held
/// for retry), not a deterministic rejection.
pub(crate) fn clock_reward_root(
    clock: &dyn quil_types::store::ClockStore,
    cited_frame: u64,
    finalized_global_frame: u64,
) -> quil_types::error::Result<[u8; 32]> {
    use quil_types::error::QuilError;
    let unavailable = |message: String| QuilError::ExecutionUnavailable(format!("mint: {message}"));
    if cited_frame > finalized_global_frame {
        return Err(QuilError::InvalidArgument(format!(
            "mint: future global reward frame (cited {cited_frame}, anchor {finalized_global_frame})"
        )));
    }
    let frame = clock
        .get_global_clock_frame(cited_frame)
        .map_err(|e| unavailable(format!("cannot load canonical global reward frame: {e}")))?;
    let header = frame.header.ok_or_else(|| unavailable("global reward frame has no header".into()))?;
    if header.frame_number != cited_frame {
        return Err(unavailable("global reward frame number mismatch".into()));
    }
    header
        .prover_tree_commitment
        .as_slice()
        .try_into()
        .map_err(|_| unavailable("global reward root is not 32 bytes".into()))
}
