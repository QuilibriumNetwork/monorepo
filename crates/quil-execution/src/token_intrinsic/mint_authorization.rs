//! Global mint authorization record for later app-side consumption.
//! Record construction alone confers no authority: only a membership proof
//! against a consensus-authenticated global root can authorize app outputs.
#[cfg(test)]
use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
use quil_lattice_ct::confidential::{
    transfer::{parameter_context, Output},
    MAX_PRIVATE_COINS,
};
use quil_types::error::{QuilError, Result};
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
    if s.application != crate::domains::QUIL_TOKEN {
        return Err(invalid());
    }
    if !witness.found {
        // Not yet visible at a global root this node retains; retry later.
        return Err(QuilError::ExecutionUnavailable(
            "mint authorization not yet finalized at a retained global root".into(),
        ));
    }
    let root = witness
        .global_root
        .as_slice()
        .try_into()
        .map_err(|_| invalid())?;
    let receipt = receipt_address(s)?;
    verify_membership(
        &s.network,
        &s.application,
        &receipt,
        &s.outputs,
        s.fee,
        &root,
        &witness.forest_proof,
    )?;
    Ok(quil_lattice_ct::confidential::mint_claim::MintClaim {
        network: s.network,
        application: s.application,
        cited_global_frame: witness.cited_frame,
        global_root: root,
        receipt,
        fee: s.fee,
        outputs: s.outputs.clone(),
        forest_proof: witness.forest_proof,
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
    verify_membership_with(
        network,
        application,
        receipt,
        outputs,
        fee,
        root,
        proof,
        true,
    )
}

/// [`verify_membership`] under the consensus rule of the claim's anchor:
/// `bind_values` from `quil_types::consensus::vertex_value_binding_active`.
#[allow(clippy::too_many_arguments)]
pub fn verify_membership_with(
    network: &[u8; 32],
    application: &[u8; 32],
    receipt: &[u8; 32],
    outputs: &[Output],
    fee: u128,
    root: &[u8; 32],
    proof: &[u8],
    bind_values: bool,
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
    quil_forest::verify_vertex_membership_with(
        root,
        &membership.inputs[0],
        &fields(network, application, outputs, fee)?,
        bind_values,
    )
    .map_err(|_| invalid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_lattice_ct::confidential::{transfer::MEMO_BYTES, AmountOpening, CommitmentKey};

    /// Rewrite the leaf at `key` to carry `value`, committing its original
    /// value as `hash_target` and trimming the stored (recomputed)
    /// commitment so the blob keeps its length.
    fn with_unbound_value(blob: &[u8], key: &[u8], value: &[u8]) -> Vec<u8> {
        fn rewrite(node: &mut quil_tries::VectorCommitmentNode, key: &[u8], value: &[u8]) -> bool {
            match node {
                quil_tries::VectorCommitmentNode::Leaf(leaf) if leaf.key == key => {
                    leaf.hash_target = std::mem::replace(&mut leaf.value, value.to_vec());
                    let keep = leaf.commitment.len() - value.len();
                    leaf.commitment.truncate(keep);
                    true
                }
                quil_tries::VectorCommitmentNode::Leaf(_) => false,
                quil_tries::VectorCommitmentNode::Branch(branch) => branch
                    .children
                    .iter_mut()
                    .flatten()
                    .any(|child| rewrite(child, key, value)),
            }
        }
        let mut root = quil_tries::deserialize_go_tree(blob).unwrap().unwrap();
        assert!(rewrite(&mut root, key, value));
        quil_tries::serialize_go_tree(Some(&root)).unwrap()
    }

    /// A record whose outputs-hash leaf commits the authorized hash as its
    /// `hash_target` keeps the committed record while naming other outputs.
    /// Under the binding rule only the authorized outputs verify.
    #[test]
    fn mint_authorization_rejects_outputs_its_record_does_not_bind() {
        let network = [1; 32];
        let app = crate::domains::QUIL_TOKEN;
        let context = parameter_context(&network, &app);
        let key = CommitmentKey::derive(&context);
        let opening = AmountOpening::from_seed(&context, &[2; 32]);
        let output = |amount: u128, owner: u8| Output {
            commitment: key.commit(amount, &opening),
            owner: [owner; IDENTITY_BYTES],
            memo: [4; MEMO_BYTES],
        };
        let authorized = vec![output(7, 3)];
        let other = vec![output(7_000_000, 5)];
        let receipt = [6; 32];
        let blob = create_record(&network, &app, &authorized, 2).unwrap();
        let other_hash = fields(&network, &app, &other, 2).unwrap()[2].1.clone();
        let forged_blob = with_unbound_value(&blob, &[4], &other_hash);
        let leaf = quil_tries::vertex_leaf_value(&blob).unwrap();
        assert_eq!(quil_tries::vertex_leaf_value(&forged_blob).unwrap(), leaf);
        let forest = quil_forest::Forest::in_memory();
        let root = forest
            .commit_shard_phase_raw(
                b"authorization-test",
                quil_forest::Phase::VertexAdds,
                0,
                [(receipt.to_vec(), leaf)],
            )
            .unwrap();
        let mut address = crate::domains::GLOBAL.to_vec();
        address.extend_from_slice(&receipt);
        let prove = |blob: &[u8]| {
            let membership = forest
                .build_vertex_membership_proof(
                    b"authorization-test",
                    quil_forest::Phase::VertexAdds,
                    0,
                    &address,
                    blob,
                )
                .unwrap();
            quil_forest::MembershipProof {
                inputs: vec![membership],
            }
            .to_bytes()
        };
        let honest = prove(&blob);
        let forged = prove(&forged_blob);
        verify_membership(&network, &app, &receipt, &authorized, 2, &root, &honest).unwrap();
        verify_membership_with(&network, &app, &receipt, &other, 2, &root, &forged, false)
            .expect("the legacy rule reads the unbound outputs hash");
        assert!(verify_membership(&network, &app, &receipt, &other, 2, &root, &forged).is_err());
    }

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
            network,
            application: app,
            cited_frame: 1,
            reward_root: [8; 32],
            fee: 2,
            claims: vec![quil_lattice_ct::confidential::mint::RewardClaim {
                owner: [8; 32],
                value: 18,
                public_key: [0; 897],
                forest_proof: vec![1],
            }],
            outputs: outputs.clone(),
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
            found: true,
            cited_frame: 9,
            global_root: root.to_vec(),
            forest_proof: proof.clone(),
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
            use super::super::{mint_claim::verify_from_clock, state::SnapshotLimits};
            use quil_types::{
                execution::FrameExecutionContext,
                proto::global::{GlobalFrame, GlobalFrameHeader},
            };
            use std::sync::Arc;
            let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
            let context = FrameExecutionContext {
                frame_number: 2,
                finalized_global_frame: Some(9),
                venue: None,
                shard: quil_types::execution::ShardPath::WHOLE,
            };
            let verify = |context| {
                verify_from_clock(clock.as_ref(), context, &network, &app, &claim_bytes, 2)
            };
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
                Err(QuilError::InvalidArgument(_))
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
            use crate::engines::{ExecutionMode, TokenExecutionEngine};
            use quil_types::execution::ShardExecutionEngine;
            for mode in [ExecutionMode::Global, ExecutionMode::Application] {
                let local = Arc::new(quil_hypergraph::HypergraphCrdt::new(
                    Arc::new(quil_hypergraph::testing::MemStore::new()),
                    Arc::new(quil_types::crypto::NoopInclusionProver),
                ));
                let view = crate::hypergraph_state::HypergraphState::new(local.clone());
                let stubs = crate::testing::NoopExecutionCrypto::new();
                let engine = TokenExecutionEngine::new_with_state(
                    mode,
                    Arc::new(quil_types::crypto::NoopInclusionProver),
                    local,
                    stubs.key_manager,
                    clock.clone(),
                )
                .with_token_proofs(super::super::dispatch::TokenPolicy {
                    network,
                    limits: quil_lattice_ct::confidential::transfer::CompileLimits {
                        max_inputs: 2,
                        max_outputs: 2,
                        max_depth: 32,
                    },
                    snapshots: limits,
                    native_budget:
                        quil_lattice_ct::confidential::relation::backend::native::NativeBudget {
                            max_native_bytes: 0,
                        },
                })
                .unwrap();
                let message =
                    crate::message_envelope::CanonicalMessageRequest::wrap(claim_bytes.clone())
                        .unwrap()
                        .to_canonical_bytes()
                        .unwrap();
                engine.validate_message(10, &app, &message).unwrap();
                // A shard holding only part of the application runs it too: it
                // verifies and relays, and the global frame decides. Nothing is
                // written there, whatever part of the application it holds.
                for partial in [
                    quil_types::execution::ShardPath::from_bits(&[false]),
                    quil_types::execution::ShardPath::from_bits(&[
                        true, false, true, true, false, true,
                    ]),
                ] {
                    engine
                        .process_message_with_context(
                            FrameExecutionContext {
                                frame_number: 10,
                                finalized_global_frame: Some(9),
                                venue: Some(quil_types::execution::Venue::Application),
                                shard: partial,
                            },
                            &0.into(),
                            &app,
                            &message,
                        )
                        .unwrap();
                    assert!(super::super::roots::read_current(&view, &network, &app)
                        .unwrap()
                        .is_none());
                }
                // An app-shard frame names its venue: replayed by a node whose
                // engine is the global venue (an archive), it only verifies —
                // it never commits inline outside a global frame.
                engine
                    .process_message_with_context(
                        FrameExecutionContext {
                            frame_number: 10,
                            finalized_global_frame: Some(9),
                            shard: quil_types::execution::ShardPath::WHOLE,
                            venue: Some(quil_types::execution::Venue::Application),
                        },
                        &0.into(),
                        &app,
                        &message,
                    )
                    .unwrap();
                assert!(super::super::roots::read_current(&view, &network, &app)
                    .unwrap()
                    .is_none());
                if mode == ExecutionMode::Global {
                    // An explicit anchor is authoritative in either venue and
                    // bounds the citation: anchor 8 cannot admit frame 9's root.
                    engine
                        .process_message_with_context(
                            FrameExecutionContext {
                                frame_number: 100,
                                finalized_global_frame: Some(8),
                                venue: None,
                                shard: quil_types::execution::ShardPath::WHOLE,
                            },
                            &0.into(),
                            &app,
                            &message,
                        )
                        .unwrap_err();
                    assert!(super::super::roots::read_current(&view, &network, &app)
                        .unwrap()
                        .is_none());
                }
                engine
                    .process_message_with_context(
                        FrameExecutionContext {
                            frame_number: 10,
                            finalized_global_frame: if mode == ExecutionMode::Global {
                                None
                            } else {
                                Some(9)
                            },
                            venue: None,
                            shard: quil_types::execution::ShardPath::WHOLE,
                        },
                        &0.into(),
                        &app,
                        &message,
                    )
                    .unwrap();
                let accepted = super::super::roots::read_current(&view, &network, &app).unwrap();
                let replay = engine.process_message_with_context(
                    FrameExecutionContext {
                        frame_number: 11,
                        finalized_global_frame: Some(9),
                        venue: None,
                        shard: quil_types::execution::ShardPath::WHOLE,
                    },
                    &0.into(),
                    &app,
                    &message,
                );
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
                assert_eq!(
                    super::super::roots::read_current(&view, &network, &app).unwrap(),
                    accepted
                );
            }
            // The claim commits like every other confidential operation; the
            // last app-path group contains two data bits in a full vertex ID.
            let tp = crate::token_engine::TYPE_LATTICE_MINT_CLAIM;
            let commit = |frame| {
                crate::token_intrinsic::commit_apply::commit_and_place(
                    &state,
                    frame,
                    &network,
                    &app,
                    tp,
                    &claim_bytes,
                    limits,
                )
            };
            crdt.set_covered_prefix(&quil_tries::get_full_path(&app))
                .unwrap();
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

    /// A mint authorization record commits the hash of its authorized outputs.
    /// A proof whose outputs-hash leaf carries another hash, with the
    /// authorized hash moved to its `hash_target`, still matches the committed
    /// record; it must not authorize those other outputs.
    #[test]
    fn reproduces_forged_mint_output_accepted() {
        fn rewrite(node: &mut quil_tries::VectorCommitmentNode, key: &[u8], value: &[u8]) -> bool {
            match node {
                quil_tries::VectorCommitmentNode::Leaf(leaf) if leaf.key == key => {
                    leaf.hash_target = std::mem::replace(&mut leaf.value, value.to_vec());
                    let keep = leaf.commitment.len() - value.len();
                    leaf.commitment.truncate(keep);
                    true
                }
                quil_tries::VectorCommitmentNode::Leaf(_) => false,
                quil_tries::VectorCommitmentNode::Branch(branch) => branch
                    .children
                    .iter_mut()
                    .flatten()
                    .any(|child| rewrite(child, key, value)),
            }
        }
        let network = [1; 32];
        let app = crate::domains::QUIL_TOKEN;
        let context = parameter_context(&network, &app);
        let key = CommitmentKey::derive(&context);
        let opening = AmountOpening::from_seed(&context, &[2; 32]);
        let output = |amount: u128, owner: u8| Output {
            commitment: key.commit(amount, &opening),
            owner: [owner; IDENTITY_BYTES],
            memo: [4; MEMO_BYTES],
        };
        let authorized = vec![output(7, 3)];
        let other = vec![output(7_000_000, 5)];
        let receipt = [6; 32];
        let blob = create_record(&network, &app, &authorized, 2).unwrap();
        let other_hash = fields(&network, &app, &other, 2).unwrap()[2].1.clone();
        let mut node = quil_tries::deserialize_go_tree(&blob).unwrap().unwrap();
        assert!(rewrite(&mut node, &[4], &other_hash));
        let forged_blob = quil_tries::serialize_go_tree(Some(&node)).unwrap();
        let leaf = quil_tries::vertex_leaf_value(&blob).unwrap();
        assert_eq!(quil_tries::vertex_leaf_value(&forged_blob).unwrap(), leaf);
        let forest = quil_forest::Forest::in_memory();
        let root = forest
            .commit_shard_phase_raw(
                b"authorization-test",
                quil_forest::Phase::VertexAdds,
                0,
                [(receipt.to_vec(), leaf)],
            )
            .unwrap();
        let mut address = crate::domains::GLOBAL.to_vec();
        address.extend_from_slice(&receipt);
        let prove = |blob: &[u8]| {
            let membership = forest
                .build_vertex_membership_proof(
                    b"authorization-test",
                    quil_forest::Phase::VertexAdds,
                    0,
                    &address,
                    blob,
                )
                .unwrap();
            quil_forest::MembershipProof {
                inputs: vec![membership],
            }
            .to_bytes()
        };
        let honest = prove(&blob);
        let forged = prove(&forged_blob);
        verify_membership(&network, &app, &receipt, &authorized, 2, &root, &honest).unwrap();
        assert!(
            verify_membership(&network, &app, &receipt, &other, 2, &root, &forged).is_err(),
            "forged mint outputs accepted: the membership proof verified outputs \
             the authorization record does not bind"
        );
    }

    /// From the citation window epoch a citation trailing the anchor by more
    /// than the window is refused even where the frame is held, and one at
    /// the window's edge still resolves. Before it the old frame resolves.
    #[test]
    fn clock_reward_root_refuses_citations_outside_the_window() {
        use quil_types::consensus::{
            set_global_citation_window_epoch_for_thread, GLOBAL_CITATION_WINDOW_FRAMES,
        };
        use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader};
        let clock = quil_store::testing::InMemoryClockStore::new();
        let anchor = 3 * GLOBAL_CITATION_WINDOW_FRAMES;
        let edge = anchor - GLOBAL_CITATION_WINDOW_FRAMES;
        for (frame, root) in [(edge, [1u8; 32]), (edge - 1, [2u8; 32])] {
            clock.seed_frame(GlobalFrame {
                header: Some(GlobalFrameHeader {
                    frame_number: frame,
                    prover_tree_commitment: root.to_vec(),
                    ..Default::default()
                }),
                ..Default::default()
            });
        }
        set_global_citation_window_epoch_for_thread(Some(u64::MAX));
        assert_eq!(
            clock_reward_root(&clock, edge - 1, anchor).unwrap(),
            [2; 32]
        );
        set_global_citation_window_epoch_for_thread(Some(0));
        assert_eq!(clock_reward_root(&clock, edge, anchor).unwrap(), [1; 32]);
        assert!(matches!(
            clock_reward_root(&clock, edge - 1, anchor),
            Err(QuilError::InvalidArgument(reason)) if reason.contains("citation window")
        ));
        assert!(matches!(
            clock_reward_root(&clock, 1, anchor),
            Err(QuilError::InvalidArgument(reason)) if reason.contains("citation window")
        ));
        assert!(matches!(
            clock_reward_root(&clock, edge + 1, anchor),
            Err(QuilError::ExecutionUnavailable(_))
        ));
        assert!(matches!(
            clock_reward_root(&clock, anchor + 1, anchor),
            Err(QuilError::InvalidArgument(reason)) if reason.contains("future")
        ));
        set_global_citation_window_epoch_for_thread(None);
    }

    /// Witnesses cite the newest root their node retains, at most the reward
    /// witness lookback before their cap, and a mint claim's cap trails the
    /// latest frame by the citation lag. The window holds twice that.
    #[test]
    fn the_citation_window_admits_every_honest_witness_citation() {
        let honest = crate::token_intrinsic::reward_witness::REWARD_WITNESS_LOOKBACK_FRAMES
            + crate::token_intrinsic::constants::MINT_CLAIM_CITATION_LAG;
        assert!(quil_types::consensus::GLOBAL_CITATION_WINDOW_FRAMES >= 2 * honest);
    }
}

/// The canonical GLOBAL prover-shard root committed by global frame
/// `cited_frame`, which must not follow the executing frame's finalized global
/// anchor and, from the global citation window epoch, must not trail it by
/// more than [`GLOBAL_CITATION_WINDOW_FRAMES`]. Both bounds are deterministic
/// rejections. Missing local history within them is an execution failure (the
/// frame is held for retry).
///
/// [`GLOBAL_CITATION_WINDOW_FRAMES`]: quil_types::consensus::GLOBAL_CITATION_WINDOW_FRAMES
pub(crate) fn clock_reward_root(
    clock: &dyn quil_types::store::ClockStore,
    cited_frame: u64,
    finalized_global_frame: u64,
) -> quil_types::error::Result<[u8; 32]> {
    use quil_types::consensus::{global_citation_window_active, GLOBAL_CITATION_WINDOW_FRAMES};
    use quil_types::error::QuilError;
    let unavailable = |message: String| QuilError::ExecutionUnavailable(format!("mint: {message}"));
    if cited_frame > finalized_global_frame {
        return Err(QuilError::InvalidArgument(format!(
            "mint: future global reward frame (cited {cited_frame}, anchor {finalized_global_frame})"
        )));
    }
    if global_citation_window_active(finalized_global_frame)
        && finalized_global_frame - cited_frame > GLOBAL_CITATION_WINDOW_FRAMES
    {
        return Err(QuilError::InvalidArgument(format!(
            "mint: global reward frame outside the citation window (cited {cited_frame}, \
             anchor {finalized_global_frame}, window {GLOBAL_CITATION_WINDOW_FRAMES})"
        )));
    }
    let frame = clock
        .get_global_clock_frame(cited_frame)
        .map_err(|e| unavailable(format!("cannot load canonical global reward frame: {e}")))?;
    let header = frame
        .header
        .ok_or_else(|| unavailable("global reward frame has no header".into()))?;
    if header.frame_number != cited_frame {
        return Err(unavailable("global reward frame number mismatch".into()));
    }
    header
        .prover_tree_commitment
        .as_slice()
        .try_into()
        .map_err(|_| unavailable("global reward root is not 32 bytes".into()))
}

/// First GLOBAL frame whose prover root an operation executed on `network`
/// (the executing node's `network_identifier`) may cite:
/// [`MAINNET_FIRST_CITABLE_GLOBAL_FRAME`] on mainnet, frame 0 elsewhere.
///
/// [`MAINNET_FIRST_CITABLE_GLOBAL_FRAME`]: super::constants::MAINNET_FIRST_CITABLE_GLOBAL_FRAME
pub(crate) fn first_citable_global_frame(network: &[u8; 32]) -> u64 {
    if *network == super::state::network_identifier(crate::pricing::MAINNET_NETWORK) {
        super::constants::MAINNET_FIRST_CITABLE_GLOBAL_FRAME
    } else {
        0
    }
}

/// [`clock_reward_root`] for an operation (`citer`, named in the log)
/// executed on `network`. A cited frame before the network's first citable
/// frame is refused deterministically, before any clock read: no node holds a
/// forest root for it, so the read would fail on every node and the frame
/// carrying the operation could never finish anywhere.
pub(crate) fn cited_reward_root(
    clock: &dyn quil_types::store::ClockStore,
    network: &[u8; 32],
    citer: &'static str,
    cited_frame: u64,
    finalized_global_frame: u64,
) -> quil_types::error::Result<[u8; 32]> {
    let first = first_citable_global_frame(network);
    if cited_frame < first {
        note_uncitable(citer, cited_frame, first, finalized_global_frame);
        return Err(quil_types::error::QuilError::InvalidArgument(format!(
            "{citer}: global reward frame {cited_frame} precedes the network's first citable \
             frame {first}"
        )));
    }
    clock_reward_root(clock, cited_frame, finalized_global_frame)
}

/// When the last refusal warning was logged, and the refusals quieted since.
static UNCITABLE_WARNED: std::sync::Mutex<Option<(std::time::Instant, u64)>> =
    std::sync::Mutex::new(None);

/// At most one refusal warning per interval, so a flood of such operations
/// cannot flood the log; the next warning counts the quieted ones.
const UNCITABLE_WARN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);

/// Whether a refusal at `now` is due a warning, with the refusals quieted
/// since the last one; otherwise this refusal is counted as quieted.
fn uncitable_warning_due(
    last: &mut Option<(std::time::Instant, u64)>,
    now: std::time::Instant,
) -> Option<u64> {
    match *last {
        Some((at, quieted)) if now.duration_since(at) < UNCITABLE_WARN_INTERVAL => {
            *last = Some((at, quieted + 1));
            None
        }
        previous => {
            *last = Some((now, 0));
            Some(previous.map_or(0, |(_, quieted)| quieted))
        }
    }
}

fn note_uncitable(citer: &str, cited_frame: u64, first_citable_frame: u64, anchor: u64) {
    let due = match UNCITABLE_WARNED.lock() {
        Ok(mut last) => uncitable_warning_due(&mut last, std::time::Instant::now()),
        Err(_) => None,
    };
    let Some(quieted) = due else {
        return;
    };
    tracing::warn!(
        citer,
        cited_frame,
        first_citable_frame,
        anchor,
        refusals_since_last_warning = quieted,
        scope = "network: a submitted operation cites a GLOBAL frame no node holds a forest \
            root for; not this node",
        action = "none here: this build refuses the operation and the frame carrying it \
            completes; a node on an older build stays stopped at that frame until it upgrades; \
            report it to the maintainers with the cited frame if it repeats",
        "refused an operation citing a GLOBAL frame before the network's first citable frame",
    );
}

#[cfg(test)]
mod first_citable_frame_tests {
    use super::*;
    use quil_types::error::QuilError;
    use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader};
    use std::time::{Duration, Instant};

    fn network(selector: u8) -> [u8; 32] {
        super::super::state::network_identifier(selector)
    }

    #[test]
    fn only_mainnet_bounds_citations_from_below() {
        assert_eq!(
            first_citable_global_frame(&network(crate::pricing::MAINNET_NETWORK)),
            669_976
        );
        for other in [network(1), network(7), network(255), [1; 32]] {
            assert_eq!(first_citable_global_frame(&other), 0);
        }
    }

    /// The frame before the bound is refused even where it is held, so the
    /// refusal precedes the clock read; the bound itself and every frame on a
    /// test network still resolve.
    #[test]
    fn a_citation_before_the_first_citable_frame_is_refused_before_the_read() {
        let first = super::super::constants::MAINNET_FIRST_CITABLE_GLOBAL_FRAME;
        let clock = quil_store::testing::InMemoryClockStore::new();
        for (number, root) in [(first - 1, [1u8; 32]), (first, [2u8; 32])] {
            clock.seed_frame(GlobalFrame {
                header: Some(GlobalFrameHeader {
                    frame_number: number,
                    prover_tree_commitment: root.to_vec(),
                    ..Default::default()
                }),
                ..Default::default()
            });
        }
        let mainnet = network(crate::pricing::MAINNET_NETWORK);
        let anchor = first + 10;
        assert!(matches!(
            cited_reward_root(&clock, &mainnet, "test", first - 1, anchor),
            Err(QuilError::InvalidArgument(reason)) if reason.contains("first citable frame")
        ));
        assert!(matches!(
            cited_reward_root(&clock, &mainnet, "test", 0, anchor),
            Err(QuilError::InvalidArgument(_))
        ));
        assert_eq!(
            cited_reward_root(&clock, &mainnet, "test", first, anchor).unwrap(),
            [2; 32]
        );
        assert_eq!(
            cited_reward_root(&clock, &network(1), "test", first - 1, anchor).unwrap(),
            [1; 32]
        );
        assert!(matches!(
            cited_reward_root(&clock, &network(1), "test", 5, anchor),
            Err(QuilError::ExecutionUnavailable(_))
        ));
    }

    #[test]
    fn refusal_warnings_are_bounded_and_count_the_quieted() {
        let start = Instant::now();
        let mut last = None;
        assert_eq!(uncitable_warning_due(&mut last, start), Some(0));
        for second in 1..=3 {
            let now = start + Duration::from_secs(second);
            assert_eq!(uncitable_warning_due(&mut last, now), None);
        }
        let next = start + UNCITABLE_WARN_INTERVAL;
        assert_eq!(uncitable_warning_due(&mut last, next), Some(3));
        let soon = next + Duration::from_secs(1);
        assert_eq!(uncitable_warning_due(&mut last, soon), None);
    }
}
