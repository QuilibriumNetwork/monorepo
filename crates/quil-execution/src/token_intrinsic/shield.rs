//! Shield admission: the checks a legacy transparent coin's move into the
//! confidential accumulator needs, which verification runs and the global
//! commit then decides.
#[cfg(test)]
use super::{roots, spent_check, state::{self, SnapshotLimits}};
#[cfg(test)]
use quil_lattice_ct::confidential::{relation::backend::native::{self, NativeBudget}, transfer::parameter_context};
use super::{
    legacy_migration, materialize,
};
use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
#[cfg(test)]
use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
use quil_lattice_ct::confidential::shield::{Shield, ShieldStatement};
use quil_types::error::{QuilError, Result};

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("shield: {message}"))
}

/// The legacy source coin exists, is a well-formed transparent coin, holds
/// exactly the shielded amount, and belongs to the signing key. Legacy coins
/// never change once written, so this holds wherever it is checked; whether
/// the source was already shielded is a consume-once decision made elsewhere.
pub(crate) fn check_source(state: &HypergraphState, s: &ShieldStatement) -> Result<()> {
    let disc = vertex_adds_discriminator()?;
    let blob = state
        .get(&s.application, &s.transparent_address, &disc)?
        .ok_or_else(|| invalid("source coin not found"))?;
    let tree = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(&blob).map_err(|_| invalid("invalid source coin"))?,
    };
    let expected_type = legacy_migration::transparent_type_hash(&s.application)?;
    if tree.leaves().len() != 4
        || tree.get(&[0xff; 32]) != Some(expected_type.as_slice())
        || tree.get(&[8]).map(|v| v.len()) != Some(32)
        || materialize::coin_content_address(&tree)? != s.transparent_address
    {
        return Err(invalid("invalid transparent source"));
    }
    let owner: [u8; 32] = tree
        .get(&[0])
        .ok_or_else(|| invalid("missing source owner"))?
        .try_into()
        .map_err(|_| invalid("invalid source owner"))?;
    let amount = u128::from_le_bytes(
        tree.get(&[4])
            .ok_or_else(|| invalid("missing source amount"))?
            .try_into()
            .map_err(|_| invalid("invalid source amount"))?,
    );
    if amount != s.amount {
        return Err(invalid("source amount mismatch"));
    }
    let public_address = quil_crypto::poseidon::hash_bytes_to_32(&s.owner_public_key)?;
    let peer = quil_crypto::peer_id_multihash_from_ed448_pubkey(&s.owner_public_key);
    if owner != public_address && owner != quil_crypto::poseidon::hash_bytes_to_32(&peer)? {
        return Err(invalid("source owner mismatch"));
    }
    Ok(())
}

pub(crate) fn check_authorization(shield: &Shield) -> Result<()> {
    let context = shield
        .statement
        .context_bytes()
        .map_err(|_| invalid("invalid statement"))?;
    if !quil_crypto::ed448_verify(
        &shield.statement.owner_public_key,
        &context,
        &shield.signature,
    ) {
        return Err(invalid("invalid source authorization"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_lattice_ct::confidential::{
        transfer::{Output, MEMO_BYTES},
        AmountOpening, CommitmentKey,
    };
    use quil_types::crypto::{NoopInclusionProver, Signer};
    use std::sync::Arc;

    fn disk_state(path: &std::path::Path) -> HypergraphState {
        let db = quil_store::RocksDb::open(path).unwrap();
        HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
            Arc::new(NoopInclusionProver),
        )))
    }

    #[test]
    #[ignore = "complete native shield proof and RocksDB admission"]
    fn complete_shield_authorizes_proves_and_reopens() {
        run_complete_shield(false, None);
    }

    #[test]
    #[ignore = "complete native shield through the token engine and RocksDB"]
    fn complete_shield_through_token_engine() {
        run_complete_shield(true, None);
    }

    #[test]
    #[ignore = "requires native worker; complete shield through the engine and RocksDB recovery"]
    fn complete_shield_with_worker() {
        use quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier;
        let path = std::env::var("QUIL_AMOUNT_WORKER_PATH").expect("native worker path");
        let worker = WorkerVerifier::from_test_env(path.into()).unwrap();
        run_complete_shield(true, Some(worker));
    }

    fn run_complete_shield(engine_route: bool, worker: Option<quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier>) {
        use pqcrypto_ntruprime::sntrup761;
        use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
        use quil_lattice_ct::confidential::{
            address::RecipientAddress,
            memo::{create_output, open_output},
            relation::membership::RecipientSecret,
            transfer::TARGET_TRANSACTION_BYTES,
        };
        let started = std::time::Instant::now();
        let directory = tempfile::tempdir().unwrap();
        let state = disk_state(directory.path());
        let network = [21; 32];
        let application = if engine_route {
            crate::domains::QUIL_TOKEN
        } else {
            [22; 32]
        };
        let context = parameter_context(&network, &application);
        let public = quil_crypto::Ed448Signer::derive_public(&[23; 57]).unwrap();
        let signer = quil_crypto::Ed448Signer::from_bytes(&[23; 57], &public).unwrap();
        let tree = legacy_migration::create_transparent_coin_tree(
            &legacy_migration::TransparentCoin {
                owner_address: quil_crypto::poseidon::hash_bytes_to_32(&public).unwrap(),
                amount: u128::MAX,
            },
            &legacy_migration::transparent_type_hash(&application).unwrap(),
            &[24; 32],
        )
        .unwrap();
        let source = materialize::coin_content_address(&tree).unwrap();
        let disc = vertex_adds_discriminator().unwrap();
        state
            .set(
                &application,
                &source,
                &disc,
                1,
                quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
            )
            .unwrap();
        state.commit().unwrap();
        state.abort();
        state.crdt().commit(1).unwrap();
        let amounts = [u128::MAX - 258, 256];
        let mut recipients = Vec::new();
        let mut created = Vec::new();
        for (i, amount) in amounts.iter().enumerate() {
            let recipient = RecipientSecret::from_seed(&context, &[25 + i as u8; 32]);
            let (public, secret) = sntrup761::keypair();
            let address = RecipientAddress::new(&context, &recipient, public.as_bytes()).unwrap();
            created.push(create_output(&context, &address, *amount).unwrap());
            recipients.push((recipient, secret));
        }
        let statement = ShieldStatement {
            network,
            application,
            transparent_address: source,
            owner_public_key: public.try_into().unwrap(),
            amount: u128::MAX,
            fee: 2,
            outputs: created.iter().map(|o| o.output.clone()).collect(),
        };
        let openings: Vec<_> = amounts
            .iter()
            .zip(&created)
            .map(|(&a, o)| (a, &o.opening))
            .collect();
        let relation = statement.private_relation(&openings, 2).unwrap();
        let signature = signer
            .sign(&statement.context_bytes().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let budget = NativeBudget {
            max_native_bytes: 1024 * 1024 * 1024,
        };
        let proof = native::prove(&relation, budget).unwrap();
        drop(relation);
        let proof_bytes = proof.len();
        let encoded = Shield {
            statement,
            signature,
            proof,
        }
        .encode()
        .unwrap();
        assert!(encoded.len() < TARGET_TRANSACTION_BYTES);
        let limits = SnapshotLimits {
            max_coins: 8,
            max_depth: 3,
            max_nodes: 24,
        };
        let consumed = |state: &HypergraphState| crate::token_intrinsic::global_commit::is_consumed(
            state, &application, &spent_check::key_image_spent_address(&source).unwrap()).unwrap();
        let tp = crate::token_engine::TYPE_LATTICE_SHIELD;
        let output_addresses: Vec<[u8; 32]> = if engine_route {
            use crate::{
                engines::{ExecutionMode, TokenExecutionEngine},
                message_envelope::CanonicalMessageRequest,
                token_intrinsic::dispatch::TokenPolicy,
            };
            use quil_lattice_ct::confidential::transfer::CompileLimits;
            use quil_types::execution::ShardExecutionEngine;
            let stubs = crate::testing::NoopExecutionCrypto::new();
            let make_engine = |native_budget| {
                let engine = TokenExecutionEngine::new_with_state(
                    ExecutionMode::Global,
                    Arc::new(NoopInclusionProver),
                    state.crdt().clone(),
                    stubs.key_manager.clone(),
                    stubs.clock_store.clone(),
                )
                .with_token_proofs(TokenPolicy {
                    network,
                    limits: CompileLimits {
                        max_inputs: 2,
                        max_outputs: 2,
                        max_depth: 3,
                    },
                    snapshots: limits,
                    native_budget,
                })
                .unwrap();
                match &worker {
                    Some(worker) => engine.with_token_worker(worker.clone()).unwrap(),
                    None => engine,
                }
            };
            let message = CanonicalMessageRequest {
                inner_type_prefix: crate::token_engine::TYPE_LATTICE_SHIELD,
                inner_bytes: encoded.clone(),
            }
            .to_canonical_bytes()
            .unwrap();
            let unavailable = make_engine(NativeBudget {
                max_native_bytes: 0,
            });
            assert!(matches!(
                unavailable.process_message(
                    2,
                    &num_bigint::BigInt::from(0),
                    &application,
                    &message
                ),
                Err(QuilError::ExecutionUnavailable(_))
            ));
            assert!(
                roots::read_current(&state, &network, &application)
                    .unwrap()
                    .is_none()
            );
            assert!(!consumed(&state));
            let engine = make_engine(budget);
            assert!(engine.validate_message(2, &[99; 32], &message).is_err());
            engine.validate_message(2, &application, &message).unwrap();
            engine
                .process_message(2, &num_bigint::BigInt::from(0), &application, &message)
                .unwrap();
            let root = roots::read_current(&state, &network, &application)
                .unwrap()
                .unwrap();
            // Engine-level replay is a deterministic rejected operation, with no
            // changed root or newly materialized output.
            engine
                .process_message(2, &num_bigint::BigInt::from(0), &application, &message)
                .unwrap_err();
            assert_eq!(
                roots::read_current(&state, &network, &application).unwrap(),
                Some(root.clone())
            );
            let _ = root;
            created
                .iter()
                .map(|o| state::coin_identity(&context, 2, &o.output).unwrap().0)
                .collect()
        } else {
            let clock = crate::testing::NoopClockStore;
            let at = |frame: u64| quil_types::execution::FrameExecutionContext {
                frame_number: frame, finalized_global_frame: Some(frame - 1),
                shard: quil_types::execution::ShardPath::WHOLE, venue: None,
            };
            let compile = quil_lattice_ct::confidential::transfer::CompileLimits {
                max_inputs: 1, max_outputs: 2, max_depth: 1,
            };
            let verify = |budget| crate::token_intrinsic::commit_verify::verify_for_commit(
                &state, &clock, at(2), &network, &application, tp, &encoded, compile, budget, worker.as_ref());
            // Verification writes nothing and decides nothing.
            let checkpoint = state.changeset_len();
            verify(budget).unwrap();
            assert_eq!(state.changeset_len(), checkpoint);
            assert!(!consumed(&state));
            // A snapshot budget too small to place the outputs fails the
            // commit; the caller rolls its changeset back, as the engine does.
            let too_small = SnapshotLimits { max_coins: 1, ..limits };
            assert!(crate::token_intrinsic::commit_apply::commit_and_place(&state, 2, &network, &application, tp, &encoded, too_small).is_err());
            state.rollback_to(checkpoint);
            assert!(!consumed(&state));
            crate::token_intrinsic::commit_apply::commit_and_place(&state, 2, &network, &application, tp, &encoded, limits).unwrap()
        };
        assert_eq!(output_addresses.len(), 2);
        let root = roots::read_current(&state, &network, &application).unwrap().unwrap();
        // The legacy source is consumed once, in GLOBAL, so the same coin
        // cannot be shielded again — by this operation or another.
        assert!(consumed(&state));
        assert!(crate::token_intrinsic::commit_apply::commit_and_place(&state, 3, &network, &application, tp, &encoded, limits).is_err());
        state.commit().unwrap();
        state.abort();
        state.crdt().commit(2).unwrap();
        drop(state);
        let state = disk_state(directory.path());
        assert_eq!(
            roots::read_current(&state, &network, &application).unwrap(),
            Some(root)
        );
        assert!(crate::token_intrinsic::commit_apply::commit_and_place(&state, 4, &network, &application, tp, &encoded, limits).is_err());
        assert!(consumed(&state));
        for (i, address) in output_addresses.iter().enumerate() {
            let blob = state.get(&application, address, &disc).unwrap().unwrap();
            let tree = quil_tries::VectorCommitmentTree {
                root: quil_tries::deserialize_go_tree(&blob).unwrap(),
            };
            let coin = state::read_coin(&tree, &context)
                .unwrap()
                .unwrap();
            let (recipient, secret) = &recipients[i];
            assert_eq!(
                open_output(&context, secret.as_bytes(), recipient, &coin.output)
                    .unwrap()
                    .amount,
                amounts[i]
            );
        }
        if let Ok(path) = std::env::var("QUIL_TEST_TRANSACTION_PATH") {
            std::fs::write(path, &encoded).unwrap();
        }
        eprintln!("shield_complete native_verified=true authorized=true rocksdb_reopened=true recipients_recovered=2 legacy_replay_rejected=true engine_route={} bytes={} proof_bytes={} seconds={:.3}",
            engine_route, encoded.len(), proof_bytes, started.elapsed().as_secs_f64());
    }

    #[test]
    fn shield_authorization_checks_source_value_owner_context_and_shared_spend() {
        let state = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(NoopInclusionProver),
        )));
        let network = [1; 32];
        let application = [2; 32];
        let public = quil_crypto::Ed448Signer::derive_public(&[3; 57]).unwrap();
        let signer = quil_crypto::Ed448Signer::from_bytes(&[3; 57], &public).unwrap();
        let owner = quil_crypto::poseidon::hash_bytes_to_32(&public).unwrap();
        let tree = legacy_migration::create_transparent_coin_tree(
            &legacy_migration::TransparentCoin {
                owner_address: owner,
                amount: 12,
            },
            &legacy_migration::transparent_type_hash(&application).unwrap(),
            &[4; 32],
        )
        .unwrap();
        let address = materialize::coin_content_address(&tree).unwrap();
        let disc = vertex_adds_discriminator().unwrap();
        state
            .set(
                &application,
                &address,
                &disc,
                1,
                quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
            )
            .unwrap();
        let context = parameter_context(&network, &application);
        let key = CommitmentKey::derive(&context);
        let opening = AmountOpening::from_seed(&context, &[5; 32]);
        let statement = ShieldStatement {
            network,
            application,
            transparent_address: address,
            owner_public_key: public.try_into().unwrap(),
            amount: 12,
            fee: 1,
            outputs: vec![Output {
                commitment: key.commit(11, &opening),
                owner: [6; IDENTITY_BYTES],
                memo: [7; MEMO_BYTES],
            }],
        };
        let signature = signer
            .sign(&statement.context_bytes().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        // Authorization-only fixture; no valid native proof or opaque verified value.
        let shield = Shield {
            statement,
            signature,
            proof: Vec::new(),
        };
        assert!(check_source(&state, &shield.statement).is_ok());
        assert!(check_authorization(&shield).is_ok());
        // A validly authorized statement with a local zero submission budget
        // is unavailable verification, not an invalid transaction verdict.
        let mut submitted = shield.clone();
        submitted.proof = vec![0; 40];
        submitted.proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        let encoded = submitted.encode().unwrap();
        let clock = crate::testing::NoopClockStore;
        let at = quil_types::execution::FrameExecutionContext {
            frame_number: 2, finalized_global_frame: Some(1),
            shard: quil_types::execution::ShardPath::WHOLE, venue: None,
        };
        let tp = crate::token_engine::TYPE_LATTICE_SHIELD;
        let compile = quil_lattice_ct::confidential::transfer::CompileLimits {
            max_inputs: 1, max_outputs: 1, max_depth: 1,
        };
        let exhausted = NativeBudget { max_native_bytes: 0 };
        let verify = |bytes: &[u8]| crate::token_intrinsic::commit_verify::verify_for_commit(
            &state, &clock, at, &network, &application, tp, bytes, compile, exhausted, None);
        assert!(matches!(verify(&encoded), Err(QuilError::ExecutionUnavailable(_))));
        submitted.signature[0] ^= 1;
        assert!(matches!(verify(&submitted.encode().unwrap()), Err(QuilError::InvalidArgument(_))));
        let before = state.changeset_len();
        let mut changed = shield.clone();
        changed.statement.amount += 1;
        assert!(check_source(&state, &changed.statement).is_err());
        assert!(check_authorization(&changed).is_err());
        changed = shield.clone();
        changed.statement.owner_public_key[0] ^= 1;
        assert!(check_source(&state, &changed.statement).is_err());
        changed = shield.clone();
        changed.statement.outputs[0].memo[0] ^= 1;
        assert!(check_authorization(&changed).is_err());
        changed = shield.clone();
        changed.statement.network[0] ^= 1;
        assert!(check_authorization(&changed).is_err());
        assert_eq!(state.changeset_len(), before);
        // Spending the legacy coin is decided once, by the global commit:
        // the source stays valid to check, and the second shield of it is
        // refused there rather than by a marker this shard wrote.
        assert_eq!(state.changeset_len(), before);
        let entry = crate::token_intrinsic::spend_entries::spend_entry(&network, &application, tp, &encoded, 2).unwrap();
        assert_eq!(entry.consumptions, vec![spent_check::key_image_spent_address(&address).unwrap()]);
        assert!(matches!(
            crate::token_intrinsic::global_commit::commit_entry(&state, 2, &application, &entry, quil_types::execution::ShardPath::WHOLE).unwrap(),
            crate::token_intrinsic::global_commit::Outcome::Committed { .. }
        ));
        assert!(check_source(&state, &shield.statement).is_ok());
        let mut other = shield.clone();
        other.proof = vec![0; 40];
        other.proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        other.statement.outputs[0].memo[0] ^= 1;
        let entry = crate::token_intrinsic::spend_entries::spend_entry(&network, &application, tp, &other.encode().unwrap(), 3).unwrap();
        assert_eq!(
            crate::token_intrinsic::global_commit::commit_entry(&state, 3, &application, &entry, quil_types::execution::ShardPath::WHOLE).unwrap(),
            crate::token_intrinsic::global_commit::Outcome::Rejected("already consumed")
        );
    }
}
