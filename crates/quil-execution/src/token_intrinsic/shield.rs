//! Shield admission: the checks a legacy transparent coin's move into the
//! confidential accumulator needs, which verification runs and the global
//! commit then decides.
use super::{
    roots,
    state::{self, SnapshotLimits},
    legacy_migration, materialize, spent_check,
};
use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
#[cfg(test)]
use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
use quil_lattice_ct::confidential::{
    relation::backend::native::{self, NativeBudget},
    shield::{AnyShield, ShieldStatement},
    transfer::parameter_context,
};
#[cfg(test)]
use quil_lattice_ct::confidential::shield::Shield;
use quil_types::error::{QuilError, Result};
use std::collections::BTreeSet;

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("shield: {message}"))
}

/// The legacy source coin exists, is a well-formed transparent coin, holds
/// exactly the shielded amount, and belongs to the signing key. Legacy coins
/// never change once written, so this holds wherever it is checked; whether
/// the source was already shielded is a consume-once decision made elsewhere.
pub(crate) fn check_source(state: &HypergraphState, s: &ShieldStatement) -> Result<()> {
    check_coin(state, &s.application, &s.transparent_address, s.amount, &s.owner_public_key)
}

/// Every source of `shield` passes [`check_source`]'s checks. From the batch
/// shield frame (`active`), every source must also lie in the executing
/// shard's range: a shard reads only its own store, so a source elsewhere is
/// refused for that reason, identically on every member and on an archive
/// replaying the frame (which holds every shard). Before it, a batch is
/// refused outright.
pub(crate) fn check_sources(
    state: &HypergraphState,
    shard: quil_types::execution::ShardPath,
    active: bool,
    application: &[u8; 32],
    shield: &AnyShield,
) -> Result<()> {
    if shield.is_batch() && !active {
        return Err(invalid("batch shields are not active yet"));
    }
    for source in shield.sources() {
        if active && !shard.covers(&source.address) {
            return Err(invalid("source outside this shard"));
        }
        check_coin(state, application, &source.address, source.amount, shield.owner_public_key())?;
    }
    Ok(())
}

fn check_coin(
    state: &HypergraphState,
    application: &[u8; 32],
    address: &[u8; 32],
    expected_amount: u128,
    owner_public_key: &[u8; 57],
) -> Result<()> {
    let disc = vertex_adds_discriminator()?;
    let blob = state
        .get(application, address, &disc)?
        .ok_or_else(|| invalid("source coin not found"))?;
    let tree = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(&blob).map_err(|_| invalid("invalid source coin"))?,
    };
    let expected_type = legacy_migration::transparent_type_hash(application)?;
    if tree.leaves().len() != 4
        || tree.get(&[0xff; 32]) != Some(expected_type.as_slice())
        || tree.get(&[8]).map(|v| v.len()) != Some(32)
        || materialize::coin_content_address(&tree)? != *address
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
    if amount != expected_amount {
        return Err(invalid("source amount mismatch"));
    }
    let public_address = quil_crypto::poseidon::hash_bytes_to_32(owner_public_key)?;
    let peer = quil_crypto::peer_id_multihash_from_ed448_pubkey(owner_public_key);
    if owner != public_address && owner != quil_crypto::poseidon::hash_bytes_to_32(&peer)? {
        return Err(invalid("source owner mismatch"));
    }
    Ok(())
}

/// The legacy owner signed the shield's statement bytes, which bind every
/// source, amount, fee and output.
pub(crate) fn check_authorization(shield: &AnyShield) -> Result<()> {
    let context = shield.context_bytes().map_err(|_| invalid("invalid statement"))?;
    if !quil_crypto::ed448_verify(shield.owner_public_key(), &context, shield.signature()) {
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
        assert!(check_authorization(&AnyShield::Single(shield.clone())).is_ok());
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
        assert!(check_authorization(&AnyShield::Single(changed.clone())).is_err());
        changed = shield.clone();
        changed.statement.owner_public_key[0] ^= 1;
        assert!(check_source(&state, &changed.statement).is_err());
        changed = shield.clone();
        changed.statement.outputs[0].memo[0] ^= 1;
        assert!(check_authorization(&AnyShield::Single(changed.clone())).is_err());
        changed = shield.clone();
        changed.statement.network[0] ^= 1;
        assert!(check_authorization(&AnyShield::Single(changed.clone())).is_err());
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

    /// A batch's sources: each a transparent coin of the signing key (either
    /// owner form), at its listed amount; from activation inside the executing
    /// shard; and before activation a batch is refused while a single shield
    /// is checked as it always was.
    #[test]
    fn batch_sources_are_checked_coin_by_coin_against_the_shard_and_activation() {
        use quil_lattice_ct::confidential::shield::{BatchShield, BatchShieldStatement, ShieldSource};
        use quil_types::execution::ShardPath;
        let state = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(NoopInclusionProver),
        )));
        let (network, application) = ([1; 32], [2; 32]);
        let public = quil_crypto::Ed448Signer::derive_public(&[3; 57]).unwrap();
        let signer = quil_crypto::Ed448Signer::from_bytes(&[3; 57], &public).unwrap();
        let by_key = quil_crypto::poseidon::hash_bytes_to_32(&public).unwrap();
        let by_peer = quil_crypto::poseidon::hash_bytes_to_32(&quil_crypto::peer_id_multihash_from_ed448_pubkey(&public)).unwrap();
        let disc = vertex_adds_discriminator().unwrap();
        let place = |owner: [u8; 32], amount: u128, origin: u8| {
            let tree = legacy_migration::create_transparent_coin_tree(
                &legacy_migration::TransparentCoin { owner_address: owner, amount },
                &legacy_migration::transparent_type_hash(&application).unwrap(),
                &[origin; 32],
            ).unwrap();
            let address = materialize::coin_content_address(&tree).unwrap();
            state.set(&application, &address, &disc, 1, quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()).unwrap();
            ShieldSource { address, amount }
        };
        let mut sources = vec![place(by_key, 10, 1), place(by_peer, 20, 2), place(by_key, 30, 3)];
        sources.sort_by_key(|source| source.address);
        let stranger = place([9; 32], 40, 4);
        let context = parameter_context(&network, &application);
        let opening = AmountOpening::from_seed(&context, &[5; 32]);
        let statement = |sources: Vec<ShieldSource>| BatchShieldStatement {
            network, application, owner_public_key: public.clone().try_into().unwrap(), sources, fee: 1,
            outputs: vec![Output { commitment: CommitmentKey::derive(&context).commit(59, &opening), owner: [6; IDENTITY_BYTES], memo: [7; MEMO_BYTES] }],
        };
        let shield = |statement: BatchShieldStatement| {
            let signature = signer.sign(&statement.context_bytes().unwrap()).unwrap().try_into().unwrap();
            AnyShield::Batch(BatchShield { statement, signature, proof: Vec::new() })
        };
        let batch = shield(statement(sources.clone()));
        assert!(check_sources(&state, ShardPath::WHOLE, true, &application, &batch).is_ok(), "both owner forms of one key");
        assert!(check_authorization(&batch).is_ok());
        let error = check_sources(&state, ShardPath::WHOLE, false, &application, &batch).unwrap_err();
        assert!(error.to_string().contains("not active"), "{error}");

        // From activation every source must be in the executing shard.
        let first_bit = sources[0].address[0] & 0x80 != 0;
        let one = shield(statement(vec![sources[0]]));
        assert!(check_sources(&state, ShardPath::from_bits(&[first_bit]), true, &application, &one).is_ok());
        let error = check_sources(&state, ShardPath::from_bits(&[!first_bit]), true, &application, &one).unwrap_err();
        assert!(error.to_string().contains("outside this shard"), "{error}");

        // Each source is the signer's, at its listed amount.
        let mut wrong_amount = sources.clone();
        wrong_amount[1].amount += 1;
        assert!(check_sources(&state, ShardPath::WHOLE, true, &application, &shield(statement(wrong_amount))).is_err());
        let mut foreign = sources.clone();
        foreign.push(stranger);
        foreign.sort_by_key(|source| source.address);
        let error = check_sources(&state, ShardPath::WHOLE, true, &application, &shield(statement(foreign))).unwrap_err();
        assert!(error.to_string().contains("owner mismatch"), "{error}");
        let mut missing = sources.clone();
        missing[2].address[31] ^= 1;
        missing.sort_by_key(|source| source.address);
        assert!(check_sources(&state, ShardPath::WHOLE, true, &application, &shield(statement(missing))).is_err());

        // A signature over another statement does not authorize this one.
        let AnyShield::Batch(mut forged) = batch.clone() else { unreachable!() };
        forged.statement.fee = 2;
        assert!(check_authorization(&AnyShield::Batch(forged)).is_err());

        // A single shield before activation is checked as it always was.
        let single = AnyShield::Single(Shield {
            statement: ShieldStatement {
                network, application, transparent_address: sources[0].address,
                owner_public_key: public.clone().try_into().unwrap(), amount: sources[0].amount, fee: 1,
                outputs: statement(Vec::new()).outputs,
            },
            signature: [0; 114],
            proof: Vec::new(),
        });
        assert!(check_sources(&state, ShardPath::from_bits(&[!first_bit]), false, &application, &single).is_ok(),
            "before activation the shard range is not checked");
    }

    /// A real batch: three legacy coins of one key (both owner forms) proven
    /// as one issuance, refused before the batch shield frame, verified after
    /// it, relayed as one entry of three consumptions and committed whole.
    #[test]
    #[ignore = "native batch shield proof"]
    fn complete_batch_shield_verifies_relays_and_commits() {
        use pqcrypto_ntruprime::sntrup761;
        use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
        use quil_lattice_ct::confidential::{
            address::RecipientAddress,
            memo::{create_output, open_output},
            relation::membership::RecipientSecret,
            shield::{BatchShield, BatchShieldStatement, ShieldSource},
        };
        use crate::token_intrinsic::global_commit;
        let directory = tempfile::tempdir().unwrap();
        let state = disk_state(directory.path());
        let (network, application) = ([31; 32], [32; 32]);
        let context = parameter_context(&network, &application);
        let public = quil_crypto::Ed448Signer::derive_public(&[33; 57]).unwrap();
        let signer = quil_crypto::Ed448Signer::from_bytes(&[33; 57], &public).unwrap();
        let by_key = quil_crypto::poseidon::hash_bytes_to_32(&public).unwrap();
        let by_peer = quil_crypto::poseidon::hash_bytes_to_32(&quil_crypto::peer_id_multihash_from_ed448_pubkey(&public)).unwrap();
        let disc = vertex_adds_discriminator().unwrap();
        let mut sources = Vec::new();
        for (i, (owner, amount)) in [(by_key, 1_000u128), (by_peer, 2_000), (by_key, 3_000)].into_iter().enumerate() {
            let tree = legacy_migration::create_transparent_coin_tree(
                &legacy_migration::TransparentCoin { owner_address: owner, amount },
                &legacy_migration::transparent_type_hash(&application).unwrap(),
                &[34 + i as u8; 32],
            ).unwrap();
            let address = materialize::coin_content_address(&tree).unwrap();
            state.set(&application, &address, &disc, 1, quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()).unwrap();
            sources.push(ShieldSource { address, amount });
        }
        sources.sort_by_key(|source| source.address);
        state.commit().unwrap();
        state.abort();
        state.crdt().commit(1).unwrap();

        let recipient = RecipientSecret::from_seed(&context, &[40; 32]);
        let (kem_public, kem_secret) = sntrup761::keypair();
        let address = RecipientAddress::new(&context, &recipient, kem_public.as_bytes()).unwrap();
        let fee = 6;
        let created = create_output(&context, &address, 6_000 - fee).unwrap();
        let statement = BatchShieldStatement {
            network, application, owner_public_key: public.clone().try_into().unwrap(),
            sources: sources.clone(), fee, outputs: vec![created.output.clone()],
        };
        let relation = statement.private_relation(&[(6_000 - fee, &created.opening)], 1).unwrap();
        let signature = signer.sign(&statement.context_bytes().unwrap()).unwrap().try_into().unwrap();
        let budget = NativeBudget { max_native_bytes: 1024 * 1024 * 1024 };
        let started = std::time::Instant::now();
        let proof = native::prove(&relation, budget).unwrap();
        let proving = started.elapsed();
        drop(relation);
        let encoded = BatchShield { statement, signature, proof }.encode().unwrap();

        global_commit::set_batch_shield_frame_for_thread(Some(10));
        let clock = crate::testing::NoopClockStore;
        let tp = crate::token_engine::TYPE_LATTICE_SHIELD;
        let compile = quil_lattice_ct::confidential::transfer::CompileLimits { max_inputs: 1, max_outputs: 1, max_depth: 1 };
        let at = |anchor: u64| quil_types::execution::FrameExecutionContext {
            frame_number: 2, finalized_global_frame: Some(anchor),
            shard: quil_types::execution::ShardPath::WHOLE, venue: None,
        };
        let verify = |anchor| crate::token_intrinsic::commit_verify::verify_for_commit(
            &state, &clock, at(anchor), &network, &application, tp, &encoded, compile, budget, None);
        let error = verify(9).unwrap_err();
        assert!(error.to_string().contains("not active"), "{error}");
        let started = std::time::Instant::now();
        verify(10).unwrap();
        let verifying = started.elapsed();

        let entry = crate::token_intrinsic::spend_entries::spend_entry(&network, &application, tp, &encoded, 2).unwrap();
        assert_eq!(entry.consumptions.len(), 3);
        let relayed = global_commit::SpendEntry::decode_at(&entry.encode().unwrap(), 11).unwrap();
        assert!(matches!(
            global_commit::commit_entry(&state, 11, &application, &relayed, quil_types::execution::ShardPath::WHOLE).unwrap(),
            global_commit::Outcome::Committed { .. }
        ));
        for source in &sources {
            let marker = spent_check::key_image_spent_address(&source.address).unwrap();
            assert!(global_commit::is_consumed(&state, &application, &marker).unwrap());
        }
        let opened = open_output(&context, kem_secret.as_bytes(), &recipient, &created.output).unwrap();
        assert_eq!(opened.amount, 6_000 - fee);
        global_commit::set_batch_shield_frame_for_thread(None);
        eprintln!("batch shield of 3: {} bytes, proving {:.1}s, verifying {:.1}s", encoded.len(), proving.as_secs_f64(), verifying.as_secs_f64());
    }
}
