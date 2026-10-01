//! Escrow claim/refund admission and atomic state staging.
//! Both authorities consume the same escrow marker. The caller supplies the
//! consensus global anchor, serializes mutation and applies enclosing fee policy.
#[cfg(test)]
use super::{escrow, roots, state::{self, SnapshotLimits}};
#[cfg(test)]
use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
#[cfg(test)]
use quil_lattice_ct::confidential::{relation::{membership::IDENTITY_BYTES, backend::{native::{self, NativeBudget}, worker_client::WorkerVerifier}}, transfer::CompileLimits};
#[cfg(test)]
use quil_types::execution::FrameExecutionContext;
use quil_lattice_ct::confidential::{
    pending_claim::{ClaimBranch, EscrowPolicy, PendingClaim},
    transfer::parameter_context,
    AmountCommitment,
};
use quil_types::error::{QuilError, Result};

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("pending claim: {message}"))
}

/// Deliberately independent of the selected authority, outputs and proof.
pub fn consumption_address(network: &[u8; 32], application: &[u8; 32], escrow: &[u8; 32]) -> Result<[u8; 32]> {
    let mut bytes = Vec::from(b"quil/escrow/consumed/QCT3/v3\0".as_slice());
    bytes.extend_from_slice(&parameter_context(network, application));
    bytes.extend_from_slice(escrow);
    quil_crypto::poseidon::hash_bytes_to_32(&bytes)
}

/// `source` and `policy` must be loaded independently from the canonical escrow
/// identified by `escrow_address`. The caller must also establish that it has
/// not been consumed. The global reference must come from consensus execution,
/// never from the transaction or a local latest-head query.
#[allow(clippy::too_many_arguments)]
pub(crate) fn check_authorization(
    claim: &PendingClaim,
    network: &[u8; 32],
    application: &[u8; 32],
    escrow_address: &[u8; 32],
    source: &AmountCommitment,
    policy: &EscrowPolicy,
    finalized_global_frame: Option<u64>,
) -> Result<()> {
    let s = &claim.statement;
    if &s.network != network || &s.application != application || &s.escrow_address != escrow_address
        || &s.source != source || &s.policy != policy {
        return Err(invalid("claim does not match the stored escrow"));
    }
    let public_key = match s.branch {
        // Expiry does not revoke the recipient's right to claim.
        ClaimBranch::Recipient => &policy.recipient,
        ClaimBranch::Refund => {
            let frame = finalized_global_frame.ok_or_else(|| QuilError::ExecutionUnavailable(
                "refund requires consensus global anchor".into()))?;
            policy.key_for_branch(ClaimBranch::Refund, frame)
                .ok_or_else(|| invalid("refund before global deadline"))?
        }
    };
    let context = s.context_bytes().map_err(|_| invalid("invalid claim statement"))?;
    if !quil_crypto::falcon_verify(public_key, &claim.signature, &context,
        &parameter_context(network, application)) {
        return Err(invalid("invalid selected authority signature"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_lattice_ct::confidential::{
        pending_claim::PendingClaimStatement,
        transfer::{Output, MEMO_BYTES}, AmountOpening, CommitmentKey,
    };
    use quil_types::crypto::Signer;

    #[test]
    #[ignore = "native claim/refund proofs through configured worker and both execution venues"]
    fn complete_pending_claim_and_refund_with_worker() {
        use crate::{engines::{ExecutionMode, TokenExecutionEngine}, message_envelope::CanonicalMessageRequest,
            token_intrinsic::dispatch::TokenPolicy};
        use quil_lattice_ct::confidential::{address::RecipientAddress,
            memo::{create_escrow_recovery, create_output, open_escrow_recovery, open_output},
            relation::membership::RecipientSecret, transfer::TARGET_TRANSACTION_BYTES};
        use quil_types::execution::ShardExecutionEngine;
        use pqcrypto_ntruprime::sntrup761;
        use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
        use std::sync::Arc;
        let worker = WorkerVerifier::from_test_env(std::path::PathBuf::from(std::env::var("QUIL_AMOUNT_WORKER_PATH").unwrap())).unwrap();
        let budget = NativeBudget { max_native_bytes: 1 << 30 };
        let network = [111; 32]; let application = crate::domains::QUIL_TOKEN;
        let domain = parameter_context(&network, &application);
        let limits = SnapshotLimits { max_coins: 8, max_depth: 3, max_nodes: 24 };
        let policy = TokenPolicy { network, limits: CompileLimits { max_inputs: 1, max_outputs: 2, max_depth: 3 },
            snapshots: limits, native_budget: budget };
        let disk_state = |path: &std::path::Path| {
            let db = quil_store::RocksDb::open(path).unwrap();
            HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
                Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
                Arc::new(quil_types::crypto::NoopInclusionProver))))
        };
        for branch in [ClaimBranch::Recipient, ClaimBranch::Refund] {
            let started = std::time::Instant::now();
            let recipient = quil_crypto::FalconSigner::generate();
            let refunder = quil_crypto::FalconSigner::generate();
            let parties: Vec<_> = [112, 113].into_iter().map(|seed| {
                let secret = RecipientSecret::from_seed(&domain, &[seed; 32]);
                let (kem_public, kem_secret) = sntrup761::keypair();
                let address = RecipientAddress::new(&domain, &secret, kem_public.as_bytes()).unwrap();
                (secret, kem_secret, address)
            }).collect();
            let escrow = create_escrow_recovery(&domain, &parties[0].2, &parties[1].2, u128::MAX).unwrap();
            let escrow_policy = EscrowPolicy { recipient: recipient.public_key().try_into().unwrap(),
                refund: refunder.public_key().try_into().unwrap(), refund_after_global_frame: 100 };
            let pending_output = Output { commitment: escrow.commitment.clone(), owner: escrow.recipient.owner, memo: escrow.recipient.ciphertext };
            let (escrow_address, tree) = escrow::create_escrow(&domain, 1, &pending_output, &escrow_policy, &escrow.refund).unwrap();
            // Public bootstrap source, not proof of a prior funding transaction.
            let escrow_blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
            let selected = if branch == ClaimBranch::Recipient { 0 } else { 1 };
            let recovery = if selected == 0 { &escrow.recipient } else { &escrow.refund };
            let recovered = open_escrow_recovery(&domain, parties[selected].1.as_bytes(), &parties[selected].0,
                &escrow.commitment, recovery).unwrap();
            assert_eq!(recovered.amount(), u128::MAX);
            let amounts = [u128::MAX - 258, 256];
            let created: Vec<_> = amounts.iter().zip(&parties).map(|(&amount, party)|
                create_output(&domain, &party.2, amount).unwrap()).collect();
            let source_commitment = escrow.commitment.to_bytes();
            let escrow_refund_after = escrow_policy.refund_after_global_frame;
            let escrow_recipient = escrow_policy.recipient;
            let escrow_refund = escrow_policy.refund;
            let statement = PendingClaimStatement { network, application, escrow_address,
                source: escrow.commitment, policy: escrow_policy, branch, fee: 2,
                outputs: created.iter().map(|output| output.output.clone()).collect() };
            let openings: Vec<_> = amounts.iter().zip(&created).map(|(&amount, output)| (amount, &output.opening)).collect();
            let relation = statement.private_relation((recovered.amount(), recovered.opening()), &openings, 2).unwrap();
            eprintln!("native_pending_claim_proving branch={branch:?} seconds={:.3}", started.elapsed().as_secs_f64());
            let proof = native::prove(&relation, budget).unwrap(); drop(relation);
            let signer = if selected == 0 { &recipient } else { &refunder };
            let signature = signer.sign_with_domain(&statement.context_bytes().unwrap(), &domain).unwrap().try_into().unwrap();
            let claim = PendingClaim { statement, signature, proof };
            let bytes = claim.encode().unwrap();
            assert!(bytes.len() <= TARGET_TRANSACTION_BYTES);
            let message = CanonicalMessageRequest::wrap(bytes.clone()).unwrap().to_canonical_bytes().unwrap();
            assert!(message.len() < 1 << 20);
            if let Ok(directory) = std::env::var("QUIL_TEST_PENDING_CLAIM_DIR") {
                let directory = std::path::PathBuf::from(directory); std::fs::create_dir_all(&directory).unwrap();
                let name = if selected == 0 { "recipient" } else { "refund" };
                std::fs::write(directory.join(format!("{name}.bin")), &bytes).unwrap();
                std::fs::write(directory.join(format!("{name}-escrow.bin")), &escrow_blob).unwrap();
            }
            eprintln!("native_pending_claim_proved branch={branch:?} bytes={} proof_bytes={} seconds={:.3}", bytes.len(), claim.proof.len(), started.elapsed().as_secs_f64());
            for mode in [ExecutionMode::Application, ExecutionMode::Global] {
                let directory = tempfile::tempdir().unwrap();
                let state = disk_state(directory.path());
                let disc = vertex_adds_discriminator().unwrap();
                state.set(&application, &escrow_address, &disc, 1, escrow_blob.clone()).unwrap();
                // The escrow's creation committed: its GLOBAL record is what a
                // claim is decided against, and the blob above is the copy its
                // delivery left on the shard.
                let binding = crate::token_intrinsic::global_commit::escrow_binding(
                    &domain, &escrow_address, &source_commitment,
                    &escrow_recipient, &escrow_refund, escrow_refund_after);
                state.set(&crate::global_schema::GLOBAL_INTRINSIC_ADDRESS,
                    &crate::token_intrinsic::global_commit::escrow_address(&application, &escrow_address).unwrap(),
                    &disc, 1,
                    crate::token_intrinsic::global_commit::encode_escrow_record(
                        &binding, escrow_refund_after, false).unwrap()).unwrap();
                roots::refresh_root(&state, &network, &application, limits).unwrap();
                state.commit().unwrap(); state.abort(); state.crdt().commit(1).unwrap();
                let stubs = crate::testing::NoopExecutionCrypto::new();
                let engine = TokenExecutionEngine::new_with_state(mode,
                    Arc::new(quil_types::crypto::NoopInclusionProver), state.crdt().clone(), stubs.key_manager, stubs.clock_store)
                    .with_token_proofs(policy).unwrap().with_token_worker(worker.clone()).unwrap();
                let frame = if mode == ExecutionMode::Global { 101 } else { 10_000 };
                let execution = FrameExecutionContext { frame_number: frame, finalized_global_frame: Some(100), venue: None, shard: quil_types::execution::ShardPath::WHOLE };
                engine.validate_message(frame, &application, &message).unwrap();
                if branch == ClaimBranch::Refund {
                    let premature = if mode == ExecutionMode::Global {
                        // A caller-supplied anchor can carry a refund past
                        // verification, and the commit still refuses it: the
                        // frame that decides is the global frame it commits in.
                        FrameExecutionContext { frame_number: 99, finalized_global_frame: Some(999), venue: None, shard: quil_types::execution::ShardPath::WHOLE }
                    } else { FrameExecutionContext { finalized_global_frame: Some(99), ..execution } };
                    let before = roots::read_current(&state, &network, &application).unwrap();
                    let error = engine.process_message_with_context(premature, &num_bigint::BigInt::from(0), &application, &message).unwrap_err();
                    if mode == ExecutionMode::Global {
                        assert!(error.to_string().contains("refund before the escrow's refund frame"), "{error}");
                    }
                    assert_eq!(roots::read_current(&state, &network, &application).unwrap(), before);
                    assert!(!crate::token_intrinsic::global_commit::escrow(
                        &state, &application, &escrow_address).unwrap().unwrap().2);
                    for output in &claim.statement.outputs {
                        let (address, _) = state::coin_identity(&domain, premature.frame_number, output).unwrap();
                        assert!(state.get(&application, &address, &disc).unwrap().is_none());
                    }
                }
                engine.process_message_with_context(execution, &num_bigint::BigInt::from(0), &application, &message).unwrap();
                if mode == ExecutionMode::Application {
                    // An app shard verifies and relays the claim; the escrow is
                    // consumed and the outputs placed by the global commit, so
                    // no coin appeared here and a re-run verifies again.
                    assert_eq!(roots::read_current(&state, &network, &application).unwrap().unwrap().coins, 0);
                    assert!(!crate::token_intrinsic::global_commit::escrow(
                        &state, &application, &escrow_address).unwrap().unwrap().2);
                    engine.process_message_with_context(execution, &num_bigint::BigInt::from(0), &application, &message).unwrap();
                    eprintln!("native_pending_claim_verified branch={branch:?} mode={mode:?} bytes={}", bytes.len());
                    continue;
                }
                let root = roots::read_current(&state, &network, &application).unwrap().unwrap();
                assert_eq!(root.coins, 2);
                // The commit holds the escrow consumed, once.
                assert!(crate::token_intrinsic::global_commit::escrow(
                    &state, &application, &escrow_address).unwrap().unwrap().2);
                // Deterministically invalid operations roll back and return
                // rejection to the frame caller. A later frame would give new
                // coin addresses if the duplicate were mistakenly executed.
                let replay = FrameExecutionContext { frame_number: frame + 1, ..execution };
                engine.process_message_with_context(replay, &num_bigint::BigInt::from(0), &application, &message).unwrap_err();
                assert_eq!(roots::read_current(&state, &network, &application).unwrap(), Some(root.clone()));
                for output in &claim.statement.outputs {
                    let (address, _) = state::coin_identity(&domain, replay.frame_number, output).unwrap();
                    assert!(state.get(&application, &address, &disc).unwrap().is_none());
                }
                state.crdt().commit(frame).unwrap(); drop(engine); drop(state);
                let reopened = disk_state(directory.path());
                for (index, output) in claim.statement.outputs.iter().enumerate() {
                    let (address, _) = state::coin_identity(&domain, frame, output).unwrap();
                    let blob = reopened.get(&application, &address, &disc).unwrap().unwrap();
                    let tree = quil_tries::VectorCommitmentTree { root: quil_tries::deserialize_go_tree(&blob).unwrap() };
                    let stored = state::read_coin(&tree, &domain).unwrap().unwrap();
                    let opened = open_output(&domain, parties[index].1.as_bytes(), &parties[index].0, &stored.output).unwrap();
                    assert_eq!(opened.amount, amounts[index]);
                }
                let mut other = claim.clone();
                other.statement.branch = if selected == 0 { ClaimBranch::Refund } else { ClaimBranch::Recipient };
                let other_signer = if selected == 0 { &refunder } else { &recipient };
                other.signature = other_signer.sign_with_domain(&other.statement.context_bytes().unwrap(), &domain).unwrap().try_into().unwrap();
                // Both authorities are refused by the commit's consumed escrow,
                // including this altered-branch proof.
                let claim_tp = crate::token_engine::TYPE_LATTICE_PENDING_CLAIM;
                for refused in [&claim, &other] {
                    let error = crate::token_intrinsic::commit_apply::commit_and_place(
                        &reopened, frame + 2, &network, &application, claim_tp,
                        &refused.encode().unwrap(), limits).unwrap_err();
                    assert!(error.to_string().contains("already decided") || error.to_string().contains("escrow already consumed"), "{error}");
                    reopened.rollback_to(0);
                }
                assert_eq!(reopened.changeset_len(), 0);
                let snapshot = state::load_committed_snapshot(&reopened, &network, &application, limits).unwrap();
                assert_eq!(snapshot.root_at_depth(usize::from(root.depth)).unwrap(), root);
                eprintln!("native_pending_claim_executed branch={branch:?} mode={mode:?} bytes={} envelope_bytes={} seconds={:.3}", bytes.len(), message.len(), started.elapsed().as_secs_f64());
            }
        }
    }

    #[test]
    fn pending_claim_and_refund_share_consumption_and_rollback_after_restart() {
        use quil_lattice_ct::confidential::memo::EscrowRecoveryMemo;
        use std::sync::Arc;
        let disk_state = |path: &std::path::Path| {
            let db = quil_store::RocksDb::open(path).unwrap();
            HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
                Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
                Arc::new(quil_types::crypto::NoopInclusionProver),
            )))
        };
        for first in [ClaimBranch::Recipient, ClaimBranch::Refund] {
            let directory = tempfile::tempdir().unwrap();
            let state = disk_state(directory.path());
            let network = [91; 32]; let application = crate::domains::QUIL_TOKEN;
            let domain = parameter_context(&network, &application);
            let key = CommitmentKey::derive(&domain);
            let opening = AmountOpening::from_seed(&domain, &[92; 32]);
            let recipient = quil_crypto::FalconSigner::generate();
            let refunder = quil_crypto::FalconSigner::generate();
            let policy = EscrowPolicy { recipient: recipient.public_key().try_into().unwrap(),
                refund: refunder.public_key().try_into().unwrap(), refund_after_global_frame: 100 };
            let output = Output { commitment: key.commit(17, &opening), owner: [93; IDENTITY_BYTES], memo: [94; MEMO_BYTES] };
            let recovery = EscrowRecoveryMemo { owner: [95; IDENTITY_BYTES], ciphertext: [96; MEMO_BYTES] };
            let (escrow_address, tree) = escrow::create_escrow(&domain, 1, &output, &policy, &recovery).unwrap();
            let disc = vertex_adds_discriminator().unwrap();
            state.set(&application, &escrow_address, &disc, 1, quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()).unwrap();
            let limits = SnapshotLimits { max_coins: 4, max_depth: 3, max_nodes: 16 };
            let root = roots::refresh_root(&state, &network, &application, limits).unwrap();
            assert_eq!(root.coins, 0);
            let source_commitment = output.commitment.to_bytes();
            let (policy_recipient, policy_refund, policy_refund_after) = (policy.recipient, policy.refund, policy.refund_after_global_frame);
            let mut claim = PendingClaim { statement: PendingClaimStatement {
                network, application, escrow_address, source: output.commitment, policy,
                branch: first, fee: 2, outputs: vec![Output { commitment: key.commit(15, &opening), owner: [97; IDENTITY_BYTES], memo: [98; MEMO_BYTES] }],
            }, signature: [0; 666], proof: Vec::new() };
            let sign = |claim: &mut PendingClaim| {
                let signer = if claim.statement.branch == ClaimBranch::Recipient { &recipient } else { &refunder };
                claim.signature = signer.sign_with_domain(&claim.statement.context_bytes().unwrap(), &domain).unwrap().try_into().unwrap();
            };
            sign(&mut claim);
            let mut other = claim.clone();
            other.statement.branch = if first == ClaimBranch::Recipient { ClaimBranch::Refund } else { ClaimBranch::Recipient };
            sign(&mut other);
            // Structural proof framing: the commit decides consumption, and
            // nothing here verifies a proof.
            let placeholder = {
                let mut proof = vec![0; 40];
                proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
                proof
            };
            claim.proof = placeholder.clone();
            other.proof = placeholder;
            let refund = if first == ClaimBranch::Refund { &claim } else { &other };
            // The escrow's GLOBAL record is what a claim is decided against;
            // the blob on the shard is only the copy its delivery left there.
            let binding = crate::token_intrinsic::global_commit::escrow_binding(
                &domain, &escrow_address, &source_commitment,
                &policy_recipient, &policy_refund, policy_refund_after);
            let record_address = crate::token_intrinsic::global_commit::escrow_address(&application, &escrow_address).unwrap();
            state.set(&crate::global_schema::GLOBAL_INTRINSIC_ADDRESS, &record_address, &disc, 1,
                crate::token_intrinsic::global_commit::encode_escrow_record(&binding, 100, false).unwrap()).unwrap();
            let tp = crate::token_engine::TYPE_LATTICE_PENDING_CLAIM;
            let commit = |state: &HypergraphState, frame: u64, claim: &PendingClaim, limits| {
                crate::token_intrinsic::commit_apply::commit_and_place(
                    state, frame, &network, &application, tp, &claim.encode().unwrap(), limits)
            };
            let execution = FrameExecutionContext { frame_number: 10_000, finalized_global_frame: Some(100), venue: None, shard: quil_types::execution::ShardPath::WHOLE };
            // A refund commits only at or after the escrow's refund frame, and
            // the frame that decides it is the global one, not the app height.
            let saved = state.changeset_len();
            let error = commit(&state, 99, refund, limits).unwrap_err();
            assert!(error.to_string().contains("refund before the escrow's refund frame"), "{error}");
            state.rollback_to(saved);
            // A claim against an escrow the commit does not hold is refused.
            let mut unknown = claim.clone();
            unknown.statement.escrow_address = [77; 32];
            sign(&mut unknown);
            let error = commit(&state, 100, &unknown, limits).unwrap_err();
            assert!(error.to_string().contains("escrow does not exist"), "{error}");
            state.rollback_to(saved);
            // Partial coverage and an exhausted snapshot budget write nothing.
            state.crdt().set_covered_prefix(&quil_tries::get_full_path(&application)).unwrap();
            assert!(matches!(commit(&state, 100, &claim, limits), Err(QuilError::ExecutionUnavailable(_))));
            state.crdt().set_covered_prefix(&[]).unwrap();
            assert!(commit(&state, 100, &claim, SnapshotLimits { max_coins: 0, ..limits }).is_err());
            state.rollback_to(saved);
            assert_eq!(state.changeset_len(), saved);
            assert_eq!(roots::read_current(&state, &network, &application).unwrap(), Some(root));
            // Proof framing is structural here. Verify that exhaustion stays
            // unavailable and the worker's amount dispatcher recognizes claims.
            let bytes = claim.encode().unwrap();
            let dispatch = super::super::dispatch::TokenPolicy {
                network, limits: CompileLimits { max_inputs: 1, max_outputs: 2, max_depth: 1 },
                snapshots: limits, native_budget: NativeBudget { max_native_bytes: 0 },
            };
            let tp = crate::token_engine::TYPE_LATTICE_PENDING_CLAIM;
            dispatch.preflight(&application, &bytes, tp).unwrap();
            assert!(dispatch.preflight(&[0; 32], &bytes, tp).is_err());
            assert!((super::super::dispatch::TokenPolicy {
                limits: CompileLimits { max_outputs: 0, ..dispatch.limits }, ..dispatch
            }).preflight(&application, &bytes, tp).is_err());
            if first == ClaimBranch::Refund {
                assert!(matches!(dispatch.dispatch_for_commit(&state,
                    FrameExecutionContext { finalized_global_frame: Some(99), ..execution }, &crate::testing::NoopClockStore,
                    &application, &bytes, tp, None, None),
                    Err(QuilError::InvalidArgument(_))));
            }
            assert!(matches!(dispatch.dispatch_for_commit(&state, execution, &crate::testing::NoopClockStore,
                &application, &bytes, tp, None, None),
                Err(QuilError::ExecutionUnavailable(_))));
            use quil_lattice_ct::confidential::relation::backend::worker_request::{WorkerRequest, verify_amount_proof};
            assert!(matches!(verify_amount_proof(&WorkerRequest { network, application,
                limits: CompileLimits { max_inputs: 1, max_outputs: 2, max_depth: 1 }, submission_bytes: 0, transaction: &bytes }),
                Err(native::NativeError::AllocationBudget)));
            assert_eq!(state.changeset_len(), saved);
            // The commit places the claim's output and consumes the escrow.
            let placed = commit(&state, 100, &claim, limits).unwrap();
            assert_eq!(placed.len(), 1);
            let committed = roots::read_current(&state, &network, &application).unwrap().unwrap();
            assert_eq!(committed.coins, 1);
            assert!(crate::token_intrinsic::global_commit::escrow(&state, &application, &escrow_address).unwrap().unwrap().2);
            // Neither authority can claim it again.
            let saved = state.changeset_len();
            for replay in [&claim, &other] {
                let error = commit(&state, 101, replay, limits).unwrap_err();
                assert!(error.to_string().contains("already decided") || error.to_string().contains("escrow already consumed"), "{error}");
                state.rollback_to(saved);
            }
            state.commit().unwrap(); state.abort(); state.crdt().commit(execution.frame_number).unwrap(); drop(state);
            let reopened = disk_state(directory.path());
            for replay in [&claim, &other] {
                assert!(commit(&reopened, 102, replay, limits).is_err());
                reopened.rollback_to(0);
            }
            assert_eq!(reopened.changeset_len(), 0);
            let snapshot = state::load_committed_snapshot(&reopened, &network, &application, limits).unwrap();
            assert_eq!(snapshot.root_at_depth(usize::from(committed.depth)).unwrap(), committed);
            assert!(reopened.get(&application, &escrow_address, &disc).unwrap().is_some());
        }
    }

    #[test]
    fn pending_claim_authorization_uses_stored_policy_and_global_refund_boundary() {
        let recipient = quil_crypto::FalconSigner::generate();
        let refunder = quil_crypto::FalconSigner::generate();
        let network = [81; 32];
        let app = crate::domains::QUIL_TOKEN;
        let domain = parameter_context(&network, &app);
        let key = CommitmentKey::derive(&domain);
        let opening = AmountOpening::from_seed(&domain, &[82; 32]);
        let source = key.commit(17, &opening);
        let address = [83; 32];
        let policy = EscrowPolicy {
            recipient: recipient.public_key().try_into().unwrap(),
            refund: refunder.public_key().try_into().unwrap(),
            refund_after_global_frame: 100,
        };
        let mut claim = PendingClaim {
            statement: PendingClaimStatement {
                network, application: app, escrow_address: address,
                source: source.clone(), policy: policy.clone(), branch: ClaimBranch::Recipient,
                fee: 2, outputs: vec![Output { commitment: key.commit(15, &opening),
                    owner: [84; IDENTITY_BYTES], memo: [85; MEMO_BYTES] }],
            }, signature: [0; 666], proof: Vec::new(),
        };
        let sign = |claim: &mut PendingClaim, signer: &quil_crypto::FalconSigner| {
            claim.signature = signer.sign_with_domain(&claim.statement.context_bytes().unwrap(), &domain)
                .unwrap().try_into().unwrap();
        };
        let check = |claim: &PendingClaim, frame| check_authorization(claim, &network, &app,
            &address, &source, &policy, frame);
        sign(&mut claim, &recipient);
        for frame in [None, Some(0), Some(99), Some(100), Some(u64::MAX)] {
            check(&claim, frame).unwrap();
        }
        let original = claim.clone();
        claim.statement.branch = ClaimBranch::Refund;
        assert!(check(&claim, Some(100)).is_err()); // Recipient signature cannot authorize refund.
        sign(&mut claim, &refunder);
        assert!(matches!(check(&claim, None), Err(QuilError::ExecutionUnavailable(_))));
        assert!(matches!(check(&claim, Some(99)), Err(QuilError::InvalidArgument(_))));
        check(&claim, Some(100)).unwrap();
        check(&claim, Some(u64::MAX)).unwrap();
        claim.statement.branch = ClaimBranch::Recipient;
        assert!(check(&claim, Some(100)).is_err());

        // Re-signing transaction-supplied source policy cannot replace state.
        let mut altered = original.clone();
        altered.statement.policy.recipient = policy.refund;
        sign(&mut altered, &refunder);
        assert!(check(&altered, Some(100)).is_err());
        let mut altered = original.clone(); altered.statement.policy.refund_after_global_frame = 0;
        sign(&mut altered, &recipient); assert!(check(&altered, Some(0)).is_err());
        let mut altered = original.clone(); altered.statement.source = key.commit(18, &opening);
        sign(&mut altered, &recipient); assert!(check(&altered, Some(100)).is_err());
        let mut altered = original.clone(); altered.statement.escrow_address[0] ^= 1;
        sign(&mut altered, &recipient); assert!(check(&altered, Some(100)).is_err());
        // The complete destination and fee are covered by the selected signature.
        for field in 0..4 {
            let mut altered = original.clone();
            match field {
                0 => altered.statement.outputs[0].owner[0] ^= 1,
                1 => altered.statement.outputs[0].memo[0] ^= 1,
                2 => altered.statement.outputs[0].commitment = key.commit(14, &opening),
                _ => altered.statement.fee += 1,
            }
            assert!(check(&altered, Some(100)).is_err());
        }
        assert!(check_authorization(&original, &[86; 32], &app, &address, &source, &policy, Some(100)).is_err());
        // Empty proof is intentional: this check alone is not proof admission.
        assert!(original.proof.is_empty());
    }
}
