//! Verification of a confidential operation that commits through the global
//! frame.
//!
//! The executing shard checks the proof and everything provable from the
//! operation itself — encodings, dimensions, signatures, payment coins, a
//! mint claim's authorization against its cited global root, a shield's
//! immutable legacy source. It does not read consume-once state (spent images,
//! escrow records, receipts) or decide root retention: those are the global
//! commit's to decide, once, for every shard. It writes nothing.
use super::{mint_claim, pending_claim, shield};
use crate::hypergraph_state::HypergraphState;
use crate::token_engine::{
    TYPE_LATTICE_MINT_CLAIM, TYPE_LATTICE_PENDING, TYPE_LATTICE_PENDING_CLAIM,
    TYPE_LATTICE_SETTLEMENT, TYPE_LATTICE_SHIELD, TYPE_LATTICE_TRANSACTION,
};
use quil_lattice_ct::confidential::{
    pending_claim::PendingClaim,
    pending_create::PendingCreate,
    relation::backend::{
        native::{self, NativeBudget},
        worker_client::WorkerVerifier,
    },
    settlement::Settlement,
    shield::AnyShield,
    transfer::{CompileLimits, Transfer, TransferStatement},
    MAX_PRIVATE_COINS,
};
use quil_types::{
    error::{QuilError, Result},
    execution::FrameExecutionContext,
    store::ClockStore,
};
use std::collections::BTreeSet;

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("commit verification: {message}"))
}

/// The proof, in the configured worker or in process.
fn verify_proof(
    worker: Option<&WorkerVerifier>,
    network: &[u8; 32],
    application: &[u8; 32],
    bytes: &[u8],
    limits: CompileLimits,
    budget: NativeBudget,
    relation: impl FnOnce() -> Result<quil_lattice_ct::confidential::relation::PublicAmountRelation>,
    proof: &[u8],
) -> Result<()> {
    if let Some(worker) = worker {
        return super::dispatch::verify_in_worker(
            worker,
            network,
            application,
            bytes,
            limits,
            budget,
        );
    }
    let accepted = native::verify_owned(relation()?, proof, budget)
        .map_err(|e| QuilError::ExecutionUnavailable(format!("proof backend: {e:?}")))?;
    if !accepted {
        return Err(invalid("invalid proof"));
    }
    Ok(())
}

fn funding_shape(s: &TransferStatement, limits: CompileLimits) -> Result<()> {
    if s.images.is_empty()
        || s.images.len() > MAX_PRIVATE_COINS
        || s.images.iter().collect::<BTreeSet<_>>().len() != s.images.len()
        || s.images.len() > limits.max_inputs
        || s.outputs.len() > limits.max_outputs
        || usize::from(s.depth) > limits.max_depth
    {
        return Err(invalid("spend shape outside the configured limits"));
    }
    Ok(())
}

/// A pending claim's branch authority signed it, under the escrow terms the
/// claim names (the global commit holds them to the stored escrow); a
/// refund is also held to GLOBAL frame `frame`, the executing frame's
/// anchor.
fn claim_authorization(
    claim: &PendingClaim,
    network: &[u8; 32],
    application: &[u8; 32],
    frame: Option<u64>,
) -> Result<()> {
    let s = &claim.statement;
    pending_claim::check_authorization(
        claim,
        network,
        application,
        &s.escrow_address,
        &s.source,
        &s.policy,
        frame,
    )
}

/// Whether [`verify_for_commit`] refuses pending claim `claim` before its
/// proof for its authority's signature, at whatever frame executes it: its
/// authorization check at a frame past any refund deadline, which reads the
/// signature alone. Whether a refund is due yet is the executing frame's
/// to judge, and is not read here.
pub(crate) fn claim_signature_refused(
    claim: &PendingClaim,
    network: &[u8; 32],
    application: &[u8; 32],
) -> bool {
    matches!(
        claim_authorization(claim, network, application, Some(u64::MAX)),
        Err(QuilError::InvalidArgument(_))
    )
}

/// A settlement's terms that [`verify_for_commit`] checks before its proof,
/// from its bytes alone: its payment coin matches its payment, and a
/// pre-funded claimant's key is post-quantum.
pub(crate) fn settlement_terms(tx: &Settlement) -> Result<()> {
    tx.statement
        .check_payment()
        .map_err(|_| invalid("payment coin does not match the payment"))?;
    if let Some(claimant) = &tx.statement.claimant {
        if !super::signature::is_post_quantum_authority(claimant.key_type) {
            return Err(invalid(
                "settlement claimant keys must be post-quantum (Falcon-512)",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn verify_for_commit(
    state: &HypergraphState,
    clock: &dyn ClockStore,
    context: FrameExecutionContext,
    network: &[u8; 32],
    application: &[u8; 32],
    tp: u32,
    bytes: &[u8],
    limits: CompileLimits,
    budget: NativeBudget,
    worker: Option<&WorkerVerifier>,
) -> Result<()> {
    let decode = |_| invalid("invalid operation encoding or context");
    match tp {
        TYPE_LATTICE_TRANSACTION => {
            let tx = Transfer::decode(bytes, network, application).map_err(decode)?;
            funding_shape(&tx.statement, limits)?;
            verify_proof(
                worker,
                network,
                application,
                bytes,
                limits,
                budget,
                || {
                    tx.statement
                        .public_relation(limits)
                        .map_err(|_| invalid("invalid or oversized relation"))
                },
                &tx.proof,
            )
        }
        TYPE_LATTICE_PENDING => {
            let tx = PendingCreate::decode(bytes, network, application).map_err(decode)?;
            tx.statement
                .split_outputs()
                .map_err(|_| invalid("missing escrow output"))?;
            funding_shape(&tx.statement.funding, limits)?;
            verify_proof(
                worker,
                network,
                application,
                bytes,
                limits,
                budget,
                || {
                    tx.statement
                        .public_relation(limits)
                        .map_err(|_| invalid("invalid or oversized relation"))
                },
                &tx.proof,
            )
        }
        TYPE_LATTICE_PENDING_CLAIM => {
            let claim = PendingClaim::decode(bytes, network, application).map_err(decode)?;
            let s = &claim.statement;
            if s.outputs.len() > limits.max_outputs {
                return Err(invalid("too many outputs"));
            }
            // The branch's authority signs the claim. A refund is also held to
            // this frame's anchor here (the commit re-checks it at its own,
            // later frame), so an early refund is not relayed at all.
            claim_authorization(&claim, network, application, context.finalized_global_frame)?;
            let claim_limits = CompileLimits {
                max_inputs: 1,
                max_outputs: limits.max_outputs,
                max_depth: 1,
            };
            verify_proof(
                worker,
                network,
                application,
                bytes,
                claim_limits,
                budget,
                || {
                    s.public_relation(limits.max_outputs)
                        .map_err(|_| invalid("invalid or oversized relation"))
                },
                &claim.proof,
            )
        }
        TYPE_LATTICE_SHIELD => {
            // One legacy coin, or (from the batch shield frame) many.
            let tx = AnyShield::decode(bytes, network, application).map_err(decode)?;
            if tx.outputs().len() > limits.max_outputs {
                return Err(invalid("too many outputs"));
            }
            let active = super::global_commit::batch_shields_active(context.finalized_global_frame);
            let migrated_owners =
                super::legacy_migration::migrated_owners_active(context.finalized_global_frame);
            shield::check_sources(
                state,
                context.shard,
                active,
                migrated_owners,
                application,
                &tx,
            )?;
            shield::check_authorization(&tx)?;
            let shield_limits = CompileLimits {
                max_inputs: 1,
                max_outputs: limits.max_outputs,
                max_depth: 1,
            };
            verify_proof(
                worker,
                network,
                application,
                bytes,
                shield_limits,
                budget,
                || {
                    tx.public_relation(limits.max_outputs)
                        .map_err(|_| invalid("invalid or oversized relation"))
                },
                tx.proof(),
            )
        }
        TYPE_LATTICE_MINT_CLAIM => {
            // Proves its authorization receipt against a cited global root;
            // whether the receipt was already claimed is the commit's decision.
            mint_claim::verify_from_clock(
                clock,
                context,
                network,
                application,
                bytes,
                limits.max_outputs,
            )
            .map(|_| ())
        }
        TYPE_LATTICE_SETTLEMENT => {
            if application != &crate::domains::QUIL_TOKEN {
                return Err(invalid("settlements spend QUIL"));
            }
            let tx = Settlement::decode(bytes, network, application).map_err(decode)?;
            settlement_terms(&tx)?;
            funding_shape(&tx.statement.funding, limits)?;
            verify_proof(
                worker,
                network,
                application,
                bytes,
                limits,
                budget,
                || {
                    tx.statement
                        .public_relation(limits)
                        .map_err(|_| invalid("invalid or oversized relation"))
                },
                &tx.proof,
            )
        }
        _ => Err(invalid(
            "operation does not commit through the global frame",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypergraph_state::vertex_adds_discriminator;
    use crate::token_intrinsic::{
        commit_apply, roots,
        state::{self, SnapshotLimits},
    };
    use quil_lattice_ct::confidential::{
        relation::backend::native,
        transfer::{parameter_context, TransferStatement},
    };
    use quil_types::crypto::NoopInclusionProver;
    use std::sync::Arc;

    /// Class guard for execution's refusals before the proof: every check
    /// [`verify_for_commit`] makes ahead of a proof (each literal refusal
    /// and each call whose error `?` returns) is classed here: read ahead by
    /// `ExecutionEngineManager::execution_standing` through the same routine
    /// (so arrival, the proposal filter and every pre-verification refuse
    /// it before any proof work), made by dispatch's preflight first, or
    /// not readable ahead, with why. A new check fails this test until it is
    /// classed, and a check classed as read ahead must be called there.
    #[test]
    fn every_refusal_before_the_proof_is_read_ahead_or_classed() {
        use crate::token_intrinsic::global_commit::{
            guard_body, guard_fallible_calls, guard_source,
        };
        // (check, the call execution_standing reads it by, or why none).
        const CLASSED: [(&str, std::result::Result<&str, &str>); 17] = [
            (
                "invalid operation encoding or context",
                Err("preflight decodes it first"),
            ),
            ("Transfer::decode", Err("preflight decodes it first")),
            ("PendingCreate::decode", Err("preflight decodes it first")),
            ("PendingClaim::decode", Err("preflight decodes it first")),
            ("AnyShield::decode", Err("preflight decodes it first")),
            ("Settlement::decode", Err("preflight decodes it first")),
            (
                "funding_shape",
                Err("preflight's dimensions; decoding refuses no, duplicate or too many images"),
            ),
            (
                "split_outputs",
                Err("decoding refuses a spend without outputs"),
            ),
            (
                "missing escrow output",
                Err("decoding refuses a spend without outputs"),
            ),
            ("too many outputs", Err("preflight's dimensions")),
            (
                "settlements spend QUIL",
                Err("preflight's application check"),
            ),
            (
                "claim_authorization",
                Ok("commit_verify::claim_signature_refused("),
            ),
            ("shield::check_sources", Ok("shield::source_standing(")),
            (
                "shield::check_authorization",
                Ok("shield::source_standing("),
            ),
            ("settlement_terms", Ok("commit_verify::settlement_terms(")),
            (
                "invalid or oversized relation",
                Err("the relation its proof is verified against: proof work"),
            ),
            (
                "operation does not commit through the global frame",
                Err("dispatch_for_commit routes only what commits globally here"),
            ),
        ];
        let source = guard_source(include_str!("commit_verify.rs"));
        let manager = include_str!("../manager.rs");
        let standing = {
            let start = manager
                .find("fn execution_standing(")
                .expect("execution_standing");
            let end = start + manager[start..].find("fn proof_refused(").expect("its end");
            &manager[start..end]
        };
        // The checks of verify_for_commit's body in `source` no entry classes.
        let unclassed = |source: &str| -> Vec<String> {
            let body = guard_body(source, "pub fn verify_for_commit");
            let mut checks: Vec<String> = body
                .match_indices("invalid(\"")
                .map(|(at, call)| {
                    let rest = &body[at + call.len()..];
                    rest[..rest.find('"').expect("end of the literal")].to_string()
                })
                .collect();
            checks.extend(guard_fallible_calls(body));
            checks.retain(|check| !CLASSED.iter().any(|(classed, _)| classed == check));
            checks
        };
        let unread = unclassed(&source);
        assert!(
            unread.is_empty(),
            "verify_for_commit refuses before the proof for {unread:?}: read it ahead in \
             ExecutionEngineManager::execution_standing through the same routine, or class it \
             here with why it cannot be"
        );
        let body = guard_body(&source, "pub fn verify_for_commit");
        for (check, read) in CLASSED {
            assert!(
                body.contains(check),
                "{check:?} is no longer a check of verify_for_commit: drop it here"
            );
            if let Ok(call) = read {
                assert!(
                    standing.contains(call),
                    "{check:?} is classed as read ahead by {call:?}, which execution_standing \
                     does not call"
                );
            }
        }
        // The guard catches a check added ahead of a proof.
        let planted = source.replacen(
            "            settlement_terms(&tx)?;\n",
            "            settlement_terms(&tx)?;\nplanted_check(&tx)?;\n\
             return Err(invalid(\"planted refusal\"));\n",
            1,
        );
        assert_eq!(
            unclassed(&planted),
            ["planted refusal", "planted_check"],
            "the guard missed a planted check"
        );
    }

    /// A claim's authority signature is judged ahead of the proof at any
    /// frame: one its branch's authority signed stands, before its refund
    /// deadline too (the executing frame judges that), and one signed by
    /// another key or not at all is refused.
    #[test]
    fn a_claims_signature_is_judged_ahead_and_its_refund_deadline_is_not() {
        use quil_lattice_ct::confidential::{
            pending_claim::{ClaimBranch, EscrowPolicy, PendingClaimStatement},
            transfer::{Output, MEMO_BYTES},
            AmountOpening, CommitmentKey,
        };
        use quil_types::crypto::Signer;
        let (recipient, refunder) = (
            quil_crypto::FalconSigner::generate(),
            quil_crypto::FalconSigner::generate(),
        );
        let (network, application) = ([91; 32], crate::domains::QUIL_TOKEN);
        let domain = parameter_context(&network, &application);
        let key = CommitmentKey::derive(&domain);
        let opening = AmountOpening::from_seed(&domain, &[92; 32]);
        let claim = |branch: ClaimBranch, signer: Option<&quil_crypto::FalconSigner>| {
            let statement = PendingClaimStatement {
                network,
                application,
                escrow_address: [93; 32],
                source: key.commit(17, &opening),
                policy: EscrowPolicy {
                    recipient: recipient.public_key().try_into().unwrap(),
                    refund: refunder.public_key().try_into().unwrap(),
                    refund_after_global_frame: 100,
                },
                branch,
                fee: 2,
                outputs: vec![Output {
                    commitment: key.commit(15, &opening),
                    owner: [94;
                        quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES],
                    memo: [95; MEMO_BYTES],
                }],
            };
            let signature = signer.map_or([0; 666], |signer| {
                signer
                    .sign_with_domain(&statement.context_bytes().unwrap(), &domain)
                    .unwrap()
                    .try_into()
                    .unwrap()
            });
            PendingClaim {
                statement,
                signature,
                proof: Vec::new(),
            }
        };
        let refused = |claim: &PendingClaim| claim_signature_refused(claim, &network, &application);
        let early_refund = claim(ClaimBranch::Refund, Some(&refunder));
        assert!(
            !refused(&claim(ClaimBranch::Recipient, Some(&recipient))) && !refused(&early_refund),
            "a claim its authority signed was refused ahead, a refund before its deadline too"
        );
        assert!(
            claim_authorization(&early_refund, &network, &application, Some(99)).is_err(),
            "execution refuses the refund before its deadline"
        );
        for (name, forged) in [
            ("unsigned", claim(ClaimBranch::Recipient, None)),
            (
                "another key",
                claim(ClaimBranch::Recipient, Some(&refunder)),
            ),
            (
                "a refund signed by the recipient",
                claim(ClaimBranch::Refund, Some(&recipient)),
            ),
        ] {
            assert!(refused(&forged), "{name}: not refused ahead");
        }
    }

    fn disk_state(path: &std::path::Path) -> HypergraphState {
        let db = quil_store::RocksDb::open(path).unwrap();
        HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
            Arc::new(NoopInclusionProver),
        )))
    }

    fn context_at(frame: u64) -> FrameExecutionContext {
        FrameExecutionContext {
            frame_number: frame,
            finalized_global_frame: Some(frame.saturating_sub(1)),
            shard: quil_types::execution::ShardPath::WHOLE,
            venue: None,
        }
    }

    #[test]
    #[ignore = "complete native proof uses substantial time and memory; run via Taskfile"]
    fn complete_transfer_verifies_and_commits() {
        run_complete_transfer(false, None);
    }

    #[test]
    #[ignore = "complete native transfer through the token engine and RocksDB"]
    fn complete_transfer_through_token_engine() {
        run_complete_transfer(true, None);
    }

    #[test]
    #[ignore = "requires native worker; complete transfer through the engine and RocksDB recovery"]
    fn complete_transfer_with_worker() {
        use quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier;
        let path = std::env::var("QUIL_AMOUNT_WORKER_PATH").expect("native worker path");
        let worker = WorkerVerifier::from_test_env(path.into()).unwrap();
        run_complete_transfer(true, Some(worker));
    }

    /// Prove a real transfer, then take it through the path a live operation
    /// takes: verification that writes nothing, then the commit, which decides
    /// the spend once, places the outputs at the positions it assigns and
    /// publishes the root they produce.
    fn run_complete_transfer(
        engine_route: bool,
        worker: Option<
            quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier,
        >,
    ) {
        use pqcrypto_ntruprime::sntrup761;
        use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
        use quil_lattice_ct::confidential::{
            address::RecipientAddress,
            memo::{create_output, open_output},
            relation::membership::{InputPath, MembershipKey, RecipientSecret},
            transfer::TARGET_TRANSACTION_BYTES,
        };
        let started = std::time::Instant::now();
        let budget = NativeBudget {
            max_native_bytes: std::env::var("QUIL_TEST_NATIVE_MIB")
                .unwrap_or_else(|_| "24576".into())
                .parse::<usize>()
                .unwrap()
                .checked_mul(1 << 20)
                .unwrap(),
        };
        let directory = tempfile::tempdir().unwrap();
        let state = disk_state(directory.path());
        let network = [1; 32];
        let application = if engine_route {
            crate::domains::QUIL_TOKEN
        } else {
            [2; 32]
        };
        // Reserve above the strict payload ceiling for a unit dynamic price.
        // The fee remains proof-bound; adjust the first recipient accordingly.
        let fee: u128 = if engine_route { 1 << 20 } else { 2 };
        let context = parameter_context(&network, &application);
        // Coins sit at the positions their blocks give them, so the
        // accumulator has its real depth and the circuit must match it.
        let limits = SnapshotLimits {
            max_coins: 8,
            max_depth: 32,
            max_nodes: 1 << 12,
        };
        let disc = vertex_adds_discriminator().unwrap();
        let recipient = RecipientSecret::from_seed(&context, &[99; 32]);
        let (public, secret) = sntrup761::keypair();
        let address = RecipientAddress::new(&context, &recipient, public.as_bytes()).unwrap();
        let mut input_outputs = Vec::new();
        let mut input_notes = Vec::new();
        let mut input_addresses = Vec::new();
        // Bootstrap only the initial funded state, at the positions the
        // accumulator's blocks give them — the spend proves against that root.
        let mut staged = std::collections::BTreeMap::new();
        for amount in [u128::MAX, 257] {
            let created = create_output(&context, &address, amount).unwrap();
            let opened =
                open_output(&context, secret.as_bytes(), &recipient, &created.output).unwrap();
            assert_eq!(opened.amount, amount);
            let (coin_address, tree) = roots::stage_coin(
                &state,
                &network,
                &application,
                &context,
                0,
                &created.output,
                &mut staged,
                limits,
            )
            .unwrap();
            state
                .set(
                    &application,
                    &coin_address,
                    &disc,
                    0,
                    quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
                )
                .unwrap();
            input_addresses.push(coin_address);
            input_outputs.push(created.output);
            input_notes.push(opened);
        }
        let root = roots::refresh_root(&state, &network, &application, limits).unwrap();
        // What a shard's accumulator report publishes for a split application,
        // and the inline commit for a global one: without it no spend's root is
        // canonical and the commit refuses every one of them.
        commit_apply::publish_canonical_root(&state, 1, &network, &application).unwrap();
        state.commit().unwrap();
        state.abort();
        state.crdt().commit(1).unwrap();
        let snapshot =
            state::load_committed_snapshot(&state, &network, &application, limits).unwrap();
        assert_eq!(
            snapshot.root_at_depth(snapshot.current_depth()).unwrap(),
            root
        );
        let auth: Vec<_> = input_addresses
            .iter()
            .map(|address| {
                snapshot
                    .auth_path_at_depth(address, usize::from(root.depth))
                    .unwrap()
            })
            .collect();
        let admitted_root_bytes = root.encode().unwrap();
        let paths: Vec<_> = input_notes
            .iter()
            .zip(&auth)
            .map(|(note, path)| InputPath {
                owner: &note.secrets.owner,
                siblings: &path.siblings,
                right: &path.right,
            })
            .collect();
        let inputs: Vec<_> = input_notes
            .iter()
            .zip(&input_outputs)
            .map(|(note, output)| (note.amount, &note.secrets.opening, &output.commitment))
            .collect();
        let membership = MembershipKey::derive(&context);
        let mut statement = TransferStatement {
            network,
            application,
            depth: root.depth,
            root: root.root.clone(),
            images: input_notes
                .iter()
                .map(|note| {
                    membership
                        .key_image(&note.secrets.owner)
                        .identity_bytes()
                        .unwrap()
                })
                .collect(),
            outputs: Vec::new(),
            fee,
        };
        let mut output_openings = Vec::new();
        let mut recipients = Vec::new();
        let output_amounts = [u128::MAX - (fee - 1), 256];
        for (i, &amount) in output_amounts.iter().enumerate() {
            let recipient = RecipientSecret::from_seed(&context, &[110 + i as u8; 32]);
            let (public, secret) = sntrup761::keypair();
            let address = RecipientAddress::new(&context, &recipient, public.as_bytes()).unwrap();
            let address = RecipientAddress::decode(&address.encode(), &context).unwrap();
            let created = create_output(&context, &address, amount).unwrap();
            statement.outputs.push(created.output);
            output_openings.push(created.opening);
            recipients.push((recipient, secret));
        }
        let outputs: Vec<_> = output_amounts
            .iter()
            .zip(&output_openings)
            .map(|(&amount, opening)| (amount, opening))
            .collect();
        let compile_limits = CompileLimits {
            max_inputs: 2,
            max_outputs: 2,
            max_depth: 32,
        };
        let relation = statement
            .private_relation(&inputs, &outputs, &paths, compile_limits)
            .unwrap();
        eprintln!(
            "execution_transfer_loaded depth={} seconds={:.3}",
            statement.depth,
            started.elapsed().as_secs_f64()
        );
        let proof = native::prove(&relation, budget).unwrap();
        drop(relation);
        let transfer = Transfer { statement, proof };
        let bytes = transfer.encode().unwrap();
        assert!(bytes.len() <= TARGET_TRANSACTION_BYTES);
        if let Ok(path) = std::env::var("QUIL_TEST_TRANSACTION_PATH") {
            std::fs::write(&path, &bytes).unwrap();
            std::fs::write(format!("{path}.root"), &admitted_root_bytes).unwrap();
        }
        eprintln!(
            "execution_transfer_proved bytes={} proof_bytes={} seconds={:.3}",
            bytes.len(),
            transfer.proof.len(),
            started.elapsed().as_secs_f64()
        );

        let tp = crate::token_engine::TYPE_LATTICE_TRANSACTION;
        let clock = crate::testing::NoopClockStore;
        let output_addresses: Vec<[u8; 32]> = if engine_route {
            use crate::{
                engines::{ExecutionMode, TokenExecutionEngine},
                message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest},
                token_intrinsic::dispatch::TokenPolicy,
            };
            use quil_types::execution::ShardExecutionEngine;
            let stubs = crate::testing::NoopExecutionCrypto::new();
            // The global venue: it verifies, commits and places in one pass, as
            // it does for an application no shard covers.
            let engine = TokenExecutionEngine::new_with_state(
                ExecutionMode::Global,
                Arc::new(NoopInclusionProver),
                state.crdt().clone(),
                stubs.key_manager,
                stubs.clock_store,
            )
            .with_token_proofs(TokenPolicy {
                network,
                limits: compile_limits,
                snapshots: limits,
                native_budget: budget,
            })
            .unwrap();
            let engine = match &worker {
                Some(worker) => engine.with_token_worker(worker.clone()).unwrap(),
                None => engine,
            };
            let request = CanonicalMessageRequest::wrap(bytes.clone()).unwrap();
            // The same operation twice: the commit decides it once, so the
            // second is a rejection that rolls the whole bundle back.
            let bundle = CanonicalMessageBundle {
                requests: vec![Some(request.clone()), Some(request.clone())],
                timestamp: 0,
            }
            .to_canonical_bytes()
            .unwrap();
            assert!(engine.validate_message(2, &[99; 32], &bundle).is_err());
            engine.validate_message(2, &application, &bundle).unwrap();
            let before = roots::read_current(&state, &network, &application).unwrap();
            // The charge is the committed state growth, not the payload length.
            let growth = u128::from(super::super::cost::state_growth(&bytes).unwrap());
            assert!(fee >= growth);
            let excessive_price = num_bigint::BigInt::from(fee / growth + 1);
            let underpaid = engine
                .process_message(
                    2,
                    &excessive_price,
                    &application,
                    &request.to_canonical_bytes().unwrap(),
                )
                .unwrap_err();
            assert!(underpaid
                .to_string()
                .contains("QUIL fee below operation's dynamic cost"));
            assert_eq!(
                roots::read_current(&state, &network, &application).unwrap(),
                before
            );
            let error = engine
                .process_message(2, &num_bigint::BigInt::from(1), &application, &bundle)
                .unwrap_err();
            assert!(!error.is_execution_unavailable());
            assert_eq!(
                roots::read_current(&state, &network, &application).unwrap(),
                before
            );
            engine
                .process_message(
                    2,
                    &num_bigint::BigInt::from(1),
                    &application,
                    &request.to_canonical_bytes().unwrap(),
                )
                .unwrap();
            transfer
                .statement
                .outputs
                .iter()
                .map(|output| state::coin_identity(&context, 2, output).unwrap().0)
                .collect()
        } else {
            // Verification alone: an app shard checks exactly this and writes
            // nothing, relaying the spend for the global frame to decide.
            let before = state.changeset_len();
            verify_for_commit(
                &state,
                &clock,
                context_at(2),
                &network,
                &application,
                tp,
                &bytes,
                compile_limits,
                budget,
                worker.as_ref(),
            )
            .unwrap();
            assert_eq!(
                state.changeset_len(),
                before,
                "verification must not write state"
            );
            commit_apply::commit_and_place(&state, 2, &network, &application, tp, &bytes, limits)
                .unwrap()
        };
        let committed = roots::read_current(&state, &network, &application)
            .unwrap()
            .unwrap();
        assert_eq!(committed.coins, 4); // Spent inputs remain in the anonymity set.
                                        // Replaying it is refused by the commit — the images are consumed —
                                        // and the verification it would pass is not enough to spend twice.
        verify_for_commit(
            &state,
            &clock,
            context_at(3),
            &network,
            &application,
            tp,
            &bytes,
            compile_limits,
            budget,
            worker.as_ref(),
        )
        .unwrap();
        let replay =
            commit_apply::commit_and_place(&state, 3, &network, &application, tp, &bytes, limits)
                .unwrap_err();
        assert!(replay.to_string().contains("already decided"), "{replay}");
        state.commit().unwrap();
        state.abort();
        state.crdt().commit(2).unwrap();
        // Drop every database owner, then require replay rejection and recipient
        // recovery from a fresh RocksDB handle rather than retained CRDT caches.
        drop(state);
        let state = disk_state(directory.path());
        let replay =
            commit_apply::commit_and_place(&state, 4, &network, &application, tp, &bytes, limits)
                .unwrap_err();
        assert!(replay.to_string().contains("already decided"), "{replay}");
        for ((address, (recipient, secret)), &amount) in output_addresses
            .iter()
            .zip(&recipients)
            .zip(&output_amounts)
        {
            let blob = state.get(&application, address, &disc).unwrap().unwrap();
            let tree = quil_tries::VectorCommitmentTree {
                root: quil_tries::deserialize_go_tree(&blob).unwrap(),
            };
            let coin = state::read_coin(&tree, &context).unwrap().unwrap();
            let opened = open_output(&context, secret.as_bytes(), recipient, &coin.output).unwrap();
            assert_eq!(opened.amount, amount);
            assert_eq!(
                membership
                    .owner_key(&opened.secrets.owner)
                    .identity_bytes()
                    .unwrap(),
                coin.output.owner
            );
        }
        let snapshot =
            state::load_committed_snapshot(&state, &network, &application, limits).unwrap();
        assert_eq!(
            snapshot
                .root_at_depth(usize::from(committed.depth))
                .unwrap(),
            committed
        );
        eprintln!("execution_transfer_complete native_verified=true rocksdb_reopened=true persisted_recipients=2 replay_rejected=true engine_route={} fee={} bytes={} seconds={:.3}",
            engine_route, fee, bytes.len(), started.elapsed().as_secs_f64());
    }
}
