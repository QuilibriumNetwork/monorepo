//! Explicit token-suite policy for token-engine integration.
//! There is no default policy and no fallback to the old confidential suite.
use super::{custom_mint, state::SnapshotLimits};
use crate::{domains, hypergraph_state::HypergraphState, token_engine::*};
use quil_lattice_ct::confidential::relation::backend::{
    worker_client::{ClientError, WorkerVerifier},
    worker_request::WorkerRequest,
};
#[cfg(test)]
use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
use quil_lattice_ct::confidential::{
    custom_mint::CustomMint,
    mint::Mint,
    mint_claim::MintClaim,
    pending_claim::PendingClaim,
    pending_create::PendingCreate,
    relation::backend::native::NativeBudget,
    shield::AnyShield,
    transfer::{CompileLimits, Transfer},
};
use quil_types::error::{QuilError, Result};

#[derive(Clone, Copy)]
pub struct TokenPolicy {
    pub network: [u8; 32],
    pub limits: CompileLimits,
    pub snapshots: SnapshotLimits,
    pub native_budget: NativeBudget,
}

impl TokenPolicy {
    /// The network-agreed token policy, keyed by the p2p network byte
    /// like `network_identifier`. Circuit limits match the node witness RPC
    /// (four inputs, two outputs, depth 32); the hot-path coin cap is the
    /// tree capacity, since the accumulator appends incrementally. The
    /// native budget is submission accounting, not an RSS cap.
    pub fn for_network(network: u8) -> Self {
        Self {
            network: super::state::network_identifier(network),
            limits: CompileLimits {
                max_inputs: 4,
                max_outputs: 2,
                max_depth: 32,
            },
            snapshots: SnapshotLimits {
                max_coins: 1 << 32,
                max_depth: 32,
                max_nodes: 1 << 34,
            },
            native_budget: NativeBudget {
                max_native_bytes: 24 << 30,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A materialization put off for background verification reads as
    /// `PROOF_VERIFICATION_PENDING`, distinct from a busy worker.
    #[test]
    fn a_deferred_materialization_is_recognizably_pending() {
        let pending =
            QuilError::ExecutionUnavailable(super::super::PROOF_VERIFICATION_PENDING.into());
        assert!(super::super::is_proof_verification_pending(&pending));
        assert!(!super::super::is_proof_worker_busy(&pending));
        let busy = QuilError::ExecutionUnavailable(super::super::PROOF_WORKER_BUSY.into());
        assert!(!super::super::is_proof_verification_pending(&busy));
        assert!(!super::super::is_proof_verification_pending(
            &QuilError::InvalidArgument(super::super::PROOF_VERIFICATION_PENDING.into())
        ));
    }

    /// Each size class is estimated from its own measurements, so a slow
    /// batch shield does not price a transfer like itself, and a class not
    /// measured yet takes the mean of all.
    #[test]
    fn verification_is_estimated_per_size_class() {
        // A 96-source shield and a transfer fall in different classes.
        assert_ne!(verify_class(600 * 1024), verify_class(40 * 1024));
        assert_eq!(verify_class(0), 0);
        assert_eq!(verify_class(2048), 1);
        assert_eq!(verify_class(usize::MAX), VERIFY_CLASSES - 1);
        // A class's first measurement is its estimate, then a 1/4-weighted
        // mean; an unmeasured class takes the overall mean.
        let first = ewma_next(0, 300_000_000);
        assert_eq!(estimate_from(first, 8.0), 300.0);
        assert_eq!(estimate_from(ewma_next(first, 100_000_000), 8.0), 250.0);
        assert_eq!(estimate_from(0, 8.0), 8.0);
    }

    /// `LEVEL message field=value ...` of each event logged while `run` runs.
    fn logged(run: impl FnOnce()) -> Vec<String> {
        use std::sync::{Arc, Mutex};
        struct Recorder(Arc<Mutex<Vec<String>>>);
        impl tracing::Subscriber for Recorder {
            fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn event(&self, event: &tracing::Event<'_>) {
                struct Fields(String);
                impl tracing::field::Visit for Fields {
                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        self.0.push_str(&format!(" {}={:?}", field.name(), value));
                    }
                }
                let mut fields = Fields(event.metadata().level().to_string());
                event.record(&mut fields);
                self.0.lock().unwrap().push(fields.0);
            }
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }
        let lines = Arc::new(Mutex::new(Vec::new()));
        tracing::subscriber::with_default(Recorder(lines.clone()), run);
        let lines = lines.lock().unwrap().clone();
        lines
    }

    /// A long verification logs once that it runs long, warns once when it
    /// overruns, and logs its end; a short one logs nothing. Its result is
    /// returned as is.
    #[test]
    fn a_long_verification_reports_its_progress_and_end() {
        let long = std::time::Duration::from_millis(100);
        let application = [5u8; 32];
        let count = |lines: &[String], level: &str, text: &str| {
            lines
                .iter()
                .filter(|line| line.starts_with(level) && line.contains(text))
                .count()
        };
        let lines = logged(|| {
            let result = watched_verification_every(long, long * 2, &application, 2048, || {
                std::thread::sleep(long * 4);
                7u32
            });
            assert_eq!(result, 7);
        });
        assert_eq!(count(&lines, "INFO", "running long"), 1, "{lines:?}");
        assert_eq!(
            count(&lines, "WARN", "overran twice its estimate"),
            1,
            "{lines:?}"
        );
        assert_eq!(
            lines.iter().filter(|l| l.starts_with("WARN")).count(),
            1,
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.starts_with("INFO")
                && line.contains("confidential proof verification finished")
                && line.contains("operation_bytes=2048")),
            "{lines:?}"
        );
        // Long but within its estimate: no warning.
        let within = logged(|| {
            watched_verification_every(long, long * 10, &application, 2048, || {
                std::thread::sleep(long * 2)
            });
        });
        assert_eq!(
            within.iter().filter(|l| l.starts_with("WARN")).count(),
            0,
            "{within:?}"
        );
        assert_eq!(count(&within, "INFO", "running long"), 1, "{within:?}");
        let quick = logged(|| {
            assert!(watched_verification_every(
                long,
                long * 2,
                &application,
                2048,
                || true
            ));
        });
        assert!(quick.is_empty(), "{quick:?}");
    }

    /// The overrun warning comes at twice the estimate, never before the
    /// floor; an operation is known to fit a budget only once its size class
    /// is measured.
    #[test]
    fn overruns_and_fits_follow_the_measured_estimate() {
        assert_eq!(overrun_after(8.0), VERIFY_OVERRUN_FLOOR);
        assert_eq!(overrun_after(600.0), std::time::Duration::from_secs(1200));
        assert!(
            !known_to_fit(0, 12.0),
            "an unmeasured class is not known to fit"
        );
        assert!(known_to_fit(8_000_000, 12.0));
        assert!(!known_to_fit(300_000_000, 12.0));
    }

    /// A refused admission reads as `PROOF_WORKER_BUSY`, which callers tell
    /// apart from other worker failures.
    #[test]
    fn a_refused_admission_is_recognizably_busy() {
        use quil_lattice_ct::confidential::relation::backend::worker_client::ClientError;
        let busy =
            QuilError::ExecutionUnavailable(format!("token proof worker: {:?}", ClientError::Busy));
        assert!(super::super::is_proof_worker_busy(&busy));
        let crashed = QuilError::ExecutionUnavailable(format!(
            "token proof worker: {:?}",
            ClientError::Poisoned
        ));
        assert!(!super::super::is_proof_worker_busy(&crashed));
        assert!(!super::super::is_proof_worker_busy(
            &QuilError::InvalidArgument(super::super::PROOF_WORKER_BUSY.into())
        ));
    }

    /// Callers verifying one operation at the same time share a single
    /// verification; an attempt that ends without a verdict leaves the next
    /// caller to verify, and only the caller whose attempt failed sees it.
    #[test]
    fn concurrent_verifications_of_one_operation_share_one_attempt() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let runs = AtomicUsize::new(0);
        let key = [0xa5; 32];
        let results: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        verdict_once(key, || {
                            runs.fetch_add(1, SeqCst);
                            std::thread::sleep(std::time::Duration::from_millis(50));
                            Ok::<bool, &str>(true)
                        })
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(results.iter().all(|r| *r == Ok(true)));
        assert_eq!(runs.load(SeqCst), 1);

        let attempts = AtomicUsize::new(0);
        let key = [0x5a; 32];
        let results: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        verdict_once(key, || {
                            let attempt = attempts.fetch_add(1, SeqCst);
                            std::thread::sleep(std::time::Duration::from_millis(30));
                            if attempt == 0 {
                                Err("busy")
                            } else {
                                Ok(false)
                            }
                        })
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(
            attempts.load(SeqCst),
            2,
            "the failed attempt, then one more"
        );
        assert_eq!(results.iter().filter(|r| **r == Err("busy")).count(), 1);
        assert_eq!(results.iter().filter(|r| **r == Ok(false)).count(), 3);
    }

    #[test]
    fn verdict_cache_keys_every_input_and_capacity_follows_budget_and_ewma() {
        let limits = CompileLimits {
            max_inputs: 4,
            max_outputs: 2,
            max_depth: 32,
        };
        let budget = NativeBudget {
            max_native_bytes: 1 << 30,
        };
        let key = verdict_key(&[1; 32], &[2; 32], b"tx", limits, budget);
        assert_ne!(key, verdict_key(&[3; 32], &[2; 32], b"tx", limits, budget));
        assert_ne!(key, verdict_key(&[1; 32], &[4; 32], b"tx", limits, budget));
        assert_ne!(key, verdict_key(&[1; 32], &[2; 32], b"ty", limits, budget));
        assert_ne!(
            key,
            verdict_key(
                &[1; 32],
                &[2; 32],
                b"tx",
                CompileLimits {
                    max_depth: 1,
                    ..limits
                },
                budget
            )
        );
        assert_ne!(
            key,
            verdict_key(
                &[1; 32],
                &[2; 32],
                b"tx",
                limits,
                NativeBudget {
                    max_native_bytes: 1
                }
            )
        );
        assert_eq!(cached_verdict(&key), None);
        record_verdict(key, false);
        assert_eq!(cached_verdict(&key), Some(false));
        record_verdict(key, true);
        assert_eq!(cached_verdict(&key), Some(true));
        // Capacity: concurrency × budget / mean duration, at least one.
        set_verification_budget_secs(6);
        VERIFY_EWMA_MICROS.store(3_000_000, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(frame_verification_capacity(1), 2);
        assert_eq!(frame_verification_capacity(4), 8);
        VERIFY_EWMA_MICROS.store(60_000_000, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(frame_verification_capacity(1), 1);
        record_duration(1, std::time::Duration::from_secs(20));
        assert!(verification_ewma_secs() < 60.0 && verification_ewma_secs() > 20.0);
        VERIFY_EWMA_MICROS.store(8_000_000, std::sync::atomic::Ordering::Relaxed);
        // Request shapes mirror dispatch: transfers use the policy limits,
        // shields/claims/custom mints single-input depth-1 shapes.
        let policy = TokenPolicy::for_network(1);
        let quil = domains::QUIL_TOKEN;
        assert_eq!(
            policy
                .worker_request_shape(&quil, TYPE_LATTICE_TRANSACTION)
                .map(|s| s.1),
            Some(policy.limits)
        );
        assert_eq!(
            policy
                .worker_request_shape(&quil, TYPE_LATTICE_SHIELD)
                .map(|s| s.1.max_depth),
            Some(1)
        );
        assert_eq!(
            policy
                .worker_request_shape(&quil, TYPE_LATTICE_MINT)
                .map(|s| s.1.max_inputs),
            Some(policy.limits.max_inputs)
        );
        assert!(policy
            .worker_request_shape(&quil, TYPE_LATTICE_MINT_CLAIM)
            .is_none());
    }
    use quil_lattice_ct::confidential::{
        shield::{Shield, ShieldStatement},
        transfer::{parameter_context, Output, MEMO_BYTES},
        AmountOpening, CommitmentKey,
    };

    #[test]
    fn self_paid_quil_fee_rejects_underpayment_before_dispatch_in_both_venues() {
        use crate::{
            engines::{ExecutionMode, TokenExecutionEngine},
            message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest},
        };
        use num_bigint::BigInt;
        use quil_types::{crypto::NoopInclusionProver, execution::ShardExecutionEngine};
        use std::sync::Arc;
        let policy = TokenPolicy::for_network(1);
        let application = domains::QUIL_TOKEN;
        let context = parameter_context(&policy.network, &application);
        let mut proof = vec![0; 40];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        // Structural fixture only. It must never reach proof verification on
        // an insufficient fee, and a sufficient claimed fee cannot admit it.
        let mut tx = Shield {
            statement: ShieldStatement {
                network: policy.network,
                application,
                transparent_address: [3; 32],
                owner_public_key: [4; 57],
                amount: 1_000_000,
                fee: 2,
                outputs: vec![Output {
                    commitment: CommitmentKey::derive(&context)
                        .commit(10, &AmountOpening::from_seed(&context, &[2; 32])),
                    owner: [5; IDENTITY_BYTES],
                    memo: [6; MEMO_BYTES],
                }],
            },
            signature: [0; 114],
            proof,
        };
        let bytes = tx.encode().unwrap();
        assert!(policy
            .check_self_paid_fee(&application, &bytes, TYPE_LATTICE_SHIELD, &BigInt::from(0))
            .is_ok());
        for multiplier in [
            BigInt::from(-1),
            BigInt::from(1),
            BigInt::from(u128::MAX) + 1u8,
        ] {
            assert!(policy
                .check_self_paid_fee(&application, &bytes, TYPE_LATTICE_SHIELD, &multiplier)
                .is_err());
        }
        // The charge is the staged state growth (one coin and one marker), not
        // the payload length.
        let cost = u128::from(super::super::cost::state_growth(&bytes).unwrap());
        assert_eq!(
            cost,
            u128::from(
                super::super::cost::shape_growth(
                    &context,
                    super::super::cost::Shape {
                        coins: 1,
                        markers: 1,
                        escrow: false
                    }
                )
                .unwrap()
            )
        );
        for (fee, accepted) in [
            (cost * 3 - 1, false),
            (cost * 3, true),
            (cost * 3 + 1, true),
        ] {
            tx.statement.fee = fee;
            let encoded = tx.encode().unwrap();
            assert_eq!(encoded.len(), bytes.len());
            assert_eq!(
                policy
                    .check_self_paid_fee(
                        &application,
                        &encoded,
                        TYPE_LATTICE_SHIELD,
                        &BigInt::from(3)
                    )
                    .is_ok(),
                accepted
            );
        }
        // Mint claims cannot turn a historical fee into a new debit; the mint
        // itself is charged (it pays out of the minted amount).
        assert!(policy
            .check_self_paid_fee(&application, &[], TYPE_LATTICE_MINT, &BigInt::from(1))
            .is_err());
        for tp in [TYPE_LATTICE_MINT_CLAIM] {
            assert!(policy
                .check_self_paid_fee(&application, &[], tp, &BigInt::from(1))
                .is_ok());
        }
        for mode in [ExecutionMode::Application, ExecutionMode::Global] {
            let db = quil_store::RocksDb::open_in_memory().unwrap();
            let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
                Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
                Arc::new(NoopInclusionProver),
            ));
            let state = HypergraphState::new(crdt.clone());
            let stubs = crate::testing::NoopExecutionCrypto::new();
            let engine = TokenExecutionEngine::new_with_state(
                mode,
                Arc::new(NoopInclusionProver),
                crdt,
                stubs.key_manager,
                stubs.clock_store,
            )
            .with_token_proofs(policy)
            .unwrap();
            let request = CanonicalMessageRequest::wrap(bytes.clone()).unwrap();
            let bundle = CanonicalMessageBundle {
                requests: vec![Some(request.clone())],
                timestamp: 0,
            };
            for message in [
                request.to_canonical_bytes().unwrap(),
                bundle.to_canonical_bytes().unwrap(),
            ] {
                let error = engine
                    .process_message(1, &BigInt::from(1), &application, &message)
                    .unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("QUIL fee below operation's dynamic cost"),
                    "{error}"
                );
                let output_address = crate::token_intrinsic::state::create_coin(
                    &context,
                    1,
                    &tx.statement.outputs[0],
                    0,
                )
                .unwrap()
                .0;
                assert!(state
                    .get(
                        &application,
                        &output_address,
                        &crate::hypergraph_state::vertex_adds_discriminator().unwrap()
                    )
                    .unwrap()
                    .is_none());
                assert!(crate::token_intrinsic::roots::read_current(
                    &state,
                    &policy.network,
                    &application
                )
                .unwrap()
                .is_none());
            }
            // Overpayment is not proof verification: this fixture still fails.
            let funded = CanonicalMessageRequest::wrap(tx.encode().unwrap())
                .unwrap()
                .to_canonical_bytes()
                .unwrap();
            assert!(engine
                .process_message(1, &BigInt::from(1), &application, &funded)
                .is_err());
        }
    }

    /// Every QUIL operation that carries a self-paid fee is charged at the
    /// GLOBAL vote of one, so that is the only price a wallet is ever quoted
    /// for QUIL (`token_fee_provider`). Each priced type is either relayed —
    /// committed by the global frame, and priced at its vote by the shard that
    /// merely carries it — or barred from the application venue outright.
    ///
    /// Adding a QUIL type that is priced AND executes in the app venue would
    /// reintroduce the split-only failure this pins: an archive quoting the
    /// global vote while an app shard charges its own, so every submission is
    /// skipped as `QUIL fee below operation's dynamic cost`.
    #[test]
    fn every_priced_quil_operation_is_charged_at_the_global_vote() {
        use crate::engines::ExecutionMode;
        let policy = TokenPolicy::for_network(1);
        let application = domains::QUIL_TOKEN;
        // The types `check_self_paid_fee` prices (its own match arm).
        for tp in [
            TYPE_LATTICE_TRANSACTION,
            TYPE_LATTICE_PENDING,
            TYPE_LATTICE_MINT,
            TYPE_LATTICE_PENDING_CLAIM,
            TYPE_LATTICE_SHIELD,
            TYPE_LATTICE_SETTLEMENT,
        ] {
            let relayed = super::super::spend_entries::commits_globally(&application, tp);
            let app_venue_barred = policy
                .check_venue(ExecutionMode::Application, &application, tp)
                .is_err();
            assert!(relayed || app_venue_barred,
                "QUIL type {tp:#06x} is priced but executes in the app venue at that shard's own fee vote");
        }
        // The QUIL reward mint is the barred one, and it is barred everywhere
        // but the global venue.
        assert!(!super::super::spend_entries::commits_globally(
            &application,
            TYPE_LATTICE_MINT
        ));
        assert!(policy
            .check_venue(ExecutionMode::Application, &application, TYPE_LATTICE_MINT)
            .is_err());
        assert!(policy
            .check_venue(ExecutionMode::Global, &application, TYPE_LATTICE_MINT)
            .is_ok());
        // A settlement is the converse: app-venue only, yet relayed, so the
        // global commit still prices it.
        assert!(super::super::spend_entries::commits_globally(
            &application,
            TYPE_LATTICE_SETTLEMENT
        ));
        assert!(policy
            .check_venue(ExecutionMode::Global, &application, TYPE_LATTICE_SETTLEMENT)
            .is_err());
    }

    #[test]
    fn network_policy_is_compiled_per_network_and_matches_wallet_limits() {
        for network in [0u8, 1, 7] {
            let policy = TokenPolicy::for_network(network);
            assert_eq!(
                policy.network,
                super::super::state::network_identifier(network)
            );
            assert_eq!(
                (
                    policy.limits.max_inputs,
                    policy.limits.max_outputs,
                    policy.limits.max_depth
                ),
                (4, 2, 32)
            );
            assert_eq!(policy.snapshots.max_depth, 32);
            assert!(policy.snapshots.max_coins >= 1 << 32);
            // A stateless engine still refuses the policy: token admission needs state.
            let stubs = crate::testing::NoopExecutionCrypto::new();
            let stateless = crate::engines::TokenExecutionEngine::new(
                crate::engines::ExecutionMode::Application,
                std::sync::Arc::new(quil_types::crypto::NoopInclusionProver),
                stubs.key_manager,
                stubs.clock_store,
            );
            assert!(stateless.with_token_proofs(policy).is_err());
        }
        assert_ne!(
            TokenPolicy::for_network(0).network,
            TokenPolicy::for_network(1).network
        );
    }

    #[test]
    fn pending_preflight_checks_domain_dimensions_and_fee() {
        use quil_lattice_ct::confidential::{
            memo::EscrowRecoveryMemo,
            mint::FALCON_PUBLIC_BYTES,
            pending_claim::EscrowPolicy,
            pending_create::PendingCreateStatement,
            relation::membership::{Node, NODE_BYTES},
            transfer::TransferStatement,
        };
        let network = [1; 32];
        let application = domains::QUIL_TOKEN;
        let context = parameter_context(&network, &application);
        let policy = TokenPolicy {
            network,
            limits: CompileLimits {
                max_inputs: 2,
                max_outputs: 2,
                max_depth: 3,
            },
            snapshots: SnapshotLimits {
                max_coins: 8,
                max_depth: 3,
                max_nodes: 24,
            },
            native_budget: NativeBudget {
                max_native_bytes: 0,
            },
        };
        let output = Output {
            owner: [2; IDENTITY_BYTES],
            memo: [3; MEMO_BYTES],
            commitment: CommitmentKey::derive(&context)
                .commit(4, &AmountOpening::from_seed(&context, &[5; 32])),
        };
        let mut proof = vec![0; 40];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        let mut tx = PendingCreate {
            statement: PendingCreateStatement {
                funding: TransferStatement {
                    network,
                    application,
                    depth: 1,
                    root: Node::from_bytes(&[0; NODE_BYTES]).unwrap(),
                    images: vec![[6; IDENTITY_BYTES]],
                    fee: 2,
                    outputs: vec![output],
                },
                policy: EscrowPolicy {
                    recipient: [7; FALCON_PUBLIC_BYTES],
                    refund: [8; FALCON_PUBLIC_BYTES],
                    refund_after_global_frame: 100,
                },
                refund_recovery: EscrowRecoveryMemo {
                    owner: [9; IDENTITY_BYTES],
                    ciphertext: [10; MEMO_BYTES],
                },
            },
            proof,
        };
        // Framing/policy only: the placeholder proof is not admitted here.
        let bytes = tx.encode().unwrap();
        assert!(policy
            .preflight(&application, &bytes, TYPE_LATTICE_PENDING)
            .is_ok());
        assert!(policy
            .preflight(&application, &bytes, TYPE_LATTICE_TRANSACTION)
            .is_err());
        assert!(policy
            .preflight(&[11; 32], &bytes, TYPE_LATTICE_PENDING)
            .is_err());
        assert!(TokenPolicy {
            network: [12; 32],
            ..policy
        }
        .preflight(&application, &bytes, TYPE_LATTICE_PENDING)
        .is_err());
        for limits in [
            CompileLimits {
                max_inputs: 0,
                ..policy.limits
            },
            CompileLimits {
                max_outputs: 0,
                ..policy.limits
            },
            CompileLimits {
                max_depth: 0,
                ..policy.limits
            },
        ] {
            assert!(TokenPolicy { limits, ..policy }
                .preflight(&application, &bytes, TYPE_LATTICE_PENDING)
                .is_err());
        }
        // QUIL fees have no compiled minimum: the dynamic charge is checked at
        // execution against the staged state growth, so a fee of 1 preflights.
        tx.statement.funding.fee = 1;
        assert!(policy
            .preflight(&application, &tx.encode().unwrap(), TYPE_LATTICE_PENDING)
            .is_ok());
        tx.statement.funding.application = [11; 32];
        assert!(policy
            .preflight(&[11; 32], &tx.encode().unwrap(), TYPE_LATTICE_PENDING)
            .is_err());
        tx.statement.funding.fee = 0;
        assert!(policy
            .preflight(&[11; 32], &tx.encode().unwrap(), TYPE_LATTICE_PENDING)
            .is_ok());
    }

    #[test]
    fn dispatch_preflight_enforces_suite_context_dimensions_and_fee_asset() {
        let network = [1; 32];
        let application = domains::QUIL_TOKEN;
        let context = parameter_context(&network, &application);
        let key = CommitmentKey::derive(&context);
        let opening = AmountOpening::from_seed(&context, &[2; 32]);
        let policy = TokenPolicy {
            network,
            limits: CompileLimits {
                max_inputs: 2,
                max_outputs: 2,
                max_depth: 3,
            },
            snapshots: SnapshotLimits {
                max_coins: 8,
                max_depth: 3,
                max_nodes: 24,
            },
            native_budget: NativeBudget {
                max_native_bytes: 0,
            },
        };
        let mut proof = vec![0; 40];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        // Structural-only fixture: authorization and native proof are not valid.
        let mut tx = Shield {
            statement: ShieldStatement {
                network,
                application,
                transparent_address: [3; 32],
                owner_public_key: [4; 57],
                amount: 12,
                fee: 2,
                outputs: vec![Output {
                    commitment: key.commit(10, &opening),
                    owner: [5; IDENTITY_BYTES],
                    memo: [6; MEMO_BYTES],
                }],
            },
            signature: [0; 114],
            proof,
        };
        let bytes = tx.encode().unwrap();
        let stubs = crate::testing::NoopExecutionCrypto::new();
        let stateless = crate::engines::TokenExecutionEngine::new(
            crate::engines::ExecutionMode::Application,
            std::sync::Arc::new(quil_types::crypto::NoopInclusionProver),
            stubs.key_manager,
            stubs.clock_store,
        );
        assert!(stateless.with_token_proofs(policy).is_err());
        assert!(policy
            .preflight(&application, &bytes, TYPE_LATTICE_SHIELD)
            .is_ok());
        assert!(policy
            .preflight(&[9; 32], &bytes, TYPE_LATTICE_SHIELD)
            .is_err());
        assert!(policy
            .preflight(&domains::GLOBAL, &bytes, TYPE_LATTICE_SHIELD)
            .is_err());
        assert!(policy
            .preflight(&application[..31], &bytes, TYPE_LATTICE_SHIELD)
            .is_err());
        for tp in [
            TYPE_LATTICE_MINT,
            TYPE_LATTICE_PENDING,
            TYPE_LATTICE_PENDING_CLAIM,
        ] {
            assert!(policy.preflight(&application, &bytes, tp).is_err());
        }
        let mut old_version = bytes.clone();
        old_version[4..12].fill(0);
        assert!(policy
            .preflight(&application, &old_version, TYPE_LATTICE_SHIELD)
            .is_err());
        let mut constrained = policy;
        constrained.limits.max_outputs = 0;
        assert!(constrained
            .preflight(&application, &bytes, TYPE_LATTICE_SHIELD)
            .is_err());
        tx.statement.fee = 1;
        assert!(policy
            .preflight(&application, &tx.encode().unwrap(), TYPE_LATTICE_SHIELD)
            .is_ok());
        tx.statement.application = [7; 32];
        assert!(policy
            .preflight(&[7; 32], &tx.encode().unwrap(), TYPE_LATTICE_SHIELD)
            .is_err());
        tx.statement.fee = 0;
        assert!(policy
            .preflight(&[7; 32], &tx.encode().unwrap(), TYPE_LATTICE_SHIELD)
            .is_ok());
    }
}

pub fn is_confidential_type(tp: u32) -> bool {
    matches!(
        tp,
        TYPE_LATTICE_TRANSACTION
            | TYPE_LATTICE_SHIELD
            | TYPE_LATTICE_MINT
            | TYPE_LATTICE_PENDING
            | TYPE_LATTICE_PENDING_CLAIM
            | TYPE_LATTICE_MINT_CLAIM
            | TYPE_LATTICE_SETTLEMENT
    )
}

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("token dispatcher: {message}"))
}

/// Verdicts of completed worker verifications, keyed by every input the
/// verdict depends on (network, application, limits, native budget and the
/// exact operation bytes). A verdict is a pure function of that key, so a
/// pre-pass can verify a frame's operations concurrently and the sequential
/// materialization loop consumes the results. Bounded; cleared when full.
static VERDICTS: std::sync::Mutex<Option<std::collections::HashMap<[u8; 32], bool>>> =
    std::sync::Mutex::new(None);
const VERDICT_CACHE_ENTRIES: usize = 4096;
/// Exponentially weighted mean of one worker verification's wall time, in
/// microseconds; seeds at 8 s until measured.
static VERIFY_EWMA_MICROS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(8_000_000);
/// Proof-verification seconds a shard proposal may schedule per frame.
static VERIFY_BUDGET_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(6);

pub fn set_verification_budget_secs(secs: u64) {
    VERIFY_BUDGET_SECS.store(secs.clamp(1, 10), std::sync::atomic::Ordering::Relaxed);
}

/// Measured mean wall time of one worker verification.
pub fn verification_ewma_secs() -> f64 {
    VERIFY_EWMA_MICROS.load(std::sync::atomic::Ordering::Relaxed) as f64 / 1e6
}

/// Confidential operations a proposal may carry so that their verification,
/// `concurrency` at a time at the measured mean duration, fits the budget.
pub fn frame_verification_capacity(concurrency: usize) -> usize {
    let budget = VERIFY_BUDGET_SECS.load(std::sync::atomic::Ordering::Relaxed) as f64;
    let per_op = verification_ewma_secs().max(0.05);
    ((concurrency.max(1) as f64 * budget / per_op).floor() as usize).max(1)
}

/// Proof-verification seconds a shard proposal may schedule per frame.
pub fn verification_budget_secs() -> f64 {
    VERIFY_BUDGET_SECS.load(std::sync::atomic::Ordering::Relaxed) as f64
}

/// Size classes of the per-operation estimate: an operation's bytes in powers
/// of two from 1 KiB. A 96-source batch shield verifies for minutes and a
/// transfer for seconds; one mean over both priced the shield as a transfer
/// and the transfers as shields.
const VERIFY_CLASSES: usize = 16;
/// Exponentially weighted wall time of one worker verification per size
/// class, in microseconds; 0 until a verification of that class is measured.
static VERIFY_CLASS_EWMA_MICROS: [std::sync::atomic::AtomicU64; VERIFY_CLASSES] =
    [const { std::sync::atomic::AtomicU64::new(0) }; VERIFY_CLASSES];

fn verify_class(operation_bytes: usize) -> usize {
    ((operation_bytes / 1024).max(1).ilog2() as usize).min(VERIFY_CLASSES - 1)
}

/// Estimated wall time of verifying one confidential operation of
/// `operation_bytes` bytes: the measured mean of its size class, or the mean
/// of all classes until one of its class is measured.
pub fn estimated_verify_secs(operation_bytes: usize) -> f64 {
    estimate_from(
        VERIFY_CLASS_EWMA_MICROS[verify_class(operation_bytes)]
            .load(std::sync::atomic::Ordering::Relaxed),
        verification_ewma_secs(),
    )
}

/// A class's estimate: its measured mean (`class_micros`), or `mean_secs`
/// until it has one.
fn estimate_from(class_micros: u64, mean_secs: f64) -> f64 {
    if class_micros > 0 {
        class_micros as f64 / 1e6
    } else {
        mean_secs
    }
}

/// Whether verifying one confidential operation of `operation_bytes` bytes
/// is known to take at most `budget_secs`: its size class was measured on
/// this node and its estimate fits. A class not measured yet is not known
/// to fit: the first 96-source batch shield a node saw was estimated at the
/// 8 s mean of transfers and verified for minutes (devnet, 2026-10-29).
pub fn verification_known_to_fit(operation_bytes: usize, budget_secs: f64) -> bool {
    known_to_fit(
        VERIFY_CLASS_EWMA_MICROS[verify_class(operation_bytes)]
            .load(std::sync::atomic::Ordering::Relaxed),
        budget_secs,
    )
}

/// [`verification_known_to_fit`] of a class whose measured mean is
/// `class_micros` (0: not measured).
fn known_to_fit(class_micros: u64, budget_secs: f64) -> bool {
    class_micros > 0 && class_micros as f64 / 1e6 <= budget_secs
}

/// The next exponentially weighted mean after `micros`, 1/4 weight on the
/// newest; the first measurement (`previous` 0) is taken as is.
fn ewma_next(previous: u64, micros: u64) -> u64 {
    if previous == 0 {
        micros.max(1)
    } else {
        (previous - previous / 4 + micros / 4).max(1)
    }
}

fn verdict_key(
    network: &[u8; 32],
    application: &[u8; 32],
    bytes: &[u8],
    limits: CompileLimits,
    budget: NativeBudget,
) -> [u8; 32] {
    use sha3::Digest;
    let mut hash = sha3::Sha3_256::new();
    hash.update(b"quil/token/verdict/v1\0");
    hash.update(network);
    hash.update(application);
    for value in [
        limits.max_inputs,
        limits.max_outputs,
        limits.max_depth,
        budget.max_native_bytes,
    ] {
        hash.update((value as u64).to_le_bytes());
    }
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    hash.finalize().into()
}

fn cached_verdict(key: &[u8; 32]) -> Option<bool> {
    VERDICTS.lock().ok()?.as_ref()?.get(key).copied()
}

fn record_verdict(key: [u8; 32], accepted: bool) {
    if let Ok(mut cache) = VERDICTS.lock() {
        let map = cache.get_or_insert_with(std::collections::HashMap::new);
        if map.len() >= VERDICT_CACHE_ENTRIES {
            map.clear();
        }
        map.insert(key, accepted);
    }
}

/// Verdict keys whose worker verification is running in this process. The
/// shards a node works for carry the same submissions, so their
/// materializations and pre-passes often verify one operation at the same
/// moment; each would take its own worker slot, and those left waiting give
/// up as `Busy` and fail their frames. The first verifies; the rest wait for
/// its verdict.
static IN_FLIGHT: std::sync::Mutex<Option<std::collections::HashSet<[u8; 32]>>> =
    std::sync::Mutex::new(None);
static IN_FLIGHT_DONE: std::sync::Condvar = std::sync::Condvar::new();

/// The cached verdict for `key`, or `verify`'s, run by one caller at a time.
/// A caller that finds it running waits, and runs it itself only if that
/// attempt produced no verdict (a busy worker, say).
fn verdict_once<E>(
    key: [u8; 32],
    verify: impl FnOnce() -> std::result::Result<bool, E>,
) -> std::result::Result<bool, E> {
    struct Claim([u8; 32]);
    impl Drop for Claim {
        fn drop(&mut self) {
            let mut flight = IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(keys) = flight.as_mut() {
                keys.remove(&self.0);
            }
            drop(flight);
            IN_FLIGHT_DONE.notify_all();
        }
    }
    let claim = {
        let mut flight = IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(accepted) = cached_verdict(&key) {
                return Ok(accepted);
            }
            if flight.get_or_insert_with(Default::default).insert(key) {
                break Claim(key);
            }
            flight = IN_FLIGHT_DONE
                .wait(flight)
                .unwrap_or_else(|e| e.into_inner());
        }
    };
    let accepted = verify()?;
    record_verdict(key, accepted);
    drop(claim);
    Ok(accepted)
}

fn record_duration(operation_bytes: usize, elapsed: std::time::Duration) {
    let micros = elapsed.as_micros().min(u64::MAX as u128) as u64;
    let previous = VERIFY_EWMA_MICROS.load(std::sync::atomic::Ordering::Relaxed);
    // 1/4 weight on the newest observation.
    let next = previous - previous / 4 + micros / 4;
    VERIFY_EWMA_MICROS.store(next.max(1), std::sync::atomic::Ordering::Relaxed);
    let class = &VERIFY_CLASS_EWMA_MICROS[verify_class(operation_bytes)];
    let previous = class.load(std::sync::atomic::Ordering::Relaxed);
    class.store(
        ewma_next(previous, micros),
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// A verification running this long logs that it is running, once.
const LONG_VERIFY: std::time::Duration = std::time::Duration::from_secs(60);
/// A long verification warns once when it has run twice its estimate, and
/// at least this long: a 96-source batch shield verifies for 5-8 min on a
/// loaded node, longer while the node verifies another (devnet,
/// 2026-10-29).
const VERIFY_OVERRUN_FLOOR: std::time::Duration = std::time::Duration::from_secs(900);

/// When a verification estimated at `estimate_secs` has overrun.
fn overrun_after(estimate_secs: f64) -> std::time::Duration {
    std::time::Duration::from_secs_f64((2.0 * estimate_secs).max(0.0)).max(VERIFY_OVERRUN_FLOOR)
}

/// Watch one verification while `verify` runs it: an info line once it has
/// run [`LONG_VERIFY`], one warning if it overruns ([`overrun_after`]), and
/// an info line with its duration when a long one ends.
fn watched_verification<T: Send>(
    application: &[u8; 32],
    operation_bytes: usize,
    verify: impl FnOnce() -> T + Send,
) -> T {
    let estimate = estimated_verify_secs(operation_bytes);
    watched_verification_every(
        LONG_VERIFY,
        overrun_after(estimate),
        application,
        operation_bytes,
        verify,
    )
}

/// [`watched_verification`] reporting a long verification at `long` and an
/// overrun at `overrun`. The verification runs on a scoped thread and the
/// reports come from the calling thread, so they carry its span and
/// subscriber.
fn watched_verification_every<T: Send>(
    long: std::time::Duration,
    overrun: std::time::Duration,
    application: &[u8; 32],
    operation_bytes: usize,
    verify: impl FnOnce() -> T + Send,
) -> T {
    let start = std::time::Instant::now();
    let estimate = estimated_verify_secs(operation_bytes);
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let result = std::thread::scope(|scope| {
        scope.spawn(move || {
            let _ = sender.send(verify());
        });
        let (mut reported_long, mut warned) = (false, false);
        loop {
            let next_report = match (reported_long, warned) {
                (false, _) => Some(long),
                (true, false) => Some(overrun.max(long)),
                (true, true) => None,
            };
            let received = match next_report {
                Some(at) => receiver.recv_timeout(at.saturating_sub(start.elapsed())),
                None => receiver
                    .recv()
                    .map_err(|_| std::sync::mpsc::RecvTimeoutError::Disconnected),
            };
            match received {
                Ok(result) => break Some(result),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    let elapsed = start.elapsed();
                    if !reported_long {
                        reported_long = true;
                        tracing::info!(
                            scope = "this node's proof worker",
                            application = %hex::encode(&application[..8]),
                            operation_bytes,
                            secs = elapsed.as_secs(),
                            estimate_secs = estimate.round() as u64,
                            overrun_warn_secs = overrun.as_secs(),
                            "confidential proof verification running long; it logs its end"
                        );
                    } else {
                        warned = true;
                        tracing::warn!(
                            scope = "this node's proof worker",
                            application = %hex::encode(&application[..8]),
                            operation_bytes,
                            secs = elapsed.as_secs(),
                            estimate_secs = estimate.round() as u64,
                            action = "a proposal leaves the operation out until it verifies, and a frame \
                                      carrying it waits for it; if this repeats for every operation, check \
                                      this node's CPU and proofWorker settings",
                            "confidential proof verification overran twice its estimate"
                        );
                    }
                }
                // The verifying thread panicked: the scope re-raises it.
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break None,
            }
        }
    });
    let result =
        result.expect("a scope whose thread panicked re-raises the panic before returning");
    let elapsed = start.elapsed();
    if elapsed >= long {
        tracing::info!(
            scope = "this node's proof worker",
            application = %hex::encode(&application[..8]),
            operation_bytes,
            secs = elapsed.as_secs(),
            estimate_secs = estimate.round() as u64,
            "confidential proof verification finished"
        );
    }
    result
}

/// The trusted client reconstructs the amount relation inside its child. Local
/// admission/resource failures must never become deterministic invalidity.
pub(crate) fn verify_in_worker(
    worker: &WorkerVerifier,
    network: &[u8; 32],
    application: &[u8; 32],
    bytes: &[u8],
    limits: CompileLimits,
    budget: NativeBudget,
) -> Result<()> {
    let key = verdict_key(network, application, bytes, limits, budget);
    let accepted = verdict_once(key, || {
        worker_verdict(worker, network, application, bytes, limits, budget)
    })
    .map_err(|error| QuilError::ExecutionUnavailable(format!("token proof worker: {error:?}")))?;
    if !accepted {
        return Err(invalid("invalid amount proof"));
    }
    Ok(())
}

/// One worker verification, its wall time recorded.
fn worker_verdict(
    worker: &WorkerVerifier,
    network: &[u8; 32],
    application: &[u8; 32],
    bytes: &[u8],
    limits: CompileLimits,
    budget: NativeBudget,
) -> std::result::Result<bool, ClientError> {
    let start = std::time::Instant::now();
    let accepted = watched_verification(application, bytes.len(), || {
        worker.verify(&WorkerRequest {
            network: *network,
            application: *application,
            limits,
            submission_bytes: budget.max_native_bytes,
            transaction: bytes,
        })
    })?;
    record_duration(bytes.len(), start.elapsed());
    Ok(accepted)
}

/// What [`TokenPolicy::preverify`] made of one operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preverified {
    /// Its verdict was cached already.
    Cached,
    /// Verified now (or by a concurrent caller it waited for); cached.
    Verified,
    /// No worker slot within the admission wait; nothing cached.
    Busy,
    /// The worker failed (timeout, crash, resource cap); nothing cached.
    Unavailable,
    /// No worker proof to verify (mint claims, unknown types).
    NotApplicable,
}

impl TokenPolicy {
    /// The worker request `dispatch` would issue for one confidential
    /// operation, so a pre-pass fills the verdict cache with the same key.
    /// Operations without a proof (mint claims) and unknown types yield `None`.
    pub(crate) fn worker_request_shape(
        &self,
        address: &[u8],
        tp: u32,
    ) -> Option<([u8; 32], CompileLimits)> {
        let application = self.application(address).ok()?;
        let limits = match tp {
            TYPE_LATTICE_TRANSACTION | TYPE_LATTICE_PENDING | TYPE_LATTICE_SETTLEMENT => {
                self.limits
            }
            TYPE_LATTICE_SHIELD | TYPE_LATTICE_PENDING_CLAIM => CompileLimits {
                max_inputs: 1,
                max_outputs: self.limits.max_outputs,
                max_depth: 1,
            },
            TYPE_LATTICE_MINT if application != domains::QUIL_TOKEN => CompileLimits {
                max_inputs: 1,
                max_outputs: self.limits.max_outputs,
                max_depth: 1,
            },
            TYPE_LATTICE_MINT => CompileLimits {
                max_inputs: self.limits.max_inputs,
                max_outputs: self.limits.max_outputs,
                max_depth: 1,
            },
            _ => return None,
        };
        Some((application, limits))
    }

    /// Whether one confidential operation needs no worker verification
    /// before it executes: its verdict is cached, or it carries no worker
    /// proof (mint claims, unknown types).
    pub fn verdict_cached(&self, address: &[u8], bytes: &[u8], tp: u32) -> bool {
        let Some((application, limits)) = self.worker_request_shape(address, tp) else {
            return true;
        };
        cached_verdict(&verdict_key(
            &self.network,
            &application,
            bytes,
            limits,
            self.native_budget,
        ))
        .is_some()
    }

    /// Verify one confidential operation ahead of materialization so the
    /// verdict is cached. The outcome only reports what happened: busy
    /// workers, invalid proofs and unknown types are all re-handled by
    /// `dispatch`.
    pub fn preverify(
        &self,
        worker: &WorkerVerifier,
        address: &[u8],
        bytes: &[u8],
        tp: u32,
    ) -> Preverified {
        let Some((application, limits)) = self.worker_request_shape(address, tp) else {
            return Preverified::NotApplicable;
        };
        let key = verdict_key(
            &self.network,
            &application,
            bytes,
            limits,
            self.native_budget,
        );
        if cached_verdict(&key).is_some() {
            return Preverified::Cached;
        }
        match verdict_once(key, || {
            worker_verdict(
                worker,
                &self.network,
                &application,
                bytes,
                limits,
                self.native_budget,
            )
        }) {
            Ok(_) => Preverified::Verified,
            Err(ClientError::Busy) => Preverified::Busy,
            Err(_) => Preverified::Unavailable,
        }
    }
}

impl TokenPolicy {
    pub(crate) fn check_venue(
        &self,
        mode: crate::engines::ExecutionMode,
        address: &[u8],
        tp: u32,
    ) -> Result<()> {
        // Claims mutate application state. Like transfers, they may execute
        // through the global materializer's uncovered-application route. Only
        // the QUIL reward mint debits global rewards and needs the global venue;
        // custom-token issuance (same type prefix) is application state.
        if tp == TYPE_LATTICE_MINT
            && address == domains::QUIL_TOKEN.as_slice()
            && mode != crate::engines::ExecutionMode::Global
        {
            return Err(invalid("reward mint requires serialized global execution"));
        }
        // A settlement's record reaches GLOBAL state only through the QUIL
        // shard's certified frame header; the global venue has no such relay.
        if tp == TYPE_LATTICE_SETTLEMENT && mode != crate::engines::ExecutionMode::Application {
            return Err(invalid("settlement requires QUIL shard execution"));
        }
        // A globally executed application's outputs are placed inline; only an
        // app shard takes deliveries.
        if tp == super::constants::TYPE_COIN_DELIVERY
            && mode != crate::engines::ExecutionMode::Application
        {
            return Err(invalid("deliveries are applied by app shards"));
        }
        Ok(())
    }

    fn application(&self, address: &[u8]) -> Result<[u8; 32]> {
        let address = address
            .try_into()
            .map_err(|_| invalid("application must be 32 bytes"))?;
        if address == domains::GLOBAL || address == domains::COMPUTE {
            return Err(invalid("system domain is not a token application"));
        }
        Ok(address)
    }

    /// Check a QUIL operation's own dynamic charge before dispatch/staging.
    /// The charge is the shared world-state-growth price (`crate::pricing`)
    /// applied to the bytes this operation's admission stages
    /// (`super::cost`); there is no compiled minimum. The typed fee is only a
    /// claim here: dispatch must still verify the bound proof and debit. No
    /// surplus is credited to another operation or domain. A reward mint pays
    /// the same charge out of the minted amount (outputs = reward − fee), so a
    /// prover with no coins can still mint; the mint claim is exempt because
    /// the authorization already paid. Cross-domain settlement is separate.
    pub(crate) fn check_self_paid_fee(
        &self,
        address: &[u8],
        bytes: &[u8],
        tp: u32,
        multiplier: &num_bigint::BigInt,
    ) -> Result<()> {
        use num_bigint::{BigInt, Sign};
        if multiplier.sign() == Sign::Minus {
            return Err(invalid("negative fee multiplier"));
        }
        if address != domains::QUIL_TOKEN.as_slice()
            || !matches!(
                tp,
                TYPE_LATTICE_TRANSACTION
                    | TYPE_LATTICE_PENDING
                    | TYPE_LATTICE_MINT
                    | TYPE_LATTICE_PENDING_CLAIM
                    | TYPE_LATTICE_SHIELD
                    | TYPE_LATTICE_SETTLEMENT
            )
        {
            return Ok(());
        }
        // Keep arbitrary-precision multiplication: a charge beyond u128 must
        // reject rather than truncate to a fee the transaction can represent.
        let required = multiplier * BigInt::from(super::cost::state_growth(bytes)?);
        let paid = super::wire::fee(bytes)?;
        if BigInt::from(paid) < required {
            return Err(invalid("QUIL fee below operation's dynamic cost"));
        }
        Ok(())
    }

    fn check_fee(&self, application: &[u8; 32], fee: u128) -> Result<()> {
        // QUIL fees are priced dynamically at execution (`check_self_paid_fee`).
        // Custom-token conservation must not treat those units as QUIL gas.
        if application != &domains::QUIL_TOKEN && fee != 0 {
            return Err(invalid("custom-token outflow cannot pay a QUIL fee"));
        }
        Ok(())
    }

    /// Cheap domain, version, dimensions and fee checks before native work.
    /// Authorization and proof validity are checked by dispatch, not here.
    pub(crate) fn preflight(&self, address: &[u8], bytes: &[u8], tp: u32) -> Result<()> {
        let application = self.application(address)?;
        match tp {
            super::constants::TYPE_COIN_DELIVERY => {
                super::delivery::CoinDelivery::decode(bytes, &self.network, &application)?;
                Ok(())
            }
            TYPE_LATTICE_PENDING_CLAIM => {
                let tx = PendingClaim::decode(bytes, &self.network, &application)
                    .map_err(|_| invalid("invalid pending claim encoding or context"))?;
                if self.limits.max_inputs < 1
                    || tx.statement.outputs.len() > self.limits.max_outputs
                {
                    return Err(invalid("pending claim exceeds configured dimensions"));
                }
                self.check_fee(&application, tx.statement.fee)
            }
            TYPE_LATTICE_MINT_CLAIM => {
                let tx = MintClaim::decode(bytes, &self.network, &application)
                    .map_err(|_| invalid("invalid mint claim encoding or context"))?;
                if application != domains::QUIL_TOKEN || tx.outputs.len() > self.limits.max_outputs
                {
                    return Err(invalid("unsupported mint claim application or dimensions"));
                }
                // The fee was paid by the globally authorized mint. Do not
                // impose today's fee floor on a previously paid authorization.
                Ok(())
            }
            TYPE_LATTICE_MINT if application != domains::QUIL_TOKEN => {
                // Custom-token issuance: policy authorization happens in
                // dispatch against the deployed configuration.
                let tx = CustomMint::decode(bytes, &self.network, &application)
                    .map_err(|_| invalid("invalid custom mint encoding or context"))?;
                if tx.statement.outputs.len() > self.limits.max_outputs {
                    return Err(invalid("custom mint exceeds configured dimensions"));
                }
                self.check_fee(&application, 0)
            }
            TYPE_LATTICE_MINT => {
                let tx = Mint::decode(bytes, &self.network, &application)
                    .map_err(|_| invalid("invalid mint encoding or context"))?;
                if tx.statement.claims.len() > self.limits.max_inputs
                    || tx.statement.outputs.len() > self.limits.max_outputs
                {
                    return Err(invalid("mint exceeds configured dimensions"));
                }
                self.check_fee(&application, tx.statement.fee)
            }
            TYPE_LATTICE_TRANSACTION => {
                let tx = Transfer::decode(bytes, &self.network, &application)
                    .map_err(|_| invalid("invalid transfer encoding or context"))?;
                let s = &tx.statement;
                if s.images.len() > self.limits.max_inputs
                    || s.outputs.len() > self.limits.max_outputs
                    || usize::from(s.depth) > self.limits.max_depth
                {
                    return Err(invalid("transfer exceeds configured dimensions"));
                }
                self.check_fee(&application, s.fee)
            }
            TYPE_LATTICE_PENDING => {
                let tx = PendingCreate::decode(bytes, &self.network, &application)
                    .map_err(|_| invalid("invalid pending creation encoding or context"))?;
                let s = &tx.statement.funding;
                if s.images.len() > self.limits.max_inputs
                    || s.outputs.len() > self.limits.max_outputs
                    || usize::from(s.depth) > self.limits.max_depth
                {
                    return Err(invalid("pending creation exceeds configured dimensions"));
                }
                self.check_fee(&application, s.fee)
            }
            // Structural only: whether a batch is active at the executing
            // frame is decided at execution.
            TYPE_LATTICE_SHIELD => {
                let tx = AnyShield::decode(bytes, &self.network, &application)
                    .map_err(|_| invalid("invalid shield encoding or context"))?;
                if tx.outputs().len() > self.limits.max_outputs {
                    return Err(invalid("shield exceeds configured dimensions"));
                }
                self.check_fee(&application, tx.fee())
            }
            TYPE_LATTICE_SETTLEMENT => {
                let tx = quil_lattice_ct::confidential::settlement::Settlement::decode(
                    bytes,
                    &self.network,
                    &application,
                )
                .map_err(|_| invalid("invalid settlement encoding or context"))?;
                let s = &tx.statement.funding;
                if application != domains::QUIL_TOKEN
                    || s.images.len() > self.limits.max_inputs
                    || s.outputs.len() > self.limits.max_outputs
                    || usize::from(s.depth) > self.limits.max_depth
                {
                    return Err(invalid("settlement application or dimensions unsupported"));
                }
                self.check_fee(&application, tx.statement.fee)
            }
            _ => Err(invalid(
                "operation has not been integrated with the token suite",
            )),
        }
    }

    /// App-shard venue of an operation that commits through the global frame:
    /// verify everything provable from the operation and write nothing. The
    /// frame relays its spend entry.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_for_commit(
        &self,
        state: &HypergraphState,
        context: quil_types::execution::FrameExecutionContext,
        clock: &dyn quil_types::store::ClockStore,
        address: &[u8],
        bytes: &[u8],
        tp: u32,
        worker: Option<&WorkerVerifier>,
        paid: Option<custom_mint::PaidMintAllowance>,
    ) -> Result<()> {
        self.preflight(address, bytes, tp)?;
        let application = self.application(address)?;
        if !super::spend_entries::commits_globally(&application, tp) {
            return Err(invalid(
                "operation does not commit through the global frame",
            ));
        }
        if tp == TYPE_LATTICE_MINT {
            custom_mint::verify_custom_mint_with_worker(
                state,
                &self.network,
                &application,
                bytes,
                self.limits.max_outputs,
                self.native_budget,
                worker,
                paid,
            )?;
            return Ok(());
        }
        super::commit_verify::verify_for_commit(
            state,
            clock,
            context,
            &self.network,
            &application,
            tp,
            bytes,
            self.limits,
            self.native_budget,
            worker,
        )
    }

    /// Global venue of an operation that commits through the global frame: the
    /// global materializer is both executor and committer, so it verifies,
    /// commits, and places the outputs in one pass.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_commit_inline(
        &self,
        state: &HypergraphState,
        context: quil_types::execution::FrameExecutionContext,
        clock: &dyn quil_types::store::ClockStore,
        address: &[u8],
        bytes: &[u8],
        tp: u32,
        worker: Option<&WorkerVerifier>,
        paid: Option<custom_mint::PaidMintAllowance>,
    ) -> Result<()> {
        self.dispatch_for_commit(state, context, clock, address, bytes, tp, worker, paid)?;
        let application = self.application(address)?;
        super::commit_apply::commit_and_place(
            state,
            context.frame_number,
            &self.network,
            &application,
            tp,
            bytes,
            self.snapshots,
        )?;
        Ok(())
    }

    /// Apply a delivery of a committed output.
    pub(crate) fn dispatch_delivery(
        &self,
        state: &HypergraphState,
        context: quil_types::execution::FrameExecutionContext,
        clock: &dyn quil_types::store::ClockStore,
        address: &[u8],
        bytes: &[u8],
    ) -> Result<()> {
        let application = self.application(address)?;
        super::delivery::verify_and_apply(
            state,
            context,
            clock,
            &self.network,
            &application,
            bytes,
            self.snapshots,
        )?;
        Ok(())
    }

    /// Global materialization owns reward serialization and routing. The cited
    /// frame must precede this frame; app-frame counters are never used here.
    /// Non-QUIL applications carry custom issuance under the same type prefix.
    pub(crate) fn dispatch_global_mint(
        &self,
        state: &HypergraphState,
        frame: u64,
        clock: &dyn quil_types::store::ClockStore,
        address: &[u8],
        bytes: &[u8],
        worker: Option<&WorkerVerifier>,
    ) -> Result<()> {
        if self.application(address)? != domains::QUIL_TOKEN {
            // Custom issuance commits through the global frame
            // (`dispatch_for_commit` / `dispatch_commit_inline`).
            return Err(invalid("custom issuance commits through the global frame"));
        }
        self.preflight(address, bytes, TYPE_LATTICE_MINT)?;
        let finalized = frame
            .checked_sub(1)
            .ok_or_else(|| invalid("mint requires a prior global frame"))?;
        super::mint::verify_mint_from_clock_with_worker(
            state,
            clock,
            &self.network,
            &self.application(address)?,
            finalized,
            bytes,
            self.limits.max_inputs,
            self.limits.max_outputs,
            self.native_budget,
            worker,
        )?
        .authorize_global(state, frame)?;
        Ok(())
    }
}
