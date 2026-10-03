//! QUIL reward-mint admission. Clock-backed admission resolves the
//! cited global root; callers must serialize global reward/token mutation.
#[cfg(test)]
use super::{roots, materialize, state::{self, SnapshotLimits}};
use crate::{
    domains, global_schema,
    hypergraph_state::{vertex_adds_discriminator, HypergraphState},
};
use quil_lattice_ct::confidential::{
    mint::{Mint, MintStatement, FALCON_PUBLIC_BYTES, FALCON_SIGNATURE_BYTES},
    relation::backend::native::{self, NativeBudget},
    transfer::parameter_context,
};
use quil_types::error::{QuilError, Result};

const _: [(); FALCON_PUBLIC_BYTES] = [(); quil_crypto::FALCON_PUBLIC_KEY_LEN];
const _: [(); FALCON_SIGNATURE_BYTES] = [(); quil_crypto::FALCON_SIGNATURE_LEN];
const _: [(); quil_lattice_ct::confidential::mint::MAX_REWARD_PROOF_BYTES] =
    [(); super::reward_witness::MAX_REWARD_PROOF_BYTES];
const REWARD: &str = "reward:ProverReward";

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("mint: {message}"))
}
fn unavailable(message: &str) -> QuilError {
    QuilError::ExecutionUnavailable(format!("mint: {message}"))
}

/// Receipt identity excludes signatures/proof bytes, so alternate valid
/// encodings of those cannot consume the same signed authorization again.
fn receipt_address(s: &MintStatement) -> Result<[u8; 32]> {
    super::mint_authorization::receipt_address(s)
}

fn check_authorization(
    tx: &Mint,
    finalized_global_frame: u64,
    trusted_root: &[u8; 32],
) -> Result<()> {
    let s = &tx.statement;
    if s.application != domains::QUIL_TOKEN {
        return Err(invalid("custom-token mint policy is not integrated"));
    }
    if s.cited_frame > finalized_global_frame || &s.reward_root != trusted_root {
        return Err(invalid("untrusted or future reward root"));
    }
    if tx.signatures.len() != s.claims.len() {
        return Err(invalid("signature count mismatch"));
    }
    let context = s
        .context_bytes()
        .map_err(|_| invalid("invalid statement"))?;
    let domain = parameter_context(&s.network, &s.application);
    for (claim, signature) in s.claims.iter().zip(&tx.signatures) {
        if quil_crypto::poseidon::hash_bytes_to_32(&claim.public_key)? != claim.owner
            || !quil_crypto::falcon_verify(&claim.public_key, signature, &context, &domain)
        {
            return Err(invalid("invalid claimant authorization"));
        }
        super::reward_witness::verify_reward_membership(
            &claim.owner,
            claim.value,
            trusted_root,
            &claim.forest_proof,
        )
        .map_err(|_| invalid("invalid reward membership"))?;
    }
    Ok(())
}

struct RewardUpdate {
    address: [u8; 32],
    blob: Vec<u8>,
}

fn prepare_rewards(
    state: &HypergraphState,
    s: &MintStatement,
) -> Result<([u8; 32], Vec<RewardUpdate>)> {
    if s.application != domains::QUIL_TOKEN {
        return Err(invalid("unsupported reward domain"));
    }
    let receipt = receipt_address(s)?;
    let disc = vertex_adds_discriminator()?;
    if state.get(&s.application, &receipt, &disc)?.is_some()
        || state.get(&domains::GLOBAL, &receipt, &disc)?.is_some()
    {
        return Err(invalid("authorization already consumed"));
    }
    let mut updates = Vec::with_capacity(s.claims.len());
    for claim in &s.claims {
        let address = crate::global_intrinsic::materialize::reward_address(&claim.owner)?;
        let blob = state
            .get(&domains::GLOBAL, &address, &disc)?
            .ok_or_else(|| invalid("reward no longer exists"))?;
        let mut tree = quil_tries::VectorCommitmentTree {
            root: quil_tries::deserialize_go_tree(&blob)
                .map_err(|_| unavailable("cannot decode current reward"))?,
        };
        if global_schema::read_type(&tree) != Some(REWARD) {
            return Err(unavailable("invalid current reward type"));
        }
        let owner = global_schema::read_field(&tree, REWARD, "DelegateAddress")
            .ok_or_else(|| unavailable("missing current reward owner"))?;
        if owner.len() != 32 {
            return Err(unavailable("invalid current reward owner"));
        }
        if owner != claim.owner {
            return Err(invalid("reward owner changed"));
        }
        let balance = global_schema::read_field(&tree, REWARD, "Balance")
            .ok_or_else(|| unavailable("missing current reward balance"))?;
        if balance.len() != 32 {
            return Err(unavailable("invalid current reward balance"));
        }
        let current = num_bigint::BigUint::from_bytes_be(&balance);
        let amount = num_bigint::BigUint::from(claim.value);
        if current < amount {
            return Err(invalid("insufficient current reward balance"));
        }
        let remaining = (current - amount).to_bytes_be();
        let mut padded = [0; 32];
        padded[32 - remaining.len()..].copy_from_slice(&remaining);
        global_schema::write_field(&mut tree, REWARD, "Balance", &padded)?;
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref())
            .map_err(|_| unavailable("cannot encode reward update"))?;
        updates.push(RewardUpdate { address, blob });
    }
    Ok((receipt, updates))
}

pub struct VerifiedMint {
    mint: Mint,
}

/// Resolve only the canonical global frame named by the signed statement.
/// The bound must come from consensus execution, not the local latest frame
/// (which can vary between validators) or an application-frame counter.
pub(crate) use super::mint_authorization::clock_reward_root;

/// Admit against the stored canonical global frame. Missing local history is
/// an execution failure, not a deterministic rejection of the transaction.
/// This does not establish the execution venue or coordinate reward writes.
pub fn verify_mint_from_clock(
    state: &HypergraphState,
    clock: &dyn quil_types::store::ClockStore,
    network: &[u8; 32],
    application: &[u8; 32],
    finalized_global_frame: u64,
    bytes: &[u8],
    max_claims: usize,
    max_outputs: usize,
    budget: NativeBudget,
) -> Result<VerifiedMint> {
    verify_mint_from_clock_with_worker(state, clock, network, application, finalized_global_frame, bytes, max_claims, max_outputs, budget, None)
}

pub(crate) fn verify_mint_from_clock_with_worker(
    state: &HypergraphState,
    clock: &dyn quil_types::store::ClockStore,
    network: &[u8; 32],
    application: &[u8; 32],
    finalized_global_frame: u64,
    bytes: &[u8],
    max_claims: usize,
    max_outputs: usize,
    budget: NativeBudget,
    worker: Option<&quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier>,
) -> Result<VerifiedMint> {
    let mint = Mint::decode(bytes, network, application)
        .map_err(|_| invalid("invalid encoding or context"))?;
    if mint.statement.claims.len() > max_claims || mint.statement.outputs.len() > max_outputs {
        return Err(invalid("configured dimensions exceeded"));
    }
    if mint.statement.application != domains::QUIL_TOKEN {
        return Err(invalid("custom-token mint policy is not integrated"));
    }
    let root = clock_reward_root(clock, mint.statement.cited_frame, finalized_global_frame)?;
    verify_decoded_mint(
        state,
        mint,
        finalized_global_frame,
        &root,
        max_claims,
        max_outputs,
        budget,
        worker.map(|worker| (worker, bytes)),
    )
}

/// `finalized_global_frame` bounds the cited global reward root. It is not an
/// application-frame number; staging has its own storage-frame argument.
pub fn verify_mint(
    state: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    finalized_global_frame: u64,
    trusted_reward_root: &[u8; 32],
    bytes: &[u8],
    max_claims: usize,
    max_outputs: usize,
    budget: NativeBudget,
) -> Result<VerifiedMint> {
    let mint = Mint::decode(bytes, network, application)
        .map_err(|_| invalid("invalid encoding or context"))?;
    if mint.statement.claims.len() > max_claims || mint.statement.outputs.len() > max_outputs {
        return Err(invalid("configured dimensions exceeded"));
    }
    verify_decoded_mint(
        state,
        mint,
        finalized_global_frame,
        trusted_reward_root,
        max_claims,
        max_outputs,
        budget,
        None,
    )
}

fn verify_decoded_mint(
    state: &HypergraphState,
    mint: Mint,
    finalized_global_frame: u64,
    trusted_reward_root: &[u8; 32],
    max_claims: usize,
    max_outputs: usize,
    budget: NativeBudget,
    worker: Option<(&quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier, &[u8])>,
) -> Result<VerifiedMint> {
    state.require_full_domain_coverage(&domains::GLOBAL)?;
    prepare_rewards(state, &mint.statement)?;
    check_authorization(&mint, finalized_global_frame, trusted_reward_root)?;
    if let Some((worker, bytes)) = worker {
        super::dispatch::verify_in_worker(worker, &mint.statement.network, &mint.statement.application, bytes,
            quil_lattice_ct::confidential::transfer::CompileLimits { max_inputs: max_claims, max_outputs, max_depth: 1 }, budget)?;
    } else {
        let relation = mint
            .statement
            .public_relation(max_claims, max_outputs)
            .map_err(|_| invalid("invalid amount relation"))?;
        if !native::verify_owned(relation, &mint.proof, budget)
            .map_err(|e| unavailable(&format!("native backend: {e:?}")))?
        {
            return Err(invalid("invalid amount proof"));
        }
    }
    Ok(VerifiedMint { mint })
}

impl VerifiedMint {
    /// Debit global rewards and publish a fixed-output authorization. Does not
    /// write token-app state. The global materializer must serialize and commit
    /// these writes; app-side consumption remains a separate operation.
    pub fn authorize_global(self, state: &HypergraphState, frame: u64) -> Result<[u8; 32]> {
        state.require_full_domain_coverage(&domains::GLOBAL)?;
        let s = &self.mint.statement;
        let (receipt, rewards) = prepare_rewards(state, s)?;
        if rewards.iter().any(|r| r.address == receipt) {
            return Err(invalid("authorization collides with reward address"));
        }
        let blob = super::mint_authorization::create_record(
            &s.network,
            &s.application,
            &s.outputs,
            s.fee,
        )?;
        let disc = vertex_adds_discriminator()?;
        let checkpoint = state.changeset_len();
        let result = (|| {
            for update in rewards {
                state.set(&domains::GLOBAL, &update.address, &disc, frame, update.blob)?;
            }
            state.set(&domains::GLOBAL, &receipt, &disc, frame, blob)?;
            Ok(receipt)
        })();
        if result.is_err() {
            state.rollback_to(checkpoint);
        }
        result
    }

    pub fn fee(&self) -> u128 {
        self.mint.statement.fee
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_ntruprime::sntrup761;
    use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
    use quil_lattice_ct::confidential::{
        address::RecipientAddress,
        memo::{create_output, open_output},
        mint::RewardClaim,
        relation::membership::RecipientSecret,
        AmountOpening,
    };
    use quil_types::crypto::{NoopInclusionProver, Signer};
    use std::sync::Arc;

    struct Fixture {
        state: HypergraphState,
        mint: Mint,
        signers: Vec<quil_crypto::FalconSigner>,
        openings: Vec<AmountOpening>,
        amounts: [u128; 2],
        recipients: Vec<(RecipientSecret, sntrup761::SecretKey)>,
        rewards: Vec<([u8; 32], Vec<u8>)>,
    }

    fn fixture(state: HypergraphState) -> Fixture {
        let network = [1; 32];
        let application = domains::QUIL_TOKEN;
        let context = parameter_context(&network, &application);
        let signers: Vec<_> = (0..2)
            .map(|_| quil_crypto::FalconSigner::generate())
            .collect();
        let values = [u128::MAX - 257, 257];
        let disc = vertex_adds_discriminator().unwrap();
        let mut rewards = Vec::new();
        let mut claims = Vec::new();
        for (signer, value) in signers.iter().zip(values) {
            let owner = quil_crypto::poseidon::hash_bytes_to_32(signer.public_key()).unwrap();
            let address = crate::global_intrinsic::materialize::reward_address(&owner).unwrap();
            let mut tree = quil_tries::VectorCommitmentTree::new();
            global_schema::write_type(&mut tree, REWARD).unwrap();
            global_schema::write_field(&mut tree, REWARD, "DelegateAddress", &owner).unwrap();
            let mut balance = [0; 32];
            balance[16..].copy_from_slice(&value.to_be_bytes());
            global_schema::write_field(&mut tree, REWARD, "Balance", &balance).unwrap();
            let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
            state
                .set(&domains::GLOBAL, &address, &disc, 1, blob.clone())
                .unwrap();
            rewards.push((address, blob));
            claims.push(RewardClaim {
                owner,
                value,
                public_key: signer.public_key().try_into().unwrap(),
                forest_proof: Vec::new(),
            });
        }
        let forest = quil_forest::Forest::in_memory();
        let leaves = rewards.iter().map(|(address, blob)| {
            (
                address.to_vec(),
                quil_tries::vertex_leaf_value(blob).unwrap(),
            )
        });
        let reward_root = forest
            .commit_shard_phase_raw(b"mint-rewards", quil_forest::Phase::VertexAdds, 0, leaves)
            .unwrap();
        for (claim, (address, blob)) in claims.iter_mut().zip(&rewards) {
            let mut vertex = [0; 64];
            vertex[..32].copy_from_slice(&domains::GLOBAL);
            vertex[32..].copy_from_slice(address);
            let proof = forest
                .build_vertex_membership_proof(
                    b"mint-rewards",
                    quil_forest::Phase::VertexAdds,
                    0,
                    &vertex,
                    blob,
                )
                .unwrap();
            claim.forest_proof = quil_forest::MembershipProof {
                inputs: vec![proof],
            }
            .to_bytes();
        }
        state.commit().unwrap();
        state.abort();
        state.crdt().commit(1).unwrap();
        assert_eq!(
            state.crdt().compute_shard_root(
                "vertex",
                "adds",
                &quil_types::store::ShardKey {
                    l1: [0; 3],
                    l2: domains::GLOBAL,
                }
            ),
            reward_root.to_vec(),
            "fixture root must match committed global reward state"
        );
        let amounts = [u128::MAX - 258, 256];
        let mut outputs = Vec::new();
        let mut openings = Vec::new();
        let mut recipients = Vec::new();
        for (i, amount) in amounts.iter().enumerate() {
            let recipient = RecipientSecret::from_seed(&context, &[20 + i as u8; 32]);
            let (public, secret) = sntrup761::keypair();
            let address = RecipientAddress::new(&context, &recipient, public.as_bytes()).unwrap();
            let created = create_output(&context, &address, *amount).unwrap();
            outputs.push(created.output);
            openings.push(created.opening);
            recipients.push((recipient, secret));
        }
        let statement = MintStatement {
            network,
            application,
            cited_frame: 1,
            reward_root,
            claims,
            outputs,
            fee: 2,
        };
        let signatures = signers
            .iter()
            .map(|s| {
                s.sign_with_domain(&statement.context_bytes().unwrap(), &context)
                    .unwrap()
                    .try_into()
                    .unwrap()
            })
            .collect();
        // Placeholder proof used only for authorization tests; the full test
        // replaces it with native proving before constructing VerifiedMint.
        let mut proof = vec![0; 40];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        Fixture {
            state,
            mint: Mint {
                statement,
                signatures,
                proof,
            },
            signers,
            openings,
            amounts,
            recipients,
            rewards,
        }
    }

    fn sign(f: &Fixture, mint: &mut Mint) {
        let s = &mint.statement;
        mint.signatures = f
            .signers
            .iter()
            .map(|signer| {
                signer
                    .sign_with_domain(
                        &s.context_bytes().unwrap(),
                        &parameter_context(&s.network, &s.application),
                    )
                    .unwrap()
                    .try_into()
                    .unwrap()
            })
            .collect();
    }

    #[test]
    fn mint_dispatch_policy_rejects_wrong_venue_limits_fee_and_future_citation() {
        use crate::{
            engines::ExecutionMode, token_intrinsic::dispatch::TokenPolicy,
        };
        use quil_lattice_ct::confidential::transfer::CompileLimits;
        let f = fixture(HypergraphState::new(Arc::new(
            quil_hypergraph::HypergraphCrdt::new(
                Arc::new(quil_hypergraph::testing::MemStore::new()),
                Arc::new(NoopInclusionProver),
            ),
        )));
        let s = &f.mint.statement;
        let bytes = f.mint.encode().unwrap();
        let policy = TokenPolicy {
            network: s.network,
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
        let tp = crate::token_engine::TYPE_LATTICE_MINT;
        assert!(policy.check_venue(ExecutionMode::Global, &s.application, tp).is_ok());
        assert!(policy.check_venue(ExecutionMode::Application, &s.application, tp).is_err());
        // Custom-token issuance shares the type prefix but is application state.
        assert!(policy.check_venue(ExecutionMode::Application, &[7; 32], tp).is_ok());
        assert!(policy.preflight(&s.application, &bytes, tp).is_ok());
        let mut bad = policy;
        bad.limits.max_inputs = 1;
        assert!(bad.preflight(&s.application, &bytes, tp).is_err());
        let mut bad = policy;
        bad.limits.max_outputs = 1;
        assert!(bad.preflight(&s.application, &bytes, tp).is_err());
        let clock = crate::testing::NoopClockStore;
        for frame in [0, 1] {
            assert!(matches!(
                policy.dispatch_global_mint(&f.state, frame, &clock, &s.application, &bytes, None),
                Err(QuilError::InvalidArgument(_))
            ));
        }
        assert!(matches!(
            policy.dispatch_global_mint(&f.state, 2, &clock, &s.application, &bytes, None),
            Err(QuilError::ExecutionUnavailable(_))
        ));
        assert_eq!(f.state.changeset_len(), 0);
    }

    #[test]
    fn mint_clock_admission_uses_cited_global_root_and_preserves_missing_history() {
        use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader};
        let state = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(NoopInclusionProver),
        )));
        let f = fixture(state);
        let clock = quil_store::testing::InMemoryClockStore::new();
        let s = &f.mint.statement;
        let bytes = f.mint.encode().unwrap();
        let verify = |bound, max_claims| {
            verify_mint_from_clock(
                &f.state,
                &clock,
                &s.network,
                &s.application,
                bound,
                &bytes,
                max_claims,
                2,
                NativeBudget {
                    max_native_bytes: 0,
                },
            )
        };
        let before = f.state.changeset_len();
        // Cheap consensus constraints reject before a missing-history lookup.
        assert!(matches!(verify(0, 2), Err(QuilError::InvalidArgument(_))));
        assert!(matches!(verify(2, 1), Err(QuilError::InvalidArgument(_))));
        assert!(
            matches!(verify(2, 2), Err(QuilError::ExecutionUnavailable(e))
            if e.contains("cannot load canonical"))
        );
        let seed = |number, root| {
            clock.seed_frame(GlobalFrame {
                header: Some(GlobalFrameHeader {
                    frame_number: number,
                    prover_tree_commitment: root,
                    ..Default::default()
                }),
                ..Default::default()
            })
        };
        seed(s.cited_frame, vec![0; 31]);
        assert!(
            matches!(verify(2, 2), Err(QuilError::ExecutionUnavailable(e))
            if e.contains("not 32 bytes"))
        );
        seed(s.cited_frame, vec![99; 32]);
        assert!(matches!(verify(2, 2), Err(QuilError::InvalidArgument(_))));
        seed(s.cited_frame, s.reward_root.to_vec());
        // A newer local head must neither supply the root nor change the bound.
        seed(100, vec![99; 32]);
        assert!(matches!(verify(0, 2), Err(QuilError::InvalidArgument(_))));
        assert!(
            matches!(verify(2, 2), Err(QuilError::ExecutionUnavailable(e))
            if e.contains("native backend"))
        );
        // Partial global coverage must fail before native verification or any
        // staging: a matching boundary group still selects only some data.
        let global_path = quil_tries::get_full_path(&domains::GLOBAL);
        let boundary = domains::GLOBAL.len() * 8 / quil_tries::BRANCH_BITS + 1;
        f.state.crdt().set_covered_prefix(&global_path[..boundary]).unwrap();
        assert!(
            matches!(verify(2, 2), Err(QuilError::ExecutionUnavailable(e))
            if e.contains("complete domain coverage"))
        );
        assert_eq!(f.state.changeset_len(), before);
    }

    #[test]
    fn mint_requires_reward_membership_current_authority_and_unconsumed_authorization() {
        let state = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(NoopInclusionProver),
        )));
        let f = fixture(state);
        let s = &f.mint.statement;
        assert!(check_authorization(&f.mint, 2, &s.reward_root).is_ok());
        assert!(prepare_rewards(&f.state, s).is_ok());
        let before = f.state.changeset_len();
        assert!(matches!(
            verify_mint(
                &f.state,
                &s.network,
                &s.application,
                2,
                &s.reward_root,
                &f.mint.encode().unwrap(),
                2,
                2,
                NativeBudget {
                    max_native_bytes: 0
                }
            ),
            Err(QuilError::ExecutionUnavailable(_))
        ));
        assert_eq!(f.state.changeset_len(), before);
        let mut changed = f.mint.clone();
        changed.statement.claims[0].value -= 1;
        sign(&f, &mut changed);
        assert!(check_authorization(&changed, 2, &s.reward_root).is_err());
        changed = f.mint.clone();
        changed.statement.cited_frame = 3;
        sign(&f, &mut changed);
        assert!(check_authorization(&changed, 2, &s.reward_root).is_err());
        changed = f.mint.clone();
        changed.statement.outputs[0].memo[0] ^= 1;
        assert!(check_authorization(&changed, 2, &s.reward_root).is_err());
        assert!(check_authorization(&f.mint, 2, &[99; 32]).is_err());
        let disc = vertex_adds_discriminator().unwrap();
        let (address, blob) = &f.rewards[0];
        let mut tree = quil_tries::VectorCommitmentTree {
            root: quil_tries::deserialize_go_tree(blob).unwrap(),
        };
        global_schema::write_field(&mut tree, REWARD, "DelegateAddress", &[55; 32]).unwrap();
        f.state
            .set(
                &domains::GLOBAL,
                address,
                &disc,
                2,
                quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
            )
            .unwrap();
        assert!(prepare_rewards(&f.state, s).is_err());
        f.state.rollback_to(before);
        let marker = materialize::create_spent_marker_tree().unwrap();
        f.state
            .set(
                &s.application,
                &receipt_address(s).unwrap(),
                &disc,
                2,
                quil_tries::serialize_go_tree(marker.root.as_ref()).unwrap(),
            )
            .unwrap();
        assert!(prepare_rewards(&f.state, s).is_err());
    }

    fn disk_state(path: &std::path::Path) -> HypergraphState {
        let db = quil_store::RocksDb::open(path).unwrap();
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
            Arc::new(NoopInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::new(db.inner()));
        HypergraphState::new(crdt)
    }

    // Exercise identical mint/claim assertions through either the direct token
    // engine or the manager used to route production execution.
    enum MintExecutor {
        Token(crate::engines::TokenExecutionEngine),
        Manager(crate::manager::ExecutionEngineManager),
    }

    impl MintExecutor {
        fn validate_message(&self, frame: u64, app: &[u8], bytes: &[u8]) -> Result<()> {
            use quil_types::execution::ShardExecutionEngine;
            match self {
                Self::Token(engine) => engine.validate_message(frame, app, bytes),
                Self::Manager(manager) => manager.validate_message(frame, app, bytes),
            }
        }
        fn process_message(&self, frame: u64, fee: &num_bigint::BigInt, app: &[u8], bytes: &[u8])
            -> Result<quil_types::execution::ProcessMessageResult> {
            self.process_message_with_context(quil_types::execution::FrameExecutionContext {
                frame_number: frame, finalized_global_frame: None, venue: None, shard: quil_types::execution::ShardPath::WHOLE
            }, fee, app, bytes)
        }
        fn process_message_with_context(&self, context: quil_types::execution::FrameExecutionContext,
            fee: &num_bigint::BigInt, app: &[u8], bytes: &[u8]) -> Result<quil_types::execution::ProcessMessageResult> {
            use quil_types::execution::ShardExecutionEngine;
            match self {
                Self::Token(engine) => engine.process_message_with_context(context, fee, app, bytes),
                Self::Manager(manager) => manager.process_message_with_context(context, fee, app, bytes),
            }
        }
    }

    fn mint_executor(
        mode: crate::engines::ExecutionMode,
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
        clock: Arc<dyn quil_types::store::ClockStore>,
        key_manager: Arc<dyn quil_types::crypto::KeyManager>,
        policy: super::super::dispatch::TokenPolicy,
        worker: Option<&quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier>,
    ) -> MintExecutor {
        if let Some(worker) = worker {
            MintExecutor::Manager(crate::manager::ExecutionEngineManager::new(
                Arc::new(NoopInclusionProver), key_manager, crdt,
                Arc::new(crate::testing::NoopCircuitCompiler), clock,
                Arc::new(crate::testing::NoopHypergraphConfigResolver),
                mode == crate::engines::ExecutionMode::Global,
            ).with_token_worker(policy, worker.clone()).unwrap())
        } else {
            MintExecutor::Token(crate::engines::TokenExecutionEngine::new_with_state(
                mode, Arc::new(NoopInclusionProver), crdt, key_manager, clock,
            ).with_token_proofs(policy).unwrap())
        }
    }

    #[test]
    #[ignore = "complete native global reward authorization and restart"]
    fn complete_reward_mint_authorizes_global_outputs_once() {
        reward_mint_authorization_roundtrip(None);
    }

    #[test]
    #[ignore = "requires native worker; complete mint and both claim venues"]
    fn complete_reward_mint_with_worker() {
        use quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier;
        let path = std::env::var("QUIL_AMOUNT_WORKER_PATH").expect("native worker path");
        let worker = WorkerVerifier::from_test_env(path.into()).unwrap();
        reward_mint_authorization_roundtrip(Some(worker));
    }

    fn reward_mint_authorization_roundtrip(
        worker: Option<quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier>,
    ) {
        let started = std::time::Instant::now();
        let directory = tempfile::tempdir().unwrap();
        let mut f = fixture(disk_state(directory.path()));
        let budget = NativeBudget {
            max_native_bytes: 1024 * 1024 * 1024,
        };
        let openings: Vec<_> = f
            .amounts
            .iter()
            .zip(&f.openings)
            .map(|(&a, r)| (a, r))
            .collect();
        let relation = f.mint.statement.private_relation(&openings, 2, 2).unwrap();
        f.mint.proof = native::prove(&relation, budget).unwrap();
        drop(relation);
        let bytes = f.mint.encode().unwrap();
        let s = &f.mint.statement;
        let crdt = f.state.crdt().clone();
        let receipt;
        {
            let _guard = crdt.lock_forest_writes();
            let _direct = verify_mint(
                &f.state,
                &s.network,
                &s.application,
                2,
                &s.reward_root,
                &bytes,
                2,
                2,
                budget,
            )
            .unwrap();
            let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
            clock.seed_frame(quil_types::proto::global::GlobalFrame {
                header: Some(quil_types::proto::global::GlobalFrameHeader {
                    frame_number: s.cited_frame, prover_tree_commitment: s.reward_root.to_vec(),
                    ..Default::default()
                }), ..Default::default()
            });
            let stubs = crate::testing::NoopExecutionCrypto::new();
            let make_engine = |mode, native_budget, override_worker: Option<&quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier>| {
                mint_executor(mode, crdt.clone(), clock.clone(), stubs.key_manager.clone(),
                    super::super::dispatch::TokenPolicy {
                        network: s.network,
                        limits: quil_lattice_ct::confidential::transfer::CompileLimits {
                            max_inputs: 2, max_outputs: 2, max_depth: 32,
                        }, snapshots: SnapshotLimits { max_coins: 8, max_depth: 32, max_nodes: 128 },
                        native_budget,
                    }, override_worker.or(worker.as_ref()))
            };
            let carrier = quil_types::proto::global::MessageRequest {
                request: Some(quil_types::proto::global::message_request::Request::TokenOperation(
                    quil_types::proto::token::TokenOperation { canonical_bytes: bytes.clone() })),
                ..Default::default()
            };
            let inner = crate::message_envelope::proto_message_request_to_canonical_inner_bytes(&carrier).unwrap();
            assert_eq!(inner, bytes);
            let message = crate::message_envelope::CanonicalMessageRequest::wrap(inner).unwrap()
                .to_canonical_bytes().unwrap();
            let app = make_engine(crate::engines::ExecutionMode::Application, budget, None);
            assert!(app.validate_message(2, &s.application, &message).is_err());
            if worker.is_some() {
                // A configured process failure must not fall back to the
                // otherwise-valid in-process proof, nor stage any writes.
                let missing_path = directory.path().join("absent-proof-worker");
                let missing = quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier::new(
                    missing_path, 1, std::time::Duration::from_secs(2)).unwrap();
                let failed = make_engine(crate::engines::ExecutionMode::Global, budget, Some(&missing));
                let before = f.state.changeset_len();
                assert!(matches!(failed.process_message(2, &num_bigint::BigInt::from(0),
                    &s.application, &message), Err(QuilError::ExecutionUnavailable(_))));
                assert_eq!(f.state.changeset_len(), before);
            }
            let unavailable = make_engine(crate::engines::ExecutionMode::Global, NativeBudget { max_native_bytes: 0 }, None);
            assert!(matches!(unavailable.process_message(2, &num_bigint::BigInt::from(0),
                &s.application, &message), Err(QuilError::ExecutionUnavailable(_))));
            let engine = make_engine(crate::engines::ExecutionMode::Global, budget, None);
            engine.validate_message(2, &s.application, &message).unwrap();
            engine.process_message(2, &num_bigint::BigInt::from(0), &s.application, &message).unwrap();
            receipt = receipt_address(s).unwrap();
            let disc = vertex_adds_discriminator().unwrap();
            let authorization = f.state.get(&domains::GLOBAL, &receipt, &disc).unwrap().unwrap();
            engine.process_message(2, &num_bigint::BigInt::from(0), &s.application, &message).unwrap_err();
            assert_eq!(f.state.get(&domains::GLOBAL, &receipt, &disc).unwrap(), Some(authorization));
            // The reward mint authorizes and debits; it creates no coins in
            // any venue. Its claim does, through the commit.
            assert!(
                roots::read_current(&f.state, &s.network, &s.application)
                    .unwrap()
                    .is_none()
            );
            let disc = vertex_adds_discriminator().unwrap();
            for (address, _) in &f.rewards {
                let blob = f
                    .state
                    .get(&domains::GLOBAL, address, &disc)
                    .unwrap()
                    .unwrap();
                let tree = quil_tries::VectorCommitmentTree {
                    root: quil_tries::deserialize_go_tree(&blob).unwrap(),
                };
                assert!(global_schema::read_field(&tree, REWARD, "Balance")
                    .unwrap()
                    .iter()
                    .all(|b| *b == 0));
            }
            f.state.commit().unwrap();
            f.state.abort();
            crdt.commit(2).unwrap();
        }
        let root: [u8; 32] = crdt
            .compute_shard_root(
                "vertex",
                "adds",
                &quil_types::store::ShardKey {
                    l1: [0; 3],
                    l2: domains::GLOBAL,
                },
            )
            .try_into()
            .unwrap();
        let proof = quil_forest::MembershipProof {
            inputs: vec![crdt
                .global_vertex_membership_at_root(&root, &receipt)
                .unwrap()
                .unwrap()],
        }
        .to_bytes();
        super::super::mint_authorization::verify_membership(
            &s.network,
            &s.application,
            &receipt,
            &s.outputs,
            s.fee,
            &root,
            &proof,
        )
        .unwrap();
        drop(f.state);
        drop(crdt);
        let state = disk_state(directory.path());
        let reopened = quil_forest::MembershipProof {
            inputs: vec![state
                .crdt()
                .global_vertex_membership_at_root(&root, &receipt)
                .unwrap()
                .unwrap()],
        }
        .to_bytes();
        assert_eq!(reopened, proof);
        // App execution uses a separate DB and canonical global header; it has
        // no local reward vertices and does not rerun the native amount proof.
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        clock.seed_frame(quil_types::proto::global::GlobalFrame {
            header: Some(quil_types::proto::global::GlobalFrameHeader {
                frame_number: 3,
                prover_tree_commitment: root.to_vec(),
                ..Default::default()
            }),
            ..Default::default()
        });
        // The shard's latest anchor (3) bounds the citation; a claim cannot cite
        // a global frame after it, and with no stored frame at or before a lower
        // anchor there is nothing to cite yet.
        let witness = super::super::mint_authorization_witness::witness(&state, clock.as_ref(), &receipt, Some(3)).unwrap();
        assert_eq!(witness.cited_frame, 3);
        assert_eq!(witness.forest_proof, reopened);
        assert!(!super::super::mint_authorization_witness::witness(&state, clock.as_ref(), &[9; 32], Some(3)).unwrap().found);
        assert!(super::super::mint_authorization_witness::witness(&state, clock.as_ref(), &receipt, Some(2)).is_err());
        let claim = super::super::mint_authorization::claim_from_witness(s, witness).unwrap();
        let claim_bytes = claim.encode().unwrap();
        assert!(bytes.len() + claim_bytes.len()
            < quil_lattice_ct::confidential::transfer::TARGET_TRANSACTION_BYTES);
        let execution = quil_types::execution::FrameExecutionContext {
            frame_number: 7,
            finalized_global_frame: Some(3), venue: None, shard: quil_types::execution::ShardPath::WHOLE
        };
        let verify_claim = || {
            super::super::mint_claim::verify_from_clock(
                clock.as_ref(),
                execution,
                &s.network,
                &s.application,
                &claim_bytes,
                2,
            )
            .unwrap()
        };
        for mode in [crate::engines::ExecutionMode::Application, crate::engines::ExecutionMode::Global] {
            let app_directory = tempfile::tempdir().unwrap();
            let app_state = disk_state(app_directory.path());
            let limits = SnapshotLimits {
                max_coins: 8,
                max_depth: 32,
                max_nodes: 128,
            };
            let stubs = crate::testing::NoopExecutionCrypto::new();
            let policy = super::super::dispatch::TokenPolicy {
                network: s.network,
                limits: quil_lattice_ct::confidential::transfer::CompileLimits {
                    max_inputs: 2, max_outputs: 2, max_depth: 32,
                },
                snapshots: limits,
                native_budget: budget,
            };
            let engine = mint_executor(mode, app_state.crdt().clone(), clock.clone(),
                stubs.key_manager.clone(), policy, worker.as_ref());
            let message = crate::message_envelope::CanonicalMessageRequest::wrap(claim_bytes.clone())
                .unwrap().to_canonical_bytes().unwrap();
            engine.validate_message(7, &s.application, &message).unwrap();
            if mode == crate::engines::ExecutionMode::Application {
                assert!(matches!(engine.process_message(7, &num_bigint::BigInt::from(0),
                    &s.application, &message), Err(QuilError::ExecutionUnavailable(_))));
            } else {
                // An explicit anchor is authoritative in either venue and bounds
                // the citation: anchor 2 cannot admit the root of frame 3.
                engine.process_message_with_context(quil_types::execution::FrameExecutionContext {
                    frame_number: 100, finalized_global_frame: Some(2), venue: None, shard: quil_types::execution::ShardPath::WHOLE
                }, &num_bigint::BigInt::from(0), &s.application, &message).unwrap_err();
            }
            assert!(roots::read_current(&app_state, &s.network, &s.application).unwrap().is_none());
            let claim_execution = quil_types::execution::FrameExecutionContext {
                finalized_global_frame: if mode == crate::engines::ExecutionMode::Global { None } else { Some(3) },
                ..execution
            };
            engine.process_message_with_context(claim_execution, &num_bigint::BigInt::from(0),
                &s.application, &message).unwrap();
            let accepted_root = roots::read_current(&app_state, &s.network, &s.application).unwrap();
            if mode == crate::engines::ExecutionMode::Application {
                // An app shard verifies and relays: the coins are placed by the
                // owning shard once the global frame commits the claim, so
                // nothing is written here and a re-run verifies just as well.
                assert!(accepted_root.is_none());
                engine.process_message_with_context(claim_execution, &num_bigint::BigInt::from(0),
                    &s.application, &message).unwrap();
                assert!(roots::read_current(&app_state, &s.network, &s.application).unwrap().is_none());
                verify_claim();
                continue;
            }
            // The global venue commits and places inline, once.
            assert!(accepted_root.is_some());
            engine.process_message_with_context(claim_execution, &num_bigint::BigInt::from(0),
                &s.application, &message).unwrap_err();
            assert_eq!(roots::read_current(&app_state, &s.network, &s.application).unwrap(), accepted_root);
            let context = parameter_context(&s.network, &s.application);
            let output_addresses: Vec<_> = s.outputs.iter()
                .map(|output| state::coin_identity(&context, execution.frame_number, output).unwrap().0)
                .collect();
            let claim_tp = crate::token_engine::TYPE_LATTICE_MINT_CLAIM;
            let replay = crate::token_intrinsic::commit_apply::commit_and_place(
                &app_state, 8, &s.network, &s.application, claim_tp, &claim_bytes, limits).unwrap_err();
            assert!(replay.to_string().contains("already decided"), "{replay}");
            app_state.rollback_to(0);
            app_state.commit().unwrap();
            app_state.abort();
            app_state.crdt().commit(7).unwrap();
            drop(engine);
            drop(app_state);
            let app_state = disk_state(app_directory.path());
            let replay = crate::token_intrinsic::commit_apply::commit_and_place(
                &app_state, 8, &s.network, &s.application, claim_tp, &claim_bytes, limits).unwrap_err();
            assert!(replay.to_string().contains("already decided"), "{replay}");
            app_state.rollback_to(0);
            let disc = vertex_adds_discriminator().unwrap();
            for (i, address) in output_addresses.iter().enumerate() {
                let blob = app_state
                    .get(&s.application, address, &disc)
                    .unwrap()
                    .unwrap();
                let tree = quil_tries::VectorCommitmentTree {
                    root: quil_tries::deserialize_go_tree(&blob).unwrap(),
                };
                let context = parameter_context(&s.network, &s.application);
                let coin = state::read_coin(&tree, &context)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    open_output(
                        &context,
                        f.recipients[i].1.as_bytes(),
                        &f.recipients[i].0,
                        &coin.output
                    )
                    .unwrap()
                    .amount,
                    f.amounts[i]
                );
            }
            for (address, _) in &f.rewards {
                assert!(app_state
                    .get(&domains::GLOBAL, address, &disc)
                    .unwrap()
                    .is_none());
            }
            eprintln!("mint_claim_executed venue={mode:?} dispatcher=true invalid_anchor_rejected=true separate_app_rocksdb_reopened=true recipients_recovered=2 replay_rejected=true claim_bytes={} combined_bytes={}",
                claim_bytes.len(), bytes.len() + claim_bytes.len());
        }
        let disc = vertex_adds_discriminator().unwrap();
        for (address, original) in &f.rewards {
            state
                .set(&domains::GLOBAL, address, &disc, 3, original.clone())
                .unwrap();
        }
        assert!(
            matches!(verify_mint(&state,&s.network,&s.application,3,&s.reward_root,&bytes,2,2,budget),
            Err(QuilError::InvalidArgument(e)) if e.contains("authorization already consumed"))
        );
        state.abort();
        assert!(
            roots::read_current(&state, &s.network, &s.application)
                .unwrap()
                .is_none()
        );
        assert!(
            bytes.len() < quil_lattice_ct::confidential::transfer::TARGET_TRANSACTION_BYTES
        );
        assert!(proof.len() < super::super::reward_witness::MAX_REWARD_PROOF_BYTES);
        if let Ok(path) = std::env::var("QUIL_TEST_TRANSACTION_PATH") {
            std::fs::write(&path, &bytes).unwrap();
            std::fs::write(format!("{path}.claim"), &claim_bytes).unwrap();
        }
        eprintln!("mint_authorized global_dispatcher=true native_verified=true reward_debits=2 global_phase_app_writes=false rocksdb_forest_reopened=true replay_rejected=true bytes={} proof_bytes={} authorization_proof_bytes={} seconds={:.3}",bytes.len(),f.mint.proof.len(),proof.len(),started.elapsed().as_secs_f64());
    }

    #[test]
    #[ignore = "complete native reward mint and RocksDB recovery"]
    fn complete_reward_mint_proves_debits_and_reopens() {
        run_complete_mint();
    }

    #[test]
    #[ignore = "complete native reward mint through global token engine"]
    fn complete_reward_mint_through_global_dispatcher() {
        complete_reward_mint_authorizes_global_outputs_once();
    }

    fn run_complete_mint() {
        let started = std::time::Instant::now();
        let directory = tempfile::tempdir().unwrap();
        let mut f = fixture(disk_state(directory.path()));
        let budget = NativeBudget {
            max_native_bytes: 1024 * 1024 * 1024,
        };
        let openings: Vec<_> = f
            .amounts
            .iter()
            .zip(&f.openings)
            .map(|(&a, r)| (a, r))
            .collect();
        let relation = f.mint.statement.private_relation(&openings, 2, 2).unwrap();
        f.mint.proof = native::prove(&relation, budget).unwrap();
        drop(relation);
        let bytes = f.mint.encode().unwrap();
        assert!(
            bytes.len() < quil_lattice_ct::confidential::transfer::TARGET_TRANSACTION_BYTES
        );
        let s = &f.mint.statement;
        // Persist and reopen the canonical global frame independently of the
        // token store, as a node loading reward history would do.
        let clock_directory = tempfile::tempdir().unwrap();
        {
            use quil_types::store::ClockStore;
            let db = quil_store::RocksDb::open(clock_directory.path()).unwrap();
            let clock = quil_store::RocksClockStore::new(db.inner());
            let txn = clock.new_transaction(false).unwrap();
            clock
                .put_global_clock_frame(
                    &quil_types::proto::global::GlobalFrame {
                        header: Some(quil_types::proto::global::GlobalFrameHeader {
                            frame_number: s.cited_frame,
                            prover_tree_commitment: s.reward_root.to_vec(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    txn.as_ref(),
                )
                .unwrap();
            txn.commit().unwrap();
        }
        let clock_db = quil_store::RocksDb::open(clock_directory.path()).unwrap();
        let clock = Arc::new(quil_store::RocksClockStore::new(clock_db.inner()));
        let verify = || {
            verify_mint_from_clock(
                &f.state,
                clock.as_ref(),
                &s.network,
                &s.application,
                2,
                &bytes,
                2,
                2,
                budget,
            )
            .unwrap()
        };
        let limits = SnapshotLimits {
            max_coins: 8,
            max_depth: 3,
            max_nodes: 24,
        };
        let checkpoint = f.state.changeset_len();
        let _ = limits;
        let disc = vertex_adds_discriminator().unwrap();
        for (address, original) in &f.rewards {
            assert_eq!(
                f.state
                    .get(&domains::GLOBAL, address, &disc)
                    .unwrap()
                    .as_ref(),
                Some(original)
            );
        }
        let verified = verify();
        assert_eq!(verified.fee(), 2);
        // The mint authorizes its claims and debits the rewards; the coins
        // come later, from claims the global frame commits.
        let receipt = verified.authorize_global(&f.state, 2).unwrap();
        assert!(f.state.get(&domains::GLOBAL, &receipt,
            &vertex_adds_discriminator().unwrap()).unwrap().is_some());
        assert!(f.state.changeset_len() > checkpoint);
        for (address, _) in &f.rewards {
            let blob = f
                .state
                .get(&domains::GLOBAL, address, &disc)
                .unwrap()
                .unwrap();
            let tree = quil_tries::VectorCommitmentTree {
                root: quil_tries::deserialize_go_tree(&blob).unwrap(),
            };
            assert_eq!(
                global_schema::read_field(&tree, REWARD, "Balance"),
                Some(vec![0; 32])
            );
        }
        f.state.commit().unwrap();
        f.state.abort();
        f.state.crdt().commit(2).unwrap();
        drop(f.state);
        let state = disk_state(directory.path());
        // Authorization creates no coins, so the accumulator is untouched.
        assert!(roots::read_current(&state, &s.network, &s.application).unwrap().is_none());
        assert!(state.get(&domains::GLOBAL, &receipt, &disc).unwrap().is_some());
        // Replenishing rewards does not revive this already consumed signed mint.
        for (address, original) in &f.rewards {
            state
                .set(&domains::GLOBAL, address, &disc, 3, original.clone())
                .unwrap();
        }
        assert!(
            matches!(verify_mint(&state, &s.network, &s.application, 3, &s.reward_root, &bytes, 2, 2, budget),
            Err(QuilError::InvalidArgument(message)) if message.contains("authorization already consumed"))
        );
        state.abort();
        if let Ok(path) = std::env::var("QUIL_TEST_TRANSACTION_PATH") {
            std::fs::write(path, &bytes).unwrap();
        }
        eprintln!("mint_complete native_verified=true authorized_claims=2 reward_debits=2 rocksdb_reopened=true replenished_reward_replay_rejected=true bytes={} proof_bytes={} seconds={:.3}",
            bytes.len(), f.mint.proof.len(), started.elapsed().as_secs_f64());
    }
}
