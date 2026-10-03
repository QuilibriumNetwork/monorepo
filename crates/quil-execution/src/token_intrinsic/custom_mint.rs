//! Custom-token (non-QUIL) mint admission. The issuance policy
//! comes from the token's deployed configuration, read through execution state
//! so same-frame deploys and updates are visible. Supported policies mirror the
//! legacy mint behaviors: `MintWithAuthority`/`MintWithSignature` require the
//! configured authority's signature over the canonical statement, and a free
//! `MintWithPayment` policy (no fee basis) is permissionless. Paid payment
//! mints and proof-basis (PoMW/verkle) mints are rejected explicitly. Like the
//! legacy path, no supply cap is enforced here.
use super::{
    roots,
    state::{self, SnapshotLimits},
    config::TokenMintStrategy,
    config_resolver::{MintVariant, StaticTokenConfigResolver, StaticTokenEntry},
    constants::MINTABLE,
    materialize, metadata_schema,
};
use crate::{
    domains,
    hypergraph_state::{vertex_adds_discriminator, HypergraphState, HYPERGRAPH_METADATA_ADDRESS},
};
use quil_lattice_ct::confidential::{
    custom_mint::{CustomMint, CustomMintStatement},
    relation::backend::native::{self, NativeBudget},
    transfer::parameter_context,
};
use quil_types::error::{QuilError, Result};
pub use super::signature::verify_authority_signature;
use sha3::{Digest, Sha3_256};
use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
use std::collections::BTreeSet;

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("custom mint: {message}"))
}
fn unavailable(message: &str) -> QuilError {
    QuilError::ExecutionUnavailable(format!("custom mint: {message}"))
}

/// One-time consumption identity. Signature and proof bytes are excluded so
/// alternate encodings of them cannot mint the same statement twice.
pub fn receipt_address(s: &CustomMintStatement) -> Result<[u8; 32]> {
    let context = s.context_bytes().map_err(|_| invalid("invalid statement"))?;
    let mut bytes = Vec::from(b"quil/custom-mint/receipt/v1\0".as_slice());
    bytes.extend_from_slice(&parameter_context(&s.network, &s.application));
    bytes.extend_from_slice(&Sha3_256::digest(context));
    quil_crypto::poseidon::hash_bytes_to_32(&bytes)
}

/// Deployed mint policy of a token application.
pub struct MintPolicy {
    pub behavior: u16,
    pub entry: StaticTokenEntry,
}

/// Read the token configuration through execution state (pending changeset
/// first) at `(application, HYPERGRAPH_METADATA_ADDRESS)`, the same vertex
/// both the deploy and update paths write.
pub fn load_policy(state: &HypergraphState, application: &[u8; 32]) -> Result<MintPolicy> {
    let disc = vertex_adds_discriminator()?;
    let blob = state
        .get(application, &HYPERGRAPH_METADATA_ADDRESS, &disc)?
        .filter(|blob| !blob.is_empty())
        .ok_or_else(|| invalid("token application is not deployed"))?;
    let outer = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(&blob)
            .map_err(|_| unavailable("cannot decode token metadata"))?,
    };
    let inner_blob = outer
        .get(&materialize::TOKEN_CONFIG_OUTER_KEY)
        .ok_or_else(|| invalid("token configuration missing"))?;
    let inner = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(inner_blob)
            .map_err(|_| unavailable("cannot decode token configuration"))?,
    };
    let config = metadata_schema::decode_token_config_from_tree(&inner)
        .map_err(|_| unavailable("cannot decode token configuration"))?;
    let behavior =
        u16::try_from(config.behavior).map_err(|_| invalid("invalid token behavior"))?;
    if config.mint_strategy.is_empty() {
        return Err(invalid("token has no mint strategy"));
    }
    let strategy = TokenMintStrategy::from_canonical_bytes(&config.mint_strategy)
        .map_err(|_| invalid("invalid mint strategy"))?;
    let entry = StaticTokenConfigResolver::entry_from_mint_strategy(&strategy)
        .map_err(|_| invalid("invalid mint strategy"))?;
    Ok(MintPolicy { behavior, entry })
}

/// A settlement payment admitted at bundle level for one paid custom mint:
/// the payee's payment address and the payment coin's public value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaidMintAllowance {
    pub payment_address: [u8; 32],
    pub payment: u128,
}

fn check_authorization(mint: &CustomMint, policy: &MintPolicy, paid: Option<&PaidMintAllowance>) -> Result<()> {
    let s = &mint.statement;
    if policy.behavior & MINTABLE == 0 {
        return Err(invalid("token is not mintable"));
    }
    let context = s.context_bytes().map_err(|_| invalid("invalid statement"))?;
    let domain = parameter_context(&s.network, &s.application);
    match policy.entry.variant {
        MintVariant::Authority | MintVariant::Signature => {
            let (Some(key_type), Some(public_key)) = (
                policy.entry.authority_key_type,
                policy.entry.authority_public_key.as_ref(),
            ) else {
                return Err(invalid("token authority is not configured"));
            };
            if s.authority_key_type != key_type || &s.authority_public_key != public_key {
                return Err(invalid("statement authority does not match token policy"));
            }
            verify_authority_signature(key_type, public_key, &context, &domain, &mint.signature)
        }
        MintVariant::Payment => {
            if let Some(baseline) = &policy.entry.payment_fee_baseline {
                // The mint's price is paid to the token's payment address by
                // a public payment coin in the settlement the bundle's claim
                // consumes; the transaction's own fee is the claim's
                // settlement, paid to the provers.
                let paid = paid.ok_or_else(|| invalid("paid custom mint requires a settlement claim carrying its payment"))?;
                let payee = policy.entry.payment_address.as_deref()
                    .ok_or_else(|| invalid("paid mint policy has no payment address"))?;
                if payee != paid.payment_address.as_slice() {
                    return Err(invalid("payment is not made to the token's payment address"));
                }
                let price = baseline * num_bigint::BigInt::from(s.amount);
                if num_bigint::BigInt::from(paid.payment) < price {
                    return Err(invalid("payment below the mint price"));
                }
            }
            // Free payment policy: legacy free mints carry no authority.
            if !s.is_permissionless() || !mint.signature.is_empty() {
                return Err(invalid("permissionless mint carries no authority"));
            }
            Ok(())
        }
        MintVariant::MerkleEntitlementWithSignature => {
            // The token's configuration carries a Merkle root of
            // entitlements; a mint proves its leaf, which binds the minting
            // key and the exact amount, and signs the statement
            // with that key. The leaf is consumed once (checked and written in
            // `check_state` / `stage`).
            let root = policy.entry.entitlement_root.as_deref()
                .ok_or_else(|| invalid("proof-basis token has no entitlement root"))?;
            if s.is_permissionless() {
                return Err(invalid("a proof-basis mint carries its entitled key"));
            }
            let leaf = super::entitlement::leaf(&s.network, s.authority_key_type, &s.authority_public_key, s.amount);
            super::entitlement::verify(&leaf, &s.entitlement_proof, root)?;
            verify_authority_signature(s.authority_key_type, &s.authority_public_key, &context, &domain, &mint.signature)
        }
        MintVariant::ProofOfMeaningfulWork => {
            // Custom tokens do not mint by proof of meaningful work.
            Err(invalid("custom tokens do not mint by proof of meaningful work"))
        }
        MintVariant::VerkleMultiproofWithSignature => {
            Err(invalid("verkle proof basis is retired; use the Merkle entitlement basis"))
        }
        MintVariant::NoMint | MintVariant::Unknown => {
            Err(invalid("token mint policy does not permit minting"))
        }
    }
}

/// The entitlement leaf a proof-basis mint spends, or `None` under any other
/// policy. The leaf binds the token, the minting key and the exact amount.
fn entitlement_leaf(policy: &MintPolicy, s: &CustomMintStatement) -> Option<[u8; 32]> {
    (policy.entry.variant == MintVariant::MerkleEntitlementWithSignature && !s.is_permissionless()).then(|| {
        super::entitlement::leaf(
            &s.network,
            s.authority_key_type,
            &s.authority_public_key,
            s.amount,
        )
    })
}

/// The one-time markers a custom mint consumes when it commits through the
/// global frame: its receipt and, under the proof basis, its entitlement leaf.
pub fn commit_consumptions(state: &HypergraphState, bytes: &[u8], network: &[u8; 32], application: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
    let mint = CustomMint::decode(bytes, network, application).map_err(|_| invalid("invalid encoding or context"))?;
    let s = &mint.statement;
    let policy = load_policy(state, application)?;
    let mut consumptions = vec![receipt_address(s)?];
    if let Some(leaf) = entitlement_leaf(&policy, s) {
        consumptions.push(super::entitlement::consumed_marker(application, &leaf)?);
    }
    Ok(consumptions)
}

/// State checks verification can make: domain, coverage and the deployed
/// policy. Whether the receipt or the entitlement has already been spent is
/// the global commit's decision, not a shard's — see [`commit_consumptions`].
/// Returns the receipt address and policy.
fn check_state(state: &HypergraphState, s: &CustomMintStatement) -> Result<([u8; 32], MintPolicy)> {
    if s.application == domains::QUIL_TOKEN {
        return Err(invalid("QUIL issuance uses the reward mint"));
    }
    state.require_full_domain_coverage(&s.application)?;
    let policy = load_policy(state, &s.application)?;
    Ok((receipt_address(s)?, policy))
}

/// Only successful policy authorization and native verification construct it.
pub struct VerifiedCustomMint {
    mint: CustomMint,
    paid: Option<PaidMintAllowance>,
}

pub fn verify_custom_mint(
    state: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    bytes: &[u8],
    max_outputs: usize,
    budget: NativeBudget,
) -> Result<VerifiedCustomMint> {
    verify_custom_mint_with_worker(state, network, application, bytes, max_outputs, budget, None, None)
}

pub(crate) fn verify_custom_mint_with_worker(
    state: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    bytes: &[u8],
    max_outputs: usize,
    budget: NativeBudget,
    worker: Option<&quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier>,
    paid: Option<PaidMintAllowance>,
) -> Result<VerifiedCustomMint> {
    let mint = CustomMint::decode(bytes, network, application)
        .map_err(|_| invalid("invalid encoding or context"))?;
    if mint.statement.outputs.len() > max_outputs {
        return Err(invalid("configured dimensions exceeded"));
    }
    let (_, policy) = check_state(state, &mint.statement)?;
    check_authorization(&mint, &policy, paid.as_ref())?;
    if let Some(worker) = worker {
        super::dispatch::verify_in_worker(
            worker,
            network,
            application,
            bytes,
            quil_lattice_ct::confidential::transfer::CompileLimits {
                max_inputs: 1,
                max_outputs,
                max_depth: 1,
            },
            budget,
        )?;
    } else {
        let relation = mint
            .statement
            .public_relation(max_outputs)
            .map_err(|_| invalid("invalid or oversized relation"))?;
        if !native::verify_owned(relation, &mint.proof, budget)
            .map_err(|e| unavailable(&format!("native backend: {e:?}")))?
        {
            return Err(invalid("invalid amount proof"));
        }
    }
    Ok(VerifiedCustomMint { mint, paid })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::KeyType;
    use crate::token_intrinsic::{
        config::{Authority, FeeBasisStruct, TokenConfiguration, TokenMintStrategy},
        constants::{
            DIVISIBLE, MINT_WITH_AUTHORITY, MINT_WITH_PAYMENT, MINT_WITH_PROOF, MINT_WITH_SIGNATURE,
            PER_UNIT, PROOF_OF_MEANINGFUL_WORK,
        },
    };
    use quil_lattice_ct::confidential::{
        transfer::{CompileLimits, Output, MEMO_BYTES},
        AmountOpening, CommitmentKey,
    };
    use quil_types::crypto::{NoopInclusionProver, Signer};
    use std::sync::Arc;

    fn mem_state() -> HypergraphState {
        HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(NoopInclusionProver),
        )))
    }

    fn disk_state(path: &std::path::Path) -> HypergraphState {
        let db = quil_store::RocksDb::open(path).unwrap();
        HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
            Arc::new(NoopInclusionProver),
        )))
    }

    /// Application authority keys are post-quantum only, so every fixture
    /// authority is Falcon-512. The seed only distinguishes fixtures.
    fn authority_signer(_seed: u8) -> quil_crypto::FalconSigner {
        quil_crypto::FalconSigner::generate()
    }

    fn authority_strategy(behavior: u16, key_type: u32, public_key: &[u8]) -> TokenMintStrategy {
        TokenMintStrategy {
            mint_behavior: behavior as u32,
            proof_basis: 0,
            verkle_root: Vec::new(),
            authority: Authority { key_type, public_key: public_key.to_vec(), can_burn: false }
                .to_canonical_bytes()
                .unwrap(),
            payment_address: Vec::new(),
            fee_basis: Vec::new(),
        }
    }

    /// Deploy a token through the real deploy materializer; the domain is
    /// derived from the configuration content, so `salt` separates tokens.
    fn deploy(state: &HypergraphState, behavior: u16, strategy: TokenMintStrategy, salt: u8) -> [u8; 32] {
        let config = TokenConfiguration {
            behavior: behavior as u32,
            mint_strategy: strategy.to_canonical_bytes().unwrap(),
            units: vec![1],
            supply: Vec::new(),
            name: format!("custom-{salt}").into_bytes(),
            symbol: b"CST".to_vec(),
            additional_reference: Vec::new(),
            owner_public_key: Vec::new(),
        };
        materialize::materialize_token_deploy_init(state, &config, 1, &NoopInclusionProver).unwrap()
    }

    /// A paid mint in a token bundle: its price must arrive through the
    /// bundle's settlement claim as a payment to the token's payment address.
    /// The fixture proof is not native-verifiable, so reaching proof
    /// verification (an execution-unavailable budget error) shows the payment
    /// was admitted; policy rejections are deterministic errors first.
    #[test]
    fn paid_mint_bundle_requires_the_claimed_payment_before_proof_work() {
        use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        use crate::token_intrinsic::{dispatch::TokenPolicy, settlement_claim::*, settlement_record::*};
        use quil_types::execution::{FrameExecutionContext, ShardExecutionEngine};
        use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader};
        let network = [81; 32];
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()), Arc::new(NoopInclusionProver)));
        let state = HypergraphState::new(crdt.clone());
        let app = deploy(&state, MINTABLE | DIVISIBLE, TokenMintStrategy {
            mint_behavior: MINT_WITH_PAYMENT as u32,
            payment_address: vec![1; 32],
            fee_basis: FeeBasisStruct { fee_type: PER_UNIT as u32, baseline: vec![5] }.to_canonical_bytes().unwrap(),
            ..TokenMintStrategy::default() }, 21);
        state.commit().unwrap();
        state.abort();
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let stubs = crate::testing::NoopExecutionCrypto::new();
        let engine = crate::engines::TokenExecutionEngine::new_with_state(
            crate::engines::ExecutionMode::Application, Arc::new(NoopInclusionProver), crdt.clone(),
            stubs.key_manager, clock.clone(),
        ).with_token_proofs(TokenPolicy {
            network,
            limits: CompileLimits { max_inputs: 1, max_outputs: 2, max_depth: 1 },
            snapshots: SnapshotLimits { max_coins: 8, max_depth: 3, max_nodes: 24 },
            native_budget: NativeBudget { max_native_bytes: 0 },
        }).unwrap();
        let mint = CustomMint {
            statement: statement(network, app, (0, Vec::new()), 8, &[9, 10]),
            signature: Vec::new(), proof: placeholder_proof(),
        };
        let mint_request = CanonicalMessageRequest::wrap(mint.encode().unwrap()).unwrap();
        let rest = CanonicalMessageBundle { requests: vec![None, Some(mint_request.clone())], timestamp: 3 };
        let context = bundle_context(&rest).unwrap();
        let bundle_with = |payment: u128, receipt: u8| {
            let entry = SettlementEntry {
                receipt: [receipt; 32],
                parameter_context: parameter_context(&network, &domains::QUIL_TOKEN),
                destination: app, context, settlement: 1_000, payment_address: [1; 32], payment, claimant: [0; 32],
            };
            let blob = create_record(&entry).unwrap();
            let forest = quil_forest::Forest::in_memory();
            let root = forest.commit_shard_phase_raw(b"paid-mint", quil_forest::Phase::VertexAdds, 0,
                [(entry.receipt.to_vec(), quil_tries::vertex_leaf_value(&blob).unwrap())]).unwrap();
            let address = [domains::GLOBAL.to_vec(), entry.receipt.to_vec()].concat();
            let membership = forest.build_vertex_membership_proof(b"paid-mint", quil_forest::Phase::VertexAdds, 0, &address, &blob).unwrap();
            clock.seed_frame(GlobalFrame {
                header: Some(GlobalFrameHeader { frame_number: 9, prover_tree_commitment: root.to_vec(), ..Default::default() }),
                ..Default::default()
            });
            let claim = SettlementClaim {
                network, application: app, cited_global_frame: 9, global_root: root, receipt: entry.receipt,
                settlement: 1_000, context, payment_address: [1; 32], payment,
                claimant_key_type: 0, claimant_public_key: Vec::new(), claimant_signature: Vec::new(),
                forest_proof: quil_forest::MembershipProof { inputs: vec![membership] }.to_bytes(),
            };
            let mut bundle = rest.clone();
            bundle.requests[0] = Some(CanonicalMessageRequest::wrap(claim.encode().unwrap()).unwrap());
            (bundle.to_canonical_bytes().unwrap(), consumption_marker(&app, &entry.receipt).unwrap())
        };
        let run = |bytes: &[u8]| engine.process_message_with_context(
            FrameExecutionContext { frame_number: 10, finalized_global_frame: Some(9), venue: None, shard: quil_types::execution::ShardPath::WHOLE },
            &num_bigint::BigInt::from(0), &app, bytes);
        let disc = vertex_adds_discriminator().unwrap();
        let view = HypergraphState::new(crdt.clone());

        // No claim: the paid mint is refused outright.
        let unpaid = CanonicalMessageBundle { requests: vec![Some(mint_request.clone())], timestamp: 3 };
        let error = run(&unpaid.to_canonical_bytes().unwrap()).unwrap_err();
        assert!(error.to_string().contains("requires a settlement claim"), "{error}");
        // Underpaid (price 5 × 19 = 95): refused, and the claim's marker is rolled back.
        let (bytes, marker) = bundle_with(94, 0x61);
        let error = run(&bytes).unwrap_err();
        assert!(error.to_string().contains("below the mint price"), "{error}");
        assert!(view.get(&app, &marker, &disc).unwrap().is_none());
        // Paid in full: authorization passes and verification is reached.
        let (bytes, marker) = bundle_with(95, 0x62);
        assert!(matches!(run(&bytes), Err(QuilError::ExecutionUnavailable(_))));
        assert!(view.get(&app, &marker, &disc).unwrap().is_none());
    }

    /// Custom-token operations carry a QUIL fee: at a nonzero price a
    /// state-growing custom-token bundle or lone request without a settlement
    /// claim is refused before any proof work; at a zero price it proceeds.
    #[test]
    fn custom_token_operations_require_a_quil_settlement_at_a_nonzero_price() {
        use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        use crate::token_intrinsic::dispatch::TokenPolicy;
        use quil_types::execution::{FrameExecutionContext, ShardExecutionEngine};
        let network = [82; 32];
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()), Arc::new(NoopInclusionProver)));
        let state = HypergraphState::new(crdt.clone());
        let app = deploy(&state, MINTABLE | DIVISIBLE, TokenMintStrategy {
            mint_behavior: MINT_WITH_PAYMENT as u32, ..TokenMintStrategy::default() }, 22);
        state.commit().unwrap();
        state.abort();
        let stubs = crate::testing::NoopExecutionCrypto::new();
        let engine = crate::engines::TokenExecutionEngine::new_with_state(
            crate::engines::ExecutionMode::Application, Arc::new(NoopInclusionProver), crdt,
            stubs.key_manager, Arc::new(quil_store::testing::InMemoryClockStore::new()),
        ).with_token_proofs(TokenPolicy {
            network,
            limits: CompileLimits { max_inputs: 1, max_outputs: 2, max_depth: 1 },
            snapshots: SnapshotLimits { max_coins: 8, max_depth: 3, max_nodes: 24 },
            native_budget: NativeBudget { max_native_bytes: 0 },
        }).unwrap();
        let mint = CustomMint {
            statement: statement(network, app, (0, Vec::new()), 8, &[9, 10]),
            signature: Vec::new(), proof: placeholder_proof(),
        };
        let request = CanonicalMessageRequest::wrap(mint.encode().unwrap()).unwrap();
        let bundle = CanonicalMessageBundle { requests: vec![Some(request.clone())], timestamp: 1 }.to_canonical_bytes().unwrap();
        let lone = request.to_canonical_bytes().unwrap();
        let run = |bytes: &[u8], multiplier: u64| engine.process_message_with_context(
            FrameExecutionContext { frame_number: 10, finalized_global_frame: Some(9), venue: None, shard: quil_types::execution::ShardPath::WHOLE },
            &num_bigint::BigInt::from(multiplier), &app, bytes);
        for bytes in [&bundle, &lone] {
            let error = run(bytes, 1).unwrap_err();
            assert!(error.to_string().contains("requires a settlement claim"), "{error}");
            // Free at a zero price: the (fixture) proof is reached.
            assert!(matches!(run(bytes, 0), Err(QuilError::ExecutionUnavailable(_))));
        }
    }

    fn placeholder_proof() -> Vec<u8> {
        let mut proof = vec![0; 40];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        proof
    }

    fn statement(
        network: [u8; 32],
        application: [u8; 32],
        authority: (u32, Vec<u8>),
        nonce: u8,
        amounts: &[u128],
    ) -> CustomMintStatement {
        let context = parameter_context(&network, &application);
        let key = CommitmentKey::derive(&context);
        let opening = AmountOpening::from_seed(&context, &[nonce; 32]);
        CustomMintStatement {
            network,
            application,
            authority_key_type: authority.0,
            authority_public_key: authority.1,
            nonce: [nonce; 32],
            entitlement_proof: Vec::new(),
            amount: amounts.iter().sum(),
            outputs: amounts
                .iter()
                .enumerate()
                .map(|(i, &amount)| Output {
                    commitment: key.commit(amount, &opening),
                    owner: [10 + i as u8; IDENTITY_BYTES],
                    memo: [20 + i as u8; MEMO_BYTES],
                })
                .collect(),
        }
    }

    fn sign(mint: &mut CustomMint, signer: &dyn Signer) {
        let s = &mint.statement;
        mint.signature = signer
            .sign_with_domain(&s.context_bytes().unwrap(), &parameter_context(&s.network, &s.application))
            .unwrap();
    }

    /// A proof-basis token mints only what its configured entitlement root
    /// authorizes: the leaf binds the key and the exact amount, the key signs,
    /// and the leaf mints once. Custom tokens never mint by proof of
    /// meaningful work, and the retired verkle basis is refused.
    #[test]
    fn proof_basis_mints_require_a_signed_entitlement_and_mint_once() {
        use crate::token_intrinsic::constants::{MERKLE_ENTITLEMENT_WITH_SIGNATURE, MINT_WITH_PROOF};
        use crate::token_intrinsic::entitlement;
        let state = mem_state();
        let network = [95; 32];
        let signer = authority_signer(3);
        let authority = (quil_types::crypto::KeyType::Falcon512 as u32, signer.public_key().to_vec());
        // Two entitlements: this key for 19, another key for 5. Leaves bind
        // the network, not the token, so the tree is built before the deploy.
        let placeholder = [0x77u8; quil_crypto::FALCON_PUBLIC_KEY_LEN];
        let leaves = vec![
            entitlement::leaf(&network, authority.0, &authority.1, 19),
            entitlement::leaf(&network, authority.0, &placeholder, 5),
        ];
        let (root, proofs) = entitlement::build(&leaves).unwrap();
        let deploy_domain = |root: Vec<u8>, basis: u16, salt: u8| deploy(&state, MINTABLE | DIVISIBLE, TokenMintStrategy {
            mint_behavior: MINT_WITH_PROOF as u32,
            proof_basis: basis as u32,
            verkle_root: root,
            ..TokenMintStrategy::default() }, salt);
        let domain = deploy_domain(root.to_vec(), MERKLE_ENTITLEMENT_WITH_SIGNATURE, 33);
        let policy = load_policy(&state, &domain).unwrap();
        assert_eq!(policy.entry.entitlement_root.as_deref(), Some(root.as_slice()));

        let mint_for = |amount_parts: &[u128], proof: Vec<u8>| {
            let mut mint = CustomMint {
                statement: CustomMintStatement {
                    entitlement_proof: proof,
                    ..statement(network, domain, authority.clone(), 9, amount_parts)
                },
                signature: Vec::new(), proof: placeholder_proof(),
            };
            sign(&mut mint, &signer);
            mint
        };
        // The entitled amount, proof and signature: authorized.
        let mint = mint_for(&[9, 10], proofs[0].clone());
        assert_eq!(mint.statement.amount, 19);
        check_authorization(&mint, &policy, None).unwrap();
        // A different amount, a different leaf's proof, no proof, another
        // key's signature, or an unsigned statement: refused.
        assert!(check_authorization(&mint_for(&[9, 11], proofs[0].clone()), &policy, None).is_err());
        assert!(check_authorization(&mint_for(&[9, 10], proofs[1].clone()), &policy, None).is_err());
        assert!(check_authorization(&mint_for(&[9, 10], Vec::new()), &policy, None).is_err());
        let mut forged = mint_for(&[9, 10], proofs[0].clone());
        sign(&mut forged, &authority_signer(4));
        assert!(check_authorization(&forged, &policy, None).is_err());
        let open = CustomMint {
            statement: statement(network, domain, (0, Vec::new()), 9, &[9, 10]),
            signature: Vec::new(), proof: placeholder_proof(),
        };
        assert!(check_authorization(&open, &policy, None).is_err());

        // The leaf mints once: the commit consumes its marker alongside the
        // receipt, so a second mint of the same entitlement — even one with
        // different outputs — is refused there.
        let marker = entitlement::consumed_marker(&domain, &leaves[0]).unwrap();
        let tp = crate::token_engine::TYPE_LATTICE_MINT;
        let entry = |mint: &CustomMint, frame: u64| crate::token_intrinsic::spend_entries::commit_entry(
            &state, &network, &domain, tp, &mint.encode().unwrap(), frame).unwrap();
        let first = entry(&mint, 1);
        assert!(first.consumptions.contains(&marker));
        assert!(first.consumptions.contains(&receipt_address(&mint.statement).unwrap()));
        assert!(check_state(&state, &mint.statement).is_ok());
        assert!(matches!(
            crate::token_intrinsic::global_commit::commit_entry(&state, 1, &domain, &first, quil_types::execution::ShardPath::WHOLE).unwrap(),
            crate::token_intrinsic::global_commit::Outcome::Committed { .. }
        ));
        let other_outputs = mint_for(&[19], proofs[0].clone());
        assert_eq!(
            crate::token_intrinsic::global_commit::commit_entry(&state, 2, &domain, &entry(&other_outputs, 2),
                quil_types::execution::ShardPath::WHOLE).unwrap(),
            crate::token_intrinsic::global_commit::Outcome::Rejected("already consumed")
        );

        // Proof of meaningful work and the retired verkle basis never mint.
        for (basis, message) in [
            (crate::token_intrinsic::constants::PROOF_OF_MEANINGFUL_WORK, "proof of meaningful work"),
            (crate::token_intrinsic::constants::VERKLE_MULTIPROOF_WITH_SIGNATURE, "retired"),
        ] {
            let other = deploy_domain(root.to_vec(), basis, 40 + basis as u8);
            let error = check_authorization(&mint, &load_policy(&state, &other).unwrap(), None).unwrap_err();
            assert!(error.to_string().contains(message), "{error}");
        }
    }

    #[test]
    fn custom_mint_authorization_follows_deployed_policy() {
        let state = mem_state();
        let network = [91; 32];
        let signer = authority_signer(1);
        let other = authority_signer(2);
        let authority = (KeyType::Falcon512 as u32, signer.public_key().to_vec());
        let domain = deploy(&state, MINTABLE | DIVISIBLE,
            authority_strategy(MINT_WITH_AUTHORITY, authority.0, &authority.1), 1);
        let mut mint = CustomMint {
            statement: statement(network, domain, authority.clone(), 3, &[u128::MAX - 1, 1]),
            signature: Vec::new(),
            proof: placeholder_proof(),
        };
        sign(&mut mint, &signer);
        let policy = load_policy(&state, &domain).unwrap();
        assert_eq!(policy.entry.variant, MintVariant::Authority);
        check_authorization(&mint, &policy, None).unwrap();
        let before = state.changeset_len();
        let bytes = mint.encode().unwrap();
        // Authorization passes; the placeholder proof reaches native admission,
        // where a zero budget is local unavailability, not invalidity.
        assert!(matches!(
            verify_custom_mint(&state, &network, &domain, &bytes, 2, NativeBudget { max_native_bytes: 0 }),
            Err(QuilError::ExecutionUnavailable(_))
        ));
        assert!(matches!(
            verify_custom_mint(&state, &network, &domain, &bytes, 1, NativeBudget { max_native_bytes: 0 }),
            Err(QuilError::InvalidArgument(_))
        ));
        assert_eq!(state.changeset_len(), before);

        // Wrong signer, mismatched statement authority, wrong key type, missing
        // authority and post-signature tampering are all deterministic rejections.
        let mut wrong = mint.clone();
        sign(&mut wrong, &other);
        assert!(check_authorization(&wrong, &policy, None).is_err());
        let mut mismatched = mint.clone();
        mismatched.statement.authority_public_key = other.public_key().to_vec();
        sign(&mut mismatched, &other);
        assert!(check_authorization(&mismatched, &policy, None).is_err());
        let mut typed = mint.clone();
        typed.statement.authority_key_type = KeyType::Ed25519 as u32;
        sign(&mut typed, &signer);
        assert!(check_authorization(&typed, &policy, None).is_err());
        let permissionless = CustomMint {
            statement: statement(network, domain, (0, Vec::new()), 4, &[5]),
            signature: Vec::new(),
            proof: placeholder_proof(),
        };
        assert!(check_authorization(&permissionless, &policy, None).is_err());
        for field in 0..4 {
            let mut tampered = mint.clone();
            match field {
                0 => tampered.statement.outputs[0].memo[0] ^= 1,
                1 => tampered.statement.outputs[1].owner[0] ^= 1,
                2 => tampered.statement.nonce[0] ^= 1,
                _ => tampered.statement.amount -= 1,
            }
            assert!(check_authorization(&tampered, &policy, None).is_err());
        }
        // The signature variant shares the authority check.
        let signature_domain = deploy(&state, MINTABLE | DIVISIBLE,
            authority_strategy(MINT_WITH_SIGNATURE, authority.0, &authority.1), 2);
        let mut signed = CustomMint {
            statement: statement(network, signature_domain, authority.clone(), 5, &[7]),
            signature: Vec::new(), proof: placeholder_proof(),
        };
        sign(&mut signed, &signer);
        let signature_policy = load_policy(&state, &signature_domain).unwrap();
        assert_eq!(signature_policy.entry.variant, MintVariant::Signature);
        check_authorization(&signed, &signature_policy, None).unwrap();

        // QUIL issuance is the reward mint, never custom issuance.
        let quil = CustomMint {
            statement: statement(network, domains::QUIL_TOKEN, authority.clone(), 6, &[1]),
            signature: vec![0; 114], proof: placeholder_proof(),
        };
        assert!(matches!(
            verify_custom_mint(&state, &network, &domains::QUIL_TOKEN, &quil.encode().unwrap(), 2,
                NativeBudget { max_native_bytes: 0 }),
            Err(QuilError::InvalidArgument(_))
        ));
        // Undeployed application.
        assert!(matches!(load_policy(&state, &[77; 32]), Err(QuilError::InvalidArgument(_))));
        // Deployed but not mintable.
        let frozen = deploy(&state, DIVISIBLE, authority_strategy(MINT_WITH_AUTHORITY, authority.0, &authority.1), 3);
        let mut frozen_mint = CustomMint {
            statement: statement(network, frozen, authority.clone(), 7, &[1]),
            signature: Vec::new(), proof: placeholder_proof(),
        };
        sign(&mut frozen_mint, &signer);
        assert!(check_authorization(&frozen_mint, &load_policy(&state, &frozen).unwrap(), None).is_err());
        // Authority variant without a configured key.
        let keyless = deploy(&state, MINTABLE | DIVISIBLE, TokenMintStrategy {
            mint_behavior: MINT_WITH_AUTHORITY as u32, ..TokenMintStrategy::default() }, 4);
        assert!(check_authorization(&mint, &load_policy(&state, &keyless).unwrap(), None).is_err());

        // Free payment policy is permissionless; a signed statement is rejected.
        let free = deploy(&state, MINTABLE | DIVISIBLE, TokenMintStrategy {
            mint_behavior: MINT_WITH_PAYMENT as u32, ..TokenMintStrategy::default() }, 5);
        let free_policy = load_policy(&state, &free).unwrap();
        assert_eq!(free_policy.entry.variant, MintVariant::Payment);
        let open = CustomMint {
            statement: statement(network, free, (0, Vec::new()), 8, &[9, 10]),
            signature: Vec::new(), proof: placeholder_proof(),
        };
        check_authorization(&open, &free_policy, None).unwrap();
        let mut closed = CustomMint {
            statement: statement(network, free, authority.clone(), 9, &[9]),
            signature: Vec::new(), proof: placeholder_proof(),
        };
        sign(&mut closed, &signer);
        assert!(check_authorization(&closed, &free_policy, None).is_err());
        // Paid payment mints need an admitted payment of baseline × amount to
        // the token's payment address (5 × 19 = 95 here).
        let paid = deploy(&state, MINTABLE | DIVISIBLE, TokenMintStrategy {
            mint_behavior: MINT_WITH_PAYMENT as u32,
            payment_address: vec![1; 32],
            fee_basis: FeeBasisStruct { fee_type: PER_UNIT as u32, baseline: vec![5] }.to_canonical_bytes().unwrap(),
            ..TokenMintStrategy::default() }, 6);
        let paid_policy = load_policy(&state, &paid).unwrap();
        assert_eq!(open.statement.amount, 19);
        assert!(check_authorization(&open, &paid_policy, None).is_err());
        let allowance = PaidMintAllowance { payment_address: [1; 32], payment: 95 };
        check_authorization(&open, &paid_policy, Some(&allowance)).unwrap();
        assert!(check_authorization(&open, &paid_policy, Some(&PaidMintAllowance { payment: 94, ..allowance })).is_err());
        assert!(check_authorization(&open, &paid_policy, Some(&PaidMintAllowance { payment_address: [2; 32], ..allowance })).is_err());
        // A paid policy is still permissionless: a signed statement is refused.
        assert!(check_authorization(&closed, &paid_policy, Some(&allowance)).is_err());
        // Proof-basis and no-mint policies reject.
        let pomw = deploy(&state, MINTABLE | DIVISIBLE, TokenMintStrategy {
            mint_behavior: MINT_WITH_PROOF as u32, proof_basis: PROOF_OF_MEANINGFUL_WORK as u32,
            ..TokenMintStrategy::default() }, 7);
        assert!(check_authorization(&open, &load_policy(&state, &pomw).unwrap(), None).is_err());
        let none = deploy(&state, MINTABLE | DIVISIBLE, TokenMintStrategy::default(), 8);
        assert!(check_authorization(&open, &load_policy(&state, &none).unwrap(), None).is_err());
        // Application authority is post-quantum only: the classical curves and
        // BLS are rejected as key types, never verified.
        for classical in [KeyType::Ed448, KeyType::Ed25519, KeyType::Bls48581G1, KeyType::Bls48581G2, KeyType::Secp256k1Sha256] {
            let error = verify_authority_signature(classical as u32, &[0; 74], b"m", b"d", &[0; 114]).unwrap_err();
            assert!(error.to_string().contains("post-quantum"), "{error}");
            assert!(!super::super::signature::is_post_quantum_authority(classical as u32));
        }
        assert!(super::super::signature::is_post_quantum_authority(KeyType::Falcon512 as u32));
        // A token whose configured authority is classical cannot be deployed.
        let classical = authority_strategy(MINT_WITH_AUTHORITY, KeyType::Ed448 as u32, &[0x11; 57]);
        assert!(crate::token_intrinsic::config_resolver::StaticTokenConfigResolver::check_post_quantum_authority(&classical).is_err());
        assert!(crate::token_intrinsic::config_resolver::StaticTokenConfigResolver::check_post_quantum_authority(
            &authority_strategy(MINT_WITH_AUTHORITY, KeyType::Falcon512 as u32, signer.public_key())).is_ok());
    }

    #[test]
    fn custom_mint_stages_receipt_outputs_and_root_with_rollback_and_reopen() {
        use crate::engines::ExecutionMode;
        use crate::token_intrinsic::dispatch::TokenPolicy;
        use quil_lattice_ct::confidential::relation::backend::worker_request::{verify_amount_proof, WorkerRequest};
        let directory = tempfile::tempdir().unwrap();
        let state = disk_state(directory.path());
        let network = [92; 32];
        let signer = authority_signer(3);
        let authority = (KeyType::Falcon512 as u32, signer.public_key().to_vec());
        let domain = deploy(&state, MINTABLE | DIVISIBLE,
            authority_strategy(MINT_WITH_AUTHORITY, authority.0, &authority.1), 11);
        let context = parameter_context(&network, &domain);
        let limits = SnapshotLimits { max_coins: 8, max_depth: 3, max_nodes: 24 };
        let mut mint = CustomMint {
            statement: statement(network, domain, authority.clone(), 12, &[u128::MAX - 3, 3]),
            signature: Vec::new(),
            proof: placeholder_proof(),
        };
        sign(&mut mint, &signer);
        let bytes = mint.encode().unwrap();
        let disc = vertex_adds_discriminator().unwrap();

        // Dispatcher policy: custom issuance shares 0x0513 but selects the
        // custom decoder, application venue and zero QUIL fee.
        let policy = TokenPolicy {
            network,
            limits: CompileLimits { max_inputs: 1, max_outputs: 2, max_depth: 1 },
            snapshots: limits,
            native_budget: NativeBudget { max_native_bytes: 0 },
        };
        let tp = crate::token_engine::TYPE_LATTICE_MINT;
        policy.preflight(&domain, &bytes, tp).unwrap();
        assert!(policy.preflight(&domain, &bytes, crate::token_engine::TYPE_LATTICE_TRANSACTION).is_err());
        assert!(policy.preflight(&domains::QUIL_TOKEN, &bytes, tp).is_err());
        assert!(policy.preflight(&[93; 32], &bytes, tp).is_err());
        assert!((TokenPolicy { limits: CompileLimits { max_outputs: 1, ..policy.limits }, ..policy })
            .preflight(&domain, &bytes, tp).is_err());
        policy.check_venue(ExecutionMode::Application, &domain, tp).unwrap();
        policy.check_venue(ExecutionMode::Global, &domain, tp).unwrap();
        let saved = state.changeset_len();
        let at = |frame: u64| quil_types::execution::FrameExecutionContext {
            frame_number: frame, finalized_global_frame: frame.checked_sub(1),
            shard: quil_types::execution::ShardPath::WHOLE, venue: None,
        };
        for frame in [0, 5] {
            // Custom issuance never takes the reward mint's global path.
            assert!(matches!(
                policy.dispatch_global_mint(&state, frame, &crate::testing::NoopClockStore, &domain, &bytes, None),
                Err(QuilError::InvalidArgument(_))
            ));
            // Either commit venue verifies first: an exhausted budget is unavailability.
            assert!(matches!(
                policy.dispatch_for_commit(&state, at(frame), &crate::testing::NoopClockStore, &domain, &bytes, tp, None, None),
                Err(QuilError::ExecutionUnavailable(_))
            ));
            assert!(matches!(
                policy.dispatch_commit_inline(&state, at(frame), &crate::testing::NoopClockStore, &domain, &bytes, tp, None, None),
                Err(QuilError::ExecutionUnavailable(_))
            ));
        }
        assert_eq!(state.changeset_len(), saved);
        assert!(matches!(
            verify_amount_proof(&WorkerRequest { network, application: domain,
                limits: CompileLimits { max_inputs: 1, max_outputs: 2, max_depth: 1 },
                submission_bytes: 0, transaction: &bytes }),
            Err(native::NativeError::AllocationBudget)
        ));

        // Issuance commits through the global frame like every other
        // confidential operation. Coverage and an exhausted snapshot budget
        // roll back completely.
        let commit = |state: &HypergraphState, frame: u64, bytes: &[u8], limits| crate::token_intrinsic::commit_apply::commit_and_place(
            state, frame, &network, &domain, tp, bytes, limits);
        state.crdt().set_covered_prefix(&quil_tries::get_full_path(&domain)).unwrap();
        assert!(matches!(commit(&state, 5, &bytes, limits), Err(QuilError::ExecutionUnavailable(_))));
        state.crdt().set_covered_prefix(&[]).unwrap();
        assert!(commit(&state, 5, &bytes, SnapshotLimits { max_coins: 0, ..limits }).is_err());
        state.rollback_to(saved);
        assert_eq!(state.changeset_len(), saved);

        let placed = commit(&state, 5, &bytes, limits).unwrap();
        let root = roots::read_current(&state, &network, &domain).unwrap().unwrap();
        assert_eq!(root.coins, 2);
        assert_eq!(placed.len(), 2);
        // The receipt is consumed once, in GLOBAL, not by a marker here.
        let receipt = receipt_address(&mint.statement).unwrap();
        assert!(state.get(&domain, &receipt, &disc).unwrap().is_none());
        assert!(crate::token_intrinsic::global_commit::is_consumed(&state, &domain, &receipt).unwrap());
        for (address, output) in placed.iter().zip(&mint.statement.outputs) {
            let blob = state.get(&domain, address, &disc).unwrap().unwrap();
            let tree = quil_tries::VectorCommitmentTree { root: quil_tries::deserialize_go_tree(&blob).unwrap() };
            assert_eq!(state::read_coin(&tree, &context).unwrap().unwrap().output, *output);
        }
        // The commit refuses the replay: its receipt is consumed there.
        // Verification does not decide it — it gets as far as proof work,
        // which an exhausted budget reports as unavailable, not invalid.
        let saved = state.changeset_len();
        let error = commit(&state, 6, &bytes, limits).unwrap_err();
        assert!(error.to_string().contains("already decided"), "{error}");
        state.rollback_to(saved);
        assert!(matches!(
            policy.dispatch_for_commit(&state, at(6), &crate::testing::NoopClockStore, &domain, &bytes, tp, None, None),
            Err(QuilError::ExecutionUnavailable(_))
        ));
        assert_eq!(state.changeset_len(), saved);
        // A different nonce is a fresh issuance under the same policy.
        let mut second = CustomMint {
            statement: statement(network, domain, authority.clone(), 13, &[4]),
            signature: Vec::new(), proof: placeholder_proof(),
        };
        sign(&mut second, &signer);
        commit(&state, 6, &second.encode().unwrap(), limits).unwrap();
        let second_root = roots::read_current(&state, &network, &domain).unwrap().unwrap();
        assert_eq!(second_root.coins, 3);

        state.commit().unwrap();
        state.abort();
        state.crdt().commit(6).unwrap();
        drop(state);
        let reopened = disk_state(directory.path());
        assert_eq!(reopened.changeset_len(), 0);
        load_policy(&reopened, &domain).unwrap();
        for replay in [&mint, &second] {
            let error = crate::token_intrinsic::commit_apply::commit_and_place(
                &reopened, 7, &network, &domain, tp, &replay.encode().unwrap(), limits).unwrap_err();
            assert!(error.to_string().contains("already decided"), "{error}");
            reopened.rollback_to(0);
        }
        assert_eq!(reopened.changeset_len(), 0);
        let snapshot = state::load_committed_snapshot(&reopened, &network, &domain, limits).unwrap();
        assert_eq!(snapshot.root_at_depth(usize::from(second_root.depth)).unwrap(), second_root);
    }

    #[test]
    #[ignore = "requires native worker; complete custom mint through the dispatcher and RocksDB recovery"]
    fn complete_custom_mint_with_worker() {
        use crate::token_intrinsic::dispatch::TokenPolicy;
        use pqcrypto_ntruprime::sntrup761;
        use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
        use quil_lattice_ct::confidential::{
            address::RecipientAddress,
            memo::{create_output, open_output},
            relation::backend::worker_client::WorkerVerifier,
            relation::membership::RecipientSecret,
            transfer::TARGET_TRANSACTION_BYTES,
        };
        let started = std::time::Instant::now();
        let worker = WorkerVerifier::from_test_env(
            std::env::var("QUIL_AMOUNT_WORKER_PATH").expect("native worker path").into(),
        )
        .unwrap();
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
        let network = [94; 32];
        let signer = authority_signer(4);
        let authority = (KeyType::Falcon512 as u32, signer.public_key().to_vec());
        let domain = deploy(&state, MINTABLE | DIVISIBLE,
            authority_strategy(MINT_WITH_AUTHORITY, authority.0, &authority.1), 21);
        let context = parameter_context(&network, &domain);
        let amounts = [u128::MAX - 258, 258];
        let mut outputs = Vec::new();
        let mut openings = Vec::new();
        let mut recipients = Vec::new();
        for (i, amount) in amounts.iter().enumerate() {
            let recipient = RecipientSecret::from_seed(&context, &[30 + i as u8; 32]);
            let (public, secret) = sntrup761::keypair();
            let address = RecipientAddress::new(&context, &recipient, public.as_bytes()).unwrap();
            let created = create_output(&context, &address, *amount).unwrap();
            outputs.push(created.output);
            openings.push(created.opening);
            recipients.push((recipient, secret));
        }
        let statement = CustomMintStatement {
            network, application: domain,
            authority_key_type: authority.0, authority_public_key: authority.1.clone(),
            nonce: [22; 32], amount: u128::MAX, outputs,
            entitlement_proof: Vec::new(),
        };
        let relation = statement
            .private_relation(&[(amounts[0], &openings[0]), (amounts[1], &openings[1])], 2)
            .unwrap();
        assert!(relation.validate_local_witness());
        let proof = native::prove(&relation, budget).unwrap();
        drop(relation);
        let mut mint = CustomMint { statement, signature: Vec::new(), proof };
        sign(&mut mint, &signer);
        let bytes = mint.encode().unwrap();
        assert!(bytes.len() < TARGET_TRANSACTION_BYTES);
        if let Ok(path) = std::env::var("QUIL_TEST_TRANSACTION_PATH") {
            std::fs::write(path, &bytes).unwrap();
        }
        let limits = SnapshotLimits { max_coins: 8, max_depth: 3, max_nodes: 24 };
        let policy = TokenPolicy {
            network,
            limits: CompileLimits { max_inputs: 1, max_outputs: 2, max_depth: 1 },
            snapshots: limits, native_budget: budget,
        };
        // Missing worker is unavailability, never an in-process fallback.
        let absent = WorkerVerifier::new("/nonexistent/quil-amount-proof-worker".into(), 1, std::time::Duration::from_secs(1)).unwrap();
        assert!(matches!(
            verify_custom_mint_with_worker(&state, &network, &domain, &bytes, 2, budget, Some(&absent), None),
            Err(QuilError::ExecutionUnavailable(_))
        ));
        // Wrong network in the worker request is proof rejection.
        assert!(matches!(
            verify_custom_mint_with_worker(&state, &[95; 32], &domain, &bytes, 2, budget, Some(&worker), None),
            Err(QuilError::InvalidArgument(_))
        ));
        verify_custom_mint_with_worker(&state, &network, &domain, &bytes, 2, budget, Some(&worker), None).unwrap();
        let placed = crate::token_intrinsic::commit_apply::commit_and_place(
            &state, 5, &network, &domain, crate::token_engine::TYPE_LATTICE_MINT, &bytes, limits).unwrap();
        let placed_checkpoint = state.changeset_len();
        assert_eq!(roots::read_current(&state, &network, &domain).unwrap().unwrap().coins, 2);
        // A replay verifies as well as the first submission did — nothing a
        // shard can see decides it — and the commit is what refuses it.
        let at = |frame: u64| quil_types::execution::FrameExecutionContext {
            frame_number: frame, finalized_global_frame: Some(frame - 1),
            shard: quil_types::execution::ShardPath::WHOLE, venue: None,
        };
        policy.dispatch_for_commit(&state, at(6), &crate::testing::NoopClockStore, &domain, &bytes,
            crate::token_engine::TYPE_LATTICE_MINT, Some(&worker), None).unwrap();
        let replay = crate::token_intrinsic::commit_apply::commit_and_place(
            &state, 6, &network, &domain, crate::token_engine::TYPE_LATTICE_MINT, &bytes, limits).unwrap_err();
        assert!(replay.to_string().contains("already decided"), "{replay}");
        state.rollback_to(placed_checkpoint);
        state.commit().unwrap();
        state.abort();
        state.crdt().commit(5).unwrap();
        drop(state);
        let reopened = disk_state(directory.path());
        let disc = vertex_adds_discriminator().unwrap();
        for (i, address) in placed.iter().enumerate() {
            let blob = reopened.get(&domain, address, &disc).unwrap().unwrap();
            let tree = quil_tries::VectorCommitmentTree { root: quil_tries::deserialize_go_tree(&blob).unwrap() };
            let stored = state::read_coin(&tree, &context).unwrap().unwrap();
            let opened = open_output(&context, recipients[i].1.as_bytes(), &recipients[i].0, &stored.output).unwrap();
            assert_eq!(opened.amount, amounts[i]);
        }
        let replay = crate::token_intrinsic::commit_apply::commit_and_place(
            &reopened, 7, &network, &domain, crate::token_engine::TYPE_LATTICE_MINT, &bytes, limits).unwrap_err();
        assert!(replay.to_string().contains("already decided"), "{replay}");
        println!(
            "custom_mint_native bytes={} proof_bytes={} worker_verified=true recipients_recovered=2 seconds={:.3}",
            bytes.len(), mint.proof.len(), started.elapsed().as_secs_f64()
        );
    }
}
