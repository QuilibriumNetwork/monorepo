//! Settlement-claim admission for custom-token bundles: every node that
//! executes a priced token operation refuses it without a settlement claim
//! covering its price, whether or not it runs the token proof suite
//! (`proofWorker.disabled`). A node that skipped the claim applied a bundle
//! the other nodes refused, and left a claim it carried unconsumed.

use super::*;
use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
use crate::token_intrinsic::{
    constants::token_base_domain, dispatch::TokenPolicy, materialize, TokenConfiguration,
    TokenDeploy, TokenUpdate, TYPE_TOKEN_DEPLOY, TYPE_TOKEN_UPDATE,
};
use quil_types::crypto::NoopInclusionProver;
use quil_types::execution::{FrameExecutionContext, ShardExecutionEngine};

/// Owner signatures are not what these tests check: every one verifies.
struct AcceptingKeys;
impl quil_types::crypto::KeyManager for AcceptingKeys {
    fn validate_signature(
        &self,
        _: quil_types::crypto::KeyType,
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: &[u8],
    ) -> Result<bool> {
        Ok(true)
    }
}

fn config(name: &[u8]) -> TokenConfiguration {
    TokenConfiguration {
        behavior: 1,
        units: vec![1],
        name: name.to_vec(),
        symbol: b"PAR".to_vec(),
        owner_public_key: vec![7; 897],
        ..Default::default()
    }
}

/// A token engine over fresh state holding one deployed token, with the
/// token proof suite configured or not, and that token's domain.
fn engine(policy: bool) -> (TokenExecutionEngine, [u8; 32]) {
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_hypergraph::testing::MemStore::new()),
        Arc::new(NoopInclusionProver),
    ));
    let state = crate::hypergraph_state::HypergraphState::new(crdt.clone());
    let token = materialize::materialize_token_deploy_init(
        &state,
        &config(b"deployed"),
        1,
        &NoopInclusionProver,
    )
    .unwrap();
    state.commit().unwrap();
    state.abort();
    let engine = TokenExecutionEngine::new_with_state(
        ExecutionMode::Application,
        Arc::new(NoopInclusionProver),
        crdt,
        Arc::new(AcceptingKeys),
        Arc::new(quil_store::testing::InMemoryClockStore::new()),
    );
    let engine = if policy {
        engine
            .with_token_proofs(TokenPolicy::for_network(1))
            .unwrap()
    } else {
        engine
    };
    (engine, token)
}

/// A priced token operation: its routing domain and canonical bytes.
fn operation(type_prefix: u32, token: [u8; 32]) -> ([u8; 32], Vec<u8>) {
    match type_prefix {
        TYPE_TOKEN_DEPLOY => (
            token_base_domain(),
            TokenDeploy {
                config: config(b"new").to_canonical_bytes().unwrap(),
                rdf_schema: Vec::new(),
            }
            .to_canonical_bytes()
            .unwrap(),
        ),
        TYPE_TOKEN_UPDATE => (
            token,
            TokenUpdate {
                config: config(b"renamed").to_canonical_bytes().unwrap(),
                rdf_schema: Vec::new(),
                public_key_signature_bls48581: vec![1; 666],
            }
            .to_canonical_bytes()
            .unwrap(),
        ),
        other => panic!("no fixture for token type {other:#06x}"),
    }
}

/// Run `inner` as a one-request bundle (`lone`: a bare request) at fee
/// multiplier `multiplier`.
fn run(
    engine: &TokenExecutionEngine,
    address: &[u8; 32],
    inner: &[u8],
    lone: bool,
    multiplier: u64,
) -> Result<()> {
    let request = CanonicalMessageRequest::wrap(inner.to_vec())?;
    let message = if lone {
        request.to_canonical_bytes()?
    } else {
        CanonicalMessageBundle {
            requests: vec![Some(request)],
            timestamp: 1,
        }
        .to_canonical_bytes()?
    };
    engine
        .process_message_with_context(
            FrameExecutionContext {
                frame_number: 10,
                finalized_global_frame: Some(9),
                venue: None,
                shard: quil_types::execution::ShardPath::WHOLE,
            },
            &num_bigint::BigInt::from(multiplier),
            address,
            &message,
        )
        .map(|_| ())
}

/// The base reproducer: a node without the token suite applies `type_prefix`
/// unpaid at a nonzero price, where a node with it requires a claim.
fn reproduce(type_prefix: u32, lone: bool) {
    let (with_suite, token) = engine(true);
    let (address, inner) = operation(type_prefix, token);
    let refused = run(&with_suite, &address, &inner, lone, 1).unwrap_err();
    assert!(
        refused.to_string().contains("requires a settlement claim"),
        "harness check: a node with the token suite requires a claim: {refused}"
    );
    let (without_suite, _) = engine(false);
    let outcome = run(&without_suite, &address, &inner, lone, 1);
    assert!(
        outcome
            .as_ref()
            .is_err_and(|error| error.to_string().contains("requires a settlement claim")),
        "VULNERABLE: a node without the token suite applied an unpaid {type_prefix:#06x} \
         ({}) at fee multiplier 1 ({outcome:?}); a node with it refused the same message: \
         {refused}",
        if lone { "lone request" } else { "bundle" },
    );
}

#[test]
fn reproduces_an_unpaid_token_deploy_bundle_applied_without_the_token_suite() {
    reproduce(TYPE_TOKEN_DEPLOY, false);
}

#[test]
fn reproduces_an_unpaid_token_update_bundle_applied_without_the_token_suite() {
    reproduce(TYPE_TOKEN_UPDATE, false);
}

#[test]
fn reproduces_an_unpaid_lone_token_deploy_applied_without_the_token_suite() {
    reproduce(TYPE_TOKEN_DEPLOY, true);
}

/// The priced token operations a node runs whether or not it runs the token
/// proof suite (confidential operations need the suite).
const PRICED_UNSUITED: [u32; 2] = [TYPE_TOKEN_DEPLOY, TYPE_TOKEN_UPDATE];

/// Parity: each priced token operation, as a bundle and as a lone request,
/// gets the same verdict with and without the token suite, refused without a
/// claim at a nonzero price and applied at a zero price.
#[test]
fn priced_token_operations_get_one_verdict_with_and_without_the_token_suite() {
    for type_prefix in PRICED_UNSUITED {
        for lone in [false, true] {
            for multiplier in [1, 0] {
                let verdicts: Vec<_> = [true, false]
                    .into_iter()
                    .map(|policy| {
                        let (engine, token) = engine(policy);
                        let (address, inner) = operation(type_prefix, token);
                        run(&engine, &address, &inner, lone, multiplier).map_err(|e| e.to_string())
                    })
                    .collect();
                assert_eq!(
                    verdicts[0], verdicts[1],
                    "{type_prefix:#06x} lone={lone} multiplier={multiplier}: with the suite, \
                     then without"
                );
                assert_eq!(
                    verdicts[0].is_ok(),
                    multiplier == 0,
                    "{type_prefix:#06x} lone={lone} multiplier={multiplier}: {:?}",
                    verdicts[0]
                );
            }
        }
    }
}

/// Class guard: every live token operation type is either confidential (it
/// needs the token suite, which refuses it unpaid) or in the parity table
/// above, so a new type gets a parity row before it ships.
#[test]
fn every_live_token_type_is_in_the_settlement_parity_table() {
    let retired = [
        crate::token_engine::TYPE_TRANSACTION,
        crate::token_engine::TYPE_PENDING_TRANSACTION,
        crate::token_engine::TYPE_MINT_TRANSACTION,
    ];
    // Delivers coins a global frame already paid for; it grows no priced
    // state of its own (`settlement_claim::request_cost` is 0).
    let unpriced = [crate::token_intrinsic::constants::TYPE_COIN_DELIVERY];
    let missing: Vec<String> = (0..=u16::MAX as u32)
        .filter(|&tp| crate::token_engine::is_token_type_prefix(tp))
        .filter(|&tp| !crate::token_intrinsic::dispatch::is_confidential_type(tp))
        .filter(|tp| !retired.contains(tp) && !unpriced.contains(tp))
        .filter(|tp| !PRICED_UNSUITED.contains(tp))
        .map(|tp| format!("{tp:#06x}"))
        .collect();
    assert!(
        missing.is_empty(),
        "token types without a settlement parity row: {missing:?}"
    );
}
