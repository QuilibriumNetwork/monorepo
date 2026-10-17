//! Fee-policy matcher. Port of `node/execution/fees/matcher.go`.
//!
//! Execution engines process `MessageBundle`s — ordered lists of
//! `MessageRequest`s that may mix token transfers (fee producers) with
//! hypergraph/compute/token-admin ops (fee consumers). This module
//! captures the rules for:
//!
//! - Which QCT3 operations produce proof-bound QUIL fees on the producer domain.
//! - Which message types **consume** a single fee, based on the boolean
//! toggles in `Policy`.
//!
//! Exported helpers:
//!
//! - [`collect_bundle_fees`] — flatten fee-output BigInts FIFO
//! - [`count_fee_consumers`] — count consumers under a policy
//! - [`sanity_check`] — ensure enough producers for consumers
//! - [`needs_one_fee`] — per-request boolean predicate
//! - [`pop_fee`] — pop next fee (zero on underflow, matching Go)
//! - [`default_fee_market`] — the mainnet policy used by all three app
//! engines (token, compute, hypergraph)

use num_bigint::BigInt;
#[cfg(all(test, feature = "confidential-tokens"))]
use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
use num_traits::Zero;
use quil_types::error::{QuilError, Result};
use quil_types::proto::global::message_request::Request as MessageRequestInner;
use quil_types::proto::global::{MessageBundle, MessageRequest};

use crate::domains;

/// Fee policy. Mirror of `fees.Policy` at
/// `node/execution/fees/matcher.go:12`.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Domain whose tx/mint/pending PRODUCE fee outputs — typically
    /// `token.QUIL_TOKEN_ADDRESS` on mainnet. Alt fee markets vary.
    pub producer_domain: Vec<u8>,

    // Token consumers — each consumes exactly one fee, FIFO.
    pub consume_deploy: bool,
    pub consume_update: bool,
    pub consume_tx: bool,
    pub consume_pending_tx: bool,
    /// Usually false — mints execute free.
    pub consume_mint_tx: bool,

    // Compute consumers
    pub consume_compute_deploy: bool,
    pub consume_compute_update: bool,
    pub consume_code_deploy: bool,
    pub consume_code_execute: bool,
    pub consume_code_finalize: bool,

    // Hypergraph consumers
    pub consume_hypergraph_deploy: bool,
    pub consume_hypergraph_update: bool,
    pub consume_vertex_add: bool,
    pub consume_vertex_remove: bool,
    pub consume_hyperedge_add: bool,
    pub consume_hyperedge_remove: bool,
}

/// Mainnet default fee market.
///
/// Every producer (tx/pending-tx) under the QUIL token domain emits
/// fees FIFO; every app-domain write op consumes one. Mint is the
/// odd one out — it executes free.
pub fn default_fee_market() -> Policy {
    Policy {
        producer_domain: domains::QUIL_TOKEN.to_vec(),
        consume_deploy: true,
        consume_update: true,
        consume_tx: true,
        consume_pending_tx: true,
        consume_mint_tx: false,
        consume_compute_deploy: true,
        consume_compute_update: true,
        consume_code_deploy: true,
        consume_code_execute: true,
        consume_code_finalize: true,
        consume_hypergraph_deploy: true,
        consume_hypergraph_update: true,
        consume_vertex_add: true,
        consume_vertex_remove: true,
        consume_hyperedge_add: true,
        consume_hyperedge_remove: true,
    }
}

// =====================================================================
// Bundle traversal
// =====================================================================

/// Collect proof-bound QUIL outflows from structurally valid QCT3 operations.
/// Admission must independently verify the operation before accepting payment.
pub fn collect_bundle_fees(bundle: &MessageBundle, policy: &Policy) -> Vec<BigInt> {
    let mut queue = Vec::new();


    for op in &bundle.requests {
        match &op.request {
            Some(MessageRequestInner::TokenOperation(op)) => {
                if let Some(fee) = token_fee(op, policy) {
                    queue.push(fee);
                }
            }
            _ => {}
        }
    }

    queue
}

/// Proof-bound fee produced by a QCT3 operation on the producer
/// domain. The fee is read through the typed codec, so a malformed carrier
/// produces nothing rather than a guessed amount.
#[cfg(feature = "confidential-tokens")]
fn token_fee(
    op: &quil_types::proto::token::TokenOperation,
    policy: &Policy,
) -> Option<BigInt> {
    let bytes = &op.canonical_bytes;
    let domain = crate::token_intrinsic::wire::domain(bytes).ok()?;
    if domain.as_slice() != policy.producer_domain.as_slice() {
        return None;
    }
    let fee = crate::token_intrinsic::wire::fee(bytes).ok()?;
    // Mint claims transport an already-paid global authorization. Reusing its
    // recorded fee here would count the same debit in a second bundle/venue.
    if bytes[..4] == crate::token_engine::TYPE_LATTICE_MINT_CLAIM.to_be_bytes() {
        return None;
    }
    (fee > 0).then(|| BigInt::from(fee))
}

#[cfg(not(feature = "confidential-tokens"))]
fn token_fee(
    _op: &quil_types::proto::token::TokenOperation,
    _policy: &Policy,
) -> Option<BigInt> {
    None
}

/// QCT3 operations consume like their legacy counterparts: transfers
/// and shields as transactions, escrow funding/claims as pending transactions,
/// mints per the mint toggle. A mint claim spends an already-paid authorization.
fn token_consumes(
    op: &quil_types::proto::token::TokenOperation,
    policy: &Policy,
) -> bool {
    match op.canonical_bytes.get(..4).map(|prefix| u32::from_be_bytes(prefix.try_into().unwrap())) {
        Some(0x0512) | Some(0x0516) => policy.consume_tx,
        Some(0x0514) | Some(0x0515) => policy.consume_pending_tx,
        Some(0x0513) => policy.consume_mint_tx,
        _ => false,
    }
}

/// Count fee-consuming requests under `policy`. Mirror of
/// `fees.CountFeeConsumers`.
pub fn count_fee_consumers(bundle: &MessageBundle, policy: &Policy) -> usize {
    bundle
        .requests
        .iter()
        .filter(|op| needs_one_fee(op, policy))
        .count()
}

/// Assert enough fee outputs to cover consumers. Mirror of
/// `fees.SanityCheck`.
pub fn sanity_check(fee_queue: &[BigInt], consumers: usize) -> Result<()> {
    if fee_queue.len() < consumers {
        return Err(QuilError::InvalidArgument(format!(
            "sanity check: insufficient fees (have {} fee outputs, need {})",
            fee_queue.len(),
            consumers
        )));
    }
    Ok(())
}

/// Does this request consume a fee under `policy`? Mirror of
/// `fees.NeedsOneFee`. Returns `false` for:
///
/// - Prover admin ops (join/leave/pause/resume/confirm/reject/kick/update)
/// - Seniority/shard-split/shard-merge/alt-shard update
/// - Raw FrameHeader (shard proto)
/// - `None` request
pub fn needs_one_fee(request: &MessageRequest, policy: &Policy) -> bool {
    let Some(req) = &request.request else {
        return false;
    };
    match req {
        MessageRequestInner::TokenDeploy(_) => policy.consume_deploy,
        MessageRequestInner::TokenUpdate(_) => policy.consume_update,
        MessageRequestInner::ComputeDeploy(_) => policy.consume_compute_deploy,
        MessageRequestInner::ComputeUpdate(_) => policy.consume_compute_update,
        MessageRequestInner::CodeDeploy(_) => policy.consume_code_deploy,
        MessageRequestInner::CodeExecute(_) => policy.consume_code_execute,
        MessageRequestInner::CodeFinalize(_) => policy.consume_code_finalize,
        MessageRequestInner::HypergraphDeploy(_) => policy.consume_hypergraph_deploy,
        MessageRequestInner::HypergraphUpdate(_) => policy.consume_hypergraph_update,
        MessageRequestInner::VertexAdd(_) => policy.consume_vertex_add,
        MessageRequestInner::VertexRemove(_) => policy.consume_vertex_remove,
        MessageRequestInner::HyperedgeAdd(_) => policy.consume_hyperedge_add,
        MessageRequestInner::HyperedgeRemove(_) => policy.consume_hyperedge_remove,
        MessageRequestInner::TokenOperation(op) => token_consumes(op, policy),
        // All prover admin / shard / seniority ops are fee-free.
        _ => false,
    }
}

/// Pop the next fee from the queue. Zero on underflow.
pub fn pop_fee(queue: &mut Vec<BigInt>) -> BigInt {
    if queue.is_empty() {
        return BigInt::zero();
    }
    queue.remove(0)
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::proto::hypergraph as hg_pb;

    fn quil_domain() -> Vec<u8> {
        domains::QUIL_TOKEN.to_vec()
    }






    fn vertex_add_request() -> MessageRequest {
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::VertexAdd(hg_pb::VertexAdd {
                domain: vec![0u8; 32],
                data_address: vec![0u8; 32],
                data: vec![],
                signature: vec![],
            })),
        }
    }

    fn bundle(requests: Vec<MessageRequest>) -> MessageBundle {
        MessageBundle {
            requests,
            timestamp: 0,
        }
    }

    // -----------------------------------------------------------------
    // default_fee_market
    // -----------------------------------------------------------------

    #[test]
    fn default_fee_market_producer_is_quil_token_address() {
        let p = default_fee_market();
        assert_eq!(p.producer_domain, quil_domain());
    }

    #[test]
    fn default_fee_market_mint_is_free() {
        let p = default_fee_market();
        assert!(!p.consume_mint_tx);
    }

    #[test]
    fn default_fee_market_all_other_consumers_are_enabled() {
        let p = default_fee_market();
        assert!(p.consume_deploy);
        assert!(p.consume_update);
        assert!(p.consume_tx);
        assert!(p.consume_pending_tx);
        assert!(p.consume_compute_deploy);
        assert!(p.consume_compute_update);
        assert!(p.consume_code_deploy);
        assert!(p.consume_code_execute);
        assert!(p.consume_code_finalize);
        assert!(p.consume_hypergraph_deploy);
        assert!(p.consume_hypergraph_update);
        assert!(p.consume_vertex_add);
        assert!(p.consume_vertex_remove);
        assert!(p.consume_hyperedge_add);
        assert!(p.consume_hyperedge_remove);
    }

    // -----------------------------------------------------------------
    // collect_bundle_fees
    // -----------------------------------------------------------------






    #[test]
    fn collect_fees_from_hypergraph_op_is_nothing() {
        let p = default_fee_market();
        let b = bundle(vec![vertex_add_request()]);
        assert!(collect_bundle_fees(&b, &p).is_empty());
    }

    #[test]
    fn collect_fees_from_empty_bundle() {
        let p = default_fee_market();
        assert!(collect_bundle_fees(&bundle(vec![]), &p).is_empty());
    }

    // -----------------------------------------------------------------
    // count_fee_consumers
    // -----------------------------------------------------------------


    #[test]
    fn count_consumers_empty_bundle() {
        let p = default_fee_market();
        assert_eq!(count_fee_consumers(&bundle(vec![]), &p), 0);
    }

    // -----------------------------------------------------------------
    // sanity_check
    // -----------------------------------------------------------------

    #[test]
    fn sanity_check_passes_when_enough_fees() {
        let q = vec![BigInt::from(1), BigInt::from(2), BigInt::from(3)];
        assert!(sanity_check(&q, 3).is_ok());
        assert!(sanity_check(&q, 2).is_ok());
        assert!(sanity_check(&q, 0).is_ok());
    }

    #[test]
    fn sanity_check_fails_when_under_supplied() {
        let q = vec![BigInt::from(1)];
        assert!(sanity_check(&q, 2).is_err());
    }

    #[test]
    fn sanity_check_empty_queue_and_consumers_is_ok() {
        assert!(sanity_check(&[], 0).is_ok());
    }

    // -----------------------------------------------------------------
    // needs_one_fee
    // -----------------------------------------------------------------

    #[test]
    fn needs_one_fee_none_request_is_false() {
        let req = MessageRequest {
            timestamp: 0,
            request: None,
        };
        assert!(!needs_one_fee(&req, &default_fee_market()));
    }

    #[test]
    fn needs_one_fee_vertex_add_is_true_under_default_policy() {
        assert!(needs_one_fee(&vertex_add_request(), &default_fee_market()));
    }



    // -----------------------------------------------------------------
    // pop_fee
    // -----------------------------------------------------------------

    #[test]
    fn pop_fee_returns_head_and_shrinks() {
        let mut q = vec![BigInt::from(10), BigInt::from(20), BigInt::from(30)];
        assert_eq!(pop_fee(&mut q), BigInt::from(10));
        assert_eq!(q, vec![BigInt::from(20), BigInt::from(30)]);
    }

    #[test]
    fn pop_fee_underflow_returns_zero() {
        let mut q: Vec<BigInt> = vec![];
        assert_eq!(pop_fee(&mut q), BigInt::zero());
        assert!(q.is_empty());
    }

    // -----------------------------------------------------------------
    // QCT3 carriers
    // -----------------------------------------------------------------

    fn token_request(bytes: Vec<u8>) -> MessageRequest {
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::TokenOperation(
                quil_types::proto::token::TokenOperation { canonical_bytes: bytes },
            )),
        }
    }

    #[test]
    fn token_consumers_follow_legacy_toggles_by_operation() {
        let p = default_fee_market();
        let carrier = |prefix: u32| {
            let mut bytes = vec![0; 76];
            bytes[..4].copy_from_slice(&prefix.to_be_bytes());
            token_request(bytes)
        };
        assert!(needs_one_fee(&carrier(0x0512), &p));
        assert!(needs_one_fee(&carrier(0x0516), &p));
        assert!(needs_one_fee(&carrier(0x0514), &p));
        assert!(needs_one_fee(&carrier(0x0515), &p));
        assert!(!needs_one_fee(&carrier(0x0513), &p)); // mint is free by default
        assert!(!needs_one_fee(&carrier(0x0517), &p)); // claim of a paid authorization
        assert!(!needs_one_fee(&token_request(vec![0; 2]), &p));
        let mut mint_paid = default_fee_market();
        mint_paid.consume_mint_tx = true;
        assert!(needs_one_fee(&carrier(0x0513), &mint_paid));
        // Malformed carriers never produce fees.
        assert!(collect_bundle_fees(&bundle(vec![carrier(0x0512)]), &p).is_empty());
    }

    #[cfg(feature = "confidential-tokens")]
    #[test]
    fn token_transfers_produce_their_proof_bound_fee_on_the_producer_domain() {
        use quil_lattice_ct::confidential::{
            relation::membership::{Node, NODE_BYTES},
            transfer::{parameter_context, Output, Transfer, TransferStatement, MEMO_BYTES},
            AmountOpening, CommitmentKey,
        };
        let p = default_fee_market();
        let network = [1; 32];
        let mut proof = vec![0; 40];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        let transfer = |application: [u8; 32], fee: u128| {
            let context = parameter_context(&network, &application);
            let output = Output {
                commitment: CommitmentKey::derive(&context).commit(10, &AmountOpening::from_seed(&context, &[2; 32])),
                owner: [3; IDENTITY_BYTES],
                memo: [4; MEMO_BYTES],
            };
            token_request(Transfer { statement: TransferStatement { network, application, depth: 1,
                root: Node::from_bytes(&[0; NODE_BYTES]).unwrap(), images: vec![[5; IDENTITY_BYTES]], fee, outputs: vec![output] },
                proof: proof.clone() }.encode().unwrap())
        };
        let b = bundle(vec![
            transfer(domains::QUIL_TOKEN, 7),
            transfer([9; 32], 0),           // custom-token transfer: no QUIL fee
            transfer(domains::QUIL_TOKEN, 0), // zero fee produces nothing
            vertex_add_request(),
        ]);
        assert_eq!(collect_bundle_fees(&b, &p), vec![BigInt::from(7)]);
        // Three transfers consume, plus the vertex add; one fee output cannot
        // cover them, exactly as for legacy transactions.
        assert_eq!(count_fee_consumers(&b, &p), 4);
        assert!(sanity_check(&collect_bundle_fees(&b, &p), count_fee_consumers(&b, &p)).is_err());
        // A structurally valid claim carries its earlier fee for receipt
        // authentication, but cannot finance itself or another operation.
        let output = match &transfer(domains::QUIL_TOKEN, 7).request {
            Some(MessageRequestInner::TokenOperation(op)) =>
                Transfer::decode(&op.canonical_bytes, &network, &domains::QUIL_TOKEN).unwrap().statement.outputs[0].clone(),
            _ => unreachable!(),
        };
        let claim = quil_lattice_ct::confidential::mint_claim::MintClaim {
            network, application: domains::QUIL_TOKEN, cited_global_frame: 1,
            global_root: [6; 32], receipt: [7; 32], fee: 123,
            outputs: vec![output], forest_proof: vec![1],
        };
        let claim = token_request(claim.encode().unwrap());
        let claim_only = bundle(vec![claim.clone()]);
        assert!(collect_bundle_fees(&claim_only, &p).is_empty());
        assert_eq!(count_fee_consumers(&claim_only, &p), 0);
        let with_consumer = bundle(vec![claim.clone(), vertex_add_request()]);
        assert!(sanity_check(&collect_bundle_fees(&with_consumer, &p), count_fee_consumers(&with_consumer, &p)).is_err());
        let with_new_payment = bundle(vec![claim, transfer(domains::QUIL_TOKEN, 7)]);
        assert_eq!(collect_bundle_fees(&with_new_payment, &p), vec![BigInt::from(7)]);
    }

    // -----------------------------------------------------------------
    // End-to-end: produce, count, sanity check, pop-each-consumer loop
    // -----------------------------------------------------------------

}
