//! Fee-policy matcher. Port of `node/execution/fees/matcher.go`.
//!
//! Execution engines process `MessageBundle`s — ordered lists of
//! `MessageRequest`s that may mix token transfers (fee producers) with
//! hypergraph/compute/token-admin ops (fee consumers). This module
//! captures the rules for:
//!
//! - Which message types **produce** fee outputs when their `domain`
//!   matches `Policy::producer_domain` — currently token.Transaction,
//!   token.PendingTransaction, and token.MintTransaction carry a
//!   `fees: Vec<Vec<u8>>` field of serialized BigInts.
//! - Which message types **consume** a single fee, based on the boolean
//!   toggles in `Policy`.
//!
//! Exported helpers:
//!
//! - [`collect_bundle_fees`] — flatten fee-output BigInts FIFO
//! - [`count_fee_consumers`] — count consumers under a policy
//! - [`sanity_check`] — ensure enough producers for consumers
//! - [`needs_one_fee`] — per-request boolean predicate
//! - [`pop_fee`] — pop next fee (zero on underflow, matching Go)
//! - [`default_fee_market`] — the mainnet policy used by all three app
//!   engines (token, compute, hypergraph)

use num_bigint::BigInt;
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

/// Flatten fee outputs produced by ops in the producer domain. Mirror
/// of `fees.CollectBundleFees`.
///
/// Each eligible request carries a `Vec<Vec<u8>>` of big-endian
/// BigInts. Empty slices are skipped (matches Go `if len(b) == 0 { continue }`).
pub fn collect_bundle_fees(bundle: &MessageBundle, policy: &Policy) -> Vec<BigInt> {
    let mut queue = Vec::new();

    fn push_all(queue: &mut Vec<BigInt>, raw: &[Vec<u8>]) {
        for b in raw {
            if b.is_empty() {
                continue;
            }
            queue.push(BigInt::from_bytes_be(num_bigint::Sign::Plus, b));
        }
    }

    for op in &bundle.requests {
        match &op.request {
            Some(MessageRequestInner::PendingTransaction(tx)) => {
                if tx.domain == policy.producer_domain && !tx.fees.is_empty() {
                    push_all(&mut queue, &tx.fees);
                }
            }
            Some(MessageRequestInner::Transaction(tx)) => {
                if tx.domain == policy.producer_domain && !tx.fees.is_empty() {
                    push_all(&mut queue, &tx.fees);
                }
            }
            Some(MessageRequestInner::MintTransaction(tx)) => {
                if tx.domain == policy.producer_domain && !tx.fees.is_empty() {
                    push_all(&mut queue, &tx.fees);
                }
            }
            _ => {}
        }
    }

    queue
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
        MessageRequestInner::Transaction(_) => policy.consume_tx,
        MessageRequestInner::PendingTransaction(_) => policy.consume_pending_tx,
        MessageRequestInner::MintTransaction(_) => policy.consume_mint_tx,
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
    use quil_types::proto::token as token_pb;

    fn quil_domain() -> Vec<u8> {
        domains::QUIL_TOKEN.to_vec()
    }

    fn other_domain() -> Vec<u8> {
        vec![0u8; 32]
    }

    fn bigint_bytes(n: u64) -> Vec<u8> {
        BigInt::from(n).to_bytes_be().1
    }

    fn tx_with_fees(domain: Vec<u8>, fees: Vec<Vec<u8>>) -> MessageRequest {
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::Transaction(token_pb::Transaction {
                domain,
                inputs: vec![],
                outputs: vec![],
                fees,
                range_proof: vec![],
                ..Default::default()
            })),
        }
    }

    fn pending_tx_with_fees(domain: Vec<u8>, fees: Vec<Vec<u8>>) -> MessageRequest {
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::PendingTransaction(
                token_pb::PendingTransaction {
                    domain,
                    inputs: vec![],
                    outputs: vec![],
                    fees,
                    range_proof: vec![],
                    ..Default::default()
                },
            )),
        }
    }

    fn mint_tx_with_fees(domain: Vec<u8>, fees: Vec<Vec<u8>>) -> MessageRequest {
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::MintTransaction(
                token_pb::MintTransaction {
                    domain,
                    inputs: vec![],
                    outputs: vec![],
                    fees,
                    range_proof: vec![],
                    ..Default::default()
                },
            )),
        }
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
    fn collect_fees_from_transaction_under_producer_domain() {
        let p = default_fee_market();
        let b = bundle(vec![tx_with_fees(
            quil_domain(),
            vec![bigint_bytes(5), bigint_bytes(10)],
        )]);
        let fees = collect_bundle_fees(&b, &p);
        assert_eq!(fees, vec![BigInt::from(5), BigInt::from(10)]);
    }

    #[test]
    fn collect_fees_skips_transactions_on_other_domains() {
        let p = default_fee_market();
        let b = bundle(vec![tx_with_fees(
            other_domain(),
            vec![bigint_bytes(5)],
        )]);
        let fees = collect_bundle_fees(&b, &p);
        assert!(fees.is_empty());
    }

    #[test]
    fn collect_fees_skips_empty_fee_entries() {
        let p = default_fee_market();
        let b = bundle(vec![tx_with_fees(
            quil_domain(),
            vec![bigint_bytes(5), Vec::new(), bigint_bytes(10)],
        )]);
        let fees = collect_bundle_fees(&b, &p);
        assert_eq!(fees, vec![BigInt::from(5), BigInt::from(10)]);
    }

    #[test]
    fn collect_fees_includes_pending_transaction_and_mint() {
        let p = default_fee_market();
        let b = bundle(vec![
            pending_tx_with_fees(quil_domain(), vec![bigint_bytes(1)]),
            mint_tx_with_fees(quil_domain(), vec![bigint_bytes(2)]),
            tx_with_fees(quil_domain(), vec![bigint_bytes(3)]),
        ]);
        let fees = collect_bundle_fees(&b, &p);
        assert_eq!(
            fees,
            vec![BigInt::from(1), BigInt::from(2), BigInt::from(3)]
        );
    }

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
    fn count_consumers_mixed_bundle() {
        let p = default_fee_market();
        let b = bundle(vec![
            tx_with_fees(quil_domain(), vec![bigint_bytes(5)]), // producer AND consumer under default policy
            vertex_add_request(),                                 // hypergraph consumer
            mint_tx_with_fees(quil_domain(), vec![bigint_bytes(1)]), // NOT a consumer (mint is free)
        ]);
        // Transaction + VertexAdd = 2 consumers; mint is not counted.
        assert_eq!(count_fee_consumers(&b, &p), 2);
    }

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

    #[test]
    fn needs_one_fee_mint_is_false_under_default_policy() {
        let req = mint_tx_with_fees(quil_domain(), vec![]);
        assert!(!needs_one_fee(&req, &default_fee_market()));
    }

    #[test]
    fn needs_one_fee_toggling_policy_changes_answer() {
        let req = vertex_add_request();
        let mut p = default_fee_market();
        assert!(needs_one_fee(&req, &p));
        p.consume_vertex_add = false;
        assert!(!needs_one_fee(&req, &p));
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
    // End-to-end: produce, count, sanity check, pop-each-consumer loop
    // -----------------------------------------------------------------

    #[test]
    fn end_to_end_bundle_processing_round_trip() {
        let p = default_fee_market();
        // 3 producer tx's giving 3 fee outputs, 3 consumers: vertex_add × 3.
        let b = bundle(vec![
            tx_with_fees(
                quil_domain(),
                vec![bigint_bytes(100), bigint_bytes(200)],
            ),
            tx_with_fees(quil_domain(), vec![bigint_bytes(300)]),
            vertex_add_request(),
            vertex_add_request(),
            vertex_add_request(),
        ]);
        let mut queue = collect_bundle_fees(&b, &p);
        assert_eq!(queue.len(), 3);
        let n = count_fee_consumers(&b, &p);
        // 2 transactions (producers that also consume) + 3 vertex-adds = 5
        assert_eq!(n, 5);
        // queue is 3 but consumers are 5 → sanity check MUST fail
        assert!(sanity_check(&queue, n).is_err());

        // Second bundle: 1 tx that produces 2 fees (so it covers both
        // its own consumer side AND the vertex_add), + 1 vertex_add.
        // Total: 2 consumers, 2 producer outputs → sanity_check passes.
        let b = bundle(vec![
            tx_with_fees(
                quil_domain(),
                vec![bigint_bytes(100), bigint_bytes(200)],
            ),
            vertex_add_request(),
        ]);
        let mut queue = collect_bundle_fees(&b, &p);
        let n = count_fee_consumers(&b, &p);
        assert_eq!(queue.len(), 2);
        assert_eq!(n, 2);
        assert!(sanity_check(&queue, n).is_ok());
        // Each consumer pops exactly one fee — queue ends empty.
        for _ in 0..n {
            let _ = pop_fee(&mut queue);
        }
        assert!(queue.is_empty());
    }
}
