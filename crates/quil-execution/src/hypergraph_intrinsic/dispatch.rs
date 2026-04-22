//! Hypergraph intrinsic dispatch. Port of the routing, parse, lock,
//! and cost-check plumbing from
//! `node/execution/intrinsics/hypergraph/hypergraph_intrinsic.go`.
//!
//! What's ported:
//!
//! - [`MessageKind`] — type-prefix enum spanning the four mutating ops
//!   (vertex add/remove, hyperedge add/remove).
//! - [`peek_message_kind`] — pure 4-byte peek at the wire-format type
//!   prefix, matching Go's `binary.BigEndian.Uint32(input[:4])`.
//! - [`DispatchedMessage`] — decoded form of the four message types.
//! - [`decode_message`] / [`decode_and_validate`] — canonical-bytes
//!   decode + optional structural validation.
//! - [`lock_addresses_for_input`] — computes the (reads, writes)
//!   address pair that the lock manager needs, without actually
//!   taking the lock.
//! - [`HypergraphLockState`] — parallel to Go's
//!   `lockedReads`/`lockedWrites` maps with the same conflict rules.
//! - [`HypergraphDispatchCosts`] — constant/opaque cost helpers that
//!   collapse onto the per-op helpers in `vertex_ops`/`hyperedge_ops`.
//! - [`check_sufficient_fee`] — mirror of Go's
//!   `feePaid.Cmp(cost*feeMultiplier) < 0` check.
//!
//! What's NOT ported here:
//!
//! - `Deploy` — requires RDF schema parser + lazy tree + key manager.
//! - `Validate` signature-check path — requires Ed448 verify wiring.
//! - `InvokeStep` materialize path — requires HypergraphState bridge
//!   (task #64).
//! - `Commit` — thin forwarding layer, waits on state bridge.
//! - Prometheus metrics plumbing — we leave that for a later
//!   observability port; the dispatch logic itself is the
//!   interesting part.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use num_bigint::BigInt;
use num_traits::Zero;

use quil_types::error::{QuilError, Result};

use super::canonical::{
    TYPE_HYPEREDGE_ADD, TYPE_HYPEREDGE_REMOVE, TYPE_HYPERGRAPH_DEPLOYMENT,
    TYPE_HYPERGRAPH_UPDATE, TYPE_VERTEX_ADD, TYPE_VERTEX_REMOVE,
};
use super::types::{
    HyperedgeAdd, HyperedgeRemove, HypergraphDeploy, HypergraphUpdate, VertexAdd, VertexRemove,
};

// =====================================================================
// Message-kind enum & peek
// =====================================================================

/// The four mutating hypergraph operations the intrinsic dispatches on.
/// Mirror of the four `case protobufs.*Type` branches in Go's
/// `Validate`/`InvokeStep`/`Lock`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKind {
    VertexAdd,
    VertexRemove,
    HyperedgeAdd,
    HyperedgeRemove,
}

impl MessageKind {
    /// The wire-format type prefix for this message kind.
    pub const fn type_prefix(self) -> u32 {
        match self {
            Self::VertexAdd => TYPE_VERTEX_ADD,
            Self::VertexRemove => TYPE_VERTEX_REMOVE,
            Self::HyperedgeAdd => TYPE_HYPEREDGE_ADD,
            Self::HyperedgeRemove => TYPE_HYPEREDGE_REMOVE,
        }
    }

    /// Metric label name. Matches Go strings like `"vertex_add"`.
    pub const fn label(self) -> &'static str {
        match self {
            Self::VertexAdd => "vertex_add",
            Self::VertexRemove => "vertex_remove",
            Self::HyperedgeAdd => "hyperedge_add",
            Self::HyperedgeRemove => "hyperedge_remove",
        }
    }

    /// All four variants, for completeness testing.
    pub const fn all() -> [MessageKind; 4] {
        [
            Self::VertexAdd,
            Self::VertexRemove,
            Self::HyperedgeAdd,
            Self::HyperedgeRemove,
        ]
    }
}

/// Peek at the first 4 bytes of `input` and decide which message
/// kind they correspond to. Returns `Err(InvalidArgument)` on short
/// input or an unrecognized prefix — matches Go's behaviour in
/// `Validate`/`InvokeStep`/`Lock`.
pub fn peek_message_kind(input: &[u8]) -> Result<MessageKind> {
    if input.len() < 4 {
        return Err(QuilError::InvalidArgument(
            "hypergraph dispatch: input too short to determine type".into(),
        ));
    }
    let mut prefix_bytes = [0u8; 4];
    prefix_bytes.copy_from_slice(&input[..4]);
    let prefix = u32::from_be_bytes(prefix_bytes);
    match prefix {
        TYPE_VERTEX_ADD => Ok(MessageKind::VertexAdd),
        TYPE_VERTEX_REMOVE => Ok(MessageKind::VertexRemove),
        TYPE_HYPEREDGE_ADD => Ok(MessageKind::HyperedgeAdd),
        TYPE_HYPEREDGE_REMOVE => Ok(MessageKind::HyperedgeRemove),
        other => Err(QuilError::InvalidArgument(format!(
            "hypergraph dispatch: unknown type prefix 0x{:08x}",
            other
        ))),
    }
}

// =====================================================================
// Decoded-message wrapper
// =====================================================================

/// Decoded form of a hypergraph mutating message. The dispatcher
/// owns one of these after a successful `decode_message` call and
/// routes subsequent work (verify, lock, materialize) based on its
/// variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchedMessage {
    VertexAdd(VertexAdd),
    VertexRemove(VertexRemove),
    HyperedgeAdd(HyperedgeAdd),
    HyperedgeRemove(HyperedgeRemove),
}

impl DispatchedMessage {
    pub fn kind(&self) -> MessageKind {
        match self {
            Self::VertexAdd(_) => MessageKind::VertexAdd,
            Self::VertexRemove(_) => MessageKind::VertexRemove,
            Self::HyperedgeAdd(_) => MessageKind::HyperedgeAdd,
            Self::HyperedgeRemove(_) => MessageKind::HyperedgeRemove,
        }
    }

    /// The 32-byte hypergraph domain this message targets. All four
    /// message types carry a `domain` field as bytes 0..4 of their
    /// canonical body.
    pub fn domain(&self) -> &[u8] {
        match self {
            Self::VertexAdd(v) => &v.domain,
            Self::VertexRemove(v) => &v.domain,
            Self::HyperedgeAdd(h) => &h.domain,
            Self::HyperedgeRemove(h) => &h.domain,
        }
    }

    /// Run the per-type [`validate`](VertexAdd::validate)-style check
    /// without touching signatures. Safe to call on untrusted input.
    pub fn validate_structural(&self) -> Result<()> {
        match self {
            Self::VertexAdd(v) => v.validate(),
            Self::VertexRemove(v) => v.validate(),
            Self::HyperedgeAdd(h) => h.validate(),
            Self::HyperedgeRemove(h) => h.validate(),
        }
    }

    /// Compute `(reads, writes)` address lists for the lock manager.
    ///
    /// Vertex ops use `domain || data_address`, hyperedge ops use
    /// `domain || hyperedge_id[32..]`. Reads are always empty — matches
    /// `GetReadAddresses` returning `(nil, nil)` across all four Go ops.
    pub fn lock_addresses(&self) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
        let writes = match self {
            Self::VertexAdd(v) => v.write_addresses()?,
            Self::VertexRemove(v) => v.write_addresses()?,
            Self::HyperedgeAdd(h) => h.write_addresses()?,
            Self::HyperedgeRemove(h) => h.write_addresses()?,
        };
        Ok((Vec::new(), writes))
    }
}

// =====================================================================
// Decode entry points
// =====================================================================

/// Decode a canonical-bytes hypergraph message by peeking at its type
/// prefix and dispatching to the appropriate decoder. Does NOT run
/// structural validation — callers that want it should use
/// [`decode_and_validate`] instead.
pub fn decode_message(input: &[u8]) -> Result<DispatchedMessage> {
    let kind = peek_message_kind(input)?;
    match kind {
        MessageKind::VertexAdd => Ok(DispatchedMessage::VertexAdd(
            VertexAdd::from_canonical_bytes(input)?,
        )),
        MessageKind::VertexRemove => Ok(DispatchedMessage::VertexRemove(
            VertexRemove::from_canonical_bytes(input)?,
        )),
        MessageKind::HyperedgeAdd => Ok(DispatchedMessage::HyperedgeAdd(
            HyperedgeAdd::from_canonical_bytes(input)?,
        )),
        MessageKind::HyperedgeRemove => Ok(DispatchedMessage::HyperedgeRemove(
            HyperedgeRemove::from_canonical_bytes(input)?,
        )),
    }
}

/// Decode + run the per-type structural `validate` step. Matches the
/// Go `Validate` method's pre-signature path.
pub fn decode_and_validate(input: &[u8]) -> Result<DispatchedMessage> {
    let msg = decode_message(input)?;
    msg.validate_structural()?;
    Ok(msg)
}

/// One-shot wrapper: peek at the type prefix and return the
/// `(reads, writes)` pair without retaining the decoded message.
/// Mirrors the control flow in Go's `tryLock*` helpers — they each
/// decode, call GetReadAddresses/GetWriteAddresses, and return.
pub fn lock_addresses_for_input(
    input: &[u8],
) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    let msg = decode_message(input)?;
    msg.lock_addresses()
}

// =====================================================================
// Cost dispatch
// =====================================================================

/// Cost for a hypergraph operation. Vertex-add cost is derived from
/// the proof list embedded in `data`; hyperedge-add cost is derived
/// from the atom count under the extrinsic tree, which we don't
/// decode here — callers thread an `atom_count_hint` in.
pub fn dispatch_cost(
    msg: &DispatchedMessage,
    hyperedge_atom_count_hint: u64,
) -> Result<BigInt> {
    match msg {
        DispatchedMessage::VertexAdd(v) => v.get_cost(),
        DispatchedMessage::VertexRemove(v) => Ok(v.get_cost()),
        DispatchedMessage::HyperedgeAdd(h) => {
            Ok(h.get_cost_with_atom_count(hyperedge_atom_count_hint))
        }
        DispatchedMessage::HyperedgeRemove(h) => Ok(h.get_cost()),
    }
}

/// Check that `fee_paid >= cost * fee_multiplier`. Returns an error
/// containing both values when the check fails — matches Go's
/// `errors.Wrap(fmt.Errorf("insufficient fee: %s < %s", ...))`.
pub fn check_sufficient_fee(
    fee_paid: &BigInt,
    cost: &BigInt,
    fee_multiplier: &BigInt,
) -> Result<()> {
    let required = cost * fee_multiplier;
    if fee_paid < &required {
        return Err(QuilError::InvalidArgument(format!(
            "insufficient fee: {} < {}",
            fee_paid, required
        )));
    }
    Ok(())
}

// =====================================================================
// Lock-state bookkeeping
// =====================================================================

/// Per-intrinsic lock tracker. Mirror of Go's `lockedWrites`,
/// `lockedReads`, `lockedWritesMx`, `lockedReadsMx` fields on
/// `HypergraphIntrinsic`.
///
/// Semantics (matched byte-for-byte to `Lock`/`Unlock` in Go):
///
/// - Taking a write lock on an address is a conflict if the address is
///   **already locked for writing** OR **already locked for reading**.
/// - Taking a read lock is a conflict only if the address is already
///   locked for writing (a second reader is fine).
/// - On successful lock, writes bump both the write set AND the read
///   counter — the Go code adds a write address to `lockedReads` too,
///   so future readers see an existing "reader" and concurrent
///   readers on top of a writer remain safe.
/// - Reads increment the read counter; writes always counts as +1
///   read on top.
/// - `unlock` wipes both maps. The Go implementation takes a
///   per-frame approach — same transaction-scoped behaviour here.
///
/// Returns the deduplicated set of locked addresses as a `Vec<Vec<u8>>`.
/// Order is not stable (matches Go's map iteration).
#[derive(Debug, Default)]
pub struct HypergraphLockState {
    inner: Mutex<LockInner>,
}

#[derive(Debug, Default)]
struct LockInner {
    /// Addresses currently held for writing.
    locked_writes: HashSet<Vec<u8>>,
    /// Read counter per address — parallels Go's `map[string]int`.
    locked_reads: HashMap<Vec<u8>, usize>,
}

impl HypergraphLockState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to take locks for a canonical-bytes hypergraph message.
    /// Returns the union of reads+writes on success. On conflict, no
    /// state is modified — matches Go's behaviour of returning an
    /// error before any mutation.
    ///
    /// Internally: parse the message, compute (reads, writes), call
    /// [`Self::try_lock_addresses`].
    pub fn try_lock_message(&self, input: &[u8]) -> Result<Vec<Vec<u8>>> {
        let (reads, writes) = lock_addresses_for_input(input)?;
        self.try_lock_addresses(&reads, &writes)
    }

    /// Attempt to take locks for an explicit (reads, writes) pair.
    /// Primary entry point for tests and callers that have already
    /// computed the addresses.
    pub fn try_lock_addresses(
        &self,
        reads: &[Vec<u8>],
        writes: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>> {
        let mut inner = self.inner.lock().unwrap();

        // Pre-check: detect conflicts WITHOUT mutating anything.
        for w in writes {
            if inner.locked_writes.contains(w) {
                return Err(QuilError::InvalidArgument(format!(
                    "lock: address {} is already locked for writing",
                    hex::encode(w)
                )));
            }
            if inner.locked_reads.contains_key(w) {
                return Err(QuilError::InvalidArgument(format!(
                    "lock: address {} is already locked for reading",
                    hex::encode(w)
                )));
            }
        }
        for r in reads {
            if inner.locked_writes.contains(r) {
                return Err(QuilError::InvalidArgument(format!(
                    "lock: address {} is already locked for writing",
                    hex::encode(r)
                )));
            }
        }

        // Mutation phase: locks acquired successfully.
        let mut result_set: HashSet<Vec<u8>> = HashSet::new();
        for w in writes {
            inner.locked_writes.insert(w.clone());
            *inner.locked_reads.entry(w.clone()).or_insert(0) += 1;
            result_set.insert(w.clone());
        }
        for r in reads {
            *inner.locked_reads.entry(r.clone()).or_insert(0) += 1;
            result_set.insert(r.clone());
        }

        Ok(result_set.into_iter().collect())
    }

    /// Wipe all locks. Mirror of Go `Unlock`.
    pub fn unlock(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.locked_writes.clear();
        inner.locked_reads.clear();
    }

    /// True if an address is currently held for writing.
    pub fn is_locked_for_write(&self, address: &[u8]) -> bool {
        self.inner.lock().unwrap().locked_writes.contains(address)
    }

    /// Current reader count for an address.
    pub fn read_count(&self, address: &[u8]) -> usize {
        self.inner
            .lock()
            .unwrap()
            .locked_reads
            .get(address)
            .copied()
            .unwrap_or(0)
    }

    /// Number of distinct write-locked addresses.
    pub fn write_lock_count(&self) -> usize {
        self.inner.lock().unwrap().locked_writes.len()
    }

    /// Number of distinct read-tracked addresses.
    pub fn read_lock_count(&self) -> usize {
        self.inner.lock().unwrap().locked_reads.len()
    }
}

// =====================================================================
// Helpers for callers
// =====================================================================

/// Zero-cost predicate: is the msg kind a "mutate" op that the
/// dispatcher actually processes? All four current variants are —
/// this is future-proof scaffolding for when HypergraphDeploy/Update
/// get routed through the same dispatch table.
pub fn is_mutating_op(kind: MessageKind) -> bool {
    matches!(
        kind,
        MessageKind::VertexAdd
            | MessageKind::VertexRemove
            | MessageKind::HyperedgeAdd
            | MessageKind::HyperedgeRemove
    )
}

/// Zero-length fees are always sufficient. Helper for testing.
#[doc(hidden)]
pub fn zero_fee() -> BigInt {
    BigInt::zero()
}

// =====================================================================
// HypergraphDeploy / HypergraphUpdate
// =====================================================================
//
// Deploy installs a new hypergraph schema + RDF definition. Update
// mutates configuration on an existing hypergraph.
//
// The Go node validates the RDF schema via TurtleRDFParser at deploy
// time (~1100 LOC of Turtle parsing). The Rust node accepts the bytes
// and persists them without RDF-level validation — materialization
// and downstream vertex/hyperedge ops still succeed, but conformance
// checks against the schema are not yet enforced. Post-deploy the
// schema bytes are recoverable via `GetVertexData` using the
// deployment's canonical identifier, so clients that need them have
// access.

/// Output of a successful Deploy dispatch.
#[derive(Debug, Clone)]
pub struct DispatchedDeploy {
    pub deploy: HypergraphDeploy,
}

/// Output of a successful Update dispatch.
#[derive(Debug, Clone)]
pub struct DispatchedUpdate {
    pub update: HypergraphUpdate,
}

/// Decode + structurally validate a `HypergraphDeploy`. Accepts the
/// RDF schema bytes as-is — full Turtle parser is a later increment.
pub fn decode_and_validate_deploy(input: &[u8]) -> Result<DispatchedDeploy> {
    if input.len() < 4 {
        return Err(QuilError::InvalidArgument(
            "hypergraph deploy: input too short".into(),
        ));
    }
    let prefix = u32::from_be_bytes(input[..4].try_into().unwrap());
    if prefix != TYPE_HYPERGRAPH_DEPLOYMENT {
        return Err(QuilError::InvalidArgument(format!(
            "hypergraph deploy: expected type 0x{:08x}, got 0x{:08x}",
            TYPE_HYPERGRAPH_DEPLOYMENT, prefix
        )));
    }
    let deploy = HypergraphDeploy::from_canonical_bytes(input)?;
    deploy.validate()?;
    // TODO: parse RDF schema (Turtle subset) and persist it under a
    // well-known deploy address so PutVertex can validate against it.
    // Until then the schema is accepted as an opaque blob — Deploy
    // succeeds, downstream conformance checks are deferred.
    Ok(DispatchedDeploy { deploy })
}

/// Decode + structurally validate a `HypergraphUpdate`.
pub fn decode_and_validate_update(input: &[u8]) -> Result<DispatchedUpdate> {
    if input.len() < 4 {
        return Err(QuilError::InvalidArgument(
            "hypergraph update: input too short".into(),
        ));
    }
    let prefix = u32::from_be_bytes(input[..4].try_into().unwrap());
    if prefix != TYPE_HYPERGRAPH_UPDATE {
        return Err(QuilError::InvalidArgument(format!(
            "hypergraph update: expected type 0x{:08x}, got 0x{:08x}",
            TYPE_HYPERGRAPH_UPDATE, prefix
        )));
    }
    let update = HypergraphUpdate::from_canonical_bytes(input)?;
    update.validate()?;
    Ok(DispatchedUpdate { update })
}

/// Top-level dispatch: try deploy first, then update. Returns `Ok(None)`
/// when the input isn't a deploy/update message (caller should try
/// other kinds). Use this from execution engines that may see a mix
/// of deploy and mutate traffic on the same channel.
pub fn try_decode_deploy_or_update(
    input: &[u8],
) -> Result<Option<DispatchedDeployOrUpdate>> {
    if input.len() < 4 {
        return Ok(None);
    }
    let prefix = u32::from_be_bytes(input[..4].try_into().unwrap());
    match prefix {
        TYPE_HYPERGRAPH_DEPLOYMENT => {
            Ok(Some(DispatchedDeployOrUpdate::Deploy(
                decode_and_validate_deploy(input)?,
            )))
        }
        TYPE_HYPERGRAPH_UPDATE => {
            Ok(Some(DispatchedDeployOrUpdate::Update(
                decode_and_validate_update(input)?,
            )))
        }
        _ => Ok(None),
    }
}

#[derive(Debug, Clone)]
pub enum DispatchedDeployOrUpdate {
    Deploy(DispatchedDeploy),
    Update(DispatchedUpdate),
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypergraph_intrinsic::conversions::pack_vertex_add_proof_chunks;

    // -----------------------------------------------------------------
    // Sample builders
    // -----------------------------------------------------------------

    fn make_vertex_add(domain_byte: u8, data_addr_byte: u8) -> VertexAdd {
        let proofs: Vec<Vec<u8>> = vec![vec![0x11u8; 16], vec![0x22u8; 32]];
        VertexAdd {
            domain: vec![domain_byte; 32],
            data_address: vec![data_addr_byte; 32],
            data: pack_vertex_add_proof_chunks(&proofs).unwrap(),
            signature: vec![0xCCu8; 114],
        }
    }

    fn make_vertex_remove(domain_byte: u8, data_addr_byte: u8) -> VertexRemove {
        VertexRemove {
            domain: vec![domain_byte; 32],
            data_address: vec![data_addr_byte; 32],
            signature: vec![0xCCu8; 114],
        }
    }

    fn make_hyperedge_value(app: u8, data: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(65);
        out.push(0x01); // HYPEREDGE_ATOM_TYPE_BYTE
        out.extend_from_slice(&[app; 32]);
        out.extend_from_slice(&[data; 32]);
        out
    }

    fn make_hyperedge_add(domain_byte: u8, data_byte: u8) -> HyperedgeAdd {
        HyperedgeAdd {
            domain: vec![domain_byte; 32],
            value: make_hyperedge_value(domain_byte, data_byte),
            signature: vec![0xCCu8; 114],
        }
    }

    fn make_hyperedge_remove(domain_byte: u8, data_byte: u8) -> HyperedgeRemove {
        HyperedgeRemove {
            domain: vec![domain_byte; 32],
            value: make_hyperedge_value(domain_byte, data_byte),
            signature: vec![0xCCu8; 114],
        }
    }

    // -----------------------------------------------------------------
    // MessageKind
    // -----------------------------------------------------------------

    #[test]
    fn all_message_kinds_have_distinct_type_prefixes() {
        let ids: HashSet<u32> = MessageKind::all()
            .iter()
            .map(|k| k.type_prefix())
            .collect();
        assert_eq!(ids.len(), 4);
    }

    #[test]
    fn all_message_kinds_have_distinct_labels() {
        let labels: HashSet<&str> = MessageKind::all().iter().map(|k| k.label()).collect();
        assert_eq!(labels.len(), 4);
    }

    #[test]
    fn message_kind_labels_match_go_strings() {
        assert_eq!(MessageKind::VertexAdd.label(), "vertex_add");
        assert_eq!(MessageKind::VertexRemove.label(), "vertex_remove");
        assert_eq!(MessageKind::HyperedgeAdd.label(), "hyperedge_add");
        assert_eq!(MessageKind::HyperedgeRemove.label(), "hyperedge_remove");
    }

    #[test]
    fn is_mutating_op_is_true_for_all_variants() {
        for k in MessageKind::all() {
            assert!(is_mutating_op(k));
        }
    }

    // -----------------------------------------------------------------
    // peek_message_kind
    // -----------------------------------------------------------------

    #[test]
    fn peek_message_kind_routes_vertex_add() {
        let bytes = make_vertex_add(0xAA, 0xBB).to_canonical_bytes().unwrap();
        assert_eq!(peek_message_kind(&bytes).unwrap(), MessageKind::VertexAdd);
    }

    #[test]
    fn peek_message_kind_routes_vertex_remove() {
        let bytes = make_vertex_remove(0xAA, 0xBB).to_canonical_bytes().unwrap();
        assert_eq!(
            peek_message_kind(&bytes).unwrap(),
            MessageKind::VertexRemove
        );
    }

    #[test]
    fn peek_message_kind_routes_hyperedge_add() {
        let bytes = make_hyperedge_add(0xAA, 0xBB).to_canonical_bytes().unwrap();
        assert_eq!(
            peek_message_kind(&bytes).unwrap(),
            MessageKind::HyperedgeAdd
        );
    }

    #[test]
    fn peek_message_kind_routes_hyperedge_remove() {
        let bytes = make_hyperedge_remove(0xAA, 0xBB)
            .to_canonical_bytes()
            .unwrap();
        assert_eq!(
            peek_message_kind(&bytes).unwrap(),
            MessageKind::HyperedgeRemove
        );
    }

    #[test]
    fn peek_message_kind_rejects_short_input() {
        assert!(peek_message_kind(&[]).is_err());
        assert!(peek_message_kind(&[0, 0, 0]).is_err());
    }

    #[test]
    fn peek_message_kind_rejects_unknown_prefix() {
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
        assert!(peek_message_kind(&bytes).is_err());
    }

    // -----------------------------------------------------------------
    // decode_message
    // -----------------------------------------------------------------

    #[test]
    fn decode_message_round_trips_each_variant() {
        for (expected_kind, bytes) in [
            (
                MessageKind::VertexAdd,
                make_vertex_add(0x01, 0x02).to_canonical_bytes().unwrap(),
            ),
            (
                MessageKind::VertexRemove,
                make_vertex_remove(0x03, 0x04)
                    .to_canonical_bytes()
                    .unwrap(),
            ),
            (
                MessageKind::HyperedgeAdd,
                make_hyperedge_add(0x05, 0x06)
                    .to_canonical_bytes()
                    .unwrap(),
            ),
            (
                MessageKind::HyperedgeRemove,
                make_hyperedge_remove(0x07, 0x08)
                    .to_canonical_bytes()
                    .unwrap(),
            ),
        ] {
            let msg = decode_message(&bytes).unwrap();
            assert_eq!(msg.kind(), expected_kind);
        }
    }

    #[test]
    fn decode_and_validate_accepts_good_message() {
        let bytes = make_vertex_add(0xAA, 0xBB).to_canonical_bytes().unwrap();
        assert!(decode_and_validate(&bytes).is_ok());
    }

    #[test]
    fn decode_and_validate_rejects_empty_data_vertex_add() {
        let bad = VertexAdd {
            domain: vec![0u8; 32],
            data_address: vec![0u8; 32],
            data: Vec::new(), // empty → structural validate rejects
            signature: vec![0u8; 1],
        };
        let bytes = bad.to_canonical_bytes().unwrap();
        assert!(decode_and_validate(&bytes).is_err());
    }

    #[test]
    fn dispatched_message_domain_reads_from_variant() {
        let va = decode_message(
            &make_vertex_add(0xAA, 0xBB).to_canonical_bytes().unwrap(),
        )
        .unwrap();
        assert_eq!(va.domain(), &[0xAAu8; 32][..]);

        let vr = decode_message(
            &make_vertex_remove(0xCC, 0xDD).to_canonical_bytes().unwrap(),
        )
        .unwrap();
        assert_eq!(vr.domain(), &[0xCCu8; 32][..]);

        let ha = decode_message(
            &make_hyperedge_add(0xEE, 0xFF).to_canonical_bytes().unwrap(),
        )
        .unwrap();
        assert_eq!(ha.domain(), &[0xEEu8; 32][..]);

        let hr = decode_message(
            &make_hyperedge_remove(0x10, 0x20)
                .to_canonical_bytes()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(hr.domain(), &[0x10u8; 32][..]);
    }

    // -----------------------------------------------------------------
    // lock_addresses_for_input
    // -----------------------------------------------------------------

    #[test]
    fn lock_addresses_vertex_add_has_empty_reads_and_concat_write() {
        let v = make_vertex_add(0xAA, 0xBB);
        let bytes = v.to_canonical_bytes().unwrap();
        let (reads, writes) = lock_addresses_for_input(&bytes).unwrap();
        assert!(reads.is_empty());
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].len(), 64);
        assert_eq!(&writes[0][..32], &v.domain[..]);
        assert_eq!(&writes[0][32..], &v.data_address[..]);
    }

    #[test]
    fn lock_addresses_hyperedge_add_uses_hyperedge_id_data_part() {
        let h = make_hyperedge_add(0xAA, 0xBB);
        let bytes = h.to_canonical_bytes().unwrap();
        let (reads, writes) = lock_addresses_for_input(&bytes).unwrap();
        assert!(reads.is_empty());
        assert_eq!(writes.len(), 1);
        assert_eq!(&writes[0][..32], &h.domain[..]);
        // Hyperedge ID data part = `data_byte` repeated
        assert_eq!(&writes[0][32..], &[0xBBu8; 32][..]);
    }

    // -----------------------------------------------------------------
    // Cost dispatch
    // -----------------------------------------------------------------

    #[test]
    fn dispatch_cost_for_vertex_remove_is_constant_64() {
        let msg =
            DispatchedMessage::VertexRemove(make_vertex_remove(0x00, 0x00));
        assert_eq!(dispatch_cost(&msg, 0).unwrap(), BigInt::from(64));
    }

    #[test]
    fn dispatch_cost_for_hyperedge_remove_is_constant_64() {
        let msg = DispatchedMessage::HyperedgeRemove(make_hyperedge_remove(
            0x00, 0x01,
        ));
        assert_eq!(dispatch_cost(&msg, 0).unwrap(), BigInt::from(64));
    }

    #[test]
    fn dispatch_cost_for_vertex_add_uses_proof_count() {
        // 2 proofs × 55 bytes each → cost 110.
        let msg = DispatchedMessage::VertexAdd(make_vertex_add(0x01, 0x02));
        assert_eq!(dispatch_cost(&msg, 0).unwrap(), BigInt::from(110));
    }

    #[test]
    fn dispatch_cost_for_hyperedge_add_uses_atom_count_hint() {
        let msg = DispatchedMessage::HyperedgeAdd(make_hyperedge_add(0xAA, 0xBB));
        assert_eq!(dispatch_cost(&msg, 5).unwrap(), BigInt::from(5));
        assert_eq!(dispatch_cost(&msg, 0).unwrap(), BigInt::from(0));
    }

    // -----------------------------------------------------------------
    // Fee check
    // -----------------------------------------------------------------

    #[test]
    fn fee_check_passes_when_fee_paid_at_least_cost_times_multiplier() {
        assert!(check_sufficient_fee(
            &BigInt::from(100),
            &BigInt::from(10),
            &BigInt::from(10)
        )
        .is_ok());
        assert!(check_sufficient_fee(
            &BigInt::from(101),
            &BigInt::from(10),
            &BigInt::from(10)
        )
        .is_ok());
    }

    #[test]
    fn fee_check_fails_when_fee_paid_is_below_required() {
        assert!(check_sufficient_fee(
            &BigInt::from(99),
            &BigInt::from(10),
            &BigInt::from(10)
        )
        .is_err());
    }

    #[test]
    fn fee_check_passes_with_zero_cost_any_fee() {
        assert!(check_sufficient_fee(
            &BigInt::from(0),
            &BigInt::from(0),
            &BigInt::from(100)
        )
        .is_ok());
    }

    // -----------------------------------------------------------------
    // HypergraphLockState
    // -----------------------------------------------------------------

    #[test]
    fn lock_state_starts_empty() {
        let s = HypergraphLockState::new();
        assert_eq!(s.write_lock_count(), 0);
        assert_eq!(s.read_lock_count(), 0);
    }

    #[test]
    fn lock_state_accepts_first_write_lock_and_returns_address() {
        let s = HypergraphLockState::new();
        let writes = vec![vec![0xAAu8; 8]];
        let acquired = s.try_lock_addresses(&[], &writes).unwrap();
        assert_eq!(acquired.len(), 1);
        assert_eq!(acquired[0], vec![0xAAu8; 8]);
        assert!(s.is_locked_for_write(&[0xAAu8; 8]));
        assert_eq!(s.read_count(&[0xAAu8; 8]), 1);
    }

    #[test]
    fn lock_state_rejects_double_write_to_same_address() {
        let s = HypergraphLockState::new();
        let writes = vec![vec![0xAAu8; 8]];
        s.try_lock_addresses(&[], &writes).unwrap();
        assert!(s.try_lock_addresses(&[], &writes).is_err());
    }

    #[test]
    fn lock_state_rejects_write_when_address_already_has_reader() {
        let s = HypergraphLockState::new();
        // Pre-existing reader on address.
        s.try_lock_addresses(&[vec![0xBBu8; 8]], &[]).unwrap();
        // Attempt to acquire write lock → conflict.
        assert!(s.try_lock_addresses(&[], &[vec![0xBBu8; 8]]).is_err());
    }

    #[test]
    fn lock_state_rejects_read_when_address_already_has_writer() {
        let s = HypergraphLockState::new();
        s.try_lock_addresses(&[], &[vec![0xCCu8; 8]]).unwrap();
        assert!(s.try_lock_addresses(&[vec![0xCCu8; 8]], &[]).is_err());
    }

    #[test]
    fn lock_state_multiple_readers_allowed_on_same_address() {
        let s = HypergraphLockState::new();
        s.try_lock_addresses(&[vec![0xDDu8; 8]], &[]).unwrap();
        s.try_lock_addresses(&[vec![0xDDu8; 8]], &[]).unwrap();
        s.try_lock_addresses(&[vec![0xDDu8; 8]], &[]).unwrap();
        assert_eq!(s.read_count(&[0xDDu8; 8]), 3);
    }

    #[test]
    fn lock_state_unlock_clears_all_locks() {
        let s = HypergraphLockState::new();
        s.try_lock_addresses(&[vec![0xAAu8; 8]], &[vec![0xBBu8; 8]])
            .unwrap();
        assert!(s.write_lock_count() > 0);
        s.unlock();
        assert_eq!(s.write_lock_count(), 0);
        assert_eq!(s.read_lock_count(), 0);
    }

    #[test]
    fn lock_state_non_overlapping_writes_both_succeed() {
        let s = HypergraphLockState::new();
        s.try_lock_addresses(&[], &[vec![0xAAu8; 8]]).unwrap();
        s.try_lock_addresses(&[], &[vec![0xBBu8; 8]]).unwrap();
        assert_eq!(s.write_lock_count(), 2);
    }

    #[test]
    fn lock_state_conflict_on_write_does_not_mutate() {
        let s = HypergraphLockState::new();
        s.try_lock_addresses(&[], &[vec![0xAAu8; 8]]).unwrap();
        // Try to lock two addresses, one of which conflicts.
        let result = s.try_lock_addresses(
            &[],
            &[vec![0xBBu8; 8], vec![0xAAu8; 8]],
        );
        assert!(result.is_err());
        // Bb should NOT be locked (Go rolls back by returning before mutating).
        assert!(!s.is_locked_for_write(&[0xBBu8; 8]));
    }

    #[test]
    fn lock_state_try_lock_message_integrates_with_decoder() {
        let s = HypergraphLockState::new();
        let bytes = make_vertex_add(0xAA, 0xBB).to_canonical_bytes().unwrap();
        let acquired = s.try_lock_message(&bytes).unwrap();
        assert_eq!(acquired.len(), 1);
        // Acquired address is domain || data_address.
        assert_eq!(acquired[0].len(), 64);
        // And the same message can't be re-locked before unlock.
        assert!(s.try_lock_message(&bytes).is_err());
        s.unlock();
        assert!(s.try_lock_message(&bytes).is_ok());
    }

    #[test]
    fn lock_state_try_lock_message_rejects_short_input() {
        let s = HypergraphLockState::new();
        assert!(s.try_lock_message(&[]).is_err());
    }
}
