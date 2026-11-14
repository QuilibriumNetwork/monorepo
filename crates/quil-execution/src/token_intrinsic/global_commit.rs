//! The global commit for confidential applications.
//!
//! An executing shard verifies a confidential operation and relays a compact
//! [`SpendEntry`]; this module decides it, once, in the global frame's
//! deterministic order. A committed entry marks everything it consumes, opens
//! or closes an escrow, and gives each output its final position — the next
//! delivery sequence of the block its address selects. Nothing reaches shard
//! state until the owning shard delivers it.
//!
//! GLOBAL records (vertex trees under the global intrinsic address):
//!
//! * application context — first writer wins, so one application cannot be
//!   committed under two networks' parameters;
//! * consumed marker — its presence is the consumption;
//! * operation decision — committed or rejected, so a re-carried relay is
//!   decided exactly once;
//! * escrow — binding digest, refund frame, open or consumed;
//! * block delivery sequence — the next sequence number of a block;
//! * delivery — `(block, seq)` → the output address, its source frame and the
//!   operation, which the owning shard proves when it delivers.
use super::{
    coin_blocks, global_accumulator as records, roots,
    settlement_record::{self, SettlementEntry},
};
use crate::hypergraph_state::HypergraphState;
use quil_types::error::{QuilError, Result};
use std::collections::BTreeSet;

pub const ENTRY_VERSION: &[u8; 8] = b"QCT3SE\0\x01";
/// Consume-once markers one operation may spend.
pub const MAX_CONSUMPTIONS: usize = 16;

/// Consumptions one entry may carry at GLOBAL frame `frame`: a shield's
/// sources from the batch shield frame (one marker each), every other
/// operation's [`MAX_CONSUMPTIONS`]. Before that frame a shield is held to the
/// same limit as everything else, so earlier frames replay unchanged.
pub fn max_consumptions(kind: u32, frame: u64) -> usize {
    if kind == crate::token_engine::TYPE_LATTICE_SHIELD && frame >= batch_shield_frame() {
        quil_lattice_ct::confidential::shield::MAX_SHIELD_SOURCES
    } else {
        MAX_CONSUMPTIONS
    }
}
/// Outputs one operation may create.
pub const MAX_OUTPUTS: usize = 16;
/// Deliveries a block can ever receive: its local index space.
const BLOCK_CAPACITY: u64 = 1 << coin_blocks::SUBTREE_BITS;

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("spend entry: {message}"))
}

/// An escrow the operation creates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscrowCreate {
    pub address: [u8; 32],
    /// [`escrow_binding`] of the escrow's source commitment and policy.
    pub binding: [u8; 32],
    pub refund_after_global_frame: u64,
}

/// An escrow the operation claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscrowClaim {
    pub address: [u8; 32],
    pub binding: [u8; 32],
    /// Whether the refund branch is claimed (only at or after the refund frame).
    pub refund: bool,
}

/// What an executing shard relays for one verified confidential operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendEntry {
    /// The operation's type prefix.
    pub kind: u32,
    /// SHA3-256 of the operation's encoded bytes.
    pub tx_id: [u8; 32],
    /// The executing frame, part of every output and escrow address.
    pub source_frame: u64,
    pub context: [u8; 32],
    /// [`roots::root_digest`] of the root a membership proof was against.
    pub root_digest: Option<[u8; 32]>,
    pub consumptions: Vec<[u8; 32]>,
    pub outputs: Vec<[u8; 32]>,
    pub escrow_create: Option<EscrowCreate>,
    pub escrow_claim: Option<EscrowClaim>,
    pub fee: u128,
    /// A cross-domain settlement, recorded in GLOBAL only if this commits.
    pub settlement: Option<SettlementEntry>,
}

/// The digest binding an escrow to what a claim must present: its address,
/// source commitment and complete policy.
pub fn escrow_binding(
    context: &[u8; 32],
    address: &[u8; 32],
    source_commitment: &[u8],
    recipient: &[u8],
    refund: &[u8],
    refund_after_global_frame: u64,
) -> [u8; 32] {
    use sha3::Digest;
    let mut hash = sha3::Sha3_256::new();
    hash.update(b"quil/commit/escrow-binding/v1\0");
    hash.update(context);
    hash.update(address);
    for part in [source_commitment, recipient, refund] {
        hash.update((part.len() as u32).to_be_bytes());
        hash.update(part);
    }
    hash.update(refund_after_global_frame.to_be_bytes());
    hash.finalize().into()
}

/// The operation id: SHA3-256 of the operation's encoded bytes.
pub fn tx_id(operation: &[u8]) -> [u8; 32] {
    super::global_commit_tx_id(operation)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(invalid("truncated"));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn flag(&mut self) -> Result<bool> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid("noncanonical flag")),
        }
    }
    fn list(&mut self, max: usize) -> Result<Vec<[u8; 32]>> {
        let n = usize::from(self.take(1)?[0]);
        if n > max {
            return Err(invalid("list too long"));
        }
        (0..n).map(|_| self.array()).collect()
    }
}

impl SpendEntry {
    /// Structural bounds at GLOBAL frame `frame` (see [`max_consumptions`]).
    fn validate_at(&self, frame: u64) -> Result<()> {
        if self.consumptions.len() > max_consumptions(self.kind, frame)
            || self.outputs.len() > MAX_OUTPUTS
        {
            return Err(invalid("too many consumptions or outputs"));
        }
        if self.consumptions.iter().collect::<BTreeSet<_>>().len() != self.consumptions.len()
            || self.outputs.iter().collect::<BTreeSet<_>>().len() != self.outputs.len()
        {
            return Err(invalid("repeated consumption or output"));
        }
        if self.consumptions.is_empty() && self.escrow_claim.is_none() {
            return Err(invalid("an operation consumes something"));
        }
        if self.escrow_create.is_some() && self.escrow_claim.is_some() {
            return Err(invalid("one operation cannot create and claim an escrow"));
        }
        Ok(())
    }

    /// The executing shard encodes an entry only for an operation it admitted,
    /// which is where the batch shield frame is enforced; here only the
    /// largest bounds any frame allows apply.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate_at(u64::MAX)?;
        let mut bytes = ENTRY_VERSION.to_vec();
        bytes.extend_from_slice(&self.kind.to_be_bytes());
        bytes.extend_from_slice(&self.tx_id);
        bytes.extend_from_slice(&self.source_frame.to_be_bytes());
        bytes.extend_from_slice(&self.context);
        match &self.root_digest {
            None => bytes.push(0),
            Some(digest) => {
                bytes.push(1);
                bytes.extend_from_slice(digest);
            }
        }
        for list in [&self.consumptions, &self.outputs] {
            bytes.push(list.len() as u8);
            list.iter().for_each(|item| bytes.extend_from_slice(item));
        }
        match &self.escrow_create {
            None => bytes.push(0),
            Some(create) => {
                bytes.push(1);
                bytes.extend_from_slice(&create.address);
                bytes.extend_from_slice(&create.binding);
                bytes.extend_from_slice(&create.refund_after_global_frame.to_be_bytes());
            }
        }
        match &self.escrow_claim {
            None => bytes.push(0),
            Some(claim) => {
                bytes.push(1);
                bytes.extend_from_slice(&claim.address);
                bytes.extend_from_slice(&claim.binding);
                bytes.push(u8::from(claim.refund));
            }
        }
        bytes.extend_from_slice(&self.fee.to_be_bytes());
        match &self.settlement {
            None => bytes.push(0),
            Some(entry) => {
                bytes.push(1);
                bytes.extend_from_slice(&settlement_record::encode_entries(std::slice::from_ref(
                    entry,
                ))?);
            }
        }
        Ok(bytes)
    }

    /// An entry under the bounds of every frame before batch shields.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::decode_at(bytes, 0)
    }

    /// An entry relayed into GLOBAL frame `frame`, under that frame's bounds.
    pub fn decode_at(bytes: &[u8], frame: u64) -> Result<Self> {
        let mut r = Reader(bytes);
        if r.take(8)? != ENTRY_VERSION {
            return Err(invalid("version"));
        }
        let kind = u32::from_be_bytes(r.array()?);
        let tx_id = r.array()?;
        let source_frame = u64::from_be_bytes(r.array()?);
        let context = r.array()?;
        let root_digest = if r.flag()? { Some(r.array()?) } else { None };
        let consumptions = r.list(max_consumptions(kind, frame))?;
        let outputs = r.list(MAX_OUTPUTS)?;
        let escrow_create = if r.flag()? {
            Some(EscrowCreate {
                address: r.array()?,
                binding: r.array()?,
                refund_after_global_frame: u64::from_be_bytes(r.array()?),
            })
        } else {
            None
        };
        let escrow_claim = if r.flag()? {
            Some(EscrowClaim {
                address: r.array()?,
                binding: r.array()?,
                refund: r.flag()?,
            })
        } else {
            None
        };
        let fee = u128::from_be_bytes(r.array()?);
        let settlement = if r.flag()? {
            let mut entries =
                settlement_record::decode_entries(r.take(settlement_record::ENTRY_BYTES)?)?;
            Some(entries.pop().ok_or_else(|| invalid("empty settlement"))?)
        } else {
            None
        };
        if !r.0.is_empty() {
            return Err(invalid("trailing bytes"));
        }
        let entry = Self {
            kind,
            tx_id,
            source_frame,
            context,
            root_digest,
            consumptions,
            outputs,
            escrow_create,
            escrow_claim,
            fee,
            settlement,
        };
        entry.validate_at(frame)?;
        Ok(entry)
    }
}

/// Where a committed output was placed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placement {
    pub address: [u8; 32],
    pub block: u64,
    pub seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Decided by an earlier relay of the same operation.
    AlreadyDecided,
    Rejected(&'static str),
    Committed {
        fee: u128,
        placements: Vec<Placement>,
        /// Where a created escrow's record was queued for delivery.
        escrow: Option<Placement>,
    },
}

// ---- record addresses ------------------------------------------------------

fn context_address(application: &[u8; 32]) -> Result<[u8; 32]> {
    records::hash(&[b"quil/commit/context/v1\0", application])
}
pub fn consumed_address(application: &[u8; 32], marker: &[u8; 32]) -> Result<[u8; 32]> {
    records::hash(&[b"quil/commit/consumed/v1\0", application, marker])
}
pub fn decision_address(application: &[u8; 32], tx_id: &[u8; 32]) -> Result<[u8; 32]> {
    records::hash(&[b"quil/commit/decision/v1\0", application, tx_id])
}
pub fn escrow_address(application: &[u8; 32], escrow: &[u8; 32]) -> Result<[u8; 32]> {
    records::hash(&[b"quil/commit/escrow/v1\0", application, escrow])
}
pub fn block_sequence_address(application: &[u8; 32], block: u64) -> Result<[u8; 32]> {
    records::hash(&[
        b"quil/commit/block-sequence/v1\0",
        application,
        &block.to_be_bytes(),
    ])
}
pub fn delivery_address(application: &[u8; 32], block: u64, seq: u64) -> Result<[u8; 32]> {
    records::hash(&[
        b"quil/commit/delivery/v1\0",
        application,
        &block.to_be_bytes(),
        &seq.to_be_bytes(),
    ])
}
pub fn escrow_sequence_address(application: &[u8; 32], block: u64) -> Result<[u8; 32]> {
    records::hash(&[
        b"quil/commit/escrow-sequence/v1\0",
        application,
        &block.to_be_bytes(),
    ])
}
pub fn escrow_delivery_address(application: &[u8; 32], block: u64, seq: u64) -> Result<[u8; 32]> {
    records::hash(&[
        b"quil/commit/escrow-delivery/v1\0",
        application,
        &block.to_be_bytes(),
        &seq.to_be_bytes(),
    ])
}

pub fn placement_width_address(application: &[u8; 32]) -> Result<[u8; 32]> {
    records::hash(&[b"quil/commit/placement-width/v1\0", application])
}
pub fn orphan_address(application: &[u8; 32], block: u64) -> Result<[u8; 32]> {
    records::hash(&[
        b"quil/commit/orphan/v1\0",
        application,
        &block.to_be_bytes(),
    ])
}

const KIND_PLACEMENT_WIDTH: &str = "quil/commit/placement-width-record/v1\0";
const KIND_CONTEXT: &str = "quil/commit/context-record/v1\0";
const KIND_CONSUMED: &str = "quil/commit/consumed-record/v1\0";
const KIND_DECISION: &str = "quil/commit/decision-record/v1\0";
const KIND_ESCROW: &str = "quil/commit/escrow-record/v1\0";
const KIND_SEQUENCE: &str = "quil/commit/block-sequence-record/v1\0";
pub const KIND_DELIVERY: &str = "quil/commit/delivery-record/v1\0";
const KIND_ESCROW_SEQUENCE: &str = "quil/commit/escrow-sequence-record/v1\0";
pub const KIND_ESCROW_DELIVERY: &str = "quil/commit/escrow-delivery-record/v1\0";
const KIND_ORPHAN: &str = "quil/commit/orphan-record/v1\0";
/// A delivery record whose output was re-placed (see [`apply_orphan_attestation`]).
const KIND_DELIVERY_MOVED: &str = "quil/commit/moved-delivery-record/v1\0";
const KIND_ESCROW_DELIVERY_MOVED: &str = "quil/commit/moved-escrow-delivery-record/v1\0";

fn kind_field(tag: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    Ok((vec![0xff; 32], records::kind(tag)?.to_vec()))
}

fn read(
    state: &HypergraphState,
    address: &[u8; 32],
    tag: &str,
    keys: &[&[u8]],
) -> Result<Option<Vec<Vec<u8>>>> {
    records::read_record(state, address, &records::kind(tag)?, keys)
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| invalid("malformed record field"))
}

/// Whether the global commit has decided operation `tx_id` of `application`
/// (committed or rejected; either is final).
pub fn is_decided(
    state: &HypergraphState,
    application: &[u8; 32],
    tx_id: &[u8; 32],
) -> Result<bool> {
    Ok(read(
        state,
        &decision_address(application, tx_id)?,
        KIND_DECISION,
        &[&[0]],
    )?
    .is_some())
}

/// A consumption record's fields: the operation that consumed its marker.
fn consumed_fields(tx_id: &[u8; 32]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    Ok(vec![kind_field(KIND_CONSUMED)?, (vec![0], tx_id.to_vec())])
}

/// The blob of a consumption record, exactly as the commit stores it.
pub fn encode_consumed_record(tx_id: &[u8; 32]) -> Result<Vec<u8>> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    for (key, value) in consumed_fields(tx_id)? {
        tree.insert(&key, &value, &[], &num_bigint::BigInt::from(value.len()))?;
    }
    quil_tries::serialize_go_tree(tree.root.as_ref())
        .map_err(|_| invalid("cannot encode consumption record"))
}

/// Parse a consumption record blob as a client reads it over RPC: the
/// operation that consumed the marker.
pub fn parse_consumed_record(blob: &[u8]) -> Result<[u8; 32]> {
    let tree = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(blob)
            .map_err(|_| invalid("malformed consumption record"))?,
    };
    if tree.get(&[0xff; 32]) != Some(records::kind(KIND_CONSUMED)?.as_slice()) {
        return Err(invalid("not a consumption record"));
    }
    fixed(
        tree.get(&[0])
            .ok_or_else(|| invalid("consumption record names no operation"))?,
    )
}

/// The global commit's decision on one operation, as its GLOBAL record at
/// [`decision_address`] holds it. Either is final.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Committed { frame: u64 },
    Rejected { frame: u64, reason: String },
}

fn decision_fields(decision: &Decision) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let (committed, frame, reason) = match decision {
        Decision::Committed { frame } => (1, frame, ""),
        Decision::Rejected { frame, reason } => (0, frame, reason.as_str()),
    };
    Ok(vec![
        kind_field(KIND_DECISION)?,
        (vec![0], vec![committed]),
        (vec![4], frame.to_be_bytes().to_vec()),
        (vec![8], reason.as_bytes().to_vec()),
    ])
}

/// The blob of a decision record, exactly as the commit stores it.
pub fn encode_decision_record(decision: &Decision) -> Result<Vec<u8>> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    for (key, value) in decision_fields(decision)? {
        tree.insert(&key, &value, &[], &num_bigint::BigInt::from(value.len()))?;
    }
    quil_tries::serialize_go_tree(tree.root.as_ref())
        .map_err(|_| invalid("cannot encode decision record"))
}

/// Decode a decision record's stored bytes, as a node's vertex read of
/// [`decision_address`] returns them: `None` for an empty blob (undecided).
pub fn decode_decision(blob: &[u8]) -> Result<Option<Decision>> {
    let Some(fields) =
        records::decode_record_fields(blob, &records::kind(KIND_DECISION)?, &[&[0], &[4], &[8]])?
    else {
        return Ok(None);
    };
    let [Some(committed), Some(frame), reason] = fields.as_slice() else {
        return Err(invalid("decision record missing a field"));
    };
    let frame = u64::from_be_bytes(fixed(frame)?);
    match committed.as_slice() {
        [1] => Ok(Some(Decision::Committed { frame })),
        [0] => Ok(Some(Decision::Rejected {
            frame,
            reason: reason
                .as_deref()
                .map(|reason| String::from_utf8_lossy(reason).into_owned())
                .unwrap_or_default(),
        })),
        _ => Err(invalid("malformed decision")),
    }
}

/// Whether `marker` is consumed in `application`.
pub fn is_consumed(
    state: &HypergraphState,
    application: &[u8; 32],
    marker: &[u8; 32],
) -> Result<bool> {
    Ok(read(
        state,
        &consumed_address(application, marker)?,
        KIND_CONSUMED,
        &[&[0]],
    )?
    .is_some())
}

/// The block width new coins and escrows of `application` are placed at.
///
/// A shard reports one subtree per width layer, and it can only do that for
/// blocks it owns WHOLE: a shard deeper than a block's width owns part of the
/// block, which the accumulator cannot express. So placement is never
/// narrower than the application's deepest registered shard. The width is a
/// committed GLOBAL record, raised when a split registers deeper shards
/// ([`raise_placement_width`]); it never falls, because a block's id carries
/// its width and blocks are never re-read. Blocks created at a narrower width
/// keep their last recorded roots and receive no further coins.
pub fn placement_width(state: &HypergraphState, application: &[u8; 32]) -> Result<u8> {
    let width = match read(
        state,
        &placement_width_address(application)?,
        KIND_PLACEMENT_WIDTH,
        &[&[0]],
    )? {
        Some(fields) => match fields[0].as_slice() {
            [width] => *width,
            _ => return Err(QuilError::Store("corrupt placement width record".into())),
        },
        None => coin_blocks::INITIAL_BLOCK_BITS,
    };
    if !(coin_blocks::INITIAL_BLOCK_BITS..=coin_blocks::MAX_BLOCK_BITS).contains(&width) {
        return Err(QuilError::Store(
            "placement width record outside the accumulator's range".into(),
        ));
    }
    Ok(width)
}

/// Ensure placement is at least `shard_depth` wide. Called by the global
/// topology maintenance when a split registers shards of that depth. A depth
/// beyond the accumulator's widest block cannot be served: the split still
/// applies, and the deepest shards' reports are refused as before.
pub fn raise_placement_width(
    state: &HypergraphState,
    frame: u64,
    application: &[u8; 32],
    shard_depth: usize,
) -> Result<u8> {
    let current = placement_width(state, application)?;
    let wanted = shard_depth.min(usize::from(coin_blocks::MAX_BLOCK_BITS)) as u8;
    if wanted <= current {
        return Ok(current);
    }
    records::write_record(
        state,
        frame,
        &placement_width_address(application)?,
        &[kind_field(KIND_PLACEMENT_WIDTH)?, (vec![0], vec![wanted])],
    )?;
    tracing::info!(frame, application = %hex::encode(&application[..8]), from = current, to = wanted,
        "accumulator placement width raised");
    Ok(wanted)
}

/// Outputs and escrows the global venue has committed into blocks `shard`
/// owns, whether or not the shard has taken delivery of them.
///
/// A committed output lands in its shard only when that shard's own committee
/// executes the delivery. A split registers empty spine shards that stay latent
/// (no prover joins a shard with no data), so an output whose address falls in
/// one could never land: the shard has no committee because it has no data, and
/// it has no data because it has no committee. Counting what GLOBAL state has
/// committed TO the shard as data breaks that circle, and keeps the owner's
/// rule that a genuinely empty shard costs nobody a quorum.
pub fn committed_to_shard(
    state: &HypergraphState,
    application: &[u8; 32],
    shard: &[bool],
) -> Result<u64> {
    let width = placement_width(state, application)?;
    let owned = coin_blocks::owned_blocks(shard, width).try_fold(0u64, |total, block| {
        let here = block_sequence(state, application, block)?.saturating_add(escrow_sequence(
            state,
            application,
            block,
        )?);
        Ok::<u64, QuilError>(total.saturating_add(here))
    })?;
    // An orphan awaiting its attestation counts for the shard holding its
    // records, so that shard is staffed and can attest it.
    ancestor_blocks(shard)
        .filter(|block| holds_block_records(shard, *block))
        .try_fold(owned, |total, block| {
            let awaiting = orphan(state, application, block)?.is_some_and(|orphan| !orphan.moved);
            if !awaiting {
                return Ok(total);
            }
            let here = block_sequence(state, application, block)?.saturating_add(escrow_sequence(
                state,
                application,
                block,
            )?);
            Ok(total.saturating_add(here))
        })
}

/// The next delivery sequence of `block`: how many outputs have been committed to it.
pub fn block_sequence(state: &HypergraphState, application: &[u8; 32], block: u64) -> Result<u64> {
    match read(
        state,
        &block_sequence_address(application, block)?,
        KIND_SEQUENCE,
        &[&[0]],
    )? {
        Some(fields) => Ok(u64::from_be_bytes(fixed(&fields[0])?)),
        None => Ok(0),
    }
}

/// A committed output or escrow awaiting delivery to the shard that owns its
/// block. `source_shard` is the shard that executed the operation, which is
/// where its bytes are: on a split application that is rarely the owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub address: [u8; 32],
    pub source_frame: u64,
    pub tx_id: [u8; 32],
    pub source_shard: quil_types::execution::ShardPath,
}

/// A committed output awaiting delivery.
pub fn delivery(
    state: &HypergraphState,
    application: &[u8; 32],
    block: u64,
    seq: u64,
) -> Result<Option<Delivery>> {
    read_delivery(
        state,
        &delivery_address(application, block, seq)?,
        KIND_DELIVERY,
    )
}

/// How many escrows have been committed into `block`.
pub fn escrow_sequence(state: &HypergraphState, application: &[u8; 32], block: u64) -> Result<u64> {
    match read(
        state,
        &escrow_sequence_address(application, block)?,
        KIND_ESCROW_SEQUENCE,
        &[&[0]],
    )? {
        Some(fields) => Ok(u64::from_be_bytes(fixed(&fields[0])?)),
        None => Ok(0),
    }
}

/// A committed escrow awaiting delivery: `(address, source frame, tx id)`.
pub fn escrow_delivery(
    state: &HypergraphState,
    application: &[u8; 32],
    block: u64,
    seq: u64,
) -> Result<Option<Delivery>> {
    read_delivery(
        state,
        &escrow_delivery_address(application, block, seq)?,
        KIND_ESCROW_DELIVERY,
    )
}

fn read_delivery(
    state: &HypergraphState,
    address: &[u8; 32],
    kind: &str,
) -> Result<Option<Delivery>> {
    // A re-placed output is delivered from its new block; its old record no
    // longer names a delivery.
    let moved = if kind == KIND_DELIVERY {
        KIND_DELIVERY_MOVED
    } else {
        KIND_ESCROW_DELIVERY_MOVED
    };
    if records::record_kind(state, address)? == Some(records::kind(moved)?) {
        return Ok(None);
    }
    let Some(fields) = read(state, address, kind, &[&[0], &[4], &[8], &[12]])? else {
        return Ok(None);
    };
    Ok(Some(Delivery {
        address: fixed(&fields[0])?,
        source_frame: u64::from_be_bytes(fixed(&fields[1])?),
        tx_id: fixed(&fields[2])?,
        source_shard: quil_types::execution::ShardPath::from_bytes(&fields[3])
            .ok_or_else(|| invalid("malformed executing shard"))?,
    }))
}

/// Parse an escrow record blob as a client reads it over RPC:
/// `(binding, refund frame, consumed)`.
pub fn parse_escrow_record(blob: &[u8]) -> Result<([u8; 32], u64, bool)> {
    let tree = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(blob)
            .map_err(|_| invalid("malformed escrow record"))?,
    };
    if tree.get(&[0xff; 32]) != Some(records::kind(KIND_ESCROW)?.as_slice()) {
        return Err(invalid("not an escrow record"));
    }
    let field = |key: u8| {
        tree.get(&[key])
            .ok_or_else(|| invalid("escrow record missing a field"))
    };
    let consumed = match field(8)? {
        [0] => false,
        [1] => true,
        _ => return Err(invalid("malformed escrow record")),
    };
    Ok((
        fixed(field(0)?)?,
        u64::from_be_bytes(fixed(field(4)?)?),
        consumed,
    ))
}

/// An escrow's GLOBAL record: `(binding, refund frame, consumed)`.
pub fn escrow(
    state: &HypergraphState,
    application: &[u8; 32],
    escrow: &[u8; 32],
) -> Result<Option<([u8; 32], u64, bool)>> {
    let Some(fields) = read(
        state,
        &escrow_address(application, escrow)?,
        KIND_ESCROW,
        &[&[0], &[4], &[8]],
    )?
    else {
        return Ok(None);
    };
    Ok(Some((
        fixed(&fields[0])?,
        u64::from_be_bytes(fixed(&fields[1])?),
        fields[2] == [1],
    )))
}

// ---- outputs orphaned by a split ----------------------------------------

// The GLOBAL frame from which a split re-places the undelivered outputs of a
// block it leaves without a whole owner. Consensus-affecting for GLOBAL and
// for every application shard's report, which switch together. Off (never)
// unless `QUIL_ORPHAN_REPLACE_FRAME` names a frame; on mainnet it is
// [`MAINNET_RELEASE_ACTIVATION_FRAME`].
#[cfg(test)]
thread_local! {
    static TEST_ORPHAN_REPLACEMENT_FRAME: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Set the re-placement frame for the calling test's thread.
#[cfg(test)]
pub(crate) fn set_orphan_replacement_frame_for_test(frame: Option<u64>) {
    TEST_ORPHAN_REPLACEMENT_FRAME.with(|cell| cell.set(frame));
}

/// This release's activation frame on mainnet: the first frame after 832,777,
/// where every archive stopped on the previous build.
/// Orphan re-placement, relay records and storage pre-registration all switch
/// on here.
pub const MAINNET_RELEASE_ACTIVATION_FRAME: u64 = 832_778;

static ORPHAN_REPLACEMENT_FRAME: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// The release activation frame for `network`: fixed on mainnet, where no
/// setting may move it; `QUIL_ORPHAN_REPLACE_FRAME` elsewhere, never by default.
fn release_activation_frame(network: u8, setting: Option<&str>) -> u64 {
    if network == 0 {
        return MAINNET_RELEASE_ACTIVATION_FRAME;
    }
    setting
        .and_then(|value| value.parse().ok())
        .unwrap_or(u64::MAX)
}

/// Fix this process's re-placement frame from its network, and return it.
/// Called at startup before any frame is processed; the first call decides.
pub fn init_orphan_replacement_frame(network: u8) -> u64 {
    *ORPHAN_REPLACEMENT_FRAME.get_or_init(|| {
        release_activation_frame(
            network,
            std::env::var("QUIL_ORPHAN_REPLACE_FRAME").ok().as_deref(),
        )
    })
}

pub fn orphan_replacement_frame() -> u64 {
    #[cfg(test)]
    if let Some(frame) = TEST_ORPHAN_REPLACEMENT_FRAME.with(|cell| cell.get()) {
        return frame;
    }
    *ORPHAN_REPLACEMENT_FRAME.get_or_init(|| {
        std::env::var("QUIL_ORPHAN_REPLACE_FRAME")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(u64::MAX)
    })
}

// ---- batch shields -----------------------------------------------------------

/// Batch shields (shield encoding version 3, up to
/// `MAX_SHIELD_SOURCES` legacy coins), their larger spend entries, and the
/// check that every shield source lies in the executing shard's range, from
/// this GLOBAL frame: the first-session boundary (owner, 2026-10-06; see
/// `BATCH_SHIELD.md`). Consensus-affecting for application shards and GLOBAL,
/// which switch together. Fixed on mainnet; `QUIL_BATCH_SHIELD_FRAME`
/// elsewhere, never by default.
pub const MAINNET_BATCH_SHIELD_FRAME: u64 = 864_000;

static BATCH_SHIELD_FRAME: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

thread_local! {
    static BATCH_SHIELD_OVERRIDE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

fn batch_shield_frame_for(network: u8, setting: Option<&str>) -> u64 {
    if network == 0 {
        return MAINNET_BATCH_SHIELD_FRAME;
    }
    setting
        .and_then(|value| value.parse().ok())
        .unwrap_or(u64::MAX)
}

/// Fix this process's batch shield frame from its network, and return it.
/// Called at startup before any frame is processed; the first call decides.
pub fn init_batch_shield_frame(network: u8) -> u64 {
    *BATCH_SHIELD_FRAME.get_or_init(|| {
        batch_shield_frame_for(
            network,
            std::env::var("QUIL_BATCH_SHIELD_FRAME").ok().as_deref(),
        )
    })
}

pub fn batch_shield_frame() -> u64 {
    if let Some(frame) = BATCH_SHIELD_OVERRIDE.with(|cell| cell.get()) {
        return frame;
    }
    *BATCH_SHIELD_FRAME.get_or_init(|| {
        std::env::var("QUIL_BATCH_SHIELD_FRAME")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(u64::MAX)
    })
}

/// Set the batch shield frame for the calling thread only (tests).
pub fn set_batch_shield_frame_for_thread(frame: Option<u64>) {
    BATCH_SHIELD_OVERRIDE.with(|cell| cell.set(frame));
}

/// Whether batch shields are active for an operation whose frame is anchored
/// at GLOBAL frame `anchor` (none known: not active).
pub fn batch_shields_active(anchor: Option<u64>) -> bool {
    anchor.is_some_and(|frame| frame >= batch_shield_frame())
}

// ---- canonical owners -------------------------------------------------------

/// From this GLOBAL frame an executing shard, and GLOBAL executing an
/// application itself, refuse a confidential operation naming an owner that
/// is not a canonical identity (`spend_entries::operation_owners`). Before
/// it only a globally executed application refuses one
/// (`spend_entries::check_coin_owners`), as its fold always did; a split
/// application's executing shard relays it, GLOBAL commits it, and the
/// shard owning its block burns the coin when it places it
/// (`coin_tree::committed_leaf`). Honest wallets never make one.
///
/// Consensus-affecting for application shards and GLOBAL, which switch
/// together: a build without it relays and commits what one with it
/// refuses, so every archive and prover must run a build with it before the
/// frame; honest operations are the same on every build. Mainnet 1,063,440,
/// the first frame of epoch 1477, which GLOBAL cannot reach before
/// 2026-11-11 14:00 UTC even at ten seconds a frame: the release carrying it
/// reaches nearly every worker within a day and every archive within hours,
/// and it is the one flag day this release's other GLOBAL gates share.
/// `QUIL_CANONICAL_OWNER_FRAME` elsewhere, never by default.
pub const MAINNET_CANONICAL_OWNER_FRAME: Option<u64> = Some(1_063_440);

static CANONICAL_OWNER_FRAME: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

thread_local! {
    static CANONICAL_OWNER_OVERRIDE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

fn canonical_owner_frame_for(network: u8, setting: Option<&str>) -> u64 {
    if network == 0 {
        return MAINNET_CANONICAL_OWNER_FRAME.unwrap_or(u64::MAX);
    }
    setting
        .and_then(|value| value.parse().ok())
        .unwrap_or(u64::MAX)
}

/// Fix this process's canonical owner frame from its network, and return
/// it. Called at startup before any frame is processed; the first call
/// decides.
pub fn init_canonical_owner_frame(network: u8) -> u64 {
    *CANONICAL_OWNER_FRAME.get_or_init(|| {
        canonical_owner_frame_for(
            network,
            std::env::var("QUIL_CANONICAL_OWNER_FRAME").ok().as_deref(),
        )
    })
}

/// The frame fixed by [`init_canonical_owner_frame`]; the mainnet frame in a
/// process that never called it, so the setting cannot reach mainnet.
/// `u64::MAX`: never.
pub fn canonical_owner_frame() -> u64 {
    if let Some(frame) = CANONICAL_OWNER_OVERRIDE.with(|cell| cell.get()) {
        return frame;
    }
    *CANONICAL_OWNER_FRAME.get_or_init(|| canonical_owner_frame_for(0, None))
}

/// Set the canonical owner frame for the calling thread only (tests).
/// `Some(u64::MAX)` disables it; `None` restores the process setting.
pub fn set_canonical_owner_frame_for_thread(frame: Option<u64>) {
    CANONICAL_OWNER_OVERRIDE.with(|cell| cell.set(frame));
}

/// Whether owners must be canonical for an operation whose frame is
/// anchored at GLOBAL frame `anchor` (none known: not yet).
pub fn canonical_owners_active(anchor: Option<u64>) -> bool {
    anchor.is_some_and(|frame| frame >= canonical_owner_frame())
}

// ---- relay records across the upgrade from the mainnet build ---------------

/// The GLOBAL frame from which application shards relay this release's
/// per-frame records (fee total, settlements, spends, accumulator report).
/// A shard frame anchored below it is relay-free: the mainnet build that made
/// it writes none of these records, so no member could otherwise vote the
/// first frame after the upgrade.
///
/// Consensus-affecting for application shards and GLOBAL, which switch
/// together. On mainnet it is the release's activation frame
/// ([`MAINNET_RELEASE_ACTIVATION_FRAME`]) and no setting moves it; elsewhere
/// `QUIL_RELAY_ACTIVATION_FRAME` names it, and it is zero (always relaying)
/// by default. Fixed per process by [`init_relay_activation_frame`] before
/// any shard engine runs.
static RELAY_ACTIVATION_FRAME: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

thread_local! {
    static RELAY_ACTIVATION_OVERRIDE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Fix the relay activation frame for this process from its network, and
/// return it. The first call decides; a later one returns that value.
pub fn init_relay_activation_frame(network: u8) -> u64 {
    *RELAY_ACTIVATION_FRAME.get_or_init(|| {
        relay_activation_for(
            network,
            std::env::var("QUIL_RELAY_ACTIVATION_FRAME").ok().as_deref(),
        )
    })
}

fn relay_activation_for(network: u8, setting: Option<&str>) -> u64 {
    if network == 0 {
        return MAINNET_RELEASE_ACTIVATION_FRAME;
    }
    setting.and_then(|value| value.parse().ok()).unwrap_or(0)
}

pub fn relay_activation_frame() -> u64 {
    if let Some(frame) = RELAY_ACTIVATION_OVERRIDE.with(|cell| cell.get()) {
        return frame;
    }
    *RELAY_ACTIVATION_FRAME.get_or_init(|| {
        std::env::var("QUIL_RELAY_ACTIVATION_FRAME")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0)
    })
}

/// Set the relay activation frame for the calling thread only (tests).
pub fn set_relay_activation_frame_for_thread(frame: Option<u64>) {
    RELAY_ACTIVATION_OVERRIDE.with(|cell| cell.set(frame));
}

/// A block whose region was split deeper than its width while outputs
/// committed to it were undelivered. Nothing can deliver them there: a shard
/// deeper than the block owns only part of it. The shard holding the block's
/// own records attests how many it holds, and the rest move to the blocks
/// their addresses select at the current width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Orphan {
    /// The frame that found it orphaned.
    pub since: u64,
    pub moved: bool,
    /// Attested coins and escrows the block holds (zero until moved).
    pub coins: u64,
    pub escrows: u64,
}

pub fn orphan(
    state: &HypergraphState,
    application: &[u8; 32],
    block: u64,
) -> Result<Option<Orphan>> {
    let Some(fields) = read(
        state,
        &orphan_address(application, block)?,
        KIND_ORPHAN,
        &[&[0], &[4], &[8], &[12]],
    )?
    else {
        return Ok(None);
    };
    Ok(Some(Orphan {
        since: u64::from_be_bytes(fixed(&fields[0])?),
        moved: match fields[1].as_slice() {
            [0] => false,
            [1] => true,
            _ => return Err(invalid("malformed orphan record")),
        },
        coins: u64::from_be_bytes(fixed(&fields[2])?),
        escrows: u64::from_be_bytes(fixed(&fields[3])?),
    }))
}

fn write_orphan(
    state: &HypergraphState,
    frame: u64,
    application: &[u8; 32],
    block: u64,
    orphan: &Orphan,
) -> Result<()> {
    records::write_record(
        state,
        frame,
        &orphan_address(application, block)?,
        &[
            kind_field(KIND_ORPHAN)?,
            (vec![0], orphan.since.to_be_bytes().to_vec()),
            (vec![4], vec![u8::from(orphan.moved)]),
            (vec![8], orphan.coins.to_be_bytes().to_vec()),
            (vec![12], orphan.escrows.to_be_bytes().to_vec()),
        ],
    )
}

fn path_value(bits: &[bool]) -> u64 {
    bits.iter()
        .fold(0u64, |acc, bit| (acc << 1) | u64::from(*bit))
}

/// The blocks on `shard`'s own path narrower than the shard: the only blocks a
/// split can leave without a whole owner beneath it.
fn ancestor_blocks(shard: &[bool]) -> impl Iterator<Item = u64> + '_ {
    let top = shard
        .len()
        .min(usize::from(coin_blocks::MAX_BLOCK_BITS) + 1);
    (usize::from(coin_blocks::INITIAL_BLOCK_BITS)..top).filter_map(move |width| {
        coin_blocks::block_id(width as u8, path_value(&shard[..width])).ok()
    })
}

/// Whether `shard` holds `block`'s own records (its frontier and escrow
/// count, at `state::block_record_address`): the one shard that can attest
/// what the block received.
pub fn holds_block_records(shard: &[bool], block: u64) -> bool {
    let address = super::state::block_record_address(super::state::BLOCK_FRONTIER_TAG, block);
    shard.len() <= 256
        && shard
            .iter()
            .enumerate()
            .all(|(bit, want)| (address[bit / 8] >> (7 - bit % 8)) & 1 == u8::from(*want))
}

/// Reconcile orphan records with the registered shards of `application`
/// after a topology change. A block on the path of a `registered` or
/// `removed` shard is orphaned when no registered shard owns it whole and
/// outputs were committed to it; an awaiting orphan that a merge made whole
/// again is released, and its owner delivers it as before. Returns
/// `(marked, released)`.
pub fn reconcile_orphans(
    state: &HypergraphState,
    frame: u64,
    application: &[u8; 32],
    registered: &[Vec<bool>],
    removed: &[Vec<bool>],
) -> Result<(usize, usize)> {
    let mut candidates = BTreeSet::new();
    for shard in registered.iter().chain(removed) {
        candidates.extend(ancestor_blocks(shard));
    }
    let (mut marked, mut released) = (0, 0);
    for block in candidates {
        let owned = registered
            .iter()
            .any(|shard| coin_blocks::shard_owns_block(shard, block));
        match orphan(state, application, block)? {
            Some(existing) if owned && !existing.moved => {
                records::clear_record(state, frame, &orphan_address(application, block)?)?;
                released += 1;
            }
            Some(_) => {}
            None if owned => {}
            None => {
                if block_sequence(state, application, block)?
                    + escrow_sequence(state, application, block)?
                    > 0
                {
                    write_orphan(
                        state,
                        frame,
                        application,
                        block,
                        &Orphan {
                            since: frame,
                            moved: false,
                            coins: 0,
                            escrows: 0,
                        },
                    )?;
                    marked += 1;
                }
            }
        }
    }
    if marked + released > 0 {
        tracing::info!(frame, application = %hex::encode(&application[..8]), marked, released,
            "orphaned coin blocks reconciled with the shard grid");
    }
    Ok((marked, released))
}

/// Apply an orphaned block's attested `(coins, escrows)`: every output
/// committed to it beyond what it holds moves to the block its address
/// selects at the current placement width, with a fresh delivery record there,
/// and its old record is marked moved. Returns whether anything was applied.
///
/// The counts come from the shard holding the block's records, which never
/// owns the block, so in its lineage they are final. An output that was in
/// fact delivered there cannot be delivered again: its address is its
/// identity, and a shard refuses a coin that is already present.
pub fn apply_orphan_attestation(
    state: &HypergraphState,
    frame: u64,
    application: &[u8; 32],
    block: u64,
    coins: u64,
    escrows: u64,
) -> Result<bool> {
    let Some(existing) = orphan(state, application, block)? else {
        return Ok(false);
    };
    if existing.moved {
        if (existing.coins, existing.escrows) != (coins, escrows) {
            return Err(invalid("an orphaned block attested with different counts"));
        }
        return Ok(false);
    }
    let (committed, committed_escrows) = (
        block_sequence(state, application, block)?,
        escrow_sequence(state, application, block)?,
    );
    if coins > committed || escrows > committed_escrows {
        return Err(invalid(
            "an orphaned block attested more than was committed to it",
        ));
    }
    let width = placement_width(state, application)?;
    let mut sequences: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
    let mut escrow_sequences: std::collections::BTreeMap<u64, u64> =
        std::collections::BTreeMap::new();
    for escrow in [false, true] {
        let (from, to) = if escrow {
            (escrows, committed_escrows)
        } else {
            (coins, committed)
        };
        for seq in from..to {
            let old = if escrow {
                escrow_delivery_address(application, block, seq)?
            } else {
                delivery_address(application, block, seq)?
            };
            let record = if escrow {
                escrow_delivery(state, application, block, seq)?
            } else {
                delivery(state, application, block, seq)?
            }
            .ok_or_else(|| invalid("an orphaned block is missing a committed delivery"))?;
            let target = coin_blocks::block_for_address(width, &record.address)?;
            let next = if escrow {
                match escrow_sequences.get(&target) {
                    Some(next) => *next,
                    None => escrow_sequence(state, application, target)?,
                }
            } else {
                match sequences.get(&target) {
                    Some(next) => *next,
                    None => block_sequence(state, application, target)?,
                }
            };
            if next >= BLOCK_CAPACITY {
                return Err(invalid("block is full"));
            }
            let (new, delivery_kind, moved_kind) = if escrow {
                escrow_sequences.insert(target, next + 1);
                (
                    escrow_delivery_address(application, target, next)?,
                    KIND_ESCROW_DELIVERY,
                    KIND_ESCROW_DELIVERY_MOVED,
                )
            } else {
                sequences.insert(target, next + 1);
                (
                    delivery_address(application, target, next)?,
                    KIND_DELIVERY,
                    KIND_DELIVERY_MOVED,
                )
            };
            records::write_record(
                state,
                frame,
                &new,
                &[
                    kind_field(delivery_kind)?,
                    (vec![0], record.address.to_vec()),
                    (vec![4], record.source_frame.to_be_bytes().to_vec()),
                    (vec![8], record.tx_id.to_vec()),
                    (vec![12], record.source_shard.to_bytes().to_vec()),
                ],
            )?;
            records::write_record(
                state,
                frame,
                &old,
                &[
                    kind_field(moved_kind)?,
                    (vec![0], record.address.to_vec()),
                    (vec![4], target.to_be_bytes().to_vec()),
                    (vec![8], next.to_be_bytes().to_vec()),
                ],
            )?;
        }
    }
    // The orphaned block ends at what it holds, so nothing more is ever
    // offered from it, even to an owner a later merge recreates.
    if coins < committed {
        sequences.insert(block, coins);
    }
    if escrows < committed_escrows {
        escrow_sequences.insert(block, escrows);
    }
    for (target, next) in &sequences {
        records::write_record(
            state,
            frame,
            &block_sequence_address(application, *target)?,
            &[
                kind_field(KIND_SEQUENCE)?,
                (vec![0], next.to_be_bytes().to_vec()),
            ],
        )?;
    }
    for (target, next) in &escrow_sequences {
        records::write_record(
            state,
            frame,
            &escrow_sequence_address(application, *target)?,
            &[
                kind_field(KIND_ESCROW_SEQUENCE)?,
                (vec![0], next.to_be_bytes().to_vec()),
            ],
        )?;
    }
    write_orphan(
        state,
        frame,
        application,
        block,
        &Orphan {
            since: existing.since,
            moved: true,
            coins,
            escrows,
        },
    )?;
    tracing::info!(frame, application = %hex::encode(&application[..8]), block,
        moved = (committed - coins) + (committed_escrows - escrows), coins, escrows, width,
        "orphaned coin block re-placed at the current width");
    Ok(true)
}

/// One refusal [`commit_entry`] makes from GLOBAL state alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// No later GLOBAL frame lifts it: a consumed marker, a claimed escrow,
    /// a binding its escrow never had. The commit can only reject.
    Lasting(&'static str),
    /// A later GLOBAL frame may lift it: a root or an escrow the state does
    /// not hold yet, as a view behind GLOBAL does not.
    Pending(&'static str),
}

impl Standing {
    /// The reason the commit records for it.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Lasting(reason) | Self::Pending(reason) => reason,
        }
    }
}

/// What an operation needs of GLOBAL state to commit, as its spend entry
/// carries it ([`super::spend_entries::commit_needs`] reads it from the
/// operation's bytes, verifying nothing).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommitNeeds {
    pub context: [u8; 32],
    pub root_digest: Option<[u8; 32]>,
    pub consumptions: Vec<[u8; 32]>,
    pub escrow_claim: Option<EscrowClaim>,
}

/// [`commit_entry`]'s refusals that read GLOBAL state only, in its order,
/// each handed to `visit` until it breaks. At `frame`, the committing
/// GLOBAL frame, a refund is held to its escrow's refund frame; ahead of the
/// commit (`None`) that is not judged: a later frame lifts it.
#[allow(clippy::too_many_arguments)]
fn state_refusals(
    state: &HypergraphState,
    application: &[u8; 32],
    context: &[u8; 32],
    root_digest: Option<&[u8; 32]>,
    consumptions: &[[u8; 32]],
    escrow_claim: Option<&EscrowClaim>,
    frame: Option<u64>,
    visit: &mut dyn FnMut(Standing) -> std::ops::ControlFlow<()>,
) -> Result<()> {
    if let Some(digest) = root_digest {
        let retained = match records::read_root_history(state, application)? {
            Some(history) => roots::history_retains_digest(&history, context, digest)?,
            None => false,
        };
        if !retained
            && visit(Standing::Pending(
                "root is not in the application's canonical history",
            ))
            .is_break()
        {
            return Ok(());
        }
    }
    for marker in consumptions {
        if is_consumed(state, application, marker)?
            && visit(Standing::Lasting("already consumed")).is_break()
        {
            return Ok(());
        }
    }
    if let Some(claim) = escrow_claim {
        let standing = match escrow(state, application, &claim.address)? {
            None => Some(Standing::Pending("escrow does not exist")),
            Some((_, _, true)) => Some(Standing::Lasting("escrow already consumed")),
            Some((binding, _, _)) if binding != claim.binding => {
                Some(Standing::Lasting("claim does not match the escrow"))
            }
            Some((_, refund_after, _))
                if claim.refund && frame.is_some_and(|frame| frame < refund_after) =>
            {
                Some(Standing::Pending("refund before the escrow's refund frame"))
            }
            Some(_) => None,
        };
        if let Some(standing) = standing {
            let _ = visit(standing);
        }
    }
    Ok(())
}

/// What the global commit would make of an operation needing `needs`, read
/// ahead of it from `state`: `None` when no state check refuses it, else the
/// first lasting refusal, or the first pending one when none is lasting.
/// Nothing is pending on a view holding no root history of the application
/// or of the QUIL token: it follows no GLOBAL state (or not yet), so it
/// cannot tell a root or an escrow GLOBAL never published from one it has.
pub fn precheck(
    state: &HypergraphState,
    application: &[u8; 32],
    needs: &CommitNeeds,
) -> Result<Option<Standing>> {
    let mut found = None;
    state_refusals(
        state,
        application,
        &needs.context,
        needs.root_digest.as_ref(),
        &needs.consumptions,
        needs.escrow_claim.as_ref(),
        None,
        &mut |standing| match standing {
            Standing::Lasting(_) => {
                found = Some(standing);
                std::ops::ControlFlow::Break(())
            }
            Standing::Pending(_) => {
                found.get_or_insert(standing);
                std::ops::ControlFlow::Continue(())
            }
        },
    )?;
    if matches!(found, Some(Standing::Pending(_)))
        && records::read_root_history(state, application)?.is_none()
        && records::read_root_history(state, &crate::domains::QUIL_TOKEN)?.is_none()
    {
        return Ok(None);
    }
    Ok(found)
}

/// Whether `entry` creates an escrow GLOBAL state already holds.
fn escrow_taken(
    state: &HypergraphState,
    application: &[u8; 32],
    entry: &SpendEntry,
) -> Result<bool> {
    match &entry.escrow_create {
        Some(create) => Ok(escrow(state, application, &create.address)?.is_some()),
        None => Ok(false),
    }
}

/// Next delivery sequence per block, of the blocks [`place_outputs`] fills.
type Sequences = std::collections::BTreeMap<u64, u64>;

/// Where `outputs` land at placement `width`: each output's block and
/// sequence, and each block's next sequence after them; `None` when one of
/// their blocks is full.
fn place_outputs(
    state: &HypergraphState,
    application: &[u8; 32],
    width: u8,
    outputs: &[[u8; 32]],
) -> Result<Option<(Vec<Placement>, Sequences)>> {
    let mut placements = Vec::with_capacity(outputs.len());
    let mut sequences = Sequences::new();
    for address in outputs {
        let block = coin_blocks::block_for_address(width, address)?;
        let next = match sequences.get(&block) {
            Some(next) => *next,
            None => block_sequence(state, application, block)?,
        };
        if next >= BLOCK_CAPACITY {
            return Ok(None);
        }
        sequences.insert(block, next + 1);
        placements.push(Placement {
            address: *address,
            block,
            seq: next,
        });
    }
    Ok(Some((placements, sequences)))
}

/// Why [`commit_entry`] would refuse `entry` at GLOBAL frame `frame` (as
/// executed by `source_shard`), read from `state` without writing anything:
/// its first refusal, in its order (decided already, context, the state
/// checks [`precheck`] also makes, the escrow it creates, a full block), or
/// `None` when it would commit. The global venue reads it before verifying
/// the operation's proof, at the frame that commits it.
pub fn refusal(
    state: &HypergraphState,
    frame: u64,
    application: &[u8; 32],
    entry: &SpendEntry,
    source_shard: quil_types::execution::ShardPath,
) -> Result<Option<&'static str>> {
    entry.validate_at(frame)?;
    let decision = decision_address(application, &entry.tx_id)?;
    if read(state, &decision, KIND_DECISION, &[&[0]])?.is_some() {
        return Ok(Some("operation already decided"));
    }
    if let Some(fields) = read(state, &context_address(application)?, KIND_CONTEXT, &[&[0]])? {
        if fields[0] != entry.context {
            return Ok(Some("context differs from the application's"));
        }
    }
    let mut refused = None;
    state_refusals(
        state,
        application,
        &entry.context,
        entry.root_digest.as_ref(),
        &entry.consumptions,
        entry.escrow_claim.as_ref(),
        Some(frame),
        &mut |standing| {
            refused = Some(standing.reason());
            std::ops::ControlFlow::Break(())
        },
    )?;
    if refused.is_some() {
        return Ok(refused);
    }
    if escrow_taken(state, application, entry)? {
        return Ok(Some("escrow already exists"));
    }
    // The width the commit raises placement to, unwritten.
    let depth = source_shard.bits().map_or(0, |bits| bits.len());
    let width = placement_width(state, application)?
        .max(depth.min(usize::from(coin_blocks::MAX_BLOCK_BITS)) as u8);
    Ok(place_outputs(state, application, width, &entry.outputs)?
        .is_none()
        .then_some("block is full"))
}

/// `source` with the whitespace after each opening parenthesis dropped, so
/// a call rustfmt wraps onto several lines reads like one it does not; for
/// the class guards that read this crate's source.
#[cfg(test)]
pub(crate) fn guard_source(source: &str) -> String {
    let mut out = String::new();
    let mut open = false;
    for c in source.chars() {
        if open && c.is_whitespace() {
            continue;
        }
        open = c == '(';
        out.push(c);
    }
    out
}

/// The text of function `head` (`pub fn name`, say) in `source`, from its
/// name to its closing brace; for the class guards.
#[cfg(test)]
pub(crate) fn guard_body<'a>(source: &'a str, head: &str) -> &'a str {
    let start = source
        .find(&format!("\n{head}("))
        .unwrap_or_else(|| panic!("{head} not found"));
    let rest = &source[start + 1..];
    &rest[..rest.find("\n}\n").expect("end of the function")]
}

/// The calls in `text` whose error `?` returns (`name(..)?`, the receiver's
/// name for `name(..).map_err(..)?`), by their path as written (`read`,
/// `shield::check_sources`, a method's own name); for the class guards.
#[cfg(test)]
pub(crate) fn guard_fallible_calls(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    // The name of the call whose closing parenthesis is at `close`.
    let call = |close: usize| -> Option<(String, usize)> {
        let mut depth = 0usize;
        let mut at = close;
        loop {
            match bytes[at] {
                b')' => depth += 1,
                b'(' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            at = at.checked_sub(1)?;
        }
        let end = at;
        while at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || b"_:".contains(&bytes[at - 1])) {
            at -= 1;
        }
        (at < end).then(|| (text[at..end].to_string(), at))
    };
    let mut calls = Vec::new();
    for (at, _) in text.match_indices(")?") {
        let Some((mut name, mut start)) = call(at) else {
            continue;
        };
        while name == "map_err" {
            let mut before = start.saturating_sub(1);
            while before > 0 && bytes[before].is_ascii_whitespace() {
                before -= 1;
            }
            // `.map_err` after a call: name that call.
            if bytes[before] != b'.' {
                break;
            }
            before -= 1;
            while before > 0 && bytes[before].is_ascii_whitespace() {
                before -= 1;
            }
            if bytes[before] != b')' {
                break;
            }
            match call(before) {
                Some(receiver) => (name, start) = receiver,
                None => break,
            }
        }
        calls.push(name);
    }
    calls
}

/// Decide one relayed entry for `application` at global frame `frame`.
pub fn commit_entry(
    state: &HypergraphState,
    frame: u64,
    application: &[u8; 32],
    entry: &SpendEntry,
    source_shard: quil_types::execution::ShardPath,
) -> Result<Outcome> {
    entry.validate_at(frame)?;
    let decision = decision_address(application, &entry.tx_id)?;
    if read(state, &decision, KIND_DECISION, &[&[0]])?.is_some() {
        return Ok(Outcome::AlreadyDecided);
    }
    let reject = |reason: &'static str| -> Result<Outcome> {
        records::write_record(
            state,
            frame,
            &decision,
            &decision_fields(&Decision::Rejected {
                frame,
                reason: reason.into(),
            })?,
        )?;
        Ok(Outcome::Rejected(reason))
    };

    // One application, one network's parameters.
    match read(state, &context_address(application)?, KIND_CONTEXT, &[&[0]])? {
        Some(fields) if fields[0] != entry.context => {
            return reject("context differs from the application's")
        }
        Some(_) => {}
        None => records::write_record(
            state,
            frame,
            &context_address(application)?,
            &[kind_field(KIND_CONTEXT)?, (vec![0], entry.context.to_vec())],
        )?,
    }

    // The first of the state checks a node also makes ahead of the commit
    // ([`precheck`]), in the same order, so the two cannot diverge.
    let mut refused = None;
    state_refusals(
        state,
        application,
        &entry.context,
        entry.root_digest.as_ref(),
        &entry.consumptions,
        entry.escrow_claim.as_ref(),
        Some(frame),
        &mut |standing| {
            refused = Some(standing.reason());
            std::ops::ControlFlow::Break(())
        },
    )?;
    if let Some(reason) = refused {
        return reject(reason);
    }
    if escrow_taken(state, application, entry)? {
        return reject("escrow already exists");
    }
    // A shard that commits an operation exists, whatever route registered it:
    // an application whose grid was already deep before this record existed
    // (mainnet QUIL sits at depth nine) reaches its width on its first
    // operation instead of waiting for a split that will never come.
    let width = raise_placement_width(
        state,
        frame,
        application,
        source_shard.bits().map_or(0, |bits| bits.len()),
    )?;
    let Some((placements, sequences)) = place_outputs(state, application, width, &entry.outputs)?
    else {
        return reject("block is full");
    };

    // Commit.
    for marker in &entry.consumptions {
        records::write_record(
            state,
            frame,
            &consumed_address(application, marker)?,
            &consumed_fields(&entry.tx_id)?,
        )?;
    }
    if let Some(claim) = &entry.escrow_claim {
        let (binding, refund_after, _) =
            escrow(state, application, &claim.address)?.expect("checked above");
        write_escrow(
            state,
            frame,
            application,
            &claim.address,
            &binding,
            refund_after,
            true,
        )?;
    }
    let mut escrow_placement = None;
    if let Some(create) = &entry.escrow_create {
        write_escrow(
            state,
            frame,
            application,
            &create.address,
            &create.binding,
            create.refund_after_global_frame,
            false,
        )?;
        // Queued for delivery to the shard owning the escrow's block, so its
        // recipient can discover it there.
        let block = coin_blocks::block_for_address(width, &create.address)?;
        let seq = escrow_sequence(state, application, block)?;
        escrow_placement = Some(Placement {
            address: create.address,
            block,
            seq,
        });
        records::write_record(
            state,
            frame,
            &escrow_delivery_address(application, block, seq)?,
            &[
                kind_field(KIND_ESCROW_DELIVERY)?,
                (vec![0], create.address.to_vec()),
                (vec![4], entry.source_frame.to_be_bytes().to_vec()),
                (vec![8], entry.tx_id.to_vec()),
                (vec![12], source_shard.to_bytes().to_vec()),
            ],
        )?;
        records::write_record(
            state,
            frame,
            &escrow_sequence_address(application, block)?,
            &[
                kind_field(KIND_ESCROW_SEQUENCE)?,
                (vec![0], (seq + 1).to_be_bytes().to_vec()),
            ],
        )?;
    }
    for placement in &placements {
        records::write_record(
            state,
            frame,
            &delivery_address(application, placement.block, placement.seq)?,
            &[
                kind_field(KIND_DELIVERY)?,
                (vec![0], placement.address.to_vec()),
                (vec![4], entry.source_frame.to_be_bytes().to_vec()),
                (vec![8], entry.tx_id.to_vec()),
                (vec![12], source_shard.to_bytes().to_vec()),
            ],
        )?;
    }
    for (block, next) in &sequences {
        records::write_record(
            state,
            frame,
            &block_sequence_address(application, *block)?,
            &[
                kind_field(KIND_SEQUENCE)?,
                (vec![0], next.to_be_bytes().to_vec()),
            ],
        )?;
    }
    if let Some(settlement) = &entry.settlement {
        let address = settlement.receipt;
        let disc = crate::hypergraph_state::vertex_adds_discriminator()?;
        let global = crate::global_schema::GLOBAL_INTRINSIC_ADDRESS;
        if state
            .get(&global, &address, &disc)?
            .is_none_or(|blob| blob.is_empty())
        {
            state.set(
                &global,
                &address,
                &disc,
                frame,
                settlement_record::create_record(settlement)?,
            )?;
        }
    }
    records::write_record(
        state,
        frame,
        &decision,
        &decision_fields(&Decision::Committed { frame })?,
    )?;
    Ok(Outcome::Committed {
        fee: entry.fee,
        placements,
        escrow: escrow_placement,
    })
}

/// Structural check of a header's spend relay committed in GLOBAL frame
/// `global_frame`: canonical, inside the header's window, and every entry a
/// relayed operation type within that frame's bounds.
pub fn verify_relay(
    global_frame: u64,
    header_frame: u64,
    relay: &[u8],
) -> Result<Vec<(u64, Vec<SpendEntry>)>> {
    super::spend_relay::decode_relay(header_frame, relay)?
        .into_iter()
        .map(|(frame, entries)| {
            let entries = entries
                .iter()
                .map(|bytes| {
                    let entry = SpendEntry::decode_at(bytes, global_frame)?;
                    if entry.source_frame != frame {
                        return Err(invalid("entry relayed under another source frame"));
                    }
                    Ok(entry)
                })
                .collect::<Result<Vec<_>>>()?;
            Ok((frame, entries))
        })
        .collect()
}

/// Operations one `spends committed` line names; it counts the rest.
const LISTED_COMMITS: usize = 16;

/// What one header's relay committed: the fees [`materialize_relay`]
/// returns, and the blocks its committed outputs and escrows were queued
/// into.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayCommit {
    /// Fees credited to the relaying shard's provers.
    pub fees: u128,
    /// Per destination block: `(outputs, escrows)` committed into it.
    pub placed: std::collections::BTreeMap<u64, (u64, u64)>,
}

impl RelayCommit {
    fn place(&mut self, placements: &[Placement], escrow: Option<&Placement>) {
        for placement in placements {
            self.placed.entry(placement.block).or_default().0 += 1;
        }
        if let Some(escrow) = escrow {
            self.placed.entry(escrow.block).or_default().1 += 1;
        }
    }
}

/// Commit every entry a certified header relays, in relay order, returning
/// the fees of the operations that committed (credited to the relaying
/// shard's provers). Re-carried entries are already decided and add nothing.
/// From [`settlement_record::committed_credit_frame`] a mint claim's fee is
/// not among them: the reward mint it claims paid it, and GLOBAL credited it
/// there.
pub fn materialize_relay(
    state: &HypergraphState,
    frame: u64,
    filter: &[u8],
    header_frame: u64,
    relay: &[u8],
) -> Result<u128> {
    materialize_relay_placed(state, frame, filter, header_frame, relay).map(|commit| commit.fees)
}

/// [`materialize_relay`], also returning the blocks its committed outputs
/// and escrows were queued into, for the caller's destination line.
pub fn materialize_relay_placed(
    state: &HypergraphState,
    frame: u64,
    filter: &[u8],
    header_frame: u64,
    relay: &[u8],
) -> Result<RelayCommit> {
    use crate::token_engine::TYPE_LATTICE_MINT_CLAIM;
    if relay.is_empty() {
        return Ok(RelayCommit::default());
    }
    let application: [u8; 32] = filter
        .get(..32)
        .and_then(|a| a.try_into().ok())
        .ok_or_else(|| invalid("header filter names no application"))?;
    // The certified header's own filter says which shard executed these
    // operations, and so where an owning shard fetches their bytes from.
    let source_shard = match quil_forest::decode_shard_filter_or_root(filter, 32) {
        Some((_, bits)) => quil_types::execution::ShardPath::from_bits(&bits),
        None => return Err(invalid("header filter names no shard")),
    };
    let mint_fee_paid = frame >= settlement_record::committed_credit_frame();
    let mut commit = RelayCommit::default();
    let (mut committed, mut rejected, mut mint_claims) = (0usize, 0usize, 0usize);
    let mut listed = Vec::new();
    for (_, entries) in verify_relay(frame, header_frame, relay)? {
        for entry in entries {
            match commit_entry(state, frame, &application, &entry, source_shard)? {
                Outcome::Committed {
                    fee,
                    placements,
                    escrow,
                } => {
                    let mint_claim = entry.kind == TYPE_LATTICE_MINT_CLAIM;
                    if !(mint_fee_paid && mint_claim) {
                        commit.fees = commit.fees.saturating_add(fee);
                    }
                    commit.place(&placements, escrow.as_ref());
                    mint_claims += usize::from(mint_claim);
                    if listed.len() < LISTED_COMMITS {
                        listed.push(hex::encode(&entry.tx_id[..8]));
                    }
                    committed += 1;
                }
                Outcome::Rejected(reason) => {
                    rejected += 1;
                    tracing::info!(
                        frame,
                        application = %hex::encode(&application[..8]),
                        tx = %hex::encode(&entry.tx_id[..8]),
                        settles = entry.settlement.is_some(),
                        reason,
                        "spend rejected by the global commit",
                    );
                }
                Outcome::AlreadyDecided => {}
            }
        }
    }
    if committed > 0 {
        // An operation's commit, findable by the first 8 bytes of its id.
        tracing::info!(
            frame,
            application = %hex::encode(&application[..8]),
            shard = %hex::encode(filter),
            header_frame,
            committed,
            rejected,
            mint_claims,
            fees = commit.fees,
            txs = %listed.join(","),
            txs_unlisted = committed - listed.len(),
            "spends committed"
        );
    }
    Ok(commit)
}

fn escrow_fields(
    binding: &[u8; 32],
    refund_after: u64,
    consumed: bool,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    Ok(vec![
        kind_field(KIND_ESCROW)?,
        (vec![0], binding.to_vec()),
        (vec![4], refund_after.to_be_bytes().to_vec()),
        (vec![8], vec![u8::from(consumed)]),
    ])
}

/// The blob of an escrow record, exactly as the commit stores it.
pub fn encode_escrow_record(
    binding: &[u8; 32],
    refund_after: u64,
    consumed: bool,
) -> Result<Vec<u8>> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    for (key, value) in escrow_fields(binding, refund_after, consumed)? {
        tree.insert(&key, &value, &[], &num_bigint::BigInt::from(value.len()))?;
    }
    quil_tries::serialize_go_tree(tree.root.as_ref())
        .map_err(|_| invalid("cannot encode escrow record"))
}

fn write_escrow(
    state: &HypergraphState,
    frame: u64,
    application: &[u8; 32],
    address: &[u8; 32],
    binding: &[u8; 32],
    refund_after: u64,
    consumed: bool,
) -> Result<()> {
    records::write_record(
        state,
        frame,
        &escrow_address(application, address)?,
        &escrow_fields(binding, refund_after, consumed)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_lattice_ct::confidential::relation::membership::{Node, NODE_BYTES};

    #[test]
    fn mainnet_activates_the_release_at_832778_whatever_is_set() {
        for setting in [None, Some("5"), Some("bad")] {
            assert_eq!(super::release_activation_frame(0, setting), 832_778);
            assert_eq!(super::relay_activation_for(0, setting), 832_778);
        }
        assert_eq!(
            super::release_activation_frame(1, None),
            u64::MAX,
            "a test network re-places nothing by default"
        );
        assert_eq!(super::release_activation_frame(1, Some("230")), 230);
        assert_eq!(
            super::relay_activation_for(1, None),
            0,
            "a test network relays from genesis by default"
        );
        assert_eq!(super::relay_activation_for(1, Some("230")), 230);
    }

    fn mem_state() -> HypergraphState {
        HypergraphState::new(std::sync::Arc::new(quil_hypergraph::HypergraphCrdt::new(
            std::sync::Arc::new(quil_hypergraph::testing::MemStore::new()),
            std::sync::Arc::new(quil_types::crypto::NoopInclusionProver),
        )))
    }

    const APP: [u8; 32] = [7; 32];
    const CONTEXT: [u8; 32] = [8; 32];
    /// The shard the fixtures relay from.
    const SHARD: quil_types::execution::ShardPath = quil_types::execution::ShardPath::WHOLE;

    /// An output address inside a reachable width-6 block (Poseidon images
    /// begin `00`), so placements land where real ones do.
    fn output(n: u8) -> [u8; 32] {
        let mut address = [n; 32];
        address[0] = 0b0000_0100;
        address
    }

    fn entry(tx: u8, consumptions: &[u8], outputs: &[u8]) -> SpendEntry {
        SpendEntry {
            kind: 0x0512,
            tx_id: [tx; 32],
            source_frame: 40,
            context: CONTEXT,
            root_digest: None,
            consumptions: consumptions.iter().map(|c| [*c; 32]).collect(),
            outputs: outputs.iter().map(|o| output(*o)).collect(),
            escrow_create: None,
            escrow_claim: None,
            fee: 5,
            settlement: None,
        }
    }

    fn bits(pattern: &str) -> Vec<bool> {
        pattern.chars().map(|c| c == '1').collect()
    }

    /// Outputs and an escrow committed into block 130 (width 7, path
    /// 0000010), whose region then splits to eight bits: `0000010‖0` holds the
    /// block's records, `0000010‖1` does not, and neither owns it whole.
    fn orphaned_fixture() -> (HypergraphState, Vec<[u8; 32]>) {
        let state = mem_state();
        let seven = quil_types::execution::ShardPath::from_bits(&[false; 7]);
        let mut committed = entry(1, &[1], &[2, 3, 4]);
        let mut escrow = output(9);
        escrow[31] = 0xee;
        committed.escrow_create = Some(EscrowCreate {
            address: escrow,
            binding: [3; 32],
            refund_after_global_frame: 50,
        });
        assert!(matches!(
            commit_entry(&state, 5, &APP, &committed, seven).unwrap(),
            Outcome::Committed { .. }
        ));
        let block = coin_blocks::block_for_address(7, &output(2)).unwrap();
        assert_eq!(block, 130);
        assert_eq!(
            (
                block_sequence(&state, &APP, block).unwrap(),
                escrow_sequence(&state, &APP, block).unwrap()
            ),
            (3, 1)
        );
        raise_placement_width(&state, 6, &APP, 8).unwrap();
        (state, vec![output(2), output(3), output(4)])
    }

    #[test]
    fn a_split_past_a_block_width_orphans_its_undelivered_outputs() {
        let (state, _) = orphaned_fixture();
        let (held, other) = (bits("00000100"), bits("00000101"));
        assert!(holds_block_records(&held, 130) && !holds_block_records(&other, 130));
        let (marked, released) = reconcile_orphans(
            &state,
            6,
            &APP,
            &[held.clone(), other.clone()],
            &[bits("0000010")],
        )
        .unwrap();
        assert_eq!(
            (marked, released),
            (1, 0),
            "only block 130 holds committed outputs"
        );
        assert_eq!(
            orphan(&state, &APP, 130).unwrap(),
            Some(Orphan {
                since: 6,
                moved: false,
                coins: 0,
                escrows: 0
            })
        );
        // The holder counts it, so it is staffed and can attest.
        assert_eq!(committed_to_shard(&state, &APP, &held).unwrap(), 4);
        assert_eq!(committed_to_shard(&state, &APP, &other).unwrap(), 0);
        // Reconciling again changes nothing; a merge back releases it whole.
        assert_eq!(
            reconcile_orphans(&state, 7, &APP, &[held.clone(), other.clone()], &[]).unwrap(),
            (0, 0)
        );
        assert_eq!(
            reconcile_orphans(&state, 8, &APP, &[bits("0000010")], &[held, other]).unwrap(),
            (0, 1)
        );
        assert_eq!(orphan(&state, &APP, 130).unwrap(), None);
        assert!(
            delivery(&state, &APP, 130, 2).unwrap().is_some(),
            "its owner delivers it as before"
        );
    }

    #[test]
    fn an_attested_orphan_is_re_placed_exactly_once() {
        let (state, outputs) = orphaned_fixture();
        let children = [bits("00000100"), bits("00000101")];
        reconcile_orphans(&state, 6, &APP, &children, &[bits("0000010")]).unwrap();
        assert!(
            apply_orphan_attestation(&state, 7, &APP, 130, 4, 0).is_err(),
            "more than was committed"
        );
        // The parent delivered the first coin and no escrow.
        assert!(apply_orphan_attestation(&state, 7, &APP, 130, 1, 0).unwrap());
        let wide = coin_blocks::block_for_address(8, &outputs[1]).unwrap();
        assert_eq!(wide, 260);
        assert_eq!(
            delivery(&state, &APP, 130, 0).unwrap().unwrap().address,
            outputs[0]
        );
        assert!(
            delivery(&state, &APP, 130, 1).unwrap().is_none(),
            "a moved record names no delivery"
        );
        assert!(delivery(&state, &APP, 130, 2).unwrap().is_none());
        assert_eq!(
            delivery(&state, &APP, wide, 0).unwrap().unwrap().address,
            outputs[1]
        );
        assert_eq!(
            delivery(&state, &APP, wide, 1).unwrap().unwrap().address,
            outputs[2]
        );
        let moved = delivery(&state, &APP, wide, 0).unwrap().unwrap();
        assert_eq!(
            (moved.source_frame, moved.tx_id),
            (40, [1; 32]),
            "the operation it came from is kept"
        );
        assert!(escrow_delivery(&state, &APP, 130, 0).unwrap().is_none());
        assert!(escrow_delivery(&state, &APP, wide, 0).unwrap().is_some());
        assert_eq!(
            (
                block_sequence(&state, &APP, 130).unwrap(),
                escrow_sequence(&state, &APP, 130).unwrap()
            ),
            (1, 0)
        );
        assert_eq!(
            (
                block_sequence(&state, &APP, wide).unwrap(),
                escrow_sequence(&state, &APP, wide).unwrap()
            ),
            (2, 1)
        );
        assert_eq!(
            orphan(&state, &APP, 130).unwrap(),
            Some(Orphan {
                since: 6,
                moved: true,
                coins: 1,
                escrows: 0
            })
        );
        // Each output now counts once, for the owner of its new block.
        assert_eq!(committed_to_shard(&state, &APP, &children[0]).unwrap(), 3);
        // The same attestation again is idempotent; a different one is refused.
        assert!(!apply_orphan_attestation(&state, 8, &APP, 130, 1, 0).unwrap());
        assert!(apply_orphan_attestation(&state, 8, &APP, 130, 2, 0).is_err());
        // A block never marked orphaned ignores attestations.
        assert!(!apply_orphan_attestation(&state, 8, &APP, 260, 0, 0).unwrap());
    }

    /// A report attests an orphaned block only from the re-placement frame,
    /// only from the shard holding the block's records, and only for a block
    /// narrower than that shard.
    #[test]
    fn a_holders_report_attests_an_orphan_from_the_replacement_frame() {
        use super::super::shard_accumulator::{BlockAttestation, ShardReport};
        let (state, _) = orphaned_fixture();
        reconcile_orphans(
            &state,
            6,
            &APP,
            &[bits("00000100"), bits("00000101")],
            &[bits("0000010")],
        )
        .unwrap();
        let report = |block| {
            ShardReport {
                context: CONTEXT,
                subtrees: Vec::new(),
                attestations: vec![BlockAttestation {
                    block,
                    coins: 2,
                    escrows: 1,
                }],
            }
            .encode()
            .unwrap()
        };
        let holder = quil_forest::encode_shard_bit_path(&APP, &bits("00000100"));
        let sibling = quil_forest::encode_shard_bit_path(&APP, &bits("00000101"));
        set_orphan_replacement_frame_for_test(Some(9));
        assert!(
            records::materialize_report(&state, 8, &holder, &report(130)).is_err(),
            "before the frame"
        );
        assert!(
            records::materialize_report(&state, 9, &sibling, &report(130)).is_err(),
            "not the holder"
        );
        assert!(
            records::materialize_report(&state, 9, &holder, &report(260)).is_err(),
            "a block the shard owns"
        );
        records::materialize_report(&state, 9, &holder, &report(130)).unwrap();
        set_orphan_replacement_frame_for_test(None);
        assert_eq!(
            orphan(&state, &APP, 130).unwrap(),
            Some(Orphan {
                since: 6,
                moved: true,
                coins: 2,
                escrows: 1
            })
        );
        assert!(delivery(&state, &APP, 130, 2).unwrap().is_none());
        assert_eq!(
            delivery(&state, &APP, 260, 0).unwrap().unwrap().address,
            output(4)
        );
        assert!(
            escrow_delivery(&state, &APP, 130, 0).unwrap().is_some(),
            "the delivered escrow stays"
        );
    }

    #[test]
    fn entries_round_trip_canonically() {
        let mut full = entry(1, &[2, 3], &[4, 5]);
        full.root_digest = Some([9; 32]);
        full.escrow_create = Some(EscrowCreate {
            address: [10; 32],
            binding: [11; 32],
            refund_after_global_frame: 99,
        });
        full.settlement = Some(SettlementEntry {
            receipt: [12; 32],
            parameter_context: [13; 32],
            destination: [14; 32],
            context: [15; 32],
            settlement: 7,
            payment_address: [0; 32],
            payment: 0,
            claimant: [0; 32],
        });
        let bytes = full.encode().unwrap();
        assert_eq!(SpendEntry::decode(&bytes).unwrap(), full);
        // The compact relay the design needs: a 2-in 2-out transfer.
        let transfer = entry(1, &[2, 3], &[4, 5]).encode().unwrap();
        assert!(transfer.len() < 300, "{} bytes", transfer.len());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(SpendEntry::decode(&trailing).is_err());
        assert!(SpendEntry::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(
            entry(1, &[2, 2], &[4]).encode().is_err(),
            "repeated consumption"
        );
        assert!(entry(1, &[], &[4]).encode().is_err(), "nothing consumed");
    }

    /// The property the commit exists for: one image, one spend — whichever
    /// shard relays it and in whatever order relays arrive.
    #[test]
    fn a_consumption_commits_once_and_decisions_are_final() {
        let state = mem_state();
        assert!(!is_decided(&state, &APP, &[1; 32]).unwrap());
        let first = commit_entry(&state, 100, &APP, &entry(1, &[20, 21], &[1, 2]), SHARD).unwrap();
        let Outcome::Committed {
            fee, placements, ..
        } = first
        else {
            panic!("{first:?}")
        };
        assert_eq!(fee, 5);
        assert!(is_decided(&state, &APP, &[1; 32]).unwrap());
        assert!(
            !is_decided(&state, &[6; 32], &[1; 32]).unwrap(),
            "decisions are per application"
        );
        assert!(is_consumed(&state, &APP, &[20; 32]).unwrap());
        // Two outputs in one block take consecutive sequence numbers.
        let block =
            coin_blocks::block_for_address(coin_blocks::INITIAL_BLOCK_BITS, &output(1)).unwrap();
        assert_eq!(
            placements
                .iter()
                .map(|p| (p.block, p.seq))
                .collect::<Vec<_>>(),
            vec![(block, 0), (block, 1)]
        );
        assert_eq!(block_sequence(&state, &APP, block).unwrap(), 2);
        assert_eq!(
            delivery(&state, &APP, block, 1).unwrap(),
            Some(Delivery {
                address: output(2),
                source_frame: 40,
                tx_id: [1; 32],
                source_shard: SHARD,
            })
        );
        // A different operation spending one of the same markers is rejected,
        // writes nothing, and stays rejected.
        let double = entry(2, &[21, 22], &[3]);
        assert_eq!(
            commit_entry(&state, 101, &APP, &double, SHARD).unwrap(),
            Outcome::Rejected("already consumed")
        );
        assert!(
            is_decided(&state, &APP, &[2; 32]).unwrap(),
            "a rejection is a decision too"
        );
        assert!(!is_consumed(&state, &APP, &[22; 32]).unwrap());
        assert_eq!(block_sequence(&state, &APP, block).unwrap(), 2);
        assert_eq!(
            commit_entry(&state, 102, &APP, &double, SHARD).unwrap(),
            Outcome::AlreadyDecided
        );
        // Re-carried relays of the committed operation are not re-applied.
        assert_eq!(
            commit_entry(&state, 103, &APP, &entry(1, &[20, 21], &[1, 2]), SHARD).unwrap(),
            Outcome::AlreadyDecided
        );
        assert_eq!(block_sequence(&state, &APP, block).unwrap(), 2);
        // Consumption is per application.
        assert!(matches!(
            commit_entry(&state, 104, &[6; 32], &entry(3, &[20], &[4]), SHARD).unwrap(),
            Outcome::Committed { .. }
        ));
    }

    /// A wallet reads the decision through a node's vertex read: the stored
    /// bytes decode to the outcome and the GLOBAL frame that decided it.
    #[test]
    fn a_decision_record_decodes_from_its_stored_bytes() {
        let state = mem_state();
        let stored = |address: [u8; 32]| {
            state
                .get(
                    &crate::global_schema::GLOBAL_INTRINSIC_ADDRESS,
                    &address,
                    &crate::hypergraph_state::vertex_adds_discriminator().unwrap(),
                )
                .unwrap()
        };
        let decision = |tx: u8| stored(decision_address(&APP, &[tx; 32]).unwrap());
        assert_eq!(decision(1), None);
        assert_eq!(
            decode_decision(&[]).unwrap(),
            None,
            "an empty blob is undecided"
        );
        commit_entry(&state, 100, &APP, &entry(1, &[20, 21], &[1, 2]), SHARD).unwrap();
        let committed = Decision::Committed { frame: 100 };
        assert_eq!(
            decode_decision(&decision(1).unwrap()).unwrap(),
            Some(committed.clone())
        );
        assert_eq!(
            encode_decision_record(&committed).unwrap(),
            decision(1).unwrap()
        );
        commit_entry(&state, 107, &APP, &entry(2, &[21, 22], &[3]), SHARD).unwrap();
        let rejected = Decision::Rejected {
            frame: 107,
            reason: "already consumed".into(),
        };
        assert_eq!(
            decode_decision(&decision(2).unwrap()).unwrap(),
            Some(rejected.clone())
        );
        assert_eq!(
            encode_decision_record(&rejected).unwrap(),
            decision(2).unwrap()
        );
        // Another record kind at the address is not a decision.
        let consumed = stored(consumed_address(&APP, &[20; 32]).unwrap()).unwrap();
        assert!(decode_decision(&consumed).is_err());
        assert!(decode_decision(&[1, 2, 3]).is_err(), "malformed bytes");
    }

    #[test]
    fn a_root_must_be_canonical_and_a_context_fixed() {
        let state = mem_state();
        let mut spend = entry(1, &[20], &[1]);
        spend.root_digest = Some([9; 32]);
        assert_eq!(
            commit_entry(&state, 100, &APP, &spend, SHARD).unwrap(),
            Outcome::Rejected("root is not in the application's canonical history")
        );
        // Publish a canonical root and cite its digest.
        let root = Node::from_bytes(&[1u8; NODE_BYTES]).unwrap();
        let record = quil_lattice_ct::confidential::coin_tree::RootRecord {
            context: CONTEXT,
            depth: 32,
            coins: 1,
            root: root.clone(),
        };
        let history = roots::publish_history(None, record).unwrap();
        records::write_record(
            &state,
            100,
            &records::root_history_address(&APP).unwrap(),
            &[
                (
                    vec![0xff; 32],
                    records::kind("quil/accumulator/root-history-record/v1\0")
                        .unwrap()
                        .to_vec(),
                ),
                (vec![0], history),
            ],
        )
        .unwrap();
        let mut spend = entry(2, &[20], &[1]);
        spend.root_digest = Some(roots::root_digest(&CONTEXT, 32, &root));
        assert!(matches!(
            commit_entry(&state, 101, &APP, &spend, SHARD).unwrap(),
            Outcome::Committed { .. }
        ));
        // Once the application has a context, another one is refused.
        let mut foreign = entry(3, &[21], &[2]);
        foreign.context = [99; 32];
        assert_eq!(
            commit_entry(&state, 102, &APP, &foreign, SHARD).unwrap(),
            Outcome::Rejected("context differs from the application's")
        );
    }

    #[test]
    fn escrows_are_created_once_claimed_once_and_refunded_only_after_their_frame() {
        let state = mem_state();
        let binding = escrow_binding(&CONTEXT, &[50; 32], b"source", b"recipient", b"refund", 200);
        let mut create = entry(1, &[20], &[1]);
        create.escrow_create = Some(EscrowCreate {
            address: [50; 32],
            binding,
            refund_after_global_frame: 200,
        });
        assert!(matches!(
            commit_entry(&state, 100, &APP, &create, SHARD).unwrap(),
            Outcome::Committed { .. }
        ));
        assert_eq!(
            escrow(&state, &APP, &[50; 32]).unwrap(),
            Some((binding, 200, false))
        );
        // The same escrow address cannot be created twice.
        let mut again = entry(2, &[21], &[2]);
        again.escrow_create = Some(EscrowCreate {
            address: [50; 32],
            binding,
            refund_after_global_frame: 200,
        });
        assert_eq!(
            commit_entry(&state, 101, &APP, &again, SHARD).unwrap(),
            Outcome::Rejected("escrow already exists")
        );

        let other_binding =
            escrow_binding(&CONTEXT, &[52; 32], b"source", b"recipient", b"refund", 200);
        let claim = |tx: u8, binding: [u8; 32], refund: bool| {
            let mut claim = entry(tx, &[], &[3]);
            claim.escrow_claim = Some(EscrowClaim {
                address: [50; 32],
                binding,
                refund,
            });
            claim
        };
        assert_eq!(
            commit_entry(&state, 102, &APP, &claim(3, [0; 32], false), SHARD).unwrap(),
            Outcome::Rejected("claim does not match the escrow")
        );
        assert_eq!(
            commit_entry(&state, 150, &APP, &claim(4, binding, true), SHARD).unwrap(),
            Outcome::Rejected("refund before the escrow's refund frame")
        );
        // The recipient may claim before the refund frame; then nobody can.
        assert!(matches!(
            commit_entry(&state, 151, &APP, &claim(5, binding, false), SHARD).unwrap(),
            Outcome::Committed { .. }
        ));
        assert_eq!(
            escrow(&state, &APP, &[50; 32]).unwrap(),
            Some((binding, 200, true))
        );
        assert_eq!(
            commit_entry(&state, 250, &APP, &claim(6, binding, true), SHARD).unwrap(),
            Outcome::Rejected("escrow already consumed")
        );
        // What a wallet reads over RPC is exactly what the commit stored.
        let disc = crate::hypergraph_state::vertex_adds_discriminator().unwrap();
        let stored = state
            .get(
                &crate::global_schema::GLOBAL_INTRINSIC_ADDRESS,
                &escrow_address(&APP, &[50; 32]).unwrap(),
                &disc,
            )
            .unwrap()
            .unwrap();
        assert_eq!(stored, encode_escrow_record(&binding, 200, true).unwrap());
        assert_eq!(parse_escrow_record(&stored).unwrap(), (binding, 200, true));
        assert!(
            parse_escrow_record(&encode_escrow_record(&binding, 200, false).unwrap())
                .is_ok_and(|r| !r.2)
        );
        // Each created escrow is queued once for delivery to its block's shard.
        let block =
            coin_blocks::block_for_address(coin_blocks::INITIAL_BLOCK_BITS, &[50; 32]).unwrap();
        assert_eq!(escrow_sequence(&state, &APP, block).unwrap(), 1);
        // The record names the shard that executed it: where its bytes are.
        assert_eq!(
            escrow_delivery(&state, &APP, block, 0).unwrap(),
            Some(Delivery {
                address: [50; 32],
                source_frame: create.source_frame,
                tx_id: create.tx_id,
                source_shard: SHARD,
            })
        );
        let split = quil_types::execution::ShardPath::from_bits(&[true, false]);
        let mut elsewhere = entry(9, &[60], &[7]);
        elsewhere.escrow_create = Some(EscrowCreate {
            address: [52; 32],
            binding: other_binding,
            refund_after_global_frame: 200,
        });
        assert!(matches!(
            commit_entry(&state, 170, &APP, &elsewhere, split).unwrap(),
            Outcome::Committed { .. }
        ));
        let other_block =
            coin_blocks::block_for_address(coin_blocks::INITIAL_BLOCK_BITS, &[52; 32]).unwrap();
        assert_eq!(
            escrow_delivery(&state, &APP, other_block, 0)
                .unwrap()
                .unwrap()
                .source_shard,
            split
        );

        // A refund at or after the refund frame commits.
        let other = escrow_binding(&CONTEXT, &[51; 32], b"source", b"recipient", b"refund", 200);
        let _ = &other;
        let mut create = entry(7, &[22], &[4]);
        create.escrow_create = Some(EscrowCreate {
            address: [51; 32],
            binding: other,
            refund_after_global_frame: 200,
        });
        assert!(matches!(
            commit_entry(&state, 160, &APP, &create, SHARD).unwrap(),
            Outcome::Committed { .. }
        ));
        let mut refund = entry(8, &[], &[5]);
        refund.escrow_claim = Some(EscrowClaim {
            address: [51; 32],
            binding: other,
            refund: true,
        });
        assert!(matches!(
            commit_entry(&state, 200, &APP, &refund, SHARD).unwrap(),
            Outcome::Committed { .. }
        ));
    }

    /// A committed mint claim's fee was paid with its reward mint: from the
    /// committed-credit frame the relay credits it no second time, while the
    /// claim still commits.
    #[test]
    fn a_consumption_record_names_its_operation_from_its_stored_bytes() {
        let state = mem_state();
        commit_entry(&state, 100, &APP, &entry(1, &[20], &[]), SHARD).unwrap();
        let stored = state
            .get(
                &crate::global_schema::GLOBAL_INTRINSIC_ADDRESS,
                &consumed_address(&APP, &[20; 32]).unwrap(),
                &crate::hypergraph_state::vertex_adds_discriminator().unwrap(),
            )
            .unwrap()
            .expect("the commit wrote the record");
        assert_eq!(parse_consumed_record(&stored).unwrap(), [1; 32]);
        assert_eq!(encode_consumed_record(&[1; 32]).unwrap(), stored);
        parse_consumed_record(&[]).unwrap_err();
        // Another record is not read as a consumption.
        let (binding, refund, consumed) = ([3; 32], 50, false);
        let mut tree = quil_tries::VectorCommitmentTree::new();
        for (key, value) in escrow_fields(&binding, refund, consumed).unwrap() {
            tree.insert(&key, &value, &[], &num_bigint::BigInt::from(value.len()))
                .unwrap();
        }
        let escrow = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
        parse_consumed_record(&escrow).unwrap_err();
    }

    /// One line per header with a commit: its shard and header frame, and the
    /// operations it committed by the first 8 bytes of their ids, up to a bound.
    #[test]
    fn a_commit_line_names_the_header_and_its_operations() {
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
                let mut fields = Fields(String::new());
                event.record(&mut fields);
                self.0.lock().unwrap().push(fields.0);
            }
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }
        let commit_line = |relayed: Vec<Vec<u8>>| {
            let relay =
                crate::token_intrinsic::spend_relay::encode_relay(&[(40, relayed)]).unwrap();
            let lines = Arc::new(Mutex::new(Vec::new()));
            tracing::subscriber::with_default(Recorder(lines.clone()), || {
                materialize_relay(&mem_state(), 100, &APP, 41, &relay).unwrap();
            });
            let lines = lines.lock().unwrap().clone();
            lines
                .into_iter()
                .find(|line| line.contains("spends committed"))
                .expect("a commit logs its line")
        };
        let mut claim = entry(2, &[30], &[]);
        claim.kind = crate::token_engine::TYPE_LATTICE_MINT_CLAIM;
        let line = commit_line(vec![
            entry(1, &[20], &[]).encode().unwrap(),
            claim.encode().unwrap(),
        ]);
        let has = |line: &str, field: &str| line.split(' ').any(|token| token == field);
        assert!(has(&line, &format!("shard={}", hex::encode(APP))), "{line}");
        assert!(has(&line, "header_frame=41"), "{line}");
        assert!(has(&line, "committed=2"), "{line}");
        assert!(has(&line, "mint_claims=1"), "{line}");
        assert!(has(&line, "txs_unlisted=0"), "{line}");
        assert!(
            has(&line, "txs=0101010101010101,0202020202020202"),
            "{line}"
        );
        // Past the bound the rest are counted, and the line stays one line.
        let many = (0..LISTED_COMMITS as u8 + 3)
            .map(|n| entry(100 + n, &[100 + n], &[]).encode().unwrap())
            .collect();
        let line = commit_line(many);
        assert!(has(&line, "txs_unlisted=3"), "{line}");
        let listed = line.split(" txs=").nth(1).unwrap();
        let listed = listed.split(' ').next().unwrap();
        assert_eq!(listed.split(',').count(), LISTED_COMMITS, "{line}");
    }

    #[test]
    fn a_mint_claim_fee_is_credited_once_from_the_activation_frame() {
        use crate::token_intrinsic::settlement_record::set_committed_credit_frame_for_thread;
        let mut claim = entry(2, &[30], &[]);
        claim.kind = crate::token_engine::TYPE_LATTICE_MINT_CLAIM;
        claim.fee = 9;
        let relayed = vec![
            entry(1, &[20], &[]).encode().unwrap(),
            claim.encode().unwrap(),
        ];
        let relay = crate::token_intrinsic::spend_relay::encode_relay(&[(40, relayed)]).unwrap();
        set_committed_credit_frame_for_thread(Some(101));
        assert_eq!(
            materialize_relay(&mem_state(), 100, &APP, 41, &relay).unwrap(),
            14
        );
        set_committed_credit_frame_for_thread(Some(100));
        let state = mem_state();
        assert_eq!(materialize_relay(&state, 100, &APP, 41, &relay).unwrap(), 5);
        assert!(is_consumed(&state, &APP, &[30; 32]).unwrap());
        set_committed_credit_frame_for_thread(None);
    }

    /// The relay commit reports the blocks it queued committed outputs and
    /// escrows into; a rejected or re-carried entry places nothing.
    #[test]
    fn a_relay_commit_reports_where_its_outputs_were_placed() {
        let mut escrowed = entry(2, &[21], &[4]);
        let mut escrow = output(9);
        escrow[0] = 0b0000_1000;
        escrowed.escrow_create = Some(EscrowCreate {
            address: escrow,
            binding: [3; 32],
            refund_after_global_frame: 500,
        });
        let relayed = vec![
            entry(1, &[20], &[2, 3]).encode().unwrap(),
            escrowed.encode().unwrap(),
            entry(1, &[20], &[2, 3]).encode().unwrap(),
            entry(3, &[20], &[5]).encode().unwrap(),
        ];
        let relay = crate::token_intrinsic::spend_relay::encode_relay(&[(40, relayed)]).unwrap();
        let state = mem_state();
        let commit = materialize_relay_placed(&state, 100, &APP, 41, &relay).unwrap();
        let outputs = coin_blocks::block_for_address(6, &output(2)).unwrap();
        let escrows = coin_blocks::block_for_address(6, &escrow).unwrap();
        assert_ne!(outputs, escrows);
        assert_eq!(
            commit.fees, 10,
            "two committed, one re-carried, one rejected"
        );
        assert_eq!(
            commit.placed,
            [(outputs, (3, 0)), (escrows, (0, 1))].into_iter().collect(),
        );
        assert_eq!(
            materialize_relay_placed(&state, 101, &APP, 41, &relay).unwrap(),
            RelayCommit::default(),
            "a re-carried relay places nothing"
        );
    }

    #[test]
    fn a_settlement_record_is_written_only_when_its_spend_commits() {
        let state = mem_state();
        let settlement = SettlementEntry {
            receipt: [12; 32],
            parameter_context: CONTEXT,
            destination: [14; 32],
            context: [15; 32],
            settlement: 7,
            payment_address: [0; 32],
            payment: 0,
            claimant: [0; 32],
        };
        let disc = crate::hypergraph_state::vertex_adds_discriminator().unwrap();
        let global = crate::global_schema::GLOBAL_INTRINSIC_ADDRESS;
        let mut committed = entry(1, &[20], &[1]);
        committed.settlement = Some(settlement.clone());
        assert!(matches!(
            commit_entry(&state, 100, &APP, &committed, SHARD).unwrap(),
            Outcome::Committed { .. }
        ));
        assert!(state.get(&global, &[12; 32], &disc).unwrap().is_some());
        // A double spend carrying another settlement records nothing.
        let mut rejected = entry(2, &[20], &[2]);
        rejected.settlement = Some(SettlementEntry {
            receipt: [13; 32],
            ..settlement
        });
        assert_eq!(
            commit_entry(&state, 101, &APP, &rejected, SHARD).unwrap(),
            Outcome::Rejected("already consumed")
        );
        assert!(state.get(&global, &[13; 32], &disc).unwrap().is_none());
    }
    /// New coins are placed no narrower than the application's deepest shard,
    /// the width only rises, and earlier blocks keep their ids.
    #[test]
    fn placement_width_follows_the_deepest_shard_and_never_falls() {
        let state = mem_state();
        assert_eq!(
            placement_width(&state, &APP).unwrap(),
            coin_blocks::INITIAL_BLOCK_BITS
        );
        // Shallower than the starting width changes nothing.
        assert_eq!(
            raise_placement_width(&state, 1, &APP, 3).unwrap(),
            coin_blocks::INITIAL_BLOCK_BITS
        );
        let narrow =
            coin_blocks::block_for_address(placement_width(&state, &APP).unwrap(), &[0x21; 32])
                .unwrap();
        assert_eq!(raise_placement_width(&state, 2, &APP, 9).unwrap(), 9);
        assert_eq!(placement_width(&state, &APP).unwrap(), 9);
        assert_eq!(
            raise_placement_width(&state, 3, &APP, 7).unwrap(),
            9,
            "the width never falls"
        );
        let wide =
            coin_blocks::block_for_address(placement_width(&state, &APP).unwrap(), &[0x21; 32])
                .unwrap();
        assert_eq!(
            (
                coin_blocks::creation_width(narrow),
                coin_blocks::creation_width(wide)
            ),
            (6, 9)
        );
        assert_ne!(
            narrow, wide,
            "a wider block never reuses a narrower block's id"
        );
        // A depth-nine shard owns the wide block whole, and only part of the narrow one.
        let shard: Vec<bool> = coin_blocks::block_path(wide);
        assert!(coin_blocks::shard_owns_block(&shard, wide));
        assert!(!coin_blocks::shard_owns_block(&shard, narrow));
        // Beyond the accumulator's widest block the width saturates.
        assert_eq!(
            raise_placement_width(&state, 4, &APP, 40).unwrap(),
            coin_blocks::MAX_BLOCK_BITS
        );
        // Another application is untouched.
        assert_eq!(
            placement_width(&state, &[0x77; 32]).unwrap(),
            coin_blocks::INITIAL_BLOCK_BITS
        );
    }

    /// A commit relayed by a depth-nine shard places its outputs in width-nine
    /// blocks even though no split ever raised the width here.
    #[test]
    fn a_deep_source_shard_places_at_its_own_depth() {
        let state = mem_state();
        let deep = quil_types::execution::ShardPath::from_bits(&[false; 9]);
        assert!(matches!(
            commit_entry(&state, 5, &APP, &entry(1, &[1], &[2]), deep).unwrap(),
            Outcome::Committed { .. }
        ));
        assert_eq!(placement_width(&state, &APP).unwrap(), 9);
        let block = coin_blocks::block_for_address(9, &output(2)).unwrap();
        assert_eq!(block_sequence(&state, &APP, block).unwrap(), 1);
        let narrow =
            coin_blocks::block_for_address(coin_blocks::INITIAL_BLOCK_BITS, &output(2)).unwrap();
        assert_eq!(
            block_sequence(&state, &APP, narrow).unwrap(),
            0,
            "nothing new lands in a narrower block"
        );
    }

    /// What GLOBAL has committed into a shard's blocks counts for that shard and
    /// for no sibling, whether or not the shard ever took delivery.
    #[test]
    fn outputs_committed_into_a_shard_count_as_its_data() {
        let state = mem_state();
        assert!(matches!(
            commit_entry(&state, 5, &APP, &entry(1, &[1], &[2, 3]), SHARD).unwrap(),
            Outcome::Committed { .. }
        ));
        // `output(n)` begins 0b0000_0100: path 000001… at any depth.
        let holds = |bits: &[bool]| committed_to_shard(&state, &APP, bits).unwrap();
        assert_eq!(holds(&[]), 2, "the whole application owns every block");
        assert_eq!(holds(&[false, false, false]), 2);
        assert_eq!(
            holds(&[false, false, true]),
            0,
            "a sibling range holds nothing"
        );
        assert_eq!(holds(&[true]), 0);
        // Deeper than the placement width: the shard owns no whole block.
        assert_eq!(holds(&[false; 7]), 0);
    }

    /// A shield entry may carry up to 96 consumptions from the batch shield
    /// frame, still fitting the relay's entry; before it, and for every other
    /// operation, the limit stays 16.
    #[test]
    fn shield_entries_grow_to_the_batch_limit_only_from_activation() {
        use crate::token_engine::{TYPE_LATTICE_SHIELD, TYPE_LATTICE_TRANSACTION};
        let entry = |kind: u32, consumptions: usize| SpendEntry {
            kind,
            tx_id: [1; 32],
            source_frame: 5,
            context: [2; 32],
            root_digest: None,
            consumptions: (0..consumptions)
                .map(|i| {
                    let mut c = [3u8; 32];
                    c[..8].copy_from_slice(&(i as u64).to_be_bytes());
                    c
                })
                .collect(),
            outputs: (0..MAX_OUTPUTS).map(|i| [i as u8 + 100; 32]).collect(),
            escrow_create: None,
            escrow_claim: None,
            fee: 7,
            settlement: None,
        };
        let full = entry(
            TYPE_LATTICE_SHIELD,
            quil_lattice_ct::confidential::shield::MAX_SHIELD_SOURCES,
        );
        let bytes = full.encode().unwrap();
        assert!(
            bytes.len() <= super::super::spend_relay::MAX_ENTRY_BYTES,
            "{} bytes",
            bytes.len()
        );
        assert!(super::super::spend_relay::encode_frame_entries(&[bytes.clone()]).is_ok());
        assert!(entry(TYPE_LATTICE_SHIELD, 97).encode().is_err());
        assert!(entry(TYPE_LATTICE_TRANSACTION, MAX_CONSUMPTIONS + 1)
            .encode()
            .is_err());

        set_batch_shield_frame_for_thread(Some(1_000));
        assert!(
            SpendEntry::decode_at(&bytes, 999).is_err(),
            "before activation a shield entry holds 16"
        );
        assert!(SpendEntry::decode(&bytes).is_err());
        assert_eq!(SpendEntry::decode_at(&bytes, 1_000).unwrap(), full);
        assert_eq!(
            max_consumptions(TYPE_LATTICE_TRANSACTION, 5_000),
            MAX_CONSUMPTIONS
        );
        assert!(
            batch_shields_active(Some(1_000))
                && !batch_shields_active(Some(999))
                && !batch_shields_active(None)
        );
        set_batch_shield_frame_for_thread(None);
        assert_eq!(
            batch_shield_frame_for(0, Some("5")),
            MAINNET_BATCH_SHIELD_FRAME,
            "fixed on mainnet"
        );
        assert_eq!(batch_shield_frame_for(1, Some("5")), 5);
        assert_eq!(batch_shield_frame_for(1, None), u64::MAX);
    }

    /// The canonical owner gate: fixed on mainnet whatever the setting, set
    /// elsewhere only by `QUIL_CANONICAL_OWNER_FRAME`, and active from its
    /// frame for an operation anchored at or past it.
    #[test]
    fn the_canonical_owner_frame_is_fixed_on_mainnet_and_active_from_its_frame() {
        assert_eq!(
            canonical_owner_frame_for(0, Some("5")),
            MAINNET_CANONICAL_OWNER_FRAME.unwrap_or(u64::MAX),
            "fixed on mainnet"
        );
        assert_eq!(canonical_owner_frame_for(1, Some("5")), 5);
        assert_eq!(canonical_owner_frame_for(1, None), u64::MAX);
        set_canonical_owner_frame_for_thread(Some(1_000));
        assert!(canonical_owners_active(Some(1_000)));
        assert!(!canonical_owners_active(Some(999)));
        assert!(!canonical_owners_active(None));
        set_canonical_owner_frame_for_thread(None);
    }

    /// The commit decides by the first of its state refusals, in its order
    /// (a root before a marker); ahead of it, a lasting refusal outranks a
    /// pending one, and nothing is pending on a view holding no roots of the
    /// application or of the QUIL token.
    #[test]
    fn the_commit_refuses_for_its_first_reason_and_a_precheck_for_a_lasting_one() {
        let state = mem_state();
        assert!(matches!(
            commit_entry(&state, 100, &APP, &entry(1, &[20], &[1]), SHARD).unwrap(),
            Outcome::Committed { .. }
        ));
        let needs = |consumed: u8| CommitNeeds {
            context: CONTEXT,
            root_digest: Some([9; 32]),
            consumptions: vec![[consumed; 32]],
            escrow_claim: None,
        };
        assert_eq!(
            precheck(&state, &APP, &needs(20)).unwrap(),
            Some(Standing::Lasting("already consumed"))
        );
        assert_eq!(precheck(&state, &APP, &needs(21)).unwrap(), None);
        let root = Node::from_bytes(&[1u8; NODE_BYTES]).unwrap();
        let history = roots::publish_history(
            None,
            quil_lattice_ct::confidential::coin_tree::RootRecord {
                context: CONTEXT,
                depth: 32,
                coins: 1,
                root,
            },
        )
        .unwrap();
        records::write_record(
            &state,
            100,
            &records::root_history_address(&APP).unwrap(),
            &[
                (
                    vec![0xff; 32],
                    records::kind("quil/accumulator/root-history-record/v1\0")
                        .unwrap()
                        .to_vec(),
                ),
                (vec![0], history),
            ],
        )
        .unwrap();
        assert_eq!(
            precheck(&state, &APP, &needs(21)).unwrap(),
            Some(Standing::Pending(
                "root is not in the application's canonical history"
            ))
        );
        assert_eq!(
            precheck(&state, &APP, &needs(20)).unwrap(),
            Some(Standing::Lasting("already consumed"))
        );
        let mut both = entry(2, &[20], &[2]);
        both.root_digest = Some([9; 32]);
        assert_eq!(
            commit_entry(&state, 101, &APP, &both, SHARD).unwrap(),
            Outcome::Rejected("root is not in the application's canonical history")
        );
    }

    /// The global venue reads every refusal of the commit before the proof
    /// work ([`refusal`]) as the commit then makes it, in its order, and
    /// reading writes nothing (not even the context record a first commit
    /// writes).
    #[test]
    fn the_venue_reads_each_commit_refusal_before_the_proof_as_the_commit_makes_it() {
        let state = mem_state();
        let first = entry(1, &[20], &[1]);
        let mut foreign = entry(2, &[21], &[2]);
        foreign.context = [99; 32];
        assert_eq!(refusal(&state, 100, &APP, &first, SHARD).unwrap(), None);
        assert_eq!(
            refusal(&state, 100, &APP, &foreign, SHARD).unwrap(),
            None,
            "reading the first entry wrote the application's context"
        );
        assert!(matches!(
            commit_entry(&state, 100, &APP, &first, SHARD).unwrap(),
            Outcome::Committed { .. }
        ));
        let binding = escrow_binding(&CONTEXT, &[50; 32], b"source", b"recipient", b"refund", 200);
        let mut create = entry(3, &[22], &[3]);
        create.escrow_create = Some(EscrowCreate {
            address: [50; 32],
            binding,
            refund_after_global_frame: 200,
        });
        assert!(matches!(
            commit_entry(&state, 101, &APP, &create, SHARD).unwrap(),
            Outcome::Committed { .. }
        ));
        let claim = |tx: u8, address: u8, binding: [u8; 32], refund: bool| {
            let mut claim = entry(tx, &[], &[4]);
            claim.escrow_claim = Some(EscrowClaim {
                address: [address; 32],
                binding,
                refund,
            });
            claim
        };
        assert!(matches!(
            commit_entry(&state, 102, &APP, &claim(4, 50, binding, false), SHARD).unwrap(),
            Outcome::Committed { .. }
        ));
        let mut rooted = entry(5, &[23], &[5]);
        rooted.root_digest = Some([9; 32]);
        let mut again = entry(6, &[24], &[6]);
        again.escrow_create = create.escrow_create.clone();
        let binding_51 =
            escrow_binding(&CONTEXT, &[51; 32], b"source", b"recipient", b"refund", 300);
        let mut create_51 = entry(8, &[26], &[8]);
        create_51.escrow_create = Some(EscrowCreate {
            address: [51; 32],
            binding: binding_51,
            refund_after_global_frame: 300,
        });
        assert!(matches!(
            commit_entry(&state, 103, &APP, &create_51, SHARD).unwrap(),
            Outcome::Committed { .. }
        ));
        let cases = [
            ("decided", first.clone(), "operation already decided"),
            ("context", foreign, "context differs from the application's"),
            (
                "root",
                rooted,
                "root is not in the application's canonical history",
            ),
            ("consumed", entry(9, &[20], &[9]), "already consumed"),
            (
                "absent escrow",
                claim(10, 52, binding, false),
                "escrow does not exist",
            ),
            (
                "claimed escrow",
                claim(11, 50, binding, false),
                "escrow already consumed",
            ),
            (
                "binding",
                claim(12, 51, [0; 32], false),
                "claim does not match the escrow",
            ),
            (
                "early refund",
                claim(13, 51, binding_51, true),
                "refund before the escrow's refund frame",
            ),
            ("escrow exists", again, "escrow already exists"),
        ];
        for (name, refused, reason) in cases {
            assert_eq!(
                refusal(&state, 110, &APP, &refused, SHARD).unwrap(),
                Some(reason),
                "{name}"
            );
            let outcome = commit_entry(&state, 110, &APP, &refused, SHARD).unwrap();
            if name == "decided" {
                assert_eq!(outcome, Outcome::AlreadyDecided, "{name}");
            } else {
                assert_eq!(outcome, Outcome::Rejected(reason), "{name}");
            }
        }
        let open = claim(14, 51, binding_51, false);
        assert_eq!(refusal(&state, 111, &APP, &open, SHARD).unwrap(), None);
        assert!(matches!(
            commit_entry(&state, 111, &APP, &open, SHARD).unwrap(),
            Outcome::Committed { .. }
        ));
        // Every fixture output lands in one block; fill it.
        let full = entry(7, &[25], &[7]);
        let width = placement_width(&state, &APP).unwrap();
        let block = coin_blocks::block_for_address(width, &output(7)).unwrap();
        records::write_record(
            &state,
            111,
            &block_sequence_address(&APP, block).unwrap(),
            &[
                kind_field(KIND_SEQUENCE).unwrap(),
                (vec![0], BLOCK_CAPACITY.to_be_bytes().to_vec()),
            ],
        )
        .unwrap();
        assert_eq!(
            refusal(&state, 112, &APP, &full, SHARD).unwrap(),
            Some("block is full")
        );
        assert_eq!(
            commit_entry(&state, 112, &APP, &full, SHARD).unwrap(),
            Outcome::Rejected("block is full")
        );
    }

    /// Class guard (filing gate, section 3): every reason [`commit_entry`]
    /// rejects for is read ahead of the commit by [`precheck`] (lasting or
    /// pending: the checks of [`state_refusals`]), so no node verifies a
    /// proof for it; or it is classed here with the reason no node can read
    /// it before the proof work. A new refusal fails this test until it is
    /// one or the other, and the global venue's [`refusal`] reads each.
    #[test]
    fn every_commit_refusal_is_prechecked_or_classed() {
        const CLASSED: [(&str, &str); 3] = [
            (
                "context differs from the application's",
                "never past preflight: an operation's context is its network's with the \
                 application, dispatch decodes it against the node's own network before any \
                 proof work, and so every committed entry, and the context record the first \
                 one writes, carries that network's context",
            ),
            (
                "escrow already exists",
                "frame-dependent: the escrow's address binds the frame that executes the \
                 operation, unknown ahead of it",
            ),
            (
                "block is full",
                "frame-dependent: output addresses bind the executing frame, and the width \
                 and sequences are the committing frame's",
            ),
        ];
        let source = guard_source(include_str!("global_commit.rs"));
        let body = guard_body;
        /// The string literals `text` passes to `call` (`call` ends `("`).
        fn literals(text: &str, call: &str) -> Vec<String> {
            text.match_indices(call)
                .map(|(at, _)| {
                    let rest = &text[at + call.len()..];
                    rest[..rest.find('"').expect("end of the literal")].to_string()
                })
                .collect()
        }
        // The commit's literal refusals that are neither read ahead nor
        // classed (its state refusals reach it as one computed reason).
        let unclassed = |source: &str| -> Vec<String> {
            literals(body(source, "pub fn commit_entry"), "reject(\"")
                .into_iter()
                .filter(|reason| !CLASSED.iter().any(|(classed, _)| classed == reason))
                .collect()
        };
        let commit = body(&source, "pub fn commit_entry");
        let rejected = literals(commit, "reject(\"");
        let state_checks = body(&source, "fn state_refusals");
        let mut prechecked = literals(state_checks, "Standing::Lasting(\"");
        prechecked.extend(literals(state_checks, "Standing::Pending(\""));
        assert!(
            prechecked.len() >= 6,
            "state_refusals' reasons not found: {prechecked:?}"
        );
        assert_eq!(
            commit.matches("reject(reason)").count(),
            1,
            "the commit rejects for a computed reason other than state_refusals' first"
        );
        assert!(commit.contains("state_refusals("));
        let unread = unclassed(&source);
        assert!(
            unread.is_empty(),
            "commit_entry rejects for {unread:?}, which no node reads before verifying the \
             operation's proof: read it in state_refusals (lasting or pending), or class it \
             here with why it cannot be read ahead"
        );
        for (classed, why) in CLASSED {
            assert!(
                rejected.iter().any(|reason| reason == classed),
                "{classed:?} ({why}) is no longer a commit refusal: drop it here"
            );
        }
        // The guard catches a refusal added to the commit.
        let planted = source.replacen(
            "return reject(\"block is full\");",
            "return reject(\"planted refusal\");\nreturn reject(\"block is full\");",
            1,
        );
        assert_eq!(unclassed(&planted), ["planted refusal"]);
        let venue = body(&source, "pub fn refusal");
        let mut read_ahead = literals(venue, "Some(\"");
        read_ahead.extend(literals(venue, "then_some(\""));
        assert!(venue.contains("state_refusals("));
        for reason in &rejected {
            assert!(
                read_ahead.contains(reason),
                "the global venue does not read {reason:?} before the proof"
            );
        }
        // Refusals that are not a literal `reject`: the shape of the commit
        // ahead of its writes.
        let faults = commit_shape_faults(&source);
        assert!(
            faults.is_empty(),
            "commit_entry refuses in a way no node reads before the proof: {faults:?}"
        );
        let planted = source.replacen(
            "    // Commit.\n",
            "    if planted_check(state)? { return Ok(Outcome::Rejected(\"planted\")); }\n\
             return Err(QuilError::InvalidArgument(\"planted\".into()));\n\
             return reject(computed);\n    // Commit.\n",
            1,
        );
        assert_eq!(
            commit_shape_faults(&planted).len(),
            4,
            "the guard missed a planted refusal: {:?}",
            commit_shape_faults(&planted)
        );
    }

    /// How [`commit_entry`], in guard source `source`, refuses other than by
    /// a literal `reject` before its writes (`// Commit.`), or by the one
    /// computed reason [`state_refusals`] gives: an `Outcome::Rejected` not
    /// built by its `reject`, a `reject` of another computed reason, an
    /// error it builds, or a call whose error `?` returns that the global
    /// venue's [`refusal`] does not make too (writes and the encodings of
    /// what it writes excepted). Each is a refusal no node reads before
    /// verifying the operation's proof.
    fn commit_shape_faults(source: &str) -> Vec<String> {
        /// Calls of the commit whose errors are not refusals: its writes,
        /// and the encodings of what it writes (`raise_placement_width`
        /// writes the width `refusal` reads with `placement_width`).
        const WRITES: [&str; 4] = [
            "records::write_record",
            "kind_field",
            "decision_fields",
            "raise_placement_width",
        ];
        let commit = guard_body(source, "pub fn commit_entry");
        let venue = guard_body(source, "pub fn refusal");
        let checks = &commit[..commit.find("// Commit.").expect("the commit's writes")];
        let mut faults = Vec::new();
        let built = commit.matches("Outcome::Rejected(").count();
        if built != 1 {
            faults.push(format!(
                "{built} Outcome::Rejected built, 1 expected (its reject)"
            ));
        }
        let computed = commit.matches("reject(").count() - commit.matches("reject(\"").count();
        if computed != 1 {
            faults.push(format!(
                "{computed} rejects of a computed reason, 1 expected (state_refusals')"
            ));
        }
        if checks.contains("Err(") {
            faults.push("an error built before its writes".into());
        }
        for call in guard_fallible_calls(checks) {
            if !WRITES.contains(&call.as_str()) && !venue.contains(&format!("{call}(")) {
                faults.push(format!(
                    "{call}: its error is a refusal refusal() does not read"
                ));
            }
        }
        faults
    }

    /// A batch shield commits every source or none: one already-shielded
    /// source rejects the whole batch and consumes nothing else.
    #[test]
    fn a_batch_shield_commits_all_of_its_sources_or_none() {
        set_batch_shield_frame_for_thread(Some(100));
        let state = mem_state();
        let shield = |tx: u8, markers: std::ops::Range<u8>, out: u8| {
            let markers: Vec<u8> = markers.collect();
            let mut batch = entry(tx, &markers, &[out]);
            batch.kind = crate::token_engine::TYPE_LATTICE_SHIELD;
            batch
        };
        let first = shield(1, 10..50, 1);
        assert!(
            commit_entry(&state, 99, &APP, &first, SHARD).is_err(),
            "40 sources before activation"
        );
        assert!(matches!(
            commit_entry(&state, 100, &APP, &first, SHARD).unwrap(),
            Outcome::Committed { .. }
        ));
        assert!((10..50).all(|m| is_consumed(&state, &APP, &[m; 32]).unwrap()));
        // Overlapping one consumed source: rejected whole.
        let overlapping = shield(2, 49..80, 2);
        assert_eq!(
            commit_entry(&state, 101, &APP, &overlapping, SHARD).unwrap(),
            Outcome::Rejected("already consumed")
        );
        assert!((50..80).all(|m| !is_consumed(&state, &APP, &[m; 32]).unwrap()));
        assert!(matches!(
            commit_entry(&state, 102, &APP, &shield(3, 50..80, 3), SHARD).unwrap(),
            Outcome::Committed { .. }
        ));
        set_batch_shield_frame_for_thread(None);
    }

    /// A mint claim's fee is paid, and credited, with the reward mint it
    /// claims: when the claim commits, the relay credits it no second time.
    /// Runs at the committed-credit frame, set the way a test network sets
    /// it; a build without that rule ignores the setting.
    #[test]
    fn reproduces_double_credited_mint_claim_fee() {
        const FRAME: u64 = 1 << 40;
        std::env::set_var("QUIL_COMMITTED_CREDIT_FRAME", FRAME.to_string());
        let mut claim = entry(2, &[30], &[]);
        claim.kind = crate::token_engine::TYPE_LATTICE_MINT_CLAIM;
        claim.fee = 9;
        let relayed = vec![
            entry(1, &[20], &[]).encode().unwrap(),
            claim.encode().unwrap(),
        ];
        let relay = crate::token_intrinsic::spend_relay::encode_relay(&[(40, relayed)]).unwrap();
        let state = mem_state();
        let credited = materialize_relay(&state, FRAME, &APP, 41, &relay).unwrap();
        assert!(
            is_consumed(&state, &APP, &[30; 32]).unwrap(),
            "the mint claim commits"
        );
        assert_eq!(
            credited, 5,
            "a committed mint claim's fee is credited a second time"
        );
    }
}
