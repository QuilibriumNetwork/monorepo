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
use super::{coin_blocks, global_accumulator as records, roots, settlement_record::{self, SettlementEntry}};
use crate::hypergraph_state::HypergraphState;
use quil_types::error::{QuilError, Result};
use std::collections::BTreeSet;

pub const ENTRY_VERSION: &[u8; 8] = b"QCT3SE\0\x01";
/// Consume-once markers one operation may spend.
pub const MAX_CONSUMPTIONS: usize = 16;
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
    fn validate(&self) -> Result<()> {
        if self.consumptions.len() > MAX_CONSUMPTIONS || self.outputs.len() > MAX_OUTPUTS {
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

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
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
                bytes.extend_from_slice(&settlement_record::encode_entries(std::slice::from_ref(entry))?);
            }
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        if r.take(8)? != ENTRY_VERSION {
            return Err(invalid("version"));
        }
        let kind = u32::from_be_bytes(r.array()?);
        let tx_id = r.array()?;
        let source_frame = u64::from_be_bytes(r.array()?);
        let context = r.array()?;
        let root_digest = if r.flag()? { Some(r.array()?) } else { None };
        let consumptions = r.list(MAX_CONSUMPTIONS)?;
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
            Some(EscrowClaim { address: r.array()?, binding: r.array()?, refund: r.flag()? })
        } else {
            None
        };
        let fee = u128::from_be_bytes(r.array()?);
        let settlement = if r.flag()? {
            let mut entries = settlement_record::decode_entries(r.take(settlement_record::ENTRY_BYTES)?)?;
            Some(entries.pop().ok_or_else(|| invalid("empty settlement"))?)
        } else {
            None
        };
        if !r.0.is_empty() {
            return Err(invalid("trailing bytes"));
        }
        let entry = Self { kind, tx_id, source_frame, context, root_digest, consumptions, outputs, escrow_create, escrow_claim, fee, settlement };
        entry.validate()?;
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
    records::hash(&[b"quil/commit/block-sequence/v1\0", application, &block.to_be_bytes()])
}
pub fn delivery_address(application: &[u8; 32], block: u64, seq: u64) -> Result<[u8; 32]> {
    records::hash(&[b"quil/commit/delivery/v1\0", application, &block.to_be_bytes(), &seq.to_be_bytes()])
}
pub fn escrow_sequence_address(application: &[u8; 32], block: u64) -> Result<[u8; 32]> {
    records::hash(&[b"quil/commit/escrow-sequence/v1\0", application, &block.to_be_bytes()])
}
pub fn escrow_delivery_address(application: &[u8; 32], block: u64, seq: u64) -> Result<[u8; 32]> {
    records::hash(&[b"quil/commit/escrow-delivery/v1\0", application, &block.to_be_bytes(), &seq.to_be_bytes()])
}

pub fn placement_width_address(application: &[u8; 32]) -> Result<[u8; 32]> {
    records::hash(&[b"quil/commit/placement-width/v1\0", application])
}
pub fn orphan_address(application: &[u8; 32], block: u64) -> Result<[u8; 32]> {
    records::hash(&[b"quil/commit/orphan/v1\0", application, &block.to_be_bytes()])
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

fn read(state: &HypergraphState, address: &[u8; 32], tag: &str, keys: &[&[u8]]) -> Result<Option<Vec<Vec<u8>>>> {
    records::read_record(state, address, &records::kind(tag)?, keys)
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| invalid("malformed record field"))
}

/// Whether the global commit has decided operation `tx_id` of `application`
/// (committed or rejected; either is final).
pub fn is_decided(state: &HypergraphState, application: &[u8; 32], tx_id: &[u8; 32]) -> Result<bool> {
    Ok(read(state, &decision_address(application, tx_id)?, KIND_DECISION, &[&[0]])?.is_some())
}

/// Whether `marker` is consumed in `application`.
pub fn is_consumed(state: &HypergraphState, application: &[u8; 32], marker: &[u8; 32]) -> Result<bool> {
    Ok(read(state, &consumed_address(application, marker)?, KIND_CONSUMED, &[&[0]])?.is_some())
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
    let width = match read(state, &placement_width_address(application)?, KIND_PLACEMENT_WIDTH, &[&[0]])? {
        Some(fields) => match fields[0].as_slice() {
            [width] => *width,
            _ => return Err(QuilError::Store("corrupt placement width record".into())),
        },
        None => coin_blocks::INITIAL_BLOCK_BITS,
    };
    if !(coin_blocks::INITIAL_BLOCK_BITS..=coin_blocks::MAX_BLOCK_BITS).contains(&width) {
        return Err(QuilError::Store("placement width record outside the accumulator's range".into()));
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
    records::write_record(state, frame, &placement_width_address(application)?, &[
        kind_field(KIND_PLACEMENT_WIDTH)?,
        (vec![0], vec![wanted]),
    ])?;
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
pub fn committed_to_shard(state: &HypergraphState, application: &[u8; 32], shard: &[bool]) -> Result<u64> {
    let width = placement_width(state, application)?;
    let owned = coin_blocks::owned_blocks(shard, width).try_fold(0u64, |total, block| {
        let here = block_sequence(state, application, block)?
            .saturating_add(escrow_sequence(state, application, block)?);
        Ok::<u64, QuilError>(total.saturating_add(here))
    })?;
    // An orphan awaiting its attestation counts for the shard holding its
    // records, so that shard is staffed and can attest it.
    ancestor_blocks(shard).filter(|block| holds_block_records(shard, *block)).try_fold(owned, |total, block| {
        let awaiting = orphan(state, application, block)?.is_some_and(|orphan| !orphan.moved);
        if !awaiting {
            return Ok(total);
        }
        let here = block_sequence(state, application, block)?
            .saturating_add(escrow_sequence(state, application, block)?);
        Ok(total.saturating_add(here))
    })
}

/// The next delivery sequence of `block`: how many outputs have been committed to it.
pub fn block_sequence(state: &HypergraphState, application: &[u8; 32], block: u64) -> Result<u64> {
    match read(state, &block_sequence_address(application, block)?, KIND_SEQUENCE, &[&[0]])? {
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
pub fn delivery(state: &HypergraphState, application: &[u8; 32], block: u64, seq: u64) -> Result<Option<Delivery>> {
    read_delivery(state, &delivery_address(application, block, seq)?, KIND_DELIVERY)
}

/// How many escrows have been committed into `block`.
pub fn escrow_sequence(state: &HypergraphState, application: &[u8; 32], block: u64) -> Result<u64> {
    match read(state, &escrow_sequence_address(application, block)?, KIND_ESCROW_SEQUENCE, &[&[0]])? {
        Some(fields) => Ok(u64::from_be_bytes(fixed(&fields[0])?)),
        None => Ok(0),
    }
}

/// A committed escrow awaiting delivery: `(address, source frame, tx id)`.
pub fn escrow_delivery(state: &HypergraphState, application: &[u8; 32], block: u64, seq: u64) -> Result<Option<Delivery>> {
    read_delivery(state, &escrow_delivery_address(application, block, seq)?, KIND_ESCROW_DELIVERY)
}

fn read_delivery(state: &HypergraphState, address: &[u8; 32], kind: &str) -> Result<Option<Delivery>> {
    // A re-placed output is delivered from its new block; its old record no
    // longer names a delivery.
    let moved = if kind == KIND_DELIVERY { KIND_DELIVERY_MOVED } else { KIND_ESCROW_DELIVERY_MOVED };
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
        root: quil_tries::deserialize_go_tree(blob).map_err(|_| invalid("malformed escrow record"))?,
    };
    if tree.get(&[0xff; 32]) != Some(records::kind(KIND_ESCROW)?.as_slice()) {
        return Err(invalid("not an escrow record"));
    }
    let field = |key: u8| tree.get(&[key]).ok_or_else(|| invalid("escrow record missing a field"));
    let consumed = match field(8)? {
        [0] => false,
        [1] => true,
        _ => return Err(invalid("malformed escrow record")),
    };
    Ok((fixed(field(0)?)?, u64::from_be_bytes(fixed(field(4)?)?), consumed))
}

/// An escrow's GLOBAL record: `(binding, refund frame, consumed)`.
pub fn escrow(state: &HypergraphState, application: &[u8; 32], escrow: &[u8; 32]) -> Result<Option<([u8; 32], u64, bool)>> {
    let Some(fields) = read(state, &escrow_address(application, escrow)?, KIND_ESCROW, &[&[0], &[4], &[8]])? else {
        return Ok(None);
    };
    Ok(Some((fixed(&fields[0])?, u64::from_be_bytes(fixed(&fields[1])?), fields[2] == [1])))
}

// ---- outputs orphaned by a split ----------------------------------------

/// The GLOBAL frame from which a split re-places the undelivered outputs of a
/// block it leaves without a whole owner. Consensus-affecting for GLOBAL and
/// for every application shard's report, which switch together. Off (never)
/// unless `QUIL_ORPHAN_REPLACE_FRAME` names a frame; on mainnet it is
/// [`MAINNET_RELEASE_ACTIVATION_FRAME`].
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
    setting.and_then(|value| value.parse().ok()).unwrap_or(u64::MAX)
}

/// Fix this process's re-placement frame from its network, and return it.
/// Called at startup before any frame is processed; the first call decides.
pub fn init_orphan_replacement_frame(network: u8) -> u64 {
    *ORPHAN_REPLACEMENT_FRAME.get_or_init(|| {
        release_activation_frame(network, std::env::var("QUIL_ORPHAN_REPLACE_FRAME").ok().as_deref())
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
        relay_activation_for(network, std::env::var("QUIL_RELAY_ACTIVATION_FRAME").ok().as_deref())
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
        std::env::var("QUIL_RELAY_ACTIVATION_FRAME").ok().and_then(|value| value.parse().ok()).unwrap_or(0)
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

pub fn orphan(state: &HypergraphState, application: &[u8; 32], block: u64) -> Result<Option<Orphan>> {
    let Some(fields) = read(state, &orphan_address(application, block)?, KIND_ORPHAN, &[&[0], &[4], &[8], &[12]])? else {
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

fn write_orphan(state: &HypergraphState, frame: u64, application: &[u8; 32], block: u64, orphan: &Orphan) -> Result<()> {
    records::write_record(state, frame, &orphan_address(application, block)?, &[
        kind_field(KIND_ORPHAN)?,
        (vec![0], orphan.since.to_be_bytes().to_vec()),
        (vec![4], vec![u8::from(orphan.moved)]),
        (vec![8], orphan.coins.to_be_bytes().to_vec()),
        (vec![12], orphan.escrows.to_be_bytes().to_vec()),
    ])
}

fn path_value(bits: &[bool]) -> u64 {
    bits.iter().fold(0u64, |acc, bit| (acc << 1) | u64::from(*bit))
}

/// The blocks on `shard`'s own path narrower than the shard: the only blocks a
/// split can leave without a whole owner beneath it.
fn ancestor_blocks(shard: &[bool]) -> impl Iterator<Item = u64> + '_ {
    let top = shard.len().min(usize::from(coin_blocks::MAX_BLOCK_BITS) + 1);
    (usize::from(coin_blocks::INITIAL_BLOCK_BITS)..top)
        .filter_map(move |width| coin_blocks::block_id(width as u8, path_value(&shard[..width])).ok())
}

/// Whether `shard` holds `block`'s own records (its frontier and escrow
/// count, at `state::block_record_address`): the one shard that can attest
/// what the block received.
pub fn holds_block_records(shard: &[bool], block: u64) -> bool {
    let address = super::state::block_record_address(super::state::BLOCK_FRONTIER_TAG, block);
    shard.len() <= 256
        && shard.iter().enumerate().all(|(bit, want)| (address[bit / 8] >> (7 - bit % 8)) & 1 == u8::from(*want))
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
        let owned = registered.iter().any(|shard| coin_blocks::shard_owns_block(shard, block));
        match orphan(state, application, block)? {
            Some(existing) if owned && !existing.moved => {
                records::clear_record(state, frame, &orphan_address(application, block)?)?;
                released += 1;
            }
            Some(_) => {}
            None if owned => {}
            None => {
                if block_sequence(state, application, block)? + escrow_sequence(state, application, block)? > 0 {
                    write_orphan(state, frame, application, block, &Orphan { since: frame, moved: false, coins: 0, escrows: 0 })?;
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
    let Some(existing) = orphan(state, application, block)? else { return Ok(false) };
    if existing.moved {
        if (existing.coins, existing.escrows) != (coins, escrows) {
            return Err(invalid("an orphaned block attested with different counts"));
        }
        return Ok(false);
    }
    let (committed, committed_escrows) = (block_sequence(state, application, block)?, escrow_sequence(state, application, block)?);
    if coins > committed || escrows > committed_escrows {
        return Err(invalid("an orphaned block attested more than was committed to it"));
    }
    let width = placement_width(state, application)?;
    let mut sequences: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
    let mut escrow_sequences: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
    for escrow in [false, true] {
        let (from, to) = if escrow { (escrows, committed_escrows) } else { (coins, committed) };
        for seq in from..to {
            let old = if escrow { escrow_delivery_address(application, block, seq)? } else { delivery_address(application, block, seq)? };
            let record = if escrow { escrow_delivery(state, application, block, seq)? } else { delivery(state, application, block, seq)? }
                .ok_or_else(|| invalid("an orphaned block is missing a committed delivery"))?;
            let target = coin_blocks::block_for_address(width, &record.address)?;
            let next = if escrow {
                match escrow_sequences.get(&target) { Some(next) => *next, None => escrow_sequence(state, application, target)? }
            } else {
                match sequences.get(&target) { Some(next) => *next, None => block_sequence(state, application, target)? }
            };
            if next >= BLOCK_CAPACITY {
                return Err(invalid("block is full"));
            }
            let (new, delivery_kind, moved_kind) = if escrow {
                escrow_sequences.insert(target, next + 1);
                (escrow_delivery_address(application, target, next)?, KIND_ESCROW_DELIVERY, KIND_ESCROW_DELIVERY_MOVED)
            } else {
                sequences.insert(target, next + 1);
                (delivery_address(application, target, next)?, KIND_DELIVERY, KIND_DELIVERY_MOVED)
            };
            records::write_record(state, frame, &new, &[
                kind_field(delivery_kind)?,
                (vec![0], record.address.to_vec()),
                (vec![4], record.source_frame.to_be_bytes().to_vec()),
                (vec![8], record.tx_id.to_vec()),
                (vec![12], record.source_shard.to_bytes().to_vec()),
            ])?;
            records::write_record(state, frame, &old, &[
                kind_field(moved_kind)?,
                (vec![0], record.address.to_vec()),
                (vec![4], target.to_be_bytes().to_vec()),
                (vec![8], next.to_be_bytes().to_vec()),
            ])?;
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
        records::write_record(state, frame, &block_sequence_address(application, *target)?, &[
            kind_field(KIND_SEQUENCE)?,
            (vec![0], next.to_be_bytes().to_vec()),
        ])?;
    }
    for (target, next) in &escrow_sequences {
        records::write_record(state, frame, &escrow_sequence_address(application, *target)?, &[
            kind_field(KIND_ESCROW_SEQUENCE)?,
            (vec![0], next.to_be_bytes().to_vec()),
        ])?;
    }
    write_orphan(state, frame, application, block, &Orphan { since: existing.since, moved: true, coins, escrows })?;
    tracing::info!(frame, application = %hex::encode(&application[..8]), block,
        moved = (committed - coins) + (committed_escrows - escrows), coins, escrows, width,
        "orphaned coin block re-placed at the current width");
    Ok(true)
}

/// Decide one relayed entry for `application` at global frame `frame`.
pub fn commit_entry(
    state: &HypergraphState,
    frame: u64,
    application: &[u8; 32],
    entry: &SpendEntry,
    source_shard: quil_types::execution::ShardPath,
) -> Result<Outcome> {
    entry.validate()?;
    let decision = decision_address(application, &entry.tx_id)?;
    if read(state, &decision, KIND_DECISION, &[&[0]])?.is_some() {
        return Ok(Outcome::AlreadyDecided);
    }
    let reject = |reason: &'static str| -> Result<Outcome> {
        records::write_record(state, frame, &decision, &[
            kind_field(KIND_DECISION)?,
            (vec![0], vec![0]),
            (vec![4], frame.to_be_bytes().to_vec()),
            (vec![8], reason.as_bytes().to_vec()),
        ])?;
        Ok(Outcome::Rejected(reason))
    };

    // One application, one network's parameters.
    match read(state, &context_address(application)?, KIND_CONTEXT, &[&[0]])? {
        Some(fields) if fields[0] != entry.context => return reject("context differs from the application's"),
        Some(_) => {}
        None => records::write_record(state, frame, &context_address(application)?, &[
            kind_field(KIND_CONTEXT)?,
            (vec![0], entry.context.to_vec()),
        ])?,
    }

    if let Some(digest) = &entry.root_digest {
        let retained = match records::read_root_history(state, application)? {
            Some(history) => roots::history_retains_digest(&history, &entry.context, digest)?,
            None => false,
        };
        if !retained {
            return reject("root is not in the application's canonical history");
        }
    }
    for marker in &entry.consumptions {
        if is_consumed(state, application, marker)? {
            return reject("already consumed");
        }
    }
    if let Some(claim) = &entry.escrow_claim {
        match escrow(state, application, &claim.address)? {
            None => return reject("escrow does not exist"),
            Some((_, _, true)) => return reject("escrow already consumed"),
            Some((binding, _, _)) if binding != claim.binding => return reject("claim does not match the escrow"),
            Some((_, refund_after, _)) if claim.refund && frame < refund_after => return reject("refund before the escrow's refund frame"),
            Some(_) => {}
        }
    }
    if let Some(create) = &entry.escrow_create {
        if escrow(state, application, &create.address)?.is_some() {
            return reject("escrow already exists");
        }
    }
    // A shard that commits an operation exists, whatever route registered it:
    // an application whose grid was already deep before this record existed
    // (mainnet QUIL sits at depth nine) reaches its width on its first
    // operation instead of waiting for a split that will never come.
    let width = raise_placement_width(state, frame, application, source_shard.bits().map_or(0, |bits| bits.len()))?;
    let mut placements = Vec::with_capacity(entry.outputs.len());
    let mut sequences: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
    for address in &entry.outputs {
        let block = coin_blocks::block_for_address(width, address)?;
        let next = match sequences.get(&block) {
            Some(next) => *next,
            None => block_sequence(state, application, block)?,
        };
        if next >= BLOCK_CAPACITY {
            return reject("block is full");
        }
        sequences.insert(block, next + 1);
        placements.push(Placement { address: *address, block, seq: next });
    }

    // Commit.
    for marker in &entry.consumptions {
        records::write_record(state, frame, &consumed_address(application, marker)?, &[
            kind_field(KIND_CONSUMED)?,
            (vec![0], entry.tx_id.to_vec()),
        ])?;
    }
    if let Some(claim) = &entry.escrow_claim {
        let (binding, refund_after, _) = escrow(state, application, &claim.address)?.expect("checked above");
        write_escrow(state, frame, application, &claim.address, &binding, refund_after, true)?;
    }
    let mut escrow_placement = None;
    if let Some(create) = &entry.escrow_create {
        write_escrow(state, frame, application, &create.address, &create.binding, create.refund_after_global_frame, false)?;
        // Queued for delivery to the shard owning the escrow's block, so its
        // recipient can discover it there.
        let block = coin_blocks::block_for_address(width, &create.address)?;
        let seq = escrow_sequence(state, application, block)?;
        escrow_placement = Some(Placement { address: create.address, block, seq });
        records::write_record(state, frame, &escrow_delivery_address(application, block, seq)?, &[
            kind_field(KIND_ESCROW_DELIVERY)?,
            (vec![0], create.address.to_vec()),
            (vec![4], entry.source_frame.to_be_bytes().to_vec()),
            (vec![8], entry.tx_id.to_vec()),
            (vec![12], source_shard.to_bytes().to_vec()),
        ])?;
        records::write_record(state, frame, &escrow_sequence_address(application, block)?, &[
            kind_field(KIND_ESCROW_SEQUENCE)?,
            (vec![0], (seq + 1).to_be_bytes().to_vec()),
        ])?;
    }
    for placement in &placements {
        records::write_record(state, frame, &delivery_address(application, placement.block, placement.seq)?, &[
            kind_field(KIND_DELIVERY)?,
            (vec![0], placement.address.to_vec()),
            (vec![4], entry.source_frame.to_be_bytes().to_vec()),
            (vec![8], entry.tx_id.to_vec()),
            (vec![12], source_shard.to_bytes().to_vec()),
        ])?;
    }
    for (block, next) in &sequences {
        records::write_record(state, frame, &block_sequence_address(application, *block)?, &[
            kind_field(KIND_SEQUENCE)?,
            (vec![0], next.to_be_bytes().to_vec()),
        ])?;
    }
    if let Some(settlement) = &entry.settlement {
        let address = settlement.receipt;
        let disc = crate::hypergraph_state::vertex_adds_discriminator()?;
        let global = crate::global_schema::GLOBAL_INTRINSIC_ADDRESS;
        if state.get(&global, &address, &disc)?.is_none_or(|blob| blob.is_empty()) {
            state.set(&global, &address, &disc, frame, settlement_record::create_record(settlement)?)?;
        }
    }
    records::write_record(state, frame, &decision, &[
        kind_field(KIND_DECISION)?,
        (vec![0], vec![1]),
        (vec![4], frame.to_be_bytes().to_vec()),
        (vec![8], Vec::new()),
    ])?;
    Ok(Outcome::Committed { fee: entry.fee, placements, escrow: escrow_placement })
}

/// Structural check of a header's spend relay: canonical, inside the header's
/// window, and every entry a relayed operation type.
pub fn verify_relay(header_frame: u64, relay: &[u8]) -> Result<Vec<(u64, Vec<SpendEntry>)>> {
    super::spend_relay::decode_relay(header_frame, relay)?
        .into_iter()
        .map(|(frame, entries)| {
            let entries = entries
                .iter()
                .map(|bytes| {
                    let entry = SpendEntry::decode(bytes)?;
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

/// Commit every entry a certified header relays, in relay order, returning
/// the fees of the operations that committed (credited to the relaying
/// shard's provers). Re-carried entries are already decided and add nothing.
pub fn materialize_relay(state: &HypergraphState, frame: u64, filter: &[u8], header_frame: u64, relay: &[u8]) -> Result<u128> {
    if relay.is_empty() {
        return Ok(0);
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
    let mut fees = 0u128;
    let (mut committed, mut rejected) = (0usize, 0usize);
    for (_, entries) in verify_relay(header_frame, relay)? {
        for entry in entries {
            match commit_entry(state, frame, &application, &entry, source_shard)? {
                Outcome::Committed { fee, .. } => {
                    fees = fees.saturating_add(fee);
                    committed += 1;
                }
                Outcome::Rejected(reason) => {
                    rejected += 1;
                    tracing::info!(
                        frame,
                        application = %hex::encode(&application[..8]),
                        tx = %hex::encode(&entry.tx_id[..8]),
                        reason,
                        "spend rejected by the global commit",
                    );
                }
                Outcome::AlreadyDecided => {}
            }
        }
    }
    if committed > 0 {
        tracing::info!(frame, application = %hex::encode(&application[..8]), committed, rejected, fees, "spends committed");
    }
    Ok(fees)
}

fn escrow_fields(binding: &[u8; 32], refund_after: u64, consumed: bool) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    Ok(vec![
        kind_field(KIND_ESCROW)?,
        (vec![0], binding.to_vec()),
        (vec![4], refund_after.to_be_bytes().to_vec()),
        (vec![8], vec![u8::from(consumed)]),
    ])
}

/// The blob of an escrow record, exactly as the commit stores it.
pub fn encode_escrow_record(binding: &[u8; 32], refund_after: u64, consumed: bool) -> Result<Vec<u8>> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    for (key, value) in escrow_fields(binding, refund_after, consumed)? {
        tree.insert(&key, &value, &[], &num_bigint::BigInt::from(value.len()))?;
    }
    quil_tries::serialize_go_tree(tree.root.as_ref()).map_err(|_| invalid("cannot encode escrow record"))
}

fn write_escrow(state: &HypergraphState, frame: u64, application: &[u8; 32], address: &[u8; 32], binding: &[u8; 32], refund_after: u64, consumed: bool) -> Result<()> {
    records::write_record(state, frame, &escrow_address(application, address)?, &escrow_fields(binding, refund_after, consumed)?)
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
        assert_eq!(super::release_activation_frame(1, None), u64::MAX, "a test network re-places nothing by default");
        assert_eq!(super::release_activation_frame(1, Some("230")), 230);
        assert_eq!(super::relay_activation_for(1, None), 0, "a test network relays from genesis by default");
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
        committed.escrow_create = Some(EscrowCreate { address: escrow, binding: [3; 32], refund_after_global_frame: 50 });
        assert!(matches!(commit_entry(&state, 5, &APP, &committed, seven).unwrap(), Outcome::Committed { .. }));
        let block = coin_blocks::block_for_address(7, &output(2)).unwrap();
        assert_eq!(block, 130);
        assert_eq!((block_sequence(&state, &APP, block).unwrap(), escrow_sequence(&state, &APP, block).unwrap()), (3, 1));
        raise_placement_width(&state, 6, &APP, 8).unwrap();
        (state, vec![output(2), output(3), output(4)])
    }

    #[test]
    fn a_split_past_a_block_width_orphans_its_undelivered_outputs() {
        let (state, _) = orphaned_fixture();
        let (held, other) = (bits("00000100"), bits("00000101"));
        assert!(holds_block_records(&held, 130) && !holds_block_records(&other, 130));
        let (marked, released) = reconcile_orphans(&state, 6, &APP, &[held.clone(), other.clone()], &[bits("0000010")]).unwrap();
        assert_eq!((marked, released), (1, 0), "only block 130 holds committed outputs");
        assert_eq!(orphan(&state, &APP, 130).unwrap(), Some(Orphan { since: 6, moved: false, coins: 0, escrows: 0 }));
        // The holder counts it, so it is staffed and can attest.
        assert_eq!(committed_to_shard(&state, &APP, &held).unwrap(), 4);
        assert_eq!(committed_to_shard(&state, &APP, &other).unwrap(), 0);
        // Reconciling again changes nothing; a merge back releases it whole.
        assert_eq!(reconcile_orphans(&state, 7, &APP, &[held.clone(), other.clone()], &[]).unwrap(), (0, 0));
        assert_eq!(reconcile_orphans(&state, 8, &APP, &[bits("0000010")], &[held, other]).unwrap(), (0, 1));
        assert_eq!(orphan(&state, &APP, 130).unwrap(), None);
        assert!(delivery(&state, &APP, 130, 2).unwrap().is_some(), "its owner delivers it as before");
    }

    #[test]
    fn an_attested_orphan_is_re_placed_exactly_once() {
        let (state, outputs) = orphaned_fixture();
        let children = [bits("00000100"), bits("00000101")];
        reconcile_orphans(&state, 6, &APP, &children, &[bits("0000010")]).unwrap();
        assert!(apply_orphan_attestation(&state, 7, &APP, 130, 4, 0).is_err(), "more than was committed");
        // The parent delivered the first coin and no escrow.
        assert!(apply_orphan_attestation(&state, 7, &APP, 130, 1, 0).unwrap());
        let wide = coin_blocks::block_for_address(8, &outputs[1]).unwrap();
        assert_eq!(wide, 260);
        assert_eq!(delivery(&state, &APP, 130, 0).unwrap().unwrap().address, outputs[0]);
        assert!(delivery(&state, &APP, 130, 1).unwrap().is_none(), "a moved record names no delivery");
        assert!(delivery(&state, &APP, 130, 2).unwrap().is_none());
        assert_eq!(delivery(&state, &APP, wide, 0).unwrap().unwrap().address, outputs[1]);
        assert_eq!(delivery(&state, &APP, wide, 1).unwrap().unwrap().address, outputs[2]);
        let moved = delivery(&state, &APP, wide, 0).unwrap().unwrap();
        assert_eq!((moved.source_frame, moved.tx_id), (40, [1; 32]), "the operation it came from is kept");
        assert!(escrow_delivery(&state, &APP, 130, 0).unwrap().is_none());
        assert!(escrow_delivery(&state, &APP, wide, 0).unwrap().is_some());
        assert_eq!((block_sequence(&state, &APP, 130).unwrap(), escrow_sequence(&state, &APP, 130).unwrap()), (1, 0));
        assert_eq!((block_sequence(&state, &APP, wide).unwrap(), escrow_sequence(&state, &APP, wide).unwrap()), (2, 1));
        assert_eq!(orphan(&state, &APP, 130).unwrap(), Some(Orphan { since: 6, moved: true, coins: 1, escrows: 0 }));
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
        reconcile_orphans(&state, 6, &APP, &[bits("00000100"), bits("00000101")], &[bits("0000010")]).unwrap();
        let report = |block| ShardReport {
            context: CONTEXT, subtrees: Vec::new(),
            attestations: vec![BlockAttestation { block, coins: 2, escrows: 1 }],
        }.encode().unwrap();
        let holder = quil_forest::encode_shard_bit_path(&APP, &bits("00000100"));
        let sibling = quil_forest::encode_shard_bit_path(&APP, &bits("00000101"));
        set_orphan_replacement_frame_for_test(Some(9));
        assert!(records::materialize_report(&state, 8, &holder, &report(130)).is_err(), "before the frame");
        assert!(records::materialize_report(&state, 9, &sibling, &report(130)).is_err(), "not the holder");
        assert!(records::materialize_report(&state, 9, &holder, &report(260)).is_err(), "a block the shard owns");
        records::materialize_report(&state, 9, &holder, &report(130)).unwrap();
        set_orphan_replacement_frame_for_test(None);
        assert_eq!(orphan(&state, &APP, 130).unwrap(), Some(Orphan { since: 6, moved: true, coins: 2, escrows: 1 }));
        assert!(delivery(&state, &APP, 130, 2).unwrap().is_none());
        assert_eq!(delivery(&state, &APP, 260, 0).unwrap().unwrap().address, output(4));
        assert!(escrow_delivery(&state, &APP, 130, 0).unwrap().is_some(), "the delivered escrow stays");
    }

    #[test]
    fn entries_round_trip_canonically() {
        let mut full = entry(1, &[2, 3], &[4, 5]);
        full.root_digest = Some([9; 32]);
        full.escrow_create = Some(EscrowCreate { address: [10; 32], binding: [11; 32], refund_after_global_frame: 99 });
        full.settlement = Some(SettlementEntry {
            receipt: [12; 32], parameter_context: [13; 32], destination: [14; 32], context: [15; 32],
            settlement: 7, payment_address: [0; 32], payment: 0, claimant: [0; 32],
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
        assert!(entry(1, &[2, 2], &[4]).encode().is_err(), "repeated consumption");
        assert!(entry(1, &[], &[4]).encode().is_err(), "nothing consumed");
    }

    /// The property the commit exists for: one image, one spend — whichever
    /// shard relays it and in whatever order relays arrive.
    #[test]
    fn a_consumption_commits_once_and_decisions_are_final() {
        let state = mem_state();
        assert!(!is_decided(&state, &APP, &[1; 32]).unwrap());
        let first = commit_entry(&state, 100, &APP, &entry(1, &[20, 21], &[1, 2]), SHARD).unwrap();
        let Outcome::Committed { fee, placements, .. } = first else { panic!("{first:?}") };
        assert_eq!(fee, 5);
        assert!(is_decided(&state, &APP, &[1; 32]).unwrap());
        assert!(!is_decided(&state, &[6; 32], &[1; 32]).unwrap(), "decisions are per application");
        assert!(is_consumed(&state, &APP, &[20; 32]).unwrap());
        // Two outputs in one block take consecutive sequence numbers.
        let block = coin_blocks::block_for_address(coin_blocks::INITIAL_BLOCK_BITS, &output(1)).unwrap();
        assert_eq!(placements.iter().map(|p| (p.block, p.seq)).collect::<Vec<_>>(), vec![(block, 0), (block, 1)]);
        assert_eq!(block_sequence(&state, &APP, block).unwrap(), 2);
        assert_eq!(delivery(&state, &APP, block, 1).unwrap(), Some(Delivery {
            address: output(2), source_frame: 40, tx_id: [1; 32], source_shard: SHARD,
        }));
        // A different operation spending one of the same markers is rejected,
        // writes nothing, and stays rejected.
        let double = entry(2, &[21, 22], &[3]);
        assert_eq!(commit_entry(&state, 101, &APP, &double, SHARD).unwrap(), Outcome::Rejected("already consumed"));
        assert!(is_decided(&state, &APP, &[2; 32]).unwrap(), "a rejection is a decision too");
        assert!(!is_consumed(&state, &APP, &[22; 32]).unwrap());
        assert_eq!(block_sequence(&state, &APP, block).unwrap(), 2);
        assert_eq!(commit_entry(&state, 102, &APP, &double, SHARD).unwrap(), Outcome::AlreadyDecided);
        // Re-carried relays of the committed operation are not re-applied.
        assert_eq!(commit_entry(&state, 103, &APP, &entry(1, &[20, 21], &[1, 2]), SHARD).unwrap(), Outcome::AlreadyDecided);
        assert_eq!(block_sequence(&state, &APP, block).unwrap(), 2);
        // Consumption is per application.
        assert!(matches!(commit_entry(&state, 104, &[6; 32], &entry(3, &[20], &[4]), SHARD).unwrap(), Outcome::Committed { .. }));
    }

    #[test]
    fn a_root_must_be_canonical_and_a_context_fixed() {
        let state = mem_state();
        let mut spend = entry(1, &[20], &[1]);
        spend.root_digest = Some([9; 32]);
        assert_eq!(commit_entry(&state, 100, &APP, &spend, SHARD).unwrap(),
            Outcome::Rejected("root is not in the application's canonical history"));
        // Publish a canonical root and cite its digest.
        let root = Node::from_bytes(&[1u8; NODE_BYTES]).unwrap();
        let record = quil_lattice_ct::confidential::coin_tree::RootRecord { context: CONTEXT, depth: 32, coins: 1, root: root.clone() };
        let history = roots::publish_history(None, record).unwrap();
        records::write_record(&state, 100, &records::root_history_address(&APP).unwrap(), &[
            (vec![0xff; 32], records::kind("quil/accumulator/root-history-record/v1\0").unwrap().to_vec()),
            (vec![0], history),
        ]).unwrap();
        let mut spend = entry(2, &[20], &[1]);
        spend.root_digest = Some(roots::root_digest(&CONTEXT, 32, &root));
        assert!(matches!(commit_entry(&state, 101, &APP, &spend, SHARD).unwrap(), Outcome::Committed { .. }));
        // Once the application has a context, another one is refused.
        let mut foreign = entry(3, &[21], &[2]);
        foreign.context = [99; 32];
        assert_eq!(commit_entry(&state, 102, &APP, &foreign, SHARD).unwrap(), Outcome::Rejected("context differs from the application's"));
    }

    #[test]
    fn escrows_are_created_once_claimed_once_and_refunded_only_after_their_frame() {
        let state = mem_state();
        let binding = escrow_binding(&CONTEXT, &[50; 32], b"source", b"recipient", b"refund", 200);
        let mut create = entry(1, &[20], &[1]);
        create.escrow_create = Some(EscrowCreate { address: [50; 32], binding, refund_after_global_frame: 200 });
        assert!(matches!(commit_entry(&state, 100, &APP, &create, SHARD).unwrap(), Outcome::Committed { .. }));
        assert_eq!(escrow(&state, &APP, &[50; 32]).unwrap(), Some((binding, 200, false)));
        // The same escrow address cannot be created twice.
        let mut again = entry(2, &[21], &[2]);
        again.escrow_create = Some(EscrowCreate { address: [50; 32], binding, refund_after_global_frame: 200 });
        assert_eq!(commit_entry(&state, 101, &APP, &again, SHARD).unwrap(), Outcome::Rejected("escrow already exists"));

        let other_binding = escrow_binding(&CONTEXT, &[52; 32], b"source", b"recipient", b"refund", 200);
        let claim = |tx: u8, binding: [u8; 32], refund: bool| {
            let mut claim = entry(tx, &[], &[3]);
            claim.escrow_claim = Some(EscrowClaim { address: [50; 32], binding, refund });
            claim
        };
        assert_eq!(commit_entry(&state, 102, &APP, &claim(3, [0; 32], false), SHARD).unwrap(), Outcome::Rejected("claim does not match the escrow"));
        assert_eq!(commit_entry(&state, 150, &APP, &claim(4, binding, true), SHARD).unwrap(), Outcome::Rejected("refund before the escrow's refund frame"));
        // The recipient may claim before the refund frame; then nobody can.
        assert!(matches!(commit_entry(&state, 151, &APP, &claim(5, binding, false), SHARD).unwrap(), Outcome::Committed { .. }));
        assert_eq!(escrow(&state, &APP, &[50; 32]).unwrap(), Some((binding, 200, true)));
        assert_eq!(commit_entry(&state, 250, &APP, &claim(6, binding, true), SHARD).unwrap(), Outcome::Rejected("escrow already consumed"));
        // What a wallet reads over RPC is exactly what the commit stored.
        let disc = crate::hypergraph_state::vertex_adds_discriminator().unwrap();
        let stored = state.get(&crate::global_schema::GLOBAL_INTRINSIC_ADDRESS, &escrow_address(&APP, &[50; 32]).unwrap(), &disc).unwrap().unwrap();
        assert_eq!(stored, encode_escrow_record(&binding, 200, true).unwrap());
        assert_eq!(parse_escrow_record(&stored).unwrap(), (binding, 200, true));
        assert!(parse_escrow_record(&encode_escrow_record(&binding, 200, false).unwrap()).is_ok_and(|r| !r.2));
        // Each created escrow is queued once for delivery to its block's shard.
        let block = coin_blocks::block_for_address(coin_blocks::INITIAL_BLOCK_BITS, &[50; 32]).unwrap();
        assert_eq!(escrow_sequence(&state, &APP, block).unwrap(), 1);
        // The record names the shard that executed it: where its bytes are.
        assert_eq!(escrow_delivery(&state, &APP, block, 0).unwrap(), Some(Delivery {
            address: [50; 32], source_frame: create.source_frame, tx_id: create.tx_id, source_shard: SHARD,
        }));
        let split = quil_types::execution::ShardPath::from_bits(&[true, false]);
        let mut elsewhere = entry(9, &[60], &[7]);
        elsewhere.escrow_create = Some(EscrowCreate { address: [52; 32], binding: other_binding, refund_after_global_frame: 200 });
        assert!(matches!(commit_entry(&state, 170, &APP, &elsewhere, split).unwrap(), Outcome::Committed { .. }));
        let other_block = coin_blocks::block_for_address(coin_blocks::INITIAL_BLOCK_BITS, &[52; 32]).unwrap();
        assert_eq!(escrow_delivery(&state, &APP, other_block, 0).unwrap().unwrap().source_shard, split);

        // A refund at or after the refund frame commits.
        let other = escrow_binding(&CONTEXT, &[51; 32], b"source", b"recipient", b"refund", 200);
        let _ = &other;
        let mut create = entry(7, &[22], &[4]);
        create.escrow_create = Some(EscrowCreate { address: [51; 32], binding: other, refund_after_global_frame: 200 });
        assert!(matches!(commit_entry(&state, 160, &APP, &create, SHARD).unwrap(), Outcome::Committed { .. }));
        let mut refund = entry(8, &[], &[5]);
        refund.escrow_claim = Some(EscrowClaim { address: [51; 32], binding: other, refund: true });
        assert!(matches!(commit_entry(&state, 200, &APP, &refund, SHARD).unwrap(), Outcome::Committed { .. }));
    }

    #[test]
    fn a_settlement_record_is_written_only_when_its_spend_commits() {
        let state = mem_state();
        let settlement = SettlementEntry {
            receipt: [12; 32], parameter_context: CONTEXT, destination: [14; 32], context: [15; 32],
            settlement: 7, payment_address: [0; 32], payment: 0, claimant: [0; 32],
        };
        let disc = crate::hypergraph_state::vertex_adds_discriminator().unwrap();
        let global = crate::global_schema::GLOBAL_INTRINSIC_ADDRESS;
        let mut committed = entry(1, &[20], &[1]);
        committed.settlement = Some(settlement.clone());
        assert!(matches!(commit_entry(&state, 100, &APP, &committed, SHARD).unwrap(), Outcome::Committed { .. }));
        assert!(state.get(&global, &[12; 32], &disc).unwrap().is_some());
        // A double spend carrying another settlement records nothing.
        let mut rejected = entry(2, &[20], &[2]);
        rejected.settlement = Some(SettlementEntry { receipt: [13; 32], ..settlement });
        assert_eq!(commit_entry(&state, 101, &APP, &rejected, SHARD).unwrap(), Outcome::Rejected("already consumed"));
        assert!(state.get(&global, &[13; 32], &disc).unwrap().is_none());
    }
    /// New coins are placed no narrower than the application's deepest shard,
    /// the width only rises, and earlier blocks keep their ids.
    #[test]
    fn placement_width_follows_the_deepest_shard_and_never_falls() {
        let state = mem_state();
        assert_eq!(placement_width(&state, &APP).unwrap(), coin_blocks::INITIAL_BLOCK_BITS);
        // Shallower than the starting width changes nothing.
        assert_eq!(raise_placement_width(&state, 1, &APP, 3).unwrap(), coin_blocks::INITIAL_BLOCK_BITS);
        let narrow = coin_blocks::block_for_address(placement_width(&state, &APP).unwrap(), &[0x21; 32]).unwrap();
        assert_eq!(raise_placement_width(&state, 2, &APP, 9).unwrap(), 9);
        assert_eq!(placement_width(&state, &APP).unwrap(), 9);
        assert_eq!(raise_placement_width(&state, 3, &APP, 7).unwrap(), 9, "the width never falls");
        let wide = coin_blocks::block_for_address(placement_width(&state, &APP).unwrap(), &[0x21; 32]).unwrap();
        assert_eq!((coin_blocks::creation_width(narrow), coin_blocks::creation_width(wide)), (6, 9));
        assert_ne!(narrow, wide, "a wider block never reuses a narrower block's id");
        // A depth-nine shard owns the wide block whole, and only part of the narrow one.
        let shard: Vec<bool> = coin_blocks::block_path(wide);
        assert!(coin_blocks::shard_owns_block(&shard, wide));
        assert!(!coin_blocks::shard_owns_block(&shard, narrow));
        // Beyond the accumulator's widest block the width saturates.
        assert_eq!(raise_placement_width(&state, 4, &APP, 40).unwrap(), coin_blocks::MAX_BLOCK_BITS);
        // Another application is untouched.
        assert_eq!(placement_width(&state, &[0x77; 32]).unwrap(), coin_blocks::INITIAL_BLOCK_BITS);
    }

    /// A commit relayed by a depth-nine shard places its outputs in width-nine
    /// blocks even though no split ever raised the width here.
    #[test]
    fn a_deep_source_shard_places_at_its_own_depth() {
        let state = mem_state();
        let deep = quil_types::execution::ShardPath::from_bits(&[false; 9]);
        assert!(matches!(commit_entry(&state, 5, &APP, &entry(1, &[1], &[2]), deep).unwrap(), Outcome::Committed { .. }));
        assert_eq!(placement_width(&state, &APP).unwrap(), 9);
        let block = coin_blocks::block_for_address(9, &output(2)).unwrap();
        assert_eq!(block_sequence(&state, &APP, block).unwrap(), 1);
        let narrow = coin_blocks::block_for_address(coin_blocks::INITIAL_BLOCK_BITS, &output(2)).unwrap();
        assert_eq!(block_sequence(&state, &APP, narrow).unwrap(), 0, "nothing new lands in a narrower block");
    }

    /// What GLOBAL has committed into a shard's blocks counts for that shard and
    /// for no sibling, whether or not the shard ever took delivery.
    #[test]
    fn outputs_committed_into_a_shard_count_as_its_data() {
        let state = mem_state();
        assert!(matches!(commit_entry(&state, 5, &APP, &entry(1, &[1], &[2, 3]), SHARD).unwrap(), Outcome::Committed { .. }));
        // `output(n)` begins 0b0000_0100: path 000001… at any depth.
        let holds = |bits: &[bool]| committed_to_shard(&state, &APP, bits).unwrap();
        assert_eq!(holds(&[]), 2, "the whole application owns every block");
        assert_eq!(holds(&[false, false, false]), 2);
        assert_eq!(holds(&[false, false, true]), 0, "a sibling range holds nothing");
        assert_eq!(holds(&[true]), 0);
        // Deeper than the placement width: the shard owns no whole block.
        assert_eq!(holds(&[false; 7]), 0);
    }

}
