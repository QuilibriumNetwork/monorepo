//! One storage epoch proof per member (decided 2026-10-22).
//!
//! A node's workers each hold their own shards' replicas, so each prepares its
//! seat's part of the epoch proof where the replicas are
//! (`storage_epoch_proof::prepare`: the plain seals and the openings) and
//! hands the [`PreparedSeat`] to its node: a thread worker in process, a
//! standalone worker through its master's `SubmitWorkerProverMessage`.
//! Preparing a seal relabels its leaves (about an hour per GiB), so parts
//! reach the node far apart; a worker therefore announces its part when the
//! seat comes due, and withdraws it if preparing fails. The node proves a
//! member's collection once every announced part is in (at least
//! [`collect_secs`] after it began, so the others' announcements land: one
//! renewal registers all the member's seats, so they come due together), or
//! after [`max_wait_secs`] with what it has, in one STARK per chunk of at most
//! [`chunk_leaves`] sealed leaves (proving holds about 0.4 GB per sealed
//! leaf). GLOBAL then carries one proof per member per epoch, of about one
//! seat's size, instead of one per seat.
//!
//! GLOBAL refuses a proof whole when any seat in it fails, so a seat whose
//! earlier proof GLOBAL did not apply is proved alone, at once (`solo`): one
//! refused seat cannot hold the others back. A worker retries on a timer, not
//! on a refusal, so a retried part is dropped while a part it overlaps is
//! still waiting in a collection, or within [`RECENTLY_PROVED`] of one's proof:
//! that proof covers it, or may still be on its way to GLOBAL. The worker
//! sends the part it prepared before ([`prepare_reusing`]): a retry repeats
//! no relabeling.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use quil_execution::global_intrinsic::storage_epoch_proof::{
    self as epoch_proof, EpochClaim, HeldLeaf, SealedLeaf, SeatClaim, SeatProof, SeatWitness,
    StorageEpochProof,
};
use quil_types::error::{QuilError, Result};
use tracing::{info, warn};

/// A seat's part of an epoch proof, or its announcement or withdrawal, sent
/// from a worker to its node; never a GLOBAL request.
pub const TYPE_SEAT_WITNESS: u32 = 0x0325;

const PART: u8 = 0;
const ANNOUNCE: u8 = 1;
const WITHDRAW: u8 = 2;

const MAX_LEAF_ID: usize = 128;
const MAX_BEACON: usize = 64;
const MAX_SEAL_BYTES: usize = 64 << 20;
const MAX_PATH: usize = 64;

/// Where a finished proof goes: the node's GLOBAL submission path.
pub type Publish = Arc<dyn Fn(Vec<u8>) + Send + Sync>;

/// Seconds a node collects a member's seats before proving them.
pub fn collect_secs() -> u64 {
    std::env::var("QUIL_EPOCH_PROOF_COLLECT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20)
}

/// Seconds a node waits for a member's announced parts before proving what it
/// has.
pub fn max_wait_secs() -> u64 {
    std::env::var("QUIL_EPOCH_PROOF_MAX_WAIT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1800)
}

/// Sealed leaves one proof holds at most.
pub fn chunk_leaves() -> usize {
    std::env::var("QUIL_EPOCH_PROOF_LEAVES")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(24)
}

/// What a proof's STARK takes of its message, at most (about 0.75–1 MB).
const STARK_ALLOWANCE: usize = 5 << 18;

/// Bytes of a proof's message its seats' parts (frames and bindings) may
/// take: a GLOBAL proposal carries epoch proofs only up to
/// `STORAGE_SEAL_BYTES_PER_FRAME`, and never a larger one.
fn chunk_bytes() -> usize {
    quil_types::consensus::STORAGE_SEAL_BYTES_PER_FRAME - STARK_ALLOWANCE
}

/// Which part of an epoch proof a seat sends: its shard, and whether it seals
/// and settles.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SeatKey {
    pub filter: Vec<u8>,
    pub seals: bool,
    pub settles: bool,
}

impl SeatKey {
    /// Whether the two parts cover the same shard's seal or settlement: one
    /// proved or pending covers a retry of the other.
    pub fn overlaps(&self, other: &SeatKey) -> bool {
        self.filter == other.filter
            && ((self.seals && other.seals) || (self.settles && other.settles))
    }
}

/// What a worker sends its node about a seat's part.
#[derive(Debug, Clone)]
pub enum SeatMessage {
    /// The part, prepared.
    Part(PreparedSeat),
    /// The part is being prepared: the member's proof waits for it.
    Announce([u8; 32], SeatKey),
    /// Preparing it failed: the member's proof does not wait for it.
    Withdraw([u8; 32], SeatKey),
}

impl SeatMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Part(seat) => seat.to_bytes(),
            Self::Announce(member, key) | Self::Withdraw(member, key) => {
                let mut out = Vec::new();
                out.extend_from_slice(&TYPE_SEAT_WITNESS.to_be_bytes());
                out.extend_from_slice(member);
                out.push(if matches!(self, Self::Announce(..)) {
                    ANNOUNCE
                } else {
                    WITHDRAW
                });
                put_lp(&mut out, &key.filter);
                out.push(key.seals as u8 | (key.settles as u8) << 1);
                out
            }
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let invalid =
            |what: &str| QuilError::InvalidArgument(format!("storage seat message: {what}"));
        let kind = *data.get(36).ok_or_else(|| invalid("truncated"))?;
        if kind == PART {
            return PreparedSeat::from_bytes(data).map(Self::Part);
        }
        let mut c = Cursor { data, at: 0 };
        if c.u32()? != TYPE_SEAT_WITNESS {
            return Err(invalid("not a storage seat message"));
        }
        let member: [u8; 32] = c.take(32)?.try_into().expect("32 bytes");
        c.take(1)?;
        let filter = c.lp(MAX_LEAF_ID)?.to_vec();
        let parts = c.take(1)?[0];
        if parts == 0 || parts > 3 || c.at != data.len() {
            return Err(invalid("bad parts"));
        }
        let key = SeatKey {
            filter,
            seals: parts & 1 != 0,
            settles: parts & 2 != 0,
        };
        match kind {
            ANNOUNCE => Ok(Self::Announce(member, key)),
            WITHDRAW => Ok(Self::Withdraw(member, key)),
            _ => Err(invalid("unknown kind")),
        }
    }
}

/// One seat's part of a member's epoch proof, ready to be proved with others.
#[derive(Debug, Clone)]
pub struct PreparedSeat {
    pub member: [u8; 32],
    /// What the message says of the seat.
    pub part: SeatProof,
    pub claim: SeatClaim,
    pub witness: SeatWitness,
    /// Prove it alone: an earlier proof with it was not applied.
    pub solo: bool,
}

impl PreparedSeat {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&TYPE_SEAT_WITNESS.to_be_bytes());
        out.extend_from_slice(&self.member);
        out.push(PART);
        out.push(self.solo as u8);
        let part = StorageEpochProof {
            member: self.member,
            seats: vec![self.part.clone()],
            proof: Vec::new(),
        };
        put_lp(&mut out, &part.to_canonical_bytes());
        out.extend_from_slice(&(self.claim.seals.len() as u32).to_be_bytes());
        for leaf in &self.claim.seals {
            put_lp(&mut out, &leaf.leaf_id);
            out.extend_from_slice(&leaf.n.to_be_bytes());
            out.extend_from_slice(&quil_crypto::storage_proof::registration_root(
                &leaf.registered.comm_d,
                &leaf.registered.comm_c,
                &leaf.registered.comm_r,
            ));
            put_lp(&mut out, &leaf.beacon);
        }
        out.extend_from_slice(&(self.claim.held.len() as u32).to_be_bytes());
        for leaf in &self.claim.held {
            put_lp(&mut out, &leaf.leaf_id);
            out.extend_from_slice(&leaf.n.to_be_bytes());
            out.extend_from_slice(&leaf.comm_r);
        }
        for seal in &self.witness.seals {
            put_lp(&mut out, &seal.to_bytes());
        }
        out.extend_from_slice(&(self.witness.opened.len() as u32).to_be_bytes());
        for opened in &self.witness.opened {
            out.extend_from_slice(&opened.value);
            out.extend_from_slice(&(opened.path.len() as u16).to_be_bytes());
            for node in &opened.path {
                out.extend_from_slice(node);
            }
        }
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let invalid =
            |what: &str| QuilError::InvalidArgument(format!("prepared storage seat: {what}"));
        let mut c = Cursor { data, at: 0 };
        if c.u32()? != TYPE_SEAT_WITNESS {
            return Err(invalid("not a prepared seat"));
        }
        let member: [u8; 32] = c.take(32)?.try_into().expect("32 bytes");
        if c.take(1)?[0] != PART {
            return Err(invalid("not a part"));
        }
        let solo = match c.take(1)?[0] {
            0 => false,
            1 => true,
            _ => return Err(invalid("bad solo flag")),
        };
        let part = StorageEpochProof::from_canonical_bytes(c.lp(usize::MAX)?)?;
        let [part]: [SeatProof; 1] = part.seats.try_into().map_err(|_| invalid("not one seat"))?;
        let mut claim = SeatClaim {
            seal_epoch: part.seal_epoch(),
            settle_epoch: part.epoch,
            frames: part.frames.clone(),
            ..Default::default()
        };
        let seals = c.u32()? as usize;
        if seals != part.bindings.len() {
            return Err(invalid("a sealed leaf for each binding"));
        }
        for _ in 0..seals {
            let leaf_id = c.lp(MAX_LEAF_ID)?.to_vec();
            let n = c.u64()?;
            let registered = quil_crypto::storage_proof::parse_registration_root(
                c.take(quil_crypto::storage_proof::REGISTRATION_ROOT_BYTES)?,
            )
            .ok_or_else(|| invalid("bad registration"))?;
            let beacon = c.lp(MAX_BEACON)?.to_vec();
            claim.seals.push(SealedLeaf {
                leaf_id,
                n,
                registered,
                beacon,
            });
        }
        let held = c.u32()? as usize;
        if (held == 0) == part.settles {
            return Err(invalid("held leaves exactly when settling"));
        }
        for _ in 0..held.min(1 << 12) {
            let leaf_id = c.lp(MAX_LEAF_ID)?.to_vec();
            let n = c.u64()?;
            let comm_r: [u8; 32] = c.take(32)?.try_into().expect("32 bytes");
            claim.held.push(HeldLeaf { leaf_id, n, comm_r });
        }
        if claim.held.len() != held {
            return Err(invalid("too many held leaves"));
        }
        let params = quil_crypto::sdr::SdrParams::default();
        let mut witness = SeatWitness {
            seals: Vec::with_capacity(seals),
            opened: Vec::new(),
        };
        for leaf in &claim.seals {
            let bytes = c.lp(MAX_SEAL_BYTES)?;
            witness.seals.push(
                quil_crypto::storage_proof::SealProof::from_bytes(
                    bytes,
                    leaf.n,
                    params.layers,
                    quil_types::consensus::STORAGE_SEAL_CHALLENGES,
                )
                .ok_or_else(|| invalid("bad plain seal"))?,
            );
        }
        let opened = c.u32()? as usize;
        let expected =
            part.frames.len() * held * quil_types::consensus::STORAGE_QUERIES_PER_LEAF as usize;
        if opened != expected {
            return Err(invalid("an opening per frame, held leaf and query"));
        }
        for _ in 0..opened {
            let value: [u8; 32] = c.take(32)?.try_into().expect("32 bytes");
            let depth = u16::from_be_bytes(c.take(2)?.try_into().expect("2 bytes")) as usize;
            if depth > MAX_PATH {
                return Err(invalid("path too long"));
            }
            let path = (0..depth)
                .map(|_| c.take(32).map(|node| node.try_into().expect("32 bytes")))
                .collect::<Result<_>>()?;
            witness.opened.push(epoch_proof::Opened { value, path });
        }
        if c.at != data.len() {
            return Err(invalid("trailing bytes"));
        }
        Ok(Self {
            member,
            part,
            claim,
            witness,
            solo,
        })
    }

    pub fn key(&self) -> SeatKey {
        SeatKey {
            filter: self.part.shard_filter.clone(),
            seals: self.part.seals,
            settles: self.part.settles,
        }
    }

    /// Sealed leaves, at least one: its weight in a chunk.
    fn weight(&self) -> usize {
        self.claim.seals.len().max(1)
    }

    /// What its part adds to a proof's message.
    fn part_bytes(&self) -> usize {
        16 + self.part.shard_filter.len()
            + 72 * self.part.frames.len()
            + self
                .part
                .bindings
                .iter()
                .map(|binding| 4 + binding.to_bytes().len())
                .sum::<usize>()
    }

    /// Its seal and its settlement, each a part of its own: the two are
    /// prepared independently, so a part is its halves side by side
    /// ([`PreparedSeat::join`]).
    pub fn halves(self) -> (Option<PreparedSeat>, Option<PreparedSeat>) {
        let Self {
            member,
            part,
            claim,
            witness,
            solo,
        } = self;
        let SeatProof {
            shard_filter,
            epoch,
            seals,
            settles,
            frames,
            bindings,
        } = part;
        let SeatClaim {
            seal_epoch,
            seals: sealed,
            settle_epoch,
            held,
            frames: committed,
        } = claim;
        let SeatWitness {
            seals: seal_proofs,
            opened,
        } = witness;
        let seal = seals.then(|| PreparedSeat {
            member,
            part: SeatProof {
                shard_filter: shard_filter.clone(),
                epoch,
                seals: true,
                settles: false,
                frames: Vec::new(),
                bindings,
            },
            claim: SeatClaim {
                seal_epoch,
                seals: sealed,
                settle_epoch,
                ..Default::default()
            },
            witness: SeatWitness {
                seals: seal_proofs,
                opened: Vec::new(),
            },
            solo,
        });
        let settle = settles.then(|| PreparedSeat {
            member,
            part: SeatProof {
                shard_filter,
                epoch,
                seals: false,
                settles: true,
                frames,
                bindings: Vec::new(),
            },
            claim: SeatClaim {
                seal_epoch,
                settle_epoch,
                held,
                frames: committed,
                ..Default::default()
            },
            witness: SeatWitness {
                seals: Vec::new(),
                opened,
            },
            solo,
        });
        (seal, settle)
    }

    /// One part of a seat's seal and its settlement ([`PreparedSeat::halves`]).
    pub fn join(seal: Option<PreparedSeat>, settle: Option<PreparedSeat>) -> Option<PreparedSeat> {
        match (seal, settle) {
            (Some(seal), Some(settle)) => Some(PreparedSeat {
                member: seal.member,
                part: SeatProof {
                    settles: true,
                    frames: settle.part.frames,
                    ..seal.part
                },
                claim: SeatClaim {
                    held: settle.claim.held,
                    frames: settle.claim.frames,
                    ..seal.claim
                },
                witness: SeatWitness {
                    seals: seal.witness.seals,
                    opened: settle.witness.opened,
                },
                solo: seal.solo || settle.solo,
            }),
            (half, None) | (None, half) => half,
        }
    }
}

/// What half of a seat's part was prepared from ([`prepare_reusing`]): the
/// same inputs prepare the same half.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PartInputs {
    /// The registration sealed, and its beacon frame's output.
    Seal {
        registered_at: u64,
        leaves: Vec<Vec<u32>>,
        beacon_output: Vec<u8>,
    },
    /// The roots GLOBAL chained.
    Settle { frames: u64, accumulator: [u8; 32] },
}

#[derive(Default)]
struct PreparedHalves {
    seal: Option<(PartInputs, PreparedSeat)>,
    settle: Option<(PartInputs, PreparedSeat)>,
}

type PreparedParts = HashMap<([u8; 32], Vec<u8>, u64), PreparedHalves>;

fn prepared_parts() -> &'static Mutex<PreparedParts> {
    static PARTS: OnceLock<Mutex<PreparedParts>> = OnceLock::new();
    PARTS.get_or_init(Default::default)
}

/// `member`'s part for the seat on `filter` settling `epoch`, of the halves
/// `seal` and `settle` name by their inputs. A half this process prepared
/// before from the same inputs is reused, and `prepare(seals, settles)`
/// prepares only the others: a worker sends its part again when GLOBAL has
/// not recorded it in time (`claim_epoch_proof`), and preparing a seal
/// relabels each leaf at its challenges (about an hour per GiB). Returns the
/// part, not solo, and whether a half was reused.
pub fn prepare_reusing(
    member: &[u8; 32],
    filter: &[u8],
    epoch: u64,
    seal: Option<PartInputs>,
    settle: Option<PartInputs>,
    prepare: impl FnOnce(bool, bool) -> Result<PreparedSeat>,
) -> Result<(PreparedSeat, bool)> {
    let key = (*member, filter.to_vec(), epoch);
    let kept = |inputs: &Option<PartInputs>,
                half: fn(&PreparedHalves) -> &Option<(PartInputs, PreparedSeat)>| {
        let inputs = inputs.as_ref()?;
        let parts = prepared_parts().lock().ok()?;
        half(parts.get(&key)?)
            .as_ref()
            .filter(|(kept, _)| kept == inputs)
            .map(|(_, part)| part.clone())
    };
    let mut seal_half = kept(&seal, |halves| &halves.seal);
    let mut settle_half = kept(&settle, |halves| &halves.settle);
    let reused = seal_half.is_some() || settle_half.is_some();
    let (seals, settles) = (
        seal.is_some() && seal_half.is_none(),
        settle.is_some() && settle_half.is_none(),
    );
    if seals || settles {
        let (fresh_seal, fresh_settle) = prepare(seals, settles)?.halves();
        if let Ok(mut parts) = prepared_parts().lock() {
            parts.retain(|(_, _, e), _| *e >= epoch.saturating_sub(1));
            let halves = parts.entry(key).or_default();
            if let (true, Some(inputs), Some(half)) = (seals, seal, fresh_seal.as_ref()) {
                halves.seal = Some((inputs, half.clone()));
            }
            if let (true, Some(inputs), Some(half)) = (settles, settle, fresh_settle.as_ref()) {
                halves.settle = Some((inputs, half.clone()));
            }
        }
        seal_half = seal_half.or(fresh_seal);
        settle_half = settle_half.or(fresh_settle);
    }
    let mut part = PreparedSeat::join(seal_half, settle_half)
        .ok_or_else(|| QuilError::InvalidArgument("a part neither seals nor settles".into()))?;
    part.solo = false;
    Ok((part, reused))
}

/// Drop the halves kept for `member`'s seat on `filter` settling `epoch`:
/// GLOBAL recorded everything it owed.
pub fn forget_prepared(member: &[u8; 32], filter: &[u8], epoch: u64) {
    if let Ok(mut parts) = prepared_parts().lock() {
        parts.remove(&(*member, filter.to_vec(), epoch));
    }
}

/// Whether `bytes` is a [`SeatMessage`].
pub fn is_seat_message(bytes: &[u8]) -> bool {
    bytes.get(..4) == Some(&TYPE_SEAT_WITNESS.to_be_bytes()[..])
}

fn put_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(len)
            .filter(|&end| end <= self.data.len())
            .ok_or_else(|| QuilError::InvalidArgument("prepared storage seat: truncated".into()))?;
        let bytes = &self.data[self.at..end];
        self.at = end;
        Ok(bytes)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    fn lp(&mut self, max: usize) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(QuilError::InvalidArgument(
                "prepared storage seat: field too long".into(),
            ));
        }
        self.take(len)
    }
}

/// Split `seats` into the proofs to make: each solo seat alone, the others in
/// chunks of at most `leaves` sealed leaves and `bytes` of parts, each shard
/// once, in order.
fn chunks(seats: Vec<PreparedSeat>, leaves: usize, bytes: usize) -> Vec<Vec<PreparedSeat>> {
    let mut out: Vec<Vec<PreparedSeat>> = Vec::new();
    let mut open: Vec<PreparedSeat> = Vec::new();
    let (mut weight, mut size) = (0, 0);
    for seat in seats {
        if seat.solo {
            out.push(vec![seat]);
            continue;
        }
        let repeated = open
            .iter()
            .any(|held| held.part.shard_filter == seat.part.shard_filter);
        let part = seat.part_bytes();
        if !open.is_empty() && (repeated || weight + seat.weight() > leaves || size + part > bytes)
        {
            out.push(std::mem::take(&mut open));
            (weight, size) = (0, 0);
        }
        weight += seat.weight();
        size += part;
        open.push(seat);
    }
    if !open.is_empty() {
        out.push(open);
    }
    out
}

/// One proof over `seats` (one member's, distinct shards), as GLOBAL takes it.
pub fn prove(seats: Vec<PreparedSeat>) -> Result<Vec<u8>> {
    let member = seats
        .first()
        .map(|seat| seat.member)
        .ok_or_else(|| QuilError::InvalidArgument("no seat to prove".into()))?;
    let mut claim = EpochClaim {
        member,
        seats: Vec::with_capacity(seats.len()),
    };
    let mut witnesses = Vec::with_capacity(seats.len());
    let mut parts = Vec::with_capacity(seats.len());
    for seat in seats {
        if seat.member != member {
            return Err(QuilError::InvalidArgument(
                "seats of more than one member".into(),
            ));
        }
        claim.seats.push(seat.claim);
        witnesses.push(seat.witness);
        parts.push(seat.part);
    }
    let proof = epoch_proof::prove(&claim, &witnesses).map_err(QuilError::InvalidArgument)?;
    Ok(StorageEpochProof {
        member,
        seats: parts,
        proof,
    }
    .to_canonical_bytes())
}

/// How long after a seat's proof went out a retried part for it is dropped.
const RECENTLY_PROVED: Duration = Duration::from_secs(60);

/// When each member's seat parts were last proved, by member and part.
fn proved() -> &'static Mutex<HashMap<([u8; 32], SeatKey), Instant>> {
    static PROVED: OnceLock<Mutex<HashMap<([u8; 32], SeatKey), Instant>>> = OnceLock::new();
    PROVED.get_or_init(Default::default)
}

fn note_proved(seats: &[PreparedSeat]) {
    if let Ok(mut proved) = proved().lock() {
        proved.retain(|_, at| at.elapsed() < RECENTLY_PROVED);
        for seat in seats {
            proved.insert((seat.member, seat.key()), Instant::now());
        }
    }
}

fn recently_proved(seat: &PreparedSeat) -> bool {
    let key = seat.key();
    proved().lock().is_ok_and(|proved| {
        proved.iter().any(|((member, proved_key), at)| {
            *member == seat.member && proved_key.overlaps(&key) && at.elapsed() < RECENTLY_PROVED
        })
    })
}

/// A member's parts being collected for one proof.
struct Collection {
    started: Instant,
    /// Parts its workers said are coming.
    announced: HashSet<SeatKey>,
    parts: Vec<PreparedSeat>,
    publish: Publish,
}

impl Collection {
    /// Prove it now: every announced part is in, once the others had time to
    /// announce theirs, or it waited long enough.
    fn due(&self, collect: Duration, max_wait: Duration) -> bool {
        let waited = self.started.elapsed();
        let complete = self
            .announced
            .iter()
            .all(|key| self.parts.iter().any(|part| &part.key() == key));
        (waited >= collect && complete) || waited >= max_wait
    }
}

fn collections() -> &'static Mutex<HashMap<[u8; 32], Collection>> {
    static COLLECTIONS: OnceLock<Mutex<HashMap<[u8; 32], Collection>>> = OnceLock::new();
    COLLECTIONS.get_or_init(Default::default)
}

/// Take a worker's `message` about a seat's part, proving the member's
/// collection with `publish` as its destination once it is due. A part sent
/// again replaces the one collected for its shard; a solo part is proved
/// alone at once, replacing any collected copy.
pub fn deliver(message: SeatMessage, publish: Publish) {
    let (member, start) = {
        let Ok(mut collections) = collections().lock() else {
            return;
        };
        match message {
            SeatMessage::Part(seat) if seat.solo => {
                let key = seat.key();
                if collections
                    .get(&seat.member)
                    .is_some_and(|c| c.announced.iter().any(|k| k.overlaps(&key)))
                {
                    // Its first part has not been proved yet: that proof
                    // covers it.
                    return;
                }
                drop(collections);
                if recently_proved(&seat) {
                    tracing::debug!(member = %hex::encode(seat.member), shard = %hex::encode(&seat.part.shard_filter),
                        "storage epoch proof part retried while its proof may still be on its way; dropped");
                    return;
                }
                prove_and_publish(vec![seat], publish);
                return;
            }
            SeatMessage::Withdraw(member, key) => {
                if let Some(collection) = collections.get_mut(&member) {
                    collection.announced.remove(&key);
                }
                return;
            }
            SeatMessage::Announce(member, key) => {
                let start = !collections.contains_key(&member);
                let collection = collections.entry(member).or_insert_with(|| Collection {
                    started: Instant::now(),
                    announced: HashSet::new(),
                    parts: Vec::new(),
                    publish: publish.clone(),
                });
                collection.publish = publish;
                collection.announced.insert(key);
                (member, start)
            }
            SeatMessage::Part(seat) => {
                let member = seat.member;
                let start = !collections.contains_key(&member);
                let collection = collections.entry(member).or_insert_with(|| Collection {
                    started: Instant::now(),
                    announced: HashSet::new(),
                    parts: Vec::new(),
                    publish: publish.clone(),
                });
                collection.publish = publish;
                collection.parts.retain(|part| part.key() != seat.key());
                collection.announced.insert(seat.key());
                collection.parts.push(seat);
                (member, start)
            }
        }
    };
    if start {
        std::thread::spawn(move || watch(member));
    }
}

/// Wait for `member`'s collection to come due, then prove it.
fn watch(member: [u8; 32]) {
    let (collect, max_wait) = (
        Duration::from_secs(collect_secs()),
        Duration::from_secs(max_wait_secs()),
    );
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let Ok(mut collections) = collections().lock() else {
            return;
        };
        let Some(collection) = collections.get(&member) else {
            return;
        };
        if collection.parts.is_empty()
            && collection.announced.is_empty()
            && collection.started.elapsed() >= collect
        {
            collections.remove(&member);
            return;
        }
        if !collection.due(collect, max_wait) {
            continue;
        }
        let collection = collections.remove(&member).expect("present");
        drop(collections);
        let missing: Vec<String> = collection
            .announced
            .iter()
            .filter(|key| !collection.parts.iter().any(|part| &part.key() == *key))
            .map(|key| hex::encode(&key.filter))
            .collect();
        if !missing.is_empty() {
            warn!(member = %hex::encode(member), waited_secs = collection.started.elapsed().as_secs(), missing = ?missing,
                "storage epoch proof: proving without parts announced but not prepared in time");
        }
        if collection.parts.is_empty() {
            return;
        }
        for chunk in chunks(collection.parts, chunk_leaves(), chunk_bytes()) {
            prove_and_publish(chunk, collection.publish.clone());
        }
        return;
    }
}

/// Prove `seats` on the storage job thread and publish the proof.
fn prove_and_publish(seats: Vec<PreparedSeat>, publish: Publish) {
    note_proved(&seats);
    crate::storage_snapshot::spawn("member epoch proof", move || {
        let started = Instant::now();
        let member = seats
            .first()
            .map(|seat| hex::encode(seat.member))
            .unwrap_or_default();
        let (count, sealed) = (
            seats.len(),
            seats
                .iter()
                .map(|seat| seat.claim.seals.len())
                .sum::<usize>(),
        );
        let shards: Vec<String> = seats
            .iter()
            .map(|seat| hex::encode(&seat.part.shard_filter))
            .collect();
        match prove(seats) {
            Ok(bytes) => {
                info!(member, seats = count, sealed_leaves = sealed, bytes = bytes.len(),
                    seconds = started.elapsed().as_secs_f64(), shards = ?shards, "submitting storage epoch proof");
                publish(bytes);
                Ok(())
            }
            Err(error) => {
                warn!(member, seats = count, %error, shards = ?shards,
                    "storage epoch proof over the collected seats failed; their workers send each again alone");
                Err(error)
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_execution::global_intrinsic::storage_epoch_proof::SealedLeaf;

    fn seat(shard: u8, sealed: usize, solo: bool) -> PreparedSeat {
        let leaf = SealedLeaf {
            leaf_id: vec![shard],
            n: 4,
            registered: quil_crypto::storage_proof::Registered {
                comm_d: [0; 32],
                comm_c: [0; 32],
                comm_r: [0; 32],
            },
            beacon: Vec::new(),
        };
        PreparedSeat {
            member: [1; 32],
            part: SeatProof {
                shard_filter: vec![shard],
                seals: sealed > 0,
                settles: sealed == 0,
                ..Default::default()
            },
            claim: SeatClaim {
                seals: vec![leaf; sealed],
                ..Default::default()
            },
            witness: SeatWitness {
                seals: Vec::new(),
                opened: Vec::new(),
            },
            solo,
        }
    }

    /// A part sealing and settling, with a frame and a held leaf.
    fn sealing_and_settling(shard: u8) -> PreparedSeat {
        let mut part = seat(shard, 2, false);
        part.part.settles = true;
        part.part.epoch = 5;
        part.claim.seal_epoch = 7;
        part.claim.settle_epoch = 5;
        let frame = epoch_proof::CommittedFrame {
            frame_number: 40,
            rho_n: [2; 32],
            root: [3; 32],
        };
        part.part.frames = vec![frame.clone()];
        part.claim.frames = vec![frame];
        part.claim.held = vec![HeldLeaf {
            leaf_id: vec![shard, 1],
            n: 4,
            comm_r: [4; 32],
        }];
        part
    }

    /// A part splits into its seal and its settlement, each a part that
    /// says only its own half, and the two join back into the part.
    #[test]
    fn a_part_is_its_seal_and_its_settlement_side_by_side() {
        let part = sealing_and_settling(1);
        let (seal, settle) = part.clone().halves();
        let (seal, settle) = (seal.unwrap(), settle.unwrap());
        assert_eq!((seal.key().seals, seal.key().settles), (true, false));
        assert_eq!(
            (
                seal.claim.seals.len(),
                seal.claim.held.len(),
                seal.part.frames.len()
            ),
            (2, 0, 0)
        );
        assert_eq!((settle.key().seals, settle.key().settles), (false, true));
        assert_eq!(
            (
                settle.claim.seals.len(),
                settle.claim.held.len(),
                settle.part.frames.len()
            ),
            (0, 1, 1)
        );
        for half in [&seal, &settle] {
            assert_eq!(
                (
                    half.claim.seal_epoch,
                    half.claim.settle_epoch,
                    half.part.epoch
                ),
                (7, 5, 5)
            );
        }
        let joined = PreparedSeat::join(Some(seal.clone()), Some(settle)).unwrap();
        assert_eq!(joined.to_bytes(), part.to_bytes());
        assert_eq!(
            PreparedSeat::join(Some(seal.clone()), None)
                .unwrap()
                .to_bytes(),
            seal.to_bytes()
        );
        let (alone, none) = seal.clone().halves();
        assert!(none.is_none());
        assert_eq!(alone.unwrap().to_bytes(), seal.to_bytes());
    }

    /// A part sent again reuses each half prepared from the same inputs, even
    /// when the retry sends the halves apart; changed inputs prepare that
    /// half again.
    #[test]
    fn a_part_sent_again_is_not_prepared_again() {
        let member = [0x44; 32];
        let (filter, epoch) = (vec![0x45; 32], 9);
        let seal = || {
            Some(PartInputs::Seal {
                registered_at: 100,
                leaves: vec![vec![0]],
                beacon_output: vec![1],
            })
        };
        let settle = |accumulator| {
            Some(PartInputs::Settle {
                frames: 1,
                accumulator,
            })
        };
        let prepared = std::cell::RefCell::new(Vec::new());
        let prepare = |seals: bool, settles: bool| {
            prepared.borrow_mut().push((seals, settles));
            let (seal, settle) = sealing_and_settling(0x45).halves();
            Ok(PreparedSeat::join(seal.filter(|_| seals), settle.filter(|_| settles)).unwrap())
        };
        let (first, reused) =
            prepare_reusing(&member, &filter, epoch, seal(), settle([1; 32]), prepare).unwrap();
        assert!(!reused);
        // The retry sends the halves apart: both were prepared.
        let (settled, reused) =
            prepare_reusing(&member, &filter, epoch, None, settle([1; 32]), prepare).unwrap();
        assert!(reused && settled.part.settles && !settled.part.seals);
        let (sealed, reused) =
            prepare_reusing(&member, &filter, epoch, seal(), None, prepare).unwrap();
        assert!(reused && sealed.part.seals && !sealed.part.settles);
        assert_eq!(
            PreparedSeat::join(Some(sealed), Some(settled))
                .unwrap()
                .to_bytes(),
            first.to_bytes()
        );
        assert_eq!(*prepared.borrow(), vec![(true, true)]);
        // Other chained roots: the settlement is prepared again, the seal not.
        let (_, reused) =
            prepare_reusing(&member, &filter, epoch, seal(), settle([2; 32]), prepare).unwrap();
        assert!(reused);
        assert_eq!(*prepared.borrow(), vec![(true, true), (false, true)]);
        // Another seat, or the halves forgotten once GLOBAL recorded them.
        prepare_reusing(&member, &[0x46; 32], epoch, seal(), None, prepare).unwrap();
        forget_prepared(&member, &filter, epoch);
        prepare_reusing(&member, &filter, epoch, seal(), None, prepare).unwrap();
        assert_eq!(
            *prepared.borrow(),
            vec![(true, true), (false, true), (true, false), (true, false)]
        );
        forget_prepared(&member, &filter, epoch);
        forget_prepared(&member, &[0x46; 32], epoch);
    }

    #[test]
    fn announcements_and_withdrawals_round_trip_and_a_part_is_not_one() {
        let key = SeatKey {
            filter: vec![7; 32],
            seals: true,
            settles: false,
        };
        for message in [
            SeatMessage::Announce([3; 32], key.clone()),
            SeatMessage::Withdraw([3; 32], key.clone()),
        ] {
            let bytes = message.to_bytes();
            assert!(is_seat_message(&bytes));
            match (SeatMessage::from_bytes(&bytes).unwrap(), &message) {
                (SeatMessage::Announce(member, back), SeatMessage::Announce(..))
                | (SeatMessage::Withdraw(member, back), SeatMessage::Withdraw(..)) => {
                    assert_eq!((member, back), ([3; 32], key.clone()));
                }
                other => panic!("decoded as another kind: {other:?}"),
            }
            assert!(SeatMessage::from_bytes(&bytes[..bytes.len() - 1]).is_err());
            assert!(SeatMessage::from_bytes(&[bytes.as_slice(), &[0]].concat()).is_err());
        }
        let none = SeatMessage::Announce(
            [3; 32],
            SeatKey {
                seals: false,
                ..key
            },
        );
        assert!(
            SeatMessage::from_bytes(&none.to_bytes()).is_err(),
            "neither sealing nor settling"
        );
    }

    /// A collection is proved once every announced part is in, but not before
    /// the others had time to announce theirs; or after the longest wait.
    #[test]
    fn a_collection_is_due_when_its_announced_parts_are_in_or_it_waited_too_long() {
        let (collect, max_wait) = (Duration::from_secs(20), Duration::from_secs(1800));
        let mut collection = Collection {
            started: Instant::now(),
            announced: [seat(1, 1, false).key(), seat(2, 0, false).key()]
                .into_iter()
                .collect(),
            parts: vec![seat(1, 1, false)],
            publish: Arc::new(|_| {}),
        };
        assert!(!collection.due(collect, max_wait), "too early");
        collection.started -= Duration::from_secs(30);
        assert!(
            !collection.due(collect, max_wait),
            "shard 2 announced, not in"
        );
        collection.parts.push(seat(2, 0, false));
        assert!(collection.due(collect, max_wait));
        collection.parts.pop();
        collection.started -= max_wait;
        assert!(
            collection.due(collect, max_wait),
            "waited too long: proved without it"
        );
    }

    /// A part retried right after its seat's proof went out is not proved
    /// again; another part of the same member's is.
    #[test]
    fn a_part_proved_a_moment_ago_is_recently_proved_and_only_that_part() {
        let mut first = seat(201, 1, false);
        first.member = [201; 32];
        assert!(!recently_proved(&first));
        note_proved(std::slice::from_ref(&first));
        assert!(recently_proved(&first));
        let mut settling = first.clone();
        settling.part.seals = false;
        settling.part.settles = true;
        assert!(!recently_proved(&settling), "the seat's other part");
        assert!(!recently_proved(&seat(202, 1, false)), "another shard");
        // A combined part proved covers a retry of either part alone.
        let mut combined = seat(203, 1, false);
        combined.member = [203; 32];
        combined.part.settles = true;
        note_proved(std::slice::from_ref(&combined));
        let mut sealing = combined.clone();
        sealing.part.settles = false;
        let mut settling = combined.clone();
        settling.part.seals = false;
        assert!(recently_proved(&sealing) && recently_proved(&settling));
    }

    fn shards(chunks: &[Vec<PreparedSeat>]) -> Vec<Vec<u8>> {
        chunks
            .iter()
            .map(|chunk| chunk.iter().map(|seat| seat.part.shard_filter[0]).collect())
            .collect()
    }

    /// A member's seats go into as few proofs as the leaf cap allows, each
    /// shard once per proof, and a seat retried after a refusal alone.
    #[test]
    fn seats_are_chunked_by_sealed_leaves_with_retried_seats_alone() {
        let all = usize::MAX;
        let seats = vec![
            seat(1, 10, false),
            seat(2, 0, false),
            seat(3, 12, false),
            seat(4, 5, true),
            seat(5, 3, false),
        ];
        assert_eq!(
            shards(&chunks(seats, 24, all)),
            vec![vec![4], vec![1, 2, 3], vec![5]]
        );
        let repeated = vec![seat(1, 1, false), seat(1, 0, false), seat(2, 1, false)];
        assert_eq!(
            shards(&chunks(repeated, 24, all)),
            vec![vec![1], vec![1, 2]],
            "a shard's two parts apart"
        );
        assert_eq!(
            shards(&chunks(
                vec![seat(1, 30, false), seat(2, 1, false)],
                24,
                all
            )),
            vec![vec![1], vec![2]],
            "a seat over the cap is proved alone"
        );
        let small = vec![seat(1, 1, false), seat(2, 1, false), seat(3, 1, false)];
        let part = small[0].part_bytes();
        assert_eq!(
            shards(&chunks(small, 24, 2 * part)),
            vec![vec![1, 2], vec![3]],
            "by message bytes too"
        );
        assert!(STARK_ALLOWANCE < quil_types::consensus::STORAGE_SEAL_BYTES_PER_FRAME / 2);
    }
}
