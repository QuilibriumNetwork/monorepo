//! A member's storage seat on one shard (hash storage proofs, decided
//! 2026-10-21).
//!
//! GLOBAL no longer checks possession openings frame by frame. Each frame a
//! member proposes commits one root over the replica nodes it opened at that
//! frame's beacon (`quil_crypto::storage_proof::openings_root`), and the
//! member proves every such root, together with the seals of its next
//! registrations, in one STARK per seat per epoch
//! (`super::storage_epoch_proof`). The seat is what GLOBAL keeps in between,
//! per epoch:
//!
//! - the leaves the member registered for the shard (every leaf of the
//!   epoch's snapshot), and whether its epoch proof sealed them;
//! - the chain of the roots it committed (`accumulate`), so the proof must
//!   cover exactly the frames GLOBAL saw, in order, and which frames those
//!   were: GLOBAL never executes a header that missed its GLOBAL frame, so
//!   the member cannot tell them from its own finalized frames;
//! - the storage rewards held for it: a participant's issuance share of a
//!   frame anchored in the epoch is held here, not paid, and only a member
//!   with a sealed registration earns one (decided 2026-10-21);
//! - the proposals it was expected to make (`PROPOSAL / committee size` per
//!   app frame it took part in).
//!
//! Settlement (decided 2026-10-21): an epoch proof during the next epoch
//! settles the seat's epoch. The held rewards are paid in proportion to the
//! expected proposals the member published with a commitment, at most all of
//! them: a member that published 40% of its frames is paid 40%; the rest is
//! never issued. No proof by the end of the next epoch forfeits them, and a
//! member that committed any root then is kicked: at its next frame on the
//! shard, or by the epoch's expiry sweep (`enqueue_expiry`), whichever comes
//! first, so a member that never returns is kicked too. From the storage kick
//! suspension epoch (`quil_types::consensus::storage_kicks_suspended`) it
//! only forfeits them, and a member kicked so before may rejoin
//! (`kick_forgiven`).
//!
//! Response window: a frame commits at the beacon of its proposer's freshest
//! GLOBAL frame (`encode_commitment`), and its root counts as published only
//! if GLOBAL executed it within [`RESPONSE_WINDOW_MS`] of that frame, by the
//! two frames' timestamps (`SeatSlot::response_times`). A member that keeps no
//! replica must regenerate what a beacon chose inside that time, however
//! fast or slow GLOBAL frames come.

use quil_types::error::{QuilError, Result};
use sha3::{Digest as _, Sha3_256};

use crate::canonical_cursor::{put_u32, put_u64, read_bytes, read_u32, read_u64};
use crate::global_schema::{read_field, write_field, write_type, GLOBAL_INTRINSIC_ADDRESS};
use crate::hypergraph_state::HypergraphState;

pub const CLASS: &str = "storage:StorageSeat";
pub const EXPIRY_CLASS: &str = "storage:StorageExpiry";

/// Buckets an epoch's expiry queue is split into, one swept per GLOBAL frame
/// from the frame its settlement window closes (fewer frames when an epoch
/// is shorter than this).
pub const EXPIRY_BUCKETS: u64 = 16;

/// One expected proposal, in the fixed point `expected` counts in.
pub const PROPOSAL: u64 = 1 << 16;

/// The most a root's executing GLOBAL frame's timestamp may exceed its beacon
/// frame's for the root to count as published. Both are GLOBAL-certified,
/// and the root existed before the frame that executed it, so this bounds
/// the time from the beacon to the answer whatever the GLOBAL frame pace and
/// whatever the shard committee signs. An honest root is executed one or two
/// GLOBAL frames after its beacon (`encode_commitment`).
pub const RESPONSE_WINDOW_MS: i64 = 60_000;

/// A hash-epoch frame's `storage_attestation_root`: the openings root, then
/// the GLOBAL frame whose beacon chose the openings (big-endian). That is the
/// proposer's freshest GLOBAL frame, at or after the frame's anchor
/// (`latest − K`), so the response window starts when the beacon is known.
pub fn encode_commitment(root: &[u8; 32], beacon_frame: u64) -> Vec<u8> {
    [&root[..], &beacon_frame.to_be_bytes()[..]].concat()
}

/// The root and beacon frame of a hash-epoch commitment; `None` for any other
/// bytes.
pub fn decode_commitment(bytes: &[u8]) -> Option<([u8; 32], u64)> {
    let (root, frame) = bytes.split_at_checked(32)?;
    let root = <[u8; 32]>::try_from(root)
        .ok()
        .filter(|root| quil_crypto::storage_hash::from_bytes(root).is_some())?;
    Some((root, u64::from_be_bytes(frame.try_into().ok()?)))
}

const SLOTS_VERSION: u8 = 1;
const DST_FRAMES: &[u8] = b"quil/storage-seat/frames/v1";
const MAX_SLOTS: usize = 8;
const MAX_LEAVES: usize = 4096;
const MAX_PREFIX: usize = 256;
/// As many as an epoch proof may list (`storage_epoch_proof`).
const MAX_CHAINED: usize = 1 << 16;

/// How a seat's epoch ended.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Outcome {
    #[default]
    Open,
    /// An epoch proof settled it in this GLOBAL frame.
    Settled(u64),
    /// Its settlement window closed without one, noticed in this frame.
    Expired(u64),
}

/// Whether a hash-epoch frame anchored at GLOBAL frame `anchor` may carry
/// `bytes` as its `storage_attestation_root`, as its voters check: nothing, or
/// a commitment whose beacon frame is at or after the anchor (an honest
/// proposer's freshest frame always is). Whether GLOBAL chains it is
/// GLOBAL's to decide from its own frames.
pub fn commitment_acceptable(bytes: &[u8], anchor: u64) -> bool {
    bytes.is_empty() || decode_commitment(bytes).is_some_and(|(_, beacon)| beacon >= anchor)
}

/// A root chained into a seat.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Chained {
    /// The app frame that committed it.
    pub frame: u64,
    /// The GLOBAL frame whose beacon chose its openings.
    pub beacon: u64,
    /// The GLOBAL frame that executed it.
    pub executed: u64,
}

/// A seat's record of one epoch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SeatSlot {
    pub epoch: u64,
    /// The registered leaves' prefixes, sorted and distinct: what every
    /// commitment opens, in this order, and what the seal covers.
    pub leaves: Vec<Vec<u32>>,
    /// The GLOBAL frame that recorded the registration.
    pub registered_at: u64,
    /// The GLOBAL frame whose epoch proof sealed every leaf.
    pub sealed_at: Option<u64>,
    /// Commitments chained into `accumulator`.
    pub frames: u64,
    pub accumulator: [u8; 32],
    /// The roots chained, by ascending app frame: what the epoch proof
    /// lists. Emptied once the epoch is settled or expired.
    pub chained: Vec<Chained>,
    /// Proposals expected, in units of [`PROPOSAL`].
    pub expected: u64,
    /// The last app frame counted into `expected`.
    pub counted_through: u64,
    /// The last GLOBAL frame that held a reward here: one per frame, like
    /// `apply_reward`'s guard.
    pub held_through: u64,
    /// Held rewards, big-endian, no leading zeros.
    pub pending: Vec<u8>,
    pub outcome: Outcome,
}

impl SeatSlot {
    pub fn is_sealed(&self) -> bool {
        self.sealed_at.is_some() && !self.leaves.is_empty()
    }

    pub fn pending_amount(&self) -> num_bigint::BigInt {
        num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &self.pending)
    }

    /// What the prover registry keeps of the slot.
    pub fn view(&self) -> quil_types::consensus::StorageSeatSlot {
        quil_types::consensus::StorageSeatSlot {
            epoch: self.epoch,
            leaves: self.leaves.clone(),
            registered_at: self.registered_at,
            sealed_at: self.sealed_at,
            frames: self.frames,
            accumulator: self.accumulator,
            chained: self
                .chained
                .iter()
                .map(|chained| (chained.frame, chained.beacon))
                .collect(),
            open: self.outcome == Outcome::Open,
        }
    }

    /// Each chained root's response time, in order: how long after its
    /// beacon frame GLOBAL executed it, by `timestamp` (a GLOBAL frame's).
    pub fn response_times(&self, timestamp: impl Fn(u64) -> Result<i64>) -> Result<Vec<i64>> {
        let mut known = std::collections::HashMap::new();
        let mut at = |frame: u64| -> Result<i64> {
            if let Some(&time) = known.get(&frame) {
                return Ok(time);
            }
            let time = timestamp(frame)?;
            known.insert(frame, time);
            Ok(time)
        };
        self.chained
            .iter()
            .map(|chained| Ok(at(chained.executed)?.saturating_sub(at(chained.beacon)?)))
            .collect()
    }

    /// What settling pays of the held rewards when `timely` of the roots
    /// count as published: their share of the proposals expected, at most
    /// all of them.
    pub fn release(&self, timely: u64) -> num_bigint::BigInt {
        let pending = self.pending_amount();
        let published = (timely.min(self.frames) as u128).saturating_mul(PROPOSAL as u128);
        if self.expected == 0 || published >= self.expected as u128 {
            return pending;
        }
        pending * num_bigint::BigInt::from(published) / num_bigint::BigInt::from(self.expected)
    }
}

/// A member's seat on one shard.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Seat {
    pub member: [u8; 32],
    pub filter: Vec<u8>,
    /// Ascending by epoch.
    pub slots: Vec<SeatSlot>,
}

/// `poseidon("STORAGE_SEAT" || member || filter)`.
pub fn seat_address(member: &[u8], filter: &[u8]) -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(12 + member.len() + filter.len());
    preimage.extend_from_slice(b"STORAGE_SEAT");
    preimage.extend_from_slice(member);
    preimage.extend_from_slice(filter);
    quil_crypto::poseidon::hash_bytes_to_32(&preimage)
}

/// Fold one committed frame into a seat's chain.
pub fn accumulate(
    accumulator: &[u8; 32],
    frame_number: u64,
    rho_n: &[u8],
    root: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DST_FRAMES);
    h.update(accumulator);
    h.update(frame_number.to_be_bytes());
    h.update((rho_n.len() as u32).to_be_bytes());
    h.update(rho_n);
    h.update(root);
    h.finalize().into()
}

/// The chain over `frames` from the start.
pub fn chain<'a>(frames: impl IntoIterator<Item = (u64, &'a [u8], &'a [u8; 32])>) -> [u8; 32] {
    frames
        .into_iter()
        .fold([0u8; 32], |acc, (frame, rho_n, root)| {
            accumulate(&acc, frame, rho_n, root)
        })
}

/// GLOBAL frames `[from, until)` in which an epoch proof may settle `epoch`:
/// from the lockstep window after the epoch ended (no frame anchored in it can
/// be executed later; `audit_storage_attestation`) to the end of the next.
pub fn settlement_window(epoch: u64) -> (u64, u64) {
    let length = quil_types::consensus::epoch_length_frames();
    let next = epoch.saturating_add(1).saturating_mul(length);
    (
        next.saturating_add(super::frame_header::STORAGE_ANCHOR_LOCKSTEP_WINDOW)
            .saturating_add(1),
        next.saturating_add(length),
    )
}

impl Seat {
    pub fn new(member: [u8; 32], filter: Vec<u8>) -> Self {
        Self {
            member,
            filter,
            slots: Vec::new(),
        }
    }

    pub fn slot(&self, epoch: u64) -> Option<&SeatSlot> {
        self.slots.iter().find(|slot| slot.epoch == epoch)
    }

    fn slot_mut(&mut self, epoch: u64) -> Option<&mut SeatSlot> {
        self.slots.iter_mut().find(|slot| slot.epoch == epoch)
    }

    /// Record a registration of `leaves` for `epoch` at GLOBAL frame `frame`,
    /// replacing an earlier one for the same epoch (re-registering unseals,
    /// as for the leaf registrations).
    pub fn register(&mut self, epoch: u64, leaves: &[Vec<u32>], frame: u64) {
        let mut leaves = leaves.to_vec();
        leaves.sort();
        leaves.dedup();
        self.slots.retain(|slot| slot.epoch != epoch);
        self.slots.push(SeatSlot {
            epoch,
            leaves,
            registered_at: frame,
            ..Default::default()
        });
        self.slots.sort_by_key(|slot| slot.epoch);
        self.prune(quil_types::consensus::epoch_for_frame(frame));
    }

    /// Drop slots no settlement or kick can still need: two epochs past
    /// their own.
    pub fn prune(&mut self, current_epoch: u64) {
        self.slots
            .retain(|slot| slot.epoch.saturating_add(2) >= current_epoch);
        while self.slots.len() > MAX_SLOTS {
            self.slots.remove(0);
        }
    }

    /// Close every open slot whose settlement window ended before `frame`.
    /// True when one of them had committed a root: its member never proved
    /// what it committed, and is kicked. From the storage kick suspension
    /// epoch such a slot only forfeits its held shares, as every expired
    /// slot does, and is logged; the member is not kicked.
    pub fn expire(&mut self, frame: u64) -> bool {
        let suspended = quil_types::consensus::storage_kicks_suspended(frame);
        let mut kick = false;
        for slot in &mut self.slots {
            if slot.outcome == Outcome::Open && frame >= settlement_window(slot.epoch).1 {
                slot.outcome = Outcome::Expired(frame);
                slot.chained.clear();
                if slot.frames == 0 {
                    continue;
                }
                if suspended {
                    tracing::warn!(
                        frame,
                        member = %hex::encode(self.member),
                        shard = %hex::encode(&self.filter),
                        epoch = slot.epoch,
                        frames = slot.frames,
                        withheld = %slot.pending_amount(),
                        "storage epoch proof missing for committed openings: share withheld, not kicked"
                    );
                } else {
                    kick = true;
                }
            }
        }
        kick
    }

    /// The participant's part in app frame `app_frame`, anchored in `epoch`,
    /// of a committee of `committee` members, executed in GLOBAL frame
    /// `frame`: the frame counts toward the proposals expected of it, once,
    /// and `amount` is held, once per GLOBAL frame as `apply_reward` pays.
    /// False when nothing is held: no sealed open registration for the epoch,
    /// nothing to hold, or this GLOBAL frame already held one.
    pub fn hold(
        &mut self,
        epoch: u64,
        frame: u64,
        app_frame: u64,
        amount: &num_bigint::BigInt,
        committee: usize,
    ) -> bool {
        let Some(slot) = self.slot_mut(epoch) else {
            return false;
        };
        if !slot.is_sealed() || slot.outcome != Outcome::Open {
            return false;
        }
        if app_frame > slot.counted_through {
            slot.expected = slot
                .expected
                .saturating_add(PROPOSAL / committee.max(1) as u64);
            slot.counted_through = app_frame;
        }
        if slot.held_through >= frame || amount.sign() != num_bigint::Sign::Plus {
            return false;
        }
        let total = slot.pending_amount() + amount;
        slot.pending = total.to_bytes_be().1;
        if slot.pending == [0] {
            slot.pending.clear();
        }
        slot.held_through = frame;
        true
    }

    /// Chain the root the member committed in app frame `frame_number`,
    /// anchored in `epoch`, at the beacon `rho_n` of GLOBAL frame `beacon`,
    /// executed in GLOBAL frame `executed`. False when the member holds no
    /// sealed open registration for the epoch, or the frame is not past the
    /// last one chained (a frame applied again).
    pub fn commit(
        &mut self,
        epoch: u64,
        frame_number: u64,
        beacon: u64,
        executed: u64,
        rho_n: &[u8],
        root: &[u8; 32],
    ) -> bool {
        let Some(slot) = self.slot_mut(epoch) else {
            return false;
        };
        let last = slot.chained.last().map_or(0, |chained| chained.frame);
        if !slot.is_sealed()
            || slot.outcome != Outcome::Open
            || frame_number <= last
            || slot.chained.len() >= MAX_CHAINED
        {
            return false;
        }
        slot.accumulator = accumulate(&slot.accumulator, frame_number, rho_n, root);
        slot.frames += 1;
        slot.chained.push(Chained {
            frame: frame_number,
            beacon,
            executed,
        });
        true
    }

    /// Whether `epoch` has chained exactly one root: its seat joins the
    /// epoch's expiry queue then.
    pub fn first_commitment(&self, epoch: u64) -> bool {
        self.slot(epoch).is_some_and(|slot| slot.frames == 1)
    }

    /// Whether the member holds a sealed registration for `epoch`.
    pub fn sealed_for(&self, epoch: u64) -> bool {
        self.slot(epoch).is_some_and(SeatSlot::is_sealed)
    }

    /// Mark `epoch`'s registration sealed at `frame`.
    pub fn seal(&mut self, epoch: u64, frame: u64) -> bool {
        match self.slot_mut(epoch) {
            Some(slot) if slot.sealed_at.is_none() && !slot.leaves.is_empty() => {
                slot.sealed_at = Some(frame);
                true
            }
            _ => false,
        }
    }

    /// Settle `epoch` at `frame` with `timely` roots published: the rewards
    /// it releases ([`SeatSlot::release`]). `None` when it is not open.
    pub fn settle(&mut self, epoch: u64, frame: u64, timely: u64) -> Option<num_bigint::BigInt> {
        let slot = self.slot_mut(epoch)?;
        if slot.outcome != Outcome::Open {
            return None;
        }
        slot.outcome = Outcome::Settled(frame);
        slot.chained.clear();
        Some(slot.release(timely))
    }

    pub fn to_tree(&self) -> Result<quil_tries::VectorCommitmentTree> {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        write_type(&mut tree, CLASS)?;
        write_field(&mut tree, CLASS, "Member", &self.member)?;
        write_field(&mut tree, CLASS, "ShardFilter", &self.filter)?;
        write_field(&mut tree, CLASS, "Slots", &encode_slots(&self.slots))?;
        Ok(tree)
    }

    pub fn from_tree(tree: &quil_tries::VectorCommitmentTree) -> Result<Self> {
        let field = |name| {
            read_field(tree, CLASS, name)
                .ok_or_else(|| QuilError::InvalidArgument(format!("storage seat has no {name}")))
        };
        let member = <[u8; 32]>::try_from(field("Member")?.as_slice()).map_err(|_| {
            QuilError::InvalidArgument("storage seat member is not 32 bytes".into())
        })?;
        Ok(Self {
            member,
            filter: field("ShardFilter")?,
            slots: decode_slots(&field("Slots")?)?,
        })
    }
}

/// The seat of `member` on `filter` in committed `state`.
pub fn read(state: &HypergraphState, member: &[u8; 32], filter: &[u8]) -> Result<Option<Seat>> {
    read_address(state, &seat_address(member, filter)?)
}

/// The seat at `address` in committed `state`.
pub fn read_address(state: &HypergraphState, address: &[u8; 32]) -> Result<Option<Seat>> {
    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
    match state.get(&GLOBAL_INTRINSIC_ADDRESS[..], address, &va_disc)? {
        Some(blob) if !blob.is_empty() => Seat::from_tree(
            &crate::prover_registry::rebuild_vertex_tree_from_blob(&blob),
        )
        .map(Some),
        _ => Ok(None),
    }
}

/// Whether GLOBAL frame `frame` forgives `member`'s kick at GLOBAL frame
/// `kick_frame`: from the storage kick suspension epoch, a kick in a
/// hash-proof epoch before it that closed one of the member's seats with
/// committed roots it never proved, in that very frame, as
/// [`Seat::expire`] kicked for. The seats are looked up on the filters of
/// the member's allocations, which the kick leaves in place, and an
/// expired slot is never changed again. False for any other kick, and
/// when no such seat is found.
pub fn kick_forgiven(
    state: &HypergraphState,
    member: &[u8; 32],
    kick_frame: u64,
    frame: u64,
) -> Result<bool> {
    use quil_types::consensus::{epoch_for_frame, hash_storage_proofs_at, storage_kicks_suspended};
    if !storage_kicks_suspended(frame)
        || storage_kicks_suspended(kick_frame)
        || !hash_storage_proofs_at(epoch_for_frame(kick_frame))
    {
        return Ok(false);
    }
    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
    let ha_disc = crate::hypergraph_state::hyperedge_adds_discriminator()?;
    let hyperedge = state.get(domain, member, &ha_disc)?.unwrap_or_default();
    let mut filters: Vec<Vec<u8>> = Vec::new();
    for allocation in super::materialize::hyperedge_allocation_addresses(&hyperedge)? {
        let Some(blob) = state
            .get(domain, &allocation, &va_disc)?
            .filter(|blob| !blob.is_empty())
        else {
            continue;
        };
        let tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&blob);
        if let Some(filter) = read_field(&tree, "allocation:ProverAllocation", "ConfirmationFilter")
        {
            if !filters.contains(&filter) {
                filters.push(filter);
            }
        }
    }
    for filter in filters {
        if let Some(seat) = read(state, member, &filter)? {
            if seat
                .slots
                .iter()
                .any(|slot| slot.outcome == Outcome::Expired(kick_frame) && slot.frames > 0)
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Write `seat` at GLOBAL frame `frame`.
pub fn write(state: &HypergraphState, frame: u64, seat: &Seat) -> Result<()> {
    let address = seat_address(&seat.member, &seat.filter)?;
    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
    let blob = crate::prover_registry::vertex_tree_to_blob(&seat.to_tree()?);
    state.set(
        &GLOBAL_INTRINSIC_ADDRESS[..],
        &address,
        &va_disc,
        frame,
        blob,
    )
}

/// Epochs whose queues are kept: a queue is swept two epochs after its own,
/// before the epoch that reuses its records begins.
const EXPIRY_RING: u64 = 4;

/// `poseidon("STORAGE_EXPIRY" || epoch mod 4 || bucket)`: the records are
/// reused, never removed, each naming the epoch it holds.
pub fn expiry_address(epoch: u64, bucket: u8) -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(16);
    preimage.extend_from_slice(b"STORAGE_EXPIRY");
    preimage.push((epoch % EXPIRY_RING) as u8);
    preimage.push(bucket);
    quil_crypto::poseidon::hash_bytes_to_32(&preimage)
}

fn expiry_bucket(seat: &[u8; 32]) -> u8 {
    (seat[0] as u64 % EXPIRY_BUCKETS) as u8
}

/// The seats queued in `epoch`'s `bucket`: none when its record holds
/// another epoch.
fn read_expiry(state: &HypergraphState, epoch: u64, bucket: u8) -> Result<Vec<u8>> {
    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
    let stored = match state.get(
        &GLOBAL_INTRINSIC_ADDRESS[..],
        &expiry_address(epoch, bucket)?,
        &va_disc,
    )? {
        Some(blob) if !blob.is_empty() => {
            let tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&blob);
            read_field(&tree, EXPIRY_CLASS, "Seats").unwrap_or_default()
        }
        _ => Vec::new(),
    };
    Ok(match stored.split_at_checked(8) {
        Some((held, seats)) if held == epoch.to_be_bytes() && seats.len() % 32 == 0 => {
            seats.to_vec()
        }
        _ => Vec::new(),
    })
}

fn write_expiry(
    state: &HypergraphState,
    frame: u64,
    epoch: u64,
    bucket: u8,
    seats: &[u8],
) -> Result<()> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    write_type(&mut tree, EXPIRY_CLASS)?;
    write_field(
        &mut tree,
        EXPIRY_CLASS,
        "Seats",
        &[&epoch.to_be_bytes()[..], seats].concat(),
    )?;
    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
    state.set(
        &GLOBAL_INTRINSIC_ADDRESS[..],
        &expiry_address(epoch, bucket)?,
        &va_disc,
        frame,
        crate::prover_registry::vertex_tree_to_blob(&tree),
    )
}

/// Queue the seat at `seat` for `epoch`'s expiry sweep, at GLOBAL frame
/// `frame`: once, when it chains its first root of the epoch.
pub fn enqueue_expiry(
    state: &HypergraphState,
    frame: u64,
    epoch: u64,
    seat: &[u8; 32],
) -> Result<()> {
    let bucket = expiry_bucket(seat);
    let mut seats = read_expiry(state, epoch, bucket)?;
    if seats.chunks_exact(32).any(|queued| queued == seat) {
        return Ok(());
    }
    seats.extend_from_slice(seat);
    write_expiry(state, frame, epoch, bucket, &seats)
}

/// The expiry sweep's work at GLOBAL frame `frame`: the epoch whose window
/// closed when the epoch `frame` is in began, and the buckets of it to sweep
/// now (each once, in the first frames of the epoch).
pub fn expiry_buckets_due(frame: u64) -> Option<(u64, Vec<u8>)> {
    let length = quil_types::consensus::epoch_length_frames().max(1);
    let current = quil_types::consensus::epoch_for_frame(frame);
    let epoch = current.checked_sub(2)?;
    let frames = EXPIRY_BUCKETS.min(length);
    let offset = frame.checked_sub(current * length)?;
    (offset < frames).then(|| {
        (
            epoch,
            (offset..EXPIRY_BUCKETS)
                .step_by(frames as usize)
                .map(|bucket| bucket as u8)
                .collect(),
        )
    })
}

/// The expiry sweep at GLOBAL frame `frame` ([`expiry_buckets_due`]): closes
/// each queued seat whose settlement window ended, and returns those whose
/// member committed roots it never proved, to be kicked.
pub fn sweep_expiries(state: &HypergraphState, frame: u64) -> Result<Vec<Seat>> {
    let Some((epoch, buckets)) = expiry_buckets_due(frame) else {
        return Ok(Vec::new());
    };
    if !quil_types::consensus::hash_storage_proofs_at(epoch) {
        return Ok(Vec::new());
    }
    let mut kicks = Vec::new();
    for bucket in buckets {
        for address in take_expiry(state, frame, epoch, bucket)? {
            let Some(mut seat) = read_address(state, &address)? else {
                continue;
            };
            let before = seat.clone();
            let kick = seat.expire(frame);
            if seat != before {
                write(state, frame, &seat)?;
            }
            if kick {
                kicks.push(seat);
            }
        }
    }
    Ok(kicks)
}

/// Take `epoch`'s queued seats in `bucket` for the sweep at GLOBAL frame
/// `frame`, emptying the bucket.
pub fn take_expiry(
    state: &HypergraphState,
    frame: u64,
    epoch: u64,
    bucket: u8,
) -> Result<Vec<[u8; 32]>> {
    let seats = read_expiry(state, epoch, bucket)?;
    if seats.is_empty() {
        return Ok(Vec::new());
    }
    write_expiry(state, frame, epoch, bucket, &[])?;
    Ok(seats
        .chunks_exact(32)
        .map(|seat| seat.try_into().expect("32 bytes"))
        .collect())
}

pub fn encode_slots(slots: &[SeatSlot]) -> Vec<u8> {
    let mut out = vec![SLOTS_VERSION, slots.len() as u8];
    for slot in slots {
        put_u64(&mut out, slot.epoch);
        put_u32(&mut out, slot.leaves.len() as u32);
        for leaf in &slot.leaves {
            put_u32(&mut out, leaf.len() as u32);
            for nibble in leaf {
                put_u32(&mut out, *nibble);
            }
        }
        put_u64(&mut out, slot.registered_at);
        match slot.sealed_at {
            Some(frame) => {
                out.push(1);
                put_u64(&mut out, frame);
            }
            None => out.push(0),
        }
        put_u64(&mut out, slot.frames);
        out.extend_from_slice(&slot.accumulator);
        // Ascending frames as gaps, beacon frames as zigzag steps, executing
        // frames past their beacon frames: about three bytes a frame.
        put_u32(&mut out, slot.chained.len() as u32);
        let (mut frame, mut beacon) = (0u64, 0u64);
        for chained in &slot.chained {
            put_varint(&mut out, chained.frame - frame);
            put_varint(&mut out, zigzag(chained.beacon.wrapping_sub(beacon) as i64));
            put_varint(&mut out, chained.executed.wrapping_sub(chained.beacon));
            (frame, beacon) = (chained.frame, chained.beacon);
        }
        put_u64(&mut out, slot.expected);
        put_u64(&mut out, slot.counted_through);
        put_u64(&mut out, slot.held_through);
        put_u32(&mut out, slot.pending.len() as u32);
        out.extend_from_slice(&slot.pending);
        match slot.outcome {
            Outcome::Open => out.push(0),
            Outcome::Settled(frame) => {
                out.push(1);
                put_u64(&mut out, frame);
            }
            Outcome::Expired(frame) => {
                out.push(2);
                put_u64(&mut out, frame);
            }
        }
    }
    out
}

pub fn decode_slots(data: &[u8]) -> Result<Vec<SeatSlot>> {
    let invalid = |what: &str| QuilError::InvalidArgument(format!("storage seat slots: {what}"));
    let mut c = 0usize;
    let byte = |c: &mut usize| -> Result<u8> {
        let b = *data.get(*c).ok_or_else(|| invalid("truncated"))?;
        *c += 1;
        Ok(b)
    };
    if byte(&mut c)? != SLOTS_VERSION {
        return Err(invalid("unknown version"));
    }
    let count = byte(&mut c)? as usize;
    if count > MAX_SLOTS {
        return Err(invalid("too many slots"));
    }
    let mut slots = Vec::with_capacity(count);
    for _ in 0..count {
        let epoch = read_u64(data, &mut c)?;
        let leaf_count = read_u32(data, &mut c)? as usize;
        if leaf_count > MAX_LEAVES {
            return Err(invalid("too many leaves"));
        }
        let mut leaves = Vec::with_capacity(leaf_count);
        for _ in 0..leaf_count {
            let len = read_u32(data, &mut c)? as usize;
            if len > MAX_PREFIX {
                return Err(invalid("prefix too long"));
            }
            leaves.push(
                (0..len)
                    .map(|_| read_u32(data, &mut c))
                    .collect::<Result<Vec<u32>>>()?,
            );
        }
        let registered_at = read_u64(data, &mut c)?;
        let sealed_at = match byte(&mut c)? {
            0 => None,
            1 => Some(read_u64(data, &mut c)?),
            _ => return Err(invalid("bad seal flag")),
        };
        let frames = read_u64(data, &mut c)?;
        let accumulator: [u8; 32] = read_bytes(data, &mut c, 32)?.try_into().expect("32 bytes");
        let chained_count = read_u32(data, &mut c)? as usize;
        if chained_count > MAX_CHAINED {
            return Err(invalid("too many chained frames"));
        }
        let mut chained = Vec::with_capacity(chained_count);
        let (mut frame, mut beacon) = (0u64, 0u64);
        for _ in 0..chained_count {
            let gap = read_varint(data, &mut c).ok_or_else(|| invalid("bad frame gap"))?;
            let step = read_varint(data, &mut c).ok_or_else(|| invalid("bad beacon step"))?;
            let lag = read_varint(data, &mut c).ok_or_else(|| invalid("bad execution lag"))?;
            frame = frame
                .checked_add(gap)
                .filter(|_| gap > 0)
                .ok_or_else(|| invalid("frames not ascending"))?;
            beacon = beacon.wrapping_add(unzigzag(step) as u64);
            chained.push(Chained {
                frame,
                beacon,
                executed: beacon.wrapping_add(lag),
            });
        }
        let expected = read_u64(data, &mut c)?;
        let counted_through = read_u64(data, &mut c)?;
        let held_through = read_u64(data, &mut c)?;
        let pending_len = read_u32(data, &mut c)? as usize;
        if pending_len > 32 {
            return Err(invalid("pending amount too wide"));
        }
        let pending = read_bytes(data, &mut c, pending_len)?;
        let outcome = match byte(&mut c)? {
            0 => Outcome::Open,
            1 => Outcome::Settled(read_u64(data, &mut c)?),
            2 => Outcome::Expired(read_u64(data, &mut c)?),
            _ => return Err(invalid("bad outcome")),
        };
        slots.push(SeatSlot {
            epoch,
            leaves,
            registered_at,
            sealed_at,
            frames,
            accumulator,
            chained,
            expected,
            counted_through,
            held_through,
            pending,
            outcome,
        });
    }
    if c != data.len() {
        return Err(invalid("trailing bytes"));
    }
    Ok(slots)
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// A minimal LEB128 value, at most ten bytes.
fn read_varint(data: &[u8], c: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for i in 0..10 {
        let byte = *data.get(*c)?;
        *c += 1;
        if i == 9 && byte > 1 {
            return None;
        }
        value |= u64::from(byte & 0x7F) << (7 * i);
        if byte & 0x80 == 0 {
            return (byte != 0 || i == 0).then_some(value);
        }
    }
    None
}

fn zigzag(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)) as u64
}

fn unzigzag(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;

    fn sealed_seat(epoch: u64) -> Seat {
        let mut seat = Seat::new([7; 32], vec![1, 2, 3]);
        let frame = epoch.saturating_sub(1) * quil_types::consensus::epoch_length_frames() + 20;
        seat.register(epoch, &[vec![1], vec![0]], frame);
        assert!(seat.seal(epoch, frame + 5));
        seat
    }

    #[test]
    fn a_seat_survives_its_encoding() {
        let mut seat = sealed_seat(9);
        seat.hold(9, 100, 39, &BigInt::from(123_456_789u64), 4);
        seat.commit(9, 40, 530, 532, &[3; 32], &[4; 32]);
        seat.commit(9, 300, 526, 540, &[3; 32], &[4; 32]);
        seat.register(
            10,
            &[vec![2, 1]],
            9 * quil_types::consensus::epoch_length_frames() + 30,
        );
        let back = Seat::from_tree(&seat.to_tree().unwrap()).unwrap();
        assert_eq!(back, seat);
        assert_eq!(
            back.slot(9).unwrap().leaves,
            vec![vec![0], vec![1]],
            "leaves are kept sorted"
        );
        assert_eq!(
            back.slot(9).unwrap().chained,
            vec![
                Chained {
                    frame: 40,
                    beacon: 530,
                    executed: 532
                },
                Chained {
                    frame: 300,
                    beacon: 526,
                    executed: 540
                },
            ]
        );
        assert_eq!(
            back.slot(9).unwrap().view().chained,
            vec![(40, 530), (300, 526)],
            "members list beacon frames"
        );
        let encoded = encode_slots(&seat.slots);
        assert!(decode_slots(&encoded[..encoded.len() - 1]).is_err());
        assert!(decode_slots(&[encoded.as_slice(), &[0]].concat()).is_err());
        for value in [0, 1, 127, 128, 300, u64::MAX] {
            let mut out = Vec::new();
            put_varint(&mut out, value);
            assert_eq!(read_varint(&out, &mut 0), Some(value));
            assert_eq!(unzigzag(zigzag(value as i64)), value as i64);
        }
        assert_eq!(read_varint(&[0x80, 0x00], &mut 0), None, "not minimal");
        assert_eq!(read_varint(&[0xFF; 10], &mut 0), None, "past 64 bits");
    }

    #[test]
    fn only_a_sealed_registration_holds_rewards_once_per_global_frame() {
        let mut seat = Seat::new([7; 32], vec![1]);
        seat.register(
            5,
            &[vec![]],
            4 * quil_types::consensus::epoch_length_frames() + 20,
        );
        assert!(!seat.hold(5, 100, 30, &BigInt::from(10), 4), "unsealed");
        assert!(seat.seal(5, 4 * quil_types::consensus::epoch_length_frames() + 25));
        assert!(
            !seat.hold(6, 100, 30, &BigInt::from(10), 4),
            "no registration for that epoch"
        );
        assert!(seat.hold(5, 100, 30, &BigInt::from(10), 4));
        assert!(
            !seat.hold(5, 100, 30, &BigInt::from(10), 4),
            "the same app frame again"
        );
        assert!(
            !seat.hold(5, 100, 31, &BigInt::from(10), 4),
            "another app frame in the same GLOBAL frame"
        );
        assert!(seat.hold(5, 101, 32, &BigInt::from(5), 4));
        let slot = seat.slot(5).unwrap();
        assert_eq!(slot.pending_amount(), BigInt::from(15));
        assert_eq!(
            slot.expected,
            3 * PROPOSAL / 4,
            "every app frame counts toward the proposals expected"
        );
    }

    #[test]
    fn commitments_chain_in_frame_order_and_match_the_chain_of_their_list() {
        let mut seat = sealed_seat(5);
        assert!(seat.commit(5, 10, 301, 302, &[1; 32], &[2; 32]));
        assert!(
            !seat.commit(5, 10, 301, 303, &[1; 32], &[2; 32]),
            "a frame applied again"
        );
        assert!(
            !seat.commit(5, 9, 300, 303, &[1; 32], &[2; 32]),
            "an earlier frame"
        );
        // GLOBAL never executed frame 11.
        assert!(seat.commit(5, 12, 303, 304, &[3; 32], &[4; 32]));
        let slot = seat.slot(5).unwrap();
        assert_eq!(
            (slot.frames, slot.chained.clone()),
            (
                2,
                vec![
                    Chained {
                        frame: 10,
                        beacon: 301,
                        executed: 302
                    },
                    Chained {
                        frame: 12,
                        beacon: 303,
                        executed: 304
                    },
                ]
            )
        );
        assert_eq!(
            slot.accumulator,
            chain([
                (10, &[1u8; 32][..], &[2u8; 32]),
                (12, &[3u8; 32][..], &[4u8; 32])
            ])
        );
        assert_ne!(
            slot.accumulator,
            chain([
                (12, &[3u8; 32][..], &[4u8; 32]),
                (10, &[1u8; 32][..], &[2u8; 32])
            ])
        );
    }

    #[test]
    fn settling_pays_the_share_of_expected_proposals_the_member_published() {
        let mut seat = sealed_seat(5);
        for frame in 0..20 {
            seat.hold(5, 100 + frame, 40 + frame, &BigInt::from(10), 4);
        }
        // Twenty frames of a four-member committee: five proposals expected.
        assert_eq!(seat.slot(5).unwrap().expected, 5 * PROPOSAL);
        assert_eq!(
            seat.clone().settle(5, 900, 0),
            Some(BigInt::from(0)),
            "no commitment"
        );
        assert!(seat.commit(5, 41, 300, 301, &[1; 32], &[2; 32]));
        assert!(seat.commit(5, 45, 304, 305, &[1; 32], &[2; 32]));
        assert_eq!(
            seat.clone().settle(5, 900, 2),
            Some(BigInt::from(80)),
            "two of five: 40%"
        );
        assert_eq!(
            seat.clone().settle(5, 900, 1),
            Some(BigInt::from(40)),
            "one of them late: 20%"
        );
        assert_eq!(
            seat.clone().settle(5, 900, 9),
            Some(BigInt::from(80)),
            "never more than were chained"
        );
        let mut busy = seat.clone();
        for frame in [49, 53, 57, 58] {
            assert!(busy.commit(5, frame, 310, 311, &[1; 32], &[2; 32]));
        }
        assert_eq!(
            busy.settle(5, 900, 6),
            Some(BigInt::from(200)),
            "more than expected: all of it"
        );
        assert_eq!(seat.settle(5, 900, 2), Some(BigInt::from(80)));
        assert_eq!(
            seat.slot(5).unwrap().chained,
            vec![],
            "nothing left to list"
        );
        assert_eq!(seat.settle(5, 901, 2), None, "settled once");
        assert!(
            !seat.hold(5, 200, 70, &BigInt::from(10), 4),
            "a settled epoch holds nothing more"
        );
    }

    /// A root counts as published only if GLOBAL executed it within the
    /// response window of its beacon frame, by their timestamps: not by how
    /// many GLOBAL frames lie between them.
    #[test]
    fn a_root_counts_only_if_executed_within_the_response_window_of_its_beacon() {
        let mut seat = sealed_seat(5);
        // Frames 300.. come every 10 s; 320 after a 5 minute pause.
        let timestamp = |frame: u64| -> Result<i64> {
            match frame {
                300..=319 => Ok(1_000_000 + (frame as i64 - 300) * 10_000),
                320..=330 => Ok(1_000_000 + 190_000 + 300_000 + (frame as i64 - 320) * 10_000),
                _ => Err(QuilError::ExecutionUnavailable(format!("no frame {frame}"))),
            }
        };
        assert!(seat.commit(5, 41, 300, 301, &[1; 32], &[2; 32]), "10 s");
        assert!(
            seat.commit(5, 42, 300, 306, &[1; 32], &[2; 32]),
            "60 s: the window's edge"
        );
        assert!(seat.commit(5, 43, 301, 308, &[1; 32], &[2; 32]), "70 s");
        assert!(
            seat.commit(5, 44, 319, 320, &[1; 32], &[2; 32]),
            "one frame, but 300 s"
        );
        assert!(seat.commit(5, 45, 320, 322, &[1; 32], &[2; 32]), "20 s");
        let slot = seat.slot(5).unwrap();
        let times = slot.response_times(timestamp).unwrap();
        assert_eq!(times, vec![10_000, 60_000, 70_000, 300_000, 20_000]);
        assert_eq!(
            times
                .iter()
                .filter(|&&time| time <= RESPONSE_WINDOW_MS)
                .count(),
            3
        );
        assert!(
            slot.response_times(|frame| if frame == 322 {
                Err(QuilError::ExecutionUnavailable("gap".into()))
            } else {
                timestamp(frame)
            })
            .is_err(),
            "a missing GLOBAL frame waits, never counts either way"
        );
    }

    #[test]
    fn a_commitment_names_its_root_and_beacon_frame() {
        let root = quil_crypto::storage_hash::to_bytes(&quil_crypto::storage_hash::key_digest(
            b"openings",
        ));
        let bytes = encode_commitment(&root, 1234);
        assert_eq!(bytes.len(), 40);
        assert_eq!(decode_commitment(&bytes), Some((root, 1234)));
        assert_eq!(
            decode_commitment(&root),
            None,
            "a bare root names no beacon frame"
        );
        assert_eq!(decode_commitment(&[bytes.as_slice(), &[0]].concat()), None);
        assert_eq!(
            decode_commitment(&[[0xFF; 32].as_slice(), &1234u64.to_be_bytes()].concat()),
            None,
            "not a root"
        );
        assert!(commitment_acceptable(&[], 1234), "no commitment");
        assert!(commitment_acceptable(&bytes, 1234) && commitment_acceptable(&bytes, 1230));
        assert!(
            !commitment_acceptable(&bytes, 1235),
            "a beacon before the anchor"
        );
        assert!(!commitment_acceptable(&root, 1000), "a bare root");
    }

    struct StubProver;
    impl quil_types::crypto::InclusionProver for StubProver {
        fn commit_raw(&self, _: &[u8], _: u64) -> Result<Vec<u8>> {
            Ok(vec![0u8; 64])
        }
        fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> {
            Ok(vec![])
        }
        fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> {
            Ok(true)
        }
        fn prove_multiple(
            &self,
            _: &[&[u8]],
            _: &[&[u8]],
            _: &[u64],
            _: u64,
        ) -> Result<Box<dyn quil_types::crypto::Multiproof>> {
            Err(QuilError::Internal("batch not supported".into()))
        }
        fn verify_multiple(
            &self,
            _: &[&[u8]],
            _: &[&[u8]],
            _: &[u64],
            _: u64,
            _: &[u8],
            _: &[u8],
        ) -> bool {
            true
        }
    }

    /// A member that commits a root and is never heard from again is still
    /// kicked: its seat joined the epoch's expiry queue at its first root, and
    /// the sweep closes the queue a bucket per frame once the window ends.
    #[test]
    fn the_expiry_sweep_kicks_each_unproven_committer_once_even_if_it_never_returns() {
        let length = quil_types::consensus::epoch_length_frames();
        let epoch = 5;
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch));
        let state =
            HypergraphState::new(std::sync::Arc::new(quil_hypergraph::HypergraphCrdt::new(
                std::sync::Arc::new(crate::hypergraph_state::InMemoryHypergraphStore::new()),
                std::sync::Arc::new(StubProver),
            )));
        let frame = epoch * length + 30;
        let mut addresses = Vec::new();
        // Members 1 and 2 commit and vanish, 3 commits and settles, 4 never
        // commits.
        for (member, commits, settles) in [
            (1u8, true, false),
            (2, true, false),
            (3, true, true),
            (4, false, false),
        ] {
            let mut seat = sealed_seat(epoch);
            seat.member = [member; 32];
            if commits {
                assert!(seat.commit(epoch, 40, frame - 3, frame - 2, &[1; 32], &[2; 32]));
                assert!(seat.first_commitment(epoch));
                assert!(seat.commit(epoch, 44, frame - 2, frame - 1, &[1; 32], &[2; 32]));
                assert!(!seat.first_commitment(epoch));
                let address = seat_address(&seat.member, &seat.filter).unwrap();
                enqueue_expiry(&state, frame, epoch, &address).unwrap();
                enqueue_expiry(&state, frame, epoch, &address).unwrap();
                addresses.push(address);
            }
            if settles {
                seat.settle(epoch, settlement_window(epoch).0, 2).unwrap();
            }
            write(&state, frame, &seat).unwrap();
        }
        let close = settlement_window(epoch).1;
        assert_eq!(close, (epoch + 2) * length);
        assert!(
            sweep_expiries(&state, close - 1).unwrap().is_empty(),
            "the window is still open"
        );
        let mut kicked = Vec::new();
        for frame in close..close + EXPIRY_BUCKETS + 2 {
            kicked.extend(
                sweep_expiries(&state, frame)
                    .unwrap()
                    .into_iter()
                    .map(|seat| seat.member[0]),
            );
        }
        kicked.sort();
        assert_eq!(
            kicked,
            vec![1, 2],
            "each unproven committer once; the settled one and the idle one not"
        );
        for member in [1u8, 2] {
            let seat = read(&state, &[member; 32], &[1, 2, 3]).unwrap().unwrap();
            assert!(matches!(
                seat.slot(epoch).unwrap().outcome,
                Outcome::Expired(_)
            ));
        }
        for address in &addresses {
            let bucket = expiry_bucket(address);
            assert!(
                read_expiry(&state, epoch, bucket).unwrap().is_empty(),
                "swept"
            );
            assert!(
                read_expiry(&state, epoch + 4, bucket).unwrap().is_empty(),
                "a ring slot holds one epoch"
            );
        }
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }

    #[test]
    fn each_expiry_bucket_is_due_once() {
        let length = quil_types::consensus::epoch_length_frames();
        let mut due = Vec::new();
        for frame in 0..6 * length {
            if let Some((epoch, buckets)) = expiry_buckets_due(frame) {
                assert_eq!(epoch + 2, quil_types::consensus::epoch_for_frame(frame));
                due.extend(buckets.into_iter().map(|bucket| (epoch, bucket)));
            }
        }
        let expected: Vec<(u64, u8)> = (0..4)
            .flat_map(|epoch| (0..EXPIRY_BUCKETS as u8).map(move |bucket| (epoch, bucket)))
            .collect();
        due.sort();
        assert_eq!(due, expected);
    }

    #[test]
    fn an_unsettled_epoch_expires_after_the_next_and_kicks_only_a_committer() {
        let length = quil_types::consensus::epoch_length_frames();
        let mut seat = sealed_seat(5);
        let (from, until) = settlement_window(5);
        assert_eq!((from, until), (6 * length + 13, 7 * length));
        assert!(!seat.expire(until - 1));
        let mut idle = seat.clone();
        assert!(!idle.expire(until), "nothing committed: forfeit only");
        assert_eq!(idle.slot(5).unwrap().outcome, Outcome::Expired(until));
        assert!(seat.commit(5, 40, 330, 331, &[1; 32], &[2; 32]));
        assert!(seat.expire(until));
        assert_eq!(seat.slot(5).unwrap().chained, vec![]);
        assert!(!seat.expire(until + 1), "expired once");
        seat.prune(8);
        assert!(seat.slot(5).is_none());
    }

    /// Suspend storage kicks from `epoch` on this thread; `None` restores
    /// the process setting.
    fn suspend_storage_kicks(epoch: Option<u64>) {
        quil_types::consensus::set_storage_kick_suspension_epoch_for_thread(epoch);
    }

    /// From the storage kick suspension epoch an unproven seat still closes
    /// and forfeits what it held, but no longer kicks its member: the last
    /// frame before the epoch kicks, its first frame does not.
    #[test]
    fn from_the_suspension_epoch_an_unproven_seat_withholds_its_share_without_a_kick() {
        let length = quil_types::consensus::epoch_length_frames();
        let suspension = 8;
        suspend_storage_kicks(Some(suspension));
        let mut seat = sealed_seat(5);
        assert!(seat.hold(5, 330, 39, &BigInt::from(1_000), 4));
        assert!(seat.commit(5, 40, 330, 331, &[1; 32], &[2; 32]));
        let flag = suspension * length;
        assert!(flag > settlement_window(5).1);
        let mut before = seat.clone();
        assert!(
            before.expire(flag - 1),
            "the frame before the suspension epoch still kicks"
        );
        assert!(
            !seat.expire(flag),
            "a seat expiring from the suspension epoch kicked its member"
        );
        let slot = seat.slot(5).unwrap();
        assert_eq!(slot.outcome, Outcome::Expired(flag));
        assert_eq!(slot.chained, vec![]);
        assert_eq!(
            slot.pending_amount(),
            BigInt::from(1_000),
            "the share stays held, never paid"
        );
        assert!(
            seat.settle(5, flag + 1, 1).is_none(),
            "an expired epoch cannot be settled"
        );
        let mut idle = sealed_seat(5);
        assert!(!idle.expire(flag), "nothing committed: forfeit only");
        suspend_storage_kicks(None);
    }

    /// The expiry sweep in the epoch before the suspension epoch kicks an
    /// unproven committer; from it, it closes the seat without a kick.
    #[test]
    fn from_the_suspension_epoch_the_expiry_sweep_closes_without_kicking() {
        let epoch = 5;
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch));
        for (suspension, kicks) in [(epoch + 3, 1usize), (epoch + 2, 0)] {
            suspend_storage_kicks(Some(suspension));
            let state =
                HypergraphState::new(std::sync::Arc::new(quil_hypergraph::HypergraphCrdt::new(
                    std::sync::Arc::new(crate::hypergraph_state::InMemoryHypergraphStore::new()),
                    std::sync::Arc::new(StubProver),
                )));
            let frame = epoch * quil_types::consensus::epoch_length_frames() + 30;
            let mut seat = sealed_seat(epoch);
            assert!(seat.commit(epoch, 40, frame - 3, frame - 2, &[1; 32], &[2; 32]));
            let address = seat_address(&seat.member, &seat.filter).unwrap();
            enqueue_expiry(&state, frame, epoch, &address).unwrap();
            write(&state, frame, &seat).unwrap();
            let close = settlement_window(epoch).1;
            let mut kicked = 0;
            for frame in close..close + EXPIRY_BUCKETS + 2 {
                kicked += sweep_expiries(&state, frame).unwrap().len();
            }
            assert_eq!(
                kicked,
                kicks,
                "suspension epoch {suspension}: the sweep in epoch {} kicked {kicked}",
                epoch + 2
            );
            let seat = read(&state, &seat.member, &seat.filter).unwrap().unwrap();
            assert!(matches!(
                seat.slot(epoch).unwrap().outcome,
                Outcome::Expired(_)
            ));
        }
        suspend_storage_kicks(None);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }
}
