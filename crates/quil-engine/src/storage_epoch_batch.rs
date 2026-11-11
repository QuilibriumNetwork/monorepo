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
//!
//! GLOBAL withholds a member's storage share (before epoch 1342: kicks it)
//! for roots it committed and never proved by the settlement window's end,
//! so a settlement waits for no seal and no collection longer than its first
//! attempt, and for the next registration's seal at most a retry interval
//! into its window ([`settlement_due`]). A worker prepares a seat's
//! settlement and its seal in jobs of their own on every attempt
//! ([`part_jobs`]): a seal relabelling, or failing after it, never holds the
//! settlement's job. The node joins the halves it collected together into
//! one part ([`join_halves`]). A retry sends the settlement alone, and near
//! the window's end ([`settle_closing_frames`]), or past that wait, the
//! first attempt does too. A settlement sent alone goes again every
//! [`SETTLEMENT_RESEND_FRAMES`] GLOBAL frames until its slot shows it
//! settled: an archive drops a submission no frame carried after that many.
//! The node proves a settlement sent alone at once, beside any collection
//! waiting for its seat, and sends it again as the proof it made of it
//! before ([`reuse_settlement_proof`]), so archives hold one copy. A proof
//! carrying seals carries no settlement that already went out
//! ([`claim_settlements`]): GLOBAL refuses a proof whole when one of its
//! seats settles an epoch already settled.

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
const PERSISTENT_PART: u8 = 3;
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

/// GLOBAL frames before a settlement window's end from which a seat's
/// settlement waits for nothing: not for a seal that may still come, nor in
/// the seat's lane. A sixth of an epoch (120 frames, about 20 minutes, on
/// mainnet): room for two attempts
/// [`crate::storage_snapshot::seal_retry_frames`] apart.
pub fn settle_closing_frames() -> u64 {
    std::env::var("QUIL_SETTLE_CLOSING_FRAMES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| quil_types::consensus::epoch_length_frames() / 6)
}

/// Sealed leaves one proof holds at most.
pub fn chunk_leaves() -> usize {
    std::env::var("QUIL_EPOCH_PROOF_LEAVES")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(24)
}

fn memory_leaf_limit(configured: usize, all_native: bool, constrained: bool) -> usize {
    // Legacy AIR work scales with sealed leaves. Persistent native seals do
    // not allocate that AIR, so keep their efficient message-sized batches.
    if constrained && !all_native {
        configured.min(2)
    } else {
        configured
    }
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
        if kind == PART || kind == PERSISTENT_PART {
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
        let persistent = self
            .claim
            .seals
            .iter()
            .any(|leaf| leaf.persistent.is_some());
        out.push(if persistent { PERSISTENT_PART } else { PART });
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
            let root = leaf
                .persistent
                .map(|root| root.to_bytes())
                .unwrap_or_else(|| {
                    quil_crypto::storage_proof::registration_root(
                        &leaf.registered.comm_d,
                        &leaf.registered.comm_c,
                        &leaf.registered.comm_r,
                    )
                });
            if persistent {
                put_lp(&mut out, &root);
            } else {
                out.extend_from_slice(&root);
            }
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
        if persistent {
            for i in 0..self.claim.seals.len() {
                put_lp(
                    &mut out,
                    self.witness.certificates.get(i).map_or(&[], Vec::as_slice),
                );
            }
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
        let kind = c.take(1)?[0];
        if kind != PART && kind != PERSISTENT_PART {
            return Err(invalid("not a part"));
        }
        let persistent = kind == PERSISTENT_PART;
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
            let root = if persistent {
                c.lp(quil_crypto::persistent_storage::ROOT_BYTES)?
            } else {
                c.take(quil_crypto::storage_proof::REGISTRATION_ROOT_BYTES)?
            };
            let sector = quil_crypto::persistent_storage::Registration::parse(root);
            if sector.is_some() != quil_types::consensus::persistent_storage_at(part.seal_epoch()) {
                return Err(invalid("persistent storage is not active"));
            }
            let registered = quil_crypto::storage_proof::parse_registration_root(root)
                .ok_or_else(|| invalid("bad registration"))?;
            let beacon = c.lp(MAX_BEACON)?.to_vec();
            claim.seals.push(SealedLeaf {
                persistent: sector,
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
            certificates: Vec::new(),
            seals: Vec::with_capacity(seals),
            opened: Vec::new(),
        };
        for leaf in &claim.seals {
            let bytes = c.lp(MAX_SEAL_BYTES)?;
            witness.seals.push(
                quil_crypto::storage_proof::SealProof::from_bytes(
                    bytes,
                    leaf.n,
                    if leaf.persistent.is_some() {
                        1
                    } else {
                        params.layers
                    },
                    quil_types::consensus::STORAGE_SEAL_CHALLENGES,
                )
                .ok_or_else(|| invalid("bad plain seal"))?,
            );
        }
        if persistent {
            for _ in &claim.seals {
                witness
                    .certificates
                    .push(c.lp(epoch_proof::MAX_PROOF_LEN as usize)?.to_vec());
            }
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
                .claim
                .seals
                .iter()
                .zip(&self.witness.seals)
                .filter(|(leaf, _)| leaf.persistent.is_some())
                .map(|(leaf, proof)| {
                    8 + quil_crypto::persistent_storage::encode_proof(proof, leaf.n)
                        .map_or_else(|_| proof.to_bytes().len(), |p| p.len())
                })
                .sum::<usize>()
            + self
                .witness
                .certificates
                .iter()
                .map(|proof| 4 + proof.len())
                .sum::<usize>()
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
            certificates,
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
                certificates,
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
                certificates: Vec::new(),
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
                    certificates: seal.witness.certificates,
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
/// relabels each leaf at its challenges (about an hour per GiB). The
/// settlement is prepared first and kept at once, so that sending it alone
/// later prepares nothing, whether the seal is still relabelling or failed.
/// Returns the part, not solo, and whether a half was reused.
pub fn prepare_reusing(
    member: &[u8; 32],
    filter: &[u8],
    epoch: u64,
    seal: Option<PartInputs>,
    settle: Option<PartInputs>,
    mut prepare: impl FnMut(bool, bool) -> Result<PreparedSeat>,
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
    for (seals, settles) in [(false, settles), (seals, false)] {
        if !seals && !settles {
            continue;
        }
        let (fresh_seal, fresh_settle) = prepare(seals, settles)?.halves();
        if let Ok(mut parts) = prepared_parts().lock() {
            parts.retain(|(_, _, e), _| *e >= epoch.saturating_sub(1));
            let halves = parts.entry(key.clone()).or_default();
            if let (true, Some(inputs), Some(half)) = (seals, seal.clone(), fresh_seal.as_ref()) {
                halves.seal = Some((inputs, half.clone()));
            }
            if let (true, Some(inputs), Some(half)) =
                (settles, settle.clone(), fresh_settle.as_ref())
            {
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

/// One job preparing half of a seat's part ([`part_jobs`]): the half it
/// prepares, and whether the node's collection waits for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartJob {
    pub seals: bool,
    pub settles: bool,
    /// Announced to the node on the first attempt, so the member's
    /// collection waits for it (at most [`max_wait_secs`]); a settlement sent
    /// alone is proved at once instead.
    pub announced: bool,
}

/// The jobs preparing a seat's part, settlement first: each half in a job of
/// its own, on every attempt. A seal relabels its leaves (about an hour per
/// GiB) and can fail only after that: a leaf labelled under another replica
/// key fails at its column commitment after a full relabelling (mainnet,
/// 2026-11-08). A settlement prepared in the seal's job waited for it, past
/// its window's end, and GLOBAL withheld the member's held storage share.
/// `settle_alone`: a retry, or near the window's end, sends the settlement
/// alone, proved at once.
pub fn part_jobs(seals: bool, settles: bool, settle_alone: bool) -> Vec<PartJob> {
    let settle = settles.then_some(PartJob {
        seals: false,
        settles: true,
        announced: !settle_alone,
    });
    let seal = seals.then_some(PartJob {
        seals: true,
        settles: false,
        announced: true,
    });
    settle.into_iter().chain(seal).collect()
}

/// GLOBAL frames between sends of a settlement sent alone while its slot
/// shows it owed ([`settlement_due`]): an archive drops a submission no
/// GLOBAL frame carried after this many finalized frames
/// (`message_collector::RETENTION_WINDOW`). Sent once a retry interval (48
/// frames), every other send dropped by this node, a settlement was in
/// archives' mempools for about 50 of its window's last 400 frames, and its
/// seat expired (mainnet, 2026-11-08).
pub const SETTLEMENT_RESEND_FRAMES: u64 = 10;

/// A seat's settlement as its worker sees it at a GLOBAL frame
/// ([`settlement_due`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SettlementView {
    /// Its slot shows it owed: no epoch proof settled the epoch yet.
    pub owed: bool,
    /// The next registration's seal may still come and is not ready to
    /// prove: a registration whose beacon frame is not here yet, or one that
    /// may still land.
    pub seal_pending: bool,
    /// The GLOBAL frame this worker last sent it alone at
    /// ([`settlement_sent_alone_at`]).
    pub sent_alone_at: Option<u64>,
}

/// How a seat's settlement goes ([`settlement_due`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettleSend {
    /// Alone: the node proves it at once, not in the member's collection.
    pub alone: bool,
    /// Sent again now, apart from the seat's attempts
    /// (`crate::storage_snapshot::claim_epoch_proof`), without its seal.
    pub resend: bool,
}

/// Whether the settlement of `epoch` goes at GLOBAL frame `frame`, and how:
/// `None` outside its window, once its slot shows it settled, and while it
/// waits for the next registration's seal. It waits so the two share one
/// proof, from its window's opening for at most
/// [`crate::storage_snapshot::seal_retry_frames`], then goes alone: held for
/// a registration that landed 67 minutes into its window, a settlement first
/// went out among the window's capacity traffic, and its seat expired
/// (mainnet, 2026-11-08). Near the window's end ([`settle_closing_frames`])
/// it waits for nothing. Once sent alone, it goes again every
/// [`SETTLEMENT_RESEND_FRAMES`] while its slot shows it owed.
pub fn settlement_due(epoch: u64, frame: u64, view: SettlementView) -> Option<SettleSend> {
    let (from, until) = quil_execution::global_intrinsic::storage_seat::settlement_window(epoch);
    if !view.owed || !(from..until).contains(&frame) {
        return None;
    }
    let closing = frame >= until.saturating_sub(settle_closing_frames());
    let waited = frame >= from.saturating_add(crate::storage_snapshot::seal_retry_frames());
    if view.seal_pending && !closing && !waited && view.sent_alone_at.is_none() {
        return None;
    }
    Some(SettleSend {
        alone: closing || view.seal_pending || view.sent_alone_at.is_some(),
        resend: view
            .sent_alone_at
            .is_some_and(|at| frame >= at.saturating_add(SETTLEMENT_RESEND_FRAMES)),
    })
}

/// What a worker sent of a seat's settlement: the GLOBAL frames of its first
/// and last sends, how many, and the last sent alone.
#[derive(Debug, Clone, Copy)]
struct SettlementSends {
    first: u64,
    last: u64,
    sends: u32,
    alone_at: Option<u64>,
}

fn settlement_sends() -> &'static Mutex<HashMap<SettlementKey, SettlementSends>> {
    static SENDS: OnceLock<Mutex<HashMap<SettlementKey, SettlementSends>>> = OnceLock::new();
    SENDS.get_or_init(Default::default)
}

/// Note that this worker sent `member`'s settlement of `epoch` on `filter`
/// at GLOBAL frame `frame`, `alone` or in the member's collection.
pub fn note_settlement_sent(member: &[u8; 32], filter: &[u8], epoch: u64, frame: u64, alone: bool) {
    let Ok(mut sends) = settlement_sends().lock() else {
        return;
    };
    sends.retain(|(_, _, e), _| e.saturating_add(2) >= epoch);
    let sent = sends
        .entry((*member, filter.to_vec(), epoch))
        .or_insert(SettlementSends {
            first: frame,
            last: frame,
            sends: 0,
            alone_at: None,
        });
    sent.last = sent.last.max(frame);
    sent.sends = sent.sends.saturating_add(1);
    if alone {
        sent.alone_at = Some(sent.alone_at.map_or(frame, |at| at.max(frame)));
    }
}

/// The GLOBAL frame this worker last sent `member`'s settlement of `epoch`
/// on `filter` alone at ([`note_settlement_sent`]).
pub fn settlement_sent_alone_at(member: &[u8; 32], filter: &[u8], epoch: u64) -> Option<u64> {
    settlement_sends()
        .lock()
        .ok()?
        .get(&(*member, filter.to_vec(), epoch))
        .and_then(|sent| sent.alone_at)
}

/// How a settlement a worker sent ended ([`settlement_outcomes`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementOutcome {
    /// Its slot showed it settled within its window.
    Settled,
    /// Its window ended while its slot showed it owed in this worker's view.
    Unsettled,
}

/// Log once how each settlement this worker sent of `member`'s seat on
/// `filter` ended, as seen at GLOBAL frame `frame`: one line each, with its
/// sends; `open(epoch)` is what its slot shows (`None`: no slot in view).
/// Returns them by epoch, with the times each went again.
pub fn settlement_outcomes(
    member: &[u8; 32],
    filter: &[u8],
    frame: u64,
    open: impl Fn(u64) -> Option<bool>,
) -> Vec<(u64, SettlementOutcome, u32)> {
    let Ok(mut sends) = settlement_sends().lock() else {
        return Vec::new();
    };
    let mut ended = Vec::new();
    sends.retain(|(sent_member, sent_filter, epoch), sent| {
        if sent_member != member || sent_filter.as_slice() != filter {
            return true;
        }
        let epoch = *epoch;
        let (_, until) = quil_execution::global_intrinsic::storage_seat::settlement_window(epoch);
        let outcome = if frame >= until {
            SettlementOutcome::Unsettled
        } else if open(epoch) == Some(false) {
            SettlementOutcome::Settled
        } else {
            return true;
        };
        let resent = sent.sends.saturating_sub(1);
        match outcome {
            SettlementOutcome::Settled => {
                info!(epoch, filter = %hex::encode(filter), first_sent_frame = sent.first, last_sent_frame = sent.last,
                    resent, global_frame = frame, window_end = until,
                    "storage settlement recorded: its slot shows GLOBAL settled it");
            }
            SettlementOutcome::Unsettled => {
                warn!(epoch, filter = %hex::encode(filter), first_sent_frame = sent.first, last_sent_frame = sent.last,
                    resent, global_frame = frame, window_end = until,
                    "storage settlement not seen recorded by its window's end: no GLOBAL frame carried any of its sends in \
                     this node's view (which may trail GLOBAL by a registry pull); GLOBAL withholds the member's storage share for the \
                     unproven roots. Check this node's `storage epoch proof not delivered` lines and the GLOBAL frame rate");
            }
        }
        ended.push((epoch, outcome, resent));
        false
    });
    ended
}

/// A registration whose seal this process cannot prove: the member, the
/// shard, the epoch settled beside it (it seals `epoch + 2`), the frame it
/// was registered at and its leaves.
type UnprovableSeal = ([u8; 32], Vec<u8>, u64, u64, Vec<Vec<u32>>);

fn unprovable_seals() -> &'static Mutex<HashSet<UnprovableSeal>> {
    static UNPROVABLE: OnceLock<Mutex<HashSet<UnprovableSeal>>> = OnceLock::new();
    UNPROVABLE.get_or_init(Default::default)
}

/// Whether a seal failed for good: the registered column commitment is not
/// this build's labelling of the leaf
/// ([`quil_crypto::storage_proof::COLUMNS_NOT_REGISTERED`]). The columns
/// depend on the replica key, the leaf's size and the SDR parameters alone,
/// so every later attempt relabels the leaf to fail the same way.
pub fn seal_failed_for_good(error: &str) -> bool {
    error.contains(quil_crypto::storage_proof::COLUMNS_NOT_REGISTERED)
}

/// Note that `member`'s registration on `filter` for `epoch + 2`, made at
/// frame `registered_at` with `leaves`, cannot be sealed by this process
/// ([`seal_failed_for_good`]); true the first time.
pub fn note_unprovable_seal(
    member: &[u8; 32],
    filter: &[u8],
    epoch: u64,
    registered_at: u64,
    leaves: &[Vec<u32>],
) -> bool {
    let Ok(mut unprovable) = unprovable_seals().lock() else {
        return false;
    };
    unprovable.retain(|(_, _, e, _, _)| e.saturating_add(2) >= epoch);
    unprovable.insert((
        *member,
        filter.to_vec(),
        epoch,
        registered_at,
        leaves.to_vec(),
    ))
}

/// Whether the registration was noted unprovable
/// ([`note_unprovable_seal`]): its seal is not tried again.
pub fn seal_unprovable(
    member: &[u8; 32],
    filter: &[u8],
    epoch: u64,
    registered_at: u64,
    leaves: &[Vec<u32>],
) -> bool {
    unprovable_seals().lock().is_ok_and(|unprovable| {
        unprovable.contains(&(
            *member,
            filter.to_vec(),
            epoch,
            registered_at,
            leaves.to_vec(),
        ))
    })
}

/// What GLOBAL does with a seat's issuance in `seal_epoch` when its
/// registration for that epoch is not sealed, for the warn naming a failed
/// seal. From the unsealed issuance epoch (mainnet 1321) and before the
/// sealed storage epoch (mainnet 1467) an unsealed participant is paid its
/// share at once, so nothing is withheld; from the sealed storage epoch an
/// unsealed seat is not eligible for its committees.
pub fn unsealed_seat_outcome(seal_epoch: u64) -> &'static str {
    use quil_types::consensus::{sealed_storage_required, unsealed_issuance_epoch};
    if sealed_storage_required(seal_epoch) {
        "from the sealed storage epoch a seat without a sealed registration sits out its \
         committees in that epoch and earns nothing there"
    } else if seal_epoch >= unsealed_issuance_epoch() {
        "before the sealed storage epoch GLOBAL pays an unsealed participant its issuance \
         share at once: nothing is withheld for the missing seal"
    } else {
        "before the unsealed issuance epoch GLOBAL issues no share to a participant without \
         a sealed registration"
    }
}

/// A seat's settlement: its member, shard and the epoch it settles.
type SettlementKey = ([u8; 32], Vec<u8>, u64);

/// When this node sent each seat's settlement to GLOBAL ([`claim_settlements`]).
fn settlements_sent() -> &'static Mutex<HashMap<SettlementKey, Instant>> {
    static SENT: OnceLock<Mutex<HashMap<SettlementKey, Instant>>> = OnceLock::new();
    SENT.get_or_init(Default::default)
}

/// `seats` without the settlements this node already sent in parts that
/// seal, and the settlements they now send, claimed until their proof goes
/// out or fails ([`release_settlements`]): GLOBAL refuses a proof whole when
/// one of its seats settles an epoch already settled, losing the seals in
/// it. A part proved with the member's others gives up its settlement once
/// one went out, and proves its seal alone. A settlement sent alone goes
/// each time: its worker spaces the sends by GLOBAL frames until its slot
/// shows it settled ([`settlement_due`]), and a refused copy loses nothing
/// else. A node's own view of GLOBAL frames may stand still (one whose
/// workers run apart notes an epoch's start only), and a guard of 720 s of
/// wall time dropped every other one of its worker's sends at mainnet's
/// incident pace (2026-11-08). None is sent once its window has closed
/// (`crate::storage_snapshot::settlement_closed`): GLOBAL refuses it.
fn claim_settlements(seats: Vec<PreparedSeat>) -> (Vec<PreparedSeat>, Vec<SettlementKey>) {
    let Ok(mut sent) = settlements_sent().lock() else {
        return (seats, Vec::new());
    };
    let newest = seats.iter().map(|seat| seat.part.epoch).max().unwrap_or(0);
    sent.retain(|(_, _, e), _| e.saturating_add(1) >= newest);
    let (mut out, mut claimed) = (Vec::with_capacity(seats.len()), Vec::new());
    for seat in seats {
        if !seat.part.settles {
            out.push(seat);
            continue;
        }
        if crate::storage_snapshot::settlement_closed(seat.part.epoch, 0) {
            info!(member = %hex::encode(seat.member), shard = %hex::encode(&seat.part.shard_filter),
                epoch = seat.part.epoch, seals = seat.part.seals,
                "storage epoch proof: this seat's settlement window has closed; the part is not sent with it");
            if let (Some(seal), _) = seat.halves() {
                out.push(seal);
            }
            continue;
        }
        let key = (seat.member, seat.part.shard_filter.clone(), seat.part.epoch);
        let alone = seat.solo && !seat.part.seals;
        match sent.get(&key) {
            Some(at) if !alone => {
                info!(member = %hex::encode(seat.member), shard = %hex::encode(&seat.part.shard_filter),
                    epoch = seat.part.epoch, sent_secs_ago = at.elapsed().as_secs(), seals = seat.part.seals,
                    "storage epoch proof: this seat's settlement already went out; the part is not sent again with it");
                if let (Some(seal), _) = seat.halves() {
                    out.push(seal);
                }
            }
            _ => {
                sent.insert(key.clone(), Instant::now());
                claimed.push(key);
                out.push(seat);
            }
        }
    }
    (out, claimed)
}

/// The proof this node made of a settlement sent alone: the digest of the
/// part it proves, the proof, and the times it went again.
struct SettlementProof {
    part: [u8; 32],
    bytes: Arc<Vec<u8>>,
    resends: u32,
}

fn settlement_proofs() -> &'static Mutex<HashMap<SettlementKey, SettlementProof>> {
    static PROOFS: OnceLock<Mutex<HashMap<SettlementKey, SettlementProof>>> = OnceLock::new();
    PROOFS.get_or_init(Default::default)
}

fn part_digest(seat: &PreparedSeat) -> [u8; 32] {
    use sha3::Digest;
    sha3::Sha3_256::digest(seat.to_bytes()).into()
}

/// Keep `bytes`, the proof of `seat`, a settlement sent alone, to send again
/// unchanged ([`reuse_settlement_proof`]).
fn keep_settlement_proof(seat: &PreparedSeat, bytes: &[u8]) {
    let Ok(mut proofs) = settlement_proofs().lock() else {
        return;
    };
    let epoch = seat.part.epoch;
    proofs.retain(|(_, _, e), _| e.saturating_add(1) >= epoch);
    proofs.insert(
        (seat.member, seat.part.shard_filter.clone(), epoch),
        SettlementProof {
            part: part_digest(seat),
            bytes: Arc::new(bytes.to_vec()),
            resends: 0,
        },
    );
}

/// The proof this node made of `seat`, a settlement sent alone again from
/// the same part, and the times it has now gone again: the same bytes, so
/// archives and GLOBAL's leader hold one copy, and nothing is proved again.
/// `None` when none was made of this part.
fn reuse_settlement_proof(seat: &PreparedSeat) -> Option<(Arc<Vec<u8>>, u32)> {
    let mut proofs = settlement_proofs().lock().ok()?;
    let proof = proofs.get_mut(&(seat.member, seat.part.shard_filter.clone(), seat.part.epoch))?;
    if proof.part != part_digest(seat) {
        return None;
    }
    proof.resends = proof.resends.saturating_add(1);
    Some((proof.bytes.clone(), proof.resends))
}

/// Send `seats`, one settlement sent alone again from the same part, as the
/// proof made of it before ([`reuse_settlement_proof`]). False when there is
/// none, or its window has closed (the proving path drops it and logs why).
fn resend_settlement(seats: &[PreparedSeat], publish: &Publish) -> bool {
    let [seat] = seats else {
        return false;
    };
    if crate::storage_snapshot::settlement_closed(seat.part.epoch, 0) {
        return false;
    }
    let Some((bytes, resends)) = reuse_settlement_proof(seat) else {
        return false;
    };
    if let Ok(mut sent) = settlements_sent().lock() {
        sent.insert(
            (seat.member, seat.part.shard_filter.clone(), seat.part.epoch),
            Instant::now(),
        );
    }
    tracing::debug!(member = %hex::encode(seat.member), shard = %hex::encode(&seat.part.shard_filter),
        epoch = seat.part.epoch, resends, bytes = bytes.len(),
        "storage settlement sent again alone, as the proof made before");
    publish(bytes.to_vec());
    true
}

/// Give back the settlements a proof that failed claimed.
fn release_settlements(claimed: &[SettlementKey]) {
    if let Ok(mut sent) = settlements_sent().lock() {
        for key in claimed {
            sent.remove(key);
        }
    }
}

/// The settlements `bytes` carries, a worker's seat part or a member's epoch
/// proof: member, shard and epoch each.
fn settlements_in(bytes: &[u8]) -> Vec<SettlementKey> {
    if is_seat_message(bytes) {
        return match SeatMessage::from_bytes(bytes) {
            Ok(SeatMessage::Part(seat)) if seat.part.settles => {
                vec![(seat.member, seat.part.shard_filter, seat.part.epoch)]
            }
            _ => Vec::new(),
        };
    }
    if bytes.get(..4) != Some(&epoch_proof::TYPE_STORAGE_EPOCH_PROOF.to_be_bytes()[..]) {
        return Vec::new();
    }
    let Ok(proof) = StorageEpochProof::from_canonical_bytes(bytes) else {
        return Vec::new();
    };
    let member = proof.member;
    proof
        .seats
        .into_iter()
        .filter(|seat| seat.settles)
        .map(|seat| (member, seat.shard_filter, seat.epoch))
        .collect()
}

/// Warn that a coverage halt on this node holds `bytes` back when they
/// settle a storage epoch: GLOBAL withholds the member's storage share
/// (before epoch 1342: kicks it) if no settlement lands by the window's end.
/// At most once a minute a seat.
pub fn note_withheld(bytes: &[u8]) {
    static WARNED: OnceLock<Mutex<HashMap<SettlementKey, Instant>>> = OnceLock::new();
    for key in settlements_in(bytes) {
        let Ok(mut warned) = WARNED.get_or_init(Default::default).lock() else {
            return;
        };
        warned.retain(|_, at| at.elapsed() < Duration::from_secs(60));
        if warned.contains_key(&key) {
            continue;
        }
        warned.insert(key.clone(), Instant::now());
        let (member, shard, epoch) = key;
        let (_, window_end) =
            quil_execution::global_intrinsic::storage_seat::settlement_window(epoch);
        let global_frame = crate::storage_snapshot::global_frame();
        warn!(member = %hex::encode(member), shard = %hex::encode(&shard), epoch, window_end, global_frame = ?global_frame,
            frames_left = ?global_frame.map(|frame| window_end.saturating_sub(frame)),
            "storage settlement held back: a coverage halt on this node withholds its GLOBAL submissions; the worker sends it again \
             at its next retry, and GLOBAL withholds the member's storage share (before epoch 1342: kicks it) if none lands by the window's end");
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
    let constrained = crate::storage_jobs::constrained_memory();
    let native = |seat: &PreparedSeat| {
        !seat.part.settles
            && !seat.claim.seals.is_empty()
            && seat
                .claim
                .seals
                .iter()
                .all(|leaf| leaf.persistent.is_some())
            && seat.witness.certificates.iter().all(Vec::is_empty)
    };
    let limit = |all_native: bool| {
        if all_native && bytes == chunk_bytes() {
            quil_types::consensus::STORAGE_SEAL_BYTES_PER_FRAME.saturating_sub(4096)
        } else {
            bytes
        }
    };
    let mut out: Vec<Vec<PreparedSeat>> = Vec::new();
    let mut open: Vec<PreparedSeat> = Vec::new();
    let (mut weight, mut size) = (0, 0);
    // A large native seal can be sent independently of its small settlement.
    let seats = seats.into_iter().flat_map(|seat| {
        if seat.part.seals && seat.part.settles && seat.part_bytes() > bytes {
            let (seal, settle) = seat.halves();
            [seal, settle].into_iter().flatten().collect::<Vec<_>>()
        } else {
            vec![seat]
        }
    });
    for seat in seats {
        let part = seat.part_bytes();
        if part > limit(native(&seat)) {
            tracing::warn!(filter=%hex::encode(&seat.part.shard_filter),part_bytes=part,budget=limit(native(&seat)),
                "storage proof part exceeds message budget");
            continue;
        }
        if seat.solo
            || (seat.part.settles
                && quil_types::consensus::persistent_storage_at(seat.claim.settle_epoch))
        {
            // Keep persistent settlement AIRs seat-sized, matching worker
            // preparation and allowing independent memory-admitted proofs.
            out.push(vec![seat]);
            continue;
        }
        let repeated = open
            .iter()
            .any(|held| held.part.shard_filter == seat.part.shard_filter);
        let all_native = native(&seat) && open.iter().all(&native);
        let budget = limit(all_native);
        let leaf_limit = memory_leaf_limit(leaves, all_native, constrained);
        if !open.is_empty()
            && (repeated || weight + seat.weight() > leaf_limit || size + part > budget)
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

/// Peak admission for the actual proof dimensions. Native persistent seals
/// do not enter the legacy AIR; settlement frames still do.
pub(crate) fn proving_bytes(seats: &[PreparedSeat]) -> Result<u64> {
    let member = seats
        .first()
        .map(|s| s.member)
        .ok_or_else(|| QuilError::InvalidArgument("no seat to prove".into()))?;
    let native = seats
        .iter()
        .map(|seat| seat.part_bytes() as u64)
        .sum::<u64>()
        .saturating_mul(4);
    let mut claim = EpochClaim {
        member,
        seats: seats.iter().map(|s| s.claim.clone()).collect(),
    };
    for seat in &mut claim.seats {
        seat.seals.retain(|leaf| leaf.persistent.is_none());
    }
    let old = claim
        .seats
        .iter()
        .any(|s| !s.seals.is_empty() || !s.frames.is_empty());
    let traces = if old {
        quil_execution::global_intrinsic::persistent_storage::estimate_epoch_proving_memory_bytes(
            &claim.statement(),
            &quil_crypto::sdr::SdrParams::default(),
        )
        .map_err(QuilError::InvalidArgument)?
    } else {
        16 << 20
    };
    Ok(native.saturating_add(traces))
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
/// alone at once, replacing any collected copy. A settlement sent alone is
/// proved at once even while a collection waits for its seat's part, which
/// then goes without it ([`claim_settlements`]).
pub fn deliver(message: SeatMessage, publish: Publish) {
    let (member, start) = {
        let Ok(mut collections) = collections().lock() else {
            return;
        };
        match message {
            SeatMessage::Part(seat) if seat.solo => {
                let key = seat.key();
                let settles_alone = seat.part.settles && !seat.part.seals;
                if !settles_alone
                    && collections
                        .get(&seat.member)
                        .is_some_and(|c| c.announced.iter().any(|k| k.overlaps(&key)))
                {
                    // Its first part has not been proved yet: that proof
                    // covers it.
                    return;
                }
                drop(collections);
                if !settles_alone && recently_proved(&seat) {
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
        std::thread::Builder::new()
            .name("epoch-batch".into())
            .spawn(move || watch(member))
            .expect("spawn a storage epoch batch thread");
    }
}

/// `parts` with each seat's seal and settlement, prepared in jobs of their
/// own ([`part_jobs`]) and collected together, joined into one part
/// ([`PreparedSeat::join`]) where the first of them was: a proof lists each
/// shard once, so apart they would take a proof each. A part sent alone
/// (`solo`) is never joined.
fn join_halves(parts: Vec<PreparedSeat>) -> Vec<PreparedSeat> {
    let mut out: Vec<PreparedSeat> = Vec::with_capacity(parts.len());
    for part in parts {
        let partner = (!part.solo && part.part.seals != part.part.settles)
            .then(|| {
                out.iter().position(|held| {
                    !held.solo
                        && held.member == part.member
                        && held.part.shard_filter == part.part.shard_filter
                        && held.part.epoch == part.part.epoch
                        && held.part.seals == part.part.settles
                        && held.part.settles == part.part.seals
                })
            })
            .flatten();
        let Some(at) = partner else {
            out.push(part);
            continue;
        };
        let held = out.remove(at);
        let (seal, settle) = if held.part.seals {
            (held, part)
        } else {
            (part, held)
        };
        if let Some(joined) = PreparedSeat::join(Some(seal), Some(settle)) {
            out.insert(at, joined);
        }
    }
    out
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
        for chunk in chunks(join_halves(collection.parts), chunk_leaves(), chunk_bytes()) {
            prove_and_publish(chunk, collection.publish.clone());
        }
        return;
    }
}

/// Bytes proving holds per sealed leaf, and at least, for proofs before
/// persistent storage holds ([`proof_reservation`]).
const PROVING_BYTES_PER_SEALED_LEAF: u64 = 400 << 20;

/// Which halves a part carries, for its log line: `frames` counts only the
/// settling half, so a part that seals alone logs `frames=0`.
pub fn part_name(seals: bool, settles: bool) -> &'static str {
    match (seals, settles) {
        (true, true) => "seal+settle",
        (true, false) => "seal",
        (false, true) => "settle",
        (false, false) => "none",
    }
}

/// Proofs that began and did not finish (the job unwound), since the
/// process started.
static ABANDONED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Warns, when dropped before [`ProofWatch::finish`], that a member's epoch
/// proof began and did not end: the log otherwise shows the proof's start
/// and nothing after it, whatever interrupted it.
struct ProofWatch {
    member: String,
    seats: usize,
    shards: Vec<String>,
    started: Instant,
    finished: bool,
}

impl ProofWatch {
    fn finish(&mut self) {
        self.finished = true;
    }
}

impl Drop for ProofWatch {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        ABANDONED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        warn!(member = %self.member, seats = self.seats, shards = ?self.shards,
            seconds = self.started.elapsed().as_secs_f64(),
            "storage epoch proof started but did not finish: the node was stopping or the proving job \
             unwound; its seats' workers send each part again, alone");
    }
}

/// The lane of settlements proved alone.
const SETTLEMENT_LANE: &[u8] = b"epoch proofs: settlements alone";

/// Whether `seats` prove on persistent storage's schedule: each settles an
/// epoch where it holds (`quil_types::consensus::persistent_storage_at`).
/// Before it, a node's epoch proofs run in turn in one lane and reserve
/// [`PROVING_BYTES_PER_SEALED_LEAF`], as they were measured.
fn persistent_schedule(seats: &[PreparedSeat]) -> bool {
    !seats.is_empty()
        && seats
            .iter()
            .all(|seat| quil_types::consensus::persistent_storage_at(seat.claim.settle_epoch))
}

/// The lane `seats` prove in ([`prove_and_publish`]): settlements alone in
/// [`SETTLEMENT_LANE`], others in `crate::storage_jobs::EPOCH_PROOF_LANE`,
/// one proof at a time each. On persistent storage's schedule each
/// member, shard and epoch gets a lane of its own, so independent chunks
/// run side by side while overlapping parts keep one lane.
fn proof_lane(seats: &[PreparedSeat], alone: bool, persistent: bool) -> Vec<u8> {
    let mut lane = if alone {
        SETTLEMENT_LANE.to_vec()
    } else {
        crate::storage_jobs::EPOCH_PROOF_LANE.to_vec()
    };
    if !persistent {
        return lane;
    }
    for seat in seats {
        lane.extend_from_slice(&seat.member);
        lane.extend_from_slice(&(seat.part.shard_filter.len() as u64).to_be_bytes());
        lane.extend_from_slice(&seat.part.shard_filter);
        lane.extend_from_slice(&seat.part.epoch.to_be_bytes());
        lane.extend_from_slice(&seat.claim.seal_epoch.to_be_bytes());
        lane.extend_from_slice(&[u8::from(seat.part.seals), u8::from(seat.part.settles)]);
    }
    lane
}

/// The memory proving `seats` reserves: on persistent storage's schedule
/// its AIR estimate ([`proving_bytes`]); before it, four times the native
/// parts' bytes plus [`PROVING_BYTES_PER_SEALED_LEAF`] per leaf sealed
/// without a sector, at least one when the proof seals or settles any.
fn proof_reservation(seats: &[PreparedSeat], persistent: bool) -> Result<u64> {
    if persistent {
        return proving_bytes(seats);
    }
    let old_leaves = seats
        .iter()
        .flat_map(|seat| &seat.claim.seals)
        .filter(|leaf| leaf.persistent.is_none())
        .count() as u64;
    let old_work = old_leaves > 0 || seats.iter().any(|seat| seat.part.settles);
    let native_bytes = seats
        .iter()
        .map(|seat| seat.part_bytes() as u64)
        .sum::<u64>()
        .saturating_mul(4);
    let old_bytes = if old_work {
        PROVING_BYTES_PER_SEALED_LEAF.saturating_mul(old_leaves.max(1))
    } else {
        16 << 20
    };
    Ok(native_bytes.saturating_add(old_bytes))
}

/// Prove `seats` as a storage job (`crate::storage_jobs`), once the memory
/// proving takes is free, and publish the proof, each seat's settlement once
/// ([`claim_settlements`]). A settlement alone proves in a moment and seals
/// nothing: it goes in a lane of its own, never behind the member's sealing
/// proofs, and its memory never waits behind seals
/// (`crate::storage_jobs::reserve_settlement`).
fn prove_and_publish(seats: Vec<PreparedSeat>, publish: Publish) {
    note_proved(&seats);
    let alone = seats
        .iter()
        .all(|seat| seat.solo && seat.part.settles && !seat.part.seals);
    let persistent = persistent_schedule(&seats);
    let lane = proof_lane(&seats, alone, persistent);
    crate::storage_jobs::spawn(&lane, "member epoch proof", move || {
        // Sent again from the same part, a settlement alone goes as the
        // proof made of it before: nothing is proved again.
        if alone && resend_settlement(&seats, &publish) {
            return Ok(());
        }
        let bytes = proof_reservation(&seats, persistent)?;
        let _memory = if alone && !persistent {
            crate::storage_jobs::reserve_settlement(bytes)
        } else {
            crate::storage_jobs::reserve(bytes)
        };
        let (seats, claimed) = claim_settlements(seats);
        if seats.is_empty() {
            return Ok(());
        }
        let kept = if alone && seats.len() == 1 {
            seats.clone()
        } else {
            Vec::new()
        };
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
        let proved: Vec<SettlementKey> = seats
            .iter()
            .map(|seat| (seat.member, seat.part.shard_filter.clone(), seat.part.epoch))
            .collect();
        info!(member, seats = count, sealed_leaves = sealed, shards = ?shards,
            "proving storage epoch proof over the collected seats");
        let mut watch = ProofWatch {
            member: member.clone(),
            seats: count,
            shards: shards.clone(),
            started,
            finished: false,
        };
        let proof = prove(seats);
        watch.finish();
        match proof {
            Ok(bytes) => {
                info!(member, seats = count, sealed_leaves = sealed, bytes = bytes.len(),
                    seconds = started.elapsed().as_secs_f64(), shards = ?shards, "submitting storage epoch proof");
                if let [seat] = kept.as_slice() {
                    keep_settlement_proof(seat, &bytes);
                }
                publish(bytes);
                // Its workers' retry clocks run from now (in this process:
                // thread workers), not from their parts' claims.
                for (member, shard, epoch) in &proved {
                    crate::storage_snapshot::note_epoch_proof_published(member, shard, *epoch);
                }
                Ok(())
            }
            Err(error) => {
                release_settlements(&claimed);
                warn!(member, seats = count, %error, shards = ?shards,
                    "storage epoch proof over the collected seats failed; their workers send each again alone");
                Err(error)
            }
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_small_hosts_legacy_batches_shrink_without_fragmenting_native_seals() {
        assert_eq!(super::memory_leaf_limit(24, false, true), 2);
        assert_eq!(super::memory_leaf_limit(1, false, true), 1);
        assert_eq!(super::memory_leaf_limit(24, true, true), 24);
        assert_eq!(super::memory_leaf_limit(24, false, false), 24);
    }
    use super::*;
    use quil_execution::global_intrinsic::storage_epoch_proof::SealedLeaf;

    fn seat(shard: u8, sealed: usize, solo: bool) -> PreparedSeat {
        let leaf = SealedLeaf {
            persistent: None,
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
                certificates: Vec::new(),
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

    #[test]
    fn a_part_is_named_by_the_halves_it_carries() {
        assert_eq!(part_name(true, true), "seal+settle");
        assert_eq!(part_name(true, false), "seal");
        assert_eq!(part_name(false, true), "settle");
        assert_eq!(part_name(false, false), "none");
    }

    #[test]
    fn a_proof_that_began_and_did_not_finish_is_counted_as_abandoned() {
        let watch = || ProofWatch {
            member: String::new(),
            seats: 1,
            shards: Vec::new(),
            started: Instant::now(),
            finished: false,
        };
        let before = ABANDONED.load(std::sync::atomic::Ordering::Relaxed);
        let mut done = watch();
        done.finish();
        drop(done);
        assert_eq!(
            ABANDONED.load(std::sync::atomic::Ordering::Relaxed),
            before,
            "a finished proof is not counted"
        );
        drop(watch());
        assert_eq!(
            ABANDONED.load(std::sync::atomic::Ordering::Relaxed),
            before + 1,
            "an unfinished proof is counted"
        );
    }

    /// A part splits into its seal and its settlement, each a part that
    /// says only its own half, and the two join back into the part.
    #[test]
    fn persistent_settlements_are_independent_chunks_and_reserve_actual_air_memory() {
        let mut parts = Vec::new();
        for shard in [11, 12] {
            let (_, part) = sealing_and_settling(shard).halves();
            let mut part = part.unwrap();
            part.solo = false;
            part.part.epoch = 1500;
            part.claim.settle_epoch = 1500;
            parts.push(part);
        }
        quil_types::consensus::set_persistent_storage_epoch_for_thread(Some(1500));
        let grouped = chunks(parts.clone(), usize::MAX, usize::MAX);
        assert_eq!(grouped.len(), 2);
        assert!(grouped.iter().all(|part| part.len() == 1));
        assert!(proving_bytes(&grouped[0]).unwrap() > 0);
        quil_types::consensus::set_persistent_storage_epoch_for_thread(Some(u64::MAX));
        assert_eq!(chunks(parts, usize::MAX, usize::MAX).len(), 1);
        quil_types::consensus::set_persistent_storage_epoch_for_thread(None);
    }

    /// Two settling parts of different shards at epoch 1500, each its own
    /// chunk, as `chunks` gives them once persistent storage holds.
    fn settling_chunks() -> Vec<Vec<PreparedSeat>> {
        [11, 12]
            .into_iter()
            .map(|shard| {
                let (_, part) = sealing_and_settling(shard).halves();
                let mut part = part.unwrap();
                part.solo = false;
                part.part.epoch = 1500;
                part.claim.settle_epoch = 1500;
                vec![part]
            })
            .collect()
    }

    /// Before persistent storage holds, a node's epoch proofs of different
    /// shards share one lane and run in turn; once it holds, each member,
    /// shard and epoch has a lane of its own.
    #[test]
    fn epoch_proofs_share_one_lane_until_persistent_storage_holds() {
        let proofs = settling_chunks();
        quil_types::consensus::set_persistent_storage_epoch_for_thread(Some(u64::MAX));
        for chunk in &proofs {
            assert_eq!(
                proof_lane(chunk, false, persistent_schedule(chunk)),
                crate::storage_jobs::EPOCH_PROOF_LANE,
                "one shared lane before persistent storage"
            );
        }
        quil_types::consensus::set_persistent_storage_epoch_for_thread(Some(1500));
        let lanes: Vec<Vec<u8>> = proofs
            .iter()
            .map(|chunk| proof_lane(chunk, false, persistent_schedule(chunk)))
            .collect();
        quil_types::consensus::set_persistent_storage_epoch_for_thread(None);
        assert_ne!(lanes[0], lanes[1], "a lane per member, shard and epoch");
        for lane in &lanes {
            assert!(lane.starts_with(crate::storage_jobs::EPOCH_PROOF_LANE));
        }
    }

    /// Before persistent storage holds, an epoch proof reserves
    /// [`PROVING_BYTES_PER_SEALED_LEAF`] per sealed leaf; once it holds, its
    /// AIR estimate ([`proving_bytes`]).
    #[test]
    fn epoch_proofs_reserve_per_sealed_leaf_until_persistent_storage_holds() {
        let sealed = [seat(13, 3, false)];
        let proofs = settling_chunks();
        quil_types::consensus::set_persistent_storage_epoch_for_thread(Some(u64::MAX));
        let before = proof_reservation(&sealed, persistent_schedule(&sealed));
        quil_types::consensus::set_persistent_storage_epoch_for_thread(Some(1500));
        let after = proof_reservation(&proofs[0], persistent_schedule(&proofs[0]));
        let estimate = proving_bytes(&proofs[0]);
        quil_types::consensus::set_persistent_storage_epoch_for_thread(None);
        let native = sealed[0].part_bytes() as u64 * 4;
        assert_eq!(
            before.unwrap(),
            native + 3 * PROVING_BYTES_PER_SEALED_LEAF,
            "400 MiB per sealed leaf before persistent storage"
        );
        assert_eq!(after.unwrap(), estimate.unwrap());
    }

    #[test]
    fn native_chunks_count_proof_bytes_without_reserving_an_unused_stark() {
        let mut native = seat(197, 1, false);
        let root = quil_crypto::persistent_storage::Registration {
            profile: Default::default(),
            data: [0; 32],
            labels: [0; 32],
            replica: [0; 32],
            sector: [3; 32],
            columns: [0; 32],
        };
        native.claim.seals[0].persistent = Some(root);
        native.witness.certificates = vec![Vec::new()];
        // A large binding payload stands in for native proof bytes here;
        // part_bytes must include both, while an initial certificate reserves
        // the STARK allowance and cannot be sent over the native-only budget.
        let mut binding = quil_execution::global_intrinsic::storage_binding::LeafBinding::default();
        binding.header = vec![
            quil_execution::global_intrinsic::storage_binding::Opening {
                node: [0; 32],
                path: vec![[0; 32]; 64]
            };
            1500
        ];
        native.part.bindings = vec![binding];
        assert!(native.part_bytes() > chunk_bytes());
        assert!(native.part_bytes() < quil_types::consensus::STORAGE_SEAL_BYTES_PER_FRAME - 4096);
        assert_eq!(chunks(vec![native.clone()], 24, chunk_bytes()).len(), 1);
        native.witness.certificates[0] = vec![1; 1024];
        assert!(chunks(vec![native], 24, chunk_bytes()).is_empty());
    }

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
        assert_eq!(*prepared.borrow(), vec![(false, true), (true, false)]);
        // Other chained roots: the settlement is prepared again, the seal not.
        let (_, reused) =
            prepare_reusing(&member, &filter, epoch, seal(), settle([2; 32]), prepare).unwrap();
        assert!(reused);
        assert_eq!(
            *prepared.borrow(),
            vec![(false, true), (true, false), (false, true)]
        );
        // Another seat, or the halves forgotten once GLOBAL recorded them.
        prepare_reusing(&member, &[0x46; 32], epoch, seal(), None, prepare).unwrap();
        forget_prepared(&member, &filter, epoch);
        prepare_reusing(&member, &filter, epoch, seal(), None, prepare).unwrap();
        assert_eq!(
            *prepared.borrow(),
            vec![
                (false, true),
                (true, false),
                (false, true),
                (true, false),
                (true, false)
            ]
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

    /// A seat's settlement is prepared before its seal and kept at once: a
    /// seal still relabelling (about an hour per GiB), or one that fails,
    /// must not hold the settlement up; GLOBAL withholds the storage share of
    /// a member whose committed roots go unproven by the window's end.
    #[test]
    fn a_settlement_is_prepared_before_its_seal_and_kept_when_the_seal_fails() {
        let member = [0x47; 32];
        let (filter, epoch) = (vec![0x48; 32], 11);
        let seal = Some(PartInputs::Seal {
            registered_at: 100,
            leaves: vec![vec![0]],
            beacon_output: vec![1],
        });
        let settle = Some(PartInputs::Settle {
            frames: 1,
            accumulator: [1; 32],
        });
        let prepared = std::cell::RefCell::new(Vec::new());
        let failing_seal = |seals: bool, settles: bool| {
            prepared.borrow_mut().push((seals, settles));
            if seals {
                return Err(QuilError::ExecutionUnavailable(
                    "relabelling stopped".into(),
                ));
            }
            let (_, settling) = sealing_and_settling(0x48).halves();
            Ok(settling.unwrap())
        };
        assert!(
            prepare_reusing(&member, &filter, epoch, seal, settle.clone(), failing_seal).is_err()
        );
        let (alone, reused) =
            prepare_reusing(&member, &filter, epoch, None, settle, failing_seal).unwrap();
        forget_prepared(&member, &filter, epoch);
        assert!(
            reused && alone.part.settles && !alone.part.seals,
            "the settlement beside a seal that failed was lost: sending it alone prepares it again"
        );
        assert_eq!(
            *prepared.borrow(),
            vec![(false, true), (true, false)],
            "the settlement first, then the seal"
        );
    }

    /// A settlement sent alone (a retry, or near its window's end) is proved
    /// at once, while a collection still waits for its seat's slow part (a
    /// seal relabelling): the collection waits up to 1800 s, and GLOBAL
    /// withholds the storage share of the member whose roots go unproven by
    /// the window's end.
    #[test]
    fn a_settlement_sent_alone_is_proved_at_once_beside_a_waiting_collection() {
        let member = [0x61; 32];
        let publish: Publish = Arc::new(|_| {});
        deliver(
            SeatMessage::Announce(
                member,
                SeatKey {
                    filter: vec![1],
                    seals: true,
                    settles: true,
                },
            ),
            publish.clone(),
        );
        let mut held = seat(2, 1, false);
        held.member = member;
        held.part.settles = true;
        deliver(SeatMessage::Part(held), publish.clone());
        let mut alone = seat(1, 0, true);
        alone.member = member;
        deliver(SeatMessage::Part(alone.clone()), publish.clone());
        assert!(
            recently_proved(&alone),
            "the settlement sent alone waited for its seat's slow part in the member's collection"
        );
        // A seal sent again still waits for the collection's proof.
        let mut sealing = seat(1, 1, true);
        sealing.member = member;
        let mut other = sealing.clone();
        other.member = [0x62; 32];
        deliver(
            SeatMessage::Announce(
                other.member,
                SeatKey {
                    filter: vec![1],
                    seals: true,
                    settles: true,
                },
            ),
            publish.clone(),
        );
        deliver(SeatMessage::Part(other.clone()), publish);
        assert!(!recently_proved(&other), "a seal retry waits, as before");
    }

    /// No proof that seals carries a settlement that already went out, in
    /// any order: GLOBAL refuses a proof whole when it settles an epoch
    /// already settled, losing the seals in it. A settlement alone goes each
    /// time its worker sends it.
    #[test]
    fn each_settlement_goes_to_global_once_whatever_the_order() {
        let mut joint = sealing_and_settling(0x81);
        joint.member = [0x81; 32];
        let (_, alone) = joint.clone().halves();
        let mut alone = alone.unwrap();
        alone.solo = true;
        let settles = |seats: &[PreparedSeat]| seats.iter().filter(|s| s.part.settles).count();

        // Alone first: the joint part later proves its seal only.
        let (out, claimed) = claim_settlements(vec![alone.clone()]);
        assert_eq!((settles(&out), claimed.len()), (1, 1));
        let (out, claimed) = claim_settlements(vec![joint.clone(), seat(0x82, 1, false)]);
        assert_eq!(out.len(), 2, "the joint part's seal and the other seat");
        assert_eq!(settles(&out), 0, "no second settlement");
        assert!(out[0].part.seals && out[0].part.frames.is_empty() && claimed.is_empty());
        // Sent alone again, it goes: its worker spaces the sends by GLOBAL
        // frames (`settlement_due`).
        let (out, claimed) = claim_settlements(vec![alone.clone()]);
        assert_eq!((settles(&out), claimed.len()), (1, 1));
        // A proof that failed gives its settlement back.
        release_settlements(&claimed);
        let (out, _) = claim_settlements(vec![joint.clone()]);
        assert_eq!(settles(&out), 1, "released by the failed proof");

        // Joint first: the settlement alone after it goes when its worker
        // sends it (GLOBAL lost the joint proof, or refuses the copy whole,
        // losing nothing else); a joint part after that seals only.
        let mut later = sealing_and_settling(0x83);
        later.member = [0x83; 32];
        let (out, _) = claim_settlements(vec![later.clone()]);
        assert_eq!(settles(&out), 1);
        let (_, settling) = later.clone().halves();
        let mut settling = settling.unwrap();
        settling.solo = true;
        let (out, claimed) = claim_settlements(vec![settling]);
        assert_eq!((settles(&out), claimed.len()), (1, 1));
        let (out, claimed) = claim_settlements(vec![later]);
        assert_eq!((settles(&out), claimed.len()), (0, 0));
    }

    /// A settlement sent alone again from the same part goes as the proof
    /// made of it before: archives and GLOBAL's leader hold one copy while
    /// one waits (on mainnet each send was proved anew, 2026-11-08), and
    /// nothing is proved again. A part from other inputs is proved anew.
    #[test]
    fn a_settlement_sent_alone_again_carries_the_proof_made_before() {
        let mut joint = sealing_and_settling(0x92);
        joint.member = [0x92; 32];
        let (_, alone) = joint.halves();
        let mut alone = alone.unwrap();
        alone.solo = true;
        assert!(
            reuse_settlement_proof(&alone).is_none(),
            "nothing proved yet"
        );
        keep_settlement_proof(&alone, b"the first proof");
        let (bytes, resends) = reuse_settlement_proof(&alone).expect(
            "the settlement sent alone again was reproved: new bytes archives cannot deduplicate",
        );
        assert_eq!((bytes.as_slice(), resends), (&b"the first proof"[..], 1));
        assert_eq!(reuse_settlement_proof(&alone).map(|(_, n)| n), Some(2));
        let mut other = alone.clone();
        other.part.frames.clear();
        other.claim.frames.clear();
        assert!(
            reuse_settlement_proof(&other).is_none(),
            "a part from other inputs went as another part's proof"
        );
    }

    /// How each settlement a worker sent ended is logged once: settled when
    /// its slot shows it within its window, unsettled when the window ended
    /// first, each with the times it went again.
    #[test]
    fn a_settlements_outcome_is_logged_once() {
        let (member, filter, epoch) = ([0x93; 32], vec![0x93], 5);
        let (from, until) =
            quil_execution::global_intrinsic::storage_seat::settlement_window(epoch);
        note_settlement_sent(&member, &filter, epoch, from + 48, true);
        note_settlement_sent(&member, &filter, epoch, from + 58, true);
        assert_eq!(
            settlement_sent_alone_at(&member, &filter, epoch),
            Some(from + 58)
        );
        assert!(settlement_outcomes(&member, &filter, from + 60, |_| Some(true)).is_empty());
        assert_eq!(
            settlement_outcomes(&member, &filter, from + 61, |_| Some(false)),
            vec![(epoch, SettlementOutcome::Settled, 1)]
        );
        assert!(
            settlement_outcomes(&member, &filter, from + 62, |_| Some(false)).is_empty(),
            "a settlement's outcome was logged again: repeated"
        );
        assert_eq!(settlement_sent_alone_at(&member, &filter, epoch), None);
        let other = vec![0x94];
        note_settlement_sent(&member, &other, epoch, until - 30, true);
        assert!(settlement_outcomes(&member, &other, until - 1, |_| Some(true)).is_empty());
        assert_eq!(
            settlement_outcomes(&member, &other, until, |_| Some(true)),
            vec![(epoch, SettlementOutcome::Unsettled, 0)]
        );
    }

    /// No proof carries a settlement once this node saw GLOBAL past its
    /// window's end: GLOBAL refuses it, losing the seals proved with it.
    #[test]
    fn a_settlement_past_its_window_is_not_sent() {
        let mut joint = sealing_and_settling(0xA1);
        joint.member = [0xA1; 32];
        let (_, until) =
            quil_execution::global_intrinsic::storage_seat::settlement_window(joint.part.epoch);
        crate::storage_snapshot::note_global_frame(until);
        let (out, claimed) = claim_settlements(vec![joint.clone()]);
        assert!(
            claimed.is_empty(),
            "a settlement past its window was claimed"
        );
        assert_eq!(out.len(), 1);
        assert!(
            out[0].part.seals && !out[0].part.settles,
            "the part proves its seal only"
        );
        let (_, alone) = joint.halves();
        let mut alone = alone.unwrap();
        alone.solo = true;
        assert!(claim_settlements(vec![alone]).0.is_empty());
    }

    /// A settlement sent alone goes out each time its worker sends it again,
    /// ten GLOBAL frames later: an archive drops a submission no frame
    /// carried after ten frames, and a node that dropped a copy sent within
    /// 720 s of the last (46 to 57 frames at mainnet's pace on 2026-11-08)
    /// left every other one of its worker's sends unsent; the seat expired.
    #[test]
    fn a_settlement_sent_alone_again_goes_out_each_time_its_worker_sends_it() {
        let mut joint = sealing_and_settling(0x91);
        joint.member = [0x91; 32];
        let (_, alone) = joint.halves();
        let mut alone = alone.unwrap();
        alone.solo = true;
        let (_, until) =
            quil_execution::global_intrinsic::storage_seat::settlement_window(alone.part.epoch);
        crate::storage_snapshot::note_global_frame(until - 100);
        let (out, claimed) = claim_settlements(vec![alone.clone()]);
        assert_eq!((out.len(), claimed.len()), (1, 1), "the first send goes");
        crate::storage_snapshot::note_global_frame(until - 90);
        let (out, claimed) = claim_settlements(vec![alone]);
        assert_eq!(
            (out.len(), claimed.len()),
            (1, 1),
            "a settlement its worker sent alone again ten GLOBAL frames later was dropped: unsent"
        );
    }

    /// The settlements a withheld submission carries are found, in a
    /// worker's part and in a member's proof, so a coverage halt that holds
    /// one back is warned of.
    #[test]
    fn a_withheld_settlement_is_found_in_a_part_or_a_proof() {
        let mut settle = sealing_and_settling(0x91);
        settle.member = [0x91; 32];
        let (seal, settle) = settle.halves();
        let (seal, mut settle) = (seal.unwrap(), settle.unwrap());
        // As a worker sends it: an opening per frame, held leaf and query.
        let openings = settle.part.frames.len()
            * settle.claim.held.len()
            * quil_types::consensus::STORAGE_QUERIES_PER_LEAF as usize;
        settle.witness.opened = (0..openings)
            .map(|_| epoch_proof::Opened {
                value: [5; 32],
                path: vec![[6; 32]],
            })
            .collect();
        let key = (
            settle.member,
            settle.part.shard_filter.clone(),
            settle.part.epoch,
        );
        assert_eq!(settlements_in(&settle.to_bytes()), vec![key.clone()]);
        assert!(settlements_in(&seal.to_bytes()).is_empty());
        // Another shard's seal beside it: a proof lists each shard once.
        let mut sealing = seal.part.clone();
        sealing.shard_filter = vec![0x92];
        let proof = StorageEpochProof {
            member: settle.member,
            seats: vec![sealing, settle.part.clone()],
            proof: Vec::new(),
        };
        assert_eq!(settlements_in(&proof.to_canonical_bytes()), vec![key]);
        assert!(settlements_in(&[0, 0, 3, 0x24, 1]).is_empty());
        assert!(settlements_in(b"a frame header").is_empty());
    }

    /// A seat's settlement is prepared in a job of its own on every attempt,
    /// first, never in its seal's: a seal that relabels its leaves for an hour,
    /// or fails after relabelling (a leaf labelled under another replica key;
    /// mainnet, 2026-11-08), held the settlement past its window's end, and
    /// GLOBAL withheld the member's held storage share.
    #[test]
    fn a_settlement_is_never_prepared_in_its_seals_job() {
        let job = |seals, settles, announced| PartJob {
            seals,
            settles,
            announced,
        };
        assert_eq!(
            part_jobs(true, true, false),
            vec![job(false, true, true), job(true, false, true)],
            "settlement_in_seal_job on a first attempt"
        );
        assert_eq!(
            part_jobs(true, true, true),
            vec![job(false, true, false), job(true, false, true)],
            "settlement_in_seal_job sent alone"
        );
        for settle_alone in [false, true] {
            assert_eq!(
                part_jobs(false, true, settle_alone),
                vec![job(false, true, !settle_alone)]
            );
            assert_eq!(
                part_jobs(true, false, settle_alone),
                vec![job(true, false, true)]
            );
            assert!(part_jobs(false, false, settle_alone).is_empty());
        }
    }

    /// The halves of a seat prepared apart and collected together are proved
    /// as one part, as when they were prepared together: a proof lists each
    /// shard once, so apart they would take a proof each. A half sent alone
    /// is not joined, and nor are halves of different shards.
    #[test]
    fn a_seats_halves_collected_together_are_proved_as_one_part() {
        let halves = |shard| {
            let (seal, settle) = sealing_and_settling(shard).halves();
            (seal.unwrap(), settle.unwrap())
        };
        let (seal_a, settle_a) = halves(0x71);
        let (seal_b, _) = halves(0x72);
        let (seal_c, mut settle_c) = halves(0x73);
        settle_c.solo = true;
        let joined = join_halves(vec![
            settle_a,
            seal_b.clone(),
            settle_c.clone(),
            seal_a,
            seal_c.clone(),
        ]);
        let keys: Vec<(u8, bool, bool)> = joined
            .iter()
            .map(|part| {
                (
                    part.part.shard_filter[0],
                    part.part.seals,
                    part.part.settles,
                )
            })
            .collect();
        assert_eq!(
            keys,
            vec![
                (0x71, true, true),
                (0x72, true, false),
                (0x73, false, true),
                (0x73, true, false)
            ],
            "halves_not_joined"
        );
        assert_eq!(joined[0].to_bytes(), sealing_and_settling(0x71).to_bytes());
        assert_eq!(joined[1].to_bytes(), seal_b.to_bytes());
        assert_eq!(joined[2].to_bytes(), settle_c.to_bytes());
        assert_eq!(joined[3].to_bytes(), seal_c.to_bytes());
    }

    /// A seal that fails at its column commitment is final for its
    /// registration: noted once, it is not tried again, while another
    /// registration, member, shard or epoch is. Any other failure (a missing
    /// replica, a stopped relabelling) is tried again.
    #[test]
    fn a_registration_whose_columns_are_another_labelling_is_not_sealed_again() {
        let final_error =
            QuilError::InvalidArgument(quil_crypto::storage_proof::COLUMNS_NOT_REGISTERED.into());
        assert!(
            seal_failed_for_good(&final_error.to_string()),
            "columns_failure_not_final"
        );
        for passing in [
            QuilError::ExecutionUnavailable("no stored replica of leaf 00 for epoch 7".into()),
            QuilError::InvalidArgument(
                "the kept column digests are not the registered column commitment".into(),
            ),
        ] {
            assert!(!seal_failed_for_good(&passing.to_string()), "{passing}");
        }
        let (member, filter, epoch, at) = ([0x81; 32], vec![0x82; 32], 1431, 1_031_100);
        let leaves = vec![vec![0, 1], vec![2]];
        assert!(!seal_unprovable(&member, &filter, epoch, at, &leaves));
        assert!(note_unprovable_seal(&member, &filter, epoch, at, &leaves));
        assert!(
            !note_unprovable_seal(&member, &filter, epoch, at, &leaves),
            "noted twice"
        );
        assert!(
            seal_unprovable(&member, &filter, epoch, at, &leaves),
            "unprovable_seal_tried_again"
        );
        assert!(!seal_unprovable(&[0x83; 32], &filter, epoch, at, &leaves));
        assert!(!seal_unprovable(&member, &[0x84; 32], epoch, at, &leaves));
        assert!(!seal_unprovable(&member, &filter, epoch + 1, at, &leaves));
        assert!(!seal_unprovable(&member, &filter, epoch, at + 1, &leaves));
        assert!(!seal_unprovable(&member, &filter, epoch, at, &[vec![2]]));
    }

    /// The warn for a failed seal says what GLOBAL does with an unsealed
    /// seat: from the unsealed issuance epoch (mainnet 1321) to the sealed
    /// storage epoch (mainnet 1467) it pays the share at once, so nothing is
    /// withheld; from the sealed storage epoch the seat sits out.
    #[test]
    fn a_failed_seal_names_what_global_does_with_an_unsealed_seat() {
        use quil_types::consensus::{
            set_persistent_storage_epoch_for_thread, set_sealed_storage_epoch_for_thread,
            set_unsealed_issuance_epoch_for_thread,
        };
        set_unsealed_issuance_epoch_for_thread(Some(1321));
        set_sealed_storage_epoch_for_thread(Some(1467));
        set_persistent_storage_epoch_for_thread(Some(1467));
        let outcomes: Vec<&str> = [1320, 1321, 1433, 1466, 1467, 1500]
            .into_iter()
            .map(unsealed_seat_outcome)
            .collect();
        set_unsealed_issuance_epoch_for_thread(None);
        set_sealed_storage_epoch_for_thread(None);
        set_persistent_storage_epoch_for_thread(None);
        let paid = |outcome: &str| outcome.contains("pays an unsealed participant");
        let sits_out = |outcome: &str| outcome.contains("sits out");
        assert!(
            !paid(outcomes[0]) && !sits_out(outcomes[0]),
            "{}",
            outcomes[0]
        );
        for outcome in &outcomes[1..4] {
            assert!(
                paid(outcome) && !sits_out(outcome),
                "unsealed_outcome_wrong: {outcome}"
            );
        }
        for outcome in &outcomes[4..] {
            assert!(
                sits_out(outcome) && !paid(outcome),
                "unsealed_outcome_wrong: {outcome}"
            );
        }
    }
}
