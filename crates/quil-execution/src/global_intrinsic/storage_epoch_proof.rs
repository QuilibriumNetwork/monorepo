//! `StorageEpochProof` canonical-bytes envelope (hash storage proofs).
//!
//! One member's STARK for one or more of its storage seats
//! (`super::storage_seat`), submitted during the epoch after each seat's
//! `epoch` (decided 2026-10-21). It proves, in one proof GLOBAL checks in
//! milliseconds, for each seat:
//!
//! - **seals:** every leaf the member registered on the shard for
//!   `epoch + 2` is its own SDR encoding of the registered data, at the
//!   challenges of the beacon of the GLOBAL frame after the registration's;
//! - **openings:** every root the member committed in a frame anchored in
//!   `epoch` hashes the replica nodes its frame's beacon chose, each under its
//!   registered `comm_R`.
//!
//! One proof covers all the seats a member's node holds (decided 2026-10-22:
//! one proof per member, not per seat), so GLOBAL carries one per member per
//! epoch, of about one seat's size, however many shards the member serves.
//! Its workers prepare each seat's witness ([`prepare`]) where the replicas
//! are; the node proves them together ([`prove`]).
//!
//! GLOBAL reads every statement from committed state: the seats' leaves, the
//! leaf registrations and the chains of committed roots. The message lists the
//! committed frames only so GLOBAL need not store them; they must chain to each
//! seat's record exactly. Accepted, it seals the registrations and settles the
//! epochs' held rewards; refused, none of its seats changes. It carries no
//! signature: it proves facts about committed state, so whoever holds it may
//! submit it.
//!
//! Wire format (type 0x0324):
//!
//! ```text
//! [u32 BE type_prefix = 0x0324]
//! [u32 BE member_len = 32] [member]
//! [u32 BE seat_count]                  1..=MAX_SEATS, distinct shards
//!   per seat:
//!   [u32 BE shard_filter_len] [shard_filter]
//!   [u64 BE epoch]                     the epoch it settles; it seals epoch + 2
//!   [u8 parts]                         bit 0: seals, bit 1: settles
//!   [u32 BE frame_count]
//!     per frame: [u64 BE frame_number] [32 rho_n] [32 root]
//!   [u32 BE binding_count]             sealing: one per registered leaf
//!     per binding: [u32 BE len] [binding]
//! [u32 BE proof_len] [proof]           (`quil_storage_stark::seal::prove_epoch`)
//! ```

use quil_types::error::{QuilError, Result};

use crate::canonical_cursor::{put_u32, put_u64, read_bytes, read_u32, read_u64};

/// One opened replica node and its path, as a seat's witness carries it.
pub use quil_storage_stark::seal::Opened;

pub const TYPE_STORAGE_EPOCH_PROOF: u32 = 0x0324;

const MAX_SHARD_FILTER_LEN: u32 = 64;
/// More than a seat commits in an epoch: one per app frame it proposed.
pub const MAX_FRAMES: u32 = 1 << 16;
/// A chunk of 24 leaves proves in about 0.75 MB.
pub const MAX_PROOF_LEN: u32 = 4 << 20;
/// Seats one proof may cover.
pub const MAX_SEATS: u32 = 256;
/// As many leaves as a seat registers.
const MAX_BINDINGS: u32 = 4096;
const MAX_BINDING_LEN: u32 = 32 << 20;

const SEALS: u8 = 1;
const SETTLES: u8 = 2;

/// One frame's commitment: the app frame, its storage beacon and the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedFrame {
    pub frame_number: u64,
    pub rho_n: [u8; 32],
    pub root: [u8; 32],
}

/// One seat's part of a member's epoch proof.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SeatProof {
    /// The seat's shard filter.
    pub shard_filter: Vec<u8>,
    /// The epoch it settles; the registration it seals is for `epoch + 2`.
    pub epoch: u64,
    pub seals: bool,
    pub settles: bool,
    /// The seat's committed frames in `epoch`, in order (settling only).
    pub frames: Vec<CommittedFrame>,
    /// Sealing: each registered leaf's binding to the recorded snapshot, in
    /// the seat's leaf order (`storage_binding`).
    pub bindings: Vec<super::storage_binding::LeafBinding>,
}

impl SeatProof {
    pub fn seal_epoch(&self) -> u64 {
        self.epoch.saturating_add(2)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StorageEpochProof {
    /// The member's 32-byte prover address.
    pub member: [u8; 32],
    /// The seats it covers, each shard once.
    pub seats: Vec<SeatProof>,
    pub proof: Vec<u8>,
}

impl StorageEpochProof {
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48 + self.proof.len());
        put_u32(&mut out, TYPE_STORAGE_EPOCH_PROOF);
        put_u32(&mut out, 32);
        out.extend_from_slice(&self.member);
        put_u32(&mut out, self.seats.len() as u32);
        for seat in &self.seats {
            put_u32(&mut out, seat.shard_filter.len() as u32);
            out.extend_from_slice(&seat.shard_filter);
            put_u64(&mut out, seat.epoch);
            out.push(if seat.seals { SEALS } else { 0 } | if seat.settles { SETTLES } else { 0 });
            put_u32(&mut out, seat.frames.len() as u32);
            for frame in &seat.frames {
                put_u64(&mut out, frame.frame_number);
                out.extend_from_slice(&frame.rho_n);
                out.extend_from_slice(&frame.root);
            }
            put_u32(&mut out, seat.bindings.len() as u32);
            for binding in &seat.bindings {
                let bytes = binding.to_bytes();
                put_u32(&mut out, bytes.len() as u32);
                out.extend_from_slice(&bytes);
            }
        }
        put_u32(&mut out, self.proof.len() as u32);
        out.extend_from_slice(&self.proof);
        out
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let invalid =
            |what: String| QuilError::InvalidArgument(format!("StorageEpochProof: {what}"));
        let mut c = 0usize;
        let tp = read_u32(data, &mut c)?;
        if tp != TYPE_STORAGE_EPOCH_PROOF {
            return Err(invalid(format!("invalid type prefix 0x{tp:08x}")));
        }
        if read_u32(data, &mut c)? != 32 {
            return Err(invalid("member must be 32 bytes".into()));
        }
        let member: [u8; 32] = read_bytes(data, &mut c, 32)?.try_into().expect("32 bytes");
        let seat_count = read_u32(data, &mut c)?;
        if seat_count == 0 || seat_count > MAX_SEATS {
            return Err(invalid(format!("{seat_count} seats")));
        }
        let mut seats: Vec<SeatProof> = Vec::with_capacity(seat_count as usize);
        for _ in 0..seat_count {
            let filter_len = read_u32(data, &mut c)?;
            if filter_len > MAX_SHARD_FILTER_LEN {
                return Err(invalid(format!("shard filter of {filter_len} bytes")));
            }
            let shard_filter = read_bytes(data, &mut c, filter_len as usize)?;
            if seats.iter().any(|seat| seat.shard_filter == shard_filter) {
                return Err(invalid(format!(
                    "shard {} listed twice",
                    hex::encode(&shard_filter)
                )));
            }
            let epoch = read_u64(data, &mut c)?;
            let parts = read_bytes(data, &mut c, 1)?[0];
            if parts == 0 || parts & !(SEALS | SETTLES) != 0 {
                return Err(invalid(format!("parts 0x{parts:02x}")));
            }
            let frame_count = read_u32(data, &mut c)?;
            if frame_count > MAX_FRAMES || (parts & SETTLES == 0 && frame_count != 0) {
                return Err(invalid(format!("{frame_count} frames")));
            }
            let mut frames = Vec::with_capacity(frame_count as usize);
            for _ in 0..frame_count {
                let frame_number = read_u64(data, &mut c)?;
                let rho_n: [u8; 32] = read_bytes(data, &mut c, 32)?.try_into().expect("32 bytes");
                let root: [u8; 32] = read_bytes(data, &mut c, 32)?.try_into().expect("32 bytes");
                frames.push(CommittedFrame {
                    frame_number,
                    rho_n,
                    root,
                });
            }
            let binding_count = read_u32(data, &mut c)?;
            if binding_count > MAX_BINDINGS || (parts & SEALS == 0 && binding_count != 0) {
                return Err(invalid(format!("{binding_count} bindings")));
            }
            let mut bindings = Vec::with_capacity(binding_count as usize);
            for _ in 0..binding_count {
                let len = read_u32(data, &mut c)?;
                if len > MAX_BINDING_LEN {
                    return Err(invalid(format!("a binding of {len} bytes")));
                }
                bindings.push(
                    super::storage_binding::LeafBinding::from_bytes(&read_bytes(
                        data,
                        &mut c,
                        len as usize,
                    )?)
                    .ok_or_else(|| invalid("a malformed binding".into()))?,
                );
            }
            seats.push(SeatProof {
                shard_filter,
                epoch,
                seals: parts & SEALS != 0,
                settles: parts & SETTLES != 0,
                frames,
                bindings,
            });
        }
        let proof_len = read_u32(data, &mut c)?;
        if proof_len > MAX_PROOF_LEN {
            return Err(invalid(format!("proof of {proof_len} bytes")));
        }
        let proof = read_bytes(data, &mut c, proof_len as usize)?;
        if c != data.len() {
            return Err(invalid(format!("{} trailing bytes", data.len() - c)));
        }
        Ok(Self {
            member,
            seats,
            proof,
        })
    }
}

/// A registered leaf the proof seals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedLeaf {
    pub leaf_id: Vec<u8>,
    pub n: u64,
    pub registered: quil_crypto::storage_proof::Registered,
    /// The storage beacon of the GLOBAL frame after the registration's.
    pub beacon: Vec<u8>,
}

/// A registered leaf whose openings the proof covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldLeaf {
    pub leaf_id: Vec<u8>,
    pub n: u64,
    pub comm_r: [u8; 32],
}

/// Everything one seat's part of an epoch proof claims, owned: the prover and
/// GLOBAL build it from the same committed records, so they prove and check
/// the same statement.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SeatClaim {
    pub seal_epoch: u64,
    /// Every leaf of the seat's registration for `seal_epoch`, in the seat's
    /// order; empty when the proof seals nothing here.
    pub seals: Vec<SealedLeaf>,
    pub settle_epoch: u64,
    /// Every leaf of the seat's registration for `settle_epoch`, in the
    /// seat's order; empty when the proof settles nothing here.
    pub held: Vec<HeldLeaf>,
    /// Each opens every held leaf of the seat.
    pub frames: Vec<CommittedFrame>,
}

/// Everything a member's epoch proof claims: its seats' claims, in the
/// message's order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EpochClaim {
    pub member: [u8; 32],
    pub seats: Vec<SeatClaim>,
}

impl EpochClaim {
    /// One statement over every seat: their sealed leaves, held leaves and
    /// frames in seat order, each frame opening its own seat's held leaves.
    pub fn statement(&self) -> quil_storage_stark::seal::EpochStatement<'_> {
        use quil_storage_stark::seal::{EpochStatement, FrameOpenings, Held};
        let mut statement = EpochStatement {
            seals: Vec::new(),
            count: quil_types::consensus::STORAGE_SEAL_CHALLENGES,
            held: Vec::new(),
            frames: Vec::new(),
            queries: quil_types::consensus::STORAGE_QUERIES_PER_LEAF,
        };
        for seat in &self.seats {
            statement.seals.extend(seat.seals.iter().map(|leaf| {
                quil_crypto::storage_proof::SealStatement {
                    member: &self.member,
                    leaf_id: &leaf.leaf_id,
                    epoch: seat.seal_epoch,
                    n: leaf.n,
                    registered: leaf.registered,
                    beacon: &leaf.beacon,
                }
            }));
            let first = statement.held.len();
            statement.held.extend(seat.held.iter().map(|leaf| Held {
                member: &self.member,
                leaf_id: &leaf.leaf_id,
                epoch: seat.settle_epoch,
                n: leaf.n,
                comm_r: leaf.comm_r,
            }));
            let held: Vec<usize> = (first..statement.held.len()).collect();
            statement
                .frames
                .extend(seat.frames.iter().map(|frame| FrameOpenings {
                    frame_number: frame.frame_number,
                    rho_n: &frame.rho_n,
                    root: frame.root,
                    held: held.clone(),
                }));
        }
        statement
    }

    /// Sealed leaves across the seats: what proving costs in memory.
    pub fn sealed_leaves(&self) -> usize {
        self.seats.iter().map(|seat| seat.seals.len()).sum()
    }

    pub fn verify(&self, proof: &[u8]) -> std::result::Result<(), String> {
        quil_storage_stark::seal::verify_epoch(
            &self.statement(),
            &quil_crypto::sdr::SdrParams::default(),
            proof,
        )
    }
}

/// A held leaf's replica as its member stored it: its nodes and Merkle cap.
pub struct HeldReplica<'a> {
    pub replica: &'a [u8],
    pub cap: &'a quil_crypto::storage_proof::MerkleCap,
}

/// What a member opens in a frame whose beacon is `rho_n`: every held leaf's
/// replica node at each query's index, leaf by leaf, query by query — the
/// order its openings root hashes them and the epoch proof proves them in.
/// `None` when a replica cannot open (it is not the registered one).
pub fn frame_openings(
    member: &[u8],
    epoch: u64,
    held: &[HeldLeaf],
    replicas: &[HeldReplica],
    rho_n: &[u8],
) -> Option<Vec<quil_storage_stark::seal::Opened>> {
    if held.len() != replicas.len() {
        return None;
    }
    let mut opened =
        Vec::with_capacity(held.len() * quil_types::consensus::STORAGE_QUERIES_PER_LEAF as usize);
    for (leaf, stored) in held.iter().zip(replicas) {
        if stored.cap.n != leaf.n
            || stored
                .cap
                .commitment(quil_crypto::storage_proof::Tree::Replica)
                != leaf.comm_r
        {
            return None;
        }
        for query in 0..quil_types::consensus::STORAGE_QUERIES_PER_LEAF {
            let opening = quil_crypto::storage_proof::build_opening(
                stored.replica,
                stored.cap,
                &[],
                &leaf.leaf_id,
                epoch,
                member,
                query,
                rho_n,
            )?;
            opened.push(quil_storage_stark::seal::Opened {
                value: opening.value.as_slice().try_into().ok()?,
                path: opening
                    .path_commits
                    .iter()
                    .map(|node| node.as_slice().try_into().ok())
                    .collect::<Option<_>>()?,
            });
        }
    }
    Some(opened)
}

/// [`frame_openings`] reading each held leaf's replica only where a query
/// opens it: `read(i, nodes)` gives the serialized nodes `nodes` of
/// `held[i]`'s replica (the subtree below its cap that the opened node's path
/// is recomputed from, `MerkleCap::subtree`), or `None` when they cannot be
/// read. The same openings, in the same order, as from the whole replicas.
pub fn frame_openings_from(
    member: &[u8],
    epoch: u64,
    held: &[HeldLeaf],
    caps: &[&quil_crypto::storage_proof::MerkleCap],
    rho_n: &[u8],
    read: &mut dyn FnMut(usize, std::ops::Range<u64>) -> Option<Vec<u8>>,
) -> Option<Vec<quil_storage_stark::seal::Opened>> {
    use quil_crypto::storage_proof::{opening_index, Tree, NODE_BYTES};
    if held.len() != caps.len() {
        return None;
    }
    let mut opened =
        Vec::with_capacity(held.len() * quil_types::consensus::STORAGE_QUERIES_PER_LEAF as usize);
    for (i, (leaf, cap)) in held.iter().zip(caps).enumerate() {
        if cap.n != leaf.n || cap.commitment(Tree::Replica) != leaf.comm_r {
            return None;
        }
        for query in 0..quil_types::consensus::STORAGE_QUERIES_PER_LEAF {
            let index = opening_index(rho_n, &leaf.leaf_id, epoch, member, query, cap.n);
            let below = cap.subtree(index)?;
            let at = (index - below.start) as usize * NODE_BYTES;
            let subtree = read(i, below)?;
            let path = cap.subtree_path(&subtree, index)?;
            opened.push(quil_storage_stark::seal::Opened {
                value: subtree.get(at..at + NODE_BYTES)?.try_into().ok()?,
                path,
            });
        }
    }
    Some(opened)
}

/// The root a frame commits for `opened` ([`frame_openings`]).
pub fn openings_root(
    frame_number: u64,
    opened: &[quil_storage_stark::seal::Opened],
) -> Option<[u8; 32]> {
    quil_crypto::storage_proof::openings_root(
        frame_number,
        &opened.iter().map(|o| o.value).collect::<Vec<_>>(),
    )
}

/// What a seat's replicas give its part of an epoch proof: a plain seal per
/// sealed leaf and every frame's openings, in the claim's order. Prepared
/// where the replicas are; the proof itself may be made elsewhere, with other
/// seats' ([`prove`]).
#[derive(Debug, Clone)]
pub struct SeatWitness {
    pub seals: Vec<quil_crypto::storage_proof::SealProof>,
    pub opened: Vec<quil_storage_stark::seal::Opened>,
}

/// Prepare `seat`'s witness from the member's stored replicas: `sealed[i]` is
/// the replica of `seat.seals[i]`, `held[i]` that of `seat.held[i]`. Relabels
/// each sealed leaf at its challenges, so this runs off any latency-sensitive
/// thread.
pub fn prepare(
    member: &[u8; 32],
    seat: &SeatClaim,
    sealed: &[&[u8]],
    held: &[HeldReplica],
) -> std::result::Result<SeatWitness, String> {
    prepare_with_labels(member, seat, sealed, held, &[])
}

/// [`prepare`], opening each sealed leaf whose labels the member kept
/// (`labels[i]` for `seat.seals[i]`) from them instead of relabelling it; a
/// leaf whose kept labels are not its registration's is relabelled.
pub fn prepare_with_labels(
    member: &[u8; 32],
    seat: &SeatClaim,
    sealed: &[&[u8]],
    held: &[HeldReplica],
    labels: &[Option<&dyn quil_crypto::storage_proof::LabelSource>],
) -> std::result::Result<SeatWitness, String> {
    if sealed.len() != seat.seals.len() || held.len() != seat.held.len() {
        return Err("a replica for every leaf of the claim".into());
    }
    let params = quil_crypto::sdr::SdrParams::default();
    let seals = seat
        .seals
        .iter()
        .zip(sealed)
        .enumerate()
        .map(|(i, (leaf, replica))| {
            let statement = quil_crypto::storage_proof::SealStatement {
                member,
                leaf_id: &leaf.leaf_id,
                epoch: seat.seal_epoch,
                n: leaf.n,
                registered: leaf.registered,
                beacon: &leaf.beacon,
            };
            let count = quil_types::consensus::STORAGE_SEAL_CHALLENGES;
            labels
                .get(i)
                .copied()
                .flatten()
                .and_then(|labels| {
                    quil_crypto::storage_proof::prove_seal_with_labels(
                        replica, &statement, &params, count, labels,
                    )
                    .ok()
                })
                .map_or_else(
                    || quil_crypto::storage_proof::prove_seal(replica, &statement, &params, count),
                    Ok,
                )
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut opened = Vec::new();
    for frame in &seat.frames {
        let values = frame_openings(member, seat.settle_epoch, &seat.held, held, &frame.rho_n)
            .ok_or("a held replica is not the registered one")?;
        if openings_root(frame.frame_number, &values) != Some(frame.root) {
            return Err(format!(
                "frame {} committed another root than these replicas open",
                frame.frame_number
            ));
        }
        opened.extend(values);
    }
    Ok(SeatWitness { seals, opened })
}

/// Prove `claim` from its seats' witnesses ([`prepare`]), one per seat in
/// order.
pub fn prove(
    claim: &EpochClaim,
    witnesses: &[SeatWitness],
) -> std::result::Result<Vec<u8>, String> {
    if witnesses.len() != claim.seats.len() {
        return Err("a witness for every seat of the claim".into());
    }
    let params = quil_crypto::sdr::SdrParams::default();
    let seals: Vec<&quil_crypto::storage_proof::SealProof> =
        witnesses.iter().flat_map(|w| &w.seals).collect();
    let opened: Vec<quil_storage_stark::seal::Opened> = witnesses
        .iter()
        .flat_map(|w| w.opened.iter().cloned())
        .collect();
    quil_storage_stark::seal::prove_epoch(&claim.statement(), &params, &seals, &opened)
}

/// What an accepted epoch proof changes in one seat.
pub struct Settlement {
    /// The seat, sealed and/or settled.
    pub seat: super::storage_seat::Seat,
    /// Each sealed leaf's registration address and its tree with the seal
    /// recorded.
    pub sealed: Vec<([u8; 32], quil_tries::VectorCommitmentTree)>,
    /// The held rewards the settlement pays (`None` when it settles nothing).
    pub released: Option<num_bigint::BigInt>,
    /// The settled roots GLOBAL executed within the response window of their
    /// beacons: what counts as published
    /// (`storage_seat::SeatSlot::response_times`).
    pub timely: u64,
    /// The slowest settled root's response time, in milliseconds.
    pub slowest_ms: i64,
}

/// What GLOBAL reads a sealed registration's binding with besides its state:
/// the shard changes recorded but not applied (a split or merge child's
/// sources), and each shard's bits in its app tree.
pub struct SealContext<'a> {
    pub changes: &'a [quil_types::store::PendingShardChange],
    pub bits: &'a dyn Fn(&[u8]) -> Option<Vec<bool>>,
}

/// Check `proof` in GLOBAL frame `frame_number` against committed `state`:
/// read each seat's claim from the seat and the leaf registrations, check the
/// frames it lists chain to the seat's record and each sealed leaf's binding
/// to the snapshot recorded for it, and verify the STARK over them all.
/// `beacon_output` gives a GLOBAL frame's output (the seal beacons),
/// `timestamp` its timestamp (the settled roots' response times). Returns
/// each seat's settlement, in the message's order; `Ok(None)` when this frame
/// already applied it (the archive's second materialization). A seat that
/// fails refuses the whole proof.
pub fn check(
    frame_number: u64,
    proof: &StorageEpochProof,
    state: &crate::hypergraph_state::HypergraphState,
    beacon_output: impl Fn(u64) -> Result<Vec<u8>>,
    timestamp: impl Fn(u64) -> Result<i64>,
    context: &SealContext,
) -> Result<Option<Vec<Settlement>>> {
    use super::storage_seat::{self, Outcome};
    let invalid = |what: String| QuilError::InvalidArgument(format!("storage epoch proof: {what}"));
    let mut seats = Vec::with_capacity(proof.seats.len());
    for part in &proof.seats {
        let seat =
            storage_seat::read(state, &proof.member, &part.shard_filter)?.ok_or_else(|| {
                invalid(format!(
                    "no storage seat for this member on shard {}",
                    hex::encode(&part.shard_filter)
                ))
            })?;
        seats.push(seat);
    }
    let applied_here = proof.seats.iter().zip(&seats).all(|(part, seat)| {
        (!part.seals
            || seat
                .slot(part.seal_epoch())
                .is_some_and(|slot| slot.sealed_at == Some(frame_number)))
            && (!part.settles
                || seat
                    .slot(part.epoch)
                    .is_some_and(|slot| slot.outcome == Outcome::Settled(frame_number)))
    });
    if applied_here {
        return Ok(None);
    }
    let mut claim = EpochClaim {
        member: proof.member,
        seats: Vec::with_capacity(proof.seats.len()),
    };
    let mut checked = Vec::with_capacity(proof.seats.len());
    for (part, seat) in proof.seats.iter().zip(&seats) {
        let (seat_claim, seat_checked) = check_seat(
            frame_number,
            &proof.member,
            part,
            seat,
            state,
            &beacon_output,
            &timestamp,
            context,
        )
        .map_err(|error| match error {
            QuilError::InvalidArgument(what) => QuilError::InvalidArgument(format!(
                "{what} (shard {})",
                hex::encode(&part.shard_filter)
            )),
            other => other,
        })?;
        claim.seats.push(seat_claim);
        checked.push(seat_checked);
    }
    claim
        .verify(&proof.proof)
        .map_err(|error| invalid(format!("rejected: {error}")))?;
    Ok(Some(
        proof
            .seats
            .iter()
            .zip(seats)
            .zip(checked)
            .map(|((part, mut seat), checked)| {
                if part.seals {
                    seat.seal(part.seal_epoch(), frame_number);
                }
                let released = if part.settles {
                    seat.settle(part.epoch, frame_number, checked.timely)
                } else {
                    None
                };
                Settlement {
                    seat,
                    sealed: checked.sealed,
                    released,
                    timely: checked.timely,
                    slowest_ms: checked.slowest_ms,
                }
            })
            .collect(),
    ))
}

/// What one seat's checks found besides its claim.
struct SeatChecked {
    sealed: Vec<([u8; 32], quil_tries::VectorCommitmentTree)>,
    timely: u64,
    slowest_ms: i64,
}

/// One seat's part of [`check`]: its claim, read from committed state, once
/// the part's frames, bindings and windows check.
#[allow(clippy::too_many_arguments)]
fn check_seat(
    frame_number: u64,
    member: &[u8; 32],
    part: &SeatProof,
    seat: &super::storage_seat::Seat,
    state: &crate::hypergraph_state::HypergraphState,
    beacon_output: &impl Fn(u64) -> Result<Vec<u8>>,
    timestamp: &impl Fn(u64) -> Result<i64>,
    context: &SealContext,
) -> Result<(SeatClaim, SeatChecked)> {
    use super::materialize;
    use super::storage_seat::{self, Outcome};
    let invalid = |what: String| QuilError::InvalidArgument(format!("storage epoch proof: {what}"));
    let registration = |leaf_id: &[u8],
                        epoch: u64|
     -> Result<(
        materialize::RegistrationSlot,
        quil_tries::VectorCommitmentTree,
    )> {
        let address = materialize::leaf_root_address(member, leaf_id)?;
        let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
        let tree = state
            .get(
                &crate::global_schema::GLOBAL_INTRINSIC_ADDRESS[..],
                &address,
                &va_disc,
            )?
            .filter(|blob| !blob.is_empty())
            .map(|blob| crate::prover_registry::rebuild_vertex_tree_from_blob(&blob))
            .ok_or_else(|| invalid(format!("no registration of leaf {}", hex::encode(leaf_id))))?;
        let slot = materialize::registration_slots(&tree)
            .into_iter()
            .find(|slot| slot.epoch == epoch)
            .ok_or_else(|| {
                invalid(format!(
                    "leaf {} has no registration for epoch {epoch}",
                    hex::encode(leaf_id)
                ))
            })?;
        Ok((slot, tree))
    };
    let registered = |slot: &materialize::RegistrationSlot| {
        slot.leaf_root
            .as_deref()
            .and_then(quil_crypto::storage_proof::parse_registration_root)
            .ok_or_else(|| invalid("a registration is not a hash registration".into()))
    };

    let seal_epoch = part.seal_epoch();
    let mut claim = SeatClaim {
        seal_epoch,
        settle_epoch: part.epoch,
        ..Default::default()
    };
    let mut checked = SeatChecked {
        sealed: Vec::new(),
        timely: 0,
        slowest_ms: 0,
    };
    if part.seals {
        if !quil_types::consensus::hash_storage_proofs_at(seal_epoch) {
            return Err(invalid(format!(
                "epoch {seal_epoch} does not use hash storage proofs"
            )));
        }
        let begins = seal_epoch.saturating_mul(quil_types::consensus::epoch_length_frames());
        if frame_number >= begins {
            return Err(invalid(format!(
                "epoch {seal_epoch} began at frame {begins}, before this seal"
            )));
        }
        let slot = seat.slot(seal_epoch).ok_or_else(|| {
            invalid(format!(
                "the seat has no registration for epoch {seal_epoch}"
            ))
        })?;
        if slot.leaves.is_empty() || slot.sealed_at.is_some() {
            return Err(invalid(format!(
                "the seat's registration for epoch {seal_epoch} is empty or sealed"
            )));
        }
        let beacon_frame = slot.registered_at + 1;
        if frame_number <= beacon_frame {
            return Err(invalid(format!(
                "its beacon, frame {beacon_frame}, is not yet before this frame"
            )));
        }
        let beacon =
            quil_crypto::porep::derive_storage_beacon(beacon_frame, &beacon_output(beacon_frame)?);
        // The data the leaves register must be the shard's snapshot.
        let snapshot = super::storage_snapshot::sources(
            &part.shard_filter,
            seal_epoch,
            context.changes,
            |shard| {
                super::storage_snapshot::read(state, seal_epoch, shard)
                    .ok()
                    .flatten()
            },
        )
        .ok_or_else(|| {
            invalid(format!(
                "no snapshot of the shard for epoch {seal_epoch} is recorded"
            ))
        })?;
        let bits_of = |filter: &[u8]| {
            (context.bits)(filter)
                .ok_or_else(|| invalid(format!("shard {} has no bits", hex::encode(filter))))
        };
        let shard_bits = bits_of(&part.shard_filter)?;
        let sources = snapshot
            .iter()
            .map(|source| Ok((bits_of(&source.filter)?, source.snapshot.roots)))
            .collect::<Result<Vec<_>>>()?;
        let relative = slot
            .leaves
            .iter()
            .map(|prefix| quil_forest::shard_bit_path_from_prefix(prefix))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| invalid("a leaf prefix is not a bit path".into()))?;
        if !super::storage_binding::tiles(&relative) {
            return Err(invalid(
                "the registered leaves do not tile the shard".into(),
            ));
        }
        if part.bindings.len() != slot.leaves.len() {
            return Err(invalid(format!(
                "{} bindings for {} leaves",
                part.bindings.len(),
                slot.leaves.len()
            )));
        }
        for ((prefix, relative), binding) in slot.leaves.iter().zip(&relative).zip(&part.bindings) {
            let leaf_id = super::leaf_id_bytes(&part.shard_filter, prefix);
            let (registration, tree) = registration(&leaf_id, seal_epoch)?;
            if registration.registered_at != Some(slot.registered_at)
                || registration.sealed_at.is_some()
            {
                return Err(invalid(format!(
                    "leaf {} is not the seat's registration",
                    hex::encode(&leaf_id)
                )));
            }
            let leaf = super::storage_binding::LeafClaim {
                filter: &part.shard_filter,
                prefix,
                leaf_id: &leaf_id,
                member,
                epoch: seal_epoch,
                beacon: &beacon,
                bits: [shard_bits.as_slice(), relative].concat(),
                sources: sources.clone(),
                comm_d: registered(&registration)?.comm_d,
                n: registration.num_blocks,
            };
            super::storage_binding::verify(&leaf, binding).map_err(invalid)?;
            let leaf_sealed =
                materialize::mark_registration_sealed(&tree, seal_epoch, frame_number)?
                    .ok_or_else(|| invalid("no registration slot to seal".into()))?;
            checked.sealed.push((
                materialize::leaf_root_address(member, &leaf_id)?,
                leaf_sealed,
            ));
            claim.seals.push(SealedLeaf {
                n: registration.num_blocks,
                registered: registered(&registration)?,
                beacon: beacon.clone(),
                leaf_id,
            });
        }
    }
    if part.settles {
        let (from, until) = storage_seat::settlement_window(part.epoch);
        if !(from..until).contains(&frame_number) {
            return Err(invalid(format!(
                "epoch {} settles in frames [{from}, {until})",
                part.epoch
            )));
        }
        let slot = seat.slot(part.epoch).ok_or_else(|| {
            invalid(format!(
                "the seat has no registration for epoch {}",
                part.epoch
            ))
        })?;
        if !slot.is_sealed() || slot.outcome != Outcome::Open || slot.frames == 0 {
            return Err(invalid(format!(
                "epoch {} has nothing to settle",
                part.epoch
            )));
        }
        let listed = storage_seat::chain(
            part.frames
                .iter()
                .map(|f| (f.frame_number, &f.rho_n[..], &f.root)),
        );
        if part.frames.len() as u64 != slot.frames || listed != slot.accumulator {
            return Err(invalid(format!(
                "the {} frames listed are not the {} the seat committed",
                part.frames.len(),
                slot.frames
            )));
        }
        for prefix in &slot.leaves {
            let leaf_id = super::leaf_id_bytes(&part.shard_filter, prefix);
            let (registration, _) = registration(&leaf_id, part.epoch)?;
            claim.held.push(HeldLeaf {
                n: registration.num_blocks,
                comm_r: registered(&registration)?.comm_r,
                leaf_id,
            });
        }
        claim.frames = part.frames.clone();
        let times = slot.response_times(timestamp)?;
        checked.timely = times
            .iter()
            .filter(|&&time| time <= storage_seat::RESPONSE_WINDOW_MS)
            .count() as u64;
        checked.slowest_ms = times.into_iter().max().unwrap_or(0);
    }
    Ok((claim, checked))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Opening from the subtrees read gives what opening from the whole
    /// replicas gives, for leaves of one and several cap subtrees.
    #[test]
    fn frame_openings_from_subtrees_match_the_whole_replicas() {
        use quil_crypto::storage_proof::{MerkleTree, Tree, CAP_HEIGHT, NODE_BYTES};
        let replica = |n: usize, seed: u32| -> Vec<u8> {
            (0..n * 8)
                .map(|i| {
                    ((i as u32).wrapping_mul(0x9E37_79B9) ^ seed.wrapping_mul(0x85EB_CA6B))
                        .rotate_left(seed % 31)
                        & 0x3FFF_FFFF
                })
                .flat_map(u32::to_le_bytes)
                .collect()
        };
        let replicas = [replica(3000, 1), replica(5, 2)];
        let trees: Vec<MerkleTree> = replicas
            .iter()
            .map(|nodes| MerkleTree::from_nodes(nodes).unwrap())
            .collect();
        let caps: Vec<_> = trees.iter().map(|tree| tree.cap(CAP_HEIGHT)).collect();
        let held: Vec<HeldLeaf> = trees
            .iter()
            .enumerate()
            .map(|(i, tree)| HeldLeaf {
                leaf_id: vec![i as u8; 37],
                n: tree.n(),
                comm_r: tree.commitment(Tree::Replica),
            })
            .collect();
        let whole: Vec<HeldReplica> = replicas
            .iter()
            .zip(&caps)
            .map(|(replica, cap)| HeldReplica { replica, cap })
            .collect();
        let cap_refs: Vec<_> = caps.iter().collect();
        let member = [0x44u8; 32];
        for rho in [[1u8; 32], [2; 32], [3; 32]] {
            let expected = frame_openings(&member, 7, &held, &whole, &rho).unwrap();
            let mut read_nodes = 0u64;
            let mut read = |i: usize, nodes: std::ops::Range<u64>| {
                read_nodes += nodes.end - nodes.start;
                Some(
                    replicas[i][nodes.start as usize * NODE_BYTES..nodes.end as usize * NODE_BYTES]
                        .to_vec(),
                )
            };
            let opened = frame_openings_from(&member, 7, &held, &cap_refs, &rho, &mut read);
            assert_eq!(opened.as_ref().map(|o| o.len()), Some(expected.len()));
            for (a, b) in opened.unwrap().iter().zip(&expected) {
                assert_eq!((a.value, &a.path), (b.value, &b.path));
            }
            assert!(
                read_nodes <= 2 * (1 << CAP_HEIGHT) + 2 * 5,
                "read {read_nodes} nodes"
            );
            // A subtree that is not the replica's does not open.
            let mut wrong = |i: usize, nodes: std::ops::Range<u64>| {
                let mut bytes = replicas[i]
                    [nodes.start as usize * NODE_BYTES..nodes.end as usize * NODE_BYTES]
                    .to_vec();
                bytes[0] ^= 1;
                Some(bytes)
            };
            assert!(frame_openings_from(&member, 7, &held, &cap_refs, &rho, &mut wrong).is_none());
        }
    }

    #[test]
    fn a_proof_round_trips_and_nothing_else_decodes() {
        let seat = SeatProof {
            shard_filter: vec![1; 35],
            epoch: 1262,
            seals: true,
            settles: true,
            frames: vec![CommittedFrame {
                frame_number: 9,
                rho_n: [2; 32],
                root: [3; 32],
            }],
            bindings: vec![super::super::storage_binding::LeafBinding {
                header: vec![super::super::storage_binding::Opening {
                    node: [4; 32],
                    path: vec![[5; 32]; 3],
                }],
                ..Default::default()
            }],
        };
        let other = SeatProof {
            shard_filter: vec![2; 35],
            settles: false,
            frames: Vec::new(),
            ..seat.clone()
        };
        let proof = StorageEpochProof {
            member: [7; 32],
            seats: vec![seat.clone(), other],
            proof: vec![9; 100],
        };
        let bytes = proof.to_canonical_bytes();
        assert_eq!(
            StorageEpochProof::from_canonical_bytes(&bytes).unwrap(),
            proof
        );
        assert!(StorageEpochProof::from_canonical_bytes(&bytes[..bytes.len() - 1]).is_err());
        assert!(
            StorageEpochProof::from_canonical_bytes(&[bytes.as_slice(), &[0]].concat()).is_err()
        );
        let mut other_type = bytes.clone();
        other_type[3] = 0x22;
        assert!(StorageEpochProof::from_canonical_bytes(&other_type).is_err());
        let with = |seat: SeatProof| {
            StorageEpochProof {
                seats: vec![seat],
                ..proof.clone()
            }
            .to_canonical_bytes()
        };
        let seals_only = SeatProof {
            settles: false,
            frames: Vec::new(),
            ..seat.clone()
        };
        assert!(StorageEpochProof::from_canonical_bytes(&with(seals_only)).is_ok());
        assert!(
            StorageEpochProof::from_canonical_bytes(&with(SeatProof {
                settles: false,
                ..seat.clone()
            }))
            .is_err(),
            "frames without settling"
        );
        assert!(
            StorageEpochProof::from_canonical_bytes(&with(SeatProof {
                seals: false,
                ..seat.clone()
            }))
            .is_err(),
            "bindings without sealing"
        );
        let nothing = SeatProof {
            seals: false,
            settles: false,
            frames: Vec::new(),
            bindings: Vec::new(),
            ..seat.clone()
        };
        assert!(StorageEpochProof::from_canonical_bytes(&with(nothing)).is_err());
        let twice = StorageEpochProof {
            seats: vec![seat.clone(), seat],
            ..proof.clone()
        };
        assert!(
            StorageEpochProof::from_canonical_bytes(&twice.to_canonical_bytes()).is_err(),
            "a shard twice"
        );
        let none = StorageEpochProof {
            seats: Vec::new(),
            ..proof
        };
        assert!(
            StorageEpochProof::from_canonical_bytes(&none.to_canonical_bytes()).is_err(),
            "no seat"
        );
    }
}
