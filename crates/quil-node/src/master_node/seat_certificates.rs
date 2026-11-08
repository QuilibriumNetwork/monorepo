//! How often this node's seats sign the certificates GLOBAL credits.
//!
//! A shard frame credits only the members that signed its finalization
//! certificate (`prover_shard_update`), and a certificate holds the first
//! quorum of votes its assembler verified: `q(n) = n - floor((n - 1) / 3)`
//! of `n` members, about 70%, as simplex's batcher stops verifying at
//! quorum. A seat whose votes arrive late signs fewer certificates and earns
//! less, though its worker serves and votes (2026-11-04: an operator's seats
//! signed far fewer frames than ours, and no line or field showed it).
//!
//! The master reads the shard headers of every authenticated GLOBAL frame
//! body it receives, by gossip or by the poller, as `own_prover_ops` does.
//! For each header of a shard this node holds a seat on, it reads the
//! certificate's generation and signer bitmap without verifying it: GLOBAL
//! verifies a header before crediting it, and a regular node does not
//! execute GLOBAL frames, so a header GLOBAL refuses still counts here. The
//! seat's index in that generation's committee comes from committed GLOBAL
//! state, read once per session by the frame observation sampler. Each
//! shard frame counts once, by its own timestamp, in per-minute buckets
//! over 24 hours.
//!
//! The same counts feed the reward line per seat and epoch: what this node
//! saw its seat sign, by the epoch the frame's anchor is in (the epoch GLOBAL
//! holds the frame's reward under), beside what committed GLOBAL state says
//! the seat holds, expects and has chained, read when the epoch ended and
//! when its settlement closed. Completeness is credited over entitled: a
//! sealed seat is entitled to what GLOBAL held for it (`held`) and credited
//! up to `release_at_most`; an unsealed seat is paid at once for each frame
//! it signed, and the hourly credit line totals what the prover's balance
//! gained. Logging state only; nothing here feeds consensus.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Mutex, OnceLock};

use quil_cw_consensus::app_cert::CertificateMember;
use quil_execution::global_intrinsic::storage_seat::{self, Outcome, SeatSlot};
use quil_types::proto::node::{CertificateShare, CertificateWindow};

const MINUTE: u64 = 60;
const HOUR: u64 = 3_600;
const DAY: u64 = 86_400;
/// Seats tracked; a node holds one per worker.
const MAX_SEATS: usize = 256;
/// Committee sessions remembered per seat: GLOBAL still includes a closing
/// session's frames after its successor became the head.
const MAX_GENERATIONS: usize = 4;
/// Shard frames remembered per seat, so a frame both the gossip and the
/// poller deliver counts once.
const MAX_COUNTED: usize = 2_048;
/// Frames the last hour must hold before a low share is judged: fewer say
/// more about the shard's pace than about this seat.
pub(crate) const LOW_MIN_FRAMES: u64 = 30;
/// How often each seat's summary is logged, and a low share warned again.
pub(crate) const LOG_EVERY: u64 = HOUR;
/// How long a seat must stay out of the low share, unbroken, before its
/// episode ends: a share at the threshold crosses it on single frames, and
/// each crossing would otherwise start a new episode.
pub(crate) const LOW_END_HOLD: u64 = 15 * MINUTE;

/// Members a seat's per-member signer counts follow; a larger committee
/// is judged against its size, with no voters or rank.
const MAX_TALLY: usize = 128;

/// Epochs of a seat's counts and logged reward lines remembered.
const MAX_EPOCHS: usize = 6;
/// How often a seat's slots are read from committed state while an epoch of
/// it still lacks a reward line.
const READ_EVERY: u64 = 5 * MINUTE;
/// The reward line of an epoch that ended.
const ENDED: u8 = 1;
/// The reward line of an epoch whose settlement closed.
const CLOSED: u8 = 2;

/// This node's place in one committee session of a seat's shard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Membership {
    generation: u64,
    /// This node's index among the session's sorted members; `None` when
    /// it is not one.
    index: Option<u32>,
    committee: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Bucket {
    minute: u64,
    frames: u32,
    signed: u32,
}

/// How often each member of a committee session signed the certificates
/// of the shard frames counted in one minute.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Tally {
    minute: u64,
    generation: u64,
    frames: u32,
    counts: Vec<u16>,
}

/// The members voting in a seat's committee over the last hour: those
/// signing over a tenth of its frames, and this seat's place among them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Voters {
    pub voters: u32,
    /// 1 = most certificates signed; ties share the better rank.
    pub rank: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Low {
    since: u64,
    warned: u64,
    /// When the seat was first not low in its current unbroken stretch.
    clear_since: Option<u64>,
}

#[derive(Debug)]
struct Seat {
    /// When this process started counting the seat.
    since: u64,
    /// A seat as of the sampler's last pass; a former one keeps counting
    /// its sessions' late frames and is dropped once its buckets expire.
    current: bool,
    memberships: VecDeque<Membership>,
    counted: BTreeSet<u64>,
    buckets: VecDeque<Bucket>,
    /// Per-member signer counts of the last hour, by minute.
    tallies: VecDeque<Tally>,
    /// The committee of the latest frame counted.
    committee: u32,
    last_frame: u64,
    summarized: u64,
    low: Option<Low>,
    /// Shard frames counted, by the epoch their anchor is in.
    epochs: BTreeMap<u64, EpochCount>,
    /// Reward lines logged per epoch ([`ENDED`], [`CLOSED`]).
    rewards_logged: BTreeMap<u64, u8>,
    /// The GLOBAL frame first observed while this process counted the
    /// seat; 0 before one.
    first_global: u64,
    /// When the seat's slots were last read from committed state.
    read_at: u64,
}

/// The shard frames of one epoch this node's seat was counted in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct EpochCount {
    pub frames: u64,
    pub signed: u64,
    /// The proposals expected of the signed frames, as GLOBAL counts them
    /// (`storage_seat::PROPOSAL / committee` each).
    pub weight: u64,
}

impl Seat {
    fn new(now: u64) -> Self {
        Self {
            since: now,
            current: true,
            memberships: VecDeque::new(),
            counted: BTreeSet::new(),
            buckets: VecDeque::new(),
            tallies: VecDeque::new(),
            committee: 0,
            last_frame: 0,
            summarized: now,
            low: None,
            epochs: BTreeMap::new(),
            rewards_logged: BTreeMap::new(),
            first_global: 0,
            read_at: 0,
        }
    }

    fn member(&self) -> Option<&Membership> {
        self.memberships.iter().rev().find(|m| m.index.is_some())
    }

    fn membership(&self, generation: u64) -> Option<&Membership> {
        self.memberships.iter().find(|m| m.generation == generation)
    }

    fn window(&self, seconds: u64, now: u64) -> CertificateWindow {
        let from = now.saturating_sub(seconds);
        let (frames, signed) = self
            .buckets
            .iter()
            .filter(|b| b.minute * MINUTE + MINUTE > from && b.minute * MINUTE <= now)
            .fold((0u64, 0u64), |(f, s), b| {
                (f + u64::from(b.frames), s + u64::from(b.signed))
            });
        CertificateWindow {
            window_seconds: seconds,
            observed_seconds: now.saturating_sub(self.since).min(seconds),
            frames,
            signed_frames: signed,
        }
    }

    fn expire(&mut self, now: u64) {
        while self
            .buckets
            .front()
            .is_some_and(|b| b.minute * MINUTE + MINUTE + DAY <= now)
        {
            self.buckets.pop_front();
        }
        while self
            .tallies
            .front()
            .is_some_and(|t| t.minute * MINUTE + MINUTE + HOUR <= now)
        {
            self.tallies.pop_front();
        }
    }

    /// The members voting in this node's latest session over the last
    /// hour; `None` with under [`LOW_MIN_FRAMES`] frames of it, or a
    /// committee past [`MAX_TALLY`].
    fn voters(&self, now: u64) -> Option<Voters> {
        let member = self.member()?;
        let own = member.index? as usize;
        let size = member.committee as usize;
        if size == 0 || size > MAX_TALLY || own >= size {
            return None;
        }
        let (mut frames, mut counts) = (0u64, vec![0u64; size]);
        for t in self.tallies.iter().filter(|t| {
            t.generation == member.generation
                && t.counts.len() == size
                && t.minute * MINUTE + MINUTE + HOUR > now
        }) {
            frames += u64::from(t.frames);
            for (sum, &n) in counts.iter_mut().zip(&t.counts) {
                *sum += u64::from(n);
            }
        }
        if frames < LOW_MIN_FRAMES {
            return None;
        }
        Some(Voters {
            voters: counts.iter().filter(|&&n| n * 10 > frames).count() as u32,
            rank: 1 + counts.iter().filter(|&&n| n > counts[own]).count() as u32,
        })
    }
}

/// A shard header as a GLOBAL frame carries it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Header<'a> {
    pub filter: &'a [u8],
    pub frame: u64,
    pub timestamp_ms: i64,
    /// The header's signature field (`public_key_signature_bls48581`).
    pub signature: &'a [u8],
    /// The GLOBAL frame the shard frame anchors to (`global_frame_number`):
    /// the epoch of it is the one GLOBAL holds the frame's reward under.
    pub anchor: u64,
}

/// What [`SeatCertificates::due`] has to log.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum SeatLog {
    Summary {
        filter: Vec<u8>,
        share: CertificateShare,
    },
    Low {
        filter: Vec<u8>,
        share: CertificateShare,
        voters: Option<Voters>,
        low_secs: u64,
        repeat: bool,
    },
    Ended {
        filter: Vec<u8>,
        share: CertificateShare,
        low_secs: u64,
        how: &'static str,
    },
    /// A seat's epoch, as this node counted it and committed state records it.
    Reward {
        filter: Vec<u8>,
        epoch: u64,
        stage: &'static str,
        /// How GLOBAL pays the seat's issuance share ([`kind`]).
        kind: &'static str,
        /// `None` for a seat GLOBAL holds no slot for in the epoch.
        slot: Option<SlotRead>,
        counts: EpochCount,
        /// Whether this process observed GLOBAL from before the epoch began.
        complete: bool,
        committee: u32,
    },
    /// What the prover's reward balance gained in the last hour.
    Credits {
        window_secs: u64,
        credited: u128,
        debited: u128,
        changes: u32,
        seats: usize,
    },
}

/// A seat's slot for one epoch, as committed GLOBAL state holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SlotRead {
    pub epoch: u64,
    /// An epoch proof sealed the registration: the seat earns held rewards
    /// rather than being paid at once.
    pub sealed: bool,
    /// Roots GLOBAL chained, which the epoch proof must list.
    pub frames: u64,
    /// Proposals expected, in units of `storage_seat::PROPOSAL`.
    pub expected: u64,
    /// The rewards held for the seat.
    pub held: num_bigint::BigInt,
    /// What settling pays at most: the held rewards when every chained root
    /// counts as published in time, less when fewer roots than proposals
    /// expected were chained.
    pub release_at_most: num_bigint::BigInt,
    pub outcome: Outcome,
}

impl SlotRead {
    pub(crate) fn of(slot: &SeatSlot) -> Self {
        Self {
            epoch: slot.epoch,
            sealed: slot.is_sealed(),
            frames: slot.frames,
            expected: slot.expected,
            held: slot.pending_amount(),
            release_at_most: slot.release(slot.frames),
            outcome: slot.outcome,
        }
    }
}

/// How GLOBAL pays a seat's issuance share of a frame anchored in `epoch`
/// (`prover_shard_update::materialize_prover_shard_update_with_fees`):
/// `held` in a sealed seat until its settlement; `at_once` with the frame
/// before the hash-proof epochs, and to an unsealed seat from the unsealed
/// issuance epoch; else `fees_only`. Fees are paid at once to every kind.
/// GLOBAL gates the unsealed payment on its executing frame's epoch, which
/// trails the anchor's by under a lockstep window.
fn kind(epoch: u64, sealed: bool) -> &'static str {
    use quil_types::consensus::{hash_storage_proofs_at, unsealed_issuance_epoch};
    if sealed {
        "held"
    } else if !hash_storage_proofs_at(epoch) || epoch >= unsealed_issuance_epoch() {
        "at_once"
    } else {
        "fees_only"
    }
}

/// What the prover's balance gained since the last credit line.
#[derive(Debug, Default)]
struct Credits {
    since: u64,
    credited: u128,
    debited: u128,
    changes: u32,
}

/// Whether `window` shows a seat signing under half the certificates a
/// member voting in time signs (`quorum / committee`); `None` when it holds
/// too little to judge: under an hour counted, or under [`LOW_MIN_FRAMES`]
/// frames.
#[cfg(test)]
pub(crate) fn low_share(window: &CertificateWindow, committee: u32, quorum: u32) -> Option<bool> {
    low_share_of(window, committee, quorum)
}

/// Whether `window` shows a seat signing under half of `quorum / voters`:
/// every landed certificate holds exactly a quorum of signers, so with
/// `voters` members voting a member voting in time signs about that share of
/// them. `None` when it holds too little to judge: under an hour counted, or
/// under [`LOW_MIN_FRAMES`] frames.
pub(crate) fn low_share_of(window: &CertificateWindow, voters: u32, quorum: u32) -> Option<bool> {
    if window.observed_seconds < window.window_seconds
        || window.frames < LOW_MIN_FRAMES
        || voters == 0
    {
        return None;
    }
    Some(
        u128::from(window.signed_frames) * 2 * u128::from(voters)
            < u128::from(window.frames) * u128::from(quorum),
    )
}

#[derive(Debug, Default)]
pub(crate) struct SeatCertificates {
    seats: BTreeMap<Vec<u8>, Seat>,
    /// The newest GLOBAL frame observed.
    global_frame: u64,
    credits: Credits,
}

impl SeatCertificates {
    /// The seats the sampler found at `now`, each with its shard's head
    /// session generation. Returns the `(filter, generation)` sessions
    /// whose membership this node must read from committed state
    /// ([`Self::membership`]).
    pub fn seats(&mut self, heads: &[(Vec<u8>, u64)], now: u64) -> Vec<(Vec<u8>, u64)> {
        let current: BTreeMap<&[u8], u64> = heads.iter().map(|(f, g)| (f.as_slice(), *g)).collect();
        for (filter, seat) in self.seats.iter_mut() {
            seat.current = current.contains_key(filter.as_slice());
            seat.expire(now);
        }
        self.seats
            .retain(|_, seat| seat.current || !seat.buckets.is_empty());
        let mut missing = Vec::new();
        for (filter, generation) in heads {
            if !self.seats.contains_key(filter) {
                if self.seats.len() >= MAX_SEATS {
                    continue;
                }
                self.seats.insert(filter.clone(), Seat::new(now));
            }
            let seat = &self.seats[filter];
            if !seat.memberships.iter().any(|m| m.generation == *generation) {
                missing.push((filter.clone(), *generation));
            }
        }
        missing
    }

    /// This node's index among the members of `filter`'s session
    /// `generation` (`None`: not a member), of `committee` members.
    pub fn membership(
        &mut self,
        filter: &[u8],
        generation: u64,
        index: Option<u32>,
        committee: u32,
    ) {
        let Some(seat) = self.seats.get_mut(filter) else {
            return;
        };
        seat.memberships.retain(|m| m.generation != generation);
        seat.memberships.push_back(Membership {
            generation,
            index,
            committee,
        });
        while seat.memberships.len() > MAX_GENERATIONS {
            seat.memberships.pop_front();
        }
    }

    /// Count `header` at `now` if it is a frame of a session this node is
    /// a member of on one of its seats. Returns whether it counted.
    pub fn observe(&mut self, header: Header<'_>, now: u64) -> bool {
        use quil_cw_consensus::app_cert;
        let Some(seat) = self.seats.get(header.filter) else {
            return false;
        };
        let Some(certificate) = app_cert::unwrap_cert_from_header(header.signature) else {
            return false;
        };
        let Some(index) = app_cert::unverified_finalization_epoch(certificate)
            .and_then(|generation| seat.membership(generation))
            .and_then(|m| m.index)
        else {
            return false;
        };
        let Some((member, signers)) =
            app_cert::unverified_member_signers(certificate, index as usize)
        else {
            return false;
        };
        let counted = self.count(
            header.filter,
            header.frame,
            header.timestamp_ms,
            member,
            header.anchor,
            now,
        );
        if counted {
            self.tally(
                header.filter,
                header.timestamp_ms,
                now,
                member.generation,
                member.committee,
                &signers,
            );
        }
        counted
    }

    /// Add the `signers` of a counted frame of `filter`, signed under
    /// `committee` members of session `generation`, to the seat's
    /// per-member counts.
    pub fn tally(
        &mut self,
        filter: &[u8],
        timestamp_ms: i64,
        now: u64,
        generation: u64,
        committee: usize,
        signers: &[u32],
    ) {
        let Some(seat) = self.seats.get_mut(filter) else {
            return;
        };
        if committee == 0 || committee > MAX_TALLY {
            return;
        }
        let at = u64::try_from(timestamp_ms / 1000)
            .ok()
            .filter(|&at| at > 0 && at <= now)
            .unwrap_or(now);
        let minute = at / MINUTE;
        let slot = match seat
            .tallies
            .iter()
            .position(|t| t.minute == minute && t.generation == generation)
        {
            Some(i) => i,
            None => {
                let position = seat.tallies.partition_point(|t| t.minute < minute);
                seat.tallies.insert(
                    position,
                    Tally {
                        minute,
                        generation,
                        frames: 0,
                        counts: vec![0; committee],
                    },
                );
                position
            }
        };
        let tally = &mut seat.tallies[slot];
        if tally.counts.len() != committee {
            return;
        }
        tally.frames += 1;
        for &signer in signers {
            if let Some(n) = tally.counts.get_mut(signer as usize) {
                *n = n.saturating_add(1);
            }
        }
        seat.expire(now);
    }

    /// Note GLOBAL frame `frame` as observed: the epoch the reward lines
    /// judge ended, and where each seat's counting began.
    pub fn observe_global(&mut self, frame: u64) {
        self.global_frame = self.global_frame.max(frame);
        for seat in self.seats.values_mut() {
            if seat.first_global == 0 {
                seat.first_global = frame;
            }
        }
    }

    /// Count shard frame `frame` of `filter`, timestamped `timestamp_ms`,
    /// anchored at GLOBAL frame `anchor`, whose certificate says `member` of
    /// this node's index, at `now`.
    pub fn count(
        &mut self,
        filter: &[u8],
        frame: u64,
        timestamp_ms: i64,
        member: CertificateMember,
        anchor: u64,
        now: u64,
    ) -> bool {
        let Some(seat) = self.seats.get_mut(filter) else {
            return false;
        };
        // The certificate must come from a session this node sits in, signed
        // under the committee committed state names for it.
        let Some(committee) = seat
            .membership(member.generation)
            .filter(|m| m.index.is_some() && m.committee as usize == member.committee)
            .map(|m| m.committee)
        else {
            return false;
        };
        if seat.counted.contains(&frame)
            || (seat.counted.len() >= MAX_COUNTED
                && seat.counted.first().is_some_and(|&low| frame < low))
        {
            return false;
        }
        // A frame's own time, unless it claims one ahead of this clock.
        let at = u64::try_from(timestamp_ms / 1000)
            .ok()
            .filter(|&at| at > 0 && at <= now)
            .unwrap_or(now);
        if now - at >= DAY {
            return false;
        }
        seat.counted.insert(frame);
        while seat.counted.len() > MAX_COUNTED {
            seat.counted.pop_first();
        }
        let minute = at / MINUTE;
        let position = seat.buckets.partition_point(|b| b.minute < minute);
        if seat
            .buckets
            .get(position)
            .is_none_or(|b| b.minute != minute)
        {
            seat.buckets.insert(
                position,
                Bucket {
                    minute,
                    ..Default::default()
                },
            );
        }
        let bucket = &mut seat.buckets[position];
        bucket.frames += 1;
        bucket.signed += u32::from(member.signed);
        let epoch = quil_types::consensus::epoch_for_frame(anchor);
        let counts = seat.epochs.entry(epoch).or_default();
        counts.frames += 1;
        if member.signed {
            counts.signed += 1;
            counts.weight += storage_seat::PROPOSAL / u64::from(committee).max(1);
        }
        while seat.epochs.len() > MAX_EPOCHS {
            seat.epochs.pop_first();
        }
        if frame > seat.last_frame {
            seat.last_frame = frame;
            seat.committee = committee;
        }
        true
    }

    /// The seat's share at `now`; `None` for a shard this node holds no
    /// seat on, or none in a session with known membership.
    pub fn snapshot(&self, filter: &[u8], now: u64) -> Option<CertificateShare> {
        Self::share(self.seats.get(filter)?, now)
    }

    fn share(seat: &Seat, now: u64) -> Option<CertificateShare> {
        let committee = if seat.committee > 0 {
            seat.committee
        } else {
            seat.member()?.committee
        };
        Some(CertificateShare {
            hour: Some(seat.window(HOUR, now)),
            day: Some(seat.window(DAY, now)),
            committee,
            quorum: quil_cw_consensus::app_cert::certificate_quorum(committee as usize) as u32,
        })
    }

    /// The lines due at `now`: each current seat's summary every
    /// [`LOG_EVERY`] once it was counted that long, and a low share's
    /// start, its repeats every [`LOG_EVERY`] and its end, which comes once the
    /// seat has stayed out of the low share for [`LOW_END_HOLD`].
    pub fn due(&mut self, now: u64) -> Vec<SeatLog> {
        let mut logs = Vec::new();
        for (filter, seat) in self.seats.iter_mut() {
            let Some(share) = Self::share(seat, now) else {
                continue;
            };
            let hour = share.hour.as_ref().cloned().unwrap_or_default();
            let voters = if seat.current { seat.voters(now) } else { None };
            // Every landed certificate holds exactly a quorum of signers, so
            // the fair share is quorum / voters, not quorum / committee.
            let fair_over = voters
                .map(|v| v.voters)
                .filter(|v| (share.quorum..=share.committee).contains(v))
                .unwrap_or(share.committee);
            let judged = if seat.current {
                low_share_of(&hour, fair_over, share.quorum)
            } else {
                None
            };
            match (judged, seat.low) {
                (Some(true), None) => {
                    seat.low = Some(Low {
                        since: now,
                        warned: now,
                        clear_since: None,
                    });
                    logs.push(SeatLog::Low {
                        filter: filter.clone(),
                        share,
                        voters,
                        low_secs: 0,
                        repeat: false,
                    });
                }
                (Some(true), Some(low)) => {
                    let again = now.saturating_sub(low.warned) >= LOG_EVERY;
                    seat.low = Some(Low {
                        warned: if again { now } else { low.warned },
                        clear_since: None,
                        ..low
                    });
                    if again {
                        logs.push(SeatLog::Low {
                            filter: filter.clone(),
                            share,
                            voters,
                            low_secs: now.saturating_sub(low.since),
                            repeat: true,
                        });
                    }
                }
                (_, None) => {}
                (judged, Some(low)) => {
                    let clear = low.clear_since.unwrap_or(now);
                    if seat.current && now.saturating_sub(clear) < LOW_END_HOLD {
                        seat.low = Some(Low {
                            clear_since: Some(clear),
                            ..low
                        });
                    } else {
                        seat.low = None;
                        // A former seat ends where it is seen; otherwise the
                        // episode lasted until the share first cleared.
                        let end = if seat.current { clear } else { now };
                        logs.push(SeatLog::Ended {
                            filter: filter.clone(),
                            share,
                            low_secs: end.saturating_sub(low.since),
                            how: match (judged, seat.current) {
                                (_, false) => "the seat ended",
                                (Some(false), _) => "its share recovered",
                                _ => "too few frames in the last hour to judge",
                            },
                        });
                    }
                }
            }
            if seat.current && now.saturating_sub(seat.summarized) >= LOG_EVERY {
                seat.summarized = now;
                logs.push(SeatLog::Summary {
                    filter: filter.clone(),
                    share,
                });
            }
        }
        logs
    }
}

impl SeatCertificates {
    /// The epoch of the newest GLOBAL frame observed; 0 before one.
    fn current_epoch(&self) -> u64 {
        match self.global_frame {
            0 => 0,
            frame => quil_types::consensus::epoch_for_frame(frame),
        }
    }

    /// The seats whose slots are due a read from committed state: one of
    /// the last two epochs still lacks a reward line, and [`READ_EVERY`] has
    /// passed since the last read. A former seat counts too, until its
    /// epochs are done or it is dropped: it was held in them.
    pub fn rewards_due(&mut self, now: u64) -> Vec<Vec<u8>> {
        let current = self.current_epoch();
        if self.global_frame == 0 {
            return Vec::new();
        }
        let mut due = Vec::new();
        for (filter, seat) in self.seats.iter_mut() {
            let pending = (current.saturating_sub(2)..current).any(|epoch| {
                seat.rewards_logged.get(&epoch).copied().unwrap_or(0) != (ENDED | CLOSED)
            });
            if pending && now.saturating_sub(seat.read_at) >= READ_EVERY {
                seat.read_at = now;
                due.push(filter.clone());
            }
        }
        due
    }

    /// The reward lines `filter`'s `slots`, as committed state holds them,
    /// make due: for each of the last two epochs, a line when it ended and
    /// one when its settlement closed (settled or expired), each once. An
    /// epoch the seat holds no slot for is paid at once or not at all
    /// ([`kind`]): once it is two epochs old, when no slot can still sync
    /// in, it gets one line if the seat was held in it (tips counted, or
    /// counted since before the epoch began and still a seat), and is done.
    pub fn rewards(&mut self, filter: &[u8], slots: &[SlotRead], now: u64) -> Vec<SeatLog> {
        let current = self.current_epoch();
        let length = quil_types::consensus::epoch_length_frames();
        let Some(seat) = self.seats.get_mut(filter) else {
            return Vec::new();
        };
        seat.read_at = now;
        let committee = Self::share(seat, now).map_or(0, |share| share.committee);
        let mut logs = Vec::new();
        for epoch in current.saturating_sub(2)..current {
            let logged = seat.rewards_logged.get(&epoch).copied().unwrap_or(0);
            if logged == (ENDED | CLOSED) {
                continue;
            }
            let counts = seat.epochs.get(&epoch).copied().unwrap_or_default();
            let complete = seat.first_global > 0 && seat.first_global <= epoch * length;
            let held = counts.frames > 0 || (seat.current && complete);
            let slot = slots.iter().find(|slot| slot.epoch == epoch);
            let stage = match slot {
                None if epoch + 2 > current => continue,
                None if held && logged == 0 => Some((ENDED | CLOSED, "ended")),
                None => None,
                Some(slot) if !slot.sealed && slot.frames == 0 && counts.frames == 0 => None,
                Some(slot) => match slot.outcome {
                    Outcome::Open if logged & ENDED == 0 => Some((ENDED, "ended")),
                    Outcome::Open => continue,
                    _ if logged & CLOSED == 0 => Some((ENDED | CLOSED, "closed")),
                    _ => continue,
                },
            };
            let Some((bits, stage)) = stage else {
                seat.rewards_logged.insert(epoch, ENDED | CLOSED);
                continue;
            };
            seat.rewards_logged.insert(epoch, logged | bits);
            logs.push(SeatLog::Reward {
                filter: filter.to_vec(),
                epoch,
                stage,
                kind: kind(epoch, slot.is_some_and(|slot| slot.sealed)),
                slot: slot.cloned(),
                counts,
                complete,
                committee,
            });
        }
        while seat.rewards_logged.len() > MAX_EPOCHS {
            seat.rewards_logged.pop_first();
        }
        logs
    }

    /// Note `delta`, a change of the prover's reward balance read after a
    /// sync, at `now`.
    pub fn credited(&mut self, delta: i128, now: u64) {
        if self.credits.since == 0 {
            self.credits.since = now;
        }
        if delta >= 0 {
            self.credits.credited = self.credits.credited.saturating_add(delta as u128);
        } else {
            self.credits.debited = self.credits.debited.saturating_add(delta.unsigned_abs());
        }
        self.credits.changes = self.credits.changes.saturating_add(1);
    }

    /// The balance line, once an hour has passed since the last, while the
    /// node holds a seat.
    pub fn credits_due(&mut self, now: u64) -> Option<SeatLog> {
        if self.seats.is_empty() {
            return None;
        }
        if self.credits.since == 0 {
            self.credits.since = now;
            return None;
        }
        let window_secs = now.saturating_sub(self.credits.since);
        if window_secs < LOG_EVERY {
            return None;
        }
        let credits = std::mem::take(&mut self.credits);
        self.credits.since = now;
        Some(SeatLog::Credits {
            window_secs,
            credited: credits.credited,
            debited: credits.debited,
            changes: credits.changes,
            seats: self.seats.values().filter(|seat| seat.current).count(),
        })
    }
}

fn lock() -> std::sync::MutexGuard<'static, SeatCertificates> {
    static TRACKER: OnceLock<Mutex<SeatCertificates>> = OnceLock::new();
    TRACKER
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Count the shard headers of an authenticated GLOBAL frame body.
pub(crate) fn observe_frame(frame: &quil_types::proto::global::GlobalFrame) {
    use quil_types::proto::global::message_request::Request;
    let now = super::frame_observations::unix_seconds();
    let mut tracker = lock();
    if let Some(header) = frame.header.as_ref() {
        tracker.observe_global(header.frame_number);
    }
    if tracker.seats.is_empty() {
        return;
    }
    for request in frame
        .requests
        .iter()
        .flat_map(|bundle| bundle.requests.iter())
    {
        let Some(Request::Shard(header)) = request.request.as_ref() else {
            continue;
        };
        let Some(signature) = header.public_key_signature_bls48581.as_ref() else {
            continue;
        };
        tracker.observe(
            Header {
                filter: &header.address,
                frame: header.frame_number,
                timestamp_ms: header.timestamp,
                signature: &signature.signature,
                anchor: header.global_frame_number,
            },
            now,
        );
    }
}

/// Note a change of the local prover's reward balance (`delta`, signed),
/// for the hourly credit line.
pub(crate) fn credited(delta: &num_bigint::BigInt) {
    if let Ok(delta) = delta.to_string().parse::<i128>() {
        lock().credited(delta, super::frame_observations::unix_seconds());
    }
}

/// The share of this node's seat on `filter`, for the shard info RPC.
pub(crate) fn snapshot(filter: &[u8]) -> Option<CertificateShare> {
    lock().snapshot(filter, super::frame_observations::unix_seconds())
}

/// Update the seats from the sampler's pass at `now` (`heads`: each seat's
/// shard with its head session generation), reading the membership of new
/// sessions from committed state, and log what is due.
pub(crate) fn refresh(
    crdt: &std::sync::Arc<quil_hypergraph::HypergraphCrdt>,
    prover_address: &[u8],
    heads: &[(Vec<u8>, u64)],
    now: u64,
) {
    use quil_execution::global_intrinsic::handoff::{self, CommittedView};
    let missing = lock().seats(heads, now);
    if !missing.is_empty() {
        match CommittedView::capture(crdt) {
            Ok(view) => {
                for (filter, generation) in missing {
                    let session = match handoff::session_at_generation(&view, &filter, generation) {
                        Ok(Some(session)) => session,
                        Ok(None) => continue,
                        Err(e) => {
                            tracing::debug!(filter = %hex::encode(&filter), generation, error = %e,
                                "seat certificate share: session unreadable");
                            continue;
                        }
                    };
                    let index = session.members.iter().position(|key| {
                        quil_execution::global_intrinsic::materialize::prover_address_from_pubkey(
                            key,
                        )
                        .is_ok_and(|address| address.as_slice() == prover_address)
                    });
                    lock().membership(
                        &filter,
                        generation,
                        index.map(|i| i as u32),
                        session.members.len() as u32,
                    );
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "seat certificate share: committed state unreadable")
            }
        }
    }
    let logs = lock().due(now);
    for line in &logs {
        log(line);
    }
    log_rewards(crdt, prover_address, now);
}

/// Read the seats due a look at committed state and log their reward
/// lines, then the hour's credit line when due.
fn log_rewards(
    crdt: &std::sync::Arc<quil_hypergraph::HypergraphCrdt>,
    prover_address: &[u8],
    now: u64,
) {
    let due = lock().rewards_due(now);
    if !due.is_empty() {
        match <[u8; 32]>::try_from(prover_address) {
            Ok(member) => {
                let state = quil_execution::hypergraph_state::HypergraphState::new(crdt.clone());
                for filter in due {
                    let slots: Vec<SlotRead> = match storage_seat::read(&state, &member, &filter) {
                        Ok(seat) => seat
                            .map(|seat| seat.slots.iter().map(SlotRead::of).collect())
                            .unwrap_or_default(),
                        Err(e) => {
                            tracing::debug!(filter = %hex::encode(&filter), error = %e,
                                "seat reward line: seat unreadable");
                            continue;
                        }
                    };
                    let logs = lock().rewards(&filter, &slots, now);
                    for line in &logs {
                        log(line);
                    }
                }
            }
            Err(_) => tracing::debug!("seat reward line: prover address is not 32 bytes"),
        }
    }
    let credits = lock().credits_due(now);
    if let Some(line) = &credits {
        log(line);
    }
}

fn percent(part: u64, whole: u64) -> u64 {
    part.saturating_mul(100).checked_div(whole).unwrap_or(0)
}

fn log(line: &SeatLog) {
    match line {
        SeatLog::Summary { filter, share } => {
            let (hour, day) = (
                share.hour.as_ref().cloned().unwrap_or_default(),
                share.day.as_ref().cloned().unwrap_or_default(),
            );
            tracing::info!(filter = %hex::encode(filter), committee = share.committee,
                quorum = share.quorum,
                in_time_share_pct = percent(u64::from(share.quorum), u64::from(share.committee)),
                hour_frames = hour.frames, hour_signed = hour.signed_frames,
                hour_share_pct = percent(hour.signed_frames, hour.frames),
                hour_observed_secs = hour.observed_seconds, day_frames = day.frames,
                day_signed = day.signed_frames,
                day_share_pct = percent(day.signed_frames, day.frames),
                day_observed_secs = day.observed_seconds,
                scope = "shard headers in the GLOBAL frames this node received",
                "this seat's share of its shard's certificates: only signers earn a frame's \
                 reward, and a member voting in time signs about quorum/committee of them");
        }
        SeatLog::Low {
            filter,
            share,
            voters,
            low_secs,
            repeat,
        } => {
            let hour = share.hour.as_ref().cloned().unwrap_or_default();
            let fair_over = voters
                .map(|v| v.voters)
                .filter(|v| (share.quorum..=share.committee).contains(v))
                .unwrap_or(share.committee);
            tracing::warn!(filter = %hex::encode(filter), committee = share.committee,
                quorum = share.quorum,
                voters = voters.map(|v| u64::from(v.voters)),
                rank = voters.map(|v| u64::from(v.rank)),
                in_time_share_pct = percent(u64::from(share.quorum), u64::from(share.committee)),
                fair_share_pct = percent(u64::from(share.quorum), u64::from(fair_over)),
                hour_frames = hour.frames, hour_signed = hour.signed_frames,
                hour_share_pct = percent(hour.signed_frames, hour.frames), low_secs, repeat,
                scope = "this node's seat",
                action = "check this seat's worker: blocked or behind its shard ('this worker is \
                          behind its shard', LocalMat in qclient node prover manage), silent \
                          ('this member's silence'), or voting late from CPU load or slow peer \
                          connections. A seat voting on time can still lose a race: every landed \
                          certificate holds exactly quorum signers, so with more voters than \
                          quorum the votes reaching the assembler last go unsigned, most often \
                          at the tail of the voters (rank near voters) while peers are faster; \
                          then no local fault shows. Frames it does not sign earn it nothing",
                "this seat signed under half the shard certificates a member voting in time \
                 signs over the last hour");
        }
        SeatLog::Ended {
            filter,
            share,
            low_secs,
            how,
        } => {
            let hour = share.hour.as_ref().cloned().unwrap_or_default();
            tracing::info!(filter = %hex::encode(filter), hour_frames = hour.frames,
                hour_signed = hour.signed_frames,
                hour_share_pct = percent(hour.signed_frames, hour.frames), low_secs, how,
                "this seat's low certificate share ended");
        }
        SeatLog::Reward {
            filter,
            epoch,
            stage,
            kind,
            slot,
            counts,
            complete,
            committee,
        } => {
            let none = SlotRead {
                epoch: *epoch,
                sealed: false,
                frames: 0,
                expected: 0,
                held: 0.into(),
                release_at_most: 0.into(),
                outcome: Outcome::Open,
            };
            let read = slot.as_ref().unwrap_or(&none);
            let (outcome, closed_at) = match (slot, read.outcome) {
                (None, _) => ("no_slot", 0),
                (_, Outcome::Open) => ("open", 0),
                (_, Outcome::Settled(frame)) => ("settled", frame),
                (_, Outcome::Expired(frame)) => ("expired", frame),
            };
            let proposals = |units: u64| units as f64 / storage_seat::PROPOSAL as f64;
            tracing::info!(filter = %hex::encode(filter), epoch = *epoch, stage, kind,
                sealed = read.sealed, committee,
                tips_seen = counts.frames, tips_signed = counts.signed,
                expected_by_tips = proposals(counts.weight), counts_complete = complete,
                expected_proposals = proposals(read.expected), chained_roots = read.frames,
                held = %read.held, release_at_most = %read.release_at_most,
                outcome, closed_at_global_frame = closed_at,
                scope = "shard headers in the GLOBAL frames this node received, and committed GLOBAL state",
                "this seat's epoch rewards: kind=held is entitled to `held` and credited up to \
                 `release_at_most` once settled (nothing if expired), so completeness is the balance \
                 gained over `held`; kind=at_once is paid one issuance share at once for each of \
                 `tips_signed` GLOBAL executed (`expected_by_tips` against `expected_proposals` shows \
                 how many GLOBAL counted; outcome=no_slot when GLOBAL holds no slot for the seat), \
                 credited in the hourly reward balance line; kind=fees_only earns fees only");
        }
        SeatLog::Credits {
            window_secs,
            credited,
            debited,
            changes,
            seats,
        } => {
            tracing::info!(window_secs, credited = *credited, debited = *debited,
                balance_changes = changes, seats,
                scope = "the local prover's reward balance as the prover tree sync read it",
                "reward balance credits: what the prover's balance gained in the last hour, at-once \
                 payments and released settlements together");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_800_000_000;
    const FILTER: &[u8] = &[7; 35];

    fn member(generation: u64, committee: usize, signed: bool) -> CertificateMember {
        CertificateMember {
            generation,
            committee,
            signed,
        }
    }

    fn ms(at: u64) -> i64 {
        (at * 1000) as i64
    }

    /// A tracker with this node at index 0 of `FILTER`'s session 5 of 4.
    fn seated(now: u64) -> SeatCertificates {
        let mut t = SeatCertificates::default();
        assert_eq!(
            t.seats(&[(FILTER.to_vec(), 5)], now),
            vec![(FILTER.to_vec(), 5)]
        );
        t.membership(FILTER, 5, Some(0), 4);
        assert!(t.seats(&[(FILTER.to_vec(), 5)], now).is_empty());
        t
    }

    fn hour(t: &SeatCertificates, now: u64) -> (u64, u64) {
        let w = t.snapshot(FILTER, now).unwrap().hour.unwrap();
        (w.frames, w.signed_frames)
    }

    fn day(t: &SeatCertificates, now: u64) -> (u64, u64) {
        let w = t.snapshot(FILTER, now).unwrap().day.unwrap();
        (w.frames, w.signed_frames)
    }

    #[test]
    fn counts_signed_and_unsigned_frames_once_by_their_own_time() {
        let mut t = seated(T0);
        let now = T0 + 600;
        assert!(t.count(FILTER, 10, ms(T0 + 100), member(5, 4, true), 0, now));
        assert!(t.count(FILTER, 11, ms(T0 + 110), member(5, 4, false), 0, now));
        assert!(t.count(FILTER, 12, ms(T0 + 170), member(5, 4, false), 0, now));
        // The poller and the gossip deliver the same frame: it counts once.
        assert!(!t.count(FILTER, 11, ms(T0 + 110), member(5, 4, true), 0, now));
        // A session this node holds no known membership in, a committee
        // other than the session's, or another shard: not counted.
        assert!(!t.count(FILTER, 13, ms(T0 + 200), member(6, 4, true), 0, now));
        assert!(!t.count(FILTER, 14, ms(T0 + 200), member(5, 5, true), 0, now));
        assert!(!t.count(&[8; 35], 15, ms(T0 + 200), member(5, 4, true), 0, now));
        // A frame a day old is out of every window; one claiming a time
        // ahead of this clock, or none, counts now.
        assert!(!t.count(FILTER, 16, ms(now - DAY), member(5, 4, true), 0, now));
        assert!(t.count(FILTER, 17, ms(now + 900), member(5, 4, true), 0, now));
        assert!(t.count(FILTER, 18, 0, member(5, 4, false), 0, now));
        assert_eq!(hour(&t, now), (5, 2));
        let share = t.snapshot(FILTER, now).unwrap();
        assert_eq!((share.committee, share.quorum), (4, 3));
        assert_eq!(share.hour.unwrap().observed_seconds, 600);
        assert_eq!(share.day.unwrap().observed_seconds, 600);
        assert!(t.snapshot(&[8; 35], now).is_none());
    }

    #[test]
    fn windows_roll_off_frames_by_their_minute() {
        let mut t = seated(T0);
        let now = T0 + DAY;
        assert!(t.count(FILTER, 1, ms(T0 + 30), member(5, 4, true), 0, now));
        assert!(t.count(FILTER, 2, ms(now - 3_000), member(5, 4, false), 0, now));
        assert!(t.count(FILTER, 3, ms(now - 60), member(5, 4, true), 0, now));
        assert_eq!(hour(&t, now), (2, 1));
        assert_eq!(day(&t, now), (3, 2));
        // Out of the hour after an hour; out of the day after a day.
        assert_eq!(hour(&t, now + 3_000), (1, 1));
        assert_eq!(hour(&t, now + 3_600), (0, 0));
        assert_eq!(day(&t, now + 60), (2, 1));
        assert_eq!(day(&t, now + DAY), (0, 0));
        let w = t.snapshot(FILTER, now).unwrap();
        assert_eq!(w.hour.unwrap().observed_seconds, HOUR);
        assert_eq!(w.day.unwrap().observed_seconds, DAY);
        // A former seat stays until its frames leave the day, then goes.
        assert!(t.seats(&[], now + 60).is_empty());
        assert!(t.snapshot(FILTER, now + 60).is_some());
        assert!(t.seats(&[], now + DAY).is_empty());
        assert!(t.snapshot(FILTER, now + DAY).is_none());
    }

    #[test]
    fn no_membership_means_no_share() {
        let mut t = SeatCertificates::default();
        t.seats(&[(FILTER.to_vec(), 5)], T0);
        assert!(t.snapshot(FILTER, T0).is_none());
        t.membership(FILTER, 5, None, 4);
        assert!(!t.count(FILTER, 1, ms(T0), member(5, 4, true), 0, T0));
        assert!(t.snapshot(FILTER, T0).is_none());
        // The successor session seats this node.
        assert_eq!(
            t.seats(&[(FILTER.to_vec(), 6)], T0),
            vec![(FILTER.to_vec(), 6)]
        );
        t.membership(FILTER, 6, Some(2), 7);
        assert!(t.count(FILTER, 2, ms(T0), member(6, 7, false), 0, T0));
        assert_eq!(t.snapshot(FILTER, T0).unwrap().quorum, 5);
    }

    #[test]
    fn tracking_is_bounded() {
        let mut t = SeatCertificates::default();
        let heads: Vec<_> = (0..MAX_SEATS as u16 + 40)
            .map(|n| (n.to_be_bytes().to_vec(), 1))
            .collect();
        assert_eq!(t.seats(&heads, T0).len(), MAX_SEATS);
        assert_eq!(t.seats.len(), MAX_SEATS);
        let mut t = seated(T0);
        for generation in 6..20 {
            t.membership(FILTER, generation, Some(0), 4);
        }
        assert_eq!(t.seats[FILTER].memberships.len(), MAX_GENERATIONS);
        t.membership(FILTER, 5, Some(0), 4);
        let now = T0 + DAY;
        for frame in 1..=(MAX_COUNTED as u64 + 100) {
            assert!(t.count(FILTER, frame, ms(now), member(5, 4, true), 0, now));
        }
        assert_eq!(t.seats[FILTER].counted.len(), MAX_COUNTED);
        assert!(
            !t.count(FILTER, 50, ms(now), member(5, 4, true), 0, now),
            "a frame below the remembered range may have counted already"
        );
        assert_eq!(t.seats[FILTER].buckets.len(), 1);
    }

    #[test]
    fn low_share_is_judged_against_half_the_in_time_share() {
        let window = |observed, frames, signed| CertificateWindow {
            window_seconds: HOUR,
            observed_seconds: observed,
            frames,
            signed_frames: signed,
        };
        // 4 members, quorum 3: a member voting in time signs 75%; half is 37.5%.
        assert_eq!(low_share(&window(HOUR, 40, 15), 4, 3), Some(false));
        assert_eq!(low_share(&window(HOUR, 40, 14), 4, 3), Some(true));
        assert_eq!(low_share(&window(HOUR, 40, 0), 4, 3), Some(true));
        // Too little to judge.
        assert_eq!(low_share(&window(HOUR - 1, 40, 0), 4, 3), None);
        assert_eq!(low_share(&window(HOUR, LOW_MIN_FRAMES - 1, 0), 4, 3), None);
        assert_eq!(low_share(&window(HOUR, 40, 0), 0, 0), None);
        // 24 members, quorum 17: 70.8% in time, low under 35.4%.
        assert_eq!(low_share(&window(HOUR, 1000, 355), 24, 17), Some(false));
        assert_eq!(low_share(&window(HOUR, 1000, 354), 24, 17), Some(true));
    }

    fn kinds(logs: &[SeatLog]) -> Vec<String> {
        logs.iter()
            .map(|log| match log {
                SeatLog::Summary { share, .. } => {
                    let h = share.hour.as_ref().unwrap();
                    format!("summary {}/{}", h.signed_frames, h.frames)
                }
                SeatLog::Low {
                    low_secs, repeat, ..
                } => format!("low {low_secs} {repeat}"),
                SeatLog::Ended { low_secs, how, .. } => format!("ended {low_secs} {how}"),
                SeatLog::Reward { stage, .. } => format!("reward {stage}"),
                SeatLog::Credits { .. } => "credits".into(),
            })
            .collect()
    }

    fn frame_a_minute(t: &mut SeatCertificates, minutes: std::ops::Range<u64>, signed: bool) {
        for k in minutes {
            let at = T0 + k * 60;
            assert!(t.count(FILTER, k + 1, ms(at), member(5, 4, signed), 0, at));
        }
    }

    #[test]
    fn a_low_share_warns_once_an_hour_and_ends_with_its_duration() {
        let mut t = seated(T0);
        // Two hours of frames, one a minute, none signed by this seat.
        frame_a_minute(&mut t, 0..120, false);
        // Under an hour counted: no judgement and no summary yet.
        assert!(t.due(T0 + 1_800).is_empty());
        assert_eq!(kinds(&t.due(T0 + 3_600)), ["low 0 false", "summary 0/61"]);
        assert!(t.due(T0 + 3_660).is_empty());
        assert!(t.due(T0 + 7_140).is_empty());
        assert_eq!(kinds(&t.due(T0 + 7_200)), ["low 3600 true", "summary 0/60"]);
        // The next hour this seat signs every frame.
        frame_a_minute(&mut t, 120..180, true);
        // Not low from here, but the episode holds until the share stayed
        // out of it for LOW_END_HOLD.
        assert_eq!(kinds(&t.due(T0 + 10_800)), ["summary 60/60"]);
        assert!(t.due(T0 + 10_800 + LOW_END_HOLD - 1).is_empty());
        assert_eq!(
            kinds(&t.due(T0 + 10_800 + LOW_END_HOLD)),
            ["ended 7200 its share recovered"]
        );
        assert!(t.due(T0 + 10_800 + LOW_END_HOLD + 60).is_empty());
    }

    #[test]
    fn a_low_share_ends_when_the_shard_stops_or_the_seat_does() {
        let mut t = seated(T0);
        frame_a_minute(&mut t, 0..60, false);
        assert_eq!(kinds(&t.due(T0 + 3_600)), ["low 0 false", "summary 0/60"]);
        // No frames for the next hour: nothing to judge, so the warning ends.
        assert_eq!(kinds(&t.due(T0 + 7_300)), ["summary 0/0"]);
        assert_eq!(
            kinds(&t.due(T0 + 7_300 + LOW_END_HOLD)),
            ["ended 3700 too few frames in the last hour to judge"]
        );
        let mut t = seated(T0);
        frame_a_minute(&mut t, 0..60, false);
        assert_eq!(kinds(&t.due(T0 + 3_600)), ["low 0 false", "summary 0/60"]);
        t.seats(&[], T0 + 3_660);
        assert_eq!(kinds(&t.due(T0 + 3_660)), ["ended 60 the seat ended"]);
        assert!(t.due(T0 + 9_000).is_empty(), "a former seat logs nothing");
    }

    #[test]
    fn a_share_at_the_threshold_is_one_episode() {
        let mut t = seated(T0);
        // 4 members, quorum 3: low is 22 signed of 61 frames or fewer. A seat
        // signing 3 frames in 8 holds 22 or 23 in the hour, so each minute's
        // evaluation can fall on either side of the threshold.
        let (mut low, mut clear) = (0, 0);
        let (mut starts, mut repeats, mut ends) = (Vec::new(), Vec::new(), Vec::new());
        let (mut started_at, mut ended_at) = (Vec::new(), Vec::new());
        for k in 0..240u64 {
            let at = T0 + k * 60;
            assert!(t.count(FILTER, k + 1, ms(at), member(5, 4, k % 8 < 3), 0, at));
            if k < 60 {
                continue;
            }
            let share = t.snapshot(FILTER, at).unwrap();
            let hour = share.hour.unwrap();
            match low_share(&hour, share.committee, share.quorum) {
                Some(true) => low += 1,
                Some(false) => clear += 1,
                None => {}
            }
            for log in t.due(at) {
                match log {
                    SeatLog::Low {
                        low_secs, repeat, ..
                    } if repeat => repeats.push(low_secs),
                    SeatLog::Low { low_secs, .. } => {
                        starts.push(low_secs);
                        started_at.push(k);
                    }
                    SeatLog::Ended { low_secs, .. } => ends.push(low_secs),
                    SeatLog::Summary { .. } | SeatLog::Reward { .. } | SeatLog::Credits { .. } => {}
                }
            }
        }
        assert!(
            low > 20 && clear > 20,
            "the share must cross: {low} {clear}"
        );
        assert_eq!(starts, [0], "one start");
        // Minutes 60 and 61 hold 24 and 23 signed; minute 62 is the first at 22.
        assert_eq!(started_at, [62], "it starts at the first low evaluation");
        assert_eq!(repeats.len(), 2, "a repeat per hour: {repeats:?}");
        assert!(repeats[0] >= LOG_EVERY && repeats[1] >= 2 * LOG_EVERY);
        assert!(ends.is_empty(), "no end while it crosses: {ends:?}");
        // The seat then signs every frame: minute 241 holds 23 signed, the
        // first clear of the last stretch, and the end comes a hold later.
        for k in 240..330u64 {
            let at = T0 + k * 60;
            assert!(t.count(FILTER, k + 1, ms(at), member(5, 4, true), 0, at));
            for log in t.due(at) {
                if let SeatLog::Ended { low_secs, .. } = log {
                    ends.push(low_secs);
                    ended_at.push(k);
                }
            }
        }
        assert_eq!(ends, [(241 - 62) * MINUTE], "low until it first cleared");
        assert_eq!(ended_at, [241 + LOW_END_HOLD / MINUTE], "after the hold");
    }

    /// Count a frame a minute with `signers` signing it, as the observer does.
    fn frame_signed_by(t: &mut SeatCertificates, k: u64, signers: &[u32]) {
        let at = T0 + k * 60;
        let signed = signers.contains(&0);
        assert!(t.count(FILTER, k + 1, ms(at), member(5, 4, signed), 0, at));
        t.tally(FILTER, ms(at), at, 5, 4, signers);
    }

    #[test]
    fn voters_and_rank_come_from_the_signers_of_the_last_hour() {
        let mut t = seated(T0);
        // Member 0 (this seat) signs 28 of 60 frames; members 1 and 2 sign
        // all; member 3 never: three voters, this seat last among them.
        for k in 0..60 {
            frame_signed_by(&mut t, k, if k < 28 { &[0, 1, 2] } else { &[1, 2] });
        }
        let seat = &t.seats[FILTER];
        assert_eq!(seat.voters(T0 + 3_600), Some(Voters { voters: 3, rank: 3 }));
        // Under LOW_MIN_FRAMES frames of the session: no voters.
        let mut few = seated(T0);
        for k in 0..LOW_MIN_FRAMES - 1 {
            frame_signed_by(&mut few, k, &[0, 1, 2]);
        }
        assert_eq!(few.seats[FILTER].voters(T0 + 3_600), None);
    }

    #[test]
    fn a_seat_is_judged_against_quorum_over_voters() {
        let window = |frames, signed| CertificateWindow {
            window_seconds: HOUR,
            observed_seconds: HOUR,
            frames,
            signed_frames: signed,
        };
        // 4 members, quorum 3, 3 voting: a seat voting in time signs all
        // of them; 19 of 40 is under half, though over half of 3/4.
        assert_eq!(low_share_of(&window(40, 19), 3, 3), Some(true));
        assert_eq!(low_share(&window(40, 19), 4, 3), Some(false));
        let mut t = seated(T0);
        for k in 0..60 {
            frame_signed_by(&mut t, k, if k < 28 { &[0, 1, 2] } else { &[1, 2] });
        }
        let logs = t.due(T0 + 3_600);
        let [SeatLog::Low {
            voters,
            low_secs,
            repeat,
            ..
        }, SeatLog::Summary { .. }] = logs.as_slice()
        else {
            panic!("expected a low share and a summary: {logs:?}");
        };
        assert_eq!(*voters, Some(Voters { voters: 3, rank: 3 }));
        assert_eq!((*low_secs, *repeat), (0, false));
        // The same counts without per-member signers fall back to the
        // committee: 28 of 60 is over half of 3/4.
        let mut bare = seated(T0);
        frame_a_minute(&mut bare, 0..28, true);
        frame_a_minute(&mut bare, 28..60, false);
        assert_eq!(kinds(&bare.due(T0 + 3_600)), ["summary 28/60"]);
    }

    fn header(frame: u64, signature: &[u8]) -> Header<'_> {
        Header {
            filter: FILTER,
            frame,
            timestamp_ms: ms(T0),
            signature,
            anchor: 0,
        }
    }

    #[test]
    fn a_global_frame_header_counts_by_its_real_certificate() {
        use quil_types::crypto::Signer as _;
        let signers: Vec<_> = (0..4)
            .map(|_| quil_crypto::FalconSigner::generate())
            .collect();
        let mut members: Vec<Vec<u8>> = signers.iter().map(|s| s.public_key().to_vec()).collect();
        members.sort();
        let session = quil_cw_consensus::handoff::Session {
            chain_id: [1; 32],
            filter: FILTER.to_vec(),
            generation: 5,
            genesis: [0; 32],
            base_frame: 0,
            authorization: [2; 32],
            members,
        };
        let certificate =
            quil_engine::test_support::certify_proposal(&session, &signers, 3, 0, [9; 32]);
        let signature = quil_cw_consensus::app_cert::wrap_cert_for_header(&certificate);
        let mut t = seated(T0);
        assert!(t.observe(header(1, &signature), T0));
        assert!(!t.observe(header(1, &signature), T0));
        assert!(
            !t.observe(header(2, &certificate), T0),
            "no certificate magic"
        );
        assert!(!t.observe(header(3, b"CWCT"), T0));
        t.membership(FILTER, 5, Some(1), 3);
        assert!(
            !t.observe(header(4, &signature), T0),
            "a committee other than the session's"
        );
        t.membership(FILTER, 5, Some(3), 4);
        let anchored = Header {
            anchor: 3 * epoch_length() + 7,
            ..header(5, &signature)
        };
        assert!(t.observe(anchored, T0));
        assert_eq!(hour(&t, T0), (2, 2));
        // The frame is filed under the epoch of its anchor.
        let counts = t.seats[FILTER].epochs.get(&3).copied();
        assert_eq!(counts.map(|c| (c.frames, c.signed)), Some((1, 1)));
        let mut other = SeatCertificates::default();
        other.seats(&[(FILTER.to_vec(), 6)], T0);
        other.membership(FILTER, 6, Some(0), 4);
        assert!(
            !other.observe(header(1, &signature), T0),
            "a generation this node holds no membership in"
        );
    }

    fn epoch_length() -> u64 {
        quil_types::consensus::epoch_length_frames()
    }

    fn slot(epoch: u64, sealed: bool, frames: u64, held: u64, outcome: Outcome) -> SlotRead {
        SlotRead {
            epoch,
            sealed,
            frames,
            expected: frames * storage_seat::PROPOSAL / 4,
            held: held.into(),
            release_at_most: held.into(),
            outcome,
        }
    }

    fn rewards(logs: &[SeatLog]) -> Vec<(u64, &'static str, EpochCount)> {
        logs.iter()
            .map(|log| match log {
                SeatLog::Reward {
                    epoch,
                    stage,
                    counts,
                    ..
                } => (*epoch, *stage, *counts),
                other => panic!("not a reward line: {other:?}"),
            })
            .collect()
    }

    #[test]
    fn tips_count_by_the_epoch_of_their_anchor_and_weigh_one_over_the_committee() {
        let l = epoch_length();
        let mut t = seated(T0);
        let now = T0 + 600;
        // Epoch 5: one signed tip and one not; epoch 6: one signed.
        assert!(t.count(FILTER, 1, ms(T0 + 10), member(5, 4, true), 5 * l + 1, now));
        assert!(t.count(FILTER, 2, ms(T0 + 20), member(5, 4, false), 5 * l + 2, now));
        assert!(t.count(FILTER, 3, ms(T0 + 30), member(5, 4, true), 6 * l, now));
        t.observe_global(7 * l);
        let slots = [
            slot(5, true, 1, 100, Outcome::Open),
            slot(6, true, 1, 100, Outcome::Open),
        ];
        let logs = rewards(&t.rewards(FILTER, &slots, now));
        let one = EpochCount {
            frames: 2,
            signed: 1,
            weight: storage_seat::PROPOSAL / 4,
        };
        assert_eq!(logs[0], (5, "ended", one));
        assert_eq!(
            logs[1],
            (
                6,
                "ended",
                EpochCount {
                    frames: 1,
                    signed: 1,
                    weight: one.weight
                }
            )
        );
    }

    #[test]
    fn each_epoch_logs_when_it_ended_and_when_its_settlement_closed_once() {
        let l = epoch_length();
        let mut t = seated(T0);
        assert!(t.rewards_due(T0).is_empty(), "no GLOBAL frame observed yet");
        t.observe_global(7 * l);
        assert_eq!(t.rewards_due(T0), vec![FILTER.to_vec()]);
        assert!(t.rewards_due(T0 + READ_EVERY - 1).is_empty(), "read lately");
        let open = [
            slot(5, true, 3, 100, Outcome::Open),
            slot(6, true, 3, 100, Outcome::Open),
        ];
        assert_eq!(t.rewards(FILTER, &open, T0).len(), 2);
        assert!(t.rewards(FILTER, &open, T0).is_empty(), "ended lines once");
        let settled = [
            slot(5, true, 3, 100, Outcome::Settled(7 * l)),
            slot(6, true, 3, 100, Outcome::Open),
        ];
        let logs = t.rewards(FILTER, &settled, T0);
        assert_eq!(
            rewards(&logs)
                .iter()
                .map(|l| (l.0, l.1))
                .collect::<Vec<_>>(),
            [(5, "closed")]
        );
        assert!(
            t.rewards(FILTER, &settled, T0).is_empty(),
            "closed lines once"
        );
        assert_eq!(
            t.rewards_due(T0 + READ_EVERY),
            vec![FILTER.to_vec()],
            "epoch 6 is open"
        );
        let closed = [
            slot(5, true, 3, 100, Outcome::Settled(7 * l)),
            slot(6, true, 3, 100, Outcome::Expired(7 * l)),
        ];
        assert_eq!(t.rewards(FILTER, &closed, T0).len(), 1);
        assert!(
            t.rewards_due(T0 + 2 * READ_EVERY).is_empty(),
            "nothing left to log"
        );
        // A closed epoch seen at once logs one line, not two.
        let mut late = seated(T0);
        late.observe_global(7 * l);
        let logs = late.rewards(FILTER, &closed, T0);
        assert_eq!(rewards(&logs).len(), 2);
        assert!(late.rewards(FILTER, &open, T0).is_empty());
        // The next epoch moves the window on.
        t.observe_global(8 * l);
        assert_eq!(t.rewards_due(T0 + 3 * READ_EVERY), vec![FILTER.to_vec()]);
    }

    #[test]
    fn an_epoch_without_a_slot_or_anything_counted_logs_nothing_and_is_done() {
        let l = epoch_length();
        let mut t = seated(T0);
        t.observe_global(7 * l);
        // Epoch 5 has no slot (two old: done), epoch 6 none yet (may sync).
        assert!(t.rewards(FILTER, &[], T0).is_empty());
        assert_eq!(
            t.seats[FILTER].rewards_logged.get(&5),
            Some(&(ENDED | CLOSED))
        );
        assert_eq!(t.seats[FILTER].rewards_logged.get(&6), None);
        // An unsealed registration with no tips and no roots is nothing.
        let bare = [slot(6, false, 0, 0, Outcome::Open)];
        assert!(t.rewards(FILTER, &bare, T0).is_empty());
        // The same slot with tips counted is an at-once seat and logs.
        assert!(t.count(FILTER, 1, ms(T0), member(5, 4, true), 6 * l + 1, T0));
        let logs = rewards(&t.rewards(FILTER, &[], T0));
        assert!(logs.is_empty(), "epoch 6 is done as bare");
        let mut fresh = seated(T0);
        fresh.observe_global(7 * l);
        assert!(fresh.count(FILTER, 1, ms(T0), member(5, 4, true), 6 * l + 1, T0));
        let logs = rewards(&fresh.rewards(FILTER, &bare, T0));
        assert_eq!(logs.len(), 1);
        assert_eq!((logs[0].0, logs[0].2.signed), (6, 1));
    }

    #[test]
    fn a_seat_without_a_slot_gets_one_line_once_no_slot_can_sync_in() {
        let l = epoch_length();
        let mut t = seated(T0);
        // Counted since before epoch 5 began.
        t.observe_global(5 * l - 1);
        assert!(t.count(FILTER, 1, ms(T0), member(5, 4, true), 5 * l + 1, T0));
        assert!(t.count(FILTER, 2, ms(T0 + 1), member(5, 4, false), 5 * l + 2, T0));
        t.observe_global(6 * l);
        assert!(
            t.rewards(FILTER, &[], T0).is_empty(),
            "epoch 5 just ended: a slot may still sync in"
        );
        t.observe_global(7 * l);
        let tips = EpochCount {
            frames: 2,
            signed: 1,
            weight: storage_seat::PROPOSAL / 4,
        };
        assert_eq!(
            rewards(&t.rewards(FILTER, &[], T0)),
            [(5, "ended", tips)],
            "a seat paid at once gets its epoch line"
        );
        assert!(t.rewards(FILTER, &[], T0).is_empty(), "once");
        // Held through epoch 6 with no tip seen: a line with nothing counted.
        t.observe_global(8 * l);
        assert_eq!(
            rewards(&t.rewards(FILTER, &[], T0)),
            [(6, "ended", EpochCount::default())],
            "a seat held through an epoch gets its line without tips"
        );
    }

    #[test]
    fn a_former_seat_still_gets_the_lines_of_epochs_it_was_held_in() {
        let l = epoch_length();
        let mut t = seated(T0);
        t.observe_global(5 * l - 1);
        assert!(t.count(FILTER, 1, ms(T0), member(5, 4, true), 5 * l + 1, T0));
        t.observe_global(7 * l);
        // The seat leaves; its buckets keep it tracked for a day.
        assert!(t.seats(&[], T0).is_empty());
        assert!(!t.seats[FILTER].current);
        assert_eq!(
            t.rewards_due(T0),
            vec![FILTER.to_vec()],
            "a former seat held in epoch 5"
        );
        assert_eq!(
            rewards(&t.rewards(FILTER, &[], T0))
                .iter()
                .map(|r| (r.0, r.2.signed))
                .collect::<Vec<_>>(),
            [(5, 1)]
        );
        // Epoch 6: no tips and no longer a seat: not held, done bare.
        t.observe_global(8 * l);
        assert!(t.rewards(FILTER, &[], T0).is_empty());
        assert_eq!(
            t.seats[FILTER].rewards_logged.get(&6),
            Some(&(ENDED | CLOSED))
        );
    }

    #[test]
    fn the_reward_line_names_how_global_pays_the_seat() {
        use quil_types::consensus::{
            set_hash_storage_proof_epoch_for_thread, set_unsealed_issuance_epoch_for_thread,
        };
        set_hash_storage_proof_epoch_for_thread(Some(4));
        set_unsealed_issuance_epoch_for_thread(Some(6));
        assert_eq!(kind(3, false), "at_once", "before the hash-proof epochs");
        assert_eq!(
            kind(5, false),
            "fees_only",
            "unsealed before unsealed issuance"
        );
        assert_eq!(kind(6, false), "at_once", "unsealed from unsealed issuance");
        assert_eq!(kind(6, true), "held");
        let l = epoch_length();
        let mut t = seated(T0);
        t.observe_global(5 * l - 1);
        assert!(t.count(FILTER, 1, ms(T0), member(5, 4, true), 5 * l + 1, T0));
        assert!(t.count(FILTER, 2, ms(T0), member(5, 4, true), 6 * l + 1, T0));
        let sealed = [slot(7, true, 1, 9, Outcome::Open)];
        let mut lines = Vec::new();
        for global in [7 * l, 8 * l] {
            t.observe_global(global);
            for log in t.rewards(FILTER, &sealed, T0) {
                match log {
                    SeatLog::Reward {
                        epoch, kind, slot, ..
                    } => lines.push((epoch, kind, slot.is_some())),
                    other => panic!("not a reward line: {other:?}"),
                }
            }
        }
        set_hash_storage_proof_epoch_for_thread(None);
        set_unsealed_issuance_epoch_for_thread(None);
        assert_eq!(
            lines,
            [
                (5, "fees_only", false),
                (6, "at_once", false),
                (7, "held", true)
            ]
        );
    }

    #[test]
    fn counting_that_began_inside_an_epoch_is_marked_incomplete() {
        let l = epoch_length();
        let mut t = seated(T0);
        t.observe_global(6 * l + 10);
        t.observe_global(7 * l);
        let slots = [
            slot(5, true, 1, 1, Outcome::Open),
            slot(6, true, 1, 1, Outcome::Open),
        ];
        let complete: Vec<bool> = t
            .rewards(FILTER, &slots, T0)
            .iter()
            .map(|log| match log {
                SeatLog::Reward { complete, .. } => *complete,
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(
            complete,
            [false, false],
            "first seen at 6L+10, inside epoch 6"
        );
        let mut early = seated(T0);
        early.observe_global(5 * l + 10);
        early.observe_global(7 * l);
        let complete: Vec<bool> = early
            .rewards(FILTER, &slots, T0)
            .iter()
            .map(|log| match log {
                SeatLog::Reward { complete, .. } => *complete,
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(
            complete,
            [false, true],
            "first seen inside epoch 5, before epoch 6 began"
        );
    }

    #[test]
    fn a_slot_reads_its_held_rewards_and_the_most_settling_pays() {
        let slot = SeatSlot {
            epoch: 5,
            leaves: vec![vec![0]],
            sealed_at: Some(1),
            frames: 10,
            expected: 20 * storage_seat::PROPOSAL,
            pending: vec![0x03, 0xE8],
            ..Default::default()
        };
        let read = SlotRead::of(&slot);
        assert_eq!(read.held, 1000.into());
        assert_eq!(
            read.release_at_most,
            500.into(),
            "10 roots of 20 proposals expected"
        );
        assert!(read.sealed);
        let all = SeatSlot { frames: 20, ..slot };
        assert_eq!(SlotRead::of(&all).release_at_most, 1000.into());
    }

    #[test]
    fn the_balance_line_comes_hourly_with_credits_and_debits_apart() {
        let mut t = seated(T0);
        assert!(
            t.credits_due(T0).is_none(),
            "the hour starts at the first look"
        );
        t.credited(250, T0 + 10);
        t.credited(-30, T0 + 20);
        t.credited(100, T0 + 30);
        assert!(t.credits_due(T0 + LOG_EVERY - 1).is_none());
        match t.credits_due(T0 + LOG_EVERY) {
            Some(SeatLog::Credits {
                window_secs,
                credited,
                debited,
                changes,
                seats,
            }) => assert_eq!(
                (window_secs, credited, debited, changes, seats),
                (LOG_EVERY, 350, 30, 3, 1)
            ),
            other => panic!("{other:?}"),
        }
        assert!(t.credits_due(T0 + LOG_EVERY + 1).is_none(), "once an hour");
        assert!(
            SeatCertificates::default().credits_due(T0).is_none(),
            "no seat"
        );
    }
}
