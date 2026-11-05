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
//! over 24 hours. Logging state only; nothing here feeds consensus.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Mutex, OnceLock};

use quil_cw_consensus::app_cert::CertificateMember;
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
    /// The committee of the latest frame counted.
    committee: u32,
    last_frame: u64,
    summarized: u64,
    low: Option<Low>,
}

impl Seat {
    fn new(now: u64) -> Self {
        Self {
            since: now,
            current: true,
            memberships: VecDeque::new(),
            counted: BTreeSet::new(),
            buckets: VecDeque::new(),
            committee: 0,
            last_frame: 0,
            summarized: now,
            low: None,
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
        low_secs: u64,
        repeat: bool,
    },
    Ended {
        filter: Vec<u8>,
        share: CertificateShare,
        low_secs: u64,
        how: &'static str,
    },
}

/// Whether `window` shows a seat signing under half the certificates a
/// member voting in time signs (`quorum / committee`); `None` when it holds
/// too little to judge: under an hour counted, or under [`LOW_MIN_FRAMES`]
/// frames.
pub(crate) fn low_share(window: &CertificateWindow, committee: u32, quorum: u32) -> Option<bool> {
    if window.observed_seconds < window.window_seconds
        || window.frames < LOW_MIN_FRAMES
        || committee == 0
    {
        return None;
    }
    Some(
        u128::from(window.signed_frames) * 2 * u128::from(committee)
            < u128::from(window.frames) * u128::from(quorum),
    )
}

#[derive(Debug, Default)]
pub(crate) struct SeatCertificates {
    seats: BTreeMap<Vec<u8>, Seat>,
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
        let Some(member) = app_cert::unverified_member(certificate, index as usize) else {
            return false;
        };
        self.count(
            header.filter,
            header.frame,
            header.timestamp_ms,
            member,
            now,
        )
    }

    /// Count shard frame `frame` of `filter`, timestamped `timestamp_ms`,
    /// whose certificate says `member` of this node's index, at `now`.
    pub fn count(
        &mut self,
        filter: &[u8],
        frame: u64,
        timestamp_ms: i64,
        member: CertificateMember,
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
            let judged = if seat.current {
                low_share(&hour, share.committee, share.quorum)
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
            },
            now,
        );
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
            low_secs,
            repeat,
        } => {
            let hour = share.hour.as_ref().cloned().unwrap_or_default();
            tracing::warn!(filter = %hex::encode(filter), committee = share.committee,
                quorum = share.quorum,
                in_time_share_pct = percent(u64::from(share.quorum), u64::from(share.committee)),
                hour_frames = hour.frames, hour_signed = hour.signed_frames,
                hour_share_pct = percent(hour.signed_frames, hour.frames), low_secs, repeat,
                scope = "this node's seat",
                action = "check this seat's worker: blocked or behind its shard ('this worker is \
                          behind its shard', LocalMat in qclient node prover manage), silent \
                          ('this member's silence'), or voting late from CPU load or slow peer \
                          connections; frames it does not sign earn it nothing",
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
        assert!(t.count(FILTER, 10, ms(T0 + 100), member(5, 4, true), now));
        assert!(t.count(FILTER, 11, ms(T0 + 110), member(5, 4, false), now));
        assert!(t.count(FILTER, 12, ms(T0 + 170), member(5, 4, false), now));
        // The poller and the gossip deliver the same frame: it counts once.
        assert!(!t.count(FILTER, 11, ms(T0 + 110), member(5, 4, true), now));
        // A session this node holds no known membership in, a committee
        // other than the session's, or another shard: not counted.
        assert!(!t.count(FILTER, 13, ms(T0 + 200), member(6, 4, true), now));
        assert!(!t.count(FILTER, 14, ms(T0 + 200), member(5, 5, true), now));
        assert!(!t.count(&[8; 35], 15, ms(T0 + 200), member(5, 4, true), now));
        // A frame a day old is out of every window; one claiming a time
        // ahead of this clock, or none, counts now.
        assert!(!t.count(FILTER, 16, ms(now - DAY), member(5, 4, true), now));
        assert!(t.count(FILTER, 17, ms(now + 900), member(5, 4, true), now));
        assert!(t.count(FILTER, 18, 0, member(5, 4, false), now));
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
        assert!(t.count(FILTER, 1, ms(T0 + 30), member(5, 4, true), now));
        assert!(t.count(FILTER, 2, ms(now - 3_000), member(5, 4, false), now));
        assert!(t.count(FILTER, 3, ms(now - 60), member(5, 4, true), now));
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
        assert!(!t.count(FILTER, 1, ms(T0), member(5, 4, true), T0));
        assert!(t.snapshot(FILTER, T0).is_none());
        // The successor session seats this node.
        assert_eq!(
            t.seats(&[(FILTER.to_vec(), 6)], T0),
            vec![(FILTER.to_vec(), 6)]
        );
        t.membership(FILTER, 6, Some(2), 7);
        assert!(t.count(FILTER, 2, ms(T0), member(6, 7, false), T0));
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
            assert!(t.count(FILTER, frame, ms(now), member(5, 4, true), now));
        }
        assert_eq!(t.seats[FILTER].counted.len(), MAX_COUNTED);
        assert!(
            !t.count(FILTER, 50, ms(now), member(5, 4, true), now),
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
            })
            .collect()
    }

    fn frame_a_minute(t: &mut SeatCertificates, minutes: std::ops::Range<u64>, signed: bool) {
        for k in minutes {
            let at = T0 + k * 60;
            assert!(t.count(FILTER, k + 1, ms(at), member(5, 4, signed), at));
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
        for k in 0..240u64 {
            let at = T0 + k * 60;
            assert!(t.count(FILTER, k + 1, ms(at), member(5, 4, k % 8 < 3), at));
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
                    SeatLog::Low { low_secs, .. } => starts.push(low_secs),
                    SeatLog::Ended { low_secs, .. } => ends.push(low_secs),
                    SeatLog::Summary { .. } => {}
                }
            }
        }
        assert!(
            low > 20 && clear > 20,
            "the share must cross: {low} {clear}"
        );
        assert_eq!(starts, [0], "one start");
        assert_eq!(repeats.len(), 2, "a repeat per hour: {repeats:?}");
        assert!(repeats[0] >= LOG_EVERY && repeats[1] >= 2 * LOG_EVERY);
        assert!(ends.is_empty(), "no end while it crosses: {ends:?}");
        // The seat then signs every frame: one end, after the hold.
        for k in 240..330u64 {
            let at = T0 + k * 60;
            assert!(t.count(FILTER, k + 1, ms(at), member(5, 4, true), at));
            for log in t.due(at) {
                if let SeatLog::Ended { low_secs, .. } = log {
                    ends.push(low_secs);
                }
            }
        }
        assert_eq!(ends.len(), 1, "one end: {ends:?}");
        assert!(ends[0] >= 3 * HOUR && ends[0] < 3 * HOUR + 3_600);
    }

    fn header(frame: u64, signature: &[u8]) -> Header<'_> {
        Header {
            filter: FILTER,
            frame,
            timestamp_ms: ms(T0),
            signature,
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
        assert!(t.observe(header(5, &signature), T0));
        assert_eq!(hour(&t, T0), (2, 2));
        let mut other = SeatCertificates::default();
        other.seats(&[(FILTER.to_vec(), 6)], T0);
        other.membership(FILTER, 6, Some(0), 4);
        assert!(
            !other.observe(header(1, &signature), T0),
            "a generation this node holds no membership in"
        );
    }
}
