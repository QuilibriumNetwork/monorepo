//! Shard frames anchored past this node's executed GLOBAL state.
//!
//! A shard frame names the GLOBAL frame it is anchored to, and its
//! certificate verifies against the session GLOBAL authorized for its
//! generation. A node verifies it against executed GLOBAL state, which trails
//! the stored head while execution catches up, and may not yet hold a session
//! that a GLOBAL frame up to the anchor authorized. On mainnet (2026-10-25) an
//! archive 510 frames behind refused 6173 shard-frame submits and 9870
//! ingested frames on 83 shards as "generation has no authorization", and its
//! gap fetch fetched them again and again. Such a frame now waits until
//! execution reaches its anchor and is verified again then; one still
//! unauthorized at that point is refused.
//!
//! The refusal comes before any signature check, so a forged header can claim
//! it. A frame waits only when it names the shard's next generation (the only
//! one GLOBAL frames not yet executed can authorize), within per-shard and
//! overall caps, and only when this node or a peer it knows as an active
//! prover delivered it: past the per-shard cap a higher frame takes the
//! lowest one's place, so a forged header from any sender could otherwise
//! push the shard's real frames out. A frame from any other sender is refused
//! retryably; the members' own submissions carry it. Anything else is refused
//! as before.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quil_types::error::QuilError;
use tracing::info;

use crate::message_collector::{Provenance, ShardFrameVerdict};

/// Whether a shard frame anchored to GLOBAL frame `anchor`, refused with
/// `error` by verification against GLOBAL state executed through `executed`,
/// may wait for execution: executed state holds no session for its
/// generation, and a GLOBAL frame up to `anchor` may still authorize one.
pub fn awaits_execution(error: &QuilError, anchor: u64, executed: u64) -> bool {
    anchor > executed
        && quil_execution::global_intrinsic::handoff::frames::unauthorized_generation(error)
}

/// The session generation a shard frame's certificate (`signature`, the
/// header's signature field) names, read without verifying it.
pub fn claimed_generation(signature: &[u8]) -> Option<u64> {
    let certificate = quil_cw_consensus::app_cert::unwrap_cert_from_header(signature)?;
    quil_cw_consensus::app_cert::unverified_finalization_epoch(certificate)
}

/// The generation executed GLOBAL state would authorize next for `filter`:
/// one above its head session's, or 1 without one. Generations are
/// sequential per filter, so a lower one without a session never gets one and
/// a higher one needs this one first. `None` when it cannot be read.
pub fn next_generation(
    global: &Arc<quil_hypergraph::HypergraphCrdt>,
    filter: &[u8],
) -> Option<u64> {
    let view = crate::app_handoff::committed_view(global).ok()??;
    let head = quil_execution::global_intrinsic::handoff::head(&view, filter).ok()?;
    head.map_or(Some(1), |session| session.generation.checked_add(1))
}

/// A shard frame a bundle carries, as its header claims it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardClaim {
    pub address: Vec<u8>,
    pub frame: u64,
    pub anchor: u64,
    pub generation: Option<u64>,
}

/// Every shard frame header a canonical `MessageBundle` carries.
pub fn bundle_shard_claims(data: &[u8]) -> Vec<ShardClaim> {
    use quil_execution::global_intrinsic::frame_header::{FrameHeader, TYPE_FRAME_HEADER};
    use quil_execution::message_envelope::CanonicalMessageBundle;
    let Ok(bundle) = CanonicalMessageBundle::from_canonical_bytes(data) else {
        return Vec::new();
    };
    bundle
        .requests
        .into_iter()
        .flatten()
        .filter(|request| request.inner_type_prefix == TYPE_FRAME_HEADER)
        .filter_map(|request| FrameHeader::from_canonical_bytes(&request.inner_bytes).ok())
        .filter(|header| !header.address.is_empty())
        .map(|header| ShardClaim {
            generation: claimed_generation(&header.public_key_signature_bls48581),
            address: header.address,
            frame: header.frame_number,
            anchor: header.global_frame_number,
        })
        .collect()
}

/// Frames of one shard (by frame number; every member's copy of a frame is
/// one) the message collector admits unverified while they wait for
/// execution. The leader takes one proof per shard, the highest, so past the
/// cap a higher frame takes the lowest one's place and a lower one is
/// refused, retryably.
pub const MAX_HELD_PER_SHARD: usize = 8;

/// Shards with frames the message collector holds while they wait.
pub const MAX_HELD_SHARDS: usize = 4096;

/// Admission of the message collector's frames that wait for GLOBAL
/// execution: per shard, the frame numbers admitted and their anchors,
/// bounded by [`MAX_HELD_PER_SHARD`] and [`MAX_HELD_SHARDS`], forgotten once
/// execution reaches their anchors, and the operator lines on them. The caps
/// bound what is admitted, not what is held: a forgotten frame's copies stay
/// in the collector's rank buffers, whose per-rank limits and retention bound
/// that memory.
pub struct CollectorDeferrals {
    log: DeferralLog,
    held: Mutex<HashMap<Vec<u8>, BTreeMap<u64, u64>>>,
}

impl Default for CollectorDeferrals {
    fn default() -> Self {
        Self {
            log: DeferralLog::new("message collector"),
            held: Mutex::new(HashMap::new()),
        }
    }
}

impl CollectorDeferrals {
    /// [`Self::verdict_from`] for a bundle from a sender this node does not
    /// know as a prover ([`Provenance::Other`]).
    pub fn verdict(
        &self,
        error: &QuilError,
        bundle: &[u8],
        executed: Option<u64>,
        verified_for: u64,
        next_generation: impl Fn(&[u8]) -> Option<u64>,
    ) -> ShardFrameVerdict {
        self.verdict_from(
            error,
            bundle,
            executed,
            verified_for,
            Provenance::Other,
            next_generation,
        )
    }

    /// The verdict on a bundle `provenance` delivered, whose verification,
    /// for a GLOBAL frame no later than `verified_for`, against GLOBAL state
    /// executed through `executed`, failed with `error`.
    /// [`ShardFrameVerdict::Unavailable`] (held unverified) when every frame
    /// it carries is anchored past `executed` and at most at `verified_for`,
    /// names its shard's `next_generation` and was refused as unauthorized
    /// ([`awaits_execution`]), and a [`Provenance::Prover`] delivered it;
    /// [`ShardFrameVerdict::Full`] (refused, retryably) when such a frame came
    /// from any other sender or does not fit the caps; otherwise invalid.
    pub fn verdict_from(
        &self,
        error: &QuilError,
        bundle: &[u8],
        executed: Option<u64>,
        verified_for: u64,
        provenance: Provenance,
        next_generation: impl Fn(&[u8]) -> Option<u64>,
    ) -> ShardFrameVerdict {
        let invalid = || ShardFrameVerdict::Invalid(error.to_string());
        let Some(executed) = executed else {
            return invalid();
        };
        let claims = bundle_shard_claims(bundle);
        let waits = !claims.is_empty()
            && claims.iter().all(|claim| {
                claim.anchor <= verified_for
                    && awaits_execution(error, claim.anchor, executed)
                    && claim.generation.is_some()
                    && claim.generation == next_generation(&claim.address)
            });
        if !waits {
            return invalid();
        }
        // Its certificate cannot be checked before execution reaches its
        // anchor, and past the cap it would take a held frame's place.
        if provenance != Provenance::Prover {
            return ShardFrameVerdict::Full(format!(
                "{error}; frames waiting for GLOBAL execution are held only from active provers"
            ));
        }
        let shards = {
            let mut held = self.held.lock().unwrap_or_else(|p| p.into_inner());
            forget_reached(&mut held, executed);
            // Admit into copies of the touched shards, written back only if
            // every claim fits.
            let mut touched: HashMap<Vec<u8>, BTreeMap<u64, u64>> = HashMap::new();
            for claim in &claims {
                let frames = touched
                    .entry(claim.address.clone())
                    .or_insert_with(|| held.get(&claim.address).cloned().unwrap_or_default());
                if let Some(anchor) = frames.get_mut(&claim.frame) {
                    *anchor = (*anchor).max(claim.anchor);
                    continue;
                }
                if frames.len() >= MAX_HELD_PER_SHARD {
                    match frames.first_key_value() {
                        Some((&lowest, _)) if lowest < claim.frame => {
                            frames.remove(&lowest);
                        }
                        _ => {
                            return ShardFrameVerdict::Full(format!(
                                "{error}; {MAX_HELD_PER_SHARD} higher frames of its shard wait for GLOBAL execution"
                            ));
                        }
                    }
                }
                frames.insert(claim.frame, claim.anchor);
            }
            let new_shards = touched
                .keys()
                .filter(|address| !held.contains_key(*address))
                .count();
            if held.len() + new_shards > MAX_HELD_SHARDS {
                return ShardFrameVerdict::Full(format!(
                    "{error}; {MAX_HELD_SHARDS} shards have frames waiting for GLOBAL execution"
                ));
            }
            held.extend(touched);
            held.len()
        };
        for claim in &claims {
            self.log.deferred(
                &claim.address,
                claim.frame,
                claim.anchor,
                executed,
                Some(shards),
            );
        }
        ShardFrameVerdict::Unavailable(format!(
            "{error}; anchored past executed GLOBAL frame {executed}, verified again once execution reaches it"
        ))
    }

    /// Whether frames wait, so a caller reads the executed frame only then.
    pub fn waiting(&self) -> bool {
        self.log.waiting()
    }

    /// GLOBAL execution reached `executed`: forget the frames it passed, and
    /// log the end of the wait once it passed every anchor. Call periodically.
    pub fn executed(&self, executed: u64) {
        forget_reached(
            &mut self.held.lock().unwrap_or_else(|p| p.into_inner()),
            executed,
        );
        self.log.executed(executed);
    }
}

/// Forget admitted frames execution reached; their copies stay in the rank
/// buffers until finalized or aged out.
fn forget_reached(held: &mut HashMap<Vec<u8>, BTreeMap<u64, u64>>, executed: u64) {
    held.retain(|_, frames| {
        frames.retain(|_, anchor| *anchor > executed);
        !frames.is_empty()
    });
}

/// Least time between two lines saying frames still wait.
pub const DEFERRAL_REPORT_INTERVAL: Duration = Duration::from_secs(600);

/// What [`DeferralLog`] logged. `shards` is the caller's count of shards with
/// waiting frames, when it keeps one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeferralEvent {
    /// The first frame of a wait.
    Started {
        frame: u64,
        anchor: u64,
        executed: u64,
    },
    /// Frames still wait, at most once per [`DEFERRAL_REPORT_INTERVAL`].
    Waiting {
        frames: u64,
        shards: Option<usize>,
        highest_anchor: u64,
        executed: u64,
        waited_secs: u64,
    },
    /// Execution reached every anchor waited for.
    Ended {
        frames: u64,
        executed: u64,
        waited_secs: u64,
    },
}

struct Wait {
    since: Instant,
    reported: Instant,
    frames: u64,
    highest_anchor: u64,
}

/// One operator line when shard frames start to wait for GLOBAL execution
/// (`path` names who holds them), one per [`DEFERRAL_REPORT_INTERVAL`] while
/// more arrive, and one when execution has reached every anchor waited for.
/// `frames` counts the deferrals reported: ingest reports each frame once, the
/// collector each copy it holds.
pub struct DeferralLog {
    path: &'static str,
    wait: Mutex<Option<Wait>>,
}

impl DeferralLog {
    pub const fn new(path: &'static str) -> Self {
        Self {
            path,
            wait: Mutex::new(None),
        }
    }

    /// Frame `frame` of shard `address` waits for execution, at `executed`,
    /// to reach `anchor`; `shards` have waiting frames.
    pub fn deferred(
        &self,
        address: &[u8],
        frame: u64,
        anchor: u64,
        executed: u64,
        shards: Option<usize>,
    ) {
        let event = self.deferred_at(Instant::now(), frame, anchor, executed, shards);
        self.log(address, event);
    }

    /// Whether frames wait.
    pub fn waiting(&self) -> bool {
        self.wait
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some()
    }

    /// GLOBAL execution reached `executed`.
    pub fn executed(&self, executed: u64) {
        let event = self.executed_at(Instant::now(), executed);
        self.log(&[], event);
    }

    fn deferred_at(
        &self,
        now: Instant,
        frame: u64,
        anchor: u64,
        executed: u64,
        shards: Option<usize>,
    ) -> Option<DeferralEvent> {
        let mut guard = self.wait.lock().unwrap_or_else(|p| p.into_inner());
        match guard.as_mut() {
            None => {
                *guard = Some(Wait {
                    since: now,
                    reported: now,
                    frames: 1,
                    highest_anchor: anchor,
                });
                Some(DeferralEvent::Started {
                    frame,
                    anchor,
                    executed,
                })
            }
            Some(wait) => {
                wait.frames += 1;
                wait.highest_anchor = wait.highest_anchor.max(anchor);
                if now.saturating_duration_since(wait.reported) < DEFERRAL_REPORT_INTERVAL {
                    return None;
                }
                wait.reported = now;
                Some(DeferralEvent::Waiting {
                    frames: wait.frames,
                    shards,
                    highest_anchor: wait.highest_anchor,
                    executed,
                    waited_secs: now.saturating_duration_since(wait.since).as_secs(),
                })
            }
        }
    }

    fn executed_at(&self, now: Instant, executed: u64) -> Option<DeferralEvent> {
        let mut guard = self.wait.lock().unwrap_or_else(|p| p.into_inner());
        if guard
            .as_ref()
            .is_none_or(|wait| executed < wait.highest_anchor)
        {
            return None;
        }
        let ended = guard.take()?;
        Some(DeferralEvent::Ended {
            frames: ended.frames,
            executed,
            waited_secs: now.saturating_duration_since(ended.since).as_secs(),
        })
    }

    fn log(&self, address: &[u8], event: Option<DeferralEvent>) {
        let path = self.path;
        match event {
            None => {}
            Some(DeferralEvent::Started { frame, anchor, executed }) => info!(
                path,
                shard = %hex::encode(address),
                frame,
                anchor,
                executed,
                lag = anchor.saturating_sub(executed),
                reason = "generation has no authorization in executed GLOBAL state",
                "shard frames anchored past executed GLOBAL state wait for execution to reach their anchor, \
                 then are verified again: this node's GLOBAL execution trails its head, an expected wait \
                 that ends as it catches up"
            ),
            Some(DeferralEvent::Waiting { frames, shards, highest_anchor, executed, waited_secs }) => info!(
                path,
                frames,
                shards = shards.map_or_else(|| "untracked".to_string(), |s| s.to_string()),
                highest_anchor,
                executed,
                lag = highest_anchor.saturating_sub(executed),
                waited_secs,
                "shard frames still wait for GLOBAL execution to reach their anchors"
            ),
            Some(DeferralEvent::Ended { frames, executed, waited_secs }) => info!(
                path,
                frames,
                executed,
                waited_secs,
                "GLOBAL execution reached the anchors shard frames waited for; they are verified again \
                 as they arrive or are asked for"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message_collector::{MessageCollector, Refusal, SubmitOutcome};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    fn unauthorized() -> QuilError {
        QuilError::InvalidSignature(
            "app session certificate: generation has no authorization".into(),
        )
    }

    /// A certificate-shaped signature field naming `generation` (only its
    /// unauthenticated proposal prefix).
    pub(crate) fn certificate(generation: u64) -> Vec<u8> {
        use quil_cw_consensus::_codec::Encode as _;
        use quil_cw_consensus::_consensus::{
            simplex::types::Proposal,
            types::{Epoch, Round, View},
        };
        let proposal = Proposal::new(
            Round::new(Epoch::new(generation), View::new(5)),
            View::new(0),
            quil_cw_consensus::_crypto::sha256::Digest([0; 32]),
        );
        quil_cw_consensus::app_cert::wrap_cert_for_header(&proposal.encode().to_vec())
    }

    /// A bundle carrying frame `frame` of shard `addr`, anchored to GLOBAL
    /// frame `anchor`, whose certificate names `generation`; `copy` stands
    /// for another member's certificate.
    fn bundle(addr: u8, frame: u64, anchor: u64, generation: u64, copy: u64) -> Vec<u8> {
        use quil_execution::global_intrinsic::frame_header::{FrameHeader, TYPE_FRAME_HEADER};
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        let header = FrameHeader {
            address: vec![addr; 32],
            frame_number: frame,
            rank: copy,
            global_frame_number: anchor,
            public_key_signature_bls48581: certificate(generation),
            ..Default::default()
        };
        let request = CanonicalMessageRequest {
            inner_type_prefix: TYPE_FRAME_HEADER,
            inner_bytes: header.to_canonical_bytes().unwrap(),
        };
        CanonicalMessageBundle {
            requests: vec![Some(request)],
            timestamp: copy as i64,
        }
        .to_canonical_bytes()
        .unwrap()
    }

    #[test]
    fn only_an_unauthorized_generation_anchored_past_execution_waits() {
        assert!(awaits_execution(&unauthorized(), 100, 99));
        assert!(
            !awaits_execution(&unauthorized(), 99, 99),
            "execution reached the anchor"
        );
        let forged = QuilError::InvalidSignature(
            "app session certificate: generation 3: below quorum".into(),
        );
        assert!(
            !awaits_execution(&forged, 100, 99),
            "the session refused it"
        );
        assert!(!awaits_execution(
            &QuilError::InvalidSignature("generation has no authorization".into()),
            100,
            99
        ));
        assert_eq!(claimed_generation(&certificate(7)), Some(7));
        assert_eq!(claimed_generation(b"not a certificate"), None);
    }

    /// The collector holds a frame anchored past executed GLOBAL state
    /// unverified instead of refusing it; once execution passes its anchor and
    /// authorizes its generation, a copy verifies and supersedes it. Refused:
    /// a frame still unauthorized once execution reached its anchor, one
    /// anchored past the frame it is verified for, one naming any generation
    /// but its shard's next, and one past the shard's cap.
    #[test]
    fn the_collector_holds_a_frame_anchored_past_execution_until_execution_reaches_it() {
        let executed = Arc::new(AtomicU64::new(98));
        let authorized = Arc::new(AtomicBool::new(false));
        let deferrals = Arc::new(CollectorDeferrals::default());
        let collector = MessageCollector::new();
        collector.set_shard_frame_verifier_with_provenance({
            let (executed, authorized, deferrals) =
                (executed.clone(), authorized.clone(), deferrals.clone());
            Arc::new(move |data: &[u8], provenance: Provenance| {
                let address = crate::message_collector::extract_shard_frame_keys(data)[0]
                    .0
                    .clone();
                if authorized.load(Ordering::SeqCst) && address == vec![0x11; 32] {
                    return ShardFrameVerdict::Valid;
                }
                // Every shard's head session is generation 1.
                deferrals.verdict_from(
                    &unauthorized(),
                    data,
                    Some(executed.load(Ordering::SeqCst)),
                    100,
                    provenance,
                    |_| Some(2),
                )
            })
        });
        let refused = SubmitOutcome::Filtered(Refusal::InvalidShardFrame);

        let first = bundle(0x11, 5, 99, 2, 0);
        assert_eq!(
            collector.add_message_outcome(1, first.clone()),
            SubmitOutcome::Accepted
        );
        assert!(!collector.is_verified(&first), "held unverified");
        assert!(deferrals.waiting());
        assert_eq!(
            collector.add_message_outcome(1, bundle(0x22, 3, 101, 2, 0)),
            refused,
            "anchored past the frame it is verified for"
        );
        assert_eq!(
            collector.add_message_outcome(1, bundle(0x22, 3, 99, 9, 0)),
            refused,
            "a generation GLOBAL frames not yet executed cannot authorize"
        );
        // Members' copies of one frame take one place: the next frame of the
        // shard is still admitted.
        for copy in 0..MAX_HELD_PER_SHARD as u64 {
            assert_eq!(
                collector.add_message_outcome(1, bundle(0x44, 7, 99, 2, copy)),
                SubmitOutcome::Accepted
            );
        }
        assert_eq!(
            collector.add_message_outcome(1, bundle(0x44, 8, 99, 2, 0)),
            SubmitOutcome::Accepted
        );
        // Past the cap a higher frame takes the lowest one's place, and a
        // lower one is refused retryably.
        for frame in 9..15 {
            assert_eq!(
                collector.add_message_outcome(1, bundle(0x44, frame, 99, 2, 0)),
                SubmitOutcome::Accepted
            );
        }
        assert_eq!(
            collector.add_message_outcome(1, bundle(0x44, 15, 99, 2, 0)),
            SubmitOutcome::Accepted
        );
        assert_eq!(
            deferrals.held.lock().unwrap()[&vec![0x44; 32]]
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            (8..=15).collect::<Vec<_>>(),
            "the highest frames are admitted"
        );
        let full = collector.add_message_outcome(1, bundle(0x44, 6, 99, 2, 0));
        assert_eq!(full, SubmitOutcome::Filtered(Refusal::AwaitingExecution));
        assert!(Refusal::AwaitingExecution.retryable());
        // A sender not known as a prover holds nothing, and so displaces
        // nothing, however high its frame.
        assert_eq!(
            collector.add_message_outcome_from(1, bundle(0x44, 1_000, 99, 2, 0), Provenance::Other),
            SubmitOutcome::Filtered(Refusal::AwaitingExecution)
        );
        assert_eq!(
            collector.add_message_outcome_from(1, bundle(0x55, 3, 99, 2, 0), Provenance::Other),
            SubmitOutcome::Filtered(Refusal::AwaitingExecution)
        );
        assert_eq!(
            deferrals.held.lock().unwrap()[&vec![0x44; 32]]
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            (8..=15).collect::<Vec<_>>(),
            "an unknown sender's frame displaced a held one"
        );
        assert!(!deferrals.held.lock().unwrap().contains_key(&vec![0x55; 32]));

        // GLOBAL frame 99 executes and authorizes the first shard's session.
        executed.store(99, Ordering::SeqCst);
        authorized.store(true, Ordering::SeqCst);
        let copy = bundle(0x11, 5, 99, 2, 1);
        assert_eq!(
            collector.add_message_outcome(1, copy.clone()),
            SubmitOutcome::Accepted
        );
        assert!(collector.is_verified(&copy));
        assert_eq!(
            collector.add_message_outcome(1, bundle(0x33, 4, 99, 2, 0)),
            refused,
            "no session authorized once execution reached the anchor"
        );
        deferrals.executed(99);
        assert!(!deferrals.waiting());
        assert!(
            deferrals.held.lock().unwrap().is_empty(),
            "frames execution passed are forgotten"
        );
    }

    #[test]
    fn a_wait_is_logged_when_it_starts_at_most_once_an_interval_and_when_it_ends() {
        let log = DeferralLog::new("test");
        let start = Instant::now();
        assert_eq!(
            log.deferred_at(start, 5, 100, 90, None),
            Some(DeferralEvent::Started {
                frame: 5,
                anchor: 100,
                executed: 90
            })
        );
        assert_eq!(
            log.deferred_at(start + Duration::from_secs(1), 6, 104, 91, Some(2)),
            None
        );
        assert_eq!(
            log.deferred_at(start + DEFERRAL_REPORT_INTERVAL, 7, 102, 95, Some(2)),
            Some(DeferralEvent::Waiting {
                frames: 3,
                shards: Some(2),
                highest_anchor: 104,
                executed: 95,
                waited_secs: 600
            })
        );
        let end = start + DEFERRAL_REPORT_INTERVAL + Duration::from_secs(60);
        assert_eq!(
            log.executed_at(end, 103),
            None,
            "frames anchored at 104 still wait"
        );
        assert_eq!(
            log.executed_at(end, 104),
            Some(DeferralEvent::Ended {
                frames: 3,
                executed: 104,
                waited_secs: 660
            })
        );
        assert_eq!(log.executed_at(end, 105), None);
        assert!(!log.waiting());
    }

    /// A frame waiting for GLOBAL execution is held before its certificate
    /// can be checked, and past the per-shard cap a higher frame takes the
    /// lowest one's place: a sender that is not a known prover must not be
    /// able to push a shard's frames out with forged higher ones.
    #[test]
    fn reproduces_forged_waiting_frames_displacing_held_ones() {
        let deferrals = CollectorDeferrals::default();
        let verdict = |frame: u64| {
            deferrals.verdict(
                &unauthorized(),
                &bundle(0x66, frame, 99, 2, 0),
                Some(98),
                100,
                |_| Some(2),
            )
        };
        for frame in 5..5 + MAX_HELD_PER_SHARD as u64 {
            let _ = verdict(frame);
        }
        let forged = 1u64 << 40;
        for frame in forged..forged + MAX_HELD_PER_SHARD as u64 {
            let outcome = verdict(frame);
            assert!(
                !matches!(outcome, ShardFrameVerdict::Unavailable(_)),
                "forged frame {frame} from a sender not known as a prover was held unverified, \
                 displacing a held frame of its shard: {outcome:?}"
            );
        }
    }
}
