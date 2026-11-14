//! What restarting the node now costs one seat, from data the node holds:
//! the seat's running storage snapshot encode (`crate::storage_snapshot`)
//! and its committee's spare voters (`WorkerExecution.committee_*`). One
//! verdict per seat serves the worker view (`WorkerExecution.restart`) and
//! the pipeline and long-leaf log lines.
//!
//! Left out because this node cannot read their state with certainty: a
//! renewal that has not landed (landing is GLOBAL's record, shown by the
//! allocation's epoch) and an owed settlement (`settlements_sent` is in
//! memory and whether GLOBAL took the proof is not readable here).

use quil_types::proto::node::{RestartReadiness, WorkerExecution};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

/// A committee reading older than this says nothing: consensus refreshes it
/// each minute.
const COMMITTEE_STALE_MS: u64 = 180_000;

/// What the master's prover tree sync, registry load and first GLOBAL frame
/// take after a start: 46-67 s measured on eight restarts (2026-11-02..04).
const RESTART_SYNC: Duration = Duration::from_secs(90);

/// A seat's running snapshot encode ([`crate::storage_snapshot::seat_encode`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EncodeState {
    /// Every running leaf keeps its labelled layers on disk.
    pub labels_kept: bool,
    /// Layers labelled of the least advanced leaf, and the total.
    pub layers_done: usize,
    pub layers: usize,
    /// What the longest leaf still has to run by its estimate.
    pub remaining: Duration,
    /// The work a restart loses: at most one layer where labels are kept,
    /// else everything the leaf did.
    pub lost: Duration,
    /// The time to the renewal's grace frame; none before any GLOBAL frame.
    pub to_grace: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Ok,
    Unknown,
    CostsShare,
    StopsShard,
}

impl Verdict {
    pub fn name(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Unknown => "unknown",
            Self::CostsShare => "costs_share",
            Self::StopsShard => "stops_shard",
        }
    }

    /// The sentence the log lines carry.
    pub fn text(self) -> &'static str {
        match self {
            Self::Ok => "restart ok",
            Self::Unknown => "restart cost unknown: no GLOBAL frame seen yet",
            Self::CostsShare => "restart costs this seat's storage share this epoch",
            Self::StopsShard => "restart stops this seat's shard",
        }
    }
}

/// The seats whose snapshot encode this node noted under way and saved
/// (`crate::provers::renewal_storage`), with the epoch each registers: a
/// restarted node asks for those encodes again at its registry load
/// (`crate::prover_pipeline::ProverPipeline::request_noted_snapshots`).
static SAVED_ENCODES: Mutex<Option<HashMap<Vec<u8>, u64>>> = Mutex::new(None);

/// Note the saved encoding notes, `seats` with the epoch each registers.
pub(crate) fn note_saved_encodes(seats: HashMap<Vec<u8>, u64>) {
    *SAVED_ENCODES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(seats);
}

/// Whether a node restarted at GLOBAL `frame` asks for `filter`'s encode
/// again at its registry load: its note is saved for the epoch whose
/// snapshots a start then requests
/// (`crate::provers::lifecycle::noted_encode_epoch`).
fn resumes_at_load(filter: &[u8], frame: Option<u64>) -> bool {
    let Some(epoch) = frame.and_then(crate::provers::lifecycle::noted_encode_epoch) else {
        return false;
    };
    SAVED_ENCODES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(|seats| seats.get(filter))
        == Some(&epoch)
}

/// How long a restarted node takes before it asks for the seat's encode
/// again: the sync, which a seat whose encode is asked for at the registry
/// load (`resumed_at_load`, [`resumes_at_load`]) waits alone; any other
/// waits for its renewal, after the settle hold of a seat whose worker is
/// not yet hosting (`crate::provers::session_hosting::settle_frames`).
fn startup(frame: Option<u64>, resumed_at_load: bool) -> Duration {
    if resumed_at_load {
        return RESTART_SYNC;
    }
    let frames = crate::provers::session_hosting::settle_frames(
        quil_types::consensus::epoch_length_frames(),
    );
    let frame_ms = frame.map_or_else(
        quil_types::consensus::ideal_frame_time_ms,
        quil_types::consensus::ideal_frame_time_ms_at,
    );
    Duration::from_millis(frames.saturating_mul(frame_ms)) + RESTART_SYNC
}

/// The verdict from a seat's `encode` and its committee `margin`, and the
/// time a restart adds to the encode, asked for again at the registry load
/// when `resumed_at_load`. A committee with no spare voter stops with the
/// member whatever the encode; else a restart costs the share when the
/// encode, delayed by the work lost and the start-up, would end past the
/// grace frame.
pub(crate) fn assess(
    encode: Option<EncodeState>,
    margin: Option<i64>,
    frame: Option<u64>,
    resumed_at_load: bool,
) -> (Verdict, Duration) {
    let restart = encode.map_or(Duration::ZERO, |e| e.lost + startup(frame, resumed_at_load));
    let verdict = if margin.is_some_and(|m| m <= 0) {
        Verdict::StopsShard
    } else if let Some(e) = encode {
        match e.to_grace {
            None => Verdict::Unknown,
            Some(left) if e.remaining + restart > left => Verdict::CostsShare,
            Some(_) => Verdict::Ok,
        }
    } else {
        Verdict::Ok
    };
    (verdict, restart)
}

fn minutes(d: Duration) -> u32 {
    u32::try_from(d.as_secs().div_ceil(60)).unwrap_or(u32::MAX)
}

/// The readiness of the seat on `filter`, whose committee has `margin`.
pub fn seat_readiness(filter: &[u8], margin: Option<i64>) -> RestartReadiness {
    shards_readiness(&[filter.to_vec()], margin).0
}

/// The readiness of a seat encoding `shards` (its filter and the shards a
/// change creates from it), and its verdict.
pub fn shards_readiness(shards: &[Vec<u8>], margin: Option<i64>) -> (RestartReadiness, Verdict) {
    let encode = crate::storage_snapshot::seat_encode(shards);
    let frame = crate::storage_snapshot::global_frame();
    let resumed = shards
        .first()
        .is_some_and(|seat| resumes_at_load(seat, frame));
    let (verdict, restart) = assess(encode, margin, frame, resumed);
    let to_u32 = |n: u64| u32::try_from(n).unwrap_or(u32::MAX);
    let readiness = RestartReadiness {
        verdict: verdict.name().into(),
        encoding: encode.is_some(),
        labels_kept: encode.is_some_and(|e| e.labels_kept),
        layers_done: encode.map_or(0, |e| to_u32(e.layers_done as u64)),
        layers: encode.map_or(0, |e| to_u32(e.layers as u64)),
        restart_cost_minutes: minutes(restart),
        minutes_to_grace: encode
            .and_then(|e| e.to_grace)
            .map_or(0, |d| to_u32(d.as_secs() / 60)),
        committee_margin: margin.map(|m| i32::try_from(m).unwrap_or(i32::MAX)),
    };
    (readiness, verdict)
}

/// Voters minus quorum of the committee `execution` reports, if its worker
/// hosts the session as a member and the reading is fresh at `now_ms`.
pub fn margin_of(execution: &WorkerExecution, now_ms: u64) -> Option<i64> {
    let fresh = now_ms.saturating_sub(execution.committee_observed_unix_ms) <= COMMITTEE_STALE_MS;
    (execution.committee_members > 0 && execution.own_votes.is_some() && fresh)
        .then(|| i64::from(execution.committee_voters) - i64::from(execution.committee_quorum))
}

/// Each seat's latest committee margin, noted where the master reads the
/// workers' reports, for the log lines.
static COMMITTEES: Mutex<Option<HashMap<Vec<u8>, i64>>> = Mutex::new(None);

/// Note the committee margin `execution` reports for `filter`; a seat with no
/// fresh reading drops its note.
pub fn note_committee(filter: &[u8], execution: &WorkerExecution, now_ms: u64) {
    let mut committees = COMMITTEES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let committees = committees.get_or_insert_with(HashMap::new);
    match margin_of(execution, now_ms) {
        Some(margin) => {
            committees.insert(filter.to_vec(), margin);
        }
        None => {
            committees.remove(filter);
        }
    }
}

/// The margin last noted for `filter`.
pub fn noted_margin(filter: &[u8]) -> Option<i64> {
    COMMITTEES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(|committees| committees.get(filter).copied())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(kept: bool, remaining: u64, lost: u64, grace: Option<u64>) -> EncodeState {
        EncodeState {
            labels_kept: kept,
            layers_done: 4,
            layers: 11,
            remaining: Duration::from_secs(remaining * 60),
            lost: Duration::from_secs(lost * 60),
            to_grace: grace.map(|m| Duration::from_secs(m * 60)),
        }
    }

    fn verdict(encode: Option<EncodeState>, margin: Option<i64>) -> Verdict {
        assess(encode, margin, Some(1), false).0
    }

    #[test]
    fn nothing_running_and_slack_is_ok() {
        assert_eq!(verdict(None, None), Verdict::Ok);
        assert_eq!(verdict(None, Some(1)), Verdict::Ok);
    }

    #[test]
    fn an_encode_that_still_ends_by_grace_is_ok() {
        // Start-up is the settle hold plus the sync, about 12 minutes.
        let state = encode(true, 10, 7, Some(60));
        assert_eq!(verdict(Some(state), Some(3)), Verdict::Ok);
    }

    #[test]
    fn a_restart_that_pushes_the_encode_past_grace_costs_the_share() {
        let state = encode(true, 10, 7, Some(25));
        let (verdict, restart) = assess(Some(state), Some(3), Some(1), false);
        assert_eq!(verdict, Verdict::CostsShare);
        assert!(restart > Duration::from_secs(7 * 60), "{restart:?}");
    }

    /// A seat whose encode a restarted node asks for again at its registry
    /// load waits only the sync, not the settle hold: a restart that costs
    /// another seat its share is ok for it.
    #[test]
    fn a_seat_whose_encode_resumes_at_load_costs_only_the_sync() {
        let state = encode(true, 10, 7, Some(25));
        assert_eq!(
            assess(Some(state), Some(3), Some(1), false).0,
            Verdict::CostsShare
        );
        assert_eq!(
            assess(Some(state), Some(3), Some(1), true),
            (Verdict::Ok, Duration::from_secs(7 * 60) + RESTART_SYNC),
            "restart_cost_counts_the_settle_hold"
        );
    }

    /// Only a seat whose encoding note is saved, for the epoch a start at
    /// the frame requests, is asked for again at the registry load; a note
    /// held in memory only, an encoded seat, a frame outside the snapshot
    /// window and no GLOBAL frame are not.
    #[test]
    fn only_a_saved_encoding_note_in_its_window_resumes_at_load() {
        use crate::provers::renewal_storage::RenewalStorageNotes;
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(0));
        let epoch = 2;
        let snapshot = quil_types::consensus::storage_snapshot_frame(epoch);
        let grace = snapshot + quil_types::consensus::storage_snapshot_grace();
        let [encoding, encoded, unsaved] = [0xC1u8, 0xC2, 0xC3].map(|b| vec![b; 32]);
        let saved = RenewalStorageNotes::default();
        saved.attach(
            std::sync::Arc::new(quil_store::RocksDb::open_in_memory().unwrap()),
            &[7; 32],
        );
        saved.note(
            epoch,
            std::slice::from_ref(&encoded),
            std::slice::from_ref(&encoding),
        );
        RenewalStorageNotes::default().note(epoch, &[], std::slice::from_ref(&unsaved));
        assert!(
            !resumes_at_load(&unsaved, Some(snapshot + 5)),
            "unsaved_note_resumes: a note held in memory is lost with the process"
        );
        assert!(
            resumes_at_load(&encoding, Some(snapshot + 5)),
            "restart_cost_counts_the_settle_hold"
        );
        assert!(!resumes_at_load(&encoded, Some(snapshot + 5)));
        for frame in [Some(snapshot - 1), Some(grace), None] {
            assert!(!resumes_at_load(&encoding, frame), "{frame:?}");
        }
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }

    #[test]
    fn labels_not_kept_lose_more_than_kept() {
        let kept = verdict(Some(encode(true, 5, 7, Some(40))), None);
        let redone = verdict(Some(encode(false, 5, 38, Some(40))), None);
        assert_eq!((kept, redone), (Verdict::Ok, Verdict::CostsShare));
    }

    #[test]
    fn no_spare_voter_stops_the_shard_whatever_the_encode() {
        for margin in [0, -2] {
            assert_eq!(verdict(None, Some(margin)), Verdict::StopsShard);
            let state = encode(true, 10, 7, Some(25));
            assert_eq!(verdict(Some(state), Some(margin)), Verdict::StopsShard);
        }
        assert_eq!(verdict(None, Some(1)), Verdict::Ok);
    }

    #[test]
    fn an_encode_with_no_grace_time_is_unknown() {
        assert_eq!(
            verdict(Some(encode(true, 1, 1, None)), Some(2)),
            Verdict::Unknown
        );
    }

    #[test]
    fn a_committee_reading_counts_only_fresh_and_hosted() {
        let execution = WorkerExecution {
            committee_members: 28,
            committee_quorum: 19,
            committee_voters: 19,
            committee_observed_unix_ms: 1_000_000,
            own_votes: Some(3),
            ..Default::default()
        };
        assert_eq!(margin_of(&execution, 1_060_000), Some(0));
        assert_eq!(
            margin_of(&execution, 1_000_000 + COMMITTEE_STALE_MS + 1),
            None
        );
        let no_host = WorkerExecution {
            own_votes: None,
            ..execution.clone()
        };
        assert_eq!(margin_of(&no_host, 1_060_000), None);
        assert_eq!(margin_of(&WorkerExecution::default(), 0), None);
    }

    #[test]
    fn a_noted_committee_reaches_the_log_lines_and_clears() {
        let execution = WorkerExecution {
            committee_members: 10,
            committee_quorum: 7,
            committee_voters: 9,
            committee_observed_unix_ms: 5,
            own_votes: Some(1),
            ..Default::default()
        };
        let filter = b"restart-readiness-note".to_vec();
        note_committee(&filter, &execution, 10);
        assert_eq!(noted_margin(&filter), Some(2));
        note_committee(&filter, &WorkerExecution::default(), 10);
        assert_eq!(noted_margin(&filter), None);
    }
}
