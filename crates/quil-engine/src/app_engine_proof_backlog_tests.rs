//! A backlog of slow confidential proofs on a regular node (mainnet,
//! 2026-10-31): batch shields verifying for about 240 s each arrived faster
//! than the node's admission queue verified them. A finalized frame waiting
//! on one gave up its background wait after 30 min and verified inline,
//! where the proof worker's slots, taken by the backlog, refused it within
//! its 1.5 s admission wait ("token proof worker: Busy"); the frame failed
//! and its retry waited 30 min again (shards stalled up to 3.6 h). These
//! tests use only the queue's and the deferral's interfaces of the release
//! base, so they show the failure there.
use super::*;
use crate::admission_verify::{AdmissionJob, AdmissionQueue};
use quil_execution::manager::PreverifyCounts;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

const SHIELD_BYTES: usize = 207_976;

fn submission(tag: u8, n: u8) -> [u8; 32] {
    let mut digest = [tag; 32];
    digest[1] = n;
    digest
}

fn verified() -> PreverifyCounts {
    PreverifyCounts {
        operations: 1,
        verified: 1,
        ..Default::default()
    }
}

/// A verification of `digest` that succeeds and records it in `log`.
fn recording(log: &Arc<Mutex<Vec<[u8; 32]>>>, digest: [u8; 32]) -> AdmissionJob {
    let log = log.clone();
    Arc::new(move || {
        log.lock().unwrap().push(digest);
        verified()
    })
}

/// Thirteen shards each finalize a frame carrying one batch shield this
/// node has not verified, behind twenty arrivals already queued; the queue
/// verifies one every 240 s, and each frame asks again on its 10 s retry
/// timer. Every frame waits for its own verdict and materializes once it is
/// cached; none leaves the wait to verify inline.
#[test]
fn a_proof_backlog_never_sends_a_finalized_frame_to_inline_verification() {
    const VERIFY_SECS: u64 = 240;
    const RETRY_SECS: u64 = 10;
    const SHARDS: u8 = 13;
    let queue = AdmissionQueue::new(256, 64 << 20, false);
    let log = Arc::new(Mutex::new(Vec::new()));
    for n in 0..20 {
        let arrival = submission(0xa0, n);
        assert!(queue.offer(arrival, SHIELD_BYTES, 1, recording(&log, arrival), false));
    }
    let mut deferrals = ProofDeferrals::default();
    let start = Instant::now();
    let mut waited: Vec<Option<u64>> = vec![None; usize::from(SHARDS)];
    let mut next_verdict = VERIFY_SECS;
    let mut now = 0u64;
    while waited.iter().any(Option::is_none) {
        assert!(
            now <= 24 * 3600,
            "frames still waiting after a day: {waited:?}"
        );
        if now >= next_verdict {
            queue.run_one();
            next_verdict += VERIFY_SECS;
        }
        for shard in 0..SHARDS {
            if waited[usize::from(shard)].is_some() {
                continue;
            }
            let frame = submission(0xf0, shard);
            let cached = log.lock().unwrap().contains(&frame);
            // As `defer_for_proof_verification` asks for each submission.
            let (verifying, restarted) = if cached {
                (true, false)
            } else {
                let restarted = !queue.pending(&frame);
                let offered = queue.offer(frame, SHIELD_BYTES, 1, recording(&log, frame), true);
                (offered || queue.pending(&frame), restarted)
            };
            let decision = deferrals.decide(
                &[shard],
                1,
                usize::from(!cached),
                verifying,
                restarted,
                start + Duration::from_secs(now),
            );
            match decision {
                Deferral::Proceed {
                    inline: None,
                    waited: time,
                } => waited[usize::from(shard)] = Some(time.map_or(0, |w| w.as_secs())),
                Deferral::Proceed {
                    inline: Some(reason),
                    waited: time,
                } => panic!(
                    "shard {shard}'s finalized frame left its background wait after {}s ({reason}) to \
                     verify inline, where this node's busy proof worker refuses it within its 1.5 s \
                     admission wait (\"token proof worker: Busy\"): the frame fails and its retry \
                     waits again from the start",
                    time.map_or(0, |w| w.as_secs())
                ),
                Deferral::Wait { .. } => {}
            }
        }
        now += RETRY_SECS;
    }
    let log = log.lock().unwrap().clone();
    let frames = log.iter().filter(|digest| digest[0] == 0xf0).count();
    assert_eq!(
        frames,
        usize::from(SHARDS),
        "each frame's submission verified once"
    );
    assert!(
        log[..usize::from(SHARDS)]
            .iter()
            .all(|digest| digest[0] == 0xf0),
        "the frames' submissions verified before the arrivals queued ahead of them: {log:?}"
    );
    let longest = waited.iter().flatten().copied().max().unwrap_or(0);
    assert!(
        longest <= u64::from(SHARDS) * VERIFY_SECS + RETRY_SECS,
        "the last frame waited {longest}s, more than the {SHARDS} verifications ahead of it"
    );
}

/// A frame's submission whose verification finds the worker's slots taken
/// (by inline and proposal verifications) stays queued, first, and is
/// retried until a slot frees.
#[test]
fn a_submission_a_frame_waits_on_outlasts_a_busy_proof_worker() {
    const BUSY: usize = 5;
    let queue = AdmissionQueue::new(8, 1 << 20, false);
    let log = Arc::new(Mutex::new(Vec::new()));
    let arrival = submission(0xa1, 0);
    let frame = submission(0xf1, 0);
    let busy_left = Arc::new(AtomicUsize::new(BUSY));
    let job: AdmissionJob = {
        let (log, busy_left) = (log.clone(), busy_left.clone());
        Arc::new(move || {
            log.lock().unwrap().push(frame);
            if busy_left.load(Ordering::SeqCst) > 0 {
                busy_left.fetch_sub(1, Ordering::SeqCst);
                PreverifyCounts {
                    operations: 1,
                    busy: 1,
                    ..Default::default()
                }
            } else {
                verified()
            }
        })
    };
    assert!(queue.offer(arrival, 10, 1, recording(&log, arrival), false));
    assert!(queue.offer(frame, 10, 1, job, true));
    for _ in 0..=BUSY {
        assert!(
            queue.pending(&frame),
            "the submission a frame waits on was given up after {} verifications found the proof worker \
             busy: the frame's retry queues it again and, past its restart bound, verifies it inline, \
             where it fails \"token proof worker: Busy\"",
            BUSY - busy_left.load(Ordering::SeqCst)
        );
        assert!(queue.run_one());
    }
    assert!(!queue.pending(&frame));
    let mut expected = vec![frame; BUSY + 1];
    while queue.run_one() {}
    expected.push(arrival);
    assert_eq!(
        *log.lock().unwrap(),
        expected,
        "the frame's submission was retried behind the arrival"
    );
}

/// Arrivals past the queue's bounds drop the oldest arrival, never a
/// submission a frame waits on.
#[test]
fn the_admission_bounds_never_drop_a_submission_a_frame_waits_on() {
    let queue = AdmissionQueue::new(2, 1 << 20, false);
    let log = Arc::new(Mutex::new(Vec::new()));
    let frame = submission(0xf2, 0);
    assert!(queue.offer(frame, 10, 1, recording(&log, frame), true));
    for n in 0..4 {
        let arrival = submission(0xa2, n);
        queue.offer(arrival, 10, 1, recording(&log, arrival), false);
    }
    assert!(
        queue.pending(&frame),
        "arrivals past the queue's bound dropped the submission a frame waits on: the frame's retry \
         queues it again and, past its restart bound, verifies it inline, where it fails \"token proof \
         worker: Busy\""
    );
    while queue.run_one() {}
    assert_eq!(log.lock().unwrap().first(), Some(&frame));
}

/// Frames waiting on the queue are served in the order they first asked,
/// however often each asks again on its retry timer.
#[test]
fn frames_waiting_on_the_admission_queue_are_served_in_the_order_they_asked() {
    let queue = AdmissionQueue::new(8, 1 << 20, false);
    let log = Arc::new(Mutex::new(Vec::new()));
    for _ in 0..2 {
        for shard in 0..4 {
            let frame = submission(0xf3, shard);
            queue.offer(frame, 10, 1, recording(&log, frame), true);
        }
    }
    while queue.run_one() {}
    let served: Vec<u8> = log.lock().unwrap().iter().map(|digest| digest[1]).collect();
    assert_eq!(
        served,
        vec![0, 1, 2, 3],
        "frames waiting on the queue were served last-asked first: the first frame to wait waited \
         behind every frame that asked after it"
    );
}
