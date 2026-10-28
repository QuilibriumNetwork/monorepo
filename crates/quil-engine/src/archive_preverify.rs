//! Archive proof verification outside the ingest lock.
//!
//! An archive materializes every application frame a GLOBAL frame carries
//! while it holds its [`ArchiveAppShardIngest`], and materialization verifies
//! the frames' confidential token proofs first, in a worker child, at about
//! two minutes per batch shield. Gossip ingest, its retry pass and the gap
//! fetch's admission wait for that lock meanwhile, and the GLOBAL frame
//! executes only once every proof of its backlog has verified, one frame
//! after another.
//!
//! Verdicts are a pure function of the operation bytes and the network
//! policy, cached process-wide, so when they are computed changes nothing
//! that execution decides. This module computes them before the lock is
//! taken:
//!
//! * [`ProofPrewarm`]: frames are queued as they are admitted and their proofs
//!   verified on a background thread, so a GLOBAL frame that later carries
//!   their headers finds the verdicts cached;
//! * [`preverify_through`]: before the GLOBAL hook takes the ingest, the
//!   frames it is about to materialize are verified with the lock released.
//!
//! Every bound only moves work back to where it ran before: a verdict not
//! computed ahead is computed by the locked materialization.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use quil_execution::manager::{PreverifyCounts, PreverifyPacing};
use quil_types::proto::global::MessageBundle;
use tracing::{info, warn};

use crate::archive_ingest::ArchiveAppShardIngest;

/// Verifies `(application, canonical bundle)` pairs, filling the verdict cache
/// (`ExecutionEngineManager::preverify_bundles_paced` in a node).
pub type ProofVerifier =
    dyn Fn(&[(Vec<u8>, Vec<u8>)], &PreverifyPacing<'_>) -> PreverifyCounts + Send + Sync;

/// How often the background queues log what they did.
const SUMMARY_INTERVAL: Duration = Duration::from_secs(600);

/// GLOBAL hook passes running: the background pre-verification starts no new
/// proof while one runs, so the worker slots serve the frames GLOBAL waits on.
static SEQUENCED_PASSES: AtomicUsize = AtomicUsize::new(0);

/// A GLOBAL frame's materialization on this archive, from its proof
/// pre-verification through the locked pass; [`ProofPrewarm`] yields to it.
pub struct SequencedPass(());

impl SequencedPass {
    pub fn begin() -> Self {
        SEQUENCED_PASSES.fetch_add(1, Ordering::AcqRel);
        Self(())
    }
}

impl Drop for SequencedPass {
    fn drop(&mut self) {
        SEQUENCED_PASSES.fetch_sub(1, Ordering::AcqRel);
    }
}

fn sequenced_pass_running() -> bool {
    SEQUENCED_PASSES.load(Ordering::Acquire) > 0
}

/// `(application, canonical bytes)` of a frame's bundles, as materialization
/// hands them to the verifier. A bundle that does not encode is skipped here
/// and by materialization alike.
fn canonical_pairs(address: &[u8], requests: &[MessageBundle]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let application = address[..address.len().min(32)].to_vec();
    requests
        .iter()
        .filter_map(|bundle| crate::consensus_wire::app_bundle_to_canonical_bytes(bundle).ok())
        .map(|bytes| (application.clone(), bytes))
        .collect()
}

fn encoded_len(requests: &[MessageBundle]) -> usize {
    requests.iter().map(prost::Message::encoded_len).sum()
}

// ---------------------------------------------------------------------------
// Background pre-verification of admitted frames
// ---------------------------------------------------------------------------

/// Frames queued for background pre-verification. Past either bound the
/// oldest is dropped (counted): its proofs are then verified when GLOBAL
/// materializes it, as before.
pub const PREWARM_MAX_FRAMES: usize = 1024;
pub const PREWARM_MAX_BYTES: usize = 128 << 20;
/// How long the background thread waits after proofs found no worker slot.
const PREWARM_BUSY_PAUSE: Duration = Duration::from_secs(1);

/// Verifies the confidential proofs of admitted frames on one background
/// thread, oldest first, before a GLOBAL frame needs them. It uses the
/// worker's slots like any verification, starts no new proof while a GLOBAL
/// hook pass runs ([`SequencedPass`]), and never takes the ingest lock.
pub struct ProofPrewarm {
    shared: Arc<PrewarmShared>,
}

struct PrewarmShared {
    state: Mutex<PrewarmState>,
    wake: Condvar,
    verify: Arc<ProofVerifier>,
    max_frames: usize,
    max_bytes: usize,
}

#[derive(Default)]
struct PrewarmState {
    queue: VecDeque<PrewarmItem>,
    bytes: usize,
    started: bool,
    shutdown: bool,
    /// Since the last summary.
    window: PrewarmStats,
    /// Since start.
    total: PrewarmStats,
    summarized: Option<Instant>,
}

struct PrewarmItem {
    address: Vec<u8>,
    requests: Vec<MessageBundle>,
    bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrewarmStats {
    pub queued: usize,
    /// Frames queued again because proofs found no worker slot.
    pub requeued: usize,
    pub dropped: usize,
    pub frames: usize,
    pub counts: PreverifyCounts,
}

impl PrewarmStats {
    fn add(&mut self, other: PrewarmStats) {
        self.queued += other.queued;
        self.requeued += other.requeued;
        self.dropped += other.dropped;
        self.frames += other.frames;
        self.counts.add(other.counts);
    }
}

impl ProofPrewarm {
    pub fn new(verify: Arc<ProofVerifier>) -> Self {
        Self::with_bounds(verify, PREWARM_MAX_FRAMES, PREWARM_MAX_BYTES)
    }

    pub fn with_bounds(verify: Arc<ProofVerifier>, max_frames: usize, max_bytes: usize) -> Self {
        Self {
            shared: Arc::new(PrewarmShared {
                state: Mutex::new(PrewarmState::default()),
                wake: Condvar::new(),
                verify,
                max_frames: max_frames.max(1),
                max_bytes,
            }),
        }
    }

    /// Queue the bundles of frame `frame` of `address`, admitted above the
    /// cursor, without waiting. The thread starts with the first frame.
    pub fn offer(&self, address: &[u8], requests: &[MessageBundle]) {
        if requests.is_empty() {
            return;
        }
        let bytes = encoded_len(requests);
        let shared = &self.shared;
        let mut state = shared.lock();
        if state.shutdown {
            return;
        }
        state.queue.push_back(PrewarmItem {
            address: address.to_vec(),
            requests: requests.to_vec(),
            bytes,
        });
        state.bytes += bytes;
        state.window.queued += 1;
        while state.queue.len() > shared.max_frames || state.bytes > shared.max_bytes {
            let Some(dropped) = state.queue.pop_front() else {
                break;
            };
            state.bytes -= dropped.bytes;
            state.window.dropped += 1;
        }
        if !state.started {
            state.started = true;
            let thread_shared = shared.clone();
            let spawned = std::thread::Builder::new()
                .name("archive-proof-prewarm".into())
                .spawn(move || thread_shared.run());
            if let Err(error) = spawned {
                state.started = false;
                warn!(%error, "archive proof prewarm thread did not start; proofs verify when GLOBAL materializes their frames");
            }
        }
        drop(state);
        shared.wake.notify_one();
    }

    /// Queued frames and what was done since start (tests and summaries).
    pub fn stats(&self) -> (usize, PrewarmStats) {
        let state = self.shared.lock();
        let mut total = state.total;
        total.add(state.window);
        (state.queue.len(), total)
    }
}

impl Drop for ProofPrewarm {
    fn drop(&mut self) {
        self.shared.lock().shutdown = true;
        self.shared.wake.notify_all();
    }
}

impl PrewarmShared {
    fn lock(&self) -> std::sync::MutexGuard<'_, PrewarmState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn run(&self) {
        let pause: &(dyn Fn() -> bool + Sync) = &sequenced_pass_running;
        loop {
            let item = {
                let mut state = self.lock();
                loop {
                    if state.shutdown {
                        return;
                    }
                    Self::summarize(&mut state, self.max_frames);
                    if let Some(item) = state.queue.pop_front() {
                        state.bytes -= item.bytes;
                        break item;
                    }
                    state = match self.wake.wait_timeout(state, SUMMARY_INTERVAL) {
                        Ok((state, _)) => state,
                        Err(poisoned) => poisoned.into_inner().0,
                    };
                }
            };
            let pairs = canonical_pairs(&item.address, &item.requests);
            let counts = (*self.verify)(
                &pairs,
                &PreverifyPacing {
                    parallelism: None,
                    done: None,
                    pause: Some(pause),
                },
            );
            let mut state = self.lock();
            state.window.frames += 1;
            state.window.counts.add(counts);
            // Proofs that found no worker slot go to the back of the queue:
            // the next attempt finds the verdicts others computed meanwhile
            // cached, and the frame bound still applies.
            if counts.busy > 0 && !state.shutdown {
                state.window.requeued += 1;
                state.bytes += item.bytes;
                state.queue.push_back(item);
                while state.queue.len() > self.max_frames || state.bytes > self.max_bytes {
                    let Some(dropped) = state.queue.pop_front() else {
                        break;
                    };
                    state.bytes -= dropped.bytes;
                    state.window.dropped += 1;
                }
                drop(state);
                std::thread::sleep(PREWARM_BUSY_PAUSE);
            }
        }
    }

    /// One line per [`SUMMARY_INTERVAL`] while frames are queued or verified.
    fn summarize(state: &mut PrewarmState, max_frames: usize) {
        let now = Instant::now();
        let since = *state.summarized.get_or_insert(now);
        if now.duration_since(since) < SUMMARY_INTERVAL {
            return;
        }
        state.summarized = Some(now);
        let window = std::mem::take(&mut state.window);
        state.total.add(window);
        if window == PrewarmStats::default() && state.queue.is_empty() {
            return;
        }
        info!(
            scope = "this archive",
            queued = window.queued,
            frames = window.frames,
            operations = window.counts.operations,
            verified = window.counts.verified,
            cached = window.counts.cached,
            busy = window.counts.busy,
            failed = window.counts.unavailable,
            requeued = window.requeued,
            dropped = window.dropped,
            pending = state.queue.len(),
            max_frames,
            interval_secs = SUMMARY_INTERVAL.as_secs(),
            "archive proof prewarm summary: confidential proofs of admitted application frames verified ahead of GLOBAL; \
             dropped frames verify when GLOBAL materializes them"
        );
    }
}

// ---------------------------------------------------------------------------
// The GLOBAL hook's pre-verification
// ---------------------------------------------------------------------------

/// Application frames, and bytes of their bundles, read ahead per GLOBAL
/// frame. Frames beyond either verify under the lock, as before.
pub const PREPASS_MAX_FRAMES: usize = 1024;
pub const PREPASS_MAX_BYTES: usize = 128 << 20;
/// How long a pass retries operations that found no worker slot. Past it the
/// locked materialization verifies them, as before.
pub const PREPASS_BUSY_WINDOW: Duration = Duration::from_secs(300);
const PREPASS_BUSY_PAUSE: Duration = Duration::from_millis(500);
/// A pass longer than this is logged at info.
const PREPASS_NOTE: Duration = Duration::from_secs(5);
/// A pass longer than this warns, again every [`PREPASS_PROGRESS_INTERVAL`].
const PREPASS_WARN: Duration = Duration::from_secs(120);
const PREPASS_PROGRESS_INTERVAL: Duration = Duration::from_secs(60);

/// The bounds of [`preverify_through`].
#[derive(Clone, Copy, Debug)]
pub struct PrepassLimits {
    pub max_frames: usize,
    pub max_bytes: usize,
    pub busy_window: Duration,
    pub busy_pause: Duration,
}

impl Default for PrepassLimits {
    fn default() -> Self {
        Self {
            max_frames: PREPASS_MAX_FRAMES,
            max_bytes: PREPASS_MAX_BYTES,
            busy_window: PREPASS_BUSY_WINDOW,
            busy_pause: PREPASS_BUSY_PAUSE,
        }
    }
}

/// What [`preverify_through`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrepassReport {
    pub shards: usize,
    pub frames: usize,
    /// Frames left to the locked pass by [`PrepassLimits`].
    pub truncated: bool,
    pub rounds: usize,
    pub counts: PreverifyCounts,
}

/// A body the pass reads: held in memory, or stored above the cursor.
pub(crate) enum PlannedBody {
    Held(Vec<MessageBundle>),
    Stored(u64),
}

/// What a pass may still read: frames and bundle bytes.
pub(crate) struct PlanBudget {
    frames: usize,
    bytes: usize,
    pub(crate) truncated: bool,
}

impl PlanBudget {
    /// Take one frame of `bytes`; `false` (and truncated) past either bound.
    pub(crate) fn take(&mut self, bytes: usize) -> bool {
        if self.frames == 0 || bytes > self.bytes {
            self.truncated = true;
            return false;
        }
        self.frames -= 1;
        self.bytes -= bytes;
        true
    }

    /// Take `bytes` more for a frame already taken.
    fn take_bytes(&mut self, bytes: usize) -> bool {
        if bytes > self.bytes {
            self.truncated = true;
            return false;
        }
        self.bytes -= bytes;
        true
    }

    pub(crate) fn bundle_bytes(requests: &[MessageBundle]) -> usize {
        encoded_len(requests)
    }
}

/// Verify the confidential proofs of the frames the GLOBAL frame
/// `global_frame` is about to materialize (`targets`: per shard, the highest
/// frame it carries) without holding `ingest`, which is held only to look up
/// which bodies it holds. The locked materialization then finds their
/// verdicts cached; anything this leaves unverified it verifies itself.
pub fn preverify_through(
    ingest: &Mutex<ArchiveAppShardIngest>,
    global_frame: u64,
    targets: &[(Vec<u8>, u64)],
) -> PrepassReport {
    preverify_through_within(ingest, global_frame, targets, PrepassLimits::default())
}

pub fn preverify_through_within(
    ingest: &Mutex<ArchiveAppShardIngest>,
    global_frame: u64,
    targets: &[(Vec<u8>, u64)],
    limits: PrepassLimits,
) -> PrepassReport {
    let start = Instant::now();
    let mut report = PrepassReport::default();
    if targets.is_empty() {
        return report;
    }
    let mut budget = PlanBudget {
        frames: limits.max_frames,
        bytes: limits.max_bytes,
        truncated: false,
    };
    let (planned, verify, clock) = {
        let mut guard = ingest.lock().unwrap_or_else(|p| p.into_inner());
        let mut planned = Vec::new();
        for (address, through) in targets {
            let bodies = guard.plan_bodies(address, *through, &mut budget);
            if !bodies.is_empty() {
                planned.push((address.clone(), bodies));
            }
        }
        let (verify, clock) = guard.preverify_sources();
        (planned, verify, clock)
    };
    let mut pairs = Vec::new();
    'shards: for (address, bodies) in planned {
        let mut frames = 0;
        for body in bodies {
            let requests = match body {
                PlannedBody::Held(requests) => requests,
                PlannedBody::Stored(number) => {
                    match clock.get_shard_clock_frame(&address, number, false) {
                        Ok(frame) if budget.take_bytes(encoded_len(&frame.requests)) => {
                            frame.requests
                        }
                        Ok(_) => break 'shards,
                        Err(_) => continue,
                    }
                }
            };
            if requests.is_empty() {
                continue;
            }
            frames += 1;
            pairs.extend(canonical_pairs(&address, &requests));
        }
        if frames > 0 {
            report.shards += 1;
            report.frames += frames;
        }
    }
    report.truncated = budget.truncated;
    if pairs.is_empty() {
        return report;
    }
    let (shards, frames, bundles) = (report.shards, report.frames, pairs.len());
    let done = AtomicUsize::new(0);
    let finished = Mutex::new(false);
    let finished_signal = Condvar::new();
    std::thread::scope(|scope| {
        let progress = scope.spawn(|| {
            let mut warned: Option<Instant> = None;
            let mut finished_guard = finished.lock().unwrap_or_else(|p| p.into_inner());
            loop {
                if *finished_guard {
                    return;
                }
                let elapsed = start.elapsed();
                if elapsed >= PREPASS_WARN
                    && warned.is_none_or(|at| at.elapsed() >= PREPASS_PROGRESS_INTERVAL)
                {
                    warned = Some(Instant::now());
                    warn!(
                        scope = "this archive",
                        frame = global_frame,
                        shards,
                        frames,
                        bundles,
                        done = done.load(Ordering::Relaxed),
                        secs = elapsed.as_secs(),
                        action = "GLOBAL execution of this frame waits for these proofs; the archive ingest stays free; \
                                  it ends when they verify (raise proofWorker.maxConcurrent if CPU allows)",
                        "archive GLOBAL frame proof pre-verification still running"
                    );
                }
                finished_guard = match finished_signal.wait_timeout(finished_guard, Duration::from_secs(1)) {
                    Ok((guard, _)) => guard,
                    Err(poisoned) => poisoned.into_inner().0,
                };
            }
        });
        loop {
            report.rounds += 1;
            done.store(0, Ordering::Relaxed);
            let counts = (*verify)(
                &pairs,
                &PreverifyPacing {
                    parallelism: None,
                    done: Some(&done),
                    pause: None,
                },
            );
            if report.rounds == 1 {
                report.counts = counts;
            } else {
                // Later rounds find earlier verdicts cached; they add what
                // they verified and replace what is still outstanding.
                report.counts.verified += counts.verified;
                report.counts.busy = counts.busy;
                report.counts.unavailable = counts.unavailable;
            }
            if counts.busy == 0 || start.elapsed() >= limits.busy_window {
                break;
            }
            std::thread::sleep(limits.busy_pause);
        }
        *finished.lock().unwrap_or_else(|p| p.into_inner()) = true;
        finished_signal.notify_all();
        let _ = progress.join();
    });
    let elapsed = start.elapsed();
    if elapsed >= PREPASS_NOTE {
        let counts = report.counts;
        macro_rules! pass_line {
            ($level:ident) => {
                $level!(
                    scope = "this archive",
                    frame = global_frame,
                    shards = report.shards,
                    frames = report.frames,
                    operations = counts.operations,
                    cached = counts.cached,
                    verified = counts.verified,
                    busy = counts.busy,
                    failed = counts.unavailable,
                    rounds = report.rounds,
                    truncated = report.truncated,
                    secs = elapsed.as_secs_f64(),
                    "archive GLOBAL frame proof pre-verification: proofs verified before taking the ingest; \
                     busy or failed ones verify in the locked pass"
                )
            };
        }
        if elapsed >= PREPASS_WARN {
            pass_line!(warn);
        } else {
            pass_line!(info);
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(tag: u8) -> MessageBundle {
        MessageBundle {
            requests: Vec::new(),
            timestamp: tag as i64,
        }
    }

    fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A verifier that blocks until `gate` opens and counts its calls.
    fn gated_verifier(
        gate: Arc<(Mutex<bool>, Condvar)>,
        calls: Arc<AtomicUsize>,
    ) -> Arc<ProofVerifier> {
        Arc::new(
            move |pairs: &[(Vec<u8>, Vec<u8>)], _: &PreverifyPacing<'_>| {
                let (open, opened) = &*gate;
                let mut open = open.lock().unwrap();
                while !*open {
                    open = opened.wait(open).unwrap();
                }
                calls.fetch_add(1, Ordering::SeqCst);
                PreverifyCounts {
                    operations: pairs.len(),
                    verified: pairs.len(),
                    ..Default::default()
                }
            },
        )
    }

    /// Past its frame bound the queue drops its oldest frames, counted, and
    /// verifies the rest once the verifier is free again.
    #[test]
    fn the_prewarm_queue_drops_its_oldest_frames_past_its_bound_and_recovers() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let prewarm =
            ProofPrewarm::with_bounds(gated_verifier(gate.clone(), calls.clone()), 4, usize::MAX);
        // The first frame is taken and blocks the verifier.
        prewarm.offer(b"shard", &[bundle(0)]);
        wait_for("the first frame to be taken", || prewarm.stats().0 == 0);
        for tag in 1..=7 {
            prewarm.offer(b"shard", &[bundle(tag)]);
        }
        let (pending, stats) = prewarm.stats();
        assert_eq!((pending, stats.queued, stats.dropped), (4, 8, 3));
        // Frames without bundles are not queued.
        prewarm.offer(b"shard", &[]);
        assert_eq!(prewarm.stats().1.queued, 8);
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        wait_for("the queue to drain", || prewarm.stats().1.frames == 5);
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        assert_eq!(prewarm.stats().0, 0);
    }

    /// A frame larger than the byte bound is dropped; later frames verify.
    #[test]
    fn the_prewarm_queue_drops_frames_past_its_byte_bound() {
        let gate = Arc::new((Mutex::new(true), Condvar::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let small = encoded_len(&[bundle(1)]);
        let prewarm = ProofPrewarm::with_bounds(gated_verifier(gate, calls.clone()), 16, small);
        prewarm.offer(b"shard", &[bundle(1), bundle(2)]);
        assert_eq!(prewarm.stats().1.dropped, 1);
        prewarm.offer(b"shard", &[bundle(3)]);
        wait_for("the small frame", || calls.load(Ordering::SeqCst) == 1);
        assert_eq!(prewarm.stats().1.frames, 1);
    }

    /// Proofs that found no worker slot are tried again from the back of
    /// the queue until they verify.
    #[test]
    fn a_prewarmed_frame_whose_proofs_found_no_worker_slot_is_tried_again() {
        let calls = Arc::new(AtomicUsize::new(0));
        let verifier: Arc<ProofVerifier> = {
            let calls = calls.clone();
            Arc::new(
                move |pairs: &[(Vec<u8>, Vec<u8>)], _: &PreverifyPacing<'_>| {
                    let busy = calls.fetch_add(1, Ordering::SeqCst) == 0;
                    PreverifyCounts {
                        operations: pairs.len(),
                        verified: if busy { 0 } else { pairs.len() },
                        busy: if busy { pairs.len() } else { 0 },
                        ..Default::default()
                    }
                },
            )
        };
        let prewarm = ProofPrewarm::new(verifier);
        prewarm.offer(b"shard", &[bundle(1)]);
        wait_for("the second attempt", || prewarm.stats().1.frames == 2);
        let (pending, stats) = prewarm.stats();
        assert_eq!((pending, stats.requeued, stats.counts.verified), (0, 1, 1));
        std::thread::sleep(PREWARM_BUSY_PAUSE * 2);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "verified once it found a slot"
        );
    }
}
