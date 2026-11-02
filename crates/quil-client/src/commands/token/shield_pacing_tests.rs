use super::*;

/// GLOBAL at one frame per 10 s that stands still on `[from, to)`.
fn frames_with_stall(from: u64, to: u64) -> impl Fn(u64) -> u64 {
    move |t| {
        1_000
            + if t < from {
                t / 10
            } else if t < to {
                from / 10
            } else {
                from / 10 + (t - to) / 10
            }
    }
}

const START: u64 = 1_000_000;
const NEVER: (u64, u64) = (u64::MAX - 1, u64::MAX);

/// A fake clock and fake reads: sleeping and proving only advance time.
struct Fake {
    now: u64,
    frames: Box<dyn Fn(u64) -> u64>,
    /// Seconds after submission at which a batch reads included, or never.
    inclusion: Box<dyn Fn(usize) -> Option<u64>>,
    proves: Vec<(usize, u64)>,
    submits: Vec<(usize, u64)>,
    events: Vec<ShieldEvent>,
}

impl Fake {
    fn new(
        frames: impl Fn(u64) -> u64 + 'static,
        inclusion: impl Fn(usize) -> Option<u64> + 'static,
    ) -> Self {
        Self {
            now: START,
            frames: Box::new(frames),
            inclusion: Box::new(inclusion),
            proves: Vec::new(),
            submits: Vec::new(),
            events: Vec::new(),
        }
    }

    fn healthy(inclusion: impl Fn(usize) -> Option<u64> + 'static) -> Self {
        Self::new(frames_with_stall(NEVER.0, NEVER.1), inclusion)
    }

    fn gaps(&self) -> Vec<u64> {
        self.submits.windows(2).map(|w| w[1].1 - w[0].1).collect()
    }

    fn position(&self, wanted: fn(&ShieldEvent) -> bool) -> Option<usize> {
        self.events.iter().position(wanted)
    }
}

impl ShieldIo for Fake {
    type Proof = usize;
    fn now(&self) -> u64 {
        self.now
    }
    fn unix(&self) -> u64 {
        1_700_000_000 + self.now
    }
    async fn sleep(&mut self, secs: u64) {
        self.now += secs;
    }
    async fn head(&mut self) -> anyhow::Result<u64> {
        Ok((self.frames)(self.now))
    }
    fn coins(&self, _index: usize) -> usize {
        96
    }
    fn shard(&self, index: usize) -> String {
        format!("...feedbeef{index:02x}")
    }
    async fn prove(&mut self, index: usize) -> anyhow::Result<Option<usize>> {
        self.proves.push((index, self.now));
        self.now += 150;
        Ok(Some(index))
    }
    async fn submit(&mut self, index: usize, _proof: usize) -> anyhow::Result<()> {
        self.submits.push((index, self.now));
        Ok(())
    }
    async fn included(&mut self, index: usize) -> anyhow::Result<bool> {
        let sent = self.submits.iter().find(|(i, _)| *i == index).unwrap().1;
        Ok((self.inclusion)(index).is_some_and(|after| self.now >= sent + after))
    }
    fn event(&mut self, event: &ShieldEvent) {
        self.events.push(event.clone());
    }
}

fn pacing(min_interval: u64) -> Pacing {
    Pacing {
        min_interval,
        inclusion_timeout: DEFAULT_INCLUSION_TIMEOUT_SECS,
    }
}

/// The next batch is proved only after the previous one is included.
#[tokio::test]
async fn shield_pacing_proves_the_next_batch_after_inclusion() {
    let mut io = Fake::healthy(|_| Some(400));
    assert_eq!(run(&mut io, 3, pacing(0)).await.unwrap(), 3);
    for i in 1..3 {
        let included = io.submits[i - 1].1 + 400;
        assert!(
            io.proves[i].1 >= included,
            "batch {i} was proved at {} before batch {} was included at {included}",
            io.proves[i].1,
            i - 1,
        );
    }
    let included = io
        .events
        .iter()
        .filter(|e| matches!(e, ShieldEvent::Included { .. }))
        .count();
    assert_eq!(included, 3);
    assert!(matches!(
        io.events.last(),
        Some(ShieldEvent::Progress {
            done: 3,
            total: 3,
            ..
        })
    ));
}

/// Submissions are exactly the minimum interval apart when proving and
/// inclusion are faster; with interval 0 (devnets) only they space batches.
#[tokio::test]
async fn shield_pacing_keeps_the_minimum_interval_between_submissions() {
    let mut io = Fake::healthy(|_| Some(30));
    run(&mut io, 4, pacing(300)).await.unwrap();
    assert_eq!(io.gaps(), vec![300, 300, 300], "{:?}", io.submits);
    assert!(io
        .events
        .iter()
        .any(|e| matches!(e, ShieldEvent::WaitingInterval { .. })));

    let mut io = Fake::healthy(|_| Some(30));
    run(&mut io, 3, pacing(0)).await.unwrap();
    assert!(io.gaps().iter().all(|gap| *gap < 300), "{:?}", io.gaps());
}

/// A batch never included stops the run: the message says the batch may
/// still land, names the shard it waits on, the check to run before a rerun
/// and when its coins rejoin new runs; the next batch is not proved.
#[tokio::test]
async fn shield_pacing_stops_when_inclusion_times_out() {
    let mut io = Fake::healthy(|_| None);
    let error = run(&mut io, 3, pacing(0)).await.unwrap_err().to_string();
    assert!(error.contains("batch 1/3"), "{error}");
    assert!(error.contains("still read unshielded"), "{error}");
    assert!(error.contains("may still land"), "{error}");
    assert!(
        error.contains("shard ...feedbeef00's next frame"),
        "{error}"
    );
    assert!(
        error.contains("Check `qclient token legacy` before rerunning"),
        "{error}"
    );
    let sent_unix = 1_700_000_000 + io.submits[0].1;
    let until = utc(sent_unix + SUBMITTED_EXCLUSION_SECS);
    assert!(
        error.contains(&format!("a new run leaves its coins out until {until}")),
        "{error}"
    );
    assert_eq!(io.proves.len(), 1, "the next batch must not be proved");
    let waited = io.now - io.submits[0].1;
    let timeout = DEFAULT_INCLUSION_TIMEOUT_SECS;
    assert!(
        (timeout..timeout + 2 * POLL_SECS).contains(&waited),
        "{waited}"
    );
}

/// The default timeout outlasts the shard stalls seen after frames carrying
/// batches: on mainnet a batch committed 1,864 s after its submission
/// (2026-11-01), which the run must report as included, as it must one that
/// takes 55 minutes.
#[tokio::test]
async fn shield_pacing_default_timeout_outlasts_a_shard_stall() {
    let mut io = Fake::healthy(|_| Some(1_864));
    assert_eq!(run(&mut io, 1, pacing(0)).await.unwrap(), 1);

    let mut io = Fake::healthy(|_| Some(3_300));
    run(&mut io, 1, pacing(0))
        .await
        .expect("an inclusion after 55 minutes of healthy GLOBAL is no timeout");
}

/// A submitted batch's coins stay out of new runs at least as long as the
/// default timeout, so a run stopped by it never frees them early; after a
/// long pause the message says they are no longer left out.
#[tokio::test]
async fn shield_pacing_submitted_coins_stay_out_past_the_timeout() {
    assert!(
        SUBMITTED_EXCLUSION_SECS >= DEFAULT_INCLUSION_TIMEOUT_SECS,
        "{SUBMITTED_EXCLUSION_SECS} < {DEFAULT_INCLUSION_TIMEOUT_SECS}"
    );
    // GLOBAL stands still 5,000 s from shortly after the submission.
    let (from, to) = (START + 300, START + 5_300);
    let mut io = Fake::new(frames_with_stall(from, to), |_| None);
    let error = run(&mut io, 1, pacing(0)).await.unwrap_err().to_string();
    assert!(
        error.contains("a new run no longer leaves its coins out"),
        "{error}"
    );
}

/// Each submission names the shard whose members verify it, in short form.
#[tokio::test]
async fn shield_pacing_submitted_line_names_the_shard() {
    let mut io = Fake::healthy(|_| Some(30));
    run(&mut io, 2, pacing(0)).await.unwrap();
    let lines: Vec<String> = io
        .events
        .iter()
        .filter(|e| matches!(e, ShieldEvent::Submitted { .. }))
        .map(ShieldEvent::line)
        .collect();
    assert_eq!(lines.len(), 2);
    assert!(
        lines[1].contains("96 legacy coins of shard ...feedbeef01 submitted at"),
        "{}",
        lines[1]
    );

    let address = [0xab; 32];
    let label = |suffix: &[u8]| shard_label(&[&address[..], suffix].concat());
    assert_eq!(label(&[]), "...abababab");
    assert_eq!(label(&[0x2f]), "...abababab2f");
    assert_eq!(label(&[0x00, 0x06, 0xfc]), "...abababab0006fc");
}

/// GLOBAL standing still before the submission holds it until GLOBAL has
/// been healthy for the recovery time; both changes are reported.
#[tokio::test]
async fn shield_pacing_pauses_while_global_stalls_and_resumes_after_recovery() {
    let (from, to) = (START + 20, START + 2_000);
    let mut io = Fake::new(frames_with_stall(from, to), |_| Some(30));
    run(&mut io, 1, pacing(0)).await.unwrap();
    let sent = io.submits[0].1;
    assert!(
        sent >= to + RECOVERY_SECS,
        "submitted at {sent} before GLOBAL had been healthy for {RECOVERY_SECS} s after {to}"
    );
    assert!(sent < to + RECOVERY_SECS + 2 * POLL_SECS, "{sent}");
    let paused = io
        .position(|e| matches!(e, ShieldEvent::Paused { .. }))
        .unwrap();
    let resumed = io
        .position(|e| matches!(e, ShieldEvent::Resumed { .. }))
        .unwrap();
    assert!(paused < resumed);
    let ShieldEvent::Paused { reason, .. } = &io.events[paused] else {
        unreachable!()
    };
    // GLOBAL stood still inside the proving gap, which shows as a small advance.
    assert!(reason.contains("between reads"), "{reason}");
    assert!(
        io.position(|e| matches!(e, ShieldEvent::StillPaused { .. }))
            .is_some(),
        "a long pause repeats its notice"
    );
}

/// The wait for inclusion does not count time GLOBAL stood still: an
/// inclusion after a long stall is not a timeout.
#[tokio::test]
async fn shield_pacing_inclusion_timeout_excludes_global_pauses() {
    // Submitted near START+150; GLOBAL stands still 3,600 s from START+200.
    let (from, to) = (START + 200, START + 3_800);
    let mut io = Fake::new(frames_with_stall(from, to), |_| Some(3_900));
    run(&mut io, 1, pacing(0))
        .await
        .expect("a stalled GLOBAL is not an inclusion timeout");
}

/// Below 330 frames over the sampled hour pauses; 330 does not; and nothing
/// is judged before the samples span 10 minutes.
#[test]
fn shield_pacing_health_judges_the_hourly_frame_count() {
    let hour = |frames: u64| {
        let mut health = Health::default();
        for t in (0..=3_600).step_by(15) {
            health.observe(t, 1_000 + (frames * t).div_ceil(3_600));
        }
        health.degraded().map(str::to_owned)
    };
    assert_eq!(hour(330), None);
    let slow = hour(329).expect("329 frames in an hour is degraded");
    assert!(slow.contains("below 330/h"), "{slow}");

    let mut health = Health::default();
    for t in (0..600).step_by(30) {
        assert_eq!(health.observe(t, 5 + t / 30), None, "t={t}");
    }
    // One frame per 30 s is 120 an hour: judged once 10 minutes are sampled.
    let Some(Change::Paused(reason)) = health.observe(600, 25) else {
        panic!("120 frames an hour must pause at 10 minutes");
    };
    assert!(reason.contains("below 330/h"), "{reason}");
}

/// After a resume the window restarts, so the slow hour behind the pause
/// does not pause the run again at once.
#[test]
fn shield_pacing_resume_restarts_the_window() {
    let mut health = Health::default();
    let mut t = 0;
    let mut head = 100;
    while t < 600 {
        health.observe(t, head);
        t += 10;
        head += 1;
    }
    let mut paused = false;
    while t < 1_500 {
        paused |= matches!(health.observe(t, head), Some(Change::Paused(_)));
        t += 15;
    }
    assert!(paused);
    let mut resumed = false;
    while t < 4_000 {
        head += 1;
        match health.observe(t, head) {
            Some(Change::Resumed { .. }) => resumed = true,
            Some(Change::Paused(reason)) => panic!("paused again: {reason}"),
            _ => {}
        }
        t += 10;
    }
    assert!(resumed);
    assert_eq!(health.degraded(), None);
}

/// An unreadable head counts as no advance.
#[test]
fn shield_pacing_unreadable_head_stalls_after_the_stall_time() {
    let mut health = Health::default();
    assert_eq!(health.observe(0, 10), None);
    assert_eq!(health.unreadable(STALL_SECS - 1), None);
    assert!(matches!(
        health.unreadable(STALL_SECS),
        Some(Change::Paused(_))
    ));
}

/// Reads are sparse while a batch is proved: a head that moved only a few
/// frames across a long gap was stalled inside it.
#[test]
fn shield_pacing_sparse_reads_catch_a_stall_inside_the_gap() {
    let mut health = Health::default();
    assert_eq!(health.observe(0, 100), None);
    let Some(Change::Paused(reason)) = health.observe(150, 102) else {
        panic!("2 frames in 150 s must pause");
    };
    assert!(reason.contains("between reads"), "{reason}");

    let mut health = Health::default();
    assert_eq!(health.observe(0, 100), None);
    assert_eq!(health.observe(150, 115), None);
    // A 60 s gap that straddled one frame boundary is not a stall.
    assert_eq!(health.observe(210, 120), None);
}

#[test]
fn shield_pacing_formats_utc() {
    assert_eq!(utc(0), "1970-01-01 00:00:00Z");
    assert_eq!(utc(1_793_606_400), "2026-11-02 08:00:00Z");
    assert_eq!(utc(1_793_606_400 + 3_661), "2026-11-02 09:01:01Z");
    assert_eq!(utc(1_709_164_800), "2024-02-29 00:00:00Z");
}
