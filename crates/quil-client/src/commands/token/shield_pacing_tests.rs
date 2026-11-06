use super::*;

const START: u64 = 1_000_000;
const NEVER: (u64, u64) = (u64::MAX - 1, u64::MAX);

/// A fake clock and fake reads: sleeping and proving only advance time.
struct Fake {
    now: u64,
    node: Box<dyn Fn(u64) -> GlobalRead>,
    /// Seconds after submission at which a batch reads included, or never.
    inclusion: Box<dyn Fn(usize) -> Option<u64>>,
    /// The time from which a batch's shard has no active prover, or never.
    gone: Box<dyn Fn(usize) -> Option<u64>>,
    /// Each read of a batch's shard, and when.
    shard_reads: Vec<(usize, u64)>,
    proves: Vec<(usize, u64)>,
    submits: Vec<(usize, u64)>,
    events: Vec<ShieldEvent>,
}

impl Fake {
    fn new(
        node: impl Fn(u64) -> GlobalRead + 'static,
        inclusion: impl Fn(usize) -> Option<u64> + 'static,
    ) -> Self {
        Self {
            now: START,
            node: Box::new(node),
            inclusion: Box::new(inclusion),
            gone: Box::new(|_| None),
            shard_reads: Vec::new(),
            proves: Vec::new(),
            submits: Vec::new(),
            events: Vec::new(),
        }
    }

    fn healthy(inclusion: impl Fn(usize) -> Option<u64> + 'static) -> Self {
        Self::new(node_with_stall(NEVER.0, NEVER.1), inclusion)
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
    async fn global(&mut self) -> anyhow::Result<GlobalRead> {
        Ok((self.node)(self.now))
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
    async fn shard_live(&mut self, index: usize) -> anyhow::Result<bool> {
        self.shard_reads.push((index, self.now));
        Ok((self.gone)(index).is_none_or(|from| self.now < from))
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

/// A batch whose shard loses its last active prover while it waits is left
/// within two shard reads, not after the hour: the line names the shard,
/// says the batch may still land and when its coins rejoin new runs; the
/// run goes on with the next batches and ends with an error naming the
/// batch left and the rerun.
#[tokio::test]
async fn shield_pacing_leaves_a_batch_whose_shard_lost_its_provers() {
    let mut io = Fake::healthy(|index| (index > 0).then_some(30));
    // Batch 1 is submitted at START + 150; its shard empties 10 min on.
    io.gone = Box::new(|index| (index == 0).then_some(START + 750));
    let error = run(&mut io, 3, pacing(0)).await.unwrap_err().to_string();
    let sent = io.submits[0].1;
    assert_eq!(sent, START + 150);
    let Some(gone) = io
        .events
        .iter()
        .find(|e| matches!(e, ShieldEvent::ShardGone { index: 0, .. }))
    else {
        panic!("no ShardGone event in {:#?}", io.events);
    };
    let ShieldEvent::ShardGone {
        submitted: Some(Unconfirmed { waited, rejoins }),
        ..
    } = gone
    else {
        panic!("batch 1 was submitted: {gone:?}");
    };
    assert!(
        *waited <= 600 + u64::from(SHARD_GONE_READS) * SHARD_CHECK_SECS,
        "left after {waited} s"
    );
    let sent_unix = 1_700_000_000 + sent;
    assert_eq!(*rejoins, sent_unix + SUBMITTED_EXCLUSION_SECS);
    let line = gone.line();
    for part in [
        "Batch 1/3: shard ...feedbeef00 has no active provers in the node's shard list",
        "stopped waiting after",
        "It may still land if provers return",
        &format!(
            "a new run includes its coins from {}",
            utc(sent_unix + SUBMITTED_EXCLUSION_SECS)
        ),
        "plans them onto the live shard covering them",
        "The run goes on with the next batch.",
    ] {
        assert!(line.contains(part), "{part:?} not in {line}");
    }
    assert_eq!(io.submits.len(), 3, "{:?}", io.submits);
    let included = io
        .events
        .iter()
        .filter(|e| matches!(e, ShieldEvent::Included { .. }))
        .count();
    assert_eq!(included, 2);
    assert!(
        error.starts_with("1 batch of 3 left (batch 1): shard ...feedbeef00 had no active provers"),
        "{error}"
    );
    assert!(
        error.contains("Check `qclient token legacy`, then rerun"),
        "{error}"
    );
    assert!(
        error.contains(&format!(
            "rejoin new runs from {}",
            utc(sent_unix + SUBMITTED_EXCLUSION_SECS)
        )),
        "{error}"
    );
}

/// A batch whose shard has no active prover by its turn is neither proved
/// nor submitted (its coins stay free for a rerun); the next is.
#[tokio::test]
async fn shield_pacing_skips_a_batch_whose_shard_is_gone_before_its_proof() {
    let mut io = Fake::healthy(|_| Some(30));
    io.gone = Box::new(|index| (index == 1).then_some(START));
    let error = run(&mut io, 3, pacing(0)).await.unwrap_err().to_string();
    let proved: Vec<usize> = io.proves.iter().map(|(index, _)| *index).collect();
    assert_eq!(proved, [0, 2]);
    let submitted: Vec<usize> = io.submits.iter().map(|(index, _)| *index).collect();
    assert_eq!(submitted, [0, 2]);
    let gone = io
        .events
        .iter()
        .find(|e| matches!(e, ShieldEvent::ShardGone { .. }))
        .expect("a ShardGone event");
    assert!(
        matches!(
            gone,
            ShieldEvent::ShardGone {
                index: 1,
                submitted: None,
                ..
            }
        ),
        "{gone:?}"
    );
    assert_eq!(
        gone.line(),
        "Batch 2/3: shard ...feedbeef01 has no active provers in the node's shard list; not \
         proved. A rerun plans its coins onto the live shard covering them. The run goes on \
         with the next batch."
    );
    assert_eq!(
        error,
        "1 batch of 3 left (batch 2): shard ...feedbeef01 had no active provers in the node's \
         shard list. Check `qclient token legacy`, then rerun: it plans their coins onto the \
         live shard covering them."
    );
}

/// A live shard changes nothing: the run waits for the inclusion as
/// before, and reads the shard list once per batch and once every
/// [`SHARD_CHECK_SECS`] while waiting, not at every poll.
#[tokio::test]
async fn shield_pacing_live_shard_reads_are_bounded() {
    let mut io = Fake::healthy(|_| Some(1_864));
    assert_eq!(run(&mut io, 1, pacing(0)).await.unwrap(), 1);
    assert!(!io
        .events
        .iter()
        .any(|e| matches!(e, ShieldEvent::ShardGone { .. })));
    let sent = io.submits[0].1;
    let waiting = io.shard_reads.iter().filter(|(_, at)| *at > sent).count() as u64;
    let polls = 1_864 / POLL_SECS + 1;
    assert_eq!(waiting, 1_864 / SHARD_CHECK_SECS, "{:?}", io.shard_reads);
    assert!(waiting * 4 < polls, "{waiting} reads over {polls} polls");
    assert_eq!(
        io.shard_reads.iter().filter(|(_, at)| *at <= sent).count(),
        1
    );
}

/// A timeout whose shard has no active prover by then says so: the batch
/// cannot commit until provers return, and a rerun plans its coins onto
/// the live shard covering them. One such read alone does not leave the
/// batch early.
#[tokio::test]
async fn shield_pacing_timeout_names_a_shard_without_provers() {
    let mut io = Fake::healthy(|_| None);
    // Submitted at START + 150: the shard empties 10 s before the timeout.
    let timeout = DEFAULT_INCLUSION_TIMEOUT_SECS;
    io.gone = Box::new(move |_| Some(START + 150 + timeout - 10));
    let error = run(&mut io, 1, pacing(0)).await.unwrap_err().to_string();
    assert!(
        !io.events
            .iter()
            .any(|e| matches!(e, ShieldEvent::ShardGone { .. })),
        "{:#?}",
        io.events
    );
    for part in [
        "batch 1/1: its coins still read unshielded after",
        "Shard ...feedbeef00 has no active provers in the node's shard list now",
        "the batch may still land if provers return",
        "Check `qclient token legacy` before rerunning",
        "a new run leaves its coins out until",
        "a rerun plans them onto the live shard covering them",
    ] {
        assert!(error.contains(part), "{part:?} not in {error}");
    }
    assert!(!error.contains("shards have stalled"), "{error}");
    let waited = io.now - io.submits[0].1;
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
    let mut io = Fake::new(node_with_stall(from, to), |_| None);
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

/// The node's GLOBAL head condition before the submission holds it until
/// the node has reported GLOBAL healthy for the recovery time; both changes
/// are reported, the pause with the node's notice.
#[tokio::test]
async fn shield_pacing_pauses_while_global_stalls_and_resumes_after_recovery() {
    let (from, to) = (START + 20, START + 2_000);
    let mut io = Fake::new(node_with_stall(from, to), |_| Some(30));
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
    assert_eq!(reason, "Global head unchanged >120s");
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
    let mut io = Fake::new(node_with_stall(from, to), |_| Some(3_900));
    run(&mut io, 1, pacing(0))
        .await
        .expect("a stalled GLOBAL is not an inclusion timeout");
}

/// A repeated pause notice names the node's state as the decision reads it
/// then, not the condition that started the pause; recovery counts only
/// time the node reports GLOBAL healthy.
#[test]
fn shield_pacing_still_paused_names_the_nodes_current_state() {
    let read = |degraded: Option<&str>| {
        Ok(GlobalRead {
            head: 700,
            degraded: degraded.map(str::to_owned),
        })
    };
    let head = "Global head unchanged >120s";
    let slow = "Global frames slow: 300 in 60 min (~300/h, below 330/h)";
    let mut health = Health::default();
    assert_eq!(health.observe(0, read(None)), None);
    assert_eq!(
        health.observe(15, read(Some(head))),
        Some(Change::Paused(head.into()))
    );
    assert_eq!(health.observe(315, read(None)), None);
    assert_eq!(
        health.observe(615, read(None)),
        Some(Change::StillPaused {
            secs: 600,
            reason: "the node reports GLOBAL healthy for 300 s of the 600 s needed".into(),
        })
    );
    // The node reports GLOBAL slow: the recovery starts again.
    assert_eq!(health.observe(700, read(Some(slow))), None);
    assert_eq!(
        health.observe(1_215, read(Some(slow))),
        Some(Change::StillPaused {
            secs: 1_200,
            reason: slow.into(),
        })
    );
    assert_eq!(health.degraded(), Some(head));
    assert_eq!(health.observe(1_300, read(None)), None);
    assert_eq!(
        health.observe(1_900, read(None)),
        Some(Change::Resumed { paused_secs: 1_885 })
    );
    assert_eq!(health.degraded(), None);
}

/// A node whose judgement cannot be read (unreachable, or older than
/// health conditions) says nothing of GLOBAL: the run pauses after a minute.
#[test]
fn shield_pacing_pauses_when_the_nodes_judgement_cannot_be_read() {
    let mut health = Health::default();
    let healthy = GlobalRead {
        head: 10,
        degraded: None,
    };
    assert_eq!(health.observe(0, Ok(healthy.clone())), None);
    assert_eq!(health.observe(10, Err("refused".into())), None);
    assert_eq!(health.observe(69, Err("refused".into())), None);
    assert_eq!(
        health.observe(70, Err("refused".into())),
        Some(Change::Paused(
            "this node's GLOBAL judgement unreadable for 60 s (refused)".into()
        ))
    );
    assert_eq!(health.head(), Some(10));
}

#[test]
fn shield_pacing_formats_utc() {
    assert_eq!(utc(0), "1970-01-01 00:00:00Z");
    assert_eq!(utc(1_793_606_400), "2026-11-02 08:00:00Z");
    assert_eq!(utc(1_793_606_400 + 3_661), "2026-11-02 09:01:01Z");
    assert_eq!(utc(1_709_164_800), "2024-02-29 00:00:00Z");
}
