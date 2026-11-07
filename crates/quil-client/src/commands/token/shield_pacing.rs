//! Pacing for `token shield-all` and the node manager's shield.
//!
//! A batch shield costs every archive tens of seconds of proof verification
//! on GLOBAL's critical path, so a run must not load GLOBAL faster than the
//! archives verify. The run therefore (1) proves and submits one batch at a
//! time and waits for its inclusion before starting the next, (2) keeps a
//! minimum spacing between submissions, and (3) pauses while the node reports
//! GLOBAL's progress degraded: its health conditions `Global head unchanged`
//! and `Global frames slow` (`quil_rpc::health_conditions`), the node's one
//! judgement of GLOBAL progress. The driver is generic over [`ShieldIo`] so a
//! fake clock and fake reads test every path; the CLI prints its events, the
//! node manager shows them as notices.

/// Default minimum spacing between two submissions (at most 12 per hour).
pub(crate) const DEFAULT_MIN_INTERVAL_SECS: u64 = 300;
/// Default bound on the wait for one batch's inclusion, in seconds of
/// healthy GLOBAL (time paused for GLOBAL does not count: nothing can be
/// included then). A batch commits in GLOBAL only with its shard's next
/// frame (the header of a shard's frame N carries frame N-1's fees), and on
/// mainnet shards stalled up to about 30 min after frames carrying batch
/// shields while their quorum waited on slow voters (2026-11-01: 1,803 s; the
/// batch committed 1,864 s after its submission). Such stalls have no fixed
/// bound, so a timed-out batch may still land.
pub(crate) const DEFAULT_INCLUSION_TIMEOUT_SECS: u64 = 3_600;
/// A submitted batch's coins stay out of new runs this long (the journal
/// that `token legacy`, the node manager and shield-all read).
pub(crate) use super::legacy::SUBMITTED_EXCLUSION_SECS;
/// The node's GLOBAL judgement unreadable this long pauses the run: nothing
/// says GLOBAL is healthy.
pub(crate) const UNREAD_SECS: u64 = 60;
/// The node must report GLOBAL healthy this long before a paused run resumes.
pub(crate) const RECOVERY_SECS: u64 = 600;
/// Spacing of head reads and inclusion reads while waiting.
pub(crate) const POLL_SECS: u64 = 15;
/// While a batch waits for inclusion, its shard is read this often in the
/// node's shard list (every 8th poll): a shard without an active prover
/// makes no frame, so its batch cannot commit.
pub(crate) const SHARD_CHECK_SECS: u64 = 120;
/// Reads in a row showing the shard without an active prover before the
/// run leaves its batch, so one odd read does not leave a batch that could
/// still commit.
const SHARD_GONE_READS: u32 = 2;
/// A pause repeats its notice this often; a wait for inclusion reports this often.
const NOTICE_SECS: u64 = 600;
const WAIT_NOTICE_SECS: u64 = 300;

/// A change in GLOBAL's health that the run reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Change {
    /// The run pauses, for this reason.
    Paused(String),
    /// The pause goes on; `reason` is GLOBAL's state at `secs`, not the
    /// one that started the pause.
    StillPaused {
        secs: u64,
        reason: String,
    },
    Resumed {
        paused_secs: u64,
    },
}

/// What the node says of GLOBAL at one read ([`ShieldIo::global`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct GlobalRead {
    /// The node's GLOBAL head.
    pub head: u64,
    /// The node's current GLOBAL progress condition, if any, as a clause.
    pub degraded: Option<String>,
}

#[derive(Debug)]
struct Degraded {
    /// What started the pause.
    reason: String,
    since: u64,
    notice_at: u64,
    /// From when the node has reported GLOBAL healthy without a gap.
    healthy_since: Option<u64>,
}

/// The run's pause, from the node's GLOBAL judgement read before each step.
/// The node judges; the run only decides when to submit: it pauses while
/// the node reports a GLOBAL progress condition, or its judgement cannot be
/// read for [`UNREAD_SECS`], and resumes after [`RECOVERY_SECS`] without.
#[derive(Debug, Default)]
pub(crate) struct Health {
    head: Option<u64>,
    degraded: Option<Degraded>,
    /// Since when the node's judgement could not be read.
    unread_since: Option<u64>,
}

impl Health {
    /// Record the node's judgement read at `now` (seconds on any monotonic
    /// clock), or why it could not be read.
    pub(crate) fn observe(&mut self, now: u64, read: Result<GlobalRead, String>) -> Option<Change> {
        // `Some(reason)`: degraded; `None`: healthy; unknown below the
        // unread time.
        let state = match read {
            Ok(read) => {
                self.head = Some(read.head);
                self.unread_since = None;
                Some(read.degraded)
            }
            Err(why) => {
                let since = *self.unread_since.get_or_insert(now);
                let secs = now - since;
                (secs >= UNREAD_SECS).then(|| {
                    Some(format!(
                        "this node's GLOBAL judgement unreadable for {secs} s ({why})"
                    ))
                })
            }
        };
        let Some(degraded) = self.degraded.as_mut() else {
            let reason = state.flatten()?;
            self.degraded = Some(Degraded {
                reason: reason.clone(),
                since: now,
                notice_at: now,
                healthy_since: None,
            });
            return Some(Change::Paused(reason));
        };
        // Recovery counts only time the node reports GLOBAL healthy.
        let now_reason = match &state {
            Some(None) => {
                let from = *degraded.healthy_since.get_or_insert(now);
                if now - from >= RECOVERY_SECS {
                    let paused_secs = now - degraded.since;
                    self.degraded = None;
                    return Some(Change::Resumed { paused_secs });
                }
                format!(
                    "the node reports GLOBAL healthy for {} s of the {RECOVERY_SECS} s needed",
                    now - from
                )
            }
            Some(Some(reason)) => {
                degraded.healthy_since = None;
                reason.clone()
            }
            None => {
                degraded.healthy_since = None;
                "this node's GLOBAL judgement could not be read".to_string()
            }
        };
        if now.saturating_sub(degraded.notice_at) >= NOTICE_SECS {
            degraded.notice_at = now;
            // The state the decision uses now; the pause's start was
            // reported when it began.
            return Some(Change::StillPaused {
                secs: now - degraded.since,
                reason: now_reason,
            });
        }
        None
    }

    /// What started the run's pause, if it is paused.
    pub(crate) fn degraded(&self) -> Option<&str> {
        self.degraded.as_ref().map(|d| d.reason.as_str())
    }

    /// The latest head read.
    pub(crate) fn head(&self) -> Option<u64> {
        self.head
    }
}

/// What a run reports; `line` is the text the CLI prints. Indexes are
/// 0-based; `line` prints them 1-based.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ShieldEvent {
    /// The run's plan: batches go one at a time.
    Plan { batches: usize, min_interval: u64 },
    /// The batch's coins do not cover the fee.
    Skipped {
        index: usize,
        total: usize,
        coins: usize,
        total_units: u128,
        fee: u128,
    },
    /// Proved; waiting out the minimum spacing before submitting.
    WaitingInterval {
        index: usize,
        total: usize,
        secs: u64,
    },
    /// Submission held, or the wait for inclusion suspended, for GLOBAL.
    Paused {
        index: usize,
        total: usize,
        reason: String,
    },
    StillPaused {
        index: usize,
        total: usize,
        secs: u64,
        reason: String,
    },
    Resumed {
        index: usize,
        total: usize,
        paused_secs: u64,
    },
    Submitted {
        index: usize,
        total: usize,
        coins: usize,
        /// The shard whose members verify the batch ([`shard_label`]).
        shard: String,
        unix: u64,
        head: Option<u64>,
    },
    /// Waiting for the batch's coins to stop reading unshielded.
    WaitingInclusion {
        index: usize,
        total: usize,
        waited: u64,
    },
    Included {
        index: usize,
        total: usize,
        waited: u64,
        head: Option<u64>,
    },
    /// The batch's shard has no active prover in the node's shard list, so
    /// the batch cannot commit until provers return: the run leaves it and
    /// goes on. `submitted` is set when it was left waiting for inclusion.
    ShardGone {
        index: usize,
        total: usize,
        shard: String,
        submitted: Option<Unconfirmed>,
    },
    /// After each batch: how many are done and the projected end.
    Progress {
        done: usize,
        total: usize,
        projected_end: u64,
    },
    /// The run was asked to stop ([`ShieldIo::stop_requested`]) and ended
    /// before submitting anything more.
    Stopped { submitted: usize, total: usize },
}

/// A submitted batch the run stopped waiting for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Unconfirmed {
    /// Seconds since its submission.
    pub waited: u64,
    /// When new runs include its coins again, in Unix seconds
    /// ([`SUBMITTED_EXCLUSION_SECS`] after its submission).
    pub rejoins: u64,
}

impl ShieldEvent {
    pub(crate) fn line(&self) -> String {
        match self {
            Self::Plan {
                batches,
                min_interval,
            } => format!(
                "Pacing {batches} batch{}: one at a time, each proved after the previous one's \
                 inclusion, submissions at least {min_interval} s apart, paused while GLOBAL is \
                 degraded.",
                if *batches == 1 { "" } else { "es" }
            ),
            Self::Skipped {
                index,
                total,
                coins,
                total_units,
                fee,
            } => format!(
                "Batch {}/{total}: {coins} legacy coins worth {total_units} base units do not \
                 cover the fee {fee}; skipped.",
                index + 1
            ),
            Self::WaitingInterval { index, total, secs } => format!(
                "Batch {}/{total}: proved; waiting {secs} s for the minimum spacing.",
                index + 1
            ),
            Self::Paused {
                index,
                total,
                reason,
            } => {
                format!("Batch {}/{total}: PAUSED, {reason}.", index + 1)
            }
            Self::StillPaused {
                index,
                total,
                secs,
                reason,
            } => format!(
                "Batch {}/{total}: still paused after {} min, {reason}.",
                index + 1,
                secs / 60
            ),
            Self::Resumed {
                index,
                total,
                paused_secs,
            } => format!(
                "Batch {}/{total}: RESUMED after {} min paused; GLOBAL healthy for {} min.",
                index + 1,
                paused_secs / 60,
                RECOVERY_SECS / 60
            ),
            Self::Submitted {
                index,
                total,
                coins,
                shard,
                unix,
                head,
            } => format!(
                "Batch {}/{total}: {coins} legacy coins of shard {shard} submitted at {} \
                 (GLOBAL frame {}); waiting for inclusion.",
                index + 1,
                utc(*unix),
                frame(*head)
            ),
            Self::WaitingInclusion {
                index,
                total,
                waited,
            } => {
                format!(
                    "Batch {}/{total}: not yet included after {waited} s.",
                    index + 1
                )
            }
            Self::Included {
                index,
                total,
                waited,
                head,
            } => format!(
                "Batch {}/{total}: included after {waited} s, seen at GLOBAL frame {}.",
                index + 1,
                frame(*head)
            ),
            Self::ShardGone {
                index,
                total,
                shard,
                submitted,
            } => {
                let next = if index + 1 < *total {
                    " The run goes on with the next batch."
                } else {
                    ""
                };
                match submitted {
                    Some(Unconfirmed { waited, rejoins }) => format!(
                        "Batch {}/{total}: shard {shard} has no active provers in the node's \
                         shard list, so the batch cannot commit; stopped waiting after {waited} \
                         s. It may still land if provers return; a new run includes its coins \
                         from {} and plans them onto the live shard covering them.{next}",
                        index + 1,
                        utc(*rejoins)
                    ),
                    None => format!(
                        "Batch {}/{total}: shard {shard} has no active provers in the node's \
                         shard list; not proved. A rerun plans its coins onto the live shard \
                         covering them.{next}",
                        index + 1
                    ),
                }
            }
            Self::Progress {
                done,
                total,
                projected_end,
            } => format!(
                "Progress: {done}/{total} batches; projected end {}.",
                utc(*projected_end)
            ),
            Self::Stopped { submitted, total } => format!(
                "Stopped on request: {submitted} of {total} batches submitted; the rest were \
                 not."
            ),
        }
    }
}

/// A shard filter in short form: the last 8 hex digits of its app address
/// after "...", then its shard suffix, as `node prover manage` shows shards
/// that share one app address.
pub(crate) fn shard_label(filter: &[u8]) -> String {
    let hex = hex::encode(filter);
    let address_end = hex.len().min(64);
    format!(
        "...{}{}",
        &hex[address_end.saturating_sub(8)..address_end],
        &hex[address_end..]
    )
}

fn frame(head: Option<u64>) -> String {
    head.map_or_else(|| "unknown".into(), |h| h.to_string())
}

/// `YYYY-MM-DD HH:MM:SSZ` for Unix seconds.
pub(crate) fn utc(unix: u64) -> String {
    let (days, rest) = (unix / 86_400, unix % 86_400);
    // Civil date from days since 1970-01-01 (Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}Z",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

/// Pacing settings.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Pacing {
    pub min_interval: u64,
    pub inclusion_timeout: u64,
}

/// The reads, proofs, submissions and clock a run uses.
pub(crate) trait ShieldIo {
    type Proof;
    /// Monotonic seconds.
    fn now(&self) -> u64;
    /// Wall-clock Unix seconds.
    fn unix(&self) -> u64;
    async fn sleep(&mut self, secs: u64);
    /// The node's GLOBAL head and its GLOBAL progress condition, if one is
    /// current; an error when they cannot be read, or the node predates
    /// health conditions.
    async fn global(&mut self) -> anyhow::Result<GlobalRead>;
    /// Legacy coins in batch `index`.
    fn coins(&self, index: usize) -> usize;
    /// The shard whose members verify batch `index` ([`shard_label`]).
    fn shard(&self, index: usize) -> String;
    /// Prove batch `index`; `None` when it is skipped (reported already).
    async fn prove(&mut self, index: usize) -> anyhow::Result<Option<Self::Proof>>;
    async fn submit(&mut self, index: usize, proof: Self::Proof) -> anyhow::Result<()>;
    /// Whether none of batch `index`'s coins still reads unshielded.
    async fn included(&mut self, index: usize) -> anyhow::Result<bool>;
    /// Whether batch `index`'s shard has an active prover in the node's
    /// shard list. An error is no evidence either way.
    async fn shard_live(&mut self, index: usize) -> anyhow::Result<bool>;
    fn event(&mut self, event: &ShieldEvent);
    /// Whether the run should end before its next submission (the node
    /// manager's stop key). Checked before each proof, before each
    /// submission and while waiting for inclusion.
    fn stop_requested(&self) -> bool {
        false
    }
}

/// End the run on request, reporting what was submitted.
fn stopped<I: ShieldIo>(io: &mut I, submitted: usize, total: usize) -> anyhow::Result<usize> {
    io.event(&ShieldEvent::Stopped { submitted, total });
    Ok(submitted)
}

async fn sample<I: ShieldIo>(io: &mut I, health: &mut Health, index: usize, total: usize) {
    let now = io.now();
    let read = io.global().await.map_err(|e| format!("{e:#}"));
    let change = health.observe(now, read);
    match change {
        None => {}
        Some(Change::Paused(reason)) => io.event(&ShieldEvent::Paused {
            index,
            total,
            reason,
        }),
        Some(Change::StillPaused { secs, reason }) => io.event(&ShieldEvent::StillPaused {
            index,
            total,
            secs,
            reason,
        }),
        Some(Change::Resumed { paused_secs }) => io.event(&ShieldEvent::Resumed {
            index,
            total,
            paused_secs,
        }),
    }
}

/// A batch the run left: its index, shard and, if it was submitted, the
/// wait it stopped.
type Left = (usize, String, Option<Unconfirmed>);

/// The run's end when it left batches for shards without provers
/// ([`ShieldEvent::ShardGone`]): which, and what a rerun does with them.
fn left_error(left: &[Left], total: usize, unix: u64) -> String {
    let mut shards: Vec<&str> = left.iter().map(|(_, shard, _)| shard.as_str()).collect();
    shards.sort_unstable();
    shards.dedup();
    let batches: Vec<String> = left
        .iter()
        .map(|(index, ..)| (index + 1).to_string())
        .collect();
    let rejoins = left
        .iter()
        .filter_map(|(.., submitted)| submitted.map(|s| s.rejoins))
        .max()
        .filter(|rejoins| *rejoins > unix)
        .map_or(String::new(), |rejoins| {
            format!(
                "; coins of the submitted ones rejoin new runs from {}, unless provers return \
                 and they land first",
                utc(rejoins)
            )
        });
    format!(
        "{} of {total} left (batch {}): shard {} had no active provers in the node's shard \
         list. Check `qclient token legacy`, then rerun: it plans their coins onto the live \
         shard covering them{rejoins}.",
        if left.len() == 1 {
            "1 batch".to_owned()
        } else {
            format!("{} batches", left.len())
        },
        batches.join(", "),
        shards.join(", ")
    )
}

/// Run `total` batches under `pacing`. Returns the batches submitted. A
/// batch whose shard has no active prover is left, before its proof or
/// while it waits for inclusion, and the run goes on with the next; a run
/// that left any ends with an error naming them.
pub(crate) async fn run<I: ShieldIo>(
    io: &mut I,
    total: usize,
    pacing: Pacing,
) -> anyhow::Result<usize> {
    io.event(&ShieldEvent::Plan {
        batches: total,
        min_interval: pacing.min_interval,
    });
    let started = io.now();
    let mut health = Health::default();
    let mut last_submit: Option<u64> = None;
    let mut submitted = 0usize;
    let mut left: Vec<Left> = Vec::new();
    for index in 0..total {
        if io.stop_requested() {
            return stopped(io, submitted, total);
        }
        sample(io, &mut health, index, total).await;
        // The shard may have lost its provers since the plan: its batch
        // could not commit, and a rerun plans its coins onto a live one.
        if matches!(io.shard_live(index).await, Ok(false)) {
            let shard = io.shard(index);
            io.event(&ShieldEvent::ShardGone {
                index,
                total,
                shard: shard.clone(),
                submitted: None,
            });
            left.push((index, shard, None));
            continue;
        }
        let Some(proof) = io.prove(index).await? else {
            continue;
        };
        // Gate: GLOBAL healthy and the spacing since the last submission
        // kept; a stop request drops the proof unsubmitted.
        let mut announced = false;
        loop {
            if io.stop_requested() {
                return stopped(io, submitted, total);
            }
            sample(io, &mut health, index, total).await;
            if health.degraded().is_some() {
                io.sleep(POLL_SECS).await;
                continue;
            }
            let due = last_submit.map_or(0, |t| t + pacing.min_interval);
            let now = io.now();
            if now >= due {
                break;
            }
            if !announced {
                announced = true;
                io.event(&ShieldEvent::WaitingInterval {
                    index,
                    total,
                    secs: due - now,
                });
            }
            io.sleep((due - now).min(POLL_SECS)).await;
        }
        io.submit(index, proof).await?;
        let sent = io.now();
        let sent_unix = io.unix();
        last_submit = Some(sent);
        submitted += 1;
        io.event(&ShieldEvent::Submitted {
            index,
            total,
            coins: io.coins(index),
            shard: io.shard(index),
            unix: sent_unix,
            head: health.head(),
        });
        // Wait for inclusion; time paused for GLOBAL does not count.
        let mut active = 0u64;
        let mut noticed = sent;
        let mut last = sent;
        let mut last_error: Option<String>;
        let mut shard_read = sent;
        let mut gone_reads = 0u32;
        loop {
            io.sleep(POLL_SECS).await;
            if io.stop_requested() {
                return stopped(io, submitted, total);
            }
            sample(io, &mut health, index, total).await;
            let now = io.now();
            if health.degraded().is_none() {
                active += now - last;
            }
            last = now;
            match io.included(index).await {
                Ok(true) => {
                    io.event(&ShieldEvent::Included {
                        index,
                        total,
                        waited: now - sent,
                        head: health.head(),
                    });
                    break;
                }
                Ok(false) => last_error = None,
                Err(error) => last_error = Some(error.to_string()),
            }
            if now - shard_read >= SHARD_CHECK_SECS {
                shard_read = now;
                gone_reads = match io.shard_live(index).await {
                    Ok(true) => 0,
                    Ok(false) => gone_reads + 1,
                    Err(_) => gone_reads,
                };
                if gone_reads >= SHARD_GONE_READS {
                    let shard = io.shard(index);
                    let unconfirmed = Unconfirmed {
                        waited: now - sent,
                        rejoins: sent_unix + SUBMITTED_EXCLUSION_SECS,
                    };
                    io.event(&ShieldEvent::ShardGone {
                        index,
                        total,
                        shard: shard.clone(),
                        submitted: Some(unconfirmed),
                    });
                    left.push((index, shard, Some(unconfirmed)));
                    break;
                }
            }
            if active >= pacing.inclusion_timeout {
                let excluded_until = sent_unix + SUBMITTED_EXCLUSION_SECS;
                let exclusion = if io.unix() < excluded_until {
                    format!(
                        "a new run leaves its coins out until {}",
                        utc(excluded_until)
                    )
                } else {
                    format!(
                        "a new run no longer leaves its coins out (it did until {})",
                        utc(excluded_until)
                    )
                };
                let shard = io.shard(index);
                let why = if matches!(io.shard_live(index).await, Ok(false)) {
                    format!(
                        "Shard {shard} has no active provers in the node's shard list now, so \
                         it makes no frame to commit the batch; the batch may still land if \
                         provers return. Check `qclient token legacy` before rerunning; \
                         {exclusion}, and a rerun plans them onto the live shard covering them."
                    )
                } else {
                    format!(
                        "The batch may still land: it commits with shard {shard}'s next frame, \
                         and shards have stalled 30 min or more after a frame carrying a batch. \
                         Check `qclient token legacy` before rerunning; {exclusion}."
                    )
                };
                anyhow::bail!(
                    "batch {}/{total}: its coins still read unshielded after {active} s of \
                     healthy GLOBAL since submission{}; stopping. {why}",
                    index + 1,
                    last_error.map_or(String::new(), |e| format!(" (last read error: {e})")),
                );
            }
            if now - noticed >= WAIT_NOTICE_SECS {
                noticed = now;
                io.event(&ShieldEvent::WaitingInclusion {
                    index,
                    total,
                    waited: now - sent,
                });
            }
        }
        let done = index + 1;
        let per_batch = ((io.now() - started) / done as u64).max(pacing.min_interval);
        io.event(&ShieldEvent::Progress {
            done,
            total,
            projected_end: io.unix() + per_batch * (total - done) as u64,
        });
    }
    if !left.is_empty() {
        anyhow::bail!(left_error(&left, total, io.unix()));
    }
    Ok(submitted)
}

/// For tests: a node whose GLOBAL advances one frame per 10 s and stands
/// still on `[from, to)`, which it reports as its GLOBAL head condition from
/// 120 s into the stall until GLOBAL advances again.
#[cfg(test)]
pub(crate) fn node_with_stall(from: u64, to: u64) -> impl Fn(u64) -> GlobalRead {
    move |t| GlobalRead {
        head: 1_000
            + if t < from {
                t / 10
            } else if t < to {
                from / 10
            } else {
                from / 10 + (t - to) / 10
            },
        degraded: (t >= from.saturating_add(120) && t < to)
            .then(|| "Global head unchanged >120s".to_string()),
    }
}

#[cfg(test)]
#[path = "shield_pacing_tests.rs"]
mod tests;
