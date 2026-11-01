//! Pacing for `token shield-all`.
//!
//! A batch shield costs every archive tens of seconds of proof verification
//! on GLOBAL's critical path, so a run must not load GLOBAL faster than the
//! archives verify. The run therefore (1) proves and submits one batch at a
//! time and waits for its inclusion before starting the next, (2) keeps a
//! minimum spacing between submissions, and (3) pauses while GLOBAL is
//! degraded. The driver is generic over [`ShieldIo`] so a fake clock and fake
//! reads test every path.

use std::collections::VecDeque;

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
/// A submitted batch's coins stay out of new runs this long after its
/// submission (wall time), so a rerun after an inclusion timeout does not
/// shield them twice: twice [`DEFAULT_INCLUSION_TIMEOUT_SECS`], which counts
/// only healthy GLOBAL.
pub(crate) const SUBMITTED_EXCLUSION_SECS: u64 = 7_200;
/// GLOBAL is degraded below this many frames per hour (10 s frames = 360).
pub(crate) const MIN_FRAMES_PER_HOUR: u64 = 330;
/// GLOBAL is degraded when its head has not advanced for this long.
pub(crate) const STALL_SECS: u64 = 60;
/// GLOBAL must be healthy this long before a paused run resumes.
pub(crate) const RECOVERY_SECS: u64 = 600;
/// The hourly rate is judged over at most this window, and only once the
/// samples span [`MIN_RATE_SPAN_SECS`].
const HEALTH_WINDOW_SECS: u64 = 3_600;
const MIN_RATE_SPAN_SECS: u64 = 600;
/// Spacing of head reads and inclusion reads while waiting.
pub(crate) const POLL_SECS: u64 = 15;
/// A pause repeats its notice this often; a wait for inclusion reports this often.
const NOTICE_SECS: u64 = 600;
const WAIT_NOTICE_SECS: u64 = 300;

/// A change in GLOBAL's health that the run reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Change {
    Paused(String),
    StillPaused { secs: u64, reason: String },
    Resumed { paused_secs: u64 },
}

#[derive(Debug)]
struct Degraded {
    reason: String,
    since: u64,
    notice_at: u64,
    /// `(time, head)` from which GLOBAL has been continuously advancing.
    healthy_since: Option<(u64, u64)>,
}

/// GLOBAL's health from sampled head frames. The node RPC reports the head
/// only, so the hourly frame count is the head's advance across the sampled
/// window (judged once the samples span 10 minutes).
#[derive(Debug, Default)]
pub(crate) struct Health {
    samples: VecDeque<(u64, u64)>,
    /// When the current head was first seen: `(time, head)`.
    advanced: Option<(u64, u64)>,
    degraded: Option<Degraded>,
    /// Set when the last two reads, at least [`STALL_SECS`] apart, show GLOBAL
    /// advancing too slowly: reads are sparse while a batch is being proved,
    /// so a stall inside the gap shows only as a small advance.
    sparse_gap: Option<String>,
}

impl Health {
    /// Record a head read at `now` (seconds on any monotonic clock).
    pub(crate) fn observe(&mut self, now: u64, head: u64) -> Option<Change> {
        if self.advanced.map(|(_, h)| h) != Some(head) {
            self.advanced = Some((now, head));
        }
        // One frame of slack: reads fall anywhere inside the 10 s frame.
        self.sparse_gap = self
            .samples
            .back()
            .filter(|(t, _)| now.saturating_sub(*t) >= STALL_SECS)
            .and_then(|&(t, h)| {
                let (span, frames) = (now - t, head.saturating_sub(h));
                (!rate_ok(frames + 1, span)).then(|| {
                    format!("GLOBAL advanced only {frames} frames in {span} s between reads")
                })
            });
        self.samples.push_back((now, head));
        while self
            .samples
            .front()
            .is_some_and(|(t, _)| t + HEALTH_WINDOW_SECS < now)
        {
            self.samples.pop_front();
        }
        self.evaluate(now)
    }

    /// The head could not be read at `now`: time passes with no advance.
    pub(crate) fn unreadable(&mut self, now: u64) -> Option<Change> {
        self.sparse_gap = None;
        self.evaluate(now)
    }

    /// The reason the run is paused, if it is.
    pub(crate) fn degraded(&self) -> Option<&str> {
        self.degraded.as_ref().map(|d| d.reason.as_str())
    }

    /// The latest head seen.
    pub(crate) fn head(&self) -> Option<u64> {
        self.advanced.map(|(_, h)| h)
    }

    fn evaluate(&mut self, now: u64) -> Option<Change> {
        let (advanced_at, head) = self.advanced?;
        let silent = now.saturating_sub(advanced_at) >= STALL_SECS;
        let stalled = silent || self.sparse_gap.is_some();
        let Some(degraded) = self.degraded.as_mut() else {
            let reason = if silent {
                format!(
                    "GLOBAL head {head} has not advanced for {} s",
                    now - advanced_at
                )
            } else if let Some(gap) = self.sparse_gap.clone() {
                gap
            } else {
                self.slow(now, head)?
            };
            self.degraded = Some(Degraded {
                reason: reason.clone(),
                since: now,
                notice_at: now,
                healthy_since: None,
            });
            return Some(Change::Paused(reason));
        };
        if stalled {
            degraded.healthy_since = None;
        } else {
            let (from, from_head) = *degraded.healthy_since.get_or_insert((now, head));
            let span = now - from;
            if span >= RECOVERY_SECS {
                if rate_ok(head.saturating_sub(from_head), span) {
                    let paused_secs = now - degraded.since;
                    // The pause's own samples must not re-trigger the rule.
                    self.degraded = None;
                    self.samples.clear();
                    self.samples.push_back((now, head));
                    return Some(Change::Resumed { paused_secs });
                }
                // Advancing, but too slowly: judge again from here.
                degraded.healthy_since = Some((now, head));
            }
        }
        if now.saturating_sub(degraded.notice_at) >= NOTICE_SECS {
            degraded.notice_at = now;
            return Some(Change::StillPaused {
                secs: now - degraded.since,
                reason: degraded.reason.clone(),
            });
        }
        None
    }

    fn slow(&self, now: u64, head: u64) -> Option<String> {
        let &(first, first_head) = self.samples.front()?;
        let span = now.saturating_sub(first);
        if span < MIN_RATE_SPAN_SECS {
            return None;
        }
        let frames = head.saturating_sub(first_head);
        (!rate_ok(frames, span)).then(|| {
            format!(
                "GLOBAL advanced {frames} frames in {} min (~{}/h, below {MIN_FRAMES_PER_HOUR}/h)",
                span / 60,
                frames * 3_600 / span
            )
        })
    }
}

/// Whether `frames` over `span` seconds reach [`MIN_FRAMES_PER_HOUR`].
fn rate_ok(frames: u64, span: u64) -> bool {
    u128::from(frames) * 3_600 >= u128::from(MIN_FRAMES_PER_HOUR) * u128::from(span)
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
    /// After each batch: how many are done and the projected end.
    Progress {
        done: usize,
        total: usize,
        projected_end: u64,
    },
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
            Self::Progress {
                done,
                total,
                projected_end,
            } => format!(
                "Progress: {done}/{total} batches; projected end {}.",
                utc(*projected_end)
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
    /// The node's GLOBAL head.
    async fn head(&mut self) -> anyhow::Result<u64>;
    /// Legacy coins in batch `index`.
    fn coins(&self, index: usize) -> usize;
    /// The shard whose members verify batch `index` ([`shard_label`]).
    fn shard(&self, index: usize) -> String;
    /// Prove batch `index`; `None` when it is skipped (reported already).
    async fn prove(&mut self, index: usize) -> anyhow::Result<Option<Self::Proof>>;
    async fn submit(&mut self, index: usize, proof: Self::Proof) -> anyhow::Result<()>;
    /// Whether none of batch `index`'s coins still reads unshielded.
    async fn included(&mut self, index: usize) -> anyhow::Result<bool>;
    fn event(&mut self, event: &ShieldEvent);
}

async fn sample<I: ShieldIo>(io: &mut I, health: &mut Health, index: usize, total: usize) {
    let now = io.now();
    let change = match io.head().await {
        Ok(head) => health.observe(now, head),
        Err(_) => health.unreadable(now),
    };
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

/// Run `total` batches under `pacing`. Returns the batches submitted.
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
    for index in 0..total {
        sample(io, &mut health, index, total).await;
        let Some(proof) = io.prove(index).await? else {
            continue;
        };
        // Gate: GLOBAL healthy and the spacing since the last submission kept.
        let mut announced = false;
        loop {
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
        loop {
            io.sleep(POLL_SECS).await;
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
                anyhow::bail!(
                    "batch {}/{total}: its coins still read unshielded after {active} s of \
                     healthy GLOBAL since submission{}; stopping. The batch may still land: it \
                     commits with shard {}'s next frame, and shards have stalled 30 min or more \
                     after a frame carrying a batch. Check `qclient token legacy` before \
                     rerunning; {exclusion}.",
                    index + 1,
                    last_error.map_or(String::new(), |e| format!(" (last read error: {e})")),
                    io.shard(index)
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
    Ok(submitted)
}

#[cfg(test)]
#[path = "shield_pacing_tests.rs"]
mod tests;
