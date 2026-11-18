//! Where GLOBAL frame execution spends its time, by message type. A leader
//! executes and publishes the parent frame before it proposes, so execution
//! past the pacing budget adds directly to the frame interval; this says
//! which message types it went to.
//!
//! It logs overrun episodes, not frames: a committed execution past the
//! budget warns when an episode starts and at most every [`EPISODE_REPEAT`]
//! while it lasts, and one info line ends it. Every [`SUMMARY_INTERVAL`] one
//! info line sums up the executions. Executions for a proposal log only at
//! debug.
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use quil_execution::global_engine::peek_global_message_kind;
use quil_execution::message_envelope::{TYPE_MESSAGE_BUNDLE, TYPE_MESSAGE_REQUEST};

/// What a GLOBAL frame execution is for. It is set where each path builds
/// its materializer, never inferred from the private-branch flag, which a
/// publication shares with a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecutionRole {
    /// A selected parent and its ancestors, executed in a private branch
    /// before proposing on it and then discarded. The same frame executes
    /// again when it is published, so these are only counted: an overrun
    /// episode would count one frame twice.
    Proposal,
    /// A finalized or canonical frame, executed in a private branch and
    /// published in one batch.
    Publication,
    /// A frame executed directly in the canonical store.
    InPlace,
}

impl ExecutionRole {
    /// Whether its effects are kept: these drive overrun episodes and the
    /// interval's durations and types.
    pub fn committed(self) -> bool {
        !matches!(self, Self::Proposal)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Proposal => "proposal",
            Self::Publication => "publication",
            Self::InPlace => "in place",
        }
    }
}

/// Message types listed by name in a line; the rest are folded into one
/// entry, so a line stays bounded whatever a frame carries.
const KINDS_LISTED: usize = 6;

/// Execution sections listed by name in an overrun warning.
const SECTIONS_LISTED: usize = 8;

/// Prefix of the execution sections that apply a frame's due shard changes.
const DUE_CHANGES_PREFIX: &str = "due changes:";

/// Committed executions in a row within the budget that end an overrun
/// episode: about five minutes of 10 s frames, so frames alternating between
/// over and within the budget stay one episode.
const EPISODE_END_QUIET: u32 = 30;

/// Least time between two warnings of one overrun episode.
const EPISODE_REPEAT: Duration = Duration::from_secs(600);

/// How often the executions are summarized (as `stage_clock` does).
const SUMMARY_INTERVAL: Duration = Duration::from_secs(600);

/// The share of a GLOBAL frame interval its execution may take before it
/// delays the next proposal. The rest of the interval goes to the vote, the
/// quorum certificate, publication and building the next frame; on mainnet,
/// frames whose execution ran past about 7 of the 10 s came late by the
/// excess.
pub(crate) fn execution_budget(frame_number: u64) -> Duration {
    Duration::from_millis(quil_types::consensus::ideal_frame_time_ms_at(frame_number) * 7 / 10)
}

/// The message type of one canonical bundle: its op labels, each once, in
/// sorted order and joined by `+`. A bundle executes as a whole, so a
/// bundle of several types counts under their combination.
///
/// It runs for every bundle inside the timed execution, so it reads only
/// the length prefixes and each request's type prefix in place, copying
/// nothing of the bundle (up to 16 MiB a frame).
pub(crate) fn bundle_kind(raw: &[u8]) -> String {
    let Some(labels) = bundle_labels(raw) else {
        return "undecodable".into();
    };
    if labels.is_empty() {
        "empty".into()
    } else {
        labels.join("+")
    }
}

fn u32_at(raw: &[u8], at: usize) -> Option<u32> {
    let bytes = raw.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

/// The distinct op labels of a canonical bundle, sorted, or `None` where
/// the bundle does not decode (the layout `CanonicalMessageBundle` reads).
fn bundle_labels(raw: &[u8]) -> Option<Vec<&'static str>> {
    if u32_at(raw, 0)? != TYPE_MESSAGE_BUNDLE {
        return None;
    }
    let requests = u32_at(raw, 4)?;
    let mut at = 8usize;
    let mut labels: Vec<&'static str> = Vec::new();
    for _ in 0..requests {
        let len = usize::try_from(u32_at(raw, at)?).ok()?;
        at += 4;
        if len == 0 {
            continue;
        }
        let request = raw.get(at..at.checked_add(len)?)?;
        at += len;
        if u32_at(request, 0)? != TYPE_MESSAGE_REQUEST {
            return None;
        }
        let inner_len = usize::try_from(u32_at(request, 4)?).ok()?;
        let inner = request.get(8..8usize.checked_add(inner_len)?)?;
        if inner.len() < 4 {
            return None;
        }
        let label = peek_global_message_kind(inner).map_or("other", |kind| kind.label());
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    // The timestamp closes the bundle.
    raw.get(at..at.checked_add(8)?)?;
    labels.sort_unstable();
    Some(labels)
}

/// One message type's executions.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KindTotals {
    pub messages: u64,
    pub validate_us: u64,
    pub process_us: u64,
    pub max_us: u64,
}

impl KindTotals {
    pub fn total_us(&self) -> u64 {
        self.validate_us.saturating_add(self.process_us)
    }

    fn add(&mut self, other: &KindTotals) {
        self.messages += other.messages;
        self.validate_us = self.validate_us.saturating_add(other.validate_us);
        self.process_us = self.process_us.saturating_add(other.process_us);
        self.max_us = self.max_us.max(other.max_us);
    }
}

/// Message types costliest first, ties by name.
fn ranked(kinds: HashMap<String, KindTotals>) -> Vec<(String, KindTotals)> {
    let mut kinds: Vec<_> = kinds.into_iter().collect();
    kinds.sort_by(|a, b| {
        b.1.total_us()
            .cmp(&a.1.total_us())
            .then_with(|| a.0.cmp(&b.0))
    });
    kinds
}

fn merge(into: &mut HashMap<String, KindTotals>, kinds: &[(String, KindTotals)]) {
    for (kind, totals) in kinds {
        into.entry(kind.clone()).or_default().add(totals);
    }
}

/// `type messages×ms` per type in the given (costliest first) order; past
/// [`KINDS_LISTED`] types, one `N more types` entry.
fn by_kind(kinds: &[(String, KindTotals)]) -> String {
    let mut parts: Vec<String> = kinds
        .iter()
        .take(KINDS_LISTED)
        .map(|(kind, totals)| format!("{kind} {}×{} ms", totals.messages, totals.total_us() / 1000))
        .collect();
    let rest = &kinds[kinds.len().min(KINDS_LISTED)..];
    if !rest.is_empty() {
        let messages: u64 = rest.iter().map(|(_, totals)| totals.messages).sum();
        let us: u64 = rest.iter().map(|(_, totals)| totals.total_us()).sum();
        parts.push(format!(
            "{} more types {messages}×{} ms",
            rest.len(),
            us / 1000
        ));
    }
    parts.join(", ")
}

fn millis(time: Duration) -> u64 {
    u64::try_from(time.as_millis()).unwrap_or(u64::MAX)
}

/// Message executions of one frame, by type.
#[derive(Debug, Default)]
pub(crate) struct ExecutionTally {
    kinds: HashMap<String, KindTotals>,
}

impl ExecutionTally {
    /// Count one message of type `kind` that took `validate_us` to validate
    /// and `process_us` to process (0 when validation refused it).
    pub fn record(&mut self, kind: String, validate_us: u64, process_us: u64) {
        let totals = self.kinds.entry(kind).or_default();
        let total = validate_us.saturating_add(process_us);
        totals.messages += 1;
        totals.validate_us = totals.validate_us.saturating_add(validate_us);
        totals.process_us = totals.process_us.saturating_add(process_us);
        totals.max_us = totals.max_us.max(total);
    }

    /// The summary of a frame whose execution took `total`, with the named
    /// sections (name, times entered, time) the intrinsics marked.
    pub fn summarize(
        self,
        total: Duration,
        budget: Duration,
        sections: Vec<(&'static str, u32, Duration)>,
    ) -> ExecutionSummary {
        let kinds = ranked(self.kinds);
        let due_changes = sections
            .iter()
            .filter(|(name, _, _)| name.starts_with(DUE_CHANGES_PREFIX))
            .map(|(_, _, time)| *time)
            .sum();
        let mut sections = sections;
        sections.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(b.0)));
        ExecutionSummary {
            total,
            budget,
            kinds,
            due_changes,
            activity: None,
            sections,
        }
    }
}

/// One frame execution's time: in total, by message type (costliest
/// first), in due shard changes, and by section (longest first).
#[derive(Debug)]
pub(crate) struct ExecutionSummary {
    pub activity: Option<quil_execution::step_timing::ArchiveActivity>,
    pub total: Duration,
    pub budget: Duration,
    pub kinds: Vec<(String, KindTotals)>,
    pub due_changes: Duration,
    pub sections: Vec<(&'static str, u32, Duration)>,
}

impl ExecutionSummary {
    pub fn messages(&self) -> u64 {
        self.kinds.iter().map(|(_, totals)| totals.messages).sum()
    }

    pub fn overran(&self) -> bool {
        self.total > self.budget
    }

    /// The costliest message type and its total time in ms.
    pub fn top(&self) -> (&str, u64) {
        self.kinds.first().map_or(("none", 0), |(kind, totals)| {
            (kind.as_str(), totals.total_us() / 1000)
        })
    }

    /// `type messages×ms` per type, costliest first, bounded.
    pub fn by_kind(&self) -> String {
        by_kind(&self.kinds)
    }

    /// The costliest type's validation and processing split and slowest
    /// message, for an overrun warning.
    pub fn top_detail(&self) -> String {
        self.kinds.first().map_or_else(String::new, |(_, totals)| {
            format!(
                "validate {} ms, process {} ms, slowest {} ms",
                totals.validate_us / 1000,
                totals.process_us / 1000,
                totals.max_us / 1000
            )
        })
    }

    /// The longest sections, for an overrun warning. Sections nest, so an
    /// outer one includes its inner ones.
    pub fn top_sections(&self) -> String {
        self.sections
            .iter()
            .take(SECTIONS_LISTED)
            .map(|(name, n, time)| format!("{name} {n}×{} ms", time.as_millis()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// An overrun episode so far: committed executions from the first one past
/// the budget on, within it included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EpisodeReport {
    pub first_frame: u64,
    pub last_overrun_frame: u64,
    pub executions: u32,
    pub overruns: u32,
    pub max_ms: u64,
    pub secs: u64,
    /// Message types of the overrunning executions, costliest first.
    pub kinds: Vec<(String, KindTotals)>,
}

/// The executions of one summary interval. Durations, frames and types are
/// of committed executions; those for a proposal and attempts abandoned
/// before they committed are only counted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IntervalReport {
    pub window_secs: u64,
    pub first_frame: u64,
    pub last_frame: u64,
    pub executions: u32,
    pub over_budget: u32,
    pub p50_ms: u64,
    pub max_ms: u64,
    pub budget_ms: u64,
    pub due_changes_ms: u64,
    pub proposals: u32,
    pub proposals_over_budget: u32,
    pub abandoned: u32,
    pub kinds: Vec<(String, KindTotals)>,
}

/// What one execution logs.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Report {
    /// An execution for a proposal: a debug line only.
    Proposal,
    /// A committed execution overran with no episode open: it opens one.
    OverrunStarted,
    /// A committed execution overran [`EPISODE_REPEAT`] or more after the
    /// episode's last warning.
    OverrunContinues(EpisodeReport),
    /// [`EPISODE_END_QUIET`] committed executions in a row stayed within
    /// the budget: the episode is over.
    OverrunEnded(EpisodeReport),
    /// The summary interval is over.
    Interval(IntervalReport),
}

#[derive(Debug)]
struct Episode {
    first_frame: u64,
    last_overrun_frame: u64,
    executions: u32,
    overruns: u32,
    max_ms: u64,
    quiet: u32,
    started: Instant,
    warned: Instant,
    kinds: HashMap<String, KindTotals>,
}

impl Episode {
    fn start(frame: u64, summary: &ExecutionSummary, now: Instant) -> Self {
        let mut episode = Self {
            first_frame: frame,
            last_overrun_frame: frame,
            executions: 0,
            overruns: 0,
            max_ms: 0,
            quiet: 0,
            started: now,
            warned: now,
            kinds: HashMap::new(),
        };
        episode.overrun(frame, summary);
        episode
    }

    fn overrun(&mut self, frame: u64, summary: &ExecutionSummary) {
        self.last_overrun_frame = frame;
        self.executions += 1;
        self.overruns += 1;
        self.quiet = 0;
        self.max_ms = self.max_ms.max(millis(summary.total));
        merge(&mut self.kinds, &summary.kinds);
    }

    fn report(&self, now: Instant) -> EpisodeReport {
        EpisodeReport {
            first_frame: self.first_frame,
            last_overrun_frame: self.last_overrun_frame,
            executions: self.executions,
            overruns: self.overruns,
            max_ms: self.max_ms,
            secs: now.saturating_duration_since(self.started).as_secs(),
            kinds: ranked(self.kinds.clone()),
        }
    }
}

#[derive(Debug)]
struct Interval {
    started: Instant,
    first_frame: Option<u64>,
    last_frame: u64,
    durations_ms: Vec<u64>,
    over_budget: u32,
    budget: Duration,
    due_changes: Duration,
    proposals: u32,
    proposals_over_budget: u32,
    abandoned: u32,
    kinds: HashMap<String, KindTotals>,
}

impl Interval {
    fn new(now: Instant) -> Self {
        Self {
            started: now,
            first_frame: None,
            last_frame: 0,
            durations_ms: Vec::new(),
            over_budget: 0,
            budget: Duration::ZERO,
            due_changes: Duration::ZERO,
            proposals: 0,
            proposals_over_budget: 0,
            abandoned: 0,
            kinds: HashMap::new(),
        }
    }

    fn committed(&mut self, frame: u64, summary: &ExecutionSummary) {
        self.first_frame.get_or_insert(frame);
        self.last_frame = frame;
        self.durations_ms.push(millis(summary.total));
        self.over_budget += u32::from(summary.overran());
        self.due_changes += summary.due_changes;
        merge(&mut self.kinds, &summary.kinds);
    }

    /// The report of the interval ending at `now`, if it is over; starts
    /// the next interval.
    fn take_due(&mut self, now: Instant) -> Option<IntervalReport> {
        let window = now.saturating_duration_since(self.started);
        if window < SUMMARY_INTERVAL {
            return None;
        }
        let mut done = std::mem::replace(self, Interval::new(now));
        done.durations_ms.sort_unstable();
        Some(IntervalReport {
            window_secs: window.as_secs(),
            first_frame: done.first_frame.unwrap_or(0),
            last_frame: done.last_frame,
            executions: u32::try_from(done.durations_ms.len()).unwrap_or(u32::MAX),
            over_budget: done.over_budget,
            p50_ms: done
                .durations_ms
                .get(done.durations_ms.len() / 2)
                .copied()
                .unwrap_or(0),
            max_ms: done.durations_ms.last().copied().unwrap_or(0),
            budget_ms: millis(done.budget),
            due_changes_ms: millis(done.due_changes),
            proposals: done.proposals,
            proposals_over_budget: done.proposals_over_budget,
            abandoned: done.abandoned,
            kinds: ranked(done.kinds),
        })
    }
}

/// Decides what each GLOBAL frame execution logs: overrun episodes of
/// committed executions and a summary per interval.
#[derive(Debug, Default)]
pub(crate) struct ExecutionMonitor {
    episode: Option<Episode>,
    interval: Option<Interval>,
}

impl ExecutionMonitor {
    pub const fn new() -> Self {
        Self {
            episode: None,
            interval: None,
        }
    }

    /// What the execution of `frame` for `role` described by `summary`,
    /// ended at `now`, logs.
    pub fn observe(
        &mut self,
        frame: u64,
        role: ExecutionRole,
        summary: &ExecutionSummary,
        now: Instant,
    ) -> Vec<Report> {
        let mut reports = Vec::new();
        let interval = self.interval.get_or_insert_with(|| Interval::new(now));
        interval.budget = summary.budget;
        if !role.committed() {
            interval.proposals += 1;
            interval.proposals_over_budget += u32::from(summary.overran());
            reports.push(Report::Proposal);
        } else {
            interval.committed(frame, summary);
            reports.extend(self.episode_step(frame, summary, now));
        }
        if let Some(report) = self.interval.as_mut().and_then(|i| i.take_due(now)) {
            reports.push(Report::Interval(report));
        }
        reports
    }

    /// An execution abandoned before its effects committed, ended at
    /// `now`: counted, but its time, types and overrun are not, since the
    /// frame executes again on a later attempt.
    pub fn abandon(&mut self, now: Instant) {
        self.interval
            .get_or_insert_with(|| Interval::new(now))
            .abandoned += 1;
    }

    fn episode_step(
        &mut self,
        frame: u64,
        summary: &ExecutionSummary,
        now: Instant,
    ) -> Option<Report> {
        if summary.overran() {
            let Some(episode) = self.episode.as_mut() else {
                self.episode = Some(Episode::start(frame, summary, now));
                return Some(Report::OverrunStarted);
            };
            episode.overrun(frame, summary);
            if now.saturating_duration_since(episode.warned) < EPISODE_REPEAT {
                return None;
            }
            episode.warned = now;
            return Some(Report::OverrunContinues(episode.report(now)));
        }
        let episode = self.episode.as_mut()?;
        episode.executions += 1;
        episode.quiet += 1;
        if episode.quiet < EPISODE_END_QUIET {
            return None;
        }
        let report = episode.report(now);
        self.episode = None;
        Some(Report::OverrunEnded(report))
    }
}

/// Every GLOBAL frame execution of this node, for proposals included.
static MONITOR: Mutex<ExecutionMonitor> = Mutex::new(ExecutionMonitor::new());

#[cfg(test)]
thread_local! {
    /// The executions this thread observed: frame and role.
    static OBSERVED: std::cell::RefCell<Vec<(u64, ExecutionRole)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// The executions this thread observed since the last call.
#[cfg(test)]
pub(crate) fn take_observed() -> Vec<(u64, ExecutionRole)> {
    OBSERVED.with(|observed| std::mem::take(&mut *observed.borrow_mut()))
}

#[cfg(test)]
thread_local! {
    /// The executions this thread abandoned before they committed.
    static ABANDONED: std::cell::RefCell<Vec<(u64, ExecutionRole)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// The executions this thread abandoned since the last call.
#[cfg(test)]
pub(crate) fn take_abandoned() -> Vec<(u64, ExecutionRole)> {
    ABANDONED.with(|abandoned| std::mem::take(&mut *abandoned.borrow_mut()))
}

/// An execution not yet recorded: [`Self::completed`] records it once its
/// effects are committed (for a proposal: once it finished). Dropped before
/// that, by an error or unwinding past it, it counts only as abandoned, so a
/// publication retried after a commit conflict is recorded once.
#[derive(Debug)]
pub(crate) struct PendingExecution {
    frame: u64,
    role: ExecutionRole,
    summary: Option<ExecutionSummary>,
}

impl PendingExecution {
    pub fn new(frame: u64, role: ExecutionRole, summary: ExecutionSummary) -> Self {
        Self {
            frame,
            role,
            summary: Some(summary),
        }
    }

    pub fn completed(mut self) {
        if let Some(summary) = self.summary.take() {
            observe_execution(self.frame, self.role, summary);
        }
    }
}

impl Drop for PendingExecution {
    fn drop(&mut self) {
        if self.summary.take().is_none() {
            return;
        }
        #[cfg(test)]
        ABANDONED.with(|abandoned| abandoned.borrow_mut().push((self.frame, self.role)));
        MONITOR
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .abandon(Instant::now());
        tracing::debug!(
            frame = self.frame,
            role = self.role.label(),
            "GLOBAL frame execution abandoned before it committed; counted as abandoned only"
        );
    }
}

/// Logs what the execution of `frame` for `role` described by `summary`
/// calls for.
fn observe_execution(frame: u64, role: ExecutionRole, summary: ExecutionSummary) {
    #[cfg(test)]
    OBSERVED.with(|observed| observed.borrow_mut().push((frame, role)));
    let reports = MONITOR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .observe(frame, role, &summary, Instant::now());
    for report in reports {
        log(frame, role, &summary, report);
    }
}

fn log(frame: u64, role: ExecutionRole, summary: &ExecutionSummary, report: Report) {
    let (top_kind, top_ms) = summary.top();
    let total_ms = millis(summary.total);
    let budget_ms = millis(summary.budget);
    let due_changes_ms = millis(summary.due_changes);
    let role = role.label();
    match report {
        Report::Proposal => tracing::debug!(
            frame,
            total_ms,
            budget_ms,
            messages = summary.messages(),
            top_kind,
            top_ms,
            due_changes_ms,
            by_kind = %summary.by_kind(),
            "GLOBAL frame executed for a proposal: messages and execution time by type, costliest \
             first"
        ),
        Report::OverrunStarted => tracing::warn!(
            frame,
            role,
            total_ms,
            budget_ms,
            messages = summary.messages(),
            top_kind,
            top_ms,
            top_detail = %summary.top_detail(),
            due_changes_ms,
            by_kind = %summary.by_kind(),
            sections = %summary.top_sections(),
            seniority_checks = summary.activity.as_ref().map(|a| a.seniority_checks),
            seniority_reads_skipped = summary.activity.as_ref().map(|a| a.seniority_reads_skipped),
            seat_batch_lookups = summary.activity.as_ref().map(|a| a.seat_batch_lookups),
            seniority_same_frame = summary.activity.as_ref().map(|a| a.seniority_same_frame),
            seat_lookups = summary.activity.as_ref().map(|a| a.seat_lookups),
            seat_misses = summary.activity.as_ref().map(|a| a.seat_misses),
            seat_lookup_ms = summary.activity.as_ref().map(|a| a.seat_lookup.as_millis() as u64),
            seat_decode_ms = summary.activity.as_ref().map(|a| a.seat_decode.as_millis() as u64),
            "GLOBAL frame execution overran its pacing budget: the next proposal waits on it, so \
             the frame interval grows by the excess; top_kind took the most time. Nodes executing \
             GLOBAL frames run the same messages: a total far above other such nodes' points at \
             this node's load (CPU, disk), a similar one at top_kind. While overruns go on this \
             repeats at most every 10 min; an info line says when they stop"
        ),
        Report::OverrunContinues(episode) => tracing::warn!(
            frame,
            role,
            total_ms,
            budget_ms,
            messages = summary.messages(),
            top_kind,
            top_ms,
            top_detail = %summary.top_detail(),
            due_changes_ms,
            by_kind = %summary.by_kind(),
            sections = %summary.top_sections(),
            seniority_checks = summary.activity.as_ref().map(|a| a.seniority_checks),
            seniority_reads_skipped = summary.activity.as_ref().map(|a| a.seniority_reads_skipped),
            seat_batch_lookups = summary.activity.as_ref().map(|a| a.seat_batch_lookups),
            seniority_same_frame = summary.activity.as_ref().map(|a| a.seniority_same_frame),
            seat_lookups = summary.activity.as_ref().map(|a| a.seat_lookups),
            seat_misses = summary.activity.as_ref().map(|a| a.seat_misses),
            seat_lookup_ms = summary.activity.as_ref().map(|a| a.seat_lookup.as_millis() as u64),
            seat_decode_ms = summary.activity.as_ref().map(|a| a.seat_decode.as_millis() as u64),
            since_frame = episode.first_frame,
            overruns = episode.overruns,
            executions = episode.executions,
            max_ms = episode.max_ms,
            episode_secs = episode.secs,
            episode_by_kind = %by_kind(&episode.kinds),
            "GLOBAL frame execution still overrunning its pacing budget: overruns of the \
             executions since since_frame took longer than budget_ms; episode_by_kind sums the \
             overrunning ones by type"
        ),
        Report::OverrunEnded(episode) => tracing::info!(
            since_frame = episode.first_frame,
            last_overrun_frame = episode.last_overrun_frame,
            overruns = episode.overruns,
            executions = episode.executions,
            max_ms = episode.max_ms,
            episode_secs = episode.secs,
            budget_ms,
            quiet_executions = EPISODE_END_QUIET,
            by_kind = %by_kind(&episode.kinds),
            "GLOBAL frame execution back within its pacing budget for quiet_executions frames: \
             the overrun episode ended; by_kind sums its overrunning executions by type"
        ),
        Report::Interval(interval) => tracing::info!(
            window_secs = interval.window_secs,
            first_frame = interval.first_frame,
            last_frame = interval.last_frame,
            executions = interval.executions,
            over_budget = interval.over_budget,
            p50_ms = interval.p50_ms,
            max_ms = interval.max_ms,
            budget_ms = interval.budget_ms,
            due_changes_ms = interval.due_changes_ms,
            proposals = interval.proposals,
            proposals_over_budget = interval.proposals_over_budget,
            abandoned = interval.abandoned,
            by_kind = %by_kind(&interval.kinds),
            "GLOBAL frame executions in the last interval: committed executions (published or \
             in place), those over budget_ms, their median and longest time, and time by message \
             type, costliest first; executions for a proposal and attempts abandoned before they \
             committed only counted"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn summary_counts_and_attributes_time_by_message_type() {
        let mut tally = ExecutionTally::default();
        tally.record("shard".into(), 1_000, 9_000);
        tally.record("prover_confirm".into(), 4_000, 26_000);
        tally.record("shard".into(), 2_000, 18_000);
        // Refused at validation: counted, no processing time.
        tally.record("prover_confirm".into(), 5_000, 0);
        tally.record("prover_join".into(), 500, 1_500);
        for i in 0..6 {
            tally.record(format!("kind_{i}"), 100, 0);
        }
        let sections = vec![
            ("filter op: verify signature", 3, ms(20)),
            ("due changes: topology", 1, ms(40)),
            ("due changes: pending repair", 1, ms(2)),
            ("confirm: pending shard changes", 2, ms(7)),
        ];
        let summary = tally.summarize(ms(12_000), ms(7_000), sections);

        assert_eq!(summary.messages(), 11, "messages_counted");
        assert_eq!(summary.top(), ("prover_confirm", 35), "top_kind");
        let order: Vec<_> = summary
            .kinds
            .iter()
            .map(|(kind, _)| kind.as_str())
            .collect();
        assert_eq!(
            &order[..3],
            ["prover_confirm", "shard", "prover_join"],
            "kind_order"
        );
        let confirm = summary.kinds[0].1;
        assert_eq!(
            confirm,
            KindTotals {
                messages: 2,
                validate_us: 9_000,
                process_us: 26_000,
                max_us: 30_000,
            },
            "confirm_totals"
        );
        assert_eq!(summary.kinds[1].1.messages, 2);
        assert_eq!(summary.kinds[1].1.total_us(), 30_000);
        assert_eq!(summary.due_changes, ms(42), "due_changes_ms");
        assert!(summary.overran());
        assert_eq!(
            summary.by_kind(),
            "prover_confirm 2×35 ms, shard 2×30 ms, prover_join 1×2 ms, \
             kind_0 1×0 ms, kind_1 1×0 ms, kind_2 1×0 ms, 3 more types 3×0 ms",
            "by_kind_bounded"
        );
        assert_eq!(
            summary.top_detail(),
            "validate 9 ms, process 26 ms, slowest 30 ms"
        );
        assert!(summary
            .top_sections()
            .starts_with("due changes: topology 1×40 ms, filter op: verify signature 3×20 ms"));

        let quiet = ExecutionTally::default().summarize(ms(10), ms(7_000), Vec::new());
        assert_eq!((quiet.messages(), quiet.top()), (0, ("none", 0)));
        assert!(!quiet.overran());
        assert_eq!(quiet.by_kind(), "");
    }

    #[test]
    fn a_bundle_counts_under_its_op_types_each_once() {
        use quil_execution::global_engine::MessageKindGlobal;
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        let bundle = |prefixes: &[u32]| {
            CanonicalMessageBundle {
                requests: prefixes
                    .iter()
                    .map(|prefix| {
                        Some(CanonicalMessageRequest {
                            inner_type_prefix: *prefix,
                            inner_bytes: prefix.to_be_bytes().to_vec(),
                        })
                    })
                    .collect(),
                timestamp: 0,
            }
            .to_canonical_bytes()
            .unwrap()
        };
        let confirm = MessageKindGlobal::ProverConfirm.type_prefix();
        let join = MessageKindGlobal::ProverJoin.type_prefix();
        assert_eq!(bundle_kind(&bundle(&[confirm])), "prover_confirm");
        assert_eq!(
            bundle_kind(&bundle(&[confirm, join, confirm, 0xdead_beef])),
            "other+prover_confirm+prover_join",
            "bundle_kind_once"
        );
        assert_eq!(bundle_kind(&bundle(&[])), "empty");
        assert_eq!(bundle_kind(&[1, 2, 3]), "undecodable");
    }

    /// The in-place peek accepts exactly the bundles the decoder accepts and
    /// finds the same types in them.
    #[test]
    fn the_kind_peek_reads_a_bundle_as_the_decoder_does() {
        use quil_execution::global_engine::MessageKindGlobal;
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        let confirm = MessageKindGlobal::ProverConfirm.type_prefix();
        let join = MessageKindGlobal::ProverJoin.type_prefix();
        let request = |inner: Vec<u8>| {
            Some(CanonicalMessageRequest {
                inner_type_prefix: 0,
                inner_bytes: inner,
            })
        };
        let mut body = confirm.to_be_bytes().to_vec();
        body.extend_from_slice(&[7; 40]);
        let well_formed = CanonicalMessageBundle {
            requests: vec![request(body), None, request(join.to_be_bytes().to_vec())],
            timestamp: 5,
        }
        .to_canonical_bytes()
        .unwrap();
        let short_inner = CanonicalMessageBundle {
            requests: vec![request(vec![1, 2])],
            timestamp: 5,
        }
        .to_canonical_bytes()
        .unwrap();
        let mut wrong_request_tag = well_formed.clone();
        wrong_request_tag[12] ^= 0xff;
        let mut wrong_bundle_tag = well_formed.clone();
        wrong_bundle_tag[0] ^= 0xff;
        let mut more_requests = well_formed.clone();
        more_requests[7] += 1;
        let end = well_formed.len();
        let cases = [
            ("well formed", well_formed.clone()),
            ("no timestamp", well_formed[..end - 8].to_vec()),
            ("short timestamp", well_formed[..end - 1].to_vec()),
            ("short inner", short_inner),
            ("request tag", wrong_request_tag),
            ("bundle tag", wrong_bundle_tag),
            ("more requests than bytes", more_requests),
            ("empty input", Vec::new()),
        ];
        for (case, raw) in cases {
            let decoded = CanonicalMessageBundle::from_canonical_bytes(&raw).ok();
            let expected = decoded.map_or_else(
                || "undecodable".to_string(),
                |bundle| {
                    let mut labels: Vec<_> = bundle
                        .requests
                        .iter()
                        .flatten()
                        .map(|r| {
                            peek_global_message_kind(&r.inner_bytes).map_or("other", |k| k.label())
                        })
                        .collect();
                    labels.sort_unstable();
                    labels.dedup();
                    if labels.is_empty() {
                        "empty".to_string()
                    } else {
                        labels.join("+")
                    }
                },
            );
            assert_eq!(bundle_kind(&raw), expected, "peek_differs: {case}");
        }
        assert_eq!(bundle_kind(&well_formed), "prover_confirm+prover_join");
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// A summary of an execution that took `total_ms`, one message per type.
    fn summary_of(total_ms: u64, kinds: &[(&str, u64)]) -> ExecutionSummary {
        let mut tally = ExecutionTally::default();
        for (kind, process_ms) in kinds {
            tally.record((*kind).into(), 0, process_ms * 1000);
        }
        tally.summarize(ms(total_ms), ms(7_000), Vec::new())
    }

    /// The reports other than the interval summary.
    fn episode(reports: Vec<Report>) -> Vec<Report> {
        reports
            .into_iter()
            .filter(|report| !matches!(report, Report::Interval(_)))
            .collect()
    }

    #[test]
    fn proposal_executions_never_warn() {
        let mut monitor = ExecutionMonitor::new();
        let t0 = Instant::now();
        let slow = summary_of(9_000, &[("shard", 8_000)]);
        for i in 0..3 {
            assert_eq!(
                monitor.observe(10 + i, ExecutionRole::Proposal, &slow, t0 + secs(i)),
                vec![Report::Proposal],
                "proposal_warned"
            );
        }
        assert_eq!(
            monitor.observe(13, ExecutionRole::Publication, &slow, t0 + secs(3)),
            vec![Report::OverrunStarted],
            "committed_overrun_started"
        );
    }

    #[test]
    fn an_overrun_episode_warns_at_start_bounded_repeats_and_ends_once() {
        let mut monitor = ExecutionMonitor::new();
        let t0 = Instant::now();
        let fast = summary_of(3_000, &[("shard", 2_000)]);
        let slow = summary_of(9_000, &[("prover_confirm", 6_000), ("shard", 2_000)]);
        let mut observe = |frame: u64, summary: &ExecutionSummary, at: u64| {
            episode(monitor.observe(frame, ExecutionRole::Publication, summary, t0 + secs(at)))
        };

        assert!(observe(1, &fast, 0).is_empty(), "under_budget_logged");
        assert_eq!(observe(2, &slow, 10), vec![Report::OverrunStarted]);
        // Alternating within the repeat bound: neither a repeat nor an end.
        let (mut frame, mut at) = (3, 20);
        while at < 600 {
            assert!(observe(frame, &fast, at).is_empty(), "quiet_ended_early");
            assert!(
                observe(frame + 1, &slow, at + 10).is_empty(),
                "repeat_unbounded"
            );
            frame += 2;
            at += 20;
        }
        // The start, 29 within and 29 over the budget, and this one.
        let expected = |last_overrun_frame, executions, secs| EpisodeReport {
            first_frame: 2,
            last_overrun_frame,
            executions,
            overruns: 31,
            max_ms: 9_000,
            secs,
            kinds: vec![
                (
                    "prover_confirm".into(),
                    KindTotals {
                        messages: 31,
                        validate_us: 0,
                        process_us: 186_000_000,
                        max_us: 6_000_000,
                    },
                ),
                (
                    "shard".into(),
                    KindTotals {
                        messages: 31,
                        validate_us: 0,
                        process_us: 62_000_000,
                        max_us: 2_000_000,
                    },
                ),
            ],
        };
        assert_eq!(
            observe(frame, &slow, at + 10),
            vec![Report::OverrunContinues(expected(frame, 60, 600))],
            "repeat_missing"
        );
        let last_overrun = frame;
        at += 20;
        for _ in 1..EPISODE_END_QUIET {
            frame += 1;
            assert!(observe(frame, &fast, at).is_empty(), "quiet_ended_early");
            at += 10;
        }
        frame += 1;
        assert_eq!(
            observe(frame, &fast, at),
            vec![Report::OverrunEnded(expected(
                last_overrun,
                60 + EPISODE_END_QUIET,
                at - 10
            ))],
            "episode_end"
        );
        assert!(observe(frame + 1, &fast, at + 10).is_empty(), "ended_twice");
        assert_eq!(
            observe(frame + 2, &slow, at + 20),
            vec![Report::OverrunStarted],
            "next_episode"
        );
    }

    #[test]
    fn the_interval_summary_counts_durations_and_costliest_types() {
        let mut monitor = ExecutionMonitor::new();
        let t0 = Instant::now();
        let (publication, proposal, in_place) = (
            ExecutionRole::Publication,
            ExecutionRole::Proposal,
            ExecutionRole::InPlace,
        );
        let executions = [
            (1, publication, summary_of(3_000, &[("shard", 2_000)])),
            (2, in_place, summary_of(9_000, &[("prover_confirm", 8_000)])),
            (3, proposal, summary_of(9_000, &[("prover_confirm", 8_000)])),
            (4, publication, summary_of(5_000, &[("shard", 4_000)])),
            (5, publication, summary_of(1_000, &[("shard", 500)])),
        ];
        for (i, (frame, role, summary)) in executions.iter().enumerate() {
            let reports = monitor.observe(*frame, *role, summary, t0 + secs(i as u64 * 100));
            assert!(
                !reports.iter().any(|r| matches!(r, Report::Interval(_))),
                "interval_early"
            );
        }
        // A publication attempt abandoned on a commit conflict: counted only.
        monitor.abandon(t0 + secs(550));
        let last = summary_of(4_000, &[("prover_join", 3_000)]);
        let reports = monitor.observe(6, ExecutionRole::Publication, &last, t0 + secs(600));
        let Some(Report::Interval(interval)) = reports.last() else {
            panic!("interval_missing: {reports:?}");
        };
        assert_eq!(
            (
                interval.window_secs,
                interval.first_frame,
                interval.last_frame,
                interval.executions,
                interval.over_budget,
                interval.proposals,
                interval.proposals_over_budget,
                interval.abandoned,
            ),
            (600, 1, 6, 5, 1, 1, 1, 1),
            "interval_counts"
        );
        assert_eq!(
            (interval.p50_ms, interval.max_ms, interval.budget_ms),
            (4_000, 9_000, 7_000),
            "interval_durations"
        );
        assert_eq!(
            by_kind(&interval.kinds),
            "prover_confirm 1×8000 ms, shard 3×6500 ms, prover_join 1×3000 ms",
            "interval_kinds"
        );
        // The next interval starts empty.
        let reports = monitor.observe(7, ExecutionRole::Publication, &last, t0 + secs(1_200));
        let Some(Report::Interval(next)) = reports.last() else {
            panic!("interval_missing: {reports:?}");
        };
        assert_eq!(
            (next.first_frame, next.executions),
            (7, 1),
            "interval_reset"
        );
    }
}
