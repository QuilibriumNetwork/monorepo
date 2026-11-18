//! Named time sections inside one thread's GLOBAL frame execution. The
//! materializer collects them around its message loop and logs them when a
//! frame runs slow: the epoch-boundary lifecycle wave spends 90-190 ms per
//! message executing against about 30 ms validating, and these say where.
//! Sections nest, so an outer section's time includes its inner ones.
use std::cell::RefCell;
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub struct ArchiveActivity {
    pub seniority_checks: u64,
    pub seniority_same_frame: u64,
    pub seniority_reads_skipped: u64,
    pub seat_batch_lookups: u64,
    pub seat_lookups: u64,
    pub seat_misses: u64,
    pub seat_lookup: Duration,
    pub seat_decode: Duration,
}

thread_local! {
    static ACTIVITY: RefCell<Option<ArchiveActivity>> = const { RefCell::new(None) };
    static SECTIONS: RefCell<Option<Vec<(&'static str, u32, Duration)>>> = const { RefCell::new(None) };
}

/// Collect sections on this thread until the returned guard finishes or
/// drops, discarding any collected before.
#[must_use]
pub fn collect() -> Collection {
    collect_for_archive(false)
}

pub fn collect_for_archive(archive: bool) -> Collection {
    ACTIVITY.with(|activity| *activity.borrow_mut() = archive.then(ArchiveActivity::default));
    SECTIONS.with(|sections| *sections.borrow_mut() = Some(Vec::new()));
    Collection { finished: false }
}

fn stop() -> Vec<(&'static str, u32, Duration)> {
    SECTIONS.with(|sections| sections.borrow_mut().take().unwrap_or_default())
}

pub struct Collection {
    finished: bool,
}

impl Collection {
    /// Stop collecting; each section's name, times entered and total time,
    /// in first-entered order.
    pub fn finish(mut self) -> Vec<(&'static str, u32, Duration)> {
        self.finished = true;
        ACTIVITY.with(|activity| activity.borrow_mut().take());
        stop()
    }

    pub fn finish_with_activity(
        mut self,
    ) -> (Vec<(&'static str, u32, Duration)>, Option<ArchiveActivity>) {
        self.finished = true;
        (
            stop(),
            ACTIVITY.with(|activity| activity.borrow_mut().take()),
        )
    }
}

impl Drop for Collection {
    fn drop(&mut self) {
        if !self.finished {
            ACTIVITY.with(|activity| activity.borrow_mut().take());
            stop();
        }
    }
}

pub(crate) fn note_seniority_check(last: Option<u64>, frame: u64) {
    ACTIVITY.with(|activity| {
        if let Some(activity) = activity.borrow_mut().as_mut() {
            activity.seniority_checks += 1;
            activity.seniority_same_frame += u64::from(last == Some(frame));
        }
    });
}

pub(crate) fn note_cached_seniority(frame: u64) {
    note_seniority_check(Some(frame), frame);
    ACTIVITY.with_borrow_mut(|activity| {
        if let Some(a) = activity {
            a.seniority_reads_skipped += 1;
        }
    });
}

pub(crate) fn participant_batch_done(start: Instant, reads: usize, missing: usize) {
    ACTIVITY.with_borrow_mut(|activity| {
        if let Some(a) = activity {
            a.seat_batch_lookups += reads as u64;
            a.seat_lookups += reads as u64;
            a.seat_misses += missing as u64;
            a.seat_lookup += start.elapsed();
        }
    });
}

pub(crate) fn participant_lookup_start() -> Option<Instant> {
    ACTIVITY.with(|activity| activity.borrow().is_some().then(Instant::now))
}

pub(crate) fn participant_lookup_done(start: Instant, found: bool) -> Option<Instant> {
    let now = Instant::now();
    ACTIVITY.with(|activity| {
        if let Some(activity) = activity.borrow_mut().as_mut() {
            activity.seat_lookups += 1;
            activity.seat_misses += u64::from(!found);
            activity.seat_lookup += now - start;
        }
    });
    found.then_some(now)
}

pub(crate) fn participant_decode_done(start: Instant) {
    ACTIVITY.with(|activity| {
        if let Some(activity) = activity.borrow_mut().as_mut() {
            activity.seat_decode += start.elapsed();
        }
    });
}

/// Time the rest of the enclosing scope as `name`, while collection is on.
#[must_use]
pub fn section(name: &'static str) -> Section {
    let collecting = SECTIONS.with(|sections| sections.borrow().is_some());
    Section {
        name,
        started: collecting.then(Instant::now),
    }
}

pub struct Section {
    name: &'static str,
    started: Option<Instant>,
}

impl Drop for Section {
    fn drop(&mut self) {
        let Some(started) = self.started else { return };
        record_steps([(self.name, started.elapsed())]);
    }
}

/// Add steps already timed by a message to this frame's collection.
pub(crate) fn record_steps(steps: impl IntoIterator<Item = (&'static str, Duration)>) {
    SECTIONS.with(|sections| {
        if let Some(sections) = sections.borrow_mut().as_mut() {
            for (step, elapsed) in steps {
                match sections.iter_mut().find(|(name, _, _)| *name == step) {
                    Some((_, count, total)) => {
                        *count += 1;
                        *total += elapsed;
                    }
                    None => sections.push((step, 1, elapsed)),
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn regular_and_abandoned_frames_discard_archive_activity() {
        let archive = super::collect_for_archive(true);
        super::note_seniority_check(Some(4), 4);
        drop(archive);
        let regular = super::collect();
        super::note_seniority_check(Some(4), 4);
        assert!(super::participant_lookup_start().is_none());
        assert!(regular.finish_with_activity().1.is_none());
        let (_, fresh) = super::collect_for_archive(true).finish_with_activity();
        assert_eq!(fresh.unwrap().seniority_checks, 0);
    }

    #[test]
    fn sections_count_only_while_collecting_and_accumulate_by_name() {
        drop(super::section("before"));
        let collection = super::collect();
        for _ in 0..3 {
            let _outer = super::section("outer");
            drop(super::section("inner"));
        }
        let sections = collection.finish();
        let names: Vec<_> = sections
            .iter()
            .map(|(name, count, _)| (*name, *count))
            .collect();
        assert_eq!(names, vec![("inner", 3), ("outer", 3)]);
        drop(super::section("after"));
        // An abandoned collection stops too.
        drop(super::collect());
        drop(super::section("abandoned"));
        assert!(super::collect().finish().is_empty());
    }
}
