//! Named time sections inside one thread's GLOBAL frame execution. The
//! materializer collects them around its message loop and logs them when a
//! frame runs slow: the epoch-boundary lifecycle wave spends 90-190 ms per
//! message executing against about 30 ms validating, and these say where.
//! Sections nest, so an outer section's time includes its inner ones.
use std::cell::RefCell;
use std::time::{Duration, Instant};

thread_local! {
    static SECTIONS: RefCell<Option<Vec<(&'static str, u32, Duration)>>> = const { RefCell::new(None) };
}

/// Collect sections on this thread until the returned guard finishes or
/// drops, discarding any collected before.
#[must_use]
pub fn collect() -> Collection {
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
        stop()
    }
}

impl Drop for Collection {
    fn drop(&mut self) {
        if !self.finished {
            stop();
        }
    }
}

/// Time the rest of the enclosing scope as `name`, while collection is on.
#[must_use]
pub fn section(name: &'static str) -> Section {
    let collecting = SECTIONS.with(|sections| sections.borrow().is_some());
    Section { name, started: collecting.then(Instant::now) }
}

pub struct Section {
    name: &'static str,
    started: Option<Instant>,
}

impl Drop for Section {
    fn drop(&mut self) {
        let Some(started) = self.started else { return };
        let elapsed = started.elapsed();
        SECTIONS.with(|sections| {
            if let Some(sections) = sections.borrow_mut().as_mut() {
                match sections.iter_mut().find(|(name, _, _)| *name == self.name) {
                    Some((_, count, total)) => {
                        *count += 1;
                        *total += elapsed;
                    }
                    None => sections.push((self.name, 1, elapsed)),
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn sections_count_only_while_collecting_and_accumulate_by_name() {
        drop(super::section("before"));
        let collection = super::collect();
        for _ in 0..3 {
            let _outer = super::section("outer");
            drop(super::section("inner"));
        }
        let sections = collection.finish();
        let names: Vec<_> = sections.iter().map(|(name, count, _)| (*name, *count)).collect();
        assert_eq!(names, vec![("inner", 3), ("outer", 3)]);
        drop(super::section("after"));
        // An abandoned collection stops too.
        drop(super::collect());
        drop(super::section("abandoned"));
        assert!(super::collect().finish().is_empty());
    }
}
