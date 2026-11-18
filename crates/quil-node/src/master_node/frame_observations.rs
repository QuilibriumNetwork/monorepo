//! Bounded node-owned frame observations. Downtime is a gap, not evidence of
//! either production or a stall; a failed or skipped read within a run is not,
//! as the next good read counts the frames the committed head advanced across
//! it (up to `MAX_SPAN`). This cache is not consensus state.
use quil_types::proto::node::{FrameCadence, FrameWindow};
use std::{
    collections::{BTreeMap, VecDeque},
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const DAY: u64 = 86_400;
const MAX_SERIES: usize = 256;
const MAX_SAMPLES: usize = 1442;
const MAX_FILE: u64 = 12 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"QFRAME01";
/// Longest span between two good reads of one run that counts as observed.
/// A regular node's shard heads advance in jumps at each archive sync, and a
/// read failing at that moment must not drop the jump; a longer outage
/// stays a gap.
const MAX_SPAN: u64 = 600;

pub(super) fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
#[derive(Clone, Debug)]
struct Sample {
    at: u64,
    frame: u64,
    generation: u64,
    continuous: bool,
}
#[derive(Default, Debug)]
struct Series {
    samples: VecDeque<Sample>,
    runtime_last: Option<u64>,
    /// The latest read failed: the cadence is withheld until a good read,
    /// which still counts from the last good one.
    missed: bool,
}
#[derive(Default, Debug)]
pub(super) struct Observations {
    series: BTreeMap<Vec<u8>, Series>,
}

impl Observations {
    // Empty key denotes received GLOBAL; public shard filters are stored privately.
    pub fn track(&mut self, filter: &[u8]) {
        if filter.len() <= 128 && self.series.len() < MAX_SERIES {
            self.series.entry(filter.to_vec()).or_default();
        }
    }
    pub fn prioritize(&mut self, filters: &std::collections::BTreeSet<Vec<u8>>) {
        let global = Vec::new();
        for filter in std::iter::once(&global).chain(filters.iter()) {
            if self.series.contains_key(filter) || filter.len() > 128 {
                continue;
            }
            if self.series.len() >= MAX_SERIES {
                let victim = self
                    .series
                    .iter()
                    .filter(|(key, _)| !key.is_empty() && !filters.contains(*key))
                    .min_by_key(|(_, series)| series.samples.back().map_or(0, |s| s.at))
                    .map(|(key, _)| key.clone());
                if let Some(key) = victim {
                    self.series.remove(&key);
                }
            }
            self.track(filter);
        }
    }
    pub fn expire(&mut self, now: u64) {
        self.series.retain(|key, series| {
            key.is_empty()
                || series
                    .samples
                    .back()
                    .is_none_or(|s| now < s.at || now - s.at <= DAY)
        });
    }
    pub fn filters(&self) -> Vec<Vec<u8>> {
        self.series
            .keys()
            .filter(|k| !k.is_empty())
            .cloned()
            .collect()
    }
    pub fn observe(&mut self, filter: &[u8], head: Option<(u64, u64)>, now: u64) {
        self.track(filter);
        let Some(series) = self.series.get_mut(filter) else {
            return;
        };
        while series
            .samples
            .front()
            .is_some_and(|s| now.saturating_sub(s.at) > DAY)
        {
            series.samples.pop_front();
        }
        let Some((frame, generation)) = head.filter(|(frame, _)| *frame > 0) else {
            series.missed = true;
            return;
        };
        series.missed = false;
        if series
            .samples
            .back()
            .is_some_and(|s| s.at > now || (s.generation == generation && frame < s.frame))
        {
            series.samples.clear();
            series.runtime_last = None;
        }
        if series
            .samples
            .back()
            .is_some_and(|s| now.saturating_sub(s.at) < 50)
        {
            return;
        }
        let continuous = series.samples.back().is_some_and(|last| {
            series.runtime_last == Some(last.at)
                && now - last.at <= MAX_SPAN
                && last.generation == generation
                && frame >= last.frame
        });
        series.samples.push_back(Sample {
            at: now,
            frame,
            generation,
            continuous,
        });
        series.runtime_last = Some(now);
        while series.samples.len() > MAX_SAMPLES {
            series.samples.pop_front();
        }
    }
    pub fn snapshot(&self, filter: &[u8], now: u64) -> Option<FrameCadence> {
        let series = self.series.get(filter)?;
        let latest = series.samples.back()?;
        // A restored record alone, or one a failed read followed, is not a
        // fresh node observation.
        if series.missed
            || series.runtime_last != Some(latest.at)
            || now < latest.at
            || now - latest.at > 90
        {
            return None;
        }
        let window = |seconds| {
            let mut observed = 0;
            let mut advanced = 0u64;
            for (a, b) in series.samples.iter().zip(series.samples.iter().skip(1)) {
                if a.at >= now.saturating_sub(seconds) && b.continuous {
                    observed += b.at - a.at;
                    advanced = advanced.checked_add(b.frame - a.frame)?;
                }
            }
            (observed >= 60).then_some(FrameWindow {
                window_seconds: seconds,
                observed_seconds: observed,
                advanced_frames: advanced,
            })
        };
        Some(FrameCadence {
            last_observed_unix_seconds: latest.at,
            hour: window(3600),
            day: window(DAY),
        })
    }
    pub fn save(&self, path: &Path, scope: &[u8]) -> std::io::Result<()> {
        let temporary = path.with_extension("pending");
        let mut file = BufWriter::with_capacity(65536, std::fs::File::create(&temporary)?);
        file.write_all(MAGIC)?;
        write_bytes(&mut file, scope)?;
        write_u64(&mut file, self.series.len() as u64)?;
        for (key, series) in &self.series {
            write_bytes(&mut file, key)?;
            write_u64(&mut file, series.samples.len() as u64)?;
            for s in &series.samples {
                for n in [s.at, s.frame, s.generation] {
                    write_u64(&mut file, n)?;
                }
                file.write_all(&[u8::from(s.continuous)])?;
            }
        }
        file.flush()?;
        file.get_ref().sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
    pub fn load(path: &Path, scope: &[u8], now: u64) -> std::io::Result<Self> {
        let file = std::fs::File::open(path)?;
        if file.metadata()?.len() > MAX_FILE {
            return Err(invalid());
        }
        let mut file = BufReader::with_capacity(65536, file);
        let mut magic = [0; 8];
        file.read_exact(&mut magic)?;
        if &magic != MAGIC || read_bytes(&mut file, 128)? != scope {
            return Err(invalid());
        }
        let count = read_u64(&mut file)?;
        if count > MAX_SERIES as u64 {
            return Err(invalid());
        }
        let mut result = Self::default();
        for _ in 0..count {
            let key = read_bytes(&mut file, 128)?;
            let count = read_u64(&mut file)?;
            if count > MAX_SAMPLES as u64 || result.series.contains_key(&key) {
                return Err(invalid());
            }
            let mut series = Series::default();
            let mut previous: Option<Sample> = None;
            for _ in 0..count {
                let at = read_u64(&mut file)?;
                let frame = read_u64(&mut file)?;
                let generation = read_u64(&mut file)?;
                let mut flag = [0];
                file.read_exact(&mut flag)?;
                if flag[0] > 1
                    || frame == 0
                    || previous.as_ref().is_some_and(|p| {
                        at <= p.at
                            || flag[0] == 1
                                && (at - p.at > MAX_SPAN
                                    || frame < p.frame
                                    || generation != p.generation)
                    })
                {
                    return Err(invalid());
                }
                let sample = Sample {
                    at,
                    frame,
                    generation,
                    continuous: flag[0] == 1,
                };
                if at <= now && now - at <= DAY {
                    series.samples.push_back(sample.clone());
                }
                previous = Some(sample);
            }
            result.series.insert(key, series);
        }
        let mut extra = [0];
        if file.read(&mut extra)? != 0 {
            return Err(invalid());
        }
        Ok(result)
    }
}
/// A failing shard head read's lines: a summary at most this often.
const READ_LOG_EVERY: u64 = 3_600;
/// Good reads for this long, with no failure, end a failing episode.
const READ_QUIET: u64 = 600;
/// Bytes of a read error a line carries.
const READ_ERROR_MAX: usize = 256;

/// The sampler's committed shard head reads. A failure is bridged by the
/// next good read, so it costs no frames, but its cause is unknown: an
/// episode logs its start, at most one summary per `READ_LOG_EVERY` and its
/// end once reads stay good for `READ_QUIET`.
#[derive(Default, Debug)]
pub(super) struct ReadFailures {
    episode: Option<Episode>,
}
#[derive(Debug)]
struct Episode {
    since: u64,
    logged: u64,
    last_failure: u64,
    failed: u64,
    good: u64,
    total: u64,
    error: String,
    read_ms: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ReadLine {
    Started {
        error: String,
        read_ms: u64,
    },
    Failing {
        failed: u64,
        good: u64,
        since_secs: u64,
        error: String,
        read_ms: u64,
    },
    Recovered {
        failed: u64,
        lasted_secs: u64,
        error: String,
        read_ms: u64,
    },
}

impl ReadFailures {
    pub fn failed(&mut self, now: u64, error: &str, read_ms: u64) -> Option<ReadLine> {
        let mut error = error.to_owned();
        if error.len() > READ_ERROR_MAX {
            let mut end = READ_ERROR_MAX;
            while !error.is_char_boundary(end) {
                end -= 1;
            }
            error.truncate(end);
        }
        let Some(e) = self.episode.as_mut() else {
            self.episode = Some(Episode {
                since: now,
                logged: now,
                last_failure: now,
                failed: 0,
                good: 0,
                total: 1,
                error: error.clone(),
                read_ms,
            });
            return Some(ReadLine::Started { error, read_ms });
        };
        e.failed += 1;
        e.total += 1;
        e.last_failure = now;
        e.error = error;
        e.read_ms = read_ms;
        if now.saturating_sub(e.logged) < READ_LOG_EVERY {
            return None;
        }
        let line = ReadLine::Failing {
            failed: e.failed,
            good: e.good,
            since_secs: now.saturating_sub(e.since),
            error: e.error.clone(),
            read_ms,
        };
        (e.logged, e.failed, e.good) = (now, 0, 0);
        Some(line)
    }
    pub fn succeeded(&mut self, now: u64) -> Option<ReadLine> {
        let e = self.episode.as_mut()?;
        e.good += 1;
        if now.saturating_sub(e.last_failure) < READ_QUIET {
            return None;
        }
        let e = self.episode.take()?;
        Some(ReadLine::Recovered {
            failed: e.total,
            lasted_secs: e.last_failure.saturating_sub(e.since),
            error: e.error,
            read_ms: e.read_ms,
        })
    }
}

impl ReadLine {
    pub fn emit(&self, shards: usize) {
        match self {
            ReadLine::Started { error, read_ms } => tracing::warn!(
                shards,
                error = %error,
                read_ms,
                "shard head read failed; app frame cadence counts the next good read \
                 from the last one, and a summary follows hourly while reads fail"
            ),
            ReadLine::Failing {
                failed,
                good,
                since_secs,
                error,
                read_ms,
            } => tracing::warn!(
                shards,
                failed_reads = failed,
                good_reads = good,
                since_secs,
                last_error = %error,
                last_read_ms = read_ms,
                "shard head reads failed this interval; counts cover the interval"
            ),
            ReadLine::Recovered {
                failed,
                lasted_secs,
                error,
                read_ms,
            } => tracing::info!(
                shards,
                failed_reads = failed,
                lasted_secs,
                last_error = %error,
                last_read_ms = read_ms,
                "shard head reads recovered"
            ),
        }
    }
}

fn invalid() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "invalid frame observation cache",
    )
}
fn write_u64(w: &mut impl Write, n: u64) -> std::io::Result<()> {
    w.write_all(&n.to_be_bytes())
}
fn read_u64(r: &mut impl Read) -> std::io::Result<u64> {
    let mut b = [0; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_be_bytes(b))
}
fn write_bytes(w: &mut impl Write, b: &[u8]) -> std::io::Result<()> {
    write_u64(w, b.len() as u64)?;
    w.write_all(b)
}
fn read_bytes(r: &mut impl Read, max: usize) -> std::io::Result<Vec<u8>> {
    let n = read_u64(r)?;
    if n > max as u64 {
        return Err(invalid());
    }
    let mut b = vec![0; n as usize];
    r.read_exact(&mut b)?;
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_include_pauses_but_exclude_restart_and_generation_jumps() {
        let mut o = Observations::default();
        o.observe(b"a", Some((100, 1)), 1000);
        o.observe(b"a", Some((106, 1)), 1060);
        o.observe(b"a", Some((106, 1)), 1120);
        let h = o.snapshot(b"a", 1120).unwrap().hour.unwrap();
        assert_eq!((h.observed_seconds, h.advanced_frames), (120, 6));
        o.observe(b"a", Some((5000, 2)), 1180);
        o.observe(b"a", Some((5006, 2)), 1240);
        let h = o.snapshot(b"a", 1240).unwrap().hour.unwrap();
        assert_eq!((h.observed_seconds, h.advanced_frames), (180, 12));
        assert!(o.snapshot(b"a", 1340).is_none());
    }
    #[test]
    fn persisted_history_survives_restart_without_counting_offline_frames() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frames.bin");
        let mut o = Observations::default();
        o.observe(b"a", Some((100, 1)), 1000);
        o.observe(b"a", Some((106, 1)), 1060);
        o.save(&path, b"scope").unwrap();
        let mut restored = Observations::load(&path, b"scope", 1300).unwrap();
        assert!(restored.snapshot(b"a", 1300).is_none());
        restored.observe(b"a", Some((130, 1)), 1300);
        restored.observe(b"a", Some((136, 1)), 1360);
        let h = restored.snapshot(b"a", 1360).unwrap().hour.unwrap();
        assert_eq!((h.observed_seconds, h.advanced_frames), (120, 12));
        assert!(Observations::load(&path, b"other", 1360).is_err());
        std::fs::write(&path, b"broken").unwrap();
        assert!(Observations::load(&path, b"scope", 1360).is_err());
    }
    #[test]
    fn windows_expire_independently_and_history_is_bounded() {
        let mut o = Observations::default();
        for n in 0..=1500 {
            o.observe(b"a", Some((n + 1, 1)), 1000 + n * 60);
        }
        let s = o.snapshot(b"a", 91000).unwrap();
        assert_eq!(s.hour.unwrap().observed_seconds, 3600);
        assert_eq!(s.day.unwrap().observed_seconds, 86400);
        assert!(o.series[b"a".as_slice()].samples.len() <= MAX_SAMPLES);
        o.observe(b"a", None, 91060);
        assert!(o.snapshot(b"a", 91060).is_none());
        o.observe(b"a", Some((1, 3)), 91120);
        let h = o.snapshot(b"a", 91120).unwrap().hour.unwrap();
        assert_eq!(h.advanced_frames, 58);
    }
    #[test]
    fn no_tip_and_rollback_cannot_invent_production() {
        let mut o = Observations::default();
        o.observe(b"a", Some((0, 1)), 1000);
        o.observe(b"a", Some((2456, 1)), 1060);
        assert!(o.snapshot(b"a", 1060).unwrap().hour.is_none());
        o.observe(b"a", Some((2458, 1)), 1120);
        let h = o.snapshot(b"a", 1120).unwrap().hour.unwrap();
        assert_eq!((h.observed_seconds, h.advanced_frames), (60, 2));
        o.observe(b"a", Some((2000, 1)), 1180);
        assert!(o.snapshot(b"a", 1180).unwrap().hour.is_none());
        o.observe(b"a", Some((2000, 1)), 1240);
        assert_eq!(
            o.snapshot(b"a", 1240)
                .unwrap()
                .hour
                .unwrap()
                .advanced_frames,
            0
        );
    }

    #[test]
    fn minute_tick_jitter_does_not_turn_valid_observation_into_a_gap() {
        let mut o = Observations::default();
        for (at, frame) in [(1000, 100), (1059, 106), (1120, 112)] {
            o.observe(b"a", Some((frame, 1)), at);
        }
        let w = o.snapshot(b"a", 1120).unwrap().hour.unwrap();
        assert_eq!((w.observed_seconds, w.advanced_frames), (120, 12));
        o.expire(90000);
        assert!(!o.series.contains_key(b"a".as_slice()));
    }

    #[test]
    fn newly_owned_shards_take_priority_over_unallocated_cache_entries() {
        let mut o = Observations::default();
        o.track(&[]);
        for n in 0..MAX_SERIES {
            o.track(&(n as u16).to_be_bytes());
        }
        assert_eq!(o.series.len(), MAX_SERIES);
        let owned = std::collections::BTreeSet::from([vec![255, 255]]);
        o.prioritize(&owned);
        assert!(o.series.contains_key(&vec![255, 255]));
        assert!(o.series.contains_key(b"".as_slice()));
        assert_eq!(o.series.len(), MAX_SERIES);
        let mut full = Observations::default();
        for n in 0..MAX_SERIES {
            full.track(&(n as u16).to_be_bytes());
        }
        full.prioritize(&std::collections::BTreeSet::from([vec![0, 0]]));
        assert!(full.series.contains_key(b"".as_slice()));
        assert!(full.series.contains_key(&vec![0, 0]));
        assert_eq!(full.series.len(), MAX_SERIES);
    }

    #[test]
    fn a_read_failed_at_an_archive_sync_keeps_the_jump_it_spans() {
        // A regular node's shard heads advance 25-30 frames at each 5-minute
        // archive sync, and the committed read failed at half of them.
        let mut o = Observations::default();
        let (start, mut frame, mut total) = (100_000u64, 1_000u64, 0u64);
        for minute in 0..=60u64 {
            let now = start + minute * 60;
            if minute > 0 && minute % 5 == 0 {
                let jump = 25 + minute / 5 % 6;
                frame += jump;
                total += jump;
                if minute / 5 % 2 == 1 {
                    o.observe(b"a", None, now);
                    assert!(
                        o.snapshot(b"a", now).is_none(),
                        "stale: cadence after a failed read"
                    );
                    continue;
                }
            }
            o.observe(b"a", Some((frame, 1)), now);
        }
        let h = o.snapshot(b"a", start + 3600).unwrap().hour.unwrap();
        assert_eq!(
            (h.observed_seconds, h.advanced_frames),
            (3600, total),
            "bridged: failed reads dropped the frames they spanned"
        );
        // Reads failing for longer than MAX_SPAN leave a gap.
        for minute in 61..=71u64 {
            o.observe(b"a", None, start + minute * 60);
        }
        frame += 30;
        o.observe(b"a", Some((frame, 1)), start + 72 * 60);
        o.observe(b"a", Some((frame, 1)), start + 73 * 60);
        let d = o.snapshot(b"a", start + 73 * 60).unwrap().day.unwrap();
        assert_eq!(
            (d.observed_seconds, d.advanced_frames),
            (3660, total),
            "gap: an outage counted as observed"
        );
    }

    #[test]
    fn a_span_bridged_over_a_failed_read_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frames.bin");
        let mut o = Observations::default();
        o.observe(b"a", Some((100, 1)), 1000);
        o.observe(b"a", None, 1060);
        o.observe(b"a", Some((128, 1)), 1120);
        o.save(&path, b"scope").unwrap();
        let mut restored =
            Observations::load(&path, b"scope", 1300).expect("restored: cache refused");
        restored.observe(b"a", Some((130, 1)), 1300);
        restored.observe(b"a", Some((136, 1)), 1360);
        let h = restored.snapshot(b"a", 1360).unwrap().hour.unwrap();
        assert_eq!(
            (h.observed_seconds, h.advanced_frames),
            (180, 34),
            "bridged: failed reads dropped the frames they spanned"
        );
    }

    #[test]
    fn shard_read_failures_log_a_start_hourly_summaries_and_an_end() {
        // Reads fail at every 5-minute archive sync for two hours, then stay
        // good: one start, one hourly summary, one end; no line per tick.
        let mut f = ReadFailures::default();
        let mut lines = Vec::new();
        for minute in 0..=130u64 {
            let now = 1_000 + minute * 60;
            lines.extend(if minute % 5 == 0 && minute < 120 {
                f.failed(now, "busy", 40)
            } else {
                f.succeeded(now)
            });
        }
        assert_eq!(lines.len(), 3, "bounded: {lines:?}");
        let busy = || "busy".to_owned();
        assert_eq!(
            lines,
            [
                ReadLine::Started {
                    error: busy(),
                    read_ms: 40
                },
                ReadLine::Failing {
                    failed: 12,
                    good: 48,
                    since_secs: 3_600,
                    error: busy(),
                    read_ms: 40
                },
                ReadLine::Recovered {
                    failed: 24,
                    lasted_secs: 115 * 60,
                    error: busy(),
                    read_ms: 40
                },
            ]
        );
        // A read failing at every tick for two hours logs three lines, and
        // a long error is cut on a character boundary.
        let mut f = ReadFailures::default();
        let long = format!("a{}", "é".repeat(READ_ERROR_MAX));
        let lines: Vec<_> = (0..=120u64)
            .filter_map(|minute| f.failed(minute * 60, &long, 7))
            .collect();
        assert_eq!(lines.len(), 3, "bounded: {lines:?}");
        let ReadLine::Failing { error, .. } = &lines[2] else {
            panic!("{lines:?}");
        };
        assert_eq!(error.len(), READ_ERROR_MAX - 1);
    }

    #[test]
    fn oversized_advancement_counts_are_unavailable_instead_of_panicking() {
        let mut o = Observations::default();
        for (at, frame, generation) in [
            (1000, 1, 1),
            (1060, u64::MAX, 1),
            (1120, 1, 2),
            (1180, u64::MAX, 2),
        ] {
            o.observe(b"a", Some((frame, generation)), at);
        }
        let c = o.snapshot(b"a", 1180).unwrap();
        assert!(c.hour.is_none() && c.day.is_none());
    }
}
