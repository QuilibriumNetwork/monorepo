//! Bounded node-owned frame observations. Downtime and missing reads are gaps,
//! not evidence of either production or a stall. This cache is not consensus state.
use std::{collections::{BTreeMap, VecDeque}, io::{BufReader, BufWriter, Read, Write}, path::Path, time::{SystemTime, UNIX_EPOCH}};
use quil_types::proto::node::{FrameCadence, FrameWindow};

const DAY: u64 = 86_400;
const MAX_SERIES: usize = 256;
const MAX_SAMPLES: usize = 1442;
const MAX_FILE: u64 = 12 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"QFRAME01";

pub(super) fn unix_seconds() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }
#[derive(Clone, Debug)]
struct Sample { at: u64, frame: u64, generation: u64, continuous: bool }
#[derive(Default, Debug)]
struct Series { samples: VecDeque<Sample>, runtime_last: Option<u64> }
#[derive(Default, Debug)]
pub(super) struct Observations { series: BTreeMap<Vec<u8>, Series> }

impl Observations {
    // Empty key denotes received GLOBAL; public shard filters are stored privately.
    pub fn track(&mut self, filter: &[u8]) {
        if filter.len() <= 128 && self.series.len() < MAX_SERIES { self.series.entry(filter.to_vec()).or_default(); }
    }
    pub fn prioritize(&mut self, filters: &std::collections::BTreeSet<Vec<u8>>) {
        let global = Vec::new();
        for filter in std::iter::once(&global).chain(filters.iter()) {
            if self.series.contains_key(filter) || filter.len() > 128 { continue; }
            if self.series.len() >= MAX_SERIES {
                let victim = self.series.iter().filter(|(key, _)| !key.is_empty() && !filters.contains(*key))
                    .min_by_key(|(_, series)| series.samples.back().map_or(0, |s| s.at)).map(|(key, _)| key.clone());
                if let Some(key) = victim { self.series.remove(&key); }
            }
            self.track(filter);
        }
    }
    pub fn expire(&mut self, now: u64) {
        self.series.retain(|key, series| key.is_empty() || series.samples.back().is_none_or(|s| now < s.at || now - s.at <= DAY));
    }
    pub fn filters(&self) -> Vec<Vec<u8>> { self.series.keys().filter(|k| !k.is_empty()).cloned().collect() }
    pub fn observe(&mut self, filter: &[u8], head: Option<(u64, u64)>, now: u64) {
        self.track(filter);
        let Some(series) = self.series.get_mut(filter) else { return; };
        while series.samples.front().is_some_and(|s| now.saturating_sub(s.at) > DAY) { series.samples.pop_front(); }
        let Some((frame, generation)) = head.filter(|(frame, _)| *frame > 0) else { series.runtime_last = None; return; };
        if series.samples.back().is_some_and(|s| s.at > now || (s.generation == generation && frame < s.frame)) { series.samples.clear(); series.runtime_last = None; }
        if series.samples.back().is_some_and(|s| now.saturating_sub(s.at) < 50) { return; }
        let continuous = series.samples.back().is_some_and(|last| series.runtime_last == Some(last.at)
            && now - last.at <= 90 && last.generation == generation && frame >= last.frame);
        series.samples.push_back(Sample { at: now, frame, generation, continuous });
        series.runtime_last = Some(now);
        while series.samples.len() > MAX_SAMPLES { series.samples.pop_front(); }
    }
    pub fn snapshot(&self, filter: &[u8], now: u64) -> Option<FrameCadence> {
        let series = self.series.get(filter)?;
        let latest = series.samples.back()?;
        // A restored record alone is not a fresh node observation.
        if series.runtime_last != Some(latest.at) || now < latest.at || now - latest.at > 90 { return None; }
        let window = |seconds| {
            let mut observed = 0; let mut advanced = 0u64;
            for (a, b) in series.samples.iter().zip(series.samples.iter().skip(1)) {
                if a.at >= now.saturating_sub(seconds) && b.continuous {
                    observed += b.at - a.at; advanced = advanced.checked_add(b.frame - a.frame)?;
                }
            }
            (observed >= 60).then_some(FrameWindow { window_seconds: seconds, observed_seconds: observed, advanced_frames: advanced })
        };
        Some(FrameCadence { last_observed_unix_seconds: latest.at, hour: window(3600), day: window(DAY) })
    }
    pub fn save(&self, path: &Path, scope: &[u8]) -> std::io::Result<()> {
        let temporary = path.with_extension("pending");
        let mut file = BufWriter::with_capacity(65536, std::fs::File::create(&temporary)?);
        file.write_all(MAGIC)?; write_bytes(&mut file, scope)?; write_u64(&mut file, self.series.len() as u64)?;
        for (key, series) in &self.series {
            write_bytes(&mut file, key)?; write_u64(&mut file, series.samples.len() as u64)?;
            for s in &series.samples {
                for n in [s.at, s.frame, s.generation] { write_u64(&mut file, n)?; }
                file.write_all(&[u8::from(s.continuous)])?;
            }
        }
        file.flush()?; file.get_ref().sync_all()?; drop(file); std::fs::rename(&temporary, path)?;
        if let Some(parent) = path.parent() { std::fs::File::open(parent)?.sync_all()?; }
        Ok(())
    }
    pub fn load(path: &Path, scope: &[u8], now: u64) -> std::io::Result<Self> {
        let file = std::fs::File::open(path)?;
        if file.metadata()?.len() > MAX_FILE { return Err(invalid()); }
        let mut file = BufReader::with_capacity(65536, file);
        let mut magic = [0; 8]; file.read_exact(&mut magic)?;
        if &magic != MAGIC || read_bytes(&mut file, 128)? != scope { return Err(invalid()); }
        let count = read_u64(&mut file)?; if count > MAX_SERIES as u64 { return Err(invalid()); }
        let mut result = Self::default();
        for _ in 0..count {
            let key = read_bytes(&mut file, 128)?; let count = read_u64(&mut file)?;
            if count > MAX_SAMPLES as u64 || result.series.contains_key(&key) { return Err(invalid()); }
            let mut series = Series::default(); let mut previous: Option<Sample> = None;
            for _ in 0..count {
                let at = read_u64(&mut file)?; let frame = read_u64(&mut file)?; let generation = read_u64(&mut file)?;
                let mut flag = [0]; file.read_exact(&mut flag)?;
                if flag[0] > 1 || frame == 0 || previous.as_ref().is_some_and(|p| at <= p.at
                    || flag[0] == 1 && (at - p.at > 90 || frame < p.frame || generation != p.generation)) { return Err(invalid()); }
                let sample = Sample { at, frame, generation, continuous: flag[0] == 1 };
                if at <= now && now - at <= DAY { series.samples.push_back(sample.clone()); }
                previous = Some(sample);
            }
            result.series.insert(key, series);
        }
        let mut extra = [0]; if file.read(&mut extra)? != 0 { return Err(invalid()); }
        Ok(result)
    }
}
fn invalid() -> std::io::Error { std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid frame observation cache") }
fn write_u64(w: &mut impl Write, n: u64) -> std::io::Result<()> { w.write_all(&n.to_be_bytes()) }
fn read_u64(r: &mut impl Read) -> std::io::Result<u64> { let mut b = [0; 8]; r.read_exact(&mut b)?; Ok(u64::from_be_bytes(b)) }
fn write_bytes(w: &mut impl Write, b: &[u8]) -> std::io::Result<()> { write_u64(w, b.len() as u64)?; w.write_all(b) }
fn read_bytes(r: &mut impl Read, max: usize) -> std::io::Result<Vec<u8>> {
    let n = read_u64(r)?; if n > max as u64 { return Err(invalid()); }
    let mut b = vec![0; n as usize]; r.read_exact(&mut b)?; Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_include_pauses_but_exclude_restart_and_generation_jumps() {
        let mut o = Observations::default();
        o.observe(b"a", Some((100, 1)), 1000); o.observe(b"a", Some((106, 1)), 1060);
        o.observe(b"a", Some((106, 1)), 1120);
        let h = o.snapshot(b"a", 1120).unwrap().hour.unwrap(); assert_eq!((h.observed_seconds,h.advanced_frames),(120,6));
        o.observe(b"a", Some((5000, 2)), 1180); o.observe(b"a", Some((5006, 2)), 1240);
        let h = o.snapshot(b"a", 1240).unwrap().hour.unwrap(); assert_eq!((h.observed_seconds,h.advanced_frames),(180,12));
        assert!(o.snapshot(b"a", 1340).is_none());
    }
    #[test]
    fn persisted_history_survives_restart_without_counting_offline_frames() {
        let dir = tempfile::tempdir().unwrap(); let path = dir.path().join("frames.bin"); let mut o = Observations::default();
        o.observe(b"a", Some((100,1)), 1000); o.observe(b"a", Some((106,1)),1060); o.save(&path,b"scope").unwrap();
        let mut restored = Observations::load(&path,b"scope",1300).unwrap(); assert!(restored.snapshot(b"a",1300).is_none());
        restored.observe(b"a",Some((130,1)),1300); restored.observe(b"a",Some((136,1)),1360);
        let h = restored.snapshot(b"a",1360).unwrap().hour.unwrap(); assert_eq!((h.observed_seconds,h.advanced_frames),(120,12));
        assert!(Observations::load(&path,b"other",1360).is_err()); std::fs::write(&path,b"broken").unwrap(); assert!(Observations::load(&path,b"scope",1360).is_err());
    }
    #[test]
    fn windows_expire_independently_and_history_is_bounded() {
        let mut o = Observations::default();
        for n in 0..=1500 { o.observe(b"a",Some((n+1,1)),1000+n*60); }
        let s = o.snapshot(b"a",91000).unwrap(); assert_eq!(s.hour.unwrap().observed_seconds,3600); assert_eq!(s.day.unwrap().observed_seconds,86400);
        assert!(o.series[b"a".as_slice()].samples.len()<=MAX_SAMPLES);
        o.observe(b"a",None,91060); assert!(o.snapshot(b"a",91060).is_none());
        o.observe(b"a",Some((1,3)),91120); let h=o.snapshot(b"a",91120).unwrap().hour.unwrap(); assert_eq!(h.advanced_frames,58);
    }
    #[test]
    fn no_tip_and_rollback_cannot_invent_production() {
        let mut o = Observations::default(); o.observe(b"a",Some((0,1)),1000);
        o.observe(b"a",Some((2456,1)),1060); assert!(o.snapshot(b"a",1060).unwrap().hour.is_none());
        o.observe(b"a",Some((2458,1)),1120); let h=o.snapshot(b"a",1120).unwrap().hour.unwrap(); assert_eq!((h.observed_seconds,h.advanced_frames),(60,2));
        o.observe(b"a",Some((2000,1)),1180); assert!(o.snapshot(b"a",1180).unwrap().hour.is_none());
        o.observe(b"a",Some((2000,1)),1240); assert_eq!(o.snapshot(b"a",1240).unwrap().hour.unwrap().advanced_frames,0);
    }

    #[test]
    fn minute_tick_jitter_does_not_turn_valid_observation_into_a_gap() {
        let mut o = Observations::default();
        for (at, frame) in [(1000,100),(1059,106),(1120,112)] { o.observe(b"a",Some((frame,1)),at); }
        let w=o.snapshot(b"a",1120).unwrap().hour.unwrap(); assert_eq!((w.observed_seconds,w.advanced_frames),(120,12));
        o.expire(90000); assert!(!o.series.contains_key(b"a".as_slice()));
    }

    #[test]
    fn newly_owned_shards_take_priority_over_unallocated_cache_entries() {
        let mut o = Observations::default(); o.track(&[]);
        for n in 0..MAX_SERIES { o.track(&(n as u16).to_be_bytes()); }
        assert_eq!(o.series.len(), MAX_SERIES);
        let owned = std::collections::BTreeSet::from([vec![255,255]]);
        o.prioritize(&owned); assert!(o.series.contains_key(&vec![255,255])); assert!(o.series.contains_key(b"".as_slice())); assert_eq!(o.series.len(), MAX_SERIES);
        let mut full = Observations::default();
        for n in 0..MAX_SERIES { full.track(&(n as u16).to_be_bytes()); }
        full.prioritize(&std::collections::BTreeSet::from([vec![0,0]]));
        assert!(full.series.contains_key(b"".as_slice())); assert!(full.series.contains_key(&vec![0,0])); assert_eq!(full.series.len(), MAX_SERIES);
    }

    #[test]
    fn oversized_advancement_counts_are_unavailable_instead_of_panicking() {
        let mut o = Observations::default();
        for (at, frame, generation) in [(1000,1,1),(1060,u64::MAX,1),(1120,1,2),(1180,u64::MAX,2)] {
            o.observe(b"a",Some((frame,generation)),at);
        }
        let c=o.snapshot(b"a",1180).unwrap(); assert!(c.hour.is_none() && c.day.is_none());
    }

}
