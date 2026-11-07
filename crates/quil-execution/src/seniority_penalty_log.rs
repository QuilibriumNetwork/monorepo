//! Aggregated operator logging for seniority penalties (#976).
//!
//! GLOBAL execution charges absences per app frame and the epoch-boundary
//! pass charges halt-risk leaves and evicts; logging each charge would print
//! one line per prover per frame when many provers go offline at once. They
//! are tallied here instead, per epoch, and each epoch is reported once, at
//! the first frame executed in the next: one `info!` line for the whole
//! network (counts by rule, provers and shards affected, seniority deducted,
//! a sample of at most [`SAMPLE`] provers) and, when this node's own prover
//! was charged, one `warn!` line covering all its shards. Per-charge detail
//! goes to `debug!` only. Logging state only; it never feeds consensus.
//!
//! Rule numbers follow issue #976: rule 1 (missed turn) is not implemented;
//! rule 2 is the halt-risk leave; rule 3 the absence and its eviction.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Mutex, OnceLock};

/// Provers named in a network summary, and shards in an own-prover warning.
pub const SAMPLE: usize = 8;

/// The penalty a charge applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PenaltyRule {
    /// Rule 2: a leave departed (confirmed or expired) and left its shard at
    /// halt risk.
    HaltRiskLeave,
    /// Rule 3: a frame of its committee the member missed past the grace.
    Absence,
    /// Rule 3: the allocation reached the eviction count and was evicted.
    Eviction,
}

impl PenaltyRule {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HaltRiskLeave => "halt_risk_leave",
            Self::Absence => "absence",
            Self::Eviction => "absence_eviction",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Tally {
    halt_risk_leaves: u64,
    absent_frames: u64,
    evictions: u64,
    lost: u64,
}

/// One epoch's charges across the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSummary {
    pub epoch: u64,
    pub halt_risk_leaves: u64,
    pub absent_frames: u64,
    pub evictions: u64,
    pub provers: usize,
    pub shards: usize,
    pub seniority_lost: u64,
    /// `…<prover tail>@…<shard tail>`, at most [`SAMPLE`], most seniority
    /// lost first.
    pub sample: Vec<String>,
}

/// One epoch's charges to this node's own prover, all shards in one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnSummary {
    pub epoch: u64,
    pub seniority_lost: u64,
    /// `<full shard filter>:<rule>:<count>:<seniority lost>`, at most
    /// [`SAMPLE`] shards, most seniority lost first.
    pub shards: Vec<String>,
    /// Penalised shards beyond [`SAMPLE`].
    pub more_shards: usize,
    /// The rules charged, for the operator's next step.
    pub rules: Vec<PenaltyRule>,
}

/// The tallies of the epoch in progress and the dedupe keys that keep a
/// re-executed frame from counting twice.
#[derive(Debug, Default)]
pub struct PenaltyLog {
    epoch: Option<u64>,
    tallies: BTreeMap<(Vec<u8>, Vec<u8>), Tally>,
    /// Last app frame counted per (prover, shard) absence.
    absence_seen: HashMap<(Vec<u8>, Vec<u8>), u64>,
    /// Halt-risk leaves and evictions counted: (rule, prover, shard, key).
    events_seen: BTreeSet<(PenaltyRule, Vec<u8>, Vec<u8>, u64)>,
    ready: Option<(Option<NetworkSummary>, Option<OwnSummary>)>,
    /// The last frame a charge to the own prover was recorded at.
    own_charged_at: u64,
}

fn tail(bytes: &[u8]) -> String {
    format!("…{}", hex::encode(&bytes[bytes.len().saturating_sub(3)..]))
}

impl PenaltyLog {
    /// Record one charge at `frame`: `lost` seniority from `prover` on
    /// `shard` under `rule`. `key` identifies the charge for dedupe: the app
    /// frame for an absence, the leave frame for a halt-risk leave, the frame
    /// for an eviction. Returns whether it was new. `own` is this node's
    /// prover address, when known.
    pub fn record(
        &mut self,
        frame: u64,
        rule: PenaltyRule,
        prover: &[u8],
        shard: &[u8],
        lost: u64,
        key: u64,
        own: Option<&[u8]>,
    ) -> bool {
        self.roll(quil_types::consensus::epoch_for_frame(frame), own);
        let id = (prover.to_vec(), shard.to_vec());
        let new = match rule {
            PenaltyRule::Absence => {
                let last = self.absence_seen.entry(id.clone()).or_insert(0);
                let new = key > *last;
                *last = (*last).max(key);
                new
            }
            _ => self
                .events_seen
                .insert((rule, id.0.clone(), id.1.clone(), key)),
        };
        if !new {
            return false;
        }
        let tally = self.tallies.entry(id).or_default();
        match rule {
            PenaltyRule::HaltRiskLeave => tally.halt_risk_leaves += 1,
            PenaltyRule::Absence => tally.absent_frames += 1,
            PenaltyRule::Eviction => tally.evictions += 1,
        }
        tally.lost = tally.lost.saturating_add(lost);
        if own.is_some_and(|own| own == prover) {
            self.own_charged_at = self.own_charged_at.max(frame);
        }
        true
    }

    /// The summaries due at `frame`: those of the epoch before it, once, at
    /// the first frame of a later epoch; nothing otherwise.
    pub fn end_frame(
        &mut self,
        frame: u64,
        own: Option<&[u8]>,
    ) -> (Option<NetworkSummary>, Option<OwnSummary>) {
        self.roll(quil_types::consensus::epoch_for_frame(frame), own);
        self.ready.take().unwrap_or((None, None))
    }

    /// The last frame a charge to the own prover was recorded at (0: none).
    pub fn own_charged_at(&self) -> u64 {
        self.own_charged_at
    }

    fn roll(&mut self, epoch: u64, own: Option<&[u8]>) {
        let Some(current) = self.epoch else {
            self.epoch = Some(epoch);
            return;
        };
        if epoch <= current {
            return;
        }
        self.epoch = Some(epoch);
        self.events_seen.clear();
        let tallies = std::mem::take(&mut self.tallies);
        if tallies.is_empty() {
            return;
        }
        let mut network = NetworkSummary {
            epoch: current,
            halt_risk_leaves: 0,
            absent_frames: 0,
            evictions: 0,
            provers: tallies
                .keys()
                .map(|(p, _)| p)
                .collect::<BTreeSet<_>>()
                .len(),
            shards: tallies
                .keys()
                .map(|(_, s)| s)
                .collect::<BTreeSet<_>>()
                .len(),
            seniority_lost: 0,
            sample: Vec::new(),
        };
        let mut by_loss: Vec<(&(Vec<u8>, Vec<u8>), &Tally)> = tallies.iter().collect();
        by_loss.sort_by(|a, b| b.1.lost.cmp(&a.1.lost).then_with(|| a.0.cmp(b.0)));
        for (_, t) in &by_loss {
            network.halt_risk_leaves += t.halt_risk_leaves;
            network.absent_frames += t.absent_frames;
            network.evictions += t.evictions;
            network.seniority_lost = network.seniority_lost.saturating_add(t.lost);
        }
        network.sample = by_loss
            .iter()
            .take(SAMPLE)
            .map(|((p, s), _)| format!("{}@{}", tail(p), tail(s)))
            .collect();
        let own_summary = own.and_then(|own| {
            let mine: Vec<_> = by_loss
                .iter()
                .filter(|((p, _), _)| p.as_slice() == own)
                .collect();
            if mine.is_empty() {
                return None;
            }
            let mut rules = BTreeSet::new();
            let shards = mine
                .iter()
                .take(SAMPLE)
                .map(|((_, s), t)| {
                    let (rule, count) = if t.evictions > 0 {
                        (PenaltyRule::Eviction, t.absent_frames)
                    } else if t.halt_risk_leaves > 0 {
                        (PenaltyRule::HaltRiskLeave, t.halt_risk_leaves)
                    } else {
                        (PenaltyRule::Absence, t.absent_frames)
                    };
                    rules.insert(rule);
                    format!("{}:{}:{count}:{}", hex::encode(s), rule.as_str(), t.lost)
                })
                .collect();
            Some(OwnSummary {
                epoch: current,
                seniority_lost: mine.iter().map(|(_, t)| t.lost).sum(),
                shards,
                more_shards: mine.len().saturating_sub(SAMPLE),
                rules: rules.into_iter().collect(),
            })
        });
        self.ready = Some((Some(network), own_summary));
    }
}

fn global() -> &'static Mutex<PenaltyLog> {
    static LOG: OnceLock<Mutex<PenaltyLog>> = OnceLock::new();
    LOG.get_or_init(Default::default)
}

fn own_prover() -> Option<&'static [u8]> {
    crate::global_intrinsic::prover_shard_update::LOCAL_PROVER_ADDRESS
        .get()
        .map(Vec::as_slice)
}

/// Record a charge in this process's log; per-charge detail at `debug!`.
pub fn record(frame: u64, rule: PenaltyRule, prover: &[u8], shard: &[u8], lost: u64, key: u64) {
    tracing::debug!(frame, rule = rule.as_str(), prover = %tail(prover), shard = %hex::encode(shard),
        lost, key, "seniority penalty charged");
    if let Ok(mut log) = global().lock() {
        log.record(frame, rule, prover, shard, lost, key, own_prover());
    }
}

/// The last frame a penalty to this node's prover was recorded at (0: none).
pub fn own_charged_at() -> u64 {
    global().lock().map(|log| log.own_charged_at()).unwrap_or(0)
}

/// Log the summaries due once GLOBAL frame `frame` is executed.
pub fn end_frame(frame: u64) {
    let (network, own) = match global().lock() {
        Ok(mut log) => log.end_frame(frame, own_prover()),
        Err(_) => return,
    };
    if let Some(n) = network {
        tracing::info!(frame, epoch = n.epoch, halt_risk_leave = n.halt_risk_leaves,
            absence = n.absent_frames, evicted = n.evictions, provers = n.provers, shards = n.shards,
            seniority_deducted = n.seniority_lost, sample = ?n.sample,
            scope = "committed GLOBAL state",
            "seniority penalties in the last epoch (absence counts missed committee frames; \
             sample as …prover@…shard, most deducted first)");
    }
    if let Some(o) = own {
        let action = if o.rules.iter().any(|r| *r != PenaltyRule::HaltRiskLeave) {
            "check that the worker serving each shard runs, is synced and votes: an absence past \
             2,160 missed committee frames evicts the allocation"
        } else {
            "leave a shard only once it keeps more than 3 provers after you go; the node's planner \
             withholds such leaves, so this was a manual leave or an older build"
        };
        tracing::warn!(frame, epoch = o.epoch, seniority_lost = o.seniority_lost, shards = ?o.shards,
            more_shards = o.more_shards, scope = "local", action,
            "this prover was charged seniority penalties in the last epoch \
             (shards as filter:rule:count:seniority lost)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(epoch: u64, offset: u64) -> u64 {
        quil_types::consensus::epoch_start_frame(epoch) + offset
    }

    /// 155 provers charged in one frame: one network summary, with the
    /// right counts and a bounded sample, and none before the epoch ends.
    #[test]
    fn many_provers_penalised_in_one_frame_make_one_network_line() {
        let mut log = PenaltyLog::default();
        let shards: Vec<Vec<u8>> = (0..5u8).map(|s| vec![s; 32]).collect();
        for p in 0..155u8 {
            let prover = vec![p; 32];
            assert!(log.record(
                frame(10, 5),
                PenaltyRule::Absence,
                &prover,
                &shards[p as usize % 5],
                10,
                900,
                None
            ));
        }
        assert_eq!(log.end_frame(frame(10, 5), None), (None, None));
        let (network, own) = log.end_frame(frame(11, 0), None);
        let network = network.expect("one summary");
        assert_eq!(
            (
                network.epoch,
                network.absent_frames,
                network.provers,
                network.shards
            ),
            (10, 155, 155, 5)
        );
        assert_eq!(
            (
                network.halt_risk_leaves,
                network.evictions,
                network.seniority_lost
            ),
            (0, 0, 1_550)
        );
        assert_eq!(network.sample.len(), SAMPLE);
        assert_eq!(own, None);
        assert_eq!(
            log.end_frame(frame(11, 1), None),
            (None, None),
            "an epoch is reported once"
        );
    }

    /// A continuing absence charges every frame, but is reported once, after
    /// its epoch; a re-executed frame counts once.
    #[test]
    fn a_continuing_absence_does_not_log_every_frame() {
        let mut log = PenaltyLog::default();
        let prover = vec![7u8; 32];
        let shard = vec![9u8; 32];
        for n in 0..700u64 {
            log.record(
                frame(20, n),
                PenaltyRule::Absence,
                &prover,
                &shard,
                10,
                5_000 + n,
                None,
            );
            assert!(!log.record(
                frame(20, n),
                PenaltyRule::Absence,
                &prover,
                &shard,
                10,
                5_000 + n,
                None
            ));
            assert_eq!(log.end_frame(frame(20, n), None), (None, None), "frame {n}");
        }
        let (network, _) = log.end_frame(frame(21, 0), None);
        let network = network.unwrap();
        assert_eq!(
            (
                network.absent_frames,
                network.provers,
                network.seniority_lost
            ),
            (700, 1, 7_000)
        );
    }

    /// The own prover's charges on several shards make one warning line.
    #[test]
    fn the_own_prover_gets_one_line_for_all_its_shards() {
        let mut log = PenaltyLog::default();
        let own = vec![1u8; 32];
        let other = vec![2u8; 32];
        log.record(
            frame(30, 0),
            PenaltyRule::HaltRiskLeave,
            &own,
            &[0xA1; 32],
            7_200,
            77,
            Some(&own),
        );
        for n in 0..3u64 {
            log.record(
                frame(30, n),
                PenaltyRule::Absence,
                &own,
                &[0xA2; 32],
                10,
                100 + n,
                Some(&own),
            );
        }
        log.record(
            frame(30, 1),
            PenaltyRule::Absence,
            &other,
            &[0xA2; 32],
            10,
            100,
            Some(&own),
        );
        assert_eq!(log.own_charged_at(), frame(30, 2));
        let (network, own_summary) = log.end_frame(frame(31, 0), Some(&own));
        assert_eq!(network.unwrap().provers, 2);
        let own_summary = own_summary.expect("one own line");
        assert_eq!(own_summary.seniority_lost, 7_230);
        assert_eq!(
            own_summary.shards,
            vec![
                format!("{}:halt_risk_leave:1:7200", hex::encode([0xA1u8; 32])),
                format!("{}:absence:3:30", hex::encode([0xA2u8; 32])),
            ]
        );
        assert_eq!(own_summary.more_shards, 0);
    }
}
