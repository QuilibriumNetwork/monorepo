//! QUILIBRIUM: one bounded summary of the peer messages the batcher discards
//! for a decoding error or an epoch mismatch.
//!
//! Upstream logs a warning per discarded message (`block!`). A member whose
//! peers still vote in an earlier epoch after a committee handoff, or send
//! messages it cannot decode, then writes thousands of identical lines an
//! hour: a regular node logged 14,933 epoch mismatches and 625 decoding
//! errors in three hours, 97% of its warnings. The peers are still blocked as
//! before; this counts what was discarded and logs the first discard at once
//! and then a summary at most once per [`SUMMARY_EVERY`].

use std::{
    collections::BTreeSet,
    time::{Duration, SystemTime},
};

/// How often a continuing burst of discards is summarized again.
pub(super) const SUMMARY_EVERY: Duration = Duration::from_secs(600);

/// Distinct peers remembered per summary.
const PEERS: usize = 256;

/// Undecodable messages in one summary that warn, when they come from more
/// than one peer: about half of one committee member's vote stream over
/// [`SUMMARY_EVERY`] (three votes a view, a view every few seconds). Fewer,
/// or from one peer, is a stray or a peer on another build: its operator's
/// problem.
pub(super) const UNDECODABLE_WARN: u64 = 100;

/// What was discarded since the last summary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Summary {
    /// Seconds since the previous summary (0 for the first).
    pub secs: u64,
    /// Messages that did not decode.
    pub undecodable: u64,
    /// Messages of an earlier epoch than this member's.
    pub earlier: u64,
    /// Messages of a later epoch than this member's.
    pub later: u64,
    /// Distinct senders (at most [`PEERS`] are counted).
    pub peers: usize,
    /// Distinct senders of undecodable messages (at most [`PEERS`]).
    pub undecodable_peers: usize,
    /// Lowest and highest foreign epoch seen.
    pub epochs: Option<(u64, u64)>,
}

/// Discarded peer messages, summarized at most once per interval.
#[derive(Debug)]
pub(super) struct Discards<P: Ord> {
    /// The engine's journal partition, naming the session in each line
    /// (`app-<shard filter>` on app shards).
    pub(super) partition: String,
    logged: Option<SystemTime>,
    pending: Summary,
    peers: BTreeSet<P>,
    undecodable_peers: BTreeSet<P>,
}

impl<P: Ord> Default for Discards<P> {
    fn default() -> Self {
        Self {
            partition: String::new(),
            logged: None,
            pending: Summary::default(),
            peers: BTreeSet::new(),
            undecodable_peers: BTreeSet::new(),
        }
    }
}

impl<P: Ord + Clone> Discards<P> {
    /// A message from `peer` that did not decode; returns a summary to log.
    pub(super) fn undecodable(&mut self, now: SystemTime, peer: &P) -> Option<Summary> {
        self.pending.undecodable += 1;
        if self.undecodable_peers.len() < PEERS {
            self.undecodable_peers.insert(peer.clone());
        }
        self.record(now, peer)
    }

    /// A message from `peer` of epoch `theirs`, not this member's `ours`;
    /// returns a summary to log.
    pub(super) fn epoch(&mut self, now: SystemTime, peer: &P, theirs: u64, ours: u64) -> Option<Summary> {
        if theirs < ours {
            self.pending.earlier += 1;
        } else {
            self.pending.later += 1;
        }
        let (low, high) = self.pending.epochs.unwrap_or((theirs, theirs));
        self.pending.epochs = Some((low.min(theirs), high.max(theirs)));
        self.record(now, peer)
    }

    fn record(&mut self, now: SystemTime, peer: &P) -> Option<Summary> {
        if self.peers.len() < PEERS {
            self.peers.insert(peer.clone());
        }
        // The first discard logs at once; later ones wait for the interval
        // since the last line, which a burst after a quiet spell has passed.
        let since = self.logged.map(|logged| now.duration_since(logged).unwrap_or_default());
        if since.is_some_and(|since| since < SUMMARY_EVERY) {
            return None;
        }
        self.logged = Some(now);
        let mut summary = std::mem::take(&mut self.pending);
        summary.secs = since.map_or(0, |since| since.as_secs());
        summary.peers = std::mem::take(&mut self.peers).len();
        summary.undecodable_peers = std::mem::take(&mut self.undecodable_peers).len();
        Some(summary)
    }
}

impl Summary {
    /// Whether the undecodable messages pass [`UNDECODABLE_WARN`] from more
    /// than one peer: then this node may be the one on another build.
    pub(super) const fn warns(&self) -> bool {
        self.undecodable >= UNDECODABLE_WARN && self.undecodable_peers > 1
    }

    /// Log the summary for a member in epoch `ours` of the engine journaling
    /// to `partition`: a warning when undecodable messages pass their bound
    /// ([`Self::warns`]), otherwise an info line (messages of another epoch
    /// are expected for a while after a committee handoff, and a few
    /// undecodable ones are the sender's problem).
    pub(super) fn log(&self, partition: &str, ours: u64) {
        let (low, high) = self.epochs.unwrap_or_default();
        if self.warns() {
            tracing::warn!(
                scope = "this node or its peers",
                partition,
                epoch = ours,
                undecodable = self.undecodable,
                undecodable_peers = self.undecodable_peers,
                earlier = self.earlier,
                later = self.later,
                peers = self.peers,
                lowest_epoch = low,
                highest_epoch = high,
                secs = self.secs,
                action = "check with `qclient node info` that this node runs the current release and \
                          update it if not; if it does, report this line to the maintainer",
                "consensus messages from several peers could not be read and were dropped"
            );
        } else if self.undecodable > 0 {
            tracing::info!(
                scope = "peer",
                partition,
                epoch = ours,
                undecodable = self.undecodable,
                undecodable_peers = self.undecodable_peers,
                earlier = self.earlier,
                later = self.later,
                peers = self.peers,
                lowest_epoch = low,
                highest_epoch = high,
                secs = self.secs,
                warn_from = UNDECODABLE_WARN,
                action = "no action needed: usually a peer on another build; it warns past the bound \
                          from more than one peer",
                "some consensus messages from peers could not be read and were dropped"
            );
        } else {
            tracing::info!(
                scope = "peer",
                partition,
                epoch = ours,
                earlier = self.earlier,
                later = self.later,
                peers = self.peers,
                lowest_epoch = low,
                highest_epoch = high,
                secs = self.secs,
                "discarded consensus messages of another epoch from peers (expected for a while after a committee handoff)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000 + secs)
    }

    #[test]
    fn a_burst_logs_its_start_then_one_summary_per_interval() {
        let mut d = Discards::<u8>::default();
        let first = d.epoch(at(0), &1, 26, 27).expect("a burst begins with a line");
        assert_eq!(first, Summary { secs: 0, earlier: 1, peers: 1, epochs: Some((26, 26)), ..Summary::default() });
        for n in 1..=1_000u64 {
            assert_eq!(d.epoch(at(n / 2), &((n % 7) as u8), 26 - n % 2, 27), None);
        }
        assert_eq!(d.undecodable(at(599), &9), None);
        let summary = d.epoch(at(600), &1, 28, 27).expect("one summary per interval");
        assert_eq!(summary, Summary { secs: 600, undecodable: 1, earlier: 1_000, later: 1, peers: 8, undecodable_peers: 1, epochs: Some((25, 28)) });
    }

    #[test]
    fn a_burst_after_a_quiet_spell_logs_at_once() {
        let mut d = Discards::<u8>::default();
        assert!(d.undecodable(at(0), &1).is_some());
        let again = d.undecodable(at(3_000), &2).expect("a new burst");
        assert_eq!(again, Summary { secs: 3_000, undecodable: 1, peers: 1, undecodable_peers: 1, ..Summary::default() });
    }

    /// Undecodable messages warn only past their bound and from more than
    /// one peer: a single peer on another build, or a few strays, is info.
    #[test]
    fn undecodable_messages_warn_only_past_the_bound_from_several_peers() {
        let mut d = Discards::<u8>::default();
        assert!(!d.undecodable(at(0), &1).expect("a burst begins with a line").warns(), "one message");
        for n in 1..=500u64 {
            assert_eq!(d.undecodable(at(n), &1), None);
        }
        let one_peer = d.undecodable(at(600), &1).expect("one summary per interval");
        assert_eq!((one_peer.undecodable, one_peer.undecodable_peers), (501, 1));
        assert!(!one_peer.warns(), "one peer on another build is its operator's problem");
        for n in 1..UNDECODABLE_WARN {
            assert_eq!(d.undecodable(at(600 + n), &((n % 5) as u8)), None);
        }
        let several = d.undecodable(at(1_200), &9).expect("one summary per interval");
        assert_eq!((several.undecodable, several.undecodable_peers), (UNDECODABLE_WARN, 6));
        assert!(several.warns(), "the bound from several peers");
        for n in 1..UNDECODABLE_WARN - 1 {
            assert_eq!(d.undecodable(at(1_200 + n), &((n % 5) as u8)), None);
        }
        let below = d.undecodable(at(1_800), &9).expect("one summary per interval");
        assert_eq!(below.undecodable, UNDECODABLE_WARN - 1);
        assert!(!below.warns(), "below the bound");
    }

    #[test]
    fn each_summary_names_the_session_partition() {
        use std::{
            io,
            sync::{Arc, Mutex},
        };

        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        impl io::Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt().with_ansi(false).with_writer(move || writer.clone()).finish();
        let mut d = Discards::<u8>::default();
        d.partition = "app-00a2080".into();
        tracing::subscriber::with_default(subscriber, || {
            d.epoch(at(0), &1, 17, 18).expect("a burst begins with a line").log(&d.partition, 18);
            d.undecodable(at(600), &2).expect("one summary per interval").log(&d.partition, 18);
        });
        let out = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert_eq!(out.matches("partition=\"app-00a2080\"").count(), 2, "{out}");
    }
}
