//! App-shard resolver traffic in this process, by shard.
//!
//! A member asks one other member for a certificate it lacks, and that member
//! answers it alone. A shard whose sessions do not finalize keeps asking for
//! every view above its last finalization, so the request rate follows the
//! stall; before transmissions named their addressee, every member answered
//! every request and every member received every answer (2026-10-04 report:
//! ~1,100 answers a second on one node). These counts show the rate, how much
//! arrives addressed to someone else, and how much still comes from releases
//! that name nobody.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// Whom an inbound resolver transmission named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addressed {
    /// This member.
    Here,
    /// Another member; dropped unread.
    Elsewhere,
    /// Nobody: a broadcast from an earlier release, handled as before.
    Untagged,
}

/// Resolver messages by kind, with their bytes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct KindCounts {
    pub requests: u64,
    pub responses: u64,
    pub errors: u64,
    pub bytes: u64,
}

impl KindCounts {
    fn note(&mut self, cw_bytes: &[u8]) {
        // Commonware's resolver message: an 8-byte request id, then the
        // payload tag (0 request, 1 response, 2 error).
        match cw_bytes.get(8) {
            Some(0) => self.requests += 1,
            Some(1) => self.responses += 1,
            _ => self.errors += 1,
        }
        self.bytes += cw_bytes.len() as u64;
    }

    fn messages(&self) -> u64 {
        self.requests + self.responses + self.errors
    }

    fn add(&mut self, other: &Self) {
        self.requests += other.requests;
        self.responses += other.responses;
        self.errors += other.errors;
        self.bytes += other.bytes;
    }
}

/// One shard's resolver traffic since the last report.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ShardResolverTraffic {
    pub sent: KindCounts,
    /// Kept: addressed here or to nobody.
    pub received: KindCounts,
    /// Of `received`, those that named nobody.
    pub untagged: u64,
    pub elsewhere: KindCounts,
}

impl ShardResolverTraffic {
    fn add(&mut self, other: &Self) {
        self.sent.add(&other.sent);
        self.received.add(&other.received);
        self.untagged += other.untagged;
        self.elsewhere.add(&other.elsewhere);
    }
}

pub struct ResolverTraffic {
    shards: Mutex<(Instant, HashMap<Vec<u8>, ShardResolverTraffic>)>,
}

impl ResolverTraffic {
    fn new() -> Self {
        Self { shards: Mutex::new((Instant::now(), HashMap::new())) }
    }

    /// This process's counts.
    pub fn process() -> &'static Self {
        static TRAFFIC: OnceLock<ResolverTraffic> = OnceLock::new();
        TRAFFIC.get_or_init(Self::new)
    }

    fn with_shard(&self, filter: &[u8], update: impl FnOnce(&mut ShardResolverTraffic)) {
        let mut shards = self.shards.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match shards.1.get_mut(filter) {
            Some(shard) => update(shard),
            None => update(shards.1.entry(filter.to_vec()).or_default()),
        }
    }

    /// A resolver message this process's engine for `filter` sent.
    pub fn note_sent(&self, filter: &[u8], cw_bytes: &[u8]) {
        self.with_shard(filter, |shard| shard.sent.note(cw_bytes));
    }

    /// A resolver message that arrived for `filter`.
    pub fn note_received(&self, filter: &[u8], cw_bytes: &[u8], addressed: Addressed) {
        self.with_shard(filter, |shard| match addressed {
            Addressed::Elsewhere => shard.elsewhere.note(cw_bytes),
            Addressed::Here => shard.received.note(cw_bytes),
            Addressed::Untagged => {
                shard.received.note(cw_bytes);
                shard.untagged += 1;
            }
        });
    }

    /// The counts since the last call, and the seconds they cover.
    pub fn take(&self) -> (f64, Vec<(Vec<u8>, ShardResolverTraffic)>) {
        let mut shards = self.shards.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let seconds = std::mem::replace(&mut shards.0, Instant::now()).elapsed().as_secs_f64();
        (seconds, shards.1.drain().collect())
    }

    /// Log the counts since the last call: totals, and the busiest shards.
    pub fn log(&self) {
        let (seconds, mut shards) = self.take();
        if shards.is_empty() {
            return;
        }
        let mut total = ShardResolverTraffic::default();
        for (_, shard) in &shards {
            total.add(shard);
        }
        let inbound = |shard: &ShardResolverTraffic| shard.received.bytes + shard.elsewhere.bytes;
        shards.sort_by_key(|(_, shard)| std::cmp::Reverse(inbound(shard)));
        let busiest = shards
            .iter()
            .take(6)
            .map(|(filter, shard)| {
                let name = hex::encode(&filter[filter.len().saturating_sub(3)..]);
                format!(
                    "{name}:sent={}/{}/{},kept={}/{}/{},untagged={},elsewhere={}",
                    shard.sent.requests,
                    shard.sent.responses,
                    shard.sent.errors,
                    shard.received.requests,
                    shard.received.responses,
                    shard.received.errors,
                    shard.untagged,
                    shard.elsewhere.messages(),
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        let per_second = |count: u64| if seconds > 0.0 { count as f64 / seconds } else { 0.0 };
        tracing::info!(
            seconds = seconds.round() as u64,
            shards = shards.len(),
            sent_requests = total.sent.requests,
            sent_responses = total.sent.responses,
            sent_errors = total.sent.errors,
            sent_kib = total.sent.bytes / 1024,
            kept_requests = total.received.requests,
            kept_responses = total.received.responses,
            kept_errors = total.received.errors,
            kept_kib = total.received.bytes / 1024,
            kept_per_second = format!("{:.1}", per_second(total.received.messages())),
            untagged = total.untagged,
            elsewhere = total.elsewhere.messages(),
            elsewhere_kib = total.elsewhere.bytes / 1024,
            elsewhere_per_second = format!("{:.1}", per_second(total.elsewhere.messages())),
            busiest = %busiest,
            "app resolver traffic",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(kind: u8, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len.max(9)];
        bytes[8] = kind;
        bytes
    }

    #[test]
    fn traffic_is_counted_by_shard_kind_and_addressee_and_reset_when_taken() {
        let traffic = ResolverTraffic::new();
        let (a, b) = (vec![1u8; 35], vec![2u8; 35]);
        traffic.note_sent(&a, &message(0, 20));
        traffic.note_received(&a, &message(1, 100), Addressed::Here);
        traffic.note_received(&a, &message(1, 100), Addressed::Untagged);
        traffic.note_received(&a, &message(2, 9), Addressed::Elsewhere);
        traffic.note_received(&b, &message(0, 20), Addressed::Elsewhere);

        let (_, mut shards) = traffic.take();
        shards.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(shards.len(), 2);
        let first = shards[0].1;
        assert_eq!(first.sent, KindCounts { requests: 1, responses: 0, errors: 0, bytes: 20 });
        assert_eq!(first.received, KindCounts { requests: 0, responses: 2, errors: 0, bytes: 200 });
        assert_eq!(first.untagged, 1);
        assert_eq!(first.elsewhere, KindCounts { requests: 0, responses: 0, errors: 1, bytes: 9 });
        assert_eq!(shards[1].1.elsewhere.requests, 1);
        assert!(traffic.take().1.is_empty(), "each report covers only what came after the last");
    }
}
