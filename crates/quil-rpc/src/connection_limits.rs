//! Connection caps of the peer listener (`:8340`).
//!
//! The listener accepts a connection before it knows who dials, and a
//! connection keeps a file descriptor for as long as its peer answers h2
//! pings. Uncapped, a few hosts could hold every descriptor the process may
//! open, and the node's stores, which share that limit, would then fail to
//! open files. Each accepted connection takes a [`ConnectionSlot`], released
//! when the connection closes:
//!
//! - at most `per_source` from one public source address; an IPv6 source
//!   counts by its /64, which one host commonly holds whole. Loopback and
//!   private sources (this node's own workers, a cluster's machines) are not
//!   capped per address;
//! - at most `total` in all. The last eighth of them is a reserve: a
//!   connection accepted into it is kept past its handshake only when its
//!   peer is one the node privileges (its own identity, the GLOBAL committee,
//!   an active prover), so a flood of other peers cannot lock those out.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Default cap on connections from one public source address: well above
/// what the nodes behind one address open to a peer (a node's pooled channels
/// plus its short-lived per-request connections).
pub const DEFAULT_MAX_CONNECTIONS_PER_SOURCE: usize = 512;

/// File descriptors left to the rest of the process (stores, the p2p swarm,
/// logs, workers) when the total cap is derived from the descriptor limit.
pub const FD_HEADROOM: u64 = 4096;

/// The derived total cap never goes below this, so a host with a low
/// descriptor limit still serves its own workers and some peers.
pub const MIN_MAX_CONNECTIONS: usize = 1024;

/// The derived total cap never goes above this.
pub const MAX_DEFAULT_CONNECTIONS: usize = 65_536;

/// How often refused connections are summarized in the log.
pub const REFUSAL_REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// The default total cap for a process allowed `fd_limit` open files: what
/// the limit leaves after [`FD_HEADROOM`], within [`MIN_MAX_CONNECTIONS`]
/// and [`MAX_DEFAULT_CONNECTIONS`].
pub fn default_max_connections(fd_limit: u64) -> usize {
    usize::try_from(fd_limit.saturating_sub(FD_HEADROOM))
        .unwrap_or(usize::MAX)
        .clamp(MIN_MAX_CONNECTIONS, MAX_DEFAULT_CONNECTIONS)
}

/// Why a connection was not kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionRefusal {
    /// Its source address holds `per_source` connections.
    PerSource,
    /// The listener holds `total` connections.
    Total,
    /// It was accepted into the reserve and its peer is not privileged.
    Reserve,
}

/// Connections refused since the previous report.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RefusalReport {
    pub per_source: u64,
    pub total: u64,
    pub reserve: u64,
    /// The source address of the latest refusal.
    pub latest_source: Option<IpAddr>,
    /// Connections open when the report was taken.
    pub open: usize,
    /// Time since the previous report; `None` for the first.
    pub since_previous: Option<Duration>,
}

#[derive(Default)]
struct State {
    by_source: HashMap<IpAddr, usize>,
    open: usize,
    refused: RefusalReport,
    reported: Option<Instant>,
}

/// The caps (see the module docs).
pub struct ConnectionLimiter {
    per_source: usize,
    total: usize,
    reserved: usize,
    state: Mutex<State>,
}

impl ConnectionLimiter {
    /// At most `per_source` connections from one public source address and
    /// `total` in all (each at least 1).
    pub fn new(per_source: usize, total: usize) -> Arc<Self> {
        let total = total.max(1);
        Arc::new(Self {
            per_source: per_source.max(1),
            total,
            reserved: total / 8,
            state: Mutex::new(State::default()),
        })
    }

    pub fn per_source(&self) -> usize {
        self.per_source
    }

    pub fn total(&self) -> usize {
        self.total
    }

    /// Connections open now.
    pub fn open(&self) -> usize {
        self.lock().open
    }

    /// A slot for a connection from `source`, or why there is none.
    pub fn try_acquire(
        self: &Arc<Self>,
        source: IpAddr,
    ) -> Result<ConnectionSlot, ConnectionRefusal> {
        let key = source_key(source);
        let capped = !(uncapped_source(source) || uncapped_source(key));
        let mut state = self.lock();
        let refusal = if state.open >= self.total {
            Some(ConnectionRefusal::Total)
        } else if capped && state.by_source.get(&key).copied().unwrap_or(0) >= self.per_source {
            Some(ConnectionRefusal::PerSource)
        } else {
            None
        };
        if let Some(refusal) = refusal {
            state.count(refusal, source);
            return Err(refusal);
        }
        let reserve = state.open >= self.total - self.reserved;
        state.open += 1;
        if capped {
            *state.by_source.entry(key).or_insert(0) += 1;
        }
        Ok(ConnectionSlot {
            limiter: self.clone(),
            key: capped.then_some(key),
            source,
            reserve,
        })
    }

    /// The refusals since the previous report, at most once per
    /// [`REFUSAL_REPORT_INTERVAL`] and only when there were any.
    pub fn report_due(&self, now: Instant) -> Option<RefusalReport> {
        let mut state = self.lock();
        let refused = &state.refused;
        if refused.per_source + refused.total + refused.reserve == 0 {
            return None;
        }
        let since_previous = state.reported.map(|at| now.saturating_duration_since(at));
        if since_previous.is_some_and(|elapsed| elapsed < REFUSAL_REPORT_INTERVAL) {
            return None;
        }
        state.reported = Some(now);
        let open = state.open;
        Some(RefusalReport {
            open,
            since_previous,
            ..std::mem::take(&mut state.refused)
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn release(&self, key: Option<IpAddr>) {
        let mut state = self.lock();
        state.open = state.open.saturating_sub(1);
        if let Some(key) = key {
            let remaining = state.by_source.get_mut(&key).map(|count| {
                *count -= 1;
                *count
            });
            if remaining == Some(0) {
                state.by_source.remove(&key);
            }
        }
    }
}

impl State {
    fn count(&mut self, refusal: ConnectionRefusal, source: IpAddr) {
        match refusal {
            ConnectionRefusal::PerSource => self.refused.per_source += 1,
            ConnectionRefusal::Total => self.refused.total += 1,
            ConnectionRefusal::Reserve => self.refused.reserve += 1,
        }
        self.refused.latest_source = Some(source);
    }
}

/// A connection's place under the caps, released when dropped.
pub struct ConnectionSlot {
    limiter: Arc<ConnectionLimiter>,
    /// The source key it counts against, `None` for an uncapped source.
    key: Option<IpAddr>,
    source: IpAddr,
    reserve: bool,
}

impl ConnectionSlot {
    /// Whether the slot is in the reserve: keep the connection only for a
    /// privileged peer, otherwise [`Self::refuse`] it.
    pub fn in_reserve(&self) -> bool {
        self.reserve
    }

    /// Count the connection as refused from the reserve and release it.
    pub fn refuse(self) {
        self.limiter
            .lock()
            .count(ConnectionRefusal::Reserve, self.source);
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.limiter.release(self.key);
    }
}

impl std::fmt::Debug for ConnectionSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionSlot")
            .field("source", &self.source)
            .field("reserve", &self.reserve)
            .finish()
    }
}

/// The address a source counts under: an IPv4 address (also when mapped into
/// IPv6), or an IPv6 address's /64.
fn source_key(source: IpAddr) -> IpAddr {
    match source {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

/// Loopback, private and link-local sources: this node's own workers and a
/// cluster's machines, which may open many connections each.
fn uncapped_source(key: IpAddr) -> bool {
    match key {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_public_source_is_capped_and_its_slots_return_when_dropped() {
        let limiter = ConnectionLimiter::new(2, 100);
        let a = limiter.try_acquire(ip("203.0.113.7")).unwrap();
        let _b = limiter.try_acquire(ip("203.0.113.7")).unwrap();
        assert_eq!(
            limiter.try_acquire(ip("203.0.113.7")).unwrap_err(),
            ConnectionRefusal::PerSource
        );
        // Another address, and the same one mapped into IPv6, count apart and
        // together respectively.
        let _c = limiter.try_acquire(ip("203.0.113.8")).unwrap();
        assert_eq!(
            limiter.try_acquire(ip("::ffff:203.0.113.7")).unwrap_err(),
            ConnectionRefusal::PerSource
        );
        assert_eq!(limiter.open(), 3);
        drop(a);
        assert_eq!(limiter.open(), 2);
        let _d = limiter.try_acquire(ip("203.0.113.7")).unwrap();
    }

    #[test]
    fn an_ipv6_source_counts_by_its_64_and_local_sources_are_not_capped_per_address() {
        let limiter = ConnectionLimiter::new(1, 100);
        let _a = limiter.try_acquire(ip("2001:db8:1:2::1")).unwrap();
        assert_eq!(
            limiter.try_acquire(ip("2001:db8:1:2:ffff::9")).unwrap_err(),
            ConnectionRefusal::PerSource
        );
        let _b = limiter.try_acquire(ip("2001:db8:1:3::1")).unwrap();
        let local: Vec<_> = (0..10)
            .flat_map(|_| ["127.0.0.1", "10.1.2.3", "192.168.0.5", "::1", "fd00::1"])
            .map(|source| limiter.try_acquire(ip(source)).unwrap())
            .collect();
        assert_eq!(limiter.open(), 52);
        drop(local);
        assert_eq!(limiter.open(), 2);
    }

    #[test]
    fn the_total_is_capped_and_its_last_eighth_is_a_reserve() {
        let limiter = ConnectionLimiter::new(1, 16);
        let slots: Vec<_> = (0..16u8)
            .map(|n| {
                limiter
                    .try_acquire(IpAddr::from([198, 51, 100, n]))
                    .unwrap()
            })
            .collect();
        assert_eq!(
            slots.iter().filter(|slot| slot.in_reserve()).count(),
            2,
            "the last two of sixteen"
        );
        assert!(slots[..14].iter().all(|slot| !slot.in_reserve()));
        assert_eq!(
            limiter.try_acquire(ip("127.0.0.1")).unwrap_err(),
            ConnectionRefusal::Total,
            "the total caps local sources too"
        );
        let mut slots = slots;
        slots.pop().unwrap().refuse();
        assert_eq!(limiter.open(), 15);
        let now = Instant::now();
        let report = limiter.report_due(now).unwrap();
        assert_eq!(
            (report.per_source, report.total, report.reserve, report.open),
            (0, 1, 1, 15)
        );
        assert_eq!(report.since_previous, None);
        assert_eq!(limiter.report_due(now), None, "nothing refused since");
        assert!(limiter.try_acquire(ip("198.51.100.0")).is_err());
        assert_eq!(
            limiter.report_due(now + Duration::from_secs(1)),
            None,
            "within the interval"
        );
        let report = limiter.report_due(now + REFUSAL_REPORT_INTERVAL).unwrap();
        assert_eq!(report.per_source, 1);
        assert_eq!(report.latest_source, Some(ip("198.51.100.0")));
        assert_eq!(report.since_previous, Some(REFUSAL_REPORT_INTERVAL));
    }

    #[test]
    fn the_default_total_follows_the_descriptor_limit() {
        assert_eq!(default_max_connections(1024), MIN_MAX_CONNECTIONS);
        assert_eq!(default_max_connections(65_536), 61_440);
        assert_eq!(default_max_connections(1 << 20), MAX_DEFAULT_CONNECTIONS);
        assert_eq!(default_max_connections(u64::MAX), MAX_DEFAULT_CONNECTIONS);
    }
}
