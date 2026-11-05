//! Whether an archive peer may lack the drain anchor raise as its frame nears.
//! A build without the raise says nothing at that frame: it differs only once
//! a drain header it accepts and this one refuses is packed. So an archive
//! warns about each older archive peer, from its verified PeerInfo, in time
//! to upgrade it.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long before the raise's frame an older archive peer warns: a day of
/// 10 s frames, a restart's time many times over.
const LEAD_FRAMES: u64 = 8_640;

/// How often one peer warns again.
const REPEAT: Duration = Duration::from_secs(1800);

/// Peers remembered; more than the network's archives only off mainnet.
const MAX_PEERS: usize = 64;

/// Whether a peer archive on `peer_subpatch` is older than this node's
/// `own_subpatch` with GLOBAL head `head` and the raise at `raise_frame`. A
/// peer stating no subpatch is an older build; this node without one judges
/// nothing.
pub(super) fn behind_raise(
    raise_frame: u64,
    head: u64,
    own_subpatch: u16,
    peer_subpatch: Option<u32>,
) -> bool {
    raise_frame != u64::MAX
        && own_subpatch != 0
        && head.saturating_add(LEAD_FRAMES) >= raise_frame
        && peer_subpatch.is_none_or(|peer| peer < u32::from(own_subpatch))
}

/// When each peer last warned.
#[derive(Default)]
pub(super) struct RaiseWatch {
    warned: HashMap<Vec<u8>, Instant>,
}

impl RaiseWatch {
    /// Whether `peer` warns at `now`, which counts as its warning.
    pub(super) fn due(&mut self, peer: &[u8], now: Instant) -> bool {
        if self
            .warned
            .get(peer)
            .is_some_and(|at| now.saturating_duration_since(*at) < REPEAT)
        {
            return false;
        }
        if self.warned.len() >= MAX_PEERS {
            self.warned.clear();
        }
        self.warned.insert(peer.to_vec(), now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_older_archive_warns_from_the_lead_and_past_the_raise() {
        let raise = 100_000;
        let lead = raise - LEAD_FRAMES;
        assert!(!behind_raise(raise, lead - 1, 115, Some(114)));
        assert!(behind_raise(raise, lead, 115, Some(114)));
        assert!(behind_raise(raise, raise + 1, 115, Some(114)));
        assert!(behind_raise(raise, lead, 115, None), "no subpatch: older");
    }

    #[test]
    fn a_current_archive_or_an_unset_raise_stays_quiet() {
        let raise = 100_000;
        assert!(!behind_raise(raise, raise, 115, Some(115)));
        assert!(!behind_raise(raise, raise, 115, Some(116)));
        assert!(!behind_raise(u64::MAX, u64::MAX, 115, Some(114)));
        assert!(!behind_raise(raise, raise, 0, Some(114)), "no own subpatch");
    }

    #[test]
    fn each_peer_warns_once_per_interval() {
        let start = Instant::now();
        let mut watch = RaiseWatch::default();
        assert!(watch.due(b"a", start));
        assert!(!watch.due(b"a", start + REPEAT - Duration::from_secs(1)));
        assert!(watch.due(b"b", start));
        assert!(watch.due(b"a", start + REPEAT));
        for peer in 0..MAX_PEERS as u32 * 2 {
            watch.due(&peer.to_be_bytes(), start);
        }
        assert!(watch.warned.len() <= MAX_PEERS, "bounded");
    }
}
