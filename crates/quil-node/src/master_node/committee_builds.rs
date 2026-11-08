//! Which build and release each member of a served app committee runs, and
//! whether it follows GLOBAL, read from its verified PeerInfo: one line per
//! committee when its session changes and every thirty minutes, so members
//! that accept or reject proposals can be matched to builds, and members left
//! behind by a release they lack are named.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

/// How often a committee's member builds are logged again.
pub(super) const REPEAT: Duration = Duration::from_secs(1800);

/// A member's build as its PeerInfo states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Build {
    /// The first four bytes of its build fingerprint.
    Known([u8; 4]),
    /// PeerInfo without a fingerprint (an older build).
    NoFingerprint,
    /// No PeerInfo from it yet.
    NoPeerInfo,
    /// This node, which holds no PeerInfo of its own.
    ThisNode,
}

impl Build {
    pub(super) fn of(fingerprint: Option<Option<[u8; 32]>>) -> Self {
        match fingerprint {
            Some(Some(fingerprint)) => Build::Known([
                fingerprint[0],
                fingerprint[1],
                fingerprint[2],
                fingerprint[3],
            ]),
            Some(None) => Build::NoFingerprint,
            None => Build::NoPeerInfo,
        }
    }
}

/// A member's release as its PeerInfo states it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Release {
    /// `2.1.0.25.92`, or `2.1.0.25` from a build that advertises no subpatch.
    Known(String),
    /// No PeerInfo from it yet.
    NoPeerInfo,
    /// This node.
    ThisNode,
}

impl Release {
    pub(super) fn of(release: Option<String>) -> Self {
        match release {
            Some(release) if release.is_empty() => Release::Known("malformed version".into()),
            Some(release) => Release::Known(release),
            None => Release::NoPeerInfo,
        }
    }
}

/// A member is behind GLOBAL when the head its PeerInfo reported trails this
/// node's by more than this: peers republish PeerInfo every 30 minutes, which
/// is ~150 frames at ~12 s per frame.
pub(super) const BEHIND_FRAMES: u64 = 360;

/// Member indices grouped by key, the largest known group first and the
/// unknown ones (`known` false) after it, e.g. `6d91a5e8: 0,1,3; fca80080: 2;
/// no peer info: 4; this node: 5`.
fn grouped<K: Ord + Clone>(
    keys: &[K],
    known: impl Fn(&K) -> bool,
    name: impl Fn(&K) -> String,
) -> String {
    let mut by_key: BTreeMap<K, Vec<usize>> = BTreeMap::new();
    for (index, key) in keys.iter().enumerate() {
        by_key.entry(key.clone()).or_default().push(index);
    }
    let mut groups: Vec<_> = by_key.into_iter().collect();
    groups
        .sort_by_key(|(key, members)| (!known(key), std::cmp::Reverse(members.len()), key.clone()));
    groups
        .iter()
        .map(|(key, members)| {
            let members: Vec<String> = members.iter().map(usize::to_string).collect();
            format!("{}: {}", name(key), members.join(","))
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Member indices grouped by build, the largest known build first and
/// members without a fingerprint or PeerInfo, then this node, last, e.g.
/// `6d91a5e8: 0,1,3; fca80080: 2; no peer info: 4; this node: 5`.
pub(super) fn groups(builds: &[Build]) -> String {
    grouped(
        builds,
        |build| matches!(build, Build::Known(_)),
        |build| match build {
            Build::Known(prefix) => hex::encode(prefix),
            Build::NoFingerprint => "no fingerprint".to_string(),
            Build::NoPeerInfo => "no peer info".to_string(),
            Build::ThisNode => "this node".to_string(),
        },
    )
}

fn release_name(release: &Release) -> String {
    match release {
        Release::Known(release) => release.clone(),
        Release::NoPeerInfo => "no peer info".to_string(),
        Release::ThisNode => "this node".to_string(),
    }
}

/// Member indices grouped by release, like [`groups`], e.g.
/// `2.1.0.25.92: 0,1,3; 2.1.0.25: 2; no peer info: 4; this node: 5`.
pub(super) fn release_groups(releases: &[Release]) -> String {
    grouped(
        releases,
        |release| matches!(release, Release::Known(_)),
        release_name,
    )
}

/// The indices of members whose reported GLOBAL head trails `global_head`
/// by more than [`BEHIND_FRAMES`], with that head; members that reported no
/// head (`None` or 0) are left out.
fn behind(heads: &[Option<u64>], global_head: u64) -> Vec<(usize, u64)> {
    heads
        .iter()
        .enumerate()
        .filter_map(|(index, head)| {
            let head = head.filter(|head| *head > 0)?;
            (head.saturating_add(BEHIND_FRAMES) < global_head).then_some((index, head))
        })
        .collect()
}

/// Members behind GLOBAL ([`behind`]) as `index@head`, e.g.
/// `9@907919,12@907919`.
pub(super) fn behind_global(heads: &[Option<u64>], global_head: u64) -> Vec<String> {
    behind(heads, global_head)
        .into_iter()
        .map(|(index, head)| format!("{index}@{head}"))
        .collect()
}

/// The releases of the members behind GLOBAL ([`behind`]), their indices
/// grouped like [`release_groups`], e.g. `2.1.0.25.116: 9,12`: whether they
/// run this node's release tells an operator whose problem it is
/// ([`BEHIND_ACTION`]).
pub(super) fn behind_releases(
    heads: &[Option<u64>],
    releases: &[Release],
    global_head: u64,
) -> String {
    let mut by_release: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (index, _) in behind(heads, global_head) {
        let release = releases
            .get(index)
            .map_or_else(|| "unknown".to_string(), release_name);
        by_release
            .entry(release)
            .or_default()
            .push(index.to_string());
    }
    by_release
        .into_iter()
        .map(|(release, members)| format!("{release}: {}", members.join(",")))
        .collect::<Vec<_>>()
        .join("; ")
}

/// What an operator checks when members are behind GLOBAL: their release,
/// not an assumed one (2026-11-08: the members behind ran the current
/// release, and the action said they most likely ran an outdated one).
pub(super) const BEHIND_ACTION: &str = "nothing to fix on this node: these members report a \
    GLOBAL head over 360 frames behind this node's. Compare behind_releases with this node's \
    release: a member on the same release lags on its own host (its GLOBAL sync, CPU, disk or \
    network) and this ends when it catches up; one on an older release catches up once its \
    operator upgrades";

/// Per committee, the session last seen and when its builds were logged.
#[derive(Default)]
pub(super) struct CommitteeBuilds {
    seen: HashMap<Vec<u8>, ([u8; 32], Instant)>,
    /// Committees whose last line named members behind GLOBAL.
    behind: HashSet<Vec<u8>>,
}

impl CommitteeBuilds {
    /// Whether to log `filter`'s committee now: its session changed or
    /// [`REPEAT`] passed. A committee seen for the first time is only
    /// recorded, so the first line comes once peers had time to announce
    /// their PeerInfo.
    pub(super) fn due(&mut self, filter: &[u8], session: [u8; 32], now: Instant) -> bool {
        match self.seen.get_mut(filter) {
            None => {
                self.seen.insert(filter.to_vec(), (session, now));
                false
            }
            Some((seen, logged)) if *seen != session || now.duration_since(*logged) >= REPEAT => {
                *seen = session;
                *logged = now;
                true
            }
            Some(_) => false,
        }
    }

    /// Record whether `filter`'s committee has members behind GLOBAL now;
    /// true when it had some at its previous line and none any more, so the
    /// end of the condition is logged once.
    pub(super) fn caught_up(&mut self, filter: &[u8], behind: bool) -> bool {
        if behind {
            self.behind.insert(filter.to_vec());
            false
        } else {
            self.behind.remove(filter)
        }
    }

    /// Forget committees this node no longer serves.
    pub(super) fn retain(&mut self, served: &std::collections::BTreeSet<Vec<u8>>) {
        self.seen.retain(|filter, _| served.contains(filter));
        self.behind.retain(|filter| served.contains(filter));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_are_grouped_by_build_largest_first() {
        let (a, b) = ([0x6d, 0x91, 0xa5, 0xe8], [0xfc, 0xa8, 0x00, 0x80]);
        let builds = [
            Build::Known(a),
            Build::Known(b),
            Build::ThisNode,
            Build::Known(a),
            Build::NoPeerInfo,
            Build::NoFingerprint,
            Build::Known(a),
        ];
        assert_eq!(
            groups(&builds),
            "6d91a5e8: 0,3,6; fca80080: 1; no fingerprint: 5; no peer info: 4; this node: 2"
        );
        assert_eq!(Build::of(Some(Some([0xab; 32]))), Build::Known([0xab; 4]));
        assert_eq!(Build::of(Some(None)), Build::NoFingerprint);
        assert_eq!(Build::of(None), Build::NoPeerInfo);
    }

    #[test]
    fn members_are_grouped_by_release_and_named_when_behind_global() {
        let releases = [
            Release::of(Some("2.1.0.25.92".into())),
            Release::of(Some("2.1.0.25".into())),
            Release::ThisNode,
            Release::of(Some("2.1.0.25.92".into())),
            Release::of(None),
            Release::of(Some(String::new())),
        ];
        assert_eq!(
            release_groups(&releases),
            "2.1.0.25.92: 0,3; 2.1.0.25: 1; malformed version: 5; no peer info: 4; this node: 2"
        );
        let heads = [
            Some(908_800),
            Some(907_919),
            None,
            Some(908_440),
            Some(0),
            Some(908_439),
        ];
        assert_eq!(behind_global(&heads, 908_800), ["1@907919", "5@908439"]);
        assert!(
            behind_global(&heads, 0).is_empty(),
            "no local head, nobody is behind"
        );
    }

    /// The members behind GLOBAL are listed with their releases, so the
    /// action can leave the cause to what they run rather than assume an
    /// outdated release (2026-11-08: the members behind ran the current
    /// release).
    #[test]
    fn members_behind_global_are_named_with_their_releases() {
        let releases = [
            Release::of(Some("2.1.0.25.116".into())),
            Release::of(Some("2.1.0.25.116".into())),
            Release::ThisNode,
            Release::of(Some("2.1.0.25.92".into())),
            Release::of(Some("2.1.0.25.116".into())),
        ];
        let heads = [
            Some(908_000),
            Some(908_800),
            None,
            Some(907_919),
            Some(908_100),
        ];
        assert_eq!(
            behind_releases(&heads, &releases, 908_800),
            "2.1.0.25.116: 0,4; 2.1.0.25.92: 3",
            "behind-releases: only the members behind, by release"
        );
        assert_eq!(behind_releases(&heads, &releases, 0), "");
        assert!(
            BEHIND_ACTION.contains("behind_releases") && !BEHIND_ACTION.contains("most likely"),
            "behind-action: the action names what to check, not an assumed cause"
        );
    }

    #[test]
    fn the_end_of_members_behind_global_is_noted_once() {
        let mut builds = CommitteeBuilds::default();
        assert!(!builds.caught_up(b"f", false), "never behind");
        assert!(!builds.caught_up(b"f", true));
        assert!(!builds.caught_up(b"f", true));
        assert!(builds.caught_up(b"f", false), "caught up");
        assert!(!builds.caught_up(b"f", false), "noted once");
        assert!(!builds.caught_up(b"g", true));
        builds.retain(&std::collections::BTreeSet::new());
        assert!(!builds.caught_up(b"g", false), "forgotten once unserved");
    }

    #[test]
    fn a_committee_is_logged_on_a_new_session_and_every_half_hour() {
        let mut builds = CommitteeBuilds::default();
        let start = Instant::now();
        assert!(
            !builds.due(b"f", [1; 32], start),
            "first sight only records"
        );
        assert!(!builds.due(b"f", [1; 32], start + Duration::from_secs(60)));
        assert!(
            builds.due(b"f", [2; 32], start + Duration::from_secs(120)),
            "new session"
        );
        assert!(!builds.due(b"f", [2; 32], start + Duration::from_secs(1800)));
        assert!(
            builds.due(b"f", [2; 32], start + Duration::from_secs(1920)),
            "half an hour later"
        );
        builds.retain(&std::collections::BTreeSet::new());
        assert!(
            !builds.due(b"f", [2; 32], start + Duration::from_secs(1980)),
            "forgotten once unserved"
        );
    }
}
