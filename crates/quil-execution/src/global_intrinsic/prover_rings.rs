//! Reward rings ordered by seniority (owner decision 2026-10-05).
//!
//! A shard's members rank by cohort, then seniority, then address, and a
//! member's ring is `rank / RING_GROUP_SIZE`:
//! - **Cohort** (`RingEpoch`): the epoch its join confirm activated it, or the
//!   epoch a split, merge or the committee-handoff flag day moved it onto its
//!   shard. Earlier cohorts rank first, so a member never loses its place to a
//!   later joiner, whatever that joiner's seniority.
//! - **Seniority** (`RingSeniority`): the prover's seniority when its join
//!   confirm materialized. Most senior first. It is never updated, so ranking
//!   reads committed fields that do not drift (live seniority accrues every
//!   frame, and ranking by it once forked the prover-tree root).
//! - **Address** breaks ties.
//!
//! Rings are assigned when a committee forms, never during reward issuance:
//! a session's at its creation, recorded with it. Membership changes at epoch
//! boundaries, so a departure moves the members below it up at the next
//! boundary. A split or merge re-ranks the shard it creates as one cohort, by
//! seniority alone, and a split moves its most senior provers together onto
//! its most valuable child ([`split_groups`]).
//!
//! The rule governs frames from the committee-handoff activation
//! ([`governs`]); earlier frames keep the rule they were executed under.

use std::cmp::Ordering;

use quil_types::error::{QuilError, Result};

use crate::global_schema::{read_field, write_field};

use super::materialize::RING_GROUP_SIZE;

const ALLOCATION: &str = "allocation:ProverAllocation";

/// What ranks one member of a shard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingKey {
    /// Earlier cohorts rank first.
    pub cohort: u64,
    /// Within a cohort, the most senior rank first.
    pub seniority: u64,
}

/// Whether the seniority ring rule governs `frame`: from the committee-handoff
/// activation, the flag day that also snapshots every allocation's key.
pub fn governs(frame: u64) -> bool {
    quil_types::consensus::committee_handoff_policy().is_some_and(|policy| frame >= policy.activation_frame)
}

fn be_u64(bytes: &[u8]) -> Option<u64> {
    <[u8; 8]>::try_from(bytes).ok().map(u64::from_be_bytes)
}

/// The key recorded on an allocation, if it has one.
pub fn read_key(allocation: &quil_tries::VectorCommitmentTree) -> Option<RingKey> {
    Some(RingKey {
        cohort: be_u64(&read_field(allocation, ALLOCATION, "RingEpoch")?)?,
        seniority: be_u64(&read_field(allocation, ALLOCATION, "RingSeniority")?)?,
    })
}

/// Record `key` on an allocation.
pub fn write_key(allocation: &mut quil_tries::VectorCommitmentTree, key: RingKey) -> Result<()> {
    write_field(allocation, ALLOCATION, "RingEpoch", &key.cohort.to_be_bytes())?;
    write_field(allocation, ALLOCATION, "RingSeniority", &key.seniority.to_be_bytes())
}

/// The key a join confirm at `frame` records for a prover of `seniority`:
/// its cohort is the epoch the confirm activates it (E+2 of the join).
pub fn joined(frame: u64, seniority: u64) -> RingKey {
    RingKey { cohort: quil_types::consensus::epoch_for_frame(frame) + 1, seniority }
}

/// The key of an allocation confirmed before the rule, recorded at the flag
/// day: its cohort from its join confirm (genesis allocations, never
/// confirmed, are cohort 0), its seniority the prover's at the flag day.
pub fn preexisting(join_confirm_frame: u64, seniority: u64) -> RingKey {
    let cohort = match join_confirm_frame {
        0 => 0,
        frame => quil_types::consensus::epoch_for_frame(frame) + 1,
    };
    RingKey { cohort, seniority }
}

/// The key of an allocation a topology change moves at `frame`: a new cohort
/// in its new shard, its seniority kept.
pub fn moved(key: RingKey, frame: u64) -> RingKey {
    RingKey { cohort: quil_types::consensus::epoch_for_frame(frame), seniority: key.seniority }
}

fn rank(a: (&[u8], RingKey), b: (&[u8], RingKey), one_cohort: bool) -> Ordering {
    let cohort = if one_cohort { Ordering::Equal } else { a.1.cohort.cmp(&b.1.cohort) };
    cohort.then(b.1.seniority.cmp(&a.1.seniority)).then_with(|| a.0.cmp(b.0))
}

/// The ring of each of `members` (prover address, key), in input order.
/// `one_cohort` ranks by seniority alone, as a split or merge does for the
/// shard it creates.
pub fn assign(members: &[(&[u8], RingKey)], one_cohort: bool) -> Vec<u8> {
    let mut order: Vec<usize> = (0..members.len()).collect();
    order.sort_by(|&a, &b| rank(members[a], members[b], one_cohort));
    let mut rings = vec![0u8; members.len()];
    for (position, index) in order.into_iter().enumerate() {
        rings[index] = u8::try_from(position as u64 / RING_GROUP_SIZE).unwrap_or(u8::MAX);
    }
    rings
}

/// The children of a split, most valuable first: by reward basis (`size`,
/// the child's state size at the split frame), then filter bytes.
pub fn children_by_value(children: &[Vec<u8>], size: impl Fn(&[u8]) -> u128) -> Vec<usize> {
    let sizes: Vec<u128> = children.iter().map(|child| size(child)).collect();
    let mut order: Vec<usize> = (0..children.len()).collect();
    order.sort_by(|&a, &b| sizes[b].cmp(&sizes[a]).then_with(|| children[a].cmp(&children[b])));
    order
}

/// A split's provers in `k` groups, the most senior together: group `i` goes
/// to the `i`-th most valuable child ([`children_by_value`]). Provers are
/// ordered by seniority, then address; the first `n % k` groups take one
/// extra, so every child receives `⌊n/k⌋` or `⌈n/k⌉`.
pub fn split_groups<T>(mut provers: Vec<(T, &[u8], RingKey)>, k: usize) -> Result<Vec<Vec<T>>> {
    if k == 0 {
        return Err(QuilError::InvalidArgument("split has no children".into()));
    }
    provers.sort_by(|a, b| rank((a.1, a.2), (b.1, b.2), true));
    let (base, extra) = (provers.len() / k, provers.len() % k);
    let mut provers = provers.into_iter();
    Ok((0..k)
        .map(|group| provers.by_ref().take(base + usize::from(group < extra)).map(|p| p.0).collect())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(cohort: u64, seniority: u64) -> RingKey {
        RingKey { cohort, seniority }
    }

    #[test]
    fn an_earlier_cohort_keeps_its_ring_and_a_cohort_ranks_by_seniority() {
        // Epoch 0: A–C join with seniority 0. Epoch 1: D–J join; I and J are
        // more senior than D–H. A ring holds eight.
        let names: Vec<[u8; 1]> = (b'A'..=b'J').map(|c| [c]).collect();
        let keys = [
            key(0, 0), key(0, 0), key(0, 0),
            key(1, 5), key(1, 5), key(1, 5), key(1, 5), key(1, 5),
            key(1, 900), key(1, 800),
        ];
        let members: Vec<(&[u8], RingKey)> = names.iter().map(|n| n.as_slice()).zip(keys).collect();
        let rings = assign(&members, false);
        let ring = |c: u8| rings[(c - b'A') as usize];
        for c in [b'A', b'B', b'C', b'I', b'J', b'D', b'E', b'F'] {
            assert_eq!(ring(c), 0, "{}", c as char);
        }
        assert_eq!((ring(b'G'), ring(b'H')), (1, 1));
        // Input order never matters.
        let mut reversed = members.clone();
        reversed.reverse();
        let mut expected = rings.clone();
        expected.reverse();
        assert_eq!(assign(&reversed, false), expected);

        // A later cohort never displaces an earlier one, however senior.
        let full: Vec<[u8; 1]> = (0u8..9).map(|i| [i]).collect();
        let mut members: Vec<(&[u8], RingKey)> = full[..8].iter().map(|n| (n.as_slice(), key(0, 0))).collect();
        members.push((full[8].as_slice(), key(1, u64::MAX)));
        assert_eq!(assign(&members, false)[8], 1);
        // A split or merge re-ranks as one cohort.
        assert_eq!(assign(&members, true)[8], 0);

        // When a ring-0 member leaves, the next boundary's committee moves
        // the first ring-1 member up.
        let departed: Vec<(&[u8], RingKey)> = members[1..].to_vec();
        assert_eq!(assign(&departed, false)[7], 0);
    }

    #[test]
    fn a_split_moves_its_most_senior_together_to_its_most_valuable_child() {
        let names: Vec<[u8; 1]> = (0u8..7).map(|i| [i]).collect();
        let seniority = [10, 70, 30, 60, 20, 50, 40];
        let provers: Vec<(u8, &[u8], RingKey)> = names
            .iter()
            .zip(seniority)
            .map(|(name, s)| (name[0], name.as_slice(), key(9, s)))
            .collect();
        let groups = split_groups(provers, 3).unwrap();
        // 7 over 3 children: 3, 2, 2, by seniority 70 60 50 | 40 30 | 20 10.
        assert_eq!(groups, vec![vec![1, 3, 5], vec![6, 2], vec![4, 0]]);
        assert!(split_groups(Vec::<(u8, &[u8], RingKey)>::new(), 0).is_err());

        let children = vec![vec![0xa1], vec![0xa0], vec![0xa2]];
        let sizes = |child: &[u8]| -> u128 { if child == [0xa2] { 5 } else { 9 } };
        // Equal sizes fall back to filter order.
        assert_eq!(children_by_value(&children, sizes), vec![1, 0, 2]);
    }

    #[test]
    fn keys_round_trip_and_cohorts_follow_the_epoch() {
        let epoch = quil_types::consensus::epoch_length_frames();
        assert_eq!(joined(epoch * 3 + 5, 77), key(4, 77), "a confirm in E activates at E+1's boundary");
        assert_eq!(preexisting(0, 9), key(0, 9), "genesis allocations are the first cohort");
        assert_eq!(preexisting(epoch * 2, 9), key(3, 9));
        assert_eq!(moved(key(1, 9), epoch * 7), key(7, 9));
        let mut tree = quil_tries::VectorCommitmentTree::new();
        assert_eq!(read_key(&tree), None);
        write_key(&mut tree, key(12, 345)).unwrap();
        assert_eq!(read_key(&tree), Some(key(12, 345)));
    }
}
