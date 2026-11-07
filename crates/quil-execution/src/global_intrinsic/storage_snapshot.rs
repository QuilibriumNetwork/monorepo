//! The certified state a shard's storage registrations commit to (hash
//! storage proofs, decided 2026-10-22).
//!
//! A registration for epoch `X` binds `comm_D`, a commitment to each of the
//! shard's leaves as data. That data is the shard's state as GLOBAL certified
//! it: the state roots of the first header of the shard GLOBAL executes at or
//! after [`storage_snapshot_frame`]`(X)`, recorded here per shard and epoch.
//! Every member and archive reads the same roots however it came to hold that
//! state — by executing the shard, or by syncing its subtree pinned to them:
//! a joiner, a member of a shard a split or merge creates, one that
//! state-jumped past the snapshot.
//!
//! A shard a split or merge creates at `X` has no header before `X`. Its data
//! is its parents' snapshots, restricted to its subtree ([`sources`]).
//!
//! [`storage_snapshot_frame`]: quil_types::consensus::storage_snapshot_frame

use quil_types::consensus::StorageSnapshotRoots;
use quil_types::error::Result;

use crate::global_schema::{read_field, write_field, write_type, GLOBAL_INTRINSIC_ADDRESS};
use crate::hypergraph_state::HypergraphState;

pub const CLASS: &str = "storage:StorageSnapshot";

/// Epochs whose records are kept: a record is read until its epoch's
/// registrations are sealed, before the epoch that reuses it begins.
const RING: u64 = 4;
const ENCODED_LEN: usize = 24 + 4 * 32;

/// `poseidon("STORAGE_SNAPSHOT" || epoch mod 4 || filter)`: the records are
/// reused, never removed, each naming the epoch it holds.
pub fn snapshot_address(epoch: u64, filter: &[u8]) -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(17 + filter.len());
    preimage.extend_from_slice(b"STORAGE_SNAPSHOT");
    preimage.push((epoch % RING) as u8);
    preimage.extend_from_slice(filter);
    quil_crypto::poseidon::hash_bytes_to_32(&preimage)
}

pub fn encode(snapshot: &StorageSnapshotRoots) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENCODED_LEN);
    out.extend_from_slice(&snapshot.epoch.to_be_bytes());
    out.extend_from_slice(&snapshot.frame.to_be_bytes());
    out.extend_from_slice(&snapshot.anchor.to_be_bytes());
    for root in &snapshot.roots {
        out.extend_from_slice(root);
    }
    out
}

pub fn decode(data: &[u8]) -> Option<StorageSnapshotRoots> {
    if data.len() != ENCODED_LEN {
        return None;
    }
    let word = |i: usize| u64::from_be_bytes(data[8 * i..8 * i + 8].try_into().expect("8 bytes"));
    let mut roots = [[0u8; 32]; 4];
    for (phase, root) in roots.iter_mut().enumerate() {
        root.copy_from_slice(&data[24 + 32 * phase..24 + 32 * (phase + 1)]);
    }
    Some(StorageSnapshotRoots {
        epoch: word(0),
        frame: word(1),
        anchor: word(2),
        roots,
    })
}

/// The shard and snapshot a record's tree holds.
pub fn from_tree(
    tree: &quil_tries::VectorCommitmentTree,
) -> Option<(Vec<u8>, StorageSnapshotRoots)> {
    let filter = read_field(tree, CLASS, "ShardFilter")?;
    Some((filter, decode(&read_field(tree, CLASS, "Snapshot")?)?))
}

pub fn to_tree(
    filter: &[u8],
    snapshot: &StorageSnapshotRoots,
) -> Result<quil_tries::VectorCommitmentTree> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    write_type(&mut tree, CLASS)?;
    write_field(&mut tree, CLASS, "ShardFilter", filter)?;
    write_field(&mut tree, CLASS, "Snapshot", &encode(snapshot))?;
    Ok(tree)
}

/// `filter`'s snapshot for `epoch` in committed `state`, once recorded.
pub fn read(
    state: &HypergraphState,
    epoch: u64,
    filter: &[u8],
) -> Result<Option<StorageSnapshotRoots>> {
    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
    Ok(
        match state.get(
            &GLOBAL_INTRINSIC_ADDRESS[..],
            &snapshot_address(epoch, filter)?,
            &va_disc,
        )? {
            Some(blob) if !blob.is_empty() => from_tree(
                &crate::prover_registry::rebuild_vertex_tree_from_blob(&blob),
            )
            .filter(|(held, snapshot)| held == filter && snapshot.epoch == epoch)
            .map(|(_, snapshot)| snapshot),
            _ => None,
        },
    )
}

/// Record the roots of `header`, executed in GLOBAL frame `frame`, as its
/// shard's snapshot for the next epoch: the first such header at or after
/// that epoch's snapshot frame, in a hash-proof epoch. True when it recorded.
pub fn record(
    state: &HypergraphState,
    frame: u64,
    header: &super::frame_header::FrameHeader,
) -> Result<bool> {
    let epoch = quil_types::consensus::epoch_for_frame(frame) + 1;
    if !quil_types::consensus::hash_storage_proofs_at(epoch)
        || frame < quil_types::consensus::storage_snapshot_frame(epoch)
        || header.address.is_empty()
    {
        return Ok(false);
    }
    let Ok(roots) = header
        .state_roots
        .iter()
        .map(|root| <[u8; 32]>::try_from(root.as_slice()))
        .collect::<std::result::Result<Vec<_>, _>>()
    else {
        return Ok(false);
    };
    let Ok(roots) = <[[u8; 32]; 4]>::try_from(roots) else {
        return Ok(false);
    };
    if read(state, epoch, &header.address)?.is_some() {
        return Ok(false);
    }
    let snapshot = StorageSnapshotRoots {
        epoch,
        frame: header.frame_number,
        anchor: header.global_frame_number,
        roots,
    };
    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
    let blob = crate::prover_registry::vertex_tree_to_blob(&to_tree(&header.address, &snapshot)?);
    state.set(
        &GLOBAL_INTRINSIC_ADDRESS[..],
        &snapshot_address(epoch, &header.address)?,
        &va_disc,
        frame,
        blob,
    )?;
    Ok(true)
}

/// One shard whose snapshot a registration's data is read from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    pub filter: Vec<u8>,
    pub snapshot: StorageSnapshotRoots,
}

/// Where `filter`'s data for `epoch` is read from: the parent of a split
/// applying at `epoch` that creates it, each shard a merge applying then
/// joins into it, or else its own snapshot. `None` until every one of them
/// is recorded (`lookup`).
pub fn sources(
    filter: &[u8],
    epoch: u64,
    changes: &[quil_types::store::PendingShardChange],
    lookup: impl Fn(&[u8]) -> Option<StorageSnapshotRoots>,
) -> Option<Vec<Source>> {
    use quil_types::store::ShardChangeKind;
    let mut parents: Vec<Vec<u8>> = changes
        .iter()
        .filter(|change| change.effective_epoch == epoch)
        .find_map(|change| match change.kind {
            ShardChangeKind::Split if change.children.iter().any(|child| child == filter) => {
                Some(vec![change.parent.clone()])
            }
            ShardChangeKind::Merge if change.parent == filter => Some(change.children.clone()),
            _ => None,
        })
        .unwrap_or_else(|| vec![filter.to_vec()]);
    parents.sort();
    parents.dedup();
    if parents.is_empty() {
        return None;
    }
    parents
        .into_iter()
        .map(|parent| {
            lookup(&parent)
                .filter(|snapshot| snapshot.epoch == epoch)
                .map(|snapshot| Source {
                    filter: parent,
                    snapshot,
                })
        })
        .collect()
}

/// Encode each shard's snapshot sources, as a master sends them to the
/// worker that registers the shards.
pub fn encode_plan(plan: &[(Vec<u8>, Vec<Source>)]) -> Vec<u8> {
    let mut out = Vec::new();
    if plan.is_empty() {
        return out;
    }
    out.extend_from_slice(&(plan.len() as u32).to_be_bytes());
    for (filter, sources) in plan {
        out.extend_from_slice(&(filter.len() as u16).to_be_bytes());
        out.extend_from_slice(filter);
        out.extend_from_slice(&(sources.len() as u16).to_be_bytes());
        for source in sources {
            out.extend_from_slice(&(source.filter.len() as u16).to_be_bytes());
            out.extend_from_slice(&source.filter);
            out.extend_from_slice(&encode(&source.snapshot));
        }
    }
    out
}

/// [`encode_plan`]'s inverse; an empty encoding is an empty plan.
pub fn decode_plan(data: &[u8]) -> Option<Vec<(Vec<u8>, Vec<Source>)>> {
    const MAX_ENTRIES: usize = 4096;
    if data.is_empty() {
        return Some(Vec::new());
    }
    let mut c = 0usize;
    let mut take = |n: usize| -> Option<&[u8]> {
        let bytes = data.get(c..c.checked_add(n)?)?;
        c += n;
        Some(bytes)
    };
    let count = u32::from_be_bytes(take(4)?.try_into().ok()?) as usize;
    if count > MAX_ENTRIES {
        return None;
    }
    let mut plan = Vec::with_capacity(count);
    for _ in 0..count {
        let len = u16::from_be_bytes(take(2)?.try_into().ok()?) as usize;
        let filter = take(len)?.to_vec();
        let sources_len = u16::from_be_bytes(take(2)?.try_into().ok()?) as usize;
        let mut sources = Vec::with_capacity(sources_len.min(16));
        for _ in 0..sources_len {
            let len = u16::from_be_bytes(take(2)?.try_into().ok()?) as usize;
            let source = take(len)?.to_vec();
            sources.push(Source {
                filter: source,
                snapshot: decode(take(ENCODED_LEN)?)?,
            });
        }
        plan.push((filter, sources));
    }
    (c == data.len()).then_some(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::store::{PendingShardChange, ShardChangeKind};

    fn snapshot(epoch: u64, seed: u8) -> StorageSnapshotRoots {
        StorageSnapshotRoots {
            epoch,
            frame: 40 + seed as u64,
            anchor: 300,
            roots: [[seed; 32], [0; 32], [seed ^ 1; 32], [0; 32]],
        }
    }

    #[test]
    fn a_plan_survives_its_encoding() {
        let plan = vec![
            (
                vec![1, 2],
                vec![Source {
                    filter: vec![1],
                    snapshot: snapshot(4, 1),
                }],
            ),
            (
                vec![3],
                vec![
                    Source {
                        filter: vec![3, 0],
                        snapshot: snapshot(4, 2),
                    },
                    Source {
                        filter: vec![3, 1],
                        snapshot: snapshot(4, 3),
                    },
                ],
            ),
        ];
        let encoded = encode_plan(&plan);
        assert_eq!(decode_plan(&encoded), Some(plan));
        assert_eq!(decode_plan(&encoded[..encoded.len() - 1]), None);
        assert_eq!(decode_plan(&[encoded.as_slice(), &[0]].concat()), None);
        assert_eq!(decode_plan(&[]), Some(Vec::new()));
    }

    #[test]
    fn a_record_survives_its_encoding() {
        let record = snapshot(7, 9);
        assert_eq!(decode(&encode(&record)), Some(record.clone()));
        assert_eq!(decode(&encode(&record)[1..]), None);
        let tree = to_tree(&[1, 2, 3], &record).unwrap();
        assert_eq!(from_tree(&tree), Some((vec![1, 2, 3], record)));
        assert_eq!(
            snapshot_address(7, &[1]).unwrap(),
            snapshot_address(11, &[1]).unwrap(),
            "a ring of four epochs"
        );
        assert_ne!(
            snapshot_address(7, &[1]).unwrap(),
            snapshot_address(8, &[1]).unwrap()
        );
    }

    struct StubProver;
    impl quil_types::crypto::InclusionProver for StubProver {
        fn commit_raw(&self, _: &[u8], _: u64) -> Result<Vec<u8>> {
            Ok(vec![0u8; 64])
        }
        fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> {
            Ok(vec![])
        }
        fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> {
            Ok(true)
        }
        fn prove_multiple(
            &self,
            _: &[&[u8]],
            _: &[&[u8]],
            _: &[u64],
            _: u64,
        ) -> Result<Box<dyn quil_types::crypto::Multiproof>> {
            Err(quil_types::error::QuilError::Internal(
                "batch not supported".into(),
            ))
        }
        fn verify_multiple(
            &self,
            _: &[&[u8]],
            _: &[&[u8]],
            _: &[u64],
            _: u64,
            _: &[u8],
            _: &[u8],
        ) -> bool {
            true
        }
    }

    /// The first header executed at or after an epoch's snapshot frame names
    /// the next epoch's snapshot; later ones and earlier ones do not.
    #[test]
    fn the_first_header_at_or_after_the_snapshot_frame_records_the_next_epochs_snapshot() {
        let length = quil_types::consensus::epoch_length_frames();
        let epoch = 6;
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch));
        let state =
            HypergraphState::new(std::sync::Arc::new(quil_hypergraph::HypergraphCrdt::new(
                std::sync::Arc::new(crate::hypergraph_state::InMemoryHypergraphStore::new()),
                std::sync::Arc::new(StubProver),
            )));
        let at = quil_types::consensus::storage_snapshot_frame(epoch);
        assert_eq!(
            at,
            (epoch - 1) * length + quil_types::consensus::STORAGE_SNAPSHOT_OFFSET
        );
        let header = |frame_number: u64, seed: u8| super::super::frame_header::FrameHeader {
            address: vec![0xA0, 7],
            frame_number,
            global_frame_number: at - 3,
            state_roots: vec![vec![seed; 32], vec![0; 32], vec![seed; 32], vec![0; 32]],
            ..Default::default()
        };
        assert!(
            !record(&state, at - 1, &header(50, 1)).unwrap(),
            "before the snapshot frame"
        );
        assert!(
            !record(
                &state,
                at,
                &super::super::frame_header::FrameHeader {
                    state_roots: vec![vec![1; 32]],
                    ..header(51, 1)
                }
            )
            .unwrap(),
            "not four roots"
        );
        assert!(record(&state, at, &header(52, 2)).unwrap());
        assert!(
            !record(&state, at + 1, &header(53, 3)).unwrap(),
            "recorded once"
        );
        let recorded = read(&state, epoch, &[0xA0, 7]).unwrap().unwrap();
        assert_eq!(
            (recorded.frame, recorded.anchor, recorded.roots[0]),
            (52, at - 3, [2; 32])
        );
        assert_eq!(
            read(&state, epoch + 4, &[0xA0, 7]).unwrap(),
            None,
            "a ring slot holds one epoch"
        );
        assert!(
            !record(&state, epoch * length + 1, &header(54, 4)).unwrap(),
            "the epoch after's snapshot frame is not here yet"
        );
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }

    #[test]
    fn a_shard_reads_its_own_snapshot_a_split_child_its_parents_and_a_merge_its_sources() {
        let (parent, left, right, other) = (vec![0xA0], vec![0xA0, 0], vec![0xA0, 1], vec![0xB0]);
        let lookup = |filter: &[u8]| match filter {
            [0xA0] => Some(snapshot(9, 1)),
            [0xA0, 0] => Some(snapshot(9, 2)),
            [0xA0, 1] => Some(snapshot(9, 3)),
            [0xB0] => Some(snapshot(8, 4)),
            _ => None,
        };
        let own = sources(&parent, 9, &[], lookup).unwrap();
        assert_eq!(
            own,
            vec![Source {
                filter: parent.clone(),
                snapshot: snapshot(9, 1)
            }]
        );
        assert_eq!(
            sources(&other, 9, &[], lookup),
            None,
            "recorded for another epoch"
        );
        assert_eq!(sources(&[0xC0], 9, &[], lookup), None, "not recorded");
        let split = PendingShardChange {
            kind: ShardChangeKind::Split,
            parent: parent.clone(),
            children: vec![left.clone(), right.clone()],
            effective_epoch: 9,
            proposed_frame: 1,
        };
        assert_eq!(
            sources(&right, 9, std::slice::from_ref(&split), lookup).unwrap(),
            vec![Source {
                filter: parent.clone(),
                snapshot: snapshot(9, 1)
            }],
            "a split child reads its parent"
        );
        assert_eq!(
            sources(&right, 10, std::slice::from_ref(&split), lookup),
            None,
            "a change of another epoch"
        );
        let merge = PendingShardChange {
            kind: ShardChangeKind::Merge,
            parent: parent.clone(),
            children: vec![right.clone(), left.clone()],
            effective_epoch: 9,
            proposed_frame: 1,
        };
        assert_eq!(
            sources(&parent, 9, &[merge], lookup).unwrap(),
            vec![
                Source {
                    filter: left,
                    snapshot: snapshot(9, 2)
                },
                Source {
                    filter: right,
                    snapshot: snapshot(9, 3)
                },
            ],
            "a merge reads each source"
        );
    }
}
