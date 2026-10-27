//! Hash storage proof labels computed ahead (decided 2026-10-26).
//!
//! A leaf's labels depend on its key (the member, the leaf and the epoch) and
//! its node count, never on its data. So a member labels the leaves it will
//! register for an epoch during the epoch before ([`precompute`]), at a count
//! the data may still change around
//! (`quil_crypto::storage_proof::precompute_nodes`), and keeps every layer on
//! disk. At the snapshot only the data's part is left
//! (`storage_snapshot::encode_member`), and the seal opens the kept layers
//! rather than labelling the leaf again (`storage_snapshot::prepare_member_seat`).
//! Labelling takes about an hour per GiB of a leaf on one core, which the
//! renewal's grace after the snapshot could not hold for a large shard.
//!
//! A leaf's labels take eleven times its replica on disk, plus its column
//! digests, until its epoch begins: a registration is sealed before then.

use std::fs::{self, File};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use quil_crypto::sdr::SdrParams;
use quil_crypto::storage_hash::{self as hash, Digest};
use quil_crypto::storage_proof::{LabelSource, Node, NODE_BYTES};
use quil_hypergraph::HypergraphCrdt;
use quil_types::error::{QuilError, Result};
use tracing::info;

static STORE: OnceLock<LabelStore> = OnceLock::new();

/// Keep this process's labels under `dir`. The first call decides; a process
/// that never calls it labels nothing ahead and relabels for its seals.
pub fn install(dir: PathBuf) {
    let _ = STORE.set(LabelStore::new(dir));
}

/// This process's label store, once installed.
pub fn installed() -> Option<&'static LabelStore> {
    STORE.get()
}

fn io(what: &str, path: &Path, error: std::io::Error) -> QuilError {
    QuilError::Internal(format!(
        "storage labels: {what} {}: {error}",
        path.display()
    ))
}

/// Leaves' labels on disk: `<dir>/<epoch>/<leaf>/<n>.{layers,columns,ready}`,
/// `<leaf>` naming the member and the leaf. `layers` holds every layer in
/// order, `columns` every node's column digest, and `ready`, written last,
/// the column commitment.
pub struct LabelStore {
    dir: PathBuf,
}

impl LabelStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn leaf_dir(&self, epoch: u64, member: &[u8], leaf_id: &[u8]) -> PathBuf {
        use sha3::Digest as _;
        let mut h = sha3::Sha3_256::new();
        h.update((member.len() as u32).to_be_bytes());
        h.update(member);
        h.update(leaf_id);
        self.dir
            .join(epoch.to_string())
            .join(hex::encode(h.finalize()))
    }

    /// Label `member`'s leaf `leaf_id` for `epoch` at `n` nodes and keep its
    /// layers. Returns its column commitment and last layer.
    pub fn label(
        &self,
        epoch: u64,
        member: &[u8],
        leaf_id: &[u8],
        n: u64,
        params: &SdrParams,
    ) -> Result<(Node, Vec<Digest>)> {
        let dir = self.leaf_dir(epoch, member, leaf_id);
        fs::create_dir_all(&dir).map_err(|e| io("create", &dir, e))?;
        let [layers_path, columns_path, ready_path] = paths(&dir, n);
        let _ = fs::remove_file(&ready_path);
        let result = (|| {
            let file = File::create(&layers_path).map_err(|e| io("create", &layers_path, e))?;
            let mut writer = BufWriter::with_capacity(1 << 22, file);
            let mut failure = None;
            let key = quil_crypto::sdr::replica_key(member, leaf_id, epoch);
            let (last, columns) =
                quil_crypto::storage_proof::label_leaf(n, &key, params, &mut |_, layer| {
                    if failure.is_none() {
                        failure = write_digests(&mut writer, layer).err();
                    }
                });
            if let Some(error) = failure {
                return Err(io("write", &layers_path, error));
            }
            writer
                .into_inner()
                .map_err(|e| io("write", &layers_path, e.into_error()))?
                .sync_all()
                .map_err(|e| io("sync", &layers_path, e))?;
            let mut writer = BufWriter::with_capacity(
                1 << 22,
                File::create(&columns_path).map_err(|e| io("create", &columns_path, e))?,
            );
            write_digests(&mut writer, &columns).map_err(|e| io("write", &columns_path, e))?;
            let comm_c = quil_crypto::storage_proof::MerkleTree::from_digests(columns)
                .commitment(quil_crypto::storage_proof::Tree::Column);
            writer
                .into_inner()
                .map_err(|e| io("write", &columns_path, e.into_error()))?
                .sync_all()
                .map_err(|e| io("sync", &columns_path, e))?;
            let staged = dir.join(format!("{n}.ready.tmp"));
            fs::write(&staged, comm_c).map_err(|e| io("write", &staged, e))?;
            fs::rename(&staged, &ready_path).map_err(|e| io("rename", &ready_path, e))?;
            Ok((comm_c, last))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&layers_path);
            let _ = fs::remove_file(&columns_path);
        }
        result
    }

    /// The labels kept for `member`'s leaf `leaf_id` for `epoch` at a node
    /// count `accept` takes, if any.
    pub fn find(
        &self,
        epoch: u64,
        member: &[u8],
        leaf_id: &[u8],
        accept: impl Fn(u64) -> bool,
    ) -> Option<Kept> {
        let dir = self.leaf_dir(epoch, member, leaf_id);
        let mut counts: Vec<u64> = fs::read_dir(&dir)
            .ok()?
            .filter_map(|entry| {
                let name = entry.ok()?.file_name().into_string().ok()?;
                name.strip_suffix(".ready")?.parse().ok()
            })
            .filter(|&n| accept(n))
            .collect();
        counts.sort_unstable();
        let n = *counts.first()?;
        let [layers, columns, ready] = paths(&dir, n);
        let comm_c: Node = fs::read(ready).ok()?.try_into().ok()?;
        let layers_file = File::open(&layers).ok()?;
        let expected = n * (SdrParams::default().layers * NODE_BYTES) as u64;
        if layers_file.metadata().ok()?.len() != expected {
            return None;
        }
        Some(Kept {
            n,
            comm_c,
            layers: Mutex::new(layers_file),
            columns,
            depth: SdrParams::default().layers,
        })
    }

    /// Remove the labels kept for `member`'s leaf `leaf_id` for `epoch`: its
    /// registration is sealed, and nothing opens them again.
    pub fn forget(&self, epoch: u64, member: &[u8], leaf_id: &[u8]) {
        let dir = self.leaf_dir(epoch, member, leaf_id);
        if dir.exists() {
            let _ = fs::remove_dir_all(dir);
        }
    }

    /// Remove the labels of every epoch before `epoch`.
    pub fn evict_before(&self, epoch: u64) {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            let older = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u64>().ok())
                .is_some_and(|e| e < epoch);
            if older {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }
}

fn paths(dir: &Path, n: u64) -> [PathBuf; 3] {
    ["layers", "columns", "ready"].map(|kind| dir.join(format!("{n}.{kind}")))
}

fn write_digests(writer: &mut impl Write, digests: &[Digest]) -> std::io::Result<()> {
    for digest in digests {
        writer.write_all(&hash::to_bytes(digest))?;
    }
    Ok(())
}

/// One leaf's kept labels.
pub struct Kept {
    pub n: u64,
    pub comm_c: Node,
    layers: Mutex<File>,
    columns: PathBuf,
    depth: usize,
}

impl Kept {
    fn read(&self, offset: u64, len: usize) -> Option<Vec<u8>> {
        let mut file = self.layers.lock().ok()?;
        file.seek(SeekFrom::Start(offset)).ok()?;
        let mut bytes = vec![0u8; len];
        file.read_exact(&mut bytes).ok()?;
        Some(bytes)
    }
}

impl LabelSource for Kept {
    fn label(&self, layer: usize, v: u64) -> Option<Node> {
        if layer >= self.depth || v >= self.n {
            return None;
        }
        let at = (layer as u64 * self.n + v) * NODE_BYTES as u64;
        let node: Node = self.read(at, NODE_BYTES)?.try_into().ok()?;
        hash::from_bytes(&node).map(|_| node)
    }

    fn columns(&self) -> Option<Vec<Digest>> {
        hash::digests_from_bytes(&fs::read(&self.columns).ok()?)
            .filter(|columns| columns.len() as u64 == self.n)
    }

    fn last_layer(&self) -> Option<Vec<Digest>> {
        let size = self.n as usize * NODE_BYTES;
        hash::digests_from_bytes(&self.read((self.depth - 1) as u64 * size as u64, size)?)
    }
}

type Precomputed = std::collections::HashSet<(Vec<u8>, Vec<u8>, u64)>;

fn precomputed_set() -> std::sync::MutexGuard<'static, Precomputed> {
    static DONE: OnceLock<Mutex<Precomputed>> = OnceLock::new();
    DONE.get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Whether this process labelled `member`'s leaves of `filter` for `epoch`
/// ahead ([`precompute`]), so it need not again.
pub fn precomputed(member: &[u8], filter: &[u8], epoch: u64) -> bool {
    precomputed_set().contains(&(member.to_vec(), filter.to_vec(), epoch))
}

/// Label ahead the leaves `member` will register for `epoch` on shard
/// `filter`: the leaves of the shard's data in `crdt` now, each at
/// `precompute_nodes` of its node count, side by side
/// (`storage_jobs::for_each_parallel`). A leaf already labelled at a count
/// its data allows is left. Removes the labels of epochs that have begun.
pub fn precompute(
    store: &LabelStore,
    crdt: &Arc<HypergraphCrdt>,
    member: &[u8],
    filter: &[u8],
    epoch: u64,
) -> Result<()> {
    use quil_crypto::storage_proof::{data_node_count, padded_nodes_allowed, precompute_nodes};
    store.evict_before(epoch.saturating_sub(1));
    let source = crate::storage_snapshot::current_source(crdt, filter, epoch);
    let captured = crate::storage_snapshot::capture_at(crdt, filter, epoch, &[source])?;
    let params = SdrParams::default();
    let started = std::time::Instant::now();
    let labelled = crate::storage_jobs::for_each_parallel(&captured.prefixes, |prefix| {
        let leaf_id = quil_execution::global_intrinsic::leaf_id_bytes(filter, prefix);
        let exact = {
            let _memory = crate::storage_jobs::reserve(crate::storage_snapshot::leaf_read_bytes(
                captured.leaf_size(prefix)?,
            ));
            data_node_count(captured.leaf_data(prefix)?.len() as u64)
        };
        if store
            .find(epoch, member, &leaf_id, |n| padded_nodes_allowed(exact, n))
            .is_some()
        {
            return Ok(0);
        }
        let n = precompute_nodes(exact);
        let _memory = crate::storage_jobs::reserve(crate::storage_snapshot::encoding_bytes(n));
        store.label(epoch, member, &leaf_id, n, &params)?;
        Ok(n)
    })?;
    {
        let mut done = precomputed_set();
        done.retain(|(_, _, e)| e.saturating_add(2) >= epoch);
        done.insert((member.to_vec(), filter.to_vec(), epoch));
    }
    info!(epoch, filter = %hex::encode(filter), leaves = labelled.len(),
        labelled = labelled.iter().filter(|&&n| n > 0).count(),
        nodes = labelled.iter().sum::<u64>(), seconds = started.elapsed().as_secs_f64(),
        "storage labels computed ahead of the epoch's snapshot");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kept_labels_are_the_leaf_labelling_and_go_when_their_epoch_has() {
        let dir = std::env::temp_dir().join(format!("quil-labels-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = LabelStore::new(dir.clone());
        let params = SdrParams::default();
        let (member, leaf) = ([7u8; 32], b"leaf".as_slice());
        let n = 3_000u64;
        let (comm_c, last) = store.label(9, &member, leaf, n, &params).unwrap();
        let mut layers = Vec::new();
        let key = quil_crypto::sdr::replica_key(&member, leaf, 9);
        let (expected_last, columns) =
            quil_crypto::storage_proof::label_leaf(n, &key, &params, &mut |_, layer| {
                layers.push(layer.to_vec())
            });
        assert_eq!(last, expected_last);
        let kept = store.find(9, &member, leaf, |count| count == n).unwrap();
        assert_eq!((kept.n, kept.comm_c), (n, comm_c));
        assert_eq!(kept.columns().unwrap(), columns);
        assert_eq!(kept.last_layer().unwrap(), expected_last);
        for (layer, v) in [(0usize, 0u64), (4, 1_234), (10, n - 1)] {
            assert_eq!(
                kept.label(layer, v),
                Some(hash::to_bytes(&layers[layer][v as usize]))
            );
        }
        assert!(kept.label(11, 0).is_none() && kept.label(0, n).is_none());
        assert!(store.find(9, &member, leaf, |count| count != n).is_none());
        assert!(store.find(9, &[8u8; 32], leaf, |_| true).is_none());
        assert!(store.find(10, &member, leaf, |_| true).is_none());
        store.evict_before(9);
        assert!(store.find(9, &member, leaf, |_| true).is_some());
        store.label(9, &member, b"other", 64, &params).unwrap();
        store.forget(9, &member, leaf);
        assert!(store.find(9, &member, leaf, |_| true).is_none());
        assert!(store.find(9, &member, b"other", |_| true).is_some());
        store.evict_before(10);
        assert!(store.find(9, &member, leaf, |_| true).is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
