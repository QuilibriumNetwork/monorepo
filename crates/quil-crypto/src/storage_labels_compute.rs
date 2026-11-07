//! CPU batching and bounded-memory graph/column storage for SDR labelling.
//! Callbacks stay on the requesting thread; independent replicas occupy SIMD
//! lanes. A cancelled lane never cancels another member's work.

use crate::{sdr, storage_hash as hash};
use hash::{Digest, Domain, Packed, PackedDigest};
use p3_field::{PackedValue, PrimeCharacteristicRing};
use std::{
    cell::Cell,
    collections::HashMap,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc, Mutex, OnceLock, TryLockError, Weak,
    },
    time::Duration,
};

static COMPUTE_COUNTS: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];
pub(crate) fn metrics() -> crate::storage_proof::LabelComputeMetrics {
    let counts = COMPUTE_COUNTS.each_ref().map(|n| n.load(Ordering::Relaxed));
    crate::storage_proof::LabelComputeMetrics {
        packing_width: hash::packing_width(),
        graphs_built: counts[0],
        resident_graphs_built: counts[1],
        graph_cache_hits: counts[2],
        resident_columns_created: counts[3],
        scalar_batches: counts[4],
        packed_batches: counts[5],
    }
}

const BLOCK: usize = 1024;
thread_local! {
    // Unadmitted crypto callers retain bounded scratch storage. Node callers
    // opt into resident buffers only under their matching RAM reservation.
    static MEMORY_BUDGET: Cell<u64> = const { Cell::new(16 << 20) };
}
pub(crate) fn with_memory_budget<R>(bytes: u64, work: impl FnOnce() -> R) -> R {
    struct Restore(u64);
    impl Drop for Restore {
        fn drop(&mut self) {
            MEMORY_BUDGET.set(self.0);
        }
    }
    let _restore = Restore(MEMORY_BUDGET.replace(bytes));
    work()
}
fn memory_budget() -> u64 {
    MEMORY_BUDGET.get()
}
fn resident_columns(n: usize, budget: u64) -> bool {
    (n as u64).saturating_mul(hash::DIGEST_BYTES as u64) <= budget
}
fn resident_graph(key: GraphKey, budget: u64) -> bool {
    let columns = if resident_columns(key.n, budget) {
        (key.n as u64).saturating_mul(hash::DIGEST_BYTES as u64)
    } else {
        0
    };
    (key.n as u64)
        .saturating_mul((key.drg + key.expander) as u64)
        .saturating_mul(4)
        <= budget.saturating_sub(columns)
}
const BATCH_WAIT: Duration = Duration::from_millis(2);

static SCRATCH_DIRECTORY: OnceLock<std::path::PathBuf> = OnceLock::new();
pub(crate) fn set_scratch_directory(path: std::path::PathBuf) {
    if std::fs::create_dir_all(&path).is_ok() {
        let _ = SCRATCH_DIRECTORY.set(path);
    }
}
fn scratch_file() -> std::io::Result<File> {
    match SCRATCH_DIRECTORY.get() {
        Some(dir) => tempfile::tempfile_in(dir),
        None => tempfile::tempfile(),
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct GraphKey {
    n: usize,
    drg: usize,
    expander: usize,
}

struct Graph {
    key: GraphKey,
    storage: GraphStorage,
}
enum GraphStorage {
    Memory(Vec<u32>),
    Disk(Mutex<File>),
    Derived,
}

#[cfg(test)]
fn graph(key: GraphKey) -> Arc<Graph> {
    graph_until(key, memory_budget(), &|| false)
}
fn graph_until(key: GraphKey, budget: u64, stop: &dyn Fn() -> bool) -> Arc<Graph> {
    // Each geometry/backend has its own construction lock. Unrelated graphs
    // build concurrently, but followers never derive another copy of this one.
    type Slot = Arc<Mutex<Weak<Graph>>>;
    type Cache = HashMap<(GraphKey, bool), Slot>;
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    let resident = resident_graph(key, budget);
    let slot = {
        let mut cache = CACHE
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        cache.retain(|_, slot| {
            Arc::strong_count(slot) > 1
                || match slot.try_lock() {
                    Ok(graph) => graph.strong_count() > 0,
                    Err(_) => true,
                }
        });
        cache.entry((key, resident)).or_default().clone()
    };
    let mut cached = loop {
        if stop() {
            return Arc::new(Graph {
                key,
                storage: GraphStorage::Derived,
            });
        }
        match slot.try_lock() {
            Ok(guard) => break guard,
            Err(TryLockError::Poisoned(error)) => break error.into_inner(),
            Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    if let Some(graph) = cached.upgrade() {
        COMPUTE_COUNTS[2].fetch_add(1, Ordering::Relaxed);
        return graph;
    }
    let bytes = key
        .n
        .saturating_mul(key.drg + key.expander)
        .saturating_mul(4);
    COMPUTE_COUNTS[0].fetch_add(1, Ordering::Relaxed);
    let storage = if resident {
        COMPUTE_COUNTS[1].fetch_add(1, Ordering::Relaxed);
        let mut rows = Vec::with_capacity(bytes / 4);
        for at in (0..key.n).step_by(BLOCK) {
            if stop() {
                return Arc::new(Graph {
                    key,
                    storage: GraphStorage::Derived,
                });
            }
            rows.extend(derive_rows(key, at, BLOCK.min(key.n - at)));
        }
        GraphStorage::Memory(rows)
    } else {
        // The graph is deterministic and contains no key or replica data.
        // Failure to create scratch storage falls back to bounded derivation.
        match scratch_file().and_then(|mut file| {
            for at in (0..key.n).step_by(BLOCK) {
                if stop() {
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                let rows = derive_rows(key, at, BLOCK.min(key.n - at));
                let bytes: Vec<u8> = rows.iter().flat_map(|v| v.to_le_bytes()).collect();
                file.write_all(&bytes)?;
            }
            Ok(file)
        }) {
            Ok(file) => GraphStorage::Disk(Mutex::new(file)),
            Err(_) => GraphStorage::Derived,
        }
    };
    let result = Arc::new(Graph { key, storage });
    if !stop() {
        *cached = Arc::downgrade(&result);
    }
    result
}

pub(crate) fn with_prepared_graph<R>(n: usize, work: impl FnOnce() -> R) -> (R, bool) {
    let graph = graph_until(
        GraphKey {
            n,
            drg: 6,
            expander: 8,
        },
        memory_budget(),
        &|| false,
    );
    let prepared = !matches!(graph.storage, GraphStorage::Derived);
    let result = work();
    drop(graph);
    (result, prepared)
}

fn derive_rows(key: GraphKey, at: usize, count: usize) -> Vec<u32> {
    let width = key.drg + key.expander;
    let mut rows = vec![0; count * width];
    let (mut drg, mut expander) = (Vec::new(), Vec::new());
    for (i, row) in rows.chunks_exact_mut(width).enumerate() {
        sdr::drg_parents((at + i) as u64, key.drg, &mut drg);
        sdr::expander_parents((at + i) as u64, key.expander, key.n as u64, &mut expander);
        for (slot, &parent) in row[..key.drg].iter_mut().zip(&drg) {
            *slot = parent as u32;
        }
        for (slot, &parent) in row[key.drg..].iter_mut().zip(&expander) {
            *slot = parent as u32;
        }
    }
    rows
}

impl Graph {
    fn rows(&self, at: usize, count: usize) -> std::io::Result<Vec<u32>> {
        let width = self.key.drg + self.key.expander;
        match &self.storage {
            GraphStorage::Memory(table) => Ok(table[at * width..(at + count) * width].to_vec()),
            GraphStorage::Derived => Ok(derive_rows(self.key, at, count)),
            GraphStorage::Disk(file) => {
                let mut bytes = vec![0; count * width * 4];
                let mut file = file.lock().unwrap_or_else(|e| e.into_inner());
                file.seek(SeekFrom::Start((at * width * 4) as u64))?;
                file.read_exact(&mut bytes)?;
                Ok(bytes
                    .chunks_exact(4)
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                    .collect())
            }
        }
    }
}

enum Columns {
    Memory(Vec<Digest>),
    Disk { file: File, n: usize },
}
impl Columns {
    fn new(n: usize, budget: u64) -> Self {
        if !resident_columns(n, budget) {
            if let Ok(file) = scratch_file().and_then(|file| {
                file.set_len((n * hash::DIGEST_BYTES) as u64)?;
                Ok(file)
            }) {
                return Self::Disk { file, n };
            }
        }
        COMPUTE_COUNTS[3].fetch_add(1, Ordering::Relaxed);
        Self::Memory(vec![hash::ZERO; n])
    }
    fn update(&mut self, layer: &[Digest]) -> std::io::Result<()> {
        match self {
            Self::Memory(columns) => {
                let mut output = vec![hash::ZERO; BLOCK.min(columns.len())];
                for (left, right) in columns.chunks_mut(BLOCK).zip(layer.chunks(BLOCK)) {
                    let output = &mut output[..left.len()];
                    hash::compress_many(left, right, output, Domain::Column);
                    left.copy_from_slice(output);
                }
            }
            Self::Disk { file, n } => {
                if layer.len() != *n {
                    return Err(std::io::ErrorKind::InvalidData.into());
                }
                for (block, labels) in layer.chunks(BLOCK).enumerate() {
                    let offset = (block * BLOCK * hash::DIGEST_BYTES) as u64;
                    let mut bytes = vec![0; labels.len() * hash::DIGEST_BYTES];
                    file.seek(SeekFrom::Start(offset))?;
                    file.read_exact(&mut bytes)?;
                    let columns =
                        hash::digests_from_bytes(&bytes).ok_or(std::io::ErrorKind::InvalidData)?;
                    let mut output = vec![hash::ZERO; labels.len()];
                    hash::compress_many(&columns, labels, &mut output, Domain::Column);
                    file.seek(SeekFrom::Start(offset))?;
                    file.write_all(&hash::digests_to_bytes(&output))?;
                }
            }
        }
        Ok(())
    }
    fn finish(self) -> std::io::Result<Vec<Digest>> {
        match self {
            Self::Memory(columns) => Ok(columns),
            Self::Disk { mut file, n } => {
                file.seek(SeekFrom::Start(0))?;
                // Decode in bounded chunks: do not retain a second full byte copy.
                let mut columns = Vec::with_capacity(n);
                for at in (0..n).step_by(BLOCK) {
                    let mut bytes = vec![0; BLOCK.min(n - at) * hash::DIGEST_BYTES];
                    file.read_exact(&mut bytes)?;
                    columns.extend(
                        hash::digests_from_bytes(&bytes).ok_or(std::io::ErrorKind::InvalidData)?,
                    );
                }
                Ok(columns)
            }
        }
    }
}

struct Request {
    memory_budget: u64,
    layers: usize,
    n: usize,
    key: Digest,
    sender: SyncSender<(usize, Arc<Vec<Digest>>)>,
    cancelled: Arc<AtomicBool>,
    released: Arc<AtomicBool>,
}
impl Drop for Request {
    fn drop(&mut self) {
        self.released.store(true, Ordering::Release);
    }
}

/// The caller owns its callback and cancellation check; no borrowed callback
/// crosses a thread boundary. A zero-capacity channel bounds layer copies.
pub(crate) fn label(
    n: usize,
    key: Digest,
    layers: usize,
    on_layer: &mut dyn FnMut(usize, &[Digest]),
    stop: &dyn Fn() -> bool,
) -> Option<(Vec<Digest>, Vec<Digest>)> {
    if stop() {
        return None;
    }
    let (sender, receiver) = mpsc::sync_channel(0);
    let cancelled = Arc::new(AtomicBool::new(false));
    struct Cancel {
        cancelled: Arc<AtomicBool>,
        released: Arc<AtomicBool>,
    }
    impl Drop for Cancel {
        fn drop(&mut self) {
            self.cancelled.store(true, Ordering::Relaxed);
            // Admission remains held until the worker actually releases this
            // lane's arrays. Cancellation cannot lend the same RAM twice.
            while !self.released.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    let released = Arc::new(AtomicBool::new(false));
    let _cancel = Cancel {
        cancelled: cancelled.clone(),
        released: released.clone(),
    };
    static QUEUE: OnceLock<Mutex<Vec<Request>>> = OnceLock::new();
    let queue = QUEUE.get_or_init(Default::default);
    let mut waiting = queue.lock().unwrap_or_else(|e| e.into_inner());
    let launch = waiting.is_empty();
    waiting.push(Request {
        memory_budget: memory_budget(),
        layers,
        n,
        key,
        sender,
        cancelled,
        released,
    });
    drop(waiting);
    if launch {
        launch_worker(queue);
    }
    receive(n, layers, receiver, on_layer, stop)
}

/// Resume verified whole layers using the same bounded graph and columns as
/// fresh workers. Kept layers fold once and are never handed to the writer again.
pub(crate) fn label_resume(
    n: usize,
    key: Digest,
    layers: usize,
    kept: usize,
    read_layer: &mut dyn FnMut(usize, &mut [Digest]) -> bool,
    on_layer: &mut dyn FnMut(usize, &[Digest]),
    stop: &dyn Fn() -> bool,
) -> Option<(Vec<Digest>, Vec<Digest>)> {
    if kept == 0 {
        return label(n, key, layers, on_layer, stop);
    }
    if stop() {
        return None;
    }
    let mut columns = Columns::new(n, memory_budget());
    let mut prev = vec![hash::ZERO; n];
    for layer in 0..kept {
        if stop() || !read_layer(layer, &mut prev) {
            return None;
        }
        columns.update(&prev).ok()?;
    }
    if kept == layers {
        return Some((prev, columns.finish().ok()?));
    }
    let graph = graph_until(
        GraphKey {
            n,
            drg: 6,
            expander: 8,
        },
        memory_budget(),
        stop,
    );
    let mut cur = vec![hash::ZERO; n];
    for layer in kept..layers {
        for at in (0..n).step_by(BLOCK) {
            if stop() {
                return None;
            }
            let count = BLOCK.min(n - at);
            let rows = graph.rows(at, count).ok()?;
            for v in at..at + count {
                let row = &rows[(v - at) * 14..(v - at + 1) * 14];
                cur[v] = crate::storage_proof::label(
                    &key,
                    layer,
                    v as u64,
                    &mut row[..6].iter().map(|&p| cur[p as usize]),
                    &mut row[6..].iter().map(|&p| prev[p as usize]),
                    &sdr::SdrParams {
                        layers,
                        ..sdr::SdrParams::default()
                    },
                );
            }
        }
        columns.update(&cur).ok()?;
        on_layer(layer, &cur);
        std::mem::swap(&mut prev, &mut cur);
    }
    drop(cur);
    drop(graph);
    Some((prev, columns.finish().ok()?))
}

fn launch_worker(queue: &'static Mutex<Vec<Request>>) {
    let spawned = std::thread::Builder::new().name("storage-labels".into()).spawn(move || {
        std::thread::sleep(BATCH_WAIT);
        let mut waiting = queue.lock().unwrap_or_else(|e| e.into_inner());
        if waiting.is_empty() { return; }
        let first = waiting.remove(0);
        let mut requests = vec![first];
        let n = requests[0].n;
        let mut index = 0;
        while index < waiting.len() && requests.len() < hash::packing_width() {
            let other = waiting[index].n;
            if waiting[index].layers == requests[0].layers && n.max(other) - n.min(other) <= n.min(other) / 8 {
                requests.push(waiting.remove(index));
            } else { index += 1; }
        }
        let more = !waiting.is_empty();
        drop(waiting);
        // Queued work must not wait for this batch to finish: callers already
        // hold their memory/core admission reservations.
        if more { launch_worker(queue); }
        if let Err(error) = compute(&requests) {
            tracing::warn!(%error, "storage label scratch I/O failed; no incomplete labels accepted");
        }
    });
    if spawned.is_err() {
        queue.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

fn receive(
    n: usize,
    layers: usize,
    receiver: Receiver<(usize, Arc<Vec<Digest>>)>,
    on_layer: &mut dyn FnMut(usize, &[Digest]),
    stop: &dyn Fn() -> bool,
) -> Option<(Vec<Digest>, Vec<Digest>)> {
    let mut last = None;
    loop {
        if stop() {
            return None;
        }
        match receiver.recv_timeout(Duration::from_millis(10)) {
            Ok((layer, nodes)) if layer < layers => {
                if nodes.len() != n {
                    return None;
                }
                on_layer(layer, &nodes);
                if layer + 1 == layers {
                    last = Some(nodes);
                }
            }
            Ok((layer, columns)) if layer == layers && columns.len() == n => {
                let last = Arc::try_unwrap(last?).unwrap_or_else(|nodes| (*nodes).clone());
                let columns = Arc::try_unwrap(columns).unwrap_or_else(|nodes| (*nodes).clone());
                return Some((last, columns));
            }
            Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => return None,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

fn compute(requests: &[Request]) -> std::io::Result<()> {
    let layers = requests[0].layers;
    debug_assert!(requests.iter().all(|request| request.layers == layers));
    let n = requests.iter().map(|r| r.n).max().unwrap_or(0);
    if requests.iter().all(|r| r.cancelled.load(Ordering::Relaxed)) {
        return Ok(());
    }
    if requests.len() == 1 {
        return compute_scalar(&requests[0]);
    }
    COMPUTE_COUNTS[5].fetch_add(1, Ordering::Relaxed);
    let mut graphs: Vec<_> = requests
        .iter()
        .map(|r| {
            if r.cancelled.load(Ordering::Relaxed) {
                None
            } else {
                Some(graph_until(
                    GraphKey {
                        n: r.n,
                        drg: 6,
                        expander: 8,
                    },
                    r.memory_budget,
                    &|| r.cancelled.load(Ordering::Relaxed),
                ))
            }
        })
        .collect();
    let mut columns: Vec<_> = requests
        .iter()
        .map(|r| Columns::new(r.n, r.memory_budget))
        .collect();
    let zero = [Packed::ZERO; 8];
    let key: PackedDigest = std::array::from_fn(|j| {
        Packed::from_fn(|lane| requests.get(lane).map_or(hash::ZERO[j], |r| r.key[j]))
    });
    // Store only real scalar lanes. SIMD packing happens at the hash, so
    // partial batches never allocate phantom replicas or pad short leaves.
    let mut prev: Vec<Arc<Vec<Digest>>> = requests
        .iter()
        .map(|r| Arc::new(vec![hash::ZERO; r.n]))
        .collect();
    let mut cur: Vec<Vec<Digest>> = requests.iter().map(|r| vec![hash::ZERO; r.n]).collect();
    for layer in 0..layers {
        for at in (0..n).step_by(BLOCK) {
            release_cancelled(
                requests,
                &mut prev,
                &mut cur,
                &mut columns,
                &mut graphs,
                None,
            );
            if requests.iter().all(|r| r.cancelled.load(Ordering::Relaxed)) {
                return Ok(());
            }
            let rows: Vec<_> = graphs
                .iter()
                .map(|g| match g {
                    Some(g) => g.rows(at.min(g.key.n), BLOCK.min(g.key.n.saturating_sub(at))),
                    None => Ok(Vec::new()),
                })
                .collect::<std::io::Result<_>>()?;
            for v in at..(at + BLOCK).min(n) {
                let mut absorber = hash::PackedAbsorber::new(Domain::Label, 128);
                absorber.absorb_digest(&key);
                let mut header = zero;
                header[0] = Packed::from(hash::felt(layer as u32));
                header[1] = Packed::from(hash::felt(v as u32));
                absorber.absorb_digest(&header);
                for parent in 0..14 {
                    let digest = std::array::from_fn(|j| {
                        Packed::from_fn(|lane| {
                            let Some(request) = requests.get(lane) else {
                                return hash::ZERO[j];
                            };
                            if v >= request.n
                                || request.cancelled.load(Ordering::Relaxed)
                                || (parent < 6 && v == 0)
                                || (parent >= 6 && layer == 0)
                            {
                                return hash::ZERO[j];
                            }
                            let p = rows[lane][(v - at) * 14 + parent] as usize;
                            if parent < 6 {
                                cur[lane][p][j]
                            } else {
                                prev[lane][p][j]
                            }
                        })
                    });
                    absorber.absorb_digest(&digest);
                }
                let result = absorber.finish();
                for (lane, request) in requests.iter().enumerate() {
                    if v < request.n && !request.cancelled.load(Ordering::Relaxed) {
                        cur[lane][v] = std::array::from_fn(|j| result[j].as_slice()[lane]);
                    }
                }
            }
        }
        for (lane, request) in requests.iter().enumerate() {
            if request.cancelled.load(Ordering::Relaxed) {
                continue;
            }
            columns[lane].update(&cur[lane])?;
            let nodes = Arc::new(std::mem::take(&mut cur[lane]));
            let mut message = (layer, nodes.clone());
            let delivered = loop {
                if request.cancelled.load(Ordering::Relaxed) {
                    drop(message);
                    break false;
                }
                match request.sender.try_send(message) {
                    Ok(()) => break true,
                    Err(mpsc::TrySendError::Disconnected(_)) => break false,
                    Err(mpsc::TrySendError::Full(returned)) => {
                        message = returned;
                        release_cancelled(
                            requests,
                            &mut prev,
                            &mut cur,
                            &mut columns,
                            &mut graphs,
                            Some(lane),
                        );
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            };
            if !delivered {
                request.cancelled.store(true, Ordering::Relaxed);
                drop(nodes);
                release_cancelled(
                    requests,
                    &mut prev,
                    &mut cur,
                    &mut columns,
                    &mut graphs,
                    None,
                );
                continue;
            }
            // The synchronous delivery waits until the preceding layer's
            // callback ended. Its buffer can be reused without a full copy.
            let old = std::mem::replace(&mut prev[lane], nodes);
            cur[lane] = Arc::try_unwrap(old).unwrap_or_else(|nodes| (*nodes).clone());
        }
    }
    drop(prev);
    drop(cur);
    drop(graphs);
    for (request, columns) in requests.iter().zip(columns) {
        if !request.cancelled.load(Ordering::Relaxed) {
            let _ = request.sender.send((layers, Arc::new(columns.finish()?)));
        } else {
            drop(columns);
        }
        request.released.store(true, Ordering::Release);
    }
    Ok(())
}

fn release_cancelled(
    requests: &[Request],
    prev: &mut [Arc<Vec<Digest>>],
    cur: &mut [Vec<Digest>],
    columns: &mut [Columns],
    graphs: &mut [Option<Arc<Graph>>],
    except: Option<usize>,
) {
    for (lane, request) in requests.iter().enumerate() {
        if Some(lane) != except && request.cancelled.load(Ordering::Relaxed) {
            prev[lane] = Arc::new(Vec::new());
            cur[lane] = Vec::new();
            columns[lane] = Columns::Memory(Vec::new());
            graphs[lane] = None;
            request.released.store(true, Ordering::Release);
        }
    }
}

fn compute_scalar(request: &Request) -> std::io::Result<()> {
    COMPUTE_COUNTS[4].fetch_add(1, Ordering::Relaxed);
    let layers = request.layers;
    let graph = graph_until(
        GraphKey {
            n: request.n,
            drg: 6,
            expander: 8,
        },
        request.memory_budget,
        &|| request.cancelled.load(Ordering::Relaxed),
    );
    if request.cancelled.load(Ordering::Relaxed) {
        return Ok(());
    }
    let mut columns = Columns::new(request.n, request.memory_budget);
    let mut prev = Arc::new(vec![hash::ZERO; request.n]);
    let mut cur = vec![hash::ZERO; request.n];
    for layer in 0..layers {
        for at in (0..request.n).step_by(BLOCK) {
            if request.cancelled.load(Ordering::Relaxed) {
                return Ok(());
            }
            let count = BLOCK.min(request.n - at);
            let rows = graph.rows(at, count)?;
            for v in at..at + count {
                let row = &rows[(v - at) * 14..(v - at + 1) * 14];
                cur[v] = crate::storage_proof::label(
                    &request.key,
                    layer,
                    v as u64,
                    &mut row[..6].iter().map(|&p| cur[p as usize]),
                    &mut row[6..].iter().map(|&p| prev[p as usize]),
                    &sdr::SdrParams {
                        layers,
                        ..sdr::SdrParams::default()
                    },
                );
            }
        }
        columns.update(&cur)?;
        let nodes = Arc::new(cur);
        if request.sender.send((layer, nodes.clone())).is_err() {
            return Ok(());
        }
        let old = std::mem::replace(&mut prev, nodes);
        cur = Arc::try_unwrap(old).unwrap_or_else(|nodes| (*nodes).clone());
    }
    drop(prev);
    drop(cur);
    let _ = request.sender.send((layers, Arc::new(columns.finish()?)));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_builders_share_one_resident_graph_and_cancellation_does_not_poison_it() {
        let key = GraphKey {
            n: 4096,
            drg: 6,
            expander: 8,
        };
        let barrier = std::sync::Barrier::new(9);
        let graphs = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..9)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        graph_until(key, 1 << 20, &|| false)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(graphs.iter().all(|g| Arc::ptr_eq(g, &graphs[0])));
        assert!(matches!(graphs[0].storage, GraphStorage::Memory(_)));
        let key = GraphKey { n: 8193, ..key };
        let polls = std::sync::atomic::AtomicUsize::new(0);
        let cancelled = graph_until(key, 1 << 20, &|| polls.fetch_add(1, Ordering::Relaxed) >= 3);
        assert!(matches!(cancelled.storage, GraphStorage::Derived));
        let complete = graph_until(key, 1 << 20, &|| false);
        assert_eq!(complete.rows(0, key.n).unwrap(), derive_rows(key, 0, key.n));
    }

    #[test]
    fn resident_disk_and_resumed_labels_match_for_every_profile() {
        let key = hash::key_digest(&[73; 32]);
        for layers in [2, 3, 11] {
            let mut disk_layers = Vec::new();
            let disk = with_memory_budget(0, || {
                label(
                    73,
                    key,
                    layers,
                    &mut |_, nodes| disk_layers.push(nodes.to_vec()),
                    &|| false,
                )
            })
            .unwrap();
            let mut resident_layers = Vec::new();
            let resident = with_memory_budget(1 << 20, || {
                label(
                    73,
                    key,
                    layers,
                    &mut |_, nodes| resident_layers.push(nodes.to_vec()),
                    &|| false,
                )
            })
            .unwrap();
            assert_eq!(disk, resident);
            assert_eq!(disk_layers, resident_layers);
            let resumed = with_memory_budget(1 << 20, || {
                label_resume(
                    73,
                    key,
                    layers,
                    1,
                    &mut |layer, buffer| {
                        buffer.copy_from_slice(&disk_layers[layer]);
                        true
                    },
                    &mut |_, _| {},
                    &|| false,
                )
            })
            .unwrap();
            assert_eq!(disk, resumed);
        }
    }

    #[test]
    fn memory_policy_requires_its_full_reservation_and_restores_after_unwind() {
        let key = GraphKey {
            n: 1 << 24,
            drg: 6,
            expander: 8,
        };
        let columns = (key.n * hash::DIGEST_BYTES) as u64;
        assert!(!resident_columns(key.n, columns - 1));
        assert!(resident_columns(key.n, columns));
        assert!(!resident_graph(key, columns));
        let scratch = columns + (key.n * 14 * 4) as u64;
        assert!(resident_graph(key, scratch));
        let params = sdr::SdrParams::default();
        assert!(
            crate::storage_proof::label_leaf_peak_bytes(key.n as u64, &params)
                >= scratch + (2 * key.n * hash::DIGEST_BYTES) as u64
        );
        let before = memory_budget();
        let _ = std::panic::catch_unwind(|| with_memory_budget(123, || panic!("restore")));
        assert_eq!(memory_budget(), before);
    }

    #[test]
    fn disk_graph_and_columns_equal_their_memory_backends() {
        let key = GraphKey {
            n: 73,
            drg: 6,
            expander: 8,
        };
        let expected = derive_rows(key, 0, key.n);
        let mut file = tempfile::tempfile().unwrap();
        for value in &expected {
            file.write_all(&value.to_le_bytes()).unwrap();
        }
        let disk = Graph {
            key,
            storage: GraphStorage::Disk(Mutex::new(file)),
        };
        assert_eq!(disk.rows(0, 73).unwrap(), expected);
        assert_eq!(disk.rows(17, 21).unwrap(), expected[17 * 14..38 * 14]);
        let shared = graph(key);
        assert!(Arc::ptr_eq(&shared, &graph(key)));
        let file = tempfile::tempfile().unwrap();
        file.set_len(73 * 32).unwrap();
        let mut disk = Columns::Disk { file, n: 73 };
        let mut memory = Columns::Memory(vec![hash::ZERO; 73]);
        for layer in 0..11 {
            let labels = vec![hash::key_digest(&[layer; 32]); 73];
            disk.update(&labels).unwrap();
            memory.update(&labels).unwrap();
        }
        assert_eq!(disk.finish().unwrap(), memory.finish().unwrap());
    }
}
