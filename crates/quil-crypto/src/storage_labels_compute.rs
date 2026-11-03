//! CPU batching and bounded-memory graph/column storage for SDR labelling.
//! Callbacks stay on the requesting thread; independent replicas occupy SIMD
//! lanes. A cancelled lane never cancels another member's work.

use crate::{sdr, storage_hash as hash};
use hash::{Digest, Domain, Packed, PackedDigest};
use p3_field::{PackedValue, PrimeCharacteristicRing};
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc, Mutex, OnceLock, Weak,
    },
    time::Duration,
};

const BLOCK: usize = 1024;
const MEMORY_GRAPH_BYTES: usize = 8 << 20;
const MEMORY_COLUMN_BYTES: usize = 8 << 20;
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
    graph_until(key, &|| false)
}
fn graph_until(key: GraphKey, stop: &dyn Fn() -> bool) -> Arc<Graph> {
    type Cache = HashMap<GraphKey, Weak<Graph>>;
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    let mut cache = CACHE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(found) = cache.get(&key).and_then(Weak::upgrade) {
        return found;
    }
    cache.retain(|_, value| value.strong_count() != 0);
    drop(cache);
    let bytes = key
        .n
        .saturating_mul(key.drg + key.expander)
        .saturating_mul(4);
    let storage = if bytes <= MEMORY_GRAPH_BYTES {
        GraphStorage::Memory(derive_rows(key, 0, key.n))
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
    let mut cache = CACHE
        .get()
        .unwrap()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    cache.insert(key, Arc::downgrade(&result));
    result
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
    fn new(n: usize) -> Self {
        if n * hash::DIGEST_BYTES > MEMORY_COLUMN_BYTES {
            if let Ok(file) = scratch_file().and_then(|file| {
                file.set_len((n * hash::DIGEST_BYTES) as u64)?;
                Ok(file)
            }) {
                return Self::Disk { file, n };
            }
        }
        Self::Memory(vec![hash::ZERO; n])
    }
    fn update(&mut self, layer: &[Digest]) -> std::io::Result<()> {
        match self {
            Self::Memory(columns) => {
                for (left, right) in columns.chunks_mut(BLOCK).zip(layer.chunks(BLOCK)) {
                    let mut output = vec![hash::ZERO; left.len()];
                    hash::compress_many(left, right, &mut output, Domain::Column);
                    left.copy_from_slice(&output);
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
    receive(n, receiver, on_layer, stop)
}

/// Resume verified whole layers using the same bounded graph and columns as
/// fresh workers. Kept layers fold once and are never handed to the writer again.
pub(crate) fn label_resume(
    n: usize,
    key: Digest,
    kept: usize,
    read_layer: &mut dyn FnMut(usize, &mut [Digest]) -> bool,
    on_layer: &mut dyn FnMut(usize, &[Digest]),
    stop: &dyn Fn() -> bool,
) -> Option<(Vec<Digest>, Vec<Digest>)> {
    if kept == 0 {
        return label(n, key, on_layer, stop);
    }
    if stop() {
        return None;
    }
    let mut columns = Columns::new(n);
    let mut prev = vec![hash::ZERO; n];
    for layer in 0..kept {
        if stop() || !read_layer(layer, &mut prev) {
            return None;
        }
        columns.update(&prev).ok()?;
    }
    if kept == 11 {
        return Some((prev, columns.finish().ok()?));
    }
    let graph = graph_until(
        GraphKey {
            n,
            drg: 6,
            expander: 8,
        },
        stop,
    );
    let mut cur = vec![hash::ZERO; n];
    for layer in kept..11 {
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
                    &sdr::SdrParams::default(),
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
            if n.max(other) - n.min(other) <= n.min(other) / 8 {
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
            Ok((layer, nodes)) if layer < 11 => {
                if nodes.len() != n {
                    return None;
                }
                on_layer(layer, &nodes);
                if layer == 10 {
                    last = Some(nodes);
                }
            }
            Ok((11, columns)) if columns.len() == n => {
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
    let n = requests.iter().map(|r| r.n).max().unwrap_or(0);
    if requests.iter().all(|r| r.cancelled.load(Ordering::Relaxed)) {
        return Ok(());
    }
    if requests.len() == 1 {
        return compute_scalar(&requests[0]);
    }
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
                    &|| r.cancelled.load(Ordering::Relaxed),
                ))
            }
        })
        .collect();
    let mut columns: Vec<_> = requests.iter().map(|r| Columns::new(r.n)).collect();
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
    for layer in 0..11 {
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
            let _ = request.sender.send((11, Arc::new(columns.finish()?)));
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
    let graph = graph_until(
        GraphKey {
            n: request.n,
            drg: 6,
            expander: 8,
        },
        &|| request.cancelled.load(Ordering::Relaxed),
    );
    let mut columns = Columns::new(request.n);
    let mut prev = Arc::new(vec![hash::ZERO; request.n]);
    let mut cur = vec![hash::ZERO; request.n];
    for layer in 0..11 {
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
                    &sdr::SdrParams::default(),
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
    let _ = request.sender.send((11, Arc::new(columns.finish()?)));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
