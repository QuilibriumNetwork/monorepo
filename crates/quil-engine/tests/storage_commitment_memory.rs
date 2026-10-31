//! What one frame's storage commitment (`storage_snapshot::commitment`)
//! allocates and returns, against the replica it opens. Every frame a seat
//! proposes computes one, for every seat at once, so it must hold a bounded
//! share of the replica (the cap and the subtrees it opens), not the replica.
//! One allocator-measuring test per binary run keeps the accounting isolated
//! (nextest runs each test in its own process).
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::Arc;

use quil_crypto::storage_proof::{
    opening_index, openings_root, MerkleTree, Node, Tree, CAP_HEIGHT, NODE_BYTES,
};
use quil_execution::global_intrinsic::leaf_id_bytes;
use quil_execution::global_intrinsic::storage_epoch_proof as epoch_proof;
use quil_store::replica_store::ReplicaStore;
use quil_types::consensus::{StorageSeatSlot, STORAGE_QUERIES_PER_LEAF};

struct CountingAllocator;
static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);
static MEASURING: AtomicBool = AtomicBool::new(false);

fn account(delta: isize) {
    let live = LIVE.fetch_add(delta, Ordering::Relaxed) + delta;
    if MEASURING.load(Ordering::Relaxed) {
        PEAK.fetch_max(live, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            account(layout.size() as isize);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        account(-(layout.size() as isize));
        unsafe { System.dealloc(ptr, layout) };
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, size) };
        if !new.is_null() {
            account(size as isize - layout.size() as isize);
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// `f`'s result and the most it held allocated above what was live before.
fn measured<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    MEASURING.store(true, Ordering::Relaxed);
    let value = f();
    MEASURING.store(false, Ordering::Relaxed);
    (value, (PEAK.load(Ordering::Relaxed) - base).max(0) as usize)
}

/// `n` canonical serialized nodes (every element below 2^30).
fn replica(n: usize, seed: u32) -> Vec<u8> {
    let mut nodes = vec![0u8; n * NODE_BYTES];
    let mut x = seed.wrapping_mul(0x9E37_79B9) | 1;
    for word in nodes.chunks_exact_mut(4) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        word.copy_from_slice(&(x >> 2).to_le_bytes());
    }
    nodes
}

/// The registration root a member registered `tree`'s replica with.
fn registration_root(tree: &MerkleTree) -> Vec<u8> {
    let mut root = vec![0u8; 2 * NODE_BYTES];
    root.extend_from_slice(&tree.commitment(Tree::Replica));
    root
}

const MEMBER: [u8; 32] = [0x5A; 32];
const FILTER: [u8; 35] = [0x3C; 35];

struct Leaf {
    leaf_id: Vec<u8>,
    nodes: Vec<u8>,
    tree: MerkleTree,
}

/// Leaves of the seat `slot` stores at `epoch`, put as `put` stores them.
fn seat(
    sizes: &[usize],
    epoch: u64,
    put: &dyn Fn(&Leaf, &[u8], &[u8]),
) -> (Vec<Leaf>, StorageSeatSlot) {
    let mut leaves = Vec::new();
    let mut prefixes = Vec::new();
    for (i, &n) in sizes.iter().enumerate() {
        let prefix = vec![i as u32 * 7, 3];
        let nodes = replica(n, i as u32 + 1);
        let tree = MerkleTree::from_nodes(&nodes).unwrap();
        let leaf = Leaf {
            leaf_id: leaf_id_bytes(&FILTER, &prefix),
            nodes,
            tree,
        };
        let cap = leaf.tree.cap(CAP_HEIGHT).to_bytes();
        put(&leaf, &cap, &registration_root(&leaf.tree));
        leaves.push(leaf);
        prefixes.push(prefix);
    }
    let slot = StorageSeatSlot {
        epoch,
        leaves: prefixes,
        registered_at: 900,
        sealed_at: Some(901),
        frames: 0,
        accumulator: [0; 32],
        chained: vec![],
        open: true,
    };
    (leaves, slot)
}

/// The root from whole trees, every path read off the full tree: what the
/// commitment must equal however it reads the replica.
fn reference_root(leaves: &[Leaf], epoch: u64, frame_number: u64, rho_n: &[u8]) -> [u8; 32] {
    let mut values: Vec<Node> = Vec::new();
    for leaf in leaves {
        let n = leaf.tree.n();
        for query in 0..STORAGE_QUERIES_PER_LEAF {
            let index = opening_index(rho_n, &leaf.leaf_id, epoch, &MEMBER, query, n);
            let at = index as usize * NODE_BYTES;
            values.push(leaf.nodes[at..at + NODE_BYTES].try_into().unwrap());
            // The whole tree's path verifies the value the root takes.
            assert!(quil_crypto::storage_proof::verify_path(
                Tree::Replica,
                n,
                &leaf.tree.commitment(Tree::Replica),
                index,
                &values[values.len() - 1],
                &leaf.tree.path(index),
            ));
        }
    }
    openings_root(frame_number, &values).unwrap()
}

/// The root by the epoch proof's own opening of whole replicas
/// (`frame_openings`), as a settlement recomputes it.
fn whole_replica_root(leaves: &[Leaf], epoch: u64, frame_number: u64, rho_n: &[u8]) -> [u8; 32] {
    let caps: Vec<_> = leaves
        .iter()
        .map(|leaf| leaf.tree.cap(CAP_HEIGHT))
        .collect();
    let held: Vec<_> = leaves
        .iter()
        .map(|leaf| epoch_proof::HeldLeaf {
            leaf_id: leaf.leaf_id.clone(),
            n: leaf.tree.n(),
            comm_r: leaf.tree.commitment(Tree::Replica),
        })
        .collect();
    let replicas: Vec<_> = leaves
        .iter()
        .zip(&caps)
        .map(|(leaf, cap)| epoch_proof::HeldReplica {
            replica: &leaf.nodes,
            cap,
        })
        .collect();
    let opened = epoch_proof::frame_openings(&MEMBER, epoch, &held, &replicas, rho_n).unwrap();
    epoch_proof::openings_root(frame_number, &opened).unwrap()
}

fn store() -> ReplicaStore {
    ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()))
}

/// The value builds before the chunked layout stored a hash leaf as, under
/// `[STORAGE_REPLICA][epoch BE][leaf_id]`.
fn put_legacy(db: &dyn quil_types::store::KvDb, epoch: u64, leaf: &Leaf, cap: &[u8], root: &[u8]) {
    let mut key = vec![quil_store::encoding::STORAGE_REPLICA];
    key.extend_from_slice(&epoch.to_be_bytes());
    key.extend_from_slice(&leaf.leaf_id);
    let mut value = vec![0xA5];
    value.extend_from_slice(&(cap.len() as u32).to_be_bytes());
    value.extend_from_slice(cap);
    value.extend_from_slice(&(root.len() as u32).to_be_bytes());
    value.extend_from_slice(root);
    value.extend_from_slice(&leaf.nodes);
    db.set(&key, &value).unwrap();
}

/// The commitment's root is the one the whole replicas give, byte for
/// byte, for leaves stored now and leaves an earlier build stored whole, of
/// one cap subtree, several, and a short last one.
#[test]
fn a_frame_commitment_equals_the_whole_replica_root() {
    let epoch = 1400;
    let sizes = [3 * (1usize << CAP_HEIGHT) + 77, 5, 1 << CAP_HEIGHT];
    let current = store();
    let (leaves, slot) = seat(&sizes, epoch, &|leaf, cap, root| {
        current
            .put_hash(epoch, &leaf.leaf_id, &leaf.nodes, cap, root)
            .unwrap()
    });
    let db: Arc<dyn quil_types::store::KvDb> =
        Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
    let legacy = ReplicaStore::new(db.clone());
    seat(&sizes, epoch, &|leaf, cap, root| {
        put_legacy(db.as_ref(), epoch, leaf, cap, root)
    });
    for (frame_number, rho_n) in [(77u64, [0x11u8; 32]), (78, [0x12; 32]), (79, [0x13; 32])] {
        let expected = reference_root(&leaves, epoch, frame_number, &rho_n);
        assert_eq!(
            whole_replica_root(&leaves, epoch, frame_number, &rho_n),
            expected
        );
        for (label, replicas) in [("current", &current), ("legacy", &legacy)] {
            // A leaf stored whole by an earlier build may be converted off
            // the proposal path first: its frames commit once that is done.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            let root = loop {
                match quil_engine::storage_snapshot::commitment(
                    replicas,
                    &MEMBER,
                    &FILTER,
                    &slot,
                    frame_number,
                    &rho_n,
                ) {
                    Ok(root) => break root,
                    Err(quil_types::error::QuilError::ExecutionUnavailable(_))
                        if std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(20))
                    }
                    Err(error) => panic!("{label} commitment: {error}"),
                }
            };
            assert_eq!(root, expected, "{label} store, frame {frame_number}");
        }
    }
    // A leaf the member does not hold commits nothing.
    let mut missing = slot.clone();
    missing.leaves.push(vec![99]);
    assert!(quil_engine::storage_snapshot::commitment(
        &current,
        &MEMBER,
        &FILTER,
        &missing,
        80,
        &[0x14; 32]
    )
    .is_err());
}

/// A frame's commitment holds a bounded share of the replica: the cap and
/// the subtrees it opens. Before the chunked layout it copied the whole
/// replica twice (the store's read, then its decode).
#[test]
fn a_frame_commitment_allocates_a_bounded_share_of_the_replica() {
    let epoch = 1400;
    let n = 1usize << 18; // an 8 MiB replica
    let replicas = store();
    let (leaves, slot) = seat(&[n], epoch, &|leaf, cap, root| {
        replicas
            .put_hash(epoch, &leaf.leaf_id, &leaf.nodes, cap, root)
            .unwrap()
    });
    let cap_bytes = leaves[0].tree.cap(CAP_HEIGHT).to_bytes().len();
    let subtree_bytes = (1usize << CAP_HEIGHT) * NODE_BYTES;
    let replica_bytes = n * NODE_BYTES;
    let bound = 8 * (cap_bytes + subtree_bytes);
    for (frame_number, rho_n) in [(77u64, [0x21u8; 32]), (78, [0x22; 32])] {
        let (root, peak) = measured(|| {
            quil_engine::storage_snapshot::commitment(
                &replicas,
                &MEMBER,
                &FILTER,
                &slot,
                frame_number,
                &rho_n,
            )
            .unwrap()
        });
        println!(
            "frame={frame_number} replica_bytes={replica_bytes} cap_bytes={cap_bytes} \
             peak_bytes={peak} bound={bound}"
        );
        assert_eq!(root, reference_root(&leaves, epoch, frame_number, &rho_n));
        assert!(
            peak <= bound,
            "a commitment over a {replica_bytes}-byte replica allocated {peak} bytes at its \
             peak, beyond {bound} (8 x (cap {cap_bytes} + subtree {subtree_bytes}))"
        );
    }
}

/// Full scale (run with `--run-ignored only`; `QUIL_REPLICA_MIB` sets the
/// size, default 929 MiB, the replica size seen on mainnet): time and peak
/// memory of storing a replica and of a frame's commitment over it, on disk
/// with the node's store options. Peak RSS covers RocksDB's own buffers,
/// which the allocator count does not.
#[test]
#[ignore = "full-scale measurement: about 3 GiB of memory and a minute or more"]
fn full_scale_frame_commitment_cost() {
    let mib: usize = std::env::var("QUIL_REPLICA_MIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(929);
    let n = (mib << 20) / NODE_BYTES;
    let epoch = 1400;
    let dir = std::env::temp_dir().join(format!("replica-cost-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let replicas = ReplicaStore::new(Arc::new(quil_store::RocksDb::open(&dir).unwrap()));
    let started = std::time::Instant::now();
    let nodes = replica(n, 9);
    let tree = MerkleTree::from_nodes(&nodes).unwrap();
    let cap = tree.cap(CAP_HEIGHT).to_bytes();
    let root = registration_root(&tree);
    println!("generated n={n} nodes in {:?}", started.elapsed());
    let prefix = vec![1u32, 3];
    let leaf_id = leaf_id_bytes(&FILTER, &prefix);
    let started = std::time::Instant::now();
    let ((), put_peak) = measured(|| {
        replicas
            .put_hash(epoch, &leaf_id, &nodes, &cap, &root)
            .unwrap()
    });
    println!(
        "put_hash replica_mib={mib} ms={} peak_alloc_mib={:.1}",
        started.elapsed().as_millis(),
        put_peak as f64 / 1048576.0
    );
    let leaves = [Leaf {
        leaf_id,
        nodes,
        tree,
    }];
    let slot = StorageSeatSlot {
        epoch,
        leaves: vec![prefix],
        registered_at: 900,
        sealed_at: Some(901),
        frames: 0,
        accumulator: [0; 32],
        chained: vec![],
        open: true,
    };
    let expected: Vec<_> = (0..4u64)
        .map(|i| reference_root(&leaves, epoch, 100 + i, &[i as u8 + 1; 32]))
        .collect();
    // The generated replica and tree stay allocated; RSS growth is measured
    // above them.
    for (i, expected) in expected.iter().enumerate() {
        let rss_before = status_kib("VmRSS:");
        reset_peak_rss();
        let started = std::time::Instant::now();
        let (root, peak) = measured(|| {
            quil_engine::storage_snapshot::commitment(
                &replicas,
                &MEMBER,
                &FILTER,
                &slot,
                100 + i as u64,
                &[i as u8 + 1; 32],
            )
            .unwrap()
        });
        let ms = started.elapsed().as_secs_f64() * 1000.0;
        let hwm = status_kib("VmHWM:");
        println!(
            "commitment call={i} replica_mib={mib} ms={ms:.1} peak_alloc_mib={:.2} \
             peak_rss_growth_mib={:.1}",
            peak as f64 / 1048576.0,
            hwm.saturating_sub(rss_before) as f64 / 1024.0
        );
        assert_eq!(&root, expected);
    }
    drop(replicas);
    let _ = std::fs::remove_dir_all(&dir);
}

fn status_kib(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with(field))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|kib| kib.parse().ok())
        })
        .unwrap_or(0)
}

/// Restart VmHWM from the current RSS.
fn reset_peak_rss() {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
}
