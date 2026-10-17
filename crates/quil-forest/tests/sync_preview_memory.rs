//! Compare preview allocation against the same full JMT reconstruction that
//! sync preparation previously discarded. One test keeps allocator accounting
//! isolated from concurrent test cases.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};

use quil_forest::{Forest, Phase, TreeReader};
use sha2::{Digest, Sha256};

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
        if !ptr.is_null() { account(layout.size() as isize); }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        account(-(layout.size() as isize));
        unsafe { System.dealloc(ptr, layout) };
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, size) };
        if !new.is_null() { account(size as isize - layout.size() as isize); }
        new
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn measured<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    MEASURING.store(true, Ordering::Relaxed);
    let value = f();
    MEASURING.store(false, Ordering::Relaxed);
    (value, (PEAK.load(Ordering::Relaxed) - base).max(0) as usize)
}

#[test]
fn root_preview_auxiliary_memory_stays_bounded_as_plan_grows() {
    let app = [7; 32];
    for count in [8_192u64, 65_536] {
        let forest = Forest::in_memory();
        let mut leaves: Vec<_> = (0..count).map(|i| {
            (Sha256::digest(i.to_be_bytes()).into(), Some(vec![i as u8; 40]))
        }).collect();
        leaves.sort_by_key(|(key, _)| *key);
        let (staged, old_peak) = measured(|| forest.stage_synced_phase(
            &app, Phase::VertexAdds, 0,
            leaves.iter().map(|(key, value)| (quil_forest::KeyHash(*key), value.clone())),
            &[], None,
        ).unwrap());
        let root = staged.root();
        drop(staged);
        let (_, new_peak) = measured(|| forest.preview_synced_phase(
            &app, Phase::VertexAdds, 0, &leaves, &[], root,
        ).unwrap());
        println!("leaves={count} old_preview_peak_bytes={old_peak} root_only_peak_bytes={new_peak}");
        // At most 64 trie levels, each holding 16 children and leaf summaries.
        // The allowance includes transient nodes; input leaves are preallocated.
        assert!(new_peak < 512 * 1024, "root-only preview allocated {new_peak} bytes");
        assert!(old_peak > new_peak * 20, "baseline must expose full-batch retention");
        assert!(forest.shard_phase_reader(&app, Phase::VertexAdds)
            .get_node_option(&jmt::storage::NodeKey::new(0, jmt::storage::NibblePath::new(vec![])))
            .unwrap().is_none(), "neither preview publishes state");
    }
}
