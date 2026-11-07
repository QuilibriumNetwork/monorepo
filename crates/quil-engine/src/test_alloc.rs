//! Heap accounting for this crate's unit tests: the bytes a thread has
//! allocated and not yet freed. Counted per thread, so tests running
//! alongside on other threads do not disturb a measurement.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct ThreadCountingAllocator;

thread_local! {
    /// Bytes this thread allocated minus the bytes it freed.
    static LIVE: Cell<isize> = const { Cell::new(0) };
    /// The most [`LIVE`] reached since [`peak_by`] last reset it.
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

fn account(delta: isize) {
    // Unavailable while the thread's locals are destroyed: those
    // allocations go uncounted.
    let _ = LIVE.try_with(|live| {
        let now = live.get() + delta;
        live.set(now);
        let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
    });
}

unsafe impl GlobalAlloc for ThreadCountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            account(layout.size() as isize);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
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
static ALLOCATOR: ThreadCountingAllocator = ThreadCountingAllocator;

/// Run `f` and return its value with the most bytes it held allocated on
/// this thread at once, beyond what the thread held before.
pub(crate) fn peak_by<T>(f: impl FnOnce() -> T) -> (T, isize) {
    let before = LIVE.with(Cell::get);
    let outer = PEAK.with(|peak| peak.replace(before));
    let value = f();
    let peak = PEAK.with(|peak| peak.replace(outer.max(peak.get())));
    (value, peak - before)
}

/// Run `f` and return its value with the bytes it left allocated on this
/// thread: allocated and not freed by the time it returned.
pub(crate) fn retained_by<T>(f: impl FnOnce() -> T) -> (T, isize) {
    let before = LIVE.with(Cell::get);
    let value = f();
    (value, LIVE.with(Cell::get) - before)
}
