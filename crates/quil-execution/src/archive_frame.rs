//! Short-lived read reuse during one archive GLOBAL execution attempt.
use crate::hypergraph_state::HypergraphState;
use quil_hypergraph::HypergraphCrdt;
use std::{
    cell::RefCell,
    collections::HashMap,
    sync::{Arc, Weak},
};

struct Frame {
    number: u64,
    crdt: Weak<HypergraphCrdt>,
    // The bytes actually written with LastSeniorityFrameNumber = number.
    credited: HashMap<Vec<u8>, ([u8; 32], Vec<u8>)>,
}

thread_local! {
    static FRAME: RefCell<Option<Frame>> = const { RefCell::new(None) };
}

#[must_use]
pub struct ArchiveFrame {
    previous: Option<Frame>,
    // This guard restores only the thread on which it started.
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl ArchiveFrame {
    pub fn begin(number: u64) -> Self {
        let previous = FRAME.with(|slot| {
            slot.replace(Some(Frame {
                number,
                crdt: Weak::new(),
                credited: HashMap::new(),
            }))
        });
        Self {
            previous,
            _thread: Default::default(),
        }
    }
}

impl Drop for ArchiveFrame {
    fn drop(&mut self) {
        FRAME.with(|slot| slot.replace(self.previous.take()));
    }
}

pub(crate) fn active(number: u64) -> bool {
    FRAME.with_borrow(|frame| frame.as_ref().is_some_and(|f| f.number == number))
}

pub(crate) fn already_credited(state: &HypergraphState, key: &[u8], number: u64) -> bool {
    FRAME.with_borrow(|slot| {
        let Some(frame) = slot.as_ref().filter(|f| f.number == number) else {
            return false;
        };
        if !std::ptr::eq(frame.crdt.as_ptr(), Arc::as_ptr(state.crdt())) {
            return false;
        }
        frame
            .credited
            .get(key)
            .is_some_and(|(address, blob)| state.staged_global_vertex_matches(address, blob))
    })
}

pub(crate) fn remember_credit(
    state: &HypergraphState,
    key: &[u8],
    address: [u8; 32],
    number: u64,
    blob: Vec<u8>,
) {
    // Bound extra memory per executing archive thread. Oversized records and
    // new keys above the cap go through the ordinary seniority read.
    if blob.len() > 16 * 1024 || key.len() > 1024 {
        return;
    }
    FRAME.with_borrow_mut(|slot| {
        let Some(frame) = slot.as_mut().filter(|f| f.number == number) else {
            return;
        };
        if !std::ptr::eq(frame.crdt.as_ptr(), Arc::as_ptr(state.crdt())) {
            frame.credited.clear();
            frame.crdt = Arc::downgrade(state.crdt());
        }
        if frame.credited.len() < 1024 || frame.credited.contains_key(key) {
            frame.credited.insert(key.to_vec(), (address, blob));
        }
    });
}
