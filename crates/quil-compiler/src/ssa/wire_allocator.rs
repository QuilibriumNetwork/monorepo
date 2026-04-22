//! Wire allocation for SSA → circuit mapping. Port of `ssa/wire_allocator.go`.

use std::collections::HashMap;

use crate::circuits;
use crate::types::Size;

use super::value::ValueId;

/// Maps SSA values to circuit wires.
pub struct WireAllocator {
    /// value_id → wire indices
    map: HashMap<ValueId, Vec<usize>>,
}

impl WireAllocator {
    pub fn new() -> Self {
        WireAllocator {
            map: HashMap::new(),
        }
    }

    /// Allocate wires for a value.
    pub fn alloc(&mut self, alloc: &mut circuits::Allocator, id: ValueId, bits: Size) -> Vec<usize> {
        let wires = alloc.wires(bits);
        self.map.insert(id, wires.clone());
        wires
    }

    /// Get the wires for a value.
    pub fn get(&self, id: ValueId) -> Option<&Vec<usize>> {
        self.map.get(&id)
    }

    /// Set wires for a value (e.g., for phi nodes or aliases).
    pub fn set(&mut self, id: ValueId, wires: Vec<usize>) {
        self.map.insert(id, wires);
    }

    /// Check if a value has wires allocated.
    pub fn contains(&self, id: ValueId) -> bool {
        self.map.contains_key(&id)
    }
}
