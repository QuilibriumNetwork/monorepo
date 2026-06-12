//! Wire and gate allocator. Port of `circuits/wire.go` (Allocator portion).

use crate::circuit::Operation;
use crate::types::Size;

use super::gates::Gate;
use super::wire::Wire;

/// Allocates wires and gates.
pub struct Allocator {
    wires: Vec<Wire>,
}

impl Allocator {
    pub fn new() -> Self {
        Allocator {
            wires: Vec::with_capacity(1024),
        }
    }

    /// Allocate a single wire, returning its index.
    pub fn wire(&mut self) -> usize {
        let idx = self.wires.len();
        self.wires.push(Wire::new());
        idx
    }

    /// Allocate `n` wires, returning their indices.
    pub fn wires(&mut self, n: Size) -> Vec<usize> {
        let start = self.wires.len();
        for _ in 0..n {
            self.wires.push(Wire::new());
        }
        (start..start + n as usize).collect()
    }

    /// Access wire by index.
    pub fn get_wire(&self, idx: usize) -> &Wire {
        &self.wires[idx]
    }

    /// Access wire mutably by index.
    pub fn get_wire_mut(&mut self, idx: usize) -> &mut Wire {
        &mut self.wires[idx]
    }

    /// Create a binary gate.
    pub fn binary_gate(&mut self, op: Operation, a: usize, b: usize, o: usize) -> Gate {
        self.wires[o].set_input_gate(Some(0)); // will be set properly during compilation
        self.wires[a].add_output(0);
        self.wires[b].add_output(0);
        Gate::new(op, a, b, o)
    }

    /// Create an INV gate.
    pub fn inv_gate(&mut self, a: usize, o: usize) -> Gate {
        self.wires[o].set_input_gate(Some(0));
        self.wires[a].add_output(0);
        Gate::new(Operation::Inv, a, 0, o)
    }

    /// Total number of allocated wires.
    pub fn num_wires(&self) -> usize {
        self.wires.len()
    }
}
