//! Binary gate implementation. Port of `circuits/gates.go`.

use crate::circuit::Operation;

/// Binary gate.
pub struct Gate {
    pub op: Operation,
    pub visited: bool,
    pub compiled: bool,
    pub dead: bool,
    /// Wire indices (into the compiler's wire array).
    pub a: usize,
    pub b: usize,
    pub o: usize,
}

impl Gate {
    pub fn new(op: Operation, a: usize, b: usize, o: usize) -> Self {
        Gate {
            op,
            visited: false,
            compiled: false,
            dead: false,
            a,
            b,
            o,
        }
    }
}
