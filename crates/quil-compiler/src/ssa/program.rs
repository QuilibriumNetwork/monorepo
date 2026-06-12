//! SSA program. Port of `ssa/program.go`.

use crate::circuit::{self, Circuit};

use super::block::Block;
use super::circuitgen::CircuitGenerator;
use super::value::{Value, ValueId};

/// SSA program ready for circuit compilation.
#[derive(Debug, Clone)]
pub struct Program {
    pub inputs: circuit::IO,
    pub outputs: circuit::IO,
    pub blocks: Vec<Block>,
    pub values: Vec<Value>,
    /// SSA value IDs corresponding to each input argument.
    pub input_values: Vec<ValueId>,
    /// SSA value IDs for return values.
    pub return_values: Vec<ValueId>,
    /// Circuit stats (populated after compilation).
    pub stats: circuit::Stats,
}

impl Program {
    pub fn new() -> Self {
        Program {
            inputs: Vec::new(),
            outputs: Vec::new(),
            blocks: Vec::new(),
            values: Vec::new(),
            input_values: Vec::new(),
            return_values: Vec::new(),
            stats: circuit::Stats::default(),
        }
    }

    /// Compile the SSA program into a boolean circuit.
    pub fn compile_circuit(&self) -> Result<Circuit, String> {
        CircuitGenerator::generate(self)
    }
}
