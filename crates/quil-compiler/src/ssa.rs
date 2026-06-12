//! SSA (Static Single Assignment) intermediate representation.
//! Port of `bedlam/compiler/ssa/`.

mod bindings;
mod block;
mod circuitgen;
mod generator;
pub mod instructions;
mod peephole;
mod program;
pub mod value;
mod wire_allocator;

pub use bindings::{Binding, Bindings};
pub use block::Block;
pub use circuitgen::CircuitGenerator;
pub use generator::Generator;
pub use instructions::{Instr, Operand};
pub use peephole::PeepholeOptimizer;
pub use program::Program;
pub use value::Value;
pub use wire_allocator::WireAllocator;
