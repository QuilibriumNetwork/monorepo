//! Binary circuit compiler: gates, wires, adders, multipliers, dividers.
//! Port of `bedlam/compiler/circuits/`.

mod allocator;
pub mod compiler;
mod divider;
mod gates;
mod multiplier;
mod wire;

pub use allocator::Allocator;
pub use compiler::Compiler;
pub use divider::*;
pub use gates::Gate;
pub use multiplier::*;
pub use wire::{Wire, WireValue};
