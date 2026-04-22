//! Peephole optimization pass. Port of `ssa/peephole.go`.

use super::block::Block;
use super::instructions::{Instr, Opcode, Operand};
use super::value::Value;

/// Peephole optimizer.
pub struct PeepholeOptimizer;

impl PeepholeOptimizer {
    /// Run peephole optimizations on all blocks.
    pub fn optimize(blocks: &mut [Block], values: &mut [Value]) {
        for block in blocks.iter_mut() {
            Self::optimize_block(block, values);
        }
    }

    fn optimize_block(block: &mut Block, values: &mut [Value]) {
        let mut i = 0;
        while i < block.instructions.len() {
            let changed = Self::try_optimize(&mut block.instructions, i, values);
            if !changed {
                i += 1;
            }
        }
    }

    fn try_optimize(instrs: &mut Vec<Instr>, idx: usize, values: &mut [Value]) -> bool {
        let instr = &instrs[idx];

        // Pattern: add x, 0 → mov x
        if instr.op == Opcode::Iadd {
            if let Some(Operand::Value(b_id)) = instr.operands.get(1) {
                if let Some(ref c) = values[*b_id as usize].const_val {
                    if c.int64() == 0 {
                        if let Some(Operand::Value(a_id)) = instr.operands.get(0) {
                            let out = instr.out;
                            let a = *a_id;
                            instrs[idx] = Instr::new(Opcode::Mov)
                                .with_operand(Operand::Value(a));
                            instrs[idx].out = out;
                            return true;
                        }
                    }
                }
            }
        }

        // Pattern: mul x, 1 → mov x
        if instr.op == Opcode::Imul {
            if let Some(Operand::Value(b_id)) = instr.operands.get(1) {
                if let Some(ref c) = values[*b_id as usize].const_val {
                    if c.int64() == 1 {
                        if let Some(Operand::Value(a_id)) = instr.operands.get(0) {
                            let out = instr.out;
                            let a = *a_id;
                            instrs[idx] = Instr::new(Opcode::Mov)
                                .with_operand(Operand::Value(a));
                            instrs[idx].out = out;
                            return true;
                        }
                    }
                }
            }
        }

        // Pattern: mul x, 0 → const 0
        if instr.op == Opcode::Imul {
            for op in &instr.operands {
                if let Operand::Value(id) = op {
                    if let Some(ref c) = values[*id as usize].const_val {
                        if c.int64() == 0 {
                            if let Some(out) = instr.out {
                                values[out as usize].set_const(crate::mpa::Int::from_i64(0, 32));
                                instrs[idx] = Instr::new(Opcode::Nop);
                                instrs[idx].out = Some(out);
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }
}
