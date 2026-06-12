//! SSA code generator. Port of `ssa/generator.go`.

use crate::mpa;
use crate::types::Info;

use super::bindings::Bindings;
use super::block::Block;
use super::instructions::{Instr, Opcode, Operand};
use super::value::{Value, ValueId};

/// SSA code generator.
pub struct Generator {
    pub values: Vec<Value>,
    pub blocks: Vec<Block>,
    pub current_block: usize,
    pub bindings: Bindings,
    next_value_id: ValueId,
}

impl Generator {
    pub fn new() -> Self {
        let entry = Block::new(0, "entry");
        Generator {
            values: Vec::new(),
            blocks: vec![entry],
            current_block: 0,
            bindings: Bindings::new(),
            next_value_id: 0,
        }
    }

    /// Create a new SSA value.
    pub fn new_value(&mut self, name: &str, type_info: Info) -> ValueId {
        let id = self.next_value_id;
        self.next_value_id += 1;
        self.values.push(Value::new(id, name, type_info));
        id
    }

    /// Create a constant value.
    pub fn new_const(&mut self, val: mpa::Int, type_info: Info) -> ValueId {
        let id = self.new_value(&val.to_string(), type_info);
        self.values[id as usize].set_const(val);
        id
    }

    /// Create a new block.
    pub fn new_block(&mut self, name: &str) -> usize {
        let id = self.blocks.len();
        self.blocks.push(Block::new(id, name));
        id
    }

    /// Switch to a block.
    pub fn set_current_block(&mut self, block_id: usize) {
        self.current_block = block_id;
    }

    /// Emit an instruction to the current block.
    pub fn emit(&mut self, instr: Instr) {
        self.blocks[self.current_block].add_instr(instr);
    }

    /// Emit a binary arithmetic instruction.
    pub fn emit_binary(
        &mut self,
        op: Opcode,
        left: ValueId,
        right: ValueId,
        result_type: Info,
    ) -> ValueId {
        let out = self.new_value("", result_type.clone());
        let instr = Instr::new(op)
            .with_out(out)
            .with_operand(Operand::Value(left))
            .with_operand(Operand::Value(right))
            .with_type(result_type);
        self.emit(instr);
        out
    }

    /// Emit a unary instruction.
    pub fn emit_unary(
        &mut self,
        op: Opcode,
        operand: ValueId,
        result_type: Info,
    ) -> ValueId {
        let out = self.new_value("", result_type.clone());
        let instr = Instr::new(op)
            .with_out(out)
            .with_operand(Operand::Value(operand))
            .with_type(result_type);
        self.emit(instr);
        out
    }

    /// Emit a move instruction.
    pub fn emit_mov(&mut self, src: ValueId, dst_type: Info) -> ValueId {
        let out = self.new_value("", dst_type.clone());
        let instr = Instr::new(Opcode::Mov)
            .with_out(out)
            .with_operand(Operand::Value(src))
            .with_type(dst_type);
        self.emit(instr);
        out
    }

    /// Emit a conditional branch.
    pub fn emit_if(&mut self, cond: ValueId, true_block: usize, false_block: usize) {
        let instr = Instr::new(Opcode::If)
            .with_operand(Operand::Value(cond))
            .with_operand(Operand::Label(true_block))
            .with_operand(Operand::Label(false_block));
        self.emit(instr);

        self.blocks[self.current_block].add_succ(true_block);
        self.blocks[self.current_block].add_succ(false_block);
        self.blocks[true_block].add_pred(self.current_block);
        self.blocks[false_block].add_pred(self.current_block);
    }

    /// Emit an unconditional jump.
    pub fn emit_jump(&mut self, target: usize) {
        let instr = Instr::new(Opcode::Jump).with_operand(Operand::Label(target));
        self.emit(instr);

        self.blocks[self.current_block].add_succ(target);
        self.blocks[target].add_pred(self.current_block);
    }

    /// Emit a return.
    pub fn emit_ret(&mut self, values: &[ValueId]) {
        let mut instr = Instr::new(Opcode::Ret);
        for &v in values {
            instr = instr.with_operand(Operand::Value(v));
        }
        self.emit(instr);
    }

    /// Emit a phi node.
    pub fn emit_phi(&mut self, operands: &[(usize, ValueId)], result_type: Info) -> ValueId {
        let out = self.new_value("", result_type.clone());
        let mut instr = Instr::new(Opcode::Phi).with_out(out).with_type(result_type);
        for &(block, val) in operands {
            instr = instr
                .with_operand(Operand::Label(block))
                .with_operand(Operand::Value(val));
        }
        self.emit(instr);
        out
    }

    /// Get a value by ID.
    pub fn get_value(&self, id: ValueId) -> &Value {
        &self.values[id as usize]
    }

    /// Get a mutable value by ID.
    pub fn get_value_mut(&mut self, id: ValueId) -> &mut Value {
        &mut self.values[id as usize]
    }
}
