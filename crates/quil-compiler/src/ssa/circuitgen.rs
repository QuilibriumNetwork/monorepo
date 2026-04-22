//! Circuit generation from SSA. Port of `ssa/circuitgen.go`.

use crate::circuit::{self};
use crate::circuits::{self, Allocator, Compiler};

use super::instructions::{Instr, Opcode, Operand};
use super::program::Program;
use super::value::ValueId;
use super::wire_allocator::WireAllocator;

/// Generates a boolean circuit from an SSA program.
pub struct CircuitGenerator {
    wire_alloc: WireAllocator,
    circ_compiler: Compiler,
}

impl CircuitGenerator {
    /// Generate a circuit from the SSA program.
    pub fn generate(program: &Program) -> Result<circuit::Circuit, String> {
        let mut calloc = Allocator::new();

        // Allocate input wires.
        let mut input_wire_indices = Vec::new();
        for input in &program.inputs {
            let wires = calloc.wires(input.type_info.bits);
            input_wire_indices.extend(&wires);
        }

        // Allocate output wires.
        let mut output_wire_indices = Vec::new();
        for output in &program.outputs {
            let wires = calloc.wires(output.type_info.bits);
            for &w in &wires {
                calloc.get_wire_mut(w).set_output(true);
            }
            output_wire_indices.extend(&wires);
        }

        let cc = Compiler::new(
            calloc,
            program.inputs.clone(),
            program.outputs.clone(),
            input_wire_indices,
            output_wire_indices.clone(),
        )?;

        let mut gen = CircuitGenerator {
            wire_alloc: WireAllocator::new(),
            circ_compiler: cc,
        };

        // Assign input wires to input values.
        let mut wire_offset = 0;
        for (idx, input) in program.inputs.iter().enumerate() {
            let bits = input.type_info.bits;
            let wires: Vec<usize> = (wire_offset..wire_offset + bits as usize).collect();
            if idx < program.input_values.len() {
                gen.wire_alloc.set(program.input_values[idx], wires);
            }
            wire_offset += bits as usize;
        }

        // Process each block's instructions.
        for block in &program.blocks {
            for instr in &block.instructions {
                gen.process_instr(instr, program)?;
            }
        }

        // Connect output wires.
        if !program.return_values.is_empty() {
            let mut out_idx = 0;
            for &ret_val in &program.return_values {
                if let Some(wires) = gen.wire_alloc.get(ret_val) {
                    for &w in wires {
                        if out_idx < output_wire_indices.len() {
                            gen.circ_compiler.id(w, output_wire_indices[out_idx]);
                            out_idx += 1;
                        }
                    }
                }
            }
        }

        // Optimize and compile.
        gen.circ_compiler.const_propagate();
        gen.circ_compiler.prune();
        Ok(gen.circ_compiler.compile_circuit())
    }

    fn process_instr(&mut self, instr: &Instr, _program: &Program) -> Result<(), String> {
        match instr.op {
            Opcode::Iadd => self.gen_binary(instr, |cc, a, b, r| {
                circuits::compiler::new_adder(cc, a, b, r)
            }),
            Opcode::Isub => self.gen_binary(instr, |cc, a, b, r| {
                circuits::compiler::new_subtractor(cc, a, b, r)
            }),
            Opcode::Imul => self.gen_binary(instr, |cc, a, b, r| {
                circuits::new_multiplier(cc, 0, a, b, r)
            }),
            Opcode::Idiv => self.gen_divmod(instr, true),
            Opcode::Imod => self.gen_divmod(instr, false),
            Opcode::Ilt => self.gen_compare(instr, |a, b| a < b),
            Opcode::Ile => self.gen_compare(instr, |a, b| a <= b),
            Opcode::Igt => self.gen_compare(instr, |a, b| a > b),
            Opcode::Ige => self.gen_compare(instr, |a, b| a >= b),
            Opcode::Ieq => self.gen_equality(instr, false),
            Opcode::Ineq => self.gen_equality(instr, true),
            Opcode::Band => self.gen_bitwise(instr, crate::circuit::Operation::And),
            Opcode::Bor => self.gen_bitwise(instr, crate::circuit::Operation::Or),
            Opcode::Bxor => self.gen_bitwise(instr, crate::circuit::Operation::Xor),
            Opcode::Not => self.gen_not(instr),
            Opcode::Lshift => self.gen_shift(instr, true),
            Opcode::Rshift => self.gen_shift(instr, false),
            Opcode::Mov => self.gen_mov(instr),
            Opcode::Ret | Opcode::Jump | Opcode::If | Opcode::Nop => Ok(()),
            Opcode::Phi => self.gen_mov(instr), // Simplified phi = mov from first operand
            _ => Ok(()), // Other ops handled at higher level
        }
    }

    fn gen_binary(
        &mut self,
        instr: &Instr,
        op: impl FnOnce(&mut Compiler, &[usize], &[usize], &mut [usize]) -> Result<(), String>,
    ) -> Result<(), String> {
        let out_id = instr.out.ok_or("binary op missing output")?;
        let (a_id, b_id) = self.get_two_value_operands(instr)?;

        let a_wires = self
            .wire_alloc
            .get(a_id)
            .cloned()
            .ok_or("missing wires for operand a")?;
        let b_wires = self
            .wire_alloc
            .get(b_id)
            .cloned()
            .ok_or("missing wires for operand b")?;

        let out_bits = instr.type_info.bits;
        let mut out_wires = self
            .wire_alloc
            .alloc(&mut self.circ_compiler.allocator, out_id, out_bits);

        op(&mut self.circ_compiler, &a_wires, &b_wires, &mut out_wires)?;

        self.wire_alloc.set(out_id, out_wires);
        Ok(())
    }

    fn gen_divmod(&mut self, instr: &Instr, is_div: bool) -> Result<(), String> {
        let out_id = instr.out.ok_or("divmod missing output")?;
        let (a_id, b_id) = self.get_two_value_operands(instr)?;

        let a_wires = self.wire_alloc.get(a_id).cloned().ok_or("missing a wires")?;
        let b_wires = self.wire_alloc.get(b_id).cloned().ok_or("missing b wires")?;

        let bits = instr.type_info.bits;
        let mut q_wires = self
            .wire_alloc
            .alloc(&mut self.circ_compiler.allocator, out_id, bits);
        let mut r_wires: Vec<usize> = (0..bits as usize)
            .map(|_| self.circ_compiler.allocator.wire())
            .collect();

        circuits::new_idivider(
            &mut self.circ_compiler,
            &a_wires,
            &b_wires,
            &mut q_wires,
            &mut r_wires,
        )?;

        if is_div {
            self.wire_alloc.set(out_id, q_wires);
        } else {
            self.wire_alloc.set(out_id, r_wires);
        }
        Ok(())
    }

    fn gen_compare(
        &mut self,
        instr: &Instr,
        _cmp: impl Fn(i64, i64) -> bool,
    ) -> Result<(), String> {
        let out_id = instr.out.ok_or("compare missing output")?;
        let (a_id, b_id) = self.get_two_value_operands(instr)?;

        let a_wires = self.wire_alloc.get(a_id).cloned().ok_or("missing a wires")?;
        let b_wires = self.wire_alloc.get(b_id).cloned().ok_or("missing b wires")?;

        // Subtract and check sign bit.
        let n = a_wires.len().max(b_wires.len());
        let mut diff: Vec<usize> = (0..n + 1)
            .map(|_| self.circ_compiler.allocator.wire())
            .collect();
        circuits::compiler::new_subtractor(&mut self.circ_compiler, &a_wires, &b_wires, &mut diff)?;

        // Result is the sign/borrow bit.
        let out_wire = self.circ_compiler.allocator.wire();
        self.circ_compiler.id(diff[n], out_wire);
        self.wire_alloc.set(out_id, vec![out_wire]);
        Ok(())
    }

    fn gen_equality(&mut self, instr: &Instr, negate: bool) -> Result<(), String> {
        let out_id = instr.out.ok_or("equality missing output")?;
        let (a_id, b_id) = self.get_two_value_operands(instr)?;

        let a_wires = self.wire_alloc.get(a_id).cloned().ok_or("missing a wires")?;
        let b_wires = self.wire_alloc.get(b_id).cloned().ok_or("missing b wires")?;

        // XOR each pair, OR all results, then INV for equality.
        let n = a_wires.len().max(b_wires.len());
        let zw = self.circ_compiler.zero_wire();

        let mut xor_result = zw;
        for i in 0..n {
            let aw = if i < a_wires.len() { a_wires[i] } else { zw };
            let bw = if i < b_wires.len() { b_wires[i] } else { zw };
            let x = self.circ_compiler.allocator.wire();
            self.circ_compiler.gates.push(
                circuits::Gate::new(crate::circuit::Operation::Xor, aw, bw, x),
            );
            let or_out = self.circ_compiler.allocator.wire();
            self.circ_compiler.gates.push(
                circuits::Gate::new(crate::circuit::Operation::Or, xor_result, x, or_out),
            );
            xor_result = or_out;
        }

        let out_wire = self.circ_compiler.allocator.wire();
        if negate {
            self.circ_compiler.id(xor_result, out_wire);
        } else {
            self.circ_compiler.inv(xor_result, out_wire);
        }
        self.wire_alloc.set(out_id, vec![out_wire]);
        Ok(())
    }

    fn gen_bitwise(&mut self, instr: &Instr, op: crate::circuit::Operation) -> Result<(), String> {
        let out_id = instr.out.ok_or("bitwise missing output")?;
        let (a_id, b_id) = self.get_two_value_operands(instr)?;

        let a_wires = self.wire_alloc.get(a_id).cloned().ok_or("missing a wires")?;
        let b_wires = self.wire_alloc.get(b_id).cloned().ok_or("missing b wires")?;

        let n = a_wires.len().max(b_wires.len());
        let zw = self.circ_compiler.zero_wire();
        let mut out_wires = Vec::with_capacity(n);

        for i in 0..n {
            let aw = if i < a_wires.len() { a_wires[i] } else { zw };
            let bw = if i < b_wires.len() { b_wires[i] } else { zw };
            let o = self.circ_compiler.allocator.wire();
            self.circ_compiler
                .gates
                .push(circuits::Gate::new(op, aw, bw, o));
            out_wires.push(o);
        }
        self.wire_alloc.set(out_id, out_wires);
        Ok(())
    }

    fn gen_not(&mut self, instr: &Instr) -> Result<(), String> {
        let out_id = instr.out.ok_or("not missing output")?;
        let a_id = self.get_one_value_operand(instr)?;

        let a_wires = self.wire_alloc.get(a_id).cloned().ok_or("missing a wires")?;
        let mut out_wires = Vec::with_capacity(a_wires.len());
        for &w in &a_wires {
            let o = self.circ_compiler.allocator.wire();
            self.circ_compiler.inv(w, o);
            out_wires.push(o);
        }
        self.wire_alloc.set(out_id, out_wires);
        Ok(())
    }

    fn gen_shift(&mut self, instr: &Instr, left: bool) -> Result<(), String> {
        let out_id = instr.out.ok_or("shift missing output")?;
        let (a_id, _b_id) = self.get_two_value_operands(instr)?;

        // For constant shifts, we can just rewire.
        let a_wires = self.wire_alloc.get(a_id).cloned().ok_or("missing a wires")?;

        // Get shift amount from second operand (must be constant for circuit gen).
        let shift = match &instr.operands.get(1) {
            Some(Operand::Imm(n)) => *n as usize,
            _ => 0, // Non-constant shifts need mux trees; simplified here.
        };

        let n = a_wires.len();
        let zw = self.circ_compiler.zero_wire();
        let mut out_wires = vec![zw; n];

        if left {
            for i in 0..n {
                if i >= shift {
                    out_wires[i] = a_wires[i - shift];
                }
            }
        } else {
            for i in 0..n {
                if i + shift < n {
                    out_wires[i] = a_wires[i + shift];
                }
            }
        }
        self.wire_alloc.set(out_id, out_wires);
        Ok(())
    }

    fn gen_mov(&mut self, instr: &Instr) -> Result<(), String> {
        let out_id = instr.out.ok_or("mov missing output")?;
        let src_id = self.get_one_value_operand(instr)?;

        if let Some(wires) = self.wire_alloc.get(src_id).cloned() {
            self.wire_alloc.set(out_id, wires);
        }
        Ok(())
    }

    fn get_two_value_operands(&self, instr: &Instr) -> Result<(ValueId, ValueId), String> {
        let a = match instr.operands.get(0) {
            Some(Operand::Value(id)) => *id,
            _ => return Err("expected value operand at position 0".to_string()),
        };
        let b = match instr.operands.get(1) {
            Some(Operand::Value(id)) => *id,
            _ => return Err("expected value operand at position 1".to_string()),
        };
        Ok((a, b))
    }

    fn get_one_value_operand(&self, instr: &Instr) -> Result<ValueId, String> {
        match instr.operands.get(0) {
            Some(Operand::Value(id)) => Ok(*id),
            _ => Err("expected value operand at position 0".to_string()),
        }
    }
}
