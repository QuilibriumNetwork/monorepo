//! Circuit compiler: gate assignment, optimization, compilation.
//! Port of `circuits/compiler.go`.

use crate::circuit::{self, Operation};

use super::allocator::Allocator;
use super::gates::Gate;
use super::wire::WireValue;

/// Binary circuit compiler.
pub struct Compiler {
    pub allocator: Allocator,
    pub outputs_assigned: bool,
    pub inputs: circuit::IO,
    pub outputs: circuit::IO,
    pub input_wires: Vec<usize>,
    pub output_wires: Vec<usize>,
    pub gates: Vec<Gate>,
    next_wire_id: circuit::Wire,
    // Sentinel wires
    inv_i0_wire: Option<usize>,
    zero_wire: Option<usize>,
    one_wire: Option<usize>,
}

impl Compiler {
    /// Create a new circuit compiler.
    pub fn new(
        allocator: Allocator,
        inputs: circuit::IO,
        outputs: circuit::IO,
        input_wires: Vec<usize>,
        output_wires: Vec<usize>,
    ) -> Result<Self, String> {
        if input_wires.is_empty() {
            return Err("no inputs defined".to_string());
        }
        Ok(Compiler {
            allocator,
            outputs_assigned: false,
            inputs,
            outputs,
            input_wires,
            output_wires,
            gates: Vec::with_capacity(65536),
            next_wire_id: 0,
            inv_i0_wire: None,
            zero_wire: None,
            one_wire: None,
        })
    }

    /// Wire holding INV(input[0]). Uses a real INV gate (no dependency on one_wire).
    pub fn inv_i0_wire(&mut self) -> usize {
        if let Some(w) = self.inv_i0_wire {
            return w;
        }
        let w = self.allocator.wire();
        let i0 = self.input_wires[0];
        // INV is implemented as XOR with... we can't use one_wire yet.
        // Go uses Calloc.INVGate which is Operation::INV (unary gate).
        let gate = Gate::new(Operation::Inv, i0, 0, w);
        self.gates.push(gate);
        self.inv_i0_wire = Some(w);
        w
    }

    /// Wire holding value 0: input[0] AND INV(input[0]) = 0.
    pub fn zero_wire(&mut self) -> usize {
        if let Some(w) = self.zero_wire {
            return w;
        }
        let w = self.allocator.wire();
        let i0 = self.input_wires[0];
        let inv = self.inv_i0_wire();
        let gate = Gate::new(Operation::And, i0, inv, w);
        self.gates.push(gate);
        self.allocator.get_wire_mut(w).set_value(WireValue::Zero);
        self.zero_wire = Some(w);
        w
    }

    /// Wire holding value 1: input[0] OR INV(input[0]) = 1.
    pub fn one_wire(&mut self) -> usize {
        if let Some(w) = self.one_wire {
            return w;
        }
        let w = self.allocator.wire();
        let i0 = self.input_wires[0];
        let inv = self.inv_i0_wire();
        let gate = Gate::new(Operation::Or, i0, inv, w);
        self.gates.push(gate);
        self.allocator.get_wire_mut(w).set_value(WireValue::One);
        self.one_wire = Some(w);
        w
    }

    /// Zero-pad two wire arrays to the same length.
    pub fn zero_pad(&mut self, x: &[usize], y: &[usize]) -> (Vec<usize>, Vec<usize>) {
        if x.len() == y.len() {
            return (x.to_vec(), y.to_vec());
        }
        let max = x.len().max(y.len());
        let zw = self.zero_wire();

        let mut rx = Vec::with_capacity(max);
        for i in 0..max {
            rx.push(if i < x.len() { x[i] } else { zw });
        }
        let mut ry = Vec::with_capacity(max);
        for i in 0..max {
            ry.push(if i < y.len() { y[i] } else { zw });
        }
        (rx, ry)
    }

    /// Shift left: size bits of w, shifted count bits left.
    pub fn shift_left(&mut self, w: &[usize], size: usize, count: usize) -> Vec<usize> {
        let zw = self.zero_wire();
        let mut result = vec![zw; size];
        if count < size {
            let copy_len = w.len().min(size - count);
            result[count..count + copy_len].copy_from_slice(&w[..copy_len]);
        }
        result
    }

    /// Create INV: o = NOT i (implemented as XOR with 1).
    pub fn inv(&mut self, i: usize, o: usize) {
        let one = self.one_wire();
        self.gates.push(Gate::new(Operation::Xor, i, one, o));
    }

    /// Create identity: o = i (implemented as XOR with 0).
    pub fn id(&mut self, i: usize, o: usize) {
        let zero = self.zero_wire();
        self.gates.push(Gate::new(Operation::Xor, i, zero, o));
    }

    pub fn add_gate(&mut self, gate: Gate) {
        self.gates.push(gate);
    }

    pub fn set_next_wire_id(&mut self, next: circuit::Wire) {
        self.next_wire_id = next;
    }

    pub fn next_wire_id(&mut self) -> circuit::Wire {
        let ret = self.next_wire_id;
        self.next_wire_id += 1;
        ret
    }

    /// Constant propagation optimization pass.
    pub fn const_propagate(&mut self) {
        for gi in 0..self.gates.len() {
            let av = self.allocator.get_wire(self.gates[gi].a).value();
            let bv = self.allocator.get_wire(self.gates[gi].b).value();

            match self.gates[gi].op {
                Operation::Xor => {
                    if (av == WireValue::Zero && bv == WireValue::Zero)
                        || (av == WireValue::One && bv == WireValue::One)
                    {
                        self.allocator
                            .get_wire_mut(self.gates[gi].o)
                            .set_value(WireValue::Zero);
                    } else if (av == WireValue::Zero && bv == WireValue::One)
                        || (av == WireValue::One && bv == WireValue::Zero)
                    {
                        self.allocator
                            .get_wire_mut(self.gates[gi].o)
                            .set_value(WireValue::One);
                    }
                }
                Operation::Xnor => {
                    if (av == WireValue::Zero && bv == WireValue::Zero)
                        || (av == WireValue::One && bv == WireValue::One)
                    {
                        self.allocator
                            .get_wire_mut(self.gates[gi].o)
                            .set_value(WireValue::One);
                    } else if (av == WireValue::Zero && bv == WireValue::One)
                        || (av == WireValue::One && bv == WireValue::Zero)
                    {
                        self.allocator
                            .get_wire_mut(self.gates[gi].o)
                            .set_value(WireValue::Zero);
                    }
                }
                Operation::And => {
                    if av == WireValue::Zero || bv == WireValue::Zero {
                        self.allocator
                            .get_wire_mut(self.gates[gi].o)
                            .set_value(WireValue::Zero);
                    } else if av == WireValue::One && bv == WireValue::One {
                        self.allocator
                            .get_wire_mut(self.gates[gi].o)
                            .set_value(WireValue::One);
                    }
                }
                Operation::Or => {
                    if av == WireValue::One || bv == WireValue::One {
                        self.allocator
                            .get_wire_mut(self.gates[gi].o)
                            .set_value(WireValue::One);
                    } else if av == WireValue::Zero && bv == WireValue::Zero {
                        self.allocator
                            .get_wire_mut(self.gates[gi].o)
                            .set_value(WireValue::Zero);
                    }
                }
                Operation::Inv => {
                    if av == WireValue::One {
                        self.allocator
                            .get_wire_mut(self.gates[gi].o)
                            .set_value(WireValue::Zero);
                    } else if av == WireValue::Zero {
                        self.allocator
                            .get_wire_mut(self.gates[gi].o)
                            .set_value(WireValue::One);
                    }
                }
            }
        }
    }

    /// Prune dead gates whose output is unused.
    pub fn prune(&mut self) -> usize {
        let mut live = Vec::new();
        let mut pruned = 0;

        for i in (0..self.gates.len()).rev() {
            let ow = self.gates[i].o;
            let wire = self.allocator.get_wire(ow);
            if self.gates[i].dead || wire.output() || wire.num_outputs() > 0 {
                live.push(i);
            } else {
                self.gates[i].dead = true;
                pruned += 1;
            }
        }
        live.reverse();

        let mut new_gates = Vec::with_capacity(live.len());
        for &idx in &live {
            // Move gates — safe because we process in order
            let g = std::mem::replace(
                &mut self.gates[idx],
                Gate::new(Operation::Xor, 0, 0, 0),
            );
            new_gates.push(g);
        }
        self.gates = new_gates;
        pruned
    }

    /// Compile the circuit into a `circuit::Circuit`.
    pub fn compile_circuit(&mut self) -> circuit::Circuit {
        // Assign wire IDs to input wires.
        let input_wires = self.input_wires.clone();
        for &w in &input_wires {
            if !self.allocator.get_wire(w).assigned() {
                let id = self.next_wire_id();
                self.allocator.get_wire_mut(w).set_id(id);
            }
        }

        // Assign wire IDs to all non-output wires referenced by gates.
        let output_wires_set: std::collections::HashSet<usize> =
            self.output_wires.iter().copied().collect();

        for gi in 0..self.gates.len() {
            if self.gates[gi].dead {
                continue;
            }
            let aw = self.gates[gi].a;
            if !output_wires_set.contains(&aw) && !self.allocator.get_wire(aw).assigned() {
                let id = self.next_wire_id();
                self.allocator.get_wire_mut(aw).set_id(id);
            }
            if self.gates[gi].op != Operation::Inv {
                let bw = self.gates[gi].b;
                if !output_wires_set.contains(&bw) && !self.allocator.get_wire(bw).assigned() {
                    let id = self.next_wire_id();
                    self.allocator.get_wire_mut(bw).set_id(id);
                }
            }
            let ow = self.gates[gi].o;
            if !output_wires_set.contains(&ow) && !self.allocator.get_wire(ow).assigned() {
                let id = self.next_wire_id();
                self.allocator.get_wire_mut(ow).set_id(id);
            }
        }

        // Assign output wire IDs LAST so they get the highest wire IDs.
        // compute() expects outputs at num_wires - output_size .. num_wires - 1.
        let output_wires = self.output_wires.clone();
        for &w in &output_wires {
            let id = self.next_wire_id();
            self.allocator.get_wire_mut(w).set_id(id);
        }

        // Compile gates.
        let mut compiled = Vec::with_capacity(self.gates.len());
        let mut stats = circuit::Stats::default();

        for gate in &self.gates {
            if gate.dead {
                continue;
            }
            let a_id = self.allocator.get_wire(gate.a).id();
            let b_id = self.allocator.get_wire(gate.b).id();
            let o_id = self.allocator.get_wire(gate.o).id();

            match gate.op {
                Operation::Inv => {
                    compiled.push(circuit::Gate {
                        input0: a_id,
                        input1: 0,
                        output: o_id,
                        op: gate.op,
                        level: 0,
                    });
                }
                _ => {
                    compiled.push(circuit::Gate {
                        input0: a_id,
                        input1: b_id,
                        output: o_id,
                        op: gate.op,
                        level: 0,
                    });
                }
            }
            stats.data[gate.op as usize] += 1;
        }

        // Topological sort: ensure each gate's inputs are produced before it.
        let num_wires = self.next_wire_id as usize;
        let input_wire_count: usize = self.inputs.iter().map(|a| a.type_info.bits as usize).sum();
        let mut produced = vec![false; num_wires];
        for i in 0..input_wire_count {
            produced[i] = true;
        }

        let mut sorted = Vec::with_capacity(compiled.len());
        let mut remaining = compiled;
        let mut progress = true;
        while !remaining.is_empty() && progress {
            progress = false;
            let mut next_remaining = Vec::new();
            for gate in remaining {
                let a_ready = produced[gate.input0 as usize];
                let b_ready = gate.op == Operation::Inv || produced[gate.input1 as usize];
                if a_ready && b_ready {
                    produced[gate.output as usize] = true;
                    sorted.push(gate);
                    progress = true;
                } else {
                    next_remaining.push(gate);
                }
            }
            remaining = next_remaining;
        }
        // Append any remaining gates (shouldn't happen in well-formed circuits).
        sorted.extend(remaining);

        circuit::Circuit {
            num_gates: sorted.len(),
            num_wires,
            inputs: self.inputs.clone(),
            outputs: self.outputs.clone(),
            gates: sorted,
            stats,
        }
    }
}

// =====================================================================
// Arithmetic circuits: adder, subtractor, MUX
// =====================================================================

/// Half adder: a + b = (sum, carry).
pub fn new_half_adder(cc: &mut Compiler, a: usize, b: usize, sum: usize, carry: usize) {
    cc.gates.push(Gate::new(Operation::Xor, a, b, sum));
    cc.gates.push(Gate::new(Operation::And, a, b, carry));
}

/// Full adder: a + b + cin = (sum, carry).
pub fn new_full_adder(
    cc: &mut Compiler,
    a: usize,
    b: usize,
    cin: usize,
    sum: usize,
    carry: usize,
) {
    let w1 = cc.allocator.wire();
    let w2 = cc.allocator.wire();
    let w3 = cc.allocator.wire();

    cc.gates.push(Gate::new(Operation::Xor, a, b, w1));
    cc.gates.push(Gate::new(Operation::Xor, w1, cin, sum));
    cc.gates.push(Gate::new(Operation::And, a, b, w2));
    cc.gates.push(Gate::new(Operation::And, w1, cin, w3));
    cc.gates.push(Gate::new(Operation::Xor, w2, w3, carry));
}

/// Ripple-carry adder: x + y = result. `result` must have len = max(x,y)+1 for carry.
pub fn new_adder(
    cc: &mut Compiler,
    x: &[usize],
    y: &[usize],
    result: &mut [usize],
) -> Result<(), String> {
    let (x, y) = cc.zero_pad(x, y);
    let n = x.len();

    if result.len() < n {
        return Err("result too small for adder".to_string());
    }

    let mut carry = cc.zero_wire();
    for i in 0..n {
        let new_carry = cc.allocator.wire();
        if result[i] == usize::MAX {
            result[i] = cc.allocator.wire();
        }
        new_full_adder(cc, x[i], y[i], carry, result[i], new_carry);
        carry = new_carry;
    }
    // Set carry bit if result is big enough.
    if result.len() > n {
        if result[n] == usize::MAX {
            result[n] = cc.allocator.wire();
        }
        cc.id(carry, result[n]);
    }
    // Zero remaining.
    let zw = cc.zero_wire();
    for i in (n + 1)..result.len() {
        result[i] = zw;
    }
    Ok(())
}

/// Subtractor: x - y = result. result may have one extra bit for borrow.
pub fn new_subtractor(
    cc: &mut Compiler,
    x: &[usize],
    y: &[usize],
    result: &mut [usize],
) -> Result<(), String> {
    let (x, y) = cc.zero_pad(x, y);
    let n = x.len();

    // Two's complement: x + (~y) + 1
    let mut not_y = Vec::with_capacity(n);
    for i in 0..n {
        let w = cc.allocator.wire();
        cc.inv(y[i], w);
        not_y.push(w);
    }

    let mut carry = cc.one_wire();
    for i in 0..n {
        let new_carry = cc.allocator.wire();
        if i < result.len() {
            if result[i] == usize::MAX {
                result[i] = cc.allocator.wire();
            }
            new_full_adder(cc, x[i], not_y[i], carry, result[i], new_carry);
        } else {
            let tmp = cc.allocator.wire();
            new_full_adder(cc, x[i], not_y[i], carry, tmp, new_carry);
        }
        carry = new_carry;
    }
    // Overflow/borrow bit.
    if result.len() > n {
        // The carry out indicates no borrow (carry=1 means positive result).
        // Invert it for the sign/borrow bit.
        if result[n] == usize::MAX {
            result[n] = cc.allocator.wire();
        }
        cc.inv(carry, result[n]);
    }
    let zw = cc.zero_wire();
    for i in (n + 1)..result.len() {
        result[i] = zw;
    }
    Ok(())
}

/// 2:1 MUX: if sel[0]==0 then a else b → result.
pub fn new_mux(
    cc: &mut Compiler,
    sel: &[usize],
    a: &[usize],
    b: &[usize],
    result: &mut [usize],
) -> Result<(), String> {
    if sel.is_empty() {
        return Err("empty selector for MUX".to_string());
    }
    let s = sel[0];
    for i in 0..result.len() {
        let ai = if i < a.len() { a[i] } else { cc.zero_wire() };
        let bi = if i < b.len() { b[i] } else { cc.zero_wire() };

        // MUX: (a XOR b) AND sel XOR a
        let t1 = cc.allocator.wire();
        cc.gates.push(Gate::new(Operation::Xor, ai, bi, t1));
        let t2 = cc.allocator.wire();
        cc.gates.push(Gate::new(Operation::And, t1, s, t2));

        if result[i] == usize::MAX {
            result[i] = cc.allocator.wire();
        }
        cc.gates.push(Gate::new(Operation::Xor, ai, t2, result[i]));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{IOArg, IOExt};
    use crate::types::Type;
    use num_bigint::BigInt;

    fn make_adder_circuit(bits: i32) -> circuit::Circuit {
        let mut alloc = Allocator::new();
        let iw_a = alloc.wires(bits);
        let iw_b = alloc.wires(bits);

        let inputs = vec![
            IOArg::new("a", Type::Uint, bits),
            IOArg::new("b", Type::Uint, bits),
        ];
        let outputs = vec![IOArg::new("sum", Type::Uint, bits)];

        let mut input_wires = iw_a.clone();
        input_wires.extend(&iw_b);

        // Pre-allocate output wires.
        let ow = alloc.wires(bits);
        for &w in &ow {
            alloc.get_wire_mut(w).set_output(true);
        }

        let mut cc = Compiler::new(alloc, inputs, outputs, input_wires, ow.clone()).unwrap();

        // Create adder result with extra carry bit (not in outputs).
        let mut result: Vec<usize> = ow;
        result.push(usize::MAX); // will be allocated by adder for carry
        new_adder(&mut cc, &iw_a, &iw_b, &mut result).unwrap();
        cc.compile_circuit()
    }

    #[test]
    fn adder_8bit() {
        let c = make_adder_circuit(8);
        // 100 + 200 = 300, but 300 doesn't fit in 8 bits (overflow).
        // Use values that fit: 50 + 100 = 150.
        let r = c.compute(&[BigInt::from(50u32), BigInt::from(100u32)]).unwrap();
        assert_eq!(r[0], BigInt::from(150u32));
    }

    #[test]
    fn adder_small() {
        let c = make_adder_circuit(8);
        let r = c.compute(&[BigInt::from(1u32), BigInt::from(2u32)]).unwrap();
        assert_eq!(r[0], BigInt::from(3u32));
    }

    fn make_sub_circuit(bits: i32) -> circuit::Circuit {
        let mut alloc = Allocator::new();
        let iw_a = alloc.wires(bits);
        let iw_b = alloc.wires(bits);

        let inputs = vec![
            IOArg::new("a", Type::Uint, bits),
            IOArg::new("b", Type::Uint, bits),
        ];
        let outputs = vec![IOArg::new("diff", Type::Uint, bits)];

        let mut input_wires = iw_a.clone();
        input_wires.extend(&iw_b);

        let ow = alloc.wires(bits);
        for &w in &ow {
            alloc.get_wire_mut(w).set_output(true);
        }

        let mut cc = Compiler::new(alloc, inputs, outputs, input_wires, ow.clone()).unwrap();
        let mut result: Vec<usize> = ow;
        result.push(usize::MAX); // borrow bit
        new_subtractor(&mut cc, &iw_a, &iw_b, &mut result).unwrap();
        cc.compile_circuit()
    }

    #[test]
    fn subtractor_basic() {
        let c = make_sub_circuit(8);
        let r = c.compute(&[BigInt::from(200u32), BigInt::from(100u32)]).unwrap();
        assert_eq!(r[0], BigInt::from(100u32));
    }
}
