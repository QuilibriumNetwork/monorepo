//! Boolean circuit data structures, serialization, and evaluation.
//! Port of `bedlam/circuit/`.

use std::fmt;
use std::io::{self, Read, Write};

use num_bigint::BigInt;
use num_traits::{One, Zero};

use crate::types::{self, Info, Size, Type};

/// Gate operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Operation {
    Xor = 0,
    Xnor = 1,
    And = 2,
    Or = 3,
    Inv = 4,
}

/// Stats array indices beyond the 5 gate ops.
const COUNT_IDX: usize = 5;
const NUM_LEVELS_IDX: usize = 6;
const MAX_WIDTH_IDX: usize = 7;
const STATS_LEN: usize = 8;

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operation::Xor => write!(f, "XOR"),
            Operation::Xnor => write!(f, "XNOR"),
            Operation::And => write!(f, "AND"),
            Operation::Or => write!(f, "OR"),
            Operation::Inv => write!(f, "INV"),
        }
    }
}

impl Operation {
    pub fn from_byte(b: u8) -> Option<Operation> {
        match b {
            0 => Some(Operation::Xor),
            1 => Some(Operation::Xnor),
            2 => Some(Operation::And),
            3 => Some(Operation::Or),
            4 => Some(Operation::Inv),
            _ => None,
        }
    }

    /// Whether this is a binary (2-input) gate.
    pub fn is_binary(&self) -> bool {
        !matches!(self, Operation::Inv)
    }
}

/// Known multi-party computation roles.
pub const ID_GARBLER: usize = 0;
pub const ID_EVALUATOR: usize = 1;

/// Wire identifier.
pub type Wire = u32;

/// Invalid wire sentinel.
pub const INVALID_WIRE: Wire = u32::MAX;

/// Level: gate's distance from input wires.
pub type Level = u32;

/// Circuit statistics.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub data: [u64; STATS_LEN],
}

impl Stats {
    pub fn add(&mut self, o: &Stats) {
        for i in 0..COUNT_IDX {
            self.data[i] += o.data[i];
        }
        self.data[COUNT_IDX] += 1;
        for i in NUM_LEVELS_IDX..=MAX_WIDTH_IDX {
            if o.data[i] > self.data[i] {
                self.data[i] = o.data[i];
            }
        }
    }

    pub fn count(&self) -> u64 {
        self.data[..COUNT_IDX].iter().sum()
    }

    pub fn cost(&self) -> u64 {
        (self.data[Operation::And as usize] + self.data[Operation::Inv as usize]) * 2
            + self.data[Operation::Or as usize] * 3
    }
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "XOR={} XNOR={} AND={} OR={} INV={} xor={} !xor={} levels={} width={}",
            self.data[Operation::Xor as usize],
            self.data[Operation::Xnor as usize],
            self.data[Operation::And as usize],
            self.data[Operation::Or as usize],
            self.data[Operation::Inv as usize],
            self.data[Operation::Xor as usize] + self.data[Operation::Xnor as usize],
            self.data[Operation::And as usize]
                + self.data[Operation::Or as usize]
                + self.data[Operation::Inv as usize],
            self.data[NUM_LEVELS_IDX],
            self.data[MAX_WIDTH_IDX],
        )
    }
}

/// A boolean gate.
#[derive(Debug, Clone)]
pub struct Gate {
    pub input0: Wire,
    pub input1: Wire,
    pub output: Wire,
    pub op: Operation,
    pub level: Level,
}

impl Gate {
    pub fn inputs(&self) -> Vec<Wire> {
        if self.op == Operation::Inv {
            vec![self.input0]
        } else {
            vec![self.input0, self.input1]
        }
    }
}

impl fmt::Display for Gate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} {} w{}", self.inputs(), self.op, self.output)
    }
}

/// I/O argument for circuit inputs/outputs.
#[derive(Debug, Clone)]
pub struct IOArg {
    pub name: String,
    pub type_info: Info,
    pub compound: Vec<IOArg>,
}

impl IOArg {
    pub fn new(name: &str, typ: Type, bits: Size) -> Self {
        IOArg {
            name: name.to_string(),
            type_info: Info {
                typ,
                is_concrete: true,
                bits,
                ..Default::default()
            },
            compound: Vec::new(),
        }
    }

    /// Parse input values into a BigInt.
    pub fn parse_input(&self, inputs: &[&str]) -> Result<BigInt, String> {
        if self.compound.is_empty() {
            if inputs.len() != 1 {
                return Err(format!(
                    "invalid amount of arguments, got {}, expected 1",
                    inputs.len()
                ));
            }
            let input = inputs[0];
            match self.type_info.typ {
                Type::Int | Type::Uint => {
                    parse_bigint(input).ok_or_else(|| format!("invalid input '{}'", input))
                }
                Type::Bool => match input {
                    "0" | "f" | "false" => Ok(BigInt::zero()),
                    "1" | "t" | "true" => Ok(BigInt::one()),
                    _ => Err(format!("invalid bool constant: {}", input)),
                },
                _ => Err(format!("unsupported input type: {}", self.type_info)),
            }
        } else {
            if inputs.len() != self.compound.len() {
                return Err(format!(
                    "invalid amount of arguments, got {}, expected {}",
                    inputs.len(),
                    self.compound.len()
                ));
            }
            let mut result = BigInt::zero();
            let mut offset = 0u32;
            for (idx, arg) in self.compound.iter().enumerate() {
                let val = arg.parse_input(&[inputs[idx]])?;
                result |= val << offset;
                offset += arg.type_info.bits as u32;
            }
            Ok(result)
        }
    }
}

impl fmt::Display for IOArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.compound.is_empty() {
            let parts: Vec<String> = self.compound.iter().map(|c| c.to_string()).collect();
            write!(f, "{}", parts.join(", "))
        } else if !self.name.is_empty() {
            write!(f, "{}:{}", self.name, self.type_info)
        } else {
            write!(f, "{}", self.type_info)
        }
    }
}

/// Circuit I/O argument list.
pub type IO = Vec<IOArg>;

/// Extension trait for IO.
pub trait IOExt {
    fn size(&self) -> i32;
    fn split(&self, input: &BigInt) -> Vec<BigInt>;
}

impl IOExt for IO {
    fn size(&self) -> i32 {
        self.iter().map(|a| a.type_info.bits).sum()
    }

    fn split(&self, input: &BigInt) -> Vec<BigInt> {
        let mut result = Vec::new();
        let mut bit = 0u32;
        for arg in self.iter() {
            let mut r = BigInt::zero();
            for i in 0..arg.type_info.bits as u32 {
                if input.bit(bit as u64) {
                    r |= BigInt::one() << i;
                }
                bit += 1;
            }
            result.push(r);
        }
        result
    }
}

/// Boolean circuit.
#[derive(Debug, Clone)]
pub struct Circuit {
    pub num_gates: usize,
    pub num_wires: usize,
    pub inputs: IO,
    pub outputs: IO,
    pub gates: Vec<Gate>,
    pub stats: Stats,
}

impl fmt::Display for Circuit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "#gates={} ({}) #w={}",
            self.num_gates, self.stats, self.num_wires
        )
    }
}

impl Circuit {
    pub fn num_parties(&self) -> usize {
        self.inputs.len()
    }

    pub fn cost(&self) -> u64 {
        self.stats.cost()
    }

    /// Assign levels to gates (distance from input wires).
    pub fn assign_levels(&mut self) {
        let mut levels = vec![0u32; self.num_wires];
        let mut count_by_level = vec![0u32; self.num_wires];
        let mut max_level: u32 = 0;

        for gate in self.gates.iter_mut() {
            let mut level = levels[gate.input0 as usize];
            if gate.op != Operation::Inv {
                let l1 = levels[gate.input1 as usize];
                if l1 > level {
                    level = l1;
                }
            }
            gate.level = level;
            if (level as usize) < count_by_level.len() {
                count_by_level[level as usize] += 1;
            }
            level += 1;
            levels[gate.output as usize] = level;
            if level > max_level {
                max_level = level;
            }
        }
        self.stats.data[NUM_LEVELS_IDX] = max_level as u64;
        let max_width = count_by_level.iter().copied().max().unwrap_or(0);
        self.stats.data[MAX_WIDTH_IDX] = max_width as u64;
    }

    /// Evaluate the circuit with the given input values.
    pub fn compute(&self, inputs: &[BigInt]) -> Result<Vec<BigInt>, String> {
        // Flatten circuit arguments.
        let mut args = Vec::new();
        for io in &self.inputs {
            if !io.compound.is_empty() {
                args.extend(io.compound.iter().cloned());
            } else {
                args.push(io.clone());
            }
        }
        if inputs.len() != args.len() {
            return Err(format!(
                "invalid inputs: got {}, expected {}",
                inputs.len(),
                args.len()
            ));
        }

        let mut wires = vec![0u8; self.num_wires];
        let mut w = 0usize;
        for (idx, io) in args.iter().enumerate() {
            for bit in 0..io.type_info.bits {
                if inputs[idx].bit(bit as u64) {
                    wires[w] = 1;
                }
                w += 1;
            }
        }

        // Evaluate gates.
        for gate in &self.gates {
            let result = match gate.op {
                Operation::Xor => wires[gate.input0 as usize] ^ wires[gate.input1 as usize],
                Operation::Xnor => {
                    if wires[gate.input0 as usize] ^ wires[gate.input1 as usize] == 0 {
                        1
                    } else {
                        0
                    }
                }
                Operation::And => wires[gate.input0 as usize] & wires[gate.input1 as usize],
                Operation::Or => wires[gate.input0 as usize] | wires[gate.input1 as usize],
                Operation::Inv => {
                    if wires[gate.input0 as usize] == 0 {
                        1
                    } else {
                        0
                    }
                }
            };
            wires[gate.output as usize] = result;
        }

        // Construct outputs.
        let out_size: i32 = self.outputs.size();
        w = self.num_wires - out_size as usize;
        let mut result = Vec::new();
        for io in &self.outputs {
            let mut r = BigInt::zero();
            for bit in 0..io.type_info.bits {
                if wires[w] != 0 {
                    r |= BigInt::one() << bit as u32;
                }
                w += 1;
            }
            result.push(r);
        }
        Ok(result)
    }
}

// =====================================================================
// Serialization — QCL circuit format (magic 0x63726300)
// =====================================================================

const MAGIC: u32 = 0x63726300;

impl Circuit {
    /// Marshal the circuit in QCL binary format.
    pub fn marshal<W: Write>(&self, out: &mut W) -> io::Result<()> {
        out.write_all(&MAGIC.to_be_bytes())?;
        out.write_all(&(self.num_gates as u32).to_be_bytes())?;
        out.write_all(&(self.num_wires as u32).to_be_bytes())?;
        out.write_all(&(self.inputs.len() as u32).to_be_bytes())?;
        out.write_all(&(self.outputs.len() as u32).to_be_bytes())?;

        for input in &self.inputs {
            marshal_io_arg(out, input)?;
        }
        for output in &self.outputs {
            marshal_io_arg(out, output)?;
        }

        for g in &self.gates {
            out.write_all(&[g.op as u8])?;
            match g.op {
                Operation::Xor | Operation::Xnor | Operation::And | Operation::Or => {
                    out.write_all(&g.input0.to_be_bytes())?;
                    out.write_all(&g.input1.to_be_bytes())?;
                    out.write_all(&g.output.to_be_bytes())?;
                }
                Operation::Inv => {
                    out.write_all(&g.input0.to_be_bytes())?;
                    out.write_all(&g.output.to_be_bytes())?;
                }
            }
        }
        Ok(())
    }

    /// Parse a QCL binary circuit.
    pub fn parse_qclc<R: Read>(r: &mut R) -> io::Result<Circuit> {
        let magic = read_u32(r)?;
        if magic != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid magic: 0x{:08x}", magic),
            ));
        }
        let num_gates = read_u32(r)? as usize;
        let num_wires = read_u32(r)? as usize;
        let num_inputs = read_u32(r)? as usize;
        let num_outputs = read_u32(r)? as usize;

        let mut wires_seen = vec![false; num_wires];

        let mut inputs = Vec::with_capacity(num_inputs);
        let mut input_wires = 0usize;
        for _ in 0..num_inputs {
            let arg = parse_io_arg(r)?;
            input_wires += arg.type_info.bits as usize;
            inputs.push(arg);
        }
        let mut outputs = Vec::with_capacity(num_outputs);
        for _ in 0..num_outputs {
            outputs.push(parse_io_arg(r)?);
        }

        for i in 0..input_wires {
            if i < wires_seen.len() {
                wires_seen[i] = true;
            }
        }

        let mut gates = Vec::with_capacity(num_gates);
        let mut stats = Stats::default();
        let mut gate_count = 0;

        loop {
            let mut op_buf = [0u8; 1];
            match r.read_exact(&mut op_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
            let op = Operation::from_byte(op_buf[0]).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported gate type {}", op_buf[0]),
                )
            })?;

            let gate = if op.is_binary() {
                let i0 = read_u32(r)?;
                let i1 = read_u32(r)?;
                let o = read_u32(r)?;
                check_wire_seen(&wires_seen, i0, gate_count)?;
                check_wire_seen(&wires_seen, i1, gate_count)?;
                set_wire_seen(&mut wires_seen, o)?;
                Gate {
                    input0: i0,
                    input1: i1,
                    output: o,
                    op,
                    level: 0,
                }
            } else {
                let i0 = read_u32(r)?;
                let o = read_u32(r)?;
                check_wire_seen(&wires_seen, i0, gate_count)?;
                set_wire_seen(&mut wires_seen, o)?;
                Gate {
                    input0: i0,
                    input1: 0,
                    output: o,
                    op,
                    level: 0,
                }
            };

            stats.data[op as usize] += 1;
            gates.push(gate);
            gate_count += 1;
        }

        if gate_count != num_gates {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "not enough gates: got {}, expected {}",
                    gate_count, num_gates
                ),
            ));
        }

        for (i, seen) in wires_seen.iter().enumerate() {
            if !*seen {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("wire {} not assigned", i),
                ));
            }
        }

        Ok(Circuit {
            num_gates,
            num_wires,
            inputs,
            outputs,
            gates,
            stats,
        })
    }
}

fn marshal_io_arg<W: Write>(out: &mut W, arg: &IOArg) -> io::Result<()> {
    marshal_string(out, &arg.name)?;
    marshal_string(out, &arg.type_info.to_string())?;
    out.write_all(&(arg.type_info.bits as u32).to_be_bytes())?;
    out.write_all(&(arg.compound.len() as u32).to_be_bytes())?;
    for c in &arg.compound {
        marshal_io_arg(out, c)?;
    }
    Ok(())
}

fn marshal_string<W: Write>(out: &mut W, s: &str) -> io::Result<()> {
    let bytes = s.as_bytes();
    out.write_all(&(bytes.len() as u32).to_be_bytes())?;
    out.write_all(bytes)?;
    Ok(())
}

fn parse_io_arg<R: Read>(r: &mut R) -> io::Result<IOArg> {
    let name = parse_string(r)?;
    let type_str = parse_string(r)?;
    let bits = read_u32(r)? as Size;
    let num_compound = read_u32(r)? as usize;

    let mut type_info = types::parse_type(&type_str).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("type parse: {}", e))
    })?;
    type_info.bits = bits;

    let mut compound = Vec::with_capacity(num_compound);
    for _ in 0..num_compound {
        compound.push(parse_io_arg(r)?);
    }

    Ok(IOArg {
        name,
        type_info,
        compound,
    })
}

fn parse_string<R: Read>(r: &mut R) -> io::Result<String> {
    let len = read_u32(r)? as usize;
    if len == 0 {
        return Ok(String::new());
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    String::from_utf8(buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid UTF-8: {}", e)))
}

fn read_u32<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

fn check_wire_seen(seen: &[bool], wire: u32, gate: usize) -> io::Result<()> {
    if (wire as usize) >= seen.len() || !seen[wire as usize] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("input {} of gate {} not set", wire, gate),
        ));
    }
    Ok(())
}

fn set_wire_seen(seen: &mut [bool], wire: u32) -> io::Result<()> {
    if (wire as usize) >= seen.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid wire {}", wire),
        ));
    }
    seen[wire as usize] = true;
    Ok(())
}

/// Parse a BigInt from string (supports 0x, 0b, 0o prefixes).
fn parse_bigint(s: &str) -> Option<BigInt> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        BigInt::parse_bytes(hex.as_bytes(), 16)
    } else if let Some(bin) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
        BigInt::parse_bytes(bin.as_bytes(), 2)
    } else if let Some(oct) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
        BigInt::parse_bytes(oct.as_bytes(), 8)
    } else {
        BigInt::parse_bytes(s.as_bytes(), 10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_and_circuit() -> Circuit {
        // 2-input AND: w0 AND w1 -> w2
        Circuit {
            num_gates: 1,
            num_wires: 3,
            inputs: vec![
                IOArg::new("a", Type::Bool, 1),
                IOArg::new("b", Type::Bool, 1),
            ],
            outputs: vec![IOArg::new("c", Type::Bool, 1)],
            gates: vec![Gate {
                input0: 0,
                input1: 1,
                output: 2,
                op: Operation::And,
                level: 0,
            }],
            stats: Stats::default(),
        }
    }

    #[test]
    fn compute_and_gate() {
        let c = simple_and_circuit();
        let r = c.compute(&[BigInt::from(1), BigInt::from(1)]).unwrap();
        assert_eq!(r[0], BigInt::from(1));

        let r = c.compute(&[BigInt::from(1), BigInt::from(0)]).unwrap();
        assert_eq!(r[0], BigInt::from(0));

        let r = c.compute(&[BigInt::from(0), BigInt::from(0)]).unwrap();
        assert_eq!(r[0], BigInt::from(0));
    }

    #[test]
    fn compute_xor_gate() {
        let c = Circuit {
            num_gates: 1,
            num_wires: 3,
            inputs: vec![
                IOArg::new("a", Type::Bool, 1),
                IOArg::new("b", Type::Bool, 1),
            ],
            outputs: vec![IOArg::new("c", Type::Bool, 1)],
            gates: vec![Gate {
                input0: 0,
                input1: 1,
                output: 2,
                op: Operation::Xor,
                level: 0,
            }],
            stats: Stats::default(),
        };
        assert_eq!(
            c.compute(&[BigInt::from(1), BigInt::from(0)]).unwrap()[0],
            BigInt::from(1)
        );
        assert_eq!(
            c.compute(&[BigInt::from(1), BigInt::from(1)]).unwrap()[0],
            BigInt::from(0)
        );
    }

    #[test]
    fn marshal_roundtrip() {
        let c = simple_and_circuit();
        let mut buf = Vec::new();
        c.marshal(&mut buf).unwrap();

        let parsed = Circuit::parse_qclc(&mut &buf[..]).unwrap();
        assert_eq!(parsed.num_gates, 1);
        assert_eq!(parsed.num_wires, 3);
        assert_eq!(parsed.gates[0].op, Operation::And);
        assert_eq!(parsed.inputs.len(), 2);
        assert_eq!(parsed.outputs.len(), 1);
    }

    #[test]
    fn assign_levels_basic() {
        let mut c = Circuit {
            num_gates: 2,
            num_wires: 4,
            inputs: vec![
                IOArg::new("a", Type::Bool, 1),
                IOArg::new("b", Type::Bool, 1),
            ],
            outputs: vec![IOArg::new("c", Type::Bool, 1)],
            gates: vec![
                Gate {
                    input0: 0,
                    input1: 1,
                    output: 2,
                    op: Operation::And,
                    level: 0,
                },
                Gate {
                    input0: 2,
                    input1: 0,
                    output: 3,
                    op: Operation::Xor,
                    level: 0,
                },
            ],
            stats: Stats::default(),
        };
        c.assign_levels();
        assert_eq!(c.gates[0].level, 0);
        assert_eq!(c.gates[1].level, 1);
    }
}
