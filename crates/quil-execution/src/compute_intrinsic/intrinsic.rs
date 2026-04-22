//! Compute intrinsic operations: CodeDeployment, CodeExecute,
//! CodeFinalize verify + materialize.

use num_bigint::BigInt;
use quil_types::error::{QuilError, Result};
use quil_types::execution::CircuitCompiler;

/// Upper bound on compiled circuit size accepted for deployment.
/// Matches Go's `MaxCircuitSize` in `node/compiler/circuit` (currently
/// 16 MiB — circuits this large indicate corruption or a
/// misconfigured compile step, since sane QCL programs are sub-MB).
pub const MAX_CIRCUIT_SIZE: usize = 16 * 1024 * 1024;
/// Minimum plausible circuit size: the QCLC format carries at least
/// a 4-byte magic + 4-byte version + 4-byte section count. Anything
/// smaller is a protocol-level bug.
pub const MIN_CIRCUIT_SIZE: usize = 12;

/// A baseline [`CircuitCompiler`] implementation that enforces
/// structural invariants on circuit bytes without running the full
/// QCLC parser. Rejects empty, trivially-small, or oversized circuits.
///
/// Accepts any byte blob within the size bounds — so this is NOT a
/// substitute for the full semantic validation Go's
/// `bedlam_compiler.ValidateCircuit` performs (which runs
/// `circuit.ParseQCLC`). Suitable for archive-mode nodes that only
/// need to gate DoS-level abuse; nodes that actually execute QCL
/// programs need the full parser.
#[derive(Debug, Default, Clone, Copy)]
pub struct StructuralCircuitValidator;

impl CircuitCompiler for StructuralCircuitValidator {
    fn compile(&self, _source: &str, _input_sizes: &[Vec<i32>]) -> Result<Vec<u8>> {
        Err(QuilError::InvalidArgument(
            "StructuralCircuitValidator does not implement compile — use the bedlam compiler".into(),
        ))
    }

    fn validate_circuit(&self, circuit: &[u8]) -> Result<()> {
        if circuit.len() < MIN_CIRCUIT_SIZE {
            return Err(QuilError::InvalidArgument(format!(
                "circuit too short: {} bytes (min {})",
                circuit.len(),
                MIN_CIRCUIT_SIZE
            )));
        }
        if circuit.len() > MAX_CIRCUIT_SIZE {
            return Err(QuilError::InvalidArgument(format!(
                "circuit too large: {} bytes (max {})",
                circuit.len(),
                MAX_CIRCUIT_SIZE
            )));
        }
        Ok(())
    }
}

// =====================================================================
// QCLC semantic validator
// =====================================================================
//
// Port of `bedlam/circuit/parser.go::ParseQCLC`. The Go side uses
// ParseQCLC's success as `ValidateCircuit`'s accept signal — so here
// we walk the same wire format and confirm gates reference
// previously-defined wires, the gate count matches the header, and
// every wire is assigned.
//
// Unlike the Go reference we do NOT reconstruct the full `Circuit`
// struct — validation is what matters; parse tables aren't retained.

/// QCLC gate operations. Values match Go's `Operation` enum at
/// `bedlam/circuit/circuit.go`.
const QCLC_OP_XOR: u8 = 0;
const QCLC_OP_XNOR: u8 = 1;
const QCLC_OP_AND: u8 = 2;
const QCLC_OP_OR: u8 = 3;
const QCLC_OP_INV: u8 = 4;

/// [`CircuitCompiler`] implementation that runs the full QCLC
/// semantic validation. Accepts anything Go's `ParseQCLC` would
/// accept. Does not implement `compile` — that still requires the
/// full Bedlam compiler (source → QCLC bytes).
///
/// Structural size bounds from [`StructuralCircuitValidator`] still
/// apply; this validator runs them first and only proceeds with the
/// wire walk if the size is in range.
#[derive(Debug, Default, Clone, Copy)]
pub struct QclcCircuitValidator;

impl QclcCircuitValidator {
    fn validate_bytes(&self, circuit: &[u8]) -> Result<()> {
        StructuralCircuitValidator.validate_circuit(circuit)?;

        let mut r = QclcReader::new(circuit);

        // Header (5 × u32, big-endian, matching Go's binary.BigEndian `bo`).
        let _magic = r.read_u32()?;
        let num_gates = r.read_u32()?;
        let num_wires = r.read_u32()?;
        let num_inputs = r.read_u32()?;
        let num_outputs = r.read_u32()?;

        // Sanity caps. Rejects absurd values that would cause OOM
        // before we even start walking gates. Go doesn't cap these;
        // we do because untrusted input reaches this path via a
        // public RPC.
        const MAX_WIRES: u32 = 16 * 1024 * 1024;
        const MAX_GATES: u32 = 32 * 1024 * 1024;
        const MAX_IO: u32 = 1024;
        if num_wires > MAX_WIRES {
            return Err(QuilError::InvalidArgument(format!(
                "qclc: num_wires {} exceeds cap", num_wires
            )));
        }
        if num_gates > MAX_GATES {
            return Err(QuilError::InvalidArgument(format!(
                "qclc: num_gates {} exceeds cap", num_gates
            )));
        }
        if num_inputs > MAX_IO || num_outputs > MAX_IO {
            return Err(QuilError::InvalidArgument(
                "qclc: io argument count exceeds cap".into(),
            ));
        }

        // Parse IO args and accumulate total input wire width.
        let mut input_wires: u64 = 0;
        for _ in 0..num_inputs {
            input_wires = input_wires.saturating_add(r.parse_ioarg_bits()?);
        }
        let mut output_wires_total: u64 = 0;
        for _ in 0..num_outputs {
            output_wires_total = output_wires_total.saturating_add(r.parse_ioarg_bits()?);
        }
        let _ = output_wires_total; // Go records but doesn't use beyond parse.

        if input_wires > num_wires as u64 {
            return Err(QuilError::InvalidArgument(
                "qclc: input wires exceed num_wires".into(),
            ));
        }

        // Wires seen bitmap: 1 bit per wire. Input wires start seen.
        let mut seen = WireSeen::new(num_wires as usize);
        for i in 0..input_wires as usize {
            seen.set(i).map_err(|e| QuilError::InvalidArgument(e))?;
        }

        // Walk gates until EOF or until num_gates are consumed.
        let mut gate_index: u32 = 0;
        loop {
            let op = match r.read_u8_opt() {
                Some(v) => v,
                None => break, // Clean EOF at gate boundary.
            };
            match op {
                QCLC_OP_XOR | QCLC_OP_XNOR | QCLC_OP_AND | QCLC_OP_OR => {
                    let i0 = r.read_u32()?;
                    let i1 = r.read_u32()?;
                    let out = r.read_u32()?;
                    if i0 >= num_wires || i1 >= num_wires || out >= num_wires {
                        return Err(QuilError::InvalidArgument(format!(
                            "qclc: gate {} wire out of range", gate_index
                        )));
                    }
                    if !seen.get(i0 as usize) {
                        return Err(QuilError::InvalidArgument(format!(
                            "qclc: input {} of gate {} not set", i0, gate_index
                        )));
                    }
                    if !seen.get(i1 as usize) {
                        return Err(QuilError::InvalidArgument(format!(
                            "qclc: input {} of gate {} not set", i1, gate_index
                        )));
                    }
                    seen.set(out as usize).map_err(|e| QuilError::InvalidArgument(e))?;
                }
                QCLC_OP_INV => {
                    let i0 = r.read_u32()?;
                    let out = r.read_u32()?;
                    if i0 >= num_wires || out >= num_wires {
                        return Err(QuilError::InvalidArgument(format!(
                            "qclc: INV gate {} wire out of range", gate_index
                        )));
                    }
                    if !seen.get(i0 as usize) {
                        return Err(QuilError::InvalidArgument(format!(
                            "qclc: INV input {} of gate {} not set", i0, gate_index
                        )));
                    }
                    seen.set(out as usize).map_err(|e| QuilError::InvalidArgument(e))?;
                }
                other => {
                    return Err(QuilError::InvalidArgument(format!(
                        "qclc: unknown gate op {} at gate {}", other, gate_index
                    )));
                }
            }
            gate_index = gate_index.saturating_add(1);
            if gate_index > num_gates {
                return Err(QuilError::InvalidArgument(format!(
                    "qclc: more gates than header claims ({})", num_gates
                )));
            }
        }

        if gate_index != num_gates {
            return Err(QuilError::InvalidArgument(format!(
                "qclc: got {} gates, header claims {}", gate_index, num_gates
            )));
        }

        // Every wire assigned.
        for i in 0..num_wires as usize {
            if !seen.get(i) {
                return Err(QuilError::InvalidArgument(format!(
                    "qclc: wire {} not assigned", i
                )));
            }
        }

        Ok(())
    }
}

impl CircuitCompiler for QclcCircuitValidator {
    fn compile(&self, _source: &str, _input_sizes: &[Vec<i32>]) -> Result<Vec<u8>> {
        Err(QuilError::InvalidArgument(
            "QclcCircuitValidator does not implement compile — source compilation requires the full Bedlam compiler".into(),
        ))
    }

    fn validate_circuit(&self, circuit: &[u8]) -> Result<()> {
        self.validate_bytes(circuit)
    }
}

struct QclcReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> QclcReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn ensure(&self, n: usize) -> Result<()> {
        if self.pos + n > self.buf.len() {
            Err(QuilError::InvalidArgument(format!(
                "qclc: short read at {} (need {}, have {})",
                self.pos,
                n,
                self.buf.len() - self.pos
            )))
        } else {
            Ok(())
        }
    }

    fn read_u8_opt(&mut self) -> Option<u8> {
        if self.pos < self.buf.len() {
            let v = self.buf[self.pos];
            self.pos += 1;
            Some(v)
        } else {
            None
        }
    }

    fn read_u32(&mut self) -> Result<u32> {
        self.ensure(4)?;
        let v = u32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn read_string(&mut self) -> Result<()> {
        let len = self.read_u32()? as usize;
        // Cap string length so malicious headers can't stall the walk.
        if len > 4096 {
            return Err(QuilError::InvalidArgument(format!(
                "qclc: string length {} exceeds cap", len
            )));
        }
        self.ensure(len)?;
        self.pos += len;
        Ok(())
    }

    /// Parse an IOArg, returning the total bit-width contributed.
    /// Structure (matching `parser.go::parseIOArg`):
    /// `name: string, type: string, bits: u32, compound_count: u32,
    /// compound_args: [IOArg; compound_count]`.
    fn parse_ioarg_bits(&mut self) -> Result<u64> {
        self.read_string()?; // name
        self.read_string()?; // type
        let bits = self.read_u32()? as u64;
        let compound_count = self.read_u32()?;
        if compound_count > 1024 {
            return Err(QuilError::InvalidArgument(format!(
                "qclc: compound count {} exceeds cap", compound_count
            )));
        }
        for _ in 0..compound_count {
            let _ = self.parse_ioarg_bits()?;
        }
        Ok(bits)
    }
}

struct WireSeen {
    bits: Vec<u8>,
    n: usize,
}

impl WireSeen {
    fn new(n: usize) -> Self {
        Self { bits: vec![0u8; (n + 7) / 8], n }
    }
    fn set(&mut self, i: usize) -> core::result::Result<(), String> {
        if i >= self.n {
            return Err(format!("wire {} out of range ({})", i, self.n));
        }
        self.bits[i / 8] |= 1 << (i % 8);
        Ok(())
    }
    fn get(&self, i: usize) -> bool {
        if i >= self.n { return false; }
        (self.bits[i / 8] & (1 << (i % 8))) != 0
    }
}

// =====================================================================
// CodeDeployment
// =====================================================================

/// Verify a code deployment by validating the compiled circuit.
pub fn verify_code_deployment(
    compiler: &dyn CircuitCompiler,
    circuit: &[u8],
) -> Result<bool> {
    compiler.validate_circuit(circuit)?;
    Ok(true)
}

/// Get the cost of a code deployment (proportional to circuit size).
pub fn code_deployment_cost(circuit: &[u8]) -> BigInt {
    BigInt::from(circuit.len() as i64)
}

/// Compute the address for a deployed code vertex.
/// `poseidon(domain || circuit)` → 32 bytes.
pub fn code_deployment_address(domain: &[u8], circuit: &[u8]) -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(domain.len() + circuit.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(circuit);
    quil_crypto::poseidon::hash_bytes_to_32(&preimage)
}

/// Create a code vertex tree storing the compiled circuit.
pub fn create_code_vertex_tree(
    circuit: &[u8],
) -> Result<quil_tries::VectorCommitmentTree> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    tree.insert(&[0x00], circuit, &[], &BigInt::from(circuit.len() as i64))
        .map_err(|e| QuilError::Internal(format!("code tree: {}", e)))?;
    Ok(tree)
}

// =====================================================================
// CodeExecute
// =====================================================================

/// Get the cost of a code execution (based on operation count).
pub fn code_execute_cost(execute_operations: &[Vec<u8>]) -> BigInt {
    // Cost proportional to number of operations × average operation size
    let total_bytes: usize = execute_operations.iter().map(|op| op.len()).sum();
    BigInt::from(total_bytes as i64)
}

// =====================================================================
// CodeFinalize
// =====================================================================

/// Get the cost of a code finalization.
pub fn code_finalize_cost(
    results: &[Vec<u8>],
    state_changes: &[Vec<u8>],
) -> BigInt {
    let total: usize = results.iter().map(|r| r.len()).sum::<usize>()
        + state_changes.iter().map(|s| s.len()).sum::<usize>();
    BigInt::from(total as i64)
}

/// Create a state transition vertex for a finalized execution result.
pub fn create_state_transition_vertex(
    _domain: &[u8; 32],
    address: &[u8],
    old_value: &[u8],
    new_value: &[u8],
) -> Result<quil_tries::VectorCommitmentTree> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    // Index 0: old value
    tree.insert(&[0x00], old_value, &[], &BigInt::from(old_value.len() as i64))
        .map_err(|e| QuilError::Internal(format!("state transition: {}", e)))?;
    // Index 1: new value
    tree.insert(&[1 << 2], new_value, &[], &BigInt::from(new_value.len() as i64))
        .map_err(|e| QuilError::Internal(format!("state transition: {}", e)))?;
    // Index 2: address
    tree.insert(&[2 << 2], address, &[], &BigInt::from(address.len() as i64))
        .map_err(|e| QuilError::Internal(format!("state transition: {}", e)))?;
    Ok(tree)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AcceptCompiler;
    impl CircuitCompiler for AcceptCompiler {
        fn compile(&self, _source: &str, _input_sizes: &[Vec<i32>]) -> Result<Vec<u8>> {
            Ok(vec![0xAA; 100])
        }
        fn validate_circuit(&self, _circuit: &[u8]) -> Result<()> {
            Ok(())
        }
    }

    struct RejectCompiler;
    impl CircuitCompiler for RejectCompiler {
        fn compile(&self, _source: &str, _input_sizes: &[Vec<i32>]) -> Result<Vec<u8>> {
            Err(QuilError::InvalidArgument("compile failed".into()))
        }
        fn validate_circuit(&self, _circuit: &[u8]) -> Result<()> {
            Err(QuilError::InvalidArgument("invalid circuit".into()))
        }
    }

    #[test]
    fn verify_deployment_accepts_valid() {
        assert!(verify_code_deployment(&AcceptCompiler, b"circuit-bytes").unwrap());
    }

    #[test]
    fn verify_deployment_rejects_invalid() {
        assert!(verify_code_deployment(&RejectCompiler, b"bad").is_err());
    }

    #[test]
    fn deployment_cost_proportional_to_size() {
        assert_eq!(code_deployment_cost(&[0u8; 100]), BigInt::from(100));
        assert_eq!(code_deployment_cost(&[0u8; 0]), BigInt::from(0));
    }

    #[test]
    fn deployment_address_is_deterministic() {
        let a1 = code_deployment_address(&[0xAAu8; 32], b"circuit").unwrap();
        let a2 = code_deployment_address(&[0xAAu8; 32], b"circuit").unwrap();
        assert_eq!(a1, a2);
    }

    #[test]
    fn deployment_address_differs_by_circuit() {
        let a1 = code_deployment_address(&[0xAAu8; 32], b"circuit-a").unwrap();
        let a2 = code_deployment_address(&[0xAAu8; 32], b"circuit-b").unwrap();
        assert_ne!(a1, a2);
    }

    #[test]
    fn create_code_vertex_stores_circuit() {
        let circuit = b"test-circuit-bytecode";
        let tree = create_code_vertex_tree(circuit).unwrap();
        assert_eq!(tree.get(&[0x00]).unwrap(), circuit);
    }

    #[test]
    fn execute_cost() {
        let ops = vec![vec![0u8; 50], vec![0u8; 30]];
        assert_eq!(code_execute_cost(&ops), BigInt::from(80));
    }

    #[test]
    fn finalize_cost() {
        let results = vec![vec![0u8; 20]];
        let changes = vec![vec![0u8; 40], vec![0u8; 10]];
        assert_eq!(code_finalize_cost(&results, &changes), BigInt::from(70));
    }

    #[test]
    fn structural_validator_rejects_empty() {
        let v = StructuralCircuitValidator;
        assert!(v.validate_circuit(&[]).is_err());
    }

    #[test]
    fn structural_validator_rejects_trivially_small() {
        let v = StructuralCircuitValidator;
        assert!(v.validate_circuit(&[0u8; MIN_CIRCUIT_SIZE - 1]).is_err());
    }

    #[test]
    fn structural_validator_accepts_plausible_size() {
        let v = StructuralCircuitValidator;
        assert!(v.validate_circuit(&[0u8; MIN_CIRCUIT_SIZE]).is_ok());
        assert!(v.validate_circuit(&[0u8; 1024]).is_ok());
    }

    #[test]
    fn structural_validator_rejects_oversize() {
        let v = StructuralCircuitValidator;
        let too_big = vec![0u8; MAX_CIRCUIT_SIZE + 1];
        assert!(v.validate_circuit(&too_big).is_err());
    }

    #[test]
    fn structural_validator_compile_not_supported() {
        let v = StructuralCircuitValidator;
        assert!(v.compile("source", &[]).is_err());
    }

    // ---- QclcCircuitValidator tests -----------------------------------

    /// Build a minimal valid QCLC circuit with `input_bits` free input
    /// wires and a single XOR gate producing a single output wire.
    /// Total wires = input_bits + 1. All wires are assigned: inputs by
    /// initial marking, output by the XOR gate.
    fn build_simple_qclc_circuit(input_bits: u32) -> Vec<u8> {
        let mut out = Vec::new();
        // Header: magic, num_gates, num_wires, num_inputs, num_outputs.
        out.extend_from_slice(&0xDEADBEEFu32.to_be_bytes()); // magic
        out.extend_from_slice(&1u32.to_be_bytes()); // num_gates
        out.extend_from_slice(&(input_bits + 1).to_be_bytes()); // num_wires
        out.extend_from_slice(&1u32.to_be_bytes()); // num_inputs
        out.extend_from_slice(&1u32.to_be_bytes()); // num_outputs
        // Input arg: name="a", type="int", bits=input_bits, no compound
        out.extend_from_slice(&1u32.to_be_bytes()); out.push(b'a');
        out.extend_from_slice(&3u32.to_be_bytes()); out.extend_from_slice(b"int");
        out.extend_from_slice(&input_bits.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // compound_count
        // Output arg: name="o", type="int", bits=1, no compound
        out.extend_from_slice(&1u32.to_be_bytes()); out.push(b'o');
        out.extend_from_slice(&3u32.to_be_bytes()); out.extend_from_slice(b"int");
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        // Single XOR gate: inputs (0, 1) → output (input_bits)
        out.push(QCLC_OP_XOR);
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&input_bits.to_be_bytes());
        out
    }

    #[test]
    fn qclc_validator_accepts_simple_circuit() {
        let v = QclcCircuitValidator;
        let c = build_simple_qclc_circuit(2);
        assert!(v.validate_circuit(&c).is_ok(), "should accept 2-bit XOR circuit");
    }

    #[test]
    fn qclc_validator_rejects_truncated_header() {
        let v = QclcCircuitValidator;
        // 12 bytes passes the MIN_CIRCUIT_SIZE check but isn't a full
        // 20-byte header.
        let too_short = vec![0u8; 12];
        assert!(v.validate_circuit(&too_short).is_err());
    }

    #[test]
    fn qclc_validator_rejects_out_of_range_wire() {
        let v = QclcCircuitValidator;
        let mut c = build_simple_qclc_circuit(2);
        // Overwrite the output wire index (last 4 bytes) to a value
        // beyond num_wires. num_wires = 3, so wire index 99 is bad.
        let len = c.len();
        c[len - 4..].copy_from_slice(&99u32.to_be_bytes());
        assert!(v.validate_circuit(&c).is_err());
    }

    #[test]
    fn qclc_validator_rejects_unassigned_wire() {
        let v = QclcCircuitValidator;
        // Circuit declares 10 wires but only wire 2 is used as gate
        // output; inputs are wires 0..2, leaving 3..10 unassigned.
        let mut out = Vec::new();
        out.extend_from_slice(&0u32.to_be_bytes()); // magic
        out.extend_from_slice(&1u32.to_be_bytes()); // num_gates
        out.extend_from_slice(&10u32.to_be_bytes()); // num_wires (too many)
        out.extend_from_slice(&1u32.to_be_bytes()); // num_inputs
        out.extend_from_slice(&1u32.to_be_bytes()); // num_outputs
        out.extend_from_slice(&1u32.to_be_bytes()); out.push(b'a');
        out.extend_from_slice(&3u32.to_be_bytes()); out.extend_from_slice(b"int");
        out.extend_from_slice(&2u32.to_be_bytes()); // bits=2
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes()); out.push(b'o');
        out.extend_from_slice(&3u32.to_be_bytes()); out.extend_from_slice(b"int");
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.push(QCLC_OP_XOR);
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&2u32.to_be_bytes()); // output wire 2
        assert!(v.validate_circuit(&out).is_err(), "wires 3..10 unassigned");
    }

    #[test]
    fn qclc_validator_rejects_use_before_define() {
        let v = QclcCircuitValidator;
        // Input 0 of first gate references wire 2 which has never been
        // assigned (inputs are wires 0 and 1 only).
        let mut out = Vec::new();
        out.extend_from_slice(&0u32.to_be_bytes()); // magic
        out.extend_from_slice(&1u32.to_be_bytes()); // num_gates
        out.extend_from_slice(&3u32.to_be_bytes()); // num_wires
        out.extend_from_slice(&1u32.to_be_bytes()); // num_inputs
        out.extend_from_slice(&1u32.to_be_bytes()); // num_outputs
        out.extend_from_slice(&1u32.to_be_bytes()); out.push(b'a');
        out.extend_from_slice(&3u32.to_be_bytes()); out.extend_from_slice(b"int");
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes()); out.push(b'o');
        out.extend_from_slice(&3u32.to_be_bytes()); out.extend_from_slice(b"int");
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.push(QCLC_OP_XOR);
        out.extend_from_slice(&2u32.to_be_bytes()); // undefined input
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&2u32.to_be_bytes());
        assert!(v.validate_circuit(&out).is_err());
    }

    #[test]
    fn qclc_validator_rejects_unknown_op() {
        let v = QclcCircuitValidator;
        let mut c = build_simple_qclc_circuit(2);
        // Overwrite the gate op byte. Length - 13 = opcode position.
        let len = c.len();
        c[len - 13] = 99; // unknown op
        assert!(v.validate_circuit(&c).is_err());
    }

    #[test]
    fn qclc_validator_inv_gate_accepted() {
        let v = QclcCircuitValidator;
        let mut out = Vec::new();
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes()); // 1 gate
        out.extend_from_slice(&2u32.to_be_bytes()); // 2 wires
        out.extend_from_slice(&1u32.to_be_bytes()); // 1 input
        out.extend_from_slice(&1u32.to_be_bytes()); // 1 output
        out.extend_from_slice(&1u32.to_be_bytes()); out.push(b'a');
        out.extend_from_slice(&3u32.to_be_bytes()); out.extend_from_slice(b"int");
        out.extend_from_slice(&1u32.to_be_bytes()); // bits=1
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes()); out.push(b'o');
        out.extend_from_slice(&3u32.to_be_bytes()); out.extend_from_slice(b"int");
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        // INV: input 0 → output 1
        out.push(QCLC_OP_INV);
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        assert!(v.validate_circuit(&out).is_ok());
    }

    #[test]
    fn qclc_validator_rejects_gate_count_mismatch() {
        let v = QclcCircuitValidator;
        let mut c = build_simple_qclc_circuit(2);
        // Header says num_gates=1, but add a trailing INV gate.
        c.push(QCLC_OP_INV);
        c.extend_from_slice(&0u32.to_be_bytes());
        c.extend_from_slice(&2u32.to_be_bytes()); // output = wire 2 (already set)
        assert!(v.validate_circuit(&c).is_err());
    }

    #[test]
    fn state_transition_vertex_stores_values() {
        let domain = [0xAAu8; 32];
        let tree = create_state_transition_vertex(
            &domain, b"addr", b"old-val", b"new-val",
        ).unwrap();
        assert_eq!(tree.get(&[0x00]).unwrap(), b"old-val");
        assert_eq!(tree.get(&[1 << 2]).unwrap(), b"new-val");
        assert_eq!(tree.get(&[2 << 2]).unwrap(), b"addr");
    }
}
