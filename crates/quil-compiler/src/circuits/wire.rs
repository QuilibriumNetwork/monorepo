//! Wire connecting binary gates. Port of `circuits/wire.go`.

use std::fmt;

use crate::circuit;

const UNASSIGNED_ID: circuit::Wire = u32::MAX;
const OUTPUT_MASK: u32 = 0b10000000000000000000000000000000;
const VALUE_MASK: u32 = 0b01100000000000000000000000000000;
const NUM_MASK: u32 = 0b00011111111111111111111111111111;
const VALUE_SHIFT: u32 = 29;

/// Wire value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WireValue {
    Unknown = 0,
    Zero = 1,
    One = 2,
}

impl fmt::Display for WireValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireValue::Zero => write!(f, "0"),
            WireValue::One => write!(f, "1"),
            WireValue::Unknown => write!(f, "?"),
        }
    }
}

/// Wire connecting binary gates.
pub struct Wire {
    /// Packed: output flag | value | num_outputs
    ovnum: u32,
    id: circuit::Wire,
    /// gates[0] = input gate, gates[1..] = output gates
    gates: Vec<usize>, // indices into gate array
}

impl Wire {
    pub fn new() -> Self {
        Wire {
            ovnum: 0,
            id: UNASSIGNED_ID,
            gates: Vec::new(),
        }
    }

    pub fn reset(&mut self, id: circuit::Wire) {
        self.set_output(false);
        self.set_value(WireValue::Unknown);
        self.id = id;
        self.gates.clear();
    }

    pub fn id(&self) -> circuit::Wire {
        self.id
    }

    pub fn set_id(&mut self, id: circuit::Wire) {
        self.id = id;
    }

    pub fn assigned(&self) -> bool {
        self.id != UNASSIGNED_ID
    }

    pub fn output(&self) -> bool {
        self.ovnum & OUTPUT_MASK != 0
    }

    pub fn set_output(&mut self, output: bool) {
        if output {
            self.ovnum |= OUTPUT_MASK;
        } else {
            self.ovnum &= !OUTPUT_MASK;
        }
    }

    pub fn value(&self) -> WireValue {
        match (self.ovnum & VALUE_MASK) >> VALUE_SHIFT {
            0 => WireValue::Unknown,
            1 => WireValue::Zero,
            2 => WireValue::One,
            _ => WireValue::Unknown,
        }
    }

    pub fn set_value(&mut self, value: WireValue) {
        self.ovnum &= !VALUE_MASK;
        self.ovnum |= ((value as u32) << VALUE_SHIFT) & VALUE_MASK;
    }

    pub fn num_outputs(&self) -> u32 {
        self.ovnum & NUM_MASK
    }

    fn set_num_outputs(&mut self, num: u32) {
        assert!(num <= NUM_MASK, "too big circuit, wire outputs overflow");
        self.ovnum &= !NUM_MASK;
        self.ovnum |= num;
    }

    pub fn disconnect_outputs(&mut self) {
        self.set_num_outputs(0);
        if self.gates.len() > 1 {
            self.gates.truncate(1);
        }
    }

    pub fn input_gate(&self) -> Option<usize> {
        self.gates.first().copied()
    }

    pub fn set_input_gate(&mut self, gate: Option<usize>) {
        match gate {
            None => {
                if !self.gates.is_empty() {
                    self.gates[0] = usize::MAX; // sentinel for "no input"
                }
            }
            Some(g) => {
                if self.gates.is_empty() {
                    self.gates.push(g);
                } else {
                    self.gates[0] = g;
                }
            }
        }
    }

    pub fn is_input(&self) -> bool {
        self.gates.is_empty() || self.gates[0] == usize::MAX
    }

    pub fn output_gates(&self) -> &[usize] {
        if self.gates.len() > 1 {
            &self.gates[1..]
        } else {
            &[]
        }
    }

    pub fn add_output(&mut self, gate: usize) {
        if self.gates.is_empty() {
            self.gates.push(usize::MAX); // placeholder for input
        }
        self.gates.push(gate);
        self.set_num_outputs(self.num_outputs() + 1);
    }

    pub fn remove_output(&mut self, _gate: usize) {
        // Matching Go: just decrements counter, doesn't actually remove from vec
        self.set_num_outputs(self.num_outputs().saturating_sub(1));
    }
}

impl fmt::Display for Wire {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Wire{{0x{:x}, Value:{}, Output={}}}",
            self.id,
            self.value(),
            self.output()
        )
    }
}
