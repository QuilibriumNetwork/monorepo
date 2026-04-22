//! SSA instructions. Port of `ssa/instructions.go`.

use std::fmt;

use crate::types::Info;

use super::value::ValueId;

/// SSA instruction opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    // Arithmetic
    Iadd,
    Isub,
    Imul,
    Idiv,
    Imod,
    // Comparison
    Ilt,
    Ile,
    Igt,
    Ige,
    Ieq,
    Ineq,
    // Logical
    And,
    Or,
    Not,
    // Bitwise
    Band,
    Bor,
    Bxor,
    Bclear,
    Bts,    // bit test
    Btc,    // bit test and clear
    // Shift
    Lshift,
    Rshift,
    // Memory / data flow
    Mov,
    Phi,
    Slice,
    Index,
    // Control flow
    Jump,
    If,
    Ret,
    Call,
    Builtin,
    // Type operations
    Cast,
    Make,
    // Special
    Nop,
    GC,
    // Circuit-specific
    Circ,
    Amov,  // array move
    Smov,  // struct move
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Opcode::Iadd => "iadd",
            Opcode::Isub => "isub",
            Opcode::Imul => "imul",
            Opcode::Idiv => "idiv",
            Opcode::Imod => "imod",
            Opcode::Ilt => "ilt",
            Opcode::Ile => "ile",
            Opcode::Igt => "igt",
            Opcode::Ige => "ige",
            Opcode::Ieq => "ieq",
            Opcode::Ineq => "ineq",
            Opcode::And => "and",
            Opcode::Or => "or",
            Opcode::Not => "not",
            Opcode::Band => "band",
            Opcode::Bor => "bor",
            Opcode::Bxor => "bxor",
            Opcode::Bclear => "bclear",
            Opcode::Bts => "bts",
            Opcode::Btc => "btc",
            Opcode::Lshift => "lshift",
            Opcode::Rshift => "rshift",
            Opcode::Mov => "mov",
            Opcode::Phi => "phi",
            Opcode::Slice => "slice",
            Opcode::Index => "index",
            Opcode::Jump => "jump",
            Opcode::If => "if",
            Opcode::Ret => "ret",
            Opcode::Call => "call",
            Opcode::Builtin => "builtin",
            Opcode::Cast => "cast",
            Opcode::Make => "make",
            Opcode::Nop => "nop",
            Opcode::GC => "gc",
            Opcode::Circ => "circ",
            Opcode::Amov => "amov",
            Opcode::Smov => "smov",
        };
        write!(f, "{}", s)
    }
}

/// Operand of an SSA instruction.
#[derive(Debug, Clone)]
pub enum Operand {
    /// Reference to an SSA value.
    Value(ValueId),
    /// Immediate integer constant.
    Imm(i64),
    /// Block label (for jumps).
    Label(usize),
    /// Type info (for casts).
    Type(Info),
    /// Function name (for calls).
    Func(String),
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::Value(id) => write!(f, "v{}", id),
            Operand::Imm(v) => write!(f, "{}", v),
            Operand::Label(l) => write!(f, "L{}", l),
            Operand::Type(t) => write!(f, "{}", t),
            Operand::Func(name) => write!(f, "@{}", name),
        }
    }
}

/// SSA instruction.
#[derive(Debug, Clone)]
pub struct Instr {
    pub op: Opcode,
    pub out: Option<ValueId>,
    pub operands: Vec<Operand>,
    pub type_info: Info,
}

impl Instr {
    pub fn new(op: Opcode) -> Self {
        Instr {
            op,
            out: None,
            operands: Vec::new(),
            type_info: Info::default(),
        }
    }

    pub fn with_out(mut self, out: ValueId) -> Self {
        self.out = Some(out);
        self
    }

    pub fn with_operand(mut self, op: Operand) -> Self {
        self.operands.push(op);
        self
    }

    pub fn with_type(mut self, t: Info) -> Self {
        self.type_info = t;
        self
    }
}

impl fmt::Display for Instr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(out) = self.out {
            write!(f, "v{} = ", out)?;
        }
        write!(f, "{}", self.op)?;
        for (i, op) in self.operands.iter().enumerate() {
            if i == 0 {
                write!(f, " {}", op)?;
            } else {
                write!(f, ", {}", op)?;
            }
        }
        Ok(())
    }
}
