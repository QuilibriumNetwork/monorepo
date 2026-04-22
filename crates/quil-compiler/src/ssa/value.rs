//! SSA value types. Port of `ssa/value.go`.

use std::fmt;

use crate::mpa;
use crate::types::{Info, Size, Type};

/// Unique SSA value ID.
pub type ValueId = u32;

/// SSA value.
#[derive(Debug, Clone)]
pub struct Value {
    pub id: ValueId,
    pub name: String,
    pub type_info: Info,
    pub const_val: Option<mpa::Int>,
    /// Bit offset for struct fields.
    pub bit_offset: Size,
    /// Whether this is a parameter value.
    pub param: bool,
}

impl Value {
    pub fn new(id: ValueId, name: &str, type_info: Info) -> Self {
        Value {
            id,
            name: name.to_string(),
            type_info,
            const_val: None,
            bit_offset: 0,
            param: false,
        }
    }

    pub fn is_const(&self) -> bool {
        self.const_val.is_some()
    }

    pub fn bits(&self) -> Size {
        self.type_info.bits
    }

    pub fn set_const(&mut self, val: mpa::Int) {
        self.const_val = Some(val);
    }

    /// Check if this value's type is compatible with another for operations.
    pub fn type_compatible(&self, other: &Value) -> bool {
        if self.type_info.typ == other.type_info.typ {
            return true;
        }
        // Int and Uint are compatible.
        matches!(
            (self.type_info.typ, other.type_info.typ),
            (Type::Int, Type::Uint) | (Type::Uint, Type::Int)
        )
    }

    /// Resolve the concrete size of this value (max of both operands).
    pub fn resolve_size(&self, other: &Value) -> Size {
        self.type_info.bits.max(other.type_info.bits)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref c) = self.const_val {
            write!(f, "{}:{}", c, self.type_info)
        } else {
            write!(f, "v{}:{}", self.id, self.type_info)
        }
    }
}
