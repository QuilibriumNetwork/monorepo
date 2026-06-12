//! QCL type system. Port of `bedlam/types/types.go`.

use std::fmt;

/// Unique ID for named types.
pub type TypeId = i32;

/// Circuit size / bit count.
pub type Size = i32;

/// Byte size in bits.
pub const BYTE_BITS: Size = 8;

/// QCL types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i8)]
pub enum Type {
    Undefined = 0,
    Bool = 1,
    Int = 2,
    Uint = 3,
    Float = 4,
    String = 5,
    Struct = 6,
    Array = 7,
    Slice = 8,
    Ptr = 9,
    Nil = 10,
}

impl Type {
    /// Tests if the type is an Array or a Slice.
    pub fn is_array(&self) -> bool {
        matches!(self, Type::Array | Type::Slice)
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Undefined => write!(f, "<Undefined>"),
            Type::Bool => write!(f, "bool"),
            Type::Int => write!(f, "int"),
            Type::Uint => write!(f, "uint"),
            Type::Float => write!(f, "float"),
            Type::String => write!(f, "string"),
            Type::Struct => write!(f, "struct"),
            Type::Array => write!(f, "array"),
            Type::Slice => write!(f, "slice"),
            Type::Ptr => write!(f, "ptr"),
            Type::Nil => write!(f, "nil"),
        }
    }
}

impl Type {
    pub fn short_string(&self) -> &'static str {
        match self {
            Type::Undefined => "?",
            Type::Bool => "b",
            Type::Int => "i",
            Type::Uint => "u",
            Type::Float => "f",
            Type::String => "str",
            Type::Struct => "struct",
            Type::Array => "arr",
            Type::Slice => "slice",
            Type::Ptr => "*",
            Type::Nil => "nil",
        }
    }
}

/// Structure field definition.
#[derive(Debug, Clone)]
pub struct StructField {
    pub name: String,
    pub type_info: Info,
}

impl fmt::Display for StructField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[{}:{}]",
            self.type_info.typ,
            self.type_info.offset,
            self.type_info.offset + self.type_info.bits
        )
    }
}

/// Type information.
#[derive(Debug, Clone)]
pub struct Info {
    pub id: TypeId,
    pub typ: Type,
    pub is_concrete: bool,
    pub bits: Size,
    pub min_bits: Size,
    pub fields: Vec<StructField>,
    pub element_type: Option<Box<Info>>,
    pub array_size: Size,
    pub offset: Size,
}

impl Default for Info {
    fn default() -> Self {
        Info {
            id: 0,
            typ: Type::Undefined,
            is_concrete: true,
            bits: 0,
            min_bits: 0,
            fields: Vec::new(),
            element_type: None,
            array_size: 0,
            offset: 0,
        }
    }
}

impl Info {
    pub fn undefined() -> Self {
        Info {
            typ: Type::Undefined,
            is_concrete: true,
            ..Default::default()
        }
    }

    pub fn nil() -> Self {
        Info {
            typ: Type::Nil,
            is_concrete: true,
            ..Default::default()
        }
    }

    pub fn bool() -> Self {
        Info {
            typ: Type::Bool,
            is_concrete: true,
            bits: 1,
            min_bits: 1,
            ..Default::default()
        }
    }

    pub fn byte() -> Self {
        Info {
            typ: Type::Uint,
            is_concrete: true,
            bits: 8,
            min_bits: 8,
            ..Default::default()
        }
    }

    pub fn rune() -> Self {
        Info {
            typ: Type::Int,
            is_concrete: true,
            bits: 32,
            min_bits: 32,
            ..Default::default()
        }
    }

    pub fn int32() -> Self {
        Info {
            typ: Type::Int,
            is_concrete: true,
            bits: 32,
            min_bits: 32,
            ..Default::default()
        }
    }

    pub fn uint32() -> Self {
        Info {
            typ: Type::Uint,
            is_concrete: true,
            bits: 32,
            min_bits: 32,
            ..Default::default()
        }
    }

    pub fn uint64() -> Self {
        Info {
            typ: Type::Uint,
            is_concrete: true,
            bits: 64,
            min_bits: 64,
            ..Default::default()
        }
    }

    pub fn is_undefined(&self) -> bool {
        self.typ == Type::Undefined
    }

    pub fn concrete(&self) -> bool {
        if self.typ != Type::Struct {
            return self.is_concrete;
        }
        self.fields.iter().all(|f| f.type_info.concrete())
    }

    pub fn set_concrete(&mut self, c: bool) {
        self.is_concrete = c;
    }

    pub fn equal(&self, o: &Info) -> bool {
        if self.typ != o.typ {
            return false;
        }
        match self.typ {
            Type::Undefined | Type::Bool | Type::Int | Type::Uint
            | Type::Float | Type::String => self.bits == o.bits,
            Type::Struct => {
                if self.fields.len() != o.fields.len() || self.bits != o.bits {
                    return false;
                }
                self.fields
                    .iter()
                    .zip(o.fields.iter())
                    .all(|(a, b)| a.type_info.equal(&b.type_info))
            }
            Type::Array | Type::Slice => {
                if self.array_size != o.array_size || self.bits != o.bits {
                    return false;
                }
                match (&self.element_type, &o.element_type) {
                    (Some(a), Some(b)) => a.equal(b),
                    _ => false,
                }
            }
            Type::Ptr => match (&self.element_type, &o.element_type) {
                (Some(a), Some(b)) => a.equal(b),
                _ => false,
            },
            _ => false,
        }
    }

    pub fn specializable(&self, o: &Info) -> bool {
        if self.typ != o.typ {
            return false;
        }
        match self.typ {
            Type::Undefined | Type::Bool | Type::Int | Type::Uint
            | Type::Float | Type::String => !self.concrete() || self.bits == o.bits,
            Type::Struct => {
                if self.fields.len() != o.fields.len()
                    || (self.concrete() && self.bits != o.bits)
                {
                    return false;
                }
                self.fields
                    .iter()
                    .zip(o.fields.iter())
                    .all(|(a, b)| a.type_info.specializable(&b.type_info))
            }
            Type::Array => {
                if self.concrete()
                    && (self.array_size != o.array_size || self.bits != o.bits)
                {
                    return false;
                }
                match (&self.element_type, &o.element_type) {
                    (Some(a), Some(b)) => a.specializable(b),
                    _ => false,
                }
            }
            Type::Slice | Type::Ptr => match (&self.element_type, &o.element_type) {
                (Some(a), Some(b)) => a.specializable(b),
                _ => false,
            },
            _ => false,
        }
    }

    pub fn can_assign_const(&self, o: &Info) -> bool {
        match self.typ {
            Type::Int | Type::Uint => {
                (o.typ == Type::Int || o.typ == Type::Uint) && self.bits >= o.min_bits
            }
            Type::Slice => {
                o.typ.is_array()
                    && self
                        .element_type
                        .as_ref()
                        .zip(o.element_type.as_ref())
                        .map_or(false, |(a, b)| a.equal(b))
            }
            Type::Array => {
                if o.typ == Type::Nil {
                    return true;
                }
                if !o.typ.is_array() {
                    return false;
                }
                self.element_type
                    .as_ref()
                    .zip(o.element_type.as_ref())
                    .map_or(false, |(a, b)| a.equal(b))
                    && self.bits >= o.min_bits
            }
            _ => self.typ == o.typ && self.bits >= o.min_bits,
        }
    }

    /// Instantiate template type to match parameter type.
    pub fn instantiate(&mut self, o: &Info) -> bool {
        if self.typ != o.typ {
            match self.typ {
                Type::Array => match o.typ {
                    Type::Nil => {
                        if !self.element_type.as_ref().map_or(false, |e| e.concrete()) {
                            return false;
                        }
                        self.is_concrete = true;
                        self.bits = 0;
                        self.min_bits = 0;
                        self.array_size = 0;
                        return true;
                    }
                    Type::Ptr => {
                        if !o
                            .element_type
                            .as_ref()
                            .map_or(false, |e| e.typ.is_array())
                        {
                            return false;
                        }
                        self.typ = Type::Ptr;
                        self.element_type = o.element_type.clone();
                    }
                    _ => return false,
                },
                Type::Slice => match o.typ {
                    Type::Nil => {
                        self.is_concrete = true;
                        self.bits = 0;
                        self.min_bits = 0;
                        self.array_size = 0;
                        return true;
                    }
                    Type::Array => { /* continue below */ }
                    Type::Ptr => {
                        if !o
                            .element_type
                            .as_ref()
                            .map_or(false, |e| e.typ.is_array())
                        {
                            return false;
                        }
                        self.typ = Type::Ptr;
                        self.element_type = o.element_type.clone();
                    }
                    _ => return false,
                },
                Type::Int => {
                    if o.typ == Type::Uint && o.min_bits < o.bits {
                        self.is_concrete = true;
                        self.bits = o.bits;
                        self.min_bits = o.bits;
                        return true;
                    }
                    return false;
                }
                _ => return false,
            }
        }
        if self.concrete() {
            return false;
        }
        match self.typ {
            Type::Struct => false,
            Type::Array | Type::Slice => {
                if let (Some(ref mut el), Some(ref oel)) =
                    (&mut self.element_type, &o.element_type)
                {
                    if !el.concrete() && !el.instantiate(oel) {
                        return false;
                    }
                    if el.typ != oel.typ {
                        return false;
                    }
                } else {
                    return false;
                }
                self.is_concrete = true;
                self.bits = o.bits;
                self.array_size = o.array_size;
                true
            }
            Type::Ptr => {
                if let (Some(ref el), Some(ref oel)) =
                    (&self.element_type, &o.element_type)
                {
                    if el.typ != oel.typ {
                        return false;
                    }
                } else {
                    return false;
                }
                self.is_concrete = true;
                self.bits = o.bits;
                true
            }
            _ => {
                self.is_concrete = true;
                self.bits = o.bits;
                true
            }
        }
    }

    /// Instantiate with input sizes.
    pub fn instantiate_with_sizes(&mut self, sizes: &[i32]) -> Result<(), String> {
        if sizes.is_empty() {
            return Err(format!("not enough sizes for type {:?}", self));
        }
        match self.typ {
            Type::Bool => {}
            Type::Int | Type::Uint | Type::Float => {
                if !self.concrete() {
                    self.bits = sizes[0] as Size;
                }
            }
            Type::Struct => {
                let mut struct_bits: Size = 0;
                for idx in 0..self.fields.len() {
                    if idx >= sizes.len() {
                        return Err(format!("not enough sizes for type {:?}", self));
                    }
                    self.fields[idx]
                        .type_info
                        .instantiate_with_sizes(&sizes[idx..])?;
                    self.fields[idx].type_info.offset = struct_bits;
                    struct_bits += self.fields[idx].type_info.bits;
                }
                self.bits = struct_bits;
            }
            Type::Array => {
                if !self.element_type.as_ref().map_or(false, |e| e.concrete()) {
                    return Err(format!("array element type unspecified: {:?}", self));
                }
                if !self.concrete() {
                    let el_bits = self.element_type.as_ref().unwrap().bits;
                    self.array_size = sizes[0] as Size / el_bits;
                    if sizes[0] as Size % el_bits != 0 {
                        self.array_size += 1;
                    }
                    self.bits = self.array_size * el_bits;
                }
            }
            Type::Slice => {
                if !self.element_type.as_ref().map_or(false, |e| e.concrete()) {
                    return Err(format!("slice element type unspecified: {:?}", self));
                }
                let el_bits = self.element_type.as_ref().unwrap().bits;
                self.array_size = sizes[0] as Size / el_bits;
                if sizes[0] as Size % el_bits != 0 {
                    self.array_size += 1;
                }
                self.bits = self.array_size * el_bits;
            }
            _ => {
                return Err(format!("can't specify {:?}", self));
            }
        }
        self.set_concrete(true);
        Ok(())
    }
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.typ {
            Type::Array => {
                write!(
                    f,
                    "[{}]{}",
                    self.array_size,
                    self.element_type.as_ref().unwrap()
                )
            }
            Type::Slice => {
                write!(f, "[]{}", self.element_type.as_ref().unwrap())
            }
            Type::Ptr => {
                write!(f, "*{}", self.element_type.as_ref().unwrap())
            }
            _ => {
                if !self.concrete() {
                    write!(f, "{}", self.typ)
                } else {
                    write!(f, "{}{}", self.typ, self.bits)
                }
            }
        }
    }
}

/// Parse a type string into Info. Port of `bedlam/types/parse.go`.
pub fn parse_type(s: &str) -> Result<Info, String> {
    // Handle "bool" with optional size suffix (e.g., "bool1" from serialization).
    if s == "bool" || s.starts_with("bool") {
        let rest = &s[4..];
        if rest.is_empty() {
            return Ok(Info::bool());
        }
        if let Ok(bits) = rest.parse::<i32>() {
            return Ok(Info {
                typ: Type::Bool,
                is_concrete: true,
                bits: bits as Size,
                min_bits: bits as Size,
                ..Default::default()
            });
        }
        return Ok(Info::bool());
    }
    if s == "byte" {
        return Ok(Info::byte());
    }
    if s == "rune" {
        return Ok(Info::rune());
    }
    // Sized types: "int32", "uint64", etc.
    for (prefix, typ) in [
        ("int", Type::Int),
        ("uint", Type::Uint),
        ("string", Type::String),
        ("struct", Type::Struct),
        ("float", Type::Float),
    ] {
        if let Some(rest) = s.strip_prefix(prefix) {
            if rest.is_empty() {
                return Ok(Info {
                    typ,
                    is_concrete: false,
                    ..Default::default()
                });
            }
            if let Ok(bits) = rest.parse::<i32>() {
                return Ok(Info {
                    typ,
                    is_concrete: true,
                    bits: bits as Size,
                    min_bits: bits as Size,
                    ..Default::default()
                });
            }
        }
    }
    // Array: "[N]elem"
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(idx) = rest.find(']') {
            let size_str = &rest[..idx];
            let elem_str = &rest[idx + 1..];
            if size_str.is_empty() {
                // Slice: "[]elem"
                let elem = parse_type(elem_str)?;
                return Ok(Info {
                    typ: Type::Slice,
                    is_concrete: false,
                    element_type: Some(Box::new(elem)),
                    ..Default::default()
                });
            }
            let size = size_str
                .parse::<i32>()
                .map_err(|e| format!("invalid array size: {}", e))?;
            let elem = parse_type(elem_str)?;
            let bits = size * elem.bits;
            return Ok(Info {
                typ: Type::Array,
                is_concrete: true,
                bits,
                array_size: size as Size,
                element_type: Some(Box::new(elem)),
                ..Default::default()
            });
        }
    }
    // Pointer: "*elem"
    if let Some(rest) = s.strip_prefix('*') {
        let elem = parse_type(rest)?;
        return Ok(Info {
            typ: Type::Ptr,
            is_concrete: true,
            bits: elem.bits,
            element_type: Some(Box::new(elem)),
            ..Default::default()
        });
    }
    Err(format!("unsupported type: {}", s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_types() {
        let b = parse_type("bool").unwrap();
        assert_eq!(b.typ, Type::Bool);
        assert_eq!(b.bits, 1);

        let i = parse_type("int32").unwrap();
        assert_eq!(i.typ, Type::Int);
        assert_eq!(i.bits, 32);

        let u = parse_type("uint64").unwrap();
        assert_eq!(u.typ, Type::Uint);
        assert_eq!(u.bits, 64);
    }

    #[test]
    fn parse_array_type() {
        let a = parse_type("[4]uint8").unwrap();
        assert_eq!(a.typ, Type::Array);
        assert_eq!(a.array_size, 4);
        assert_eq!(a.bits, 32);
    }

    #[test]
    fn type_equality() {
        let a = Info {
            typ: Type::Int,
            is_concrete: true,
            bits: 32,
            ..Default::default()
        };
        let b = Info {
            typ: Type::Int,
            is_concrete: true,
            bits: 32,
            ..Default::default()
        };
        assert!(a.equal(&b));
    }
}
