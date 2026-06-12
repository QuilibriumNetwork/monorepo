//! AST node definitions. Port of `bedlam/compiler/ast/ast.go`.

use std::collections::HashMap;
use std::fmt;

use crate::lexer::Point;
use crate::mpa;
use crate::types::Info;

/// Annotation lines from comments.
pub type Annotations = Vec<String>;

/// Binary operator type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryType {
    Mul,
    Div,
    Mod,
    Lshift,
    Rshift,
    Band,
    Bclear,
    Add,
    Sub,
    Bor,
    Bxor,
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Neq,
    And,
    Or,
}

impl fmt::Display for BinaryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BinaryType::Mul => write!(f, "*"),
            BinaryType::Div => write!(f, "/"),
            BinaryType::Mod => write!(f, "%"),
            BinaryType::Lshift => write!(f, "<<"),
            BinaryType::Rshift => write!(f, ">>"),
            BinaryType::Band => write!(f, "&"),
            BinaryType::Bclear => write!(f, "&^"),
            BinaryType::Add => write!(f, "+"),
            BinaryType::Sub => write!(f, "-"),
            BinaryType::Bor => write!(f, "|"),
            BinaryType::Bxor => write!(f, "^"),
            BinaryType::Lt => write!(f, "<"),
            BinaryType::Le => write!(f, "<="),
            BinaryType::Gt => write!(f, ">"),
            BinaryType::Ge => write!(f, ">="),
            BinaryType::Eq => write!(f, "=="),
            BinaryType::Neq => write!(f, "!="),
            BinaryType::And => write!(f, "&&"),
            BinaryType::Or => write!(f, "||"),
        }
    }
}

/// Unary operator type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryType {
    Plus,
    Minus,
    Not,
    Xor,
    Ptr,
    Addr,
    Send,
}

impl fmt::Display for UnaryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnaryType::Plus => write!(f, "+"),
            UnaryType::Minus => write!(f, "-"),
            UnaryType::Not => write!(f, "!"),
            UnaryType::Xor => write!(f, "^"),
            UnaryType::Ptr => write!(f, "*"),
            UnaryType::Addr => write!(f, "&"),
            UnaryType::Send => write!(f, "<-"),
        }
    }
}

/// AST expression node.
#[derive(Debug, Clone)]
pub enum Expr {
    /// Integer/bool/string constant.
    Constant {
        loc: Point,
        value: ConstValue,
        type_info: Info,
    },
    /// Variable reference.
    VariableRef {
        loc: Point,
        name: String,
        type_info: Info,
    },
    /// Binary expression.
    Binary {
        loc: Point,
        op: BinaryType,
        left: Box<Expr>,
        right: Box<Expr>,
        type_info: Info,
    },
    /// Unary expression.
    Unary {
        loc: Point,
        op: UnaryType,
        expr: Box<Expr>,
        type_info: Info,
    },
    /// Type cast.
    Cast {
        loc: Point,
        expr: Box<Expr>,
        target: Info,
    },
    /// Function call.
    Call {
        loc: Point,
        name: String,
        args: Vec<Expr>,
        type_info: Info,
    },
    /// Index expression (array/slice).
    Index {
        loc: Point,
        expr: Box<Expr>,
        index: Box<Expr>,
        type_info: Info,
    },
    /// Slice expression.
    Slice {
        loc: Point,
        expr: Box<Expr>,
        from: Option<Box<Expr>>,
        to: Option<Box<Expr>>,
        type_info: Info,
    },
    /// Dot access (field/method).
    Dot {
        loc: Point,
        expr: Box<Expr>,
        name: String,
        type_info: Info,
    },
    /// Composite literal.
    CompositeLit {
        loc: Point,
        type_info: Info,
        elements: Vec<Expr>,
    },
    /// Make built-in.
    Make {
        loc: Point,
        type_info: Info,
        args: Vec<Expr>,
    },
}

impl Expr {
    pub fn location(&self) -> &Point {
        match self {
            Expr::Constant { loc, .. }
            | Expr::VariableRef { loc, .. }
            | Expr::Binary { loc, .. }
            | Expr::Unary { loc, .. }
            | Expr::Cast { loc, .. }
            | Expr::Call { loc, .. }
            | Expr::Index { loc, .. }
            | Expr::Slice { loc, .. }
            | Expr::Dot { loc, .. }
            | Expr::CompositeLit { loc, .. }
            | Expr::Make { loc, .. } => loc,
        }
    }
}

/// Constant value.
#[derive(Debug, Clone)]
pub enum ConstValue {
    Int(mpa::Int),
    Bool(bool),
    String(String),
    Nil,
}

/// AST statement.
#[derive(Debug, Clone)]
pub enum Stmt {
    /// Variable definition.
    Var {
        loc: Point,
        names: Vec<String>,
        type_info: Option<Info>,
        init: Vec<Expr>,
    },
    /// Const definition.
    Const {
        loc: Point,
        name: String,
        type_info: Option<Info>,
        init: Expr,
    },
    /// Assignment.
    Assign {
        loc: Point,
        targets: Vec<Expr>,
        values: Vec<Expr>,
    },
    /// Short variable declaration (:=).
    ShortDecl {
        loc: Point,
        names: Vec<String>,
        values: Vec<Expr>,
    },
    /// Expression statement.
    ExprStmt {
        loc: Point,
        expr: Expr,
    },
    /// Increment (++).
    Increment {
        loc: Point,
        expr: Expr,
    },
    /// Decrement (--).
    Decrement {
        loc: Point,
        expr: Expr,
    },
    /// Compound assignment (+=, -=, etc.).
    CompoundAssign {
        loc: Point,
        op: BinaryType,
        target: Expr,
        value: Expr,
    },
    /// If statement.
    If {
        loc: Point,
        init: Option<Box<Stmt>>,
        cond: Expr,
        body: Vec<Stmt>,
        else_body: Vec<Stmt>,
    },
    /// For loop.
    For {
        loc: Point,
        init: Option<Box<Stmt>>,
        cond: Option<Expr>,
        post: Option<Box<Stmt>>,
        body: Vec<Stmt>,
    },
    /// For-range loop.
    ForRange {
        loc: Point,
        key: Option<String>,
        value: Option<String>,
        expr: Expr,
        body: Vec<Stmt>,
    },
    /// Return.
    Return {
        loc: Point,
        values: Vec<Expr>,
    },
    /// Block.
    Block {
        loc: Point,
        body: Vec<Stmt>,
    },
}

impl Stmt {
    pub fn location(&self) -> &Point {
        match self {
            Stmt::Var { loc, .. }
            | Stmt::Const { loc, .. }
            | Stmt::Assign { loc, .. }
            | Stmt::ShortDecl { loc, .. }
            | Stmt::ExprStmt { loc, .. }
            | Stmt::Increment { loc, .. }
            | Stmt::Decrement { loc, .. }
            | Stmt::CompoundAssign { loc, .. }
            | Stmt::If { loc, .. }
            | Stmt::For { loc, .. }
            | Stmt::ForRange { loc, .. }
            | Stmt::Return { loc, .. }
            | Stmt::Block { loc, .. } => loc,
        }
    }
}

/// Function definition.
#[derive(Debug, Clone)]
pub struct FuncDef {
    pub loc: Point,
    pub name: String,
    pub params: Vec<(String, Info)>,
    pub returns: Vec<(String, Info)>,
    pub body: Vec<Stmt>,
    pub annotations: Annotations,
}

impl FuncDef {
    pub fn location(&self) -> &Point {
        &self.loc
    }
}

/// Type definition.
#[derive(Debug, Clone)]
pub struct TypeDef {
    pub loc: Point,
    pub name: String,
    pub type_info: Info,
}

/// Package.
#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    pub source: String,
    pub imports: HashMap<String, String>,
    pub functions: Vec<FuncDef>,
    pub types: Vec<TypeDef>,
    pub constants: Vec<Stmt>,
    pub variables: Vec<Stmt>,
}

impl Package {
    pub fn new(name: &str, source: &str) -> Self {
        Package {
            name: name.to_string(),
            source: source.to_string(),
            imports: HashMap::new(),
            functions: Vec::new(),
            types: Vec::new(),
            constants: Vec::new(),
            variables: Vec::new(),
        }
    }

    /// Find the main function.
    pub fn main(&self) -> Option<&FuncDef> {
        self.functions.iter().find(|f| f.name == "main")
    }
}
