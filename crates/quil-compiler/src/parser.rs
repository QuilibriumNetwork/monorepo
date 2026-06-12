//! QCL parser. Port of `bedlam/compiler/parser.go`.
//!
//! Parses QCL source into AST Package.

use crate::ast::*;
use crate::lexer::{ConstVal, Lexer, Point, Token, TokenType};
use crate::mpa;
use crate::types::{self, Info, Size, Type};

/// QCL parser.
pub struct Parser {
    lexer: Lexer,
}

impl Parser {
    pub fn new(source: &str, input: &str) -> Self {
        Parser {
            lexer: Lexer::new(source, input),
        }
    }

    /// Parse a complete QCL package.
    pub fn parse(&mut self, pkg: &mut Package) -> Result<(), String> {
        // Parse package declaration.
        let tok = self.lexer.get()?;
        if tok.typ != TokenType::SymPackage {
            return Err(format!("{}: expected 'package', got {}", tok.from, tok.typ));
        }
        let name_tok = self.expect_ident()?;
        pkg.name = name_tok.str_val;

        // Parse top-level declarations.
        loop {
            let tok = self.lexer.get()?;
            match tok.typ {
                TokenType::Eof => break,
                TokenType::SymImport => self.parse_import(pkg)?,
                TokenType::SymFunc => {
                    let annotations = self
                        .lexer
                        .annotations(&tok.from)
                        .unwrap_or_default();
                    let func = self.parse_func(annotations)?;
                    pkg.functions.push(func);
                }
                TokenType::SymType => {
                    let td = self.parse_type_def()?;
                    pkg.types.push(td);
                }
                TokenType::SymVar => {
                    let var = self.parse_var()?;
                    pkg.variables.push(var);
                }
                TokenType::SymConst => {
                    let c = self.parse_const()?;
                    pkg.constants.push(c);
                }
                _ => {
                    return Err(format!(
                        "{}: unexpected token {}, expected top-level declaration",
                        tok.from, tok.typ
                    ));
                }
            }
        }
        Ok(())
    }

    fn parse_import(&mut self, pkg: &mut Package) -> Result<(), String> {
        let tok = self.lexer.get()?;
        if tok.typ == TokenType::Char(b'(') {
            // Multi import.
            loop {
                let tok = self.lexer.get()?;
                if tok.typ == TokenType::Char(b')') {
                    break;
                }
                if let Some(ConstVal::String(path)) = &tok.const_val {
                    let alias = path.rsplit('/').next().unwrap_or(path).to_string();
                    pkg.imports.insert(alias, path.clone());
                } else {
                    return Err(format!("{}: expected import path string", tok.from));
                }
            }
        } else if let Some(ConstVal::String(path)) = &tok.const_val {
            let alias = path.rsplit('/').next().unwrap_or(path).to_string();
            pkg.imports.insert(alias, path.clone());
        } else {
            return Err(format!("{}: expected import path", tok.from));
        }
        Ok(())
    }

    fn parse_func(&mut self, annotations: Annotations) -> Result<FuncDef, String> {
        let name_tok = self.expect_ident()?;
        self.expect(TokenType::Char(b'('))?;

        let params = self.parse_param_list()?;
        self.expect(TokenType::Char(b')'))?;

        let returns = self.parse_return_types()?;

        self.expect(TokenType::Char(b'{'))?;
        let body = self.parse_block_body()?;

        Ok(FuncDef {
            loc: name_tok.from.clone(),
            name: name_tok.str_val,
            params,
            returns,
            body,
            annotations,
        })
    }

    fn parse_param_list(&mut self) -> Result<Vec<(String, Info)>, String> {
        let mut params = Vec::new();
        loop {
            let tok = self.lexer.get()?;
            if tok.typ == TokenType::Char(b')') {
                self.lexer.unget(tok);
                break;
            }
            if tok.typ == TokenType::Char(b',') {
                continue;
            }
            if tok.typ == TokenType::Identifier {
                // Collect names separated by commas before the type.
                let mut names = vec![tok.str_val.clone()];
                loop {
                    let next = self.lexer.get()?;
                    if next.typ == TokenType::Char(b',') {
                        let name_tok = self.lexer.get()?;
                        if name_tok.typ == TokenType::Identifier {
                            // Check if next token is a type or another name.
                            let peek = self.lexer.get()?;
                            if peek.typ == TokenType::Char(b',')
                                || peek.typ == TokenType::Identifier
                            {
                                // This identifier could be another name or the type.
                                // Try parsing as type.
                                if types::parse_type(&name_tok.str_val).is_ok() {
                                    // It's a type — all collected names get this type.
                                    let type_info = types::parse_type(&name_tok.str_val)
                                        .map_err(|e| format!("{}", e))?;
                                    for name in &names {
                                        params.push((name.clone(), type_info.clone()));
                                    }
                                    names.clear();
                                    // Continue with peek token.
                                    self.lexer.unget(peek);
                                    break;
                                }
                                // It's another param name.
                                self.lexer.unget(peek);
                                names.push(name_tok.str_val.clone());
                            } else {
                                self.lexer.unget(peek);
                                names.push(name_tok.str_val.clone());
                            }
                        } else {
                            self.lexer.unget(name_tok);
                            break;
                        }
                    } else {
                        self.lexer.unget(next);
                        break;
                    }
                }
                if !names.is_empty() {
                    let type_info = self.parse_type()?;
                    for name in names {
                        params.push((name, type_info.clone()));
                    }
                }
            } else {
                self.lexer.unget(tok);
                break;
            }
        }
        Ok(params)
    }

    fn parse_return_types(&mut self) -> Result<Vec<(String, Info)>, String> {
        let tok = self.lexer.get()?;
        if tok.typ == TokenType::Char(b'{') {
            self.lexer.unget(tok);
            return Ok(Vec::new());
        }
        if tok.typ == TokenType::Char(b'(') {
            let types = self.parse_param_list()?;
            self.expect(TokenType::Char(b')'))?;
            return Ok(types);
        }
        // Single return type.
        self.lexer.unget(tok);
        let type_info = self.parse_type()?;
        Ok(vec![("".to_string(), type_info)])
    }

    fn parse_type(&mut self) -> Result<Info, String> {
        let tok = self.lexer.get()?;
        match tok.typ {
            TokenType::Identifier => {
                // Named type: int32, uint64, bool, etc.
                let name = &tok.str_val;
                types::parse_type(name).map_err(|e| format!("{}: {}", tok.from, e))
            }
            TokenType::Char(b'[') => {
                // Array or slice type.
                let tok2 = self.lexer.get()?;
                if tok2.typ == TokenType::Char(b']') {
                    // Slice.
                    let elem = self.parse_type()?;
                    Ok(Info {
                        typ: Type::Slice,
                        is_concrete: false,
                        element_type: Some(Box::new(elem)),
                        ..Default::default()
                    })
                } else if let Some(ConstVal::Int(ref size)) = tok2.const_val {
                    let array_size = size.int64() as Size;
                    self.expect(TokenType::Char(b']'))?;
                    let elem = self.parse_type()?;
                    let bits = array_size * elem.bits;
                    Ok(Info {
                        typ: Type::Array,
                        is_concrete: true,
                        bits,
                        array_size,
                        element_type: Some(Box::new(elem)),
                        ..Default::default()
                    })
                } else {
                    Err(format!("{}: expected array size or ']'", tok2.from))
                }
            }
            TokenType::Char(b'*') => {
                let elem = self.parse_type()?;
                Ok(Info {
                    typ: Type::Ptr,
                    is_concrete: true,
                    bits: elem.bits,
                    element_type: Some(Box::new(elem)),
                    ..Default::default()
                })
            }
            TokenType::SymStruct => {
                self.expect(TokenType::Char(b'{'))?;
                let mut fields = Vec::new();
                let mut struct_bits: Size = 0;
                loop {
                    let tok = self.lexer.get()?;
                    if tok.typ == TokenType::Char(b'}') {
                        break;
                    }
                    if tok.typ == TokenType::Identifier {
                        let name = tok.str_val.clone();
                        let mut fi = self.parse_type()?;
                        fi.offset = struct_bits;
                        struct_bits += fi.bits;
                        fields.push(types::StructField {
                            name,
                            type_info: fi,
                        });
                    }
                }
                Ok(Info {
                    typ: Type::Struct,
                    is_concrete: true,
                    bits: struct_bits,
                    fields,
                    ..Default::default()
                })
            }
            _ => Err(format!("{}: expected type, got {}", tok.from, tok.typ)),
        }
    }

    fn parse_type_def(&mut self) -> Result<TypeDef, String> {
        let name_tok = self.expect_ident()?;
        let type_info = self.parse_type()?;
        Ok(TypeDef {
            loc: name_tok.from.clone(),
            name: name_tok.str_val,
            type_info,
        })
    }

    fn parse_var(&mut self) -> Result<Stmt, String> {
        let loc = self.lexer.get()?.from.clone();
        self.lexer.unget(Token {
            typ: TokenType::Identifier,
            from: loc.clone(),
            to: loc.clone(),
            str_val: String::new(),
            const_val: None,
        });

        let name_tok = self.expect_ident()?;
        let type_info = self.parse_type().ok();

        let init = if self.peek_is(TokenType::Char(b'='))? {
            self.lexer.get()?; // consume =
            vec![self.parse_expr()?]
        } else {
            Vec::new()
        };

        Ok(Stmt::Var {
            loc,
            names: vec![name_tok.str_val],
            type_info,
            init,
        })
    }

    fn parse_const(&mut self) -> Result<Stmt, String> {
        let loc = self.lexer.get()?.from.clone();
        self.lexer.unget(Token {
            typ: TokenType::Identifier,
            from: loc.clone(),
            to: loc.clone(),
            str_val: String::new(),
            const_val: None,
        });

        let name_tok = self.expect_ident()?;
        let type_info = self.parse_type().ok();

        self.expect(TokenType::Char(b'='))?;
        let init = self.parse_expr()?;

        Ok(Stmt::Const {
            loc,
            name: name_tok.str_val,
            type_info,
            init,
        })
    }

    fn parse_block_body(&mut self) -> Result<Vec<Stmt>, String> {
        let mut stmts = Vec::new();
        loop {
            let tok = self.lexer.get()?;
            if tok.typ == TokenType::Char(b'}') || tok.typ == TokenType::Eof {
                break;
            }
            self.lexer.unget(tok);
            stmts.push(self.parse_stmt()?);
        }
        Ok(stmts)
    }

    fn parse_stmt(&mut self) -> Result<Stmt, String> {
        let tok = self.lexer.get()?;
        match tok.typ {
            TokenType::SymVar => self.parse_var(),
            TokenType::SymReturn => {
                let mut values = Vec::new();
                if !self.peek_is_any(&[
                    TokenType::Char(b'}'),
                    TokenType::Eof,
                    TokenType::Char(b';'),
                ])? {
                    values.push(self.parse_expr()?);
                    while self.peek_is(TokenType::Char(b','))? {
                        self.lexer.get()?;
                        values.push(self.parse_expr()?);
                    }
                }
                Ok(Stmt::Return {
                    loc: tok.from,
                    values,
                })
            }
            TokenType::SymIf => self.parse_if(tok.from),
            TokenType::SymFor => self.parse_for(tok.from),
            TokenType::Char(b'{') => {
                let body = self.parse_block_body()?;
                Ok(Stmt::Block {
                    loc: tok.from,
                    body,
                })
            }
            _ => {
                self.lexer.unget(tok.clone());
                let expr = self.parse_expr()?;

                let next = self.lexer.get()?;
                match next.typ {
                    TokenType::DefAssign => {
                        // Short declaration: name := value
                        let name = match &expr {
                            Expr::VariableRef { name, .. } => name.clone(),
                            _ => return Err(format!("{}: expected variable name for :=", next.from)),
                        };
                        let value = self.parse_expr()?;
                        Ok(Stmt::ShortDecl {
                            loc: tok.from,
                            names: vec![name],
                            values: vec![value],
                        })
                    }
                    TokenType::Char(b'=') => {
                        let value = self.parse_expr()?;
                        Ok(Stmt::Assign {
                            loc: tok.from,
                            targets: vec![expr],
                            values: vec![value],
                        })
                    }
                    TokenType::PlusPlus => Ok(Stmt::Increment {
                        loc: tok.from,
                        expr,
                    }),
                    TokenType::MinusMinus => Ok(Stmt::Decrement {
                        loc: tok.from,
                        expr,
                    }),
                    TokenType::PlusEq | TokenType::MinusEq | TokenType::MultEq
                    | TokenType::DivEq | TokenType::AndEq | TokenType::OrEq
                    | TokenType::XorEq | TokenType::LshiftEq | TokenType::RshiftEq => {
                        let op = match next.typ {
                            TokenType::PlusEq => BinaryType::Add,
                            TokenType::MinusEq => BinaryType::Sub,
                            TokenType::MultEq => BinaryType::Mul,
                            TokenType::DivEq => BinaryType::Div,
                            TokenType::AndEq => BinaryType::Band,
                            TokenType::OrEq => BinaryType::Bor,
                            TokenType::XorEq => BinaryType::Bxor,
                            TokenType::LshiftEq => BinaryType::Lshift,
                            TokenType::RshiftEq => BinaryType::Rshift,
                            _ => unreachable!(),
                        };
                        let value = self.parse_expr()?;
                        Ok(Stmt::CompoundAssign {
                            loc: tok.from,
                            op,
                            target: expr,
                            value,
                        })
                    }
                    _ => {
                        self.lexer.unget(next);
                        Ok(Stmt::ExprStmt {
                            loc: tok.from,
                            expr,
                        })
                    }
                }
            }
        }
    }

    fn parse_if(&mut self, loc: Point) -> Result<Stmt, String> {
        let cond = self.parse_expr()?;
        self.expect(TokenType::Char(b'{'))?;
        let body = self.parse_block_body()?;

        let else_body = if self.peek_is(TokenType::SymElse)? {
            self.lexer.get()?;
            if self.peek_is(TokenType::SymIf)? {
                let tok = self.lexer.get()?;
                vec![self.parse_if(tok.from)?]
            } else {
                self.expect(TokenType::Char(b'{'))?;
                self.parse_block_body()?
            }
        } else {
            Vec::new()
        };

        Ok(Stmt::If {
            loc,
            init: None,
            cond,
            body,
            else_body,
        })
    }

    fn parse_for(&mut self, loc: Point) -> Result<Stmt, String> {
        // Check for range.
        if self.peek_is(TokenType::SymRange)? {
            self.lexer.get()?;
            let expr = self.parse_expr()?;
            self.expect(TokenType::Char(b'{'))?;
            let body = self.parse_block_body()?;
            return Ok(Stmt::ForRange {
                loc,
                key: None,
                value: None,
                expr,
                body,
            });
        }

        // Three-clause for.
        let init = if !self.peek_is(TokenType::Char(b';'))? && !self.peek_is(TokenType::Char(b'{'))? {
            let stmt = self.parse_stmt()?;
            Some(Box::new(stmt))
        } else {
            None
        };

        if self.peek_is(TokenType::Char(b'{'))? {
            self.lexer.get()?;
            let body = self.parse_block_body()?;
            return Ok(Stmt::For {
                loc,
                init,
                cond: None,
                post: None,
                body,
            });
        }

        self.expect(TokenType::Char(b';'))?;
        let cond = if !self.peek_is(TokenType::Char(b';'))? {
            Some(self.parse_expr()?)
        } else {
            None
        };
        self.expect(TokenType::Char(b';'))?;

        let post = if !self.peek_is(TokenType::Char(b'{'))? {
            Some(Box::new(self.parse_stmt()?))
        } else {
            None
        };

        self.expect(TokenType::Char(b'{'))?;
        let body = self.parse_block_body()?;

        Ok(Stmt::For {
            loc,
            init,
            cond,
            post,
            body,
        })
    }

    // =====================================================================
    // Expression parsing (Pratt parser)
    // =====================================================================

    fn parse_expr(&mut self) -> Result<Expr, String> {
        self.parse_or_expr()
    }

    fn parse_or_expr(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_and_expr()?;
        while self.peek_is(TokenType::Or)? {
            let tok = self.lexer.get()?;
            let right = self.parse_and_expr()?;
            left = Expr::Binary {
                loc: tok.from,
                op: BinaryType::Or,
                left: Box::new(left),
                right: Box::new(right),
                type_info: Info::bool(),
            };
        }
        Ok(left)
    }

    fn parse_and_expr(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_comparison_expr()?;
        while self.peek_is(TokenType::And)? {
            let tok = self.lexer.get()?;
            let right = self.parse_comparison_expr()?;
            left = Expr::Binary {
                loc: tok.from,
                op: BinaryType::And,
                left: Box::new(left),
                right: Box::new(right),
                type_info: Info::bool(),
            };
        }
        Ok(left)
    }

    fn parse_comparison_expr(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_add_expr()?;
        loop {
            let tok = self.lexer.get()?;
            let op = match tok.typ {
                TokenType::Eq => BinaryType::Eq,
                TokenType::Neq => BinaryType::Neq,
                TokenType::Lt => BinaryType::Lt,
                TokenType::Le => BinaryType::Le,
                TokenType::Gt => BinaryType::Gt,
                TokenType::Ge => BinaryType::Ge,
                _ => {
                    self.lexer.unget(tok);
                    break;
                }
            };
            let right = self.parse_add_expr()?;
            left = Expr::Binary {
                loc: tok.from,
                op,
                left: Box::new(left),
                right: Box::new(right),
                type_info: Info::bool(),
            };
        }
        Ok(left)
    }

    fn parse_add_expr(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_mul_expr()?;
        loop {
            let tok = self.lexer.get()?;
            let op = match tok.typ {
                TokenType::Char(b'+') => BinaryType::Add,
                TokenType::Char(b'-') => BinaryType::Sub,
                TokenType::Char(b'|') => BinaryType::Bor,
                TokenType::Char(b'^') => BinaryType::Bxor,
                _ => {
                    self.lexer.unget(tok);
                    break;
                }
            };
            let right = self.parse_mul_expr()?;
            left = Expr::Binary {
                loc: tok.from,
                op,
                left: Box::new(left),
                right: Box::new(right),
                type_info: Info::default(),
            };
        }
        Ok(left)
    }

    fn parse_mul_expr(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_shift_expr()?;
        loop {
            let tok = self.lexer.get()?;
            let op = match tok.typ {
                TokenType::Char(b'*') => BinaryType::Mul,
                TokenType::Char(b'/') => BinaryType::Div,
                TokenType::Char(b'%') => BinaryType::Mod,
                TokenType::Char(b'&') => BinaryType::Band,
                TokenType::BitClear => BinaryType::Bclear,
                _ => {
                    self.lexer.unget(tok);
                    break;
                }
            };
            let right = self.parse_shift_expr()?;
            left = Expr::Binary {
                loc: tok.from,
                op,
                left: Box::new(left),
                right: Box::new(right),
                type_info: Info::default(),
            };
        }
        Ok(left)
    }

    fn parse_shift_expr(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_unary_expr()?;
        loop {
            let tok = self.lexer.get()?;
            let op = match tok.typ {
                TokenType::Lshift => BinaryType::Lshift,
                TokenType::Rshift => BinaryType::Rshift,
                _ => {
                    self.lexer.unget(tok);
                    break;
                }
            };
            let right = self.parse_unary_expr()?;
            left = Expr::Binary {
                loc: tok.from,
                op,
                left: Box::new(left),
                right: Box::new(right),
                type_info: Info::default(),
            };
        }
        Ok(left)
    }

    fn parse_unary_expr(&mut self) -> Result<Expr, String> {
        let tok = self.lexer.get()?;
        match tok.typ {
            TokenType::Char(b'-') | TokenType::Char(b'+') | TokenType::Char(b'!')
            | TokenType::Char(b'^') | TokenType::Char(b'*') | TokenType::Char(b'&') => {
                let op = tok.typ.unary_type();
                let expr = self.parse_unary_expr()?;
                Ok(Expr::Unary {
                    loc: tok.from,
                    op,
                    expr: Box::new(expr),
                    type_info: Info::default(),
                })
            }
            _ => {
                self.lexer.unget(tok);
                self.parse_postfix_expr()
            }
        }
    }

    fn parse_postfix_expr(&mut self) -> Result<Expr, String> {
        let mut expr = self.parse_primary_expr()?;
        loop {
            let tok = self.lexer.get()?;
            match tok.typ {
                TokenType::Char(b'(') => {
                    // Function call.
                    let name = match &expr {
                        Expr::VariableRef { name, .. } => name.clone(),
                        _ => return Err(format!("{}: expected function name", tok.from)),
                    };
                    let args = self.parse_expr_list(b')')?;
                    expr = Expr::Call {
                        loc: tok.from,
                        name,
                        args,
                        type_info: Info::default(),
                    };
                }
                TokenType::Char(b'[') => {
                    let index = self.parse_expr()?;
                    self.expect(TokenType::Char(b']'))?;
                    expr = Expr::Index {
                        loc: tok.from,
                        expr: Box::new(expr),
                        index: Box::new(index),
                        type_info: Info::default(),
                    };
                }
                TokenType::Char(b'.') => {
                    let name_tok = self.expect_ident()?;
                    expr = Expr::Dot {
                        loc: tok.from,
                        expr: Box::new(expr),
                        name: name_tok.str_val,
                        type_info: Info::default(),
                    };
                }
                _ => {
                    self.lexer.unget(tok);
                    break;
                }
            }
        }
        Ok(expr)
    }

    fn parse_primary_expr(&mut self) -> Result<Expr, String> {
        let tok = self.lexer.get()?;
        match tok.typ {
            TokenType::Constant => {
                let (value, type_info) = match &tok.const_val {
                    Some(ConstVal::Int(v)) => (
                        ConstValue::Int(v.clone()),
                        Info {
                            typ: Type::Int,
                            is_concrete: true,
                            bits: v.bits.max(32),
                            min_bits: v.bit_len() as Size,
                            ..Default::default()
                        },
                    ),
                    Some(ConstVal::Bool(b)) => (ConstValue::Bool(*b), Info::bool()),
                    Some(ConstVal::String(s)) => (
                        ConstValue::String(s.clone()),
                        Info {
                            typ: Type::String,
                            is_concrete: true,
                            bits: (s.len() as Size) * 8,
                            ..Default::default()
                        },
                    ),
                    Some(ConstVal::Char(c)) => (
                        ConstValue::Int(mpa::Int::from_i64(*c as i64, 32)),
                        Info::rune(),
                    ),
                    None => return Err(format!("{}: empty constant", tok.from)),
                };
                Ok(Expr::Constant {
                    loc: tok.from,
                    value,
                    type_info,
                })
            }
            TokenType::Identifier => Ok(Expr::VariableRef {
                loc: tok.from.clone(),
                name: tok.str_val,
                type_info: Info::default(),
            }),
            TokenType::SymNil => Ok(Expr::Constant {
                loc: tok.from,
                value: ConstValue::Nil,
                type_info: Info::nil(),
            }),
            TokenType::Char(b'(') => {
                let expr = self.parse_expr()?;
                self.expect(TokenType::Char(b')'))?;
                Ok(expr)
            }
            _ => Err(format!(
                "{}: unexpected token {}, expected expression",
                tok.from, tok.typ
            )),
        }
    }

    fn parse_expr_list(&mut self, end: u8) -> Result<Vec<Expr>, String> {
        let mut exprs = Vec::new();
        if self.peek_is(TokenType::Char(end))? {
            self.lexer.get()?;
            return Ok(exprs);
        }
        exprs.push(self.parse_expr()?);
        while self.peek_is(TokenType::Char(b','))? {
            self.lexer.get()?;
            if self.peek_is(TokenType::Char(end))? {
                break;
            }
            exprs.push(self.parse_expr()?);
        }
        self.expect(TokenType::Char(end))?;
        Ok(exprs)
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    fn expect_ident(&mut self) -> Result<Token, String> {
        let tok = self.lexer.get()?;
        if tok.typ != TokenType::Identifier {
            return Err(format!("{}: expected identifier, got {}", tok.from, tok.typ));
        }
        Ok(tok)
    }

    fn expect(&mut self, expected: TokenType) -> Result<Token, String> {
        let tok = self.lexer.get()?;
        if tok.typ != expected {
            return Err(format!(
                "{}: expected {}, got {}",
                tok.from, expected, tok.typ
            ));
        }
        Ok(tok)
    }

    fn peek_is(&mut self, expected: TokenType) -> Result<bool, String> {
        let tok = self.lexer.get()?;
        let matches = tok.typ == expected;
        self.lexer.unget(tok);
        Ok(matches)
    }

    fn peek_is_any(&mut self, expected: &[TokenType]) -> Result<bool, String> {
        let tok = self.lexer.get()?;
        let matches = expected.contains(&tok.typ);
        self.lexer.unget(tok);
        Ok(matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_function() {
        let src = r#"
package main

func main(a, b int32) int32 {
    return a + b
}
"#;
        let mut parser = Parser::new("test.qcl", src);
        let mut pkg = Package::new("main", "test.qcl");
        parser.parse(&mut pkg).unwrap();
        assert_eq!(pkg.name, "main");
        assert_eq!(pkg.functions.len(), 1);
        assert_eq!(pkg.functions[0].name, "main");
    }

    #[test]
    fn parse_import() {
        let src = r#"
package main

import (
    "fmt"
    "math"
)

func main() {
}
"#;
        let mut parser = Parser::new("test.qcl", src);
        let mut pkg = Package::new("main", "test.qcl");
        parser.parse(&mut pkg).unwrap();
        assert_eq!(pkg.imports.len(), 2);
        assert!(pkg.imports.contains_key("fmt"));
        assert!(pkg.imports.contains_key("math"));
    }
}
