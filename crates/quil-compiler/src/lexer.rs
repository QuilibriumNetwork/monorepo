//! QCL lexical analyzer. Port of `bedlam/compiler/lexer.go`.

use std::collections::HashMap;
use std::fmt;

use crate::ast;
use crate::mpa;

/// Source location.
#[derive(Debug, Clone, Default)]
pub struct Point {
    pub source: String,
    pub line: usize,
    pub col: usize,
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.source, self.line, self.col)
    }
}

/// Token type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenType {
    // Single-character tokens (stored as their ASCII value).
    Char(u8),
    // Multi-character / keyword tokens.
    Identifier,
    Constant,
    SymPackage,
    SymImport,
    SymFunc,
    SymIf,
    SymElse,
    SymBreak,
    SymContinue,
    SymGoto,
    SymReturn,
    SymStruct,
    SymVar,
    SymConst,
    SymType,
    SymFor,
    SymRange,
    SymNil,
    DefAssign,   // :=
    MultEq,      // *=
    DivEq,       // /=
    LshiftEq,    // <<=
    Lshift,      // <<
    RshiftEq,    // >>=
    Rshift,      // >>
    PlusPlus,    // ++
    PlusEq,      // +=
    MinusMinus,  // --
    MinusEq,     // -=
    OrEq,        // |=
    XorEq,       // ^=
    AndEq,       // &=
    Lt,          // <
    Le,          // <=
    Gt,          // >
    Ge,          // >=
    Eq,          // ==
    Neq,         // !=
    And,         // &&
    Or,          // ||
    BitClear,    // &^
    Send,        // <-
    Eof,
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenType::Char(c) => write!(f, "{}", *c as char),
            TokenType::Identifier => write!(f, "identifier"),
            TokenType::Constant => write!(f, "constant"),
            TokenType::SymPackage => write!(f, "package"),
            TokenType::SymImport => write!(f, "import"),
            TokenType::SymFunc => write!(f, "func"),
            TokenType::SymIf => write!(f, "if"),
            TokenType::SymElse => write!(f, "else"),
            TokenType::SymBreak => write!(f, "break"),
            TokenType::SymContinue => write!(f, "continue"),
            TokenType::SymGoto => write!(f, "goto"),
            TokenType::SymReturn => write!(f, "return"),
            TokenType::SymStruct => write!(f, "struct"),
            TokenType::SymVar => write!(f, "var"),
            TokenType::SymConst => write!(f, "const"),
            TokenType::SymType => write!(f, "type"),
            TokenType::SymFor => write!(f, "for"),
            TokenType::SymRange => write!(f, "range"),
            TokenType::SymNil => write!(f, "nil"),
            TokenType::DefAssign => write!(f, ":="),
            TokenType::MultEq => write!(f, "*="),
            TokenType::DivEq => write!(f, "/="),
            TokenType::LshiftEq => write!(f, "<<="),
            TokenType::Lshift => write!(f, "<<"),
            TokenType::RshiftEq => write!(f, ">>="),
            TokenType::Rshift => write!(f, ">>"),
            TokenType::PlusPlus => write!(f, "++"),
            TokenType::PlusEq => write!(f, "+="),
            TokenType::MinusMinus => write!(f, "--"),
            TokenType::MinusEq => write!(f, "-="),
            TokenType::OrEq => write!(f, "|="),
            TokenType::XorEq => write!(f, "^="),
            TokenType::AndEq => write!(f, "&="),
            TokenType::Lt => write!(f, "<"),
            TokenType::Le => write!(f, "<="),
            TokenType::Gt => write!(f, ">"),
            TokenType::Ge => write!(f, ">="),
            TokenType::Eq => write!(f, "=="),
            TokenType::Neq => write!(f, "!="),
            TokenType::And => write!(f, "&&"),
            TokenType::Or => write!(f, "||"),
            TokenType::BitClear => write!(f, "&^"),
            TokenType::Send => write!(f, "<-"),
            TokenType::Eof => write!(f, "EOF"),
        }
    }
}

impl TokenType {
    /// Convert to AST binary operator type.
    pub fn binary_type(&self) -> ast::BinaryType {
        match self {
            TokenType::Char(b'*') => ast::BinaryType::Mul,
            TokenType::Char(b'+') => ast::BinaryType::Add,
            TokenType::Char(b'-') => ast::BinaryType::Sub,
            TokenType::Char(b'/') => ast::BinaryType::Div,
            TokenType::Char(b'%') => ast::BinaryType::Mod,
            TokenType::Lt => ast::BinaryType::Lt,
            TokenType::Le => ast::BinaryType::Le,
            TokenType::Gt => ast::BinaryType::Gt,
            TokenType::Ge => ast::BinaryType::Ge,
            TokenType::Eq => ast::BinaryType::Eq,
            TokenType::Neq => ast::BinaryType::Neq,
            TokenType::And => ast::BinaryType::And,
            TokenType::Or => ast::BinaryType::Or,
            TokenType::Char(b'&') => ast::BinaryType::Band,
            TokenType::Char(b'|') => ast::BinaryType::Bor,
            TokenType::Char(b'^') => ast::BinaryType::Bxor,
            TokenType::BitClear => ast::BinaryType::Bclear,
            TokenType::Lshift => ast::BinaryType::Lshift,
            TokenType::Rshift => ast::BinaryType::Rshift,
            _ => panic!("invalid binary operator {:?}", self),
        }
    }

    /// Convert to AST unary operator type.
    pub fn unary_type(&self) -> ast::UnaryType {
        match self {
            TokenType::Char(b'+') => ast::UnaryType::Plus,
            TokenType::Char(b'-') => ast::UnaryType::Minus,
            TokenType::Char(b'!') => ast::UnaryType::Not,
            TokenType::Char(b'^') => ast::UnaryType::Xor,
            TokenType::Char(b'*') => ast::UnaryType::Ptr,
            TokenType::Char(b'&') => ast::UnaryType::Addr,
            TokenType::Send => ast::UnaryType::Send,
            _ => panic!("invalid unary operator {:?}", self),
        }
    }
}

/// Constant value in a token.
#[derive(Debug, Clone)]
pub enum ConstVal {
    String(String),
    Int(mpa::Int),
    Bool(bool),
    Char(i32),
}

/// Token.
#[derive(Debug, Clone)]
pub struct Token {
    pub typ: TokenType,
    pub from: Point,
    pub to: Point,
    pub str_val: String,
    pub const_val: Option<ConstVal>,
}

impl Token {
    pub fn display_str(&self) -> String {
        if !self.str_val.is_empty() {
            return self.str_val.clone();
        }
        match &self.const_val {
            Some(ConstVal::Int(v)) => v.to_string(),
            Some(ConstVal::Bool(b)) => b.to_string(),
            Some(ConstVal::String(s)) => s.clone(),
            Some(ConstVal::Char(c)) => format!("'{}'", char::from_u32(*c as u32).unwrap_or('?')),
            None => self.typ.to_string(),
        }
    }
}

/// Comment.
#[derive(Debug, Clone, Default)]
pub struct Comment {
    pub start: Point,
    pub end: Point,
    pub lines: Vec<String>,
}

impl Comment {
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

/// Keyword lookup table.
fn keywords() -> HashMap<&'static str, TokenType> {
    let mut m = HashMap::new();
    m.insert("import", TokenType::SymImport);
    m.insert("const", TokenType::SymConst);
    m.insert("type", TokenType::SymType);
    m.insert("for", TokenType::SymFor);
    m.insert("range", TokenType::SymRange);
    m.insert("nil", TokenType::SymNil);
    m.insert("else", TokenType::SymElse);
    m.insert("func", TokenType::SymFunc);
    m.insert("if", TokenType::SymIf);
    m.insert("package", TokenType::SymPackage);
    m.insert("return", TokenType::SymReturn);
    m.insert("struct", TokenType::SymStruct);
    m.insert("var", TokenType::SymVar);
    m
}

/// QCL Lexer.
pub struct Lexer {
    chars: Vec<char>,
    pos: usize,
    point: Point,
    token_start: Point,
    ungot: Option<Token>,
    last_comment: Comment,
    kw: HashMap<&'static str, TokenType>,
}

impl Lexer {
    pub fn new(source: &str, input: &str) -> Self {
        Lexer {
            chars: input.chars().collect(),
            pos: 0,
            point: Point {
                source: source.to_string(),
                line: 1,
                col: 0,
            },
            token_start: Point::default(),
            ungot: None,
            last_comment: Comment::default(),
            kw: keywords(),
        }
    }

    pub fn source(&self) -> &str {
        &self.point.source
    }

    fn read_char(&mut self) -> Option<char> {
        if self.pos >= self.chars.len() {
            return None;
        }
        let ch = self.chars[self.pos];
        self.pos += 1;
        if ch == '\n' {
            self.point.line += 1;
            self.point.col = 0;
        } else {
            self.point.col += 1;
        }
        Some(ch)
    }

    fn unread_char(&mut self) {
        if self.pos > 0 {
            self.pos -= 1;
            let ch = self.chars[self.pos];
            if ch == '\n' {
                self.point.line -= 1;
                // col is approximate after unread
            } else {
                self.point.col = self.point.col.saturating_sub(1);
            }
        }
    }

    fn peek_char(&self) -> Option<char> {
        if self.pos < self.chars.len() {
            Some(self.chars[self.pos])
        } else {
            None
        }
    }

    fn token(&self, typ: TokenType) -> Token {
        Token {
            typ,
            from: self.token_start.clone(),
            to: self.point.clone(),
            str_val: String::new(),
            const_val: None,
        }
    }

    pub fn unget(&mut self, t: Token) {
        self.ungot = Some(t);
    }

    /// Annotations preceding the current location.
    pub fn annotations(&self, loc: &Point) -> Option<Vec<String>> {
        if self.last_comment.is_empty() || self.last_comment.end.line + 1 != loc.line {
            return None;
        }
        Some(self.last_comment.lines.clone())
    }

    /// Get the next token.
    pub fn get(&mut self) -> Result<Token, String> {
        if let Some(t) = self.ungot.take() {
            return Ok(t);
        }

        loop {
            self.token_start = self.point.clone();
            let ch = match self.read_char() {
                Some(c) => c,
                None => return Ok(self.token(TokenType::Eof)),
            };

            if ch.is_whitespace() {
                continue;
            }

            match ch {
                '%' | '(' | ')' | '{' | '}' | '[' | ']' | ',' | ';' | '.' => {
                    return Ok(self.token(TokenType::Char(ch as u8)));
                }

                '^' => {
                    if self.peek_char() == Some('=') {
                        self.read_char();
                        return Ok(self.token(TokenType::XorEq));
                    }
                    return Ok(self.token(TokenType::Char(b'^')));
                }

                '+' => match self.peek_char() {
                    Some('+') => {
                        self.read_char();
                        return Ok(self.token(TokenType::PlusPlus));
                    }
                    Some('=') => {
                        self.read_char();
                        return Ok(self.token(TokenType::PlusEq));
                    }
                    _ => return Ok(self.token(TokenType::Char(b'+'))),
                },

                '-' => match self.peek_char() {
                    Some('-') => {
                        self.read_char();
                        return Ok(self.token(TokenType::MinusMinus));
                    }
                    Some('=') => {
                        self.read_char();
                        return Ok(self.token(TokenType::MinusEq));
                    }
                    _ => return Ok(self.token(TokenType::Char(b'-'))),
                },

                '*' => {
                    if self.peek_char() == Some('=') {
                        self.read_char();
                        return Ok(self.token(TokenType::MultEq));
                    }
                    return Ok(self.token(TokenType::Char(b'*')));
                }

                '/' => match self.peek_char() {
                    Some('/') => {
                        self.read_char();
                        let start = self.point.clone();
                        let mut comment = String::new();
                        while let Some(c) = self.read_char() {
                            if c == '\n' {
                                break;
                            }
                            comment.push(c);
                        }
                        self.add_comment(&comment, &start);
                        continue;
                    }
                    Some('*') => {
                        self.read_char();
                        let start = self.point.clone();
                        let mut comment = String::new();
                        loop {
                            match self.read_char() {
                                None => break,
                                Some('*') => {
                                    if self.peek_char() == Some('/') {
                                        self.read_char();
                                        break;
                                    }
                                    comment.push('*');
                                }
                                Some(c) => comment.push(c),
                            }
                        }
                        self.add_comment(&comment, &start);
                        continue;
                    }
                    Some('=') => {
                        self.read_char();
                        return Ok(self.token(TokenType::DivEq));
                    }
                    _ => return Ok(self.token(TokenType::Char(b'/'))),
                },

                '<' => match self.peek_char() {
                    Some('=') => {
                        self.read_char();
                        return Ok(self.token(TokenType::Le));
                    }
                    Some('<') => {
                        self.read_char();
                        if self.peek_char() == Some('=') {
                            self.read_char();
                            return Ok(self.token(TokenType::LshiftEq));
                        }
                        return Ok(self.token(TokenType::Lshift));
                    }
                    Some('-') => {
                        self.read_char();
                        return Ok(self.token(TokenType::Send));
                    }
                    _ => return Ok(self.token(TokenType::Lt)),
                },

                '>' => match self.peek_char() {
                    Some('=') => {
                        self.read_char();
                        return Ok(self.token(TokenType::Ge));
                    }
                    Some('>') => {
                        self.read_char();
                        if self.peek_char() == Some('=') {
                            self.read_char();
                            return Ok(self.token(TokenType::RshiftEq));
                        }
                        return Ok(self.token(TokenType::Rshift));
                    }
                    _ => return Ok(self.token(TokenType::Gt)),
                },

                '=' => {
                    if self.peek_char() == Some('=') {
                        self.read_char();
                        return Ok(self.token(TokenType::Eq));
                    }
                    return Ok(self.token(TokenType::Char(b'=')));
                }

                ':' => {
                    if self.peek_char() == Some('=') {
                        self.read_char();
                        return Ok(self.token(TokenType::DefAssign));
                    }
                    return Ok(self.token(TokenType::Char(b':')));
                }

                '|' => match self.peek_char() {
                    Some('|') => {
                        self.read_char();
                        return Ok(self.token(TokenType::Or));
                    }
                    Some('=') => {
                        self.read_char();
                        return Ok(self.token(TokenType::OrEq));
                    }
                    _ => return Ok(self.token(TokenType::Char(b'|'))),
                },

                '&' => match self.peek_char() {
                    Some('&') => {
                        self.read_char();
                        return Ok(self.token(TokenType::And));
                    }
                    Some('^') => {
                        self.read_char();
                        return Ok(self.token(TokenType::BitClear));
                    }
                    Some('=') => {
                        self.read_char();
                        return Ok(self.token(TokenType::AndEq));
                    }
                    _ => return Ok(self.token(TokenType::Char(b'&'))),
                },

                '"' => {
                    let mut val = String::new();
                    loop {
                        match self.read_char() {
                            None => return Err("unterminated string".to_string()),
                            Some('"') => break,
                            Some('\\') => {
                                self.unread_char();
                                val.push(char::from_u32(self.read_escape()? as u32).unwrap_or('?'));
                            }
                            Some(c) => val.push(c),
                        }
                    }
                    let mut tok = self.token(TokenType::Constant);
                    tok.const_val = Some(ConstVal::String(val));
                    return Ok(tok);
                }

                '\'' => {
                    let i32_val = self.read_escape()?;
                    match self.read_char() {
                        Some('\'') => {}
                        _ => return Err("unterminated character literal".to_string()),
                    }
                    let mut tok = self.token(TokenType::Constant);
                    tok.const_val = Some(ConstVal::Char(i32_val));
                    return Ok(tok);
                }

                '!' => {
                    if self.peek_char() == Some('=') {
                        self.read_char();
                        return Ok(self.token(TokenType::Neq));
                    }
                    return Ok(self.token(TokenType::Char(b'!')));
                }

                '0' => {
                    let ival = match self.peek_char() {
                        Some('b') | Some('B') => {
                            self.read_char();
                            self.read_binary_literal()?
                        }
                        Some('o') | Some('O') => {
                            self.read_char();
                            self.read_octal_literal()?
                        }
                        Some('x') | Some('X') => {
                            self.read_char();
                            self.read_hex_literal()?
                        }
                        Some(c) if ('0'..='7').contains(&c) => {
                            self.read_octal_literal()?
                        }
                        _ => mpa::Int::from_i64(0, 0),
                    };
                    let mut tok = self.token(TokenType::Constant);
                    tok.const_val = Some(ConstVal::Int(ival));
                    return Ok(tok);
                }

                _ => {
                    if ch.is_alphabetic() || ch == '_' {
                        let mut sym = String::from(ch);
                        while let Some(c) = self.peek_char() {
                            if c.is_alphanumeric() || c == '_' {
                                sym.push(c);
                                self.read_char();
                            } else {
                                break;
                            }
                        }
                        if let Some(&tt) = self.kw.get(sym.as_str()) {
                            return Ok(self.token(tt));
                        }
                        if sym == "true" || sym == "false" {
                            let mut tok = self.token(TokenType::Constant);
                            tok.const_val = Some(ConstVal::Bool(sym == "true"));
                            return Ok(tok);
                        }
                        let mut tok = self.token(TokenType::Identifier);
                        tok.str_val = sym;
                        return Ok(tok);
                    }
                    if ch.is_ascii_digit() {
                        let mut val = String::from(ch);
                        while let Some(c) = self.peek_char() {
                            if c.is_ascii_digit() {
                                val.push(c);
                                self.read_char();
                            } else {
                                break;
                            }
                        }
                        let ival = mpa::Int::parse(&val, 10)
                            .ok_or_else(|| format!("invalid literal '{}'", val))?;
                        let mut tok = self.token(TokenType::Constant);
                        tok.const_val = Some(ConstVal::Int(ival));
                        return Ok(tok);
                    }
                    return Err(format!("{}: unexpected character '{}'", self.point, ch));
                }
            }
        }
    }

    fn read_escape(&mut self) -> Result<i32, String> {
        let ch = self.read_char().ok_or("unexpected EOF in escape")?;
        if ch != '\\' {
            return Ok(ch as i32);
        }
        let ch = self.read_char().ok_or("unexpected EOF in escape")?;
        match ch {
            'a' => Ok(7),
            'b' => Ok(8),
            'f' => Ok(12),
            'n' => Ok(10),
            'r' => Ok(13),
            't' => Ok(9),
            'v' => Ok(11),
            '\\' => Ok(92),
            'u' => {
                let mut v: i32 = 0;
                for _ in 0..4 {
                    v <<= 4;
                    let c = self.read_char().ok_or("unexpected EOF in \\u escape")?;
                    v += hex_digit(c)?;
                }
                Ok(v)
            }
            'x' => {
                let mut v: i32 = 0;
                for _ in 0..2 {
                    v <<= 4;
                    let c = self.read_char().ok_or("unexpected EOF in \\x escape")?;
                    v += hex_digit(c)?;
                }
                Ok(v)
            }
            c if ('0'..='7').contains(&c) => {
                let mut v = c as i32 - '0' as i32;
                for _ in 0..2 {
                    let c = self.read_char().ok_or("unexpected EOF in octal escape")?;
                    if !('0'..='7').contains(&c) {
                        return Err(format!("invalid octal escape char '{}'", c));
                    }
                    v = v * 8 + (c as i32 - '0' as i32);
                }
                Ok(v)
            }
            _ => Err(format!("unknown escape: \\{}", ch)),
        }
    }

    fn read_binary_literal(&mut self) -> Result<mpa::Int, String> {
        let mut val = String::new();
        while let Some(c) = self.peek_char() {
            if c == '0' || c == '1' {
                val.push(c);
                self.read_char();
            } else {
                break;
            }
        }
        mpa::Int::parse(&val, 2).ok_or_else(|| format!("malformed binary literal '{}'", val))
    }

    fn read_octal_literal(&mut self) -> Result<mpa::Int, String> {
        let mut val = String::new();
        while let Some(c) = self.peek_char() {
            if ('0'..='7').contains(&c) {
                val.push(c);
                self.read_char();
            } else {
                break;
            }
        }
        if val.is_empty() {
            return Ok(mpa::Int::from_i64(0, 0));
        }
        mpa::Int::parse(&val, 8).ok_or_else(|| format!("malformed octal literal '{}'", val))
    }

    fn read_hex_literal(&mut self) -> Result<mpa::Int, String> {
        let mut val = String::new();
        while let Some(c) = self.peek_char() {
            if c.is_ascii_hexdigit() {
                val.push(c);
                self.read_char();
            } else {
                break;
            }
        }
        mpa::Int::parse(&val, 16).ok_or_else(|| format!("malformed hex literal '{}'", val))
    }

    fn add_comment(&mut self, line: &str, loc: &Point) {
        if self.last_comment.is_empty() || self.last_comment.end.line + 1 != loc.line {
            self.last_comment = Comment {
                start: loc.clone(),
                end: loc.clone(),
                lines: vec![line.to_string()],
            };
        } else {
            self.last_comment.end = loc.clone();
            self.last_comment.lines.push(line.to_string());
        }
    }
}

fn hex_digit(c: char) -> Result<i32, String> {
    match c {
        '0'..='9' => Ok(c as i32 - '0' as i32),
        'a'..='f' => Ok(10 + c as i32 - 'a' as i32),
        'A'..='F' => Ok(10 + c as i32 - 'A' as i32),
        _ => Err(format!("invalid hex digit '{}'", c)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lex_basic_tokens() {
        let mut l = Lexer::new("test", "a + b");
        let t = l.get().unwrap();
        assert_eq!(t.typ, TokenType::Identifier);
        assert_eq!(t.str_val, "a");

        let t = l.get().unwrap();
        assert_eq!(t.typ, TokenType::Char(b'+'));

        let t = l.get().unwrap();
        assert_eq!(t.typ, TokenType::Identifier);
        assert_eq!(t.str_val, "b");

        let t = l.get().unwrap();
        assert_eq!(t.typ, TokenType::Eof);
    }

    #[test]
    fn lex_keywords() {
        let mut l = Lexer::new("test", "func if return var for");
        assert_eq!(l.get().unwrap().typ, TokenType::SymFunc);
        assert_eq!(l.get().unwrap().typ, TokenType::SymIf);
        assert_eq!(l.get().unwrap().typ, TokenType::SymReturn);
        assert_eq!(l.get().unwrap().typ, TokenType::SymVar);
        assert_eq!(l.get().unwrap().typ, TokenType::SymFor);
    }

    #[test]
    fn lex_numbers() {
        let mut l = Lexer::new("test", "42 0xff 0b1010");
        let t = l.get().unwrap();
        assert!(matches!(t.const_val, Some(ConstVal::Int(_))));
        if let Some(ConstVal::Int(v)) = &t.const_val {
            assert_eq!(v.int64(), 42);
        }

        let t = l.get().unwrap();
        if let Some(ConstVal::Int(v)) = &t.const_val {
            assert_eq!(v.int64(), 255);
        }

        let t = l.get().unwrap();
        if let Some(ConstVal::Int(v)) = &t.const_val {
            assert_eq!(v.int64(), 10);
        }
    }

    #[test]
    fn lex_string_literal() {
        let mut l = Lexer::new("test", r#""hello world""#);
        let t = l.get().unwrap();
        assert!(matches!(&t.const_val, Some(ConstVal::String(s)) if s == "hello world"));
    }

    #[test]
    fn lex_operators() {
        let mut l = Lexer::new("test", ":= == != <= >= << >> && || &^");
        assert_eq!(l.get().unwrap().typ, TokenType::DefAssign);
        assert_eq!(l.get().unwrap().typ, TokenType::Eq);
        assert_eq!(l.get().unwrap().typ, TokenType::Neq);
        assert_eq!(l.get().unwrap().typ, TokenType::Le);
        assert_eq!(l.get().unwrap().typ, TokenType::Ge);
        assert_eq!(l.get().unwrap().typ, TokenType::Lshift);
        assert_eq!(l.get().unwrap().typ, TokenType::Rshift);
        assert_eq!(l.get().unwrap().typ, TokenType::And);
        assert_eq!(l.get().unwrap().typ, TokenType::Or);
        assert_eq!(l.get().unwrap().typ, TokenType::BitClear);
    }

    #[test]
    fn lex_comments() {
        let mut l = Lexer::new("test", "a // comment\nb");
        let t = l.get().unwrap();
        assert_eq!(t.str_val, "a");
        let t = l.get().unwrap();
        assert_eq!(t.str_val, "b");
    }
}
