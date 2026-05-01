//! Focused Turtle/RDF subset parser for Quilibrium schemas.
//!
//! Ports the surface of Go's `types/schema/rdf.go::TurtleRDFParser`
//! that the consensus layer actually uses: extract `(class, field,
//! order, size, rdf_type)` tuples from a Turtle-RDF schema document.
//! We do NOT implement a general-purpose RDF graph engine — instead
//! we parse Quilibrium's constrained schema shape directly:
//!
//! ```turtle
//! BASE <https://types.quilibrium.com/schema-repository/>
//! @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
//! @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
//! @prefix qcl: <https://types.quilibrium.com/qcl/> .
//! @prefix prover: <https://types.quilibrium.com/.../prover/> .
//!
//! prover:Prover a rdfs:Class .
//! prover:PublicKey a rdfs:Property ;
//!   rdfs:domain qcl:ByteArray ;
//!   qcl:size 585 ;
//!   qcl:order 0 ;
//!   rdfs:range prover:Prover .
//! ```
//!
//! Output type [`ParsedSchema`] gives the same surface Go's
//! `RDFMultiprover` consumes: a class → field-name → tag map.
//!
//! Limitations vs Go (`rdf2go`):
//! - No support for blank nodes, lists, or RDF reification.
//! - No URI resolution against `BASE`.
//! - Comments must be on their own line or at end of line; Turtle's
//!   in-statement `#` form inside literal strings is not handled.
//! - Namespace prefixes are looked up by exact key; the trailing
//!   slash quirk Go's parser handles is replicated here.

use quil_types::error::{QuilError, Result};
use std::collections::HashMap;

/// One field on an RDF class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedField {
    /// Field name (after prefix expansion). e.g. `"PublicKey"`.
    pub name: String,
    /// Schema-declared order. Used by `order_to_key` to derive the
    /// tree lookup key.
    pub order: u16,
    /// Schema-declared size (bytes for ByteArray, max length for
    /// String, fixed for primitives).
    pub size: u32,
    /// QCL RDF type string: `"Uint"`, `"Int"`, `"ByteArray"`,
    /// `"Bool"`, `"String"`, `"Struct"`. Empty string for fields
    /// where the domain wasn't a known QCL type.
    pub rdf_type: String,
    /// Range — the parent class this field belongs to. Used for
    /// validation only.
    pub range_class: String,
}

/// One RDF class definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedClass {
    /// Class name (after prefix expansion). e.g. `"prover:Prover"`.
    pub name: String,
    /// Fields keyed by field name.
    pub fields: HashMap<String, ParsedField>,
}

/// Output of [`parse_turtle_schema`].
#[derive(Debug, Clone, Default)]
pub struct ParsedSchema {
    /// Classes keyed by `prefix:name`.
    pub classes: HashMap<String, ParsedClass>,
    /// Maximum `order` across all fields. Used by callers to pick
    /// the correct `order_to_key` width.
    pub max_order: u16,
}

impl ParsedSchema {
    /// Look up a field tag by `(class, field)` name. `None` when
    /// either the class or field doesn't exist in the schema.
    pub fn field(&self, class: &str, field: &str) -> Option<&ParsedField> {
        self.classes.get(class)?.fields.get(field)
    }
}

/// Parse a Turtle schema document into [`ParsedSchema`]. Ports
/// `TurtleRDFParser.GetTags` at `types/schema/rdf.go:87-360`.
pub fn parse_turtle_schema(document: &str) -> Result<ParsedSchema> {
    let prefix_map = extract_prefixes(document);
    let statements = tokenize(document)?;
    let mut schema = ParsedSchema::default();

    // Pass 1: identify class declarations (`X a rdfs:Class .`).
    let mut class_iris: Vec<String> = Vec::new();
    for stmt in &statements {
        let subject = expand_iri(&stmt.subject, &prefix_map);
        for pred_obj in &stmt.predicate_objects {
            let pred = expand_iri(&pred_obj.predicate, &prefix_map);
            for obj in &pred_obj.objects {
                let obj_iri = expand_iri(obj, &prefix_map);
                if (pred == RDF_TYPE_FULL || pred == "a")
                    && obj_iri == RDFS_CLASS_FULL
                {
                    class_iris.push(subject.clone());
                    let class_name = collapse_iri(&subject, &prefix_map);
                    schema.classes.entry(class_name.clone()).or_insert_with(|| {
                        ParsedClass {
                            name: class_name,
                            fields: HashMap::new(),
                        }
                    });
                }
            }
        }
    }

    // Pass 2: identify property declarations (those with `rdfs:range`)
    // and attach them to the named class.
    for stmt in &statements {
        let subject_iri = expand_iri(&stmt.subject, &prefix_map);
        let mut range_class: Option<String> = None;
        let mut domain_type: Option<String> = None;
        let mut order: Option<u16> = None;
        let mut size: Option<u32> = None;

        for pred_obj in &stmt.predicate_objects {
            let pred = expand_iri(&pred_obj.predicate, &prefix_map);
            for obj in &pred_obj.objects {
                let obj_iri_full = expand_iri(obj, &prefix_map);
                let obj_local = local_name(&obj_iri_full);
                if pred == RDFS_RANGE_FULL {
                    range_class = Some(collapse_iri(&obj_iri_full, &prefix_map));
                } else if pred == RDFS_DOMAIN_FULL {
                    // Restrict to QCL types we recognize.
                    if obj_iri_full.starts_with(QCL_NS) {
                        domain_type = Some(obj_local.to_string());
                    }
                } else if pred == QCL_ORDER_FULL {
                    let v = parse_literal_or_iri_int(obj)?;
                    order = Some(u16::try_from(v).map_err(|_| {
                        QuilError::InvalidArgument(format!(
                            "turtle: order {} out of range", v
                        ))
                    })?);
                } else if pred == QCL_SIZE_FULL {
                    let v = parse_literal_or_iri_int(obj)?;
                    size = Some(u32::try_from(v).map_err(|_| {
                        QuilError::InvalidArgument(format!(
                            "turtle: size {} out of range", v
                        ))
                    })?);
                }
            }
        }

        let Some(range) = range_class else { continue; };
        let Some(class) = schema.classes.get_mut(&range) else { continue; };

        let field_name = local_name(&subject_iri).to_string();
        // Bool has implicit size = 1 (matches Go).
        let final_size = match (size, domain_type.as_deref()) {
            (Some(s), _) => s,
            (None, Some("Bool")) => 1,
            _ => 0,
        };
        let final_order = order.unwrap_or(u16::MAX);
        if final_order != u16::MAX && final_order > schema.max_order {
            schema.max_order = final_order;
        }
        class.fields.insert(
            field_name.clone(),
            ParsedField {
                name: field_name,
                order: final_order,
                size: final_size,
                rdf_type: domain_type.unwrap_or_default(),
                range_class: range,
            },
        );
    }

    Ok(schema)
}

// ---------------------------------------------------------------------------
// Turtle micro-tokenizer
// ---------------------------------------------------------------------------

/// One predicate-object cluster.
#[derive(Debug)]
struct PredicateObjects {
    predicate: String,
    objects: Vec<String>,
}

/// One subject-multi-predicate-object statement, terminated by `.`.
#[derive(Debug)]
struct Statement {
    subject: String,
    predicate_objects: Vec<PredicateObjects>,
}

/// Tokenize a Turtle document into statements.
///
/// Recognizes: `subject pred obj1, obj2 ; pred2 obj3 . next-subject ...`
/// — the canonical subject `;`-list form Quilibrium schemas use.
/// Skips lines starting with `#`, `@prefix`, `@base`, `PREFIX`, `BASE`.
fn tokenize(document: &str) -> Result<Vec<Statement>> {
    // Strip comments + directive lines, then collapse whitespace.
    let mut filtered = String::with_capacity(document.len());
    for raw_line in document.lines() {
        let line = strip_inline_comment(raw_line.trim());
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("@prefix")
            || lower.starts_with("@base")
            || lower.starts_with("prefix ")
            || lower.starts_with("base ")
        {
            // Directive lines are end-with-`.` per spec — skip the
            // entire line. They're handled by extract_prefixes.
            continue;
        }
        filtered.push_str(line);
        filtered.push(' ');
    }

    // Split on top-level `.` while respecting `<...>` and `"..."`.
    let mut statements = Vec::new();
    let mut buf = String::new();
    let mut in_iri = false;
    let mut in_string = false;
    for c in filtered.chars() {
        match c {
            '<' if !in_string => {
                in_iri = true;
                buf.push(c);
            }
            '>' if !in_string => {
                in_iri = false;
                buf.push(c);
            }
            '"' if !in_iri => {
                in_string = !in_string;
                buf.push(c);
            }
            '.' if !in_iri && !in_string => {
                let chunk = buf.trim().to_string();
                if !chunk.is_empty() {
                    statements.push(parse_statement(&chunk)?);
                }
                buf.clear();
            }
            _ => buf.push(c),
        }
    }
    let trailing = buf.trim();
    if !trailing.is_empty() {
        statements.push(parse_statement(trailing)?);
    }
    Ok(statements)
}

fn parse_statement(text: &str) -> Result<Statement> {
    let tokens = split_tokens(text);
    if tokens.is_empty() {
        return Err(QuilError::InvalidArgument(
            "turtle: empty statement".into(),
        ));
    }
    let subject = tokens[0].clone();
    let mut predicate_objects: Vec<PredicateObjects> = Vec::new();
    let mut i = 1;
    while i < tokens.len() {
        let pred = tokens[i].clone();
        i += 1;
        let mut objs: Vec<String> = Vec::new();
        while i < tokens.len() {
            let tok = &tokens[i];
            if tok == ";" {
                i += 1;
                break;
            }
            if tok == "," {
                i += 1;
                continue;
            }
            objs.push(tok.clone());
            i += 1;
        }
        predicate_objects.push(PredicateObjects {
            predicate: pred,
            objects: objs,
        });
    }
    Ok(Statement { subject, predicate_objects })
}

/// Split a single statement (already without `.`) into tokens.
/// Tokens: `<iri>`, `prefix:local`, `"literal"`, `;`, `,`, integers.
fn split_tokens(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut buf = String::new();
    let mut in_iri = false;
    let mut in_string = false;
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            buf.push(c);
            if c == '"' && (i == 0 || chars[i - 1] != '\\') {
                in_string = false;
                out.push(std::mem::take(&mut buf));
            }
            i += 1;
            continue;
        }
        if in_iri {
            buf.push(c);
            if c == '>' {
                in_iri = false;
                out.push(std::mem::take(&mut buf));
            }
            i += 1;
            continue;
        }
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                if !buf.is_empty() {
                    out.push(std::mem::take(&mut buf));
                }
            }
            ';' | ',' => {
                if !buf.is_empty() {
                    out.push(std::mem::take(&mut buf));
                }
                out.push(c.to_string());
            }
            '<' => {
                if !buf.is_empty() {
                    out.push(std::mem::take(&mut buf));
                }
                in_iri = true;
                buf.push(c);
            }
            '"' => {
                if !buf.is_empty() {
                    out.push(std::mem::take(&mut buf));
                }
                in_string = true;
                buf.push(c);
            }
            _ => buf.push(c),
        }
        i += 1;
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

fn strip_inline_comment(line: &str) -> &str {
    // Comments start with `#` outside of strings/IRIs. Quilibrium
    // schemas don't use `#` inside literals, so a simple split is
    // sufficient.
    let mut in_iri = false;
    let mut in_string = false;
    for (idx, c) in line.char_indices() {
        match c {
            '<' if !in_string => in_iri = true,
            '>' if !in_string => in_iri = false,
            '"' if !in_iri => in_string = !in_string,
            '#' if !in_iri && !in_string => return line[..idx].trim_end(),
            _ => {}
        }
    }
    line
}

// ---------------------------------------------------------------------------
// Prefix resolution
// ---------------------------------------------------------------------------

const RDF_NS: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
const RDFS_NS: &str = "http://www.w3.org/2000/01/rdf-schema#";
const QCL_NS: &str = "https://types.quilibrium.com/qcl/";

const RDF_TYPE_FULL: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDFS_CLASS_FULL: &str = "http://www.w3.org/2000/01/rdf-schema#Class";
const RDFS_RANGE_FULL: &str = "http://www.w3.org/2000/01/rdf-schema#range";
const RDFS_DOMAIN_FULL: &str = "http://www.w3.org/2000/01/rdf-schema#domain";
const QCL_ORDER_FULL: &str = "https://types.quilibrium.com/qcl/order";
const QCL_SIZE_FULL: &str = "https://types.quilibrium.com/qcl/size";

/// Map prefix → namespace IRI.
fn extract_prefixes(document: &str) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    map.insert("rdf:".into(), RDF_NS.into());
    map.insert("rdfs:".into(), RDFS_NS.into());
    map.insert("qcl:".into(), QCL_NS.into());
    for raw_line in document.lines() {
        let line = strip_inline_comment(raw_line.trim());
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        let is_prefix =
            lower.starts_with("@prefix") || lower.starts_with("prefix ");
        if !is_prefix {
            continue;
        }
        // Format: `@prefix x: <url> .` or `PREFIX x: <url>`.
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let prefix = parts[1];
        let url_token = parts[2];
        let url = url_token.trim_matches(|c: char| c == '<' || c == '>' || c == '.');
        if url.is_empty() {
            continue;
        }
        let key = if prefix.ends_with(':') {
            prefix.to_string()
        } else {
            format!("{}:", prefix)
        };
        map.insert(key, url.to_string());
    }
    map
}

/// Expand `prefix:local` → full IRI; pass through `<...>` IRIs;
/// pass through bare literals and integers.
fn expand_iri(token: &str, prefixes: &HashMap<String, String>) -> String {
    if token.starts_with('<') && token.ends_with('>') {
        return token[1..token.len() - 1].to_string();
    }
    // Special case: `a` is shorthand for `rdf:type`.
    if token == "a" {
        return RDF_TYPE_FULL.to_string();
    }
    if let Some(idx) = token.find(':') {
        let prefix = &token[..idx + 1];
        let local = &token[idx + 1..];
        if let Some(ns) = prefixes.get(prefix) {
            return format!("{}{}", ns, local);
        }
    }
    token.to_string()
}

/// Inverse of `expand_iri`: collapse a full IRI back to
/// `prefix:local` if a prefix matches; otherwise return the local
/// part. Mirrors Go's parser which uses last-`#`/`/`-segment as the
/// class name.
fn collapse_iri(iri: &str, prefixes: &HashMap<String, String>) -> String {
    // Find the longest namespace prefix.
    let mut best: Option<(&String, &String)> = None;
    for (k, v) in prefixes {
        if iri.starts_with(v.as_str()) {
            match best {
                Some((_, ref bv)) if v.len() <= bv.len() => {}
                _ => best = Some((k, v)),
            }
        }
    }
    if let Some((prefix, ns)) = best {
        return format!("{}{}", prefix, &iri[ns.len()..]);
    }
    local_name(iri).to_string()
}

/// Return the last segment of a `#`/`/`-delimited IRI.
fn local_name(iri: &str) -> &str {
    if let Some(pos) = iri.rfind('#') {
        return &iri[pos + 1..];
    }
    if let Some(pos) = iri.rfind('/') {
        return &iri[pos + 1..];
    }
    iri
}

/// Parse an integer literal token. Accepts:
/// - bare integer: `5`
/// - quoted literal: `"5"`
/// - typed literal: `"5"^^<...>` (we ignore the type annotation)
/// - prefixed-IRI integer (e.g. `qcl:5` from Go's parser fallback)
fn parse_literal_or_iri_int(token: &str) -> Result<u64> {
    let cleaned = if token.starts_with('"') {
        // `"5"` or `"5"^^<...>`
        let end = token[1..].find('"').ok_or_else(|| QuilError::InvalidArgument(
            format!("turtle: unterminated literal '{}'", token),
        ))?;
        &token[1..1 + end]
    } else if let Some(idx) = token.rfind(':') {
        // `qcl:5` — pull out everything after the last `:`
        &token[idx + 1..]
    } else if token.starts_with('<') && token.ends_with('>') {
        let inner = &token[1..token.len() - 1];
        if let Some(p) = inner.rfind('/') {
            &inner[p + 1..]
        } else if let Some(p) = inner.rfind('#') {
            &inner[p + 1..]
        } else {
            inner
        }
    } else {
        token
    };
    cleaned.parse::<u64>().map_err(|e| QuilError::InvalidArgument(format!(
        "turtle: invalid integer '{}' (cleaned '{}'): {e}", token, cleaned
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUIL_TOKEN_SCHEMA: &str = r#"
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix qcl: <https://types.quilibrium.com/qcl/> .
@prefix config: <https://types.quilibrium.com/schema-repository/token/configuration/> .

config:TokenConfiguration a rdfs:Class .
config:Behavior a rdfs:Property ;
  rdfs:domain qcl:Uint ;
  qcl:size 2 ;
  qcl:order 0 ;
  rdfs:range config:TokenConfiguration .
config:MintStrategy a rdfs:Property ;
  rdfs:domain qcl:ByteArray ;
  qcl:size 701 ;
  qcl:order 1 ;
  rdfs:range config:TokenConfiguration .
config:Units a rdfs:Property ;
  rdfs:domain qcl:ByteArray ;
  qcl:size 32 ;
  qcl:order 2 ;
  rdfs:range config:TokenConfiguration .
config:Name a rdfs:Property ;
  rdfs:domain qcl:String ;
  qcl:size 64 ;
  qcl:order 4 ;
  rdfs:range config:TokenConfiguration .
"#;

    #[test]
    fn parses_token_configuration_class() {
        let s = parse_turtle_schema(QUIL_TOKEN_SCHEMA).unwrap();
        assert!(s.classes.contains_key("config:TokenConfiguration"));
        let class = &s.classes["config:TokenConfiguration"];
        assert_eq!(class.fields.len(), 4);
    }

    #[test]
    fn extracts_field_order_and_size() {
        let s = parse_turtle_schema(QUIL_TOKEN_SCHEMA).unwrap();
        let behavior = s.field("config:TokenConfiguration", "Behavior").unwrap();
        assert_eq!(behavior.order, 0);
        assert_eq!(behavior.size, 2);
        assert_eq!(behavior.rdf_type, "Uint");

        let mint = s.field("config:TokenConfiguration", "MintStrategy").unwrap();
        assert_eq!(mint.order, 1);
        assert_eq!(mint.size, 701);
        assert_eq!(mint.rdf_type, "ByteArray");
    }

    #[test]
    fn max_order_tracks_highest_field() {
        let s = parse_turtle_schema(QUIL_TOKEN_SCHEMA).unwrap();
        assert_eq!(s.max_order, 4);
    }

    #[test]
    fn handles_string_type() {
        let s = parse_turtle_schema(QUIL_TOKEN_SCHEMA).unwrap();
        let name = s.field("config:TokenConfiguration", "Name").unwrap();
        assert_eq!(name.rdf_type, "String");
        assert_eq!(name.size, 64);
    }

    #[test]
    fn handles_bool_implicit_size_one() {
        let schema = r#"
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix qcl: <https://types.quilibrium.com/qcl/> .
@prefix x: <https://example.com/> .

x:Foo a rdfs:Class .
x:Flag a rdfs:Property ;
  rdfs:domain qcl:Bool ;
  qcl:order 0 ;
  rdfs:range x:Foo .
"#;
        let s = parse_turtle_schema(schema).unwrap();
        let flag = s.field("x:Foo", "Flag").unwrap();
        assert_eq!(flag.size, 1);
        assert_eq!(flag.rdf_type, "Bool");
    }

    #[test]
    fn handles_comments_and_blank_lines() {
        let schema = r#"
# top comment
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix qcl: <https://types.quilibrium.com/qcl/> .
@prefix x: <https://example.com/> .

# Another comment
x:Foo a rdfs:Class . # inline comment
x:N a rdfs:Property ;
  rdfs:domain qcl:Uint ;
  qcl:size 4 ;     # size comment
  qcl:order 0 ;
  rdfs:range x:Foo .
"#;
        let s = parse_turtle_schema(schema).unwrap();
        let f = s.field("x:Foo", "N").unwrap();
        assert_eq!(f.size, 4);
        assert_eq!(f.order, 0);
    }

    #[test]
    fn rejects_invalid_size() {
        let schema = r#"
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix qcl: <https://types.quilibrium.com/qcl/> .
@prefix x: <https://example.com/> .

x:Foo a rdfs:Class .
x:N a rdfs:Property ;
  rdfs:domain qcl:Uint ;
  qcl:size notanumber ;
  qcl:order 0 ;
  rdfs:range x:Foo .
"#;
        assert!(parse_turtle_schema(schema).is_err());
    }

    #[test]
    fn handles_quoted_integer_literals() {
        let schema = r#"
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix qcl: <https://types.quilibrium.com/qcl/> .
@prefix x: <https://example.com/> .

x:Foo a rdfs:Class .
x:N a rdfs:Property ;
  rdfs:domain qcl:Uint ;
  qcl:size "8" ;
  qcl:order "3" ;
  rdfs:range x:Foo .
"#;
        let s = parse_turtle_schema(schema).unwrap();
        let f = s.field("x:Foo", "N").unwrap();
        assert_eq!(f.size, 8);
        assert_eq!(f.order, 3);
    }

    #[test]
    fn empty_document_yields_empty_schema() {
        let s = parse_turtle_schema("").unwrap();
        assert!(s.classes.is_empty());
        assert_eq!(s.max_order, 0);
    }

    #[test]
    fn schema_with_only_directives_yields_no_classes() {
        let s = parse_turtle_schema(
            "@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .",
        )
        .unwrap();
        assert!(s.classes.is_empty());
    }
}
