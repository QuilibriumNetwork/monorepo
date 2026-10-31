//! Commenting out the settings of earlier releases in an operator's
//! config, for `qclient node config clean`.
//!
//! A line editor, so every other line, comment and the key order stay as
//! written. It comments out the retired keys [`unused_keys`] names, the
//! same ones the node lists at startup, each with its whole value; keys it
//! does not know (possible typos) and qclient's `alias` section stay. Each
//! result is verified by parsing it again: it must load, name no retired
//! key and keep every other value. YAML the editor cannot change safely
//! (anchors, aliases or tags on a retired key, a flow collection spanning
//! lines, a retired key inside a flow mapping) is refused, unchanged.

use serde_yaml::Value;

use crate::{unused_keys, Config, UnusedKey};

/// The prefix of each commented-out line.
pub const OBSOLETE_PREFIX: &str = "# obsolete, no effect: ";

/// A retired key that was commented out, with its 1-based line range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanedKey {
    pub path: String,
    pub first_line: usize,
    pub last_line: usize,
}

/// The cleaned config text and the keys commented out in it, in file
/// order; no keys when there was nothing to clean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanedConfig {
    pub contents: String,
    pub keys: Vec<CleanedKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CleanError {
    #[error("the config does not parse: {0}")]
    Parse(String),
    #[error("cannot safely comment out {key}: {reason}; nothing was changed, edit it by hand")]
    Unsafe { key: String, reason: String },
    #[error("the cleaned config failed verification: {0}")]
    Verification(String),
}

/// `contents` with every retired key and its value commented out.
pub fn clean_retired_keys(contents: &str) -> Result<CleanedConfig, CleanError> {
    serde_yaml::from_str::<Config>(contents).map_err(|e| CleanError::Parse(e.to_string()))?;
    let retired = retired_paths(contents);
    if retired.is_empty() {
        return Ok(CleanedConfig {
            contents: contents.to_string(),
            keys: Vec::new(),
        });
    }
    let lines = split_lines(contents);
    let scan = scan(&lines);
    let refuse = |key: &str, reason: &str| CleanError::Unsafe {
        key: key.to_string(),
        reason: reason.to_string(),
    };
    let mut commented = vec![false; lines.len()];
    let mut keys = Vec::new();
    for path in &retired {
        let key = scan
            .keys
            .iter()
            .find(|key| &key.path == path)
            .ok_or_else(|| refuse(path.as_str(), "it is not a plain key on a line of its own"))?;
        let last = block_end(&lines, &scan, key.line, key.indent);
        if (key.line..=last).any(|j| scan.flow_start[j]) {
            return Err(refuse(
                path.as_str(),
                "its value is a flow collection spanning lines",
            ));
        }
        let own_value = &lines[key.line].text[key.value_offset..];
        let properties = has_node_property(own_value)
            || (key.line + 1..=last).any(|j| {
                !scan.continuation[j] && has_node_property(lines[j].text.trim_start_matches(' '))
            });
        if properties {
            return Err(refuse(path.as_str(), "it uses a YAML anchor, alias or tag"));
        }
        for j in key.line..=last {
            commented[j] = is_content(&lines[j], scan.continuation[j]);
        }
        keys.push(CleanedKey {
            path: path.clone(),
            first_line: key.line + 1,
            last_line: last + 1,
        });
    }
    // A section left without settings becomes `{}`, as an empty mapping
    // still loads where an empty value would not.
    let mut emptied = Vec::new();
    for path in &retired {
        let Some((parent, _)) = path.rsplit_once('.') else {
            continue;
        };
        let section = scan
            .keys
            .iter()
            .find(|key| key.path == parent)
            .ok_or_else(|| {
                refuse(
                    path.as_str(),
                    "its section is not a plain key on a line of its own",
                )
            })?;
        let last = block_end(&lines, &scan, section.line, section.indent);
        let remains = (section.line + 1..=last)
            .any(|j| !commented[j] && is_content(&lines[j], scan.continuation[j]));
        if !remains && !emptied.contains(&section.line) {
            let value = lines[section.line].text[section.value_offset..].trim_start();
            if !(value.is_empty() || value.starts_with('#')) {
                return Err(refuse(
                    path.as_str(),
                    "it is the only setting of a section with an unusual form",
                ));
            }
            emptied.push(section.line);
        }
    }
    let mut out = String::with_capacity(contents.len() + 32 * retired.len());
    for (j, line) in lines.iter().enumerate() {
        if commented[j] {
            let indent = indent_of(line.text);
            out.push_str(&line.text[..indent]);
            out.push_str(OBSOLETE_PREFIX);
            out.push_str(&line.text[indent..]);
        } else if emptied.contains(&j) {
            let offset = scan
                .keys
                .iter()
                .find(|key| key.line == j)
                .map_or(line.text.len(), |key| key.value_offset);
            out.push_str(&line.text[..offset]);
            out.push_str(" {}");
            out.push_str(&line.text[offset..]);
        } else {
            out.push_str(line.text);
        }
        out.push_str(line.eol);
    }
    verify_cleaned(contents, &out, &retired)?;
    keys.sort_by_key(|key| key.first_line);
    Ok(CleanedConfig {
        contents: out,
        keys,
    })
}

/// Checks that `cleaned` loads, names no retired key and equals
/// `original` without the `removed` key paths.
pub fn verify_cleaned(original: &str, cleaned: &str, removed: &[String]) -> Result<(), CleanError> {
    let fail = |reason: String| CleanError::Verification(reason);
    serde_yaml::from_str::<Config>(cleaned)
        .map_err(|e| fail(format!("it no longer loads: {e}")))?;
    if let Some(left) = retired_paths(cleaned).first() {
        return Err(fail(format!("{left} is still set")));
    }
    let mut expected: Value = serde_yaml::from_str(original).map_err(|e| fail(e.to_string()))?;
    for path in removed {
        if !remove_path(&mut expected, path) {
            return Err(fail(format!("{path} is not in the original")));
        }
    }
    let actual: Value = serde_yaml::from_str(cleaned).map_err(|e| fail(e.to_string()))?;
    if expected != actual {
        return Err(fail("another setting changed".to_string()));
    }
    Ok(())
}

fn retired_paths(contents: &str) -> Vec<String> {
    unused_keys(contents)
        .into_iter()
        .filter_map(|key| {
            if let UnusedKey::Retired(path) = key {
                Some(path)
            } else {
                None
            }
        })
        .collect()
}

fn remove_path(value: &mut Value, path: &str) -> bool {
    let Value::Mapping(mapping) = value else {
        return false;
    };
    match path.split_once('.') {
        None => mapping.remove(path).is_some(),
        Some((head, rest)) => mapping
            .get_mut(head)
            .is_some_and(|child| remove_path(child, rest)),
    }
}

/// A line without its ending, and the ending (`\n`, `\r\n` or none).
struct Line<'a> {
    text: &'a str,
    eol: &'a str,
}

fn split_lines(contents: &str) -> Vec<Line<'_>> {
    contents
        .split_inclusive('\n')
        .map(|piece| {
            let body = piece.strip_suffix('\n').unwrap_or(piece);
            let len = body.strip_suffix('\r').unwrap_or(body).len();
            Line {
                text: &piece[..len],
                eol: &piece[len..],
            }
        })
        .collect()
}

fn indent_of(text: &str) -> usize {
    text.len() - text.trim_start_matches(' ').len()
}

/// A non-blank line that is not a comment, or a non-blank line of a
/// multi-line value.
fn is_content(line: &Line<'_>, continuation: bool) -> bool {
    let trimmed = line.text.trim_start_matches(' ');
    !trimmed.trim().is_empty() && (continuation || !trimmed.starts_with('#'))
}

/// A mapping key on a line of its own.
struct KeyLine {
    line: usize,
    indent: usize,
    path: String,
    /// Byte offset of the text after the key's colon.
    value_offset: usize,
}

struct Scan {
    keys: Vec<KeyLine>,
    /// Lines inside a multi-line value started on an earlier line.
    continuation: Vec<bool>,
    /// Lines whose value opens a flow collection closed on a later line.
    flow_start: Vec<bool>,
}

/// How the lines after a value continue it.
#[derive(Clone, Copy)]
enum Continues {
    No,
    /// A block scalar, more indented than its key.
    Block(usize),
    /// A flow collection at this bracket depth.
    Flow(i64),
    /// A quoted scalar not yet closed.
    Quoted(char),
}

fn scan(lines: &[Line<'_>]) -> Scan {
    let mut keys = Vec::new();
    let mut continuation = vec![false; lines.len()];
    let mut flow_start = vec![false; lines.len()];
    let mut parents: Vec<(usize, String)> = Vec::new();
    let mut continues = Continues::No;
    for (j, line) in lines.iter().enumerate() {
        let text = line.text;
        let trimmed = text.trim_start_matches(' ');
        let indent = text.len() - trimmed.len();
        match continues {
            Continues::Block(parent) => {
                if trimmed.trim().is_empty() || indent > parent {
                    continuation[j] = true;
                    continue;
                }
                continues = Continues::No;
            }
            Continues::Flow(depth) => {
                continuation[j] = true;
                let depth = depth + flow_depth(text);
                continues = if depth > 0 {
                    Continues::Flow(depth)
                } else {
                    Continues::No
                };
                continue;
            }
            Continues::Quoted(quote) => {
                continuation[j] = true;
                if closing_quote(text, quote, 0).is_some() {
                    continues = Continues::No;
                }
                continue;
            }
            Continues::No => {}
        }
        if trimmed.trim().is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if indent == 0 && (trimmed.starts_with("---") || trimmed.starts_with("...")) {
            parents.clear();
            continue;
        }
        let (value, value_indent) = if trimmed == "-" || trimmed.starts_with("- ") {
            while parents.last().is_some_and(|(parent, _)| *parent > indent) {
                parents.pop();
            }
            (&trimmed[1..], indent)
        } else if let Some((key, rest)) = parse_key(trimmed) {
            while parents.last().is_some_and(|(parent, _)| *parent >= indent) {
                parents.pop();
            }
            let path = parents
                .iter()
                .map(|(_, name)| name.as_str())
                .chain([key.as_str()])
                .collect::<Vec<_>>()
                .join(".");
            keys.push(KeyLine {
                line: j,
                indent,
                path,
                value_offset: text.len() - rest.len(),
            });
            parents.push((indent, key));
            (rest, indent)
        } else {
            continue;
        };
        continues = continues_after(value, value_indent);
        if matches!(continues, Continues::Flow(_)) {
            flow_start[j] = true;
        }
    }
    Scan {
        keys,
        continuation,
        flow_start,
    }
}

fn continues_after(value: &str, indent: usize) -> Continues {
    let value = value.trim_start();
    match value.chars().next() {
        Some('|') | Some('>') => Continues::Block(indent),
        Some('[') | Some('{') => match flow_depth(value) {
            depth if depth > 0 => Continues::Flow(depth),
            _ => Continues::No,
        },
        Some(quote @ ('"' | '\'')) if closing_quote(value, quote, 1).is_none() => {
            Continues::Quoted(quote)
        }
        _ => Continues::No,
    }
}

/// The last line of the value of the key on line `start`.
fn block_end(lines: &[Line<'_>], scan: &Scan, start: usize, key_indent: usize) -> usize {
    let mut last = start;
    for j in start + 1..lines.len() {
        let trimmed = lines[j].text.trim_start_matches(' ');
        if scan.continuation[j] {
            if !trimmed.trim().is_empty() {
                last = j;
            }
            continue;
        }
        if trimmed.trim().is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = lines[j].text.len() - trimmed.len();
        if indent > key_indent
            || (indent == key_indent && (trimmed == "-" || trimmed.starts_with("- ")))
        {
            last = j;
            continue;
        }
        break;
    }
    last
}

/// The key and the text after its colon, for a line holding a plain,
/// double- or single-quoted key.
fn parse_key(trimmed: &str) -> Option<(String, &str)> {
    let (key, after) = match trimmed.chars().next()? {
        '"' => {
            let end = closing_quote(trimmed, '"', 1)?;
            (
                trimmed[1..end].replace("\\\"", "\"").replace("\\\\", "\\"),
                &trimmed[end + 1..],
            )
        }
        '\'' => {
            let end = closing_quote(trimmed, '\'', 1)?;
            (trimmed[1..end].replace("''", "'"), &trimmed[end + 1..])
        }
        first if "-?:,[]{}#&*!|>%@`".contains(first) => return None,
        _ => {
            let colon = plain_key_colon(trimmed)?;
            (trimmed[..colon].trim_end().to_string(), &trimmed[colon..])
        }
    };
    let rest = after.trim_start_matches(' ').strip_prefix(':')?;
    (rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t')).then_some((key, rest))
}

fn plain_key_colon(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    for (i, byte) in bytes.iter().enumerate() {
        let next_blank = matches!(bytes.get(i + 1), None | Some(b' ') | Some(b'\t'));
        let prev_blank = i > 0 && matches!(bytes[i - 1], b' ' | b'\t');
        match *byte {
            b':' if next_blank => return Some(i),
            b'#' if prev_blank => return None,
            _ => {}
        }
    }
    None
}

/// The byte index of the quote closing a scalar opened before `from`.
fn closing_quote(text: &str, quote: char, from: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut i = from;
    while i < bytes.len() {
        match (quote, bytes[i]) {
            ('"', b'\\') => i += 2,
            ('"', b'"') => return Some(i),
            ('\'', b'\'') if bytes.get(i + 1) == Some(&b'\'') => i += 2,
            ('\'', b'\'') => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// Brackets opened minus brackets closed on a line, outside quotes and
/// comments.
fn flow_depth(text: &str) -> i64 {
    let mut depth = 0;
    let mut quote: Option<char> = None;
    let mut prev = ' ';
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some('"') => {
                if c == '\\' {
                    chars.next();
                } else if c == '"' {
                    quote = None;
                }
            }
            Some(_) => {
                if c == '\'' {
                    if chars.peek() == Some(&'\'') {
                        chars.next();
                    } else {
                        quote = None;
                    }
                }
            }
            None => match c {
                '#' if prev == ' ' || prev == '\t' => break,
                '"' | '\'' if matches!(prev, ' ' | '\t' | '[' | '{' | ',' | ':') => quote = Some(c),
                '[' | '{' => depth += 1,
                ']' | '}' => depth -= 1,
                _ => {}
            },
        }
        prev = c;
    }
    depth
}

/// Whether a value starts a token with an anchor (`&`), alias (`*`) or
/// tag (`!`), outside quotes and comments.
fn has_node_property(text: &str) -> bool {
    let mut quote: Option<char> = None;
    let mut at_token = true;
    for c in text.chars() {
        if let Some(open) = quote {
            if c == open {
                quote = None;
            }
            at_token = false;
            continue;
        }
        match c {
            '#' if at_token => return false,
            '&' | '*' | '!' if at_token => return true,
            '"' | '\'' if at_token => quote = Some(c),
            _ => {}
        }
        at_token = matches!(c, ' ' | '\t' | '[' | '{' | ',' | '-' | ':');
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The input and the expected output of a fixture whose lines to be
    /// commented out start with `!`.
    fn fixture(marked: &str) -> (String, String) {
        let marked = marked.strip_prefix('\n').unwrap_or(marked);
        let (mut input, mut expected) = (String::new(), String::new());
        for line in marked.split_inclusive('\n') {
            match line.strip_prefix('!') {
                Some(rest) => {
                    input.push_str(rest);
                    let indent = indent_of(rest);
                    expected.push_str(&rest[..indent]);
                    expected.push_str(OBSOLETE_PREFIX);
                    expected.push_str(&rest[indent..]);
                }
                None => {
                    input.push_str(line);
                    expected.push_str(line);
                }
            }
        }
        (input, expected)
    }

    fn assert_cleans(input: &str, expected: &str, paths: &[&str]) -> CleanedConfig {
        let cleaned = clean_retired_keys(input).unwrap();
        assert_eq!(cleaned.contents, expected);
        assert_eq!(
            cleaned
                .keys
                .iter()
                .map(|key| key.path.as_str())
                .collect::<Vec<_>>(),
            paths
        );
        let again = clean_retired_keys(&cleaned.contents).unwrap();
        assert_eq!(
            (again.contents.as_str(), again.keys.len()),
            (expected, 0),
            "a second run has nothing to clean"
        );
        cleaned
    }

    /// A config the Rust node wrote before these settings were removed:
    /// two-space indentation, sequences at their key's indentation and
    /// nested sections under retired keys.
    #[test]
    fn cleans_a_generated_config() {
        let (input, expected) = fixture(
            r#"
key:
!  keyManagerType: file
  keyManagerFile:
    path: keys.yml
    createIfMissing: true
    encryptionKey: '00'
p2p:
!  d: 0
  dLo: 0
  bootstrapPeers:
  - /ip4/192.0.2.1/udp/8336/quic-v1/p2p/QmA
!  connectors: 0
  network: 0
engine:
  provingKeyId: default-proving-key
!  filter: ''
  dataWorkerFilters: []
!  syncMessageLimits:
!    maxRecvMsgSize: 67108864
!    maxSendMsgSize: 67108864
!  framePublish:
!    mode: full
!    threshold: 1048576
!    fragmentation:
!      algorithm: reed-solomon
!      reedSolomon:
!        dataShards: 224
!        parityShards: 32
!    ballastSize: 0
  archiveMode: false
logger:
  path: ''
  logFilters: {}
listenGrpcMultiaddr: /ip4/127.0.0.1/tcp/8337
!listenRESTMultiaddr: ''
"#,
        );
        let cleaned = assert_cleans(
            &input,
            &expected,
            &[
                "key.keyManagerType",
                "p2p.d",
                "p2p.connectors",
                "engine.filter",
                "engine.syncMessageLimits",
                "engine.framePublish",
                "listenRESTMultiaddr",
            ],
        );
        let frame_publish = &cleaned.keys[5];
        assert_eq!(
            (frame_publish.first_line, frame_publish.last_line),
            (21, 29)
        );
    }

    /// A config migrated from the Go node: comments, blank lines, Go
    /// durations, a key the node does not know and qclient's `alias`
    /// section, which all stay.
    #[test]
    fn cleans_a_go_migrated_config_and_keeps_unknown_keys() {
        let (input, expected) = fixture(
            r#"
# Peer id: QmA
alias: null
key:
!  keyManagerType: file
  keyManagerFile:
    path: keys.yml
    createIfMissing: false
    encryptionKey: "00"
p2p:
!  d: 0
  dLo: 0
!  maxIHaveLength: 0
  heartbeatInterval: 0s
!  pingTimeout: 0s
  bootstrapPeers:
  - /dns/proxy/udp/8336/quic-v1
  listenMultiaddr: /ip4/0.0.0.0/udp/8336/quic-v1
!  minBootstrapPeers: 1
  reportPeerInfoInterval: 5s
  network: 1
engine:
  provingKeyId: default-proving-key
  # Concatenated keys
  genesisSeed: "00"
!  pendingCommitWorkers: 4
!  syncTimeout: 0s
!  syncMessageLimits:
!    maxRecvMsgSize: 0
!    maxSendMsgSize: 0
!  allowExcessiveGOMAXPROCS: false
  archiveMode: true

!  rebuildstart: ""
!  framePublish:
!    mode: ""
!    fragmentation:
!      reedSolomon:
!        dataShards: 0
db:
  path: .config/store
!  inmemorydonotuse: false
logger: null
listenGrpcMultiaddr: /ip4/0.0.0.0/tcp/8337
!listenRESTMultiaddr: /ip4/0.0.0.0/tcp/8338
"#,
        );
        let cleaned = assert_cleans(
            &input,
            &expected,
            &[
                "key.keyManagerType",
                "p2p.d",
                "p2p.maxIHaveLength",
                "p2p.pingTimeout",
                "p2p.minBootstrapPeers",
                "engine.pendingCommitWorkers",
                "engine.syncTimeout",
                "engine.syncMessageLimits",
                "engine.allowExcessiveGOMAXPROCS",
                "engine.rebuildstart",
                "engine.framePublish",
                "db.inmemorydonotuse",
                "listenRESTMultiaddr",
            ],
        );
        assert_eq!(
            unused_keys(&cleaned.contents),
            vec![UnusedKey::Unknown("p2p.reportPeerInfoInterval".into())]
        );
    }

    /// Four-space indentation, quoted keys, block and multi-line quoted
    /// scalars (whose lines may look like keys), sequences and one-line
    /// flow values under retired keys.
    #[test]
    fn cleans_multi_line_and_flow_values() {
        let (input, expected) = fixture(
            r#"
p2p:
    network: 1
!    "connectors": 8
!    traceLogFile: |
!        line one
!        d: not a key

!        line three
    dLo: 6
!    directConnectTicks: >-
!        folded
engine:
!    filter: "multi
!        line"
!    dataWorkerMultiaddrs:
!    - /ip4/192.0.2.1/tcp/1
!    -   /ip4/192.0.2.2/tcp/2
!    syncMessageLimits: {maxRecvMsgSize: 0, maxSendMsgSize: 0}
!    rewardsAddress: [a, b]   # trailing comment
    archiveMode: true
"#,
        );
        assert_cleans(
            &input,
            &expected,
            &[
                "p2p.connectors",
                "p2p.traceLogFile",
                "p2p.directConnectTicks",
                "engine.filter",
                "engine.dataWorkerMultiaddrs",
                "engine.syncMessageLimits",
                "engine.rewardsAddress",
            ],
        );
    }

    /// CRLF line endings stay, and a retired key on a last line without a
    /// newline is commented out.
    #[test]
    fn keeps_crlf_endings_and_a_last_line_without_newline() {
        let input = "p2p:\r\n  network: 1\r\n  d: 8\r\nengine:\r\n  archiveMode: true\r\n  rewardsAddress: abc";
        let expected = format!(
            "p2p:\r\n  network: 1\r\n  {OBSOLETE_PREFIX}d: 8\r\nengine:\r\n  archiveMode: true\r\n  {OBSOLETE_PREFIX}rewardsAddress: abc"
        );
        assert_cleans(input, &expected, &["p2p.d", "engine.rewardsAddress"]);
    }

    /// A section whose only settings are retired becomes an empty mapping,
    /// keeping its comment, so the config still loads.
    #[test]
    fn a_section_left_empty_becomes_an_empty_mapping() {
        let input = "key:   # keys\n  keyManagerType: file\np2p:\n  network: 1\n";
        let expected = format!(
            "key: {{}}   # keys\n  {OBSOLETE_PREFIX}keyManagerType: file\np2p:\n  network: 1\n"
        );
        assert_cleans(input, &expected, &["key.keyManagerType"]);
    }

    /// Nothing to clean leaves the text as it is, unknown keys included.
    #[test]
    fn a_config_without_retired_keys_is_unchanged() {
        let input = "p2p:\n  network: 1\n  bootstrapPeer: x\nalias:\n  aliasFile: {path: a.yml}\n";
        assert_eq!(
            clean_retired_keys(input).unwrap(),
            CleanedConfig {
                contents: input.to_string(),
                keys: Vec::new()
            }
        );
        assert!(matches!(
            clean_retired_keys("p2p: [unclosed"),
            Err(CleanError::Parse(_))
        ));
    }

    /// YAML the line editor cannot change safely is refused, naming the key.
    #[test]
    fn refuses_anchors_aliases_tags_and_flow_collections() {
        for (input, key) in [
            ("p2p:\n  network: 1\n  d: &degree 8\n", "p2p.d"),
            ("p2p:\n  dLo: &degree 6\n  dHi: *degree\n", "p2p.dHi"),
            ("p2p:\n  d: !!int 8\n", "p2p.d"),
            (
                "engine:\n  framePublish:\n    mode: &mode full\n",
                "engine.framePublish",
            ),
            (
                "engine:\n  syncMessageLimits: {maxRecvMsgSize: 0,\n    maxSendMsgSize: 0}\n",
                "engine.syncMessageLimits",
            ),
            ("p2p: {network: 1, d: 8}\n", "p2p.d"),
        ] {
            match clean_retired_keys(input) {
                Err(CleanError::Unsafe { key: refused, .. }) => assert_eq!(refused, key, "{input}"),
                other => panic!("{input}: {other:?}"),
            }
        }
    }

    /// Verification catches a changed value or a retired key left set.
    #[test]
    fn verification_rejects_other_changes() {
        let original = "p2p:\n  network: 1\n  d: 8\n";
        let removed = vec!["p2p.d".to_string()];
        assert_eq!(
            verify_cleaned(original, "p2p:\n  network: 1\n", &removed),
            Ok(())
        );
        assert!(matches!(
            verify_cleaned(original, "p2p:\n  network: 2\n", &removed),
            Err(CleanError::Verification(_))
        ));
        assert!(matches!(
            verify_cleaned(original, original, &removed),
            Err(CleanError::Verification(_))
        ));
        assert!(matches!(
            verify_cleaned(original, "p2p: [", &removed),
            Err(CleanError::Verification(_))
        ));
    }
}
