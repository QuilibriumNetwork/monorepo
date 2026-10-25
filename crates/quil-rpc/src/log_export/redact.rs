//! Redaction of personal data from node log lines, for log exports:
//! `qclient node log export` and the bundles of peers' log requests.
//!
//! Pure: no I/O. A [`Redactor`] replaces each sensitive value with a token
//! `<class>#<8 hex>` (first 4 bytes of HMAC-SHA256 over the class and the
//! value, keyed by a per-export random salt), so equal values stay
//! correlatable within one export but not across exports. Classes:
//!
//! * `ip4`, `ip6` — IP addresses (ports are kept: `ip4#…:8340`), also as
//!   `/ip4/…` and `/ip6/…` multiaddr components;
//! * `dns` — `/dns*/…` multiaddr hosts;
//! * `peer` — libp2p peer IDs (`Qm…`, `12D3KooW…`, `16Uiu2HA…`);
//! * `path` — absolute home paths (`/home/<user>/…`, `/Users/<user>/…`,
//!   `/root/…`), keeping the last segment: `path#…/<basename>`;
//! * `key` — Falcon public keys: `FalconPublicKey(key#…)`;
//! * `host`, `user` — literal host and user names supplied by the caller;
//! * `balance` — reward balances (JSON keys [`BALANCE_KEYS`]), whose
//!   values become `"<removed>"`;
//! * `self:peer`, `self:prover` — this node's own identity (JSON keys
//!   [`SELF_KEYS`]), unless `keep_self`.
//!
//! Shard filters and other hex, frame numbers, versions, timestamps, levels
//! and callsites are kept. Public endpoints (the mainnet bootstrap archive
//! peers) keep their IPs and peer IDs, as do loopback/unspecified addresses.
//! The policy is the same in every field and message: an archive endpoint
//! stays wherever it occurs (`addr`, `peer`, free text), including a
//! `peer` field naming a bootstrap archive; any other peer ID or address is
//! tokenized.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use regex::{Captures, Regex};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// JSON keys whose values are reward balances; their values are removed.
pub const BALANCE_KEYS: &[&str] = &["delta", "new_balance", "balance"];

/// JSON keys whose values identify this node (tokenized as `self:…`).
pub const SELF_KEYS: &[&str] = &["prover_address", "peer_id", "ed448_peer_id"];

/// Replacement for removed values.
pub const REMOVED: &str = "<removed>";

/// Words that occur in ordinary log text (or are token classes) and are
/// therefore never redacted as a host or user name.
const COMMON_WORDS: &[&str] = &[
    "localhost", "root", "node", "user", "admin", "host", "server", "test", "quil", "quilibrium",
    "prover", "worker", "master", "archive", "global", "shard", "frame", "peer", "path", "key",
    "self", "dns", "ip4", "ip6", "removed", "balance",
];

/// Characters of an absolute path as the path sweep reads it.
fn is_path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'@' | b'~' | b'/' | b'-')
}

/// What to redact beyond the built-in classes, and what to keep.
#[derive(Debug, Clone, Default)]
pub struct RedactOptions {
    /// Keep this node's own identity values instead of tokenizing them.
    pub keep_self: bool,
    /// Multiaddrs of public endpoints whose IPs and peer IDs are kept (the
    /// upstream bootstrap list).
    pub public_endpoints: Vec<String>,
    /// Literal words to tokenize wherever they occur as a whole word, as
    /// `(class, word)`, e.g. `("host", <host name>)`. Short or common words
    /// are ignored.
    pub literals: Vec<(&'static str, String)>,
}

impl RedactOptions {
    /// Options keeping the upstream mainnet bootstrap archive endpoints.
    pub fn with_bootstrap_endpoints(keep_self: bool) -> Self {
        RedactOptions {
            keep_self,
            public_endpoints: quil_config::MAINNET_BOOTSTRAP_PEERS.iter().map(|s| s.to_string()).collect(),
            literals: Vec::new(),
        }
    }
}

/// HMAC-SHA256 of the concatenation of `parts` under `key` (RFC 2104).
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    for part in parts {
        inner.update(part);
    }
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

/// The token of `value` in `class` under `salt`: `<class>#<8 hex>`.
pub fn token(salt: &[u8; 32], class: &str, value: &str) -> String {
    let mac = hmac_sha256(salt, &[class.as_bytes(), &[0u8][..], value.as_bytes()]);
    format!("{class}#{}", hex::encode(&mac[..4]))
}

/// The class of a self-identity key's value.
fn self_class(key: &str) -> &'static str {
    if key == "prover_address" {
        "prover"
    } else {
        "peer"
    }
}

/// Compiled patterns of the text sweep.
struct Patterns {
    path: Regex,
    falcon_array: Regex,
    falcon_hex: Regex,
    multiaddr: Regex,
    ip6_bracket: Regex,
    ip4: Regex,
    ip6_bare: Regex,
    peer: Regex,
    raw_balance: Regex,
    raw_self: Regex,
}

impl Patterns {
    fn new() -> Self {
        let re = |s: &str| Regex::new(s).expect("valid redaction pattern");
        Patterns {
            path: re(r"(?:/home/|/Users/)[A-Za-z0-9._+@~-]+[A-Za-z0-9._+@~/-]*|/root(?:/[A-Za-z0-9._+@~/-]*)?"),
            falcon_array: re(r"FalconPublicKey\(\[([0-9,\s]*)\]\)"),
            falcon_hex: re(r"FalconPublicKey\(([0-9A-Fa-f]{16,})(?:…|\.\.\.)?\)"),
            multiaddr: re(r#"/(ip4|ip6|dns|dns4|dns6|dnsaddr)/([^/\s"'\\,;)\]}]+)"#),
            ip6_bracket: re(r"\[([0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*)(%[0-9A-Za-z]+)?\]"),
            ip4: re(r"\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b"),
            ip6_bare: re(r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}"),
            // No `\b` anchors: `_` is a word byte, so `peer_<id>` and `<id>_x`
            // (labels glued to an ID by a logging format) must still match.
            peer: re(r"(?:Qm[1-9A-HJ-NP-Za-km-z]{44}|12D3KooW[1-9A-HJ-NP-Za-km-z]{44}|16Uiu2HA[1-9A-HJ-NP-Za-km-z]{45})"),
            raw_balance: re(r#""(delta|new_balance|balance)"\s*:\s*(?:"(?:[^"\\]|\\.)*"|[-+0-9.eE]+)"#),
            raw_self: re(r#""(prover_address|peer_id|ed448_peer_id)"\s*:\s*"([^"\\]*)""#),
        }
    }
}

/// Mutable redaction state: salt, kept values, token map and counts.
struct State {
    salt: [u8; 32],
    keep_self: bool,
    kept: HashSet<String>,
    self_values: HashMap<String, &'static str>,
    literals: Vec<(&'static str, String)>,
    map: BTreeMap<String, String>,
    counts: BTreeMap<String, u64>,
    unparseable: u64,
}

impl State {
    /// Tokenize `value` in `class` (as `self:<class>#…` when `self_tag`),
    /// recording the token and counting the replacement.
    fn token(&mut self, class: &str, value: &str, self_tag: bool) -> String {
        let plain = token(&self.salt, class, value);
        let (tok, counted) = if self_tag {
            (format!("self:{plain}"), format!("self:{class}"))
        } else {
            (plain, class.to_string())
        };
        *self.counts.entry(counted).or_insert(0) += 1;
        self.map.entry(tok.clone()).or_insert_with(|| value.to_string());
        tok
    }

    /// Count one replacement without a token (removed values).
    fn count(&mut self, class: &str) {
        *self.counts.entry(class.to_string()).or_insert(0) += 1;
    }

    /// Record `value` of self-identity `key` as this node's.
    fn learn_self(&mut self, key: &str, value: &str) {
        if value.is_empty() {
            return;
        }
        self.self_values.insert(value.to_string(), self_class(key));
        if self.keep_self {
            self.kept.insert(value.to_string());
        }
    }

    /// The replacement of self-identity `value` under `key`, or `None` to
    /// keep it.
    fn self_token(&mut self, key: &str, value: &str) -> Option<String> {
        self.learn_self(key, value);
        if self.keep_self || value.is_empty() {
            return None;
        }
        Some(self.token(self_class(key), value, true))
    }

    /// The replacement of a swept `value` in `class`, or `None` to keep it
    /// (public endpoints, `--keep-self`).
    fn sweep_token(&mut self, class: &str, value: &str) -> Option<String> {
        if self.kept.contains(value) {
            return None;
        }
        let self_tag = self.self_values.get(value).is_some_and(|c| *c == class);
        Some(self.token(class, value, self_tag))
    }
}

/// Redacts node log lines; see the module documentation.
pub struct Redactor {
    pats: Patterns,
    st: State,
}

impl Redactor {
    /// A redactor tokenizing under `salt`.
    pub fn new(salt: [u8; 32], opts: RedactOptions) -> Self {
        let mut kept = HashSet::new();
        for addr in &opts.public_endpoints {
            let parts: Vec<&str> = addr.split('/').collect();
            for pair in parts.windows(2) {
                if matches!(pair[0], "ip4" | "ip6" | "p2p") && !pair[1].is_empty() {
                    kept.insert(pair[1].to_string());
                }
            }
        }
        let literals = opts
            .literals
            .into_iter()
            .filter(|(_, w)| w.len() >= 3 && !COMMON_WORDS.contains(&w.to_ascii_lowercase().as_str()))
            .collect();
        Redactor {
            pats: Patterns::new(),
            st: State {
                salt,
                keep_self: opts.keep_self,
                kept,
                self_values: HashMap::new(),
                literals,
                map: BTreeMap::new(),
                counts: BTreeMap::new(),
                unparseable: 0,
            },
        }
    }

    /// Replacements made so far, per class (`ip4`, `self:peer`, `balance`, …).
    pub fn counts(&self) -> &BTreeMap<String, u64> {
        &self.st.counts
    }

    /// Total replacements made so far.
    pub fn total(&self) -> u64 {
        self.st.counts.values().sum()
    }

    /// Distinct tokenized values so far, per class.
    pub fn distinct(&self) -> BTreeMap<String, u64> {
        let mut out = BTreeMap::new();
        for tok in self.st.map.keys() {
            let class = tok.split('#').next().unwrap_or("").to_string();
            *out.entry(class).or_insert(0) += 1;
        }
        out
    }

    /// Lines whose JSON field block was missing or unparseable (and was
    /// redacted by the text sweep instead).
    pub fn unparseable(&self) -> u64 {
        self.st.unparseable
    }

    /// Token → original value. Private: never part of a shared bundle.
    pub fn token_map(&self) -> &BTreeMap<String, String> {
        &self.st.map
    }

    /// Redact one log line: a node line
    /// `TIMESTAMP\tLEVEL\tCALLER\tMESSAGE\t{json}` has its message swept and
    /// its JSON fields redacted by key and value; any other line (a
    /// continuation of a multi-line message) is swept as text.
    pub fn redact_line(&mut self, line: &str) -> String {
        if parse_log_timestamp(line).is_none() {
            return self.redact_text(line);
        }
        let cols: Vec<&str> = line.splitn(4, '\t').collect();
        if cols.len() < 4 {
            self.st.unparseable += 1;
            return self.redact_text(line);
        }
        let (ts, level, caller, rest) = (cols[0], cols[1], cols[2], cols[3]);
        let (message, tail) = match rest.rsplit_once('\t') {
            Some((m, t)) => (m, Some(t)),
            None => (rest, None),
        };
        let parsed = tail.and_then(|t| match serde_json::from_str::<Value>(t) {
            Ok(v @ Value::Object(_)) => Some(v),
            _ => None,
        });
        match (tail, parsed) {
            (_, Some(mut fields)) => {
                self.learn_self_fields(&fields);
                let message = self.redact_text(message);
                self.redact_value(&mut fields);
                let fields = serde_json::to_string(&fields).unwrap_or_else(|_| "{}".to_string());
                format!("{ts}\t{level}\t{caller}\t{message}\t{fields}")
            }
            (Some(raw), None) => {
                self.st.unparseable += 1;
                let raw = self.redact_raw_fields(raw);
                let message = self.redact_text(message);
                format!("{ts}\t{level}\t{caller}\t{message}\t{raw}")
            }
            (None, None) => {
                self.st.unparseable += 1;
                let message = self.redact_text(message);
                format!("{ts}\t{level}\t{caller}\t{message}")
            }
        }
    }

    /// Learn self-identity values from the top-level JSON fields, so the
    /// message of the same line already tags them.
    fn learn_self_fields(&mut self, fields: &Value) {
        if let Value::Object(map) = fields {
            for key in SELF_KEYS {
                if let Some(Value::String(v)) = map.get(*key) {
                    self.st.learn_self(key, v);
                }
            }
        }
    }

    /// Redact a JSON value in place: balances removed, release versions
    /// under a version or release key kept, self-identity keys tokenized,
    /// every other string swept.
    fn redact_value(&mut self, value: &mut Value) {
        match value {
            Value::Object(map) => {
                for (key, child) in map.iter_mut() {
                    if BALANCE_KEYS.contains(&key.as_str()) {
                        if !child.is_null() {
                            *child = Value::String(REMOVED.to_string());
                            self.st.count("balance");
                        }
                    } else if is_release_key(key) && is_version_value(child) {
                        // Versions are kept verbatim (they look like IPv4).
                    } else if SELF_KEYS.contains(&key.as_str()) && child.is_string() {
                        let v = child.as_str().unwrap_or_default().to_string();
                        if let Some(tok) = self.st.self_token(key, &v) {
                            *child = Value::String(tok);
                        }
                    } else {
                        self.redact_value(child);
                    }
                }
            }
            Value::Array(items) => {
                for item in items.iter_mut() {
                    self.redact_value(item);
                }
            }
            Value::String(s) => {
                let redacted = self.redact_text(s);
                *s = redacted;
            }
            _ => {}
        }
    }

    /// Redact an unparseable JSON field block as text: balances and
    /// self-identity values by key pattern, then the text sweep.
    fn redact_raw_fields(&mut self, raw: &str) -> String {
        let st = &mut self.st;
        let raw = self.pats.raw_balance.replace_all(raw, |c: &Captures| {
            st.count("balance");
            format!("\"{}\":\"{REMOVED}\"", &c[1])
        });
        let raw = self.pats.raw_self.replace_all(&raw, |c: &Captures| match st.self_token(&c[1], &c[2]) {
            Some(tok) => format!("\"{}\":\"{tok}\"", &c[1]),
            None => c[0].to_string(),
        });
        let raw = raw.into_owned();
        self.redact_text(&raw)
    }

    /// Sweep free text for every class of sensitive value.
    pub fn redact_text(&mut self, text: &str) -> String {
        let p = &self.pats;
        let st = &mut self.st;
        let t = sweep_paths(&p.path, st, text);
        let t = rewrite(&p.falcon_array, &t, |c, _| {
            let m = c.get(0)?;
            let canon: String = c[1].chars().filter(|ch| !ch.is_whitespace()).collect();
            Some((m.start(), m.end(), format!("FalconPublicKey({})", st.token("key", &canon, false))))
        });
        let t = rewrite(&p.falcon_hex, &t, |c, _| {
            let m = c.get(0)?;
            let canon = c[1].to_ascii_lowercase();
            Some((m.start(), m.end(), format!("FalconPublicKey({})", st.token("key", &canon, false))))
        });
        let t = rewrite(&p.multiaddr, &t, |c, _| {
            let host = c.get(2)?;
            let (class, canon) = match &c[1] {
                "ip4" => {
                    let ip: Ipv4Addr = host.as_str().parse().ok()?;
                    if ip.is_loopback() || ip.is_unspecified() {
                        return None;
                    }
                    ("ip4", host.as_str().to_string())
                }
                "ip6" => {
                    let ip: Ipv6Addr = host.as_str().parse().ok()?;
                    if ip.is_loopback() || ip.is_unspecified() || st.kept.contains(host.as_str()) {
                        return None;
                    }
                    ("ip6", ip.to_string())
                }
                _ => {
                    let name = host.as_str().to_ascii_lowercase();
                    if name == "localhost" {
                        return None;
                    }
                    ("dns", name)
                }
            };
            let tok = st.sweep_token(class, &canon)?;
            Some((host.start(), host.end(), tok))
        });
        let t = rewrite(&p.ip6_bracket, &t, |c, _| {
            let addr = c.get(1)?;
            let ip: Ipv6Addr = addr.as_str().parse().ok()?;
            if ip.is_loopback() || ip.is_unspecified() {
                return None;
            }
            let end = c.get(2).map_or(addr.end(), |z| z.end());
            let tok = st.sweep_token("ip6", &ip.to_string())?;
            Some((addr.start(), end, tok))
        });
        let t = rewrite(&p.ip4, &t, |c, text| {
            let m = c.get(0)?;
            if !is_ipv4_candidate(text, m.start(), m.end()) {
                return None;
            }
            let ip: Ipv4Addr = m.as_str().parse().ok()?;
            if ip.is_loopback() || ip.is_unspecified() || ip.is_broadcast() {
                return None;
            }
            let tok = st.sweep_token("ip4", m.as_str())?;
            Some((m.start(), m.end(), tok))
        });
        let t = rewrite(&p.ip6_bare, &t, |c, text| {
            let m = c.get(0)?;
            let bytes = text.as_bytes();
            let before = m.start().checked_sub(1).map(|i| bytes[i]);
            let after = bytes.get(m.end()).copied();
            let joined = |b: Option<u8>| b.is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'.'));
            if joined(before) || joined(after) {
                return None;
            }
            let ip: Ipv6Addr = m.as_str().parse().ok()?;
            if ip.is_loopback() || ip.is_unspecified() {
                return None;
            }
            let tok = st.sweep_token("ip6", &ip.to_string())?;
            Some((m.start(), m.end(), tok))
        });
        let t = rewrite(&p.peer, &t, |c, _| {
            let m = c.get(0)?;
            let tok = st.sweep_token("peer", m.as_str())?;
            Some((m.start(), m.end(), tok))
        });
        sweep_literals(st, t)
    }
}

/// Rebuild `text`, replacing the span `(start, end)` returned by `f` for a
/// match with the returned string; `None` keeps the match. Spans must not
/// reach before the previous replacement.
fn rewrite(
    re: &Regex,
    text: &str,
    mut f: impl FnMut(&Captures, &str) -> Option<(usize, usize, String)>,
) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for caps in re.captures_iter(text) {
        if let Some((start, end, rep)) = f(&caps, text) {
            let start = start.max(last);
            out.push_str(&text[last..start]);
            out.push_str(&rep);
            last = end.max(start);
        }
    }
    out.push_str(&text[last..]);
    out
}

/// Replace home paths with `path#…/<basename>`; the token covers the
/// directory, and a bare home directory is tokenized whole.
fn sweep_paths(re: &Regex, st: &mut State, text: &str) -> String {
    rewrite(re, text, |c, text| {
        let m = c.get(0)?;
        let bytes = text.as_bytes();
        let mut start = m.start();
        let mut end = m.end();
        let is_root = m.as_str().starts_with("/root");
        if is_root {
            // `/root` must be a path start and a whole segment (`/rootfs`
            // and `tree/root` are not home paths).
            if start > 0 && is_path_byte(bytes[start - 1]) {
                return None;
            }
            if bytes.get(start + 5).is_some_and(|b| *b != b'/' && is_path_byte(*b)) {
                return None;
            }
        } else {
            // A home directory inside a longer path (`/mnt/home/<user>`).
            while start > 0 && is_path_byte(bytes[start - 1]) {
                start -= 1;
            }
        }
        while end > m.start() + 1 && bytes[end - 1] == b'.' {
            end -= 1;
        }
        let full = &text[start..end];
        // End of the home directory itself within `full`.
        let offset = m.start() - start;
        let home_end = if is_root {
            offset + 5
        } else {
            let after_prefix = offset + if m.as_str().starts_with("/home/") { 6 } else { 7 };
            full[after_prefix..].find('/').map_or(full.len(), |i| after_prefix + i)
        };
        if full.len() <= home_end + 1 {
            return Some((start, end, st.token("path", full.trim_end_matches('/'), false)));
        }
        let slash = full.rfind('/').unwrap_or(home_end);
        let (dir, base) = (&full[..slash], &full[slash + 1..]);
        Some((start, end, format!("{}/{base}", st.token("path", dir, false))))
    })
}

/// Replace whole-word occurrences of the configured literals.
fn sweep_literals(st: &mut State, mut text: String) -> String {
    let literals = st.literals.clone();
    for (class, word) in &literals {
        if !text.contains(word.as_str()) {
            continue;
        }
        let bytes = text.as_bytes();
        let joined = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for (i, _) in text.match_indices(word.as_str()) {
            let end = i + word.len();
            if i < last || (i > 0 && joined(bytes[i - 1])) || bytes.get(end).is_some_and(|b| joined(*b)) {
                continue;
            }
            out.push_str(&text[last..i]);
            out.push_str(&st.token(class, word, false));
            last = end;
        }
        out.push_str(&text[last..]);
        text = out;
    }
    text
}

/// The lowercase words of a JSON key: `peer_version` and `peerVersion`
/// are `peer`, `version`.
fn key_words(key: &str) -> Vec<String> {
    let mut words = vec![String::new()];
    let mut previous_lower = false;
    for c in key.chars() {
        if !c.is_ascii_alphanumeric() {
            words.push(String::new());
            previous_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && previous_lower {
            words.push(String::new());
        }
        previous_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        words.last_mut().expect("never empty").push(c.to_ascii_lowercase());
    }
    words.retain(|word| !word.is_empty());
    words
}

/// Whether a JSON key names release versions: a whole word of it is
/// `version`, `release` or their plural (`version`, `peer_version`,
/// `releases`, `release_eligibility`; not `released_by`).
fn is_release_key(key: &str) -> bool {
    key_words(key).iter().any(|word| matches!(word.as_str(), "version" | "versions" | "release" | "releases"))
}

/// Words the node logs beside release versions (`this node: 24`, `no peer
/// info: 3,8`).
const RELEASE_LABELS: &[&str] =
    &["this", "node", "no", "peer", "info", "fingerprint", "malformed", "version", "none", "never", "unknown"];

/// Whether `text` holds release versions only: dotted numbers (`2.1.0.25`,
/// `v2.1.0.25.96`), numbers, [`RELEASE_LABELS`] and the separators `,`,
/// `;`, `=` and a trailing `:`. An address with a port, a multiaddr, a path
/// or a peer ID is none of these.
fn is_version_text(text: &str) -> bool {
    text.split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '=')).all(|token| {
        let token = token.strip_suffix(':').unwrap_or(token);
        let number = token.strip_prefix('v').unwrap_or(token);
        token.is_empty()
            || number.split('.').all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
            || RELEASE_LABELS.contains(&token.to_ascii_lowercase().as_str())
    })
}

/// Whether a JSON value under a release key is kept verbatim: a number, or
/// a string or array of strings of [`is_version_text`]. Anything else, an
/// object included, is redacted as usual.
fn is_version_value(value: &Value) -> bool {
    match value {
        Value::Number(_) => true,
        Value::String(text) => is_version_text(text),
        Value::Array(items) => items.iter().all(|item| item.as_str().is_some_and(is_version_text)),
        _ => false,
    }
}

/// Release file names: `node-` or `qclient-`, the version, then a platform
/// followed by `-` or the end: `node-2.1.0.25-linux-amd64`.
const RELEASE_BINARIES: &[&str] = &["node-", "qclient-"];
const RELEASE_PLATFORMS: &[&str] = &["-linux", "-darwin", "-windows", "-freebsd"];

/// Whether the dotted quad at `text[start..end]` is the version of a
/// release file name.
fn in_release_file_name(text: &str, start: usize, end: usize) -> bool {
    let named = RELEASE_BINARIES.iter().any(|binary| {
        text[..start].strip_suffix(binary).is_some_and(|before| before.chars().next_back().is_none_or(|c| !c.is_ascii_alphanumeric()))
    });
    named
        && RELEASE_PLATFORMS
            .iter()
            .any(|platform| text[end..].strip_prefix(platform).is_some_and(|rest| rest.is_empty() || rest.starts_with('-')))
}

/// Whether the dotted quad at `text[start..end]` is an address rather than
/// part of a longer dotted string, a version (`version 2.1.0.25`,
/// `"version":"2.1.0.25"`, `v2.1.0.25`) or a release file name
/// (`node-2.1.0.25-linux-amd64`). A quad with a port is an address.
fn is_ipv4_candidate(text: &str, start: usize, end: usize) -> bool {
    let bytes = text.as_bytes();
    if start > 0 && matches!(bytes[start - 1], b'.' | b'_') {
        return false;
    }
    if bytes.get(end) == Some(&b'.') && bytes.get(end + 1).is_some_and(|b| b.is_ascii_digit()) {
        return false;
    }
    if bytes.get(end) == Some(&b':') && bytes.get(end + 1).is_some_and(|b| b.is_ascii_digit()) {
        return true;
    }
    if in_release_file_name(text, start, end) {
        return false;
    }
    let before = text[..start].trim_end_matches(|c: char| c.is_whitespace() || matches!(c, ':' | '=' | '"' | '\''));
    let word: String = before
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>()
        .to_ascii_lowercase();
    // The last word of `version`, `peer_version`; not `conversion`.
    let word = word.rsplit('_').next().unwrap_or_default();
    !matches!(word, "version" | "versions" | "v" | "ver")
}

/// The UTC Unix time of a node log line's leading `YYYY-MM-DDTHH:MM:SSZ`
/// timestamp (followed by a tab or the end of the line), or `None` for a
/// continuation line.
pub fn parse_log_timestamp(line: &str) -> Option<i64> {
    let ts = line.get(..20)?;
    if !matches!(line.as_bytes().get(20), None | Some(b'\t')) {
        return None;
    }
    parse_rfc3339_utc(ts)
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.fff](Z|+00:00)?` (or with a space for `T`)
/// as UTC Unix seconds; a missing offset is read as UTC, any other offset
/// is rejected.
pub fn parse_rfc3339_utc(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = s.get(r)?;
        if part.bytes().all(|c| c.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    let (y, mo, d, h, mi, se) = (num(0..4)?, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let mut rest = &s[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        let digits = frac.bytes().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 {
            return None;
        }
        rest = &frac[digits..];
    }
    if !matches!(rest, "" | "Z" | "z" | "+00:00" | "-00:00") {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se)
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `(year, month, day)` of a day count since 1970-01-01.
pub fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// `YYYY-MM-DDTHH:MM:SSZ` of UTC Unix seconds.
pub fn format_rfc3339_utc(secs: i64) -> String {
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let s = secs.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, s / 60 % 60, s % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; 32] = [7; 32];
    /// Synthetic peer IDs (valid base58 shapes, no real peer).
    const QM: &str = "QmSyntheticPeerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const ED: &str = "12D3KooWSyntheticPeerBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const FILTER: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9";

    fn redactor() -> Redactor {
        Redactor::new(
            SALT,
            RedactOptions { keep_self: false, public_endpoints: Vec::new(), literals: vec![("host", "examplehost".to_string())] },
        )
    }

    fn line(message: &str, fields: &str) -> String {
        format!("2026-10-17T18:57:00Z\tinfo\tquil_node/src/p2p.rs:42\t{message}\t{fields}")
    }

    /// Inputs of the golden test: one line per class, and its expected
    /// redaction under `SALT` (tokens computed independently).
    fn golden() -> Vec<(String, String)> {
        let c0 = r#"{"coreId":0}"#;
        vec![
            (line("dialing 192.0.2.10:8340", c0), line("dialing ip4#6fe0c5ee:8340", c0)),
            (line("connected to [2001:db8::1]:8336", c0), line("connected to [ip6#d029fa0c]:8336", c0)),
            (line("listening on 2001:db8::1 port 8336", c0), line("listening on ip6#d029fa0c port 8336", c0)),
            (
                line("peer joined", &format!(r#"{{"addr":"/ip4/198.51.100.7/udp/8336/quic-v1/p2p/{QM}","coreId":3}}"#)),
                line("peer joined", r#"{"addr":"/ip4/ip4#3f6c10d6/udp/8336/quic-v1/p2p/peer#bf5694cc","coreId":3}"#),
            ),
            (line("via /ip6/2001:db8:0:0:0:0:0:2/udp/8336", c0), line("via /ip6/ip6#ccf876c7/udp/8336", c0)),
            (line("via /dns4/node.example.org/tcp/8336", c0), line("via /dns4/dns#b6affde4/tcp/8336", c0)),
            (line(&format!("scored peer {ED}: 4.5"), c0), line("scored peer peer#c92daf7b: 4.5", c0)),
            (
                line("store open failed", r#"{"coreId":0,"error":"open /home/alice/quil/node/.config/store: permission denied"}"#),
                line("store open failed", r#"{"coreId":0,"error":"open path#01c1082b/store: permission denied"}"#),
            ),
            (line("config /Users/bob/Library/quil/keys.yml", c0), line("config path#1f36e62e/keys.yml", c0)),
            (line("config /root/.quilibrium/node/config.yml", c0), line("config path#251d35a6/config.yml", c0)),
            (line("home is /home/alice", c0), line("home is path#86521c88", c0)),
            (line("signer FalconPublicKey(0123456789abcdef…)", c0), line("signer FalconPublicKey(key#a1dc447c)", c0)),
            (line("signer FalconPublicKey([1, 2, 3, 250])", c0), line("signer FalconPublicKey(key#75db8148)", c0)),
            (
                line("reward", r#"{"balance":"12.5","coreId":0,"delta":"0.1","new_balance":12.6}"#),
                line("reward", r#"{"balance":"<removed>","coreId":0,"delta":"<removed>","new_balance":"<removed>"}"#),
            ),
            (line("running on examplehost", c0), line("running on host#f9de1b30", c0)),
            (
                line("P2P identity ready", &format!(r#"{{"coreId":0,"peer_id":"{QM}"}}"#)),
                line("P2P identity ready", r#"{"coreId":0,"peer_id":"self:peer#bf5694cc"}"#),
            ),
            (
                line("prover", r#"{"coreId":0,"prover_address":"0a0b0c0d0e0f"}"#),
                line("prover", r#"{"coreId":0,"prover_address":"self:prover#0091ae48"}"#),
            ),
        ]
    }

    /// Sensitive values of every test input; none may survive redaction.
    const SENSITIVE: &[&str] = &[
        "192.0.2.10", "198.51.100.7", "203.0.113.42", "2001:db8::1", "2001:db8:0:0:0:0:0:2", "node.example.org",
        QM, ED, "/home/alice", "alice", "/Users/bob", "/root/.quilibrium", "0123456789abcdef", "1, 2, 3, 250",
        "12.5", "0.1", "12.6", "examplehost", "0a0b0c0d0e0f",
    ];

    #[test]
    fn hmac_matches_rfc4231() {
        let mac = hmac_sha256(b"Jefe", &[&b"what do ya want for nothing?"[..]]);
        assert_eq!(hex::encode(mac), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn golden_line_per_class() {
        for (input, expected) in golden() {
            assert_eq!(redactor().redact_line(&input), expected, "input: {input}");
        }
    }

    #[test]
    fn no_original_value_survives() {
        let mut r = redactor();
        let mut out = String::new();
        let mut inputs: Vec<String> = golden().into_iter().map(|(i, _)| i).collect();
        inputs.push(line("x", r#"{"coreId":0,"detail":{"via":"/ip4/192.0.2.10/udp/8336"},"peers":["/ip4/203.0.113.42/tcp/8336"]}"#));
        inputs.push("  at /home/alice/quil/src/main.rs:12 near 203.0.113.42".to_string());
        for input in &inputs {
            out.push_str(&r.redact_line(input));
            out.push('\n');
        }
        for value in SENSITIVE {
            assert!(!out.contains(value), "{value} survived in:\n{out}");
        }
    }

    #[test]
    fn same_salt_same_token_other_salt_other_token() {
        let mut r = redactor();
        let a = r.redact_line(&line("dial 192.0.2.10", r#"{"coreId":0}"#));
        let b = r.redact_line(&line("retry", r#"{"addr":"192.0.2.10:8340","coreId":1}"#));
        let ip = token(&SALT, "ip4", "192.0.2.10");
        assert!(a.contains(&ip) && b.contains(&format!("{ip}:8340")), "{a}\n{b}");
        assert_eq!(r.distinct().get("ip4"), Some(&1));
        assert_eq!(r.counts().get("ip4"), Some(&2));
        let mut other = Redactor::new([8; 32], RedactOptions::default());
        let c = other.redact_line(&line("dial 192.0.2.10", r#"{"coreId":0}"#));
        assert!(c.contains(&token(&[8; 32], "ip4", "192.0.2.10")) && !c.contains(&ip), "{c}");
        assert_ne!(token(&SALT, "ip4", "192.0.2.10"), token(&[8; 32], "ip4", "192.0.2.10"));
        // The class is part of the token input.
        assert_ne!(token(&SALT, "ip4", "x")[4..], token(&SALT, "dns", "x")[4..]);
    }

    #[test]
    fn versions_are_not_addresses() {
        let mut r = redactor();
        for kept in [
            line("node version 2.1.0.25 started", r#"{"coreId":0}"#),
            line("upgrade to v2.1.0.25", r#"{"coreId":0}"#),
            line("peer info", r#"{"coreId":0,"version":"2.1.0.25"}"#),
            line("peer info", r#"{"coreId":0,"peer_version":"2.1.0.24"}"#),
            line("build 10.0.0.1.2 tag", r#"{"coreId":0}"#),
            line("at quil_engine::app::fee 18:57:00", r#"{"coreId":0}"#),
        ] {
            assert_eq!(r.redact_line(&kept), kept);
        }
        // Raw (unparseable) field blocks keep versions too.
        assert_eq!(r.redact_text(r#""version":"2.1.0.25""#), r#""version":"2.1.0.25""#);
        assert_eq!(r.total(), 0);
        let real = r.redact_line(&line("peer at 192.0.2.10", r#"{"coreId":0}"#));
        assert_eq!(real, line("peer at ip4#6fe0c5ee", r#"{"coreId":0}"#));
    }

    /// Committee builds by member index name bare 4-part releases; a
    /// release or version key keeps versions only, and an address in
    /// another field of the line is still tokenized.
    #[test]
    fn release_fields_keep_bare_versions() {
        let mut r = redactor();
        let releases = r#""releases":"2.1.0.25.96: 3,8,11; 2.1.0.25: 1,2,5; no peer info: 4; this node: 24""#;
        let kept = line("app committee member builds by member index", &format!("{{\"coreId\":4,{releases}}}"));
        assert_eq!(r.redact_line(&kept), kept);
        for kept in [
            line("release eligibility", r#"{"coreId":0,"release_eligibility":"910000=2.1.0.25,920000=2.1.0.26"}"#),
            line("confirm", r#"{"coreId":0,"release":"2.1.0.25"}"#),
            line("builds", r#"{"coreId":0,"peerVersion":"v2.1.0.24","releases":["2.1.0.25","2.1.0.25.96"],"version":1}"#),
        ] {
            assert_eq!(r.redact_line(&kept), kept);
        }
        assert_eq!(r.total(), 0);
        let mixed = line("app committee member builds by member index", &format!("{{\"peer\":\"192.0.2.10:8340\",{releases}}}"));
        assert_eq!(r.redact_line(&mixed), line("app committee member builds by member index",
            &format!("{{\"peer\":\"ip4#6fe0c5ee:8340\",{releases}}}")));
    }

    /// A release or version key keeps nothing but versions: an address,
    /// multiaddr, peer ID or home path under it, or in an object under it,
    /// is tokenized, and so is any value of a key that only contains the
    /// word (`released_by`).
    #[test]
    fn release_keys_keep_no_addresses() {
        let mut r = redactor();
        for (fields, original) in [
            (r#"{"release_addr":"/ip4/198.51.100.7/tcp/8336"}"#, "198.51.100.7"),
            (r#"{"release":{"peer":"192.0.2.10:8340"}}"#, "192.0.2.10"),
            (r#"{"releases":["2.1.0.25","/home/alice/quil"]}"#, "alice"),
            (&*format!(r#"{{"release":"{QM}"}}"#), QM),
            (r#"{"version":"192.0.2.10:8340"}"#, "192.0.2.10"),
            (r#"{"version":"[2001:db8::1]:8336"}"#, "2001:db8::1"),
            (r#"{"released_by":"192.0.2.10"}"#, "192.0.2.10"),
            (r#"{"conversion":"192.0.2.10"}"#, "192.0.2.10"),
        ] {
            let redacted = r.redact_line(&line("peer", fields));
            assert!(!redacted.contains(original), "{fields}: {redacted}");
        }
    }

    /// Release binary names keep their version, in paths and free text;
    /// addresses beside them, with a port or in a multiaddr, are tokenized.
    #[test]
    fn release_file_names_keep_their_version() {
        let mut r = redactor();
        let worker = r.redact_line(&line("token proof worker configured",
            r#"{"coreId":0,"worker":"/home/alice/quil/node-2.1.0.25-linux-amd64"}"#));
        assert!(worker.contains(r#"/node-2.1.0.25-linux-amd64""#) && !worker.contains("ip4#") && !worker.contains("alice"), "{worker}");
        for name in ["qclient-2.1.0.25-darwin-arm64", "node-2.1.0.25-windows-amd64.exe", "node-2.1.0.25-freebsd-amd64", "node-2.1.0.25-linux"] {
            let kept = line(&format!("downloaded {name}"), r#"{"coreId":0}"#);
            assert_eq!(r.redact_line(&kept), kept);
        }
        assert_eq!(r.total(), 1, "only the home path");
        let near = r.redact_line(&line("node-2.1.0.25-linux-amd64 dialing 192.0.2.10:8340 via /ip4/198.51.100.7/tcp/8336", r#"{"coreId":0}"#));
        assert_eq!(near, line("node-2.1.0.25-linux-amd64 dialing ip4#6fe0c5ee:8340 via /ip4/ip4#3f6c10d6/tcp/8336", r#"{"coreId":0}"#));
        for text in ["host-192.0.2.10-backup", "host-192.0.2.10-linux", "foo-192.0.2.10-linux-amd64", "mynode-192.0.2.10-linux-amd64",
            "node-192.0.2.10-linuxbox", "node-192.0.2.10:8336-linux-amd64"] {
            let redacted = r.redact_line(&line(text, r#"{"coreId":0}"#));
            assert!(!redacted.contains("192.0.2.10") && redacted.contains("ip4#6fe0c5ee"), "{text}: {redacted}");
        }
    }

    /// Only the exact words version, v and ver before a quad keep it, and
    /// never with a port.
    #[test]
    fn only_a_version_word_keeps_a_quad_in_text() {
        let mut r = redactor();
        for text in ["release 192.0.2.10", "release=192.0.2.10", "release 192.0.2.10:8336", "prerelease 192.0.2.10",
            "conversion 192.0.2.10", "version 192.0.2.10:8336", "peer_version=192.0.2.10:8336"] {
            let redacted = r.redact_text(text);
            assert!(!redacted.contains("192.0.2.10"), "{text}: {redacted}");
        }
        for text in ["version 2.1.0.25", "peer_version=2.1.0.24", "ver 2.1.0.25"] {
            assert_eq!(r.redact_text(text), text);
        }
    }

    #[test]
    fn multiaddrs_nested_in_json_strings_are_redacted() {
        let mut r = redactor();
        let out = r.redact_line(&line(
            "peers",
            &format!(r#"{{"coreId":0,"detail":{{"via":"/ip4/192.0.2.10/udp/8336"}},"peers":["/ip4/203.0.113.42/tcp/8336/p2p/{QM}"]}}"#),
        ));
        assert_eq!(
            out,
            line(
                "peers",
                r#"{"coreId":0,"detail":{"via":"/ip4/ip4#6fe0c5ee/udp/8336"},"peers":["/ip4/ip4#38dfe4a4/tcp/8336/p2p/peer#bf5694cc"]}"#
            )
        );
    }

    #[test]
    fn error_with_home_path_and_ip_is_redacted() {
        let out = redactor().redact_line(&line(
            "sync failed",
            r#"{"coreId":0,"error":"dial 198.51.100.7:8340 failed; cache /home/alice/quil/node/.config/peers.db"}"#,
        ));
        assert_eq!(
            out,
            line("sync failed", r#"{"coreId":0,"error":"dial ip4#3f6c10d6:8340 failed; cache path#01c1082b/peers.db"}"#)
        );
    }

    #[test]
    fn falcon_key_forms_are_tokenized() {
        let mut r = redactor();
        let out = r.redact_text("a FalconPublicKey([1, 2, 3, 250]) b FalconPublicKey(0123456789ABCDEF...) c FalconPublicKey(897 bytes)");
        assert_eq!(out, "a FalconPublicKey(key#75db8148) b FalconPublicKey(key#a1dc447c) c FalconPublicKey(897 bytes)");
        assert_eq!(r.counts().get("key"), Some(&2));
    }

    #[test]
    fn bootstrap_archive_endpoints_are_kept() {
        let addr = quil_config::MAINNET_BOOTSTRAP_PEERS[0];
        let parts: Vec<&str> = addr.split('/').collect();
        let (ip, peer) = (parts[2], parts[parts.len() - 1]);
        let mut r = Redactor::new(SALT, RedactOptions::with_bootstrap_endpoints(false));
        let input = line(&format!("archive {ip}:8340 via {addr}, and 192.0.2.10:8340 peer {peer}"), r#"{"coreId":0}"#);
        let out = r.redact_line(&input);
        assert_eq!(
            out,
            line(&format!("archive {ip}:8340 via {addr}, and ip4#6fe0c5ee:8340 peer {peer}"), r#"{"coreId":0}"#)
        );
    }

    /// A line shaped like the node's "inbound SubmitGlobalConsensus" record.
    fn submit_line(peer: &str) -> String {
        line(
            "inbound SubmitGlobalConsensus",
            &format!(r#"{{"bitmask":"0013","bytes":1892,"coreId":0,"kind":"other","peer":"{peer}"}}"#),
        )
    }

    #[test]
    fn peer_ids_are_tokenized_in_any_field_shape() {
        let mut r = redactor();
        let (qm, ed) = (token(&SALT, "peer", QM), token(&SALT, "peer", ED));
        assert_eq!(r.redact_line(&submit_line(QM)), submit_line(&qm));
        assert_eq!(r.redact_line(&submit_line(ED)), submit_line(&ed));
        // IDs glued to a label or suffix by `_` are still IDs.
        assert_eq!(r.redact_line(&submit_line(&format!("peer_{QM}"))), submit_line(&format!("peer_{qm}")));
        assert_eq!(r.redact_line(&submit_line(&format!("{ED}_inbound"))), submit_line(&format!("{ed}_inbound")));
        assert_eq!(
            r.redact_line(&line(&format!("rejected submit_{QM}_x"), r#"{"coreId":0}"#)),
            line(&format!("rejected submit_{qm}_x"), r#"{"coreId":0}"#)
        );
        assert!(!r.token_map().values().any(|v| v.contains("_")), "tokens map whole IDs only");
    }

    #[test]
    fn bootstrap_archive_policy_is_the_same_in_every_field() {
        let addr = quil_config::MAINNET_BOOTSTRAP_PEERS[0];
        let parts: Vec<&str> = addr.split('/').collect();
        let (ip, peer) = (parts[2], parts[parts.len() - 1]);
        let mut r = Redactor::new(SALT, RedactOptions::with_bootstrap_endpoints(false));
        // Public archive endpoints stay in `peer` and `addr` fields ...
        let kept = line("archive poll", &format!(r#"{{"addr":"{ip}:8340","coreId":0,"peer":"{peer}"}}"#));
        assert_eq!(r.redact_line(&kept), kept);
        // ... while any other peer or address is tokenized in the same fields.
        let other = line("archive poll", &format!(r#"{{"addr":"192.0.2.10:8340","coreId":0,"peer":"{QM}"}}"#));
        let want = line("archive poll", &format!(r#"{{"addr":"ip4#6fe0c5ee:8340","coreId":0,"peer":"{}"}}"#, token(&SALT, "peer", QM)));
        assert_eq!(r.redact_line(&other), want);
    }

    #[test]
    fn self_identity_is_tagged_unless_kept() {
        let identity = line("P2P identity ready", &format!(r#"{{"coreId":0,"peer_id":"{QM}"}}"#));
        let dial = line(&format!("dialing /ip4/192.0.2.10/udp/8336/quic-v1/p2p/{QM}"), r#"{"coreId":0}"#);

        let mut r = redactor();
        assert!(r.redact_line(&identity).contains(r#""peer_id":"self:peer#bf5694cc""#));
        assert_eq!(r.redact_line(&dial), line("dialing /ip4/ip4#6fe0c5ee/udp/8336/quic-v1/p2p/self:peer#bf5694cc", r#"{"coreId":0}"#));
        assert_eq!(r.counts().get("self:peer"), Some(&2));

        let mut keep = Redactor::new(SALT, RedactOptions { keep_self: true, ..RedactOptions::default() });
        assert_eq!(keep.redact_line(&identity), identity);
        assert_eq!(keep.redact_line(&dial), line(&format!("dialing /ip4/ip4#6fe0c5ee/udp/8336/quic-v1/p2p/{QM}"), r#"{"coreId":0}"#));
        assert_eq!(keep.counts().get("self:peer"), None);
    }

    #[test]
    fn unparseable_fields_fall_back_to_the_sweep_and_are_counted() {
        let mut r = redactor();
        let truncated = line("dial", r#"{"addr":"192.0.2.10:8340","balance":5,"peer_id":"0a0b"#);
        let out = r.redact_line(&truncated);
        assert!(out.contains(r#""addr":"ip4#6fe0c5ee:8340""#), "{out}");
        assert!(out.contains(r#""balance":"<removed>""#), "{out}");
        assert!(!out.contains("192.0.2.10") && !out.contains(":5,"), "{out}");
        let bare = "2026-10-17T18:57:00Z\tinfo\tquil_node/src/p2p.rs:42\tno fields 203.0.113.42";
        assert_eq!(r.redact_line(bare), "2026-10-17T18:57:00Z\tinfo\tquil_node/src/p2p.rs:42\tno fields ip4#38dfe4a4");
        assert_eq!(r.unparseable(), 2);
        let ok = r.redact_line(&line("fine", r#"{"coreId":0}"#));
        assert_eq!(ok, line("fine", r#"{"coreId":0}"#));
        assert_eq!(r.unparseable(), 2);
    }

    #[test]
    fn kept_values_stay() {
        let mut r = redactor();
        let kept = line(
            "frame 123456 rank 2 session 7f3a9c",
            &format!(r#"{{"coreId":2,"filter":"{FILTER}","frame":123456,"generation":9,"root":"{FILTER}"}}"#),
        );
        assert_eq!(r.redact_line(&kept), kept);
        let local = "loopback 127.0.0.1:8337 [::1]:8337 /ip4/0.0.0.0/tcp/8336 /rootfs tree/root";
        assert_eq!(r.redact_text(local), local);
        assert_eq!(r.total(), 0);
    }

    #[test]
    fn token_map_holds_originals() {
        let mut r = redactor();
        r.redact_line(&line("dial 192.0.2.10", r#"{"coreId":0}"#));
        assert_eq!(r.token_map().get("ip4#6fe0c5ee").map(String::as_str), Some("192.0.2.10"));
    }

    #[test]
    fn timestamps_round_trip() {
        assert_eq!(parse_rfc3339_utc("2026-10-17T18:57:00Z"), Some(1_792_263_420));
        assert_eq!(parse_rfc3339_utc("2026-10-17 18:57:00.250+00:00"), Some(1_792_263_420));
        assert_eq!(parse_rfc3339_utc("2000-02-29T00:00:00Z"), Some(951_782_400));
        assert_eq!(parse_rfc3339_utc("2026-10-17T18:57:00+02:00"), None);
        assert_eq!(parse_rfc3339_utc("2026-13-17T18:57:00Z"), None);
        assert_eq!(format_rfc3339_utc(1_792_263_420), "2026-10-17T18:57:00Z");
        assert_eq!(format_rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
        for days in [-1000, 0, 59, 60, 11_016, 20_743] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
        assert_eq!(parse_log_timestamp(&line("x", "{}")), Some(1_792_263_420));
        assert_eq!(parse_log_timestamp("  at main.rs:12"), None);
    }
}
