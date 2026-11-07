//! What an API key is allowed to be shown.
//!
//! The node's diagnostics health report is worker state with no logs, no
//! addresses and no keys. A log export is redacted before it leaves the
//! node, and the keystore is never part of either. qagent applies that
//! boundary to every key an assistant holds.
//!
//! The operator's first full key may see this node's peer id. A read-only
//! key, and any later full key issued to someone else, is an external key:
//! it receives the health-report view. No key is given `peerPrivKey`, the
//! keystore encryption key, or anything read from `keys.yml`.

use crate::auth::Access;

/// Who is asking. External keys are read-only keys and full keys other than
/// the operator's first full key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audience {
    /// The operator's own full key, on this computer.
    Operator,
    /// A read-only key, or a full key issued to another tool.
    External,
}

impl Audience {
    pub fn of(access: Access, external: bool) -> Self {
        if external || access == Access::ReadOnly {
            Self::External
        } else {
            Self::Operator
        }
    }
}

/// Returned instead of a result that would have carried config or keystore
/// material. The material itself is not in this sentence.
pub const WITHHELD: &str =
    "That was not returned. The node config's private key and the keystore are never sent to an API key.";

/// `text` contains node-config or keystore material: `peerPrivKey`,
/// `encryptionKey`, a `keys.yml` entry, or a hex run long enough to be one
/// of those keys.
pub fn holds_config_secret(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "peerprivkey",
        "privatekey",
        "encryptionkey",
        "publickey:",
        "keys.yml",
        "keys.yaml",
        "keymanagerfile",
    ];
    if MARKERS.iter().any(|marker| lower.contains(marker)) {
        return true;
    }
    hex_run_at_least(text, 228)
}

/// The text an API key may see. A secret is refused whole. An external key
/// also loses home paths and peer ids, the way a log export tokenizes them.
pub fn release(audience: Audience, api_secrets: &[String], text: String) -> String {
    if holds_config_secret(&text) || contains_secret(&text, api_secrets) {
        return WITHHELD.to_string();
    }
    match audience {
        Audience::Operator => text,
        Audience::External => redact_external(&text),
    }
}

/// Whether `text` contains one of `secrets`. Short values are ignored so a
/// test key cannot match an ordinary word.
fn contains_secret(text: &str, secrets: &[String]) -> bool {
    secrets
        .iter()
        .any(|secret| secret.len() >= 16 && text.contains(secret.as_str()))
}

fn hex_run_at_least(text: &str, min: usize) -> bool {
    let mut run = 0usize;
    for byte in text.bytes() {
        if byte.is_ascii_hexdigit() {
            run += 1;
            if run >= min {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Home paths and libp2p peer ids, replaced the way a diagnostics log export
/// removes them. Loopback addresses and frame numbers stay.
fn redact_external(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        if let Some(end) = path_len(rest) {
            out.push_str("path");
            rest = &rest[end..];
            continue;
        }
        if let Some(end) = peer_len(rest) {
            out.push_str("peer");
            rest = &rest[end..];
            continue;
        }
        let Some(ch) = rest.chars().next() else {
            break;
        };
        out.push(ch);
        rest = &rest[ch.len_utf8()..];
    }
    out
}

fn path_len(text: &str) -> Option<usize> {
    const ROOTS: &[&str] = &["/home/", "/Users/", "/root/"];
    if !ROOTS.iter().any(|root| text.starts_with(root)) {
        return None;
    }
    let end = text
        .bytes()
        .position(|byte| !is_path_byte(byte))
        .unwrap_or(text.len());
    Some(end)
}

fn is_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'@' | b'~' | b'/' | b'-')
}

fn peer_len(text: &str) -> Option<usize> {
    const PREFIXES: &[&str] = &["12D3KooW", "16Uiu2HA", "Qm"];
    let prefix = PREFIXES.iter().find(|prefix| text.starts_with(*prefix))?;
    let min = if *prefix == "Qm" {
        46
    } else {
        prefix.len() + 8
    };
    let end = text
        .bytes()
        .position(|byte| !is_base58(byte))
        .unwrap_or(text.len());
    if end >= min {
        Some(end)
    } else {
        None
    }
}

fn is_base58(byte: u8) -> bool {
    matches!(byte, b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_config_or_keystore_dump_is_refused_for_every_key() {
        let peer = "ab".repeat(114);
        for audience in [Audience::Operator, Audience::External] {
            let refused = release(audience, &[], format!("p2p:\n  peerPrivKey: {peer}\n"));
            assert_eq!(refused, WITHHELD);
            assert!(!refused.contains(&peer));
            assert_eq!(
                release(audience, &[], "privateKey: abc\npublicKey: def\n".into()),
                WITHHELD
            );
            assert_eq!(
                release(audience, &[], format!("key material {peer}")),
                WITHHELD
            );
        }
        assert!(!holds_config_secret("Workers: 1 running, reachable true"));
        assert!(!holds_config_secret("1.000000000000 QUIL"));
    }

    #[test]
    fn an_external_key_loses_paths_and_peer_ids_and_keeps_the_health_facts() {
        let text = release(
            Audience::External,
            &[],
            "Workers: 2 running\nPeer: 12D3KooWAbCdEfGh1234\nConfig: /home/someone/.quilibrium/configs/NAME/config.yml\nReachable: true".into(),
        );
        assert!(text.contains("Workers: 2 running"), "{text}");
        assert!(text.contains("Reachable: true"), "{text}");
        assert!(text.contains("peer"), "{text}");
        assert!(!text.contains("12D3KooW"), "{text}");
        assert!(!text.contains("/home/someone"), "{text}");
        assert!(text.contains("path"), "{text}");
    }

    #[test]
    fn the_operator_keeps_the_peer_id_and_still_loses_a_pasted_api_secret() {
        let peer = "12D3KooWAbCdEfGh1234";
        let shown = release(Audience::Operator, &[], format!("Peer: {peer}"));
        assert!(shown.contains(peer), "{shown}");
        let secret = "0123456789abcdef0123456789abcdef";
        let refused = release(Audience::External, &[secret.into()], format!("token {secret}"));
        assert_eq!(refused, WITHHELD);
        assert!(!refused.contains(secret));
    }
}
